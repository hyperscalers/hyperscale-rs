//! Block-sync invariants pinned by the shard sim.

mod common;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::test_utils::verified_test_transaction;
use hyperscale_types::{
    AggregateSignature, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, BlockManifest,
    CertifiedBlock, Hash, ProposerTimestamp, QuorumCertificate, Round, SignerBitfield, ValidatorId,
    WeightedTimestamp,
};

const MAX_STEPS: usize = 10_000;

/// A fully honest run's committed chain: heights 1..=N, round-contiguous
/// (no view change), reusable as sync-apply input for a lagging replica.
/// Same `(n, seed)` ⇒ same committee and genesis, so the certified blocks
/// verify against any sim built with the same parameters.
fn reference_chain(n: usize, seed: u64, heights: usize) -> Vec<CertifiedBlock> {
    let mut sim = ShardCoordinatorSim::new(n, seed);
    sim.kick_off();
    sim.run_until_committed(heights, MAX_STEPS);
    sim.commits[0]
        .iter()
        .map(|c| (**c.certified).clone())
        .collect()
}

/// The round-contiguous two-chain rule applies on the sync path: a synced
/// block does not finalize on its own QC — only when a child certified at
/// exactly `round + 1` is admitted. A single QC is not a commit certificate;
/// an orphan sibling at the same height carries one too, so committing on the
/// bare QC would let a peer-served orphan fork a lagging node.
#[test]
fn synced_block_needs_round_contiguous_child_to_commit() {
    let seed = 0x5A_FE;
    let reference = reference_chain(4, seed, 3);
    assert!(
        reference.len() >= 2,
        "need at least two committed heights to feed a parent and its child",
    );

    // A fresh replica at committed height 0 catches up purely via sync apply.
    let mut sim = ShardCoordinatorSim::new(4, seed);
    let lagging = ValidatorId::new(3);

    // Feed only the first block. Without its round-contiguous child it must
    // not commit — this is the orphan-sibling case (the child never exists, so
    // a Byzantine peer cannot forge the 2f+1 QC that would certify it).
    sim.deliver_synced_block(lagging, &reference[0]);
    sim.run_for_at_most(2_000);
    assert_eq!(
        sim.coordinators[3].committed_height(),
        BlockHeight::new(0),
        "synced block committed on its bare QC without a round-contiguous child",
    );
    assert!(
        sim.commits[3].is_empty(),
        "lagging replica recorded a commit it should have deferred",
    );

    // Feed the round-contiguous child. Now the parent finalizes. The
    // replica may go on to propose over the QC it synced, and the idle
    // committee carry the chain further, so the parent is pinned as the
    // first commit rather than as the tip.
    sim.deliver_synced_block(lagging, &reference[1]);
    sim.run_for_at_most(2_000);
    assert_eq!(
        sim.commits[3].first().map(|c| c.certified.block().hash()),
        Some(reference[0].block().hash()),
        "round-contiguous child did not finalize its parent on the sync path",
    );
}

/// A replica that misses h=1's header but receives everything else hits the
/// missing-parent path on h=2's arrival and emits `StartBlockSync`. It then
/// catches up when the chain is delivered via sync apply, finalizing every
/// block whose round-contiguous child is also delivered — all but the
/// frontier, which finalizes through live consensus.
#[test]
fn silenced_replica_triggers_sync_and_catches_up_via_apply() {
    let seed = 0x5C_DC;
    // Several round-contiguous heights so the catch-up commits more than the
    // single deferred frontier block.
    let reference = reference_chain(4, seed, 4);
    assert!(reference.len() >= 3, "need a multi-height reference chain");

    let mut sim = ShardCoordinatorSim::new(4, seed);
    let lagging = ValidatorId::new(3);

    sim.hold_matching(
        lagging,
        HoldFilter::BlockHeaderAtHeight(BlockHeight::new(1)),
    );
    sim.kick_off();

    let aggregators: Vec<usize> = vec![0, 2];
    sim.run_until_committed_for(&aggregators, 1, MAX_STEPS);
    assert_eq!(
        sim.commits[3].len(),
        0,
        "lagging replica unexpectedly committed despite held h=1 header",
    );

    assert!(
        !sim.sync_targets[3].is_empty(),
        "replica 3 didn't emit StartBlockSync on missing-parent path",
    );
    let sync_target = *sim.sync_targets[3]
        .iter()
        .max()
        .expect("at least one sync target captured");
    assert!(
        sim.coordinators[3].is_block_syncing(),
        "replica 3 should be in sync mode after emitting StartBlockSync",
    );

    // Feed the reference chain into the lagging replica's sync apply path. Each
    // block runs through QC verification + the round-contiguous two-chain rule;
    // the sync entry attests QC trust via `from_qc_attestation` instead of
    // re-running per-root verifications.
    for certified in &reference {
        sim.deliver_synced_block(lagging, certified);
        sim.run_for_at_most(500);
    }

    // The processed frontier reaches the target, so sync completes and the
    // replica resumes consensus — completion tracks admission, not the commit
    // that lags it by a block.
    assert!(
        !sim.coordinators[3].is_block_syncing(),
        "replica 3 still in sync mode after the processed frontier reached the target",
    );

    // The round-contiguous rule finalizes every fed block except the last;
    // live consensus, which the rest of the committee keeps running, carries
    // the replica on from there.
    let frontier = reference.last().unwrap().block().height();
    let expected_committed = BlockHeight::new(frontier.inner() - 1);
    assert!(
        sim.coordinators[3].committed_height() >= expected_committed,
        "replica 3 didn't catch up to one below the delivered frontier: committed={:?}",
        sim.coordinators[3].committed_height(),
    );
    assert!(
        sim.coordinators[3].committed_height() >= sync_target,
        "replica 3 stayed below the sync target: committed={:?} target={:?}",
        sim.coordinators[3].committed_height(),
        sync_target,
    );

    // Every committed height the reference covers matches it byte-for-byte.
    for (h, (committed, reference)) in sim.commits[3].iter().zip(&reference).enumerate() {
        assert_eq!(
            committed.block_hash,
            reference.block().hash(),
            "replica 3 diverged from the reference chain at height index {h}",
        );
        assert_eq!(
            committed.state_root,
            reference.block().header().state_root(),
            "replica 3 diverged on state root at height index {h}",
        );
    }
}

/// A header whose parent QC claims every signer over a block far above
/// the chain, with no real signature behind it, starts no block sync.
/// Block sync has no exit for a height the network cannot serve, so a
/// sync toward it would hold the replica in sync mode, proposing only
/// empty blocks, until it restarts. The replica stays out of sync mode and
/// the chain goes on committing the transactions it is handed.
#[test]
fn a_forged_parent_certificate_starts_no_sync() {
    let mut sim = ShardCoordinatorSim::new(4, 0xF0_57);
    let receiver = ValidatorId::new(3);
    sim.kick_off();
    sim.run_until_committed(2, MAX_STEPS);
    let base = sim.commits[3]
        .last()
        .expect("the receiver committed")
        .certified
        .block()
        .header()
        .clone();

    let claimed_height = BlockHeight::new(sim.coordinators[3].committed_height().inner() + 100);
    let claimed_round = Round::new(base.round().inner() + 100);
    let mut signers = SignerBitfield::new(sim.n());
    for idx in 0..sim.n() {
        signers.set(idx);
    }
    let claimed = BlockHash::from_raw(Hash::from_bytes(b"a block nobody certified"));
    let forged = QuorumCertificate::new(
        claimed,
        base.shard_id(),
        claimed_height,
        BlockHash::ZERO,
        claimed_round,
        signers,
        AggregateSignature::ZERO,
        WeightedTimestamp::ZERO,
    );
    let header = BlockHeader::new(BlockHeaderParts {
        height: claimed_height.next(),
        round: claimed_round.next(),
        parent_block_hash: claimed,
        parent_qc: forged.into(),
        proposer: ValidatorId::new(1),
        timestamp: ProposerTimestamp::from_millis(sim.now.as_millis()),
        ..base.into_parts()
    });
    sim.deliver_header_now(receiver, &header, BlockManifest::default());

    let tx = verified_test_transaction(0x5C);
    let tx_hash = tx.hash();
    sim.admit_transaction(&tx);
    let before = sim.commits[3].len();
    sim.run_until_committed(before + 4, MAX_STEPS);

    assert!(
        !sim.sync_claim_results[3].is_empty() && sim.sync_claim_results[3].iter().all(|ok| !ok),
        "the forged certificate must be checked and refuted: {:?}",
        sim.sync_claim_results[3],
    );
    assert!(
        sim.sync_targets[3].is_empty(),
        "a forged certificate set a sync target: {:?}",
        sim.sync_targets[3],
    );
    assert!(
        !sim.coordinators[3].is_block_syncing(),
        "a forged certificate put the receiver in sync mode",
    );
    assert!(
        sim.commits[3][before..].iter().any(|commit| commit
            .certified
            .block()
            .transactions()
            .iter()
            .any(|t| t.hash() == tx_hash)),
        "the chain stopped carrying transactions after the forged header",
    );
}

/// Tripwire on the sim's capture machinery: a fresh coordinator
/// has no `StartBlockSync` targets recorded.
#[test]
fn fresh_sim_has_no_sync_targets_captured() {
    let sim = ShardCoordinatorSim::new(4, 0xCA_FE);
    for (idx, targets) in sim.sync_targets.iter().enumerate() {
        assert!(
            targets.is_empty(),
            "replica {idx} reported a sync target before any deafening: {targets:?}",
        );
    }
    let _ = BlockHeight::new(0);
}
