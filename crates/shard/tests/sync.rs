//! Block-sync invariants pinned by the shard sim.

mod common;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{BlockHeight, CertifiedBlock, ValidatorId};

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

    // Feed the round-contiguous child. Now the parent finalizes.
    sim.deliver_synced_block(lagging, &reference[1]);
    sim.run_for_at_most(2_000);
    assert_eq!(
        sim.coordinators[3].committed_height(),
        reference[0].block().height(),
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
