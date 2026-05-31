//! Transaction admission + data availability + ready-signal dwell
//! invariants pinned by the shard sim.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::ShardCoordinatorSim;
use hyperscale_types::test_utils::verified_test_transaction;
use hyperscale_types::{BlockHeight, MAX_READY_WINDOW_BLOCKS, Round, ValidatorId};

const TARGET_COMMITS: usize = 1;
const MAX_STEPS: usize = 5_000;

/// An admitted tx survives admission → proposal selection → block
/// construction → commit.
#[test]
fn every_committed_block_carries_admitted_txs() {
    let mut sim = ShardCoordinatorSim::new(4, 0xA1_AD);
    let tx = Arc::new(verified_test_transaction(/* seed */ 0x11));
    let tx_hash = tx.hash();
    sim.admit_transaction(&tx);
    sim.kick_off();
    sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let committed_block = sim.commits[0][0].certified.block();
    let included: Vec<_> = committed_block
        .transactions()
        .iter()
        .map(|t| t.hash())
        .collect();
    assert!(
        included.contains(&tx_hash),
        "admitted tx {tx_hash:?} not present in committed block: {included:?}",
    );
}

/// Admitting a tx on the round-0 leader must surface a
/// `BuildProposal` end-to-end via `queue_ready_proposal` + the
/// post-dispatch drain. Pre-kickoff, this latch + retry is the
/// only path the leader has to discover ready txs; a silent-latch
/// regression would only surface as a liveness break.
#[test]
fn transactions_admitted_latches_proposal_on_leader() {
    let mut sim = ShardCoordinatorSim::new(4, 0x1A_7C);
    // proposer_for(shard=0, h=1, r=0) = committee[(1+0) % 4] = idx 1.
    let leader_idx = 1u64;
    assert_eq!(
        sim.topology
            .proposer_for(sim.shard, BlockHeight::new(1), Round::INITIAL),
        ValidatorId::new(leader_idx),
        "test assumes idx {leader_idx} is the round-0 height-1 leader",
    );
    let tx = Arc::new(verified_test_transaction(/* seed */ 0x22));
    sim.admit_transaction(&tx);
    sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let proposer = sim.commits[0][0].certified.block().header().proposer();
    assert_eq!(
        proposer,
        ValidatorId::new(leader_idx),
        "committed block must carry the round-0 leader as proposer",
    );
}

/// Data-availability gating: a replica whose local tx pool can't
/// reconstruct the block's manifest holds back its vote until
/// admission catches up. The honest 2f+1 still form quorum.
#[test]
fn vote_withheld_until_tx_admission_completes_header() {
    let mut sim = ShardCoordinatorSim::new(4, 0xDA_70);
    let tx = Arc::new(verified_test_transaction(/* seed */ 0x33));
    // Admit on every replica except idx 0.
    let honest_idxs: Vec<usize> = (1..sim.n()).collect();
    for &idx in &honest_idxs {
        sim.admit_transaction_on(idx, Arc::clone(&tx));
    }
    sim.kick_off();
    // Idx 0's local DA gate keeps it from voting; only the honest
    // subset hits the commit target.
    sim.run_until_committed_for(&honest_idxs, TARGET_COMMITS, MAX_STEPS);

    // The leader (idx 1) had the tx in its own pool, so its
    // committed block must include it.
    let leader_block = sim.commits[1][0].certified.block();
    assert!(
        leader_block
            .transactions()
            .iter()
            .any(|t| t.hash() == tx.hash()),
        "leader's committed block missing the admitted tx",
    );
}

/// A ready signal admitted at `t = 0` and proposed against at
/// `t < MIN_READY_SIGNAL_DWELL` must NOT contribute a
/// beacon-witness leaf. `ReadySignalPool::dwell_eligible_at` is
/// what excludes it.
#[test]
fn ready_signal_below_min_dwell_excluded_from_proposal() {
    use hyperscale_shard::ready_signal_pool::MIN_READY_SIGNAL_DWELL;

    let mut sim = ShardCoordinatorSim::new(4, 0xD1_E1);
    let signer_idx = 2;
    let window_start = BlockHeight::new(1);
    let window_end = window_start + (MAX_READY_WINDOW_BLOCKS - 1);
    sim.emit_ready_signal(signer_idx, window_start, window_end);
    // Bump the clock just shy of the dwell threshold so subsequent
    // proposals' `now` stays below the eligibility cutoff.
    sim.advance_clock(
        MIN_READY_SIGNAL_DWELL
            .checked_sub(Duration::from_millis(20))
            .expect("MIN_READY_SIGNAL_DWELL > 20ms"),
    );
    sim.kick_off();
    sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    // Zero beacon-witness leaf-count delta on every committed
    // block — the accumulator hasn't grown.
    for replica in 0..sim.n() {
        let leaf_count = sim.commits[replica][0]
            .certified
            .block()
            .header()
            .beacon_witness_leaf_count();
        assert_eq!(
            leaf_count.inner(),
            0,
            "replica {replica}: ready signal contributed a leaf despite dwell unmet \
             ({leaf_count:?})",
        );
    }
}
