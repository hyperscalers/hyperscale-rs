//! Public-API contract tests for `MempoolCoordinator`.
//!
//! These tests see only the crate's public surface
//! (`use hyperscale_mempool::...`), so any regression in the documented
//! API is caught here rather than by inline tests that can reach into
//! private fields.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, MempoolMemoryStats};
use hyperscale_types::test_utils::{
    TestCommittee, certify, make_finalization, make_live_block, test_transaction,
};
use hyperscale_types::{
    BlockHeight, Hash, LocalTimestamp, ShardId, ShardTrie, TopologySnapshot, Transaction,
    TransactionDecision, TransactionStatus, TxHash, TxResolution, ValidatorId, Verified,
};

/// Test-only convenience: wrap any `Transaction` in a `Verified`
/// witness via the test-only gate.
const fn verified(tx: Transaction) -> Verified<Transaction> {
    Verified::new_unchecked_for_test(tx)
}

fn test_topology() -> TopologySnapshot {
    TestCommittee::new(4, 42).topology_snapshot(1)
}

fn coordinator_with_zero_dwell() -> MempoolCoordinator {
    MempoolCoordinator::with_config(
        ShardId::ROOT,
        MempoolConfig {
            min_dwell_time: Duration::ZERO,
            ..MempoolConfig::default()
        },
    )
}

/// Destructures every field of `MempoolMemoryStats`, so adding a field
/// without updating this test (and the tests that check its initial value)
/// triggers a compile error. Keeps the memory-stats surface from silently
/// drifting.
#[test]
fn memory_stats_destructures_all_fields_for_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    let MempoolMemoryStats {
        pool,
        pending,
        tombstones,
    } = coord.memory_stats();

    assert_eq!(pool, 0);
    assert_eq!(pending, 0);
    assert_eq!(tombstones, 0);
}

#[test]
fn fresh_coordinator_reports_empty_pool_and_ready_set() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert_eq!(coord.len(), 0);
    assert!(coord.is_empty());
    assert_eq!(coord.pending_count(), 0);
    assert_eq!(coord.tombstone_count(), 0);
}

#[test]
fn at_pending_limit_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.at_pending_limit());
}

#[test]
fn has_transaction_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.has_transaction(&TxHash::from(Hash::from_bytes(b"unknown"))));
    assert!(
        coord
            .status(&TxHash::from(Hash::from_bytes(b"unknown")))
            .is_none()
    );
    assert!(
        coord
            .get_transaction(&TxHash::from(Hash::from_bytes(b"unknown")))
            .is_none()
    );
}

#[test]
fn ready_transactions_is_empty_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(
        coord
            .ready_transactions(100, 0, &ShardTrie::single(), LocalTimestamp::ZERO, |_| true)
            .is_empty()
    );
}

#[test]
fn is_tombstoned_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.is_tombstoned(&TxHash::from(Hash::from_bytes(b"unknown"))));
}

#[test]
fn submit_then_ready_round_trips_a_transaction() {
    let topology_snapshot = test_topology();
    let mut coord = coordinator_with_zero_dwell();

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(
        &topology_snapshot,
        Arc::new(verified(tx)),
        LocalTimestamp::ZERO,
    );

    assert!(coord.has_transaction(&tx_hash));
    assert_eq!(coord.status(&tx_hash), Some(TransactionStatus::Pending));

    let ready =
        coord.ready_transactions(10, 0, &ShardTrie::single(), LocalTimestamp::ZERO, |_| true);
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].hash(), tx_hash);
}

#[test]
fn on_block_committed_transitions_pending_to_committed() {
    let topology_snapshot = test_topology();
    let mut coord = MempoolCoordinator::new(ShardId::ROOT);

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(
        &topology_snapshot,
        Arc::new(verified(tx.clone())),
        LocalTimestamp::ZERO,
    );

    let block = make_live_block(
        ShardId::ROOT,
        BlockHeight::new(1),
        1_000,
        ValidatorId::new(0),
        vec![Arc::new(tx)],
        vec![],
    );
    coord.on_block_committed(&topology_snapshot, &certify(block, 1_000));

    assert_eq!(
        coord.status(&tx_hash),
        Some(TransactionStatus::Committed(BlockHeight::new(1)))
    );
}

#[test]
fn on_block_committed_with_finalization_tombstones_and_evicts() {
    let topology_snapshot = test_topology();
    let mut coord = MempoolCoordinator::new(ShardId::ROOT);

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(
        &topology_snapshot,
        Arc::new(verified(tx.clone())),
        LocalTimestamp::ZERO,
    );

    // The block includes the tx, and what its finalization settles
    // arrives from the execution ledger's reading of it.
    let fw = make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept);
    let block = make_live_block(
        ShardId::ROOT,
        BlockHeight::new(1),
        1_000,
        ValidatorId::new(0),
        vec![Arc::new(tx.clone())],
        vec![Arc::new(fw.into())],
    );
    coord.on_block_committed(&topology_snapshot, &certify(block, 1_000));
    coord.on_resolutions(&[(tx_hash, TxResolution::Decided(TransactionDecision::Accept))]);

    // Terminal state: evicted from pool, tombstoned so gossip can't revive it.
    assert!(coord.status(&tx_hash).is_none());
    assert!(coord.is_tombstoned(&tx_hash));

    let actions = coord.on_transaction_gossip(
        &topology_snapshot,
        Arc::new(verified(tx)),
        false,
        LocalTimestamp::ZERO,
    );
    assert!(actions.is_empty(), "tombstoned tx must not be re-accepted");
    assert!(!coord.has_transaction(&tx_hash));
}
