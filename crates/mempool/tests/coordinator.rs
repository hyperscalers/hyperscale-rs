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
    TestCommittee, certify, make_finalized_wave, make_live_block, test_transaction,
};
use hyperscale_types::{
    BlockHeight, Hash, LocalTimestamp, RoutableTransaction, ShardId, TopologySnapshot,
    TransactionDecision, TransactionStatus, TxHash, ValidatorId, Verified,
};

/// Test-only convenience: wrap any `RoutableTransaction` in a `Verified`
/// witness via the test-only gate.
const fn verified(tx: RoutableTransaction) -> Verified<RoutableTransaction> {
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
        ready,
        tombstones,
        locked_nodes,
        deferred_by_nodes,
        txs_deferred_by_node,
        ready_txs_by_node,
    } = coord.memory_stats();

    assert_eq!(pool, 0);
    assert_eq!(ready, 0);
    assert_eq!(tombstones, 0);
    assert_eq!(locked_nodes, 0);
    assert_eq!(deferred_by_nodes, 0);
    assert_eq!(txs_deferred_by_node, 0);
    assert_eq!(ready_txs_by_node, 0);
}

#[test]
fn fresh_coordinator_reports_empty_pool_and_ready_set() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert_eq!(coord.len(), 0);
    assert!(coord.is_empty());
    assert_eq!(coord.in_flight(), 0);
    assert_eq!(coord.pending_count(), 0);
    assert_eq!(coord.tombstone_count(), 0);
}

#[test]
fn at_in_flight_limit_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.at_in_flight_limit());
}

#[test]
fn at_pending_limit_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.at_pending_limit());
}

#[test]
fn has_transaction_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.has_transaction(&TxHash::from_raw(Hash::from_bytes(b"unknown"))));
    assert!(
        coord
            .status(&TxHash::from_raw(Hash::from_bytes(b"unknown")))
            .is_none()
    );
    assert!(
        coord
            .get_transaction(&TxHash::from_raw(Hash::from_bytes(b"unknown")))
            .is_none()
    );
}

#[test]
fn ready_transactions_is_empty_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(
        coord
            .ready_transactions(100, 0, 0, LocalTimestamp::ZERO, None)
            .is_empty()
    );
}

#[test]
fn lock_contention_stats_zero_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    let stats = coord.lock_contention_stats();
    assert_eq!(stats.locked_nodes, 0);
    assert_eq!(stats.pending_count, 0);
    assert_eq!(stats.pending_deferred, 0);
    assert_eq!(stats.in_flight_count, 0);
    assert!(stats.contention_ratio().abs() < f64::EPSILON);
}

#[test]
fn is_tombstoned_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new(ShardId::ROOT);
    assert!(!coord.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"unknown"))));
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

    let ready = coord.ready_transactions(10, 0, 0, LocalTimestamp::ZERO, None);
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].hash(), tx_hash);
}

#[test]
fn on_block_committed_transitions_pending_to_committed_and_bumps_in_flight() {
    let topology_snapshot = test_topology();
    let mut coord = MempoolCoordinator::new(ShardId::ROOT);

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(
        &topology_snapshot,
        Arc::new(verified(tx.clone())),
        LocalTimestamp::ZERO,
    );
    assert_eq!(coord.in_flight(), 0);

    let block = make_live_block(
        ShardId::ROOT,
        BlockHeight::new(1),
        1_000,
        ValidatorId::new(0),
        vec![Arc::new(tx)],
        vec![],
    );
    coord.on_block_committed(&topology_snapshot, &certify(block, 1_000));

    assert_eq!(coord.in_flight(), 1);
    assert_eq!(
        coord.status(&tx_hash),
        Some(TransactionStatus::Committed(BlockHeight::new(1)))
    );
}

#[test]
fn on_block_committed_with_finalized_wave_tombstones_and_evicts() {
    let topology_snapshot = test_topology();
    let mut coord = MempoolCoordinator::new(ShardId::ROOT);

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(
        &topology_snapshot,
        Arc::new(verified(tx.clone())),
        LocalTimestamp::ZERO,
    );

    // Single block that both includes the tx and carries the wave cert
    // completing it — drives Pending → Committed → Completed in one call.
    let fw = make_finalized_wave(BlockHeight::new(1), tx_hash, TransactionDecision::Accept);
    let block = make_live_block(
        ShardId::ROOT,
        BlockHeight::new(1),
        1_000,
        ValidatorId::new(0),
        vec![Arc::new(tx.clone())],
        vec![Arc::new(fw.into())],
    );
    coord.on_block_committed(&topology_snapshot, &certify(block, 1_000));

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
