//! Public-API contract tests for `MempoolCoordinator`.
//!
//! These tests see only the crate's public surface
//! (`use hyperscale_mempool::...`), so any regression in the documented
//! API is caught here rather than by inline tests that can reach into
//! private fields.

use hyperscale_core::TransactionStatus;
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator, MempoolMemoryStats};
use hyperscale_test_helpers::{certify, make_finalized_wave, make_live_block, TestCommittee};
use hyperscale_types::{
    test_utils::test_transaction, BlockHeight, Hash, LocalTimestamp, ShardGroupId,
    TopologySnapshot, TransactionDecision, TxHash, ValidatorId,
};
use std::sync::Arc;
use std::time::Duration;

fn test_topology() -> TopologySnapshot {
    TestCommittee::new(4, 42).topology_snapshot(0, 1)
}

fn coordinator_with_zero_dwell() -> MempoolCoordinator {
    MempoolCoordinator::with_config(MempoolConfig {
        min_dwell_time: Duration::ZERO,
        ..MempoolConfig::default()
    })
}

/// Destructures every field of `MempoolMemoryStats`, so adding a field
/// without updating this test (and the tests that check its initial value)
/// triggers a compile error. Keeps the memory-stats surface from silently
/// drifting.
#[test]
fn memory_stats_destructures_all_fields_for_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    let MempoolMemoryStats {
        pool,
        ready,
        tombstones,
        recently_evicted,
        locked_nodes,
        deferred_by_nodes,
        txs_deferred_by_node,
        ready_txs_by_node,
    } = coord.memory_stats();

    assert_eq!(pool, 0);
    assert_eq!(ready, 0);
    assert_eq!(tombstones, 0);
    assert_eq!(recently_evicted, 0);
    assert_eq!(locked_nodes, 0);
    assert_eq!(deferred_by_nodes, 0);
    assert_eq!(txs_deferred_by_node, 0);
    assert_eq!(ready_txs_by_node, 0);
}

#[test]
fn fresh_coordinator_reports_empty_pool_and_ready_set() {
    let coord = MempoolCoordinator::new();
    assert_eq!(coord.len(), 0);
    assert!(coord.is_empty());
    assert_eq!(coord.in_flight(), 0);
    assert_eq!(coord.pending_count(), 0);
    assert_eq!(coord.tombstone_count(), 0);
}

#[test]
fn at_in_flight_limit_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    assert!(!coord.at_in_flight_limit());
}

#[test]
fn at_pending_limit_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    assert!(!coord.at_pending_limit());
}

#[test]
fn has_transaction_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    assert!(!coord.has_transaction(&TxHash::from_raw(Hash::from_bytes(b"unknown"))));
    assert!(coord
        .status(&TxHash::from_raw(Hash::from_bytes(b"unknown")))
        .is_none());
    assert!(coord
        .get_transaction(&TxHash::from_raw(Hash::from_bytes(b"unknown")))
        .is_none());
}

#[test]
fn ready_transactions_is_empty_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    assert!(coord
        .ready_transactions(100, 0, 0, LocalTimestamp::ZERO)
        .is_empty());
}

#[test]
fn lock_contention_stats_zero_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    let stats = coord.lock_contention_stats();
    assert_eq!(stats.locked_nodes, 0);
    assert_eq!(stats.pending_count, 0);
    assert_eq!(stats.pending_deferred, 0);
    assert_eq!(stats.committed_count, 0);
    assert_eq!(stats.executed_count, 0);
    assert_eq!(stats.contention_ratio(), 0.0);
}

#[test]
fn is_tombstoned_is_false_on_fresh_coordinator() {
    let coord = MempoolCoordinator::new();
    assert!(!coord.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"unknown"))));
}

#[test]
fn submit_then_ready_round_trips_a_transaction() {
    let topology = test_topology();
    let mut coord = coordinator_with_zero_dwell();

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(&topology, Arc::new(tx), LocalTimestamp::ZERO);

    assert!(coord.has_transaction(&tx_hash));
    assert_eq!(coord.status(&tx_hash), Some(TransactionStatus::Pending));

    let ready = coord.ready_transactions(10, 0, 0, LocalTimestamp::ZERO);
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].hash(), tx_hash);
}

#[test]
fn on_block_committed_transitions_pending_to_committed_and_bumps_in_flight() {
    let topology = test_topology();
    let mut coord = MempoolCoordinator::new();

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);
    assert_eq!(coord.in_flight(), 0);

    let block = make_live_block(
        ShardGroupId(0),
        BlockHeight(1),
        1_000,
        ValidatorId(0),
        vec![Arc::new(tx)],
        vec![],
    );
    coord.on_block_committed(&topology, &certify(block, 1_000), LocalTimestamp::ZERO);

    assert_eq!(coord.in_flight(), 1);
    assert_eq!(
        coord.status(&tx_hash),
        Some(TransactionStatus::Committed(BlockHeight(1)))
    );
}

#[test]
fn on_block_committed_with_finalized_wave_tombstones_and_evicts() {
    let topology = test_topology();
    let mut coord = MempoolCoordinator::new();

    let tx = test_transaction(1);
    let tx_hash = tx.hash();
    coord.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);

    // Single block that both includes the tx and carries the wave cert
    // completing it — drives Pending → Committed → Completed in one call.
    let fw = make_finalized_wave(BlockHeight(1), tx_hash, TransactionDecision::Accept);
    let block = make_live_block(
        ShardGroupId(0),
        BlockHeight(1),
        1_000,
        ValidatorId(0),
        vec![Arc::new(tx.clone())],
        vec![Arc::new(fw)],
    );
    coord.on_block_committed(&topology, &certify(block, 1_000), LocalTimestamp::ZERO);

    // Terminal state: evicted from pool, tombstoned so gossip can't revive it.
    assert!(coord.status(&tx_hash).is_none());
    assert!(coord.is_tombstoned(&tx_hash));

    let actions = coord.on_transaction_gossip(&topology, Arc::new(tx), false, LocalTimestamp::ZERO);
    assert!(actions.is_empty(), "tombstoned tx must not be re-accepted");
    assert!(!coord.has_transaction(&tx_hash));
}
