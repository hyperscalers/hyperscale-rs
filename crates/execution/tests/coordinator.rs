//! Public-API contract tests for `ExecutionCoordinator`.
//!
//! These tests see only the crate's public surface
//! (`use hyperscale_execution::...`), so any regression in the documented
//! API is caught here rather than by inline tests that can reach into
//! private fields.

use std::sync::Arc;

use hyperscale_engine::AllCodeRuns;
use hyperscale_execution::{ExecutionCoordinator, ExecutionMemoryStats};
use hyperscale_types::test_utils::TestCommittee;
use hyperscale_types::{FinalizationHash, Hash, ShardId, TopologySchedule, TxHash, ValidatorId};

fn fresh_coordinator() -> ExecutionCoordinator {
    ExecutionCoordinator::new(ValidatorId::new(0), ShardId::ROOT, Arc::new(AllCodeRuns))
}

fn fresh_coordinator_with_topology() -> (ExecutionCoordinator, TopologySchedule) {
    let topology_schedule =
        TopologySchedule::single(Arc::new(TestCommittee::new(4, 42).topology_snapshot(1)));
    (fresh_coordinator(), topology_schedule)
}

#[test]
fn fresh_coordinator_reports_no_finalized_state() {
    let coord = fresh_coordinator();
    assert!(!coord.is_finalized(TxHash::from(Hash::from_bytes(b"anything"))));
    assert!(coord.finalized_tx_hashes().is_empty());
    assert!(coord.get_finalizations().is_empty());
}

/// Destructures every field of `ExecutionMemoryStats`, so adding a field
/// without updating this test (and the tests that check its initial value)
/// triggers a compile error. Keeps the memory-stats surface from silently
/// drifting.
#[test]
fn memory_stats_destructures_all_fields_for_fresh_coordinator() {
    let coord = fresh_coordinator();
    let ExecutionMemoryStats {
        tick_execution_receipts,
        finalizations,
        ticks,
        unresolved_txs,
        vote_trackers,
        early_votes,
        expected_exec_certs,
        absorbed_provisions,
        required_provision_shards,
        ticks_with_ec,
        pending_vote_retries,
        tick_assignments,
        early_attestations,
        pending_routing,
        fulfilled_exec_certs,
        outbound_certs,
        proven_remote_blocks,
        unproven_ecs,
    } = coord.memory_stats();

    assert_eq!(tick_execution_receipts, 0);
    assert_eq!(finalizations, 0);
    assert_eq!(unresolved_txs, 0);
    assert_eq!(ticks, 0);
    assert_eq!(vote_trackers, 0);
    assert_eq!(early_votes, 0);
    assert_eq!(expected_exec_certs, 0);
    assert_eq!(absorbed_provisions, 0);
    assert_eq!(required_provision_shards, 0);
    assert_eq!(ticks_with_ec, 0);
    assert_eq!(pending_vote_retries, 0);
    assert_eq!(tick_assignments, 0);
    assert_eq!(early_attestations, 0);
    assert_eq!(pending_routing, 0);
    assert_eq!(fulfilled_exec_certs, 0);
    assert_eq!(outbound_certs, 0);
    assert_eq!(proven_remote_blocks, 0);
    assert_eq!(unproven_ecs, 0);
}

#[test]
fn fresh_tick_assignment_for_returns_none_for_any_tx() {
    let coord = fresh_coordinator();
    assert!(
        coord
            .tick_assignment_for(TxHash::from(Hash::from_bytes(b"tx1")))
            .is_none()
    );
    assert!(coord.tick_assignment_for(TxHash::ZERO).is_none());
}

#[test]
fn fresh_get_finalization_returns_none_for_any_tx() {
    let coord = fresh_coordinator();
    assert!(
        coord
            .get_finalization_for_tx(TxHash::from(Hash::from_bytes(b"tx1")))
            .is_none()
    );
}

#[test]
fn fresh_get_finalization_returns_none_for_any_id() {
    let coord = fresh_coordinator();
    let id = FinalizationHash::from_raw(Hash::from_bytes(b"absent"));
    assert!(coord.get_finalization(&id).is_none());
}

#[test]
fn fresh_cross_shard_pending_count_is_zero() {
    let coord = fresh_coordinator();
    assert_eq!(coord.cross_shard_pending_count(), 0);
}

#[test]
fn fresh_emit_vote_actions_is_empty() {
    let (mut coord, topology_schedule) = fresh_coordinator_with_topology();
    let actions = coord.emit_vote_actions(&topology_schedule);
    assert!(actions.is_empty());
}

#[test]
fn fresh_scan_votable_ticks_is_empty() {
    let (mut coord, topology_schedule) = fresh_coordinator_with_topology();
    assert!(coord.scan_votable_ticks(&topology_schedule).is_empty());
}

#[test]
fn certificate_tracking_debug_reports_no_assignment_for_unknown_tx() {
    let coord = fresh_coordinator();
    let debug = coord.certificate_tracking_debug(TxHash::from(Hash::from_bytes(b"tx1")));
    assert!(
        debug.contains("no tick assignment"),
        "unexpected debug output: {debug}"
    );
    assert!(
        debug.contains("early_attestations=0"),
        "unexpected debug output: {debug}"
    );
}

/// A coordinator holding no tick expects no counterpart's outcome, so
/// there is nothing for the commit-independent flush to request.
#[test]
fn a_coordinator_holding_no_tick_fetches_nothing() {
    let (mut coord, _topology) = fresh_coordinator_with_topology();

    assert_eq!(coord.memory_stats().expected_exec_certs, 0);
    assert!(coord.flush_expected_certs().is_empty());
}
