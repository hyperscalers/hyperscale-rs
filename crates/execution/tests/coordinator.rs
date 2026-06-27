//! Public-API contract tests for `ExecutionCoordinator`.
//!
//! These tests see only the crate's public surface
//! (`use hyperscale_execution::...`), so any regression in the documented
//! API is caught here rather than by inline tests that can reach into
//! private fields.

use std::sync::Arc;

use hyperscale_execution::{ExecutionCoordinator, ExecutionMemoryStats};
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{BlockHeight, Hash, ShardId, TopologySchedule, TxHash, ValidatorId, WaveId};

fn fresh_coordinator() -> ExecutionCoordinator {
    ExecutionCoordinator::new(ValidatorId::new(0), ShardId::ROOT)
}

fn fresh_coordinator_with_topology() -> (ExecutionCoordinator, TopologySchedule) {
    let topology_schedule =
        TopologySchedule::single(Arc::new(TestCommittee::new(4, 42).topology_snapshot(1)));
    (fresh_coordinator(), topology_schedule)
}

#[test]
fn fresh_coordinator_reports_no_finalized_state() {
    let coord = fresh_coordinator();
    assert!(!coord.is_finalized(TxHash::from_raw(Hash::from_bytes(b"anything"))));
    assert!(coord.finalized_tx_hashes().is_empty());
    assert!(coord.get_finalized_waves().is_empty());
}

/// Destructures every field of `ExecutionMemoryStats`, so adding a field
/// without updating this test (and the tests that check its initial value)
/// triggers a compile error. Keeps the memory-stats surface from silently
/// drifting.
#[test]
fn memory_stats_destructures_all_fields_for_fresh_coordinator() {
    let coord = fresh_coordinator();
    let ExecutionMemoryStats {
        wave_execution_receipts,
        finalized_wave_certificates,
        waves,
        vote_trackers,
        early_votes,
        expected_exec_certs,
        verified_provisions,
        required_provision_shards,
        received_provision_shards,
        waves_with_ec,
        pending_vote_retries,
        wave_assignments,
        early_wave_attestations,
        pending_routing,
        fulfilled_exec_certs,
        outbound_certs,
    } = coord.memory_stats();

    assert_eq!(wave_execution_receipts, 0);
    assert_eq!(finalized_wave_certificates, 0);
    assert_eq!(waves, 0);
    assert_eq!(vote_trackers, 0);
    assert_eq!(early_votes, 0);
    assert_eq!(expected_exec_certs, 0);
    assert_eq!(verified_provisions, 0);
    assert_eq!(required_provision_shards, 0);
    assert_eq!(received_provision_shards, 0);
    assert_eq!(waves_with_ec, 0);
    assert_eq!(pending_vote_retries, 0);
    assert_eq!(wave_assignments, 0);
    assert_eq!(early_wave_attestations, 0);
    assert_eq!(pending_routing, 0);
    assert_eq!(fulfilled_exec_certs, 0);
    assert_eq!(outbound_certs, 0);
}

#[test]
fn fresh_get_wave_assignment_returns_none_for_any_tx() {
    let coord = fresh_coordinator();
    assert!(
        coord
            .get_wave_assignment(TxHash::from_raw(Hash::from_bytes(b"tx1")))
            .is_none()
    );
    assert!(coord.get_wave_assignment(TxHash::ZERO).is_none());
}

#[test]
fn fresh_get_finalized_certificate_returns_none_for_any_tx() {
    let coord = fresh_coordinator();
    assert!(
        coord
            .get_finalized_certificate(TxHash::from_raw(Hash::from_bytes(b"tx1")))
            .is_none()
    );
}

#[test]
fn fresh_get_finalized_wave_returns_none_for_any_id() {
    let coord = fresh_coordinator();
    let wid = WaveId::new(
        ShardId::ROOT,
        BlockHeight::new(1),
        std::collections::BTreeSet::new(),
    );
    assert!(coord.get_finalized_wave(&wid).is_none());
}

#[test]
fn fresh_cross_shard_pending_count_is_zero() {
    let coord = fresh_coordinator();
    assert_eq!(coord.cross_shard_pending_count(), 0);
}

#[test]
fn fresh_is_awaiting_provisioning_is_false_for_any_tx() {
    let coord = fresh_coordinator();
    assert!(!coord.is_awaiting_provisioning(TxHash::from_raw(Hash::from_bytes(b"tx1"))));
}

#[test]
fn fresh_emit_vote_actions_is_empty() {
    let (mut coord, topology_schedule) = fresh_coordinator_with_topology();
    let actions = coord.emit_vote_actions(&topology_schedule);
    assert!(actions.is_empty());
}

#[test]
fn fresh_scan_complete_waves_is_empty() {
    let mut coord = fresh_coordinator();
    assert!(coord.scan_complete_waves().is_empty());
}

#[test]
fn certificate_tracking_debug_reports_no_assignment_for_unknown_tx() {
    let coord = fresh_coordinator();
    let debug = coord.certificate_tracking_debug(TxHash::from_raw(Hash::from_bytes(b"tx1")));
    assert!(
        debug.contains("no wave assignment"),
        "unexpected debug output: {debug}"
    );
    assert!(
        debug.contains("early_wave_attestations=0"),
        "unexpected debug output: {debug}"
    );
}

#[test]
fn on_verified_remote_header_registers_expectation_for_wave_targeting_local_shard() {
    let (mut coord, topology_schedule) = fresh_coordinator_with_topology();
    let local_shard = ShardId::ROOT;
    let _ = &topology_schedule;
    // A remote shard's wave that targets our local shard must register an
    // expectation. With committed_ts still ZERO the initial-deadline
    // gate is silenced, but the expectation count must reflect the header.
    let remote_shard = ShardId::leaf(8, 99);
    let wave = WaveId::new(
        remote_shard,
        BlockHeight::new(5),
        std::iter::once(local_shard).collect(),
    );
    coord.on_verified_remote_header(remote_shard, BlockHeight::new(5), &[wave]);

    assert_eq!(
        coord.memory_stats().expected_exec_certs,
        1,
        "expectation must register for a wave targeting the local shard"
    );
}

#[test]
fn on_verified_remote_header_ignores_waves_not_targeting_local_shard() {
    let (mut coord, _topology) = fresh_coordinator_with_topology();
    // Wave targets ShardId::leaf(3, 7) only; local is ShardId::ROOT. No
    // expectation should land.
    let wave = WaveId::new(
        ShardId::leaf(8, 99),
        BlockHeight::new(5),
        std::iter::once(ShardId::leaf(3, 7)).collect(),
    );
    coord.on_verified_remote_header(ShardId::leaf(8, 99), BlockHeight::new(5), &[wave]);

    assert_eq!(
        coord.memory_stats().expected_exec_certs,
        0,
        "no expectation should register for a wave that doesn't target us"
    );
}
