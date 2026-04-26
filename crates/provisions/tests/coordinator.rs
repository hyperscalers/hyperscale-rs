//! Public-API contract tests for `ProvisionCoordinator`.
//!
//! These tests see only the crate's public surface
//! (`use hyperscale_provisions::...`), so any regression in the documented
//! API is caught here rather than by inline tests that can reach into
//! private fields.

use hyperscale_provisions::{ProvisionConfig, ProvisionCoordinator, ProvisionMemoryStats};
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, CertificateRoot, CertifiedBlock,
    CommittedBlockHeader, Hash, LocalReceiptRoot, LocalTimestamp, ProposerTimestamp, ProvisionHash,
    ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, StateRoot, TopologySnapshot,
    TransactionRoot, ValidatorId, WaveId, WeightedTimestamp,
};
use std::sync::Arc;

const TEST_BLOCK_INTERVAL_MS: u64 = 500;

fn fresh_coordinator() -> ProvisionCoordinator {
    ProvisionCoordinator::new()
}

fn fresh_coordinator_with_topology() -> (ProvisionCoordinator, TopologySnapshot) {
    let topology = TestCommittee::new(4, 42).topology_snapshot(0, 2);
    (fresh_coordinator(), topology)
}

fn make_block(height: BlockHeight) -> CertifiedBlock {
    let mut header = BlockHeader::genesis(ShardGroupId(0), ValidatorId(0), StateRoot::ZERO);
    header.height = height;
    let block = Block::Live {
        header,
        transactions: vec![],
        certificates: vec![],
        provisions: vec![],
    };
    let qc = QuorumCertificate {
        block_hash: block.hash(),
        weighted_timestamp: WeightedTimestamp(height.0 * TEST_BLOCK_INTERVAL_MS),
        ..QuorumCertificate::genesis()
    };
    CertifiedBlock::new_unchecked(block, qc)
}

/// Build a remote committed header whose only wave targets `local_shard`,
/// so a `ProvisionCoordinator` running on `local_shard` will register an
/// expectation on receipt.
fn make_remote_header_targeting(
    source_shard: ShardGroupId,
    height: BlockHeight,
    local_shard: ShardGroupId,
) -> Arc<CommittedBlockHeader> {
    let waves = vec![WaveId {
        shard_group_id: source_shard,
        block_height: height,
        remote_shards: std::collections::BTreeSet::from([local_shard]),
    }];
    let header = BlockHeader {
        shard_group_id: source_shard,
        height,
        parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
        parent_qc: QuorumCertificate::genesis(),
        proposer: ValidatorId(0),
        timestamp: ProposerTimestamp(1000 + height.0),
        round: Round::INITIAL,
        is_fallback: false,
        state_root: StateRoot::ZERO,
        transaction_root: TransactionRoot::ZERO,
        certificate_root: CertificateRoot::ZERO,
        local_receipt_root: LocalReceiptRoot::ZERO,
        provision_root: ProvisionsRoot::ZERO,
        waves,
        provision_tx_roots: std::collections::BTreeMap::new(),
        in_flight: 0,
    };
    let header_hash = header.hash();
    let mut qc = QuorumCertificate::genesis();
    qc.block_hash = header_hash;
    qc.shard_group_id = source_shard;
    qc.height = height;
    Arc::new(CommittedBlockHeader::new(header, qc))
}

#[test]
fn fresh_coordinator_reports_no_state() {
    let coord = fresh_coordinator();
    assert_eq!(coord.verified_remote_header_count(), 0);
    assert!(coord
        .get_remote_header(ShardGroupId(1), BlockHeight(1))
        .is_none());
    assert!(coord
        .get_provisions_by_hash(&ProvisionHash::from_raw(Hash::from_bytes(b"any")))
        .is_none());
    assert!(coord.queued_provisions(LocalTimestamp::ZERO).is_empty());
    assert!(coord.store().is_empty());
}

/// Destructures every field of `ProvisionMemoryStats`, so adding a field
/// without updating this test (and the assertions on its initial value)
/// triggers a compile error. Keeps the memory-stats surface from silently
/// drifting.
#[test]
fn memory_stats_destructures_all_fields_for_fresh_coordinator() {
    let coord = fresh_coordinator();
    let ProvisionMemoryStats {
        verified_remote_headers,
        pending_provisions,
        verified_provisions,
        expected_provisions,
        provisions_by_hash,
        queued_provisions,
        committed_tombstones,
    } = coord.memory_stats();

    assert_eq!(verified_remote_headers, 0);
    assert_eq!(pending_provisions, 0);
    assert_eq!(verified_provisions, 0);
    assert_eq!(expected_provisions, 0);
    assert_eq!(provisions_by_hash, 0);
    assert_eq!(queued_provisions, 0);
    assert_eq!(committed_tombstones, 0);
}

#[test]
fn with_config_honours_dwell_time_setting() {
    let config = ProvisionConfig {
        min_dwell_time: std::time::Duration::from_millis(750),
    };
    let coord = ProvisionCoordinator::with_config(config);
    // No queued provisions yet — but the constructor must accept the config
    // without panicking, and the queue must be live.
    assert!(coord.queued_provisions(LocalTimestamp::ZERO).is_empty());
}

#[test]
fn on_block_committed_empty_block_yields_no_actions() {
    let (mut coord, topology) = fresh_coordinator_with_topology();
    let actions = coord.on_block_committed(&topology, &make_block(BlockHeight(1)));
    assert!(actions.is_empty());
}

#[test]
fn flush_expected_provisions_with_no_expectations_yields_no_actions() {
    let (mut coord, topology) = fresh_coordinator_with_topology();
    let actions = coord.flush_expected_provisions(&topology);
    assert!(actions.is_empty());
}

#[test]
fn on_verified_remote_header_for_own_shard_is_no_op() {
    let (mut coord, topology) = fresh_coordinator_with_topology();
    let local = topology.local_shard();
    // Header from our own shard must not register an expectation.
    let own_header = make_remote_header_targeting(local, BlockHeight(5), local);
    let actions = coord.on_verified_remote_header(&topology, own_header);
    assert!(actions.is_empty());
    assert_eq!(coord.memory_stats().expected_provisions, 0);
    assert_eq!(coord.verified_remote_header_count(), 0);
}

#[test]
fn on_verified_remote_header_targeting_local_shard_registers_expectation() {
    let (mut coord, topology) = fresh_coordinator_with_topology();
    let local = topology.local_shard();
    let remote = ShardGroupId(if local.0 == 0 { 1 } else { 0 });
    let header = make_remote_header_targeting(remote, BlockHeight(5), local);
    coord.on_verified_remote_header(&topology, Arc::clone(&header));

    let stats = coord.memory_stats();
    assert_eq!(
        stats.expected_provisions, 1,
        "expectation must register when the remote wave targets us"
    );
    assert_eq!(
        stats.verified_remote_headers, 1,
        "header must be retained while the expectation is outstanding"
    );
    let stored = coord
        .get_remote_header(remote, BlockHeight(5))
        .expect("present");
    assert!(Arc::ptr_eq(stored, &header));
}

#[test]
fn first_commit_retro_stamps_pre_genesis_expectations() {
    // Regression: an expectation registered before the first local commit
    // must have its discovered_at retro-stamped on commit, otherwise the
    // immediate timeout sweep would fire (entry's discovered_at is ZERO,
    // committed_ts is suddenly ~now, age reports ~57 years).
    let (mut coord, topology) = fresh_coordinator_with_topology();
    let local = topology.local_shard();
    let remote = ShardGroupId(if local.0 == 0 { 1 } else { 0 });
    let header = make_remote_header_targeting(remote, BlockHeight(5), local);
    coord.on_verified_remote_header(&topology, header);

    // First commit must NOT trigger a fallback fetch storm.
    let actions = coord.on_block_committed(&topology, &make_block(BlockHeight(1)));
    assert!(
        actions.is_empty(),
        "first commit must retro-stamp before timeout sweep so no fallback fires"
    );
    assert_eq!(coord.memory_stats().expected_provisions, 1);
}

#[test]
fn debug_impl_runs_without_panicking() {
    let coord = fresh_coordinator();
    let s = format!("{coord:?}");
    assert!(s.contains("ProvisionCoordinator"));
}
