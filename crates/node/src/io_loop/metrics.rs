//! Metrics aggregation for the I/O loop.
//!
//! Splits the per-tick metrics work into two phases:
//!
//! 1. [`IoLoop::metrics_snapshot`] runs on the pinned thread and reads
//!    `.len()` / `.stats()` from every subsystem. No locks (beyond cheap
//!    cache `len()`s), no I/O, no prometheus calls.
//! 2. [`record_metrics`] takes the snapshot and dispatches the actual
//!    prometheus `set_*` calls plus the `RocksDB` property queries that
//!    feed memory metrics. Designed to run off-thread via `spawn_blocking`
//!    so the I/O loop never blocks on compaction-pressured `RocksDB` reads.

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics::{
    MemoryMetrics, set_backpressure_active, set_bft_round, set_fetch_in_flight, set_in_flight,
    set_lock_contention, set_memory_metrics, set_mempool_size, set_sync_blocks_behind,
    set_sync_in_progress, set_sync_round_in_flight, set_view_changes, set_view_syncs,
};
use hyperscale_network::Network;
use hyperscale_storage::{ChainWriter, Storage};

use crate::io_loop::IoLoop;

/// Lightweight snapshot of `io_loop` state for metrics recording.
///
/// All fields are plain integers collected via `.len()` calls on the pinned
/// thread. The expensive work (`RocksDB` property queries, prometheus recording)
/// happens off-thread via [`record_metrics`].
// Field names match the metric/gauge they feed; per-field doc comments would
// just restate the name.
#[allow(missing_docs)]
pub struct MetricsSnapshot {
    pub bft_round: u64,
    pub view_changes: u64,
    pub view_syncs: u64,
    pub mempool_size: usize,
    pub contention_ratio: f64,
    pub in_flight: usize,
    pub backpressure_active: bool,
    pub blocks_behind: u64,
    pub is_syncing: bool,
    /// In-flight range fetches for block-sync.
    pub block_sync_round_in_flight: usize,
    /// Sum of `blocks_behind` across every remote-header sync scope.
    pub remote_header_blocks_behind: u64,
    /// Any remote-header sync scope is below target.
    pub remote_header_is_syncing: bool,
    /// In-flight range fetches across all remote-header sync scopes.
    pub remote_header_round_in_flight: usize,
    pub fetch_transaction: usize,
    pub fetch_provision: usize,
    pub fetch_local_provision: usize,
    pub fetch_exec_cert: usize,
    pub fetch_finalized_wave: usize,
    pub memory: MemoryMetrics,
}

/// Record a [`MetricsSnapshot`] to the metrics backend.
///
/// This performs the prometheus `set_*` calls (76 label lookups) plus
/// the `RocksDB` property queries for storage memory usage. Designed to
/// run off the pinned thread via `spawn_blocking`.
pub fn record_metrics<S: ChainWriter>(snapshot: MetricsSnapshot, storage: &S) {
    set_bft_round(snapshot.bft_round);
    set_view_changes(snapshot.view_changes);
    set_view_syncs(snapshot.view_syncs);
    set_mempool_size(snapshot.mempool_size);
    set_lock_contention(snapshot.contention_ratio);
    set_in_flight(snapshot.in_flight);
    set_backpressure_active(snapshot.backpressure_active);
    set_sync_blocks_behind("block", snapshot.blocks_behind);
    set_sync_in_progress("block", snapshot.is_syncing);
    set_sync_round_in_flight("block", snapshot.block_sync_round_in_flight);
    set_sync_blocks_behind("remote_header", snapshot.remote_header_blocks_behind);
    set_sync_in_progress("remote_header", snapshot.remote_header_is_syncing);
    set_sync_round_in_flight("remote_header", snapshot.remote_header_round_in_flight);
    set_fetch_in_flight("transaction", snapshot.fetch_transaction);
    set_fetch_in_flight("provision", snapshot.fetch_provision);
    set_fetch_in_flight("local_provision", snapshot.fetch_local_provision);
    set_fetch_in_flight("exec_cert", snapshot.fetch_exec_cert);
    set_fetch_in_flight("finalized_wave", snapshot.fetch_finalized_wave);

    // RocksDB property queries — potentially slow under compaction pressure.
    let (rocksdb_bc, rocksdb_mt) = storage.memory_usage_bytes();
    let mut memory = snapshot.memory;
    memory.rocksdb_block_cache_usage_bytes = rocksdb_bc;
    memory.rocksdb_memtable_usage_bytes = rocksdb_mt;
    set_memory_metrics(&memory);
}

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Capture a lightweight metrics snapshot from state-machine internals.
    ///
    /// Only reads `.len()` / `.stats()` from subsystems — no locks, no I/O,
    /// no prometheus calls. The caller dispatches [`record_metrics`] off-thread
    /// to do the expensive work (`RocksDB` queries, prometheus recording).
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex`-protected caches are poisoned.
    #[must_use]
    #[allow(clippy::too_many_lines)] // single aggregation snapshot; cheap reads stitched together
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let state = &self.vnodes[0].state;
        let bft_stats = state.bft().stats();
        let mempool = state.mempool();
        let contention = mempool.lock_contention_stats();
        let fetches = self.shard_fetches().metrics();
        let syncs = self.syncs.metrics();
        let block_sync_status = &syncs.block_sync_status;

        let bft_mem = state.bft().memory_stats();
        let exec_mem = state.execution().memory_stats();
        let mempool_mem = state.mempool().memory_stats();
        let prov_mem = state.provisions().memory_stats();
        let rh_mem = state.remote_headers().memory_stats();

        MetricsSnapshot {
            bft_round: bft_stats.current_round,
            view_changes: bft_stats.view_changes,
            view_syncs: bft_stats.view_syncs,
            mempool_size: mempool.len(),
            contention_ratio: contention.contention_ratio(),
            in_flight: mempool.in_flight(),
            backpressure_active: mempool.at_in_flight_limit(),
            blocks_behind: self.syncs.block.blocks_behind(),
            is_syncing: self.syncs.block.is_syncing(),
            block_sync_round_in_flight: self.syncs.block.in_flight_ranges(),
            remote_header_blocks_behind: self.syncs.remote_header.total_blocks_behind(),
            remote_header_is_syncing: self.syncs.remote_header.is_syncing(),
            remote_header_round_in_flight: self.syncs.remote_header.in_flight_ranges(),
            fetch_transaction: fetches.transaction_in_flight,
            fetch_provision: fetches.provision_in_flight,
            fetch_local_provision: fetches.local_provision_in_flight,
            fetch_exec_cert: fetches.exec_cert_in_flight,
            fetch_finalized_wave: fetches.finalized_wave_in_flight,
            memory: MemoryMetrics {
                // BFT
                bft_pending_blocks: bft_mem.pending_blocks,
                bft_vote_sets: bft_mem.vote_sets,
                bft_pending_commits: bft_mem.pending_commits,
                bft_pending_commits_awaiting_data: bft_mem.pending_commits_awaiting_data,
                bft_voted_heights: bft_mem.voted_heights,
                bft_received_votes_by_height: bft_mem.received_votes_by_height,
                bft_committed_tx_lookup: bft_mem.committed_tx_lookup,
                bft_committed_cert_lookup: bft_mem.committed_cert_lookup,
                bft_committed_provision_lookup: bft_mem.committed_provision_lookup,
                bft_pending_qc_verifications: bft_mem.pending_qc_verifications,
                bft_verified_qcs: bft_mem.verified_qcs,
                bft_pending_state_root_verifications: bft_mem.pending_state_root_verifications,
                bft_buffered_synced_blocks: bft_mem.buffered_synced_blocks,
                bft_pending_synced_block_verifications: bft_mem.pending_synced_block_verifications,
                // Execution
                exec_cache_entries: exec_mem.wave_execution_receipts,
                exec_finalized_wave_certificates: exec_mem.finalized_wave_certificates,
                exec_waves: exec_mem.waves,
                exec_vote_trackers: exec_mem.vote_trackers,
                exec_early_votes: exec_mem.early_votes,
                exec_expected_exec_certs: exec_mem.expected_exec_certs,
                exec_verified_provisions: exec_mem.verified_provisions,
                exec_required_provision_shards: exec_mem.required_provision_shards,
                exec_received_provision_shards: exec_mem.received_provision_shards,
                exec_waves_with_ec: exec_mem.waves_with_ec,
                exec_pending_vote_retries: exec_mem.pending_vote_retries,
                exec_wave_assignments: exec_mem.wave_assignments,
                exec_early_wave_attestations: exec_mem.early_wave_attestations,
                exec_pending_routing: exec_mem.pending_routing,
                exec_fulfilled_exec_certs: exec_mem.fulfilled_exec_certs,
                exec_outbound_certs: exec_mem.outbound_certs,
                // Mempool
                mempool_pool: mempool_mem.pool,
                mempool_ready: mempool_mem.ready,
                mempool_tombstones: mempool_mem.tombstones,
                mempool_locked_nodes: mempool_mem.locked_nodes,
                mempool_deferred_by_nodes: mempool_mem.deferred_by_nodes,
                mempool_txs_deferred_by_node: mempool_mem.txs_deferred_by_node,
                mempool_ready_txs_by_node: mempool_mem.ready_txs_by_node,
                // Remote Headers
                rh_pending_headers: rh_mem.pending_headers,
                rh_verified_headers: rh_mem.verified_headers,
                rh_expected_headers: rh_mem.expected_headers,
                // Provision
                prov_verified_remote_headers: prov_mem.verified_remote_headers,
                prov_pending_provisions: prov_mem.pending_provisions,
                prov_verified_provisions: prov_mem.verified_provisions,
                prov_expected_provisions: prov_mem.expected_provisions,
                prov_provisions_by_hash: prov_mem.provisions_by_hash,
                prov_queued_provisions: prov_mem.queued_provisions,
                // Node (io_loop)
                node_tx_store: self.shard_caches().tx_store.len(),
                node_tx_status_cache: self.shard_caches().tx_status.len(),
                node_finalized_wave_cache: self.shard_caches().finalized_wave.len(),
                node_provision_cache: self.shard_caches().provision_store.len(),
                node_exec_cert_cache: self.shard_caches().exec_cert_store.len(),
                node_prepared_commits: self.shard_block_commit().prepared_len(),
                node_pending_validation: self.pending_validation.len(),
                node_locally_submitted: self.locally_submitted.len(),
                node_pending_block_commits: self.shard_block_commit().pending_len(),
                node_validation_batch: self.validation_batch.len(),
                node_committed_header_batch: self.committed_header_batch.len(),
                node_block_sync_queued_heights: block_sync_status.queued_heights,
                node_block_sync_in_flight_fetches: block_sync_status.pending_fetches,
                node_tx_fetch_blocks: fetches.transaction_pending,
                node_local_provision_fetch_pending: fetches.local_provision_pending,
                node_finalized_wave_fetch_pending: fetches.finalized_wave_pending,
                node_provision_fetch_pending: fetches.provision_pending,
                node_exec_cert_fetch_pending: fetches.exec_cert_pending,
                node_remote_header_fetch_pending: self.syncs.remote_header.in_flight_ranges(),
                // Storage — filled in by record_metrics off-thread.
                rocksdb_block_cache_usage_bytes: 0,
                rocksdb_memtable_usage_bytes: 0,
            },
        }
    }
}
