//! Metrics aggregation for the I/O loop.
//!
//! Splits the per-tick metrics work into two phases:
//!
//! 1. [`NodeHost::metrics_snapshot`] runs on the pinned thread and reads
//!    `.len()` / `.stats()` from every subsystem. No locks (beyond cheap
//!    cache `len()`s), no I/O, no prometheus calls.
//! 2. [`record_metrics`] takes the snapshot and dispatches the actual
//!    prometheus `set_*` calls plus the `RocksDB` property queries that
//!    feed memory metrics. Designed to run off-thread via `spawn_blocking`
//!    so the I/O loop never blocks on compaction-pressured `RocksDB` reads.
//!
//! # Layered snapshot
//!
//! The snapshot mirrors the three-layer architecture: per-shard
//! infrastructure counts in [`ShardMetrics`] (sync / fetch state) and
//! per-vnode consensus counts in [`VnodeMetrics`] (shard consensus / mempool state).
//! The prometheus backend uses flat (unlabeled) gauges, so
//! [`record_metrics`] picks a representative shard + vnode via
//! [`MetricsSnapshot::primary`] and emits its values.

use std::collections::HashMap;

use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::{
    MemoryMetrics, set_backpressure_active, set_fetch_in_flight, set_fetch_oldest_in_flight_age_ms,
    set_in_flight, set_lock_contention, set_memory_metrics, set_mempool_size, set_shard_round,
    set_sync_blocks_behind, set_sync_in_progress, set_sync_round_in_flight, set_view_changes,
    set_view_syncs,
};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{ShardGroupId, ValidatorId};

use crate::host::NodeHost;

/// Per-shard infrastructure counts.
#[allow(missing_docs)] // fields are flat readouts; names are the documentation
pub struct ShardMetrics {
    /// Block-sync FSM lag.
    pub blocks_behind: u64,
    pub is_syncing: bool,
    pub block_sync_round_in_flight: usize,
    /// Sum across every remote-header sync scope.
    pub remote_header_blocks_behind: u64,
    pub remote_header_is_syncing: bool,
    pub remote_header_round_in_flight: usize,
    /// Per-payload fetch in-flight counts.
    pub fetch_transaction: usize,
    pub fetch_provision: usize,
    pub fetch_local_provision: usize,
    pub fetch_exec_cert: usize,
    pub fetch_finalized_wave: usize,
}

/// Per-vnode consensus counts.
#[allow(missing_docs)] // fields are flat readouts; names are the documentation
pub struct VnodeMetrics {
    /// Shard this vnode participates in. Carried alongside the consensus
    /// counts so [`record_metrics`] can label the per-vnode gauges with
    /// both `shard` and `validator_id`.
    pub shard: ShardGroupId,
    pub shard_round: u64,
    pub view_changes: u64,
    pub view_syncs: u64,
    pub mempool_size: usize,
    pub contention_ratio: f64,
    pub in_flight: usize,
    pub backpressure_active: bool,
}

/// Composite metrics snapshot.
///
/// Per-shard infrastructure metrics live in `shards`; per-vnode consensus
/// metrics live in `vnodes`. `memory` is a flat readout populated from a
/// representative shard + vnode (see [`Self::primary`]).
pub struct MetricsSnapshot {
    /// Per-hosted-shard infrastructure metrics.
    pub shards: HashMap<ShardGroupId, ShardMetrics>,
    /// Per-hosted-vnode consensus metrics.
    pub vnodes: HashMap<ValidatorId, VnodeMetrics>,
    /// Flat memory readouts, assembled from primary shard + primary vnode.
    pub memory: MemoryMetrics,
}

impl MetricsSnapshot {
    /// Pick a representative `(ShardMetrics, VnodeMetrics)` pair for
    /// the memory readouts and any flat gauge that's still process-wide.
    /// Returns `None` if there's nothing hosted (shouldn't happen for a
    /// running `NodeHost`).
    #[must_use]
    pub fn primary(&self) -> Option<(&ShardMetrics, &VnodeMetrics)> {
        let shard = self.shards.values().next()?;
        let vnode = self.vnodes.values().next()?;
        Some((shard, vnode))
    }
}

/// Record a [`MetricsSnapshot`] to the metrics backend.
///
/// Iterates the per-shard and per-vnode maps and emits one labeled gauge
/// per entry. Process-wide `RocksDB` readouts (block-cache, memtable
/// bytes) come from `rocksdb_block_cache_bytes` / `rocksdb_memtable_bytes`,
/// summed across hosted shards by the caller. Designed to run off the
/// pinned thread via `spawn_blocking`.
pub fn record_metrics(
    snapshot: MetricsSnapshot,
    rocksdb_block_cache_bytes: u64,
    rocksdb_memtable_bytes: u64,
) {
    for (shard_id, shard) in &snapshot.shards {
        let s = shard_id.inner();
        set_sync_blocks_behind("block", s, shard.blocks_behind);
        set_sync_in_progress("block", s, shard.is_syncing);
        set_sync_round_in_flight("block", s, shard.block_sync_round_in_flight);
        set_sync_blocks_behind("remote_header", s, shard.remote_header_blocks_behind);
        set_sync_in_progress("remote_header", s, shard.remote_header_is_syncing);
        set_sync_round_in_flight("remote_header", s, shard.remote_header_round_in_flight);
        set_fetch_in_flight("transaction", s, shard.fetch_transaction);
        set_fetch_in_flight("provision", s, shard.fetch_provision);
        set_fetch_in_flight("local_provision", s, shard.fetch_local_provision);
        set_fetch_in_flight("exec_cert", s, shard.fetch_exec_cert);
        set_fetch_in_flight("finalized_wave", s, shard.fetch_finalized_wave);
    }

    for (validator_id, vnode) in &snapshot.vnodes {
        let s = vnode.shard.inner();
        let v = validator_id.inner();
        set_shard_round(s, v, vnode.shard_round);
        set_view_changes(s, v, vnode.view_changes);
        set_view_syncs(s, v, vnode.view_syncs);
        set_mempool_size(s, v, vnode.mempool_size);
        set_lock_contention(s, v, vnode.contention_ratio);
        set_in_flight(s, v, vnode.in_flight);
        set_backpressure_active(s, v, vnode.backpressure_active);
    }

    let mut memory = snapshot.memory;
    memory.rocksdb_block_cache_usage_bytes = rocksdb_block_cache_bytes;
    memory.rocksdb_memtable_usage_bytes = rocksdb_memtable_bytes;
    set_memory_metrics(&memory);
}

impl<S, N, D> super::ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Emit this shard's per-shard and per-vnode prometheus gauges.
    /// Called from the shard's pinned thread on the metrics tick.
    /// Process-wide gauges (memory, `RocksDB`) are emitted separately
    /// by the runner after aggregating per-shard contributions.
    pub fn record_prometheus(&self) {
        let s = self.shard.inner();
        let fetches = self.io.fetches.metrics();
        let syncs = &self.io.syncs;

        set_sync_blocks_behind("block", s, syncs.block.blocks_behind());
        set_sync_in_progress("block", s, syncs.block.is_syncing());
        set_sync_round_in_flight("block", s, syncs.block.in_flight_ranges());
        set_sync_blocks_behind(
            "remote_header",
            s,
            syncs.remote_header.total_blocks_behind(),
        );
        set_sync_in_progress("remote_header", s, syncs.remote_header.is_syncing());
        set_sync_round_in_flight("remote_header", s, syncs.remote_header.in_flight_ranges());
        set_fetch_in_flight("transaction", s, fetches.transaction_in_flight);
        set_fetch_in_flight("provision", s, fetches.provision_in_flight);
        set_fetch_in_flight("local_provision", s, fetches.local_provision_in_flight);
        set_fetch_in_flight("exec_cert", s, fetches.exec_cert_in_flight);
        set_fetch_in_flight("finalized_wave", s, fetches.finalized_wave_in_flight);
        set_fetch_oldest_in_flight_age_ms(
            "transaction",
            s,
            fetches.transaction_oldest_in_flight_age_ms,
        );
        set_fetch_oldest_in_flight_age_ms(
            "provision",
            s,
            fetches.provision_oldest_in_flight_age_ms,
        );
        set_fetch_oldest_in_flight_age_ms(
            "local_provision",
            s,
            fetches.local_provision_oldest_in_flight_age_ms,
        );
        set_fetch_oldest_in_flight_age_ms(
            "exec_cert",
            s,
            fetches.exec_cert_oldest_in_flight_age_ms,
        );
        set_fetch_oldest_in_flight_age_ms(
            "finalized_wave",
            s,
            fetches.finalized_wave_oldest_in_flight_age_ms,
        );

        for vnode in &self.vnodes {
            let v = vnode.validator_id.inner();
            let state = &vnode.state;
            let shard_stats = state.shard_coordinator().stats();
            let mempool = state.mempool_coordinator();
            let contention = mempool.lock_contention_stats();
            set_shard_round(s, v, shard_stats.current_round);
            set_view_changes(s, v, shard_stats.view_changes);
            set_view_syncs(s, v, shard_stats.view_syncs);
            set_mempool_size(s, v, mempool.len());
            set_lock_contention(s, v, contention.contention_ratio());
            set_in_flight(s, v, mempool.in_flight());
            set_backpressure_active(s, v, mempool.at_in_flight_limit());
        }
    }
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
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
        let mut shards = HashMap::new();
        let mut vnodes = HashMap::new();

        for shard in self.hosted_shards() {
            let fetches = self.shard_io(shard).fetches.metrics();
            let syncs = &self.shard_io(shard).syncs;
            shards.insert(
                shard,
                ShardMetrics {
                    blocks_behind: syncs.block.blocks_behind(),
                    is_syncing: syncs.block.is_syncing(),
                    block_sync_round_in_flight: syncs.block.in_flight_ranges(),
                    remote_header_blocks_behind: syncs.remote_header.total_blocks_behind(),
                    remote_header_is_syncing: syncs.remote_header.is_syncing(),
                    remote_header_round_in_flight: syncs.remote_header.in_flight_ranges(),
                    fetch_transaction: fetches.transaction_in_flight,
                    fetch_provision: fetches.provision_in_flight,
                    fetch_local_provision: fetches.local_provision_in_flight,
                    fetch_exec_cert: fetches.exec_cert_in_flight,
                    fetch_finalized_wave: fetches.finalized_wave_in_flight,
                },
            );

            for vnode_idx in 0..self.vnodes_len(shard) {
                let vnode = self.vnode(shard, vnode_idx);
                let state = &vnode.state;
                let shard_stats = state.shard_coordinator().stats();
                let mempool = state.mempool_coordinator();
                let contention = mempool.lock_contention_stats();
                vnodes.insert(
                    vnode.validator_id,
                    VnodeMetrics {
                        shard,
                        shard_round: shard_stats.current_round,
                        view_changes: shard_stats.view_changes,
                        view_syncs: shard_stats.view_syncs,
                        mempool_size: mempool.len(),
                        contention_ratio: contention.contention_ratio(),
                        in_flight: mempool.in_flight(),
                        backpressure_active: mempool.at_in_flight_limit(),
                    },
                );
            }
        }

        // Memory readouts come from a primary shard + vnode; iteration
        // order matches the maps above so this aligns with
        // `MetricsSnapshot::primary`.
        let primary_shard = self
            .hosted_shards()
            .next()
            .expect("NodeHost hosts at least one shard");
        let primary_vnode = &self.vnode(primary_shard, 0).state;
        let shard_mem = primary_vnode.shard_coordinator().memory_stats();
        let exec_mem = primary_vnode.execution_coordinator().memory_stats();
        let mempool_mem = primary_vnode.mempool_coordinator().memory_stats();
        let prov_mem = primary_vnode.provisions_coordinator().memory_stats();
        let rh_mem = primary_vnode.remote_headers_coordinator().memory_stats();
        let fetches = self.shard_io(primary_shard).fetches.metrics();
        let block_sync_status = self.shard_io(primary_shard).syncs.block.block_sync_status();

        let memory = MemoryMetrics {
            // Shard consensus
            shard_pending_blocks: shard_mem.pending_blocks,
            shard_vote_sets: shard_mem.vote_sets,
            shard_pending_commits: shard_mem.pending_commits,
            shard_pending_commits_awaiting_data: shard_mem.pending_commits_awaiting_data,
            shard_voted_heights: shard_mem.voted_heights,
            shard_received_votes_by_height: shard_mem.received_votes_by_height,
            shard_committed_tx_lookup: shard_mem.committed_tx_lookup,
            shard_committed_cert_lookup: shard_mem.committed_cert_lookup,
            shard_committed_provision_lookup: shard_mem.committed_provision_lookup,
            shard_pending_qc_verifications: shard_mem.pending_qc_verifications,
            shard_verified_qcs: shard_mem.verified_qcs,
            shard_pending_state_root_verifications: shard_mem.pending_state_root_verifications,
            shard_buffered_synced_blocks: shard_mem.buffered_synced_blocks,
            shard_pending_synced_block_verifications: shard_mem.pending_synced_block_verifications,
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
            // Node (io_loop, per-shard)
            node_tx_store: self.shard_io(primary_shard).caches.tx_store.len(),
            node_tx_status_cache: self.shard_io(primary_shard).caches.tx_status.len(),
            node_finalized_wave_cache: self.shard_io(primary_shard).caches.finalized_wave.len(),
            node_provision_cache: self.shard_io(primary_shard).caches.provision_store.len(),
            node_exec_cert_cache: self.shard_io(primary_shard).caches.exec_cert_store.len(),
            node_prepared_commits: self.shard_io(primary_shard).block_commit.prepared_len(),
            node_pending_validation: self.shard_io(primary_shard).pending_validation.len(),
            node_locally_submitted: self.shard_io(primary_shard).locally_submitted.len(),
            node_pending_block_commits: self.shard_io(primary_shard).block_commit.pending_len(),
            node_validation_batch: self.shard_io(primary_shard).validation_batch.len(),
            node_committed_header_batch: self.shard_io(primary_shard).committed_header_batch.len(),
            node_block_sync_queued_heights: block_sync_status.queued_heights,
            node_block_sync_in_flight_fetches: block_sync_status.pending_fetches,
            node_tx_fetch_blocks: fetches.transaction_pending,
            node_local_provision_fetch_pending: fetches.local_provision_pending,
            node_finalized_wave_fetch_pending: fetches.finalized_wave_pending,
            node_provision_fetch_pending: fetches.provision_pending,
            node_exec_cert_fetch_pending: fetches.exec_cert_pending,
            node_remote_header_fetch_pending: self
                .shard_io(primary_shard)
                .syncs
                .remote_header
                .in_flight_ranges(),
            // Storage — filled in by record_metrics off-thread.
            rocksdb_block_cache_usage_bytes: 0,
            rocksdb_memtable_usage_bytes: 0,
        };

        MetricsSnapshot {
            shards,
            vnodes,
            memory,
        }
    }
}
