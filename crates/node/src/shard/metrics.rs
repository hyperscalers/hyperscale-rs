//! Prometheus emission for the I/O loop.
//!
//! [`ShardLoop::record_prometheus`] runs on the shard's pinned thread on
//! the metrics tick and emits every gauge this shard owns: sync and fetch
//! state per shard, consensus and mempool counts per vnode, and the
//! coordinator collection sizes each `memory_stats().gauges()` reports.
//! All reads are `.len()` / `.stats()` — no locks beyond cheap cache
//! lengths, no I/O.

use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::{
    MemoryFamily, set_fetch_in_flight, set_fetch_oldest_in_flight_age_ms, set_mempool_size,
    set_shard_memory_gauge, set_shard_round, set_sync_blocks_behind, set_sync_in_progress,
    set_sync_round_in_flight, set_view_changes, set_view_syncs, set_vnode_memory_gauge,
};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;

impl<S, N, D> super::ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Emit this shard's per-shard and per-vnode prometheus gauges.
    /// Called from the shard's pinned thread on the metrics tick.
    pub fn record_prometheus(&self) {
        let s = self.shard.inner();
        let fetches = self.io.fetch_metrics();
        let block_sync = &self.io.consensus.block_sync;
        let rh = &self.io.cross_shard.remote_header_sync;

        set_sync_blocks_behind("block", s, block_sync.blocks_behind());
        set_sync_in_progress("block", s, block_sync.is_syncing());
        set_sync_round_in_flight("block", s, block_sync.in_flight_ranges());
        set_sync_blocks_behind("remote_header", s, rh.total_blocks_behind());
        set_sync_in_progress("remote_header", s, rh.is_syncing());
        set_sync_round_in_flight("remote_header", s, rh.in_flight_ranges());
        set_fetch_in_flight("transaction", s, fetches.transaction_in_flight);
        set_fetch_in_flight("provision", s, fetches.provision_in_flight);
        set_fetch_in_flight("local_provision", s, fetches.local_provision_in_flight);
        set_fetch_in_flight("exec_cert", s, fetches.exec_cert_in_flight);
        set_fetch_in_flight("finalization", s, fetches.finalization_in_flight);
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
            "finalization",
            s,
            fetches.finalization_oldest_in_flight_age_ms,
        );

        for vnode in &self.vnodes {
            let v = vnode.validator_id.inner();
            let state = &vnode.state;
            let shard_stats = state.shard_coordinator().stats();
            let mempool = state.mempool_coordinator();
            set_shard_round(s, v, shard_stats.current_round);
            set_view_changes(s, v, shard_stats.view_changes);
            set_view_syncs(s, v, shard_stats.view_syncs);
            set_mempool_size(s, v, mempool.len());
        }

        self.record_memory_gauges();
    }

    /// Emit every coordinator's collection sizes, plus the runner state no
    /// single vnode owns.
    fn record_memory_gauges(&self) {
        let s = self.shard.inner();
        let fetches = self.io.fetch_metrics();
        let rh = &self.io.cross_shard.remote_header_sync;

        for vnode in &self.vnodes {
            let v = vnode.validator_id.inner();
            let state = &vnode.state;
            let mempool = state.mempool_coordinator();
            let families = [
                (
                    MemoryFamily::Shard,
                    state.shard_coordinator().memory_stats().gauges(),
                ),
                (
                    MemoryFamily::Execution,
                    state.execution_coordinator().memory_stats().gauges(),
                ),
                (MemoryFamily::Mempool, mempool.memory_stats().gauges()),
                (
                    MemoryFamily::RemoteHeaders,
                    state.remote_headers_coordinator().memory_stats().gauges(),
                ),
                (
                    MemoryFamily::Provisions,
                    state.provisions_coordinator().memory_stats().gauges(),
                ),
            ];
            for (family, gauges) in families {
                for (field, value) in gauges {
                    set_vnode_memory_gauge(family, field, s, v, value);
                }
            }
        }

        // `tx_status` is process-wide; every hosted shard reports the same
        // figure under its own label.
        let block_sync_status = self.io.consensus.block_sync.block_sync_status();
        let caches = &self.io.caches;
        let mempool_io = &self.io.mempool;
        for (field, value) in [
            ("tx_store", caches.tx_store.len()),
            ("tx_status_cache", self.process.tx_status.len()),
            ("finalization_cache", caches.finalization.len()),
            ("provision_cache", caches.provision_store.len()),
            ("exec_cert_cache", caches.exec_cert_store.len()),
            ("prepared_commits", self.io.block_commit.prepared_len()),
            ("pending_block_commits", self.io.block_commit.pending_len()),
            ("pending_validation", mempool_io.pending_validation.len()),
            ("locally_submitted", mempool_io.locally_submitted.len()),
            ("validation_batch", mempool_io.validation_batch.len()),
            (
                "certified_header_batch",
                self.io.consensus.certified_header_batch.len(),
            ),
            (
                "block_sync_queued_heights",
                block_sync_status.queued_heights,
            ),
            (
                "block_sync_in_flight_fetches",
                block_sync_status.pending_fetches,
            ),
            ("tx_fetch_blocks", fetches.transaction_pending),
            (
                "local_provision_fetch_pending",
                fetches.local_provision_pending,
            ),
            ("finalization_fetch_pending", fetches.finalization_pending),
            ("provision_fetch_pending", fetches.provision_pending),
            ("exec_cert_fetch_pending", fetches.exec_cert_pending),
            ("remote_header_fetch_pending", rh.in_flight_ranges()),
        ] {
            set_shard_memory_gauge(field, s, value);
        }
    }
}
