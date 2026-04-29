//! Bundle of fetch + sync protocols owned by the I/O loop.
//!
//! `ProtocolHost` holds the per-payload fetch state machines plus the
//! block-sync and remote-header-sync state machines. Lifting these out of
//! `IoLoop` makes "what the I/O loop is orchestrating" explicit.

use super::binding::{
    ExecCertBinding, ExecCertFetch, FetchBinding, FinalizedWaveBinding, FinalizedWaveFetch,
    LocalProvisionBinding, LocalProvisionFetch, ProvisionBinding, ProvisionFetch,
    TransactionBinding, TransactionFetch,
};
use super::block_sync::{BlockSyncInput, BlockSyncOutput, BlockSyncProtocol, BlockSyncStatus};
use super::fetch::FetchConfig;
use super::remote_header_sync::{
    RemoteHeaderSyncConfig, RemoteHeaderSyncInput, RemoteHeaderSyncOutput, RemoteHeaderSyncProtocol,
};
use crate::config::NodeConfig;
use hyperscale_core::ProtocolEvent;
use std::time::Instant;

/// Sync + per-payload fetch protocols owned by the I/O loop.
pub struct ProtocolHost {
    /// Block-sync state machine.
    pub block_sync: BlockSyncProtocol,

    /// Multi-shard remote-header sync state machine. Catches up missing
    /// committed-header chains by batching contiguous heights into range
    /// fetches.
    pub remote_header_sync: RemoteHeaderSyncProtocol,

    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub transaction: TransactionFetch,

    /// Per-block local-provision fetch (intra-shard, pinned to proposer).
    pub local_provision: LocalProvisionFetch,

    /// Per-block finalized-wave fetch (intra-shard, rotates through committee).
    pub finalized_wave: FinalizedWaveFetch,

    /// Cross-shard provision fetch (rotates through source committee).
    pub provision: ProvisionFetch,

    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub exec_cert: ExecCertFetch,
}

impl ProtocolHost {
    /// Build the protocol host from a node config.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            block_sync: BlockSyncProtocol::new(config.block_sync.clone()),
            remote_header_sync: RemoteHeaderSyncProtocol::new(RemoteHeaderSyncConfig::default()),
            transaction: TransactionFetch::new("transaction", config.transaction_fetch.clone()),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            finalized_wave: FinalizedWaveFetch::new(
                "finalized_wave",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
        }
    }

    /// True if any fetch protocol has work outstanding (in-flight or
    /// queued), or if sync has heights parked behind a backoff.
    #[must_use]
    pub fn has_any_pending(&self) -> bool {
        self.transaction.has_pending()
            || self.local_provision.has_pending()
            || self.finalized_wave.has_pending()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
            || self.block_sync.has_deferred()
            || self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
    }

    /// Fan an admission `ProtocolEvent` across every binding. Each
    /// binding's `apply_admission` is a no-op for events it doesn't
    /// subscribe to.
    pub fn apply_admission(&mut self, event: &ProtocolEvent) {
        TransactionBinding::apply_admission(&mut self.transaction, event);
        LocalProvisionBinding::apply_admission(&mut self.local_provision, event);
        FinalizedWaveBinding::apply_admission(&mut self.finalized_wave, event);
        ProvisionBinding::apply_admission(&mut self.provision, event);
        ExecCertBinding::apply_admission(&mut self.exec_cert, event);
    }

    /// Drive the block-sync protocol's periodic tick. Returns the outputs the
    /// I/O loop should dispatch (block fetches, deliveries, sync-complete).
    pub fn block_sync_tick(&mut self, now: Instant) -> Vec<BlockSyncOutput> {
        self.block_sync.handle(BlockSyncInput::Tick { now })
    }

    /// Drive the remote-header-sync periodic tick. Returns range fetches
    /// and any newly-emitted `SyncComplete` for shards that just caught up.
    pub fn remote_header_sync_tick(&mut self, now: Instant) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Tick { now })
    }

    /// Notify the remote-header-sync FSM that `RemoteHeaderCoordinator`
    /// admitted a header at `height` for `source_shard`.
    pub fn on_remote_header_admitted(
        &mut self,
        source_shard: hyperscale_types::ShardGroupId,
        height: hyperscale_types::BlockHeight,
    ) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::HeaderAdmitted {
                source_shard,
                height,
            })
    }

    /// Snapshot per-binding fetch counts plus sync status. The I/O loop
    /// flattens this into the larger `MetricsSnapshot`.
    #[must_use]
    pub fn metrics(&self) -> ProtocolMetrics {
        ProtocolMetrics {
            transaction_in_flight: self.transaction.in_flight_count(),
            transaction_pending: self.transaction.pending_count(),
            local_provision_in_flight: self.local_provision.in_flight_count(),
            local_provision_pending: self.local_provision.pending_count(),
            finalized_wave_in_flight: self.finalized_wave.in_flight_count(),
            finalized_wave_pending: self.finalized_wave.pending_count(),
            provision_in_flight: self.provision.in_flight_count(),
            provision_pending: self.provision.pending_count(),
            exec_cert_in_flight: self.exec_cert.in_flight_count(),
            exec_cert_pending: self.exec_cert.pending_count(),
            block_sync_status: self.block_sync.block_sync_status(),
        }
    }
}

/// Cheap aggregate of per-binding fetch counts plus sync status.
///
/// Returned by [`ProtocolHost::metrics`]; flattened into the broader
/// `MetricsSnapshot` by the I/O loop.
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct ProtocolMetrics {
    pub transaction_in_flight: usize,
    pub transaction_pending: usize,
    pub local_provision_in_flight: usize,
    pub local_provision_pending: usize,
    pub finalized_wave_in_flight: usize,
    pub finalized_wave_pending: usize,
    pub provision_in_flight: usize,
    pub provision_pending: usize,
    pub exec_cert_in_flight: usize,
    pub exec_cert_pending: usize,
    pub block_sync_status: BlockSyncStatus,
}
