//! Per-shard cross-shard subsystem.
//!
//! Owns the per-shard state and code for everything a shard does *across*
//! shard boundaries: tracking other shards' certified headers, fetching and
//! serving cross-shard data (provisions, execution certificates, finalized
//! waves), and reconstructing the settled-waves fence at a split boundary.
//!
//! [`CrossShardState`] is the per-shard state struct `ShardIo` composes;
//! subsystem-specific FSM instances, bindings, serves, and glue live here
//! beside it.

mod exec_cert_serve;
mod fetch;
mod finalized_wave_serve;
mod local_provision_serve;
mod provision_serve;
mod remote_header;
mod remote_header_serve;
mod remote_header_sync;
mod settled_set;
mod settled_set_sync;
mod settled_waves_serve;

use std::time::Instant;

pub use exec_cert_serve::serve_execution_certs_request;
pub use fetch::{
    ExecCertBinding, ExecCertFetch, FinalizedWaveBinding, FinalizedWaveFetch,
    LocalProvisionBinding, LocalProvisionFetch, ProvisionBinding, ProvisionFetch,
};
pub use finalized_wave_serve::serve_finalized_waves_request;
use hyperscale_types::{BlockHeight, ShardId};
pub use local_provision_serve::serve_local_provisions_request;
pub use provision_serve::serve_provision_request;
use remote_header::{RemoteHeaderSync, RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
pub use remote_header_serve::serve_remote_headers_request;
pub use settled_set::SettledWavesAcquisitionHost;
pub use settled_waves_serve::serve_settled_waves_request;

use crate::config::NodeConfig;
use crate::fetch::FetchConfig;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct CrossShardState {
    /// Multi-shard remote-header sync: tracks other shards' certified header
    /// chains for the cross-shard data dependencies a shard provisions against.
    pub remote_header_sync: RemoteHeaderSync,

    /// Cross-shard provision fetch (rotates through source committee).
    pub provision: ProvisionFetch,
    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub exec_cert: ExecCertFetch,
    /// Finalized-wave fetch (rotates through committee).
    pub finalized_wave: FinalizedWaveFetch,
    /// Local-provision fetch (pinned to proposer).
    pub local_provision: LocalProvisionFetch,

    /// Settled-waves acquisition drivers — one per past-terminal remote
    /// shard whose `S_P` this node is acquiring for the split-boundary fence.
    pub settled_set_sync: SettledWavesAcquisitionHost,
}

impl CrossShardState {
    /// Build cross-shard state for a freshly hosted shard.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            remote_header_sync: RemoteHeaderSync::new(remote_header::default_config()),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
            finalized_wave: FinalizedWaveFetch::new(
                "finalized_wave",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            settled_set_sync: SettledWavesAcquisitionHost::new(),
        }
    }

    /// True if any cross-shard FSM (remote-header sync, the cross-shard
    /// fetches, or settled-waves acquisition) has pending work — keeps this
    /// shard's `FetchTick` alive so deferred work retries.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
            || self.finalized_wave.has_pending()
            || self.local_provision.has_pending()
            || self.settled_set_sync.has_pending()
    }

    /// Drive the remote-header-sync FSM's periodic tick. Returns range
    /// fetches and any newly-emitted `SyncComplete` for shards that just
    /// caught up.
    pub fn remote_header_tick(&mut self, now: Instant) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Tick { now })
    }

    /// Notify the remote-header-sync FSM that `RemoteHeaderCoordinator`
    /// admitted a header at `height` for `source_shard`.
    pub fn on_remote_header_admitted(
        &mut self,
        source_shard: ShardId,
        height: BlockHeight,
    ) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Admitted {
                scope: source_shard,
                height,
            })
    }
}
