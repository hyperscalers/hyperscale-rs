//! Per-shard cross-shard subsystem.
//!
//! Owns the per-shard state and code for everything a shard does *across*
//! shard boundaries: tracking other shards' certified headers, fetching and
//! serving cross-shard data (provisions, execution certificates, finalized
//! ticks, a departed shard's settled set).
//!
//! [`CrossShardState`] is the per-shard state struct `ShardIo` composes;
//! subsystem-specific FSM instances, bindings, serves, and glue live here
//! beside it.

mod committed_txs_serve;
mod exec_cert_serve;
mod fetch;
mod finalization_serve;
mod local_provision_serve;
mod provision_serve;
mod remote_header;
mod remote_header_serve;
mod remote_header_sync;
mod settled_txs_serve;
mod state_proof_serve;

pub use committed_txs_serve::{CommittedTxsCache, serve_committed_txs_request};
pub use exec_cert_serve::serve_execution_certs_request;
pub use fetch::{
    CommittedTxBinding, CommittedTxFetch, CrossingPullBinding, ExecCertBinding, ExecCertFetch,
    FinalizationBinding, FinalizationFetch, LocalProvisionBinding, LocalProvisionFetch,
    ProvisionBinding, ProvisionFetch, SettledTxsBinding, SettledTxsFetch, StateProofBinding,
    StateProofFetch,
};
pub use finalization_serve::serve_finalizations_request;
use hyperscale_types::{BlockHeight, LocalTimestamp, ShardId};
pub use local_provision_serve::serve_local_provisions_request;
pub use provision_serve::serve_provision_request;
use remote_header::{RemoteHeaderSync, RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
pub use remote_header_serve::{serve_local_certified_headers, serve_remote_headers_request};
pub use settled_txs_serve::{SettledTxsCache, serve_settled_txs_request};
pub use state_proof_serve::{serve_cells_request, serve_state_proof_request};

use crate::config::NodeConfig;
use crate::fetch::FetchConfig;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct CrossShardState {
    /// Multi-shard remote-header sync: tracks other shards' certified header
    /// chains for the cross-shard data dependencies a shard provisions against.
    pub(crate) remote_header_sync: RemoteHeaderSync,

    /// Cross-shard provision fetch (rotates through source committee).
    pub(crate) provision: ProvisionFetch,
    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub(crate) exec_cert: ExecCertFetch,
    /// Finalization fetch (rotates through committee).
    pub(crate) finalization: FinalizationFetch,
    /// Local-provision fetch (pinned to proposer).
    pub(crate) local_provision: LocalProvisionFetch,
    /// Committed-transaction membership fetch against the chains this
    /// one succeeds (rotates through the predecessor's committee).
    pub(crate) committed_tx: CommittedTxFetch,
    /// State-proof fetch against other shards' commit-proven headers
    /// (rotates through the anchor's committee).
    pub(crate) state_proof: StateProofFetch,
    /// Settled-set fetch against departed shards' terminals (rotates
    /// through the terminal committee).
    pub(crate) settled_txs: SettledTxsFetch,
    /// Crossing-record pull against a producer's commit-proven anchor,
    /// for a delivery that needs the record's value. Its own slot beside
    /// [`Self::provision`] because the two are keyed differently: that
    /// one by the block that promised a bundle, this one by the anchor
    /// the asker can verify.
    pub(crate) crossing_pull: StateProofFetch,
}

impl CrossShardState {
    /// Build cross-shard state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        Self {
            remote_header_sync: RemoteHeaderSync::new(remote_header::default_config()),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
            finalization: FinalizationFetch::new(
                "finalization",
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
            committed_tx: CommittedTxFetch::new(
                "committed_tx",
                FetchConfig {
                    max_in_flight: 256,
                    max_ids_per_request: 64,
                    parallel_chunks_per_tick: 2,
                },
            ),
            state_proof: StateProofFetch::new(
                "state_proof",
                FetchConfig {
                    max_in_flight: 256,
                    max_ids_per_request: 64,
                    parallel_chunks_per_tick: 2,
                },
            ),
            settled_txs: SettledTxsFetch::new(
                "settled_txs",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 8,
                    parallel_chunks_per_tick: 2,
                },
            ),
            crossing_pull: StateProofFetch::new(
                "crossing_pull",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
        }
    }

    /// True if any cross-shard FSM (remote-header sync or the cross-shard
    /// fetches) has pending work — keeps this shard's `FetchTick` alive so
    /// deferred work retries.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
            || self.finalization.has_pending()
            || self.local_provision.has_pending()
            || self.committed_tx.has_pending()
            || self.state_proof.has_pending()
            || self.settled_txs.has_pending()
            || self.crossing_pull.has_pending()
    }

    /// Drive the remote-header-sync FSM's periodic tick. Returns range
    /// fetches and any newly-emitted `SyncComplete` for shards that just
    /// caught up.
    pub(crate) fn remote_header_tick(
        &mut self,
        now: LocalTimestamp,
    ) -> Vec<RemoteHeaderSyncOutput> {
        self.remote_header_sync
            .handle(RemoteHeaderSyncInput::Tick { now })
    }

    /// Notify the remote-header-sync FSM that `RemoteHeaderCoordinator`
    /// admitted a header at `height` for `source_shard`.
    pub(crate) fn on_remote_header_admitted(
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
