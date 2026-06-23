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

pub mod remote_header;
pub mod remote_header_serve;
mod remote_header_sync;
pub mod settled_set;
mod settled_set_sync;
pub mod settled_waves_serve;

use std::time::Instant;

use hyperscale_types::{BlockHeight, ShardId};
use remote_header::{RemoteHeaderSync, RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
pub use remote_header_serve::serve_remote_headers_request;
pub use settled_set::SettledWavesAcquisitionHost;
pub use settled_waves_serve::serve_settled_waves_request;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo). Grows as the cross-shard
/// fetch instances/stores move in.
pub struct CrossShardState {
    /// Multi-shard remote-header sync: tracks other shards' certified header
    /// chains for the cross-shard data dependencies a shard provisions against.
    pub remote_header_sync: RemoteHeaderSync,

    /// Settled-waves acquisition drivers — one per past-terminal remote
    /// shard whose `S_P` this node is acquiring for the split-boundary fence.
    pub settled_set_sync: SettledWavesAcquisitionHost,
}

impl CrossShardState {
    /// Build cross-shard state for a freshly hosted shard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            remote_header_sync: RemoteHeaderSync::new(remote_header::default_config()),
            settled_set_sync: SettledWavesAcquisitionHost::new(),
        }
    }

    /// True if remote-header sync or settled-waves acquisition has pending
    /// work — keeps this shard's `FetchTick` alive so deferred work retries.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.remote_header_sync.has_deferred()
            || self.remote_header_sync.is_syncing()
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

impl Default for CrossShardState {
    fn default() -> Self {
        Self::new()
    }
}
