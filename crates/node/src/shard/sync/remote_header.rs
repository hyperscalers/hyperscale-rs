//! Remote-header sync binding for the generic [`Sync`] state machine.
//!
//! [`RemoteHeaderSyncBinding`] declares per-binding type info: per-shard
//! scope (`Scope = ShardGroupId`) and no payload-private state
//! (`State = ()`).
//!
//! The `IoLoop` remote-header-sync handlers own request dispatch, response
//! decoding, and forward delivered headers through the existing
//! `RemoteHeaderReceived` path.

use hyperscale_types::ShardGroupId;

use super::{Sync, SyncBinding, SyncConfig, SyncInput, SyncOutput};

/// Default upper bound on heights packed into a single range fetch.
/// Matches `MAX_REMOTE_HEADERS_PER_REQUEST` so the responder never has to
/// short-cap on `count` alone.
pub const DEFAULT_MAX_HEADERS_PER_FETCH: u64 = 64;

/// Default per-shard window. How far ahead of `committed` the FSM queues
/// fetches. Bounded so the heap can't grow without bound when `target`
/// jumps far ahead.
pub const DEFAULT_SYNC_WINDOW_SIZE: u64 = 256;

/// Default cap on concurrent in-flight range fetches per shard.
/// Source-shard committee responsiveness is the bottleneck, not local
/// resources, so the limit is per-shard.
pub const DEFAULT_MAX_CONCURRENT_FETCHES_PER_SHARD: usize = 4;

/// Type alias: remote-header sync is `Sync<RemoteHeaderSyncBinding>`.
pub type RemoteHeaderSync = Sync<RemoteHeaderSyncBinding>;

/// Type alias for remote-header sync inputs.
pub type RemoteHeaderSyncInput = SyncInput<RemoteHeaderSyncBinding>;

/// Type alias for remote-header sync outputs.
pub type RemoteHeaderSyncOutput = SyncOutput<RemoteHeaderSyncBinding>;

/// Marker type implementing [`SyncBinding`] for remote-header sync.
pub struct RemoteHeaderSyncBinding;

impl SyncBinding for RemoteHeaderSyncBinding {
    type Scope = ShardGroupId;
    type State = ();
    const NAME: &'static str = "remote_header_sync";
}

/// Construct a [`SyncConfig`] populated with the remote-header defaults.
#[must_use]
pub const fn default_config() -> SyncConfig {
    SyncConfig {
        max_per_request: DEFAULT_MAX_HEADERS_PER_FETCH,
        window_size: DEFAULT_SYNC_WINDOW_SIZE,
        max_concurrent_per_scope: DEFAULT_MAX_CONCURRENT_FETCHES_PER_SHARD,
    }
}
