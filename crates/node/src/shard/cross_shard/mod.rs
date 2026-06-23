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

pub mod settled_set;
mod settled_set_sync;
pub mod settled_waves_serve;

pub use settled_set::SettledWavesAcquisitionHost;
pub use settled_waves_serve::serve_settled_waves_request;

/// Per-shard cross-shard subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo). Grows as the cross-shard
/// remote-header sync and the cross-shard fetch instances/stores move in.
#[derive(Default)]
pub struct CrossShardState {
    /// Settled-waves acquisition drivers — one per past-terminal remote
    /// shard whose `S_P` this node is acquiring for the split-boundary fence.
    pub settled_set_sync: SettledWavesAcquisitionHost,
}

impl CrossShardState {
    /// Build empty cross-shard state for a freshly hosted shard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
