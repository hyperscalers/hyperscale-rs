//! Per-shard I/O state hosted by the `IoLoop`.
//!
//! One [`ShardIo`] per hosted shard. Same-shard `Vnode`s share their
//! `ShardIo`; cross-shard `Vnode`s live independently. Shard-scoped
//! state (storage today; fetch host, sync host, block-commit pipeline,
//! request-serving caches, and batch accumulators in due course) lives
//! here so that multi-vnode hosting captures the natural sharing
//! structure without leaking state across `IoLoop`s.

use std::sync::Arc;

use hyperscale_storage::Storage;

/// Per-shard I/O state hosted by the `IoLoop`.
pub struct ShardIo<S: Storage> {
    /// Persistent block / receipt / JMT store for this shard. `Arc` so
    /// delegated closures (block-commit, fetch-serve, sync) can read
    /// it from thread pools without crossing back to the pinned thread.
    pub storage: Arc<S>,
}
