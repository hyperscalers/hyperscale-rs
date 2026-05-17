//! Per-shard I/O state hosted by the `IoLoop`.
//!
//! One [`ShardIo`] per hosted shard. Same-shard `Vnode`s share their
//! `ShardIo`; cross-shard `Vnode`s live independently. Shard-scoped
//! state (storage today; fetch host, sync host, block-commit pipeline,
//! request-serving caches, and batch accumulators in due course) lives
//! here so that multi-vnode hosting captures the natural sharing
//! structure without leaking state across `IoLoop`s.

pub mod block_commit;

use std::sync::Arc;

use hyperscale_storage::{PendingChain, Storage};

use crate::shard::block_commit::BlockCommitCoordinator;

/// Per-shard I/O state hosted by the `IoLoop`.
pub struct ShardIo<S: Storage> {
    /// Persistent block / receipt / JMT store for this shard. `Arc` so
    /// delegated closures (block-commit, fetch-serve, sync) can read
    /// it from thread pools without crossing back to the pinned thread.
    pub storage: Arc<S>,

    /// Chain-anchored pending state. Indexed by block hash; reads
    /// happen through `PendingChain::view_at(parent_block_hash)` which
    /// walks the parent chain back to the committed tip. Orphaned
    /// blocks are not ancestors and are structurally invisible to
    /// anchored views.
    pub pending_chain: Arc<PendingChain<S>>,

    /// Block commit pipeline: accumulates commits, applies persistence
    /// backpressure, and drains them into a single async closure that
    /// runs on the execution pool. Owns the prepared-commit cache
    /// shared with delegated dispatch closures.
    pub block_commit: BlockCommitCoordinator<S>,
}
