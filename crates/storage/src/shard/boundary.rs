//! Serving-side access to shard state pinned at epoch boundaries.
//!
//! A serving shard member pins its committed state at recent epoch
//! boundary blocks so a joining vnode can snap-sync against the
//! beacon-attested boundary `state_root` while the live store keeps
//! committing and garbage-collecting. The pinning mechanics are the
//! backend's business — `RocksDB` uses hard-link checkpoints, the
//! in-memory store serves its versioned tree directly — so the node
//! layer's boundary trigger and range-serving code stay generic and run
//! identically in simulation and production.

use hyperscale_jmt::{Key, TreeReader};
use hyperscale_types::BlockHeight;

use super::overlay::SubstateLookup;

/// How many boundary pins a backend retains before evicting the oldest.
pub const BOUNDARY_RETAIN: usize = 3;

/// Resolve a JMT leaf back to the raw substate pair it represents.
///
/// `jmt_leaf_key` is one-way, so range serving needs this to turn leaves
/// enumerated out of the tree into the raw `(storage key, value)` pairs
/// a snap-syncing joiner imports. Backends answer from their
/// leaf-association mapping at the boundary's pinned state.
pub trait ResolveLeaf {
    /// The raw `(storage key, value)` behind `leaf_key`, or `None` when
    /// the leaf is unknown at this boundary.
    fn resolve_leaf(&self, leaf_key: &Key) -> Option<(Vec<u8>, Vec<u8>)>;
}

/// Pin and serve committed state at epoch boundary heights.
pub trait BoundaryStore {
    /// A pinned boundary opened for serving: the JMT at the pinned
    /// version plus raw substate reads at that same state.
    type Boundary: TreeReader + SubstateLookup + ResolveLeaf + Send;

    /// Pin the committed state at `height` — the shard's epoch boundary
    /// block — keeping the newest [`BOUNDARY_RETAIN`] pins. Idempotent
    /// per height.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure (e.g. checkpoint I/O). A
    /// failed pin degrades serving, never correctness — callers log and
    /// continue.
    fn pin_boundary(&self, height: BlockHeight) -> Result<(), String>;

    /// Open the pin at exactly `height`, or `None` if it was never
    /// pinned or has been evicted from the ring.
    fn open_boundary(&self, height: BlockHeight) -> Option<Self::Boundary>;

    /// The newest pinned height, if any.
    fn latest_boundary(&self) -> Option<BlockHeight>;
}
