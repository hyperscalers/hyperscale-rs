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

use hyperscale_jmt::TreeReader;
use hyperscale_types::BlockHeight;

use super::overlay::SubstateLookup;

/// How many boundary pins a backend retains before evicting the oldest.
pub const BOUNDARY_RETAIN: usize = 3;

/// Pin and serve committed state at epoch boundary heights.
pub trait BoundaryStore {
    /// A pinned boundary opened for serving: the JMT at the pinned
    /// version plus raw substate reads at that same state.
    type Boundary: TreeReader + SubstateLookup + Send;

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
