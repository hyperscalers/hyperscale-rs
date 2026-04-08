//! JVT node cache with version-aware eviction.
//!
//! Holds hydrated `jvt::Node` values keyed by `NodeKey` (version + byte path),
//! eliminating the expensive `StoredNode::to_jvt()` deserialization on repeated
//! reads.
//!
//! # Design
//!
//! - **Backed by `DashMap`** — concurrent reads/writes with no global lock.
//! - **No LRU eviction** — eviction is driven by JVT GC, which removes nodes
//!   by version when they fall outside the history retention window. This
//!   avoids the pathological LRU behavior where a burst of leaf-node reads
//!   evicts always-hot upper-level nodes (root, depth 1-2).
//! - **`put_at_version` is read-only** — speculative computations (state root
//!   verification, proposal building) read from the cache but never write.
//!   New nodes are only inserted after an actual block commit, via
//!   [`NodeCache::populate`]. This prevents speculative nodes from
//!   contaminating the cache and causing panics when evicted.

use std::sync::Arc;

use dashmap::DashMap;
use jellyfish_verkle_tree as jvt;

use crate::tree_store::{StoredNode, StoredNodeKey};

/// Shared node cache for hydrated JVT nodes.
///
/// Thread-safe (`Send + Sync`). Populated only during block commits and
/// cache-miss reads from storage. Never written to by speculative computations.
pub struct NodeCache {
    inner: DashMap<jvt::NodeKey, Arc<jvt::Node>>,
}

impl NodeCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Look up a cached node.
    pub fn get(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        self.inner.get(key).map(|r| Arc::clone(r.value()))
    }

    /// Insert a single node.
    ///
    /// Used by `StoreAdapter` to populate the cache on read-miss (committed
    /// data read from storage). For bulk insertion after block commit, use
    /// [`populate`] instead.
    pub fn insert(&self, key: jvt::NodeKey, node: Arc<jvt::Node>) {
        self.inner.insert(key, node);
    }

    /// Bulk-insert nodes after a committed block.
    ///
    /// Called after `put_at_version` + RocksDB write to populate the cache
    /// with the newly created nodes. Re-hydrates from `StoredNode` since
    /// the serialized form is what survives in `CollectedWrites`/`JvtSnapshot`.
    pub fn populate(&self, nodes: &[(StoredNodeKey, StoredNode)]) {
        for (stored_key, stored_node) in nodes {
            let jvt_key = stored_key.to_jvt();
            let jvt_node = Arc::new(stored_node.to_jvt());
            self.inner.insert(jvt_key, jvt_node);
        }
    }

    /// Remove a node from the cache.
    ///
    /// Called during JVT GC when stale nodes are deleted from RocksDB.
    pub fn remove(&self, key: &StoredNodeKey) {
        self.inner.remove(&key.to_jvt());
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for NodeCache {
    fn default() -> Self {
        Self::new()
    }
}
