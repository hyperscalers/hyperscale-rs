//! Storage traits and reference in-memory backend.
//!
//! The tree is stateless — callers plug their own storage in by
//! implementing [`TreeReader`] (required for reads and proofs) and
//! [`TreeWriter`] (to persist [`TreeUpdateBatch`] results).
//!
//! A `RocksDB` backend should implement these against column families;
//! the node-key encoding ([`NodeKey::encode`]) is LSM-friendly with
//! version as the big-endian prefix.

use std::collections::HashMap;
use std::sync::Arc;

use crate::node::{Node, NodeKey, StaleNodeIndex};
use crate::tree::UpdateResult;

// ============================================================
// Traits
// ============================================================

/// Read-only storage interface. Proof generation, reads, and the internal
/// walks performed by `apply_updates` all go through this trait.
///
/// With the `parallel` feature enabled, implementations must be `Sync`
/// so the recursive update walk can dispatch bucket sub-trees across
/// rayon worker threads.
#[cfg(feature = "parallel")]
pub trait TreeReader: Sync {
    /// Fetch a node by its key. Returns `None` if the node is absent
    /// (valid for pruned or never-written paths).
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>>;

    /// Look up the root key for a committed version. Returns `None` for
    /// versions that were never committed or have been pruned.
    fn get_root_key(&self, version: u64) -> Option<NodeKey>;
}

/// Read-only storage interface. Proof generation, reads, and the internal
/// walks performed by `apply_updates` all go through this trait.
#[cfg(not(feature = "parallel"))]
pub trait TreeReader {
    /// Fetch a node by its key. Returns `None` if the node is absent
    /// (valid for pruned or never-written paths).
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>>;

    /// Look up the root key for a committed version. Returns `None` for
    /// versions that were never committed or have been pruned.
    fn get_root_key(&self, version: u64) -> Option<NodeKey>;
}

/// Write storage interface. `TreeUpdateBatch` fields are applied via
/// these three methods.
pub trait TreeWriter {
    /// Persist a node under its versioned key.
    fn put_node(&mut self, key: NodeKey, node: Node);
    /// Record the root key that identifies the tree at the given version.
    fn set_root_key(&mut self, version: u64, key: NodeKey);
    /// Record that a previously written node became stale at a version.
    fn record_stale(&mut self, entry: StaleNodeIndex);
}

// ============================================================
// MemoryStore — reference implementation
// ============================================================

/// In-memory storage backend. Useful for tests, simulation, and as a
/// reference implementation.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    nodes: HashMap<NodeKey, Arc<Node>>,
    root_keys: HashMap<u64, NodeKey>,
    stale_index: Vec<StaleNodeIndex>,
}

impl MemoryStore {
    /// Create an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply an [`UpdateResult`] from [`Tree::apply_updates`](crate::Tree::apply_updates)
    /// to this store. Persists new nodes, records stale entries, and
    /// updates the root-key mapping.
    pub fn apply(&mut self, result: &UpdateResult) {
        for (nk, node) in &result.batch.new_nodes {
            self.put_node(nk.clone(), node.clone());
        }
        for stale in &result.batch.stale_nodes {
            self.record_stale(stale.clone());
        }
        if let Some((v, ref rk)) = result.batch.root_key {
            self.set_root_key(v, rk.clone());
        }
    }

    /// Prune all nodes that became stale at or before the given version.
    /// After calling, reads at pruned versions may fail.
    pub fn prune(&mut self, up_to_version: u64) {
        let (to_remove, to_keep): (Vec<_>, Vec<_>) = self
            .stale_index
            .drain(..)
            .partition(|e| e.stale_since_version <= up_to_version);
        for entry in &to_remove {
            self.nodes.remove(&entry.node_key);
        }
        self.stale_index = to_keep;
    }

    /// Number of stored nodes (across all versions).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of recorded stale-node entries pending pruning.
    #[must_use]
    pub const fn stale_count(&self) -> usize {
        self.stale_index.len()
    }

    /// All committed versions, sorted ascending.
    #[must_use]
    pub fn versions(&self) -> Vec<u64> {
        let mut vs: Vec<u64> = self.root_keys.keys().copied().collect();
        vs.sort_unstable();
        vs
    }

    /// Highest committed version, if any.
    #[must_use]
    pub fn latest_version(&self) -> Option<u64> {
        self.root_keys.keys().max().copied()
    }

    /// Root key of the highest committed version, if any.
    #[must_use]
    pub fn latest_root_key(&self) -> Option<NodeKey> {
        let v = self.latest_version()?;
        self.root_keys.get(&v).cloned()
    }
}

impl TreeReader for MemoryStore {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        self.root_keys.get(&version).cloned()
    }
}

impl TreeWriter for MemoryStore {
    fn put_node(&mut self, key: NodeKey, node: Node) {
        self.nodes.insert(key, Arc::new(node));
    }

    fn set_root_key(&mut self, version: u64, key: NodeKey) {
        self.root_keys.insert(version, key);
    }

    fn record_stale(&mut self, entry: StaleNodeIndex) {
        self.stale_index.push(entry);
    }
}

// Forward trait impls through Arc/Box so users can hand a shared store
// to the stateless functions without needing to call as_ref() everywhere.
//
// `Arc<T>: Sync` requires `T: Send + Sync`, so when the `parallel`
// feature gates `TreeReader: Sync`, the inner type must additionally be
// `Send`.
#[cfg(feature = "parallel")]
impl<T: TreeReader + Send + ?Sized> TreeReader for Arc<T> {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        (**self).get_node(key)
    }
    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        (**self).get_root_key(version)
    }
}

#[cfg(not(feature = "parallel"))]
impl<T: TreeReader + ?Sized> TreeReader for Arc<T> {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        (**self).get_node(key)
    }
    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        (**self).get_root_key(version)
    }
}

impl<T: TreeReader + ?Sized> TreeReader for &T {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        (**self).get_node(key)
    }
    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        (**self).get_root_key(version)
    }
}
