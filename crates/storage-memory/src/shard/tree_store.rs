//! Simple in-memory JMT tree store for simulation.
//!
//! Implements [`TreeReader`] directly over hydrated `Arc<Node>` entries —
//! no serialization layer. Thread safety is provided by the outer
//! `RwLock<SharedState>`.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt::{NibblePath, Node, NodeKey, TreeReader};

/// Simple in-memory tree store that implements `TreeReader`.
///
/// Stores hydrated JMT nodes directly (no serialization layer).
/// Thread safety is handled by the outer `RwLock<SharedState>`.
#[derive(Clone)]
pub struct SimTreeStore {
    nodes: HashMap<NodeKey, Arc<Node>>,
    /// Prefix this tree is rooted at — the shard's prefix, so the root node is
    /// the global tree's subtree at that prefix. Empty for a whole-keyspace store.
    root_path: NibblePath,
}

impl SimTreeStore {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_path: NibblePath::empty(),
        }
    }

    /// Set the prefix this tree is rooted at (its shard's prefix). Set once
    /// before any writes, while the store is empty.
    pub fn set_root_path(&mut self, root_path: NibblePath) {
        self.root_path = root_path;
    }

    pub fn insert(&mut self, key: NodeKey, node: Arc<Node>) {
        self.nodes.insert(key, node);
    }

    pub fn remove(&mut self, key: &NodeKey) {
        self.nodes.remove(key);
    }
}

impl TreeReader for SimTreeStore {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        let root = NodeKey::new(version, self.root_path.clone());
        if self.nodes.contains_key(&root) {
            Some(root)
        } else {
            None
        }
    }

    fn root_path(&self) -> NibblePath {
        self.root_path.clone()
    }
}
