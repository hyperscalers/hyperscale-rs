//! Simple in-memory JVT tree store for simulation.
//!
//! Implements `jmt::TreeReader` directly, replacing the old
//! `TypedInMemoryTreeStore` wrapper that used stored/serialized node types.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt as jmt;

/// Simple in-memory tree store that implements `jmt::TreeReader`.
///
/// Stores hydrated JVT nodes directly (no serialization layer).
/// Thread safety is handled by the outer `RwLock<SharedState>`.
pub struct SimTreeStore {
    nodes: HashMap<jmt::NodeKey, Arc<jmt::Node>>,
}

impl SimTreeStore {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: jmt::NodeKey, node: Arc<jmt::Node>) {
        self.nodes.insert(key, node);
    }

    pub fn remove(&mut self, key: &jmt::NodeKey) {
        self.nodes.remove(key);
    }
}

impl jmt::TreeReader for SimTreeStore {
    fn get_node(&self, key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<jmt::NodeKey> {
        let root = jmt::NodeKey::root(version);
        if self.nodes.contains_key(&root) {
            Some(root)
        } else {
            None
        }
    }
}
