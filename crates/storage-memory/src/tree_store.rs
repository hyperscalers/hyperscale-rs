//! Simple in-memory JVT tree store for simulation.
//!
//! Implements `jvt::TreeReader` directly, replacing the old
//! `TypedInMemoryTreeStore` wrapper that used stored/serialized node types.

use std::collections::HashMap;
use std::sync::Arc;

use jellyfish_verkle_tree as jvt;

/// Simple in-memory tree store that implements `jvt::TreeReader`.
///
/// Stores hydrated JVT nodes directly (no serialization layer).
/// Thread safety is handled by the outer `RwLock<SharedState>`.
pub struct SimTreeStore {
    nodes: HashMap<jvt::NodeKey, Arc<jvt::Node>>,
}

impl SimTreeStore {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: jvt::NodeKey, node: Arc<jvt::Node>) {
        self.nodes.insert(key, node);
    }

    pub fn remove(&mut self, key: &jvt::NodeKey) {
        self.nodes.remove(key);
    }
}

impl jvt::TreeReader for SimTreeStore {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        self.nodes.get(key).cloned()
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        let root = jvt::NodeKey::root(version);
        if self.nodes.contains_key(&root) {
            Some(root)
        } else {
            None
        }
    }
}
