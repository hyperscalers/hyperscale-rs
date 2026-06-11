//! JMT snapshot for deferred application of block commits.

use std::sync::Arc;

use hyperscale_jmt::{Key, Node, NodeKey};
use hyperscale_types::{BlockHeight, StateRoot};

use super::CollectedWrites;

/// Associates a JMT leaf (hashed key) with the raw substate storage key
/// it represents.
///
/// `jmt_leaf_key` is one-way, so this is the only route from a leaf
/// enumerated out of the tree back to the raw `(storage key, value)`
/// pair a snap-syncing joiner imports. Backends persist the mapping
/// alongside the tree: it is deterministic and immutable per key, so
/// retaining entries for deleted leaves is always safe.
#[derive(Debug, Clone)]
pub struct LeafSubstateKeyAssociation {
    /// The 32-byte hashed JMT leaf key.
    pub leaf_key: Key,
    /// The raw substate storage key, or `None` when this write deleted
    /// the leaf.
    pub storage_key: Option<Vec<u8>>,
}

/// A snapshot of JMT nodes computed during speculative execution.
///
/// Created during speculative state root computation (e.g., block verification).
/// Can be applied to the real JMT during block commit, avoiding redundant computation.
///
/// Nodes are stored as `(NodeKey, Arc<Node>)` — the canonical hydrated form.
/// Storage backends serialize at write time.
#[derive(Debug, Clone)]
#[must_use]
pub struct JmtSnapshot {
    /// The JMT root this snapshot was computed from.
    pub base_root: StateRoot,
    /// The block height this snapshot was computed from.
    pub base_height: BlockHeight,
    /// The resulting state root after applying all updates.
    pub result_root: StateRoot,
    /// The block height after applying this snapshot.
    pub new_height: BlockHeight,
    /// New tree nodes.
    pub nodes: Vec<(NodeKey, Arc<Node>)>,
    /// Keys of nodes that became stale.
    pub stale_node_keys: Vec<NodeKey>,
    /// Hashed-leaf-key → raw-storage-key associations for this
    /// computation's writes, persisted so snap-sync serving can
    /// resolve enumerated leaves back to raw substate pairs.
    pub leaf_associations: Vec<LeafSubstateKeyAssociation>,
    /// Net change to the tree's leaf (substate) count in this block.
    pub leaf_delta: i64,
}

impl JmtSnapshot {
    /// Create a snapshot from collected writes.
    pub fn from_collected_writes(
        collected: CollectedWrites,
        base_root: StateRoot,
        base_height: BlockHeight,
        result_root: StateRoot,
        new_height: BlockHeight,
    ) -> Self {
        Self {
            base_root,
            base_height,
            result_root,
            new_height,
            nodes: collected.nodes,
            stale_node_keys: collected.stale_node_keys,
            leaf_associations: collected.leaf_associations,
            leaf_delta: collected.leaf_delta,
        }
    }
}
