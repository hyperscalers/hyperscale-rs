//! JMT snapshot for deferred application of block commits.

use std::sync::Arc;

use super::CollectedWrites;
use hyperscale_jmt as jmt;
use hyperscale_types::{BlockHeight, StateRoot};

/// Associates a JMT leaf node with the substate value it represents.
///
/// Enables historical state queries by linking the JMT structure
/// (which is versioned) to actual substate values.
#[derive(Debug, Clone)]
pub struct LeafSubstateKeyAssociation {
    /// The JMT leaf node key.
    pub tree_node_key: jmt::NodeKey,
    /// The substate value associated with this leaf.
    pub substate_value: Vec<u8>,
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
    pub nodes: Vec<(jmt::NodeKey, Arc<jmt::Node>)>,
    /// Keys of nodes that became stale.
    pub stale_node_keys: Vec<jmt::NodeKey>,
    /// Leaf-to-substate associations for historical queries.
    pub leaf_substate_associations: Vec<LeafSubstateKeyAssociation>,
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
            leaf_substate_associations: Vec::new(),
        }
    }
}
