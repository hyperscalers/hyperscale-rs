//! JVT snapshot for deferred application of speculative computation.
//!
//! This module provides [`JvtSnapshot`], which captures JVT nodes computed during
//! speculative state root computation. The snapshot can be cached and applied
//! during block commit, avoiding redundant recomputation.

use std::sync::Arc;

use crate::jmt::{CollectedWrites, JvtNode, JvtNodeKey, StoredNodeKey};
use crate::StateRootHash;

/// Associates a JVT leaf node with the substate value it represents.
///
/// This enables historical state queries by linking the JVT structure
/// (which is versioned) to actual substate values. Without this association,
/// the JVT only contains hashes, not the actual values.
#[derive(Debug, Clone)]
pub struct LeafSubstateKeyAssociation {
    /// The JVT leaf node key. This uniquely identifies the leaf in the
    /// versioned tree structure.
    pub tree_node_key: StoredNodeKey,

    /// The substate value associated with this leaf.
    /// This is the actual data, not a hash.
    pub substate_value: Vec<u8>,
}

/// A snapshot of JVT nodes computed during speculative execution.
///
/// Created during speculative state root computation (e.g., block verification).
/// Can be applied to the real JVT during block commit, avoiding redundant computation.
///
/// Nodes are stored in hydrated form `(JvtNodeKey, Arc<JvtNode>)` — the canonical
/// output of `put_at_version`. Storage backends serialize to `StoredNodeKey`/`StoredNode`
/// at write time. The cache takes the hydrated form directly.
#[derive(Debug, Clone)]
#[must_use]
pub struct JvtSnapshot {
    /// The JVT root this snapshot was computed from.
    /// Used to verify the JVT is in the expected state before applying.
    pub base_root: StateRootHash,

    /// The JVT version (= parent block height) this snapshot was computed from.
    /// Used together with base_root to verify the JVT is in the expected state.
    pub base_version: u64,

    /// The resulting state root after applying all certificate writes.
    pub result_root: StateRootHash,

    /// The new JVT version (= block height) after applying this snapshot.
    pub new_version: u64,

    /// Hydrated nodes — canonical form from the JVT computation.
    pub nodes: Vec<(JvtNodeKey, Arc<JvtNode>)>,

    /// Stale node keys for GC tracking. Stored in serialized form because
    /// they're persisted to RocksDB and read back during GC.
    pub stale_node_keys: Vec<StoredNodeKey>,

    /// Associations between JVT leaf nodes and their substate values.
    ///
    /// Only populated when historical substate values are enabled.
    /// These should be persisted to enable historical state queries.
    pub leaf_substate_associations: Vec<LeafSubstateKeyAssociation>,
}

impl JvtSnapshot {
    /// Create a snapshot from collected writes.
    pub fn from_collected_writes(
        collected: CollectedWrites,
        base_root: StateRootHash,
        base_version: u64,
        result_root: StateRootHash,
        new_version: u64,
    ) -> Self {
        Self {
            base_root,
            base_version,
            result_root,
            new_version,
            nodes: collected.nodes,
            stale_node_keys: collected.stale_node_keys,
            leaf_substate_associations: Vec::new(),
        }
    }
}
