//! JMT snapshot for deferred application of speculative computation.
//!
//! This module provides [`JmtSnapshot`], which captures JMT nodes computed during
//! speculative state root computation. The snapshot can be cached and applied
//! during block commit, avoiding redundant recomputation.
//!
//! # Historical State Support
//!
//! When historical substate queries are enabled, the snapshot also captures
//! [`LeafSubstateKeyAssociation`] records that link JMT leaf nodes to their
//! substate values. These associations are persisted to enable querying
//! historical state at any past version (within the retention window).

use crate::jmt::{StaleTreePart, StoredTreeNodeKey, TierCollectedWrites, TreeNode};
use crate::overlay::SubstateLookup;
use crate::StateRootHash;

/// Associates a JMT leaf node with the substate value it represents.
///
/// This enables historical state queries by linking the JMT structure
/// (which is versioned) to actual substate values. Without this association,
/// the JMT only contains hashes, not the actual values.
///
/// # When Used
///
/// These associations are collected during JMT updates when historical
/// substate values are enabled. They are persisted to a dedicated column
/// family (`associated_state_tree_values` in production) and can be used
/// to retrieve the value of any substate at any historical state version.
#[derive(Debug, Clone)]
pub struct LeafSubstateKeyAssociation {
    /// The JMT leaf node key. This uniquely identifies the leaf in the
    /// versioned tree structure.
    pub tree_node_key: StoredTreeNodeKey,

    /// The substate value associated with this leaf.
    /// This is the actual data, not a hash.
    pub substate_value: Vec<u8>,
}

/// A snapshot of JMT nodes computed during speculative execution.
///
/// Created during speculative state root computation (e.g., block verification).
/// Can be applied to the real JMT during block commit, avoiding redundant computation.
///
/// # Usage
///
/// ```ignore
/// // During verification (speculative computation)
/// let (root, collected) = put_at_version(&store, parent_version, height, &updates, dispatch);
/// let snapshot = JmtSnapshot::from_collected_writes(collected, base_root, base_ver, root, height, Some(&lookup));
/// cache.insert(block_hash, snapshot);
///
/// // During commit
/// let snapshot = cache.remove(&block_hash);
/// storage.apply_jmt_snapshot(snapshot);
/// ```
///
/// # Historical State Support
///
/// When `leaf_substate_associations` is non-empty, the snapshot includes
/// associations between JMT leaf nodes and their substate values. These
/// should be persisted alongside the JMT nodes to enable historical queries.
#[derive(Debug, Clone)]
#[must_use]
pub struct JmtSnapshot {
    /// The JMT root this snapshot was computed from.
    /// Used to verify the JMT is in the expected state before applying.
    pub base_root: StateRootHash,

    /// The JMT version (= parent block height) this snapshot was computed from.
    /// Used together with base_root to verify the JMT is in the expected state.
    pub base_version: u64,

    /// The resulting state root after applying all certificate writes.
    pub result_root: StateRootHash,

    /// The new JMT version (= block height) after applying this snapshot.
    pub new_version: u64,

    /// Nodes created during speculative computation.
    /// These are inserted directly into the real JMT on apply.
    pub nodes: Vec<(StoredTreeNodeKey, TreeNode)>,

    /// Stale tree parts to prune when applying the snapshot.
    pub stale_tree_parts: Vec<StaleTreePart>,

    /// Associations between JMT leaf nodes and their substate values.
    ///
    /// Only populated when historical substate values are enabled.
    /// These should be persisted to enable historical state queries.
    pub leaf_substate_associations: Vec<LeafSubstateKeyAssociation>,
}

impl JmtSnapshot {
    /// Create a snapshot from tier-collected writes.
    ///
    /// When `lookup` is `Some`, `Unchanged` associations are resolved by looking up
    /// the actual substate value. When `None`, associations are discarded.
    pub fn from_collected_writes(
        collected: TierCollectedWrites,
        base_root: StateRootHash,
        base_version: u64,
        result_root: StateRootHash,
        new_version: u64,
        lookup: Option<&(dyn SubstateLookup + Sync)>,
    ) -> Self {
        let leaf_substate_associations = match lookup {
            Some(lookup) => collected
                .associations
                .into_iter()
                .filter_map(|a| {
                    let (tree_node_key, substate_value) =
                        a.resolve(|pk, sk| lookup.lookup_substate(pk, sk))?;
                    Some(LeafSubstateKeyAssociation {
                        tree_node_key,
                        substate_value,
                    })
                })
                .collect(),
            None => Vec::new(),
        };
        Self {
            base_root,
            base_version,
            result_root,
            new_version,
            nodes: collected.nodes,
            stale_tree_parts: collected.stale_tree_parts,
            leaf_substate_associations,
        }
    }
}
