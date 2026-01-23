//! Overlay tree store for speculative JMT computation.
//!
//! This module provides `OverlayTreeStore`, which wraps a base tree store and
//! captures all writes without modifying the underlying storage. This enables
//! speculative state root computation for block validation.
//!
//! The overlay can be converted into a [`JmtSnapshot`] which captures the computed
//! nodes for later application to the real JMT during block commit. This avoids
//! recomputing the same JMT updates twice (once during verification, once during commit).

use crate::{
    AssociatedSubstateValue, DbPartitionKey, DbSortKey, ReadableTreeStore, StaleTreePart,
    StateRootHash, StoredTreeNodeKey, TreeNode, TypedInMemoryTreeStore, WriteableTreeStore,
};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// A snapshot of JMT nodes computed during speculative execution.
///
/// Created from an [`OverlayTreeStore`] after computing a speculative state root.
/// Can be applied to the real JMT during block commit, avoiding redundant computation.
///
/// # Usage
///
/// ```ignore
/// // During verification
/// let overlay = OverlayTreeStore::new(&jmt);
/// let root = compute_root(&overlay, writes);
/// let snapshot = overlay.into_snapshot(base_root, root, num_certs);
/// cache.insert(block_hash, snapshot);
///
/// // During commit
/// let snapshot = cache.remove(&block_hash);
/// jmt.apply_snapshot(snapshot);
/// ```
#[derive(Debug, Clone)]
pub struct JmtSnapshot {
    /// The JMT root this snapshot was computed from.
    /// Used to verify the JMT is in the expected state before applying.
    pub base_root: StateRootHash,

    /// The JMT version this snapshot was computed from.
    /// Used together with base_root to verify the JMT is in the expected state.
    pub base_version: u64,

    /// The resulting state root after applying all certificate writes.
    pub result_root: StateRootHash,

    /// Number of JMT versions this snapshot advances.
    /// Equal to the number of certificates processed.
    pub num_versions: u64,

    /// Nodes created during speculative computation.
    /// These are inserted directly into the real JMT on apply.
    pub nodes: HashMap<StoredTreeNodeKey, TreeNode>,
}

/// An overlay tree store that captures writes without modifying the underlying store.
///
/// Reads check the overlay first, then fall through to the base store.
/// Writes only go to the overlay and are discarded when the overlay is dropped.
///
/// This enables speculative JMT root computation where we need to compute what
/// the root WOULD be without actually persisting any nodes. Multiple concurrent
/// speculative computations can run without corrupting each other.
///
/// # Example
///
/// ```ignore
/// use hyperscale_engine::{OverlayTreeStore, put_at_next_version, TypedInMemoryTreeStore};
///
/// let base_store = TypedInMemoryTreeStore::new();
/// let overlay = OverlayTreeStore::new(&base_store);
///
/// // Compute speculative root - writes go to overlay only
/// let new_root = put_at_next_version(&overlay, Some(current_version), &updates);
///
/// // overlay is dropped here - base_store is unchanged
/// ```
pub struct OverlayTreeStore<'a> {
    /// The underlying tree store (read-only access).
    base: &'a TypedInMemoryTreeStore,

    /// Overlay of node insertions. Maps key -> node.
    /// Nodes inserted during speculative computation are stored here.
    inserted_nodes: RefCell<HashMap<StoredTreeNodeKey, TreeNode>>,

    /// Set of keys that have been marked as stale (deleted) in the overlay.
    /// Lookups for these keys return None even if they exist in the base store.
    stale_keys: RefCell<HashSet<StoredTreeNodeKey>>,
}

impl<'a> OverlayTreeStore<'a> {
    /// Create a new overlay wrapping the given base store.
    pub fn new(base: &'a TypedInMemoryTreeStore) -> Self {
        Self {
            base,
            inserted_nodes: RefCell::new(HashMap::new()),
            stale_keys: RefCell::new(HashSet::new()),
        }
    }

    /// Convert this overlay into a snapshot that can be applied later.
    ///
    /// Consumes the overlay and extracts the captured nodes into a [`JmtSnapshot`].
    /// The snapshot can be cached and applied to the real JMT during block commit,
    /// avoiding redundant recomputation of the same tree updates.
    ///
    /// # Arguments
    ///
    /// * `base_root` - The JMT root this computation started from
    /// * `base_version` - The JMT version this computation started from
    /// * `result_root` - The computed state root after applying all writes
    /// * `num_versions` - Number of JMT versions advanced (typically = number of certificates)
    pub fn into_snapshot(
        self,
        base_root: StateRootHash,
        base_version: u64,
        result_root: StateRootHash,
        num_versions: u64,
    ) -> JmtSnapshot {
        JmtSnapshot {
            base_root,
            base_version,
            result_root,
            num_versions,
            nodes: self.inserted_nodes.into_inner(),
        }
    }
}

impl<'a> ReadableTreeStore for OverlayTreeStore<'a> {
    fn get_node(&self, key: &StoredTreeNodeKey) -> Option<TreeNode> {
        // Check if the key was marked as stale (deleted)
        if self.stale_keys.borrow().contains(key) {
            return None;
        }

        // Check overlay first
        if let Some(node) = self.inserted_nodes.borrow().get(key) {
            return Some(node.clone());
        }

        // Fall through to base store
        self.base.get_node(key)
    }
}

impl<'a> WriteableTreeStore for OverlayTreeStore<'a> {
    fn insert_node(&self, key: StoredTreeNodeKey, node: TreeNode) {
        // Remove from stale set if it was previously marked stale
        self.stale_keys.borrow_mut().remove(&key);
        // Insert into overlay
        self.inserted_nodes.borrow_mut().insert(key, node);
    }

    fn associate_substate(
        &self,
        _state_tree_leaf_key: &StoredTreeNodeKey,
        _partition_key: &DbPartitionKey,
        _sort_key: &DbSortKey,
        _substate_value: AssociatedSubstateValue,
    ) {
        // No-op for speculative computation.
        // Substate associations are only needed for historical queries.
    }

    fn record_stale_tree_part(&self, part: StaleTreePart) {
        // Mark nodes as stale in the overlay so subsequent reads return None.
        //
        // NOTE: For `StaleTreePart::Subtree`, we only mark the root as stale rather than
        // recursively walking the entire subtree. This is correct for speculative computation
        // because:
        //
        // 1. Stale nodes are from the PREVIOUS version of the tree (before our speculative update)
        // 2. The speculative computation creates NEW nodes at a NEW version number
        // 3. Reads during `put_at_next_version` use version-qualified keys: (version, nibble_path)
        // 4. New nodes are stored at version N+1, stale nodes were at version N
        // 5. Therefore, reads for child nodes will either:
        //    a) Find them in the overlay (newly created) - correct
        //    b) Find them in the base store at their old version - correct (we're reading
        //       parent chain nodes that weren't modified)
        //    c) Not find them because the whole subtree was replaced - also correct
        //
        // The real tree store DOES need full recursive deletion for garbage collection,
        // but the overlay is temporary and discarded after computing the speculative root.
        match part {
            StaleTreePart::Node(key) => {
                self.stale_keys.borrow_mut().insert(key);
            }
            StaleTreePart::Subtree(root_key) => {
                // Mark only the subtree root as stale. See explanation above for why
                // recursive deletion is not needed for speculative computation.
                self.stale_keys.borrow_mut().insert(root_key);
            }
        }
    }
}
