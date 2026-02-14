//! Overlay tree store for speculative JMT computation.
//!
//! Provides [`OverlayTreeStore`], which captures JMT writes without modifying
//! the underlying store. Used by both in-memory and RocksDB storage backends
//! for speculative state root computation.

use crate::jmt::{
    AssociatedSubstateValue, ReadableTreeStore, StaleTreePart, StoredTreeNodeKey, TreeNode,
    WriteableTreeStore,
};
use crate::{DbPartitionKey, DbSortKey, JmtSnapshot, LeafSubstateKeyAssociation, StateRootHash};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Trait for looking up substate values during overlay computation.
///
/// Used to look up unchanged substate values when collecting historical
/// leaf-to-substate associations. The overlay needs this to record what
/// value a JMT leaf node points to, even when that value hasn't changed.
pub trait SubstateLookup {
    /// Look up a substate value by partition key and sort key.
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>>;
}

/// Adapter to use a `&dyn SubstateDatabase` as a [`SubstateLookup`].
///
/// This is needed because Rust can't coerce `dyn SubstateDatabase` to
/// `dyn SubstateLookup` even with a blanket impl.
pub struct SubstateDbLookup<'a>(pub &'a dyn crate::SubstateDatabase);

impl SubstateLookup for SubstateDbLookup<'_> {
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        self.0.get_raw_substate_by_db_key(partition_key, sort_key)
    }
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
/// # Type Parameter
/// `B` is the base store type, which must implement `ReadableTreeStore`. This is
/// typically either a direct storage reference or a snapshot-based store for
/// isolation from concurrent writes.
///
/// # Historical State Support
///
/// When a substate lookup is provided via [`with_substate_lookup`], the overlay
/// collects associations between JMT leaf nodes and their substate values.
/// This enables historical state queries.
pub struct OverlayTreeStore<'a, B: ReadableTreeStore> {
    /// The underlying store (read-only access).
    base: &'a B,

    /// Overlay of node insertions. Maps key -> node.
    inserted_nodes: RefCell<HashMap<StoredTreeNodeKey, TreeNode>>,

    /// Set of keys that have been marked as stale (deleted) in the overlay.
    stale_keys: RefCell<HashSet<StoredTreeNodeKey>>,

    /// Stale tree parts for pruning on commit.
    stale_tree_parts: RefCell<Vec<StaleTreePart>>,

    /// Associations between JMT leaf nodes and their substate values.
    leaf_substate_associations: RefCell<Vec<LeafSubstateKeyAssociation>>,

    /// Optional substate lookup for collecting historical associations.
    substate_lookup: Option<&'a dyn SubstateLookup>,
}

impl<'a, B: ReadableTreeStore> OverlayTreeStore<'a, B> {
    /// Create a new overlay wrapping the given base store.
    ///
    /// Historical value collection is disabled by default. Use
    /// [`with_substate_lookup`] to enable it.
    pub fn new(base: &'a B) -> Self {
        Self {
            base,
            inserted_nodes: RefCell::new(HashMap::new()),
            stale_keys: RefCell::new(HashSet::new()),
            stale_tree_parts: RefCell::new(Vec::new()),
            leaf_substate_associations: RefCell::new(Vec::new()),
            substate_lookup: None,
        }
    }

    /// Enable historical value collection with a substate lookup.
    ///
    /// When enabled, the overlay will collect associations between JMT leaf nodes
    /// and their substate values. For unchanged values, the lookup is used to
    /// retrieve the current value.
    pub fn with_substate_lookup(mut self, lookup: &'a dyn SubstateLookup) -> Self {
        self.substate_lookup = Some(lookup);
        self
    }

    /// Convert this overlay into a snapshot that can be applied later.
    ///
    /// Consumes the overlay and extracts the captured nodes into a [`JmtSnapshot`].
    /// The snapshot can be cached and applied to the real JMT during block commit,
    /// avoiding redundant recomputation of the same tree updates.
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
            stale_tree_parts: self.stale_tree_parts.into_inner(),
            leaf_substate_associations: self.leaf_substate_associations.into_inner(),
        }
    }
}

impl<B: ReadableTreeStore> ReadableTreeStore for OverlayTreeStore<'_, B> {
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

impl<B: ReadableTreeStore> WriteableTreeStore for OverlayTreeStore<'_, B> {
    fn insert_node(&self, key: StoredTreeNodeKey, node: TreeNode) {
        // Remove from stale set if it was previously marked stale
        self.stale_keys.borrow_mut().remove(&key);
        // Insert into overlay
        self.inserted_nodes.borrow_mut().insert(key, node);
    }

    fn associate_substate(
        &self,
        state_tree_leaf_key: &StoredTreeNodeKey,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
        substate_value: AssociatedSubstateValue,
    ) {
        let Some(lookup) = self.substate_lookup else {
            return;
        };

        let value = match substate_value {
            AssociatedSubstateValue::Upserted(v) => v.to_vec(),
            AssociatedSubstateValue::Unchanged => {
                // Look up the unchanged value from the substate lookup.
                // This may fail if the substate was created earlier in the same batch
                // (not yet persisted). In that case, skip the association -
                // we'll have captured it when it was originally created.
                match lookup.lookup_substate(partition_key, sort_key) {
                    Some(v) => v,
                    None => return,
                }
            }
        };

        self.leaf_substate_associations
            .borrow_mut()
            .push(LeafSubstateKeyAssociation {
                tree_node_key: state_tree_leaf_key.clone(),
                substate_value: value,
            });
    }

    fn record_stale_tree_part(&self, part: StaleTreePart) {
        // INVARIANT: JMT traversal is top-down. Marking the subtree root as stale
        // causes `get_node` to return None for it, which prevents the JMT from
        // ever traversing into child nodes. Therefore, tracking only the root key
        // is sufficient to make the entire subtree invisible.
        let key = match &part {
            StaleTreePart::Node(k) => k.clone(),
            StaleTreePart::Subtree(k) => k.clone(),
        };
        self.stale_keys.borrow_mut().insert(key);
        self.stale_tree_parts.borrow_mut().push(part);
    }
}
