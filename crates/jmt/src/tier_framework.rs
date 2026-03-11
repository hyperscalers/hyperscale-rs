// Forked from radixdlt-scrypto (originally from Aptos). Modified to use Blake3.

use core::iter;
use std::collections::VecDeque;
use std::mem;
use std::ops::Deref;
use std::sync::Arc;

use super::jellyfish::JellyfishMerkleTree;
use super::jellyfish::TreeUpdateBatch;
use super::tree_store::*;
use super::types::*;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use radix_common::prelude::DatabaseUpdateRef;
use radix_substate_store_interface::interface::{
    DbNodeKey, DbPartitionKey, DbSortKey, PartitionDatabaseUpdates,
};

// Rename for this file to avoid confusion with TreeNodes!
pub(crate) type DbEntityKey = DbNodeKey;

pub const TIER_SEPARATOR: u8 = b'_';

pub trait StoredNode {
    type Payload;

    #[allow(clippy::wrong_self_convention)]
    fn into_jmt_node(&self, key: &TreeNodeKey) -> Node<Self::Payload>;
    fn from_jmt_node(node: &Node<Self::Payload>, key: &TreeNodeKey) -> Self;
}

pub trait StateTreeTier {
    type TypedLeafKey;
    type StoredNode: StoredNode<Payload = Self::Payload>;
    type Payload: Clone;

    fn to_leaf_key(typed_key: &Self::TypedLeafKey) -> LeafKey;
    fn to_typed_key(leaf_key: LeafKey) -> Self::TypedLeafKey;
    fn root_version(&self) -> Option<Version>;
}

pub trait ReadableTier: StateTreeTier {
    /// Gets node by key, if it exists.
    fn get_local_node(&self, local_key: &TreeNodeKey) -> Option<Self::StoredNode>;

    fn jmt(&self) -> JellyfishMerkleTree<'_, Self, Self::Payload> {
        JellyfishMerkleTree::new(self)
    }

    fn get_persisted_leaf_payload(&self, key: &Self::TypedLeafKey) -> Option<Self::Payload> {
        let root_version = self.root_version()?;

        let leaf_key = Self::to_leaf_key(key);

        let (leaf_node_data, _proof) = self.jmt().get_with_proof(&leaf_key, root_version).unwrap();
        leaf_node_data.map(|(_hash, payload, _version)| payload)
    }
}

pub struct TierLeaf<T: StateTreeTier> {
    pub key: T::TypedLeafKey,
    pub value_hash: Hash,
    pub payload: T::Payload,

    /// A local tree node key of the leaf (i.e. expressed within tier [`T`]).
    pub local_key: TreeNodeKey,
}

impl<T: StateTreeTier<Payload = Version>> TierLeaf<T> {
    pub fn new(local_key: TreeNodeKey, leaf: TreeLeafNode) -> Self {
        let TreeLeafNode {
            key_suffix,
            value_hash,
            last_hash_change_version,
        } = leaf;
        let full_key = NibblePath::from_iter(
            local_key
                .nibble_path()
                .nibbles()
                .chain(key_suffix.nibbles()),
        );
        Self {
            key: T::to_typed_key(LeafKey::new(full_key.bytes())),
            value_hash,
            payload: last_hash_change_version,
            local_key,
        }
    }
}

/// Returns a lexicographically-sorted iterator of all the leaves existing at the given `tier`'s
/// current version and greater or equal to the given `from_key`.
pub fn iter_leaves_from<'t, T>(
    tier: impl Deref<Target = T> + Clone + 't,
    from_key: Option<&T::TypedLeafKey>,
) -> Box<dyn Iterator<Item = TierLeaf<T>> + 't>
where
    T: ReadableTier<StoredNode = TreeNode, Payload = Version> + 't,
    T::TypedLeafKey: 't,
{
    tier.root_version()
        .map(|version| {
            recurse_until_leaves(
                tier,
                TreeNodeKey::new_empty_path(version),
                from_key
                    .map(|from| T::to_leaf_key(from).into_path().nibbles().collect())
                    .unwrap_or_else(VecDeque::new),
            )
        })
        .unwrap_or_else(|| Box::new(iter::empty()))
}

/// Returns a lexicographically-sorted iterator of all the leaves located below the `at_key` node
/// and having [`NibblePath`]s greater or equal to the given `from_nibbles`.
pub fn recurse_until_leaves<'t, T>(
    tier: impl Deref<Target = T> + Clone + 't,
    at_key: TreeNodeKey,
    from_nibbles: VecDeque<Nibble>,
) -> Box<dyn Iterator<Item = TierLeaf<T>> + 't>
where
    T: ReadableTier<StoredNode = TreeNode, Payload = Version> + 't,
    T::TypedLeafKey: 't,
{
    let Some(node) = tier.get_local_node(&at_key) else {
        panic!("{:?} referenced but not found in the storage", at_key);
    };
    match node {
        TreeNode::Internal(internal) => {
            let mut child_from_nibbles = from_nibbles;
            let from_nibble = child_from_nibbles.pop_front();
            Box::new(
                internal
                    .children
                    .into_iter()
                    .filter(move |child| Some(child.nibble) >= from_nibble)
                    .flat_map(move |child| {
                        let child_key = at_key.gen_child_node_key(child.version, child.nibble);
                        let child_from_nibbles = if Some(child.nibble) == from_nibble {
                            mem::take(&mut child_from_nibbles)
                        } else {
                            VecDeque::new()
                        };
                        recurse_until_leaves(tier.clone(), child_key, child_from_nibbles)
                    }),
            )
        }
        TreeNode::Leaf(leaf) => Box::new(
            Some(leaf)
                .filter(move |leaf| leaf.key_suffix.nibbles().ge(from_nibbles))
                .map(|leaf| TierLeaf::new(at_key, leaf))
                .into_iter(),
        ),
        TreeNode::Null => Box::new(iter::empty()),
    }
}

impl<R: ReadableTier + ?Sized> TreeReader<<R::StoredNode as StoredNode>::Payload> for R {
    fn get_node_option(
        &self,
        node_key: &TreeNodeKey,
    ) -> Result<Option<Node<<R::StoredNode as StoredNode>::Payload>>, StorageError> {
        Ok(self
            .get_local_node(node_key)
            .map(|tree_node| tree_node.into_jmt_node(node_key)))
    }
}

pub struct TierUpdateBatch<P> {
    pub new_version: Version,
    pub new_root_hash: Option<Hash>,
    pub tree_update_batch: TreeUpdateBatch<P>,
}

// ─── Batch-collection types ─────────────────────────────────────────────

/// Writes collected during tier computation, to be applied after the parallel phase.
///
/// Each parallel task (entity, partition) builds its own `TierCollectedWrites` and returns
/// it. The caller merges all results sequentially via [`merge`], matching the pattern
/// already used by `TreeUpdateBatch::merge()` in `jellyfish.rs`.

#[derive(Default)]
pub struct TierCollectedWrites {
    pub nodes: Vec<(StoredTreeNodeKey, TreeNode)>,
    pub stale_tree_parts: Vec<StaleTreePart>,
    pub associations: Vec<CollectedAssociation>,
}

/// A JMT leaf → substate association collected during tier computation.
pub struct CollectedAssociation {
    pub tree_node_key: StoredTreeNodeKey,
    pub partition_key: Arc<DbPartitionKey>,
    pub sort_key: DbSortKey,
    pub value: CollectedSubstateValue,
}

/// The substate value associated with a collected JMT leaf.
pub enum CollectedSubstateValue {
    /// The substate was upserted — value bytes included.
    Upserted(Vec<u8>),
    /// The substate was unchanged (tree restructuring created a new leaf).
    Unchanged,
}

impl CollectedAssociation {
    /// Resolve this association's value, using `lookup` for `Unchanged` entries.
    ///
    /// Returns `Some((tree_node_key, value_bytes))` if the value was resolved,
    /// or `None` if the lookup returned `None` for an `Unchanged` entry.
    pub fn resolve(
        self,
        lookup: impl FnOnce(&DbPartitionKey, &DbSortKey) -> Option<Vec<u8>>,
    ) -> Option<(StoredTreeNodeKey, Vec<u8>)> {
        let value = match self.value {
            CollectedSubstateValue::Upserted(bytes) => bytes,
            CollectedSubstateValue::Unchanged => lookup(&self.partition_key, &self.sort_key)?,
        };
        Some((self.tree_node_key, value))
    }
}

impl TierCollectedWrites {
    /// Merge another `TierCollectedWrites` into this one (append all vecs).
    pub fn merge(&mut self, mut other: Self) {
        self.nodes.append(&mut other.nodes);
        self.stale_tree_parts.append(&mut other.stale_tree_parts);
        self.associations.append(&mut other.associations);
    }

    /// Collect nodes and stale entries from a `TierUpdateBatch`, converting local
    /// tree-node keys to global `StoredTreeNodeKey`s via the provided closure.
    pub fn collect_from_tier_batch(
        &mut self,
        batch: &TierUpdateBatch<Version>,
        to_global_key: impl Fn(&TreeNodeKey) -> StoredTreeNodeKey,
    ) {
        for (key, node) in batch.tree_update_batch.node_batch.iter().flatten() {
            self.nodes
                .push((to_global_key(key), TreeNode::from_jmt_node(node, key)));
        }
        for stale_node in batch
            .tree_update_batch
            .stale_node_index_batch
            .iter()
            .flatten()
        {
            self.stale_tree_parts
                .push(StaleTreePart::Node(to_global_key(&stale_node.node_key)));
        }
    }

    /// Collect substate-tier leaf associations from a `TreeUpdateBatch`, correlating
    /// newly-created leaf nodes with their substate updates.
    pub fn collect_associations<T: StateTreeTier<TypedLeafKey = DbSortKey, Payload = Version>>(
        &mut self,
        updates: &PartitionDatabaseUpdates,
        tree_update_batch: &TreeUpdateBatch<Version>,
        partition_key: &Arc<DbPartitionKey>,
        to_global_key: impl Fn(&TreeNodeKey) -> StoredTreeNodeKey,
    ) {
        for (key, node) in tree_update_batch.node_batch.iter().flatten() {
            let Node::Leaf(leaf_node) = &node else {
                continue;
            };
            let sort_key = T::to_typed_key(leaf_node.leaf_key().clone());
            let value = updates
                .get_substate_change(&sort_key)
                .map(|change| match change {
                    DatabaseUpdateRef::Set(value) => {
                        // Copies value bytes into owned Vec. This is a deliberate
                        // trade-off: the parallel dispatch model requires owned data
                        // (Send across threads), so we can't borrow from the input.
                        CollectedSubstateValue::Upserted(value.to_vec())
                    }
                    DatabaseUpdateRef::Delete => {
                        panic!("deletes are not represented by new tree leafs")
                    }
                })
                .unwrap_or(CollectedSubstateValue::Unchanged);
            self.associations.push(CollectedAssociation {
                tree_node_key: to_global_key(key),
                partition_key: Arc::clone(partition_key),
                sort_key,
                value,
            });
        }
    }

    /// Apply collected nodes and stale parts to a `WriteableTreeStore`,
    /// returning the associations for the caller to resolve separately.
    pub fn apply_to(self, store: &(impl WriteableTreeStore + ?Sized)) -> Vec<CollectedAssociation> {
        for (key, node) in self.nodes {
            store.insert_node(key, node);
        }
        for part in self.stale_tree_parts {
            store.record_stale_tree_part(part);
        }
        self.associations
    }
}

// ─── ReadableTier extension: generate_tier_update_batch ─────────────────

pub trait ReadableTierExt: ReadableTier {
    fn generate_tier_update_batch<'a, D: Dispatch>(
        &self,
        new_version: Version,
        leaf_updates: impl Iterator<Item = (&'a Self::TypedLeafKey, Option<(Hash, Self::Payload)>)>,
        dispatch: &D,
    ) -> TierUpdateBatch<Self::Payload>
    where
        Self: Sync,
        Self::Payload: Send + Sync,
        <Self as StateTreeTier>::TypedLeafKey: 'a,
    {
        let value_set = leaf_updates
            .map(|(key, option)| (Self::to_leaf_key(key), option))
            .collect();
        let (root_hash, update_batch) = self
            .jmt()
            .batch_put_value_set(value_set, None, self.root_version(), new_version, dispatch)
            .expect("error while reading tree during put");

        let root_hash = if root_hash == SPARSE_MERKLE_PLACEHOLDER_HASH {
            None
        } else {
            Some(root_hash)
        };

        TierUpdateBatch {
            new_version,
            tree_update_batch: update_batch,
            new_root_hash: root_hash,
        }
    }
}

impl<T: ReadableTier> ReadableTierExt for T {}
