// Forked from radixdlt-scrypto (originally from Aptos). Modified to use Blake3.

use super::substate_tier::*;
use super::tier_framework::*;
use super::tree_store::*;
use super::types::*;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use radix_substate_store_interface::interface::NodeDatabaseUpdates;
use radix_substate_store_interface::interface::*;
use std::rc::Rc;

/// The middle tier of the 3-tier JMT, corresponding to the partition part of a substate key.
///
/// Its leaf keys are partition numbers (a single byte, two nibbles).
///
/// Its leaves have:
/// * Value Hash: The partition root hash of the corresponding nested partition tree in the `SubstateTier`
/// * Payload: The state version of the root of the corresponding nested partition tree in the `SubstateTier`
pub struct PartitionTier<'s, S> {
    base_store: &'s S,
    root_version: Option<Version>,
    entity_key: DbEntityKey,
    tree_node_prefix: Vec<u8>,
}

impl<'s, S> StateTreeTier for PartitionTier<'s, S> {
    type TypedLeafKey = DbPartitionNum;
    type StoredNode = TreeNode;
    type Payload = Version;

    fn to_leaf_key(partition: &DbPartitionNum) -> LeafKey {
        LeafKey::new(&[*partition])
    }

    fn to_typed_key(leaf_key: LeafKey) -> DbPartitionNum {
        leaf_key.bytes[0]
    }

    fn root_version(&self) -> Option<Version> {
        self.root_version
    }
}

impl<'s, S> PartitionTier<'s, S> {
    pub fn new(base_store: &'s S, root_version: Option<Version>, entity_key: DbEntityKey) -> Self {
        let mut tree_node_prefix = Vec::with_capacity(entity_key.len() + 1);
        tree_node_prefix.extend_from_slice(&entity_key);
        tree_node_prefix.push(TIER_SEPARATOR);

        Self {
            base_store,
            root_version,
            entity_key,
            tree_node_prefix,
        }
    }

    pub fn entity_key(&self) -> &DbEntityKey {
        &self.entity_key
    }

    fn stored_node_key(&self, local_key: &TreeNodeKey) -> StoredTreeNodeKey {
        StoredTreeNodeKey::prefixed(&self.tree_node_prefix, local_key)
    }
}

impl<'s, S: ReadableTreeStore> PartitionTier<'s, S> {
    pub fn iter_partition_substate_tiers_from(
        &self,
        from: Option<DbPartitionNum>,
    ) -> impl Iterator<Item = SubstateTier<'s, S>> + '_ {
        iter_leaves_from(self, from.as_ref()).map(self.create_substate_tier_mapper())
    }

    pub fn into_iter_partition_substate_tiers_from(
        self,
        from: Option<DbPartitionNum>,
    ) -> impl Iterator<Item = SubstateTier<'s, S>> + 's {
        let substate_tier_mapper = self.create_substate_tier_mapper(); // we soon lose `self`
        iter_leaves_from(Rc::new(self), from.as_ref()).map(substate_tier_mapper)
    }

    pub fn get_partition_substate_tier(&self, partition: DbPartitionNum) -> SubstateTier<'s, S> {
        let partition_root_version = self.get_persisted_leaf_payload(&partition);
        SubstateTier::new(
            self.base_store,
            partition_root_version,
            self.entity_key.clone(),
            partition,
        )
    }

    fn create_substate_tier_mapper(&self) -> impl FnMut(TierLeaf<Self>) -> SubstateTier<'s, S> {
        let base_store = self.base_store; // Note: This avoids capturing the `_ lifetime below.
        let entity_key = self.entity_key.clone(); // Note: This is the only reason for `move` below.
        move |leaf| SubstateTier::new(base_store, Some(leaf.payload), entity_key.clone(), leaf.key)
    }
}

impl<'s, S: ReadableTreeStore> ReadableTier for PartitionTier<'s, S> {
    fn get_local_node(&self, local_key: &TreeNodeKey) -> Option<TreeNode> {
        self.base_store.get_node(&self.stored_node_key(local_key))
    }
}

impl<'s, S: ReadableTreeStore + Sync> PartitionTier<'s, S> {
    pub(crate) fn apply_entity_updates<D: Dispatch>(
        &mut self,
        next_version: Version,
        updates: &NodeDatabaseUpdates,
        dispatch: &D,
    ) -> (Option<Hash>, TierCollectedWrites) {
        // Phase 1: parallel partition processing.
        let self_ref: &Self = &*self;
        let partitions: Vec<_> = updates.partition_updates.iter().collect();
        let results: Vec<_> = dispatch.map_local(&partitions, |(partition, part_updates)| {
            let mut st = self_ref.get_partition_substate_tier(**partition);
            let (root, collected) =
                st.apply_partition_updates(next_version, part_updates, dispatch);
            (*partition, root.map(|h| (h, next_version)), collected)
        });

        // Merge collected writes from all partitions.
        let mut collected = TierCollectedWrites::default();
        let leaf_updates: Vec<_> = results
            .into_iter()
            .map(|(pk, root, writes)| {
                collected.merge(writes);
                (pk, root)
            })
            .collect();

        // Phase 2: partition-tier JMT.
        let update_batch = self.generate_tier_update_batch(
            next_version,
            leaf_updates.iter().map(|(k, v)| (*k, *v)),
            dispatch,
        );

        // Phase 3: collect partition-tier writes.
        collected.collect_from_tier_batch(&update_batch, |k| self.stored_node_key(k));
        self.root_version = Some(update_batch.new_version);
        (update_batch.new_root_hash, collected)
    }
}
