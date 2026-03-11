// Forked from radixdlt-scrypto (originally from Aptos). Modified to use Blake3.

use super::partition_tier::*;
use super::tier_framework::*;
use super::tree_store::*;
use super::types::*;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use radix_substate_store_interface::interface::DatabaseUpdates;
use std::rc::Rc;

/// The top tier of the 3-tier JMT, corresponding to the `DbNodeKey` (aka `DbEntityKey`) part of a substate key.
/// We use the synonym "Entity" rather than "Node" to avoid confusion with TreeNodes.
///
/// Its leaf keys are `DbEntityKey` (a hash of the ReNodeId, to promote spread leaves for a performant JMT).
///
/// Its leaves have:
/// * Value Hash: The entity root hash of the corresponding nested entity tree in the `PartitionTier`
/// * Payload: The state version of the root of the corresponding nested entity tree in the `PartitionTier`
pub struct EntityTier<'s, S> {
    base_store: &'s S,
    root_version: Option<Version>,
}

impl<'s, S> EntityTier<'s, S> {
    pub fn new(base_store: &'s S, root_version: Option<Version>) -> Self {
        Self {
            base_store,
            root_version,
        }
    }

    fn stored_node_key(&self, local_key: &TreeNodeKey) -> StoredTreeNodeKey {
        StoredTreeNodeKey::unprefixed(local_key.clone())
    }
}

impl<'s, S: ReadableTreeStore> EntityTier<'s, S> {
    pub fn iter_entity_partition_tiers_from(
        &self,
        from: Option<&DbEntityKey>,
    ) -> impl Iterator<Item = PartitionTier<'s, S>> + '_ {
        iter_leaves_from(self, from).map(self.create_partition_tier_mapper())
    }

    pub fn into_iter_entity_partition_tiers_from(
        self,
        from: Option<&DbEntityKey>,
    ) -> impl Iterator<Item = PartitionTier<'s, S>> + 's {
        let partition_tier_mapper = self.create_partition_tier_mapper(); // we soon lose `self`
        iter_leaves_from(Rc::new(self), from).map(partition_tier_mapper)
    }

    pub fn get_entity_partition_tier(&self, entity_key: DbEntityKey) -> PartitionTier<'s, S> {
        let entity_root_version = self.get_persisted_leaf_payload(&entity_key);
        PartitionTier::new(self.base_store, entity_root_version, entity_key)
    }

    fn create_partition_tier_mapper(&self) -> impl FnMut(TierLeaf<Self>) -> PartitionTier<'s, S> {
        let base_store = self.base_store; // Note: This avoids capturing the `_ lifetime below.
        move |leaf| PartitionTier::new(base_store, Some(leaf.payload), leaf.key)
    }
}

impl<'s, S> StateTreeTier for EntityTier<'s, S> {
    type TypedLeafKey = DbEntityKey;
    type StoredNode = TreeNode;
    type Payload = Version;

    fn to_leaf_key(entity_key: &DbEntityKey) -> LeafKey {
        LeafKey::new(entity_key)
    }

    fn to_typed_key(leaf_key: LeafKey) -> Self::TypedLeafKey {
        leaf_key.bytes
    }

    fn root_version(&self) -> Option<Version> {
        self.root_version
    }
}

impl<'s, S: ReadableTreeStore> ReadableTier for EntityTier<'s, S> {
    fn get_local_node(&self, local_key: &TreeNodeKey) -> Option<TreeNode> {
        // No prefixing needed in top layer
        self.base_store.get_node(&self.stored_node_key(local_key))
    }
}

impl<'s, S: ReadableTreeStore + Sync> EntityTier<'s, S> {
    pub fn put_entity_updates<D: Dispatch>(
        &mut self,
        next_version: Version,
        updates: &DatabaseUpdates,
        dispatch: &D,
    ) -> (Option<Hash>, TierCollectedWrites) {
        // Phase 1: parallel entity processing.
        // Explicit reborrow of &mut self as &self — required because the Fn
        // closure sent to map_local cannot capture &mut self.
        let self_ref: &Self = &*self;
        let entities: Vec<_> = updates.node_updates.iter().collect();
        let results: Vec<_> = dispatch.map_local(&entities, |(entity_key, entity_db_updates)| {
            let mut pt = self_ref.get_entity_partition_tier((*entity_key).clone());
            let (root, collected) =
                pt.apply_entity_updates(next_version, entity_db_updates, dispatch);
            (*entity_key, root.map(|h| (h, next_version)), collected)
        });

        // Merge collected writes from all entities.
        let mut collected = TierCollectedWrites::default();
        let leaf_updates: Vec<_> = results
            .into_iter()
            .map(|(ek, root, writes)| {
                collected.merge(writes);
                (ek, root)
            })
            .collect();

        // Phase 2: entity-tier JMT.
        let update_batch = self.generate_tier_update_batch(
            next_version,
            leaf_updates.iter().map(|(k, v)| (*k, *v)),
            dispatch,
        );

        // Phase 3: collect entity-tier writes (&mut self — shared borrow has been released).
        collected.collect_from_tier_batch(&update_batch, |k| self.stored_node_key(k));
        self.root_version = Some(update_batch.new_version);
        (update_batch.new_root_hash, collected)
    }
}
