// Forked from radixdlt-scrypto (originally from Aptos). Modified to use Blake3.

use super::tier_framework::*;
use super::tree_store::*;
use super::types::*;
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
use radix_substate_store_interface::interface::*;
use std::rc::Rc;
use std::sync::Arc;

/// The bottom tier of the 3-tier JMT, corresponding to the `DbSortKey` part of a substate key.
///
/// Its leaf keys are `DbSortKeys` (an ordered key for substates under a partition).
///
/// Its leaves have:
/// * Value Hash: The blake3 hash of the substate value
/// * Payload: The state version when the substate value was set
pub struct SubstateTier<'s, S> {
    base_store: &'s S,
    root_version: Option<Version>,
    partition_key: DbPartitionKey,
    tree_node_prefix: Vec<u8>,
}

impl<'s, S> SubstateTier<'s, S> {
    pub fn new(
        base_store: &'s S,
        root_version: Option<Version>,
        entity_key: DbEntityKey,
        partition: DbPartitionNum,
    ) -> Self {
        let mut tree_node_prefix = Vec::with_capacity(entity_key.len() + 3);
        tree_node_prefix.extend_from_slice(&entity_key);
        tree_node_prefix.push(TIER_SEPARATOR);
        tree_node_prefix.push(partition);
        tree_node_prefix.push(TIER_SEPARATOR);

        Self {
            base_store,
            root_version,
            partition_key: DbPartitionKey {
                node_key: entity_key,
                partition_num: partition,
            },
            tree_node_prefix,
        }
    }

    pub fn partition_key(&self) -> &DbPartitionKey {
        &self.partition_key
    }

    fn stored_node_key(&self, local_key: &TreeNodeKey) -> StoredTreeNodeKey {
        StoredTreeNodeKey::prefixed(&self.tree_node_prefix, local_key)
    }
}

impl<'s, S> StateTreeTier for SubstateTier<'s, S> {
    type TypedLeafKey = DbSortKey;
    type StoredNode = TreeNode;
    type Payload = Version;

    fn to_leaf_key(sort_key: &DbSortKey) -> LeafKey {
        LeafKey::new(&sort_key.0)
    }

    fn to_typed_key(leaf_key: LeafKey) -> DbSortKey {
        DbSortKey(leaf_key.bytes)
    }

    fn root_version(&self) -> Option<Version> {
        self.root_version
    }
}

impl<'s, S: ReadableTreeStore> ReadableTier for SubstateTier<'s, S> {
    fn get_local_node(&self, local_key: &TreeNodeKey) -> Option<TreeNode> {
        self.base_store.get_node(&self.stored_node_key(local_key))
    }
}

impl<'s, S: ReadableTreeStore> SubstateTier<'s, S> {
    pub fn get_substate_summary(&self, sort_key: &DbSortKey) -> Option<SubstateSummary> {
        self.iter_substate_summaries_from(Some(sort_key))
            .next()
            .filter(|least_ge_summary| &least_ge_summary.sort_key == sort_key)
    }

    pub fn iter_substate_summaries_from(
        &self,
        from: Option<&DbSortKey>,
    ) -> impl Iterator<Item = SubstateSummary> + '_ {
        iter_leaves_from(self, from).map(self.create_summary_mapper())
    }

    pub fn into_iter_substate_summaries_from(
        self,
        from: Option<&DbSortKey>,
    ) -> impl Iterator<Item = SubstateSummary> + 's {
        let summary_mapper = self.create_summary_mapper(); // we soon lose `self`
        iter_leaves_from(Rc::new(self), from).map(summary_mapper)
    }

    fn create_summary_mapper(&self) -> impl FnMut(TierLeaf<Self>) -> SubstateSummary {
        let tree_node_prefix = self.tree_node_prefix.clone();
        move |leaf| SubstateSummary {
            sort_key: leaf.key,
            upsert_version: leaf.payload,
            value_hash: leaf.value_hash,
            state_tree_leaf_key: StoredTreeNodeKey::prefixed(&tree_node_prefix, &leaf.local_key),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstateSummary {
    pub sort_key: DbSortKey,
    pub upsert_version: Version,
    pub value_hash: Hash,

    /// A global tree node key of this Substate's leaf.
    pub state_tree_leaf_key: StoredTreeNodeKey,
}

impl<'s, S: ReadableTreeStore + Sync> SubstateTier<'s, S> {
    pub fn apply_partition_updates<D: Dispatch>(
        &mut self,
        next_version: Version,
        updates: &PartitionDatabaseUpdates,
        dispatch: &D,
    ) -> (Option<Hash>, TierCollectedWrites) {
        let mut collected = TierCollectedWrites::default();

        let leaf_updates: Box<dyn Iterator<Item = _>> = match updates {
            PartitionDatabaseUpdates::Delta { substate_updates } => {
                Box::new(substate_updates.iter().map(|(sort_key, update)| {
                    let new_leaf = match update {
                        DatabaseUpdate::Set(value) => Some(Self::new_leaf(value, next_version)),
                        DatabaseUpdate::Delete => None,
                    };
                    (sort_key, new_leaf)
                }))
            }
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            } => {
                // First we handle the reset by:
                // * Recording the stale subtree for cleanup (into collected writes)
                // * Setting this tier's root version to None, so that when we generate an update batch, it's
                //   on an empty tree
                if let Some(substate_root_version) = self.root_version {
                    collected.stale_tree_parts.push(StaleTreePart::Subtree(
                        self.stored_node_key(&TreeNodeKey::new_empty_path(substate_root_version)),
                    ));
                }
                self.root_version = None;

                Box::new(
                    new_substate_values
                        .iter()
                        .map(|(sort_key, new_substate_value)| {
                            let new_leaf = Some(Self::new_leaf(new_substate_value, next_version));
                            (sort_key, new_leaf)
                        }),
                )
            }
        };

        let tier_update_batch =
            self.generate_tier_update_batch(next_version, leaf_updates, dispatch);
        collected.collect_from_tier_batch(&tier_update_batch, |k| self.stored_node_key(k));
        let partition_key = Arc::new(self.partition_key.clone());
        collected.collect_associations::<Self>(
            updates,
            &tier_update_batch.tree_update_batch,
            &partition_key,
            |k| self.stored_node_key(k),
        );
        self.root_version = Some(tier_update_batch.new_version);

        (tier_update_batch.new_root_hash, collected)
    }

    fn new_leaf(
        new_substate_value: &DbSubstateValue,
        new_version: Version,
    ) -> (Hash, <Self as StateTreeTier>::Payload) {
        // Hash the substate value with blake3
        let value_hash = Hash::from_bytes(new_substate_value);
        let new_leaf_payload = new_version;
        (value_hash, new_leaf_payload)
    }
}
