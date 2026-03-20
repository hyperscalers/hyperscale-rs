//! Genesis bootstrap wrapper.
//!
//! During genesis, the Radix Engine calls `commit()` multiple times. Each call
//! writes substates only (no JMT computation). After bootstrap completes, the
//! accumulated updates are available as a single merged `DatabaseUpdates` for
//! a one-shot JMT computation at version 0.

use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};

/// Merge `source` into `target` in place (last writer wins).
fn merge_into(target: &mut DatabaseUpdates, source: &DatabaseUpdates) {
    for (entity_key, node_updates) in &source.node_updates {
        merge_node_updates(
            target.node_updates.entry(entity_key.clone()).or_default(),
            node_updates,
        );
    }
}

fn merge_node_updates(target: &mut NodeDatabaseUpdates, source: &NodeDatabaseUpdates) {
    for (partition, part_updates) in &source.partition_updates {
        match target.partition_updates.entry(*partition) {
            indexmap::map::Entry::Vacant(e) => {
                e.insert(part_updates.clone());
            }
            indexmap::map::Entry::Occupied(mut e) => {
                merge_partition_updates(e.get_mut(), part_updates);
            }
        }
    }
}

fn merge_partition_updates(
    target: &mut PartitionDatabaseUpdates,
    source: &PartitionDatabaseUpdates,
) {
    match (target, source) {
        (
            PartitionDatabaseUpdates::Delta {
                substate_updates: target_updates,
            },
            PartitionDatabaseUpdates::Delta {
                substate_updates: source_updates,
            },
        ) => {
            target_updates.extend(source_updates.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        (target, PartitionDatabaseUpdates::Reset { .. }) => {
            *target = source.clone();
        }
        (
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            },
            PartitionDatabaseUpdates::Delta { substate_updates },
        ) => {
            for (sort_key, update) in substate_updates {
                match update {
                    DatabaseUpdate::Set(value) => {
                        new_substate_values.insert(sort_key.clone(), value.clone());
                    }
                    DatabaseUpdate::Delete => {
                        new_substate_values.swap_remove(sort_key);
                    }
                }
            }
        }
    }
}

/// Storage backends that can write substates without JMT computation.
pub trait SubstatesOnlyCommit {
    /// Persist substate data without updating the JMT.
    fn commit_substates_only(&self, updates: &DatabaseUpdates);
}

/// Wrapper for genesis bootstrap that writes substates only (no JMT) and
/// merges updates incrementally for a single JMT computation afterwards.
pub struct GenesisWrapper<'a, S> {
    storage: &'a S,
    merged: DatabaseUpdates,
}

impl<'a, S> GenesisWrapper<'a, S> {
    /// Create a new genesis wrapper around the given storage.
    pub fn new(storage: &'a S) -> Self {
        Self {
            storage,
            merged: DatabaseUpdates::default(),
        }
    }

    /// Consume the wrapper and return the merged updates.
    pub fn into_merged(self) -> DatabaseUpdates {
        self.merged
    }
}

impl<S: SubstateDatabase> SubstateDatabase for GenesisWrapper<'_, S> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.storage
            .get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        self.storage
            .list_raw_values_from_db_key(partition_key, from_sort_key)
    }
}

impl<S: SubstatesOnlyCommit + SubstateDatabase> CommittableSubstateDatabase
    for GenesisWrapper<'_, S>
{
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.storage.commit_substates_only(updates);
        merge_into(&mut self.merged, updates);
    }
}
