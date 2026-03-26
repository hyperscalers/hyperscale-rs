//! Genesis bootstrap wrapper.
//!
//! During genesis, the Radix Engine calls `commit()` multiple times. Each call
//! writes substates only (no JVT computation). After bootstrap completes, the
//! accumulated updates are available as a single merged `DatabaseUpdates` for
//! a one-shot JVT computation at version 0.

use crate::writes::merge_into;
use radix_common::prelude::DbSubstateValue;
use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, PartitionEntry,
    SubstateDatabase,
};

/// Storage backends that can write substates without JVT computation.
pub trait SubstatesOnlyCommit {
    /// Persist substate data without updating the JVT.
    fn commit_substates_only(&self, updates: &DatabaseUpdates);
}

/// Wrapper for genesis bootstrap that writes substates only (no JVT) and
/// merges updates incrementally for a single JVT computation afterwards.
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
