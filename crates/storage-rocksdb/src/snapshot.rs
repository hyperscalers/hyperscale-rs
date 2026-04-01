//! RocksDB snapshot for consistent reads.

use crate::column_families::{CfHandles, StateCf};
use crate::substate_key;
use crate::typed_cf::{self, TypedCf};
use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use rocksdb::{Snapshot, DB};

/// RocksDB snapshot for consistent reads.
///
/// Uses RocksDB's native snapshot feature to provide point-in-time isolation.
/// Any writes that occur after the snapshot is created are invisible to reads
/// through this snapshot.
pub struct RocksDbSnapshot<'a> {
    pub(crate) snapshot: Snapshot<'a>,
    pub(crate) db: &'a DB,
}

impl SubstateDatabase for RocksDbSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let cf = CfHandles::resolve(self.db);
        typed_cf::get::<StateCf>(
            &self.snapshot,
            StateCf::handle(&cf),
            &(partition_key.clone(), sort_key.clone()),
        )
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = substate_key::partition_prefix(partition_key);
        let start = match from_sort_key {
            Some(sort_key) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sort_key.0);
                s
            }
            None => prefix.clone(),
        };

        let state_cf = StateCf::handle(&CfHandles::resolve(self.db));
        Box::new(
            typed_cf::prefix_iter_from_snap::<StateCf>(&self.snapshot, state_cf, &prefix, &start)
                .map(|((_pk, sk), value)| (sk, value)),
        )
    }
}
