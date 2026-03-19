//! Adapter bridging the framework's [`SubstateReader`] to Radix's [`SubstateDatabase`].
//!
//! The framework's storage traits use raw byte slices (`&[u8]`) while the Radix
//! engine expects its own key types (`DbPartitionKey`, `DbSortKey`). This adapter
//! wraps any `SubstateReader` and presents it as a `SubstateDatabase` so the Radix
//! engine can execute transactions against framework snapshots.

use hyperscale_storage::SubstateReader;
use radix_substate_store_interface::interface::{
    DbPartitionKey, DbSortKey, PartitionEntry, SubstateDatabase,
};

/// Bridges the framework's `SubstateReader` to Radix's `SubstateDatabase`.
pub struct RadixStorageAdapter<'a, R: SubstateReader + ?Sized>(pub &'a R);

impl<R: SubstateReader + ?Sized> SubstateDatabase for RadixStorageAdapter<'_, R> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        self.0.get_raw_substate(
            &partition_key.node_key,
            partition_key.partition_num,
            &sort_key.0,
        )
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let iter = self.0.list_raw_substates(
            &partition_key.node_key,
            partition_key.partition_num,
            from_sort_key.map(|k| k.0.as_slice()),
        );
        Box::new(iter.map(|(k, v)| (DbSortKey(k), v)))
    }
}
