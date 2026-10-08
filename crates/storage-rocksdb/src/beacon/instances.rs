//! Fetched-record persistence — `FetchedInstanceStore` for
//! [`RocksDbBeaconStorage`].

use hyperscale_storage::FetchedInstanceStore;
use hyperscale_types::Address;
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::FetchedInstancesCf;
use super::core::RocksDbBeaconStorage;

impl FetchedInstanceStore for RocksDbBeaconStorage {
    fn store_fetched_instances(&self, records: &[(Address, Vec<u8>)]) {
        let mut batch = WriteBatch::default();
        for (instance, record) in records {
            // First write wins: a row is the preimage of its key, so a
            // second one at that address is the same record.
            if self.cf_get::<FetchedInstancesCf>(instance).is_none() {
                self.cf_batch_put::<FetchedInstancesCf>(&mut batch, instance, record);
            }
        }
        if batch.is_empty() {
            return;
        }
        // Synced: a block routed on one of these commits to the shard's
        // own store, and a replay of it after power loss derives the
        // transaction again from this row.
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.db
            .write_opt(batch, &opts)
            .expect("fetched-record write failed");
    }

    fn fetched_instance(&self, instance: Address) -> Option<Vec<u8>> {
        self.cf_get::<FetchedInstancesCf>(&instance)
    }
}
