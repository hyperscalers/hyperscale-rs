//! Fetched-record persistence — `FetchedInstanceStore` for
//! [`SimBeaconStorage`].

use hyperscale_storage::FetchedInstanceStore;
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_types::Address;

use super::core::SimBeaconStorage;
use crate::crash_point;

impl FetchedInstanceStore for SimBeaconStorage {
    fn store_fetched_instances(&self, records: &[(Address, Vec<u8>)]) {
        crash_point::write();
        let mut inner = write_or_recover(&self.inner);
        let mut kept = false;
        for (instance, record) in records {
            // First write wins: a row is the preimage of its key, so a
            // second one at that address is the same record.
            if !inner.fetched_instances.contains_key(instance) {
                inner.fetched_instances.insert(*instance, record.clone());
                kept = true;
            }
        }
        drop(inner);
        if kept {
            self.sync();
        }
    }

    fn fetched_instance(&self, instance: Address) -> Option<Vec<u8>> {
        read_or_recover(&self.inner)
            .fetched_instances
            .get(&instance)
            .cloned()
    }
}
