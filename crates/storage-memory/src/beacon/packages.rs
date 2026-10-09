//! Fetched-package persistence — `FetchedPackageStore` for
//! [`SimBeaconStorage`].

use hyperscale_storage::FetchedPackageStore;
use hyperscale_types::Hash;

use super::core::SimBeaconStorage;
use crate::crash_point;

impl FetchedPackageStore for SimBeaconStorage {
    fn store_fetched_package(&self, package: Hash, artifact: &[u8]) {
        crash_point::write();
        self.inner
            .write()
            .expect("beacon store lock poisoned")
            .fetched_packages
            .insert(package, artifact.to_vec());
    }

    fn fetched_packages(&self) -> Vec<Vec<u8>> {
        self.inner
            .read()
            .expect("beacon store lock poisoned")
            .fetched_packages
            .values()
            .cloned()
            .collect()
    }
}
