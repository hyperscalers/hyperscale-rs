//! `BeaconChainWriter` implementation for `RocksDbBeaconStorage`.

use hyperscale_storage::BeaconChainWriter;
use hyperscale_types::{BeaconState, CertifiedBeaconBlock, Verified};

use super::core::RocksDbBeaconStorage;

impl BeaconChainWriter for RocksDbBeaconStorage {
    fn commit_beacon_block(&self, block: &Verified<CertifiedBeaconBlock>, state: &BeaconState) {
        self.commit_block_inner(block, state);
    }
}
