//! `BeaconChainWriter` implementation for `RocksDbBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainWriter;
use hyperscale_types::{BeaconState, CertifiedBeaconBlock};

use super::core::RocksDbBeaconStorage;

impl BeaconChainWriter for RocksDbBeaconStorage {
    fn commit_beacon_block(&self, block: &Arc<CertifiedBeaconBlock>, state: &BeaconState) {
        self.commit_block_inner(block, state);
    }
}
