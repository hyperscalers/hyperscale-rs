//! `BeaconChainWriter` implementation for `SimBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainWriter;
use hyperscale_storage::lock_recover::write_or_recover;
use hyperscale_types::{BeaconState, CertifiedBeaconBlock};

use super::core::SimBeaconStorage;

impl BeaconChainWriter for SimBeaconStorage {
    fn commit_beacon_block(&self, block: &Arc<CertifiedBeaconBlock>, state: &BeaconState) {
        let mut inner = write_or_recover(&self.inner);
        let epoch = block.epoch();
        let hash = block.block_hash();
        inner.blocks_by_epoch.insert(epoch, Arc::clone(block));
        inner.hash_to_epoch.insert(hash, epoch);
        inner.state_by_epoch.insert(epoch, Arc::new(state.clone()));
    }
}
