//! `BeaconChainReader` implementation for `SimBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainReader;
use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_types::{BeaconBlockHash, BeaconState, CertifiedBeaconBlock, Epoch};

use super::core::SimBeaconStorage;

impl BeaconChainReader for SimBeaconStorage {
    fn get_beacon_block_by_epoch(&self, epoch: Epoch) -> Option<Arc<CertifiedBeaconBlock>> {
        read_or_recover(&self.inner)
            .blocks_by_epoch
            .get(&epoch)
            .cloned()
    }

    fn get_beacon_block_by_hash(&self, hash: BeaconBlockHash) -> Option<Arc<CertifiedBeaconBlock>> {
        let inner = read_or_recover(&self.inner);
        let epoch = *inner.hash_to_epoch.get(&hash)?;
        inner.blocks_by_epoch.get(&epoch).cloned()
    }

    fn get_state_by_epoch(&self, epoch: Epoch) -> Option<Arc<BeaconState>> {
        read_or_recover(&self.inner)
            .state_by_epoch
            .get(&epoch)
            .cloned()
    }

    fn latest_committed_epoch(&self) -> Option<Epoch> {
        read_or_recover(&self.inner)
            .blocks_by_epoch
            .keys()
            .next_back()
            .copied()
    }

    fn latest_committed(&self) -> Option<(Arc<CertifiedBeaconBlock>, Arc<BeaconState>)> {
        let inner = read_or_recover(&self.inner);
        let (&epoch, block) = inner.blocks_by_epoch.iter().next_back()?;
        let state = inner.state_by_epoch.get(&epoch).cloned()?;
        let block = Arc::clone(block);
        drop(inner);
        Some((block, state))
    }
}
