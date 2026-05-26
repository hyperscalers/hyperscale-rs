//! `BeaconChainReader` implementation for `RocksDbBeaconStorage`.

use std::sync::Arc;

use hyperscale_storage::BeaconChainReader;
use hyperscale_types::{BeaconBlockHash, BeaconState, CertifiedBeaconBlock, Epoch};
use rocksdb::IteratorMode;

use super::column_families::{BeaconBlocksByEpochCf, BeaconHashToEpochCf, BeaconStateByEpochCf};
use super::core::RocksDbBeaconStorage;
use crate::typed_cf::TypedCf;

impl BeaconChainReader for RocksDbBeaconStorage {
    fn get_beacon_block_by_epoch(&self, epoch: Epoch) -> Option<Arc<CertifiedBeaconBlock>> {
        self.cf_get::<BeaconBlocksByEpochCf>(&epoch.inner())
            .map(Arc::new)
    }

    fn get_beacon_block_by_hash(&self, hash: BeaconBlockHash) -> Option<Arc<CertifiedBeaconBlock>> {
        let epoch = self.cf_get::<BeaconHashToEpochCf>(&hash.into_raw())?;
        self.cf_get::<BeaconBlocksByEpochCf>(&epoch).map(Arc::new)
    }

    fn get_state_by_epoch(&self, epoch: Epoch) -> Option<Arc<BeaconState>> {
        self.cf_get::<BeaconStateByEpochCf>(&epoch.inner())
            .map(Arc::new)
    }

    fn latest_committed_epoch(&self) -> Option<Epoch> {
        // First entry in End-mode iteration is the largest key; keys
        // are big-endian u64 epochs, so lex-max == numeric-max.
        let cf = BeaconBlocksByEpochCf::handle(&self.cf());
        let mut iter = self.db.iterator_cf(cf, IteratorMode::End);
        let (key, _) = iter.next()?.expect("BFT CRITICAL: beacon iter failed");
        let bytes: [u8; 8] = key
            .as_ref()
            .try_into()
            .expect("beacon epoch key must be 8 bytes");
        Some(Epoch::new(u64::from_be_bytes(bytes)))
    }

    fn latest_committed(&self) -> Option<(Arc<CertifiedBeaconBlock>, Arc<BeaconState>)> {
        let epoch = self.latest_committed_epoch()?;
        let block = self.get_beacon_block_by_epoch(epoch)?;
        let state = self.get_state_by_epoch(epoch)?;
        Some((block, state))
    }
}
