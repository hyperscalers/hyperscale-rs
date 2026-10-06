//! Durable beacon consensus registers — `BeaconVoteRegisterStore` for
//! [`RocksDbBeaconStorage`].

use hyperscale_storage::BeaconVoteRegisterStore;
use hyperscale_types::{BeaconVote, BeaconVoteAdmission, BeaconVoteRecord, ValidatorId};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::BeaconVoteRegistersCf;
use super::core::RocksDbBeaconStorage;
use crate::typed_cf::{TypedCf, batch_put};

impl BeaconVoteRegisterStore for RocksDbBeaconStorage {
    fn admit_beacon_vote(&self, validator: ValidatorId, vote: &BeaconVote) -> bool {
        let _guard = self
            .beacon_vote_lock
            .lock()
            .expect("beacon_vote_lock poisoned");
        let stored = self.cf_get::<BeaconVoteRegistersCf>(&validator);
        let record = match BeaconVoteRecord::admit(stored.as_ref(), vote) {
            BeaconVoteAdmission::Record(record) => record,
            BeaconVoteAdmission::Repeat => return true,
            BeaconVoteAdmission::Refuse => return false,
        };
        let mut batch = WriteBatch::default();
        batch_put::<BeaconVoteRegistersCf>(
            &mut batch,
            BeaconVoteRegistersCf::handle(&self.cf()),
            &validator,
            &record,
        );
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: beacon vote register write failed");
        true
    }
}
