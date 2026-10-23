//! Durable ratification registers — `RatifyRegisterStore` for
//! [`RocksDbBeaconStorage`].

use hyperscale_storage::RatifyRegisterStore;
use hyperscale_types::{
    BeaconBlockHash, Epoch, RatifyPhase, RatifyPolka, RatifyRound, RatifyVoteAdmission,
    RatifyVoteRecord, ValidatorId,
};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::RatifyRegistersCf;
use super::core::RocksDbBeaconStorage;
use crate::typed_cf::{TypedCf, batch_put};

impl RatifyRegisterStore for RocksDbBeaconStorage {
    fn admit_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
        polka: RatifyPolka,
    ) -> bool {
        // One guard spans the read-decide-write so concurrent signers
        // cannot both admit at one slot; ratify votes are write-cold (one
        // or two per member per epoch), so serialising the fsync costs
        // nothing.
        let _guard = self.ratify_lock.lock().expect("ratify_lock poisoned");
        let stored = self.cf_get::<RatifyRegistersCf>(&validator);
        let record = match RatifyVoteRecord::admit(
            stored.as_ref(),
            epoch,
            round,
            phase,
            block_hash,
            polka,
        ) {
            RatifyVoteAdmission::Record(record) => record,
            RatifyVoteAdmission::Repeat => return true,
            RatifyVoteAdmission::Refuse => return false,
        };

        let mut batch = WriteBatch::default();
        batch_put::<RatifyRegistersCf>(
            &mut batch,
            RatifyRegistersCf::handle(&self.cf()),
            &validator,
            &record,
        );
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: ratify register write failed");
        true
    }

    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord> {
        self.cf_get::<RatifyRegistersCf>(&validator)
    }

    fn restore_ratify_record(&self, validator: ValidatorId, record: &RatifyVoteRecord) {
        let _guard = self.ratify_lock.lock().expect("ratify_lock poisoned");
        let mut batch = WriteBatch::default();
        batch_put::<RatifyRegistersCf>(
            &mut batch,
            RatifyRegistersCf::handle(&self.cf()),
            &validator,
            record,
        );
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db
            .write_opt(batch, &write_opts)
            .expect("BFT CRITICAL: ratify register write failed");
    }
}
