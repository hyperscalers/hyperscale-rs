//! Durable ratification registers — `RatifyRegisterStore` for
//! [`RocksDbBeaconStorage`].

use hyperscale_storage::RatifyRegisterStore;
use hyperscale_types::{
    BeaconBlockHash, Epoch, RatifyPhase, RatifyRound, RatifyVoteRecord, ValidatorId,
};
use rocksdb::{WriteBatch, WriteOptions};

use super::column_families::RatifyRegistersCf;
use super::core::RocksDbBeaconStorage;
use crate::typed_cf::{TypedCf, batch_put};

impl RatifyRegisterStore for RocksDbBeaconStorage {
    fn record_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) {
        // One guard spans the read-merge-write so concurrent signers'
        // writes stay monotone; ratify votes are write-cold (one or two
        // per member per epoch), so serialising the fsync costs nothing.
        let _guard = self.ratify_lock.lock().expect("ratify_lock poisoned");
        let mut record = self
            .cf_get::<RatifyRegistersCf>(&validator)
            // A stored record for a newer epoch never regresses; one
            // for an older epoch is superseded outright.
            .filter(|stored| stored.epoch >= epoch)
            .unwrap_or_else(|| RatifyVoteRecord::new(epoch));
        if record.epoch > epoch || !record.record(round, phase, block_hash) {
            return; // superseded epoch or occupied slot — nothing to persist
        }

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
    }

    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord> {
        self.cf_get::<RatifyRegistersCf>(&validator)
    }
}
