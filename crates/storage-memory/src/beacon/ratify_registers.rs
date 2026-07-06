//! Durable ratification registers — `RatifyRegisterStore` for
//! [`SimBeaconStorage`].
//!
//! Records live exactly as long as the store handle, which is what a
//! simulated restart preserves: rebuilding a coordinator over the same
//! `SimBeaconStorage` models a crash that loses process memory but
//! keeps disk.

use hyperscale_storage::RatifyRegisterStore;
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_types::{
    BeaconBlockHash, Epoch, RatifyPhase, RatifyRound, RatifyVoteRecord, ValidatorId,
};

use super::core::SimBeaconStorage;

impl RatifyRegisterStore for SimBeaconStorage {
    fn record_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) {
        let mut inner = write_or_recover(&self.inner);
        let record = inner
            .ratify_records
            .entry(validator)
            .or_insert_with(|| RatifyVoteRecord::new(epoch));
        // A stored record for a newer epoch never regresses; one for an
        // older epoch is superseded outright.
        if record.epoch > epoch {
            return;
        }
        if record.epoch < epoch {
            *record = RatifyVoteRecord::new(epoch);
        }
        record.record(round, phase, block_hash);
        drop(inner);
    }

    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord> {
        read_or_recover(&self.inner)
            .ratify_records
            .get(&validator)
            .cloned()
    }
}
