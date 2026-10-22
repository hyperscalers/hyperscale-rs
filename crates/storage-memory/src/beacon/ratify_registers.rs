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
    BeaconBlockHash, Epoch, RatifyPhase, RatifyPolka, RatifyRound, RatifyVoteAdmission,
    RatifyVoteRecord, ValidatorId,
};

use super::core::SimBeaconStorage;
use crate::crash_point;

impl RatifyRegisterStore for SimBeaconStorage {
    fn admit_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
        polka: RatifyPolka,
    ) -> bool {
        crash_point::write();
        let mut inner = write_or_recover(&self.inner);
        let stored = inner.ratify_records.get(&validator);
        let record = match RatifyVoteRecord::admit(stored, epoch, round, phase, block_hash, polka) {
            RatifyVoteAdmission::Record(record) => record,
            RatifyVoteAdmission::Repeat => return true,
            RatifyVoteAdmission::Refuse => return false,
        };
        inner.ratify_records.insert(validator, record);
        drop(inner);
        self.sync();
        true
    }

    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord> {
        read_or_recover(&self.inner)
            .ratify_records
            .get(&validator)
            .cloned()
    }
}
