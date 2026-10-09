//! Durable beacon consensus registers — `BeaconVoteRegisterStore` for
//! [`SimBeaconStorage`].

use hyperscale_storage::BeaconVoteRegisterStore;
use hyperscale_storage::lock_recover::write_or_recover;
use hyperscale_types::{BeaconVote, BeaconVoteAdmission, BeaconVoteRecord, ValidatorId};

use super::core::SimBeaconStorage;
use crate::crash_point;

impl BeaconVoteRegisterStore for SimBeaconStorage {
    fn admit_beacon_vote(&self, validator: ValidatorId, vote: &BeaconVote) -> bool {
        crash_point::write();
        let mut inner = write_or_recover(&self.inner);
        let stored = inner.beacon_vote_records.get(&validator);
        let record = match BeaconVoteRecord::admit(stored, vote) {
            BeaconVoteAdmission::Record(record) => record,
            BeaconVoteAdmission::Repeat => return true,
            BeaconVoteAdmission::Refuse => return false,
        };
        inner.beacon_vote_records.insert(validator, record);
        drop(inner);
        self.sync();
        true
    }
}
