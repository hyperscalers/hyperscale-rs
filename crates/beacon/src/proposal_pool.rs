//! Per-epoch gossip-arrival cache for committee members'
//! `BeaconProposal`s.
//!
//! Each beacon-committee member broadcasts one `BeaconProposal` per
//! epoch carrying its witnesses + VRF reveal. The local coordinator
//! pools these by `ValidatorId` and consults the pool when building
//! the local SPC input vector and when decoding SPC's committed
//! output back into the `(ValidatorId, BeaconProposal)` slice
//! `apply_epoch` consumes.
//!
//! The pool is scoped to one in-flight epoch — the epoch the local
//! `SpcInstance` is driving consensus over. Proposals tagged with a
//! different epoch are out-of-scope: a stale-epoch proposal is dead
//! weight (we've already committed past it), and a future-epoch
//! proposal can't be applied until the committee for that epoch is
//! known. Both get dropped at admission.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{BeaconProposal, Epoch, ValidatorId, Verified};

/// Per-epoch cache of verified `BeaconProposal`s indexed by sender.
#[derive(Debug)]
pub struct BeaconProposalPool {
    /// Epoch this pool tracks. Admissions for any other epoch get
    /// dropped.
    epoch: Epoch,
    /// Received proposals keyed by sender id. One entry per
    /// committee member; subsequent admissions from the same sender
    /// are dropped (first-write wins, mirroring the equivocation
    /// pool's discipline).
    proposals: BTreeMap<ValidatorId, Arc<Verified<BeaconProposal>>>,
}

impl BeaconProposalPool {
    /// Fresh empty pool tracking `epoch`.
    #[must_use]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            proposals: BTreeMap::new(),
        }
    }

    /// Reset the pool for `epoch`, dropping every prior entry. Called
    /// after a successful commit so the next in-flight epoch starts
    /// from a clean slate.
    pub fn reset(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.proposals.clear();
    }

    /// Attempt to admit `proposal` from `from`. Returns `true` on
    /// admission, `false` on rejection.
    ///
    /// Rejected if `epoch` doesn't match the pool's tracked epoch, or
    /// if `from` already has a proposal in the pool — first-write
    /// wins so a re-gossip of a different proposal from the same
    /// sender can't displace the earlier one.
    pub fn admit(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    ) -> bool {
        if epoch != self.epoch {
            return false;
        }
        if self.proposals.contains_key(&from) {
            return false;
        }
        self.proposals.insert(from, proposal);
        true
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl BeaconProposalPool {
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub fn get(&self, from: ValidatorId) -> Option<&Arc<Verified<BeaconProposal>>> {
        self.proposals.get(&from)
    }

    #[must_use]
    pub fn contains(&self, from: ValidatorId) -> bool {
        self.proposals.contains_key(&from)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.proposals.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BeaconProposal, Epoch, ValidatorId, Verified, VrfOutput, VrfProof};

    use super::*;

    fn proposal(seed: u8) -> Arc<Verified<BeaconProposal>> {
        Arc::new(Verified::new_unchecked_for_test(BeaconProposal::vrf_only(
            VrfOutput::new([seed; 32]),
            VrfProof::new([seed; 96]),
        )))
    }

    #[test]
    fn empty_after_new() {
        let pool = BeaconProposalPool::new(Epoch::new(1));
        assert_eq!(pool.epoch(), Epoch::new(1));
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn admits_matching_epoch() {
        let mut pool = BeaconProposalPool::new(Epoch::new(1));
        assert!(pool.admit(ValidatorId::new(0), Epoch::new(1), proposal(0xAB)));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(ValidatorId::new(0)));
    }

    #[test]
    fn rejects_wrong_epoch() {
        let mut pool = BeaconProposalPool::new(Epoch::new(1));
        assert!(!pool.admit(ValidatorId::new(0), Epoch::new(2), proposal(0xAB)));
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_duplicate_sender_first_wins() {
        let mut pool = BeaconProposalPool::new(Epoch::new(1));
        assert!(pool.admit(ValidatorId::new(0), Epoch::new(1), proposal(0xAB)));
        // Second submission from same sender is rejected; the first
        // entry is what the pool keeps.
        assert!(!pool.admit(ValidatorId::new(0), Epoch::new(1), proposal(0xCD)));
        assert_eq!(pool.len(), 1);
        let kept = pool.get(ValidatorId::new(0)).expect("first entry kept");
        assert_eq!(kept.vrf_output(), VrfOutput::new([0xAB; 32]));
    }

    #[test]
    fn reset_clears_and_re_targets_epoch() {
        let mut pool = BeaconProposalPool::new(Epoch::new(1));
        pool.admit(ValidatorId::new(0), Epoch::new(1), proposal(0xAB));
        pool.admit(ValidatorId::new(1), Epoch::new(1), proposal(0xCD));
        assert_eq!(pool.len(), 2);
        pool.reset(Epoch::new(2));
        assert_eq!(pool.epoch(), Epoch::new(2));
        assert!(pool.is_empty());
        // Old-epoch proposal still rejected after reset.
        assert!(!pool.admit(ValidatorId::new(0), Epoch::new(1), proposal(0xAB)));
        // New-epoch proposal accepted.
        assert!(pool.admit(ValidatorId::new(0), Epoch::new(2), proposal(0xAB)));
        assert_eq!(pool.len(), 1);
    }
}
