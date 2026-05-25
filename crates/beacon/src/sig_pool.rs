//! Per-epoch cache of BLS signatures over a beacon block header.
//!
//! Each committee member signs the canonical header bytes after SPC
//! reaches `OutputHigh` and `apply_epoch` runs. The local coordinator
//! pools these sigs by `ValidatorId` and aggregates once ≥ ⅔ have
//! arrived into the `BeaconBlock`'s `aggregate_sig`. Mirrors
//! [`BeaconProposalPool`](crate::proposal_pool::BeaconProposalPool)'s
//! shape: scoped to one in-flight epoch, first-write-wins, reset on
//! commit.

use std::collections::BTreeMap;

use hyperscale_types::{Bls12381G2Signature, Epoch, ValidatorId};

/// Per-epoch cache of received header sigs indexed by signer.
#[derive(Debug)]
pub struct BeaconBlockSigPool {
    /// Epoch this pool tracks. Admissions for any other epoch get
    /// dropped — a stale-epoch sig is dead weight and a future-epoch
    /// sig can't be verified against a header we haven't built yet.
    epoch: Epoch,
    /// Received sigs keyed by signer id. Subsequent admissions from
    /// the same signer are dropped: a peer re-broadcasting their
    /// own sig is just gossip noise, not a second contributor.
    sigs: BTreeMap<ValidatorId, Bls12381G2Signature>,
}

impl BeaconBlockSigPool {
    /// Fresh empty pool tracking `epoch`.
    #[must_use]
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            sigs: BTreeMap::new(),
        }
    }

    /// Reset the pool for `epoch`, dropping every prior entry. Called
    /// after a successful commit so the next in-flight epoch starts
    /// from a clean slate.
    pub fn reset(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.sigs.clear();
    }

    /// Attempt to admit `sig` from `from`. Returns `true` on
    /// admission, `false` on rejection (wrong epoch or duplicate
    /// sender).
    pub fn admit(&mut self, from: ValidatorId, epoch: Epoch, sig: Bls12381G2Signature) -> bool {
        if epoch != self.epoch {
            return false;
        }
        if self.sigs.contains_key(&from) {
            return false;
        }
        self.sigs.insert(from, sig);
        true
    }

    /// Iterate `(signer, sig)` pairs in committee-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &Bls12381G2Signature)> {
        self.sigs.iter()
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl BeaconBlockSigPool {
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    #[must_use]
    pub fn contains(&self, from: ValidatorId) -> bool {
        self.sigs.contains_key(&from)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Bls12381G2Signature, Epoch, ValidatorId};

    use super::*;

    fn sig(seed: u8) -> Bls12381G2Signature {
        Bls12381G2Signature([seed; 96])
    }

    #[test]
    fn empty_after_new() {
        let p = BeaconBlockSigPool::new(Epoch::new(1));
        assert_eq!(p.epoch(), Epoch::new(1));
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn admits_matching_epoch() {
        let mut p = BeaconBlockSigPool::new(Epoch::new(1));
        assert!(p.admit(ValidatorId::new(0), Epoch::new(1), sig(0xAB)));
        assert_eq!(p.len(), 1);
        assert!(p.contains(ValidatorId::new(0)));
    }

    #[test]
    fn rejects_wrong_epoch() {
        let mut p = BeaconBlockSigPool::new(Epoch::new(1));
        assert!(!p.admit(ValidatorId::new(0), Epoch::new(2), sig(0xAB)));
        assert!(p.is_empty());
    }

    #[test]
    fn rejects_duplicate_sender() {
        let mut p = BeaconBlockSigPool::new(Epoch::new(1));
        assert!(p.admit(ValidatorId::new(0), Epoch::new(1), sig(0xAB)));
        assert!(!p.admit(ValidatorId::new(0), Epoch::new(1), sig(0xCD)));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn reset_clears_and_re_targets_epoch() {
        let mut p = BeaconBlockSigPool::new(Epoch::new(1));
        p.admit(ValidatorId::new(0), Epoch::new(1), sig(0xAB));
        p.admit(ValidatorId::new(1), Epoch::new(1), sig(0xCD));
        p.reset(Epoch::new(2));
        assert_eq!(p.epoch(), Epoch::new(2));
        assert!(p.is_empty());
        assert!(!p.admit(ValidatorId::new(0), Epoch::new(1), sig(0xAB)));
        assert!(p.admit(ValidatorId::new(0), Epoch::new(2), sig(0xAB)));
    }
}
