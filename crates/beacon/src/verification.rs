//! Async-verification bookkeeping for beacon-side crypto checks.

use std::collections::BTreeSet;

use hyperscale_types::Hash;

/// What kind of verification the pipeline is tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationKind {
    /// PC 3-round QC signature.
    PcQc3,
    /// SPC certificate signature.
    SpcCert,
    /// Committee aggregate signature over a beacon block header.
    BeaconBlockAggregate,
    /// VRF reveal (output + proof) from a beacon proposal.
    VrfReveal,
    /// Merkle proof path into a shard's witness accumulator.
    ShardWitnessProof,
}

/// Tracks asynchronous verifications dispatched to the crypto pool.
///
/// One slot per `(kind, key)` pair where `key` is a 32-byte
/// identifier the caller chooses (typically a block hash, a cert
/// content hash, or a salted hash of `(validator_id, epoch, …)`).
/// The coordinator dispatches verification by marking a slot
/// in-flight; the result handler clears the slot and records it as
/// verified iff the crypto check passed.
#[derive(Debug, Default)]
pub struct BeaconVerificationPipeline {
    in_flight: BTreeSet<(VerificationKind, Hash)>,
    verified: BTreeSet<(VerificationKind, Hash)>,
}

impl BeaconVerificationPipeline {
    /// Empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `(kind, key)` as a verification in flight. Returns `true`
    /// when newly inserted, `false` when the slot was already
    /// in-flight or already verified — the caller should treat
    /// `false` as "don't redispatch."
    pub fn mark_in_flight(&mut self, kind: VerificationKind, key: Hash) -> bool {
        if self.is_verified(kind, key) || self.is_in_flight(kind, key) {
            return false;
        }
        self.in_flight.insert((kind, key));
        true
    }

    /// Apply a verification result. Clears the in-flight slot; on
    /// `valid`, records the slot as verified. Returns whether the
    /// slot was previously in-flight — a `false` here means the
    /// result arrived for a slot the pipeline never dispatched
    /// (stale callback, duplicate result, or programming error).
    pub fn on_result(&mut self, kind: VerificationKind, key: Hash, valid: bool) -> bool {
        let was_in_flight = self.in_flight.remove(&(kind, key));
        if was_in_flight && valid {
            self.verified.insert((kind, key));
        }
        was_in_flight
    }

    /// Drop the slot entirely (both in-flight and verified state).
    /// The coordinator calls this after the associated block is
    /// committed and the verification result is no longer needed.
    pub fn forget(&mut self, kind: VerificationKind, key: Hash) {
        self.in_flight.remove(&(kind, key));
        self.verified.remove(&(kind, key));
    }
}

// Flat queries; names are the documentation.
#[allow(missing_docs)]
impl BeaconVerificationPipeline {
    #[must_use]
    pub fn is_in_flight(&self, kind: VerificationKind, key: Hash) -> bool {
        self.in_flight.contains(&(kind, key))
    }

    #[must_use]
    pub fn is_verified(&self, kind: VerificationKind, key: Hash) -> bool {
        self.verified.contains(&(kind, key))
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.verified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> Hash {
        Hash::from_bytes(&[seed])
    }

    #[test]
    fn empty_after_new() {
        let p = BeaconVerificationPipeline::new();
        assert_eq!(p.in_flight_count(), 0);
        assert_eq!(p.verified_count(), 0);
        assert!(!p.is_in_flight(VerificationKind::PcQc3, key(0)));
        assert!(!p.is_verified(VerificationKind::PcQc3, key(0)));
    }

    #[test]
    fn mark_in_flight_first_time_returns_true() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_in_flight(VerificationKind::PcQc3, key(1)));
        assert!(p.is_in_flight(VerificationKind::PcQc3, key(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn duplicate_mark_returns_false_without_replacing() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_in_flight(VerificationKind::PcQc3, key(1)));
        assert!(!p.mark_in_flight(VerificationKind::PcQc3, key(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn mark_after_verified_returns_false() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_in_flight(VerificationKind::PcQc3, key(1));
        p.on_result(VerificationKind::PcQc3, key(1), true);
        assert!(!p.mark_in_flight(VerificationKind::PcQc3, key(1)));
    }

    #[test]
    fn on_result_valid_moves_to_verified() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_in_flight(VerificationKind::SpcCert, key(2));
        let was_in_flight = p.on_result(VerificationKind::SpcCert, key(2), true);
        assert!(was_in_flight);
        assert!(!p.is_in_flight(VerificationKind::SpcCert, key(2)));
        assert!(p.is_verified(VerificationKind::SpcCert, key(2)));
    }

    #[test]
    fn on_result_invalid_just_clears_in_flight() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_in_flight(VerificationKind::VrfReveal, key(3));
        p.on_result(VerificationKind::VrfReveal, key(3), false);
        assert!(!p.is_in_flight(VerificationKind::VrfReveal, key(3)));
        assert!(!p.is_verified(VerificationKind::VrfReveal, key(3)));
    }

    #[test]
    fn on_result_for_unknown_slot_returns_false() {
        let mut p = BeaconVerificationPipeline::new();
        let was_in_flight = p.on_result(VerificationKind::PcQc3, key(99), true);
        assert!(!was_in_flight);
        assert!(!p.is_verified(VerificationKind::PcQc3, key(99)));
    }

    #[test]
    fn kinds_are_independent_under_same_key() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_in_flight(VerificationKind::PcQc3, key(5));
        p.mark_in_flight(VerificationKind::SpcCert, key(5));
        assert_eq!(p.in_flight_count(), 2);
        p.on_result(VerificationKind::PcQc3, key(5), true);
        assert!(p.is_in_flight(VerificationKind::SpcCert, key(5)));
        assert!(p.is_verified(VerificationKind::PcQc3, key(5)));
    }

    #[test]
    fn forget_clears_both_states() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_in_flight(VerificationKind::VrfReveal, key(7));
        p.on_result(VerificationKind::VrfReveal, key(7), true);
        p.forget(VerificationKind::VrfReveal, key(7));
        assert!(!p.is_verified(VerificationKind::VrfReveal, key(7)));

        p.mark_in_flight(VerificationKind::VrfReveal, key(8));
        p.forget(VerificationKind::VrfReveal, key(8));
        assert!(!p.is_in_flight(VerificationKind::VrfReveal, key(8)));
    }
}
