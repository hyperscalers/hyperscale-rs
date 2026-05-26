//! Async-verification bookkeeping for beacon-side crypto checks.

use std::collections::BTreeSet;

use hyperscale_types::{BeaconBlockHash, Hash};

/// In-flight + verified slots over an arbitrary key.
///
/// The coordinator marks a slot in-flight when it dispatches the
/// verification action; the result handler clears the slot and records
/// it as verified iff the crypto check passed.
#[derive(Debug)]
struct VerificationSlots<K> {
    in_flight: BTreeSet<K>,
    verified: BTreeSet<K>,
}

impl<K> Default for VerificationSlots<K> {
    fn default() -> Self {
        Self {
            in_flight: BTreeSet::new(),
            verified: BTreeSet::new(),
        }
    }
}

impl<K: Ord> VerificationSlots<K> {
    fn mark_in_flight(&mut self, key: K) -> bool {
        if self.verified.contains(&key) || self.in_flight.contains(&key) {
            return false;
        }
        self.in_flight.insert(key);
        true
    }

    fn on_result(&mut self, key: &K, valid: bool)
    where
        K: Clone,
    {
        if self.in_flight.remove(key) && valid {
            self.verified.insert(key.clone());
        }
    }

    fn forget(&mut self, key: &K) {
        self.in_flight.remove(key);
        self.verified.remove(key);
    }

    fn is_in_flight(&self, key: &K) -> bool {
        self.in_flight.contains(key)
    }

    fn is_verified(&self, key: &K) -> bool {
        self.verified.contains(key)
    }

    fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    fn verified_count(&self) -> usize {
        self.verified.len()
    }
}

/// Tracks asynchronous beacon verifications dispatched to the crypto
/// pool.
///
/// Two domains: block-cert verifications (keyed on block hash) and
/// skip-request sig verifications (keyed on the request's content
/// hash). The two never share keys by construction — different domain
/// types, both blake3.
#[derive(Debug, Default)]
pub struct BeaconVerificationPipeline {
    blocks: VerificationSlots<BeaconBlockHash>,
    skip_requests: VerificationSlots<Hash>,
}

impl BeaconVerificationPipeline {
    /// Empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a block-cert verification in flight. Returns `true` when
    /// newly inserted, `false` when the slot was already in-flight or
    /// already verified — caller should treat `false` as "don't
    /// redispatch."
    pub fn mark_block_in_flight(&mut self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.mark_in_flight(block_hash)
    }

    /// Apply a block-cert verification result. Clears the in-flight
    /// slot; on `valid`, records the slot as verified.
    pub fn on_block_result(&mut self, block_hash: BeaconBlockHash, valid: bool) {
        self.blocks.on_result(&block_hash, valid);
    }

    /// Drop the block slot entirely. Called after the block is adopted
    /// and the verification result is no longer needed.
    pub fn forget_block(&mut self, block_hash: BeaconBlockHash) {
        self.blocks.forget(&block_hash);
    }

    /// Mark a skip-request sig verification in flight. Same semantics
    /// as [`Self::mark_block_in_flight`].
    pub fn mark_skip_request_in_flight(&mut self, key: Hash) -> bool {
        self.skip_requests.mark_in_flight(key)
    }

    /// Apply a skip-request sig verification result.
    pub fn on_skip_request_result(&mut self, key: Hash, valid: bool) {
        self.skip_requests.on_result(&key, valid);
    }

    /// Drop the skip-request slot. Called after admission to the
    /// [`SkipTracker`](crate::skip_tracker::SkipTracker).
    pub fn forget_skip_request(&mut self, key: Hash) {
        self.skip_requests.forget(&key);
    }
}

// Flat queries; names are the documentation.
#[allow(missing_docs)]
impl BeaconVerificationPipeline {
    #[must_use]
    pub fn is_block_in_flight(&self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.is_in_flight(&block_hash)
    }

    #[must_use]
    pub fn is_block_verified(&self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.is_verified(&block_hash)
    }

    #[must_use]
    pub fn is_skip_request_in_flight(&self, key: Hash) -> bool {
        self.skip_requests.is_in_flight(&key)
    }

    #[must_use]
    pub fn is_skip_request_verified(&self, key: Hash) -> bool {
        self.skip_requests.is_verified(&key)
    }

    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.blocks.in_flight_count() + self.skip_requests.in_flight_count()
    }

    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.blocks.verified_count() + self.skip_requests.verified_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_hash(seed: u8) -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(&[seed]))
    }

    fn skip_key(seed: u8) -> Hash {
        Hash::from_bytes(&[seed])
    }

    #[test]
    fn empty_after_new() {
        let p = BeaconVerificationPipeline::new();
        assert_eq!(p.in_flight_count(), 0);
        assert_eq!(p.verified_count(), 0);
        assert!(!p.is_block_in_flight(block_hash(0)));
        assert!(!p.is_block_verified(block_hash(0)));
        assert!(!p.is_skip_request_in_flight(skip_key(0)));
    }

    #[test]
    fn mark_block_in_flight_first_time_returns_true() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_block_in_flight(block_hash(1)));
        assert!(p.is_block_in_flight(block_hash(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn duplicate_mark_returns_false() {
        let mut p = BeaconVerificationPipeline::new();
        assert!(p.mark_block_in_flight(block_hash(1)));
        assert!(!p.mark_block_in_flight(block_hash(1)));
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn mark_after_verified_returns_false() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(1));
        p.on_block_result(block_hash(1), true);
        assert!(!p.mark_block_in_flight(block_hash(1)));
    }

    #[test]
    fn on_result_valid_moves_to_verified() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(2));
        p.on_block_result(block_hash(2), true);
        assert!(!p.is_block_in_flight(block_hash(2)));
        assert!(p.is_block_verified(block_hash(2)));
    }

    #[test]
    fn on_result_invalid_just_clears_in_flight() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(3));
        p.on_block_result(block_hash(3), false);
        assert!(!p.is_block_in_flight(block_hash(3)));
        assert!(!p.is_block_verified(block_hash(3)));
    }

    #[test]
    fn on_result_for_unknown_slot_is_noop() {
        let mut p = BeaconVerificationPipeline::new();
        p.on_block_result(block_hash(99), true);
        assert!(!p.is_block_in_flight(block_hash(99)));
        assert!(!p.is_block_verified(block_hash(99)));
    }

    #[test]
    fn block_and_skip_request_pools_are_independent() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(5));
        p.mark_skip_request_in_flight(skip_key(5));
        assert_eq!(p.in_flight_count(), 2);
        p.on_block_result(block_hash(5), true);
        assert!(p.is_skip_request_in_flight(skip_key(5)));
        assert!(p.is_block_verified(block_hash(5)));
    }

    #[test]
    fn forget_clears_both_states() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_skip_request_in_flight(skip_key(7));
        p.on_skip_request_result(skip_key(7), true);
        p.forget_skip_request(skip_key(7));
        assert!(!p.is_skip_request_verified(skip_key(7)));

        p.mark_skip_request_in_flight(skip_key(8));
        p.forget_skip_request(skip_key(8));
        assert!(!p.is_skip_request_in_flight(skip_key(8)));
    }
}
