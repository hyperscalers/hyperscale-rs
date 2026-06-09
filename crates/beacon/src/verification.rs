//! Async-verification bookkeeping for beacon-side crypto checks.
//!
//! Pure verifiers live alongside their wire types in
//! [`hyperscale_types::beacon`]; this module owns the in-flight slot
//! pools the coordinator uses to dedup crypto-check dispatch.

use std::collections::BTreeSet;

use hyperscale_types::{BeaconBlockHash, Epoch, ValidatorId};

/// In-flight verification slots over an arbitrary key.
///
/// A slot is marked when the verification action is dispatched and
/// cleared when the result lands (or the slot is otherwise no longer
/// needed). A marked slot suppresses redundant redispatch of the same
/// check. Reused by [`BeaconVerificationPipeline`] (block + skip-request
/// slots) and by [`SpcDriver`](crate::spc_driver::SpcDriver) (PC-vote +
/// SPC-message slots).
#[derive(Debug)]
pub(crate) struct VerificationSlots<K> {
    in_flight: BTreeSet<K>,
}

impl<K> Default for VerificationSlots<K> {
    fn default() -> Self {
        Self {
            in_flight: BTreeSet::new(),
        }
    }
}

impl<K: Ord> VerificationSlots<K> {
    /// Returns `true` when newly inserted, `false` when a slot for this
    /// key is already in flight.
    #[must_use]
    pub(crate) fn mark_in_flight(&mut self, key: K) -> bool {
        self.in_flight.insert(key)
    }

    pub(crate) fn clear(&mut self, key: &K) {
        self.in_flight.remove(key);
    }

    #[must_use]
    pub(crate) fn is_in_flight(&self, key: &K) -> bool {
        self.in_flight.contains(key)
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.in_flight.len()
    }
}

/// Slot key for a pending skip-request sig verification.
///
/// Per-`(anchor, epoch_to_skip, signer)` — the canonical identity of a
/// skip request, independent of its signature bytes. Keying on identity
/// rather than the encoded-request hash bounds a Byzantine peer to one
/// in-flight slot per claimed signer: replaying the same triple with
/// forged signatures can't mint additional verification slots. The slot
/// clears on both verify arms (the key rides back in the result event),
/// so a failed forgery can't pin a signer's slot and block their later
/// honest request.
pub type SkipRequestSlotKey = (BeaconBlockHash, Epoch, ValidatorId);

/// Tracks the asynchronous block-cert and skip-request verifications the
/// coordinator dispatches to the crypto pool.
///
/// Suppresses redundant redispatch while a check is outstanding. The
/// PC-vote and SPC-message slot pools live on
/// [`SpcDriver`](crate::spc_driver::SpcDriver).
///
/// Two domains, each an independent in-flight slot pool:
/// - Block-cert verifications, keyed on [`BeaconBlockHash`].
/// - Skip-request sig verifications, keyed on
///   `(anchor, epoch_to_skip, signer)`.
///
/// Domains never share keys by construction — different `K` types per
/// slot pool.
#[derive(Debug, Default)]
pub struct BeaconVerificationPipeline {
    blocks: VerificationSlots<BeaconBlockHash>,
    skip_requests: VerificationSlots<SkipRequestSlotKey>,
}

impl BeaconVerificationPipeline {
    /// Empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a block-cert verification in flight. Returns `true` when
    /// newly inserted, `false` when a slot for this block is already in
    /// flight — caller treats `false` as "don't redispatch".
    pub fn mark_block_in_flight(&mut self, block_hash: BeaconBlockHash) -> bool {
        self.blocks.mark_in_flight(block_hash)
    }

    /// Clear the block slot once its verification result lands, or after
    /// the block is adopted.
    pub fn forget_block(&mut self, block_hash: BeaconBlockHash) {
        self.blocks.clear(&block_hash);
    }

    /// Mark a skip-request sig verification in flight. Same semantics as
    /// [`Self::mark_block_in_flight`].
    pub fn mark_skip_request_in_flight(&mut self, key: SkipRequestSlotKey) -> bool {
        self.skip_requests.mark_in_flight(key)
    }

    /// Clear the skip-request slot once its result lands.
    pub fn forget_skip_request(&mut self, key: SkipRequestSlotKey) {
        self.skip_requests.clear(&key);
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
    pub fn in_flight_count(&self) -> usize {
        self.blocks.len() + self.skip_requests.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Hash;

    use super::*;

    fn block_hash(seed: u8) -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(&[seed]))
    }

    fn skip_key(seed: u8) -> SkipRequestSlotKey {
        (
            BeaconBlockHash::from_raw(Hash::from_bytes(&[seed])),
            Epoch::new(u64::from(seed)),
            ValidatorId::new(u64::from(seed)),
        )
    }

    #[test]
    fn empty_after_new() {
        let p = BeaconVerificationPipeline::new();
        assert_eq!(p.in_flight_count(), 0);
        assert!(!p.is_block_in_flight(block_hash(0)));
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
    fn forget_clears_in_flight_and_allows_remark() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(2));
        p.forget_block(block_hash(2));
        assert!(!p.is_block_in_flight(block_hash(2)));
        // A cleared slot is markable again.
        assert!(p.mark_block_in_flight(block_hash(2)));
    }

    #[test]
    fn forget_unknown_slot_is_noop() {
        let mut p = BeaconVerificationPipeline::new();
        p.forget_block(block_hash(99));
        assert!(!p.is_block_in_flight(block_hash(99)));
        assert_eq!(p.in_flight_count(), 0);
    }

    #[test]
    fn domains_are_independent() {
        let mut p = BeaconVerificationPipeline::new();
        p.mark_block_in_flight(block_hash(5));
        p.mark_skip_request_in_flight(skip_key(5));
        assert_eq!(p.in_flight_count(), 2);
        p.forget_block(block_hash(5));
        assert_eq!(p.in_flight_count(), 1);
    }
}
