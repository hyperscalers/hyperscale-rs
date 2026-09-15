//! Positional `(SignerBitfield, parallel-item)` bundle.

use hyperscale_hbor::Hbor;

use crate::SignerBitfield;
use crate::primitives::signer_bitfield::MAX_SIGNERS;

/// A signer bitfield paired with one item per set bit, in set-bit order.
///
/// Replaces `Vec<(ValidatorId, T)>` shapes whose validator field is
/// purely positional metadata against the committee enumeration. The
/// bitfield carries identity; the parallel `items` vector carries
/// per-signer payload. Consumers iterate via [`iter`](Self::iter),
/// resolving each `(committee_index, &item)` pair through the committee
/// they already hold.
///
/// # Invariants
///
/// - `items.len() == signers.count_ones()`. Enforced at decode time.
/// - Pairing is positional: the k-th item belongs to the k-th set bit
///   in `signers.set_indices()` order.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(validate = check_positional)]
pub struct PositionalBundle<T> {
    signers: SignerBitfield,
    #[hbor(max = MAX_SIGNERS)]
    items: Vec<T>,
}

/// The cross-field invariant, run at the wire boundary: without it a peer
/// can supply mismatched lengths and [`PositionalBundle::iter`] produces a
/// silently truncated stream.
fn check_positional<T>(bundle: &PositionalBundle<T>) -> Result<(), &'static str> {
    if bundle.items.len() == bundle.signers.count_ones() {
        Ok(())
    } else {
        Err("items must pair one-to-one with set signer bits")
    }
}

impl<T> PositionalBundle<T> {
    /// Build a `PositionalBundle` from a bitfield and matching items.
    ///
    /// # Panics
    ///
    /// Panics if `items.len() != signers.count_ones()` or if `items.len() > MAX_SIGNERS`.
    #[must_use]
    pub fn new(signers: SignerBitfield, items: Vec<T>) -> Self {
        assert_eq!(
            items.len(),
            signers.count_ones(),
            "PositionalBundle: items length must match signer count",
        );
        assert!(
            items.len() <= MAX_SIGNERS,
            "PositionalBundle: items past the signer cap",
        );
        Self { signers, items }
    }

    /// Empty bundle (no signers, no items).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            signers: SignerBitfield::empty(),
            items: Vec::new(),
        }
    }

    /// Signer bitfield.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Number of `(index, item)` pairs.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the bundle is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Iterate `(committee_index, &item)` pairs in set-bit order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &T)> + '_ {
        self.signers.set_indices().zip(self.items.iter())
    }

    /// Borrow the items as a slice, in set-bit order.
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    fn bitfield(num_validators: usize, set: &[usize]) -> SignerBitfield {
        let mut bf = SignerBitfield::new(num_validators);
        for &i in set {
            bf.set(i);
        }
        bf
    }

    #[test]
    fn new_pairs_items_with_set_bits_in_order() {
        let bf = bitfield(10, &[1, 4, 7]);
        let bundle = PositionalBundle::new(bf, vec!["a", "b", "c"]);
        let pairs: Vec<_> = bundle.iter().collect();
        assert_eq!(pairs, vec![(1, &"a"), (4, &"b"), (7, &"c")]);
    }

    #[test]
    #[should_panic(expected = "items length must match signer count")]
    fn new_panics_on_length_mismatch() {
        let bf = bitfield(10, &[1, 4, 7]);
        let _ = PositionalBundle::new(bf, vec!["a", "b"]);
    }

    #[test]
    fn empty_bundle_iterates_nothing() {
        let bundle: PositionalBundle<u32> = PositionalBundle::empty();
        assert!(bundle.is_empty());
        assert_eq!(bundle.iter().count(), 0);
    }

    #[test]
    fn hbor_round_trip() {
        let bf = bitfield(100, &[3, 50, 99]);
        let bundle = PositionalBundle::new(bf, vec![10u32, 20, 30]);
        let bytes = hbor_to_vec(&bundle).unwrap();
        let decoded: PositionalBundle<u32> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(bundle, decoded);
        let pairs: Vec<_> = decoded.iter().collect();
        assert_eq!(pairs, vec![(3, &10), (50, &20), (99, &30)]);
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Forge a tuple with bitfield count_ones=3 but items.len()=2.
        let bf = bitfield(10, &[0, 1, 2]);
        let items = vec![1u32, 2];
        let attacker = ManualBundle { signers: bf, items };
        let bytes = hbor_to_vec(&attacker).unwrap();
        let err = hbor_from_slice::<PositionalBundle<u32>>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    #[test]
    fn decode_accepts_canonical_match() {
        let bf = bitfield(10, &[0, 1, 2]);
        let items = vec![1u32, 2, 3];
        let canonical = ManualBundle { signers: bf, items };
        let bytes = hbor_to_vec(&canonical).unwrap();
        let decoded: PositionalBundle<u32> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
    }

    /// Mirror of `PositionalBundle`'s wire layout for forging test
    /// payloads.
    #[derive(Hbor)]
    struct ManualBundle {
        signers: SignerBitfield,
        items: Vec<u32>,
    }
}
