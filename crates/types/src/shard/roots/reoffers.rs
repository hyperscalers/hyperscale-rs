//! [`ReofferRoot`]: the root over a block's crossing re-offers, one leaf
//! per offer.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{CrossingReoffer, Hash, LeafRoot, ReofferRoot};

/// Domain tag separating a re-offer's merkle leaf from every other leaf
/// preimage the codebase hashes.
const REOFFER_LEAF_TAG: &[u8] = b"hyperscale.crossing_reoffer_leaf.v1";

impl LeafRoot for ReofferRoot {
    type Leaf = CrossingReoffer;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One offer's leaf: the tag and its canonical encoding — the
    /// consumer owed the claim, the transaction, and every record cell
    /// the bundle is built from — so two blocks claiming the same root
    /// build the same bundles.
    ///
    /// # Panics
    ///
    /// If the offer does not encode, which a value built through
    /// [`CrossingReoffer::new`] under its caps always does.
    fn leaf(offer: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(offer).expect("a crossing re-offer encodes");
        Hash::from_parts(&[REOFFER_LEAF_TAG, &bytes])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, AddressClass, LocalKey, RootMismatch, ShardId, SubstateKey, TxHash};

    fn key(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    fn offer(target: u64, seed: u8) -> CrossingReoffer {
        CrossingReoffer::new(
            ShardId::leaf(1, target),
            TxHash::from(Hash::from_bytes(&[seed; 8])),
            [key(seed)],
        )
    }

    #[test]
    fn an_empty_section_is_the_zero_root() {
        assert_eq!(ReofferRoot::over(&[]), ReofferRoot::ZERO);
    }

    #[test]
    fn every_term_of_an_offer_moves_the_root() {
        let base = ReofferRoot::over(&[offer(0, 1)]);
        assert_ne!(base, ReofferRoot::over(&[offer(1, 1)]));
        assert_ne!(base, ReofferRoot::over(&[offer(0, 2)]));
        assert_ne!(
            base,
            ReofferRoot::over(&[CrossingReoffer::new(
                ShardId::leaf(1, 0),
                TxHash::from(Hash::from_bytes(&[1; 8])),
                [key(1), key(2)],
            )]),
        );
    }

    #[test]
    fn a_section_verifies_against_the_root_it_computes_to() {
        use crate::{Verified, Verify};

        let section = vec![offer(0, 1), offer(1, 2)];
        let root = Verified::<ReofferRoot>::compute(&section).into_inner();
        assert!(root.verify(section.as_slice()).is_ok());
        assert!(matches!(
            root.verify([offer(0, 1)].as_slice()),
            Err(RootMismatch { .. })
        ));
    }
}
