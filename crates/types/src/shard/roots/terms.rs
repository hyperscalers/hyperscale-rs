//! [`TermsRoot`]: the root over a block's terms section, one leaf per
//! entry, in section order.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{Hash, LeafRoot, StatedTerms, TermsRoot};

/// Domain tag separating a terms entry's merkle leaf from every other
/// leaf preimage the codebase hashes.
const TERMS_LEAF_TAG: &[u8] = b"hyperscale.terms_leaf.v1";

impl LeafRoot for TermsRoot {
    type Leaf = StatedTerms;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One entry's leaf: the tag and its canonical encoding.
    ///
    /// # Panics
    ///
    /// If the entry does not encode, which an entry within its caps
    /// always does.
    fn leaf(entry: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(entry).expect("a terms entry encodes");
        Hash::from_parts(&[TERMS_LEAF_TAG, &bytes])
    }
}
