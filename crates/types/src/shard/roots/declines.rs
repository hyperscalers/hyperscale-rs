//! [`DeclineRoot`]: the root over a block's crossing declines, one leaf
//! per refusal.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{CrossingDecline, DeclineRoot, Hash, LeafRoot};

/// Domain tag separating a decline's merkle leaf from every other leaf
/// preimage the codebase hashes.
const DECLINE_LEAF_TAG: &[u8] = b"hyperscale.crossing_decline_leaf.v1";

impl LeafRoot for DeclineRoot {
    type Leaf = CrossingDecline;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One decline's leaf: the tag and its canonical encoding — the
    /// record refused and the cell the producer committed for it — so
    /// two blocks claiming the same root write the same cells and refuse
    /// on the same terms.
    ///
    /// # Panics
    ///
    /// If the decline does not encode, which a value carrying a record
    /// cell under its own cap always does.
    fn leaf(decline: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(decline).expect("a crossing decline encodes");
        Hash::from_parts(&[DECLINE_LEAF_TAG, &bytes])
    }
}
