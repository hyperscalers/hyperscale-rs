//! [`EngagementRoot`]: the set root over the engagements a block's
//! provisions name, one leaf per entry.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{Engagement, EngagementRoot, Hash, SetRoot};

/// Domain tag separating an engagement's merkle leaf from every other
/// leaf preimage the codebase hashes.
const ENGAGEMENT_LEAF_TAG: &[u8] = b"hyperscale.engagement_leaf.v1";

impl SetRoot for EngagementRoot {
    type Member = Engagement;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One entry's leaf: the tag and its canonical encoding.
    ///
    /// # Panics
    ///
    /// Never: an entry is three fixed-width fields.
    fn leaf(engagement: &Engagement) -> Hash {
        let bytes = hbor_to_vec(engagement).expect("an engagement encodes");
        Hash::from_parts(&[ENGAGEMENT_LEAF_TAG, &bytes])
    }
}
