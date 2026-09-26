//! [`TickManifestRoot`]: the root over a block's tick manifest, one
//! leaf per line, in manifest order.

use hyperscale_hbor::to_vec as hbor_to_vec;

use crate::{Hash, LeafRoot, TickLine, TickManifestRoot};

/// Domain tag separating a tick line's merkle leaf from every other leaf
/// preimage the codebase hashes.
const TICK_LINE_LEAF_TAG: &[u8] = b"hyperscale.tick_line_leaf.v1";

impl LeafRoot for TickManifestRoot {
    type Leaf = TickLine;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    /// One line's leaf: the tag and its canonical encoding.
    ///
    /// # Panics
    ///
    /// If the line does not encode, which a line within its caps always
    /// does.
    fn leaf(line: &Self::Leaf) -> Hash {
        let bytes = hbor_to_vec(line).expect("a tick line encodes");
        Hash::from_parts(&[TICK_LINE_LEAF_TAG, &bytes])
    }
}
