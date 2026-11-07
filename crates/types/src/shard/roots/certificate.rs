//! [`CertificateRoot`]: the root over a block's finalizations, one leaf
//! per finalization's receipt hash.

use crate::{CertificateRoot, Finalization, Hash, LeafRoot, Verifiable};

impl LeafRoot for CertificateRoot {
    type Leaf = Verifiable<Finalization>;

    const ZERO: Self = Self::ZERO;

    fn from_raw(raw: Hash) -> Self {
        Self::from_raw(raw)
    }

    fn leaf(finalization: &Self::Leaf) -> Hash {
        finalization.receipt_hash().into_raw()
    }
}
