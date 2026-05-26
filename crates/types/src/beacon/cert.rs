//! Authenticator for a [`BeaconBlock`](crate::BeaconBlock).
//!
//! Discriminates Genesis / Normal / Skip blocks without putting the
//! discriminator into the block hash — the cert is side-data on a
//! [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) wrapper, never
//! a field on the block itself.

use sbor::prelude::*;

use crate::{GenesisConfigHash, SkipEpochCert, SpcCert};

/// Authenticator for a beacon block.
///
/// - [`Self::Genesis`]: bootstrap-only. `config_hash` binds the chain
///   to a specific [`BeaconGenesisConfig`](crate::BeaconGenesisConfig).
/// - [`Self::Normal`]: an SPC cert finalising the epoch's committed
///   proposals.
/// - [`Self::Skip`]: a pool-quorum cert attesting the epoch was
///   abandoned. Multiple valid certs (different signer subsets) at the
///   same `(anchor, epoch)` are all legal; they all authenticate the
///   same block hash.
///
/// Pairing-invariant with [`BeaconBlock`](crate::BeaconBlock) is
/// enforced on construction of
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock):
///
/// - `Genesis` ⇔ `block.epoch == GENESIS` ∧ `committed_proposals.is_empty()`
/// - `Normal` ⇔ `block.epoch > GENESIS`
/// - `Skip` ⇔ `block.epoch > GENESIS` ∧ `committed_proposals.is_empty()`
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum BeaconCert {
    /// Bootstrap-only cert; binds the chain to a `BeaconGenesisConfig`.
    Genesis(GenesisConfigHash),
    /// SPC cert finalising a Normal-epoch block. Boxed so the enum
    /// stays compact when the variant is `Skip` or `Genesis`.
    Normal(Box<SpcCert>),
    /// Pool-quorum cert authenticating a skipped epoch.
    Skip(SkipEpochCert),
}

impl BeaconCert {
    /// Whether this is the `Genesis` variant.
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        matches!(self, Self::Genesis(_))
    }

    /// Whether this is the `Normal` variant.
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal(_))
    }

    /// Whether this is the `Skip` variant.
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Skip(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BeaconBlockHash, Bls12381G2Signature, Epoch, Hash, SignerBitfield};

    fn sample_skip_cert() -> SkipEpochCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn genesis_round_trip() {
        let original = BeaconCert::Genesis(GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg")));
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.is_genesis());
        assert!(!decoded.is_normal());
        assert!(!decoded.is_skip());
    }

    #[test]
    fn skip_round_trip() {
        let original = BeaconCert::Skip(sample_skip_cert());
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.is_skip());
        assert!(!decoded.is_normal());
    }
}
