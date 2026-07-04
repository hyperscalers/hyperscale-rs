//! Authenticator for a [`BeaconBlock`](crate::BeaconBlock).
//!
//! Discriminates Genesis / Normal / Skip blocks without putting the
//! discriminator into the block hash — the cert is side-data on a
//! [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) wrapper, never
//! a field on the block itself.

use sbor::prelude::*;

use crate::{GenesisConfigHash, RatifyCert, SpcCert};

/// Authenticator for a beacon block.
///
/// - [`Self::Genesis`]: bootstrap-only. `config_hash` binds the chain
///   to a specific [`BeaconGenesisConfig`](crate::BeaconGenesisConfig).
/// - [`Self::Normal`]: the committee's SPC certificate authenticating
///   the epoch's committed proposals, plus the pool's ratification
///   certificate committing the block. The SPC cert alone is a
///   proposal certificate — content, not commitment.
/// - [`Self::Skip`]: a pool ratification cert committing the epoch's
///   canonical skip block.
///
/// Every non-genesis commit is a pool quorum, so any two commit
/// certificates for one epoch share an honest signer whatever the
/// pool-to-committee ratio. Multiple valid certs (different signer
/// subsets, different rounds) at the same block hash are all legal;
/// they all authenticate the same block.
///
/// Pairing-invariant with [`BeaconBlock`](crate::BeaconBlock) is
/// enforced on construction of
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock):
///
/// - `Genesis` ⇔ `block.epoch == GENESIS` ∧ `committed_proposals.is_empty()`
/// - `Normal` ⇔ `block.epoch > GENESIS`
/// - `Skip` ⇔ `block.epoch > GENESIS` ∧ `committed_proposals.is_empty()`
/// - non-genesis ⇒ the ratify cert names the block's hash, epoch, and
///   parent
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum BeaconCert {
    /// Bootstrap-only cert; binds the chain to a `BeaconGenesisConfig`.
    Genesis(GenesisConfigHash),
    /// SPC proposal cert plus pool ratification cert finalising a
    /// Normal-epoch block.
    Normal {
        /// Committee certificate over the epoch's committed proposals.
        /// Boxed so the enum stays compact when the variant is `Skip`
        /// or `Genesis`.
        spc: Box<SpcCert>,
        /// Pool quorum committing the block.
        ratify: RatifyCert,
    },
    /// Pool ratification cert committing a skipped epoch.
    Skip(RatifyCert),
}

impl BeaconCert {
    /// The pool ratification cert committing this block, if the
    /// variant carries one (`Genesis` doesn't).
    #[must_use]
    pub const fn ratify(&self) -> Option<&RatifyCert> {
        match self {
            Self::Genesis(_) => None,
            Self::Normal { ratify, .. } | Self::Skip(ratify) => Some(ratify),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BeaconBlockHash, Bls12381G2Signature, Epoch, Hash, RatifyRound, SignerBitfield};

    fn sample_ratify_cert() -> RatifyCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RatifyCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RatifyRound::INITIAL,
            BeaconBlockHash::from_raw(Hash::from_bytes(b"block")),
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
    }

    #[test]
    fn skip_round_trip() {
        let original = BeaconCert::Skip(sample_ratify_cert());
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn ratify_accessor_covers_both_commit_variants() {
        let cert = sample_ratify_cert();
        assert!(
            BeaconCert::Genesis(GenesisConfigHash::from_raw(Hash::from_bytes(b"cfg")))
                .ratify()
                .is_none()
        );
        assert_eq!(BeaconCert::Skip(cert.clone()).ratify(), Some(&cert));
    }
}
