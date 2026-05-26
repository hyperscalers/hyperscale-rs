//! Beacon-chain skip primitive: per-validator skip attestations and the
//! pool-quorum certificate they assemble into.
//!
//! When the beacon chain stalls past [`SKIP_TIMEOUT`](crate::SKIP_TIMEOUT)
//! at a given anchor, active validators broadcast individually signed
//! [`SkipRequest`]s naming `(anchor_hash, epoch_to_skip)`. Once ⌈2M/3⌉ + 1
//! of the active pool sign the same pair, anyone can aggregate them into
//! a [`SkipEpochCert`] authenticating an empty skip block at
//! `epoch_to_skip`.
//!
//! Cert lives outside the block hash — see
//! [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock). Multiple
//! distinct certs (different signer subsets) at the same
//! `(anchor_hash, epoch_to_skip)` authenticate byte-identical block
//! hashes, so adoption converges.

use sbor::prelude::*;

use crate::{BeaconBlockHash, Bls12381G2Signature, Epoch, SignerBitfield, ValidatorId};

/// One active validator's signed vote that the chain should abandon
/// `epoch_to_skip`.
///
/// Gossiped all-to-all across the active validator pool. ⌈2M/3⌉ + 1
/// signers over the same `(anchor_hash, epoch_to_skip)` pair assemble
/// into a [`SkipEpochCert`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipRequest {
    anchor_hash: BeaconBlockHash,
    epoch_to_skip: Epoch,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl SkipRequest {
    /// Build a `SkipRequest` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch_to_skip,
            signer,
            sig,
        }
    }

    /// Hash of the anchor block the request is pinned to — the latest
    /// finalized block whose epoch immediately precedes
    /// [`Self::epoch_to_skip`].
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch the signer is voting to abandon.
    #[must_use]
    pub const fn epoch_to_skip(&self) -> Epoch {
        self.epoch_to_skip
    }

    /// Validator that signed this request.
    #[must_use]
    pub const fn signer(&self) -> ValidatorId {
        self.signer
    }

    /// BLS signature over the canonical signing message.
    #[must_use]
    pub const fn sig(&self) -> Bls12381G2Signature {
        self.sig
    }
}

/// Pool-quorum certificate: ⌈2M/3⌉ + 1 active signers attested that
/// `epoch_to_skip` should be abandoned at the anchor.
///
/// Carried as side-data on a
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) — never part
/// of the block hash. Multiple valid certs with different signer
/// subsets all authenticate the same block hash; adoption converges
/// on the unique hash.
///
/// `signers` is positionally indexed against the active validator pool
/// at the anchor's epoch (the same enumeration
/// `derive_active_pool(state)` produces). `aggregate_sig` verifies
/// under the union of the set bits' pubkeys over the canonical
/// skip-request signing bytes for `(anchor_hash, epoch_to_skip)`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipEpochCert {
    anchor_hash: BeaconBlockHash,
    epoch_to_skip: Epoch,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl SkipEpochCert {
    /// Build a `SkipEpochCert` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch_to_skip,
            signers,
            aggregate_sig,
        }
    }

    /// Anchor block hash the cert is pinned to.
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch the cert attests should be skipped.
    #[must_use]
    pub const fn epoch_to_skip(&self) -> Epoch {
        self.epoch_to_skip
    }

    /// Bitfield indexing the active pool's positional ordering at the
    /// anchor's epoch.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over the canonical
    /// `(anchor_hash, epoch_to_skip)` signing bytes, verifying under
    /// the union of [`Self::signers`]' pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Number of validators contributing to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn sample_request() -> SkipRequest {
        SkipRequest::new(
            anchor(),
            Epoch::new(7),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_cert() -> SkipEpochCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        SkipEpochCert::new(
            anchor(),
            Epoch::new(7),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn request_sbor_round_trip() {
        let original = sample_request();
        let bytes = basic_encode(&original).unwrap();
        let decoded: SkipRequest = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_sbor_round_trip() {
        let original = sample_cert();
        let bytes = basic_encode(&original).unwrap();
        let decoded: SkipEpochCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_signer_count_reflects_bitfield() {
        assert_eq!(sample_cert().signer_count(), 3);
    }
}
