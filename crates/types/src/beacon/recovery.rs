//! Beacon-chain recovery: timeout attestations and the self-authenticating
//! certificate they assemble into.
//!
//! When the beacon chain stalls past the recovery timeout at a given
//! anchor, active validators broadcast individually signed
//! [`RecoveryRequest`]s naming `(last_block_hash, last_block_epoch,
//! recovery_round)`. Once ≥⅔ of the active set sign the same triple,
//! anyone can aggregate them into a [`RecoveryCertificate`] that triggers
//! deterministic committee replacement at the consensus layer.
//!
//! Carried verbatim on the next finalized [`BeaconBlock`](crate::BeaconBlock).
//! Block-level authentication is the SPC cert, so the recovery cert
//! doesn't need a separate binding hash: any tamper changes the block
//! body and breaks the SPC cert's verifier-derived committee.

use sbor::prelude::*;

use crate::{
    BeaconBlockHash, Bls12381G2Signature, BoundedVec, Epoch, MAX_EXCLUDED_VALIDATORS,
    RecoveryRound, SignerBitfield, SpcCert, ValidatorId,
};

/// One active validator's signed attestation that the beacon chain has
/// not progressed past `(last_block_hash, last_block_epoch)` within the
/// recovery timeout.
///
/// Gossiped across the full active validator set; ≥⅔ of active signers
/// (one validator one vote) signing the same `(anchor, epoch, round)`
/// triple assemble into a [`RecoveryCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryRequest {
    last_block_hash: BeaconBlockHash,
    last_block_epoch: Epoch,
    recovery_round: RecoveryRound,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl RecoveryRequest {
    /// Build a `RecoveryRequest` from its parts.
    #[must_use]
    pub const fn new(
        last_block_hash: BeaconBlockHash,
        last_block_epoch: Epoch,
        recovery_round: RecoveryRound,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_epoch,
            recovery_round,
            signer,
            sig,
        }
    }

    /// Hash of the anchor block the request claims is the latest finalized.
    #[must_use]
    pub const fn last_block_hash(&self) -> BeaconBlockHash {
        self.last_block_hash
    }

    /// Epoch of the anchor block.
    #[must_use]
    pub const fn last_block_epoch(&self) -> Epoch {
        self.last_block_epoch
    }

    /// Which recovery attempt at this anchor this request belongs to.
    #[must_use]
    pub const fn recovery_round(&self) -> RecoveryRound {
        self.recovery_round
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

/// Self-authenticating certificate: ≥⅔ of active signers (one validator
/// one vote) attested that no finalization had occurred past
/// `(last_block_hash, last_block_epoch)` within their recovery timeout.
///
/// Triggers deterministic committee replacement when the cert is
/// observed by the beacon state machine. Carried verbatim inside the
/// next [`BeaconBlock`](crate::BeaconBlock); the SPC cert that
/// authenticates the block covers the recovery cert implicitly via
/// the block-level canonical encoding.
///
/// Signer membership is positional against the active validator set at
/// the anchor block's epoch — [`signers`](Self::signers) is a bitfield
/// indexed into that enumeration, paired with a single aggregate
/// signature that verifies under the union of the corresponding pubkeys.
///
/// `excluded_validators` lists the cumulative set of dead committees
/// from every failed recovery round for this anchor's epoch — used by
/// the recovery-aware committee sampler to avoid landing on
/// already-failed validators. Bounded by
/// [`MAX_EXCLUDED_VALIDATORS`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryCertificate {
    last_block_hash: BeaconBlockHash,
    last_block_epoch: Epoch,
    recovery_round: RecoveryRound,
    excluded_validators: BoundedVec<ValidatorId, MAX_EXCLUDED_VALIDATORS>,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl RecoveryCertificate {
    /// Build a `RecoveryCertificate` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `excluded_validators.len() > MAX_EXCLUDED_VALIDATORS`.
    #[must_use]
    pub fn new(
        last_block_hash: BeaconBlockHash,
        last_block_epoch: Epoch,
        recovery_round: RecoveryRound,
        excluded_validators: Vec<ValidatorId>,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_epoch,
            recovery_round,
            excluded_validators: excluded_validators.into(),
            signers,
            aggregate_sig,
        }
    }

    /// Cumulative set of validators excluded from the post-recovery
    /// committee sampler — the union of all dead committees across
    /// failed recovery rounds for this anchor's epoch.
    #[must_use]
    pub const fn excluded_validators(&self) -> &BoundedVec<ValidatorId, MAX_EXCLUDED_VALIDATORS> {
        &self.excluded_validators
    }

    /// Hash of the anchor block the cert pins as the chain's latest
    /// finalized.
    #[must_use]
    pub const fn last_block_hash(&self) -> BeaconBlockHash {
        self.last_block_hash
    }

    /// Epoch of the anchor block.
    #[must_use]
    pub const fn last_block_epoch(&self) -> Epoch {
        self.last_block_epoch
    }

    /// Which recovery attempt at this anchor produced this cert.
    #[must_use]
    pub const fn recovery_round(&self) -> RecoveryRound {
        self.recovery_round
    }

    /// Bitfield indicating which validators (by position in the active
    /// set at the anchor's epoch) contributed signatures.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over the canonical signing message,
    /// verifying under the union of the [`signers`](Self::signers)'
    /// pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Number of validators that contributed to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

/// Self-authenticating evidence that a single validator signed both:
///   1. a [`RecoveryRequest`] claiming `request.last_block_hash` was their
///      latest finalized view, AND
///   2. a finalized [`BeaconBlock`](crate::BeaconBlock) at an epoch
///      strictly greater than `request.last_block_epoch`.
///
/// The two attestations are semantically contradictory. The recovery
/// request is carried verbatim; the finalized block is collapsed to
/// just its [`SpcCert`] (the cert IS the committee aggregate; the
/// equivocator's bit is set in the cert's signer bitfield).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryEquivocation {
    /// Validator whose double-attestation is the evidence.
    pub validator: ValidatorId,
    /// Recovery request claiming the anchor was the validator's latest view.
    pub request: RecoveryRequest,
    /// Epoch of a finalized beacon block strictly past
    /// `request.last_block_epoch`.
    pub block_epoch: Epoch,
    /// SPC cert from that block. The verifier checks the cert validates
    /// as a real SPC cert under the epoch's committee, and that the
    /// equivocator's position is set in the cert's signer bitfield
    /// (`proof.all_signers` for Direct, `skip_reports.signers()` for
    /// Indirect).
    pub block_cert: SpcCert,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn sample_cert() -> RecoveryCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RecoveryRound::new(1),
            Vec::new(),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    fn sample_request() -> RecoveryRequest {
        RecoveryRequest::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RecoveryRound::new(1),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    #[test]
    fn cert_sbor_round_trip() {
        let original = sample_cert();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RecoveryCertificate = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn request_sbor_round_trip() {
        let original = sample_request();
        let bytes = basic_encode(&original).unwrap();
        let decoded: RecoveryRequest = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_signer_count_reflects_bitfield() {
        let cert = sample_cert();
        assert_eq!(cert.signer_count(), 3);
    }

    fn sample_recovery_equivocation() -> RecoveryEquivocation {
        use crate::{PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, SpcView};
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers.clone(),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        let proof = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            signers,
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        );
        RecoveryEquivocation {
            validator: ValidatorId::new(2),
            request: sample_request(),
            block_epoch: Epoch::new(8),
            block_cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: PcVector::empty(),
                proof,
            },
        }
    }

    #[test]
    fn recovery_equivocation_sbor_round_trip() {
        let e = sample_recovery_equivocation();
        let bytes = basic_encode(&e).unwrap();
        let decoded: RecoveryEquivocation = basic_decode(&bytes).unwrap();
        assert_eq!(e, decoded);
    }
}
