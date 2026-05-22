//! Beacon-chain recovery: timeout attestations and the self-authenticating
//! certificate they assemble into.
//!
//! When the beacon chain stalls past the recovery timeout at a given
//! anchor, active validators broadcast individually signed
//! [`RecoveryRequest`]s naming `(last_block_hash, last_block_slot,
//! recovery_round)`. Once ≥⅔ of the active set sign the same triple,
//! anyone can aggregate them into a [`RecoveryCertificate`] that triggers
//! deterministic committee replacement at the consensus layer.
//!
//! The cert's content hash rides inside the next [`BeaconBlockHeader`]'s
//! `recovery_cert_hash` field via [`recovery_cert_hash`], binding it into
//! the post-recovery committee's aggregate signature so the cert body
//! cannot be swapped post-hoc.

use sbor::prelude::*;

use crate::{
    BeaconBlockHash, Bls12381G2Signature, Hash, RecoveryCertHash, RecoveryRound, SignerBitfield,
    Slot, ValidatorId,
};

/// One active validator's signed attestation that the beacon chain has
/// not progressed past `(last_block_hash, last_block_slot)` within the
/// recovery timeout.
///
/// Gossiped across the full active validator set; ≥⅔ of active signers
/// (one validator one vote) signing the same `(anchor, slot, round)`
/// triple assemble into a [`RecoveryCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryRequest {
    last_block_hash: BeaconBlockHash,
    last_block_slot: Slot,
    recovery_round: RecoveryRound,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl RecoveryRequest {
    /// Build a `RecoveryRequest` from its parts.
    #[must_use]
    pub const fn new(
        last_block_hash: BeaconBlockHash,
        last_block_slot: Slot,
        recovery_round: RecoveryRound,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_slot,
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

    /// Slot of the anchor block.
    #[must_use]
    pub const fn last_block_slot(&self) -> Slot {
        self.last_block_slot
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
/// `(last_block_hash, last_block_slot)` within their recovery timeout.
///
/// Triggers deterministic committee replacement when the cert is
/// observed by the beacon state machine. The cert's content hash is
/// bound into the next [`BeaconBlockHeader`]'s `recovery_cert_hash` via
/// [`recovery_cert_hash`] so the post-recovery committee's aggregate
/// signature covers it.
///
/// Signer membership is positional against the active validator set at
/// the anchor block's epoch — [`signers`](Self::signers) is a bitfield
/// indexed into that enumeration, paired with a single aggregate
/// signature that verifies under the union of the corresponding pubkeys.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RecoveryCertificate {
    last_block_hash: BeaconBlockHash,
    last_block_slot: Slot,
    recovery_round: RecoveryRound,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl RecoveryCertificate {
    /// Build a `RecoveryCertificate` from its parts.
    #[must_use]
    pub const fn new(
        last_block_hash: BeaconBlockHash,
        last_block_slot: Slot,
        recovery_round: RecoveryRound,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            last_block_hash,
            last_block_slot,
            recovery_round,
            signers,
            aggregate_sig,
        }
    }

    /// Hash of the anchor block the cert pins as the chain's latest
    /// finalized.
    #[must_use]
    pub const fn last_block_hash(&self) -> BeaconBlockHash {
        self.last_block_hash
    }

    /// Slot of the anchor block.
    #[must_use]
    pub const fn last_block_slot(&self) -> Slot {
        self.last_block_slot
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

/// Content hash of an optional recovery certificate, used to bind the
/// cert into a [`BeaconBlockHeader`]'s
/// `recovery_cert_hash` field.
///
/// Returns [`RecoveryCertHash::ZERO`] for `None`. For `Some(cert)`,
/// returns the SBOR-encoded cert's hash under the workspace `Hash`
/// function.
///
/// # Cryptographic assumption
///
/// Aliasing condition: a `Some(cert)` whose SBOR hash happens to be all
/// zero would alias `None`. Under BLAKE3's pre-image resistance (~2^256)
/// and collision resistance (~2^128 birthday work for a 32-byte digest),
/// this is cryptographically infeasible — but if BLAKE3 were broken, an
/// attacker could swap the cert body to `None` while keeping the header
/// verifying against the same committee aggregate.
///
/// # Panics
///
/// Panics if SBOR encoding fails — `RecoveryCertificate` is a closed
/// SBOR type and encoding is infallible in practice.
#[must_use]
pub fn recovery_cert_hash(cert: Option<&RecoveryCertificate>) -> RecoveryCertHash {
    cert.map_or(RecoveryCertHash::ZERO, |c| {
        let bytes = basic_encode(c).expect("RecoveryCertificate serialization should never fail");
        RecoveryCertHash::from_raw(Hash::from_bytes(&bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> RecoveryCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Slot::new(7),
            RecoveryRound::new(1),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    fn sample_request() -> RecoveryRequest {
        RecoveryRequest::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Slot::new(7),
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

    #[test]
    fn recovery_cert_hash_of_none_is_zero() {
        assert_eq!(recovery_cert_hash(None), RecoveryCertHash::ZERO);
    }

    #[test]
    fn recovery_cert_hash_of_some_is_not_zero() {
        let cert = sample_cert();
        assert_ne!(recovery_cert_hash(Some(&cert)), RecoveryCertHash::ZERO);
    }

    #[test]
    fn recovery_cert_hash_is_content_sensitive() {
        let a = sample_cert();
        let b = RecoveryCertificate::new(
            a.last_block_hash(),
            a.last_block_slot(),
            a.recovery_round().next(),
            a.signers().clone(),
            a.aggregate_sig(),
        );
        assert_ne!(recovery_cert_hash(Some(&a)), recovery_cert_hash(Some(&b)));
    }

    #[test]
    fn recovery_cert_hash_is_deterministic() {
        let cert = sample_cert();
        assert_eq!(
            recovery_cert_hash(Some(&cert)),
            recovery_cert_hash(Some(&cert))
        );
    }
}
