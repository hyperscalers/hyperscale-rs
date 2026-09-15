//! Shard consensus timeout share.
//!
//! [`Timeout`] is a validator's signed claim that it timed out at `round`,
//! carrying its `high_qc` so the next leader can adopt and extend the highest
//! certified block. Its verified form is `Verified<Timeout>`; predicate at
//! [`impl Verify<&TimeoutContext<'_>>`](Verify::verify) below.
//!
//! The signature share covers only `(shard, round)`. The carried `high_qc` is a
//! self-authenticating quorum certificate (its own 2f+1 aggregate), so a
//! recipient verifies it as a QC against the committee rather than trusting a
//! field bound in the timeout signature — which is what lets HotStuff-2's
//! pacemaker work without a timeout certificate on the wire.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::signing::NetworkId;
use crate::{
    ConsensusPublicKey, ConsensusSignature, NetworkDefinition, QuorumCertificate, Round, ShardId,
    ValidatorId, Verified, Verify, signed_bytes,
};

/// A validator's timeout for a shard consensus round.
///
/// Broadcast when the round timer fires, instead of advancing locally. On
/// `2f+1` timeouts for a round, every honest replica adopts the maximum
/// `high_qc` among them and advances together — the quorum-driven view change
/// that keeps voters synchronised.
///
/// The type hosts its own signing domain: a signature covers `(shard_id,
/// round)` under the network context. `high_qc` is held out as
/// self-authenticating, and `voter` is held out so every timeout for a
/// round signs the same bytes — which is what lets shares aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-timeout-v1", signing_context = NetworkId)]
pub struct Timeout {
    shard_id: ShardId,
    round: Round,
    #[hbor(unsigned)]
    high_qc: QuorumCertificate,
    #[hbor(unsigned)]
    voter: ValidatorId,
    #[hbor(unsigned)]
    signature: ConsensusSignature,
}

impl Timeout {
    /// Create a new timeout with domain-separated signing over `(shard, round)`.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    pub fn new(
        network: &NetworkDefinition,
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signer: &dyn Signer,
    ) -> Result<Self, SignError> {
        // The signature is unsigned content, so the placeholder never
        // enters the bytes being signed.
        let mut timeout = Self {
            shard_id,
            round,
            high_qc,
            voter,
            signature: ConsensusSignature::ZERO,
        };
        timeout.signature = signer.sign(&signed_bytes(&timeout, network))?;
        Ok(timeout)
    }

    /// Build a `Timeout` from its parts without re-signing. Caller is
    /// responsible for the signature being valid for the other fields.
    #[must_use]
    pub const fn from_parts(
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signature: ConsensusSignature,
    ) -> Self {
        Self {
            shard_id,
            round,
            high_qc,
            voter,
            signature,
        }
    }

    /// Shard group this timeout belongs to (prevents cross-shard replay).
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Round the validator timed out on.
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// The validator's highest certified block at timeout — what the next
    /// leader adopts and extends. Carried as a full (self-authenticating) QC.
    #[must_use]
    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }

    /// Round of the carried `high_qc`.
    #[must_use]
    pub const fn high_qc_round(&self) -> Round {
        self.high_qc.round()
    }

    /// Validator who timed out.
    #[must_use]
    pub const fn voter(&self) -> ValidatorId {
        self.voter
    }

    /// Signature over the domain-separated signing message.
    #[must_use]
    pub const fn signature(&self) -> ConsensusSignature {
        self.signature
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ShardId,
        Round,
        QuorumCertificate,
        ValidatorId,
        ConsensusSignature,
    ) {
        (
            self.shard_id,
            self.round,
            self.high_qc,
            self.voter,
            self.signature,
        )
    }

    /// Build the canonical signing message for this timeout.
    #[must_use]
    pub(crate) fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(self, network)
    }
}

/// Inputs the [`Timeout`] verifier reads against. Borrows everything; nothing
/// is consumed.
///
/// Note this checks only the timeout's *own* signature share. The carried `high_qc`
/// is a QC and must be verified separately (against the committee) before it
/// is adopted — see the pacemaker.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// Public key of the validator who timed out.
    pub voter_public_key: &'a ConsensusPublicKey,
    /// Scheme verifier the signature check runs through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`Timeout`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TimeoutVerifyError {
    /// The signature did not validate against the voter's public key
    /// for the timeout's domain-separated signing message.
    #[error("signature invalid")]
    InvalidSignature,
}

/// Construction asserts: the signature on the timeout validates against
/// the voter's public key for the timeout's own domain-separated signing
/// bytes. It does **not** assert anything about the carried `high_qc` —
/// that is verified as a QC where it is adopted.
///
/// Construction goes through one of two gates:
///
/// - [`<Timeout as Verify>::verify`](Verify::verify) — runs the signature
///   check against the voter's public key.
/// - [`Verified::<Timeout>::sign_local`] — signs a fresh timeout with the
///   caller's key; the act of signing is the predicate witness.
impl Verify<&TimeoutContext<'_>> for Timeout {
    type Error = TimeoutVerifyError;

    fn verify(&self, ctx: &TimeoutContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let message = self.signing_message(ctx.network);
        if !ctx
            .verifier
            .verify(ctx.voter_public_key, &message, &self.signature)
        {
            return Err(TimeoutVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Timeout> {
    /// Sign a fresh [`Timeout`] with `signer` and return its verified form.
    ///
    /// The predicate holds by construction: the signature over the
    /// timeout's canonical signing bytes is produced by `signer` inside
    /// this call. Used at the pacemaker site that echoes the signed
    /// timeout back to the local `TimeoutKeeper`.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    pub fn sign_local(
        network: &NetworkDefinition,
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signer: &dyn Signer,
    ) -> Result<Self, SignError> {
        // SAFETY: the signature is produced by `signer` over the
        // timeout's canonical signing bytes, which is exactly the
        // `Timeout::verify` predicate's check against this voter's
        // matching pubkey.
        Ok(Self::new_unchecked(Timeout::new(
            network, shard_id, round, high_qc, voter, signer,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::{AggregateSignature, BlockHash, BlockHeight, SignerBitfield, WeightedTimestamp};

    const SHARD: ShardId = ShardId::ROOT;

    fn high_qc_at(round: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::ZERO,
            SHARD,
            BlockHeight::new(round),
            BlockHash::ZERO,
            Round::new(round),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    #[test]
    fn sign_local_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let timeout = Verified::<Timeout>::sign_local(
            &net,
            SHARD,
            Round::new(7),
            high_qc_at(3),
            ValidatorId::new(2),
            &signer,
        )
        .expect("sign")
        .into_inner();

        assert_eq!(timeout.round(), Round::new(7));
        assert_eq!(timeout.high_qc_round(), Round::new(3));
        assert!(
            timeout
                .verify(&TimeoutContext {
                    verifier: &BlsVerifier,
                    network: &net,
                    voter_public_key: &signer.public_key(),
                })
                .is_ok()
        );
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let timeout = Timeout::new(
            &net,
            SHARD,
            Round::new(5),
            high_qc_at(1),
            ValidatorId::new(0),
            &signer,
        )
        .expect("sign");

        let intruder = BlsSigner::generate();
        assert!(matches!(
            timeout.verify(&TimeoutContext {
                verifier: &BlsVerifier,
                network: &net,
                voter_public_key: &intruder.public_key(),
            }),
            Err(TimeoutVerifyError::InvalidSignature),
        ));
    }
}
