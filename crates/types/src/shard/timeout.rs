//! Shard consensus timeout share.
//!
//! [`Timeout`] is a validator's signed claim that it timed out at `round`,
//! carrying its `high_qc` so the next leader can adopt and extend the highest
//! certified block. Its verified form is `Verified<Timeout>`; predicate at
//! [`impl Verify<&TimeoutContext<'_>>`](Verify::verify) below.
//!
//! The signature share covers `(shard, round, high_qc_round)`. The carried
//! `high_qc` is a self-authenticating quorum certificate (its own 2f+1
//! aggregate), verified as a QC against the committee where it is adopted;
//! only its round is signed, so a timeout certificate assembled from shares
//! states each signer's reported round, which a proposal justified by it must
//! extend.

use hyperscale_crypto::{SignError, Signer, VerifiedSignature, Verifier};
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::signing::TimeoutMessage;
use crate::{
    ConsensusPublicKey, ConsensusSignature, NetworkDefinition, QuorumCertificate, Round, ShardId,
    TimeoutCertificate, ValidatorId, Verified, Verify, signed_bytes,
};

/// A validator's timeout for a shard consensus round.
///
/// Broadcast when the round timer fires, instead of advancing locally. On
/// `2f+1` timeouts for a round, every honest replica adopts the maximum
/// `high_qc` among them and advances together — the quorum-driven view change
/// that keeps voters synchronised.
///
/// A signature covers [`TimeoutMessage`] — `(shard_id, round,
/// high_qc_round)` under the network context. `high_qc` is held out as
/// self-authenticating, and `voter` is held out so shares reporting the same
/// round sign the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct Timeout {
    shard_id: ShardId,
    round: Round,
    /// `high_qc`'s round, signed: the bound this share reports to a
    /// timeout certificate. [`Verify`] rejects a share whose carried QC
    /// disagrees with it.
    high_qc_round: Round,
    high_qc: QuorumCertificate,
    /// The sender's highest timeout certificate, outside the signature
    /// and self-authenticating: a receiver behind the round it abandons
    /// syncs its view to it.
    high_tc: Option<TimeoutCertificate>,
    voter: ValidatorId,
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
        let mut timeout = Self {
            shard_id,
            round,
            high_qc_round: high_qc.round(),
            high_qc,
            high_tc: None,
            voter,
            signature: ConsensusSignature::ZERO,
        };
        timeout.signature = signer.sign(&timeout.signing_message(network))?;
        Ok(timeout)
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

    /// Round of the carried `high_qc`, as signed.
    #[must_use]
    pub const fn high_qc_round(&self) -> Round {
        self.high_qc_round
    }

    /// The sender's highest timeout certificate, unverified.
    #[must_use]
    pub const fn high_tc(&self) -> Option<&TimeoutCertificate> {
        self.high_tc.as_ref()
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

    /// Build the canonical signing message for this timeout.
    #[must_use]
    pub(crate) fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &TimeoutMessage {
                shard_id: self.shard_id,
                round: self.round,
                high_qc_round: self.high_qc_round,
            },
            network,
        )
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
    /// The signed `high_qc_round` is not the carried QC's round.
    #[error("signed high QC round disagrees with the carried QC")]
    HighQcRoundMismatch,
}

/// Construction asserts: the signature on the timeout validates against
/// the voter's public key for the timeout's own domain-separated signing
/// bytes, and the signed `high_qc_round` is the carried QC's round. It does
/// **not** verify the carried `high_qc` itself — that is verified as a QC
/// where it is adopted.
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
        if self.high_qc_round != self.high_qc.round() {
            return Err(TimeoutVerifyError::HighQcRoundMismatch);
        }
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
    /// The timeout's signature as a [`VerifiedSignature`]: every gate that
    /// makes this value either checks the signature against the voter's
    /// key or produces it with the voter's signer.
    #[must_use]
    pub(crate) fn verified_signature(&self) -> VerifiedSignature {
        VerifiedSignature::new_unchecked(self.as_ref().signature)
    }

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

    /// Carry `high_tc` beside the share. It sits outside the signed
    /// message and is checked where it is used, so attaching it leaves the
    /// share's predicate as it was.
    #[must_use]
    pub fn with_high_tc(self, high_tc: Option<TimeoutCertificate>) -> Self {
        Self::new_unchecked(Timeout {
            high_tc,
            ..self.into_inner()
        })
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

    /// A share whose carried QC is swapped after signing no longer states
    /// the round its signature covers, and is refused.
    #[test]
    fn verify_rejects_a_carried_qc_the_signed_round_does_not_name() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let mut timeout = Timeout::new(
            &net,
            SHARD,
            Round::new(7),
            high_qc_at(3),
            ValidatorId::new(2),
            &signer,
        )
        .expect("sign");
        timeout.high_qc = high_qc_at(5);
        assert_eq!(
            timeout.verify(&TimeoutContext {
                verifier: &BlsVerifier,
                network: &net,
                voter_public_key: &signer.public_key(),
            }),
            Err(TimeoutVerifyError::HighQcRoundMismatch),
        );
    }

    /// The signed round is inside the signature: a share re-labelled with
    /// another round and a matching QC fails verification.
    #[test]
    fn verify_rejects_a_relabelled_high_qc_round() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let mut timeout = Timeout::new(
            &net,
            SHARD,
            Round::new(7),
            high_qc_at(3),
            ValidatorId::new(2),
            &signer,
        )
        .expect("sign");
        timeout.high_qc = high_qc_at(5);
        timeout.high_qc_round = Round::new(5);
        assert_eq!(
            timeout.verify(&TimeoutContext {
                verifier: &BlsVerifier,
                network: &net,
                voter_public_key: &signer.public_key(),
            }),
            Err(TimeoutVerifyError::InvalidSignature),
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
