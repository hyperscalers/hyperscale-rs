//! Shard consensus timeout share.
//!
//! [`Timeout`] is a validator's signed claim that it timed out at `round`,
//! carrying its `high_qc` so the next leader can adopt and extend the highest
//! certified block. Its verified form is `Verified<Timeout>`; predicate at
//! [`impl Verify<&TimeoutContext<'_>>`](Verify::verify) below.
//!
//! The BLS share covers only `(shard, round)`. The carried `high_qc` is a
//! self-authenticating quorum certificate (its own 2f+1 aggregate), so a
//! recipient verifies it as a QC against the committee rather than trusting a
//! field bound in the timeout signature — which is what lets HotStuff-2's
//! pacemaker work without a timeout certificate on the wire.

use thiserror::Error;

use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, NetworkDefinition,
    QuorumCertificate, Round, ShardId, ValidatorId, Verified, Verify, timeout_message,
    verify_bls12381_v1,
};

/// A validator's timeout for a shard consensus round.
///
/// Broadcast when the round timer fires, instead of advancing locally. On
/// `2f+1` timeouts for a round, every honest replica adopts the maximum
/// `high_qc` among them and advances together — the quorum-driven view change
/// that keeps voters synchronised.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct Timeout {
    shard_id: ShardId,
    round: Round,
    high_qc: QuorumCertificate,
    voter: ValidatorId,
    signature: Bls12381G2Signature,
}

impl Timeout {
    /// Create a new timeout with domain-separated signing over `(shard, round)`.
    #[must_use]
    pub fn new(
        network: &NetworkDefinition,
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
    ) -> Self {
        let message = timeout_message(network, shard_id, round);
        let signature = signing_key.sign_v1(&message);
        Self {
            shard_id,
            round,
            high_qc,
            voter,
            signature,
        }
    }

    /// Build a `Timeout` from its parts without re-signing. Caller is
    /// responsible for the signature being valid for the other fields.
    #[must_use]
    pub const fn from_parts(
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signature: Bls12381G2Signature,
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

    /// BLS signature over the domain-separated signing message.
    #[must_use]
    pub const fn signature(&self) -> Bls12381G2Signature {
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
        Bls12381G2Signature,
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
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        timeout_message(network, self.shard_id, self.round)
    }
}

/// Inputs the [`Timeout`] verifier reads against. Borrows everything; nothing
/// is consumed.
///
/// Note this checks only the timeout's *own* BLS share. The carried `high_qc`
/// is a QC and must be verified separately (against the committee) before it
/// is adopted — see the pacemaker.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// BLS public key of the validator who timed out.
    pub voter_public_key: &'a Bls12381G1PublicKey,
}

/// Failure modes of [`Timeout`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TimeoutVerifyError {
    /// The BLS signature did not validate against the voter's public key
    /// for the timeout's domain-separated signing message.
    #[error("BLS signature invalid")]
    InvalidSignature,
}

/// Construction asserts: the BLS signature on the timeout validates against
/// the voter's public key for the domain-separated signing message
/// `timeout_message(network, shard, round)`. It does **not** assert anything
/// about the carried `high_qc` — that is verified as a QC where it is adopted.
///
/// Construction goes through one of two gates:
///
/// - [`<Timeout as Verify>::verify`](Verify::verify) — runs the BLS signature
///   check against the voter's public key.
/// - [`Verified::<Timeout>::sign_local`] — signs a fresh timeout with the
///   caller's key; the act of signing is the predicate witness.
impl Verify<&TimeoutContext<'_>> for Timeout {
    type Error = TimeoutVerifyError;

    fn verify(&self, ctx: &TimeoutContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let message = self.signing_message(ctx.network);
        if !verify_bls12381_v1(&message, ctx.voter_public_key, &self.signature) {
            return Err(TimeoutVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Timeout> {
    /// Sign a fresh [`Timeout`] with `signing_key` and return its verified form.
    ///
    /// The predicate holds by construction: the BLS signature over the
    /// canonical `timeout_message` is produced from `signing_key` inside this
    /// call. Used at the pacemaker site that echoes the signed timeout back to
    /// the local `TimeoutKeeper`.
    #[must_use]
    pub fn sign_local(
        network: &NetworkDefinition,
        shard_id: ShardId,
        round: Round,
        high_qc: QuorumCertificate,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
    ) -> Self {
        // SAFETY: the BLS signature is produced by `signing_key` over the
        // canonical `timeout_message`, which is exactly the `Timeout::verify`
        // predicate's check against this voter's matching pubkey.
        Self::new_unchecked(Timeout::new(
            network,
            shard_id,
            round,
            high_qc,
            voter,
            signing_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeight, SignerBitfield, WeightedTimestamp, generate_bls_keypair,
        zero_bls_signature,
    };

    const SHARD: ShardId = ShardId::ROOT;

    fn high_qc_at(round: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::ZERO,
            SHARD,
            BlockHeight::new(round),
            BlockHash::ZERO,
            Round::new(round),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    #[test]
    fn sign_local_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let key = generate_bls_keypair();
        let timeout = Verified::<Timeout>::sign_local(
            &net,
            SHARD,
            Round::new(7),
            high_qc_at(3),
            ValidatorId::new(2),
            &key,
        )
        .into_inner();

        assert_eq!(timeout.round(), Round::new(7));
        assert_eq!(timeout.high_qc_round(), Round::new(3));
        let pk = key.public_key();
        assert!(
            timeout
                .verify(&TimeoutContext {
                    network: &net,
                    voter_public_key: &pk,
                })
                .is_ok()
        );
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let net = NetworkDefinition::simulator();
        let key = generate_bls_keypair();
        let timeout = Timeout::new(
            &net,
            SHARD,
            Round::new(5),
            high_qc_at(1),
            ValidatorId::new(0),
            &key,
        );

        let intruder = generate_bls_keypair().public_key();
        assert!(matches!(
            timeout.verify(&TimeoutContext {
                network: &net,
                voter_public_key: &intruder,
            }),
            Err(TimeoutVerifyError::InvalidSignature),
        ));
    }
}
