//! Timeout certificate: a quorum's proof that a shard consensus round was
//! abandoned.
//!
//! A [`TimeoutCertificate`] aggregates the [`Timeout`] shares of a quorum for
//! one round. Each share signs the round of the QC its signer reported, so the
//! certificate states every signer's reported round and a proposal that skips
//! rounds on it can be held to extend at least the highest of them. Its
//! verified form is `Verified<TimeoutCertificate>`; predicate at
//! [`impl Verify<&TimeoutCertificateContext<'_>>`](Verify::verify) below.

use hyperscale_crypto::Verifier;
use hyperscale_hbor::{Capped, Hbor};
use thiserror::Error;

use crate::primitives::signer_bitfield::MAX_SIGNERS;
use crate::signing::TimeoutMessage;
use crate::{
    AggregateSignature, ConsensusPublicKey, ConsensusSignature, NetworkDefinition,
    PositionalBundle, QuorumCertificate, Round, ShardId, SignerBitfield, Timeout, Verified, Verify,
    VoteCount, signed_bytes,
};

/// A quorum of timeout shares for one round of one shard's consensus.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct TimeoutCertificate {
    shard_id: ShardId,
    round: Round,
    /// Each signer's reported `high_qc_round`, positional against the
    /// committee the certificate verifies under.
    high_qc_rounds: PositionalBundle<Round>,
    aggregated_signature: AggregateSignature,
    /// A QC at least as high as every reported round, carried as a hint for
    /// a holder that lacks it. Not part of the certificate's predicate: a
    /// holder adopts it through ordinary QC verification when it can.
    high_qc: QuorumCertificate,
}

impl TimeoutCertificate {
    /// Shard whose consensus the abandoned round belongs to.
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// The abandoned round.
    #[must_use]
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Committee positions of the signers.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        self.high_qc_rounds.signers()
    }

    /// The highest QC round any signer reported: the floor a proposal
    /// justified by this certificate must extend.
    #[must_use]
    pub fn max_high_qc_round(&self) -> Round {
        self.high_qc_rounds
            .items()
            .iter()
            .copied()
            .max()
            .unwrap_or(Round::INITIAL)
    }

    /// The carried QC hint — at least as high as
    /// [`Self::max_high_qc_round`], unverified.
    #[must_use]
    pub const fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }
}

/// Inputs a [`TimeoutCertificate`] verifies against: the committee the
/// caller names for it — the tip committee for view sync, the header's
/// committee for a proposal.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutCertificateContext<'a> {
    /// Network identifier — feeds the domain-separated signing messages.
    pub network: &'a NetworkDefinition,
    /// Public keys of the committee, in committee order.
    pub public_keys: &'a [ConsensusPublicKey],
    /// Minimum signer count that constitutes a quorum.
    pub quorum_threshold: VoteCount,
    /// Scheme verifier the aggregate check runs through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`TimeoutCertificate`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TimeoutCertificateVerifyError {
    /// No signer is set.
    #[error("timeout certificate has no signers")]
    NoSigners,
    /// A signer's position lies outside the committee.
    #[error("signer position {0} is outside the committee")]
    SignerOutsideCommittee(usize),
    /// The aggregate does not verify against the signers' messages.
    #[error("aggregated signature invalid")]
    InvalidSignature,
    /// The signers fall short of a quorum.
    #[error("insufficient quorum power: have {have:?}, need {need:?}")]
    InsufficientQuorumPower {
        /// Signers present.
        have: VoteCount,
        /// Signers a quorum needs.
        need: VoteCount,
    },
    /// The carried hint sits below a round a signer reported.
    #[error("carried high QC round {carried:?} is below the reported {reported:?}")]
    HintBelowReported {
        /// The hint's round.
        carried: Round,
        /// The highest reported round.
        reported: Round,
    },
}

impl Verify<&TimeoutCertificateContext<'_>> for TimeoutCertificate {
    type Error = TimeoutCertificateVerifyError;

    /// Every signer sits in the committee, signed [`TimeoutMessage`] for this
    /// round and its reported round, and together they make a quorum. The
    /// carried hint is checked only for sitting at or above the reported
    /// rounds.
    fn verify(&self, ctx: &TimeoutCertificateContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if self.high_qc_rounds.is_empty() {
            return Err(TimeoutCertificateVerifyError::NoSigners);
        }
        let mut messages = Vec::with_capacity(self.high_qc_rounds.len());
        let mut keys = Vec::with_capacity(self.high_qc_rounds.len());
        for (position, &high_qc_round) in self.high_qc_rounds.iter() {
            let key = ctx.public_keys.get(position).ok_or(
                TimeoutCertificateVerifyError::SignerOutsideCommittee(position),
            )?;
            keys.push(*key);
            messages.push(signed_bytes(
                &TimeoutMessage {
                    shard_id: self.shard_id,
                    round: self.round,
                    high_qc_round,
                },
                ctx.network,
            ));
        }
        let have = VoteCount::of(keys.len());
        if have < ctx.quorum_threshold {
            return Err(TimeoutCertificateVerifyError::InsufficientQuorumPower {
                have,
                need: ctx.quorum_threshold,
            });
        }
        let reported = self.max_high_qc_round();
        if self.high_qc.round() < reported {
            return Err(TimeoutCertificateVerifyError::HintBelowReported {
                carried: self.high_qc.round(),
                reported,
            });
        }
        let message_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        if !ctx.verifier.verify_aggregate_different_messages(
            &message_refs,
            &self.aggregated_signature,
            &keys,
        ) {
            return Err(TimeoutCertificateVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<TimeoutCertificate> {
    /// Aggregate verified shares for one round into a certificate.
    ///
    /// `shares` pairs each share with its signer's position in the committee
    /// the shares were verified under; they must all name `shard_id` and
    /// `round`. `high_qc` is the assembler's own QC, at or above every share's
    /// reported round. `None` when a share breaks either condition, when two
    /// shares hold one position, when they fall short of `quorum_threshold`,
    /// or when the signatures do not aggregate.
    ///
    /// The predicate holds by construction under that committee: each
    /// signature was verified against its signer's key over exactly the
    /// message the certificate re-derives for that position, and the signers
    /// make a quorum.
    #[must_use]
    pub fn from_verified_timeouts(
        verifier: &dyn Verifier,
        shard_id: ShardId,
        round: Round,
        shares: &[(usize, &Verified<Timeout>)],
        high_qc: QuorumCertificate,
        quorum_threshold: VoteCount,
    ) -> Option<Self> {
        if VoteCount::of(shares.len()) < quorum_threshold {
            return None;
        }
        let mut sorted: Vec<(usize, &Verified<Timeout>)> = shares.to_vec();
        sorted.sort_by_key(|(position, _)| *position);
        if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }
        if sorted.iter().any(|(_, share)| {
            share.shard_id() != shard_id
                || share.round() != round
                || share.high_qc_round() > high_qc.round()
        }) {
            return None;
        }
        let width = sorted.last().map(|(position, _)| position + 1)?;
        let mut signers = SignerBitfield::new(width);
        let mut rounds = Vec::with_capacity(sorted.len());
        let mut signatures: Vec<ConsensusSignature> = Vec::with_capacity(sorted.len());
        for (position, share) in &sorted {
            signers.set(*position);
            rounds.push(share.high_qc_round());
            signatures.push(share.signature());
        }
        let aggregated_signature = verifier.aggregate(&signatures).ok()?;
        let rounds: Capped<Vec<Round>, MAX_SIGNERS> = Capped::new(rounds).ok()?;
        Some(Self::new_unchecked(TimeoutCertificate {
            shard_id,
            round,
            high_qc_rounds: PositionalBundle::new(signers, rounds),
            aggregated_signature,
            high_qc,
        }))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHash, BlockHeight, ValidatorId, WeightedTimestamp};

    const SHARD: ShardId = ShardId::ROOT;
    const ROUND: Round = Round::new(9);

    fn qc_at(round: u64) -> QuorumCertificate {
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

    fn committee(n: usize) -> Vec<BlsSigner> {
        (0..n).map(|_| BlsSigner::generate()).collect()
    }

    fn share(keys: &[BlsSigner], position: usize, reported: u64) -> Verified<Timeout> {
        Verified::<Timeout>::sign_local(
            &NetworkDefinition::simulator(),
            SHARD,
            ROUND,
            qc_at(reported),
            ValidatorId::new(position as u64),
            &keys[position],
        )
        .expect("sign")
    }

    /// Assemble a certificate from `(position, reported round)` shares.
    fn certificate(keys: &[BlsSigner], reported: &[(usize, u64)], hint: u64) -> TimeoutCertificate {
        let shares: Vec<Verified<Timeout>> = reported
            .iter()
            .map(|&(position, round)| share(keys, position, round))
            .collect();
        let refs: Vec<(usize, &Verified<Timeout>)> = reported
            .iter()
            .map(|&(position, _)| position)
            .zip(&shares)
            .collect();
        Verified::<TimeoutCertificate>::from_verified_timeouts(
            &BlsVerifier,
            SHARD,
            ROUND,
            &refs,
            qc_at(hint),
            VoteCount::of(reported.len()),
        )
        .expect("assembles")
        .into_inner()
    }

    fn verify(
        tc: &TimeoutCertificate,
        keys: &[BlsSigner],
    ) -> Result<Verified<TimeoutCertificate>, TimeoutCertificateVerifyError> {
        let public_keys: Vec<ConsensusPublicKey> = keys.iter().map(Signer::public_key).collect();
        tc.verify(&TimeoutCertificateContext {
            network: &NetworkDefinition::simulator(),
            public_keys: &public_keys,
            quorum_threshold: VoteCount::of(3),
            verifier: &BlsVerifier,
        })
    }

    #[test]
    fn a_quorum_reporting_different_rounds_verifies() {
        let keys = committee(4);
        let tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        assert_eq!(tc.max_high_qc_round(), Round::new(7));
        assert!(verify(&tc, &keys).is_ok());
    }

    #[test]
    fn it_round_trips_through_hbor() {
        let keys = committee(4);
        let tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        let bytes = hbor_to_vec(&tc).expect("encode");
        let decoded: TimeoutCertificate = hbor_from_slice(&bytes).expect("decode");
        assert_eq!(decoded, tc);
    }

    #[test]
    fn short_of_a_quorum_it_fails() {
        let keys = committee(4);
        let tc = certificate(&keys, &[(0, 5), (1, 5)], 5);
        assert!(matches!(
            verify(&tc, &keys),
            Err(TimeoutCertificateVerifyError::InsufficientQuorumPower { .. })
        ));
    }

    /// Lowering a signer's reported round changes the message it must have
    /// signed, so the aggregate no longer verifies: the floor a certificate
    /// states cannot be understated after assembly.
    #[test]
    fn a_tampered_reported_round_fails() {
        let keys = committee(4);
        let mut tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        let signers = tc.high_qc_rounds.signers().clone();
        tc.high_qc_rounds = PositionalBundle::new(
            signers,
            Capped::from_array([Round::new(5), Round::new(5), Round::new(6)]),
        );
        assert_eq!(
            verify(&tc, &keys).err(),
            Some(TimeoutCertificateVerifyError::InvalidSignature),
        );
    }

    #[test]
    fn another_round_fails() {
        let keys = committee(4);
        let mut tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        tc.round = Round::new(10);
        assert_eq!(
            verify(&tc, &keys).err(),
            Some(TimeoutCertificateVerifyError::InvalidSignature),
        );
    }

    #[test]
    fn another_committee_fails() {
        let keys = committee(4);
        let tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        assert_eq!(
            verify(&tc, &committee(4)).err(),
            Some(TimeoutCertificateVerifyError::InvalidSignature),
        );
        assert_eq!(
            verify(&tc, &keys[..3]).err(),
            Some(TimeoutCertificateVerifyError::SignerOutsideCommittee(3)),
        );
    }

    #[test]
    fn a_hint_below_the_reported_rounds_fails() {
        let keys = committee(4);
        let mut tc = certificate(&keys, &[(0, 5), (1, 7), (3, 6)], 7);
        tc.high_qc = qc_at(6);
        assert!(matches!(
            verify(&tc, &keys),
            Err(TimeoutCertificateVerifyError::HintBelowReported { .. })
        ));
    }

    /// Assembly refuses shares reporting above the hint it is given, a
    /// position given twice, and too few shares for the quorum it is held to.
    #[test]
    fn assembly_refuses_a_share_above_its_hint_or_a_repeated_position() {
        let keys = committee(4);
        let (low, high) = (share(&keys, 0, 5), share(&keys, 1, 8));
        assert!(
            Verified::<TimeoutCertificate>::from_verified_timeouts(
                &BlsVerifier,
                SHARD,
                ROUND,
                &[(0, &low), (1, &high)],
                qc_at(7),
                VoteCount::of(2),
            )
            .is_none()
        );
        assert!(
            Verified::<TimeoutCertificate>::from_verified_timeouts(
                &BlsVerifier,
                SHARD,
                ROUND,
                &[(0, &low), (0, &low)],
                qc_at(7),
                VoteCount::of(2),
            )
            .is_none()
        );
        assert!(
            Verified::<TimeoutCertificate>::from_verified_timeouts(
                &BlsVerifier,
                SHARD,
                ROUND,
                &[(0, &low)],
                qc_at(7),
                VoteCount::of(3),
            )
            .is_none()
        );
    }
}
