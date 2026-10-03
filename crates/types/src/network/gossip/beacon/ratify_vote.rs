//! Ratify-vote gossip — broadcast to the active validator pool.

use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor};

use crate::network::{GossipMessage, TopicScope};
use crate::primitives::signer_bitfield::MAX_SIGNERS;
use crate::{MessageClass, NetworkMessage, RatifyVote, Verifiable};

/// Votes a prevote's proof carries. A proof is at most one quorum of
/// the pool, and a pool indexes a signer bitfield, so the bitfield's
/// cap bounds it.
pub type RatifyProof = Capped<Vec<Arc<Verifiable<RatifyVote>>>, MAX_SIGNERS>;

/// Broadcasts one active validator's signed epoch-ratification vote.
///
/// Gossiped across the full active validator pool; a quorum of active
/// signers precommitting the same
/// `(anchor_hash, epoch, round, block_hash)` assemble into a
/// [`RatifyCert`](crate::RatifyCert) committing the epoch's block.
/// Prevotes ride the same wrapper — the phase discriminator lives on
/// the inner vote.
///
/// A prevote carries `proof`: other signers' votes proving the newest
/// polka the sender has evidence of. Each proof vote is
/// self-authenticating and bound to its own `(anchor, epoch, round,
/// phase, block_hash)`, so a receiver treats it exactly as that vote
/// arriving on its own; the wrapper vouches for nothing. Votes are
/// published once, so the proof is what carries a polka to members
/// that lost its votes. Precommits carry an empty proof.
///
/// The inner [`RatifyVote`] is self-authenticating — it carries the
/// signer id and a signature. Each validator publishes a distinct
/// vote with their own signature, so per-publisher bytes differ and
/// gossipsub's bytes-id dedup handles accidental re-publications
/// without an explicit content-key dedup.
///
/// Wire decode lands the wrapper as `Verifiable::Unverified`;
/// locally-dispatched sends from a colocated signer preserve
/// `Verifiable::Verified`.
///
/// `MessageClass::Consensus` — ratification is commit-blocking: until
/// a precommit quorum assembles, the epoch's block doesn't exist.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct RatifyVoteGossip {
    /// The signed ratification vote.
    pub vote: Arc<Verifiable<RatifyVote>>,
    /// Votes proving the newest polka the sender has evidence of.
    pub proof: RatifyProof,
}

impl RatifyVoteGossip {
    /// Wrap a [`RatifyVote`] for gossip broadcast with no proof.
    /// Accepts a raw vote or a `Verified<RatifyVote>` — the wrapper
    /// preserves the marker.
    #[must_use]
    pub fn new(vote: impl Into<Arc<Verifiable<RatifyVote>>>) -> Self {
        Self::with_proof(vote, RatifyProof::empty())
    }

    /// Wrap a [`RatifyVote`] with the proof riding alongside it.
    #[must_use]
    pub fn with_proof(vote: impl Into<Arc<Verifiable<RatifyVote>>>, proof: RatifyProof) -> Self {
        Self {
            vote: vote.into(),
            proof,
        }
    }

    /// Get the inner vote (raw view, regardless of verification
    /// state).
    #[must_use]
    pub fn vote(&self) -> &RatifyVote {
        self.vote.as_unverified()
    }

    /// Consume into every vote the message carries — the sender's own,
    /// then its proof — each preserving its verification marker. A
    /// receiver admits each on its own merits.
    pub fn into_votes(self) -> impl Iterator<Item = Arc<Verifiable<RatifyVote>>> {
        std::iter::once(self.vote).chain(self.proof)
    }
}

impl NetworkMessage for RatifyVoteGossip {
    fn message_type_id() -> &'static str {
        "beacon.ratify_vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl GossipMessage for RatifyVoteGossip {
    const SCOPE: TopicScope = TopicScope::Global;
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{
        BeaconBlockHash, ConsensusSignature, Epoch, Hash, RatifyPhase, RatifyRound, ValidatorId,
    };

    fn sample_vote() -> RatifyVote {
        RatifyVote::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RatifyRound::new(2),
            RatifyPhase::Precommit,
            BeaconBlockHash::from_raw(Hash::from_bytes(b"block")),
            ValidatorId::new(3),
            ConsensusSignature::new([0x33; 96]),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let g = RatifyVoteGossip::new(Arc::new(Verifiable::from(sample_vote())));
        let bytes = hbor_to_vec(&g).unwrap();
        let decoded: RatifyVoteGossip = hbor_from_slice(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn hbor_round_trip_with_proof_yields_every_vote() {
        let proof = RatifyProof::new(vec![
            Arc::new(Verifiable::from(sample_vote())),
            Arc::new(Verifiable::from(sample_vote())),
        ])
        .unwrap();
        let g = RatifyVoteGossip::with_proof(Arc::new(Verifiable::from(sample_vote())), proof);
        let bytes = hbor_to_vec(&g).unwrap();
        let decoded: RatifyVoteGossip = hbor_from_slice(&bytes).unwrap();
        assert_eq!(g, decoded);
        assert_eq!(decoded.into_votes().count(), 3);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(RatifyVoteGossip::class(), MessageClass::Consensus);
    }

    #[test]
    fn scope_is_global() {
        assert!(matches!(RatifyVoteGossip::SCOPE, TopicScope::Global));
    }
}
