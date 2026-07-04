//! Ratify-vote gossip — broadcast to the active validator pool.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, RatifyVote, Verifiable};

/// Broadcasts one active validator's signed epoch-ratification vote.
///
/// Gossiped across the full active validator pool; ⌈2M/3⌉ + 1 active
/// signers precommitting the same
/// `(anchor_hash, epoch, round, block_hash)` assemble into a
/// [`RatifyCert`](crate::RatifyCert) committing the epoch's block.
/// Prevotes ride the same wrapper — the phase discriminator lives on
/// the inner vote.
///
/// The inner [`RatifyVote`] is self-authenticating — it carries the
/// signer id and a BLS signature. Each validator publishes a distinct
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct RatifyVoteGossip {
    /// The signed ratification vote.
    pub vote: Arc<Verifiable<RatifyVote>>,
}

impl RatifyVoteGossip {
    /// Wrap a [`RatifyVote`] for gossip broadcast. Accepts a raw vote
    /// or a `Verified<RatifyVote>` — the wrapper preserves the marker.
    #[must_use]
    pub fn new(vote: impl Into<Arc<Verifiable<RatifyVote>>>) -> Self {
        Self { vote: vote.into() }
    }

    /// Get the inner vote (raw view, regardless of verification
    /// state).
    #[must_use]
    pub fn vote(&self) -> &RatifyVote {
        self.vote.as_unverified()
    }

    /// Consume and return the inner vote, preserving the verification
    /// marker.
    #[must_use]
    pub fn into_vote(self) -> Arc<Verifiable<RatifyVote>> {
        self.vote
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
    use sbor::prelude::*;

    use super::*;
    use crate::{
        BeaconBlockHash, Bls12381G2Signature, Epoch, Hash, RatifyPhase, RatifyRound, ValidatorId,
    };

    fn sample_vote() -> RatifyVote {
        RatifyVote::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(7),
            RatifyRound::new(2),
            RatifyPhase::Precommit,
            BeaconBlockHash::from_raw(Hash::from_bytes(b"block")),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let g = RatifyVoteGossip::new(Arc::new(Verifiable::from(sample_vote())));
        let bytes = basic_encode(&g).unwrap();
        let decoded: RatifyVoteGossip = basic_decode(&bytes).unwrap();
        assert_eq!(g, decoded);
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
