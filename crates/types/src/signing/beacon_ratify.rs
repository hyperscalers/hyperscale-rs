//! Signing message for beacon epoch-ratification votes.
//!
//! Each active validator ratifies a beacon block for an epoch by signing
//! `(anchor_hash, epoch, round, phase, block_hash)`. A prevote and a
//! precommit at the same round sign different bytes, so neither can stand
//! in for the other; a quorum of precommits over the same tuple
//! aggregates into a [`RatifyCert`](crate::RatifyCert) committing the
//! block.
//!
//! The signing domain keeps a ratify sig from being confused with a PC
//! vote, a VRF reveal, or any other consensus message reusing the same
//! key material.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{BeaconBlockHash, Epoch, RatifyPhase, RatifyRound};

/// What a ratify vote's signature covers — also the message behind the
/// aggregate signature on the assembled
/// [`RatifyCert`](crate::RatifyCert).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-ratify-vote-v1", signing_context = NetworkId)]
pub struct RatifyVoteMessage {
    /// The commit-anchor hash the ratification round runs under.
    pub(crate) anchor_hash: BeaconBlockHash,
    /// The epoch being ratified.
    pub(crate) epoch: Epoch,
    /// Ratification round.
    pub(crate) round: RatifyRound,
    /// Prevote or precommit — the phase byte is load-bearing: without it
    /// a single signature could count toward both a polka and a commit.
    pub(crate) phase: RatifyPhase,
    /// The beacon block being ratified.
    pub(crate) block_hash: BeaconBlockHash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::signed_bytes;
    use crate::{Hash, NetworkDefinition};

    /// A prevote and a precommit over the same tuple sign different
    /// bytes.
    #[test]
    fn ratify_vote_message_differs_across_phases() {
        let mk = |phase| {
            signed_bytes(
                &RatifyVoteMessage {
                    anchor_hash: BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
                    epoch: Epoch::new(5),
                    round: RatifyRound::INITIAL,
                    phase,
                    block_hash: BeaconBlockHash::from_raw(Hash::from_bytes(b"block")),
                },
                &NetworkDefinition::simulator(),
            )
        };
        assert_ne!(mk(RatifyPhase::Prevote), mk(RatifyPhase::Precommit));
    }
}
