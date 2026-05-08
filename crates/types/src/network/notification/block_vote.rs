//! `BlockVote` notification message.

use sbor::prelude::BasicSbor;

use crate::{BlockVote, MessageClass, NetworkMessage};

/// Vote on a block proposal. 2f+1 matching votes create a `QuorumCertificate`.
///
/// Sent via unicast notification to committee members. The inner `BlockVote`
/// contains the voter identity and BLS signature, making it self-authenticating.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockVoteNotification {
    /// The block vote.
    pub vote: BlockVote,
}

impl BlockVoteNotification {
    /// Create a new block vote notification message.
    #[must_use]
    pub const fn new(vote: BlockVote) -> Self {
        Self { vote }
    }

    /// Get the inner block vote.
    #[must_use]
    pub const fn vote(&self) -> &BlockVote {
        &self.vote
    }

    /// Consume and return the inner block vote.
    #[must_use]
    pub const fn into_vote(self) -> BlockVote {
        self.vote
    }
}

// Network message implementation
impl NetworkMessage for BlockVoteNotification {
    fn message_type_id() -> &'static str {
        "block.vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeight, Hash, ProposerTimestamp, Round, ShardGroupId, ValidatorId,
        zero_bls_signature,
    };

    #[test]
    fn test_block_vote_gossip_creation() {
        let vote = BlockVote::from_parts(
            BlockHash::from_raw(Hash::from_bytes(b"block_hash")),
            ShardGroupId::new(0),
            BlockHeight::new(10),
            Round::INITIAL,
            ValidatorId::new(2),
            zero_bls_signature(),
            ProposerTimestamp::from_millis(1_000_000_000_000),
        );

        let gossip = BlockVoteNotification::new(vote.clone());
        assert_eq!(gossip.vote(), &vote);
    }

    #[test]
    fn test_block_vote_gossip_into_vote() {
        let vote = BlockVote::from_parts(
            BlockHash::from_raw(Hash::from_bytes(b"test")),
            ShardGroupId::new(0),
            BlockHeight::new(5),
            Round::INITIAL,
            ValidatorId::new(1),
            zero_bls_signature(),
            ProposerTimestamp::from_millis(1_000_000_000_000),
        );

        let gossip = BlockVoteNotification::new(vote.clone());
        let extracted = gossip.into_vote();
        assert_eq!(extracted, vote);
    }
}
