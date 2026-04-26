//! `BlockVote` notification message.

use hyperscale_types::{BlockVote, MessagePriority, NetworkMessage};
use sbor::prelude::BasicSbor;

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
    pub fn new(vote: BlockVote) -> Self {
        Self { vote }
    }

    /// Get the inner block vote.
    #[must_use]
    pub fn vote(&self) -> &BlockVote {
        &self.vote
    }

    /// Consume and return the inner block vote.
    #[must_use]
    pub fn into_vote(self) -> BlockVote {
        self.vote
    }
}

// Network message implementation
impl NetworkMessage for BlockVoteNotification {
    fn message_type_id() -> &'static str {
        "block.vote"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        zero_bls_signature, BlockHash, BlockHeight, Hash, ProposerTimestamp, Round, ShardGroupId,
        ValidatorId,
    };

    use super::*;

    #[test]
    fn test_block_vote_gossip_creation() {
        let vote = BlockVote {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_hash")),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(10),
            round: Round::INITIAL,
            voter: ValidatorId(2),
            signature: zero_bls_signature(),
            timestamp: ProposerTimestamp(1_000_000_000_000),
        };

        let gossip = BlockVoteNotification::new(vote.clone());
        assert_eq!(gossip.vote(), &vote);
    }

    #[test]
    fn test_block_vote_gossip_into_vote() {
        let vote = BlockVote {
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"test")),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(5),
            round: Round::INITIAL,
            voter: ValidatorId(1),
            signature: zero_bls_signature(),
            timestamp: ProposerTimestamp(1_000_000_000_000),
        };

        let gossip = BlockVoteNotification::new(vote.clone());
        let extracted = gossip.into_vote();
        assert_eq!(extracted, vote);
    }
}
