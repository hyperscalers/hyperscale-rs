//! BlockVote gossip message.

use hyperscale_types::{BlockVote, MessagePriority, NetworkMessage, ShardMessage};
use sbor::prelude::BasicSbor;

/// Vote on a block proposal. 2f+1 matching votes create a QuorumCertificate.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockVoteGossip {
    /// The block vote being gossiped
    pub vote: BlockVote,
}

impl BlockVoteGossip {
    /// Create a new block vote gossip message.
    pub fn new(vote: BlockVote) -> Self {
        Self { vote }
    }

    /// Get the inner block vote.
    pub fn vote(&self) -> &BlockVote {
        &self.vote
    }

    /// Consume and return the inner block vote.
    pub fn into_vote(self) -> BlockVote {
        self.vote
    }
}

// Network message implementation
impl NetworkMessage for BlockVoteGossip {
    fn message_type_id() -> &'static str {
        "block.vote"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

impl ShardMessage for BlockVoteGossip {}

#[cfg(test)]
mod tests {
    use hyperscale_types::{zero_bls_signature, BlockHeight, Hash, ShardGroupId, ValidatorId};

    use super::*;

    #[test]
    fn test_block_vote_gossip_creation() {
        let vote = BlockVote {
            block_hash: Hash::from_bytes(b"block_hash"),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(10),
            round: 0,
            voter: ValidatorId(2),
            signature: zero_bls_signature(),
            timestamp: 1000000000000,
        };

        let gossip = BlockVoteGossip::new(vote.clone());
        assert_eq!(gossip.vote(), &vote);
    }

    #[test]
    fn test_block_vote_gossip_into_vote() {
        let vote = BlockVote {
            block_hash: Hash::from_bytes(b"test"),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(5),
            round: 0,
            voter: ValidatorId(1),
            signature: zero_bls_signature(),
            timestamp: 1000000000000,
        };

        let gossip = BlockVoteGossip::new(vote.clone());
        let extracted = gossip.into_vote();
        assert_eq!(extracted, vote);
    }
}
