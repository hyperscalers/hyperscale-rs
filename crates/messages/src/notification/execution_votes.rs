//! `ExecutionVotesNotification` message.

use hyperscale_types::{
    Bls12381G2Signature, ExecutionVote, MessagePriority, NetworkMessage, ShardGroupId, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched execution votes within a shard.
///
/// Each vote covers all transactions in a deterministic wave partition
/// of a block. 2f+1 matching votes create an `ExecutionCertificate`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVotesNotification {
    /// The execution votes being sent.
    pub votes: Vec<ExecutionVote>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ExecutionVotesNotification {
    /// Create a new signed execution vote batch.
    #[must_use]
    pub fn new(
        votes: Vec<ExecutionVote>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            votes,
            sender,
            sender_signature,
        }
    }

    /// Build the canonical signing message for this batch.
    #[must_use]
    pub fn signing_message(&self, shard: ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_vote_batch_message(shard, &self.votes)
    }

    /// Get the votes.
    #[must_use]
    pub fn votes(&self) -> &[ExecutionVote] {
        &self.votes
    }

    /// Consume and return the votes.
    #[must_use]
    pub fn into_votes(self) -> Vec<ExecutionVote> {
        self.votes
    }

    /// Check if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Get the number of votes in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.votes.len()
    }
}

impl NetworkMessage for ExecutionVotesNotification {
    fn message_type_id() -> &'static str {
        "execution.vote.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
