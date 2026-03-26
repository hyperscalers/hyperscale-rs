//! ExecutionWaveVotesNotification message.

use hyperscale_types::{
    Bls12381G2Signature, ExecutionWaveVote, MessagePriority, NetworkMessage, ShardGroupId,
    ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched wave votes on execution results within a shard.
///
/// Each wave vote covers all transactions in a deterministic wave partition
/// of a block. 2f+1 matching wave votes create an ExecutionWaveCertificate.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionWaveVotesNotification {
    /// The execution wave votes being sent.
    pub votes: Vec<ExecutionWaveVote>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ExecutionWaveVotesNotification {
    /// Create a new signed execution wave vote batch.
    pub fn new(
        votes: Vec<ExecutionWaveVote>,
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
    pub fn signing_message(&self, shard: ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_wave_vote_batch_message(shard, &self.votes)
    }

    /// Get the votes.
    pub fn votes(&self) -> &[ExecutionWaveVote] {
        &self.votes
    }

    /// Consume and return the votes.
    pub fn into_votes(self) -> Vec<ExecutionWaveVote> {
        self.votes
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Get the number of votes in the batch.
    pub fn len(&self) -> usize {
        self.votes.len()
    }
}

impl NetworkMessage for ExecutionWaveVotesNotification {
    fn message_type_id() -> &'static str {
        "execution.wave_vote.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
