//! ExecutionVotesNotification message.

use hyperscale_types::{
    Bls12381G2Signature, ExecutionVote, MessagePriority, NetworkMessage, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched votes on transaction execution results within a shard.
///
/// 2f+1 matching votes create an ExecutionCertificate with aggregated BLS signature.
/// The sender signature authenticates the batch, allowing receivers to reject forged
/// vote batches before doing expensive per-vote BLS signature verification.
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
    pub fn signing_message(&self, shard: hyperscale_types::ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_vote_batch_message(shard, &self.votes)
    }

    /// Create a batch from a single vote.
    pub fn single(
        vote: ExecutionVote,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self::new(vec![vote], sender, sender_signature)
    }

    /// Get the votes.
    pub fn votes(&self) -> &[ExecutionVote] {
        &self.votes
    }

    /// Consume and return the votes.
    pub fn into_votes(self) -> Vec<ExecutionVote> {
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

impl NetworkMessage for ExecutionVotesNotification {
    fn message_type_id() -> &'static str {
        "execution.vote.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{zero_bls_signature, Hash, ShardGroupId, ValidatorId};

    #[test]
    fn test_execution_vote_batch() {
        let vote = ExecutionVote {
            transaction_hash: Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            writes_commitment: Hash::from_bytes(b"commitment"),
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        let batch =
            ExecutionVotesNotification::single(vote.clone(), ValidatorId(0), zero_bls_signature());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.votes()[0], vote);

        let extracted = batch.into_votes();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], vote);
    }

    #[test]
    fn test_empty_batch() {
        let votes = ExecutionVotesNotification::new(vec![], ValidatorId(0), zero_bls_signature());
        assert!(votes.is_empty());
        assert_eq!(votes.len(), 0);
    }

    #[test]
    fn test_message_type_id() {
        assert_eq!(
            ExecutionVotesNotification::message_type_id(),
            "execution.vote.batch"
        );
    }
}
