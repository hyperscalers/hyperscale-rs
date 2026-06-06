//! `ExecutionVotesNotification` message.

use sbor::prelude::BasicSbor;

use crate::{
    Bls12381G2Signature, ExecutionVote, MessageClass, NetworkDefinition, NetworkMessage, ShardId,
    Signed, ValidatorId, Verifiable, exec_vote_batch_message,
};

/// Batched execution votes within a shard.
///
/// Each vote covers all transactions in a deterministic wave partition
/// of a block. 2f+1 matching votes create an `ExecutionCertificate`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVotesNotification {
    /// The execution votes being sent. Wire bytes always land in
    /// [`Verifiable::Unverified`]; local-dispatched sends from a
    /// colocated voter preserve [`Verifiable::Verified`].
    pub votes: Vec<Verifiable<ExecutionVote>>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ExecutionVotesNotification {
    /// Create a new signed execution vote batch.
    #[must_use]
    pub const fn new(
        votes: Vec<Verifiable<ExecutionVote>>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            votes,
            sender,
            sender_signature,
        }
    }

    /// Get the votes.
    #[must_use]
    pub fn votes(&self) -> &[Verifiable<ExecutionVote>] {
        &self.votes
    }

    /// Consume and return the votes.
    #[must_use]
    pub fn into_votes(self) -> Vec<Verifiable<ExecutionVote>> {
        self.votes
    }

    /// Check if the batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Get the number of votes in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.votes.len()
    }
}

impl Signed for ExecutionVotesNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &Bls12381G2Signature {
        &self.sender_signature
    }

    /// Derives the batch's shard from `votes[0]`. Empty batches use a
    /// sentinel shard so the resulting message can never match a real
    /// signature; the `IoLoop` also early-drops empty batches before
    /// verification, so this branch is defensive only.
    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        let shard = self.votes.first().map_or(ShardId::ROOT, |v| v.shard_id());
        exec_vote_batch_message(
            network,
            shard,
            self.votes.iter().map(Verifiable::as_unverified),
        )
    }
}

impl NetworkMessage for ExecutionVotesNotification {
    fn message_type_id() -> &'static str {
        "execution.vote.batch"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
