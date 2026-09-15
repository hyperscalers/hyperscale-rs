//! `ExecutionVoteNotification` message.

use hyperscale_hbor::Hbor;

use crate::{ExecutionVote, MessageClass, NetworkMessage, Verifiable};

/// One validator's execution vote over a tick. 2f+1 matching votes create
/// an `ExecutionCertificate`.
///
/// Sent via unicast notification to the tick leader. The inner
/// [`ExecutionVote`] contains the voter identity and signature, making it
/// self-authenticating — the same shape the block vote beside it has, and
/// for the same reason: a relay has nothing to add to a vote that already
/// says who cast it.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ExecutionVoteNotification {
    /// The execution vote — wire bytes always land in
    /// `Verifiable::Unverified`; local-dispatched sends from a colocated
    /// voter preserve `Verifiable::Verified`.
    pub vote: Verifiable<ExecutionVote>,
}

impl ExecutionVoteNotification {
    /// Create a new execution vote notification message.
    #[must_use]
    pub fn new(vote: impl Into<Verifiable<ExecutionVote>>) -> Self {
        Self { vote: vote.into() }
    }

    /// Get the inner vote (raw view, regardless of verification state).
    #[must_use]
    pub fn vote(&self) -> &ExecutionVote {
        self.vote.as_unverified()
    }

    /// Consume and return the inner vote wrapper.
    #[must_use]
    pub fn into_vote(self) -> Verifiable<ExecutionVote> {
        self.vote
    }
}

impl NetworkMessage for ExecutionVoteNotification {
    fn message_type_id() -> &'static str {
        "execution.vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeight, ConsensusSignature, GlobalReceiptRoot, Hash, ShardId, TickId,
        ValidatorId, WeightedTimestamp,
    };

    fn vote() -> ExecutionVote {
        ExecutionVote::new(
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(10),
            WeightedTimestamp::from_millis(1_000),
            TickId::new(ShardId::ROOT, BlockHeight::new(3)),
            ShardId::ROOT,
            GlobalReceiptRoot::ZERO,
            0,
            Vec::new(),
            ValidatorId::new(2),
            ConsensusSignature::ZERO,
        )
    }

    #[test]
    fn the_notification_carries_the_vote_whole() {
        let notification = ExecutionVoteNotification::new(vote());
        assert_eq!(notification.vote(), &vote());
        assert_eq!(notification.into_vote().as_unverified(), &vote());
    }
}
