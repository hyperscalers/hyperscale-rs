//! `ShardForkProof` gossip message for broadcasting committee-fork evidence.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{MessageClass, NetworkMessage, ShardForkProof, ShardId};

/// Gossips a shard fork proof globally.
///
/// A [`ShardForkProof`] is self-authenticating — it carries the accused
/// committee's own QCs — so the message needs no sender signature: every
/// recipient re-verifies the proof against its local topology and fences
/// uniformly, trusting the evidence rather than the messenger. Broadcast
/// on first local verification (assembly or a verified gossip receipt) so
/// the whole network converges on the fence.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardForkProofGossip {
    /// The self-proving fork evidence.
    pub proof: Arc<ShardForkProof>,
}

impl NetworkMessage for ShardForkProofGossip {
    fn message_type_id() -> &'static str {
        "shard.fork_proof"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for ShardForkProofGossip {
    const SCOPE: TopicScope = TopicScope::Global;

    fn source_shard(&self) -> Option<ShardId> {
        Some(self.proof.shard())
    }

    fn dedup_key(&self) -> Option<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // One fence per forked `(shard, height)`, so every node's copy of a
        // proof for the same fork collapses to a single key regardless of
        // which conflicting blocks each proof happens to carry.
        let mut hasher = DefaultHasher::new();
        self.proof.shard().hash(&mut hasher);
        self.proof.height().hash(&mut hasher);
        Some(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::BlockHeight;
    use crate::test_utils::{TestCommittee, shard_fork_proof};

    fn sample_proof() -> ShardForkProof {
        shard_fork_proof(
            &TestCommittee::new(4, 1),
            ShardId::ROOT,
            BlockHeight::new(5),
        )
    }

    #[test]
    fn message_type_id_is_stable() {
        assert_eq!(ShardForkProofGossip::message_type_id(), "shard.fork_proof");
    }

    #[test]
    fn sbor_round_trip() {
        let gossip = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        let bytes = basic_encode(&gossip).unwrap();
        let decoded: ShardForkProofGossip = basic_decode(&bytes).unwrap();
        assert_eq!(gossip, decoded);
    }

    #[test]
    fn dedup_key_folds_the_same_fork() {
        let g1 = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        let g2 = ShardForkProofGossip {
            proof: Arc::new(sample_proof()),
        };
        assert_eq!(g1.dedup_key(), g2.dedup_key());
        assert_eq!(g1.source_shard(), Some(ShardId::ROOT));
    }
}
