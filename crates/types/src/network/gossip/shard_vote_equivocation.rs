//! `ShardVoteEquivocation` gossip for broadcasting double-vote evidence.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::network::{GossipMessage, GossipScope};
use crate::{MessageClass, NetworkMessage, ShardId, ShardVoteEquivocation};

/// Gossips a shard double-vote pair globally.
///
/// A [`ShardVoteEquivocation`] is self-authenticating — both signatures
/// verify under the accused validator's registered pubkey — so the
/// message needs no sender signature: every recipient re-verifies the
/// pair and trusts the evidence rather than the messenger. Broadcast on
/// first local verification (vote-keeper detection or a verified gossip
/// receipt) so the evidence reaches the beacon even after every holder
/// has left the source committee.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ShardVoteEquivocationGossip {
    /// The self-proving double-vote pair.
    pub evidence: Arc<ShardVoteEquivocation>,
}

impl NetworkMessage for ShardVoteEquivocationGossip {
    fn message_type_id() -> &'static str {
        "shard.vote_equivocation"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for ShardVoteEquivocationGossip {
    const SCOPE: GossipScope = GossipScope::Global;

    fn source_shard(&self) -> Option<ShardId> {
        Some(self.evidence.shard)
    }

    fn dedup_key(&self) -> Option<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // One conviction per key, so every pair naming the same
        // validator collapses to a single dedup slot regardless of
        // which two blocks each copy happens to carry.
        let mut hasher = DefaultHasher::new();
        self.evidence.shard.hash(&mut hasher);
        self.evidence.validator.hash(&mut hasher);
        Some(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHash, BlockHeight, ConsensusSignature, Hash, Round, ValidatorId};

    fn sample() -> ShardVoteEquivocation {
        ShardVoteEquivocation {
            validator: ValidatorId::new(7),
            shard: ShardId::ROOT,
            height: BlockHeight::new(5),
            round: Round::new(2),
            block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"a")),
            parent_block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"pa")),
            sig_a: ConsensusSignature::ZERO,
            block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"b")),
            parent_block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"pb")),
            sig_b: ConsensusSignature::ZERO,
        }
    }

    #[test]
    fn message_type_id_is_stable() {
        assert_eq!(
            ShardVoteEquivocationGossip::message_type_id(),
            "shard.vote_equivocation"
        );
    }

    #[test]
    fn hbor_round_trip() {
        let gossip = ShardVoteEquivocationGossip {
            evidence: Arc::new(sample()),
        };
        let bytes = hbor_to_vec(&gossip).unwrap();
        let decoded: ShardVoteEquivocationGossip = hbor_from_slice(&bytes).unwrap();
        assert_eq!(gossip, decoded);
    }

    #[test]
    fn dedup_key_folds_the_same_accusation() {
        let g1 = ShardVoteEquivocationGossip {
            evidence: Arc::new(sample()),
        };
        let mut other = sample();
        other.block_hash_b = BlockHash::from_raw(Hash::from_bytes(b"c"));
        let g2 = ShardVoteEquivocationGossip {
            evidence: Arc::new(other),
        };
        assert_eq!(g1.dedup_key(), g2.dedup_key());
        assert_eq!(g1.source_shard(), Some(ShardId::ROOT));
    }
}
