//! CommittedBlockHeader gossip message for cross-shard header broadcast.

use hyperscale_types::{CommittedBlockHeader, MessagePriority, NetworkMessage};
use sbor::prelude::BasicSbor;

/// Gossips a committed block header globally to all shards.
///
/// This is used for the light-client provisions pattern: when a block commits,
/// the committed header (header + QC) is broadcast globally so remote shards
/// can verify state roots and validate merkle inclusion proofs for provisions.
///
/// Does NOT implement `ShardMessage` — this is a global broadcast.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommittedBlockHeaderGossip {
    /// The committed block header (header + QC).
    pub committed_header: CommittedBlockHeader,
}

impl NetworkMessage for CommittedBlockHeaderGossip {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_id() {
        assert_eq!(
            CommittedBlockHeaderGossip::message_type_id(),
            "block.committed"
        );
    }

    #[test]
    fn test_sbor_roundtrip() {
        use hyperscale_types::{
            BlockHeader, BlockHeight, Hash, QuorumCertificate, ShardGroupId, ValidatorId,
        };

        let header = BlockHeader {
            shard_group_id: ShardGroupId(1),
            height: BlockHeight(42),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let qc = QuorumCertificate::genesis();

        let gossip = CommittedBlockHeaderGossip {
            committed_header: CommittedBlockHeader { header, qc },
        };

        let encoded = sbor::basic_encode(&gossip).unwrap();
        let decoded: CommittedBlockHeaderGossip = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }
}
