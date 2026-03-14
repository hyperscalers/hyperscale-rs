//! CommittedBlockHeader gossip message for cross-shard header broadcast.

use hyperscale_types::{
    committed_block_header_message, Bls12381G2Signature, CommittedBlockHeader, MessagePriority,
    NetworkMessage, ValidatorId,
};
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
    /// The validator who sent this gossip (should be the block proposer).
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl CommittedBlockHeaderGossip {
    /// Build the canonical signing message for this gossip.
    ///
    /// Uses `DOMAIN_COMMITTED_BLOCK_HEADER` tag for domain separation.
    pub fn signing_message(&self) -> Vec<u8> {
        committed_block_header_message(
            self.committed_header.header.shard_group_id,
            self.committed_header.header.height.0,
            &self.committed_header.header.hash(),
        )
    }
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
            zero_bls_signature, BlockHeader, BlockHeight, Hash, QuorumCertificate, ShardGroupId,
            ValidatorId,
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
            transaction_root: Hash::ZERO,
            receipt_root: Hash::ZERO,
            provision_targets: vec![],
        };
        let qc = QuorumCertificate::genesis();

        let gossip = CommittedBlockHeaderGossip {
            committed_header: CommittedBlockHeader { header, qc },
            sender: ValidatorId(0),
            sender_signature: zero_bls_signature(),
        };

        let encoded = sbor::basic_encode(&gossip).unwrap();
        let decoded: CommittedBlockHeaderGossip = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }
}
