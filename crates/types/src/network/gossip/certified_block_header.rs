//! `CertifiedBlockHeader` gossip message for cross-shard header broadcast.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{
    CertifiedBlockHeader, CertifiedBlockHeaderSenderMessage, ConsensusSignature, MessageClass,
    NetworkDefinition, NetworkMessage, ShardId, Signed, ValidatorId, Verifiable, signed_bytes,
};

/// Gossips a committed block header globally to all shards.
///
/// Used for the light-client provisions pattern: when a block commits,
/// the certified header (header + QC) is broadcast globally so remote
/// shards can verify state roots and validate merkle inclusion proofs
/// for provisions.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct CertifiedBlockHeaderGossip {
    /// The committed block header (header + QC). Wire bytes always land
    /// in `Verifiable::Unverified`; local-dispatched broadcasts from a
    /// colocated proposer preserve `Verifiable::Verified`.
    pub certified_header: Arc<Verifiable<CertifiedBlockHeader>>,
    /// The validator who sent this gossip (should be the block proposer).
    pub sender: ValidatorId,
    /// Signature over the domain-separated signing message, by the sender.
    pub sender_signature: ConsensusSignature,
}

impl Signed for CertifiedBlockHeaderGossip {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &ConsensusSignature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &CertifiedBlockHeaderSenderMessage {
                shard_id: self.certified_header.header().shard_id(),
                height: self.certified_header.header().height(),
                block_hash: self.certified_header.header().hash(),
            },
            network,
        )
    }
}

impl NetworkMessage for CertifiedBlockHeaderGossip {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for CertifiedBlockHeaderGossip {
    const SCOPE: TopicScope = TopicScope::Global;

    fn source_shard(&self) -> Option<ShardId> {
        Some(self.certified_header.header().shard_id())
    }

    fn dedup_key(&self) -> Option<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Hash of the certified header (excludes sender / sender_signature),
        // so every committee member's copy of the same logical header
        // collapses to a single key.
        let mut hasher = DefaultHasher::new();
        self.certified_header.header().hash().hash(&mut hasher);
        Some(hasher.finish())
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHash, ProposerTimestamp};

    #[test]
    fn test_message_type_id() {
        assert_eq!(
            CertifiedBlockHeaderGossip::message_type_id(),
            "block.committed"
        );
    }

    #[test]
    fn test_hbor_roundtrip() {
        use crate::{
            BlockHeader, BlockHeaderParts, BlockHeight, ChainOrigin, Hash, QuorumCertificate,
            ShardId, ValidatorId,
        };

        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(1, 1),
            height: BlockHeight::new(42),
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            ..Default::default()
        });
        let qc = QuorumCertificate::genesis(ShardId::leaf(1, 0), ChainOrigin::ROOT);

        let gossip = CertifiedBlockHeaderGossip {
            certified_header: Arc::new(Verifiable::from(CertifiedBlockHeader::new(header, qc))),
            sender: ValidatorId::new(0),
            sender_signature: ConsensusSignature::ZERO,
        };

        let encoded = hbor_to_vec(&gossip).unwrap();
        let decoded: CertifiedBlockHeaderGossip = hbor_from_slice(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }
}
