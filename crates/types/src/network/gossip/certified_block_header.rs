//! `CertifiedBlockHeader` gossip message for cross-shard header broadcast.

use hyperscale_hbor::Hbor;

use crate::network::{GossipMessage, GossipScope};
use crate::{
    CertifiedBlockHeader, CertifiedBlockHeaderSenderMessage, ConsensusSignature, Hash,
    MessageClass, NetworkDefinition, NetworkMessage, ShardId, Signed, ValidatorId, Verifiable,
    signed_bytes,
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
    pub certified_header: Verifiable<CertifiedBlockHeader>,
    /// The validator who sent this gossip (should be the block proposer).
    pub sender: ValidatorId,
    /// Signature over the domain-separated signing message, by the sender.
    pub sender_signature: ConsensusSignature,
}

impl CertifiedBlockHeaderGossip {
    /// A digest naming this exact copy: the header copy's own digest, its
    /// sender, and the sender's signature.
    #[must_use]
    pub fn copy_digest(&self) -> Hash {
        Hash::from_parts(&[
            b"hyperscale.verdict.gossip-copy",
            self.certified_header
                .as_unverified()
                .copy_digest()
                .as_bytes(),
            &self.sender.inner().to_le_bytes(),
            self.sender_signature.as_bytes(),
        ])
    }
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
    const SCOPE: GossipScope = GossipScope::Global;

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
    use crate::{BlockHash, ProposerTimestamp, WeightedTimestamp};

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
            parent_qc: QuorumCertificate::genesis(
                ShardId::leaf(1, 0),
                ChainOrigin::root(WeightedTimestamp::ZERO),
            )
            .into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            ..Default::default()
        });
        let qc = QuorumCertificate::genesis(
            ShardId::leaf(1, 0),
            ChainOrigin::root(WeightedTimestamp::ZERO),
        );

        let gossip = CertifiedBlockHeaderGossip {
            certified_header: Verifiable::from(CertifiedBlockHeader::new(header, qc)),
            sender: ValidatorId::new(0),
            sender_signature: ConsensusSignature::ZERO,
        };

        let encoded = hbor_to_vec(&gossip).unwrap();
        let decoded: CertifiedBlockHeaderGossip = hbor_from_slice(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }

    /// A copy of one header at height 42, certified by `qc_shard`'s
    /// genesis QC and sent by `sender` under `signature`.
    fn copy(qc_shard: u64, sender: u64, signature: u8) -> CertifiedBlockHeaderGossip {
        use crate::{
            BlockHeader, BlockHeaderParts, BlockHeight, ChainOrigin, QuorumCertificate, ShardId,
            ValidatorId,
        };

        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(1, 1),
            height: BlockHeight::new(42),
            ..Default::default()
        });
        let qc = QuorumCertificate::genesis(
            ShardId::leaf(1, qc_shard),
            ChainOrigin::root(WeightedTimestamp::ZERO),
        );
        CertifiedBlockHeaderGossip {
            certified_header: Verifiable::from(CertifiedBlockHeader::new(header, qc)),
            sender: ValidatorId::new(sender),
            sender_signature: ConsensusSignature::new([signature; 96]),
        }
    }

    #[test]
    fn copies_differing_in_a_signed_byte_have_distinct_digests() {
        let base = copy(0, 0, 1).copy_digest();
        assert_ne!(base, copy(0, 1, 1).copy_digest(), "sender");
        assert_ne!(base, copy(0, 0, 2).copy_digest(), "signature");
        assert_ne!(base, copy(1, 0, 1).copy_digest(), "QC");
        assert_eq!(base, copy(0, 0, 1).copy_digest(), "an equal copy");
    }

    #[test]
    fn a_header_copy_and_its_gossip_copy_have_distinct_digests() {
        let gossip = copy(0, 0, 1);
        assert_ne!(
            gossip.copy_digest(),
            gossip.certified_header.as_unverified().copy_digest()
        );
    }

    #[test]
    fn a_decoded_copy_keeps_its_digest() {
        let gossip = copy(0, 0, 1);
        let decoded: CertifiedBlockHeaderGossip =
            hbor_from_slice(&hbor_to_vec(&gossip).unwrap()).unwrap();
        assert_eq!(gossip.copy_digest(), decoded.copy_digest());
        assert_eq!(
            gossip.certified_header.as_unverified().copy_digest(),
            decoded.certified_header.as_unverified().copy_digest()
        );
    }
}
