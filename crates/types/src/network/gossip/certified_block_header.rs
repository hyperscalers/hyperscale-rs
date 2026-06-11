//! `CertifiedBlockHeader` gossip message for cross-shard header broadcast.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::network::{GossipMessage, TopicScope};
use crate::{
    Bls12381G2Signature, CertifiedBlockHeader, MessageClass, NetworkDefinition, NetworkMessage,
    ShardId, Signed, ValidatorId, Verifiable, certified_block_header_message,
};

/// Gossips a committed block header globally to all shards.
///
/// Used for the light-client provisions pattern: when a block commits,
/// the certified header (header + QC) is broadcast globally so remote
/// shards can verify state roots and validate merkle inclusion proofs
/// for provisions.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CertifiedBlockHeaderGossip {
    /// The committed block header (header + QC). Wire bytes always land
    /// in [`Verifiable::Unverified`]; local-dispatched broadcasts from a
    /// colocated proposer preserve [`Verifiable::Verified`].
    pub certified_header: Arc<Verifiable<CertifiedBlockHeader>>,
    /// The validator who sent this gossip (should be the block proposer).
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl Signed for CertifiedBlockHeaderGossip {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &Bls12381G2Signature {
        &self.sender_signature
    }

    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        certified_block_header_message(
            network,
            self.certified_header.header().shard_id(),
            self.certified_header.header().height(),
            &self.certified_header.header().hash(),
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
    use std::collections::BTreeMap;

    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{BlockHash, InFlightCount, ProposerTimestamp};

    #[test]
    fn test_message_type_id() {
        assert_eq!(
            CertifiedBlockHeaderGossip::message_type_id(),
            "block.committed"
        );
    }

    #[test]
    fn test_sbor_roundtrip() {
        use crate::{
            BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, BlockHeight, CertificateRoot,
            Hash, LocalReceiptRoot, ProvisionsRoot, QuorumCertificate, Round, ShardId, StateRoot,
            TransactionRoot, ValidatorId, WeightedTimestamp, zero_bls_signature,
        };

        let header = BlockHeader::new(
            ShardId::leaf(1, 1),
            BlockHeight::new(42),
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::leaf(1, 0), WeightedTimestamp::ZERO),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
        );
        let qc = QuorumCertificate::genesis(ShardId::leaf(1, 0), WeightedTimestamp::ZERO);

        let gossip = CertifiedBlockHeaderGossip {
            certified_header: Arc::new(Verifiable::from(CertifiedBlockHeader::new(header, qc))),
            sender: ValidatorId::new(0),
            sender_signature: zero_bls_signature(),
        };

        let encoded = basic_encode(&gossip).unwrap();
        let decoded: CertifiedBlockHeaderGossip = basic_decode(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }
}
