//! `CommittedBlockHeader` gossip message for cross-shard header broadcast.

use std::sync::Arc;

use sbor::prelude::BasicSbor;

use crate::{
    Bls12381G2Signature, CommittedBlockHeader, MessageClass, NetworkMessage, ValidatorId,
    committed_block_header_message,
};

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
    pub committed_header: Arc<CommittedBlockHeader>,
    /// The validator who sent this gossip (should be the block proposer).
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl CommittedBlockHeaderGossip {
    /// Build the canonical signing message for this gossip.
    ///
    /// Uses `DOMAIN_COMMITTED_BLOCK_HEADER` tag for domain separation.
    #[must_use]
    pub fn signing_message(&self) -> Vec<u8> {
        committed_block_header_message(
            self.committed_header.header().shard_group_id(),
            self.committed_header.header().height(),
            &self.committed_header.header().hash(),
        )
    }
}

impl NetworkMessage for CommittedBlockHeaderGossip {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
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
            CommittedBlockHeaderGossip::message_type_id(),
            "block.committed"
        );
    }

    #[test]
    fn test_sbor_roundtrip() {
        use crate::{
            BlockHeader, BlockHeight, CertificateRoot, Hash, LocalReceiptRoot, ProvisionsRoot,
            QuorumCertificate, Round, ShardGroupId, StateRoot, TransactionRoot, ValidatorId,
            zero_bls_signature,
        };

        let header = BlockHeader::new(
            ShardGroupId::new(1),
            BlockHeight::new(42),
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
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
        );
        let qc = QuorumCertificate::genesis(ShardGroupId::new(0));

        let gossip = CommittedBlockHeaderGossip {
            committed_header: Arc::new(CommittedBlockHeader::new(header, qc)),
            sender: ValidatorId::new(0),
            sender_signature: zero_bls_signature(),
        };

        let encoded = basic_encode(&gossip).unwrap();
        let decoded: CommittedBlockHeaderGossip = basic_decode(&encoded).unwrap();
        assert_eq!(gossip, decoded);
    }
}
