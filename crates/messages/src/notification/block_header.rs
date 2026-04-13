//! BlockHeader notification message.

use hyperscale_types::{
    block_header_message, BlockHeader, BlockManifest, Bls12381G2Signature, MessagePriority,
    NetworkMessage,
};
use sbor::prelude::BasicSbor;

/// Notifies committee members of a block proposal (header + manifest, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
///
/// The `proposer_signature` is a BLS signature by the proposer over a domain-separated
/// message, ensuring that block proposals cannot be forged by non-proposers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeaderNotification {
    /// The block header being proposed.
    pub header: BlockHeader,

    /// Block contents manifest (transaction hashes, certificates, deferrals, etc.)
    pub manifest: BlockManifest,

    /// BLS signature by the proposer over the domain-separated block header message.
    /// Verifies that the claimed proposer actually created this proposal.
    pub proposer_signature: Bls12381G2Signature,
}

impl BlockHeaderNotification {
    /// Create a block header notification message.
    pub fn new(
        header: BlockHeader,
        manifest: BlockManifest,
        proposer_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            header,
            manifest,
            proposer_signature,
        }
    }

    /// Build the domain-separated signing message for this block header.
    pub fn signing_message(&self) -> Vec<u8> {
        block_header_message(
            self.header.shard_group_id,
            self.header.height.0,
            self.header.round,
            &self.header.hash(),
        )
    }

    /// Consume and return header, manifest, and proposer signature.
    pub fn into_parts(self) -> (BlockHeader, BlockManifest, Bls12381G2Signature) {
        (self.header, self.manifest, self.proposer_signature)
    }
}

// Network message implementation
impl NetworkMessage for BlockHeaderNotification {
    fn message_type_id() -> &'static str {
        "block.header"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, Hash, QuorumCertificate, ShardGroupId, ValidatorId};

    use super::*;

    fn make_header(height: u64) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves: vec![],
            in_flight: 0,
        }
    }

    fn zero_sig() -> Bls12381G2Signature {
        Bls12381G2Signature([0u8; Bls12381G2Signature::LENGTH])
    }

    #[test]
    fn test_block_header_gossip_creation() {
        let header = make_header(1);
        let manifest = BlockManifest {
            tx_hashes: vec![
                Hash::from_bytes(b"tx1"),
                Hash::from_bytes(b"tx2"),
                Hash::from_bytes(b"tx3"),
                Hash::from_bytes(b"tx4"),
            ],
            ..Default::default()
        };

        let gossip = BlockHeaderNotification::new(header.clone(), manifest.clone(), zero_sig());
        assert_eq!(gossip.header, header);
        assert_eq!(gossip.manifest, manifest);
        assert_eq!(gossip.manifest.transaction_count(), 4);
    }

    #[test]
    fn test_block_header_gossip_into_parts() {
        let header = make_header(5);
        let manifest = BlockManifest {
            tx_hashes: vec![Hash::from_bytes(b"tx1")],
            ..Default::default()
        };

        let gossip = BlockHeaderNotification::new(header.clone(), manifest.clone(), zero_sig());
        let (h, m, _sig) = gossip.into_parts();
        assert_eq!(h, header);
        assert_eq!(m, manifest);
    }

    #[test]
    fn test_block_header_gossip_all_transaction_hashes() {
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let tx3 = Hash::from_bytes(b"tx3");

        let gossip = BlockHeaderNotification::new(
            make_header(1),
            BlockManifest {
                tx_hashes: vec![tx1, tx2, tx3],
                ..Default::default()
            },
            zero_sig(),
        );

        let all: Vec<Hash> = gossip.manifest.tx_hashes.to_vec();
        assert_eq!(all, vec![tx1, tx2, tx3]);
    }
}
