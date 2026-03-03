//! BlockHeader gossip message.

use hyperscale_types::{BlockHeader, BlockManifest, MessagePriority, NetworkMessage, ShardMessage};
use sbor::prelude::BasicSbor;

/// Gossips a block proposal (header + manifest, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
///
/// Transaction hashes are split into three priority sections in the manifest:
/// 1. **retry_hashes**: Retry transactions (highest priority, critical for liveness)
/// 2. **priority_hashes**: Cross-shard transactions with commitment proofs
/// 3. **tx_hashes**: All other transactions
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeaderGossip {
    /// The block header being gossiped.
    pub header: BlockHeader,

    /// Block contents manifest (transaction hashes, certificates, deferrals, etc.)
    pub manifest: BlockManifest,
}

impl BlockHeaderGossip {
    /// Create a block header gossip message.
    pub fn new(header: BlockHeader, manifest: BlockManifest) -> Self {
        Self { header, manifest }
    }

    /// Consume and return header + manifest.
    pub fn into_parts(self) -> (BlockHeader, BlockManifest) {
        (self.header, self.manifest)
    }
}

// Network message implementation
impl NetworkMessage for BlockHeaderGossip {
    fn message_type_id() -> &'static str {
        "block.header"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

impl ShardMessage for BlockHeaderGossip {}

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
            state_version: 0,
            transaction_root: Hash::ZERO,
        }
    }

    #[test]
    fn test_block_header_gossip_creation() {
        let header = make_header(1);
        let manifest = BlockManifest {
            retry_hashes: vec![Hash::from_bytes(b"retry1")],
            priority_hashes: vec![Hash::from_bytes(b"priority1")],
            tx_hashes: vec![Hash::from_bytes(b"tx1"), Hash::from_bytes(b"tx2")],
            ..Default::default()
        };

        let gossip = BlockHeaderGossip::new(header.clone(), manifest.clone());
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

        let gossip = BlockHeaderGossip::new(header.clone(), manifest.clone());
        let (h, m) = gossip.into_parts();
        assert_eq!(h, header);
        assert_eq!(m, manifest);
    }

    #[test]
    fn test_block_header_gossip_all_transaction_hashes() {
        let retry = Hash::from_bytes(b"retry");
        let priority = Hash::from_bytes(b"priority");
        let other = Hash::from_bytes(b"other");

        let gossip = BlockHeaderGossip::new(
            make_header(1),
            BlockManifest {
                retry_hashes: vec![retry],
                priority_hashes: vec![priority],
                tx_hashes: vec![other],
                ..Default::default()
            },
        );

        let all: Vec<Hash> = gossip.manifest.all_tx_hashes().copied().collect();
        assert_eq!(all, vec![retry, priority, other]);
    }
}
