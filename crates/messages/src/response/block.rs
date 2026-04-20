//! Block fetch response.

use hyperscale_types::{Block, Hash, MessagePriority, NetworkMessage, QuorumCertificate};
use sbor::prelude::BasicSbor;

/// Response to a block fetch request containing the full Block and its QC.
///
/// ECs are carried inside `Block.certificates[i].wave_certificate.execution_certificates`
/// and receipts are carried inline as part of `Block.certificates[i].receipts`.
///
/// `provision_hashes` carries the block manifest's provision batch hashes so the
/// receiver can resolve them against its own `ProvisionCoordinator` cache —
/// provisions themselves are not persisted.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockResponse {
    /// The requested block (None if not found).
    pub block: Option<Block>,
    /// The QC that certifies this block (None if block not found or at tip).
    pub qc: Option<QuorumCertificate>,
    /// Provision batch hashes the block commits to (manifest.provision_hashes).
    /// Empty if block not found or has no provisions.
    pub provision_hashes: Vec<Hash>,
}

impl GetBlockResponse {
    /// Create a response with a found block, its certifying QC, and the
    /// block's provision batch hashes.
    pub fn found(block: Block, qc: QuorumCertificate, provision_hashes: Vec<Hash>) -> Self {
        Self {
            block: Some(block),
            qc: Some(qc),
            provision_hashes,
        }
    }

    /// Create a response for a block not found.
    pub fn not_found() -> Self {
        Self {
            block: None,
            qc: None,
            provision_hashes: Vec::new(),
        }
    }

    /// Check if the block was found.
    pub fn has_block(&self) -> bool {
        self.block.is_some()
    }

    /// Get the block if present.
    pub fn block(&self) -> Option<&Block> {
        self.block.as_ref()
    }

    /// Get the QC if present.
    pub fn qc(&self) -> Option<&QuorumCertificate> {
        self.qc.as_ref()
    }

    /// Consume and return the block, QC, and provision hashes.
    pub fn into_parts(self) -> (Option<Block>, Option<QuorumCertificate>, Vec<Hash>) {
        (self.block, self.qc, self.provision_hashes)
    }
}

// Network message implementation
impl NetworkMessage for GetBlockResponse {
    fn message_type_id() -> &'static str {
        "block.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        test_utils::test_transaction, zero_bls_signature, BlockHeader, BlockHeight, Hash,
        ShardGroupId, SignerBitfield, ValidatorId,
    };

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block {
            header: BlockHeader {
                shard_group_id: ShardGroupId(0),
                height: BlockHeight(1),
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
            },
            transactions: vec![std::sync::Arc::new(tx)],
            certificates: vec![],
        }
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            shard_group_id: ShardGroupId(0),
            height: block.header.height,
            parent_block_hash: block.header.parent_hash,
            round: block.header.round,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(0),
            weighted_timestamp_ms: 0,
        }
    }

    #[test]
    fn test_block_response_found() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let response = GetBlockResponse::found(block.clone(), qc.clone(), vec![]);

        assert!(response.has_block());
        assert_eq!(response.block(), Some(&block));
        assert_eq!(response.qc(), Some(&qc));
    }

    #[test]
    fn test_block_response_not_found() {
        let response = GetBlockResponse::not_found();

        assert!(!response.has_block());
        assert_eq!(response.block(), None);
        assert_eq!(response.qc(), None);
    }

    #[test]
    fn test_block_response_into_parts() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let response = GetBlockResponse::found(block.clone(), qc.clone(), vec![]);

        let (extracted_block, extracted_qc, extracted_provisions) = response.into_parts();
        assert_eq!(extracted_block, Some(block));
        assert_eq!(extracted_qc, Some(qc));
        assert!(extracted_provisions.is_empty());
    }
}
