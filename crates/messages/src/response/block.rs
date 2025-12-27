//! Block fetch response.

use hyperscale_types::{Block, MessagePriority, NetworkMessage, QuorumCertificate};
use sbor::prelude::BasicSbor;

/// Response to a block fetch request containing the full Block and its QC.
///
/// Note: The wire format encodes this as `sbor_encode((Option<Block>, Option<QC>))`.
/// This type exists for documentation and type-safety in the message layer.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockResponse {
    /// The requested block (None if not found).
    pub block: Option<Block>,
    /// The QC that certifies this block (None if block not found or at tip).
    pub qc: Option<QuorumCertificate>,
}

impl GetBlockResponse {
    /// Create a response with a found block and its certifying QC.
    pub fn found(block: Block, qc: QuorumCertificate) -> Self {
        Self {
            block: Some(block),
            qc: Some(qc),
        }
    }

    /// Create a response for a block not found.
    pub fn not_found() -> Self {
        Self {
            block: None,
            qc: None,
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

    /// Consume and return the block and QC if present.
    pub fn into_parts(self) -> (Option<Block>, Option<QuorumCertificate>) {
        (self.block, self.qc)
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
        test_utils::test_transaction, BlockHeader, BlockHeight, Hash, Signature, SignerBitfield,
        ValidatorId, VotePower,
    };

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block {
            header: BlockHeader {
                height: BlockHeight(1),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![std::sync::Arc::new(tx)],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        }
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            height: block.header.height,
            parent_block_hash: block.header.parent_hash,
            round: block.header.round,
            aggregated_signature: Signature::zero(),
            signers: SignerBitfield::new(0),
            voting_power: VotePower(u64::MAX),
            weighted_timestamp_ms: 0,
        }
    }

    #[test]
    fn test_block_response_found() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let response = GetBlockResponse::found(block.clone(), qc.clone());

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
        let response = GetBlockResponse::found(block.clone(), qc.clone());

        let (extracted_block, extracted_qc) = response.into_parts();
        assert_eq!(extracted_block, Some(block));
        assert_eq!(extracted_qc, Some(qc));
    }
}
