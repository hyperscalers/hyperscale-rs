//! Block fetch response.

use hyperscale_types::{CertifiedBlock, MessagePriority, NetworkMessage};
use sbor::prelude::BasicSbor;

/// Response to a block fetch request.
///
/// When found, carries the block together with the QC that certifies it
/// (`CertifiedBlock`). ECs are inside
/// `certified.block.certificates[i].wave_certificate.execution_certificates`
/// and receipts are inline in `certified.block.certificates[i].receipts`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockResponse {
    /// The requested block + certifying QC (None if not found).
    pub certified: Option<CertifiedBlock>,
}

impl GetBlockResponse {
    /// Create a response with a found block and its certifying QC.
    pub fn found(certified: CertifiedBlock) -> Self {
        Self {
            certified: Some(certified),
        }
    }

    /// Create a response for a block not found.
    pub fn not_found() -> Self {
        Self { certified: None }
    }

    /// Check if the block was found.
    pub fn has_block(&self) -> bool {
        self.certified.is_some()
    }

    /// Get the certified block if present.
    pub fn certified(&self) -> Option<&CertifiedBlock> {
        self.certified.as_ref()
    }

    /// Consume and return the certified block.
    pub fn into_certified(self) -> Option<CertifiedBlock> {
        self.certified
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
        test_utils::test_transaction, zero_bls_signature, Block, BlockHash, BlockHeader,
        BlockHeight, CertificateRoot, Hash, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot, TransactionRoot,
        ValidatorId, WeightedTimestamp,
    };
    use std::collections::BTreeMap;

    fn create_test_block() -> Block {
        let tx = test_transaction(1);

        Block::Live {
            header: BlockHeader {
                shard_group_id: ShardGroupId(0),
                height: BlockHeight(1),
                parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: ProposerTimestamp(1234567890),
                round: Round::INITIAL,
                is_fallback: false,
                state_root: StateRoot::ZERO,
                transaction_root: TransactionRoot::ZERO,
                certificate_root: CertificateRoot::ZERO,
                local_receipt_root: LocalReceiptRoot::ZERO,
                provision_root: ProvisionsRoot::ZERO,
                waves: vec![],
                provision_tx_roots: BTreeMap::new(),
                in_flight: 0,
            },
            transactions: vec![std::sync::Arc::new(tx)],
            certificates: vec![],
            provisions: vec![],
        }
    }

    fn create_test_qc(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            shard_group_id: ShardGroupId(0),
            height: block.height(),
            parent_block_hash: block.header().parent_hash,
            round: block.header().round,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(0),
            weighted_timestamp: WeightedTimestamp::ZERO,
        }
    }

    #[test]
    fn test_block_response_found() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        let response = GetBlockResponse::found(certified.clone());

        assert!(response.has_block());
        assert_eq!(response.certified(), Some(&certified));
    }

    #[test]
    fn test_block_response_not_found() {
        let response = GetBlockResponse::not_found();

        assert!(!response.has_block());
        assert_eq!(response.certified(), None);
    }

    #[test]
    fn test_block_response_into_certified() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        let response = GetBlockResponse::found(certified.clone());

        assert_eq!(response.into_certified(), Some(certified));
    }
}
