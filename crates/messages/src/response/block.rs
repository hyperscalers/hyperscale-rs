//! Block fetch response.

use hyperscale_codec as sbor;
use hyperscale_codec::{Decoder as _, Encoder as _};
use hyperscale_types::{
    Block, LedgerReceiptEntry, MessagePriority, NetworkMessage, QuorumCertificate, TypeConfig,
};

/// Response to a block fetch request containing the full Block and its QC.
#[derive(Debug, Clone)]
pub struct GetBlockResponse<C: TypeConfig> {
    /// The requested block (None if not found).
    pub block: Option<Block<C>>,
    /// The QC that certifies this block (None if block not found or at tip).
    pub qc: Option<QuorumCertificate>,
    /// Ledger receipts for the block's certificates. Empty if block not found.
    pub ledger_receipts: Vec<LedgerReceiptEntry<C>>,
}

impl<C: TypeConfig> GetBlockResponse<C> {
    /// Create a response with a found block and its certifying QC.
    pub fn found(
        block: Block<C>,
        qc: QuorumCertificate,
        ledger_receipts: Vec<LedgerReceiptEntry<C>>,
    ) -> Self {
        Self {
            block: Some(block),
            qc: Some(qc),
            ledger_receipts,
        }
    }

    /// Create a response for a block not found.
    pub fn not_found() -> Self {
        Self {
            block: None,
            qc: None,
            ledger_receipts: vec![],
        }
    }

    /// Check if the block was found.
    pub fn has_block(&self) -> bool {
        self.block.is_some()
    }

    /// Get the block if present.
    pub fn block(&self) -> Option<&Block<C>> {
        self.block.as_ref()
    }

    /// Get the QC if present.
    pub fn qc(&self) -> Option<&QuorumCertificate> {
        self.qc.as_ref()
    }

    /// Consume and return the block, QC, and receipts.
    pub fn into_parts(
        self,
    ) -> (
        Option<Block<C>>,
        Option<QuorumCertificate>,
        Vec<LedgerReceiptEntry<C>>,
    ) {
        (self.block, self.qc, self.ledger_receipts)
    }
}

// Manual SBOR impls — Block<C> has manual SBOR, and LedgerReceiptEntry<C>
// also has manual SBOR, so we need manual impls here too.

impl<'a, C: TypeConfig> sbor::Encode<sbor::NoCustomValueKind, sbor::BasicEncoder<'a>>
    for GetBlockResponse<C>
{
    fn encode_value_kind(
        &self,
        encoder: &mut sbor::BasicEncoder<'a>,
    ) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut sbor::BasicEncoder<'a>) -> Result<(), sbor::EncodeError> {
        encoder.write_size(3)?;
        encoder.encode(&self.block)?;
        encoder.encode(&self.qc)?;
        encoder.encode(&self.ledger_receipts)?;
        Ok(())
    }
}

impl<'a, C: TypeConfig> sbor::Decode<sbor::NoCustomValueKind, sbor::BasicDecoder<'a>>
    for GetBlockResponse<C>
{
    fn decode_body_with_value_kind(
        decoder: &mut sbor::BasicDecoder<'a>,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 3 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 3,
                actual: length,
            });
        }
        let block: Option<Block<C>> = decoder.decode()?;
        let qc: Option<QuorumCertificate> = decoder.decode()?;
        let ledger_receipts: Vec<LedgerReceiptEntry<C>> = decoder.decode()?;
        Ok(Self {
            block,
            qc,
            ledger_receipts,
        })
    }
}

impl<C: TypeConfig> sbor::Categorize<sbor::NoCustomValueKind> for GetBlockResponse<C> {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl<C: TypeConfig> sbor::Describe<sbor::NoCustomTypeKind> for GetBlockResponse<C> {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetBlockResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// Network message implementation
impl<C: TypeConfig> NetworkMessage for GetBlockResponse<C> {
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
    use hyperscale_radix_config::RadixConfig;
    use hyperscale_radix_types::test_utils::test_transaction;
    use hyperscale_types::{
        zero_bls_signature, BlockHeader, BlockHeight, Hash, ShardGroupId, SignerBitfield,
        ValidatorId,
    };

    fn create_test_block() -> Block<RadixConfig> {
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
                receipt_root: Hash::ZERO,
                provision_targets: vec![],
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![std::sync::Arc::new(tx)],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        }
    }

    fn create_test_qc(block: &Block<RadixConfig>) -> QuorumCertificate {
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
        let response: GetBlockResponse<RadixConfig> =
            GetBlockResponse::found(block.clone(), qc.clone(), vec![]);

        assert!(response.has_block());
        assert_eq!(response.qc(), Some(&qc));
        assert!(response.ledger_receipts.is_empty());
    }

    #[test]
    fn test_block_response_not_found() {
        let response: GetBlockResponse<RadixConfig> = GetBlockResponse::not_found();

        assert!(!response.has_block());
        assert_eq!(response.block(), None);
        assert_eq!(response.qc(), None);
        assert!(response.ledger_receipts.is_empty());
    }

    #[test]
    fn test_block_response_into_parts() {
        let block = create_test_block();
        let qc = create_test_qc(&block);
        let response: GetBlockResponse<RadixConfig> =
            GetBlockResponse::found(block.clone(), qc.clone(), vec![]);

        let (extracted_block, extracted_qc, extracted_receipts) = response.into_parts();
        assert!(extracted_block.is_some());
        assert_eq!(extracted_qc, Some(qc));
        assert!(extracted_receipts.is_empty());
    }
}
