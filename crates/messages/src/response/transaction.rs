//! Transaction fetch response.

use hyperscale_codec as sbor;
use hyperscale_codec::{Decoder as _, Encoder as _};
use hyperscale_types::{
    ConcreteConfig, ConsensusTransaction, MessagePriority, NetworkMessage, TypeConfig,
};
use std::fmt::Debug;
use std::sync::Arc;

/// Response to a transaction fetch request.
///
/// Contains the requested transactions (those that the responder has).
/// Missing transactions are simply not included in the response.
pub struct GetTransactionsResponse<C: TypeConfig = ConcreteConfig> {
    /// The requested transactions that were found.
    /// Uses Arc to avoid copying transaction data.
    pub transactions: Vec<Arc<C::Transaction>>,
}

impl<C: TypeConfig> Debug for GetTransactionsResponse<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetTransactionsResponse")
            .field("transactions", &self.transactions)
            .finish()
    }
}

impl<C: TypeConfig> Clone for GetTransactionsResponse<C> {
    fn clone(&self) -> Self {
        Self {
            transactions: self.transactions.clone(),
        }
    }
}

impl<C: TypeConfig> GetTransactionsResponse<C> {
    /// Create a response with found transactions.
    pub fn new(transactions: Vec<Arc<C::Transaction>>) -> Self {
        Self { transactions }
    }

    /// Create an empty response (no transactions found).
    pub fn empty() -> Self {
        Self {
            transactions: vec![],
        }
    }

    /// Get the number of transactions in the response.
    pub fn count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the response is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Consume and return the transactions.
    pub fn into_transactions(self) -> Vec<Arc<C::Transaction>> {
        self.transactions
    }
}

// Manual PartialEq - compare by transaction hashes
impl<C: TypeConfig> PartialEq for GetTransactionsResponse<C> {
    fn eq(&self, other: &Self) -> bool {
        if self.transactions.len() != other.transactions.len() {
            return false;
        }
        self.transactions
            .iter()
            .zip(other.transactions.iter())
            .all(|(a, b)| a.tx_hash() == b.tx_hash())
    }
}

impl<C: TypeConfig> Eq for GetTransactionsResponse<C> {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// ============================================================================

impl<'a, C: TypeConfig> sbor::Encode<sbor::NoCustomValueKind, sbor::BasicEncoder<'a>>
    for GetTransactionsResponse<C>
{
    fn encode_value_kind(
        &self,
        encoder: &mut sbor::BasicEncoder<'a>,
    ) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut sbor::BasicEncoder<'a>) -> Result<(), sbor::EncodeError> {
        encoder.write_size(1)?; // 1 field

        // Encode transactions array (unwrap Arc for each)
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.transactions.len())?;
        for tx in &self.transactions {
            encoder.encode_deeper_body(tx.as_ref())?;
        }

        Ok(())
    }
}

impl<'a, C: TypeConfig> sbor::Decode<sbor::NoCustomValueKind, sbor::BasicDecoder<'a>>
    for GetTransactionsResponse<C>
{
    fn decode_body_with_value_kind(
        decoder: &mut sbor::BasicDecoder<'a>,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 1 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 1,
                actual: length,
            });
        }

        // Decode transactions array (wrap each in Arc)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let tx_count = decoder.read_size()?;
        if tx_count > 1_000 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 1_000,
                actual: tx_count,
            });
        }
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: C::Transaction =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            transactions.push(Arc::new(tx));
        }

        Ok(Self { transactions })
    }
}

impl<C: TypeConfig> sbor::Categorize<sbor::NoCustomValueKind> for GetTransactionsResponse<C> {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl<C: TypeConfig> sbor::Describe<sbor::NoCustomTypeKind> for GetTransactionsResponse<C> {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetTransactionsResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// Network message implementation
impl<C: TypeConfig> NetworkMessage for GetTransactionsResponse<C> {
    fn message_type_id() -> &'static str {
        "transaction.response"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_codec::{basic_decode, basic_encode};
    use hyperscale_types::test_utils::test_transaction;

    #[test]
    fn test_get_transactions_response() {
        let tx1 = Arc::new(test_transaction(1));
        let tx2 = Arc::new(test_transaction(2));

        let response: GetTransactionsResponse =
            GetTransactionsResponse::new(vec![tx1.clone(), tx2.clone()]);
        assert_eq!(response.count(), 2);
        assert!(!response.is_empty());
    }

    #[test]
    fn test_empty_response() {
        let response: GetTransactionsResponse = GetTransactionsResponse::empty();
        assert_eq!(response.count(), 0);
        assert!(response.is_empty());
    }

    #[test]
    fn test_sbor_roundtrip() {
        let tx1 = Arc::new(test_transaction(1));
        let tx2 = Arc::new(test_transaction(2));

        let response: GetTransactionsResponse =
            GetTransactionsResponse::new(vec![tx1.clone(), tx2.clone()]);

        let encoded = basic_encode(&response).expect("encode");
        let decoded: GetTransactionsResponse = basic_decode(&encoded).expect("decode");

        assert_eq!(response, decoded);
    }
}
