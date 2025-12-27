//! Transaction fetch response.

use hyperscale_types::{MessagePriority, NetworkMessage, RoutableTransaction};
use std::sync::Arc;

/// Response to a transaction fetch request.
///
/// Contains the requested transactions (those that the responder has).
/// Missing transactions are simply not included in the response.
#[derive(Debug, Clone)]
pub struct GetTransactionsResponse {
    /// The requested transactions that were found.
    /// Uses Arc to avoid copying transaction data.
    pub transactions: Vec<Arc<RoutableTransaction>>,
}

impl GetTransactionsResponse {
    /// Create a response with found transactions.
    pub fn new(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
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
    pub fn into_transactions(self) -> Vec<Arc<RoutableTransaction>> {
        self.transactions
    }
}

// Manual PartialEq - compare by transaction hashes
impl PartialEq for GetTransactionsResponse {
    fn eq(&self, other: &Self) -> bool {
        if self.transactions.len() != other.transactions.len() {
            return false;
        }
        self.transactions
            .iter()
            .zip(other.transactions.iter())
            .all(|(a, b)| a.hash() == b.hash())
    }
}

impl Eq for GetTransactionsResponse {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for GetTransactionsResponse
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
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

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for GetTransactionsResponse
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
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
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: RoutableTransaction =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            transactions.push(Arc::new(tx));
        }

        Ok(Self { transactions })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for GetTransactionsResponse {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for GetTransactionsResponse {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("GetTransactionsResponse", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// Network message implementation
impl NetworkMessage for GetTransactionsResponse {
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
    use hyperscale_types::test_utils::test_transaction;
    use sbor::prelude::{basic_decode, basic_encode};

    #[test]
    fn test_get_transactions_response() {
        let tx1 = Arc::new(test_transaction(1));
        let tx2 = Arc::new(test_transaction(2));

        let response = GetTransactionsResponse::new(vec![tx1.clone(), tx2.clone()]);
        assert_eq!(response.count(), 2);
        assert!(!response.is_empty());
    }

    #[test]
    fn test_empty_response() {
        let response = GetTransactionsResponse::empty();
        assert_eq!(response.count(), 0);
        assert!(response.is_empty());
    }

    #[test]
    fn test_sbor_roundtrip() {
        let tx1 = Arc::new(test_transaction(1));
        let tx2 = Arc::new(test_transaction(2));

        let response = GetTransactionsResponse::new(vec![tx1.clone(), tx2.clone()]);

        let encoded = basic_encode(&response).expect("encode");
        let decoded: GetTransactionsResponse = basic_decode(&encoded).expect("decode");

        assert_eq!(response, decoded);
    }
}
