//! Transaction fetch response.

use std::sync::Arc;

use hyperscale_types::{MessageClass, NetworkMessage, RoutableTransaction};
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

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
    #[must_use]
    pub const fn new(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
        Self { transactions }
    }

    /// Create an empty response (no transactions found).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            transactions: vec![],
        }
    }

    /// Get the number of transactions in the response.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the response is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Consume and return the transactions.
    #[must_use]
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
// Manual SBOR. Bounds the decoded transaction count at 1000.
// ============================================================================

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for GetTransactionsResponse {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(1)?; // 1 field

        // Encode transactions array (unwrap Arc for each)
        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(ValueKind::Tuple)?;
        encoder.write_size(self.transactions.len())?;
        for tx in &self.transactions {
            encoder.encode_deeper_body(tx.as_ref())?;
        }

        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for GetTransactionsResponse {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 1 {
            return Err(DecodeError::UnexpectedSize {
                expected: 1,
                actual: length,
            });
        }

        // Decode transactions array (wrap each in Arc)
        decoder.read_and_check_value_kind(ValueKind::Array)?;
        decoder.read_and_check_value_kind(ValueKind::Tuple)?;
        let tx_count = decoder.read_size()?;
        if tx_count > 1_000 {
            return Err(DecodeError::UnexpectedSize {
                expected: 1_000,
                actual: tx_count,
            });
        }
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: RoutableTransaction =
                decoder.decode_deeper_body_with_value_kind(ValueKind::Tuple)?;
            transactions.push(Arc::new(tx));
        }

        Ok(Self { transactions })
    }
}

impl Categorize<NoCustomValueKind> for GetTransactionsResponse {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for GetTransactionsResponse {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("GetTransactionsResponse", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

// Network message implementation
impl NetworkMessage for GetTransactionsResponse {
    fn message_type_id() -> &'static str {
        "transaction.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_transaction;
    use sbor::prelude::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_get_transactions_response() {
        let tx1 = Arc::new(test_transaction(1));
        let tx2 = Arc::new(test_transaction(2));

        let response = GetTransactionsResponse::new(vec![tx1, tx2]);
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

        let response = GetTransactionsResponse::new(vec![tx1, tx2]);

        let encoded = basic_encode(&response).expect("encode");
        let decoded: GetTransactionsResponse = basic_decode(&encoded).expect("decode");

        assert_eq!(response, decoded);
    }
}
