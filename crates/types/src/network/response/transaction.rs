//! Transaction fetch response.

use std::sync::Arc;

use sbor::prelude::*;

use crate::{BoundedVec, MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, RoutableTransaction};

/// Response to a transaction fetch request.
///
/// Contains the requested transactions (those that the responder has).
/// Missing transactions are simply not included in the response.
#[derive(Debug, Clone, BasicSbor)]
pub struct GetTransactionsResponse {
    /// The requested transactions that were found.
    /// Uses Arc to avoid copying transaction data.
    pub transactions: BoundedVec<Arc<RoutableTransaction>, MAX_TXS_PER_BLOCK>,
}

impl GetTransactionsResponse {
    /// Create a response with found transactions.
    ///
    /// # Panics
    ///
    /// Panics if `transactions.len() > MAX_TXS_PER_BLOCK`.
    #[must_use]
    pub fn new(transactions: Vec<Arc<RoutableTransaction>>) -> Self {
        Self {
            transactions: transactions.into(),
        }
    }

    /// Create an empty response (no transactions found).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            transactions: BoundedVec::new(),
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
        self.transactions.into_inner()
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
    use sbor::prelude::{basic_decode, basic_encode};

    use super::*;
    use crate::test_utils::test_transaction;

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
