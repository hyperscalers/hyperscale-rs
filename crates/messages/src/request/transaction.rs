//! Transaction fetch request.

use crate::response::GetTransactionsResponse;
use hyperscale_types::{MessagePriority, NetworkMessage, Request, TxHash};
use sbor::prelude::BasicSbor;

/// Request to fetch transactions by hash.
///
/// Used when a validator is missing transactions referenced by a pending
/// block (or by any other consumer waiting on tx data). The responder
/// resolves each hash from local state — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTransactionsRequest {
    /// Hashes of the transactions being requested.
    pub tx_hashes: Vec<TxHash>,
}

impl GetTransactionsRequest {
    /// Create a new transaction fetch request.
    #[must_use]
    pub const fn new(tx_hashes: Vec<TxHash>) -> Self {
        Self { tx_hashes }
    }

    /// Get the number of transactions being requested.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.tx_hashes.len()
    }
}

// Network message implementation
impl NetworkMessage for GetTransactionsRequest {
    fn message_type_id() -> &'static str {
        "transaction.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

/// Type-safe request/response pairing.
impl Request for GetTransactionsRequest {
    type Response = GetTransactionsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::Hash;
    use sbor::prelude::basic_encode;

    #[test]
    fn test_get_transactions_request() {
        let tx_hashes = vec![
            TxHash::from_raw(Hash::from_bytes(b"tx1")),
            TxHash::from_raw(Hash::from_bytes(b"tx2")),
            TxHash::from_raw(Hash::from_bytes(b"tx3")),
        ];

        let request = GetTransactionsRequest::new(tx_hashes.clone());
        assert_eq!(request.tx_hashes, tx_hashes);
        assert_eq!(request.count(), 3);
    }

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetTransactionsRequest::new(vec![TxHash::from_raw(Hash::from_bytes(b"tx1"))]);
        let bytes = basic_encode(&request).unwrap();
        let decoded: GetTransactionsRequest = sbor::prelude::basic_decode(&bytes).unwrap();
        assert_eq!(request, decoded);
    }
}
