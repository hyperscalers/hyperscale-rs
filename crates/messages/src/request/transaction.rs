//! Transaction fetch request.

use crate::response::GetTransactionsResponse;
use hyperscale_types::{Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch transactions by hash for a pending block.
///
/// Used when a validator receives a block header but is missing some
/// transactions that weren't in their mempool or didn't arrive via gossip.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetTransactionsRequest {
    /// Hash of the block that needs these transactions.
    /// Used by the responder to prioritize and validate the request.
    pub block_hash: Hash,

    /// Hashes of the transactions being requested.
    pub tx_hashes: Vec<Hash>,
}

impl GetTransactionsRequest {
    /// Create a new transaction fetch request.
    pub fn new(block_hash: Hash, tx_hashes: Vec<Hash>) -> Self {
        Self {
            block_hash,
            tx_hashes,
        }
    }

    /// Get the number of transactions being requested.
    pub fn count(&self) -> usize {
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
    use sbor::prelude::basic_encode;

    #[test]
    fn test_get_transactions_request() {
        let block_hash = Hash::from_bytes(b"block123");
        let tx_hashes = vec![
            Hash::from_bytes(b"tx1"),
            Hash::from_bytes(b"tx2"),
            Hash::from_bytes(b"tx3"),
        ];

        let request = GetTransactionsRequest::new(block_hash, tx_hashes.clone());
        assert_eq!(request.block_hash, block_hash);
        assert_eq!(request.tx_hashes, tx_hashes);
        assert_eq!(request.count(), 3);
    }

    #[test]
    fn test_sbor_roundtrip() {
        let request =
            GetTransactionsRequest::new(Hash::from_bytes(b"block"), vec![Hash::from_bytes(b"tx1")]);
        let bytes = basic_encode(&request).unwrap();
        let decoded: GetTransactionsRequest = sbor::prelude::basic_decode(&bytes).unwrap();
        assert_eq!(request, decoded);
    }
}
