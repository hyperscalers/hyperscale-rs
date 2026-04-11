//! Local provision batch fetch request (intra-shard DA).

use crate::response::GetLocalProvisionsResponse;
use hyperscale_types::{Hash, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch provision batch data for a pending block.
///
/// Used when a validator receives a block header with `provision_batch_hashes`
/// but doesn't have the batch data locally (missed the gossip from the source shard).
/// Same pattern as `GetTransactionsRequest` — tries the proposer first, rotates to peers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsRequest {
    /// Hash of the block that needs these provision batches.
    pub block_hash: Hash,

    /// Hashes of the provision batches being requested.
    pub batch_hashes: Vec<Hash>,
}

impl GetLocalProvisionsRequest {
    pub fn new(block_hash: Hash, batch_hashes: Vec<Hash>) -> Self {
        Self {
            block_hash,
            batch_hashes,
        }
    }
}

impl NetworkMessage for GetLocalProvisionsRequest {
    fn message_type_id() -> &'static str {
        "local_provision.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl Request for GetLocalProvisionsRequest {
    type Response = GetLocalProvisionsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetLocalProvisionsRequest {
            block_hash: Hash::from_bytes(b"block"),
            batch_hashes: vec![Hash::from_bytes(b"batch1"), Hash::from_bytes(b"batch2")],
        };
        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetLocalProvisionsRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
