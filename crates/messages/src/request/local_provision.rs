//! Local provisions fetch request (intra-shard DA).

use crate::response::GetLocalProvisionsResponse;
#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{BlockHash, MessagePriority, NetworkMessage, ProvisionHash, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch provisions data for a pending block.
///
/// Used when a validator receives a block header with `provision_hashes`
/// but doesn't have the provisions locally (missed the gossip from the source shard).
/// Same pattern as `GetTransactionsRequest` — tries the proposer first, rotates to peers.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetLocalProvisionsRequest {
    /// Hash of the block that needs these provisions.
    pub block_hash: BlockHash,

    /// Hashes of the provisions being requested.
    pub batch_hashes: Vec<ProvisionHash>,
}

impl GetLocalProvisionsRequest {
    pub fn new(block_hash: BlockHash, batch_hashes: Vec<ProvisionHash>) -> Self {
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
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
            batch_hashes: vec![
                ProvisionHash::from_raw(Hash::from_bytes(b"batch1")),
                ProvisionHash::from_raw(Hash::from_bytes(b"batch2")),
            ],
        };
        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetLocalProvisionsRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
