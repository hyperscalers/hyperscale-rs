//! Committed block header fetch request for fallback recovery.

use crate::response::GetCommittedBlockHeaderResponse;
use hyperscale_types::{BlockHeight, MessagePriority, NetworkMessage, Request, ShardGroupId};
use sbor::prelude::BasicSbor;

/// Request to fetch a missing committed block header from a source shard.
///
/// Sent by remote shards when committed block headers haven't arrived via
/// gossip within the liveness timeout. Any validator in the source shard
/// can serve this request from its local storage.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetCommittedBlockHeaderRequest {
    /// The shard to fetch the header from.
    pub shard: ShardGroupId,
    /// The block height to fetch.
    pub height: BlockHeight,
}

impl NetworkMessage for GetCommittedBlockHeaderRequest {
    fn message_type_id() -> &'static str {
        "committed_header.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl Request for GetCommittedBlockHeaderRequest {
    type Response = GetCommittedBlockHeaderResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetCommittedBlockHeaderRequest {
            shard: ShardGroupId(2),
            height: BlockHeight(42),
        };

        let encoded = sbor::basic_encode(&request).unwrap();
        let decoded: GetCommittedBlockHeaderRequest = sbor::basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
