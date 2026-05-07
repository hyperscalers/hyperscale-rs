//! Provision fetch request for fallback recovery.

use hyperscale_types::{BlockHeight, MessageClass, NetworkMessage, Request, ShardGroupId};
use sbor::prelude::BasicSbor;

use crate::response::GetProvisionResponse;

/// Request to fetch missing provisions from a source shard.
///
/// Sent by target shards when a remote block's `waves` field indicates
/// the target shard but no provisions arrived within the timeout window.
/// This is the fallback recovery mechanism for byzantine proposers that
/// silently drop provisions.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetProvisionsRequest {
    /// Height of the source block whose provisions are needed.
    pub block_height: BlockHeight,
    /// The shard requesting provisions (so the source knows which
    /// state entries to include in the response).
    pub target_shard: ShardGroupId,
}

impl NetworkMessage for GetProvisionsRequest {
    fn message_type_id() -> &'static str {
        "provision.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetProvisionsRequest {
    type Response = GetProvisionResponse;
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetProvisionsRequest {
            block_height: BlockHeight::new(42),
            target_shard: ShardGroupId::new(1),
        };

        let encoded = basic_encode(&request).unwrap();
        let decoded: GetProvisionsRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
