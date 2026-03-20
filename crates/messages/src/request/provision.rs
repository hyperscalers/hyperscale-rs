//! Provision fetch request for fallback recovery.

use hyperscale_codec as sbor;
use hyperscale_codec::BasicSbor;
use hyperscale_types::{
    BlockHeight, MessagePriority, NetworkMessage, Request, ShardGroupId, TypeConfig,
};

/// Request to fetch missing provisions from a source shard.
///
/// Sent by target shards when a remote block's `provision_targets` includes
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

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl<C: TypeConfig> Request<C> for GetProvisionsRequest {
    type Response = crate::response::GetProvisionsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_codec::{basic_decode, basic_encode};

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetProvisionsRequest {
            block_height: BlockHeight(42),
            target_shard: ShardGroupId(1),
        };

        let encoded = basic_encode(&request).unwrap();
        let decoded: GetProvisionsRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
