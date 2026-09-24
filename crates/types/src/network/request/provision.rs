//! Provision fetch request.

use hyperscale_hbor::Hbor;

use crate::network::response::GetProvisionResponse;
use crate::{BlockHeight, MessageClass, NetworkMessage, Request, ShardId};

/// Request to fetch provisions from a source shard: everything the source
/// block promised this target, at that block's own height.
///
/// The push's fallback: a remote block's `ticks` named this shard and no
/// provisions arrived, so the bundle is rebuilt from the block that owed
/// it. The height fixes the reading, and the producing header's
/// `provision_tx_roots` says what a complete answer is. A bundle carries
/// read sets only; a crossing record reaches its consumer as a state
/// claim.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProvisionsRequest {
    /// The source block whose promise is rebuilt.
    pub height: BlockHeight,
    /// The shard requesting provisions (so the source knows which
    /// state entries to include in the response).
    pub target_shard: ShardId,
}

impl GetProvisionsRequest {
    /// Rebuild what the block at `height` owed `target_shard`.
    #[must_use]
    pub const fn new(height: BlockHeight, target_shard: ShardId) -> Self {
        Self {
            height,
            target_shard,
        }
    }
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

    fn is_empty_response(response: &Self::Response) -> bool {
        response.provisions.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetProvisionsRequest::new(BlockHeight::new(42), ShardId::ROOT);
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetProvisionsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
