//! Provision fetch request.

use hyperscale_hbor::{Capped, Hbor};

use crate::network::response::GetProvisionResponse;
use crate::{BlockHeight, MAX_TXS_PER_BLOCK, MessageClass, NetworkMessage, Request, ShardId};

/// Request to fetch provision parts from a source shard: the parts at
/// `indices` of what the source block at `height` owes `target_shard`.
///
/// The push's fallback: a commit-proven remote header owes this shard
/// parts and not all of them arrived, so the missing ones are rebuilt
/// from the block that owed them. The height fixes the reading, and the
/// producing header's `provision_tx_roots` is what each part's leaf path
/// walks to. A part carries one transaction's read set; a crossing
/// record reaches its consumer as a state claim.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetProvisionsRequest {
    /// The source block whose parts are rebuilt.
    pub height: BlockHeight,
    /// The shard requesting provisions (so the source knows which
    /// transactions' parts it owes).
    pub target_shard: ShardId,
    /// The leaf indices asked for, ascending.
    pub indices: Capped<Vec<u32>, MAX_TXS_PER_BLOCK>,
}

impl GetProvisionsRequest {
    /// Rebuild the parts at `indices` of what the block at `height` owed
    /// `target_shard`.
    #[must_use]
    pub const fn new(
        height: BlockHeight,
        target_shard: ShardId,
        indices: Capped<Vec<u32>, MAX_TXS_PER_BLOCK>,
    ) -> Self {
        Self {
            height,
            target_shard,
            indices,
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

    /// An answer stating the count is not empty, even with no part: a
    /// holder of the block that cannot build the asked index still
    /// teaches how many there are.
    fn is_empty_response(response: &Self::Response) -> bool {
        response.parts.is_empty() && response.count.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetProvisionsRequest::new(
            BlockHeight::new(42),
            ShardId::ROOT,
            Capped::from_array([0, 3, 7]),
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetProvisionsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
