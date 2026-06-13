//! Settled-wave reveal request for the split-boundary fence.
//!
//! After a shard P terminates at a split, a surviving counterpart must
//! decide, for any cross-shard wave still referencing P, whether P
//! actually settled that wave in its chain at or before the terminal
//! block B. It learns this by walking P's tail chain back from B,
//! reading each block's settled-wave reveal. The server resolves the
//! block at `height` and answers the wave-ids its committed
//! certificates carry; the requester binds the reveal to B's chain via
//! `block_hash` and the header chain (see [`GetSettledWavesResponse`]).

use sbor::prelude::BasicSbor;

use crate::network::response::GetSettledWavesResponse;
use crate::{BlockHash, BlockHeight, MessageClass, NetworkMessage, Request};

/// Request the settled-wave reveal for one committed block of a
/// terminated shard's tail chain.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetSettledWavesRequest {
    /// Height of the block whose certificates the requester wants
    /// revealed.
    pub height: BlockHeight,
    /// Expected hash of that block. The requester learns it from the
    /// beacon-attested terminal anchor (for B) or the previous block's
    /// `parent_block_hash` (walking back); the server serves by height
    /// and the requester rejects a hash mismatch.
    pub block_hash: BlockHash,
}

impl GetSettledWavesRequest {
    /// Request the reveal for the block at `height` whose hash the
    /// requester expects to be `block_hash`.
    #[must_use]
    pub const fn new(height: BlockHeight, block_hash: BlockHash) -> Self {
        Self { height, block_hash }
    }
}

impl NetworkMessage for GetSettledWavesRequest {
    fn message_type_id() -> &'static str {
        "settled_waves.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetSettledWavesRequest {
    type Response = GetSettledWavesResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.reveal.is_none()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetSettledWavesRequest::new(
            BlockHeight::new(98),
            BlockHash::from_raw(Hash::from_bytes(b"terminal")),
        );
        let encoded = basic_encode(&request).unwrap();
        let decoded: GetSettledWavesRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
