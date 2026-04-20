//! Block fetch request.

use crate::response::GetBlockResponse;
use hyperscale_types::{BlockHeight, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch a full Block by height during sync or catch-up.
///
/// `target_height` carries the requester's catch-up goal so the serving
/// peer can decide whether to return the block as `Live` (still within
/// the execution window relative to the target) or `Sealed` (past the
/// window, no provisions needed).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockRequest {
    /// Height of the block being requested.
    pub height: BlockHeight,
    /// Height the requester is catching up to. Used by the serving peer
    /// to pick between `Block::Live` and `Block::Sealed`.
    pub target_height: BlockHeight,
}

impl GetBlockRequest {
    /// Create a new block fetch request. Panics if `target_height <
    /// height` — a request for a block past the stated sync target is a
    /// programming error in the caller (sync always catches up forward).
    pub fn new(height: BlockHeight, target_height: BlockHeight) -> Self {
        assert!(
            target_height >= height,
            "GetBlockRequest: target_height ({}) must be >= height ({})",
            target_height.0,
            height.0,
        );
        Self {
            height,
            target_height,
        }
    }
}

// Network message implementation
impl NetworkMessage for GetBlockRequest {
    fn message_type_id() -> &'static str {
        "block.request"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Background
    }
}

/// Type-safe request/response pairing.
/// GetBlockRequest expects GetBlockResponse.
impl Request for GetBlockRequest {
    type Response = GetBlockResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_block_request() {
        let request = GetBlockRequest::new(BlockHeight(42), BlockHeight(100));
        assert_eq!(request.height, BlockHeight(42));
        assert_eq!(request.target_height, BlockHeight(100));
    }
}
