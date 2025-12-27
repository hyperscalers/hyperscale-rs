//! Block fetch request.

use crate::response::GetBlockResponse;
use hyperscale_types::{BlockHeight, MessagePriority, NetworkMessage, Request};
use sbor::prelude::BasicSbor;

/// Request to fetch a full Block by height during sync or catch-up.
///
/// Note: The wire format encodes this as `height.to_le_bytes()` (8 bytes).
/// This type exists for documentation and type-safety in the message layer.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockRequest {
    /// Height of the block being requested.
    pub height: BlockHeight,
}

impl GetBlockRequest {
    /// Create a new block fetch request.
    pub fn new(height: BlockHeight) -> Self {
        Self { height }
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
        let request = GetBlockRequest::new(BlockHeight(42));
        assert_eq!(request.height, BlockHeight(42));
    }
}
