//! Block fetch response.

use sbor::prelude::BasicSbor;

use crate::block::inventory::ElidedCertifiedBlock;
use crate::network::{MessageClass, NetworkMessage};

/// Response to a block fetch request.
///
/// Carries a block in elided form together with its certifying QC.
/// Inline bodies may be omitted for items the requester already holds
/// (see [`ElidedCertifiedBlock`]); hash lists are always complete.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockResponse {
    /// The requested block (elided) + certifying QC. `None` when the
    /// serving peer doesn't have the block.
    pub certified: Option<ElidedCertifiedBlock>,
}

impl GetBlockResponse {
    /// Create a response with a found block.
    #[must_use]
    pub const fn found(certified: ElidedCertifiedBlock) -> Self {
        Self {
            certified: Some(certified),
        }
    }

    /// Create a response for a block not found.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { certified: None }
    }

    /// Check if the block was found.
    #[must_use]
    pub const fn has_block(&self) -> bool {
        self.certified.is_some()
    }

    /// Consume and return the elided block.
    #[must_use]
    pub fn into_elided(self) -> Option<ElidedCertifiedBlock> {
        self.certified
    }
}

impl NetworkMessage for GetBlockResponse {
    fn message_type_id() -> &'static str {
        "block.response"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}
