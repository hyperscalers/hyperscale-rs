//! Block fetch response.

use hyperscale_hbor::Hbor;

use crate::BlockHeight;
use crate::network::{MessageClass, NetworkMessage};
use crate::shard::inventory::ElidedCertifiedBlock;

/// Response to a block fetch request.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum GetBlockResponse {
    /// The requested block in elided form together with its certifying
    /// QC. Inline bodies may be omitted for items the requester already
    /// holds (see [`ElidedCertifiedBlock`]); hash lists are always
    /// complete.
    Found(Box<ElidedCertifiedBlock>),
    /// The serving peer does not hold the block.
    NotFound,
    /// The height lies below the serving peer's chain floor: it keeps no
    /// block beneath `floor`, and never will again. A requester that
    /// needs such a height from every peer cannot be served by block
    /// sync at all.
    BelowFloor {
        /// The lowest height the serving peer holds.
        floor: BlockHeight,
    },
}

impl GetBlockResponse {
    /// Create a response with a found block.
    #[must_use]
    pub fn found(certified: ElidedCertifiedBlock) -> Self {
        Self::Found(Box::new(certified))
    }

    /// Create a response for a block not found.
    #[must_use]
    pub const fn not_found() -> Self {
        Self::NotFound
    }

    /// Create a response for a height below the serving peer's floor.
    #[must_use]
    pub const fn below_floor(floor: BlockHeight) -> Self {
        Self::BelowFloor { floor }
    }

    /// Check if the block was found.
    #[must_use]
    pub const fn has_block(&self) -> bool {
        matches!(self, Self::Found(_))
    }

    /// The elided block, when one was found.
    #[must_use]
    pub fn block(&self) -> Option<&ElidedCertifiedBlock> {
        match self {
            Self::Found(certified) => Some(certified),
            Self::NotFound | Self::BelowFloor { .. } => None,
        }
    }

    /// Consume and return the elided block.
    #[must_use]
    pub fn into_elided(self) -> Option<Box<ElidedCertifiedBlock>> {
        match self {
            Self::Found(certified) => Some(certified),
            Self::NotFound | Self::BelowFloor { .. } => None,
        }
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

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn a_below_floor_answer_round_trips_with_its_floor() {
        let answer = GetBlockResponse::below_floor(BlockHeight::new(40));
        let decoded: GetBlockResponse = hbor_from_slice(&hbor_to_vec(&answer).unwrap()).unwrap();
        assert_eq!(decoded, answer);
        assert!(!decoded.has_block());
    }
}
