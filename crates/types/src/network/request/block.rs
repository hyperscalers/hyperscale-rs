//! Block fetch request.

use sbor::prelude::BasicSbor;

use crate::BlockHeight;
use crate::block::inventory::Inventory;
use crate::network::response::GetBlockResponse;
use crate::network::{MessageClass, NetworkMessage, Request};

/// Request to fetch a full Block by height during sync or catch-up.
///
/// `target_height` carries the requester's catch-up goal so the serving
/// peer can decide whether to return the block as `Live` (still within
/// the execution window relative to the target) or `Sealed` (past the
/// window, no provisions needed).
///
/// `inventory` advertises what the requester already has locally so the
/// responder can elide transaction / certificate / provision bodies the
/// requester can resolve without a re-download.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetBlockRequest {
    /// Height of the block being requested.
    pub height: BlockHeight,
    /// Height the requester is catching up to. Used by the serving peer
    /// to pick between `Block::Live` and `Block::Sealed`.
    pub target_height: BlockHeight,
    /// Per-category inventory of hashes already held locally. Bodies
    /// matching these filters may be omitted from the response.
    pub inventory: Inventory,
}

impl GetBlockRequest {
    /// Create a new block fetch request with no inventory advertised.
    /// Callers that participate in the elision scheme attach an inventory
    /// via [`Self::with_inventory`] immediately after construction.
    ///
    /// # Panics
    ///
    /// Panics if `target_height < height` — a request for a block past
    /// the stated sync target is a programming error in the caller (sync
    /// always catches up forward).
    #[must_use]
    pub fn new(height: BlockHeight, target_height: BlockHeight) -> Self {
        assert!(
            target_height >= height,
            "GetBlockRequest: target_height ({}) must be >= height ({})",
            target_height.inner(),
            height.inner(),
        );
        Self {
            height,
            target_height,
            inventory: Inventory::empty(),
        }
    }

    /// Attach the requester's inventory so the responder can elide bodies
    /// the requester already has. Typically called once per sync tick so
    /// every in-flight fetch in the batch shares a single snapshot.
    #[must_use]
    pub fn with_inventory(mut self, inventory: Inventory) -> Self {
        self.inventory = inventory;
        self
    }
}

impl NetworkMessage for GetBlockRequest {
    fn message_type_id() -> &'static str {
        "block.request"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

/// Type-safe request/response pairing.
/// `GetBlockRequest` expects `GetBlockResponse`.
impl Request for GetBlockRequest {
    type Response = GetBlockResponse;
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{BloomFilter, Hash, TxHash};

    #[test]
    fn test_get_block_request() {
        let request = GetBlockRequest::new(BlockHeight::new(42), BlockHeight::new(100));
        assert_eq!(request.height, BlockHeight::new(42));
        assert_eq!(request.target_height, BlockHeight::new(100));
        assert!(request.inventory.is_empty());
    }

    #[test]
    fn with_inventory_attaches_filters() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        bf.insert(&TxHash::from_raw(Hash::from_bytes(b"tx")));
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let req =
            GetBlockRequest::new(BlockHeight::new(1), BlockHeight::new(10)).with_inventory(inv);
        assert!(!req.inventory.is_empty());
        assert!(req.inventory.tx_have.is_some());
    }

    #[test]
    fn sbor_roundtrip_preserves_inventory() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        let h = TxHash::from_raw(Hash::from_bytes(b"tx"));
        bf.insert(&h);
        let req = GetBlockRequest::new(BlockHeight::new(1), BlockHeight::new(10)).with_inventory(
            Inventory {
                tx_have: Some(bf),
                cert_have: None,
                provision_have: None,
            },
        );
        let bytes = basic_encode(&req).unwrap();
        let decoded: GetBlockRequest = basic_decode(&bytes).unwrap();
        assert_eq!(req, decoded);
        assert!(decoded.inventory.tx_have.as_ref().unwrap().contains(&h));
    }
}
