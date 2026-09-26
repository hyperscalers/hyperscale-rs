//! Block fetch request.

use hyperscale_hbor::Hbor;

use crate::BlockHeight;
use crate::network::response::GetBlockResponse;
use crate::network::{MessageClass, NetworkMessage, Request};
use crate::shard::inventory::Inventory;

/// What the requester will do with the block it asks for.
///
/// The server cannot tell from the height. A joiner walking its history
/// down below a boundary it imported and a validator catching up to
/// execute ask for the same block at the same height, and only one of
/// them runs it — so whether the block's provision bodies are
/// load-bearing is the requester's fact, not the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum BlockIntent {
    /// The requester commits the block and runs its execution tick, so
    /// every provision body the block consumed has to ride with it and a
    /// server that cannot supply one has not answered.
    Execute,
    /// The requester records the block beneath a committed frontier it
    /// already holds — the metadata row, the transactions and the
    /// certificates — and never executes it. Provision bodies answer
    /// nothing here, so a server that retired them still holds
    /// everything this asks for.
    History,
}

/// Request to fetch a full Block by height during sync or catch-up.
///
/// `intent` says what the block is for, which is what decides whether it
/// comes back `Live` with its provision bodies attached or `Sealed`
/// without them.
///
/// `inventory` advertises what the requester already has locally so the
/// responder can elide transaction / certificate / provision bodies the
/// requester can resolve without a re-download.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetBlockRequest {
    /// Height of the block being requested.
    pub height: BlockHeight,
    /// What the requester will do with the block.
    pub intent: BlockIntent,
    /// Per-category inventory of hashes already held locally. Bodies
    /// matching these filters may be omitted from the response.
    pub inventory: Inventory,
}

impl GetBlockRequest {
    /// Create a new block fetch request with no inventory advertised.
    /// Callers that participate in the elision scheme attach an inventory
    /// via [`Self::with_inventory`] immediately after construction.
    #[must_use]
    pub fn new(height: BlockHeight, intent: BlockIntent) -> Self {
        Self {
            height,
            intent,
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

    fn is_empty_response(response: &Self::Response) -> bool {
        response.certified.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BloomFilter, Hash, TxHash};

    #[test]
    fn test_get_block_request() {
        let request = GetBlockRequest::new(BlockHeight::new(42), BlockIntent::Execute);
        assert_eq!(request.height, BlockHeight::new(42));
        assert_eq!(request.intent, BlockIntent::Execute);
        assert!(request.inventory.is_empty());
    }

    #[test]
    fn with_inventory_attaches_filters() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        bf.insert(&TxHash::from(Hash::from_bytes(b"tx")));
        let inv = Inventory {
            tx_have: Some(bf),
            cert_have: None,
            provision_have: None,
        };
        let req =
            GetBlockRequest::new(BlockHeight::new(1), BlockIntent::Execute).with_inventory(inv);
        assert!(!req.inventory.is_empty());
        assert!(req.inventory.tx_have.is_some());
    }

    #[test]
    fn hbor_roundtrip_preserves_inventory_and_intent() {
        let mut bf: BloomFilter<TxHash> = BloomFilter::with_capacity(100, 0.01).unwrap();
        let h = TxHash::from(Hash::from_bytes(b"tx"));
        bf.insert(&h);
        let req = GetBlockRequest::new(BlockHeight::new(1), BlockIntent::History).with_inventory(
            Inventory {
                tx_have: Some(bf),
                cert_have: None,
                provision_have: None,
            },
        );
        let bytes = hbor_to_vec(&req).unwrap();
        let decoded: GetBlockRequest = hbor_from_slice(&bytes).unwrap();
        assert_eq!(req, decoded);
        assert_eq!(decoded.intent, BlockIntent::History);
        assert!(decoded.inventory.tx_have.as_ref().unwrap().contains(&h));
    }
}
