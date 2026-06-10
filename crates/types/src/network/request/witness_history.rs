//! Snap-sync beacon-witness history request.

use sbor::prelude::BasicSbor;

use crate::network::response::GetWitnessHistoryResponse;
use crate::{BlockHash, BlockHeight, MessageClass, NetworkMessage, Request};

/// Request a page of a shard's beacon-witness leaf-hash history at its
/// beacon-attested boundary anchor.
///
/// Sent by a joining vnode bootstrapping the target shard: block
/// headers commit `(beacon_witness_root, beacon_witness_leaf_count)`
/// over the accumulator's full leaf-hash vector, so verifying any
/// future proposal requires the hashes up to the anchor. The server
/// resolves the boundary header at `height`, cross-checks its hash
/// against `block_hash`, and answers leaf hashes from `start_index` in
/// leaf-index order. The joiner verifies the assembled vector against
/// the header's root and count once complete.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetWitnessHistoryRequest {
    /// The anchor's block height, read from the projected
    /// `TopologySnapshot`.
    pub height: BlockHeight,
    /// The anchor's block hash — binds the served header (and through
    /// its witness root, every served hash) to the beacon-attested
    /// boundary.
    pub block_hash: BlockHash,
    /// First leaf index of the requested page (0-based).
    pub start_index: u64,
    /// Requested hash cap for this page. The server clamps to
    /// [`MAX_HASHES_PER_WITNESS_HISTORY`](crate::network::response::MAX_HASHES_PER_WITNESS_HISTORY);
    /// `more` signals continuation.
    pub limit: u32,
}

impl NetworkMessage for GetWitnessHistoryRequest {
    fn message_type_id() -> &'static str {
        "witness_history.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetWitnessHistoryRequest {
    type Response = GetWitnessHistoryResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.history.is_none()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_sbor_roundtrip() {
        let request = GetWitnessHistoryRequest {
            height: BlockHeight::new(42),
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"anchor")),
            start_index: 1_024,
            limit: 512,
        };

        let encoded = basic_encode(&request).unwrap();
        let decoded: GetWitnessHistoryRequest = basic_decode(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
