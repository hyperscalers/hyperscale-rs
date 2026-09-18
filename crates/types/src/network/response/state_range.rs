//! Snap-sync state range response.

use hyperscale_hbor::{Capped, Hbor};

use crate::{MerkleInclusionProof, MessageClass, NetworkMessage, SubstateLeaf};

/// Cap on the leaves a single state range chunk can carry.
///
/// Bounds the response decode and the server's per-chunk enumeration;
/// a joiner paginates with `more` + cursor continuation, so the cap
/// sizes chunks, not the total transfer.
pub const MAX_LEAVES_PER_STATE_RANGE: usize = 1_024;

/// A served chunk of a shard's state at a pinned boundary: leaves in
/// ascending key order plus the completeness-checked range proof over
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct StateRangeChunk {
    /// Substate entries, strictly ascending by key.
    pub leaves: Capped<Vec<SubstateLeaf>, MAX_LEAVES_PER_STATE_RANGE>,
    /// Whether leaves beyond the last returned remain in the requested
    /// range — the chunk is complete only through its last leaf, and the
    /// joiner resumes immediately after it.
    pub more: bool,
    /// Encoded range proof (`MultiProof` wire format) for the chunk,
    /// verified against the shard's beacon-attested boundary
    /// `state_root`.
    pub proof: MerkleInclusionProof,
}

/// Response to a
/// [`GetStateRangeRequest`](crate::network::request::GetStateRangeRequest).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetStateRangeResponse {
    /// The served chunk, or `None` when this peer cannot serve the
    /// requested boundary (never pinned, or evicted from its ring) —
    /// the requester should try a different peer.
    pub chunk: Option<StateRangeChunk>,
}

impl NetworkMessage for GetStateRangeResponse {
    fn message_type_id() -> &'static str {
        "state_range.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::test_utils::test_key;

    #[test]
    fn test_hbor_roundtrip_unavailable() {
        let response = GetStateRangeResponse { chunk: None };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetStateRangeResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_chunk() {
        let leaf = SubstateLeaf {
            key: test_key(7u8),
            value: Bytes::from_array([9u8; 128]),
        };
        let response = GetStateRangeResponse {
            chunk: Some(StateRangeChunk {
                leaves: Capped::from_array([leaf]),
                more: true,
                proof: MerkleInclusionProof::new(vec![1, 2, 3]),
            }),
        };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetStateRangeResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
