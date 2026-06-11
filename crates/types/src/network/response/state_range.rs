//! Snap-sync state range response.

use sbor::prelude::BasicSbor;

use crate::{
    BoundedBytes, BoundedVec, Hash, MAX_STATE_ENTRY_KEY_LEN, MAX_STATE_ENTRY_VALUE_LEN,
    MerkleInclusionProof, MessageClass, NetworkMessage,
};

/// Cap on the leaves a single state range chunk can carry.
///
/// Bounds the response decode and the server's per-chunk enumeration;
/// a joiner paginates with `more` + cursor continuation, so the cap
/// sizes chunks, not the total transfer.
pub const MAX_LEAVES_PER_STATE_RANGE: usize = 1_024;

/// One leaf of a state range: the JMT leaf key plus the raw substate
/// pair it represents.
///
/// The verifier trusts none of it bare: `leaf_key` must prove into the
/// shard's attested `state_root` via the chunk's range proof, the low
/// half of `leaf_key` must equal `BLAKE3(storage_key)[..16]` (binding
/// the raw key without needing the owner map — the high half is the
/// owner-routing prefix, attested positionally by the proof), and the
/// proof's claimed value hash must equal the hash of `value`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateRangeLeaf {
    /// The 32-byte hashed JMT leaf key.
    pub leaf_key: Hash,
    /// The raw substate storage key, bounded by the same decode cap as
    /// a provisioned `SubstateEntry` — any committed key must be
    /// servable here, so the two limits must not diverge.
    pub storage_key: BoundedBytes<MAX_STATE_ENTRY_KEY_LEN>,
    /// The raw substate value, bounded like a provisioned entry's.
    pub value: BoundedBytes<MAX_STATE_ENTRY_VALUE_LEN>,
}

/// A served chunk of a shard's state at a pinned boundary: leaves in
/// ascending hashed-key order plus the completeness-checked range proof
/// over them.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateRangeChunk {
    /// `(leaf, raw pair)` entries, strictly ascending by `leaf_key`.
    pub leaves: BoundedVec<StateRangeLeaf, MAX_LEAVES_PER_STATE_RANGE>,
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_sbor_roundtrip_unavailable() {
        let response = GetStateRangeResponse { chunk: None };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetStateRangeResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_sbor_roundtrip_chunk() {
        let leaf = StateRangeLeaf {
            leaf_key: Hash::from_bytes(b"leaf"),
            storage_key: BoundedBytes::from(vec![7u8; 60]),
            value: BoundedBytes::from(vec![9u8; 128]),
        };
        let response = GetStateRangeResponse {
            chunk: Some(StateRangeChunk {
                leaves: vec![leaf].into(),
                more: true,
                proof: MerkleInclusionProof::new(vec![1, 2, 3]),
            }),
        };

        let encoded = basic_encode(&response).unwrap();
        let decoded: GetStateRangeResponse = basic_decode(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
