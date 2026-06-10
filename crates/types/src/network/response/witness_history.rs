//! Snap-sync beacon-witness history response.

use sbor::prelude::BasicSbor;

use crate::{BlockHeader, BoundedVec, Hash, MessageClass, NetworkMessage};

/// Cap on the leaf hashes a single witness-history page can carry.
///
/// Bounds the response decode; a joiner paginates with `more` + index
/// continuation, so the cap sizes pages (128 KiB of hashes), not the
/// total transfer.
pub const MAX_HASHES_PER_WITNESS_HISTORY: usize = 4_096;

/// One page of a shard's beacon-witness leaf-hash history at a
/// boundary anchor.
///
/// The verifier trusts none of it bare: `header` must hash to the
/// beacon-attested anchor `block_hash`, and the fully assembled hash
/// vector must merkle to `header.beacon_witness_root()` with exactly
/// `header.beacon_witness_leaf_count()` entries. Individual pages
/// carry no proof — a mismatch at final assembly restarts the fetch.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct WitnessHistoryChunk {
    /// The boundary block's header. Hash-bound to the anchor; its
    /// `beacon_witness_root` / `beacon_witness_leaf_count` are the
    /// commitment the assembled history verifies against, and its
    /// `parent_qc` carries the committee-anchor weighted timestamp the
    /// joiner seeds its recovered state with.
    pub header: BlockHeader,
    /// Leaf hashes from the requested `start_index`, in leaf-index
    /// order.
    pub leaf_hashes: BoundedVec<Hash, MAX_HASHES_PER_WITNESS_HISTORY>,
    /// Whether leaves beyond the last returned remain below the
    /// header's leaf count — the joiner resumes at the next index.
    pub more: bool,
}

/// Response to a
/// [`GetWitnessHistoryRequest`](crate::network::request::GetWitnessHistoryRequest).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GetWitnessHistoryResponse {
    /// The served page, or `None` when this peer cannot serve the
    /// requested anchor (unknown height, fork-divergent hash, or
    /// retention-pruned leaves) — the requester should try a different
    /// peer.
    pub history: Option<WitnessHistoryChunk>,
}

impl NetworkMessage for GetWitnessHistoryResponse {
    fn message_type_id() -> &'static str {
        "witness_history.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}
