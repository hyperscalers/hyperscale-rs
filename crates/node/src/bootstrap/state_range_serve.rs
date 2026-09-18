//! Inbound snap-sync state range serving.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_jmt::{Blake3Hasher, Tree, TreeReader};
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{ShardStorage, Substates};
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::{
    GetStateRangeResponse, MAX_LEAVES_PER_STATE_RANGE, StateRangeChunk,
};
use hyperscale_types::{MAX_CELL_VALUE_LEN, MerkleInclusionProof, SubstateKey, SubstateLeaf};
use tracing::warn;

type Jmt = Tree<Blake3Hasher, 1>;

/// Soft byte budget for one chunk's raw pairs. Enumeration stops past it
/// and signals continuation, keeping a maximally-adversarial range
/// (every leaf a max-size substate) inside transport frames.
const SOFT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Serve an inbound snap-sync state range request from a pinned epoch
/// boundary.
///
/// Opens the boundary the joiner's beacon-attested anchor names,
/// enumerates leaves over the requested key range, resolves each to its
/// raw value, and proves the range against the boundary's `state_root`.
/// Every degraded case — boundary not pinned (or evicted), missing
/// value, oversized value — answers `chunk: None` so the joiner rotates
/// to another peer rather than receiving something unverifiable.
///
/// # Panics
///
/// If a leaf the tree enumerated is not a well-formed key. The tree only
/// holds keys that were written through [`SubstateKey`], so this is a
/// storage corruption, not a peer's input.
pub fn serve_state_range_request<S: ShardStorage>(
    storage: &Arc<S>,
    req: &GetStateRangeRequest,
) -> GetStateRangeResponse {
    let unavailable = GetStateRangeResponse { chunk: None };

    let Some(boundary) = storage.open_boundary(req.height) else {
        return unavailable;
    };
    let version = req.height.inner();
    let Some(root_key) = boundary.get_root_key(version) else {
        return unavailable;
    };

    let start = req.start;
    let end = req.end;
    if start > end {
        return unavailable;
    }
    let limit = (req.limit as usize).clamp(1, MAX_LEAVES_PER_STATE_RANGE);

    let Ok(mut range) = Jmt::collect_range(&boundary, &root_key, &start, &end, limit) else {
        return unavailable;
    };

    // Resolve raw values under the byte budget; stopping early shortens
    // the chunk and signals continuation.
    let mut wire_leaves: Vec<SubstateLeaf> = Vec::with_capacity(range.leaves.len());
    let mut budget = SOFT_RESPONSE_BYTES;
    for (leaf_key, _) in &range.leaves {
        let key = SubstateKey::from_bytes(*leaf_key).expect("a stored leaf key names an address");
        let Some(value) = boundary.cell(key) else {
            warn!(height = version, "state range: leaf value missing");
            return unavailable;
        };
        budget = budget.saturating_sub(value.len() + 32);
        if value.len() > MAX_CELL_VALUE_LEN {
            warn!(height = version, "state range: oversized substate value");
            return unavailable;
        }
        wire_leaves.push(SubstateLeaf { key, value });
        if budget == 0 {
            break;
        }
    }
    if wire_leaves.len() < range.leaves.len() {
        range.leaves.truncate(wire_leaves.len());
        range.more = true;
    }

    let Ok(proof) = Jmt::prove_range(&boundary, &root_key, &start, &end, &range) else {
        return unavailable;
    };

    // A chunk past the cap is one this answer cannot express, and the
    // proof beside it covers the whole run.
    let Ok(leaves) = Capped::new(wire_leaves) else {
        return unavailable;
    };
    record_fetch_response_sent("state_range", leaves.len());
    GetStateRangeResponse {
        chunk: Some(StateRangeChunk {
            leaves,
            more: range.more,
            proof: MerkleInclusionProof::new(proof.encode()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{MultiProof, NibblePath, RangeChunk, next_key};
    use hyperscale_storage::test_helpers::seed_substate_commits;
    use hyperscale_storage::tree::hash_value;
    use hyperscale_storage::{BoundaryStore, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::BlockHeight;
    use hyperscale_types::test_utils::test_key;

    use super::*;

    fn populated_storage(entries: u8) -> Arc<SimShardStorage> {
        let storage = SimShardStorage::default();
        seed_substate_commits(&storage, entries);
        Arc::new(storage)
    }

    fn full_range_request(height: u64) -> GetStateRangeRequest {
        GetStateRangeRequest {
            height: BlockHeight::new(height),
            start: test_key(0u8).to_bytes(),
            end: test_key(0xFFu8).to_bytes(),
            limit: 1_000,
        }
    }

    /// The served chunk verifies end to end the way a joiner would: the
    /// range proof against the boundary root, with each leaf's value
    /// hash recomputed from the raw value.
    #[test]
    fn served_chunk_verifies_against_boundary_root() {
        let storage = populated_storage(8);
        let pinned_root = storage.state_root();
        storage.pin_boundary(BlockHeight::new(8)).unwrap();

        let req = full_range_request(8);
        let response = serve_state_range_request(&storage, &req);
        let chunk = response.chunk.expect("served");
        assert_eq!(chunk.leaves.len(), 8);
        assert!(!chunk.more);

        let jmt_chunk = RangeChunk {
            leaves: chunk
                .leaves
                .iter()
                .map(|leaf| (leaf.key.to_bytes(), hash_value(&leaf.value)))
                .collect(),
            more: chunk.more,
        };
        let proof = MultiProof::decode(chunk.proof.as_bytes()).unwrap();
        Jmt::verify_range(
            &proof,
            *pinned_root.as_raw().as_bytes(),
            &NibblePath::empty(),
            &req.start,
            &req.end,
            &jmt_chunk,
        )
        .unwrap();
    }

    #[test]
    fn unpinned_boundary_is_unavailable() {
        let storage = populated_storage(4);
        let response = serve_state_range_request(&storage, &full_range_request(4));
        assert!(response.chunk.is_none());
    }

    /// A clamped limit paginates: the chunk signals continuation and the
    /// next request resumes past the last served leaf.
    #[test]
    fn limit_paginates_with_continuation() {
        let storage = populated_storage(8);
        let pinned_root = storage.state_root();
        storage.pin_boundary(BlockHeight::new(8)).unwrap();

        let mut req = full_range_request(8);
        req.limit = 3;
        let first = serve_state_range_request(&storage, &req)
            .chunk
            .expect("served");
        assert_eq!(first.leaves.len(), 3);
        assert!(first.more);

        // Resume immediately after the last served leaf.
        let cursor = next_key(&first.leaves.last().unwrap().key.to_bytes())
            .expect("not at the key-space maximum");
        let mut resume = full_range_request(8);
        resume.start = cursor;
        let second = serve_state_range_request(&storage, &resume)
            .chunk
            .expect("served");
        assert_eq!(second.leaves.len(), 5);
        assert!(!second.more);

        // The resumed chunk verifies on its own.
        let jmt_chunk = RangeChunk {
            leaves: second
                .leaves
                .iter()
                .map(|leaf| (leaf.key.to_bytes(), hash_value(&leaf.value)))
                .collect(),
            more: second.more,
        };
        let proof = MultiProof::decode(second.proof.as_bytes()).unwrap();
        Jmt::verify_range(
            &proof,
            *pinned_root.as_raw().as_bytes(),
            &NibblePath::empty(),
            &resume.start,
            &resume.end,
            &jmt_chunk,
        )
        .unwrap();
    }

    /// Leaves past the requested end are clipped and the chunk reads as
    /// exhaustive for the span.
    #[test]
    fn end_bound_clips_the_chunk() {
        let storage = populated_storage(8);
        storage.pin_boundary(BlockHeight::new(8)).unwrap();

        // Probe a full enumeration to find a mid-range end bound.
        let all = serve_state_range_request(&storage, &full_range_request(8))
            .chunk
            .expect("served");
        let mid_end = all.leaves[3].key.to_bytes();

        let mut req = full_range_request(8);
        req.end = mid_end;
        let clipped = serve_state_range_request(&storage, &req)
            .chunk
            .expect("served");
        assert_eq!(clipped.leaves.len(), 4);
        assert!(!clipped.more);
    }
}
