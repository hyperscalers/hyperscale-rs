//! Inbound snap-sync state range serving.

use std::sync::Arc;

use hyperscale_jmt::{Blake3Hasher, Tree, TreeReader};
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{ResolveLeaf, ShardStorage};
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::{
    GetStateRangeResponse, MAX_LEAVES_PER_STATE_RANGE, StateRangeChunk, StateRangeLeaf,
};
use hyperscale_types::{BoundedBytes, Hash, MerkleInclusionProof};
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
/// enumerates leaves over the requested hashed-key range, resolves each
/// to its raw `(storage key, value)` pair, and proves the range against
/// the boundary's `state_root`. Every degraded case — boundary not
/// pinned (or evicted), missing association, oversized pair — answers
/// `chunk: None` so the joiner rotates to another peer rather than
/// receiving something unverifiable.
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

    let start = *req.start.as_bytes();
    let end = *req.end.as_bytes();
    if start > end {
        return unavailable;
    }
    let limit = (req.limit as usize).clamp(1, MAX_LEAVES_PER_STATE_RANGE);

    let Ok(mut range) = Jmt::collect_range(&boundary, &root_key, &start, limit) else {
        return unavailable;
    };

    // Clip to the requested end. Anything dropped lies past the range,
    // so the chunk is exhaustive for `[start, end]` regardless of what
    // the enumeration saw next.
    if range.leaves.last().is_some_and(|(key, _)| *key > end) {
        range.leaves.retain(|(key, _)| *key <= end);
        range.more = false;
    }

    // Resolve raw pairs under the byte budget; stopping early shortens
    // the chunk and signals continuation.
    let mut wire_leaves: Vec<StateRangeLeaf> = Vec::with_capacity(range.leaves.len());
    let mut budget = SOFT_RESPONSE_BYTES;
    for (leaf_key, _) in &range.leaves {
        let Some((storage_key, value)) = boundary.resolve_leaf(leaf_key) else {
            warn!(height = version, "state range: leaf association missing");
            return unavailable;
        };
        budget = budget.saturating_sub(storage_key.len() + value.len() + 32);
        let (Ok(storage_key), Ok(value)) = (
            BoundedBytes::try_from_vec(storage_key),
            BoundedBytes::try_from_vec(value),
        ) else {
            warn!(height = version, "state range: oversized substate pair");
            return unavailable;
        };
        wire_leaves.push(StateRangeLeaf {
            leaf_key: Hash::from_hash_bytes(leaf_key),
            storage_key,
            value,
        });
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

    record_fetch_response_sent("state_range", wire_leaves.len());
    GetStateRangeResponse {
        chunk: Some(StateRangeChunk {
            leaves: wire_leaves.into(),
            more: range.more,
            proof: MerkleInclusionProof::new(proof.encode()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{MultiProof, NibblePath, RangeChunk};
    use hyperscale_storage::test_helpers::{commit_block_with_updates, make_database_update};
    use hyperscale_storage::tree::hash_value;
    use hyperscale_storage::{BoundaryStore, SubstateStore};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::BlockHeight;

    use super::*;

    fn populated_storage(entries: u8) -> Arc<SimShardStorage> {
        let storage = SimShardStorage::default();
        for seed in 1..=entries {
            let updates =
                make_database_update(vec![seed; 50], 0, vec![seed], vec![seed, seed, seed]);
            commit_block_with_updates(&storage, BlockHeight::new(u64::from(seed)), &updates);
        }
        Arc::new(storage)
    }

    fn full_range_request(height: u64) -> GetStateRangeRequest {
        GetStateRangeRequest {
            height: BlockHeight::new(height),
            start: Hash::from_hash_bytes(&[0u8; 32]),
            end: Hash::from_hash_bytes(&[0xFFu8; 32]),
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
                .map(|leaf| (*leaf.leaf_key.as_bytes(), hash_value(&leaf.value)))
                .collect(),
            more: chunk.more,
        };
        let proof = MultiProof::decode(chunk.proof.as_bytes()).unwrap();
        Jmt::verify_range(
            &proof,
            *pinned_root.as_raw().as_bytes(),
            &NibblePath::empty(),
            req.start.as_bytes(),
            req.end.as_bytes(),
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
        let mut cursor = *first.leaves.last().unwrap().leaf_key.as_bytes();
        for byte in cursor.iter_mut().rev() {
            if *byte == u8::MAX {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
        let mut resume = full_range_request(8);
        resume.start = Hash::from_hash_bytes(&cursor);
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
                .map(|leaf| (*leaf.leaf_key.as_bytes(), hash_value(&leaf.value)))
                .collect(),
            more: second.more,
        };
        let proof = MultiProof::decode(second.proof.as_bytes()).unwrap();
        Jmt::verify_range(
            &proof,
            *pinned_root.as_raw().as_bytes(),
            &NibblePath::empty(),
            resume.start.as_bytes(),
            resume.end.as_bytes(),
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
        let mid_end = all.leaves[3].leaf_key;

        let mut req = full_range_request(8);
        req.end = mid_end;
        let clipped = serve_state_range_request(&storage, &req)
            .chunk
            .expect("served");
        assert_eq!(clipped.leaves.len(), 4);
        assert!(!clipped.more);
    }
}
