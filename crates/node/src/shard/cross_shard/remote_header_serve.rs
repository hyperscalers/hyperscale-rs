//! Inbound remote-header range request handling.
//!
//! Serves `GetRemoteHeadersRequest`s from peers catching up to this shard's
//! certified header chain. Walks local storage from `from_height` and
//! returns up to `count` consecutive headers, capped by
//! [`MAX_REMOTE_HEADERS_PER_REQUEST`] and the local tip. The response
//! short-caps on the first missing height rather than failing.
//!
//! A split child's store starts as a checkpoint of its parent's, so below
//! the child's genesis it holds the parent's chain. Those heights are not
//! the requested shard's, and a response stops at the first header of
//! another shard as it does at a missing height.

use hyperscale_hbor::Capped;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardChainReader, ShardStorage};
use hyperscale_types::network::request::{GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST};
use hyperscale_types::network::response::GetRemoteHeadersResponse;
use hyperscale_types::{BlockHeight, ShardId};

/// Serve an inbound remote-header range request.
///
/// Returns headers `[from_height, from_height + bounded_count)` in
/// ascending height order. `bounded_count` is the requested `count` clamped
/// by [`MAX_REMOTE_HEADERS_PER_REQUEST`]; iteration also stops on the first
/// missing height so the response is always a contiguous prefix of the
/// requested range.
///
/// Headers are read through [`PendingChain`] so heights that are
/// shard-committed but not yet JMT-persisted are reachable too — without
/// that, a peer racing the local persistence drain would see a `not_found`
/// gap and rotate, stretching sync.
///
/// A request starting beneath this store's chain floor is answered with
/// the floor and no header: the heights below it are gone here for good,
/// and a requester syncing forward from one has to re-anchor rather than
/// ask again.
///
/// Requests for a shard other than `local_shard` get an empty response.
/// Without this gate a shard A node would serve its own certified headers
/// in response to a request for shard B headers; the requester filters
/// only by height and would buffer them under the wrong shard scope,
/// stalling sync until rotation.
pub fn serve_remote_headers_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    local_shard: ShardId,
    req: &GetRemoteHeadersRequest,
) -> GetRemoteHeadersResponse {
    if req.source_shard != local_shard {
        return GetRemoteHeadersResponse::empty();
    }
    let floor = pending_chain.chain_floor();
    if req.from_height < floor {
        return GetRemoteHeadersResponse::below_floor(floor);
    }

    let bounded_count = req.count.min(MAX_REMOTE_HEADERS_PER_REQUEST);
    let mut headers = Capped::empty();

    for offset in 0..bounded_count.inner() {
        let height = BlockHeight::new(req.from_height.inner().saturating_add(offset));
        // Committed heights first; then the certified-but-uncommitted tip,
        // whose header carries the committed tip's committing QC — without
        // it a requester cannot complete a commit proof of the tip, and if
        // this chain has stalled no later commit will ever gossip it.
        let Some(header) = pending_chain
            .certified_header(height)
            .or_else(|| pending_chain.certified_uncommitted_header(height))
        else {
            break;
        };
        if header.shard_id() != req.source_shard {
            break;
        }
        if headers.push((**header).clone()).is_err() {
            break;
        }
    }

    if !headers.is_empty() {
        record_fetch_response_sent("remote_header", headers.len());
    }

    GetRemoteHeadersResponse::of(headers)
}

/// Serve a certified-header batch out of a committed chain reader alone.
///
/// The reshape counterpart of [`serve_remote_headers_request`], for a host
/// answering from a store it holds directly rather than through a live
/// vnode's pending chain. A recognition walk reads the chain of a shard
/// that is terminating: its committee dissolves at the cut, so by the time
/// the walk reaches the terminal there may be no committee left to ask —
/// but every member still holds the chain.
///
/// The caller selects the store by the requested source shard, so the
/// cross-shard gate [`serve_remote_headers_request`] applies is already
/// satisfied by construction here. A range starting beneath the store's
/// chain floor is answered with the floor, as a live vnode answers it.
/// Stops on the first missing height, so the response is a contiguous
/// prefix of the requested range.
pub fn serve_local_certified_headers<S: ShardChainReader>(
    storage: &S,
    req: &GetRemoteHeadersRequest,
) -> GetRemoteHeadersResponse {
    let floor = storage.chain_floor();
    if req.from_height < floor {
        return GetRemoteHeadersResponse::below_floor(floor);
    }
    let bounded_count = req.count.min(MAX_REMOTE_HEADERS_PER_REQUEST);
    let mut headers = Capped::empty();
    for offset in 0..bounded_count.inner() {
        let height = BlockHeight::new(req.from_height.inner().saturating_add(offset));
        let Some(certified) = storage.get_certified_header(height) else {
            break;
        };
        if certified.shard_id() != req.source_shard {
            break;
        }
        if headers.push(certified.as_ref().clone()).is_err() {
            break;
        }
    }
    GetRemoteHeadersResponse::of(headers)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::ShardChainWriter;
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, ChainOrigin, HeaderFetchCount,
    };

    use super::*;

    /// A store read directly answers a range beneath its chain floor as a
    /// live vnode's does: with the floor, and no header a hold or a
    /// collection yet to run happens to have left there.
    #[test]
    fn a_store_read_directly_answers_beneath_its_floor_with_it() {
        let storage = SimShardStorage::default();
        for height in 1..=4 {
            commit_settled_at(
                &storage,
                &make_test_certified(make_test_block(BlockHeight::new(height))),
                &[],
                &[],
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(3));
        let ask = |from: u64| {
            serve_local_certified_headers(
                &storage,
                &GetRemoteHeadersRequest {
                    source_shard: ShardId::ROOT,
                    from_height: BlockHeight::new(from),
                    count: HeaderFetchCount::new(4),
                },
            )
        };
        assert_eq!(
            ask(1),
            GetRemoteHeadersResponse::below_floor(BlockHeight::new(3))
        );
        let served = ask(3);
        assert_eq!(served.floor, None);
        assert_eq!(served.headers.len(), 2);
    }

    /// A range starting beneath the chain floor answers with the floor and
    /// no header; one starting at the floor is served as before.
    #[test]
    fn a_range_beneath_the_floor_is_answered_with_it() {
        let storage = SimShardStorage::default();
        for height in 1..=4 {
            commit_settled_at(
                &storage,
                &make_test_certified(make_test_block(BlockHeight::new(height))),
                &[],
                &[],
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        storage.advance_chain_floor(ShardId::ROOT, BlockHeight::new(3));
        let chain = PendingChain::new(Arc::new(storage), ChainOrigin::ROOT);
        let ask = |from: u64| {
            serve_remote_headers_request(
                &chain,
                ShardId::ROOT,
                &GetRemoteHeadersRequest {
                    source_shard: ShardId::ROOT,
                    from_height: BlockHeight::new(from),
                    count: HeaderFetchCount::new(4),
                },
            )
        };
        assert_eq!(
            ask(1),
            GetRemoteHeadersResponse::below_floor(BlockHeight::new(3))
        );
        let served = ask(3);
        assert_eq!(served.floor, None);
        assert_eq!(
            served
                .headers
                .iter()
                .map(|header| header.height().inner())
                .collect::<Vec<_>>(),
            vec![3, 4],
        );
    }
}
