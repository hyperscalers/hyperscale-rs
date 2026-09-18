//! Inbound remote-header range request handling.
//!
//! Serves `GetRemoteHeadersRequest`s from peers catching up to this shard's
//! certified header chain. Walks local storage from `from_height` and
//! returns up to `count` consecutive headers, capped by
//! [`MAX_REMOTE_HEADERS_PER_REQUEST`] and the local tip. The response
//! short-caps on the first missing height rather than failing.

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
        return GetRemoteHeadersResponse {
            headers: Capped::empty(),
        };
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
        if headers.push((**header).clone()).is_err() {
            break;
        }
    }

    if !headers.is_empty() {
        record_fetch_response_sent("remote_header", headers.len());
    }

    GetRemoteHeadersResponse { headers }
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
/// satisfied by construction here. Stops on the first missing height, so
/// the response is a contiguous prefix of the requested range.
pub fn serve_local_certified_headers<S: ShardChainReader>(
    storage: &S,
    req: &GetRemoteHeadersRequest,
) -> GetRemoteHeadersResponse {
    let bounded_count = req.count.min(MAX_REMOTE_HEADERS_PER_REQUEST);
    let mut headers = Capped::empty();
    for offset in 0..bounded_count.inner() {
        let height = BlockHeight::new(req.from_height.inner().saturating_add(offset));
        let Some(certified) = storage.get_certified_header(height) else {
            break;
        };
        if headers.push(certified.as_ref().clone()).is_err() {
            break;
        }
    }
    GetRemoteHeadersResponse { headers }
}
