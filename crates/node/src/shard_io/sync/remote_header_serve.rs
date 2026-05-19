//! Inbound remote-header range request handling.
//!
//! Serves `GetRemoteHeadersRequest`s from peers catching up to this shard's
//! committed-header chain. Walks local storage from `from_height` and
//! returns up to `count` consecutive headers, capped by
//! [`MAX_REMOTE_HEADERS_PER_REQUEST`] and the local tip. The response
//! short-caps on the first missing height rather than failing.

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::ChainReader;
use hyperscale_types::network::request::{GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST};
use hyperscale_types::network::response::GetRemoteHeadersResponse;
use hyperscale_types::{BlockHeight, ShardGroupId};

/// Serve an inbound remote-header range request.
///
/// Returns headers `[from_height, from_height + bounded_count)` in
/// ascending height order. `bounded_count` is the requested `count` clamped
/// by [`MAX_REMOTE_HEADERS_PER_REQUEST`]; iteration also stops on the first
/// missing height so the response is always a contiguous prefix of the
/// requested range.
///
/// Requests for a shard other than `local_shard` get an empty response.
/// Without this gate a shard A node would serve its own committed headers
/// in response to a request for shard B headers; the requester filters
/// only by height and would buffer them under the wrong shard scope,
/// stalling sync until rotation.
pub fn serve_remote_headers_request(
    storage: &impl ChainReader,
    local_shard: ShardGroupId,
    req: &GetRemoteHeadersRequest,
) -> GetRemoteHeadersResponse {
    if req.source_shard != local_shard {
        return GetRemoteHeadersResponse {
            headers: Vec::new(),
        };
    }

    let bounded_count = req.count.min(MAX_REMOTE_HEADERS_PER_REQUEST);
    let mut headers = Vec::with_capacity(usize::try_from(bounded_count.inner()).unwrap_or(0));

    for offset in 0..bounded_count.inner() {
        let height = BlockHeight::new(req.from_height.inner().saturating_add(offset));
        let Some(header) = storage.get_committed_header(height) else {
            break;
        };
        headers.push(header);
    }

    if !headers.is_empty() {
        record_fetch_response_sent("remote_header", headers.len());
    }

    GetRemoteHeadersResponse { headers }
}
