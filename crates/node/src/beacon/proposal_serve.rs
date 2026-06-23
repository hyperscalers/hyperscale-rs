//! Inbound beacon-proposal fetch request handling.

use std::sync::Arc;

use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_types::Verifiable;
use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
use hyperscale_types::network::response::beacon::GetBeaconProposalResponse;

/// Serve an inbound [`GetBeaconProposalRequest`] from a pool.
///
/// Returns an empty response when the request's epoch doesn't match
/// the pool's tracked epoch or when the named validator has no entry.
/// The network handler captures `Arc<BeaconProposalPool>` and calls
/// this synchronously on the network-worker thread; lock-free reads
/// against papaya make it wait-free in the common case.
#[must_use]
pub fn serve_beacon_proposal_request(
    pool: &BeaconProposalPool,
    req: &GetBeaconProposalRequest,
) -> GetBeaconProposalResponse {
    let response = if req.epoch == pool.epoch() {
        let proposal = pool
            .get(req.validator)
            .map(|verified| Arc::new(Verifiable::from((*verified).clone())));
        GetBeaconProposalResponse::new(proposal)
    } else {
        GetBeaconProposalResponse::empty()
    };
    record_fetch_response_sent("beacon_proposal", usize::from(response.proposal.is_some()));
    response
}
