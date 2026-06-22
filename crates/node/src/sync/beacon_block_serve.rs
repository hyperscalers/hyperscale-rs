//! Inbound beacon-block sync request handling.
//!
//! Serves `GetBeaconBlockRequest`s from peers catching up the beacon
//! chain. A `CertifiedBeaconBlock` is self-contained (block + cert, no
//! provisions to re-attach), so the serve is a thin storage read — much
//! simpler than the shard `block_serve` dedup-horizon dance.

use std::sync::Arc;

use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::BeaconStorage;
use hyperscale_types::Verifiable;
use hyperscale_types::network::request::beacon::GetBeaconBlockRequest;
use hyperscale_types::network::response::beacon::GetBeaconBlockResponse;

/// Serve an inbound [`GetBeaconBlockRequest`] from beacon storage.
///
/// Returns the committed `CertifiedBeaconBlock` at the requested epoch
/// (wrapped `Unverified` for the wire — the requester verifies the cert
/// before applying), or `not_found` when the epoch isn't committed
/// locally so the requester rotates to another peer. The network
/// handler calls this synchronously on the network-worker thread.
#[must_use]
pub fn serve_beacon_block_request(
    storage: &dyn BeaconStorage,
    req: &GetBeaconBlockRequest,
) -> GetBeaconBlockResponse {
    let response = storage
        .get_beacon_block_by_epoch(req.epoch)
        .map_or_else(GetBeaconBlockResponse::not_found, |block| {
            GetBeaconBlockResponse::found(Arc::new(Verifiable::from((**block).clone())))
        });
    record_fetch_response_sent("beacon_block", usize::from(response.block.is_some()));
    response
}
