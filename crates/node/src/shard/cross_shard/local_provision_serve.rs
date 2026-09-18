//! Inbound local-provision fetch request handling.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::{ProvisionStore, VerifiedHeaderBuffer};
use hyperscale_types::network::request::GetLocalProvisionsRequest;
use hyperscale_types::network::response::{GetLocalProvisionsResponse, LocalProvisionEntry};

/// Serve an inbound local-provision fetch request.
///
/// Bundles the matching source header alongside each returned blob so
/// the requester can verify and admit without first racing the
/// remote-header pipeline. Both lookups read the same maps the
/// coordinator writes through, so a present blob implies the header
/// was admitted at some point; `None` means it's since been GC'd
/// (retention sweep) and the requester falls back to the buffered path.
#[must_use]
pub fn serve_local_provisions_request(
    provision_store: &ProvisionStore,
    verified_headers: &VerifiedHeaderBuffer,
    req: &GetLocalProvisionsRequest,
) -> GetLocalProvisionsResponse {
    // One entry per hash asked, so the answer meets the cap the request
    // already met; a hash past it is simply absent, which is what a
    // partial answer already means here.
    let mut entries = Capped::empty();
    for h in &req.batch_hashes {
        if let Some(provisions) = provision_store.get(*h) {
            // The buffer holds Verified handles; the wire form takes
            // raw `Arc<CertifiedBlockHeader>`, so materialize the inner
            // header for ship.
            let source_header = verified_headers
                .get((provisions.source_shard(), provisions.block_height()))
                .map(|v| Arc::new(v.as_ref().clone().into_inner()));
            if entries
                .push(LocalProvisionEntry {
                    provisions,
                    source_header,
                })
                .is_err()
            {
                break;
            }
        }
    }

    record_fetch_response_sent("local_provision", entries.len());
    GetLocalProvisionsResponse::new(entries)
}
