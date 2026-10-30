//! Inbound local-provision fetch request handling.

use std::sync::Arc;

use hyperscale_provisions::{ProvisionStore, VerifiedHeaderBuffer};
use hyperscale_types::network::request::GetLocalProvisionsRequest;
use hyperscale_types::network::response::{GetLocalProvisionsResponse, LocalProvisionEntry};

use crate::serve::Answer;

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
    let mut entries = Answer::of(req.batch_hashes.len());
    for h in &req.batch_hashes {
        let Some(provisions) = provision_store.get(*h) else {
            continue;
        };
        // The buffer holds Verified handles; the wire form takes raw
        // `Arc<CertifiedBlockHeader>`, so materialize the inner header
        // for ship.
        let source_header = verified_headers
            .get((provisions.source_shard(), provisions.block_height()))
            .map(|v| Arc::new(v.as_ref().clone().into_inner()));
        let entry = LocalProvisionEntry {
            provisions,
            source_header,
        };
        if entries.offer(entry, 0).is_break() {
            break;
        }
    }
    GetLocalProvisionsResponse::new(entries.finish())
}
