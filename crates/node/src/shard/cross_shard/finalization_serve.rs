//! Inbound finalization fetch request handling.

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetFinalizationsRequest;
use hyperscale_types::network::response::GetFinalizationsResponse;
use hyperscale_types::{Finalization, FinalizationHash, Verifiable};
use quick_cache::sync::Cache as QuickCache;

/// Serve an inbound finalization fetch request.
///
/// Two tiers: an in-memory cache (entries live here between EC aggregation
/// and its containing block committing) and chain storage via
/// [`PendingChain`]. Storage holds attestations and per-tx receipts
/// separately; for anything missed by the cache, we reconstruct the full
/// `Finalization` by pulling both halves. Peers requesting
/// finalizations past the cache window must still get a complete answer from
/// durable storage.
///
/// The wire response carries raw `Arc<Finalization>` bodies — the
/// verification marker is process-local and doesn't cross the network.
pub fn serve_finalizations_request<S: ShardStorage>(
    pending_chain: &PendingChain<S>,
    fw_cache: &QuickCache<FinalizationHash, Arc<Verifiable<Finalization>>>,
    req: &GetFinalizationsRequest,
) -> GetFinalizationsResponse {
    // One finalization per hash asked, so the answer meets the cap the
    // request already met; one past it is simply absent, which is what a
    // partial answer already means here.
    let mut finalizations = Capped::empty();
    let mut missing: Vec<FinalizationHash> = Vec::new();
    for id in &req.finalization_hashes {
        if let Some(fw) = fw_cache.get(id) {
            if finalizations
                .push(Arc::new(fw.as_unverified().clone()))
                .is_err()
            {
                break;
            }
        } else {
            missing.push(*id);
        }
    }

    if !missing.is_empty() {
        let certs = pending_chain.certificates_batch(&missing);
        for cert in certs {
            if let Some(fw) =
                Finalization::reconstruct(cert, |h| pending_chain.consensus_receipt(h))
                && finalizations.push(Arc::new(fw)).is_err()
            {
                break;
            }
        }
    }

    record_fetch_response_sent("finalization", finalizations.len());
    GetFinalizationsResponse::new(finalizations)
}
