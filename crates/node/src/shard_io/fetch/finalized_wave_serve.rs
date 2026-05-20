//! Inbound finalized-wave fetch request handling.

use std::sync::Arc;

use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::network::request::GetFinalizedWavesRequest;
use hyperscale_types::network::response::GetFinalizedWavesResponse;
use hyperscale_types::{FinalizedWave, WaveId};
use quick_cache::sync::Cache as QuickCache;

/// Serve an inbound finalized-wave fetch request.
///
/// Two tiers: an in-memory `Arc<FinalizedWave>` cache (entries live here
/// between EC aggregation and the wave's containing block committing) and
/// chain storage via [`PendingChain`]. Storage holds `WaveCertificate`s
/// and per-tx receipts separately; for any wave missed by the cache, we
/// reconstruct the full `FinalizedWave` by pulling the certificate +
/// receipts. Peers requesting waves past the cache window must still get a
/// complete answer from durable storage.
pub fn serve_finalized_waves_request<S: Storage>(
    pending_chain: &PendingChain<S>,
    fw_cache: &QuickCache<WaveId, Arc<FinalizedWave>>,
    req: &GetFinalizedWavesRequest,
) -> GetFinalizedWavesResponse {
    let mut waves: Vec<Arc<FinalizedWave>> = Vec::new();
    let mut missing: Vec<WaveId> = Vec::new();
    for id in &req.wave_ids {
        if let Some(fw) = fw_cache.get(id) {
            waves.push(fw);
        } else {
            missing.push(id.clone());
        }
    }

    if !missing.is_empty() {
        let certs = pending_chain.certificates_batch(&missing);
        for cert in certs {
            if let Some(fw) =
                FinalizedWave::reconstruct(Arc::new(cert), |h| pending_chain.consensus_receipt(h))
            {
                waves.push(Arc::new(fw));
            }
        }
    }

    GetFinalizedWavesResponse::new(waves)
}
