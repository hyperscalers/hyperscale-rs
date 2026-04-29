//! Inbound block-sync request handling.
//!
//! Serves `GetBlockRequest`s from peers catching up via the sync protocol.
//! Reads the block from storage and decides whether to attach in-memory
//! provisions (when the block is still inside the wave-execution window)
//! or serve the persisted `Sealed` shape.

use hyperscale_messages::request::GetBlockRequest;
use hyperscale_messages::response::{ElidedCertifiedBlock, GetBlockResponse};
use hyperscale_metrics as metrics;
use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::ChainReader;
use hyperscale_types::{Provisions, WAVE_TIMEOUT};
use std::sync::Arc;
use std::time::Duration;
use tracing::trace;

/// Retention margin beyond `WAVE_TIMEOUT` for the serve decision.
///
/// A block's waves are live for `WAVE_TIMEOUT`; a late-syncing peer still
/// needs a rotation budget to fetch provisions, execute, and vote before
/// its rotation deadline passes. Sized to cover one vote-retry rotation.
const SERVE_MARGIN: Duration = Duration::from_secs(12);
const LIVE_WINDOW: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() + SERVE_MARGIN.as_secs());

/// Serve an inbound block sync request.
///
/// Storage always returns `Block::Sealed` — the persisted shape carries no
/// provisions. Whether the requester needs `Block::Live` is a function of
/// the block's own age: if its waves could still be open for execution
/// voting (`block_ts + WAVE_TIMEOUT + margin > tip_ts`), provisions are
/// attached from the local cache. Otherwise the `Sealed` block is served.
///
/// The wave-window check is based on the BFT-authenticated
/// `weighted_timestamp` of the committing QC and the serving peer's own
/// latest QC timestamp — both quantities are deterministic and don't
/// depend on the requester's view.
///
/// On cache miss inside the live window the block is still served as
/// `Sealed`; the requester fetches missing provisions through the cross-shard
/// provision fetch instead of round-robining peers.
pub fn serve_block_request(
    storage: &impl ChainReader,
    provision_store: &ProvisionStore,
    req: &GetBlockRequest,
) -> GetBlockResponse {
    trace!(
        height = req.height.0,
        target_height = req.target_height.0,
        "Handling block sync request"
    );
    let Some(hyperscale_storage::BlockForSync {
        block,
        qc,
        provision_hashes,
    }) = storage.get_block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    let block_ts = qc.weighted_timestamp;
    let tip_ts = storage
        .latest_qc()
        .map_or(block_ts, |q| q.weighted_timestamp);
    let wave_window_open = tip_ts.elapsed_since(block_ts) < LIVE_WINDOW;

    if !wave_window_open || provision_hashes.is_empty() {
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    let resolved: Option<Vec<Arc<Provisions>>> = provision_hashes
        .iter()
        .map(|h| provision_store.get(h))
        .collect();

    if let Some(provisions) = resolved {
        GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &block.into_live(provisions),
            qc,
            &req.inventory,
        ))
    } else {
        // Cache miss inside the live window. Serve Sealed and let the
        // requester pull provisions via the fetch protocol — avoids
        // the peer-rotation retry storm the old `not_found` path caused
        // when provisions had aged out everywhere.
        trace!(
            height = req.height.0,
            "Cache miss for provisions inside live window — serving sealed"
        );
        metrics::record_sync_response_error("provision_cache_miss");
        GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory))
    }
}
