//! Inbound block-sync request handling.
//!
//! Serves `GetBlockRequest`s from peers catching up via the sync protocol.
//! Reads the block from storage and either attaches in-memory provisions
//! (when the block is still inside the wave-execution window) or serves
//! the persisted `Sealed` shape. Inside the live window, a local cache
//! miss is reported as `not_found` so the requester rotates to a peer
//! that has the provisions — preserving the invariant that `Block::Sealed`
//! means the cross-shard window has passed.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_metrics::record_sync_response_error;
use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::{BlockForSync, ChainReader};
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{ElidedCertifiedBlock, Provisions, WAVE_TIMEOUT};
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
/// voting (`block_ts + WAVE_TIMEOUT + margin > tip_ts`), provisions must
/// be attached from the local cache. Otherwise the `Sealed` block is
/// served.
///
/// The wave-window check is based on the BFT-authenticated
/// `weighted_timestamp` of the committing QC and the serving peer's own
/// latest QC timestamp — both quantities are deterministic and don't
/// depend on the requester's view.
///
/// Inside the live window, a local cache miss returns `not_found`. The
/// invariant downstream commit hooks rely on — `Block::Sealed` means the
/// cross-shard window has passed and no provision hashes need to be
/// enumerated — is preserved by refusing rather than silently downgrading
/// the response. The requester rotates to another peer who has the
/// provisions cached.
pub fn serve_block_request(
    storage: &impl ChainReader,
    provision_store: &ProvisionStore,
    req: &GetBlockRequest,
) -> GetBlockResponse {
    trace!(
        height = req.height.inner(),
        target_height = req.target_height.inner(),
        "Handling block sync request"
    );
    let Some(BlockForSync {
        block,
        qc,
        provision_hashes,
    }) = storage.get_block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    let block_ts = qc.weighted_timestamp();
    let tip_ts = storage
        .latest_qc()
        .map_or(block_ts, |q| q.weighted_timestamp());
    let wave_window_open = tip_ts.elapsed_since(block_ts) < LIVE_WINDOW;

    if !wave_window_open || provision_hashes.is_empty() {
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    let resolved: Option<Vec<Arc<Provisions>>> = provision_hashes
        .iter()
        .map(|h| provision_store.get(*h))
        .collect();

    let Some(provisions) = resolved else {
        trace!(
            height = req.height.inner(),
            "Cache miss for provisions inside live window — returning not_found so requester rotates"
        );
        record_sync_response_error("block", "provision_cache_miss");
        return GetBlockResponse::not_found();
    };

    GetBlockResponse::found(ElidedCertifiedBlock::elide(
        &block.into_live(Arc::new(provisions.into())),
        qc,
        &req.inventory,
    ))
}
