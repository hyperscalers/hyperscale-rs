//! Inbound block-sync request handling.
//!
//! Serves `GetBlockRequest`s from peers catching up via the sync protocol.
//! Reads the block through `PendingChain` so BFT-committed-but-unpersisted
//! heights are served from memory — those blocks are already in their
//! `Block::Live` shape with provisions inline, so no cache lookup is
//! needed. Persisted blocks come back `Block::Sealed`; if the dedup
//! horizon still binds, we re-attach provisions from the local cache, and
//! a miss is reported as `not_found` so the requester rotates to a peer
//! that has them.

use std::sync::Arc;

use hyperscale_metrics::record_sync_response_error;
use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::{BlockForSync, PendingChain, Storage};
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{ElidedCertifiedBlock, ProvisionHash, Provisions, RETENTION_HORIZON};
use tracing::{trace, warn};

/// Serve an inbound block sync request.
///
/// Whether the requester needs `Block::Live` is a function of the block's
/// own age against the dedup horizon: until `block_ts + RETENTION_HORIZON`
/// passes, every honest validator still keeps the block's provision hashes
/// in its `CommitDedupIndex`, so a peer that commits this block via sync
/// must learn those hashes too. Past the horizon, the dedup entries are
/// gone everywhere and the `Sealed` block is safe to serve.
///
/// The horizon check is based on the BFT-authenticated
/// `weighted_timestamp` of the committing QC and the serving peer's own
/// latest QC timestamp — both quantities are deterministic and don't
/// depend on the requester's view.
///
/// Inside the horizon for a `Sealed` block, a local cache miss returns
/// `not_found`. The invariant downstream commit hooks rely on —
/// `Block::Sealed` means no provision hashes remain load-bearing for
/// dedup — is preserved by refusing rather than silently downgrading the
/// response. The requester rotates to another peer who has the provisions
/// cached. Pending-window blocks never hit this path because their
/// provisions are inline.
pub fn serve_block_request<S: Storage>(
    pending_chain: &PendingChain<S>,
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
    }) = pending_chain.block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    let block_ts = qc.weighted_timestamp();
    let tip_ts = pending_chain
        .latest_qc()
        .map_or(block_ts, |q| q.weighted_timestamp());
    let inside_dedup_horizon = tip_ts.elapsed_since(block_ts) < RETENTION_HORIZON;

    if !inside_dedup_horizon {
        // Past the execution window — provisions are no longer load-bearing
        // for dedup or for executor wave state, so serve whatever shape we
        // already have. The receiver will commit `Sealed` and skip
        // execution; that's the correct outcome at this point.
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    // Pending-window blocks are already Live with provisions inline; no
    // cache round-trip needed. Persisted blocks come back Sealed and need
    // the upgrade even when the block consumed no provisions — the
    // variant tag itself is load-bearing on the requester so its commit
    // path runs the execution wave through `on_live_block_committed`.
    if block.is_live() {
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    let resolved: Vec<(ProvisionHash, Option<Arc<Provisions>>)> = provision_hashes
        .iter()
        .map(|h| (*h, provision_store.get(*h)))
        .collect();

    let missing: Vec<ProvisionHash> = resolved
        .iter()
        .filter_map(|(h, p)| p.is_none().then_some(*h))
        .collect();

    if !missing.is_empty() {
        warn!(
            height = req.height.inner(),
            requested = provision_hashes.len(),
            missing_count = missing.len(),
            missing = ?missing,
            "Cache miss for provisions inside dedup horizon — returning not_found so requester rotates"
        );
        record_sync_response_error("block", "provision_cache_miss");
        return GetBlockResponse::not_found();
    }

    let provisions: Vec<Arc<Provisions>> = resolved
        .into_iter()
        .map(|(_, p)| p.expect("missing entries handled above"))
        .collect();

    GetBlockResponse::found(ElidedCertifiedBlock::elide(
        &block.into_live(Arc::new(provisions.into())),
        qc,
        &req.inventory,
    ))
}
