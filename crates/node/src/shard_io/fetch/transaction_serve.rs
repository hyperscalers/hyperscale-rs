//! Inbound transaction-fetch request handling.

use std::sync::Arc;

use hyperscale_mempool::TxStore;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::network::request::GetTransactionsRequest;
use hyperscale_types::network::response::GetTransactionsResponse;
use tracing::{debug, trace};

/// Maximum items returned in a single transaction fetch response.
const MAX_ITEMS_PER_RESPONSE: usize = 500;

/// Serve an inbound transaction fetch request.
///
/// Two tiers: the shared [`TxStore`] (transactions we admitted to our own
/// mempool, retained until their tombstone window elapses) and chain
/// storage via [`PendingChain`] (committed transactions). We deliberately
/// do *not* serve transactions we never admitted — if we didn't vouch for
/// it, we're not the right source.
///
/// Intentionally caller-agnostic: the function takes no requester identity
/// and no shard scope. Any peer that knows the tx hash can fetch the body,
/// which is what makes cross-shard data-availability fallback work — when
/// gossip drops a tx whose provisions have already arrived at a remote
/// shard, that shard's mempool fetches by hash from the source committee
/// and this handler answers without distinction. Don't add a peer / shard
/// check here without redesigning the cross-shard DA path.
pub fn serve_transaction_request<S: Storage>(
    pending_chain: &PendingChain<S>,
    tx_store: &TxStore,
    req: &GetTransactionsRequest,
) -> GetTransactionsResponse {
    let requested_count = req.tx_hashes.len();
    trace!(
        tx_count = requested_count,
        "Handling transaction fetch request"
    );

    let hashes = if requested_count > MAX_ITEMS_PER_RESPONSE {
        &req.tx_hashes[..MAX_ITEMS_PER_RESPONSE]
    } else {
        &req.tx_hashes
    };

    let mut found = Vec::with_capacity(hashes.len());
    let mut missing = Vec::new();
    for hash in hashes {
        if let Some(tx) = tx_store.get(hash) {
            found.push(tx);
        } else {
            missing.push(*hash);
        }
    }
    if !missing.is_empty() {
        found.extend(
            pending_chain
                .transactions_batch(&missing)
                .into_iter()
                .map(Arc::new),
        );
    }

    let found_count = found.len();
    debug!(
        requested = requested_count,
        found = found_count,
        "Responding to transaction fetch request"
    );
    record_fetch_response_sent("transaction", found_count);
    GetTransactionsResponse::new(found)
}
