//! Inbound transaction-fetch request handling.

use hyperscale_messages::request::GetTransactionsRequest;
use hyperscale_messages::response::GetTransactionsResponse;
use hyperscale_metrics as metrics;
use hyperscale_storage::ChainReader;
use hyperscale_types::{RoutableTransaction, TxHash};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use tracing::{debug, trace};

/// Maximum items returned in a single transaction fetch response.
const MAX_ITEMS_PER_RESPONSE: usize = 500;

/// Serve an inbound transaction fetch request.
///
/// Checks the in-memory cache first (for recently received but not yet
/// committed transactions), then falls back to storage.
pub fn serve_transaction_request(
    storage: &impl ChainReader,
    tx_cache: &QuickCache<TxHash, Arc<RoutableTransaction>>,
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
        if let Some(tx) = tx_cache.get(hash) {
            found.push(tx);
        } else {
            missing.push(*hash);
        }
    }
    if !missing.is_empty() {
        found.extend(
            storage
                .get_transactions_batch(&missing)
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
    metrics::record_fetch_response_sent("transaction", found_count);
    GetTransactionsResponse::new(found)
}
