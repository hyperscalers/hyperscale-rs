//! Inbound transaction-fetch request handling.

use std::sync::Arc;

use hyperscale_mempool::TxStore;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetTransactionsRequest;
use hyperscale_types::network::response::GetTransactionsResponse;
use hyperscale_types::{MAX_FETCH_RESPONSE_BYTES, Transaction};
use tracing::{debug, trace};

/// Maximum items returned in a single transaction fetch response.
const MAX_ITEMS_PER_RESPONSE: usize = 500;

/// The longest prefix of `found` that encodes under the response's byte
/// budget, in the order given.
///
/// A response is chunked by bytes rather than by count, because the
/// requester asks by hash and cannot know what it asked for weighs: fifty
/// maximal envelopes would overrun the frame however few they are. What
/// is cut is simply not answered, and the requester asks for it again.
fn within_byte_budget(found: Vec<Arc<Transaction>>) -> Vec<Arc<Transaction>> {
    let mut bytes = 0usize;
    let mut kept = Vec::with_capacity(found.len());
    for tx in found {
        bytes = bytes.saturating_add(tx.serialized_bytes().len());
        if bytes > MAX_FETCH_RESPONSE_BYTES {
            break;
        }
        kept.push(tx);
    }
    kept
}

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
pub fn serve_transaction_request<S: ShardStorage>(
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

    let mut found: Vec<Arc<Transaction>> = Vec::with_capacity(hashes.len());
    let mut missing = Vec::new();
    for hash in hashes {
        if let Some(tx) = tx_store.get(hash) {
            found.push(Arc::new((**tx).clone()));
        } else {
            missing.push(*hash);
        }
    }
    if !missing.is_empty() {
        found.extend(
            pending_chain
                .transactions_batch(&missing)
                .into_iter()
                .map(|tx| Arc::new(tx.into_inner())),
        );
    }

    let found = within_byte_budget(found);
    let found_count = found.len();
    debug!(
        requested = requested_count,
        found = found_count,
        "Responding to transaction fetch request"
    );
    record_fetch_response_sent("transaction", found_count);
    GetTransactionsResponse::new(found)
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        MAX_ARTIFACT_BYTES, MAX_WIRE_MESSAGE_BYTES, PrincipalAddr, SchemeId, Terms,
        TransactionEnvelope,
    };

    use super::*;

    /// A transaction whose body is at the wire cap: a publish carrying
    /// the largest artifact an envelope admits.
    fn maximal(seed: u8) -> Arc<Transaction> {
        Arc::new(Transaction::new(TransactionEnvelope {
            tree: vec![seed],
            terms: Terms {
                fee_payer: PrincipalAddr::new([seed; 31]),
                max_fee: 0,
                gas_limits: Vec::new(),
                priority_bp: 0,
                message: Vec::new(),
            },
            artifact: Some(vec![seed; MAX_ARTIFACT_BYTES]),
            subintent_sigs: Vec::new(),
            signer_scheme: SchemeId::NONE,
            signer: Vec::new(),
            signature: Vec::new(),
        }))
    }

    /// Fifty maximal transactions do not fit one response: the budget
    /// cuts the list at a prefix that encodes under the frame, and what
    /// is cut is left for the next request rather than dropped with the
    /// whole message.
    #[test]
    fn a_response_is_cut_at_the_byte_budget() {
        let found: Vec<Arc<Transaction>> = (0..50u8).map(maximal).collect();
        let kept = within_byte_budget(found.clone());
        assert!(
            kept.len() < found.len(),
            "fifty maximal envelopes overrun the budget"
        );
        assert!(!kept.is_empty());
        let bytes: usize = kept.iter().map(|tx| tx.serialized_bytes().len()).sum();
        assert!(bytes <= MAX_FETCH_RESPONSE_BYTES);
        assert!(bytes < MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(
            kept.iter().map(|tx| tx.hash()).collect::<Vec<_>>(),
            found[..kept.len()]
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            "the prefix is kept in the order asked"
        );
        // Under the budget, everything asked for is answered.
        assert_eq!(within_byte_budget(found[..3].to_vec()).len(), 3);
    }
}
