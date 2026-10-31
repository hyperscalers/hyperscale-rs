//! Inbound transaction-fetch request handling.

use hyperscale_mempool::TxStore;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetTransactionsRequest;
use hyperscale_types::network::response::GetTransactionsResponse;
use hyperscale_types::{MAX_FETCH_RESPONSE_BYTES, MAX_TXS_PER_BLOCK, Transaction, Verified};
use tracing::{debug, trace};

use crate::serve::Answer;

/// The prefix of `found` an answer to an ask of `asked` carries.
///
/// Cut by bytes as well as by count, because the requester asks by hash
/// and cannot know what it asked for weighs: fifty maximal envelopes
/// would overrun the frame however few they are. What is cut is simply
/// not answered, and the requester asks for it again.
fn answer_of(asked: usize, found: Vec<Transaction>) -> Answer<Transaction, MAX_TXS_PER_BLOCK> {
    let mut answer = Answer::of(asked).within(MAX_FETCH_RESPONSE_BYTES);
    answer.offer_all(found, |tx| tx.serialized_bytes().len());
    answer
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

    let mut found: Vec<Transaction> = Vec::with_capacity(requested_count);
    let mut missing = Vec::new();
    for hash in req.tx_hashes.iter() {
        if let Some(tx) = tx_store.get(hash) {
            found.push(tx.into_inner());
        } else {
            missing.push(*hash);
        }
    }
    if !missing.is_empty() {
        found.extend(
            pending_chain
                .transactions_batch(&missing)
                .into_iter()
                .map(Verified::into_inner),
        );
    }

    let kept = answer_of(requested_count, found).finish();
    debug!(
        requested = requested_count,
        found = kept.len(),
        "Responding to transaction fetch request"
    );
    GetTransactionsResponse::new(kept)
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::{
        MAX_ARTIFACT_BYTES, MAX_WIRE_MESSAGE_BYTES, PrincipalAddr, Terms, TransactionEnvelope,
    };

    use super::*;

    /// A transaction whose body is at the wire cap: a publish carrying
    /// the largest artifact an envelope admits.
    fn maximal(seed: u8) -> Transaction {
        Transaction::new(TransactionEnvelope {
            tree: Bytes::from_array([seed]),
            terms: Terms {
                fee_payer: PrincipalAddr::new([seed; 31]),
                max_fee: 0,
                gas_limits: Capped::empty(),
                priority_bp: 0,
                message: Bytes::empty(),
            },
            artifact: Some(vec![seed; MAX_ARTIFACT_BYTES].try_into().unwrap()),
            signatures: Capped::empty(),
        })
    }

    /// Fifty maximal transactions do not fit one response: the budget
    /// cuts the list at a prefix that encodes under the frame, and what
    /// is cut is left for the next request rather than dropped with the
    /// whole message.
    #[test]
    fn a_response_is_cut_at_the_byte_budget() {
        let found: Vec<Transaction> = (0..50u8).map(maximal).collect();
        let kept = answer_of(found.len(), found.clone()).finish();
        assert!(
            kept.len() < found.len(),
            "fifty maximal envelopes overrun the budget"
        );
        assert!(!kept.is_empty());
        let bytes: usize = kept.iter().map(|tx| tx.serialized_bytes().len()).sum();
        assert!(bytes <= MAX_FETCH_RESPONSE_BYTES);
        assert!(bytes < MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(
            kept.iter().map(Transaction::hash).collect::<Vec<_>>(),
            found[..kept.len()]
                .iter()
                .map(Transaction::hash)
                .collect::<Vec<_>>(),
            "the prefix is kept in the order asked"
        );
        // Under the budget, everything asked for is answered.
        assert_eq!(answer_of(3, found[..3].to_vec()).finish().len(), 3);
    }
}
