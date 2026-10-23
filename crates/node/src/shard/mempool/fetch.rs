//! Transaction fetch binding.
//!
//! The [`FetchBinding`] impl for the per-block transaction payload. Its
//! `fetch_mut` resolves the `Fetch` instance out of this shard's
//! [`MempoolState`](super::MempoolState). The generic engine, the
//! `FetchBinding` trait, and the shared `partition_solicited` helper live in
//! [`crate::fetch`].

use hyperscale_core::FetchIds;
use hyperscale_hbor::Capped;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::TxHash;
use hyperscale_types::network::request::GetTransactionsRequest;

use crate::fetch::{
    Fetch, FetchBinding, FetchedBy, Route, ShardReply, failed_chunk, partition_solicited,
};
use crate::shard::{ShardIo, ShardScopedInput, push_shard_input};

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;

/// Marker type for the per-block transaction fetch.
pub struct TransactionBinding;

impl FetchBinding for TransactionBinding {
    type Id = TxHash;

    const NAME: &'static str = "transaction";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Transactions(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for TransactionBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<TxHash> {
        &mut shard.mempool.transaction
    }

    fn dispatch_chunk<N: Network>(ids: Vec<TxHash>, route: Route, network: &N, reply: &ShardReply) {
        let local_shard = reply.shard;
        let sender = &reply.sender;
        let es = sender.clone();
        let hs = ids.clone();
        route.request(
            network,
            GetTransactionsRequest::new(
                Capped::new(ids).expect("the fetch config clamps a chunk below the wire cap"),
            ),
            Box::new(move |result| {
                let resp = match result {
                    Ok(resp) => resp,
                    Err(error) => {
                        push_shard_input(&es, local_shard, failed_chunk(&error, Self::ids(hs)));
                        return ResponseVerdict::Accept;
                    }
                };
                let split = partition_solicited(resp.into_transactions(), &hs, |tx| [tx.hash()]);
                if !split.kept.is_empty() {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::TransactionsFetched { batch: split.kept },
                    );
                }
                if !split.missing.is_empty() {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::FetchFailed(Self::ids(split.missing.clone())),
                    );
                }
                // Reject the response if the peer shipped unsolicited
                // txs (injection attempt or buggy peer) OR if any
                // requested hash was missing from the delivery.
                if split.unsolicited > 0 || !split.missing.is_empty() {
                    ResponseVerdict::Reject
                } else {
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}
