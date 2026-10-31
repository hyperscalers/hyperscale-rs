//! Transaction fetch binding.
//!
//! The [`FetchBinding`] impl for the per-block transaction payload. Its
//! `fetch_mut` resolves the `Fetch` instance out of this shard's
//! [`MempoolState`](super::MempoolState). The generic engine, the
//! `FetchBinding` trait, and the shared [`SolicitedAnswer`] response
//! boundary live in [`crate::fetch`].

use hyperscale_core::FetchIds;
use hyperscale_hbor::Capped;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::GetTransactionsRequest;
use hyperscale_types::network::response::GetTransactionsResponse;
use hyperscale_types::{Transaction, TxHash};

use crate::event::ShardScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchedBy, Route, Settles, ShardReply, SolicitedAnswer, dispatch_solicited,
};
use crate::shard::ShardIo;

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;

/// Marker type for the per-block transaction fetch.
pub struct TransactionBinding;

impl FetchBinding for TransactionBinding {
    type Id = TxHash;

    const NAME: &'static str = "transaction";

    type Ids = FetchIds;

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Transactions(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for TransactionBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<TxHash> {
        &mut shard.mempool.transaction
    }

    fn dispatch_chunk<N: Network>(ids: Vec<TxHash>, route: Route, network: &N, reply: &ShardReply) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// A transaction is its own hash, so a delivered body is the one asked
/// for and its ids retire as it lands; the bodies then go to validation.
impl SolicitedAnswer for TransactionBinding {
    type Request = GetTransactionsRequest;
    type Item = Transaction;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnAnswer;

    fn request(ids: &[TxHash]) -> GetTransactionsRequest {
        GetTransactionsRequest::new(
            Capped::new(ids.to_vec()).expect("the fetch config clamps a chunk below the wire cap"),
        )
    }

    fn items(response: GetTransactionsResponse) -> Vec<Transaction> {
        response.into_transactions()
    }

    fn answers_for(tx: &Transaction) -> impl IntoIterator<Item = TxHash> + use<> {
        [tx.hash()]
    }

    fn deliver(batch: Vec<Transaction>) -> Vec<ShardScopedInput> {
        vec![ShardScopedInput::TransactionsFetched { batch }]
    }
}
