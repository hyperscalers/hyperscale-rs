//! Transaction fetch binding.
//!
//! The [`FetchBinding`] impl for the per-block transaction payload. Its
//! `fetch_mut` resolves the `Fetch` instance out of this shard's
//! [`MempoolState`](super::MempoolState). The generic engine, the
//! `FetchBinding` trait, and the shared `partition_solicited` helper live in
//! [`crate::fetch`].

use crossbeam::channel::Sender;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::GetTransactionsRequest;
use hyperscale_types::{MessageClass, ShardId, TxHash, ValidatorId};

use crate::fetch::{Fetch, FetchBinding, partition_solicited};
use crate::shard::ShardIo;
use crate::shard_loop::{HostEvent, ShardScopedInput, push_shard_input};

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;

/// Marker type for the per-block transaction fetch.
pub struct TransactionBinding;

impl FetchBinding for TransactionBinding {
    type Id = TxHash;

    const NAME: &'static str = "transaction";

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<TxHash> {
        &mut shard.mempool.transaction
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<TxHash>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            shard,
            preferred,
            GetTransactionsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.into_transactions(), &hs, |tx| tx.hash());
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
                            ShardScopedInput::TransactionsFetchFailed {
                                hashes: split.missing.clone(),
                            },
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
                } else {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::TransactionsFetchFailed { hashes: hs },
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}
