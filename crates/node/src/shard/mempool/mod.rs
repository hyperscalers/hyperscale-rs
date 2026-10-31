//! Per-shard mempool subsystem.
//!
//! Owns the per-shard state and code for the transaction path a shard
//! drives: fetching missing transaction bodies, serving inbound body
//! requests, the async signature/format validation pipeline, and the
//! outbound tx-gossip routing accumulators.
//!
//! [`MempoolState`] is the per-shard state struct `ShardIo` composes;
//! subsystem-specific FSM instances, bindings, serves, and glue live here
//! beside it. The shared `TxStore` read-handle stays on
//! [`SharedCaches`](crate::shard::caches::SharedCaches) — it is a
//! request-serving cache, cross-cutting and read-only.

mod deferred;
mod transaction_fetch;
mod transaction_serve;
mod validation;

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

pub use deferred::{DeferredForRecords, DeferredTransaction, Orphaned};
use hyperscale_types::network::gossip::MAX_GOSSIP_TX_BATCH;
use hyperscale_types::{ShardId, Transaction, TxHash};
pub use transaction_fetch::{TransactionBinding, TransactionFetch};
pub use transaction_serve::serve_transaction_request;

use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;

/// How an envelope reached this loop's admission, which decides what
/// admission may refuse it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Gossip or a submission: nobody here asked for it. The payer
    /// filters and the pool's ceiling apply, and a refusal costs
    /// nothing, since what a block names is fetched.
    Unbidden,
    /// A fetch answering an id a block or a tick here named. It is chain
    /// content, so neither the payer filters nor the pool's ceiling
    /// refuse it: refusing it would strand what asked.
    Asked,
}

/// Per-shard mempool subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct MempoolState {
    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub(crate) transaction: TransactionFetch,

    /// Hashes currently in the validation pipeline — sitting in
    /// `validation_batch`, being verified off-thread, or held in
    /// `deferred_records`. The dedup guard an unbidden offer checks, so
    /// duplicate gossip and re-submits do not enqueue twice. Entries are
    /// removed when a verdict on the hash comes back.
    pub(crate) pending_validation: HashSet<TxHash>,

    /// Subset of `pending_validation` for which this shard is the
    /// designated source for a locally-submitted tx — i.e. it received
    /// `AdmitAndGossipTransaction`. Carried through validation so the
    /// resulting `TransactionValidated` event flags
    /// `submitted_locally = true` for mempool admission accounting.
    ///
    /// At most one hosted shard per node enters a given tx hash here,
    /// so the finalization metric fires exactly once per node per
    /// locally-submitted tx even when multiple co-hosted shards touch
    /// it. Passive co-hosts admit via `AdmitTransaction` without
    /// inserting; gossip-only hosts via `GossipTransaction` don't
    /// admit at all.
    pub(crate) locally_submitted: HashSet<TxHash>,

    /// Envelopes awaiting batched verification, each beside how it
    /// reached admission.
    pub(crate) validation_batch: BatchAccumulator<(Transaction, Origin)>,

    /// Envelopes this node cannot derive yet, waiting on the component
    /// records a fetch is out for. Entries stay in
    /// `pending_validation` while they wait, so a re-gossip does not
    /// enqueue a second copy.
    pub(crate) deferred_records: DeferredForRecords,

    /// Per-destination-shard outbound `TransactionGossip` accumulators.
    /// This shard acts as the "source" — locally-submitted or validated
    /// transactions are appended here keyed by destination, each batch
    /// fills until its count cap or time window expires, then flushes
    /// as a single batched gossip message published to the destination
    /// shard's topic.
    pub(crate) outbound_gossip_batches: BTreeMap<ShardId, BatchAccumulator<Transaction>>,

    /// Size cap for new tx-gossip accumulators.
    pub(crate) tx_gossip_max: usize,

    /// Time window for new tx-gossip accumulators.
    pub(crate) tx_gossip_window: Duration,
}

impl MempoolState {
    /// Build mempool state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        let b = &config.batch;
        Self {
            transaction: TransactionFetch::new("transaction", config.transaction_fetch.clone()),
            pending_validation: HashSet::new(),
            locally_submitted: HashSet::new(),
            validation_batch: BatchAccumulator::new(b.tx_validation_max, b.tx_validation_window),
            deferred_records: DeferredForRecords::new(),
            outbound_gossip_batches: BTreeMap::new(),
            // The decode-side batch bound is the ceiling a configured
            // flush point cannot pass: a batch past it is one the far
            // end refuses whole.
            tx_gossip_max: b.tx_gossip_max.min(MAX_GOSSIP_TX_BATCH),
            tx_gossip_window: b.tx_gossip_window,
        }
    }

    /// True if the transaction fetch has work outstanding (in-flight or
    /// queued) — keeps this shard's `FetchTick` alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.transaction.has_pending()
    }
}
