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

mod fetch;
mod serve;
mod validation;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub use fetch::{TransactionBinding, TransactionFetch};
use hyperscale_types::{RoutableTransaction, ShardId, TxHash};
pub use serve::serve_transaction_request;

use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;

/// Per-shard mempool subsystem state.
///
/// Composed into [`ShardIo`](crate::shard::ShardIo).
pub struct MempoolState {
    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub transaction: TransactionFetch,

    /// Hashes currently in the validation pipeline — either sitting in
    /// `validation_batch` or being verified off-thread. Acts as a
    /// dedup guard so duplicate gossip / re-submits don't enqueue
    /// twice. Entries are removed by `TransactionValidated` /
    /// `TransactionValidationsFailed` handlers.
    pub pending_validation: HashSet<TxHash>,

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
    pub locally_submitted: HashSet<TxHash>,

    /// Pending transactions awaiting batched signature / format /
    /// declared-shard verification on the `tx_validation` pool.
    pub validation_batch: BatchAccumulator<Arc<RoutableTransaction>>,

    /// Per-destination-shard outbound `TransactionGossip` accumulators.
    /// This shard acts as the "source" — locally-submitted or validated
    /// transactions are appended here keyed by destination, each batch
    /// fills until its count cap or time window expires, then flushes
    /// as a single batched gossip message published to the destination
    /// shard's topic.
    pub outbound_gossip_batches: BTreeMap<ShardId, BatchAccumulator<Arc<RoutableTransaction>>>,

    /// Size cap for new tx-gossip accumulators.
    pub tx_gossip_max: usize,

    /// Time window for new tx-gossip accumulators.
    pub tx_gossip_window: Duration,
}

impl MempoolState {
    /// Build mempool state for a freshly hosted shard.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        let b = &config.batch;
        Self {
            transaction: TransactionFetch::new("transaction", config.transaction_fetch.clone()),
            pending_validation: HashSet::new(),
            locally_submitted: HashSet::new(),
            validation_batch: BatchAccumulator::new(b.tx_validation_max, b.tx_validation_window),
            outbound_gossip_batches: BTreeMap::new(),
            tx_gossip_max: b.tx_gossip_max,
            tx_gossip_window: b.tx_gossip_window,
        }
    }

    /// True if the transaction fetch has work outstanding (in-flight or
    /// queued) — keeps this shard's `FetchTick` alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.transaction.has_pending()
    }
}
