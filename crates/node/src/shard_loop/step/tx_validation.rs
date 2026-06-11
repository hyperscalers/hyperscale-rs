//! Transaction-validation pipeline step handlers.
//!
//! Five `NodeInput` variants drive the pipeline:
//!
//! - `TransactionGossipReceived` — raw gossip arrival; queue for batched
//!   validation if not already cached/tombstoned. Never reaches the state
//!   machine.
//! - `TransactionsFetched` — raw fetch-response delivery; drive the
//!   fetch-FSM drain for every delivered hash, dispatch the batch for
//!   validation, then surface the valid subset as
//!   `ProtocolEvent::TransactionsReceived`.
//! - `SubmitTransaction` — locally-submitted tx: gossip to relevant shards,
//!   then queue for validation if needed;
//! - `TransactionValidated` — async-validation success: resolve
//!   locally-submitted from the tracking set, feed
//!   `ProtocolEvent::TransactionValidated` to state-machine admission;
//! - `TransactionValidationsFailed` — async-validation failure: clean up
//!   tracking sets so the tx can be re-validated later.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::{RoutableTransaction, ShardId, TxHash, Verified};

use crate::batch_accumulator::BatchAccumulator;
use crate::host::NodeHost;
use crate::process_io::SubmitFanout;
use crate::shard_io::fetch::FetchInput;
use crate::shard_io::fetch::binding::TransactionBinding;
use crate::shard_loop::{ShardLoop, ShardScopedInput, push_protocol_event, push_shard_input};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── step() handlers ────────────────────────────────────────────────

    /// Validation succeeded — settle the locally-submitted flag and feed
    /// the tx into the state machine's gossip-admission path. Body
    /// insertion into [`TxStore`] happens inside
    /// [`MempoolCoordinator::on_transaction_gossip`] on successful
    /// admission, not here — we only serve bodies we vouched for.
    ///
    /// [`TxStore`]: hyperscale_mempool::TxStore
    /// [`MempoolCoordinator::on_transaction_gossip`]: hyperscale_mempool::MempoolCoordinator
    pub(in crate::shard_loop) fn handle_transaction_validated(
        &mut self,
        tx: Arc<Verified<RoutableTransaction>>,
    ) {
        let tx_hash = tx.hash();
        self.io.pending_validation.remove(&tx_hash);
        let submitted_locally = self.io.locally_submitted.remove(&tx_hash);
        self.dispatch_event(ProtocolEvent::TransactionValidated {
            tx,
            submitted_locally,
        });
    }

    /// Validation failed — drop tracking entries so the tx can be
    /// re-validated if it shows up again.
    pub(in crate::shard_loop) fn handle_transaction_validations_failed(
        &mut self,
        hashes: &[TxHash],
    ) {
        for hash in hashes {
            self.io.pending_validation.remove(hash);
            self.io.locally_submitted.remove(hash);
        }
    }

    /// Passive co-host admission of a locally-submitted tx: admit to
    /// the validation pipeline if not already pending or cached. Does
    /// NOT mark `locally_submitted` and does NOT enqueue outbound
    /// gossip — both of those are the source shard's role via
    /// [`Self::handle_admit_and_gossip_transaction`]. Co-locating
    /// `locally_submitted` on a single shard per node keeps the
    /// finalization metric from double-counting txs whose touched set
    /// spans multiple hosted shards.
    pub(in crate::shard_loop) fn handle_admit_transaction(&mut self, tx: Arc<RoutableTransaction>) {
        let tx_hash = tx.hash();
        if !self.io.pending_validation.contains(&tx_hash)
            && !self.io.caches.tx_store.contains(&tx_hash)
        {
            self.io.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Source-shard handling for a locally-submitted tx: enqueue
    /// outbound gossip for every destination in `touched_shards`, then
    /// admit locally and mark `locally_submitted` so the resulting
    /// `ProtocolEvent::TransactionValidated` carries the
    /// submitted-locally flag. The source shard owns the
    /// `outbound_gossip_batches` map; one batch per destination shard
    /// (hosted or not) gets the tx appended.
    pub(in crate::shard_loop) fn handle_admit_and_gossip_transaction(
        &mut self,
        tx: Arc<RoutableTransaction>,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, Arc::clone(&tx));
        }
        let tx_hash = tx.hash();
        if !self.io.pending_validation.contains(&tx_hash)
            && !self.io.caches.tx_store.contains(&tx_hash)
        {
            self.io.locally_submitted.insert(tx_hash);
            self.io.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Gossip-only handling for a locally-submitted tx whose touched
    /// shards are all non-hosted on this node: enqueue outbound gossip
    /// for every destination. No admission, no validation, no
    /// `locally_submitted` entry — this shard isn't part of the tx's
    /// touched set and won't see it in mempool.
    pub(in crate::shard_loop) fn handle_gossip_transaction(
        &mut self,
        tx: &Arc<RoutableTransaction>,
        touched_shards: &[ShardId],
    ) {
        for dst in touched_shards {
            self.enqueue_tx_for_gossip(*dst, Arc::clone(tx));
        }
    }

    /// Intercept a gossip-received transaction before it reaches the state
    /// machine: queue for batched async validation if we don't already
    /// have it cached and it isn't tombstoned by mempool.
    pub(in crate::shard_loop) fn handle_gossip_received_tx_for_validation(
        &mut self,
        tx: Arc<RoutableTransaction>,
    ) {
        let tx_hash = tx.hash();
        // Already-vouched (in TxStore) or terminally-rejected (tombstoned)
        // are skipped. `pending_validation` blocks duplicate enqueues.
        // Tombstones are identical across same-shard vnodes (deterministic
        // mempool processing) — peek at vnode 0's set as representative.
        if !self.io.caches.tx_store.contains(&tx_hash)
            && !self
                .vnode(0)
                .state
                .mempool_coordinator()
                .is_tombstoned(&tx_hash)
        {
            self.io.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Intercept a fetch-delivered batch before it reaches the state
    /// machine. Drives the fetch-FSM drain for every delivered hash
    /// (releases in-flight slots regardless of validation outcome,
    /// so an invalid-signature payload can't pin a slot) and dispatches
    /// the batch for async validation. The valid subset surfaces as
    /// `ProtocolEvent::TransactionsReceived`; invalid hashes surface as
    /// `ShardScopedInput::TransactionValidationsFailed`, mirroring the
    /// gossip-path tracking-set cleanup.
    pub(in crate::shard_loop) fn handle_fetched_txs_for_validation(
        &mut self,
        batch: Vec<Arc<RoutableTransaction>>,
    ) {
        if batch.is_empty() {
            return;
        }

        // Each shard's fetch responses decode fresh instances;
        // canonicalizing lets co-hosted shards share one validation
        // verdict.
        let batch: Vec<Arc<RoutableTransaction>> = batch
            .into_iter()
            .map(|tx| self.process.canonical_txs.canonicalize(&tx))
            .collect();

        let delivered_ids: Vec<TxHash> = batch.iter().map(|tx| tx.hash()).collect();
        self.drive_fetch::<TransactionBinding>(FetchInput::Admitted { ids: delivered_ids });

        let validator = self.process.tx_validator.clone();
        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        let par: Parallelism = self.process.dispatch.parallelism();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let results: Vec<(TxHash, Option<Verified<RoutableTransaction>>)> =
                    par.map(batch, |tx| {
                        let hash = tx.hash();
                        (hash, validator.verify_transaction(&tx).ok())
                    });

                let mut valid: Vec<Arc<Verified<RoutableTransaction>>> = Vec::new();
                let mut failed_hashes = Vec::new();
                for (hash, verified) in results {
                    if let Some(v) = verified {
                        valid.push(Arc::new(v));
                    } else {
                        failed_hashes.push(hash);
                    }
                }

                if !valid.is_empty() {
                    push_protocol_event(
                        &event_tx,
                        local_shard,
                        ProtocolEvent::TransactionsReceived {
                            transactions: valid,
                        },
                    );
                }
                if !failed_hashes.is_empty() {
                    push_shard_input(
                        &event_tx,
                        local_shard,
                        ShardScopedInput::TransactionValidationsFailed {
                            hashes: failed_hashes,
                        },
                    );
                }
            });
    }

    /// Append a tx to the destination shard's outbound gossip
    /// accumulator on this shard, flushing immediately if the count cap
    /// is hit. Time-based flushes happen via
    /// [`NodeHost::flush_expired_batches`]. The accumulator lives on the
    /// "source" `ShardLoop` (this one) — when the gossip flushes it
    /// publishes to the destination shard's topic.
    pub(in crate::shard_loop) fn enqueue_tx_for_gossip(
        &mut self,
        dst: ShardId,
        tx: Arc<RoutableTransaction>,
    ) {
        let now = self.now;
        let max = self.tx_gossip_max;
        let window = self.tx_gossip_window;
        let batch = self
            .outbound_gossip_batches
            .entry(dst)
            .or_insert_with(|| BatchAccumulator::new(max, window));
        if batch.push(tx, now) {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Drain this shard's outbound gossip accumulator for destination
    /// shard `dst` and publish it as a single `TransactionGossip` batch.
    /// No-op if empty.
    pub(crate) fn flush_tx_gossip_batch(&mut self, dst: ShardId) {
        let Some(batch) = self.outbound_gossip_batches.get_mut(&dst) else {
            return;
        };
        let txs = batch.take();
        if txs.is_empty() {
            return;
        }
        let gossip = TransactionGossip::new(txs);
        self.process.network.broadcast_to_shard(dst, &gossip);
    }

    // ─── Validation batching ────────────────────────────────────────────

    /// Queue a transaction for batch validation on this shard.
    pub(in crate::shard_loop) fn queue_validation(&mut self, tx: Arc<RoutableTransaction>) {
        let now = self.now;
        if self.io.validation_batch.push(tx, now) {
            self.flush_validation_batch();
        }
    }

    /// Flush this shard's validation batch, dispatching to the
    /// `tx_validation` pool.
    ///
    /// Valid transactions are sent back as `TransactionValidated` events
    /// through the event channel; failures land as
    /// `TransactionValidationsFailed` so the shard can clean up
    /// `pending_validation` / `locally_submitted`.
    pub(crate) fn flush_validation_batch(&mut self) {
        let batch = self.io.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let validator = self.process.tx_validator.clone();
        let event_tx = self.event_sender().clone();
        let local_shard = self.shard;
        let par: Parallelism = self.process.dispatch.parallelism();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let results: Vec<(TxHash, Option<Verified<RoutableTransaction>>)> =
                    par.map(batch, |tx| {
                        let hash = tx.hash();
                        (hash, validator.verify_transaction(&tx).ok())
                    });

                let mut failed_hashes = Vec::new();
                for (hash, verified) in results {
                    if let Some(v) = verified {
                        push_shard_input(
                            &event_tx,
                            local_shard,
                            ShardScopedInput::TransactionValidated { tx: Arc::new(v) },
                        );
                    } else {
                        failed_hashes.push(hash);
                    }
                }
                if !failed_hashes.is_empty() {
                    push_shard_input(
                        &event_tx,
                        local_shard,
                        ShardScopedInput::TransactionValidationsFailed {
                            hashes: failed_hashes,
                        },
                    );
                }
            });
    }
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Locally-submitted transaction (sim): compute the routing decision
    /// via [`ProcessIo::compute_submit_fanout`] and apply it synchronously
    /// — each affected hosted shard's `step()` runs in this call frame.
    ///
    /// Production's RPC ingestion thread reuses
    /// [`ProcessIo::compute_submit_fanout`] but applies the decision via
    /// `process.shard_event_senders` so cross-thread fan-out doesn't
    /// require a `&mut NodeHost`.
    ///
    /// [`ProcessIo::compute_submit_fanout`]: crate::process_io::ProcessIo::compute_submit_fanout
    pub(crate) fn handle_submit_transaction(&mut self, tx: &Arc<RoutableTransaction>) {
        // Seed the canonical-instance cache so gossip echoes of this tx
        // arriving on other hosted shards' topics share its validation
        // verdict.
        let tx = &self.process.canonical_txs.canonicalize(tx);
        match self.process.compute_submit_fanout(tx) {
            SubmitFanout::Admit {
                source,
                passive,
                touched_shards,
            } => {
                self.shard_loop_mut(source)
                    .step(ShardScopedInput::AdmitAndGossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    });
                for shard in passive {
                    self.shard_loop_mut(shard)
                        .step(ShardScopedInput::AdmitTransaction { tx: Arc::clone(tx) });
                }
            }
            SubmitFanout::GossipOnly {
                host,
                touched_shards,
            } => {
                self.shard_loop_mut(host)
                    .step(ShardScopedInput::GossipTransaction {
                        tx: Arc::clone(tx),
                        touched_shards,
                    });
            }
        }
    }
}
