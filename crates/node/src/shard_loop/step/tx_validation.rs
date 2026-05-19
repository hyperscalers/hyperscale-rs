//! Transaction-validation pipeline step handlers.
//!
//! Four `NodeInput` variants drive the pipeline:
//!
//! - `TransactionGossipReceived` — raw gossip arrival; queue for batched
//!   validation if not already cached/tombstoned. Never reaches the state
//!   machine.
//! - `SubmitTransaction` — locally-submitted tx: gossip to relevant shards,
//!   then queue for validation if needed;
//! - `TransactionValidated` — async-validation success: resolve
//!   locally-submitted from the tracking set, feed
//!   `ProtocolEvent::TransactionValidated` to state-machine admission;
//! - `TransactionValidationsFailed` — async-validation failure: clean up
//!   tracking sets so the tx can be re-validated later.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::{RoutableTransaction, ShardGroupId, TxHash, shard_for_node};

use crate::batch_accumulator::BatchAccumulator;
use crate::host::NodeHost;
use crate::shard_loop::{ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D, E> ShardLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
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
        tx: Arc<RoutableTransaction>,
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
            && !self.vnode(0).state.mempool().is_tombstoned(&tx_hash)
        {
            self.io.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Append a tx to the destination shard's outbound gossip
    /// accumulator on this shard, flushing immediately if the count cap
    /// is hit. Time-based flushes happen via
    /// [`NodeHost::flush_expired_batches`]. The accumulator lives on the
    /// "source" `ShardLoop` (this one) — when the gossip flushes it
    /// publishes to the destination shard's topic.
    pub(in crate::shard_loop) fn enqueue_tx_for_gossip(
        &mut self,
        dst: ShardGroupId,
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
    pub(crate) fn flush_tx_gossip_batch(&mut self, dst: ShardGroupId) {
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
        let event_tx = self.process.event_sender.clone();
        let local_shard = self.shard;
        self.process
            .dispatch
            .spawn(DispatchPool::TxValidation, move || {
                let results: Vec<bool> = batch
                    .iter()
                    .map(|tx| validator.validate_transaction(tx).is_ok())
                    .collect();

                let mut failed_hashes = Vec::new();
                for (tx, valid) in batch.into_iter().zip(results) {
                    if valid {
                        push_shard_input(
                            &event_tx,
                            local_shard,
                            ShardScopedInput::TransactionValidated { tx },
                        );
                    } else {
                        failed_hashes.push(tx.hash());
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

impl<S, N, D, E> NodeHost<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Locally-submitted transaction (RPC/sim): enqueue into outbound
    /// gossip accumulators for every shard the tx touches, and admit
    /// locally on every hosted shard the tx touches.
    ///
    /// A tx may admit on multiple hosted shards (e.g. reading shard A
    /// and writing shard B on a host that carries vnodes in both).
    /// Gossip uses the first hosted shard as the "from" for batching —
    /// gossipsub dedup handles any incidental duplication on the wire.
    pub(crate) fn handle_submit_transaction(&mut self, tx: &Arc<RoutableTransaction>) {
        let tx_hash = tx.hash();

        let num_shards = self.process.topology_snapshot.load().num_shards();
        let touched_shards: std::collections::BTreeSet<ShardGroupId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|node_id| shard_for_node(node_id, num_shards))
            .collect();

        // Admit locally on every hosted shard the tx touches.
        let hosted_touched: Vec<ShardGroupId> = self
            .hosted_shards()
            .filter(|s| touched_shards.contains(s))
            .collect();

        // Pick the first hosted touched shard as the gossip source — its
        // `outbound_gossip_batches` accumulates the broadcast for every
        // destination shard. Falls back to the first hosted shard if none
        // of this tx's touched shards are hosted (rare; tx routed to a
        // shard we don't carry).
        let source_shard = hosted_touched
            .first()
            .copied()
            .or_else(|| self.hosted_shards().next());

        if let Some(source) = source_shard {
            for dst in &touched_shards {
                self.shard_loop_mut(source)
                    .enqueue_tx_for_gossip(*dst, Arc::clone(tx));
            }
        }

        for shard in hosted_touched {
            if !self
                .shard_io_mut(shard)
                .pending_validation
                .contains(&tx_hash)
                && !self.shard_io(shard).caches.tx_store.contains(&tx_hash)
            {
                // Paired with validation: only queued txs are removed on completion.
                self.shard_io_mut(shard).locally_submitted.insert(tx_hash);
                self.shard_io_mut(shard).pending_validation.insert(tx_hash);
                self.shard_loop_mut(shard).queue_validation(Arc::clone(tx));
            }
        }
    }
}
