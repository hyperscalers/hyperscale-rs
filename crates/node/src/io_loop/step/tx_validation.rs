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
//!
//! Batch dispatch lives in [`super::super::batches`].

use crate::io_loop::IoLoop;
use hyperscale_core::{NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::Engine;
use hyperscale_messages::TransactionGossip;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{RoutableTransaction, ShardGroupId, TxHash};
use std::sync::Arc;

impl<S, N, D, E> IoLoop<S, N, D, E>
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
    pub(in crate::io_loop) fn handle_transaction_validated(
        &mut self,
        tx: Arc<RoutableTransaction>,
    ) {
        let tx_hash = tx.hash();
        self.pending_validation.remove(&tx_hash);
        let submitted_locally = self.locally_submitted.remove(&tx_hash);
        self.actions_generated = 0;
        self.feed_event(ProtocolEvent::TransactionValidated {
            tx,
            submitted_locally,
        });
    }

    /// Validation failed — drop tracking entries so the tx can be
    /// re-validated if it shows up again.
    pub(in crate::io_loop) fn handle_transaction_validations_failed(&mut self, hashes: &[TxHash]) {
        for hash in hashes {
            self.pending_validation.remove(hash);
            self.locally_submitted.remove(hash);
        }
    }

    /// Intercept a gossip-received transaction before it reaches the state
    /// machine: queue for batched async validation if we don't already
    /// have it cached and it isn't tombstoned by mempool.
    pub(in crate::io_loop) fn handle_gossip_received_tx_for_validation(
        &mut self,
        tx: Arc<RoutableTransaction>,
    ) {
        let tx_hash = tx.hash();
        // Already-vouched (in TxStore) or terminally-rejected (tombstoned)
        // are skipped. `pending_validation` blocks duplicate enqueues.
        if !self.caches.tx_store.contains(&tx_hash) && !self.state.mempool().is_tombstoned(&tx_hash)
        {
            self.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    /// Locally-submitted transaction (RPC/sim): broadcast to all relevant
    /// shards (reads + writes) and queue for validation if not already
    /// in flight or cached.
    pub(in crate::io_loop) fn handle_submit_transaction(&mut self, tx: Arc<RoutableTransaction>) {
        let tx_hash = tx.hash();

        // Gossip to all relevant shards (reads + writes).
        let shards: std::collections::BTreeSet<ShardGroupId> = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .map(|node_id| hyperscale_types::shard_for_node(node_id, self.num_shards))
            .collect();
        for shard in shards {
            let gossip = TransactionGossip::from_arc(Arc::clone(&tx));
            self.network.broadcast_to_shard(shard, &gossip);
        }

        if !self.pending_validation.contains(&tx_hash) && !self.caches.tx_store.contains(&tx_hash) {
            // Paired with validation: only queued txs are removed on completion.
            self.locally_submitted.insert(tx_hash);
            self.pending_validation.insert(tx_hash);
            self.queue_validation(tx);
        }
    }

    // ─── Validation batching ────────────────────────────────────────────

    /// Queue a transaction for batch validation.
    pub(in crate::io_loop) fn queue_validation(&mut self, tx: Arc<RoutableTransaction>) {
        if self.validation_batch.push(tx, self.state.now()) {
            self.flush_validation_batch();
        }
    }

    /// Flush the validation batch, dispatching to the `tx_validation` pool.
    ///
    /// Valid transactions are sent back as `TransactionValidated` events
    /// through the event channel; failures land as `TransactionValidationsFailed`.
    pub(in crate::io_loop) fn flush_validation_batch(&mut self) {
        let batch = self.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let validator = self.tx_validator.clone();
        let event_tx = self.event_sender.clone();
        self.dispatch.spawn(DispatchPool::TxValidation, move || {
            let results: Vec<bool> = batch
                .iter()
                .map(|tx| validator.validate_transaction(tx).is_ok())
                .collect();

            let mut failed_hashes = Vec::new();
            for (tx, valid) in batch.into_iter().zip(results) {
                if valid {
                    let _ = event_tx.send(NodeInput::TransactionValidated { tx });
                } else {
                    failed_hashes.push(tx.hash());
                }
            }
            if !failed_hashes.is_empty() {
                let _ = event_tx.send(NodeInput::TransactionValidationsFailed {
                    hashes: failed_hashes,
                });
            }
        });
    }
}
