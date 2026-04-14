//! Batch accumulation and flushing for verification and broadcast.

use super::verify::verify_bls_with_metrics;
use super::IoLoop;
use hyperscale_core::{NodeInput, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::RoutableTransaction;
use std::sync::Arc;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: ChainWriter + SubstateStore + ChainReader + Send + Sync,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    // ─── Transaction Validation Batching ──────────────────────────────

    /// Queue a transaction for batch validation.
    pub(super) fn queue_validation(&mut self, tx: Arc<RoutableTransaction>) {
        if self.validation_batch.push(tx, self.state.now()) {
            self.flush_validation_batch();
        }
    }

    /// Flush the validation batch, dispatching to the tx_validation pool.
    ///
    /// Valid transactions are sent back as `TransactionGossipReceived` events
    /// through the event channel. IoLoop recognises them via `pending_validation`
    /// and passes them through to the state machine.
    pub(super) fn flush_validation_batch(&mut self) {
        let batch = self.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let validator = self.tx_validator.clone();
        let event_tx = self.event_sender.clone();
        self.dispatch.spawn_tx_validation(move || {
            let results: Vec<bool> = batch
                .iter()
                .map(|tx| validator.validate_transaction(tx).is_ok())
                .collect();

            let mut failed_hashes = Vec::new();
            for (tx, valid) in batch.into_iter().zip(results) {
                if valid {
                    let _ = event_tx.send(NodeInput::TransactionValidated {
                        tx,
                        submitted_locally: false, // IoLoop sets from locally_submitted
                    });
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

    /// Flush accumulated committed header sender-signature verifications.
    ///
    /// Spawns one closure on the crypto pool that verifies each sender's BLS
    /// signature. Valid headers are sent back as `CommittedHeaderValidated`.
    pub(super) fn flush_committed_header_verifications(&mut self) {
        let items = self.committed_header_batch.take();
        if items.is_empty() {
            return;
        }

        let event_tx = self.event_sender.clone();
        self.dispatch.spawn_crypto(move || {
            for (committed_header, sender, public_key, sender_signature) in items {
                let msg = hyperscale_types::committed_block_header_message(
                    committed_header.header.shard_group_id,
                    committed_header.header.height.0,
                    &committed_header.header.hash(),
                );
                let valid = verify_bls_with_metrics(
                    &msg,
                    &public_key,
                    &sender_signature,
                    "committed_header",
                );
                if valid {
                    let _ = event_tx.send(NodeInput::CommittedHeaderValidated {
                        committed_header,
                        sender,
                    });
                } else {
                    tracing::warn!(
                        sender = sender.0,
                        height = committed_header.header.height.0,
                        "Committed header sender signature verification failed"
                    );
                }
            }
        });
    }
}
