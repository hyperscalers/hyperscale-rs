//! Batch accumulation and flushing for verification and broadcast.

use super::verify::verify_bls_with_metrics;
use super::{ExecutionVoteVerificationItem, IoLoop};
use hyperscale_core::{
    CrossShardExecutionRequest, NodeConfig, NodeInput, ProtocolEvent, StateMachine,
    TransactionValidator,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_messages::{ExecutionCertificatesNotification, ExecutionVotesNotification};
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_types::{
    Bls12381G1PublicKey, ExecutionCertificate, ExecutionResult, ExecutionVote, Hash,
    RoutableTransaction, ShardGroupId,
};
use std::sync::Arc;

impl<Cfg: NodeConfig> IoLoop<Cfg> {
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
        let dispatch = self.dispatch.clone();
        self.dispatch.spawn_tx_validation(move || {
            // Validate in parallel across all tx_validation pool threads,
            // then send results sequentially to preserve ordering.
            let results: Vec<bool> =
                dispatch.map_local(&batch, |tx| validator.validate_transaction(tx).is_ok());

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

    /// Flush a batch of cross-shard executions to the execution pool.
    pub(super) fn flush_cross_shard_executions(&mut self) {
        let requests = self.cross_shard_batch.take();
        if requests.is_empty() {
            return;
        }

        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let signing_key = Arc::clone(&self.signing_key);
        let dispatch = self.dispatch.clone();
        let local_shard = self.local_shard;
        let num_shards = self.num_shards;
        let validator_id = self.validator_id;
        let event_tx = self.event_sender.clone();

        self.dispatch.spawn_execution(move || {
            let start = std::time::Instant::now();
            let pairs: Vec<_> = dispatch.map_local(&requests, |req| {
                hyperscale_execution::handlers::execute_and_sign_cross_shard(
                    &executor,
                    &*storage,
                    req.tx_hash,
                    &req.transaction,
                    &req.provisions,
                    &signing_key,
                    local_shard,
                    validator_id,
                )
            });
            metrics::record_execution_latency(start.elapsed().as_secs_f64());

            // Separate votes and results, converting SingleTxResult → ExecutionResult
            // and filtering database_updates to the local shard (matching the single-shard
            // path in action_handler.rs).
            let (votes, results): (Vec<ExecutionVote>, Vec<_>) = pairs.into_iter().unzip();
            let results = results
                .into_iter()
                .map(|r| {
                    let mut result = ExecutionResult::from(r);
                    if num_shards > 1 {
                        result.database_updates =
                            <Cfg::C as hyperscale_types::TypeConfig>::filter_state_update_to_shard(
                                &result.database_updates,
                                local_shard,
                                num_shards,
                            );
                    }
                    result
                })
                .collect();

            // Send results back to the state machine via the same event that single-shard
            // execution uses. This populates the execution cache (enabling VerifyStateRoot)
            // and stores receipts (enabling serve_block_request for sync).
            let _ = event_tx.send(NodeInput::Protocol(
                ProtocolEvent::ExecutionBatchCompleted {
                    votes,
                    results,
                    speculative: false,
                },
            ));
        });
    }

    /// Flush accumulated execution vote verifications as a single batch.
    ///
    /// Spawns one closure on the crypto pool that uses cross-transaction BLS
    /// batch verification (~2 pairings) instead of N individual dispatches.
    pub(super) fn flush_execution_vote_verifications(&mut self) {
        let items = self.execution_vote_batch.take();
        if items.is_empty() {
            return;
        }

        let event_tx = self.event_sender.clone();
        self.dispatch.spawn_crypto(move || {
            let start = std::time::Instant::now();
            for (tx_hash, verified_votes) in
                hyperscale_execution::handlers::batch_verify_and_aggregate_execution_votes(items)
            {
                let _ = event_tx.send(NodeInput::Protocol(
                    ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                        tx_hash,
                        verified_votes,
                    },
                ));
            }
            metrics::record_signature_verification_latency(
                "bls_execution_vote",
                start.elapsed().as_secs_f64(),
            );
        });
    }

    /// Flush accumulated execution certificate verifications as a single batch.
    ///
    /// Spawns one closure on the crypto pool that uses cross-certificate BLS
    /// batch verification (~2 pairings) instead of N individual dispatches.
    pub(super) fn flush_execution_certificate_verifications(&mut self) {
        let items = self.execution_certificate_batch.take();
        if items.is_empty() {
            return;
        }

        let event_tx = self.event_sender.clone();
        self.dispatch.spawn_crypto(move || {
            let start = std::time::Instant::now();
            let results =
                hyperscale_execution::handlers::batch_verify_execution_certificate_signatures(
                    &items,
                );
            for ((certificate, _), valid) in items.into_iter().zip(results) {
                let _ = event_tx.send(NodeInput::Protocol(
                    ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid },
                ));
            }
            metrics::record_signature_verification_latency(
                "bls_execution_cert",
                start.elapsed().as_secs_f64(),
            );
        });
    }

    // ─── Batch Accumulation ─────────────────────────────────────────────

    pub(super) fn accumulate_cross_shard_execution(
        &mut self,
        tx_hash: Hash,
        transaction: Arc<RoutableTransaction>,
        provisions: Vec<hyperscale_types::StateProvision>,
    ) {
        let req = CrossShardExecutionRequest {
            tx_hash,
            transaction,
            provisions,
        };
        if self.cross_shard_batch.push(req, self.state.now()) {
            self.flush_cross_shard_executions();
        }
    }

    pub(super) fn accumulate_execution_vote_verification(
        &mut self,
        item: ExecutionVoteVerificationItem,
    ) {
        let weight = item.1.len();
        if self
            .execution_vote_batch
            .push_weighted(item, weight, self.state.now())
        {
            self.flush_execution_vote_verifications();
        }
    }

    pub(super) fn accumulate_execution_certificate_verification(
        &mut self,
        certificate: ExecutionCertificate,
        public_keys: Vec<Bls12381G1PublicKey>,
    ) {
        if self
            .execution_certificate_batch
            .push((certificate, public_keys), self.state.now())
        {
            self.flush_execution_certificate_verifications();
        }
    }

    pub(super) fn accumulate_broadcast_vote(&mut self, shard: ShardGroupId, vote: ExecutionVote) {
        if self
            .broadcast_vote_batch
            .push(shard, vote, self.state.now())
        {
            self.flush_broadcast_votes();
        }
    }

    pub(super) fn accumulate_broadcast_cert(
        &mut self,
        shard: ShardGroupId,
        cert: Arc<ExecutionCertificate>,
    ) {
        if self
            .broadcast_cert_batch
            .push(shard, cert, self.state.now())
        {
            self.flush_broadcast_certs();
        }
    }

    // ─── Batch Flushing ─────────────────────────────────────────────────

    pub(super) fn flush_broadcast_votes(&mut self) {
        for (shard, votes) in self.broadcast_vote_batch.take() {
            if !votes.is_empty() {
                let msg = hyperscale_types::exec_vote_batch_message(shard, &votes);
                let sig = self.signing_key.sign_v1(&msg);
                let batch = ExecutionVotesNotification::new(votes, self.validator_id, sig);
                self.network.notify(&self.cached_local_peers, &batch);
            }
        }
    }

    pub(super) fn flush_broadcast_certs(&mut self) {
        for (shard, certs) in self.broadcast_cert_batch.take() {
            if !certs.is_empty() {
                let owned: Vec<ExecutionCertificate> =
                    certs.into_iter().map(Arc::unwrap_or_clone).collect();
                let msg = hyperscale_types::exec_cert_batch_message(shard, &owned);
                let sig = self.signing_key.sign_v1(&msg);
                let batch = ExecutionCertificatesNotification::new(owned, self.validator_id, sig);
                if let Some(recipients) = self.cert_broadcast_recipients.remove(&shard) {
                    self.network.notify(&recipients, &batch);
                } else {
                    tracing::warn!(
                        shard = shard.0,
                        cert_count = batch.certificates.len(),
                        "Dropping execution certificate broadcast: no recipients recorded for shard"
                    );
                }
            }
        }
        // Clear any stale entries for shards that had no certs to flush.
        self.cert_broadcast_recipients.clear();
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
