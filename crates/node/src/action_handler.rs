//! Action handler for immediately-dispatched computation.
//!
//! [`handle_delegated_action`] routes each delegated [`Action`] variant to the
//! coordinator crate that owns it. Each crate's `handle_action` runs the pure
//! computation and pushes outcomes via `ctx.notify` and `ctx.commit_prepared`.
//!
//! Batched work (execution votes, execution certs) and block commits are
//! handled inline by the I/O loop's flush closures.

use hyperscale_core::{Action, ActionContext, NodeInput, ProtocolEvent};
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHash, LocalExecutionEntry};

/// Which dispatch pool an action should run on in production.
pub enum DispatchPool {
    /// Liveness-critical consensus crypto (QC verification, block votes,
    /// state root verification, proposal building).
    ConsensusCrypto,
    /// General crypto verification (cert aggregation, provision proofs).
    Crypto,
    /// Transaction execution (single-shard, merkle).
    Execution,
}

/// Map a delegated action to its execution pool.
///
/// Returns `None` for actions that are not delegated (network, timers, etc.)
/// and should be handled by the runner directly.
pub const fn dispatch_pool_for(action: &Action) -> Option<DispatchPool> {
    match action {
        // Consensus-critical crypto + state root computation
        Action::VerifyAndBuildQuorumCertificate { .. }
        | Action::VerifyQcSignature { .. }
        | Action::VerifyRemoteHeaderQc { .. }
        | Action::VerifyTransactionRoot { .. }
        | Action::VerifyProvisionRoot { .. }
        | Action::VerifyCertificateRoot { .. }
        | Action::VerifyLocalReceiptRoot { .. }
        | Action::VerifyProvisionTxRoots { .. }
        | Action::VerifyStateRoot { .. }
        | Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto (cert aggregation, provision proofs)
        Action::AggregateExecutionCertificate { .. }
        | Action::VerifyAndAggregateExecutionVotes { .. }
        | Action::VerifyExecutionCertificateSignature { .. }
        | Action::VerifyProvisions { .. }
        | Action::FetchAndBroadcastProvisions { .. } => Some(DispatchPool::Crypto),

        // Execution
        Action::ExecuteTransactions { .. } | Action::ExecuteCrossShardTransactions { .. } => {
            Some(DispatchPool::Execution)
        }
        _ => None,
    }
}

/// Anchor block hash for `PendingChain::view_at` for actions that read
/// state via the substate overlay. Returns `None` for actions that
/// don't read state, in which case the dispatcher falls back to
/// `view_at_committed_tip()`.
///
/// The anchor names the block whose state the action reads against:
/// - `BuildProposal`/`VerifyStateRoot` use the parent block (state we
///   build on / verify against).
/// - `Execute*` and `FetchAndBroadcastProvisions` use the kicked-off
///   block (the committed block whose state these actions act on).
pub const fn parent_hash_for(action: &Action) -> Option<BlockHash> {
    match action {
        Action::VerifyStateRoot {
            parent_block_hash, ..
        } => Some(*parent_block_hash),
        Action::BuildProposal { parent_hash, .. } => Some(*parent_hash),
        Action::ExecuteTransactions { block_hash, .. }
        | Action::ExecuteCrossShardTransactions { block_hash, .. }
        | Action::FetchAndBroadcastProvisions { block_hash, .. } => Some(*block_hash),
        _ => None,
    }
}

/// Route a delegated action to the coordinator crate that owns it.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain).
/// No-ops for non-delegated actions; callers gate via [`dispatch_pool_for`].
#[allow(clippy::too_many_lines)] // single dispatch over delegated Action variants
pub fn handle_delegated_action<S: Storage, E: Engine>(
    action: Action,
    ctx: &ActionContext<'_, S, E>,
) {
    match &action {
        Action::VerifyAndBuildQuorumCertificate { .. }
        | Action::VerifyQcSignature { .. }
        | Action::VerifyRemoteHeaderQc { .. }
        | Action::VerifyTransactionRoot { .. }
        | Action::VerifyProvisionTxRoots { .. }
        | Action::VerifyProvisionRoot { .. }
        | Action::VerifyCertificateRoot { .. }
        | Action::VerifyLocalReceiptRoot { .. }
        | Action::VerifyStateRoot { .. }
        | Action::BuildProposal { .. } => {
            return hyperscale_bft::action_handlers::handle_action(action, ctx);
        }
        _ => {}
    }

    match action {
        // --- Execution Vote Aggregation and Verification ---
        Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            let certificate =
                hyperscale_execution::action_handlers::aggregate_execution_certificate(
                    &wave_id,
                    global_receipt_root,
                    &votes,
                    &committee,
                );
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::ExecutionCertificateAggregated {
                    wave_id,
                    certificate,
                },
            ));
        }

        Action::VerifyAndAggregateExecutionVotes {
            wave_id,
            block_hash,
            votes,
        } => {
            let verified =
                hyperscale_execution::action_handlers::batch_verify_execution_votes(votes);
            let verified_votes: Vec<_> = verified.collect();
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                    wave_id,
                    block_hash,
                    verified_votes,
                },
            ));
        }

        Action::VerifyExecutionCertificateSignature {
            certificate,
            public_keys,
            ..
        } => {
            let valid =
                hyperscale_execution::action_handlers::verify_execution_certificate_signature(
                    &certificate,
                    &public_keys,
                );
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid },
            ));
        }

        // --- State Provision Batch Verification ---
        Action::VerifyProvisions {
            provisions,
            committed_header,
        } => {
            let merkle_start = std::time::Instant::now();
            let all_valid = {
                let all_entries = provisions.all_entries_deduped();
                if all_entries.is_empty() {
                    true
                } else {
                    let valid = hyperscale_storage::tree::proofs::verify_proof(
                        &provisions.proof,
                        &all_entries,
                        committed_header.header.state_root,
                        |e| &e.storage_key,
                    );
                    if !valid {
                        tracing::warn!(
                            source_shard = provisions.source_shard.0,
                            block_height = provisions.block_height.0,
                            header_height = committed_header.header.height.0,
                            header_state_root = ?committed_header.header.state_root,
                            entry_count = all_entries.len(),
                            proof_len = provisions.proof.as_bytes().len(),
                            "Provision merkle proof verification failed"
                        );
                    }
                    valid
                }
            };
            metrics::record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::StateProvisionsVerified {
                    provisions,
                    committed_header: Some(committed_header),
                    valid: all_valid,
                },
            ));
        }

        // --- Transaction execution ---
        Action::ExecuteTransactions {
            wave_id,
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let start = std::time::Instant::now();
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            let view_snap =
                <hyperscale_storage::SubstateView<_> as hyperscale_storage::SubstateStore>::snapshot(
                    &*ctx.view,
                );
            let batch_result = ctx.executor.execute_single_shard(
                &view_snap,
                transactions.as_slice(),
                local_shard,
                num_shards,
            );
            let per_tx: Vec<_> = match batch_result {
                Ok(output) => output.results,
                Err(e) => {
                    tracing::warn!(error = %e, "single-shard batch execution failed");
                    transactions
                        .iter()
                        .map(|tx| {
                            hyperscale_engine::SingleTxResult::failure(tx.hash(), e.to_string())
                        })
                        .collect()
                }
            };
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = per_tx
                .into_iter()
                .map(|r| {
                    let outcome = hyperscale_engine::action_handlers::extract_execution_result(&r);
                    (outcome, LocalExecutionEntry::from(r))
                })
                .unzip();
            metrics::record_execution_latency(start.elapsed().as_secs_f64());
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::ExecutionBatchCompleted {
                    wave_id,
                    results,
                    tx_outcomes,
                },
            ));
        }

        // --- Cross-shard transaction execution ---
        Action::ExecuteCrossShardTransactions {
            wave_id,
            block_hash: _,
            requests,
        } => {
            let start = std::time::Instant::now();
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            let view_snap =
                <hyperscale_storage::SubstateView<_> as hyperscale_storage::SubstateStore>::snapshot(
                    &*ctx.view,
                );
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = requests
                .iter()
                .map(|req| {
                    let output = ctx.executor.execute_cross_shard(
                        &view_snap,
                        std::slice::from_ref(&req.transaction),
                        &req.provisions,
                        local_shard,
                        num_shards,
                    );
                    let r = match output {
                        Ok(mut o) => o.results.pop().unwrap_or_else(|| {
                            hyperscale_engine::SingleTxResult::failure(
                                req.tx_hash,
                                "No cross-shard execution result returned",
                            )
                        }),
                        Err(e) => {
                            tracing::warn!(tx_hash = ?req.tx_hash, error = %e, "cross-shard execution failed");
                            hyperscale_engine::SingleTxResult::failure(req.tx_hash, e.to_string())
                        }
                    };
                    let outcome = hyperscale_engine::action_handlers::extract_execution_result(&r);
                    (outcome, LocalExecutionEntry::from(r))
                })
                .unzip();
            metrics::record_execution_latency(start.elapsed().as_secs_f64());
            (ctx.notify)(NodeInput::Protocol(
                ProtocolEvent::ExecutionBatchCompleted {
                    wave_id,
                    results,
                    tx_outcomes,
                },
            ));
        }

        // --- Provision fetch + broadcast ---
        Action::FetchAndBroadcastProvisions {
            block_hash: _,
            requests,
            source_shard,
            block_height,
            shard_recipients,
        } => {
            let batches = hyperscale_provisions::action_handlers::fetch_and_broadcast_provision(
                ctx.executor,
                &ctx.view,
                source_shard,
                block_height,
                &requests,
                &shard_recipients,
            );
            (ctx.notify)(NodeInput::ProvisionsReady { batches });
        }

        _ => {}
    }
}
