//! Action handler for immediately-dispatched computation.
//!
//! [`handle_delegated_action`] bridges individual [`Action`] variants to pure
//! computation (crypto verification, execution, proposal building). The node
//! loop's `dispatch_delegated_action` spawns closures that call this function
//! on the appropriate thread pool.
//!
//! Batched work (execution votes, execution certs) and block commits are
//! handled inline by the I/O loop's flush closures.

use hyperscale_core::{Action, NodeInput, ProtocolEvent};
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::{BlockHash, BlockHeight, LocalExecutionEntry};
use std::sync::Arc;

/// Context for executing delegated actions.
pub struct ActionContext<
    'a,
    S: ChainWriter + SubstateStore + hyperscale_storage::VersionedStore + ChainReader,
    E: Engine,
> {
    pub executor: &'a E,
    pub topology: &'a hyperscale_types::TopologySnapshot,
    /// Anchored read view over base storage + the chain of unpersisted
    /// blocks back to the committed tip. Built per-dispatch by
    /// `PendingChain::view_at(parent_hash_for(action))`.
    pub view: Arc<hyperscale_storage::SubstateView<S>>,
}

/// Result of handling a delegated action.
pub struct DelegatedResult<P: Send> {
    /// Events to deliver to the state machine.
    pub events: Vec<NodeInput>,
    /// Prepared commit + receipts to cache.
    ///
    /// Receipts travel alongside the prepared handle so the `io_loop` can
    /// build a `ChainEntry` and insert into `PendingChain` in one step
    /// — eliminating the prior separate `db_updates` plumbing that was
    /// always produced together with `prepared_commit` anyway.
    pub prepared_commit: Option<PreparedBlock<P>>,
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
pub struct PreparedBlock<P: Send> {
    pub block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub prepared: P,
    pub receipts: Vec<Arc<hyperscale_types::LocalReceipt>>,
}

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
        | Action::FetchAndBroadcastProvision { .. } => Some(DispatchPool::Crypto),

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
/// - `Execute*` and `FetchAndBroadcastProvision` use the kicked-off
///   block (the committed block whose state these actions act on).
pub const fn parent_hash_for(action: &Action) -> Option<BlockHash> {
    match action {
        Action::VerifyStateRoot {
            parent_block_hash, ..
        } => Some(*parent_block_hash),
        Action::BuildProposal { parent_hash, .. } => Some(*parent_hash),
        Action::ExecuteTransactions { block_hash, .. }
        | Action::ExecuteCrossShardTransactions { block_hash, .. }
        | Action::FetchAndBroadcastProvision { block_hash, .. } => Some(*block_hash),
        _ => None,
    }
}

/// Handle a delegated action using the shared pure functions.
///
/// Returns `None` for non-delegated actions (timers, broadcasts, persist, etc.)
/// that the runner must handle directly.
///
/// For execution actions (`ExecuteTransactions`), the
/// returned events include `ProtocolEvent::ExecutionBatchCompleted`.
/// The runner is responsible for additionally broadcasting votes to shard
/// peers (network-specific).
#[allow(clippy::too_many_lines)]
pub fn handle_delegated_action<
    S: ChainWriter
        + SubstateStore
        + hyperscale_storage::VersionedStore
        + ChainReader
        + hyperscale_storage::JmtTreeReader
        + Sync,
    E: Engine,
>(
    action: Action,
    ctx: &ActionContext<'_, S, E>,
) -> Option<DelegatedResult<S::PreparedCommit>> {
    match action {
        // --- BFT crypto verification ---
        Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_group_id,
            height,
            round,
            parent_block_hash,
            votes_to_verify,
            verified_votes,
            total_voting_power,
        } => {
            let start = std::time::Instant::now();
            let result = hyperscale_bft::handlers::verify_and_build_qc(
                block_hash,
                shard_group_id,
                height,
                round,
                parent_block_hash,
                votes_to_verify,
                verified_votes,
                total_voting_power,
            );
            metrics::record_signature_verification_latency("vote", start.elapsed().as_secs_f64());
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::QuorumCertificateResult {
                        block_hash: result.block_hash,
                        qc: result.qc,
                        verified_votes: result.verified_votes,
                    },
                )],
                prepared_commit: None,
            })
        }

        Action::VerifyQcSignature {
            qc,
            public_keys,
            block_hash,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_qc_signature(&qc, &public_keys);
            metrics::record_signature_verification_latency("qc", start.elapsed().as_secs_f64());
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::QcSignatureVerified {
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyRemoteHeaderQc {
            header,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
            shard,
            height,
        } => {
            let start = std::time::Instant::now();

            // Verify QC signature (BLS pairing)
            let qc_valid =
                hyperscale_bft::handlers::verify_qc_signature(&header.qc, &committee_public_keys);

            // Verify voting power meets quorum and block_hash matches header
            let valid = if qc_valid {
                let total_power: u64 = header
                    .qc
                    .signers
                    .set_indices()
                    .filter_map(|idx| committee_voting_power.get(idx).copied())
                    .sum();
                total_power >= quorum_threshold && header.qc.block_hash == header.header.hash()
            } else {
                false
            };

            metrics::record_signature_verification_latency(
                "remote_header_qc",
                start.elapsed().as_secs_f64(),
            );

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::RemoteHeaderQcVerified {
                    shard,
                    height,
                    header,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            transactions,
            validity_anchor,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_transaction_root(
                expected_root,
                &transactions,
                validity_anchor,
            );
            metrics::record_signature_verification_latency(
                "transaction_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::TransactionRoot,
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyProvisionTxRoots {
            block_hash,
            expected,
            transactions,
            topology,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_provision_tx_roots(
                &expected,
                &transactions,
                &topology,
            );
            metrics::record_signature_verification_latency(
                "provision_tx_roots",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::ProvisionTxRoots,
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyProvisionRoot {
            block_hash,
            expected_root,
            batch_hashes,
        } => {
            let start = std::time::Instant::now();
            let raw_batch_hashes: Vec<hyperscale_types::Hash> =
                batch_hashes.iter().map(|h| h.into_raw()).collect();
            let valid =
                hyperscale_bft::handlers::verify_provision_root(expected_root, &raw_batch_hashes);
            metrics::record_signature_verification_latency(
                "provision_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::ProvisionRoot,
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyCertificateRoot {
            block_hash,
            expected_root,
            certificates,
        } => {
            let start = std::time::Instant::now();
            let valid =
                hyperscale_bft::handlers::verify_certificate_root(expected_root, &certificates);
            metrics::record_signature_verification_latency(
                "certificate_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::CertificateRoot,
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyLocalReceiptRoot {
            block_hash,
            expected_root,
            receipts,
        } => {
            let start = std::time::Instant::now();
            let valid =
                hyperscale_bft::handlers::verify_local_receipt_root(expected_root, &receipts);
            metrics::record_signature_verification_latency(
                "local_receipt_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::LocalReceiptRoot,
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        // --- BFT state root and proposal ---
        Action::VerifyStateRoot {
            block_hash,
            // Anchor already applied via ctx.view (see parent_hash_for).
            parent_block_hash: _,
            parent_state_root,
            parent_block_height,
            expected_root,
            finalized_waves,
            block_height,
        } => {
            let start = std::time::Instant::now();
            let pending_snapshots = ctx.view.pending_snapshots().to_vec();
            let result = hyperscale_bft::handlers::verify_state_root(
                &*ctx.view,
                parent_state_root,
                parent_block_height,
                expected_root,
                &finalized_waves,
                block_height,
                &pending_snapshots,
            );
            metrics::record_signature_verification_latency(
                "state_root",
                start.elapsed().as_secs_f64(),
            );
            let receipts: Vec<Arc<hyperscale_types::LocalReceipt>> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts.iter())
                .map(|b| Arc::clone(&b.local_receipt))
                .collect();
            let prepared_commit = result.prepared_commit.map(|p| PreparedBlock {
                block_hash,
                block_height,
                prepared: p,
                receipts,
            });
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::StateRoot,
                    block_hash,
                    valid: result.valid,
                })],
                prepared_commit,
            })
        }

        Action::BuildProposal {
            shard_group_id,
            proposer,
            height,
            round,
            parent_hash,
            parent_qc,
            timestamp,
            is_fallback,
            parent_state_root,
            parent_block_height,
            transactions,
            finalized_waves,
            provisions,
            parent_in_flight,
            finalized_tx_count,
        } => {
            // Anchor (parent_hash) already applied via ctx.view.
            let pending_snapshots = ctx.view.pending_snapshots().to_vec();

            let result = hyperscale_bft::handlers::build_proposal(
                &*ctx.view,
                proposer,
                height,
                round,
                parent_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_block_height,
                transactions,
                finalized_waves.clone(),
                shard_group_id,
                ctx.topology,
                provisions.clone(),
                parent_in_flight,
                finalized_tx_count,
                &pending_snapshots,
            );
            let receipts: Vec<Arc<hyperscale_types::LocalReceipt>> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts.iter())
                .map(|b| Arc::clone(&b.local_receipt))
                .collect();
            let block_hash = result.block_hash;
            let prepared_commit = result.prepared_commit.map(|p| PreparedBlock {
                block_hash,
                block_height: height,
                prepared: p,
                receipts,
            });
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::ProposalBuilt {
                    height,
                    round,
                    block: Arc::new(result.block),
                    block_hash,
                    finalized_waves,
                    provisions,
                })],
                prepared_commit,
            })
        }

        // --- Execution Vote Aggregation and Verification ---
        Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            // Aggregate BLS signatures from execution votes into an execution certificate.
            // tx_outcomes extracted from votes by the handler (all quorum votes carry identical outcomes).
            let certificate = hyperscale_execution::handlers::aggregate_execution_certificate(
                &wave_id,
                global_receipt_root,
                &votes,
                &committee,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionCertificateAggregated {
                        wave_id,
                        certificate,
                    },
                )],
                prepared_commit: None,
            })
        }

        Action::VerifyAndAggregateExecutionVotes {
            wave_id,
            block_hash,
            votes,
        } => {
            // Batch-verify execution vote signatures.
            let verified = hyperscale_execution::handlers::batch_verify_execution_votes(votes);
            let verified_votes: Vec<_> = verified.collect();
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                        wave_id,
                        block_hash,
                        verified_votes,
                    },
                )],
                prepared_commit: None,
            })
        }

        Action::VerifyExecutionCertificateSignature {
            certificate,
            public_keys,
            ..
        } => {
            let valid = hyperscale_execution::handlers::verify_execution_certificate_signature(
                &certificate,
                &public_keys,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid },
                )],
                prepared_commit: None,
            })
        }

        // --- State Provision Batch Verification ---
        // QC was already verified by RemoteHeaderCoordinator; only merkle
        // proofs need checking against the committed header's state root.
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

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::StateProvisionsVerified {
                        provisions,
                        committed_header: Some(committed_header),
                        valid: all_valid,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Transaction execution ---
        // The returned event is ExecutionBatchCompleted with results and tx_outcomes.
        Action::ExecuteTransactions {
            wave_id,
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            // ONE anchored snapshot for the whole batch. State doesn't
            // change during execution (commits serialize elsewhere), so
            // one rocksdb snapshot serves every tx — avoids per-tx
            // `db.snapshot()` + `read_jmt_metadata` overhead.
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
                    // Whole-batch failure is rare and fatal-ish; produce
                    // one failure entry per tx so the state machine can
                    // still advance without losing transactions.
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
                    let outcome = hyperscale_engine::handlers::extract_execution_result(&r);
                    (outcome, LocalExecutionEntry::from(r))
                })
                .unzip();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        wave_id,
                        results,
                        tx_outcomes,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Cross-shard transaction execution ---
        Action::ExecuteCrossShardTransactions {
            wave_id,
            block_hash: _,
            requests,
        } => {
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            // ONE anchored snapshot shared across every request's
            // execution — avoids per-request `storage.snapshot()`.
            // Each request still applies its OWN provisions (as its
            // own overlay) on top of this shared base snapshot.
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
                    let outcome = hyperscale_engine::handlers::extract_execution_result(&r);
                    (outcome, LocalExecutionEntry::from(r))
                })
                .unzip();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        wave_id,
                        results,
                        tx_outcomes,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Provision fetch + broadcast ---
        Action::FetchAndBroadcastProvision {
            block_hash: _,
            requests,
            source_shard,
            block_height,
            shard_recipients,
        } => {
            let batches = hyperscale_provisions::handlers::fetch_and_broadcast_provision(
                ctx.executor,
                &ctx.view,
                source_shard,
                block_height,
                &requests,
                &shard_recipients,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::ProvisionReady { batches }],
                prepared_commit: None,
            })
        }

        _ => None,
    }
}
