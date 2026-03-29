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
use hyperscale_engine::RadixExecutor;
use hyperscale_metrics as metrics;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::{ExecutionResult, Hash, ProvisionBatch, ShardGroupId, TxEntries};
use std::sync::Arc;
use tracing::warn;

/// Context for executing delegated actions.
pub(crate) struct ActionContext<'a, S: CommitStore + SubstateStore + ConsensusStore> {
    pub storage: &'a S,
    pub executor: &'a RadixExecutor,
    pub local_shard: ShardGroupId,
    pub num_shards: u64,
}

/// Result of handling a delegated action.
pub(crate) struct DelegatedResult<P: Send> {
    /// Events to deliver to the state machine.
    pub events: Vec<NodeInput>,
    /// Prepared commit handle to cache: (block_hash, block_height, handle).
    /// Height is stored alongside the handle so stale entries can be pruned.
    pub prepared_commit: Option<(Hash, u64, P)>,
}

/// Which dispatch pool an action should run on in production.
pub(crate) enum DispatchPool {
    /// Liveness-critical consensus crypto (QC, state root, proposal).
    ConsensusCrypto,
    /// General crypto verification (cert aggregation).
    Crypto,
    /// Transaction execution (single-shard, merkle).
    Execution,
    /// Provision proof generation and verification (IPA math).
    Provisions,
}

/// Map a delegated action to its execution pool.
///
/// Returns `None` for actions that are not delegated (network, timers, etc.)
/// and should be handled by the runner directly.
pub(crate) fn dispatch_pool_for(action: &Action) -> Option<DispatchPool> {
    match action {
        // Consensus-critical crypto
        Action::VerifyAndBuildQuorumCertificate { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyQcSignature { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyStateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyTransactionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyReceiptRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto
        Action::AggregateExecutionCertificate { .. } => Some(DispatchPool::Crypto),
        Action::VerifyAndAggregateExecutionVotes { .. } => Some(DispatchPool::Crypto),
        Action::VerifyExecutionCertificateSignature { .. } => Some(DispatchPool::Crypto),

        // Provision work: IPA proof generation and verification.
        // Dedicated pool to avoid starving execution and crypto work.
        Action::VerifyProvisionBatch { .. } => Some(DispatchPool::Provisions),
        Action::FetchAndBroadcastProvisions { .. } => Some(DispatchPool::Provisions),

        // Execution
        Action::ExecuteTransactions { .. } => Some(DispatchPool::Execution),
        Action::SpeculativeExecute { .. } => Some(DispatchPool::Execution),
        Action::ExecuteCrossShardTransactions { .. } => Some(DispatchPool::Execution),
        _ => None,
    }
}

/// Handle a delegated action using the shared pure functions.
///
/// Returns `None` for non-delegated actions (timers, broadcasts, persist, etc.)
/// that the runner must handle directly.
///
/// For execution actions (`ExecuteTransactions`, `SpeculativeExecute`), the
/// returned events include `ProtocolEvent::ExecutionBatchCompleted`.
/// The runner is responsible for additionally broadcasting votes to shard
/// peers (network-specific).
#[allow(clippy::too_many_lines)]
pub(crate) fn handle_delegated_action<S: CommitStore + SubstateStore + ConsensusStore>(
    action: Action,
    ctx: &ActionContext<'_, S>,
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

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            transactions,
        } => {
            let start = std::time::Instant::now();
            let valid =
                hyperscale_bft::handlers::verify_transaction_root(expected_root, &transactions);
            metrics::record_signature_verification_latency(
                "transaction_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::TransactionRootVerified { block_hash, valid },
                )],
                prepared_commit: None,
            })
        }

        Action::VerifyReceiptRoot {
            block_hash,
            expected_root,
            certificates,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_receipt_root(expected_root, &certificates);
            metrics::record_signature_verification_latency(
                "receipt_root",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::ReceiptRootVerified {
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        // --- BFT state root and proposal ---
        Action::VerifyStateRoot {
            block_hash,
            parent_state_root,
            expected_root,
            per_cert_updates,
            block_height,
        } => {
            let start = std::time::Instant::now();
            let merged = hyperscale_storage::merge_database_updates_from_arcs(&per_cert_updates);
            let result = hyperscale_bft::handlers::verify_state_root(
                ctx.storage,
                parent_state_root,
                expected_root,
                &merged,
                block_height,
            );
            metrics::record_signature_verification_latency(
                "state_root",
                start.elapsed().as_secs_f64(),
            );
            let prepared = result
                .prepared_commit
                .map(|p| (block_hash, block_height, p));
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::StateRootVerified {
                    block_hash,
                    valid: result.valid,
                })],
                prepared_commit: prepared,
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
            transactions,
            certificates,
            per_cert_updates,
            deferred,
            aborted,
            provision_targets,
        } => {
            let merged_updates =
                hyperscale_storage::merge_database_updates_from_arcs(&per_cert_updates);
            let result = hyperscale_bft::handlers::build_proposal(
                ctx.storage,
                proposer,
                height,
                round,
                parent_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                transactions,
                certificates,
                merged_updates,
                deferred,
                aborted,
                shard_group_id,
                provision_targets,
            );
            let prepared = result
                .prepared_commit
                .map(|p| (result.block_hash, height.0, p));
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::ProposalBuilt {
                    height,
                    round,
                    block: Arc::new(result.block),
                    block_hash: result.block_hash,
                })],
                prepared_commit: prepared,
            })
        }

        // --- Execution Vote Aggregation and Verification ---
        Action::AggregateExecutionCertificate {
            wave_id,
            block_hash: _,
            shard,
            receipt_root,
            votes,
            tx_outcomes,
            committee,
        } => {
            // Aggregate BLS signatures from execution votes into a execution certificate.
            let certificate = hyperscale_execution::handlers::aggregate_execution_certificate(
                &wave_id,
                shard,
                receipt_root,
                &votes,
                tx_outcomes,
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
        Action::VerifyProvisionBatch {
            batch,
            committed_headers,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
        } => {
            // Try each candidate header until one passes QC verification.
            let qc_start = std::time::Instant::now();
            let verified_header = committed_headers.into_iter().find(|candidate| {
                // Verify QC signature (BLS pairing — expensive)
                let qc_valid = hyperscale_bft::handlers::verify_qc_signature(
                    &candidate.qc,
                    &committee_public_keys,
                );
                if !qc_valid {
                    return false;
                }

                // Compute total voting power from this QC's signers
                let total_voting_power: u64 = candidate
                    .qc
                    .signers
                    .set_indices()
                    .filter_map(|idx| committee_voting_power.get(idx).copied())
                    .sum();

                total_voting_power >= quorum_threshold
                    && candidate.qc.block_hash == candidate.header.hash()
            });
            metrics::record_signature_verification_latency(
                "provision_qc",
                qc_start.elapsed().as_secs_f64(),
            );

            // Verify merkle proofs against the verified header's state root.
            let merkle_start = std::time::Instant::now();
            let all_valid = verified_header.as_ref().is_some_and(|header| {
                let all_entries = batch.all_entries_deduped();
                if all_entries.is_empty() {
                    return true;
                }
                hyperscale_storage::proofs::verify_all_verkle_proofs(
                    &all_entries,
                    &batch.proof,
                    header.header.state_root,
                )
            });
            metrics::record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::StateProvisionsVerified {
                        batch,
                        committed_header: verified_header,
                        valid: all_valid,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Transaction execution ---
        // The returned event is ExecutionBatchCompleted with results and tx_outcomes.
        Action::ExecuteTransactions {
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let local_shard = ctx.local_shard;
            let num_shards = ctx.num_shards;
            let raw_results: Vec<_> = transactions
                .iter()
                .map(|tx| {
                    hyperscale_execution::handlers::execute_single_shard(
                        ctx.executor,
                        ctx.storage,
                        tx,
                    )
                })
                .collect();

            // Extract per-tx outcomes on handler thread (before consuming results)
            let tx_outcomes: Vec<_> = raw_results
                .iter()
                .map(hyperscale_execution::handlers::extract_execution_result)
                .collect();
            let results = raw_results
                .into_iter()
                .map(|r| {
                    let mut result = ExecutionResult::from(r);
                    if num_shards > 1 {
                        result.database_updates = hyperscale_storage::filter_updates_to_shard(
                            &result.database_updates,
                            local_shard,
                            num_shards,
                        );
                    }
                    result
                })
                .collect();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        results,
                        tx_outcomes,
                        speculative: false,
                    },
                )],
                prepared_commit: None,
            })
        }

        Action::SpeculativeExecute {
            block_hash,
            transactions,
        } => {
            let local_shard = ctx.local_shard;
            let num_shards = ctx.num_shards;
            let raw_results: Vec<_> = transactions
                .iter()
                .map(|tx| {
                    hyperscale_execution::handlers::execute_single_shard(
                        ctx.executor,
                        ctx.storage,
                        tx,
                    )
                })
                .collect();

            // Extract per-tx outcomes on handler thread
            let tx_outcomes: Vec<_> = raw_results
                .iter()
                .map(hyperscale_execution::handlers::extract_execution_result)
                .collect();
            let tx_hashes: Vec<Hash> = raw_results.iter().map(|r| r.tx_hash).collect();
            let results = raw_results
                .into_iter()
                .map(|r| {
                    let mut result = ExecutionResult::from(r);
                    if num_shards > 1 {
                        result.database_updates = hyperscale_storage::filter_updates_to_shard(
                            &result.database_updates,
                            local_shard,
                            num_shards,
                        );
                    }
                    result
                })
                .collect();

            Some(DelegatedResult {
                events: vec![
                    NodeInput::Protocol(ProtocolEvent::ExecutionBatchCompleted {
                        results,
                        tx_outcomes,
                        speculative: true,
                    }),
                    NodeInput::Protocol(ProtocolEvent::SpeculativeExecutionComplete {
                        block_hash,
                        tx_hashes,
                    }),
                ],
                prepared_commit: None,
            })
        }

        // --- Cross-shard transaction execution ---
        Action::ExecuteCrossShardTransactions { requests } => {
            let local_shard = ctx.local_shard;
            let num_shards = ctx.num_shards;
            let raw_results: Vec<_> = requests
                .iter()
                .map(|req| {
                    hyperscale_execution::handlers::execute_cross_shard(
                        ctx.executor,
                        ctx.storage,
                        req.tx_hash,
                        &req.transaction,
                        &req.provisions,
                    )
                })
                .collect();

            let tx_outcomes: Vec<_> = raw_results
                .iter()
                .map(hyperscale_execution::handlers::extract_execution_result)
                .collect();
            let results = raw_results
                .into_iter()
                .map(|r| {
                    let mut result = ExecutionResult::from(r);
                    if num_shards > 1 {
                        result.database_updates = hyperscale_storage::filter_updates_to_shard(
                            &result.database_updates,
                            local_shard,
                            num_shards,
                        );
                    }
                    result
                })
                .collect();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        results,
                        tx_outcomes,
                        speculative: false,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Provision fetch + broadcast ---
        Action::FetchAndBroadcastProvisions {
            requests,
            source_shard,
            block_height,
            block_timestamp,
            shard_recipients,
        } => {
            use std::collections::HashMap;

            // Phase 1: Fetch state entries for all transactions.
            let mut per_tx: Vec<(
                Hash,
                Vec<ShardGroupId>,
                Arc<Vec<hyperscale_types::StateEntry>>,
            )> = Vec::with_capacity(requests.len());
            let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

            for req in &requests {
                let entries =
                    match ctx
                        .executor
                        .fetch_state_entries(ctx.storage, &req.nodes, block_height.0)
                    {
                        Some(entries) => entries,
                        None => {
                            warn!(
                                source_shard = source_shard.0,
                                block_height = block_height.0,
                                tx_hash = %req.tx_hash,
                                node_count = req.nodes.len(),
                                "fetch_state_entries returned None — JVT version unavailable"
                            );
                            continue;
                        }
                    };
                for e in &entries {
                    all_storage_keys.push(e.storage_key.clone());
                }
                per_tx.push((req.tx_hash, req.target_shards.clone(), Arc::new(entries)));
            }
            if per_tx.is_empty() {
                warn!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    request_count = requests.len(),
                    "All fetch_state_entries failed — no provisions to broadcast"
                );
                return Some(DelegatedResult {
                    events: vec![NodeInput::ProvisionsReady {
                        batches: vec![],
                        block_timestamp: 0,
                    }],
                    prepared_commit: None,
                });
            }

            // Phase 2: Generate ONE batched proof covering all entries across all transactions.
            all_storage_keys.sort();
            all_storage_keys.dedup();
            let proof = match ctx
                .storage
                .generate_verkle_proofs(&all_storage_keys, block_height.0)
            {
                Some(p) => Arc::new(p),
                None => {
                    warn!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        key_count = all_storage_keys.len(),
                        "generate_verkle_proofs returned None — JVT version unavailable"
                    );
                    return Some(DelegatedResult {
                        events: vec![NodeInput::ProvisionsReady {
                            batches: vec![],
                            block_timestamp: 0,
                        }],
                        prepared_commit: None,
                    });
                }
            };
            // Phase 3: Build provisions sharing the single proof.
            // Group entries per target shard.
            let mut shard_tx_entries: HashMap<ShardGroupId, Vec<TxEntries>> = HashMap::new();
            for (tx_hash, target_shards, entries) in per_tx {
                for &target_shard in &target_shards {
                    shard_tx_entries
                        .entry(target_shard)
                        .or_default()
                        .push(TxEntries {
                            tx_hash,
                            entries: (*entries).clone(),
                        });
                }
            }

            let batches: Vec<_> = shard_tx_entries
                .into_iter()
                .map(|(shard, transactions)| {
                    let recipients = shard_recipients.get(&shard).cloned().unwrap_or_default();
                    let batch = ProvisionBatch {
                        source_shard,
                        block_height,
                        proof: (*proof).clone(),
                        transactions,
                    };
                    (shard, batch, recipients)
                })
                .collect();
            Some(DelegatedResult {
                events: vec![NodeInput::ProvisionsReady {
                    batches,
                    block_timestamp,
                }],
                prepared_commit: None,
            })
        }

        _ => None,
    }
}
