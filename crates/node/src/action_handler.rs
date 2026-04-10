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
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::{Hash, LocalExecutionEntry, ProvisionBatch, ShardGroupId, TxEntries};
use std::sync::Arc;
use tracing::warn;

/// Context for executing delegated actions.
pub(crate) struct ActionContext<'a, S: ChainWriter + SubstateStore + ChainReader> {
    pub storage: &'a S,
    pub executor: &'a RadixExecutor,
    pub topology: &'a hyperscale_types::TopologySnapshot,
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
        Action::VerifyRemoteHeaderQc { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyStateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyTransactionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyCertificateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyLocalReceiptRoot { .. } => Some(DispatchPool::ConsensusCrypto),
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
        Action::ExecuteCrossShardTransactions { .. } => Some(DispatchPool::Execution),
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
pub(crate) fn handle_delegated_action<S: ChainWriter + SubstateStore + ChainReader>(
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
        } => {
            let start = std::time::Instant::now();
            let valid =
                hyperscale_bft::handlers::verify_transaction_root(expected_root, &transactions);
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
            parent_state_root,
            expected_root,
            finalized_waves,
            block_height,
        } => {
            let start = std::time::Instant::now();
            // Collect receipts from all finalized waves.
            // Merging happens inside prepare_block_commit on the thread pool.
            let all_receipts: Vec<hyperscale_types::ReceiptBundle> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts.iter().cloned())
                .collect();
            let result = hyperscale_bft::handlers::verify_state_root(
                ctx.storage,
                parent_state_root,
                expected_root,
                &all_receipts,
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
                events: vec![NodeInput::Protocol(ProtocolEvent::BlockRootVerified {
                    kind: hyperscale_core::VerificationKind::StateRoot,
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
            finalized_waves,
            waves,
            provision_batches,
        } => {
            // Extract certificates from finalized waves.
            // No storage reads needed — everything flows through Arc<FinalizedWave>.
            let certificates: Vec<Arc<hyperscale_types::WaveCertificate>> = finalized_waves
                .iter()
                .map(|fw| Arc::clone(&fw.certificate))
                .collect();

            // Collect all receipts from finalized waves.
            // DatabaseUpdates merging happens inside prepare_block_commit.
            let all_receipts: Vec<hyperscale_types::ReceiptBundle> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts.iter().cloned())
                .collect();

            let provision_batch_hashes: Vec<hyperscale_types::Hash> =
                provision_batches.iter().map(|b| b.hash()).collect();

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
                &all_receipts,
                shard_group_id,
                waves,
                provision_batch_hashes,
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
                    finalized_waves,
                })],
                prepared_commit: prepared,
            })
        }

        // --- Execution Vote Aggregation and Verification ---
        Action::AggregateExecutionCertificate {
            wave_id,
            shard,
            global_receipt_root,
            votes,
            committee,
        } => {
            // Aggregate BLS signatures from execution votes into an execution certificate.
            // tx_outcomes extracted from votes by the handler (all quorum votes carry identical outcomes).
            let certificate = hyperscale_execution::handlers::aggregate_execution_certificate(
                &wave_id,
                shard,
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
        // QC was already verified by RemoteHeaderCoordinator; only verkle
        // proofs need checking against the committed header's state root.
        Action::VerifyProvisionBatch {
            batch,
            committed_header,
        } => {
            let merkle_start = std::time::Instant::now();
            let all_valid = {
                let all_entries = batch.all_entries_deduped();
                if all_entries.is_empty() {
                    true
                } else {
                    hyperscale_storage::tree::proofs::verify_proof(
                        &batch.proof,
                        &all_entries,
                        committed_header.header.state_root,
                        |e| &e.storage_key,
                    )
                }
            };
            metrics::record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::StateProvisionsVerified {
                        batch,
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
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            // Engine handles execution + system/shard filtering internally.
            let raw_results: Vec<_> = transactions
                .iter()
                .map(|tx| {
                    hyperscale_engine::handlers::execute_single_shard(
                        ctx.executor,
                        ctx.storage,
                        tx,
                        local_shard,
                        num_shards,
                    )
                })
                .collect();

            let tx_outcomes: Vec<_> = raw_results
                .iter()
                .map(hyperscale_engine::handlers::extract_execution_result)
                .collect();
            let results = raw_results
                .into_iter()
                .map(LocalExecutionEntry::from)
                .collect();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        results,
                        tx_outcomes,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Cross-shard transaction execution ---
        Action::ExecuteCrossShardTransactions { requests } => {
            let local_shard = ctx.topology.local_shard();
            let num_shards = ctx.topology.num_shards();
            let raw_results: Vec<_> = requests
                .iter()
                .map(|req| {
                    hyperscale_engine::handlers::execute_cross_shard(
                        ctx.executor,
                        ctx.storage,
                        req.tx_hash,
                        &req.transaction,
                        &req.provisions,
                        local_shard,
                        num_shards,
                    )
                })
                .collect();

            let tx_outcomes: Vec<_> = raw_results
                .iter()
                .map(hyperscale_engine::handlers::extract_execution_result)
                .collect();
            let results = raw_results
                .into_iter()
                .map(LocalExecutionEntry::from)
                .collect();

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionBatchCompleted {
                        results,
                        tx_outcomes,
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
            // Phase 1: Fetch state entries for all transactions.
            let per_tx = fetch_entries_for_requests(ctx, &requests, source_shard, block_height);
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

            // Phase 2: Group by shard + generate proofs
            let batches =
                build_provision_batches(ctx, per_tx, source_shard, block_height, &shard_recipients);
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

/// Fetch state entries for each provision request at committed block height.
///
/// Expands declared account NodeIds to include their owned vaults before
/// fetching. The remote shard needs vault substates (balances) to execute
/// transfers, not just the account's own substates.
fn fetch_entries_for_requests<S: ChainWriter + SubstateStore + ChainReader>(
    ctx: &ActionContext<'_, S>,
    requests: &[hyperscale_core::ProvisionRequest],
    source_shard: ShardGroupId,
    block_height: hyperscale_types::BlockHeight,
) -> Vec<(
    Hash,
    Vec<ShardGroupId>,
    Arc<Vec<hyperscale_types::StateEntry>>,
)> {
    let mut per_tx = Vec::with_capacity(requests.len());
    for req in requests {
        // Expand account NodeIds to include owned vaults.
        let expanded_nodes =
            hyperscale_engine::sharding::expand_nodes_with_owned(ctx.storage, &req.nodes);
        let entries =
            match ctx
                .executor
                .fetch_state_entries(ctx.storage, &expanded_nodes, block_height.0)
            {
                Some(entries) => entries,
                None => {
                    warn!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        tx_hash = %req.tx_hash,
                        node_count = expanded_nodes.len(),
                        "fetch_state_entries returned None — JVT version unavailable"
                    );
                    continue;
                }
            };
        per_tx.push((req.tx_hash, req.target_shards.clone(), Arc::new(entries)));
    }
    per_tx
}

/// Group fetched entries by target shard and generate verkle proofs per shard.
fn build_provision_batches<S: ChainWriter + SubstateStore + ChainReader>(
    ctx: &ActionContext<'_, S>,
    per_tx: Vec<(
        Hash,
        Vec<ShardGroupId>,
        Arc<Vec<hyperscale_types::StateEntry>>,
    )>,
    source_shard: ShardGroupId,
    block_height: hyperscale_types::BlockHeight,
    shard_recipients: &std::collections::HashMap<ShardGroupId, Vec<hyperscale_types::ValidatorId>>,
) -> Vec<(
    ShardGroupId,
    ProvisionBatch,
    Vec<hyperscale_types::ValidatorId>,
)> {
    use std::collections::HashMap;

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

    let mut sorted_shard_entries: Vec<_> = shard_tx_entries.into_iter().collect();
    sorted_shard_entries.sort_by_key(|(shard, _)| *shard);
    let mut batches = Vec::with_capacity(sorted_shard_entries.len());
    for (shard, transactions) in sorted_shard_entries {
        let mut shard_keys: Vec<Vec<u8>> = transactions
            .iter()
            .flat_map(|te| te.entries.iter().map(|e| e.storage_key.clone()))
            .collect();
        shard_keys.sort();
        shard_keys.dedup();

        let proof = match ctx
            .storage
            .generate_verkle_proofs(&shard_keys, block_height.0)
        {
            Some(p) => p,
            None => {
                warn!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    target_shard = shard.0,
                    key_count = shard_keys.len(),
                    "generate_verkle_proofs returned None — JVT version unavailable"
                );
                continue;
            }
        };

        let recipients = shard_recipients.get(&shard).cloned().unwrap_or_default();
        let batch = ProvisionBatch {
            source_shard,
            block_height,
            proof,
            transactions,
        };
        batches.push((shard, batch, recipients));
    }
    batches
}
