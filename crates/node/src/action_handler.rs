//! Action handler for immediately-dispatched computation.
//!
//! [`handle_delegated_action`] bridges individual [`Action`] variants to pure
//! computation (crypto verification, execution, proposal building). The node
//! loop's `dispatch_delegated_action` spawns closures that call this function
//! on the appropriate thread pool.
//!
//! Batched work (execution votes, execution certs, cross-shard execution) and block
//! commits are handled inline by the I/O loop's flush closures.

use hyperscale_core::{Action, NodeInput, ProtocolEvent, ProvisionVerificationResult};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::RadixExecutor;
use hyperscale_metrics as metrics;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::{
    Bls12381G1PrivateKey, ExecutionResult, ExecutionVote, Hash, ShardGroupId, ValidatorId,
};
use std::sync::Arc;

/// Context for executing delegated actions.
pub(crate) struct ActionContext<'a, S: CommitStore + SubstateStore + ConsensusStore, D: Dispatch> {
    pub storage: &'a S,
    pub executor: &'a RadixExecutor,
    pub signing_key: &'a Bls12381G1PrivateKey,
    pub local_shard: ShardGroupId,
    pub num_shards: u64,
    pub validator_id: ValidatorId,
    pub dispatch: &'a D,
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
        Action::VerifyCommitmentProof { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyStateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyTransactionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyReceiptRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto
        Action::AggregateExecutionCertificate { .. } => Some(DispatchPool::Crypto),

        // Provision work: IPA proof generation and verification.
        // Dedicated pool to avoid starving execution and crypto work.
        Action::VerifyStateProvisions { .. } => Some(DispatchPool::Provisions),
        Action::FetchAndBroadcastProvisions { .. } => Some(DispatchPool::Provisions),

        // Execution
        Action::ExecuteTransactions { .. } => Some(DispatchPool::Execution),
        Action::SpeculativeExecute { .. } => Some(DispatchPool::Execution),
        _ => None,
    }
}

/// Handle a delegated action using the shared pure functions.
///
/// Returns `None` for non-delegated actions (timers, broadcasts, persist, etc.)
/// that the runner must handle directly.
///
/// For execution actions (`ExecuteTransactions`, `SpeculativeExecute`), the
/// returned events include `ProtocolEvent::ExecutionVoteReceived` for each vote.
/// The runner is responsible for additionally broadcasting votes to shard
/// peers (network-specific).
#[allow(clippy::too_many_lines)]
pub(crate) fn handle_delegated_action<
    S: CommitStore + SubstateStore + ConsensusStore,
    D: Dispatch,
>(
    action: Action,
    ctx: &ActionContext<'_, S, D>,
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

        Action::VerifyCommitmentProof {
            block_hash,
            deferral_index,
            commitment_proof,
            public_keys,
            voting_power,
            quorum_threshold,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_commitment_proof(
                &commitment_proof,
                &public_keys,
                voting_power,
                quorum_threshold,
            );
            metrics::record_signature_verification_latency(
                "commitment_proof",
                start.elapsed().as_secs_f64(),
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::CommitmentProofVerified {
                        block_hash,
                        deferral_index,
                        valid,
                    },
                )],
                prepared_commit: None,
            })
        }

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            retry_transactions,
            priority_transactions,
            transactions,
        } => {
            let start = std::time::Instant::now();
            let valid = hyperscale_bft::handlers::verify_transaction_root(
                expected_root,
                &retry_transactions,
                &priority_transactions,
                &transactions,
            );
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
            retry_transactions,
            priority_transactions,
            transactions,
            certificates,
            per_cert_updates,
            commitment_proofs,
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
                retry_transactions,
                priority_transactions,
                transactions,
                certificates,
                merged_updates,
                commitment_proofs,
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

        // --- Execution aggregation and verification ---
        Action::AggregateExecutionCertificate {
            tx_hash,
            shard,
            receipt_hash,
            votes,
            read_nodes,
            write_nodes,
            committee,
        } => {
            let certificate = hyperscale_execution::handlers::aggregate_execution_certificate(
                tx_hash,
                shard,
                receipt_hash,
                &votes,
                read_nodes,
                write_nodes,
                &committee,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ExecutionCertificateAggregated {
                        tx_hash,
                        certificate,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- State Provision Batch Verification ---
        Action::VerifyStateProvisions {
            provisions,
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

            eprintln!(
                "[VERIFY] START provisions={} qc_ms={}",
                provisions.len(),
                qc_start.elapsed().as_millis()
            );

            // Verify merkle proofs against the verified header's state root.
            // All provisions from the same block share a single batched proof,
            // so we collect all entries and verify once instead of N times.
            let merkle_start = std::time::Instant::now();
            let all_valid = verified_header.as_ref().is_some_and(|header| {
                // Collect all entries across all provisions, then sort+dedupe by
                // storage_key to match the order used during proof generation.
                let mut all_entries: Vec<hyperscale_types::StateEntry> = provisions
                    .iter()
                    .flat_map(|p| p.entries.iter().cloned())
                    .collect();
                if all_entries.is_empty() {
                    return true;
                }
                all_entries.sort_by(|a, b| a.storage_key.cmp(&b.storage_key));
                all_entries.dedup_by(|a, b| a.storage_key == b.storage_key);
                // Use the proof from the first provision (all share the same Arc).
                hyperscale_storage::proofs::verify_all_merkle_proofs(
                    &all_entries,
                    &provisions[0].proof,
                    header.header.state_root,
                )
            });
            eprintln!(
                "[VERIFY] DONE valid={} verify_ms={} provisions={}",
                all_valid,
                merkle_start.elapsed().as_millis(),
                provisions.len()
            );
            let results: Vec<ProvisionVerificationResult> = provisions
                .into_iter()
                .map(|provision| ProvisionVerificationResult {
                    tx_hash: provision.transaction_hash,
                    source_shard: provision.source_shard,
                    valid: all_valid,
                    provision,
                })
                .collect();
            metrics::record_signature_verification_latency(
                "inclusion_proof",
                merkle_start.elapsed().as_secs_f64(),
            );

            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::StateProvisionsVerified {
                        results,
                        committed_header: verified_header,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Transaction execution ---
        // NOTE: The returned events include ExecutionVoteReceived for each vote.
        // The runner must additionally broadcast votes to shard peers (network-specific).
        Action::ExecuteTransactions {
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let local_shard = ctx.local_shard;
            let num_shards = ctx.num_shards;
            let pairs = ctx.dispatch.map_local(&transactions, |tx| {
                hyperscale_execution::handlers::execute_and_sign_single_shard(
                    ctx.executor,
                    ctx.storage,
                    tx,
                    ctx.signing_key,
                    ctx.local_shard,
                    ctx.validator_id,
                )
            });

            let (votes, results): (Vec<ExecutionVote>, Vec<_>) = pairs.into_iter().unzip();
            let results = results
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
                        votes,
                        results,
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
            let pairs = ctx.dispatch.map_local(&transactions, |tx| {
                hyperscale_execution::handlers::execute_and_sign_single_shard(
                    ctx.executor,
                    ctx.storage,
                    tx,
                    ctx.signing_key,
                    ctx.local_shard,
                    ctx.validator_id,
                )
            });

            let (votes, results): (Vec<ExecutionVote>, Vec<_>) = pairs.into_iter().unzip();
            let results = results
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
            let tx_hashes: Vec<Hash> = votes.iter().map(|v| v.transaction_hash).collect();

            Some(DelegatedResult {
                events: vec![
                    NodeInput::Protocol(ProtocolEvent::ExecutionBatchCompleted {
                        votes,
                        results,
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

        // --- Provision fetch + broadcast ---
        Action::FetchAndBroadcastProvisions {
            requests,
            source_shard,
            block_height,
            block_timestamp,
            shard_recipients,
        } => {
            use hyperscale_types::StateProvision;
            use std::collections::HashMap;

            let proactive_start = std::time::Instant::now();
            eprintln!(
                "[PROACTIVE] START height={} requests={} shard={}",
                block_height.0,
                requests.len(),
                source_shard.0
            );

            // Phase 1: Fetch state entries for all transactions.
            let mut per_tx: Vec<(
                Hash,
                Vec<ShardGroupId>,
                Arc<Vec<hyperscale_types::StateEntry>>,
            )> = Vec::with_capacity(requests.len());
            let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

            let fetch_start = std::time::Instant::now();
            for req in &requests {
                let entries =
                    match ctx
                        .executor
                        .fetch_state_entries(ctx.storage, &req.nodes, block_height.0)
                    {
                        Some(entries) => entries,
                        None => {
                            eprintln!(
                                "[PROACTIVE] fetch_state_entries FAILED height={} tx={:?}",
                                block_height.0, req.tx_hash
                            );
                            continue;
                        }
                    };
                for e in &entries {
                    all_storage_keys.push(e.storage_key.clone());
                }
                per_tx.push((req.tx_hash, req.target_shards.clone(), Arc::new(entries)));
            }
            let fetch_ms = fetch_start.elapsed().as_millis();
            eprintln!(
                "[PROACTIVE] phase1 fetch done: height={} txs={} keys={} fetch_ms={}",
                block_height.0,
                per_tx.len(),
                all_storage_keys.len(),
                fetch_ms
            );

            if per_tx.is_empty() {
                eprintln!("[PROACTIVE] no entries, returning empty");
                return Some(DelegatedResult {
                    events: vec![NodeInput::ProvisionsReady { batches: vec![] }],
                    prepared_commit: None,
                });
            }

            // Skip proof generation if we've been queued too long — the provisions
            // would arrive stale and the target shard will use fallback anyway.
            let queued_ms = proactive_start.elapsed().as_millis();
            if queued_ms > 5000 {
                eprintln!(
                    "[PROACTIVE] SKIPPING height={} — queued {}ms, too stale",
                    block_height.0, queued_ms
                );
                return Some(DelegatedResult {
                    events: vec![NodeInput::ProvisionsReady { batches: vec![] }],
                    prepared_commit: None,
                });
            }

            // Phase 2: Generate ONE batched proof covering all entries across all transactions.
            all_storage_keys.sort();
            all_storage_keys.dedup();
            let proof_start = std::time::Instant::now();
            let proof = match ctx
                .storage
                .generate_merkle_proofs(&all_storage_keys, block_height.0)
            {
                Some(p) => Arc::new(p),
                None => {
                    eprintln!(
                        "[PROACTIVE] proof generation FAILED height={}",
                        block_height.0
                    );
                    return Some(DelegatedResult {
                        events: vec![NodeInput::ProvisionsReady { batches: vec![] }],
                        prepared_commit: None,
                    });
                }
            };
            let proof_ms = proof_start.elapsed().as_millis();
            eprintln!(
                "[PROACTIVE] phase2 proof done: height={} unique_keys={} proof_ms={} total_ms={}",
                block_height.0,
                all_storage_keys.len(),
                proof_ms,
                proactive_start.elapsed().as_millis()
            );

            // Phase 3: Build provisions sharing the single proof.
            let mut batches: HashMap<ShardGroupId, Vec<StateProvision>> = HashMap::new();
            for (tx_hash, target_shards, entries) in per_tx {
                for &target_shard in &target_shards {
                    let provision = StateProvision {
                        transaction_hash: tx_hash,
                        target_shard,
                        source_shard,
                        block_height,
                        block_timestamp,
                        entries: Arc::clone(&entries),
                        proof: Arc::clone(&proof),
                    };
                    batches.entry(target_shard).or_default().push(provision);
                }
            }

            let batches: Vec<_> = batches
                .into_iter()
                .map(|(shard, provisions)| {
                    let recipients = shard_recipients.get(&shard).cloned().unwrap_or_default();
                    (shard, provisions, recipients)
                })
                .collect();
            Some(DelegatedResult {
                events: vec![NodeInput::ProvisionsReady { batches }],
                prepared_commit: None,
            })
        }

        _ => None,
    }
}
