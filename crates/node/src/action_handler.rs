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
use hyperscale_storage::{CommitStore, SubstateStore};
use hyperscale_types::{
    Bls12381G1PrivateKey, ExecutionVote, Hash, ShardGroupId, Topology, ValidatorId,
};
use std::sync::Arc;

/// Context for executing delegated actions.
pub(crate) struct ActionContext<'a, S: CommitStore + SubstateStore, D: Dispatch> {
    pub storage: &'a S,
    pub executor: &'a RadixExecutor,
    pub topology: &'a dyn Topology,
    pub signing_key: &'a Bls12381G1PrivateKey,
    pub local_shard: ShardGroupId,
    pub validator_id: ValidatorId,
    pub dispatch: &'a D,
}

/// Result of handling a delegated action.
pub(crate) struct DelegatedResult<P: Send> {
    /// Events to deliver to the state machine.
    pub events: Vec<NodeInput>,
    /// Prepared commit handle to cache (block_hash -> handle).
    pub prepared_commit: Option<(Hash, P)>,
}

/// Which dispatch pool an action should run on in production.
pub(crate) enum DispatchPool {
    /// Liveness-critical consensus crypto (QC, state root, proposal).
    ConsensusCrypto,
    /// General crypto verification (cert aggregation, provisions).
    Crypto,
    /// Transaction execution (single-shard, merkle).
    Execution,
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
        Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto
        Action::AggregateExecutionCertificate { .. } => Some(DispatchPool::Crypto),
        Action::VerifyStateProvisions { .. } => Some(DispatchPool::Crypto),

        // Execution
        Action::ExecuteTransactions { .. } => Some(DispatchPool::Execution),
        Action::SpeculativeExecute { .. } => Some(DispatchPool::Execution),
        Action::FetchAndBroadcastProvisions { .. } => Some(DispatchPool::Execution),
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
pub(crate) fn handle_delegated_action<S: CommitStore + SubstateStore, D: Dispatch>(
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

        // --- BFT state root and proposal ---
        Action::VerifyStateRoot {
            block_hash,
            parent_state_root,
            expected_root,
            certificates,
        } => {
            let start = std::time::Instant::now();
            let result = hyperscale_bft::handlers::verify_state_root(
                ctx.storage,
                parent_state_root,
                expected_root,
                &certificates,
                ctx.local_shard,
            );
            metrics::record_signature_verification_latency(
                "state_root",
                start.elapsed().as_secs_f64(),
            );
            let prepared = result.prepared_commit.map(|p| (block_hash, p));
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
            parent_state_version,
            retry_transactions,
            priority_transactions,
            transactions,
            certificates,
            commitment_proofs,
            deferred,
            aborted,
            provision_targets,
        } => {
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
                parent_state_version,
                retry_transactions,
                priority_transactions,
                transactions,
                certificates,
                commitment_proofs,
                deferred,
                aborted,
                shard_group_id,
                provision_targets,
            );
            let prepared = result.prepared_commit.map(|p| (result.block_hash, p));
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
            writes_commitment,
            votes,
            read_nodes,
            committee_size,
        } => {
            let certificate = hyperscale_execution::handlers::aggregate_execution_certificate(
                tx_hash,
                shard,
                writes_commitment,
                &votes,
                read_nodes,
                committee_size,
                ctx.topology,
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

            // Check merkle proofs per provision against the verified header's state root.
            let merkle_start = std::time::Instant::now();
            let valid_flags: Vec<bool> = ctx.dispatch.map_crypto(&provisions, |provision| {
                verified_header.as_ref().is_some_and(|header| {
                    hyperscale_storage::proofs::verify_all_merkle_proofs(
                        &provision.entries,
                        &provision.merkle_proofs,
                        header.header.state_root,
                    )
                })
            });
            let results: Vec<ProvisionVerificationResult> = provisions
                .into_iter()
                .zip(valid_flags)
                .map(|(provision, valid)| ProvisionVerificationResult {
                    tx_hash: provision.transaction_hash,
                    source_shard: provision.source_shard,
                    valid,
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
            let votes: Vec<ExecutionVote> = ctx.dispatch.map_execution(&transactions, |tx| {
                hyperscale_execution::handlers::execute_and_sign_single_shard(
                    ctx.executor,
                    ctx.storage,
                    tx,
                    ctx.signing_key,
                    ctx.local_shard,
                    ctx.validator_id,
                )
            });

            let events = votes
                .into_iter()
                .map(|vote| NodeInput::Protocol(ProtocolEvent::ExecutionVoteReceived { vote }))
                .collect();

            Some(DelegatedResult {
                events,
                prepared_commit: None,
            })
        }

        Action::SpeculativeExecute {
            block_hash,
            transactions,
        } => {
            let votes: Vec<ExecutionVote> = ctx.dispatch.map_execution(&transactions, |tx| {
                hyperscale_execution::handlers::execute_and_sign_single_shard(
                    ctx.executor,
                    ctx.storage,
                    tx,
                    ctx.signing_key,
                    ctx.local_shard,
                    ctx.validator_id,
                )
            });

            let tx_hashes: Vec<Hash> = votes.iter().map(|v| v.transaction_hash).collect();
            let mut events: Vec<NodeInput> = votes
                .into_iter()
                .map(|vote| NodeInput::Protocol(ProtocolEvent::ExecutionVoteReceived { vote }))
                .collect();
            events.push(NodeInput::Protocol(
                ProtocolEvent::SpeculativeExecutionComplete {
                    block_hash,
                    tx_hashes,
                },
            ));

            Some(DelegatedResult {
                events,
                prepared_commit: None,
            })
        }

        // --- Provision fetch + broadcast ---
        Action::FetchAndBroadcastProvisions {
            requests,
            source_shard,
            block_height,
            block_timestamp,
            state_version,
        } => {
            use hyperscale_types::StateProvision;
            use std::collections::HashMap;

            let mut batches: HashMap<ShardGroupId, Vec<StateProvision>> = HashMap::new();

            for req in requests {
                // Fetch state entries from storage at the block's state version.
                // This is the proactive path — the proposer just committed this
                // block, so the state version must still be available.
                let entries = ctx
                    .executor
                    .fetch_state_entries(ctx.storage, &req.nodes, state_version)
                    .expect("proactive provision path: state version must be available");
                let storage_keys: Vec<Vec<u8>> =
                    entries.iter().map(|e| e.storage_key.clone()).collect();
                let merkle_proofs = ctx
                    .storage
                    .generate_merkle_proofs(&storage_keys, state_version);

                assert_eq!(
                    entries.len(),
                    merkle_proofs.len(),
                    "entries and merkle_proofs must have the same length"
                );

                // Wrap in Arc for efficient sharing across target shards
                let entries = Arc::new(entries);
                let merkle_proofs = Arc::new(merkle_proofs);

                // Build a provision per target shard
                for &target_shard in &req.target_shards {
                    let provision = StateProvision {
                        transaction_hash: req.tx_hash,
                        target_shard,
                        source_shard,
                        block_height,
                        block_timestamp,
                        state_version,
                        entries: Arc::clone(&entries),
                        merkle_proofs: Arc::clone(&merkle_proofs),
                    };
                    batches.entry(target_shard).or_default().push(provision);
                }
            }

            let batches: Vec<_> = batches.into_iter().collect();
            Some(DelegatedResult {
                events: vec![NodeInput::ProvisionsReady { batches }],
                prepared_commit: None,
            })
        }

        _ => None,
    }
}
