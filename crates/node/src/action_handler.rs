//! Action handler for immediately-dispatched computation.
//!
//! [`handle_delegated_action`] bridges individual [`Action`] variants to pure
//! computation (crypto verification, execution, proposal building). The node
//! loop's `dispatch_delegated_action` spawns closures that call this function
//! on the appropriate thread pool.
//!
//! Batched work (state votes, state certs, cross-shard execution) and block
//! commits are handled inline by the node loop's flush closures.

use hyperscale_core::{Action, NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::RadixExecutor;
use hyperscale_storage::{CommitStore, SubstateStore};
use hyperscale_types::{
    Bls12381G1PrivateKey, Hash, ShardGroupId, StateVoteBlock, Topology, ValidatorId,
};
use std::sync::Arc;

/// Context for executing delegated actions.
pub struct ActionContext<'a, S: CommitStore + SubstateStore, D: Dispatch> {
    pub storage: &'a S,
    pub executor: &'a RadixExecutor,
    pub topology: &'a dyn Topology,
    pub signing_key: &'a Bls12381G1PrivateKey,
    pub local_shard: ShardGroupId,
    pub validator_id: ValidatorId,
    pub dispatch: &'a D,
}

/// Result of handling a delegated action.
pub struct DelegatedResult<P: Send> {
    /// Events to deliver to the state machine.
    pub events: Vec<NodeInput>,
    /// Prepared commit handle to cache (block_hash -> handle).
    pub prepared_commit: Option<(Hash, P)>,
}

/// Which dispatch pool an action should run on in production.
pub enum DispatchPool {
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
pub fn dispatch_pool_for(action: &Action) -> Option<DispatchPool> {
    match action {
        // Consensus-critical crypto
        Action::VerifyAndBuildQuorumCertificate { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyQcSignature { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyCycleProof { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyStateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyTransactionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto
        Action::AggregateStateCertificate { .. } => Some(DispatchPool::Crypto),
        Action::VerifyAndAggregateProvisions { .. } => Some(DispatchPool::Crypto),

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
/// returned events include `ProtocolEvent::StateVoteReceived` for each vote.
/// The runner is responsible for additionally broadcasting votes to shard
/// peers (network-specific).
#[allow(clippy::too_many_lines)]
pub fn handle_delegated_action<S: CommitStore + SubstateStore, D: Dispatch>(
    action: Action,
    ctx: &ActionContext<'_, S, D>,
) -> Option<DelegatedResult<S::PreparedCommit>> {
    match action {
        // --- BFT crypto verification ---
        Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            height,
            round,
            parent_block_hash,
            signing_message,
            votes_to_verify,
            verified_votes,
            total_voting_power,
        } => {
            let result = hyperscale_bft::handlers::verify_and_build_qc(
                block_hash,
                height,
                round,
                parent_block_hash,
                &signing_message,
                votes_to_verify,
                verified_votes,
                total_voting_power,
            );
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
            signing_message,
        } => {
            let valid =
                hyperscale_bft::handlers::verify_qc_signature(&qc, &public_keys, &signing_message);
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::QcSignatureVerified {
                    block_hash,
                    valid,
                })],
                prepared_commit: None,
            })
        }

        Action::VerifyCycleProof {
            block_hash,
            deferral_index,
            cycle_proof,
            public_keys,
            signing_message,
            quorum_threshold,
        } => {
            let valid = hyperscale_bft::handlers::verify_cycle_proof(
                &cycle_proof,
                &public_keys,
                &signing_message,
                quorum_threshold,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(ProtocolEvent::CycleProofVerified {
                    block_hash,
                    deferral_index,
                    valid,
                })],
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
            let valid = hyperscale_bft::handlers::verify_transaction_root(
                expected_root,
                &retry_transactions,
                &priority_transactions,
                &transactions,
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
            let result = hyperscale_bft::handlers::verify_state_root(
                ctx.storage,
                parent_state_root,
                expected_root,
                &certificates,
                ctx.local_shard,
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
                ctx.local_shard,
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
        Action::AggregateStateCertificate {
            tx_hash,
            shard,
            writes_commitment,
            votes,
            read_nodes,
            voting_power,
            committee_size,
        } => {
            let certificate = hyperscale_execution::handlers::aggregate_state_certificate(
                tx_hash,
                shard,
                writes_commitment,
                &votes,
                read_nodes,
                voting_power,
                committee_size,
                ctx.topology,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::StateCertificateAggregated {
                        tx_hash,
                        certificate,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Provisions ---
        Action::VerifyAndAggregateProvisions {
            tx_hash,
            source_shard,
            block_height,
            block_timestamp,
            entries,
            provisions,
            public_keys,
            committee_size,
        } => {
            let result = hyperscale_provisions::handlers::verify_and_aggregate_provisions(
                tx_hash,
                source_shard,
                block_height,
                block_timestamp,
                entries,
                provisions,
                &public_keys,
                committee_size,
                ctx.topology,
            );
            Some(DelegatedResult {
                events: vec![NodeInput::Protocol(
                    ProtocolEvent::ProvisionsVerifiedAndAggregated {
                        tx_hash,
                        source_shard,
                        verified_provisions: result.verified_provisions,
                        commitment_proof: result.commitment_proof,
                    },
                )],
                prepared_commit: None,
            })
        }

        // --- Transaction execution ---
        // NOTE: The returned events include StateVoteReceived for each vote.
        // The runner must additionally broadcast votes to shard peers (network-specific).
        Action::ExecuteTransactions {
            block_hash: _,
            transactions,
            state_root: _,
        } => {
            let votes: Vec<StateVoteBlock> = ctx.dispatch.map_execution(&transactions, |tx| {
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
                .map(|vote| NodeInput::Protocol(ProtocolEvent::StateVoteReceived { vote }))
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
            let votes: Vec<StateVoteBlock> = ctx.dispatch.map_execution(&transactions, |tx| {
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
                .map(|vote| NodeInput::Protocol(ProtocolEvent::StateVoteReceived { vote }))
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

        _ => None,
    }
}
