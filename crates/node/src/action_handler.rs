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
use hyperscale_types::{Hash, LocalExecutionEntry, Provision, ShardGroupId, TxEntries};
use std::sync::Arc;
use tracing::warn;

/// Context for executing delegated actions.
pub(crate) struct ActionContext<
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
pub(crate) struct DelegatedResult<P: Send> {
    /// Events to deliver to the state machine.
    pub events: Vec<NodeInput>,
    /// Prepared commit + receipts to cache.
    ///
    /// Receipts travel alongside the prepared handle so the io_loop can
    /// build a `ChainEntry` and insert into `PendingChain` in one step
    /// — eliminating the prior separate `db_updates` plumbing that was
    /// always produced together with `prepared_commit` anyway.
    pub prepared_commit: Option<PreparedBlock<P>>,
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
pub(crate) struct PreparedBlock<P: Send> {
    pub block_hash: Hash,
    pub block_height: u64,
    pub prepared: P,
    pub receipts: Vec<Arc<hyperscale_types::LocalReceipt>>,
}

/// Which dispatch pool an action should run on in production.
pub(crate) enum DispatchPool {
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
pub(crate) fn dispatch_pool_for(action: &Action) -> Option<DispatchPool> {
    match action {
        // Consensus-critical crypto + state root computation
        Action::VerifyAndBuildQuorumCertificate { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyQcSignature { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyRemoteHeaderQc { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyTransactionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyProvisionRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyCertificateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyLocalReceiptRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyProvisionTxRoots { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::VerifyStateRoot { .. } => Some(DispatchPool::ConsensusCrypto),
        Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto (cert aggregation, provision proofs)
        Action::AggregateExecutionCertificate { .. } => Some(DispatchPool::Crypto),
        Action::VerifyAndAggregateExecutionVotes { .. } => Some(DispatchPool::Crypto),
        Action::VerifyExecutionCertificateSignature { .. } => Some(DispatchPool::Crypto),
        Action::VerifyProvision { .. } => Some(DispatchPool::Crypto),
        Action::FetchAndBroadcastProvision { .. } => Some(DispatchPool::Crypto),

        // Execution
        Action::ExecuteTransactions { .. } => Some(DispatchPool::Execution),
        Action::ExecuteCrossShardTransactions { .. } => Some(DispatchPool::Execution),
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
pub(crate) fn parent_hash_for(action: &Action) -> Option<Hash> {
    match action {
        Action::VerifyStateRoot {
            parent_block_hash, ..
        } => Some(*parent_block_hash),
        Action::BuildProposal { parent_hash, .. } => Some(*parent_hash),
        Action::ExecuteTransactions { block_hash, .. } => Some(*block_hash),
        Action::ExecuteCrossShardTransactions { block_hash, .. } => Some(*block_hash),
        Action::FetchAndBroadcastProvision { block_hash, .. } => Some(*block_hash),
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
pub(crate) fn handle_delegated_action<
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
            let valid =
                hyperscale_bft::handlers::verify_provision_root(expected_root, &batch_hashes);
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
            provision_batches,
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
                provision_batches.clone(),
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
                block_height: height.0,
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
                    provisions: provision_batches,
                })],
                prepared_commit,
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
        // QC was already verified by RemoteHeaderCoordinator; only merkle
        // proofs need checking against the committed header's state root.
        Action::VerifyProvision {
            batch,
            committed_header,
        } => {
            let merkle_start = std::time::Instant::now();
            let all_valid = {
                let all_entries = batch.all_entries_deduped();
                if all_entries.is_empty() {
                    true
                } else {
                    let valid = hyperscale_storage::tree::proofs::verify_proof(
                        &batch.proof,
                        &all_entries,
                        committed_header.header.state_root,
                        |e| &e.storage_key,
                    );
                    if !valid {
                        tracing::warn!(
                            source_shard = batch.source_shard.0,
                            block_height = batch.block_height.0,
                            header_height = committed_header.header.height.0,
                            header_state_root = ?committed_header.header.state_root,
                            entry_count = all_entries.len(),
                            proof_len = batch.proof.as_bytes().len(),
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
                events: vec![NodeInput::Protocol(ProtocolEvent::StateProvisionVerified {
                    batch,
                    committed_header: Some(committed_header),
                    valid: all_valid,
                })],
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
                    events: vec![NodeInput::ProvisionReady { batches: vec![] }],
                    prepared_commit: None,
                });
            }

            // Phase 2: Group by shard + generate proofs
            let batches =
                build_provision_batches(ctx, per_tx, source_shard, block_height, &shard_recipients);
            Some(DelegatedResult {
                events: vec![NodeInput::ProvisionReady { batches }],
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
/// Per-tx fetched entries: (tx_hash, target_shards_with_nodes, state_entries).
type FetchedTxEntries = (
    Hash,
    Vec<(ShardGroupId, Vec<hyperscale_types::NodeId>)>,
    Arc<Vec<hyperscale_types::StateEntry>>,
);

fn fetch_entries_for_requests<
    S: ChainWriter + SubstateStore + hyperscale_storage::VersionedStore + ChainReader,
    E: Engine,
>(
    ctx: &ActionContext<'_, S, E>,
    requests: &[hyperscale_core::ProvisionRequest],
    source_shard: ShardGroupId,
    block_height: hyperscale_types::BlockHeight,
) -> Vec<FetchedTxEntries> {
    let mut per_tx = Vec::with_capacity(requests.len());
    for req in requests {
        // Expand account NodeIds to include owned vaults at the committed block height.
        // Must use historical reads — current state may have new vaults that don't
        // exist at block_height, causing the merkle proof to fail on the remote shard.
        let expanded_nodes = match hyperscale_engine::sharding::expand_nodes_with_owned_at_height(
            &*ctx.view,
            &req.nodes,
            block_height.0,
        ) {
            Some(nodes) => nodes,
            None => {
                warn!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    tx_hash = %req.tx_hash,
                    "expand_nodes_with_owned_at_height: JMT version unavailable"
                );
                continue;
            }
        };
        let entries =
            match ctx
                .executor
                .fetch_state_entries(&*ctx.view, &expanded_nodes, block_height.0)
            {
                Some(entries) => entries,
                None => {
                    warn!(
                        source_shard = source_shard.0,
                        block_height = block_height.0,
                        tx_hash = %req.tx_hash,
                        node_count = expanded_nodes.len(),
                        "fetch_state_entries returned None — JMT version unavailable"
                    );
                    continue;
                }
            };
        per_tx.push((req.tx_hash, req.targets.clone(), Arc::new(entries)));
    }
    per_tx
}

/// Group fetched entries by target shard and generate merkle proofs per shard.
fn build_provision_batches<
    S: ChainWriter
        + SubstateStore
        + hyperscale_storage::VersionedStore
        + ChainReader
        + hyperscale_storage::JmtTreeReader
        + Sync,
    E: Engine,
>(
    ctx: &ActionContext<'_, S, E>,
    per_tx: Vec<FetchedTxEntries>,
    source_shard: ShardGroupId,
    block_height: hyperscale_types::BlockHeight,
    shard_recipients: &std::collections::HashMap<ShardGroupId, Vec<hyperscale_types::ValidatorId>>,
) -> Vec<(ShardGroupId, Provision, Vec<hyperscale_types::ValidatorId>)> {
    use std::collections::HashMap;

    let mut shard_tx_entries: HashMap<ShardGroupId, Vec<TxEntries>> = HashMap::new();
    for (tx_hash, targets, entries) in per_tx {
        for (target_shard, target_nodes) in targets {
            shard_tx_entries
                .entry(target_shard)
                .or_default()
                .push(TxEntries {
                    tx_hash,
                    entries: (*entries).clone(),
                    target_nodes,
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
            .view
            .generate_merkle_proofs_overlay(&shard_keys, block_height.0)
        {
            Some(p) => p,
            None => {
                warn!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    target_shard = shard.0,
                    key_count = shard_keys.len(),
                    "generate_merkle_proofs returned None — JMT version unavailable"
                );
                continue;
            }
        };

        let recipients = shard_recipients.get(&shard).cloned().unwrap_or_default();
        let batch = Provision::new(source_shard, block_height, proof, transactions);
        batches.push((shard, batch, recipients));
    }
    batches
}
