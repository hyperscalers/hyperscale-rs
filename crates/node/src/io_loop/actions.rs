//! Action processing and dispatch.

use super::{IoLoop, TimerOp};
use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::protocol::fetch::FetchInput;
use crate::protocol::provision_fetch::ProvisionFetchInput;
use crate::protocol::sync::SyncInput;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::ValidatorId;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{debug, trace};

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action from the state machine.
    pub(super) fn process_action(&mut self, action: Action) {
        match action {
            // ═══════════════════════════════════════════════════════════
            // Timers
            // ═══════════════════════════════════════════════════════════
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set { id, duration });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { id });
            }

            // ═══════════════════════════════════════════════════════════
            // Internal events
            // ═══════════════════════════════════════════════════════════
            Action::Continuation(pe) => {
                let _ = self.event_sender.send(NodeInput::Protocol(pe));
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — immediate (non-batched)
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastBlockHeader { shard: _, header } => {
                self.network.notify(&self.cached_local_peers, &*header);
            }
            Action::BroadcastBlockVote { shard: _, vote } => {
                self.network.notify(&self.cached_local_peers, &vote);
            }
            Action::BroadcastTransaction { shard, gossip } => {
                self.network.broadcast_to_shard(shard, &*gossip);
            }
            Action::BroadcastCommittedBlockHeader { gossip } => {
                self.network.broadcast_global(&gossip);
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — batched
            // ═══════════════════════════════════════════════════════════
            Action::SignAndBroadcastWaveVote {
                block_hash,
                block_height,
                wave_id,
                wave_receipt_root,
                tx_count,
                tx_outcomes: _,          // TODO: stash for later cert aggregation
                participating_shards: _, // TODO: stash for later cert broadcast
            } => {
                // Sign the wave vote inline (BLS signing is fast, ~1ms)
                let msg = hyperscale_types::exec_wave_vote_message(
                    &block_hash,
                    block_height,
                    &wave_id,
                    self.local_shard,
                    &wave_receipt_root,
                    tx_count,
                );
                let sig = self.signing_key.sign_v1(&msg);
                let vote = hyperscale_types::ExecutionWaveVote {
                    block_hash,
                    block_height,
                    wave_id,
                    shard_group_id: self.local_shard,
                    wave_receipt_root,
                    tx_count,
                    validator: self.validator_id,
                    signature: sig,
                };

                // Send immediately — wave is the batch, no accumulator needed
                let batch_msg = hyperscale_types::exec_wave_vote_batch_message(
                    self.local_shard,
                    std::slice::from_ref(&vote),
                );
                let batch_sig = self.signing_key.sign_v1(&batch_msg);
                let batch = hyperscale_messages::ExecutionWaveVotesNotification::new(
                    vec![vote.clone()],
                    self.validator_id,
                    batch_sig,
                );
                self.network.notify(&self.cached_local_peers, &batch);

                // Also feed our own wave vote back to the state machine for tracking
                let _ = self.event_sender.send(hyperscale_core::NodeInput::Protocol(
                    hyperscale_core::ProtocolEvent::ExecutionWaveVoteReceived { vote },
                ));
            }
            Action::BroadcastExecutionWaveVote { shard, vote } => {
                // Wave votes are already batched by wave — send immediately, no accumulator.
                let msg = hyperscale_types::exec_wave_vote_batch_message(
                    shard,
                    std::slice::from_ref(&vote),
                );
                let sig = self.signing_key.sign_v1(&msg);
                let batch = hyperscale_messages::ExecutionWaveVotesNotification::new(
                    vec![vote],
                    self.validator_id,
                    sig,
                );
                self.network.notify(&self.cached_local_peers, &batch);
            }
            Action::BroadcastExecutionWaveCertificate {
                shard: _,
                certificate,
                recipients,
            } => {
                // Wave certs are already batched by wave — send immediately, no accumulator.
                let cert = std::sync::Arc::unwrap_or_clone(certificate);
                let msg = hyperscale_types::exec_wave_cert_batch_message(
                    cert.shard_group_id,
                    std::slice::from_ref(&cert),
                );
                let sig = self.signing_key.sign_v1(&msg);
                let batch = hyperscale_messages::ExecutionWaveCertificatesNotification::new(
                    vec![cert],
                    self.validator_id,
                    sig,
                );
                self.network.notify(&recipients, &batch);
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — batched (accumulated for batch dispatch)
            // ═══════════════════════════════════════════════════════════
            // Wave delegated actions — dispatch immediately (same as AggregateExecutionCertificate)
            Action::AggregateExecutionWaveCertificate { .. }
            | Action::VerifyAndAggregateExecutionWaveVotes { .. }
            | Action::VerifyExecutionWaveCertificateSignature { .. } => {
                self.dispatch_delegated_action(action);
            }
            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                self.accumulate_cross_shard_execution(tx_hash, transaction, provisions);
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated work — immediate dispatch
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyReceiptRoot { .. }
            | Action::BuildProposal { .. }
            | Action::VerifyProvisionBatch { .. }
            | Action::ExecuteTransactions { .. }
            | Action::SpeculativeExecute { .. }
            | Action::FetchAndBroadcastProvisions { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Receipt storage — accumulated and flushed async
            // ═══════════════════════════════════════════════════════════
            Action::StoreReceiptBundles { bundles } => {
                debug!(
                    count = bundles.len(),
                    tx_hashes = ?bundles.iter().map(|b| b.tx_hash).collect::<Vec<_>>(),
                    "Receipt bundles queued for storage"
                );
                self.pending_receipt_bundles.extend(bundles);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage
            // ═══════════════════════════════════════════════════════════
            Action::PersistBlock { .. }
            | Action::PersistTransactionCertificate { .. }
            | Action::PersistAndBroadcastVote { .. }
            | Action::FetchBlock { .. }
            | Action::FetchChainMetadata => {
                self.process_storage_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Block commit + notifications
            // ═══════════════════════════════════════════════════════════
            Action::EmitCommittedBlock { block, qc } => {
                self.accumulate_block_commit(block, qc);
            }
            Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally,
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                if status.is_final() && submitted_locally {
                    let now = self.state.now();
                    let latency_secs = now.saturating_sub(added_at).as_secs_f64();
                    metrics::record_transaction_finalized(latency_secs, cross_shard);
                }
                self.tx_status_cache.insert(tx_hash, status.clone());
                self.emitted_statuses.push((tx_hash, status));
            }

            // ═══════════════════════════════════════════════════════════
            // Sync / Fetch / Provision recovery
            // ═══════════════════════════════════════════════════════════
            Action::StartSync { .. }
            | Action::FetchTransactions { .. }
            | Action::CancelFetch { .. }
            | Action::RequestMissingProvisions { .. }
            | Action::CancelProvisionFetch { .. }
            | Action::RequestTxInclusionProof { .. } => {
                self.process_sync_fetch_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Topology propagation
            // ═══════════════════════════════════════════════════════════
            Action::TopologyChanged { topology } => {
                self.topology.store(Arc::clone(&topology));
                self.rebuild_topology_cache_from(&topology);

                // Push updated validator keys to the network layer for bind verification.
                let keys: hyperscale_network::ValidatorKeyMap = topology
                    .global_validator_set()
                    .validators
                    .iter()
                    .map(|v| (v.validator_id, v.public_key))
                    .collect();
                self.network.update_validator_keys(Arc::new(keys));

                tracing::info!(
                    local_shard = self.local_shard.0,
                    local_peers = self.cached_local_peers.len(),
                    "Network topology updated"
                );
            }

            // ═══════════════════════════════════════════════════════════
            // Global consensus / epoch (not yet implemented)
            // ═══════════════════════════════════════════════════════════
            Action::ProposeGlobalBlock { .. }
            | Action::BroadcastGlobalBlockVote { .. }
            | Action::TransitionEpoch { .. }
            | Action::MarkValidatorReady { .. }
            | Action::InitiateShardSplit { .. }
            | Action::CompleteShardSplit { .. }
            | Action::InitiateShardMerge { .. }
            | Action::CompleteShardMerge { .. }
            | Action::PersistEpochConfig { .. }
            | Action::FetchEpochConfig { .. } => {}
        }
    }

    // ─── Action Handler Groups ──────────────────────────────────────────

    /// Process storage read/write actions.
    fn process_storage_action(&mut self, action: Action) {
        match action {
            Action::PersistBlock { block, qc } => {
                let height = block.header.height;
                ConsensusStore::put_block(&*self.storage, height, &block, &qc);
            }
            Action::PersistTransactionCertificate { certificate } => {
                // Populate cert cache before persisting — serves peer fetch requests
                // from memory even if storage write hasn't completed.
                self.cert_cache
                    .insert(certificate.transaction_hash, Arc::new(certificate.clone()));
                self.storage.store_certificate(&certificate);
            }
            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard: _,
                vote,
                recipients,
            } => {
                // BFT Safety: persist vote BEFORE broadcasting.
                self.storage.put_own_vote(height.0, round, block_hash);
                trace!(
                    height = height.0,
                    round,
                    block_hash = ?block_hash,
                    "Persisted own vote"
                );
                self.network.notify(&recipients, &vote);
            }
            Action::FetchBlock { height } => {
                let block = self.storage.get_block(height);
                let _ = self
                    .event_sender
                    .send(NodeInput::Protocol(ProtocolEvent::BlockFetched {
                        height,
                        block: block.map(|(b, _)| b),
                    }));
            }
            Action::FetchChainMetadata => {
                let height = self.storage.committed_height();
                let hash = self.storage.committed_hash();
                let qc = self.storage.latest_qc();
                let _ = self.event_sender.send(NodeInput::Protocol(
                    ProtocolEvent::ChainMetadataFetched { height, hash, qc },
                ));
            }
            _ => unreachable!(),
        }
    }

    /// Accumulate a block commit for batched dispatch. Records metrics
    /// immediately (on the pinned thread) and feeds the sync protocol, then
    /// defers the heavy JVT/metadata writes to [`flush_block_commits`].
    fn accumulate_block_commit(
        &mut self,
        block: hyperscale_types::Block,
        qc: hyperscale_types::QuorumCertificate,
    ) {
        let block_hash = block.hash();
        let height = block.header.height;
        debug!(height = height.0, ?block_hash, "Block committed");

        // Block commit latency: time from proposal timestamp to now.
        let now_ms = self.state.now().as_millis() as u64;
        let commit_latency_secs = (now_ms.saturating_sub(block.header.timestamp)) as f64 / 1000.0;
        metrics::record_block_committed(height.0, commit_latency_secs);
        metrics::set_block_height(height.0);
        metrics::set_txs_with_commitment_proof(block.priority_transactions.len());

        // Livelock metrics for deferrals in this block.
        for _deferral in &block.deferred {
            metrics::record_livelock_deferral();
            metrics::record_livelock_cycle_detected();
        }
        metrics::set_livelock_deferred_count(self.state.livelock().stats().pending_deferrals);

        // Feed committed height to sync protocol (just tracks progress,
        // doesn't need JVT state).
        let outputs = self
            .sync_protocol
            .handle(SyncInput::BlockCommitted { height: height.0 });
        self.process_sync_outputs(outputs);

        self.pending_block_commits.push((block, qc));
    }

    /// Flush accumulated block commits and any pending receipt bundles.
    ///
    /// If all blocks are empty (no certificates), commits synchronously.
    /// Otherwise spawns a single closure on the execution pool that persists
    /// receipt bundles first, then commits all blocks sequentially, sending
    /// `StateCommitComplete` and `BlockCommitted` events after each.
    ///
    /// Receipt bundles are drained into the same closure because the sync
    /// path reconstructs `DatabaseUpdates` by reading receipts back from
    /// storage. Writing receipts and committing in a single closure
    /// guarantees ordering — Rayon does not guarantee FIFO ordering across
    /// separate `spawn()` calls.
    ///
    /// If a previous async commit closure is still in flight, blocks and
    /// receipt bundles remain pending to avoid spawning a second closure.
    /// The in-flight closure clears the flag before sending its final
    /// events, so the resulting `feed_event` → `flush_block_commits` picks
    /// up the backlog.
    pub(super) fn flush_block_commits(&mut self) {
        if self.pending_block_commits.is_empty() {
            // Also flush any receipt bundles that arrived after their
            // block was already committed.
            self.flush_pending_receipts();
            return;
        }

        // Defer if a previous async commit is still running on the exec pool.
        if self.commit_in_flight.load(Ordering::Acquire) {
            return;
        }

        let commits = std::mem::take(&mut self.pending_block_commits);
        let pending_receipts = std::mem::take(&mut self.pending_receipt_bundles);

        let has_non_empty = commits.iter().any(|(b, _)| !b.certificates.is_empty());

        if !has_non_empty {
            // All empty blocks — synchronous fast path.
            // Still advance JVT version so it matches block height.
            if !pending_receipts.is_empty() {
                self.storage.store_receipt_bundles(&pending_receipts);
            }
            // Prune stale prepared_commits that outlived their blocks.
            let max_height = commits
                .iter()
                .map(|(b, _)| b.header.height.0)
                .max()
                .unwrap_or(0);
            {
                let mut cache = self.prepared_commits.lock().unwrap();
                cache.retain(|_, (h, _)| *h > max_height);
            }
            for (block, qc) in commits {
                let height = block.header.height;
                let block_hash = block.hash();
                let consensus = hyperscale_storage::ConsensusCommitData {
                    height,
                    hash: block_hash,
                    qc: qc.clone(),
                };
                // Empty blocks have no certificate writes — pass empty DatabaseUpdates.
                let empty_updates = hyperscale_types::DatabaseUpdates::default();
                let result = self.storage.commit_block(
                    &empty_updates,
                    &block.certificates,
                    height.0,
                    Some(consensus),
                );
                ConsensusStore::prune_own_votes(&*self.storage, height.0);
                let _ = self.event_sender.send(NodeInput::Protocol(
                    ProtocolEvent::StateCommitComplete {
                        height: height.0,
                        state_root: result,
                    },
                ));
                let _ =
                    self.event_sender
                        .send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                            block_hash,
                            height: height.0,
                            block,
                        }));
            }
            return;
        }

        // Extract prepared commit handles for each block in the batch,
        // then prune any stale entries at or below the highest committed
        // height. Stale entries accumulate when VerifyStateRoot /
        // BuildProposal complete on the crypto pool *after* the block they
        // prepared has already been committed via the sync/receipt-
        // reconstruction path. Without this prune, one orphaned
        // PreparedCommit (WriteBatch + JvtSnapshot + DatabaseUpdates) leaks
        // per block whenever the crypto pool is slower than commit dispatch.
        let max_committed_height = commits
            .iter()
            .map(|(b, _)| b.header.height.0)
            .max()
            .unwrap_or(0);

        let mut prepared_map = {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut map = Vec::with_capacity(commits.len());
            for (block, _) in &commits {
                map.push(cache.remove(&block.hash()).map(|(_, p)| p));
            }
            let before = cache.len();
            cache.retain(|_, (h, _)| *h > max_committed_height);
            let pruned = before - cache.len();
            if pruned > 0 {
                tracing::debug!(pruned, "Pruned stale prepared_commits entries");
            }
            map
        };

        let storage = Arc::clone(&self.storage);
        let event_tx = self.event_sender.clone();
        let local_shard = self.local_shard;
        let num_shards = self.num_shards;
        let in_flight = self.commit_in_flight.clone();

        self.commit_in_flight.store(true, Ordering::Release);

        self.dispatch.spawn_execution(move || {
            // Persist receipt bundles before committing — the sync path
            // reconstructs DatabaseUpdates by reading these back.
            if !pending_receipts.is_empty() {
                storage.store_receipt_bundles(&pending_receipts);
            }

            for (i, (block, qc)) in commits.into_iter().enumerate() {
                let block_hash = block.hash();
                let height = block.header.height;

                let consensus = hyperscale_storage::ConsensusCommitData {
                    height,
                    hash: block_hash,
                    qc: qc.clone(),
                };

                // Always commit — even empty blocks advance the JVT version
                // to match block height, so provision lookups succeed.
                // Consensus metadata is folded into the same atomic write.
                let prepared = prepared_map[i].take();
                let result = if let Some(prepared) = prepared {
                    // Normal path: prepared commit from VerifyStateRoot.
                    storage.commit_prepared_block(prepared, &block.certificates, Some(consensus))
                } else if !block.certificates.is_empty() {
                    // Sync path: no execution cache, reconstruct DatabaseUpdates
                    // from receipts stored during sync.
                    let per_cert: Vec<hyperscale_types::DatabaseUpdates> = block
                        .certificates
                        .iter()
                        .map(|cert| {
                            let receipt = storage
                                .get_ledger_receipt(&cert.transaction_hash)
                                .unwrap_or_else(|| {
                                    panic!(
                                        "Missing receipt for certificate {} at height {} — \
                                         sync response was incomplete and pre-storage failed",
                                        cert.transaction_hash, height.0,
                                    )
                                });
                            let updates = hyperscale_storage::receipt_to_database_updates(&receipt);
                            hyperscale_storage::filter_updates_to_shard(
                                &updates,
                                local_shard,
                                num_shards,
                            )
                        })
                        .collect();
                    let merged = hyperscale_storage::merge_database_updates(&per_cert);
                    storage.commit_block(&merged, &block.certificates, height.0, Some(consensus))
                } else {
                    // Empty block: no updates needed.
                    let empty_updates = hyperscale_types::DatabaseUpdates::default();
                    storage.commit_block(
                        &empty_updates,
                        &block.certificates,
                        height.0,
                        Some(consensus),
                    )
                };

                ConsensusStore::prune_own_votes(&*storage, height.0);

                // Clear the in-flight flag before sending events for the last
                // block. The channel send synchronizes-with recv on the main
                // thread, so the flag is guaranteed visible when the resulting
                // feed_event calls flush_block_commits to drain any backlog.
                if i == prepared_map.len() - 1 {
                    in_flight.store(false, Ordering::Release);
                }

                let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::StateCommitComplete {
                    height: height.0,
                    state_root: result,
                }));

                let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                    block_hash,
                    height: height.0,
                    block,
                }));
            }
        });
    }

    /// Flush receipt bundles that are not associated with a pending block
    /// commit. These arise when async execution (`ExecuteTransactions` /
    /// `SpeculativeExecute`) completes *after* the block that references
    /// those certificates was already committed and flushed. Storing them
    /// promptly ensures the sync protocol can serve those blocks; without
    /// this the sync protocol cannot reconstruct `DatabaseUpdates` for
    /// those blocks, stalling recovery and preventing new commits that
    /// would otherwise have drained the receipts.
    ///
    /// This is synchronous (not spawned on the execution pool) to avoid a
    /// race with `flush_block_commits`: if receipts are written async and
    /// a subsequent block commit runs before the write completes, the
    /// commit closure panics on `get_ledger_receipt` returning `None`.
    /// Receipt storage is a small RocksDB `WriteBatch`, so the main-thread
    /// cost is negligible.
    pub(super) fn flush_pending_receipts(&mut self) {
        if self.pending_receipt_bundles.is_empty() {
            return;
        }
        let bundles = std::mem::take(&mut self.pending_receipt_bundles);
        self.storage.store_receipt_bundles(&bundles);
    }

    /// Process sync, fetch, and provision recovery actions.
    fn process_sync_fetch_action(&mut self, action: Action) {
        match action {
            Action::StartSync {
                target_height,
                target_hash,
            } => {
                let outputs = self.sync_protocol.handle(SyncInput::StartSync {
                    target_height,
                    target_hash,
                });
                self.process_sync_outputs(outputs);
            }
            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                self.fetch_protocol.handle(FetchInput::RequestTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                });
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelFetch { block_hash } => {
                self.fetch_protocol
                    .handle(FetchInput::CancelFetch { block_hash });
            }
            Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer,
                peers,
            } => {
                debug_assert!(
                    !peers.is_empty(),
                    "RequestMissingProvisions for shard {} height {} has no peers — \
                     was the action enriched by NodeStateMachine?",
                    source_shard.0,
                    block_height.0,
                );
                debug!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    proposer = proposer.0,
                    peer_count = peers.len(),
                    "Requesting missing provisions from source shard"
                );
                let outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Request {
                        source_shard,
                        block_height,
                        target_shard: self.local_shard,
                        peers,
                        preferred_peer: proposer,
                    });
                self.process_provision_fetch_outputs(outputs);
                let tick_outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Tick);
                self.process_provision_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelProvisionFetch {
                source_shard,
                block_height,
            } => {
                self.provision_fetch_protocol
                    .handle(ProvisionFetchInput::Cancel {
                        source_shard,
                        block_height,
                    });
            }
            Action::RequestTxInclusionProof {
                source_shard,
                source_block_height,
                winner_tx_hash,
                reason,
                peers,
            } => {
                use crate::protocol::inclusion_proof_fetch::InclusionProofFetchInput;
                let preferred_peer = peers.first().copied().unwrap_or(ValidatorId(0));
                let outputs =
                    self.inclusion_proof_fetch_protocol
                        .handle(InclusionProofFetchInput::Request {
                            source_shard,
                            source_block_height,
                            winner_tx_hash,
                            reason,
                            peers,
                            preferred_peer,
                        });
                self.process_inclusion_proof_fetch_outputs(outputs);
                // Tick immediately to start the fetch.
                let tick_outputs = self
                    .inclusion_proof_fetch_protocol
                    .handle(InclusionProofFetchInput::Tick);
                self.process_inclusion_proof_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            _ => unreachable!(),
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via the
    /// `event_sender` channel and are processed on a future `step()` call.
    /// With `SyncDispatch` (simulation), `spawn_*` runs inline so events
    /// enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&mut self, action: Action) {
        let is_speculative = matches!(action, Action::SpeculativeExecute { .. });
        let is_execution = is_speculative || matches!(action, Action::ExecuteTransactions { .. });
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let dispatch = self.dispatch.clone();
        let local_shard = self.local_shard;
        let num_shards = self.num_shards;
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                local_shard,
                num_shards,
                dispatch: &dispatch,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    if is_speculative {
                        metrics::record_speculative_execution_latency(elapsed);
                    } else {
                        metrics::record_execution_latency(elapsed);
                    }
                }
                if let Some((hash, height, prepared)) = result.prepared_commit {
                    prepared_commits
                        .lock()
                        .unwrap()
                        .insert(hash, (height, prepared));
                }
                for event in result.events {
                    let _ = event_tx.send(event);
                }
            }
        };

        match pool {
            DispatchPool::ConsensusCrypto => self.dispatch.spawn_consensus_crypto(spawn_fn),
            DispatchPool::Crypto => self.dispatch.spawn_crypto(spawn_fn),
            DispatchPool::Execution => self.dispatch.spawn_execution(spawn_fn),
            DispatchPool::Provisions => self.dispatch.spawn_provisions(spawn_fn),
        }
    }

    /// Local shard committee excluding self, for use as the `peers` argument
    /// to `network.request()`.
    pub(super) fn local_peers(&self) -> &[ValidatorId] {
        &self.cached_local_peers
    }
}
