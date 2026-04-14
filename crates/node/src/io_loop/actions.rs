//! Action processing and dispatch.

use super::{IoLoop, TimerOp};
use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::protocol::execution_cert_fetch::ExecCertFetchInput;
use crate::protocol::finalized_wave_fetch::FinalizedWaveFetchInput;
use crate::protocol::header_fetch::HeaderFetchInput;
use crate::protocol::local_provision_fetch::LocalProvisionFetchInput;
use crate::protocol::provision_fetch::ProvisionFetchInput;
use crate::protocol::sync::SyncInput;
use crate::protocol::transaction_fetch::TransactionFetchInput;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::ValidatorId;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{debug, warn};
impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: ChainWriter + SubstateStore + ChainReader + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
    E: Engine + 'static,
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
                // Populate provision cache for request handler serving.
                if let ProtocolEvent::ProvisionVerified { ref batch } = pe {
                    self.provision_cache.insert(batch.hash(), Arc::clone(batch));
                }
                let _ = self.event_sender.send(NodeInput::Protocol(pe));
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — immediate (non-batched)
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastBlockHeader { shard: _, header } => {
                self.network.notify(&self.cached_local_peers, &*header);
            }
            Action::BroadcastVote { vote, recipients } => {
                self.network.notify(&recipients, &vote);
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
            Action::SignAndSendExecutionVote {
                block_hash,
                block_height,
                vote_height,
                wave_id,
                global_receipt_root,
                tx_outcomes,
                leader,
            } => {
                let tx_count = tx_outcomes.len() as u32;
                // Sign the execution vote inline (BLS signing is fast, ~1ms)
                let msg = hyperscale_types::exec_vote_message(
                    vote_height,
                    &wave_id,
                    self.local_shard,
                    &global_receipt_root,
                    tx_count,
                );
                let sig = self.signing_key.sign_v1(&msg);
                let vote = hyperscale_types::ExecutionVote {
                    block_hash,
                    block_height,
                    vote_height,
                    wave_id,
                    shard_group_id: self.local_shard,
                    global_receipt_root,
                    tx_count,
                    tx_outcomes,
                    validator: self.validator_id,
                    signature: sig,
                };

                // Send vote to the wave leader (unicast).
                if leader != self.validator_id {
                    let batch_msg = hyperscale_types::exec_vote_batch_message(
                        self.local_shard,
                        std::slice::from_ref(&vote),
                    );
                    let batch_sig = self.signing_key.sign_v1(&batch_msg);
                    let batch = hyperscale_messages::ExecutionVotesNotification::new(
                        vec![vote.clone()],
                        self.validator_id,
                        batch_sig,
                    );
                    self.network.notify(&[leader], &batch);
                }

                // Feed own vote to state machine only if we are the leader.
                // The leader needs its own vote in the VoteTracker for aggregation.
                // Non-leaders track retries via PendingVoteRetry in the state machine.
                if leader == self.validator_id {
                    let _ = self.event_sender.send(hyperscale_core::NodeInput::Protocol(
                        hyperscale_core::ProtocolEvent::ExecutionVoteReceived { vote },
                    ));
                }
            }
            Action::BroadcastExecutionCertificate {
                shard: _,
                certificate,
                recipients,
            } => {
                // Each cert already covers a whole wave — send immediately, no accumulator.
                let cert = std::sync::Arc::unwrap_or_clone(certificate);
                let msg = hyperscale_types::exec_cert_batch_message(
                    cert.shard_group_id(),
                    std::slice::from_ref(&cert),
                );
                let sig = self.signing_key.sign_v1(&msg);
                let batch = hyperscale_messages::ExecutionCertificatesNotification::new(
                    vec![cert],
                    self.validator_id,
                    sig,
                );
                self.network.notify(&recipients, &batch);
            }
            Action::TrackExecutionCertificate { certificate } => {
                let key = (certificate.wave_id.hash(), certificate.wave_id.clone());
                // Cache for serving EC fetch requests from remote shards.
                // Persistence is handled via wave certificates in block.certificates.
                if let Ok(mut cache) = self.exec_cert_cache.lock() {
                    cache.insert(key, Arc::clone(&certificate));
                    if cache.len() > 2000 {
                        let cutoff = cache
                            .values()
                            .map(|c| c.block_height())
                            .max()
                            .unwrap_or(0)
                            .saturating_sub(500);
                        cache.retain(|_, c| c.block_height() > cutoff);
                    }
                }
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — batched (accumulated for batch dispatch)
            // ═══════════════════════════════════════════════════════════
            // Wave delegated actions — dispatch immediately (same as AggregateExecutionCertificate)
            Action::AggregateExecutionCertificate { .. }
            | Action::VerifyAndAggregateExecutionVotes { .. }
            | Action::VerifyExecutionCertificateSignature { .. } => {
                self.dispatch_delegated_action(action);
            }
            // ═══════════════════════════════════════════════════════════
            // Delegated work — immediate dispatch
            // ═══════════════════════════════════════════════════════════
            Action::BuildProposal {
                ref provision_batches,
                ..
            } => {
                // Ensure provision data is serveable before the header reaches peers.
                for batch in provision_batches {
                    self.provision_cache.insert(batch.hash(), Arc::clone(batch));
                }
                self.dispatch_delegated_action(action);
            }
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyRemoteHeaderQc { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyProvisionRoot { .. }
            | Action::VerifyCertificateRoot { .. }
            | Action::VerifyLocalReceiptRoot { .. }
            | Action::VerifyProvision { .. }
            | Action::ExecuteTransactions { .. }
            | Action::ExecuteCrossShardTransactions { .. }
            | Action::FetchAndBroadcastProvision { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage
            // ═══════════════════════════════════════════════════════════
            Action::CacheFinalizedWave { .. } | Action::FetchChainMetadata => {
                self.process_storage_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Block commit + notifications
            // ═══════════════════════════════════════════════════════════
            Action::CommitBlock {
                block,
                qc,
                finalized_waves,
                provision_hashes,
            } => {
                self.accumulate_block_commit(super::PendingCommit::Consensus {
                    block: Arc::new(block),
                    qc: Arc::new(qc),
                    finalized_waves,
                    provision_hashes,
                });
            }
            Action::CommitSyncedBlock {
                block,
                qc,
                provision_hashes,
            } => {
                self.accumulate_block_commit(super::PendingCommit::Synced {
                    block: Arc::new(block),
                    qc: Arc::new(qc),
                    provision_hashes,
                });
            }
            Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally,
                phase_times,
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                if status.is_final() && submitted_locally {
                    let now = self.state.now();
                    let latency_secs = now.saturating_sub(added_at).as_secs_f64();
                    if latency_secs > 10.0 {
                        // Rate-limit slow tx warnings to avoid log floods during
                        // cross-shard latency spikes.
                        let since_last_warn = now.saturating_sub(self.last_slow_tx_warn);
                        if since_last_warn >= std::time::Duration::from_secs(30) {
                            self.last_slow_tx_warn = now;
                            if let Some(ref phases) = phase_times {
                                warn!(
                                    ?tx_hash,
                                    latency_secs,
                                    cross_shard,
                                    %phases,
                                    "Transaction finalization exceeded 10s"
                                );
                            } else {
                                warn!(
                                    ?tx_hash,
                                    latency_secs,
                                    cross_shard,
                                    "Transaction finalization exceeded 10s"
                                );
                            }
                        }
                    }
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
            | Action::FetchProvisionLocal { .. }
            | Action::FetchFinalizedWave { .. }
            | Action::CancelFetch { .. }
            | Action::FetchProvisionRemote { .. }
            | Action::RequestMissingExecutionCert { .. }
            | Action::CancelProvisionFetch { .. }
            | Action::RequestMissingCommittedBlockHeader { .. } => {
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
            Action::CacheFinalizedWave { wave } => {
                let wave_id_hash = wave.wave_id_hash();
                self.cert_cache
                    .insert(wave_id_hash, Arc::clone(&wave.certificate));
                self.finalized_wave_cache.insert(wave_id_hash, wave);
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
    fn accumulate_block_commit(&mut self, commit: super::PendingCommit) {
        let block = commit.block();
        let block_hash = block.hash();
        let height = block.header.height;
        debug!(
            height = height.0,
            ?block_hash,
            sync = commit.is_sync(),
            "Block committed"
        );

        // Block commit latency: time from proposal timestamp to now.
        let now_ms = self.state.now().as_millis() as u64;
        let commit_latency_secs = (now_ms.saturating_sub(block.header.timestamp)) as f64 / 1000.0;
        metrics::record_block_committed(height.0, commit_latency_secs);
        metrics::set_block_height(height.0);
        // Feed committed height to sync protocol (just tracks progress,
        // doesn't need JVT state).
        let outputs = self
            .sync_protocol
            .handle(SyncInput::BlockCommitted { height: height.0 });
        self.process_sync_outputs(outputs);

        self.pending_block_commits.push(commit);
    }

    /// Flush accumulated block commits and any pending receipt bundles.
    ///
    /// If all blocks are empty (no certificates), commits synchronously.
    /// Otherwise spawns a single closure on the execution pool that persists
    /// receipt bundles first, then commits all blocks sequentially, sending
    /// `BlockCommitted` events after each.
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
            return;
        }

        // Defer if a previous async commit is still running on the exec pool.
        if self.commit_in_flight.load(Ordering::Acquire) {
            return;
        }

        let commits = std::mem::take(&mut self.pending_block_commits);

        // Only take sync data for synced blocks we're about to commit.
        // BFT may buffer sync blocks internally for sequential ordering,
        // so sync data for future heights must stay in the map.
        let mut sync_data = std::collections::HashMap::new();
        for commit in &commits {
            if commit.is_sync() {
                let h = commit.block().header.height.0;
                if let Some(data) = self.pending_sync_data.remove(&h) {
                    sync_data.insert(h, data);
                }
            }
        }

        let has_non_empty = commits.iter().any(|c| !c.block().certificates.is_empty());

        if !has_non_empty {
            // All empty blocks — synchronous fast path.
            // Still advance JVT version so it matches block height.

            // Prune stale prepared_commits that outlived their blocks.
            let max_height = commits
                .iter()
                .map(|c| c.block().header.height.0)
                .max()
                .unwrap_or(0);
            {
                let mut cache = self.prepared_commits.lock().unwrap();
                cache.retain(|_, (h, _)| *h > max_height);
            }
            for commit in commits {
                let (block, qc, provision_hashes) = match commit {
                    super::PendingCommit::Consensus {
                        block,
                        qc,
                        provision_hashes,
                        ..
                    } => (block, qc, provision_hashes),
                    super::PendingCommit::Synced {
                        block,
                        qc,
                        provision_hashes,
                    } => (block, qc, provision_hashes),
                };
                let block_hash = block.hash();
                let height = block.header.height.0;
                let result = self.storage.commit_block(&block, &qc, &[]);
                let _ =
                    self.event_sender
                        .send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                            block_hash,
                            height,
                            block: Arc::unwrap_or_clone(block),
                            state_root: result,
                            provision_hashes,
                        }));
            }
            return;
        }

        // Extract prepared commit handles for each block in the batch,
        // then prune any stale entries at or below the highest committed
        // height.
        let max_committed_height = commits
            .iter()
            .map(|c| c.block().header.height.0)
            .max()
            .unwrap_or(0);

        // Identify blocks that are NOT yet ready to commit. A consensus
        // block with certificates can commit via prepared_commit (proposer)
        // or finalized_waves receipts (non-proposer fallback). A sync block
        // with certificates requires sync_data. Without the appropriate
        // data, committing would apply empty state updates, diverging the JVT.
        //
        // Deferred blocks are put back into pending_block_commits; they will
        // be retried on the next flush.
        let mut ready_commits: Vec<super::PendingCommit> = Vec::with_capacity(commits.len());
        let mut prepared_map = Vec::with_capacity(commits.len());
        {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut deferring = false;
            for commit in commits {
                let has_certs = !commit.block().certificates.is_empty();
                let prepared = if !deferring {
                    cache.remove(&commit.block().hash()).map(|(_, p)| p)
                } else {
                    None
                };

                let not_ready = has_certs
                    && match &commit {
                        super::PendingCommit::Consensus {
                            finalized_waves, ..
                        } => {
                            // Only defer if we have neither a prepared commit nor
                            // finalized waves with receipts. The proposer provides
                            // a PreparedCommit; non-proposers use the commit_block
                            // fallback path which recomputes state from receipts.
                            prepared.is_none() && finalized_waves.is_empty()
                        }
                        super::PendingCommit::Synced { block, .. } => {
                            !sync_data.contains_key(&block.header.height.0)
                        }
                    };

                if deferring || not_ready {
                    if !deferring {
                        tracing::debug!(
                            height = commit.block().header.height.0,
                            certs = commit.block().certificates.len(),
                            sync = commit.is_sync(),
                            "Deferring block commit — awaiting data"
                        );
                        deferring = true;
                    }
                    // Restore any sync data we extracted for this height.
                    let h = commit.block().header.height.0;
                    if let Some(data) = sync_data.remove(&h) {
                        self.pending_sync_data.insert(h, data);
                    }
                    // Put back prepared commit if we extracted one.
                    if let Some(p) = prepared {
                        let bh = commit.block().hash();
                        cache.insert(bh, (h, p));
                    }
                    self.pending_block_commits.push(commit);
                } else {
                    prepared_map.push(prepared);
                    ready_commits.push(commit);
                }
            }
            // Prune stale entries that outlived their blocks.
            let before = cache.len();
            cache.retain(|_, (h, _)| *h > max_committed_height);
            let pruned = before - cache.len();
            if pruned > 0 {
                tracing::debug!(pruned, "Pruned stale prepared_commits entries");
            }
        }

        if ready_commits.is_empty() {
            return;
        }
        let commits = ready_commits;
        let commit_count = commits.len();

        let storage = Arc::clone(&self.storage);
        let topology = Arc::clone(&self.topology);
        let event_tx = self.event_sender.clone();
        let in_flight = self.commit_in_flight.clone();

        self.commit_in_flight.store(true, Ordering::Release);

        self.dispatch.spawn_execution(move || {
            for (i, commit) in commits.into_iter().enumerate() {
                let block_hash = commit.block().hash();
                let height = commit.block().header.height;

                let prepared = prepared_map[i].take();

                let result = match commit {
                    super::PendingCommit::Consensus {
                        ref block,
                        ref qc,
                        ref finalized_waves,
                        ..
                    } => {
                        let wave_receipts: Vec<hyperscale_types::ReceiptBundle> = finalized_waves
                            .iter()
                            .flat_map(|fw| fw.receipts.iter().cloned())
                            .collect();

                        if let Some(prepared) = prepared {
                            storage.commit_prepared_block(prepared, block, qc)
                        } else {
                            storage.commit_block(block, qc, &wave_receipts)
                        }
                    }
                    super::PendingCommit::Synced {
                        ref block, ref qc, ..
                    } => {
                        if block.certificates.is_empty() {
                            storage.commit_block(block, qc, &[])
                        } else if let Some(entry) = sync_data.get(&height.0) {
                            let receipts = &entry.local_receipts;

                            // Convert sync receipts to ReceiptBundles.
                            let sync_receipt_bundles: Vec<hyperscale_types::ReceiptBundle> =
                                if !receipts.is_empty() {
                                    receipts
                                        .iter()
                                        .map(|entry| hyperscale_types::ReceiptBundle {
                                            tx_hash: entry.tx_hash,
                                            local_receipt: std::sync::Arc::new(
                                                entry.receipt.clone(),
                                            ),
                                            execution_output: None,
                                        })
                                        .collect()
                                } else {
                                    // Fallback: derive from wave certs' source blocks.
                                    let topo = topology.load();
                                    let mut bundles = Vec::new();
                                    for wc in &block.certificates {
                                        let source_height =
                                            hyperscale_types::BlockHeight(wc.wave_id.block_height);
                                        if let Some((source_block, _)) =
                                            storage.get_block(source_height)
                                        {
                                            let tx_hashes = hyperscale_types::derive_wave_tx_hashes(
                                                &topo,
                                                &wc.wave_id,
                                                &source_block.transactions,
                                            );
                                            for tx_hash in tx_hashes {
                                                if let Some(receipt) =
                                                    storage.get_local_receipt(&tx_hash)
                                                {
                                                    bundles.push(hyperscale_types::ReceiptBundle {
                                                        tx_hash,
                                                        local_receipt: receipt,
                                                        execution_output: None,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                    bundles
                                };

                            // Verify state_root via prepare→verify→commit.
                            let parent_root = storage.state_root_hash();
                            let parent_height = if height.0 > 0 { height.0 - 1 } else { 0 };
                            let (computed_root, prepared) = storage.prepare_block_commit(
                                parent_root,
                                parent_height,
                                &sync_receipt_bundles,
                                height.0,
                            );
                            if computed_root != block.header.state_root {
                                tracing::warn!(
                                    height = height.0,
                                    ?computed_root,
                                    expected = ?block.header.state_root,
                                    "Sync: state_root mismatch — committing anyway \
                                     (QC-attested, 2f+1 validators verified)"
                                );
                            }

                            storage.commit_prepared_block(prepared, block, qc)
                        } else {
                            tracing::error!(
                                height = height.0,
                                "BUG: synced block with certs but no sync data"
                            );
                            storage.commit_block(block, qc, &[])
                        }
                    }
                };

                // Extract the block and provision hashes from the commit for the event.
                let (block, provision_hashes) = match commit {
                    super::PendingCommit::Consensus {
                        block,
                        provision_hashes,
                        ..
                    } => (block, provision_hashes),
                    super::PendingCommit::Synced {
                        block,
                        provision_hashes,
                        ..
                    } => (block, provision_hashes),
                };

                // Clear the in-flight flag before sending events for the last
                // block. The channel send synchronizes-with recv on the main
                // thread, so the flag is guaranteed visible when the resulting
                // feed_event calls flush_block_commits to drain any backlog.
                if i == commit_count - 1 {
                    in_flight.store(false, Ordering::Release);
                }

                let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                    block_hash,
                    height: height.0,
                    block: Arc::unwrap_or_clone(block),
                    state_root: result,
                    provision_hashes,
                }));
            }
        });
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
                self.transaction_fetch_protocol.handle(
                    TransactionFetchInput::RequestTransactions {
                        block_hash,
                        proposer,
                        tx_hashes,
                    },
                );
                let outputs = self
                    .transaction_fetch_protocol
                    .handle(TransactionFetchInput::Tick);
                self.process_transaction_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::FetchProvisionLocal {
                block_hash,
                proposer,
                batch_hashes,
            } => {
                self.local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::Request {
                        block_hash,
                        proposer,
                        batch_hashes,
                    });
                let tick_outputs = self
                    .local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::Tick);
                self.process_local_provision_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::FetchFinalizedWave {
                block_hash,
                proposer,
                wave_id_hashes,
            } => {
                self.finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Request {
                        block_hash,
                        proposer,
                        wave_id_hashes,
                    });
                let tick_outputs = self
                    .finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Tick);
                self.process_finalized_wave_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelFetch { block_hash } => {
                self.transaction_fetch_protocol
                    .handle(TransactionFetchInput::CancelFetch { block_hash });
                self.local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::CancelFetch { block_hash });
                self.finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::CancelFetch { block_hash });
            }
            Action::FetchProvisionRemote {
                source_shard,
                block_height,
                proposer,
                peers,
            } => {
                debug_assert!(
                    !peers.is_empty(),
                    "FetchProvisionRemote for shard {} height {} has no peers — \
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
                let tick_outputs =
                    self.provision_fetch_protocol
                        .handle(ProvisionFetchInput::Tick {
                            now: std::time::Instant::now(),
                        });
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
            Action::RequestMissingExecutionCert {
                source_shard,
                block_height,
                wave_id,
                peers,
            } => {
                debug!(
                    source_shard = source_shard.0,
                    block_height,
                    wave = %wave_id,
                    peer_count = peers.len(),
                    "Requesting missing execution cert from source shard"
                );
                let outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Request {
                        source_shard,
                        block_height,
                        wave_id,
                        peers,
                    });
                self.process_exec_cert_fetch_outputs(outputs);
                let tick_outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Tick {
                        now: std::time::Instant::now(),
                        committed_height: self.state.bft().committed_height(),
                    });
                self.process_exec_cert_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }
            Action::RequestMissingCommittedBlockHeader {
                source_shard,
                from_height,
                peers,
            } => {
                debug!(
                    source_shard = source_shard.0,
                    from_height = from_height.0,
                    peer_count = peers.len(),
                    "Requesting missing committed block header from source shard"
                );
                let outputs = self
                    .header_fetch_protocol
                    .handle(HeaderFetchInput::Request {
                        source_shard,
                        from_height,
                        peers,
                    });
                self.process_header_fetch_outputs(outputs);
                let tick_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick {
                    now: std::time::Instant::now(),
                });
                self.process_header_fetch_outputs(tick_outputs);
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
        let is_execution = matches!(
            action,
            Action::ExecuteTransactions { .. } | Action::ExecuteCrossShardTransactions { .. }
        );
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let topology_snapshot = self.topology.load_full();
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                topology: &topology_snapshot,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    metrics::record_execution_latency(elapsed);
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
            DispatchPool::Provision => self.dispatch.spawn_provisions(spawn_fn),
        }
    }

    /// Local shard committee excluding self, for use as the `peers` argument
    /// to `network.request()`.
    pub(super) fn local_peers(&self) -> &[ValidatorId] {
        &self.cached_local_peers
    }
}
