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
    S: ChainWriter + SubstateStore + ChainReader + hyperscale_storage::JmtTreeReader + Send + Sync,
    N: Network,
    D: Dispatch,
    E: Engine,
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
            Action::BroadcastBlockHeader { header, manifest } => {
                // Sign proposal on consensus crypto pool, then broadcast.
                let signing_key = Arc::clone(&self.signing_key);
                let network = Arc::clone(&self.network);
                let topology = Arc::clone(&self.topology);
                let validator_id = self.validator_id;

                self.dispatch.spawn_consensus_crypto(move || {
                    let block_hash = header.hash();
                    let msg = hyperscale_types::block_header_message(
                        header.shard_group_id,
                        header.height.0,
                        header.round,
                        &block_hash,
                    );
                    let sig = signing_key.sign_v1(&msg);
                    let gossip =
                        hyperscale_messages::BlockHeaderNotification::new(*header, *manifest, sig);
                    let topo = topology.load();
                    let local_peers: Vec<ValidatorId> = topo
                        .committee_for_shard(topo.local_shard())
                        .iter()
                        .filter(|&&v| v != validator_id)
                        .copied()
                        .collect();
                    network.notify(&local_peers, &gossip);
                });
            }
            Action::SignAndBroadcastBlockVote {
                block_hash,
                height,
                round,
                timestamp,
                recipients,
            } => {
                // Sign vote on consensus crypto pool, then broadcast + loopback.
                let signing_key = Arc::clone(&self.signing_key);
                let network = Arc::clone(&self.network);
                let event_tx = self.event_sender.clone();
                let local_shard = self.local_shard;
                let validator_id = self.validator_id;

                self.dispatch.spawn_consensus_crypto(move || {
                    let vote = hyperscale_types::BlockVote::new(
                        block_hash,
                        local_shard,
                        height,
                        round,
                        validator_id,
                        &signing_key,
                        timestamp,
                    );
                    let gossip = hyperscale_messages::BlockVoteNotification { vote: vote.clone() };
                    network.notify(&recipients, &gossip);

                    // Feed our own signed vote back for local VoteSet tracking.
                    let _ = event_tx.send(hyperscale_core::NodeInput::Protocol(
                        hyperscale_core::ProtocolEvent::BlockVoteReceived { vote },
                    ));
                });
            }
            Action::BroadcastTransaction { shard, gossip } => {
                self.network.broadcast_to_shard(shard, &*gossip);
            }
            Action::BroadcastCommittedBlockHeader { committed_header } => {
                // Sign committed header on consensus crypto pool, then broadcast.
                let signing_key = Arc::clone(&self.signing_key);
                let network = Arc::clone(&self.network);
                let validator_id = self.validator_id;

                self.dispatch.spawn_consensus_crypto(move || {
                    let msg = hyperscale_types::committed_block_header_message(
                        committed_header.header.shard_group_id,
                        committed_header.header.height.0,
                        &committed_header.header.hash(),
                    );
                    let sig = signing_key.sign_v1(&msg);
                    let gossip = hyperscale_messages::CommittedBlockHeaderGossip {
                        committed_header,
                        sender: validator_id,
                        sender_signature: sig,
                    };
                    network.broadcast_global(&gossip);
                });
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
                // Spawn BLS signing + network send on crypto pool to avoid
                // blocking the io_loop. The closure owns Arc-cloned handles
                // to the signing key, network, and event sender.
                let signing_key = Arc::clone(&self.signing_key);
                let network = Arc::clone(&self.network);
                let event_tx = self.event_sender.clone();
                let local_shard = self.local_shard;
                let validator_id = self.validator_id;

                self.dispatch.spawn_crypto(move || {
                    let tx_count = tx_outcomes.len() as u32;
                    let msg = hyperscale_types::exec_vote_message(
                        vote_height,
                        &wave_id,
                        local_shard,
                        &global_receipt_root,
                        tx_count,
                    );
                    let sig = signing_key.sign_v1(&msg);
                    let vote = hyperscale_types::ExecutionVote {
                        block_hash,
                        block_height,
                        vote_height,
                        wave_id,
                        shard_group_id: local_shard,
                        global_receipt_root,
                        tx_count,
                        tx_outcomes,
                        validator: validator_id,
                        signature: sig,
                    };

                    // Send vote to the wave leader (unicast).
                    if leader != validator_id {
                        let batch_msg = hyperscale_types::exec_vote_batch_message(
                            local_shard,
                            std::slice::from_ref(&vote),
                        );
                        let batch_sig = signing_key.sign_v1(&batch_msg);
                        let batch = hyperscale_messages::ExecutionVotesNotification::new(
                            vec![vote.clone()],
                            validator_id,
                            batch_sig,
                        );
                        network.notify(&[leader], &batch);
                    }

                    // Feed own vote to state machine only if we are the leader.
                    if leader == validator_id {
                        let _ = event_tx.send(hyperscale_core::NodeInput::Protocol(
                            hyperscale_core::ProtocolEvent::ExecutionVoteReceived { vote },
                        ));
                    }
                });
            }
            Action::BroadcastExecutionCertificate {
                shard: _,
                certificate,
                recipients,
            } => {
                // Spawn BLS signing + network send on crypto pool.
                let signing_key = Arc::clone(&self.signing_key);
                let network = Arc::clone(&self.network);
                let validator_id = self.validator_id;

                self.dispatch.spawn_crypto(move || {
                    let cert = std::sync::Arc::unwrap_or_clone(certificate);
                    let msg = hyperscale_types::exec_cert_batch_message(
                        cert.shard_group_id(),
                        std::slice::from_ref(&cert),
                    );
                    let sig = signing_key.sign_v1(&msg);
                    let batch = hyperscale_messages::ExecutionCertificatesNotification::new(
                        vec![cert],
                        validator_id,
                        sig,
                    );
                    network.notify(&recipients, &batch);
                });
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
                provisions,
            } => {
                self.accumulate_block_commit(super::PendingCommit {
                    block: Arc::new(block),
                    qc: Arc::new(qc),
                    provisions,
                    committed_notified: false, // set by accumulate_block_commit
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
                    local_peers = self.local_peers().len(),
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
    /// immediately (on the pinned thread), feeds the sync protocol, fires
    /// `BlockCommitted` to the state machine, then defers the heavy
    /// JVT/metadata writes to [`flush_block_commits`].
    ///
    /// `BlockCommitted` fires immediately — before RocksDB persistence —
    /// because the QC is the proof of commit (2f+1 agreement). Subsystem
    /// notifications use event-carried data, not storage reads. The async
    /// persistence closure sends `BlockPersisted` when the write completes.
    ///
    /// **Backpressure**: if the persistence lag exceeds
    /// [`MAX_PERSISTENCE_LAG`] blocks, the immediate `BlockCommitted` is
    /// suppressed and instead fires after the disk write (falling back to
    /// the pre-decoupling behaviour). This bounds memory usage and the
    /// crash-recovery window.
    fn accumulate_block_commit(&mut self, mut commit: super::PendingCommit) {
        let block_hash = commit.block.hash();
        let height = commit.block.header.height;
        debug!(height = height.0, ?block_hash, "Block committed");

        // Block commit latency: time from proposal timestamp to now.
        let now_ms = self.state.now().as_millis() as u64;
        let commit_latency_secs =
            (now_ms.saturating_sub(commit.block.header.timestamp)) as f64 / 1000.0;
        metrics::record_block_committed(height.0, commit_latency_secs);
        metrics::set_block_height(height.0);
        // Feed committed height to sync protocol (just tracks progress,
        // doesn't need JVT state).
        let outputs = self
            .sync_protocol
            .handle(SyncInput::BlockCommitted { height: height.0 });
        self.process_sync_outputs(outputs);

        // Fire BlockCommitted immediately unless persistence is falling
        // too far behind (backpressure). When deferred, flush_block_commits
        // sends BlockCommitted after the disk write instead.
        let persistence_lag = height.0.saturating_sub(self.persisted_height);
        let notify_now = persistence_lag <= Self::MAX_PERSISTENCE_LAG;
        if notify_now {
            self.feed_event(ProtocolEvent::BlockCommitted {
                block_hash,
                height: height.0,
                block: Arc::unwrap_or_clone(Arc::clone(&commit.block)),
                provisions: commit.provisions.clone(),
            });
        } else {
            tracing::debug!(
                height = height.0,
                persisted = self.persisted_height,
                lag = persistence_lag,
                "Deferring BlockCommitted — persistence backpressure"
            );
        }

        // Record the actual notification decision on the commit so the
        // flush closure knows whether to send BlockCommitted after persist.
        commit.committed_notified = notify_now;
        self.pending_block_commits.push(commit);
    }

    /// Maximum number of blocks consensus can advance ahead of persistence
    /// before falling back to synchronous commit notification.
    const MAX_PERSISTENCE_LAG: u64 = 5;

    /// Flush accumulated block commits and any pending receipt bundles.
    ///
    /// Spawns a single closure on the execution pool that persists receipt
    /// bundles first, then commits all blocks sequentially, sending
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

        let mut commits = std::mem::take(&mut self.pending_block_commits);

        // Sort by height to ensure parent blocks are flushed before children.
        // Cascading commits (e.g. QC formation during BlockCommitted processing)
        // can push child blocks into pending_block_commits before their parent
        // (because the parent's push happens after feed_event returns). Without
        // sorting, the child block (which may lack a PreparedCommit) would defer
        // and block the ready parent, causing a deadlock where BlockPersisted
        // never fires and sync_awaiting_persistence_height is never satisfied.
        commits.sort_by_key(|c| c.block.header.height.0);

        // Extract prepared commit handles for each block in the batch,
        // then prune any stale entries at or below the highest committed
        // height.
        let max_committed_height = commits
            .iter()
            .map(|c| c.block.header.height.0)
            .max()
            .unwrap_or(0);

        // All blocks — consensus and sync — require a PreparedCommit from
        // VerifyStateRoot. Blocks without one are deferred until their
        // verification completes. Once any block defers, all subsequent
        // blocks in the batch defer too (preserves height ordering).
        let mut ready_commits: Vec<super::PendingCommit> = Vec::with_capacity(commits.len());
        let mut prepared_map: Vec<S::PreparedCommit> = Vec::with_capacity(commits.len());
        {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut deferring = false;
            for commit in commits {
                let prepared = if !deferring {
                    cache.remove(&commit.block.hash()).map(|(_, p)| p)
                } else {
                    None
                };

                let not_ready = prepared.is_none();

                if deferring || not_ready {
                    if !deferring {
                        tracing::debug!(
                            height = commit.block.header.height.0,
                            certs = commit.block.certificates.len(),
                            "Deferring block commit — awaiting PreparedCommit from VerifyStateRoot"
                        );
                        deferring = true;
                    }
                    // Put back prepared commit if we extracted one.
                    if let Some(p) = prepared {
                        let bh = commit.block.hash();
                        let h = commit.block.header.height.0;
                        cache.insert(bh, (h, p));
                    }
                    self.pending_block_commits.push(commit);
                } else {
                    prepared_map.push(prepared.unwrap());
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

        // Use the actual notification decision recorded at accumulation time,
        // not a re-derived value that could disagree due to persisted_height drift.
        let already_notified: Vec<bool> =
            ready_commits.iter().map(|c| c.committed_notified).collect();

        let commits = ready_commits;

        let storage = Arc::clone(&self.storage);
        let event_tx = self.event_sender.clone();
        let in_flight = self.commit_in_flight.clone();

        self.commit_in_flight.store(true, Ordering::Release);

        self.pending_commit_task = Some(Box::new(move || {
            // Build the batch for commit_prepared_blocks (single fsync for all).
            let mut batch: Vec<(
                S::PreparedCommit,
                Arc<hyperscale_types::Block>,
                Arc<hyperscale_types::QuorumCertificate>,
            )> = Vec::with_capacity(commits.len());

            let heights: Vec<u64> = commits.iter().map(|c| c.block.header.height.0).collect();
            let block_hashes: Vec<hyperscale_types::Hash> =
                commits.iter().map(|c| c.block.hash()).collect();

            // Wrap commits in Option so we can take() them for deferred notifications.
            let mut commit_slots: Vec<Option<super::PendingCommit>> =
                commits.into_iter().map(Some).collect();

            for (i, prepared) in prepared_map.into_iter().enumerate() {
                let commit = commit_slots[i].as_ref().unwrap();
                batch.push((prepared, Arc::clone(&commit.block), Arc::clone(&commit.qc)));
            }

            let _roots = storage.commit_prepared_blocks(batch);

            let max_persisted = heights.iter().copied().max().unwrap_or(0);

            // Send deferred BlockCommitted events for blocks that weren't notified
            // at accumulation time (due to persistence backpressure).
            for (i, &height) in heights.iter().enumerate() {
                if !already_notified[i] {
                    let commit = commit_slots[i].take().unwrap();
                    let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                        block_hash: block_hashes[i],
                        height,
                        block: Arc::unwrap_or_clone(commit.block),
                        provisions: commit.provisions,
                    }));
                }
            }

            // Clear the in-flight flag before sending BlockPersisted.
            // The channel send synchronizes-with recv on the main thread,
            // so the flag is guaranteed visible when the resulting
            // feed_event calls flush_block_commits to drain any backlog.
            in_flight.store(false, Ordering::Release);

            let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockPersisted {
                height: max_persisted,
            }));
        }));
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

        // Anchor + view for this action. Actions that don't read state
        // (no parent_hash_for) get the committed-tip view; the view is
        // unused but the construction is cheap (cache hit after first).
        let view = match action_handler::parent_hash_for(&action) {
            Some(parent_hash) => self.pending_chain.view_at(parent_hash),
            None => self.pending_chain.view_at_committed_tip(),
        };
        // Anchor parent for inserting the resulting ChainEntry into
        // PendingChain. For BuildProposal/VerifyStateRoot this is the
        // block-being-built/verified's parent. Other actions don't
        // produce prepared_commit so this is unused.
        let anchor_parent_hash = match &action {
            Action::VerifyStateRoot {
                parent_block_hash, ..
            } => Some(*parent_block_hash),
            Action::BuildProposal { parent_hash, .. } => Some(*parent_hash),
            _ => None,
        };

        // Clone cheap shared state for the 'static spawn closure.
        let executor = self.executor.clone();
        let topology_snapshot = self.topology.load_full();
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let pending_chain = Arc::clone(&self.pending_chain);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                executor: &executor,
                topology: &topology_snapshot,
                view,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    metrics::record_execution_latency(elapsed);
                }
                if let Some(prep) = result.prepared_commit {
                    let action_handler::PreparedBlock {
                        block_hash,
                        block_height,
                        prepared,
                        receipts,
                    } = prep;
                    if let Some(parent_hash) = anchor_parent_hash {
                        let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
                        pending_chain.insert(
                            block_hash,
                            hyperscale_storage::ChainEntry {
                                parent_hash,
                                height: block_height,
                                receipts,
                                jmt_snapshot,
                            },
                        );
                    }
                    prepared_commits
                        .lock()
                        .unwrap()
                        .insert(block_hash, (block_height, prepared));
                }
                for event in result.events {
                    let _ = event_tx.send(event);
                }
            }
        };

        match pool {
            DispatchPool::ConsensusCrypto => self.dispatch.spawn_consensus_crypto(spawn_fn),
            DispatchPool::Crypto => self.dispatch.spawn_crypto(spawn_fn),
            DispatchPool::StateRoot => self.dispatch.spawn_state_root(spawn_fn),
            DispatchPool::Execution => self.dispatch.spawn_execution(spawn_fn),
            DispatchPool::Provision => self.dispatch.spawn_provisions(spawn_fn),
        }
    }

    /// Local shard committee excluding self, for use as the `peers` argument
    /// to `network.request()`.
    pub(super) fn local_peers(&self) -> Vec<ValidatorId> {
        let topo = self.topology.load();
        topo.committee_for_shard(self.local_shard)
            .iter()
            .filter(|&&v| v != self.validator_id)
            .copied()
            .collect()
    }
}
