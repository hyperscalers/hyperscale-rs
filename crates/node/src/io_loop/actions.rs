//! Action processing and dispatch.

use super::IoLoop;
use super::TimerOp;
use super::block_commit::{AccumulateDecision, PendingCommit};
use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::protocol::fetch::FetchInput;
use crate::protocol::fetch_instances;
use crate::protocol::sync::SyncInput;
use hyperscale_core::{Action, CommitSource, FetchRequest, NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainWriter, Storage};
use hyperscale_types::{Block, BlockHeight, QuorumCertificate, StateRoot, ValidatorId};
use std::sync::Arc;
use tracing::{debug, trace, warn};
impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action from the state machine.
    #[allow(clippy::too_many_lines)] // single dispatch over the Action enum; one arm per variant
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
                // Each fetch instance owns its own admission predicate; the
                // arm just dispatches the event through them. Adding a new
                // payload is one new helper + one line here.
                fetch_instances::apply_transactions_admission(&mut self.transaction_fetch, &pe);
                fetch_instances::apply_local_provisions_admission(
                    &mut self.local_provision_fetch,
                    &pe,
                );
                fetch_instances::apply_finalized_waves_admission(
                    &mut self.finalized_wave_fetch,
                    &pe,
                );
                fetch_instances::apply_provisions_admission(&mut self.provision_fetch, &pe);
                fetch_instances::apply_exec_certs_admission(&mut self.exec_cert_fetch, &pe);
                fetch_instances::apply_headers_admission(&mut self.header_fetch, &pe);

                // Serving-cache insertion is io_loop's own state, not an
                // instance concern — keep it here.
                if let ProtocolEvent::FinalizedWavesAdmitted { waves } = &pe {
                    for wave in waves {
                        self.caches
                            .finalized_wave
                            .insert(wave.wave_id_hash(), Arc::clone(wave));
                    }
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
                        header.height,
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
                        committed_header.header.height,
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
                vote_anchor_ts,
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
                    let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
                    let msg = hyperscale_types::exec_vote_message(
                        vote_anchor_ts,
                        &wave_id,
                        local_shard,
                        &global_receipt_root,
                        tx_count,
                    );
                    let sig = signing_key.sign_v1(&msg);
                    let vote = hyperscale_types::ExecutionVote {
                        block_hash,
                        block_height,
                        vote_anchor_ts,
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
                if let Ok(mut cache) = self.caches.exec_cert.lock() {
                    cache.insert(key, Arc::clone(&certificate));
                    if cache.len() > 2000 {
                        let cutoff = cache
                            .values()
                            .map(|c| c.block_height())
                            .max()
                            .unwrap_or(BlockHeight::GENESIS)
                            .saturating_sub(500);
                        cache.retain(|_, c| c.block_height() > cutoff);
                    }
                }
            }
            // Delegated work — dispatch to the worker pools.
            Action::AggregateExecutionCertificate { .. }
            | Action::VerifyAndAggregateExecutionVotes { .. }
            | Action::VerifyExecutionCertificateSignature { .. }
            | Action::BuildProposal { .. }
            | Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyRemoteHeaderQc { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyProvisionRoot { .. }
            | Action::VerifyCertificateRoot { .. }
            | Action::VerifyLocalReceiptRoot { .. }
            | Action::VerifyProvisionTxRoots { .. }
            | Action::VerifyProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::ExecuteCrossShardTransactions { .. }
            | Action::FetchAndBroadcastProvisions { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage
            // ═══════════════════════════════════════════════════════════
            Action::FetchChainMetadata => {
                let height = self.storage.committed_height();
                let hash = self.storage.committed_hash();
                let qc = self.storage.latest_qc();
                let _ = self.event_sender.send(NodeInput::Protocol(
                    ProtocolEvent::ChainMetadataFetched { height, hash, qc },
                ));
            }

            // ═══════════════════════════════════════════════════════════
            // Block commit + notifications
            // ═══════════════════════════════════════════════════════════
            Action::CommitBlock { block, qc, source } => {
                self.accept_block_commit(PendingCommit {
                    block: Arc::new(block),
                    qc: Arc::new(qc),
                    source,
                    committed_notified: false, // set by accumulate
                });
            }
            Action::CommitBlockByQcOnly {
                block,
                qc,
                parent_state_root,
                parent_block_height,
                source,
            } => {
                self.handle_commit_block_by_qc_only(
                    block,
                    qc,
                    parent_state_root,
                    parent_block_height,
                    source,
                );
            }
            Action::EmitTransactionStatus {
                tx_hash,
                status,
                cross_shard,
                submitted_locally,
            } => {
                trace!(?tx_hash, ?status, "Transaction status");
                let now = self.state.now();
                let terminal_phases = self.tx_phase_times.observe_status(tx_hash, &status, now);
                if status.is_final()
                    && submitted_locally
                    && let Some(phases) = terminal_phases
                {
                    let latency_secs = now.saturating_sub(phases.added_at()).as_secs_f64();
                    if latency_secs > 10.0 {
                        // Rate-limit slow tx warnings to avoid log floods during
                        // cross-shard latency spikes.
                        let since_last_warn = now.saturating_sub(self.last_slow_tx_warn);
                        if since_last_warn >= std::time::Duration::from_secs(30) {
                            self.last_slow_tx_warn = now;
                            let phases_display = phases.display_at(now);
                            warn!(
                                ?tx_hash,
                                latency_secs,
                                cross_shard,
                                %phases_display,
                                "Transaction finalization exceeded 10s"
                            );
                        }
                    }
                    metrics::record_transaction_finalized(latency_secs, cross_shard);
                }
                self.caches.tx_status.insert(tx_hash, status.clone());
                self.emitted_statuses.push((tx_hash, status));
            }
            Action::RecordTxEcCreated { tx_hashes } => {
                self.tx_phase_times
                    .record_ec_created(&tx_hashes, self.state.now());
            }

            // ═══════════════════════════════════════════════════════════
            // Sync / Fetch
            // ═══════════════════════════════════════════════════════════
            Action::StartSync { .. } | Action::Fetch(_) => {
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

    /// Handler for [`Action::CommitBlockByQcOnly`].
    ///
    /// Computes the prepared commit inline (unless the consensus path already
    /// produced one), inserts the resulting JMT snapshot into `PendingChain`
    /// so child blocks' `VerifyStateRoot` can resolve parent nodes through the
    /// overlay, then feeds the block into the standard commit pipeline.
    ///
    /// The inline-computed `PreparedCommit`'s `base_root` may be stale by
    /// flush time (other blocks committed in between). `commit_prepared_blocks`
    /// handles that via its fallback path — skip if already committed, else
    /// recompute.
    fn handle_commit_block_by_qc_only(
        &mut self,
        block: Block,
        qc: QuorumCertificate,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        source: CommitSource,
    ) {
        let block_hash = block.hash();
        let height = block.height();

        // Hard skip only if already persisted (consensus path got all the
        // way through). We must still enqueue blocks whose prepared commit
        // was populated by the consensus path but that never had
        // `BlockReadyToCommit` fire — e.g. a self-proposed block whose
        // child arrived via sync rather than consensus, so the 2-chain
        // commit rule never triggered. Dropping the block here leaves its
        // prepared commit orphaned in the cache, and the next block to
        // reach flush trips the strict ordering assert in
        // `commit_block_inner` because its parent was never applied.
        if height <= self.block_commit.persisted_height() {
            return;
        }

        // If the consensus path already produced the prepared commit
        // (VerifyStateRoot/ExecuteTransactions), reuse it — recomputing JMT
        // here can produce a transient root mismatch and trip the
        // byzantine-detection assert below on a self-inflicted race.
        if self.block_commit.has_prepared(&block_hash) {
            debug!(
                height = height.0,
                ?block_hash,
                "Reusing prepared commit from consensus path"
            );
        } else {
            // Build view anchored at parent — includes prior synced blocks'
            // JMT snapshots so chained verification can find parent nodes.
            let view = self.pending_chain.view_at(block.header().parent_hash);
            let pending_snapshots = view.pending_snapshots().to_vec();

            // Inline JMT computation (no commit_lock — only reads).
            let finalized_waves: Vec<Arc<hyperscale_types::FinalizedWave>> =
                block.certificates().to_vec();
            let (computed_root, prepared) = view.prepare_block_commit(
                parent_state_root,
                parent_block_height,
                &finalized_waves,
                height,
                &pending_snapshots,
                // `None` → the view drains its own base-read cache internally.
                None,
            );

            // Byzantine detection: state root mismatch is fatal.
            assert_eq!(
                computed_root,
                block.header().state_root,
                "State root mismatch for synced block at height {}",
                height.0
            );

            // Insert JMT snapshot into PendingChain so child blocks'
            // VerifyStateRoot can find this block's tree nodes via the overlay.
            let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
            let receipts: Vec<Arc<hyperscale_types::LocalReceipt>> = finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts.iter())
                .map(|b| Arc::clone(&b.local_receipt))
                .collect();
            self.pending_chain.insert(
                block_hash,
                hyperscale_storage::ChainEntry {
                    parent_hash: block.header().parent_hash,
                    height,
                    receipts,
                    jmt_snapshot,
                },
            );

            self.block_commit
                .insert_prepared(block_hash, height, prepared);

            debug!(
                height = height.0,
                ?block_hash,
                "Synced block prepared, queued for persist"
            );
        }

        // Feed into the standard commit pipeline — accept_block_commit
        // fires BlockCommitted immediately, flush_block_commits batches the
        // RocksDB write with a single fsync. The coordinator dedups by
        // block_hash so double-emission (consensus + sync both reaching
        // commit) is safe.
        self.accept_block_commit(PendingCommit {
            block: Arc::new(block),
            qc: Arc::new(qc),
            source,
            committed_notified: false,
        });
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: feed the sync protocol with the new committed height and,
    /// unless persistence backpressure is active, fire `BlockCommitted`.
    ///
    /// [`BlockCommitCoordinator`]: super::block_commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, commit: PendingCommit) {
        let now = self.state.now();
        let decision = self.block_commit.accumulate(commit, now);
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted { height, notify_now } => {
                debug!(height = height.0, "Block committed");
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockCommitted { height });
                self.process_sync_outputs(outputs);
                if let Some((block, qc)) = notify_now {
                    let certified = hyperscale_types::CertifiedBlock::new_unchecked(
                        Arc::unwrap_or_clone(block),
                        Arc::unwrap_or_clone(qc),
                    );
                    self.feed_event(ProtocolEvent::BlockCommitted { certified });
                }
            }
        }
    }

    pub(super) fn flush_block_commits(&mut self) {
        self.block_commit.flush(&self.storage, &self.event_sender);
    }

    /// Process sync and unified-fetch actions.
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
            Action::Fetch(req) => self.process_fetch_request(req),
            _ => unreachable!(),
        }
    }

    /// Dispatch a typed fetch request to the corresponding instance binding.
    ///
    /// `Request` never emits `Send`s on its own — it only adds the ids to the
    /// pending set; chunks fan out under the per-tick cap. Each arm therefore
    /// feeds `Request`, then drives `Tick` and dispatches its outputs through
    /// the per-instance processor. The tick timer is refreshed once at the end.
    #[allow(clippy::too_many_lines)] // single dispatch, one arm per FetchRequest variant
    fn process_fetch_request(&mut self, req: FetchRequest) {
        match req {
            FetchRequest::Transactions { ids, peers } => {
                self.transaction_fetch
                    .handle(FetchInput::Request { ids, peers });
                let outputs = self.transaction_fetch.handle(FetchInput::Tick);
                self.process_transaction_fetch_outputs(outputs);
            }
            FetchRequest::LocalProvisions { ids, peers } => {
                self.local_provision_fetch
                    .handle(FetchInput::Request { ids, peers });
                let outputs = self.local_provision_fetch.handle(FetchInput::Tick);
                self.process_local_provision_fetch_outputs(outputs);
            }
            FetchRequest::FinalizedWaves { ids, peers } => {
                self.finalized_wave_fetch
                    .handle(FetchInput::Request { ids, peers });
                let outputs = self.finalized_wave_fetch.handle(FetchInput::Tick);
                self.process_finalized_wave_fetch_outputs(outputs);
            }
            FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                peers,
            } => {
                debug_assert!(
                    peers.preferred.is_some() || !peers.peers.is_empty(),
                    "RemoteProvisions for shard {} height {} has no peers — \
                     was the action enriched by NodeStateMachine?",
                    source_shard.0,
                    block_height.0,
                );
                debug!(
                    source_shard = source_shard.0,
                    block_height = block_height.0,
                    peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                    "Requesting missing provisions from source shard"
                );
                self.provision_fetch.handle(FetchInput::Request {
                    ids: vec![(source_shard, block_height)],
                    peers,
                });
                let outputs = self.provision_fetch.handle(FetchInput::Tick);
                self.process_provision_fetch_outputs(outputs);
            }
            FetchRequest::ExecutionCerts { wave_id, peers } => {
                debug!(
                    wave = %wave_id,
                    peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                    "Requesting missing execution cert from source shard"
                );
                self.exec_cert_fetch.handle(FetchInput::Request {
                    ids: vec![wave_id],
                    peers,
                });
                let outputs = self.exec_cert_fetch.handle(FetchInput::Tick);
                self.process_exec_cert_fetch_outputs(outputs);
            }
            FetchRequest::RemoteHeader {
                source_shard,
                from_height,
                peers,
            } => {
                debug!(
                    source_shard = source_shard.0,
                    from_height = from_height.0,
                    peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                    "Requesting missing committed block header from source shard"
                );
                self.header_fetch.handle(FetchInput::Request {
                    ids: vec![(source_shard, from_height)],
                    peers,
                });
                let outputs = self.header_fetch.handle(FetchInput::Tick);
                self.process_header_fetch_outputs(outputs);
            }
        }

        self.update_fetch_tick_timer();
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via the
    /// `event_sender` channel and are processed on a future `step()` call.
    /// With `SyncDispatch` (simulation), `spawn_*` runs inline so events
    /// enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&self, action: Action) {
        let is_execution = matches!(
            action,
            Action::ExecuteTransactions { .. } | Action::ExecuteCrossShardTransactions { .. }
        );
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Anchor + view for this action. Actions that don't read state
        // (no parent_hash_for) get the committed-tip view; the view is
        // unused but the construction is cheap (cache hit after first).
        let view = action_handler::parent_hash_for(&action).map_or_else(
            || self.pending_chain.view_at_committed_tip(),
            |parent_hash| self.pending_chain.view_at(parent_hash),
        );
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
        let prepared_commits = self.block_commit.prepared_commits_handle();
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
            DispatchPool::Execution => self.dispatch.spawn_execution(spawn_fn),
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
