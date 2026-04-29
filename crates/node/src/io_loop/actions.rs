//! Action processing and dispatch.

use super::IoLoop;
use super::TimerOp;
use super::block_commit::{AccumulateDecision, PendingCommit};
use crate::io_loop::protocol::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::io_loop::protocol::block_sync::BlockSyncInput;
use crate::io_loop::protocol::fetch::FetchInput;
use hyperscale_core::{
    Action, ActionContext, CommitSource, FetchRequest, NodeInput, PreparedBlock, ProtocolEvent,
    StateMachine,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainWriter, Storage};
use hyperscale_types::{Block, BlockHeight, QuorumCertificate, StateRoot, TxHash, ValidatorId};
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
    ///
    /// Two categories of arm:
    /// - **Coordinator policy** — delegated to coordinator crates via
    ///   `dispatch_delegated_action`. Crypto, execution, broadcasts.
    /// - **`io_loop`-internal effects** — handled inline because the work IS
    ///   `io_loop` machinery (timers, caches consumed by `io_loop`-side
    ///   serving, RPC observability, block commit pipeline, topology
    ///   plumbing).
    pub(super) fn process_action(&mut self, action: Action) {
        match action {
            // ─── Coordinator policy: delegated to worker pools ─────────────
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
            | Action::FetchAndBroadcastProvisions { .. }
            | Action::BroadcastBlockHeader { .. }
            | Action::SignAndBroadcastBlockVote { .. }
            | Action::BroadcastCommittedBlockHeader { .. }
            | Action::SignAndSendExecutionVote { .. }
            | Action::BroadcastExecutionCertificate { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ─── Sync / fetch protocol drive ───────────────────────────────
            Action::StartBlockSync { target } => {
                self.process_start_block_sync(target);
            }
            Action::StartRemoteHeaderSync {
                source_shard,
                target,
            } => self.process_start_remote_header_sync(source_shard, target),
            Action::Fetch(req) => self.process_fetch_request(req),

            // ─── io_loop-internal effects ──────────────────────────────────
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set { id, duration });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { id });
            }
            Action::Continuation(pe) => self.handle_continuation(pe),
            Action::TrackExecutionCertificate { certificate } => {
                self.handle_track_execution_certificate(&certificate);
            }
            Action::RestoreCommittedState => self.handle_restore_committed_state(),
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
                self.handle_emit_transaction_status(
                    tx_hash,
                    status,
                    cross_shard,
                    submitted_locally,
                );
            }
            Action::RecordTxEcCreated { tx_hashes } => {
                self.tx_phase_times
                    .record_ec_created(&tx_hashes, self.state.now());
            }
            Action::TopologyChanged { topology } => self.handle_topology_changed(&topology),

            // ─── Global consensus / epoch (not yet implemented) ────────────
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

    // ─── io_loop-internal effect handlers ────────────────────────────────
    //
    // These arms are handled inline (not delegated) because the work IS
    // `io_loop` state — caches consumed by `io_loop`-side serving, RPC
    // observability, topology plumbing. Migrating them to coordinator
    // crates would force a typed cache reference onto `ActionContext` per
    // arm, with no architectural payoff.

    fn handle_continuation(&mut self, pe: ProtocolEvent) {
        self.protocols.apply_admission(&pe);

        // Serving-cache insertion is io_loop's own state, not an
        // instance concern — keep it here.
        if let ProtocolEvent::FinalizedWavesAdmitted { waves } = &pe {
            for wave in waves {
                self.caches
                    .finalized_wave
                    .insert(wave.wave_id_hash(), Arc::clone(wave));
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance per-shard `committed` and emit `SyncComplete` once the
        // chain catches up. Drives any newly-emitted range fetches inline.
        if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = &pe {
            let outputs = self.protocols.on_remote_header_admitted(
                committed_header.shard_group_id(),
                committed_header.header.height,
            );
            self.process_remote_header_sync_outputs(outputs);
        }

        let _ = self.event_sender.send(NodeInput::Protocol(Box::new(pe)));
    }

    fn handle_track_execution_certificate(
        &self,
        certificate: &Arc<hyperscale_types::ExecutionCertificate>,
    ) {
        // Cache for serving EC fetch requests from remote shards.
        // Persistence is handled via wave certificates in block.certificates.
        let key = (certificate.wave_id.hash(), certificate.wave_id.clone());
        if let Ok(mut cache) = self.caches.exec_cert.lock() {
            cache.insert(key, Arc::clone(certificate));
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

    fn handle_restore_committed_state(&self) {
        let height = self.storage.committed_height();
        let hash = self.storage.committed_hash();
        let qc = self.storage.latest_qc();
        let _ = self.event_sender.send(NodeInput::Protocol(Box::new(
            ProtocolEvent::CommittedStateRestored { height, hash, qc },
        )));
    }

    fn handle_emit_transaction_status(
        &mut self,
        tx_hash: TxHash,
        status: hyperscale_types::TransactionStatus,
        cross_shard: bool,
        submitted_locally: bool,
    ) {
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

    fn handle_topology_changed(&mut self, topology: &Arc<hyperscale_types::TopologySnapshot>) {
        self.topology.store(Arc::clone(topology));
        self.rebuild_topology_cache_from(topology);

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
            let view = self.pending_chain.view_at(block.header().parent_block_hash);
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
                    parent_block_hash: block.header().parent_block_hash,
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
                    .protocols
                    .block_sync
                    .handle(BlockSyncInput::Admitted { scope: (), height });
                self.process_block_sync_outputs(outputs);
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
        self.block_commit
            .flush(&self.storage, &self.event_sender, &self.dispatch);
    }

    /// Dispatch a typed fetch request to the corresponding binding.
    ///
    /// `Request` never emits `Send`s on its own — it only adds the ids to
    /// the pending set; chunks fan out under the per-tick cap. Each arm
    /// translates the variant payload into ids+peers and delegates to
    /// `drive_fetch::<B>`. The tick timer is refreshed once at the end.
    fn process_fetch_request(&mut self, req: FetchRequest) {
        match req {
            FetchRequest::Transactions { ids, peers } => {
                self.drive_fetch::<TransactionBinding>(FetchInput::Request { ids, peers });
            }
            FetchRequest::LocalProvisions { ids, peers } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Request { ids, peers });
            }
            FetchRequest::FinalizedWaves { ids, peers } => {
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Request { ids, peers });
            }
            FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                peers,
            } => self.drive_fetch::<ProvisionBinding>(FetchInput::Request {
                ids: vec![(source_shard, block_height)],
                peers,
            }),
            FetchRequest::ExecutionCerts { wave_id, peers } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Request {
                    ids: vec![wave_id],
                    peers,
                });
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
        let pool = action
            .dispatch_pool()
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let executor = self.executor.clone();
        let topology_snapshot = self.topology.load_full();
        let prepared_commits = self.block_commit.prepared_commits_handle();
        let pending_chain = Arc::clone(&self.pending_chain);
        let network = Arc::clone(&self.network);
        let signing_key = Arc::clone(&self.signing_key);
        let event_tx = self.event_sender.clone();

        self.dispatch.spawn(pool, move || {
            let notify = move |event: NodeInput| {
                let _ = event_tx.send(event);
            };
            let pending_chain_for_commit = Arc::clone(&pending_chain);
            let commit_prepared = move |prep: PreparedBlock<S::PreparedCommit>| {
                let PreparedBlock {
                    block_hash,
                    parent_block_hash,
                    block_height,
                    prepared,
                    receipts,
                } = prep;
                let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
                pending_chain_for_commit.insert(
                    block_hash,
                    hyperscale_storage::ChainEntry {
                        parent_block_hash,
                        height: block_height,
                        receipts,
                        jmt_snapshot,
                    },
                );
                prepared_commits
                    .lock()
                    .unwrap()
                    .insert(block_hash, (block_height, prepared));
            };
            let ctx = ActionContext {
                executor: &executor,
                topology: &topology_snapshot,
                pending_chain: &pending_chain,
                network: &network,
                signing_key: &signing_key,
                notify: &notify,
                commit_prepared: &commit_prepared,
            };
            // Route to the coordinator crate that owns this Action variant.
            match &action {
                Action::VerifyAndBuildQuorumCertificate { .. }
                | Action::VerifyQcSignature { .. }
                | Action::VerifyRemoteHeaderQc { .. }
                | Action::VerifyTransactionRoot { .. }
                | Action::VerifyProvisionTxRoots { .. }
                | Action::VerifyProvisionRoot { .. }
                | Action::VerifyCertificateRoot { .. }
                | Action::VerifyLocalReceiptRoot { .. }
                | Action::VerifyStateRoot { .. }
                | Action::BuildProposal { .. }
                | Action::BroadcastBlockHeader { .. }
                | Action::SignAndBroadcastBlockVote { .. }
                | Action::BroadcastCommittedBlockHeader { .. } => {
                    hyperscale_bft::action_handlers::handle_action(action, &ctx);
                }

                Action::AggregateExecutionCertificate { .. }
                | Action::VerifyAndAggregateExecutionVotes { .. }
                | Action::VerifyExecutionCertificateSignature { .. }
                | Action::ExecuteTransactions { .. }
                | Action::ExecuteCrossShardTransactions { .. }
                | Action::SignAndSendExecutionVote { .. }
                | Action::BroadcastExecutionCertificate { .. } => {
                    hyperscale_execution::action_handlers::handle_action(action, &ctx);
                }

                Action::VerifyProvisions { .. } | Action::FetchAndBroadcastProvisions { .. } => {
                    hyperscale_provisions::action_handlers::handle_action(action, &ctx);
                }

                _ => {}
            }
        });
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
