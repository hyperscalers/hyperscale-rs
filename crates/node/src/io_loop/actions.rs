//! Action processing and dispatch.

use std::sync::Arc;

use hyperscale_bft::action_handlers::handle_action as handle_bft_action;
use hyperscale_core::{
    Action, ActionContext, CommitSource, FetchAbandon, FetchRequest, NodeInput, PreparedBlock,
    ProtocolEvent,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_execution::action_handlers::handle_action as handle_execution_action;
use hyperscale_metrics::record_transaction_finalized;
use hyperscale_network::Network;
use hyperscale_provisions::action_handlers::handle_action as handle_provisions_action;
use hyperscale_storage::{ChainEntry, ChainWriter, Storage};
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, ConsensusReceipt, FinalizedWave, QuorumCertificate,
    ShardGroupId, StateRoot, TopologySnapshot, TransactionStatus, TxHash,
};
use tracing::{debug, error, trace, warn};

use super::{IoLoop, ShardEvent, TimerOp};
use crate::shard::block_commit::{AccumulateDecision, PendingCommit};
use crate::shard::fetch::FetchInput;
use crate::shard::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::shard::sync::block::BlockSyncInput;
impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action emitted by the vnode at `(shard, vnode_idx)`'s
    /// state machine.
    ///
    /// `(shard, vnode_idx)` identifies the vnode that produced the action
    /// so dispatched off-thread work can sign with the right validator's
    /// key.
    ///
    /// Two categories of arm:
    /// - **Coordinator policy** — delegated to coordinator crates via
    ///   `dispatch_delegated_action`. Crypto, execution, broadcasts.
    /// - **`io_loop`-internal effects** — handled inline because the work IS
    ///   `io_loop` machinery (timers, caches consumed by `io_loop`-side
    ///   serving, RPC observability, block commit pipeline, topology
    ///   plumbing).
    pub(super) fn process_action(&mut self, shard: ShardGroupId, vnode_idx: usize, action: Action) {
        match action {
            // ─── Coordinator policy: delegated to worker pools ─────────────
            Action::AggregateExecutionCertificate { .. }
            | Action::VerifyAndAggregateExecutionVotes { .. }
            | Action::VerifyExecutionCertificateSignature { .. }
            | Action::VerifyFinalizedWave { .. }
            | Action::BuildProposal { .. }
            | Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyRemoteHeaderQc { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyProvisionRoot { .. }
            | Action::VerifyCertificateRoot { .. }
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
                self.dispatch_delegated_action(shard, vnode_idx, action);
            }

            // ─── Sync / fetch protocol drive ───────────────────────────────
            Action::StartBlockSync { target } => {
                self.process_start_block_sync(shard, target);
            }
            Action::StartRemoteHeaderSync {
                source_shard,
                target,
            } => self.process_start_remote_header_sync(shard, source_shard, target),
            Action::Fetch(req) => self.process_fetch_request(shard, req),
            Action::AbandonFetch(req) => self.process_fetch_abandon(shard, req),

            // ─── io_loop-internal effects ──────────────────────────────────
            Action::SetTimer { id, duration } => {
                self.vnode_mut(shard, vnode_idx)
                    .pending_timer_ops
                    .push(TimerOp::Set {
                        shard,
                        id,
                        duration,
                    });
            }
            Action::CancelTimer { id } => {
                self.vnode_mut(shard, vnode_idx)
                    .pending_timer_ops
                    .push(TimerOp::Cancel { shard, id });
            }
            Action::Continuation(pe) => self.handle_continuation(shard, pe),
            Action::RestoreCommittedState => self.handle_restore_committed_state(shard),
            Action::CommitBlock { block, qc, source } => {
                self.accept_block_commit(
                    shard,
                    PendingCommit {
                        block: Arc::new(block),
                        qc: Arc::new(qc),
                        source,
                        committed_notified: false, // set by accumulate
                    },
                );
            }
            Action::CommitBlockByQcOnly {
                block,
                qc,
                parent_state_root,
                parent_block_height,
                source,
            } => {
                self.handle_commit_block_by_qc_only(
                    shard,
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
                    shard,
                    vnode_idx,
                    tx_hash,
                    status,
                    cross_shard,
                    submitted_locally,
                );
            }
            Action::RecordTxEcCreated { tx_hashes } => {
                self.tx_phase_times
                    .record_ec_created(&tx_hashes, self.now());
            }
            Action::TopologyChanged { topology_snapshot } => {
                self.handle_topology_changed(&topology_snapshot);
            }
        }
    }

    // ─── io_loop-internal effect handlers ────────────────────────────────
    //
    // These arms are handled inline (not delegated) because the work IS
    // `io_loop` state — caches consumed by `io_loop`-side serving, RPC
    // observability, topology plumbing. Migrating them to coordinator
    // crates would force a typed cache reference onto `ActionContext` per
    // arm, with no architectural payoff.

    fn handle_continuation(&mut self, shard: ShardGroupId, pe: ProtocolEvent) {
        self.drive_fetch_admission(shard, &pe);

        // Serving-cache insertion is io_loop's own state, not an
        // instance concern — keep it here.
        if let ProtocolEvent::FinalizedWavesAdmitted { waves } = &pe {
            for wave in waves {
                self.shard_caches(shard)
                    .finalized_wave
                    .insert(wave.wave_id().clone(), Arc::clone(wave));
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance per-shard `committed` and emit `SyncComplete` once the
        // chain catches up. Drives any newly-emitted range fetches inline.
        if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = &pe {
            let outputs = self.shard_syncs_mut(shard).on_remote_header_admitted(
                committed_header.shard_group_id(),
                committed_header.header().height(),
            );
            self.process_remote_header_sync_outputs(shard, outputs);
        }

        let _ = self.event_sender.send(ShardEvent::protocol(shard, pe));
    }

    fn handle_restore_committed_state(&self, shard: ShardGroupId) {
        let storage = self.shard_storage(shard);
        let height = storage.committed_height();
        let hash = storage.committed_hash();
        let qc = storage.latest_qc();
        let _ = self.event_sender.send(ShardEvent::protocol(
            shard,
            ProtocolEvent::CommittedStateRestored { height, hash, qc },
        ));
    }

    fn handle_emit_transaction_status(
        &mut self,
        shard: ShardGroupId,
        vnode_idx: usize,
        tx_hash: TxHash,
        status: TransactionStatus,
        cross_shard: bool,
        submitted_locally: bool,
    ) {
        trace!(?tx_hash, ?status, "Transaction status");
        let now = self.now();
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
            record_transaction_finalized(latency_secs, cross_shard);
        }
        self.shard_caches(shard)
            .tx_status
            .insert(tx_hash, status.clone());
        self.vnode_mut(shard, vnode_idx)
            .emitted_statuses
            .push((tx_hash, status));
    }

    fn handle_topology_changed(&self, topology: &Arc<TopologySnapshot>) {
        self.topology_snapshot.store(Arc::clone(topology));

        // Network impl reads validator keys + shard committees off the
        // snapshot it gets here — no separate keymap push.
        self.network.update_topology(Arc::clone(topology));

        tracing::info!(
            local_shard = topology.local_shard().inner(),
            committee_size = topology.committee_for_shard(topology.local_shard()).len(),
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
    #[allow(clippy::too_many_arguments)] // unpacks Action::CommitBlockByQcOnly
    fn handle_commit_block_by_qc_only(
        &mut self,
        shard: ShardGroupId,
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
        if height <= self.shard_block_commit(shard).persisted_height() {
            return;
        }

        // If the consensus path already produced the prepared commit
        // (VerifyStateRoot/ExecuteTransactions), reuse it — recomputing JMT
        // here can produce a transient root mismatch and trip the
        // byzantine-detection assert below on a self-inflicted race.
        if self.shard_block_commit(shard).has_prepared(&block_hash) {
            debug!(
                height = height.inner(),
                ?block_hash,
                "Reusing prepared commit from consensus path"
            );
        } else {
            // Build view anchored at parent — includes prior synced blocks'
            // JMT snapshots so chained verification can find parent nodes.
            let view = self
                .shard_pending_chain(shard)
                .view_at(block.header().parent_block_hash());
            let pending_snapshots = view.pending_snapshots().to_vec();

            // Inline JMT computation (no commit_lock — only reads).
            let finalized_waves: Vec<Arc<FinalizedWave>> = block.certificates().to_vec();
            let (computed_root, prepared) = view.prepare_block_commit(
                parent_state_root,
                parent_block_height,
                &finalized_waves,
                height,
                &pending_snapshots,
                // `None` → the view drains its own base-read cache internally.
                None,
            );

            // The sync-block ingress validator rejects peer-shipped
            // divergent receipts before BFT sees the block, and
            // `WaveState`'s divergence detector keeps locally-produced
            // bad receipts out of `finalized`. A mismatch here means our
            // local parent state itself diverged from canonical — a JMT
            // or commit-batch bug, or pre-existing corruption in
            // `StateCf`. Block-by-block sync can't repair this; the
            // operator must restore from a state snapshot or
            // wipe-and-resync from genesis.
            if computed_root != block.header().state_root() {
                error!(
                    height = height.inner(),
                    ?block_hash,
                    expected_root = ?block.header().state_root(),
                    computed_root = ?computed_root,
                    ?parent_state_root,
                    parent_block_height = parent_block_height.inner(),
                    ?source,
                    "Local state divergence detected on synced block apply — \
                     parent state does not produce the canonical state root. \
                     Rebuild required: restore from state snapshot or \
                     resync from genesis."
                );
                panic!(
                    "Local state divergence at height {}: parent state root \
                     {parent_state_root:?} does not produce canonical state \
                     root {expected:?} (computed {computed:?}). Operator \
                     intervention required.",
                    height.inner(),
                    expected = block.header().state_root(),
                    computed = computed_root,
                );
            }

            // Insert JMT snapshot into PendingChain so child blocks'
            // VerifyStateRoot can find this block's tree nodes via the overlay.
            let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
            let receipts: Vec<Arc<ConsensusReceipt>> = finalized_waves
                .iter()
                .flat_map(|fw| fw.consensus_receipts())
                .collect();
            self.shard_pending_chain(shard).insert(
                block_hash,
                ChainEntry {
                    parent_block_hash: block.header().parent_block_hash(),
                    height,
                    receipts,
                    jmt_snapshot,
                },
            );

            self.shard_block_commit_mut(shard)
                .insert_prepared(block_hash, height, prepared);

            debug!(
                height = height.inner(),
                ?block_hash,
                "Synced block prepared, queued for persist"
            );
        }

        // Feed into the standard commit pipeline — accept_block_commit
        // fires BlockCommitted immediately, flush_block_commits batches the
        // RocksDB write with a single fsync. The coordinator dedups by
        // block_hash so double-emission (consensus + sync both reaching
        // commit) is safe.
        self.accept_block_commit(
            shard,
            PendingCommit {
                block: Arc::new(block),
                qc: Arc::new(qc),
                source,
                committed_notified: false,
            },
        );
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: feed the sync protocol with the new committed height and,
    /// unless persistence backpressure is active, fire `BlockCommitted`.
    ///
    /// [`BlockCommitCoordinator`]: crate::shard::block_commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, shard: ShardGroupId, commit: PendingCommit) {
        let now = self.now();
        let decision = self.shard_block_commit_mut(shard).accumulate(commit, now);
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted { height, notify_now } => {
                debug!(height = height.inner(), "Block committed");
                let outputs = self
                    .shard_syncs_mut(shard)
                    .block
                    .handle(BlockSyncInput::Admitted { scope: (), height });
                self.process_block_sync_outputs(shard, outputs);
                if let Some((block, qc)) = notify_now {
                    let certified = Arc::new(CertifiedBlock::new_unchecked(
                        Arc::unwrap_or_clone(block),
                        Arc::unwrap_or_clone(qc),
                    ));
                    self.feed_event_to_shard_vnodes(
                        shard,
                        ProtocolEvent::BlockCommitted { certified },
                    );
                }
            }
        }
    }

    pub(super) fn flush_block_commits(&mut self, shard: ShardGroupId) {
        // Clone shared handles before the `&mut self` reborrow for
        // `shard_block_commit_mut(shard)`. Dispatch is `Arc`-backed; cheap.
        let storage = Arc::clone(self.shard_storage(shard));
        let event_sender = self.event_sender.clone();
        let dispatch = self.dispatch.clone();
        self.shard_block_commit_mut(shard)
            .flush(&storage, &event_sender, &dispatch);
    }

    /// Dispatch a typed fetch request to the corresponding binding.
    ///
    /// `local_shard` identifies which hosted shard's [`FetchHost`] owns
    /// the request — it's the shard of the emitting vnode, not the
    /// routing target. The routing target (where to send the request)
    /// lives on the [`FetchRequest`] variant itself as a `shard` /
    /// `source_shard` field. `Request` never emits `Send`s on its own —
    /// it only adds the ids to the pending set; chunks fan out under
    /// the per-tick cap. The tick timer is refreshed once at the end.
    ///
    /// [`FetchHost`]: crate::shard::fetch::FetchHost
    fn process_fetch_request(&mut self, local_shard: ShardGroupId, req: FetchRequest) {
        match req {
            FetchRequest::Transactions {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<TransactionBinding>(
                    local_shard,
                    FetchInput::Request {
                        ids,
                        shard,
                        preferred,
                        class,
                    },
                );
            }
            FetchRequest::LocalProvisions {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<LocalProvisionBinding>(
                    local_shard,
                    FetchInput::Request {
                        ids,
                        shard,
                        preferred,
                        class,
                    },
                );
            }
            FetchRequest::FinalizedWaves {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<FinalizedWaveBinding>(
                    local_shard,
                    FetchInput::Request {
                        ids,
                        shard,
                        preferred,
                        class,
                    },
                );
            }
            FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                preferred,
                class,
            } => {
                self.drive_fetch::<ProvisionBinding>(
                    local_shard,
                    FetchInput::Request {
                        ids: vec![(source_shard, local_shard, block_height)],
                        shard: source_shard,
                        preferred,
                        class,
                    },
                );
            }
            FetchRequest::ExecutionCerts {
                wave_id,
                preferred,
                class,
            } => {
                let source_shard = wave_id.shard_group_id();
                self.drive_fetch::<ExecCertBinding>(
                    local_shard,
                    FetchInput::Request {
                        ids: vec![wave_id],
                        shard: source_shard,
                        preferred,
                        class,
                    },
                );
            }
        }

        self.update_fetch_tick_timer();
    }

    /// Dispatch a typed fetch-abandon to the corresponding binding.
    ///
    /// `local_shard` selects which hosted shard's [`FetchHost`] to
    /// notify — the abandoning vnode's shard, not the routing target
    /// of the original request. Symmetric to
    /// [`Self::process_fetch_request`] — translates the variant payload
    /// into ids and feeds them through `FetchInput::Abandoned`, which
    /// removes them from the binding's pending set and increments
    /// `record_fetch_abandoned` so the cancellation is observable
    /// separately from genuine admissions. Refreshes the tick timer
    /// once at the end (the pending set may now be empty).
    ///
    /// [`FetchHost`]: crate::shard::fetch::FetchHost
    #[allow(clippy::needless_pass_by_value)] // mirrors process_fetch_request; future variants carry Vec ids
    fn process_fetch_abandon(&mut self, local_shard: ShardGroupId, req: FetchAbandon) {
        match req {
            FetchAbandon::Transactions { ids } => {
                self.drive_fetch::<TransactionBinding>(local_shard, FetchInput::Abandoned { ids });
            }
            FetchAbandon::RemoteProvisions {
                source_shard,
                block_height,
            } => {
                self.drive_fetch::<ProvisionBinding>(
                    local_shard,
                    FetchInput::Abandoned {
                        ids: vec![(source_shard, local_shard, block_height)],
                    },
                );
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
    fn dispatch_delegated_action(&self, shard: ShardGroupId, vnode_idx: usize, action: Action) {
        let pool = action
            .dispatch_pool()
            .expect("dispatch_delegated_action called for delegated actions only");

        let handles = Arc::clone(&self.dispatch_handles);
        let vnode = self.vnode(shard, vnode_idx);
        // Per-vnode snapshot so the handler's `local_validator_id`
        // matches the signing key used.
        let topology_snapshot = Arc::clone(vnode.state.topology_arc());
        let event_tx = self.event_sender.clone();
        let signing_key = Arc::clone(&vnode.signing_key);

        self.dispatch.spawn(pool, move || {
            // Action handlers emit raw `NodeInput`s; wrap each with the
            // dispatching vnode's shard so the receiver routes back to the
            // right `ShardGroup`.
            let notify = move |event: NodeInput| {
                let _ = event_tx.send(ShardEvent::shard(shard, event));
            };
            let shard_handles = handles
                .per_shard
                .get(&shard)
                .expect("hosted shard derived from vnode");
            // `commit_prepared` is a `move` closure; capture per-shard Arcs
            // rather than borrowing `handles` (which the outer
            // `ActionContext` borrows below).
            let pending_chain_for_commit = Arc::clone(&shard_handles.pending_chain);
            let prepared_commits_for_commit = Arc::clone(&shard_handles.prepared_commits);
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
                    ChainEntry {
                        parent_block_hash,
                        height: block_height,
                        receipts,
                        jmt_snapshot,
                    },
                );
                prepared_commits_for_commit
                    .lock()
                    .unwrap()
                    .insert(block_hash, (block_height, prepared));
            };
            let ctx = ActionContext {
                executor: &handles.executor,
                topology_snapshot: &topology_snapshot,
                pending_chain: &shard_handles.pending_chain,
                network: &handles.network,
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
                | Action::VerifyStateRoot { .. }
                | Action::BuildProposal { .. }
                | Action::BroadcastBlockHeader { .. }
                | Action::SignAndBroadcastBlockVote { .. }
                | Action::BroadcastCommittedBlockHeader { .. } => {
                    handle_bft_action(action, &ctx);
                }

                Action::AggregateExecutionCertificate { .. }
                | Action::VerifyAndAggregateExecutionVotes { .. }
                | Action::VerifyExecutionCertificateSignature { .. }
                | Action::VerifyFinalizedWave { .. }
                | Action::ExecuteTransactions { .. }
                | Action::ExecuteCrossShardTransactions { .. }
                | Action::SignAndSendExecutionVote { .. }
                | Action::BroadcastExecutionCertificate { .. } => {
                    handle_execution_action(action, &ctx);
                }

                Action::VerifyProvisions { .. } | Action::FetchAndBroadcastProvisions { .. } => {
                    handle_provisions_action(action, &ctx);
                }

                _ => {}
            }
        });
    }
}
