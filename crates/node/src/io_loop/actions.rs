//! Action processing and dispatch.

use std::sync::Arc;

use hyperscale_bft::action_handlers::handle_action as handle_bft_action;
use hyperscale_core::{
    Action, ActionContext, ActionOwner, CommitSource, FetchAbandon, FetchRequest, NodeInput,
    ProtocolEvent,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_execution::action_handlers::handle_action as handle_execution_action;
use hyperscale_metrics::record_transaction_finalized;
use hyperscale_network::Network;
use hyperscale_provisions::action_handlers::handle_action as handle_provisions_action;
use hyperscale_storage::Storage;
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, QuorumCertificate, ShardGroupId, StateRoot,
    TopologySnapshot, TransactionStatus, TxHash,
};
use tracing::{debug, trace, warn};

use super::{IoLoop, TimerOp, push_protocol_event, push_shard_input};
use crate::shard::block_commit::{AccumulateDecision, PendingCommit, make_commit_prepared};
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
                self.pending_timer_ops.push(TimerOp::Set {
                    shard,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { shard, id });
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
                self.accept_qc_only_commit(
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
                self.shard_io(shard)
                    .caches
                    .finalized_wave
                    .insert(wave.wave_id().clone(), Arc::clone(wave));
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance per-shard `committed` and emit `SyncComplete` once the
        // chain catches up. Drives any newly-emitted range fetches inline.
        if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = &pe {
            let outputs = self.shard_io_mut(shard).syncs.on_remote_header_admitted(
                committed_header.shard_group_id(),
                committed_header.header().height(),
            );
            self.process_remote_header_sync_outputs(shard, outputs);
        }

        push_protocol_event(&self.event_sender, shard, pe);
    }

    fn handle_restore_committed_state(&self, shard: ShardGroupId) {
        let storage = &self.shard_io(shard).storage;
        let height = storage.committed_height();
        let hash = storage.committed_hash();
        let qc = storage.latest_qc();
        push_protocol_event(
            &self.event_sender,
            shard,
            ProtocolEvent::CommittedStateRestored { height, hash, qc },
        );
    }

    fn handle_emit_transaction_status(
        &mut self,
        shard: ShardGroupId,
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
        self.shard_io(shard)
            .caches
            .tx_status
            .insert(tx_hash, status.clone());
        self.emitted_statuses.push((tx_hash, status));
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

    /// Bridge an [`Action::CommitBlockByQcOnly`] to the standard commit
    /// pipeline: ask [`BlockCommitCoordinator::prepare_qc_only_commit`]
    /// to compute / reuse the prepared commit and decide whether to
    /// enqueue, then call [`Self::accept_block_commit`] when it says so.
    ///
    /// [`BlockCommitCoordinator::prepare_qc_only_commit`]: crate::shard::block_commit::BlockCommitCoordinator::prepare_qc_only_commit
    fn accept_qc_only_commit(
        &mut self,
        shard: ShardGroupId,
        block: Block,
        qc: QuorumCertificate,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        source: CommitSource,
    ) {
        let io = self.shard_io(shard);
        let should_enqueue = io.block_commit.prepare_qc_only_commit(
            &io.pending_chain,
            &block,
            parent_state_root,
            parent_block_height,
            source,
        );
        if should_enqueue {
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
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: feed the sync protocol with the new committed height and,
    /// unless persistence backpressure is active, fire `BlockCommitted`.
    ///
    /// [`BlockCommitCoordinator`]: crate::shard::block_commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, shard: ShardGroupId, commit: PendingCommit) {
        let now = self.now();
        let decision = self
            .shard_io_mut(shard)
            .block_commit
            .accumulate(commit, now);
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted { height, notify_now } => {
                debug!(height = height.inner(), "Block committed");
                let outputs = self
                    .shard_io_mut(shard)
                    .syncs
                    .block
                    .handle(BlockSyncInput::Admitted { scope: (), height });
                self.process_block_sync_outputs(shard, outputs);
                if let Some((block, qc)) = notify_now {
                    let certified = Arc::new(CertifiedBlock::new_unchecked(
                        Arc::unwrap_or_clone(block),
                        Arc::unwrap_or_clone(qc),
                    ));
                    self.dispatch_event(shard, ProtocolEvent::BlockCommitted { certified });
                }
            }
        }
    }

    pub(super) fn flush_block_commits(&mut self, shard: ShardGroupId) {
        let event_sender = self.event_sender.clone();
        let dispatch = self.dispatch.clone();
        let io = self.shard_io_mut(shard);
        io.block_commit.flush(&io.storage, &event_sender, &dispatch);
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
            let shard_handles = handles
                .per_shard
                .get(&shard)
                .expect("hosted shard derived from vnode");
            // Action handlers emit raw `NodeInput`s; wrap each with the
            // dispatching vnode's shard so the receiver routes back to the
            // right `ShardGroup`.
            let notify = move |event: NodeInput| {
                push_shard_input(&event_tx, shard, event);
            };
            let commit_prepared = make_commit_prepared(
                Arc::clone(&shard_handles.pending_chain),
                Arc::clone(&shard_handles.prepared_commits),
            );
            let ctx = ActionContext {
                executor: &handles.executor,
                topology_snapshot: &topology_snapshot,
                pending_chain: &shard_handles.pending_chain,
                network: &handles.network,
                signing_key: &signing_key,
                notify: &notify,
                commit_prepared: &commit_prepared,
            };
            match action.owner() {
                ActionOwner::Bft => handle_bft_action(action, &ctx),
                ActionOwner::Execution => handle_execution_action(action, &ctx),
                ActionOwner::Provisions => handle_provisions_action(action, &ctx),
                ActionOwner::Local => unreachable!(
                    "dispatch_delegated_action called with Local-owned action — \
                     process_action's outer match should have routed inline"
                ),
            }
        });
    }
}
