//! Action processing and dispatch.

use std::sync::Arc;

use hyperscale_beacon::action_handlers::handle_action as handle_beacon_action;
use hyperscale_core::{
    Action, ActionContext, ActionOwner, CommitSource, FetchAbandon, FetchRequest, ProtocolEvent,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_execution::action_handlers::handle_action as handle_execution_action;
use hyperscale_metrics::record_transaction_finalized;
use hyperscale_network::Network;
use hyperscale_provisions::action_handlers::handle_action as handle_provisions_action;
use hyperscale_shard::action_handlers::handle_action as handle_shard_action;
use hyperscale_storage::{BeaconWitnessCommit, ShardStorage};
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, QuorumCertificate, StateRoot, TopologySnapshot,
    TransactionStatus, TxHash,
};
use tracing::{debug, error, trace, warn};

use super::{ShardLoop, ShardScopedInput, TimerOp, push_protocol_event, push_shard_input};
use crate::shard_io::block_commit::{
    AccumulateDecision, PendingCommit, QcOnlyDecision, QcOnlyDivergence, QcOnlyKind, QcOnlyPending,
    make_commit_prepared, run_qc_only_prep,
};
use crate::shard_io::fetch::FetchInput;
use crate::shard_io::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::shard_io::sync::block::BlockSyncInput;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action emitted by the vnode at `vnode_idx`'s
    /// state machine.
    ///
    /// `vnode_idx` identifies the vnode that produced the action so
    /// dispatched off-thread work can sign with the right validator's
    /// key.
    ///
    /// Two categories of arm:
    /// - **Coordinator policy** — delegated to coordinator crates via
    ///   `dispatch_delegated_action`. Crypto, execution, broadcasts.
    /// - **`ShardLoop`-internal effects** — handled inline because the
    ///   work IS `ShardLoop` machinery (timers, caches consumed by serving,
    ///   RPC observability, block commit pipeline, topology plumbing).
    #[allow(clippy::too_many_lines)] // single dispatch over Action variants; one arm per variant
    pub(super) fn process_action(&mut self, vnode_idx: usize, action: Action) {
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
            | Action::VerifyBeaconWitnessRoot { .. }
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
            | Action::BroadcastExecutionCertificate { .. }
            | Action::SignAndBroadcastPcVote1 { .. }
            | Action::SignAndBroadcastPcVote2 { .. }
            | Action::SignAndBroadcastPcVote3 { .. }
            | Action::SignAndBroadcastEmptyView { .. }
            | Action::BroadcastSpcNewView { .. }
            | Action::BroadcastSpcNewCommit { .. }
            | Action::BroadcastBeaconBlock { .. }
            | Action::BroadcastRecoveryRequest { .. }
            | Action::FetchShardWitnesses { .. }
            | Action::VerifyBeaconRoot { .. } => {
                self.dispatch_delegated_action(vnode_idx, action);
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
            Action::AbandonFetch(req) => self.process_fetch_abandon(req),

            // ─── ShardLoop-internal effects ────────────────────────────────
            Action::SetTimer { id, duration } => {
                let shard = self.shard;
                self.pending_timer_ops.push(TimerOp::Set {
                    shard,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                let shard = self.shard;
                self.pending_timer_ops.push(TimerOp::Cancel { shard, id });
            }

            // ─── Beacon-local effects ──────────────────────────────────────
            Action::CommitBeaconBlock { block, .. } => {
                warn!(
                    epoch = block.epoch().inner(),
                    "Action::CommitBeaconBlock ignored at runner",
                );
            }
            Action::Continuation(pe) => self.handle_continuation(pe),
            Action::RestoreCommittedState => self.handle_restore_committed_state(),
            Action::CommitBlock {
                block,
                qc,
                source,
                witness,
            } => {
                self.accept_block_commit(PendingCommit {
                    block: Arc::new(block),
                    qc: Arc::new(qc),
                    source,
                    committed_notified: false, // set by accumulate
                    witness,
                });
            }
            Action::CommitBlockByQcOnly {
                block,
                qc,
                parent_state_root,
                parent_block_height,
                source,
                witness,
            } => {
                self.accept_qc_only_commit(
                    block,
                    qc,
                    parent_state_root,
                    parent_block_height,
                    source,
                    witness,
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
                let now = self.now;
                self.io.tx_phase_times.record_ec_created(&tx_hashes, now);
            }
            Action::TopologyChanged { topology_snapshot } => {
                self.handle_topology_changed(&topology_snapshot);
            }
        }
    }

    // ─── ShardLoop-internal effect handlers ──────────────────────────────
    //
    // These arms are handled inline (not delegated) because the work IS
    // `ShardLoop` state — caches consumed by serving, RPC observability,
    // topology plumbing. Migrating them to coordinator crates would force
    // a typed cache reference onto `ActionContext` per arm, with no
    // architectural payoff.

    fn handle_continuation(&mut self, pe: ProtocolEvent) {
        self.drive_fetch_admission(&pe);

        // Serving-cache insertion is `ShardLoop`'s own state, not an
        // instance concern — keep it here.
        if let ProtocolEvent::FinalizedWavesAdmitted { waves } = &pe {
            for wave in waves {
                self.io
                    .caches
                    .finalized_wave
                    .insert(wave.wave_id().clone(), Arc::clone(wave));
                self.process
                    .dispatch_handles
                    .execution_cache
                    .on_finalized_wave(self.shard, wave.tx_hashes());
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance per-shard `committed` and emit `SyncComplete` once the
        // chain catches up. Drives any newly-emitted range fetches inline.
        if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = &pe {
            let outputs = self.io.syncs.on_remote_header_admitted(
                committed_header.shard_group_id(),
                committed_header.header().height(),
            );
            self.process_remote_header_sync_outputs(outputs);
        }

        push_protocol_event(self.event_sender(), self.shard, pe);
    }

    fn handle_restore_committed_state(&self) {
        let storage = &self.io.storage;
        let height = storage.committed_height();
        let hash = storage.committed_hash();
        let qc = storage.latest_qc();
        push_protocol_event(
            self.event_sender(),
            self.shard,
            ProtocolEvent::CommittedStateRestored { height, hash, qc },
        );
    }

    fn handle_emit_transaction_status(
        &mut self,
        tx_hash: TxHash,
        status: TransactionStatus,
        cross_shard: bool,
        submitted_locally: bool,
    ) {
        trace!(?tx_hash, ?status, "Transaction status");
        let now = self.now;
        let terminal_phases = self.io.tx_phase_times.observe_status(tx_hash, &status, now);
        if status.is_final()
            && submitted_locally
            && let Some(phases) = terminal_phases
        {
            let latency_secs = now.saturating_sub(phases.added_at()).as_secs_f64();
            if latency_secs > 10.0 {
                // Rate-limit slow tx warnings to avoid log floods during
                // cross-shard latency spikes.
                let since_last_warn = now.saturating_sub(self.io.last_slow_tx_warn);
                if since_last_warn >= std::time::Duration::from_secs(30) {
                    self.io.last_slow_tx_warn = now;
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
        self.io.caches.tx_status.insert(tx_hash, status.clone());
        self.emitted_statuses.push((tx_hash, status));
    }

    /// Bridge an [`Action::CommitBlockByQcOnly`] to the standard commit
    /// pipeline. Skips the work entirely when the block is already
    /// persisted; otherwise builds a [`QcOnlyPending`] tagged with
    /// whether the prep is needed (no cached `PreparedCommit`) or can
    /// reuse the consensus path's cached entry, and submits it to the
    /// single-slot FIFO.
    ///
    /// The FIFO is the safety property — even `AlreadyPrepared` commits
    /// must wait behind any in-flight `NeedsPrep` for an earlier
    /// height, because the flush pipeline asserts strict height
    /// contiguity at JMT commit time. `try_apply_verified_synced_blocks`
    /// can emit a burst of these for consecutive heights in a single
    /// shard step.
    fn accept_qc_only_commit(
        &mut self,
        block: Block,
        qc: QuorumCertificate,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        source: CommitSource,
        witness: BeaconWitnessCommit,
    ) {
        let block_hash = block.hash();
        let height = block.height();

        let kind = match self.io.block_commit.decide_qc_only(&block_hash, height) {
            QcOnlyDecision::Skip => return,
            QcOnlyDecision::AlreadyPrepared => {
                debug!(
                    height = height.inner(),
                    ?block_hash,
                    "Reusing prepared commit from consensus path"
                );
                QcOnlyKind::AlreadyPrepared
            }
            QcOnlyDecision::NeedsPrep => QcOnlyKind::NeedsPrep,
        };

        let pending = QcOnlyPending {
            block: Arc::new(block),
            qc: Arc::new(qc),
            parent_state_root,
            parent_block_height,
            source,
            kind,
            witness,
        };
        if let Some(to_process) = self.io.block_commit.try_acquire_qc_only_slot(pending) {
            self.process_qc_only(to_process);
        }
        // else: queued; `release_qc_only_slot` hands it back when the
        // in-flight prep callback returns.
    }

    /// Drive the queue head: dispatch the JMT prep to the pool for
    /// `NeedsPrep` entries, or accept the commit inline for
    /// `AlreadyPrepared` entries. Already-prepared heads chain
    /// straight to the next queued entry without a pool round-trip,
    /// since the prepared commit is already in the cache.
    fn process_qc_only(&mut self, mut pending: QcOnlyPending) {
        loop {
            match pending.kind {
                QcOnlyKind::NeedsPrep => {
                    self.dispatch_qc_only_prep(pending);
                    return;
                }
                QcOnlyKind::AlreadyPrepared => {
                    self.accept_block_commit(PendingCommit {
                        block: pending.block,
                        qc: pending.qc,
                        source: pending.source,
                        committed_notified: false,
                        witness: pending.witness,
                    });
                    match self.io.block_commit.release_qc_only_slot() {
                        Some(next) => pending = next,
                        None => return,
                    }
                }
            }
        }
    }

    /// Spawn the JMT-prep closure on the consensus-crypto pool. The
    /// closure pushes a [`ShardScopedInput::QcOnlyCommitPrepared`] back
    /// on success or a [`ShardScopedInput::QcOnlyCommitDiverged`] on
    /// state-root mismatch; either way the slot is released on the
    /// shard thread (not the worker) so the queue + flag stay
    /// single-threaded.
    fn dispatch_qc_only_prep(&self, pending: QcOnlyPending) {
        let pending_chain = Arc::clone(&self.io.pending_chain);
        let prepared_commits = self.io.block_commit.prepared_commits_handle();
        let event_tx = self.event_sender().clone();
        let shard = self.shard;

        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let result = run_qc_only_prep(&pending_chain, &prepared_commits, &pending);
                let QcOnlyPending {
                    block,
                    qc,
                    source,
                    witness,
                    ..
                } = pending;
                match result {
                    Ok(()) => push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::QcOnlyCommitPrepared {
                            block,
                            qc,
                            source,
                            witness,
                        },
                    ),
                    Err(div) => push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::QcOnlyCommitDiverged(div),
                    ),
                }
            });
    }

    /// Callback for a successful off-thread JMT prep. Runs the standard
    /// commit pipeline for the just-prepared block, then releases the
    /// QC-only slot and drives the next queued entry — going back
    /// through [`Self::process_qc_only`] so an `AlreadyPrepared` next
    /// head accepts inline rather than triggering another pool round-trip.
    pub(in crate::shard_loop) fn handle_qc_only_commit_prepared(
        &mut self,
        block: Arc<Block>,
        qc: Arc<QuorumCertificate>,
        source: CommitSource,
        witness: BeaconWitnessCommit,
    ) {
        self.accept_block_commit(PendingCommit {
            block,
            qc,
            source,
            committed_notified: false,
            witness,
        });
        if let Some(next) = self.io.block_commit.release_qc_only_slot() {
            self.process_qc_only(next);
        }
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: feed the sync protocol with the new committed height and,
    /// unless persistence backpressure is active, fire `BlockCommitted`.
    ///
    /// [`BlockCommitCoordinator`]: crate::shard_io::block_commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, commit: PendingCommit) {
        let now = self.now;
        let decision = self.io.block_commit.accumulate(commit, now);
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted {
                height,
                handles: (block, qc),
                notify_now,
            } => {
                debug!(height = height.inner(), "Block committed");
                let outputs = self
                    .io
                    .syncs
                    .block
                    .handle(BlockSyncInput::Admitted { scope: (), height });
                self.process_block_sync_outputs(outputs);

                let weighted_ts = qc.weighted_timestamp();
                let block_hash = block.hash();
                let certified = Arc::new(CertifiedBlock::new_unchecked(
                    Arc::unwrap_or_clone(block),
                    Arc::unwrap_or_clone(qc),
                ));
                self.io
                    .pending_chain
                    .attach_certified_block(block_hash, Arc::clone(&certified));
                if notify_now {
                    self.process
                        .dispatch_handles
                        .execution_cache
                        .on_block_committed(weighted_ts);
                    self.dispatch_event(ProtocolEvent::BlockCommitted { certified });
                }
            }
        }
    }

    pub(crate) fn flush_block_commits(&mut self) {
        let event_sender = self.event_sender().clone();
        let dispatch = self.process.dispatch.clone();
        let io = &mut self.io;
        io.block_commit.flush(&io.storage, &event_sender, &dispatch);
    }

    /// Dispatch a typed fetch request to the corresponding binding.
    ///
    /// This shard's [`FetchHost`] owns the request — the shard of the
    /// emitting vnode, not the routing target. The routing target (where
    /// to send the request) lives on the [`FetchRequest`] variant itself
    /// as a `shard` / `source_shard` field. `Request` never emits `Send`s
    /// on its own — it only adds the ids to the pending set; chunks fan
    /// out under the per-tick cap. The tick timer is refreshed once at
    /// the end of `NodeHost::step`.
    ///
    /// [`FetchHost`]: crate::shard_io::fetch::FetchHost
    fn process_fetch_request(&mut self, req: FetchRequest) {
        match req {
            FetchRequest::Transactions {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<TransactionBinding>(FetchInput::Request {
                    ids,
                    shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::LocalProvisions {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Request {
                    ids,
                    shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::FinalizedWaves {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Request {
                    ids,
                    shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::RemoteProvisions {
                source_shard,
                block_height,
                preferred,
                class,
            } => {
                let local_shard = self.shard;
                self.drive_fetch::<ProvisionBinding>(FetchInput::Request {
                    ids: vec![(source_shard, local_shard, block_height)],
                    shard: source_shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::ExecutionCerts {
                wave_id,
                preferred,
                class,
            } => {
                let source_shard = wave_id.shard_group_id();
                self.drive_fetch::<ExecCertBinding>(FetchInput::Request {
                    ids: vec![wave_id],
                    shard: source_shard,
                    preferred,
                    class,
                });
            }
        }
    }

    /// Dispatch a typed fetch-abandon to the corresponding binding.
    ///
    /// This shard's [`FetchHost`] is notified — the abandoning vnode's
    /// shard, not the routing target of the original request. Symmetric
    /// to [`Self::process_fetch_request`] — translates the variant payload
    /// into ids and feeds them through `FetchInput::Abandoned`, which
    /// removes them from the binding's pending set and increments
    /// `record_fetch_abandoned` so the cancellation is observable
    /// separately from genuine admissions.
    ///
    /// [`FetchHost`]: crate::shard_io::fetch::FetchHost
    #[allow(clippy::needless_pass_by_value)] // mirrors process_fetch_request; future variants carry Vec ids
    fn process_fetch_abandon(&mut self, req: FetchAbandon) {
        match req {
            FetchAbandon::Transactions { ids } => {
                self.drive_fetch::<TransactionBinding>(FetchInput::Abandoned { ids });
            }
            FetchAbandon::RemoteProvisions {
                source_shard,
                block_height,
            } => {
                let local_shard = self.shard;
                self.drive_fetch::<ProvisionBinding>(FetchInput::Abandoned {
                    ids: vec![(source_shard, local_shard, block_height)],
                });
            }
            FetchAbandon::LocalProvisions { hashes } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Abandoned { ids: hashes });
            }
            FetchAbandon::FinalizedWaves { ids } => {
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Abandoned { ids });
            }
            FetchAbandon::ExecutionCerts { ids } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Abandoned { ids });
            }
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via
    /// this shard's event channel and are processed on a future `step()`
    /// call. With `SyncDispatch` (simulation), `spawn_*` runs inline so
    /// events enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&self, vnode_idx: usize, action: Action) {
        let pool = action
            .dispatch_pool()
            .expect("dispatch_delegated_action called for delegated actions only");

        let shard = self.shard;
        let handles = Arc::clone(&self.process.dispatch_handles);
        let vnode = self.vnode(vnode_idx);
        // Per-vnode snapshot so the handler's `local_validator_id`
        // matches the signing key used.
        let topology_snapshot = Arc::clone(vnode.state.topology_arc());
        let event_tx = self.event_sender().clone();
        let signing_key = Arc::clone(&vnode.signing_key);
        let par = self.process.dispatch.parallelism();

        self.process.dispatch.spawn(pool, move || {
            let shard_handles = handles
                .per_shard
                .get(&shard)
                .expect("hosted shard derived from vnode");
            // Action handlers emit `ProtocolEvent`s; stamp each with the
            // dispatching vnode's shard so the receiver routes back to
            // the right `ShardLoop`.
            let notify = move |event: ProtocolEvent| {
                push_protocol_event(&event_tx, shard, event);
            };
            let commit_prepared = make_commit_prepared(
                Arc::clone(&shard_handles.pending_chain),
                Arc::clone(&shard_handles.prepared_commits),
            );
            let ctx = ActionContext {
                executor: &handles.executor,
                topology_snapshot: &topology_snapshot,
                pending_chain: &shard_handles.pending_chain,
                execution_cache: &handles.execution_cache,
                network: &handles.network,
                signing_key: &signing_key,
                notify: &notify,
                commit_prepared: &commit_prepared,
                par,
            };
            match action.owner() {
                ActionOwner::Shard => handle_shard_action(action, &ctx),
                ActionOwner::Execution => handle_execution_action(action, &ctx),
                ActionOwner::Provisions => handle_provisions_action(action, &ctx),
                ActionOwner::Beacon => handle_beacon_action(action, &ctx),
                ActionOwner::Local => unreachable!(
                    "dispatch_delegated_action called with Local-owned action — \
                     process_action's outer match should have routed inline"
                ),
            }
        });
    }

    /// Adopt a fresh topology snapshot: publish it through the lock-free
    /// `ArcSwap` so off-thread closures pick it up on their next `.load()`,
    /// and push it to the network adapter (which keys validator pubkeys
    /// and shard committees off the snapshot). Idempotent across hosted
    /// shards — every same-shard vnode's `Action::TopologyChanged` lands
    /// here, but the final stored value is identical.
    pub(in crate::shard_loop) fn handle_topology_changed(&self, topology: &Arc<TopologySnapshot>) {
        self.process.topology_snapshot.store(Arc::clone(topology));

        // Network impl reads validator keys + shard committees off the
        // snapshot it gets here — no separate keymap push.
        self.process.network.update_topology(Arc::clone(topology));

        tracing::info!(
            local_shard = topology.local_shard().inner(),
            committee_size = topology.committee_for_shard(topology.local_shard()).len(),
            "Network topology updated"
        );
    }
}

/// Surface a state-root divergence reported by an off-thread QC-only
/// prep as an operator-fatal panic on the shard pinned thread.
///
/// Rayon's worker pool catches and discards task panics, so the
/// consensus-crypto worker reports a divergence by pushing
/// [`ShardScopedInput::QcOnlyCommitDiverged`] back to the shard
/// instead of panicking in place; this handler panics on receipt so
/// the operator-visible failure mode (shard thread exits with a
/// "local state divergence" message) is the same regardless of where
/// the JMT recomputation ran. The diagnostic is fully self-contained
/// on [`QcOnlyDivergence`], so this is a free function rather than a
/// method on `ShardLoop`.
pub(in crate::shard_loop) fn handle_qc_only_commit_diverged(div: &QcOnlyDivergence) {
    error!(
        height = div.block_height.inner(),
        block_hash = ?div.block_hash,
        expected_root = ?div.expected_root,
        computed_root = ?div.computed_root,
        parent_state_root = ?div.parent_state_root,
        parent_block_height = div.parent_block_height.inner(),
        source = ?div.source,
        "Local state divergence detected on synced block apply — \
         parent state does not produce the canonical state root. \
         Rebuild required: restore from state snapshot or \
         resync from genesis."
    );
    panic!(
        "Local state divergence at height {}: parent state root \
         {parent_state_root:?} does not produce canonical state \
         root {expected_root:?} (computed {computed_root:?}). Operator \
         intervention required.",
        div.block_height.inner(),
        parent_state_root = div.parent_state_root,
        expected_root = div.expected_root,
        computed_root = div.computed_root,
    );
}
