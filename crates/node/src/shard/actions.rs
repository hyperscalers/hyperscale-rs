//! Action processing and dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_beacon::action_handlers::handle_action as handle_beacon_action;
use hyperscale_core::{
    Action, ActionContext, ActionOwner, CommitSource, FetchRequest, ProtocolEvent,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_execution::action_handlers::handle_action as handle_execution_action;
use hyperscale_metrics::record_transaction_finalized;
use hyperscale_network::Network;
use hyperscale_provisions::action_handlers::handle_action as handle_provisions_action;
use hyperscale_shard::action_handlers::handle_action as handle_shard_action;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    Anchor, BeaconProposal, BeaconWitnessCommit, CertifiedBlock, Epoch, PredecessorTerminal,
    ShardId, SubstateKey, TerminalEvidence, TopologySchedule, TransactionStatus, TxHash,
    ValidatorId, Verified,
};
use tracing::{debug, error, trace, warn};

use super::{ShardLoop, ShardScopedInput, TimerOp, push_protocol_event, push_shard_input};
use crate::beacon;
use crate::beacon::{BeaconProposalBinding, ShardWitnessBinding};
use crate::fetch::{FetchInput, Release};
use crate::shard::commit::{
    AccumulateDecision, PendingCommit, QcOnlyCommit, QcOnlyDecision, QcOnlyDivergence, QcOnlyKind,
    QcOnlyPending, make_commit_prepared, run_qc_only_prep,
};
use crate::shard::consensus::BlockSyncInput;
use crate::shard::cross_shard::{
    CommittedTxBinding, ExecCertBinding, FinalizationBinding, LocalProvisionBinding,
    ProvisionBinding, SettledTxsBinding, StateProofBinding, StateProofRelayBinding,
};
use crate::shard::mempool::TransactionBinding;

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
            | Action::VerifyFinalization { .. }
            | Action::BuildProposal { .. }
            | Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyTimeout { .. }
            | Action::VerifyRemoteHeaderQc { .. }
            | Action::VerifyShardForkProof { .. }
            | Action::VerifyShardVoteEquivocation { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyBeaconWitnessRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::VerifyProvisionRoot { .. }
            | Action::VerifyCertificateRoot { .. }
            | Action::VerifyProvisionTxRoots { .. }
            | Action::VerifyReservations { .. }
            | Action::VerifyResolutions { .. }
            | Action::VerifyProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::FetchAndBroadcastProvisions { .. }
            | Action::BroadcastBlockHeader { .. }
            | Action::SignAndBroadcastBlockVote { .. }
            | Action::SignAndBroadcastTimeout { .. }
            | Action::SignAndBroadcastReadySignal { .. }
            | Action::BroadcastCertifiedBlockHeader { .. }
            | Action::BroadcastShardForkProof { .. }
            | Action::BroadcastShardVoteEquivocation { .. }
            | Action::SignAndSendExecutionVote { .. }
            | Action::BroadcastExecutionCertificate { .. }
            | Action::SignAndBroadcastPcVote1 { .. }
            | Action::SignAndBroadcastPcVote2 { .. }
            | Action::SignAndBroadcastPcVote3 { .. }
            | Action::SignAndBroadcastEmptyView { .. }
            | Action::BroadcastSpcNewView { .. }
            | Action::BroadcastSpcNewCommit { .. }
            | Action::BuildAndBroadcastBeaconProposal { .. }
            | Action::BroadcastBeaconBlock { .. }
            | Action::SignAndBroadcastRatifyVote { .. }
            | Action::BroadcastBeaconCandidate { .. }
            | Action::VerifyBeaconBlock { .. }
            | Action::VerifyRatifyVote { .. }
            | Action::VerifyBeaconCandidate { .. }
            | Action::VerifyPcVote1 { .. }
            | Action::VerifyPcVote2 { .. }
            | Action::VerifyPcVote3 { .. }
            | Action::VerifySpcNewView { .. }
            | Action::VerifySpcNewCommit { .. }
            | Action::VerifySpcEmptyView { .. } => {
                self.dispatch_delegated_action(vnode_idx, action);
            }

            // ─── Tick chain maintenance ────────────────────────────────────
            // Applied synchronously on the shard thread so a dispatch
            // action later in the same batch reads the resolved chain.
            Action::ResolveTicks { resolutions } => {
                for (tick_id, resolution) in &resolutions {
                    self.io.tick_chain.resolve(tick_id, resolution);
                }
            }
            Action::ClearTickChain => {
                self.io.tick_chain.clear();
            }

            // ─── Sync / fetch protocol drive ───────────────────────────────
            Action::StartBlockSync { target } => {
                self.process_start_block_sync(target);
            }
            Action::StartBeaconBlockSync { target } => {
                self.process_start_beacon_block_sync(target);
            }
            Action::StartRemoteHeaderSync {
                source_shard,
                target,
                floor,
            } => self.process_start_remote_header_sync(source_shard, target, floor),
            Action::FetchCommitProof {
                source_shard,
                from_height,
                count,
            } => self.process_fetch_commit_proof(source_shard, from_height, count),
            Action::ReofferTransactions { txs } => {
                // Through the client submit rail, not this shard's gossip
                // topic: the fan-out resolves each transaction against
                // the current topology, so it reaches the successor that
                // holds its keys now rather than the committee this
                // chain is leaving.
                for tx in &txs {
                    self.process.submit_transaction(tx);
                }
            }
            Action::Fetch(req) => self.process_fetch_request(req),
            Action::AbandonFetch(ids) => self.release_fetch(ids, Release::Abandoned),

            // ─── ShardLoop-internal effects ────────────────────────────────
            Action::SetTimer { id, duration } => {
                let shard = Some(self.shard);
                self.pending_timer_ops.push(TimerOp::Set {
                    shard,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                let shard = Some(self.shard);
                self.pending_timer_ops.push(TimerOp::Cancel { shard, id });
            }

            // ─── Beacon-local effects ──────────────────────────────────────
            Action::CommitBeaconBlock { block, state } => {
                let epoch = block.epoch();
                // Process-scoped dedup: only the first co-hosted vnode to
                // reach this `(epoch, hash)` writes to storage. The
                // per-vnode sync-advance and `BeaconBlockPersisted` below
                // still run on every vnode regardless.
                self.process
                    .beacon_commit
                    .commit(&self.process.beacon_storage, &block, &state);
                // Advance the beacon sync FSM's committed watermark on
                // every commit (gossip or sync) so a later
                // StartBeaconBlockSync fetches from current+1, and so
                // serial sync unblocks the next epoch's fetch.
                beacon::on_admitted(self, epoch);
                // Reconcile the global package registry: anything the
                // engine does not hold starts fetching now, ahead of any
                // transaction that would need it.
                self.reconcile_packages(&state);
                push_protocol_event(
                    self.event_sender(),
                    self.shard,
                    ProtocolEvent::BeaconBlockPersisted { epoch },
                );
            }
            Action::Continuation(pe) => self.handle_continuation(vnode_idx, pe),
            Action::RestoreCommittedState => self.handle_restore_committed_state(),
            Action::CommitBlock {
                certified,
                source,
                witness,
            } => {
                self.accept_block_commit(PendingCommit {
                    certified,
                    source,
                    committed_notified: false, // set by accumulate
                    witness,
                });
            }
            Action::CommitBlockByQcOnly {
                certified,
                parent_state_root,
                parent_block_height,
                parent_sweep_frontier,
                creations,
                source,
                witness,
            } => {
                self.accept_qc_only_commit(QcOnlyCommit {
                    certified,
                    parent_state_root,
                    parent_block_height,
                    parent_sweep_frontier,
                    creations,
                    source,
                    witness,
                });
            }
            Action::AttachCertifiedUncommitted { certified } => {
                let block_hash = certified.block().hash();
                let height = certified.block().height();
                if !self
                    .io
                    .pending_chain
                    .attach_certified_uncommitted(block_hash, certified)
                {
                    debug!(
                        ?block_hash,
                        height = height.inner(),
                        "No chain entry for certified uncommitted block — not servable to sync until commit"
                    );
                }
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
            Action::TopologyChanged { epoch, schedule } => {
                self.handle_topology_changed(epoch, schedule);
            }
            Action::ReconfigureParticipation(change) => {
                self.pending_participation_changes.push(change);
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

    fn handle_continuation(&mut self, vnode_idx: usize, pe: ProtocolEvent) {
        self.drive_fetch_admission(&pe);

        // Serving-cache insertion is `ShardLoop`'s own state, not an
        // instance concern — keep it here.
        if let ProtocolEvent::FinalizationsAdmitted { finalizations } = &pe {
            for tick in finalizations {
                self.io
                    .caches
                    .finalization
                    .insert(tick.receipt_hash(), Arc::clone(tick));
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance per-shard `committed` and emit `SyncComplete` once the
        // chain catches up. Drives any newly-emitted range fetches inline.
        //
        // Advance the watermark by the coordinator's contiguous verified
        // frontier, not this header's own height: a provision- or
        // execution-certificate-bundled source header lands above the
        // frontier when `block.committed` gossip is suppressed, and jumping
        // `committed` to it would strand the intervening heights below —
        // the sync queues from `committed + 1`, so it would never fetch the
        // gap the commit-proof walk needs contiguous.
        if let ProtocolEvent::RemoteHeaderAdmitted { certified_header } = &pe {
            let source_shard = certified_header.shard_id();
            let frontier = self.vnodes[vnode_idx]
                .state
                .remote_headers_coordinator()
                .verified_frontier(source_shard)
                .unwrap_or_else(|| certified_header.header().height());
            let outputs = self
                .io
                .cross_shard
                .on_remote_header_admitted(source_shard, frontier);
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
        self.process
            .tx_status
            .record(tx_hash, status.clone(), self.shard);
        self.emitted_statuses.push((tx_hash, status));
    }

    /// Bridge an [`Action::CommitBlockByQcOnly`] to the standard commit
    /// pipeline. Skips the work entirely when the block is already
    /// persisted; otherwise builds a [`QcOnlyPending`] tagged with
    /// whether the prep is needed (no cached `PreparedCommit`) or can
    /// reuse the consensus path's cached entry, and submits it to the
    /// single-slot FIFO.
    ///
    /// The FIFO keeps preps sequential — even `AlreadyPrepared` commits
    /// wait behind any in-flight `NeedsPrep` for an earlier height, so
    /// the flush pipeline's height-contiguity gate receives accepts in
    /// commit order instead of holding the pipeline open across a
    /// reordered burst. `try_apply_verified_synced_blocks` can emit a
    /// burst of these for consecutive heights in a single shard step.
    fn accept_qc_only_commit(&mut self, commit: QcOnlyCommit) {
        let QcOnlyCommit {
            certified,
            parent_state_root,
            parent_block_height,
            parent_sweep_frontier,
            creations,
            source,
            witness,
        } = commit;
        let block_hash = certified.block().hash();
        let height = certified.block().height();

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
            certified,
            parent_state_root,
            parent_block_height,
            parent_sweep_frontier,
            creations,
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
                        certified: pending.certified,
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
        let derivation = self.process.dispatch_handles.executor.derivation();

        self.process
            .dispatch
            .spawn(DispatchPool::Consensus, move || {
                let result = run_qc_only_prep(
                    &pending_chain,
                    &prepared_commits,
                    &pending,
                    derivation.as_ref(),
                );
                let QcOnlyPending {
                    certified,
                    source,
                    witness,
                    ..
                } = pending;
                match result {
                    Ok(()) => push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::QcOnlyCommitPrepared {
                            certified,
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
    pub(in crate::shard) fn handle_qc_only_commit_prepared(
        &mut self,
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
        witness: BeaconWitnessCommit,
    ) {
        self.accept_block_commit(PendingCommit {
            certified,
            source,
            committed_notified: false,
            witness,
        });
        if let Some(next) = self.io.block_commit.release_qc_only_slot() {
            self.process_qc_only(next);
        }
        // This accept may be the height the contiguity gate is holding the
        // flush open for. A `CommitBlock` accept reaches a drain-tail flush
        // via its `BlockCommitted`, but a QC-only accept under persistence
        // backpressure emits no such event, so drive the flush here or the
        // gate stalls on a suffix the recovery bridge is waiting to follow.
        self.flush_block_commits();
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: feed the sync protocol with the new committed height and,
    /// unless persistence backpressure is active, fire `BlockCommitted`.
    ///
    /// [`BlockCommitCoordinator`]: crate::shard::commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, commit: PendingCommit) {
        let now = self.now;
        let decision = self.io.block_commit.accumulate(commit, now);
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted {
                height,
                handle: certified,
                notify_now,
            } => {
                debug!(height = height.inner(), "Block committed");
                let outputs = self
                    .io
                    .consensus
                    .block_sync
                    .handle(BlockSyncInput::Admitted { scope: (), height });
                self.process_block_sync_outputs(outputs);

                let block_hash = certified.block().hash();
                self.io
                    .pending_chain
                    .attach_certified_block(block_hash, Arc::clone(&certified));
                if notify_now {
                    self.dispatch_event(ProtocolEvent::BlockCommitted { certified });
                }
            }
        }
    }

    pub(crate) fn flush_block_commits(&mut self) {
        let event_sender = self.event_sender().clone();
        let dispatch = self.process.dispatch.clone();
        let io = &mut self.io;
        io.block_commit.flush(&event_sender, &dispatch);
    }

    /// Dispatch a typed fetch request to the corresponding binding.
    ///
    /// The fetch instance lives in this shard's `ShardIo` — keyed by the
    /// emitting vnode's shard, not the routing target. The routing target
    /// (where to send the request) lives on the [`FetchRequest`] variant
    /// itself as a `shard` / `source_shard` field. `Request` never emits
    /// `Send`s on its own — it only adds the ids to the pending set; chunks
    /// fan out under the per-tick cap. The tick timer is refreshed once at
    /// the end of `NodeHost::step`.
    #[allow(clippy::too_many_lines)] // single dispatch over FetchRequest variants
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
            FetchRequest::Finalizations {
                ids,
                shard,
                preferred,
                class,
            } => {
                self.drive_fetch::<FinalizationBinding>(FetchInput::Request {
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
                source_shard,
                tx_hash,
                preferred,
                class,
            } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Request {
                    ids: vec![(source_shard, tx_hash)],
                    shard: source_shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::CommittedTxs {
                predecessor,
                tx_hashes,
                preferred,
                class,
            } => {
                let wanted: BTreeSet<(PredecessorTerminal, TxHash)> = tx_hashes
                    .into_iter()
                    .map(|tx_hash| (predecessor, tx_hash))
                    .collect();
                // The scan re-derives the whole wanted set for this
                // predecessor each pass, so anything the fetch still
                // holds under it and the scan no longer names is an
                // answer nobody is waiting for — a transaction that
                // expired out of the pool, or the rule retiring as the
                // chain outlives its origin. Nothing else retires these
                // ids: a terminated committee that never answers would
                // pin them for good.
                self.abandon_unwanted::<CommittedTxBinding>(&wanted, |id| {
                    id.0.shard == predecessor.shard
                });
                self.drive_fetch::<CommittedTxBinding>(FetchInput::Request {
                    ids: wanted.into_iter().collect(),
                    shard: predecessor.shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::SettledTxs {
                wanted,
                preferred,
                class,
            } => {
                // The whole wanted set arrives on every beacon fold, so
                // a terminal the fetch still holds and the set no longer
                // names — acquired, its window closed, its shard evicted
                // — is released here; nothing else retires it, and a
                // committee that never answers would pin it for good.
                let wanted: BTreeSet<TerminalEvidence> = wanted.into_iter().collect();
                self.abandon_unwanted::<SettledTxsBinding>(&wanted, |_| true);
                let mut by_shard: BTreeMap<ShardId, Vec<TerminalEvidence>> = BTreeMap::new();
                for evidence in wanted {
                    by_shard.entry(evidence.shard).or_default().push(evidence);
                }
                for (shard, ids) in by_shard {
                    self.drive_fetch::<SettledTxsBinding>(FetchInput::Request {
                        ids,
                        shard,
                        preferred,
                        class,
                    });
                }
            }
            FetchRequest::StateProof {
                anchor,
                keys,
                preferred,
                class,
            } => {
                self.drive_fetch::<StateProofBinding>(FetchInput::Request {
                    ids: keys.into_iter().map(|key| (anchor, key)).collect(),
                    shard: anchor.shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::RelayedStateProof {
                anchor,
                keys,
                shard,
                preferred,
                class,
            } => {
                let wanted: BTreeSet<(Anchor, SubstateKey)> =
                    keys.into_iter().map(|key| (anchor, key)).collect();
                // The fence re-derives what it wants relayed at this
                // anchor on every deferral, so a cell the fetch still
                // holds under it and the fence no longer names is one
                // nobody is waiting on — the block that claimed it was
                // discarded, or this validator's own probe proved the
                // cell first. Nothing else retires these ids: a
                // committee that never holds the proof would pin them
                // for good.
                self.abandon_unwanted::<StateProofRelayBinding>(&wanted, |id| id.0 == anchor);
                self.drive_fetch::<StateProofRelayBinding>(FetchInput::Request {
                    ids: wanted.into_iter().collect(),
                    shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::ShardWitnesses {
                source_shard,
                block_height,
                committed_block_hash,
                lo,
                hi,
                preferred,
                class,
            } => {
                self.drive_fetch::<ShardWitnessBinding>(FetchInput::Request {
                    ids: vec![(source_shard, block_height, committed_block_hash, lo, hi)],
                    shard: source_shard,
                    preferred,
                    class,
                });
            }
            FetchRequest::BeaconProposal {
                shard,
                epoch,
                validator,
                preferred,
                class,
            } => {
                self.drive_fetch::<BeaconProposalBinding>(FetchInput::Request {
                    ids: vec![(epoch, validator)],
                    shard,
                    preferred,
                    class,
                });
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
        let me = vnode.validator_id;

        // One beacon signature per validator per position: a co-hosted
        // vnode that hasn't claimed the current SPC view has its beacon
        // signing actions dropped here, before any signature exists.
        // The state machines stay single-node — passivity is purely a
        // driver decision at this funnel. A dissolved shard's vnode
        // stops emitting SPC traffic entirely: its successors are live,
        // so the validator's live vnode carries the duty, and a stale
        // coordinator claiming views it can't follow through starves
        // the beacon of this validator's signatures.
        if action.is_beacon_consensus_emission()
            && self.process.topology_snapshot.load().successors_live(shard)
        {
            trace!(
                validator = ?me,
                shard = shard.inner(),
                action = action.type_name(),
                "Dropping beacon emission from a dissolved shard's vnode"
            );
            return;
        }
        if let Some(position) = action.ratify_signing_position() {
            if !self.process.allow_ratify_signing(me, position) {
                trace!(
                    validator = ?me,
                    shard = shard.inner(),
                    epoch = position.0.inner(),
                    round = position.1.inner(),
                    "Dropping already-covered ratify vote position"
                );
                return;
            }
        } else if let Some((epoch, view)) = action.beacon_signing_position()
            && !self
                .process
                .allow_beacon_signing(me, Some(shard), epoch, view)
        {
            trace!(
                validator = ?me,
                shard = shard.inner(),
                epoch = epoch.inner(),
                view = view.inner(),
                action = action.type_name(),
                "Dropping beacon signing action for an unclaimed view"
            );
            return;
        }
        let topology_snapshot = Arc::clone(vnode.state.topology_arc());
        let event_tx = self.event_sender().clone();
        let signer = Arc::clone(&vnode.signer);
        let verifier = Arc::clone(&self.process.verifier);
        let par = self.process.dispatch.parallelism();
        // Resolve the shard's handles here, on the shard's own thread,
        // rather than inside the spawned closure: the dispatch pool is
        // process-wide and outlives this `ShardLoop`, so a job spawned as
        // the shard is torn down would otherwise find its entry already
        // dropped from `per_shard`.
        let shard_handles = handles
            .per_shard
            .load()
            .get(&shard)
            .expect("hosted shard derived from vnode")
            .clone();

        self.process.dispatch.spawn(pool, move || {
            // Action handlers emit `ProtocolEvent`s; stamp each with the
            // dispatching vnode's shard so the receiver routes back to
            // the right `ShardLoop`. `Arc`-shaped so handlers can clone
            // it into callback closures that outlive the action call.
            let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
                push_protocol_event(&event_tx, shard, event);
            });
            let commit_prepared = make_commit_prepared(
                Arc::clone(&shard_handles.pending_chain),
                Arc::clone(&shard_handles.prepared_commits),
            );
            let cache_beacon_proposal =
                |from: ValidatorId, epoch: Epoch, proposal: Arc<Verified<BeaconProposal>>| {
                    handles.beacon_proposal_cache.admit(from, epoch, proposal);
                };
            let ctx = ActionContext {
                executor: handles.executor.as_ref(),
                topology_snapshot: &topology_snapshot,
                me,
                shard,
                pending_chain: &shard_handles.pending_chain,
                tick_chain: &shard_handles.tick_chain,
                vote_registers: shard_handles.storage.as_ref(),
                ratify_registers: handles.beacon_storage.as_ref(),
                network: &handles.network,
                signer: &signer,
                verifier: verifier.as_ref(),
                notify,
                commit_prepared: &commit_prepared,
                cache_beacon_proposal: &cache_beacon_proposal,
                par,
            };
            match action.owner() {
                ActionOwner::Shard => handle_shard_action(action, &ctx),
                ActionOwner::Execution => handle_execution_action(action, &ctx),
                ActionOwner::Provisions => handle_provisions_action(action, &ctx),
                ActionOwner::Beacon => handle_beacon_action(action, &ctx.beacon()),
                ActionOwner::Local => unreachable!(
                    "dispatch_delegated_action called with Local-owned action — \
                     process_action's outer match should have routed inline"
                ),
            }
        });
    }

    /// Adopt a freshly folded schedule: publish its head through the
    /// lock-free `ArcSwap` so off-thread closures pick it up on their
    /// next `.load()`, and push it to the network adapter (which keys
    /// validator pubkeys and shard committees off the snapshot). Every
    /// hosted shard's `Action::TopologyChanged` lands here as it folds
    /// the beacon at `epoch`; `apply_topology` gates the store
    /// monotonically so a slower shard thread cannot regress the shared
    /// schedule to an older epoch's view.
    pub(in crate::shard) fn handle_topology_changed(
        &self,
        epoch: Epoch,
        schedule: Arc<TopologySchedule>,
    ) {
        let committee_size = schedule.head().committee_for_shard(self.shard).len();
        // The beacon attests a boundary off its child's header, and the
        // commit path pins the boundary when that child commits. A shard
        // that halts with the child certified but never committed leaves
        // its attested anchor unpinned on every member, and nothing can
        // seat against it — not a rotation's entrant, not the recovery's
        // fresh committee. The committed tip is the anchor's exact state
        // for as long as it stays the tip, so pin it the moment the
        // attestation lands. A pin that already exists costs a stat.
        if let Some(anchor) = schedule.head().boundary(self.shard)
            && anchor.height == self.io.storage.committed_height()
            && let Err(error) = self.io.storage.pin_boundary(anchor.height)
        {
            warn!(
                shard = ?self.shard,
                height = anchor.height.inner(),
                error,
                "attested boundary pin failed; this node won't serve this boundary"
            );
        }
        self.process.apply_topology(epoch, schedule);

        tracing::info!(
            local_shard = self.shard.inner(),
            committee_size,
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
pub(in crate::shard) fn handle_qc_only_commit_diverged(div: &QcOnlyDivergence) {
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
