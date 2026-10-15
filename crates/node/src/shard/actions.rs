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
    Anchor, BeaconProposal, BeaconWitnessCommit, BlockHash, BlockHeight, CandidateBeaconBlock,
    CertifiedBlock, Epoch, ShardId, SubstateKey, TerminalEvidence, TopologySchedule,
    TransactionStatus, TxHash, ValidatorId, Verified, WeightedTimestamp,
};
use tracing::{debug, error, trace, warn};

use super::{
    ShardLoop, ShardScopedInput, TimerOp, TimerOwner, push_protocol_event, push_shard_input,
};
use crate::beacon;
use crate::fetch::{FetchInput, Release};
use crate::shard::commit::{
    AccumulateDecision, PendingCommit, QcOnlyCommit, QcOnlyDecision, QcOnlyDivergence, QcOnlyPrep,
    Refuted, make_commit_prepared, run_qc_only_prep,
};
use crate::shard::cross_shard::{SettledTxsBinding, StateProofBinding, TerminalLinesBinding};

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
            | Action::VerifyBodyRoot { .. }
            | Action::VerifyProvisionTxRoots { .. }
            | Action::VerifyResolutions { .. }
            | Action::VerifyProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::FetchAndBroadcastProvisions { .. }
            | Action::PushCrossingReadings { .. }
            | Action::BroadcastBlockHeader { .. }
            | Action::SignAndBroadcastBlockVote { .. }
            | Action::SignAndBroadcastTimeout { .. }
            | Action::SignAndBroadcastQcAnnouncement { .. }
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
            Action::RaiseTickFloor { floor } => {
                self.io.tick_chain.raise_floor(floor);
            }

            // ─── Sync / fetch protocol drive ───────────────────────────────
            Action::StartBlockSync { target } => {
                self.process_start_block_sync(target);
            }
            Action::SyncBlockApplied { height } => {
                self.process_sync_block_applied(vnode_idx, height);
            }
            Action::ReopenSyncHeight { height, hash } => {
                self.process_reopen_sync_height(vnode_idx, height, hash);
            }
            Action::SettleBlockSync => {
                self.process_settle_block_sync();
            }
            Action::StartBeaconBlockSync { target } => {
                self.process_start_beacon_block_sync(target);
            }
            Action::StartRemoteHeaderSync {
                source_shard,
                target,
            } => self.process_start_remote_header_sync(source_shard, target),
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
            Action::Fetch(req) => self.process_fetch_request(vnode_idx, req),
            Action::AbandonFetch(ids) => self.release_fetch(ids, Release::Abandoned),

            // ─── ShardLoop-internal effects ────────────────────────────────
            Action::SetTimer { id, duration } => {
                let owner = TimerOwner::Seat(self.shard, self.vnode(vnode_idx).validator_id);
                self.pending_timer_ops.push(TimerOp::Set {
                    owner,
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                let owner = TimerOwner::Seat(self.shard, self.vnode(vnode_idx).validator_id);
                self.pending_timer_ops.push(TimerOp::Cancel { owner, id });
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
                // StartBeaconBlockSync fetches above every hosted tip, and
                // so serial sync unblocks the next epoch's fetch.
                beacon::on_admitted(self);
                push_protocol_event(
                    self.event_sender(),
                    self.shard,
                    ProtocolEvent::BeaconBlockPersisted { epoch },
                );
            }
            Action::Continuation(pe) => self.handle_continuation(pe),
            Action::RestoreCommittedState => self.handle_restore_committed_state(),
            Action::CommitBlock {
                certified,
                source,
                witness,
                committee_anchor,
            } => {
                self.accept_block_commit(PendingCommit {
                    certified,
                    source,
                    committed_notified: false, // set by accumulate
                    witness,
                    committee_anchor,
                });
            }
            Action::CommitBlockByQcOnly {
                certified,
                parent_state_root,
                parent_block_height,
                parent_sweep_frontier,
                creations,
                frontier,
                source,
                witness,
                committee_anchor,
            } => {
                self.accept_qc_only_commit(QcOnlyCommit {
                    certified,
                    parent_state_root,
                    parent_block_height,
                    parent_sweep_frontier,
                    creations,
                    frontier,
                    source,
                    witness,
                    committee_anchor,
                });
            }
            Action::AttachCertifiedUncommitted { certified } => {
                self.io
                    .pending_chain
                    .attach_certified_uncommitted(certified);
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

    fn handle_continuation(&mut self, pe: ProtocolEvent) {
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
        // advance the source's scope and emit `SyncComplete` once the chain
        // catches up. Drives any newly-emitted range fetches inline.
        //
        // The scope advances by the seats' contiguous verified frontier, not
        // this header's own height: a provision- or execution-certificate-
        // bundled source header lands above the frontier when
        // `block.committed` gossip is suppressed, and jumping the scope to it
        // would strand the intervening heights below, since the sync queues
        // from its frontier and would never fetch the gap the commit-proof
        // walk needs contiguous.
        if let ProtocolEvent::RemoteHeaderAdmitted { certified_header } = &pe {
            self.follow_slowest_remote_header_seat(certified_header.shard_id());
        }

        push_protocol_event(self.event_sender(), self.shard, pe);
    }

    fn handle_restore_committed_state(&self) {
        let storage = &self.io.storage;
        let (height, hash) = storage.committed_head();
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
    /// pipeline by submitting it to the single-slot FIFO, which decides
    /// what each commit needs as it reaches the head.
    ///
    /// The FIFO keeps preps sequential — even a commit whose prep the
    /// consensus path already cached waits behind any in-flight prep for
    /// an earlier height, so the flush pipeline's height-contiguity gate
    /// receives accepts in commit order instead of holding the pipeline
    /// open across a reordered burst. `try_apply_verified_synced_blocks`
    /// can emit a burst of these for consecutive heights in a single
    /// shard step.
    fn accept_qc_only_commit(&mut self, commit: QcOnlyCommit) {
        if let Some(head) = self.io.block_commit.try_acquire_qc_only_slot(commit) {
            self.process_qc_only(head);
        }
        // else: queued; `release_qc_only_slot` hands it back when the
        // in-flight prep callback returns.
    }

    /// Drive the queue head: dispatch the JMT prep to the pool for a
    /// head that needs one, or accept the commit inline for a head the
    /// consensus path already prepared. Already-prepared heads chain
    /// straight to the next queued entry without a pool round-trip,
    /// since the prepared commit is already in the cache.
    fn process_qc_only(&mut self, mut head: (QcOnlyCommit, QcOnlyDecision)) {
        loop {
            let (commit, decision) = head;
            match decision {
                QcOnlyDecision::NeedsPrep => {
                    self.dispatch_qc_only_prep(commit);
                    return;
                }
                QcOnlyDecision::AlreadyPrepared => {
                    debug!(
                        height = commit.certified.block().height().inner(),
                        block_hash = ?commit.certified.block().hash(),
                        "Reusing prepared commit from consensus path"
                    );
                    self.accept_block_commit(PendingCommit {
                        certified: commit.certified,
                        source: commit.source,
                        committed_notified: false,
                        witness: commit.witness,
                        committee_anchor: commit.committee_anchor,
                    });
                    match self.io.block_commit.release_qc_only_slot() {
                        Some(next) => head = next,
                        None => return,
                    }
                }
            }
        }
    }

    /// Spawn the JMT-prep closure on the consensus-crypto pool. The
    /// closure pushes a [`ShardScopedInput::QcOnlyCommitPrepared`] back
    /// on success, a [`ShardScopedInput::QcOnlyCommitWrittenPast`] for a
    /// block the store was written past first, or a
    /// [`ShardScopedInput::QcOnlyCommitDiverged`] on state-root mismatch;
    /// either way the slot is released on the shard thread (not the
    /// worker) so the queue + flag stay single-threaded.
    fn dispatch_qc_only_prep(&self, pending: QcOnlyCommit) {
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
                let QcOnlyCommit {
                    certified,
                    source,
                    witness,
                    committee_anchor,
                    ..
                } = pending;
                match result {
                    Ok(QcOnlyPrep::WrittenPast) => push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::QcOnlyCommitWrittenPast {
                            block_height: certified.block().height(),
                            block_hash: certified.block().hash(),
                        },
                    ),
                    Ok(QcOnlyPrep::Prepared) => push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::QcOnlyCommitPrepared {
                            certified,
                            source,
                            witness,
                            committee_anchor,
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
        committee_anchor: WeightedTimestamp,
    ) {
        self.accept_block_commit(PendingCommit {
            certified,
            source,
            committed_notified: false,
            witness,
            committee_anchor,
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

    /// Callback for an off-thread JMT prep that refuted the block's
    /// header. A block the store's write frontier reached while its prep
    /// ran was written by a sibling seat's flush, and the prep read its
    /// parent over a store already past it: the refutation is no evidence
    /// about local state, so the slot passes to the next queued entry.
    /// Anything else is fatal.
    pub(in crate::shard) fn handle_qc_only_commit_diverged(&mut self, div: &QcOnlyDivergence) {
        if !self.io.block_commit.is_written(div.block_height) {
            abort_on_refuted_commit(div);
        }
        self.handle_qc_only_commit_written_past(div.block_height, div.block_hash);
    }

    /// Callback for an off-thread JMT prep over a block the store was
    /// written past while it ran: the block is already written, so the
    /// slot passes to the next queued entry.
    pub(in crate::shard) fn handle_qc_only_commit_written_past(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
    ) {
        debug!(
            height = block_height.inner(),
            ?block_hash,
            "Dropping a QC-only prep the store was written past while it ran"
        );
        if let Some(next) = self.io.block_commit.release_qc_only_slot() {
            self.process_qc_only(next);
        }
    }

    /// Hand a commit to the [`BlockCommitCoordinator`] and act on its
    /// decision: point the sync protocol at the height every seat has
    /// committed and, unless persistence backpressure is active, fire
    /// `BlockCommitted`. A commit the pipeline already took from a sibling
    /// still moves this seat, and so perhaps the slowest one.
    ///
    /// [`BlockCommitCoordinator`]: crate::shard::commit::BlockCommitCoordinator
    fn accept_block_commit(&mut self, commit: PendingCommit) {
        let now = self.now;
        let decision = self.io.block_commit.accumulate(commit, now);
        self.follow_slowest_block_sync_seat();
        match decision {
            AccumulateDecision::Skip => {}
            AccumulateDecision::Accepted {
                height,
                handle: certified,
                committee_anchor,
                notify_now,
            } => {
                debug!(height = height.inner(), "Block committed");

                let block_hash = certified.block().hash();
                self.io
                    .pending_chain
                    .attach_certified_block(block_hash, Arc::clone(&certified));
                if notify_now {
                    self.dispatch_event(ProtocolEvent::BlockCommitted {
                        certified,
                        committee_anchor,
                    });
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
    /// emitting vnode's shard, not the routing target, which rides on the
    /// request. `Ask` never emits `Send`s on its own — it only adds the
    /// ids to the pending set; chunks fan out under the per-tick cap. The
    /// tick timer is refreshed once at the end of `NodeHost::step`.
    ///
    /// The three arms below `Ask` are a different message: the pending
    /// set under a scope is now exactly these ids. Their consumers
    /// re-derive the whole wanted set each pass, so what the fetch still
    /// holds under that scope and the consumer no longer names is retired
    /// here — for an id nobody re-asks about, against a committee that
    /// may never answer, this is the only release there is.
    #[allow(clippy::too_many_lines)] // single dispatch over FetchRequest variants
    fn process_fetch_request(&mut self, vnode_idx: usize, req: FetchRequest) {
        let seat = self.vnode(vnode_idx).validator_id;
        match req {
            FetchRequest::Ask {
                ids,
                shard,
                preferred,
                class,
            } => self.request_fetch(ids, shard, preferred, class),
            FetchRequest::PrecutProofs {
                terminal,
                keys,
                preferred,
                class,
            } => {
                let wanted: BTreeSet<(Anchor, SubstateKey)> =
                    keys.into_iter().map(|key| (terminal, key)).collect();
                // The scan re-derives the whole wanted set under this
                // terminal each pass, so anything the fetch still holds
                // under it and no seat's scan names is an answer nobody
                // is waiting for — a transaction that expired out of the
                // pool, or the rule retiring as the chain outlives its
                // origin. Nothing else retires these ids: a terminated
                // committee that never answers would pin them for good.
                let named = self
                    .io
                    .cross_shard
                    .precut_wants
                    .replace(seat, &wanted, |id| id.0 == terminal);
                self.abandon_unwanted::<StateProofBinding>(&named, |id| id.0 == terminal);
                self.drive_fetch::<StateProofBinding>(FetchInput::Request {
                    ids: wanted.into_iter().collect(),
                    shard: terminal.shard,
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
                // a terminal the fetch still holds and no seat's set
                // names — acquired, its window closed, its shard evicted
                // — is released here; nothing else retires it, and a
                // committee that never answers would pin it for good.
                let wanted: BTreeSet<TerminalEvidence> = wanted.into_iter().collect();
                let named = self
                    .io
                    .cross_shard
                    .settled_wants
                    .replace(seat, &wanted, |_| true);
                self.abandon_unwanted::<SettledTxsBinding>(&named, |_| true);
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
            FetchRequest::TerminalLines {
                wanted,
                preferred,
                class,
            } => {
                // The whole wanted set arrives on every beacon fold, so
                // a terminal the fetch still holds and no seat's set
                // names is released here. An empty set asks nothing of
                // the network.
                let wanted: BTreeSet<TerminalEvidence> = wanted.into_iter().collect();
                let named = self
                    .io
                    .cross_shard
                    .lines_wants
                    .replace(seat, &wanted, |_| true);
                self.abandon_unwanted::<TerminalLinesBinding>(&named, |_| true);
                let mut by_shard: BTreeMap<ShardId, Vec<TerminalEvidence>> = BTreeMap::new();
                for evidence in wanted {
                    by_shard.entry(evidence.shard).or_default().push(evidence);
                }
                for (shard, ids) in by_shard {
                    self.drive_fetch::<TerminalLinesBinding>(FetchInput::Request {
                        ids,
                        shard,
                        preferred,
                        class,
                    });
                }
            }
            FetchRequest::Packages { wanted } => self.fetch_wanted_packages(wanted),
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Whether `me` may emit `action` from this shard's vnode.
    ///
    /// One beacon signature per validator per position: a co-hosted
    /// vnode that hasn't claimed the current SPC view has its beacon
    /// signing actions dropped here, before any signature exists.
    /// The state machines stay single-node — passivity is purely a
    /// driver decision at this funnel. A dissolved shard's vnode
    /// stops emitting SPC traffic entirely: its successors are live,
    /// so the validator's live vnode carries the duty, and a stale
    /// coordinator claiming views it can't follow through starves
    /// the beacon of this validator's signatures.
    fn beacon_emission_allowed(&self, me: ValidatorId, action: &Action) -> bool {
        let shard = self.shard;
        if action.is_beacon_consensus_emission()
            && self.process.topology_snapshot.load().successors_live(shard)
        {
            trace!(
                validator = ?me,
                shard = shard.inner(),
                action = action.type_name(),
                "Dropping beacon emission from a dissolved shard's vnode"
            );
            return false;
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
                return false;
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
            return false;
        }
        true
    }

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via
    /// this shard's event channel and are processed on a future `step()`
    /// call. With `SyncDispatch` (simulation), `spawn_*` runs inline so
    /// events enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&self, vnode_idx: usize, action: Action) {
        let owner = action.owner();
        let pool = owner
            .pool()
            .expect("dispatch_delegated_action called for delegated actions only");

        let shard = self.shard;
        let handles = Arc::clone(&self.process.dispatch_handles);
        let vnode = self.vnode(vnode_idx);
        let me = vnode.validator_id;

        if !self.beacon_emission_allowed(me, &action) {
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

        // A tick's batch is one seat's run of it, and what comes back
        // releases that seat's next tick and the fates it holds for this
        // one. A sibling runs the tick itself, from wherever its own
        // queue stands, so the result is no word on its run.
        let own_result = matches!(action, Action::ExecuteTransactions { .. });

        self.process.dispatch.spawn(pool, move || {
            // Action handlers emit `ProtocolEvent`s; stamp each with the
            // dispatching vnode's shard so the receiver routes back to
            // the right `ShardLoop`. `Arc`-shaped so handlers can clone
            // it into callback closures that outlive the action call.
            let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
                if own_result {
                    push_shard_input(
                        &event_tx,
                        shard,
                        ShardScopedInput::SeatResult {
                            validator: me,
                            event: Box::new(event),
                        },
                    );
                } else {
                    push_protocol_event(&event_tx, shard, event);
                }
            });
            let commit_prepared = make_commit_prepared(
                Arc::clone(&shard_handles.pending_chain),
                Arc::clone(&shard_handles.prepared_commits),
            );
            let cache_beacon_proposal =
                |from: ValidatorId, epoch: Epoch, proposal: Arc<Verified<BeaconProposal>>| {
                    handles.beacon_proposal_cache.admit(from, epoch, proposal);
                };
            let cache_beacon_candidate = |candidate: Arc<Verified<CandidateBeaconBlock>>| {
                handles.beacon_candidate_cache.admit(candidate);
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
                beacon_vote_registers: handles.beacon_storage.as_ref(),
                beacon_chain: handles.beacon_storage.as_ref(),
                network: &handles.network,
                signer: &signer,
                verifier: verifier.as_ref(),
                notify,
                commit_prepared: &commit_prepared,
                cache_beacon_proposal: &cache_beacon_proposal,
                cache_beacon_candidate: &cache_beacon_candidate,
                par,
            };
            match owner {
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
        // attestation lands. A pin that already exists costs a stat. The
        // pin follows the publish so its trim holds the anchor it pins.
        let attested_tip = schedule
            .head()
            .boundary(self.shard)
            .map(|anchor| anchor.height)
            .filter(|height| *height == self.io.storage.committed_height());
        self.process.apply_topology(epoch, schedule);
        if let Some(height) = attested_tip {
            self.io.boundary_pins.pin(height);
        }

        tracing::info!(
            local_shard = self.shard.inner(),
            committee_size,
            "Network topology updated"
        );
    }
}

/// Surface a refutation reported by an off-thread QC-only prep as an
/// operator-fatal panic on the shard pinned thread.
///
/// A panic on a dispatch pool worker aborts the whole process with no
/// word of which shard or block failed, so the consensus-crypto worker
/// reports a refutation by pushing
/// [`ShardScopedInput::QcOnlyCommitDiverged`] back to the shard
/// instead of panicking in place; this handler panics on receipt so
/// the operator-visible failure mode (shard thread exits naming the
/// block and the claim it refutes) is the same regardless of where
/// the JMT recomputation ran.
fn abort_on_refuted_commit(div: &QcOnlyDivergence) -> ! {
    match div.refuted {
        Refuted::Root {
            expected_root,
            computed_root,
        } => {
            error!(
                height = div.block_height.inner(),
                block_hash = ?div.block_hash,
                ?expected_root,
                ?computed_root,
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
            );
        }
        Refuted::SweepFrontier {
            parent,
            claimed,
            bound,
        } => {
            error!(
                height = div.block_height.inner(),
                block_hash = ?div.block_hash,
                ?parent,
                ?claimed,
                ?bound,
                source = ?div.source,
                "A certified block claims a sweep frontier no walk from this \
                 replica's parent frontier lands on — the certificate or the local \
                 parent state is wrong. Operator intervention required."
            );
            panic!(
                "Certified block at height {} claims sweep frontier {claimed:?}, \
                 which no walk from the parent frontier {parent:?} lands on: it breaks \
                 the bound {bound:?}, the parent's frontier or the clock's ceiling. \
                 Either the certificate is wrong or this replica resolved the wrong \
                 parent frontier. Operator intervention required.",
                div.block_height.inner(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    use hyperscale_core::{Action, ProtocolEvent};
    use hyperscale_engine::TickEnvironment;
    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::commit_writes;
    use hyperscale_storage::{
        ChainWrites, MemberInputs, ParentAnchor, ShardChainWriter, SubstateStore,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::GetFinalizationsRequest;
    use hyperscale_types::test_utils::{install_stub_protocol_statics, stub_sweepable_cell};
    use hyperscale_types::{
        Address, AddressClass, AggregateSignature, BlockHash, BlockHeight, CheckOutcome,
        ExecutionCertificate, ExecutionOutcome, Finalization, FrontierInputs, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, Role, SWEEP_BUCKET_MS, SettledWrites, SignerBitfield, SubstateKey,
        SweepBucket, SweepFrontier, TickHalf, TickId, TxHash, TxOutcome, Verifiable,
        VerificationKind, WeightedTimestamp, shard_prefix_path,
    };

    use crate::event::{HostEvent, ShardScopedInput};
    use crate::shard::cross_shard::serve_finalizations_request;
    use crate::shard::seated_host::{Fixture, Host, SHARD, loop_of};

    /// A block may name a legs entry its proposer has since replaced by
    /// one naming more of the tick's legs. Every entry announced enters
    /// the serving cache as it is announced and stays there, so a voter
    /// asking by the hash the block names is answered with that entry
    /// whatever has replaced it.
    #[test]
    fn a_replaced_legs_entry_is_still_served_by_its_hash() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_with_events(BlockHeight::GENESIS);
        host.seat_vnode(SHARD, fix.seat(1));

        let tick_id = TickId::new(SHARD, BlockHeight::new(1));
        let legs: Vec<TxOutcome> = [b"first leg", b"other leg"]
            .into_iter()
            .map(|seed| {
                TxOutcome::new(
                    TxHash::from(Hash::from_bytes(seed)),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .as_role(Role::Core)
            })
            .collect();
        let first_leg = legs[0].tx_hash();
        let every_leg = Finalization::new(
            tick_id,
            TickHalf::Legs,
            &Capped::from_array([Arc::new(ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(1),
                GlobalReceiptRoot::ZERO,
                Capped::new(legs).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ))]),
            Capped::empty(),
        );
        let replaced = every_leg.clone().naming(&HashSet::from([first_leg]));
        assert_ne!(replaced.receipt_hash(), every_leg.receipt_hash());

        loop_of(&mut host).drain_actions(
            1,
            [&replaced, &every_leg]
                .map(|fw| {
                    Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
                        finalizations: vec![Arc::new(Verifiable::from(fw.clone()))],
                    })
                })
                .to_vec(),
        );

        let io = &loop_of(&mut host).io;
        let served = serve_finalizations_request(
            &io.pending_chain,
            &io.caches.finalization,
            &GetFinalizationsRequest::new(Capped::from_array([replaced.receipt_hash()])),
        );
        assert_eq!(
            served
                .finalizations
                .iter()
                .map(|fw| (fw.receipt_hash(), fw.tx_hashes().collect::<Vec<_>>()))
                .collect::<Vec<_>>(),
            vec![(replaced.receipt_hash(), vec![first_leg])],
        );
    }

    /// A seat's batch result reaches that seat alone. Each seat on a loop
    /// runs every tick itself, and a result is what releases its next
    /// tick and the fates it holds for the one that ran; a sibling still
    /// to run that tick, or ticks below it, is no further on for it.
    #[test]
    fn a_batch_result_reaches_only_the_seat_that_ran_it() {
        let fix = Fixture::new();
        let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
        let out = host.seat_vnode(SHARD, fix.seat(1));
        assert_eq!(out.seated, vec![fix.committee.validator_id(1)]);
        while events.try_recv().is_ok() {}

        let ran = BlockHeight::new(1);
        loop_of(&mut host).drain_actions(
            1,
            vec![Action::ExecuteTransactions {
                tick: ran,
                fates: Vec::new(),
                tick_ts: WeightedTimestamp::ZERO,
                env: TickEnvironment::unfolded(),
                requests: Vec::new(),
                included: Vec::new(),
            }],
        );
        while let Ok(event) = events.try_recv() {
            let _ = host.step(event);
        }

        let baseline_floor = |host: &mut Host, seat: usize| {
            loop_of(host)
                .vnode(seat)
                .state
                .execution_coordinator()
                .baseline_floor()
        };
        assert_eq!(
            baseline_floor(&mut host, 1),
            ran,
            "the seat that ran the tick has completed it",
        );
        assert_eq!(
            baseline_floor(&mut host, 0),
            BlockHeight::GENESIS,
            "its sibling has every tick of its own still to run",
        );
    }

    /// A store on `SHARD` whose tip holds one sweepable cell three
    /// buckets up, and the cell's key.
    fn a_store_holding_an_expired_cell() -> (SimShardStorage, SubstateKey) {
        a_store_holding_a_cell_in(3)
    }

    /// A store on `SHARD` whose tip holds one sweepable cell expiring at
    /// the start of `bucket`, and the cell's key.
    fn a_store_holding_a_cell_in(bucket: u64) -> (SimShardStorage, SubstateKey) {
        install_stub_protocol_statics();
        let storage = SimShardStorage::new(shard_prefix_path(SHARD));
        let (local, value) = stub_sweepable_cell(bucket * SWEEP_BUCKET_MS, 0x11);
        let key = SubstateKey {
            owner: Address::new([0x40; 31], AddressClass::Component),
            local,
        };
        commit_writes(
            &storage,
            &SettledWrites::from_absolutes(BTreeMap::from([(key, Some(value))])),
        );
        (storage, key)
    }

    /// How the seated loop's state root check ends for a certified,
    /// empty child of `storage`'s tip anchored twenty buckets up, whose
    /// header names `swept_to` over a parent that stopped at
    /// `swept_from`, and whose root is the tip's with `removals` taken
    /// out.
    fn certified_child_check(
        storage: &SimShardStorage,
        swept_from: SweepFrontier,
        swept_to: SweepFrontier,
        removals: &[SubstateKey],
    ) -> CheckOutcome {
        let (parent_state_root, parent_block_height) = (storage.state_root(), storage.jmt_height());
        let block_height = parent_block_height.next();
        let frontier = FrontierInputs::still(SHARD);
        let members = MemberInputs::still(SHARD);
        let (expected_root, _, _) = Arc::new(storage.clone()).prepare_block_commit(
            ParentAnchor {
                state_root: parent_state_root,
                height: parent_block_height,
                state: &storage.snapshot(),
                pending: &[],
                base_reads: None,
            },
            &[],
            ChainWrites {
                creations: &[],
                removals,
                sweep_frontier: swept_to,
                frontier: &frontier,
                state_claims: &[],
                members: &members,
            },
            block_height,
        );
        assert_eq!(
            expected_root == parent_state_root,
            removals.is_empty(),
            "only a removal moves this block's root",
        );

        let (mut host, events) =
            Fixture::new().host_with_events_over(storage.clone(), parent_block_height);
        while events.try_recv().is_ok() {}
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"a certified child"));
        loop_of(&mut host).drain_actions(
            0,
            vec![Action::VerifyStateRoot {
                block_hash,
                transactions: Arc::new(Capped::empty()),
                parent_block_hash: BlockHash::ZERO,
                parent_state_root,
                parent_block_height,
                expected_root,
                finalizations: Vec::new(),
                creations: Vec::new(),
                block_height,
                claimed_split_child_roots: None,
                split_child_roots_required: false,
                terminal_settled_txs_required: false,
                claimed_terminal_settled_txs: None,
                parent_weighted_timestamp: WeightedTimestamp::from_millis(20 * SWEEP_BUCKET_MS),
                settled_txs_window_floor: None,
                parent_sweep_frontier: swept_from,
                claimed_sweep_frontier: swept_to,
                frontier,
                members,
                parent_judgement: None,
                state_claims: Vec::new(),
            }],
        );
        events
            .try_iter()
            .find_map(|event| match event {
                HostEvent::Shard(SHARD, ShardScopedInput::Protocol(event)) => match *event {
                    ProtocolEvent::BlockCheckCompleted {
                        block_hash: checked,
                        kind: VerificationKind::StateRoot,
                        outcome,
                    } if checked == block_hash => Some(outcome),
                    _ => None,
                },
                _ => None,
            })
            .expect("the state root check answers")
    }

    /// The state root check of a certified block removes the interval
    /// the block's header names above its parent's frontier, and lands
    /// on the root the block's own sweep produced. It is handed no
    /// judgement of the block's anchor, so nothing this replica's
    /// schedule says of that anchor holds the sweep back.
    #[test]
    fn a_certified_blocks_state_root_check_removes_the_cells_its_header_swept_past() {
        let (storage, cell) = a_store_holding_an_expired_cell();
        let swept_to =
            SweepFrontier::ceiling_at(WeightedTimestamp::from_millis(20 * SWEEP_BUCKET_MS));
        assert!(matches!(
            certified_child_check(&storage, SweepFrontier::ZERO, swept_to, &[cell]),
            CheckOutcome::Checked { .. },
        ));
    }

    /// The state root check of a certified coast block removes nothing:
    /// the header repeats its parent's frontier, so the interval is
    /// empty with an expired cell standing above it that a walk at the
    /// block's anchor would take, and the check lands on the parent's
    /// root.
    #[test]
    fn a_certified_coast_blocks_state_root_check_removes_nothing() {
        let (storage, _) = a_store_holding_an_expired_cell();
        let held_at = SweepFrontier::start_of(SweepBucket(2));
        assert!(matches!(
            certified_child_check(&storage, held_at, held_at, &[]),
            CheckOutcome::Checked { .. },
        ));
    }

    /// The state root check of a certified block refuses a header
    /// frontier no walk lands on, though its root agrees: past the
    /// clock's ceiling, where the cell it removes has not expired, and
    /// below the parent's frontier.
    #[test]
    fn a_certified_blocks_state_root_check_refuses_a_frontier_no_walk_lands_on() {
        let (storage, unexpired) = a_store_holding_a_cell_in(30);
        assert_eq!(
            certified_child_check(
                &storage,
                SweepFrontier::ZERO,
                SweepFrontier::start_of(SweepBucket(31)),
                &[unexpired],
            ),
            CheckOutcome::Refused,
        );
        let (storage, _) = a_store_holding_an_expired_cell();
        assert_eq!(
            certified_child_check(
                &storage,
                SweepFrontier::start_of(SweepBucket(5)),
                SweepFrontier::start_of(SweepBucket(4)),
                &[],
            ),
            CheckOutcome::Refused,
        );
    }
}
