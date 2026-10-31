//! Action processing and dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::{
    Action, ActionContext, CommitSource, Delegated, FetchRequest, ProtocolEvent, Signing,
};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_execution::action_handlers::handle_action as handle_execution_action;
use hyperscale_metrics::record_transaction_finalized;
use hyperscale_network::Network;
use hyperscale_provisions::action_handlers::handle_action as handle_provisions_action;
use hyperscale_shard::action_handlers::handle_action as handle_shard_action;
use hyperscale_storage::ShardStorage;
use hyperscale_types::{
    Anchor, BeaconWitnessCommit, BlockHash, BlockHeight, CertifiedBlock, ShardId, SubstateKey,
    TerminalEvidence, TransactionStatus, TxHash, ValidatorId, Verified, WeightedTimestamp,
};
use tracing::{debug, error, trace, warn};

use super::{ShardLoop, push_protocol_event, push_shard_input};
use crate::event::{ShardScopedInput, TimerOp, TimerOwner};
use crate::fetch::{FetchInput, Release};
use crate::shard::commit::{
    AccumulateDecision, PendingCommit, QcOnlyCommit, QcOnlyDecision, QcOnlyDivergence, QcOnlyPrep,
    Refuted, make_commit_prepared, run_qc_only_prep,
};
use crate::shard::cross_shard::{SettledTxsBinding, StateProofBinding};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action the replica emitted.
    ///
    /// Two categories of arm:
    /// - **Coordinator policy** — delegated to coordinator crates via
    ///   `dispatch_delegated_action`. Crypto, execution, broadcasts.
    /// - **`ShardLoop`-internal effects** — handled inline because the
    ///   work IS `ShardLoop` machinery (timers, caches consumed by serving,
    ///   RPC observability, block commit pipeline, topology plumbing).
    #[allow(clippy::too_many_lines)] // single dispatch over Action variants; one arm per variant
    pub(super) fn process_action(&mut self, action: Action) {
        match action {
            // ─── Coordinator policy: delegated to worker pools ─────────────
            Action::Consensus(action) => {
                self.dispatch_delegated_action(action, handle_shard_action::<S, N>);
            }
            Action::Execution(action) => {
                self.dispatch_delegated_action(action, handle_execution_action::<S, N>);
            }
            Action::Provisions(action) => {
                self.dispatch_delegated_action(action, handle_provisions_action::<S, N>);
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
                self.io.tick_chain.raise_floor(floor, self.shard);
                // A row the crossing keeps may be stated by a tick this
                // replica never ran, or whose run lands at or below the floor.
                self.io
                    .tick_chain
                    .seed_stated(self.replica.shard_coordinator().member_rows());
            }

            // ─── Sync / fetch protocol drive ───────────────────────────────
            Action::StartBlockSync { target } => {
                self.process_start_block_sync(target);
            }
            Action::SyncBlockApplied { height } => {
                self.process_sync_block_applied(height);
            }
            Action::ReopenSyncHeight { height, hash } => {
                self.process_reopen_sync_height(height, hash);
            }
            Action::SettleBlockSync => {
                self.process_settle_block_sync();
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
            Action::Fetch(req) => self.process_fetch_request(req),
            Action::AbandonFetch(ids) => self.release_fetch(ids, Release::Abandoned),

            // ─── ShardLoop-internal effects ────────────────────────────────
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set {
                    owner: TimerOwner::Loop(self.shard),
                    id,
                    duration,
                });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel {
                    owner: TimerOwner::Loop(self.shard),
                    id,
                });
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
                    .insert(tick.receipt_hash(), tick.clone());
            }
        }

        // Tell the remote-header-sync FSM about admitted headers so it can
        // advance the source's scope and emit `SyncComplete` once the chain
        // catches up. Drives any newly-emitted range fetches inline.
        //
        // The scope advances by the replica's contiguous verified frontier,
        // not this header's own height: a provision- or execution-certificate-
        // bundled source header lands above the frontier when
        // `block.committed` gossip is suppressed, and jumping the scope to it
        // would strand the intervening heights below, since the sync queues
        // from its frontier and would never fetch the gap the commit-proof
        // walk needs contiguous.
        if let ProtocolEvent::RemoteHeaderAdmitted { certified_header } = &pe {
            self.follow_remote_header_frontier(certified_header.shard_id());
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
    /// ran was written by another commit path's flush, and the prep read
    /// its parent over a store already past it: the refutation is no
    /// evidence about local state, so the slot passes to the next queued
    /// entry. Anything else is fatal.
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
    /// decision: feed the sync protocol the new committed height and,
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
                committee_anchor,
                notify_now,
            } => {
                debug!(height = height.inner(), "Block committed");
                self.admit_committed_height(height);

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
    /// The fetch instance lives in this shard's `ShardIo`, not the
    /// routing target's, which rides on the request. `Ask` never emits `Send`s on its own — it only adds the
    /// ids to the pending set; chunks fan out under the per-tick cap. The
    /// tick timer is refreshed once at the end of `ShardLoop::step`.
    ///
    /// The three arms below `Ask` are a different message: the pending
    /// set under a scope is now exactly these ids. Their consumers
    /// re-derive the whole wanted set each pass, so what the fetch still
    /// holds under that scope and the consumer no longer names is retired
    /// here — for an id nobody re-asks about, against a committee that
    /// may never answer, this is the only release there is.
    #[allow(clippy::too_many_lines)] // single dispatch over FetchRequest variants
    fn process_fetch_request(&mut self, req: FetchRequest) {
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
                // under it and the scan no longer names is an answer nobody
                // is waiting for — a transaction that expired out of the
                // pool, or the rule retiring as the chain outlives its
                // origin. Nothing else retires these ids: a terminated
                // committee that never answers would pin them for good.
                self.abandon_unwanted::<StateProofBinding>(&wanted, |id| id.0 == terminal);
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
            FetchRequest::Packages { wanted } => self.fetch_wanted_packages(wanted),
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch delegated work to its pool, run there by `handle`, the
    /// handler of the coordinator crate whose type it is.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via
    /// this shard's event channel and are processed on a future `step()`
    /// call. With `SyncDispatch` (simulation), `spawn_*` runs inline so
    /// events enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action<A: Delegated>(
        &self,
        action: A,
        handle: fn(A, &ActionContext<'_, S, N>),
    ) {
        let shard = self.shard;
        let handles = Arc::clone(&self.process.dispatch_handles);
        let topology_snapshot = Arc::clone(self.replica.topology_arc());
        let resolution = resolve_signer(
            &action,
            &self.signers,
            topology_snapshot.committee_for_shard(shard),
        );
        let signing = match resolution {
            SignerResolution::Unsigned => None,
            SignerResolution::Signs(signer) => {
                let attached = &self.signers[&signer];
                Some((
                    signer,
                    Arc::clone(&attached.signer),
                    Arc::clone(&attached.gate),
                ))
            }
            SignerResolution::Dropped => {
                trace!(
                    action = action.type_name(),
                    signer = ?action.signer(),
                    "Dropping a signing action whose signer is not attached"
                );
                return;
            }
        };
        let event_tx = self.event_sender().clone();
        let verifier = Arc::clone(&self.process.verifier);
        let par = self.process.dispatch.parallelism();
        // The loop's own stores, so a job spawned as the shard is torn
        // down, or by a loop its host already let go of, still holds them.
        let storage = Arc::clone(&self.io.storage);
        let pending_chain = Arc::clone(&self.io.pending_chain);
        let tick_chain = Arc::clone(&self.io.tick_chain);
        let prepared_commits = self.io.block_commit.prepared_commits_handle();

        self.process.dispatch.spawn(A::POOL, move || {
            // Action handlers emit `ProtocolEvent`s; stamp each with this
            // loop's shard so the receiver routes back to it. `Arc`-shaped
            // so handlers can clone it into callback closures that outlive
            // the action call.
            let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> =
                Arc::new(move |event| push_protocol_event(&event_tx, shard, event));
            let commit_prepared =
                make_commit_prepared(Arc::clone(&pending_chain), prepared_commits);
            let ctx = ActionContext {
                executor: handles.executor.as_ref(),
                topology_snapshot: &topology_snapshot,
                signing: signing.as_ref().map(|(signer, key, gate)| Signing {
                    me: *signer,
                    key,
                    gate: gate.as_ref(),
                }),
                shard,
                pending_chain: &pending_chain,
                tick_chain: &tick_chain,
                vote_registers: storage.as_ref(),
                beacon_chain: handles.beacon_storage.as_ref(),
                network: &handles.network,
                verifier: verifier.as_ref(),
                notify,
                commit_prepared: &commit_prepared,
                par,
            };
            handle(action, &ctx);
        });
    }

    /// The beacon folded a schedule. The beacon attests a boundary off its
    /// child's header, and the commit path pins the boundary when that
    /// child commits. A shard that halts with the child certified but
    /// never committed leaves its attested anchor unpinned on every
    /// member, and nothing can seat against it — not a rotation's
    /// entrant, not the recovery's fresh committee. The committed tip is
    /// the anchor's exact state for as long as it stays the tip, so pin it
    /// the moment the attestation lands. A pin that already exists costs a
    /// stat. Then the replica holds the schedule and replays what waited
    /// on the epoch.
    pub(in crate::shard) fn handle_beacon_block_persisted(&mut self, event: ProtocolEvent) {
        if let ProtocolEvent::BeaconBlockPersisted { schedule, .. } = &event
            && let Some(anchor) = schedule.head().boundary(self.shard)
            && anchor.height == self.io.storage.committed_height()
        {
            self.io.boundary_pins.pin(anchor.height);
        }
        self.dispatch_event(event);
    }
}

/// Which attached signer a delegated action signs under.
#[derive(Debug, PartialEq, Eq)]
enum SignerResolution {
    /// The action signs nothing.
    Unsigned,
    /// The action signs under this attached signer.
    Signs(ValidatorId),
    /// The action names a signer that cannot sign it here.
    Dropped,
}

/// Resolve the signer of `action` among the `attached` signers. A
/// safety-bearing action signs only under the signer it names, whose
/// registers it ratchets. An envelope-only action authenticates a
/// self-authenticating payload, so it falls back from an unattached
/// preference to the lowest-id attached signer in `committee`, the
/// artifact's governing committee, and is dropped only with none.
fn resolve_signer<T>(
    action: &impl Delegated,
    attached: &BTreeMap<ValidatorId, T>,
    committee: &[ValidatorId],
) -> SignerResolution {
    let Some(named) = action.signer() else {
        return SignerResolution::Unsigned;
    };
    if attached.contains_key(&named) {
        return SignerResolution::Signs(named);
    }
    if !action.envelope_only() {
        return SignerResolution::Dropped;
    }
    attached
        .keys()
        .copied()
        .find(|signer| committee.contains(signer))
        .map_or(SignerResolution::Dropped, SignerResolution::Signs)
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
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Arc;

    use hyperscale_core::{
        Action, ConsensusAction, Delegated, ProtocolEvent, ProvisionAction, StateRootCheck,
    };
    use hyperscale_hbor::Capped;
    use hyperscale_storage::test_helpers::commit_writes;
    use hyperscale_storage::{
        ChainWrites, MemberInputs, ParentAnchor, ShardChainWriter, SubstateStore,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::network::request::GetFinalizationsRequest;
    use hyperscale_types::test_utils::{install_stub_protocol_statics, stub_sweepable_cell};
    use hyperscale_types::{
        Address, AddressClass, BlockHash, BlockHeight, ChainOrigin, CheckOutcome, ConsensusReceipt,
        EpochWindows, Finalization, FrontierInputs, GlobalReceiptHash, Hash, QuorumCertificate,
        SWEEP_BUCKET_MS, SettledWrites, StateWrites, StoredReceipt, SubstateKey, SweepBucket,
        SweepFrontier, TickId, TxHash, ValidatorId, Verifiable, VerificationKind,
        WeightedTimestamp, shard_prefix_path,
    };

    use super::{SignerResolution, resolve_signer};
    use crate::event::{HostEvent, ShardScopedInput};
    use crate::shard::cross_shard::serve_finalizations_request;
    use crate::shard::test_host::{Fixture, SHARD, loop_of};

    /// A block may name a legs entry its proposer has since replaced by
    /// one naming more of the tick's legs. Every entry announced enters
    /// the serving cache as it is announced and stays there, so a voter
    /// asking by the hash the block names is answered with that entry
    /// whatever has replaced it.
    #[test]
    fn a_replaced_legs_entry_is_still_served_by_its_hash() {
        let fix = Fixture::new();
        let (mut host, _events) = fix.host_with_events(BlockHeight::GENESIS);

        let tick_id = TickId::new(SHARD, BlockHeight::new(1));
        let legs: Vec<StoredReceipt> = [b"first leg", b"other leg"]
            .into_iter()
            .map(|seed| {
                StoredReceipt::new(
                    TxHash::from(Hash::from_bytes(seed)),
                    Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                        writes: StateWrites::default(),
                        beacon_witness_events: Capped::empty(),
                        events: Capped::empty(),
                    }),
                )
            })
            .collect();
        let first_leg = legs[0].tx_hash;
        let every_leg = Finalization::accepting(
            tick_id,
            Capped::new(legs).expect("a list written out in a test"),
        );
        let replaced = every_leg.clone().naming(&HashSet::from([first_leg]));
        assert_ne!(replaced.receipt_hash(), every_leg.receipt_hash());

        loop_of(&mut host).drain_actions(
            [&replaced, &every_leg]
                .map(|fw| {
                    Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
                        finalizations: vec![Verifiable::from(fw.clone())],
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

    /// How the loop's state root check ends for a certified,
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
        let check = ConsensusAction::VerifyStateRoot(Box::new(StateRootCheck {
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
        }));
        loop_of(&mut host).drain_actions(vec![Action::Consensus(check)]);
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

    /// [`resolve_signer`] among the `attached` ids.
    fn resolve(
        action: &impl Delegated,
        attached: &[ValidatorId],
        committee: &[ValidatorId],
    ) -> SignerResolution {
        let attached: BTreeMap<ValidatorId, ValidatorId> =
            attached.iter().map(|&id| (id, id)).collect();
        resolve_signer(action, &attached, committee)
    }

    fn validator(id: u64) -> ValidatorId {
        ValidatorId::new(id)
    }

    fn provisions_preferring(signer: ValidatorId) -> ProvisionAction {
        ProvisionAction::FetchAndBroadcastProvisions {
            block_hash: BlockHash::ZERO,
            requests: Vec::new(),
            source_shard: SHARD,
            block_height: BlockHeight::new(1),
            source_block_ts: WeightedTimestamp::ZERO,
            shard_recipients: HashMap::new(),
            signer,
        }
    }

    /// An envelope-only action signs under its preferred signer when that
    /// signer is attached, even beside a lower one. Otherwise it falls back
    /// to the lowest attached signer of the governing committee, and is
    /// dropped only when none is attached.
    #[test]
    fn an_envelope_action_falls_back_to_an_attached_committee_signer() {
        let committee = [validator(1), validator(2), validator(3)];
        assert_eq!(
            resolve(
                &provisions_preferring(validator(3)),
                &[validator(2), validator(3)],
                &committee,
            ),
            SignerResolution::Signs(validator(3)),
        );
        assert_eq!(
            resolve(
                &provisions_preferring(validator(1)),
                &[validator(0), validator(3), validator(2)],
                &committee,
            ),
            SignerResolution::Signs(validator(2)),
        );
        assert_eq!(
            resolve(
                &provisions_preferring(validator(1)),
                &[validator(0)],
                &committee,
            ),
            SignerResolution::Dropped,
        );
    }

    /// A safety-bearing action signs only under the signer it names, whose
    /// registers it ratcheted: naming one not attached drops it, whatever
    /// else is. An action no signer signs resolves to none.
    #[test]
    fn a_safety_bearing_action_naming_an_unattached_signer_is_dropped() {
        let committee = [validator(1), validator(2), validator(3)];
        let announcement = |signer| ConsensusAction::SignAndBroadcastQcAnnouncement {
            qc: QuorumCertificate::genesis(SHARD, ChainOrigin::root(WeightedTimestamp::ZERO)),
            recipients: Vec::new(),
            signer,
        };
        assert_eq!(
            resolve(
                &announcement(validator(1)),
                &[validator(2), validator(3)],
                &committee,
            ),
            SignerResolution::Dropped,
        );
        assert_eq!(
            resolve(&announcement(validator(1)), &[validator(1)], &committee),
            SignerResolution::Signs(validator(1)),
        );
        let check = ConsensusAction::VerifyResolutions {
            block_hash: BlockHash::ZERO,
            entries: Vec::new(),
            windows: EpochWindows::new(0, 1_000),
        };
        assert_eq!(
            resolve(&check, &[validator(1)], &committee),
            SignerResolution::Unsigned,
        );
    }

    /// A loop its host has let go of still dispatches over its own
    /// stores: the host's dispatch handles no longer name its shard, and
    /// the check answers all the same.
    #[test]
    fn a_loop_removed_from_its_host_still_dispatches_its_checks() {
        let (mut host, events) = Fixture::new().host_with_events(BlockHeight::GENESIS);
        let mut removed = host.remove_shard(SHARD).expect("the fixture hosts SHARD");
        while events.try_recv().is_ok() {}
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"a block with no records"));
        removed.drain_actions(vec![Action::Consensus(
            ConsensusAction::VerifyResolutions {
                block_hash,
                entries: Vec::new(),
                windows: EpochWindows::new(0, 1_000),
            },
        )]);
        assert!(
            events.try_iter().any(|event| matches!(
                event,
                HostEvent::Shard(SHARD, ShardScopedInput::Protocol(event))
                    if matches!(
                        *event,
                        ProtocolEvent::BlockCheckCompleted {
                            block_hash: checked,
                            kind: VerificationKind::Resolutions,
                            ..
                        } if checked == block_hash
                    )
            )),
            "the check answers on the removed loop's channel",
        );
    }
}
