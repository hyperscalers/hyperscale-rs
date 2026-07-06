//! Per-shard scope: the I/O state, core infrastructure, and the driver
//! ([`ShardLoop`]) for one hosted shard.
//!
//! [`ShardIo`] ([`io`]) composes one shard's per-subsystem state —
//! [`consensus`], [`cross_shard`], [`mempool`], and the beacon fetches in
//! [`crate::beacon`] — over shared infra (storage, the [`commit`] pipeline,
//! request-serving [`caches`]). [`ShardLoop`] is the active driver: it owns the
//! `ShardIo`, its `Vec<Vnode>`, per-step scratch, and a cloned
//! `Arc<ProcessIo>`. `ShardLoop::step(input)` dispatches one
//! [`ShardScopedInput`] to its handler; same-shard vnodes see identical inbound
//! events and produce per-validator votes.
//!
//! The top-level [`NodeHost`] composes one `ShardLoop` per hosted shard plus
//! the shared `ProcessIo`. Cross-shard concerns (transaction submission
//! fan-out, fetch tick, batch flush coordination) live on `NodeHost`; per-shard
//! concerns live here. The dispatch match below is the thin router; each
//! subsystem's `impl ShardLoop` glue lives beside its state under
//! [`consensus`], [`cross_shard`], and [`mempool`].
//!
//! [`NodeHost`]: crate::host::NodeHost

// Per-shard state, grouped by subsystem over shared infra. Crate-internal —
// `shard` is `pub` for its driver types (ShardLoop, HostEvent, …), but the
// subsystem internals are not part of the crate's external API.
pub(crate) mod caches;
pub(crate) mod commit;
pub(crate) mod consensus;
pub(crate) mod cross_shard;
pub(crate) mod io;
pub(crate) mod mempool;
pub(crate) mod phase_times;
pub(crate) mod verify;

// The driver shell: dispatch, lifecycle, metrics, the generic
// fetch/timer plumbing, and the consensus/beacon-sink driver glue.
mod actions;
mod beacon_sink;
mod fetch_dispatch;
mod lifecycle;
mod metrics;
mod protocol_event;
mod timer;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actions::handle_qc_only_commit_diverged;
use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_core::{Action, ParticipationChange, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{ProcessExecutionCache, RadixExecutor};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, PendingChain, ShardStorage};
use hyperscale_types::{
    Block, CertifiedBlock, LocalTimestamp, ShardId, TopologySnapshot, TransactionStatus, TxHash,
    Verified,
};
pub use io::ShardIo;
pub use metrics::{MetricsSnapshot, ShardMetrics, VnodeMetrics, record_metrics};

use crate::batch_accumulator::BatchAccumulator;
use crate::beacon::{
    BeaconBlockSync, BeaconProposalBinding, BeaconProposalCache, ShardWitnessBinding,
};
pub use crate::event::{
    EventPriority, FetchFailureKind, HostEvent, PoolScopedInput, ProcessScopedInput,
    ShardScopedInput,
};
use crate::fetch::FetchInput;
use crate::process::ProcessIo;
use crate::shard::commit::PreparedCommitMap;
use crate::shard::cross_shard::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
};
use crate::shard::mempool::TransactionBinding;
use crate::vnode::Vnode;

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the host when `Action::TopologyChanged` is processed.
/// Handler closures call `.load()` to get the current snapshot atomically.
pub type SharedTopologySnapshot = Arc<ArcSwap<TopologySnapshot>>;

/// Long-lived handles cloned into every delegated-action dispatch.
///
/// Wrapped in a single `Arc` so each dispatch pays one atomic-RMW for
/// the whole bundle. `topology_snapshot`, `event_sender`, and the
/// emitting vnode's signing key are not bundled — the snapshot needs
/// a fresh `load_full` per dispatch, the crossbeam `Sender` clone is
/// independent of these handles, and the signing key is per-vnode
/// (cloned separately at each dispatch site so the right validator
/// signs).
///
/// Shard-scoped handles (`pending_chain`, `prepared_commits`) live in
/// `per_shard`, keyed by the hosted shard id. Delegated handlers select
/// the right entry from the emitting vnode's shard, loading the map per
/// dispatch so shards added or dropped at runtime are observed.
pub(crate) struct DispatchHandles<S: ShardStorage, N> {
    pub(crate) executor: RadixExecutor,
    pub(crate) network: Arc<N>,
    pub(crate) execution_cache: Arc<ProcessExecutionCache>,
    /// Process-level serve cache for beacon proposals — fed by the
    /// `BuildAndBroadcastBeaconProposal` handler and the wire
    /// notification handler, read by the `GetBeaconProposalRequest`
    /// responder. No coordinator touches it.
    pub(crate) beacon_proposal_cache: Arc<BeaconProposalCache>,
    /// Process-level beacon store, threaded to the ratify-vote sign
    /// handler as its durable-register seam.
    pub(crate) beacon_storage: Arc<dyn BeaconStorage>,
    pub(crate) per_shard: ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>,
}

impl<S: ShardStorage, N> DispatchHandles<S, N> {
    /// Install the dispatch handles for a newly hosted `shard`. The
    /// reconfiguring thread is the sole writer; readers keep their
    /// loaded snapshot.
    pub(crate) fn insert_shard(&self, shard: ShardId, handles: ShardDispatchHandles<S>) {
        let mut map = (**self.per_shard.load()).clone();
        map.insert(shard, handles);
        self.per_shard.store(Arc::new(map));
    }

    /// Drop the dispatch handles for a no-longer-hosted `shard`.
    /// In-flight dispatches keep the handles their loaded snapshot
    /// carries until they complete.
    pub(crate) fn remove_shard(&self, shard: ShardId) {
        let mut map = (**self.per_shard.load()).clone();
        map.remove(&shard);
        self.per_shard.store(Arc::new(map));
    }
}

/// Per-shard subset of [`DispatchHandles`]. One entry per hosted shard.
pub(crate) struct ShardDispatchHandles<S: ShardStorage> {
    pub(crate) storage: Arc<S>,
    pub(crate) pending_chain: Arc<PendingChain<S>>,
    pub(crate) prepared_commits: Arc<Mutex<PreparedCommitMap>>,
}

impl<S: ShardStorage> Clone for ShardDispatchHandles<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            pending_chain: Arc::clone(&self.pending_chain),
            prepared_commits: Arc::clone(&self.prepared_commits),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by `ShardLoop` for the runner to process.
///
/// `shard` is the hosted shard that owns the timer. Every timer is
/// shard-scoped — the runner's timer driver keys handles by
/// `(TimerId, ShardId)`, and the firing path produces a
/// [`ShardScopedInput`] envelope targeting that shard.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Hosted shard that owns this timer.
        shard: ShardId,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Hosted shard that owns this timer.
        shard: ShardId,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`HostEvent`] the runner
/// pushes onto its event channel. Every variant produces a
/// [`HostEvent::Shard`] envelope tagged with the owning shard.
#[must_use]
pub fn timer_event(id: &TimerId, shard: ShardId) -> HostEvent {
    match id {
        TimerId::ViewChange => HostEvent::protocol(shard, ProtocolEvent::ViewChangeTimer),
        TimerId::Cleanup => HostEvent::protocol(shard, ProtocolEvent::CleanupTimer),
        TimerId::FetchTick => HostEvent::shard(shard, ShardScopedInput::FetchTick),
        TimerId::BeaconCommitteeStart => {
            HostEvent::protocol(shard, ProtocolEvent::BeaconCommitteeStartTimer)
        }
        TimerId::BeaconRatifyTrigger => {
            HostEvent::protocol(shard, ProtocolEvent::BeaconRatifyTimer)
        }
        TimerId::BeaconSpcView => HostEvent::protocol(shard, ProtocolEvent::BeaconSpcViewTimer),
        TimerId::BeaconSpcInputDwell => {
            HostEvent::protocol(shard, ProtocolEvent::BeaconSpcInputDwellTimer)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Event push helpers
// ═══════════════════════════════════════════════════════════════════════

/// Push a shard-scoped input into the event channel.
///
/// Off-thread closures and `ShardLoop` methods both use this to feed
/// results back to the next `step()`. The channel is unbounded; send
/// failure is silently ignored by design (the only failure mode is the
/// receiver having been dropped at shutdown, in which case there's
/// nothing to do).
pub(crate) fn push_shard_input(tx: &Sender<HostEvent>, shard: ShardId, input: ShardScopedInput) {
    let _ = tx.send(HostEvent::shard(shard, input));
}

/// Push a [`ProtocolEvent`] (wrapped in
/// [`ShardScopedInput::Protocol`]) into the event channel.
/// The receiver fans the event across every hosted vnode in `shard`.
/// See [`push_shard_input`] for the drop-on-shutdown convention.
pub(crate) fn push_protocol_event(tx: &Sender<HostEvent>, shard: ShardId, event: ProtocolEvent) {
    let _ = tx.send(HostEvent::protocol(shard, event));
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `NodeHost::step()`.
///
/// Aggregates the per-step scratch from every hosted shard touched by
/// the event: emitted transaction statuses, timer operations, action
/// counts. Sync/fetch I/O and block-commit dispatch happen internally
/// via the `Network` and `Dispatch` traits — the runner only processes
/// emitted transaction statuses and timer operations.
#[derive(Default)]
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted via [`Action::ReconfigureParticipation`]
    /// during this step. The runner reconfigures physical shard
    /// membership from these — they are requests to the process layer,
    /// not state-machine state.
    pub participation_changes: Vec<ParticipationChange>,
}

impl StepOutput {
    /// Fold another step's output into this one. The whole-host driver
    /// ([`NodeHost::step`](crate::host::NodeHost::step)) uses this to
    /// aggregate the per-driver outputs of every shard and the pool a
    /// single event touched.
    pub(crate) fn merge(&mut self, other: Self) {
        self.emitted_statuses.extend(other.emitted_statuses);
        self.actions_generated += other.actions_generated;
        self.timer_ops.extend(other.timer_ops);
        self.participation_changes
            .extend(other.participation_changes);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ShardLoop — per-shard I/O state plus the vnodes that share it
// ═══════════════════════════════════════════════════════════════════════

/// Active per-shard driver: one hosted shard's [`ShardIo`] plus every
/// [`Vnode`] that participates in this shard's consensus, plus per-step
/// scratch and a shared `Arc<ProcessIo>`.
///
/// Same-shard vnodes share the [`ShardIo`] (one storage, one set of fetch
/// instances, one mempool body store, etc.); cross-shard vnodes live in
/// different `ShardLoop`s. [`Self::step`] dispatches one [`ShardScopedInput`]
/// to its handler.
pub struct ShardLoop<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// Shard this loop drives. Mirrors the key in `NodeHost::shards`;
    /// held inline so methods on `ShardLoop` can self-identify without a
    /// parent-map lookup.
    pub shard: ShardId,
    /// Sender for this shard's own event channel. The channel is created
    /// with the loop and torn down with it, so the handle is cached here
    /// rather than looked up through `ProcessIo`'s swappable map on
    /// every dispatch.
    pub(crate) event_tx: Sender<HostEvent>,
    /// Process-scoped resources shared with every other hosted shard:
    /// network adapter, dispatch pool, tx validator, topology snapshot,
    /// dispatch handles, event sender. Cloned `Arc` so off-thread
    /// closures spawned from this loop's handlers can capture it cheaply.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,
    /// Per-shard I/O state shared by every vnode in `vnodes`.
    pub io: ShardIo<S>,
    /// Beacon-block catch-up sync FSM. The beacon chain is host-global, but
    /// each driver keeps its own instance (a lock-free per-thread
    /// trade-off); the driving logic lives in [`crate::beacon`]. Fed
    /// `Admitted` on every beacon commit and `StartBeaconBlockSync` when a
    /// gossiped block sits more than one epoch ahead of the local tip.
    pub(crate) beacon_block: BeaconBlockSync,
    /// Vnodes participating in this shard's consensus. Driven in order
    /// during each `step()` iteration; same-shard vnodes see identical
    /// inbound events and produce per-validator votes.
    pub vnodes: Vec<Vnode>,
    /// Cached wall-clock time for this shard. Set by the runner via
    /// `NodeHost::set_time` (which propagates to every hosted shard);
    /// read by per-vnode `state.handle(now, _)` calls and by helpers
    /// that need a single consistent stamp across an action burst.
    pub now: LocalTimestamp,
    /// Per-step scratch: timer set/cancel operations emitted during the
    /// step. Cleared at step entry; drained into the returned
    /// [`StepOutput`] for the runner to translate into timer-driver
    /// calls.
    pub pending_timer_ops: Vec<TimerOp>,
    /// Per-step scratch: `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into [`StepOutput`].
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Per-step scratch: placement deltas emitted via
    /// `Action::ReconfigureParticipation`. Drained into [`StepOutput`].
    pub pending_participation_changes: Vec<ParticipationChange>,
    /// Per-step scratch: count of actions this shard's vnodes produced
    /// during the step. Drained into [`StepOutput`] for the runner's
    /// metrics; reset at step entry.
    pub actions_generated: usize,
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Sender for this shard's own event channel — the destination for
    /// every callback this loop spawns (block-commit completions, fetch
    /// results, BLS-verify outcomes) and every protocol event it pushes
    /// back to itself.
    pub(crate) const fn event_sender(&self) -> &Sender<HostEvent> {
        &self.event_tx
    }

    /// Access the vnode at `vnode_idx` within this shard's group.
    ///
    /// # Panics
    /// Panics if `vnode_idx` is out of range.
    pub(crate) fn vnode(&self, vnode_idx: usize) -> &Vnode {
        &self.vnodes[vnode_idx]
    }

    /// Mutably access the vnode at `vnode_idx` within this shard's group.
    ///
    /// # Panics
    /// Panics if `vnode_idx` is out of range.
    pub(crate) fn vnode_mut(&mut self, vnode_idx: usize) -> &mut Vnode {
        &mut self.vnodes[vnode_idx]
    }

    /// Dispatch a [`ShardScopedInput`] to its handler. Does NOT clear or
    /// drain per-step scratch — the caller (typically [`NodeHost::step`])
    /// manages the scratch lifecycle. Refreshes this shard's `FetchTick`
    /// timer once the input has fully settled so the runner sees the
    /// final Set/Cancel for `(TimerId::FetchTick, self.shard)` in the
    /// emitted timer ops.
    ///
    /// [`NodeHost::step`]: crate::host::NodeHost::step
    pub(crate) fn step(&mut self, input: ShardScopedInput) {
        self.dispatch_input(input);
        self.update_fetch_tick_timer();
    }

    #[allow(clippy::too_many_lines)] // single dispatch over ShardScopedInput variants
    fn dispatch_input(&mut self, input: ShardScopedInput) {
        match input {
            // ── Transaction validation pipeline ────────────────────────
            ShardScopedInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(tx);
            }
            ShardScopedInput::TransactionsFetched { batch } => {
                self.handle_fetched_txs_for_validation(batch);
            }
            ShardScopedInput::AdmitTransaction { tx } => {
                self.handle_admit_transaction(tx);
            }
            ShardScopedInput::AdmitAndGossipTransaction { tx, touched_shards } => {
                self.handle_admit_and_gossip_transaction(tx, &touched_shards);
            }
            ShardScopedInput::GossipTransaction { tx, touched_shards } => {
                self.handle_gossip_transaction(&tx, &touched_shards);
            }
            ShardScopedInput::TransactionValidated { tx } => {
                self.handle_transaction_validated(tx);
            }
            ShardScopedInput::TransactionValidationsFailed { hashes } => {
                self.handle_transaction_validations_failed(&hashes);
            }
            ShardScopedInput::Protocol(event) => match *event {
                ProtocolEvent::BlockPersisted { height, .. } => self.handle_block_persisted(height),
                other => self.handle_protocol_passthrough(other),
            },

            // ── Sync protocol ──────────────────────────────────────────
            ShardScopedInput::BlockSyncResponseReceived { height, block } => {
                self.handle_block_sync_response_received(height, block);
            }
            ShardScopedInput::BlockSyncFetchFailed { height, kind } => {
                self.handle_block_sync_fetch_failed(height, kind);
            }
            ShardScopedInput::BeaconBlockSyncResponseReceived { epoch, block } => {
                self.handle_beacon_block_sync_response_received(epoch, block);
            }
            ShardScopedInput::BeaconBlockSyncFetchFailed { epoch, kind } => {
                self.handle_beacon_block_sync_fetch_failed(epoch, kind);
            }
            ShardScopedInput::SyncBlockValidated { height, certified } => {
                self.handle_sync_block_validated(height, *certified);
            }
            ShardScopedInput::SyncBlockValidationFailed { height, reason } => {
                self.handle_sync_block_validation_failed(height, reason);
            }
            ShardScopedInput::RemoteHeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
            } => {
                self.handle_remote_headers_response_received(
                    source_shard,
                    from_height,
                    count,
                    headers,
                );
            }
            ShardScopedInput::RemoteHeadersFetchFailed {
                source_shard,
                from_height,
                count,
                kind,
            } => {
                self.handle_remote_headers_fetch_failed(source_shard, from_height, count, kind);
            }
            ShardScopedInput::SettledWavesResponseReceived {
                source_shard,
                waves,
            } => {
                self.handle_settled_waves_response_received(source_shard, waves);
            }
            ShardScopedInput::SettledWavesFetchFailed { source_shard } => {
                self.handle_settled_waves_fetch_failed(source_shard);
            }

            // ── Fetch protocol ─────────────────────────────────────────
            ShardScopedInput::TransactionsFetchFailed { hashes } => {
                self.drive_fetch::<TransactionBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::ProvisionsFetchFailed {
                source_shard,
                block_height,
            } => {
                let local_shard = self.shard;
                self.drive_fetch::<ProvisionBinding>(FetchInput::Failed {
                    ids: vec![(source_shard, local_shard, block_height)],
                });
            }
            ShardScopedInput::ExecCertFetchFailed { hashes } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::LocalProvisionsFetchFailed { hashes } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Failed { ids: hashes });
            }
            ShardScopedInput::FinalizedWavesFetchFailed { ids } => {
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Failed { ids });
            }
            ShardScopedInput::ShardWitnessesFetchFailed { ids } => {
                self.drive_fetch::<ShardWitnessBinding>(FetchInput::Failed { ids });
            }
            ShardScopedInput::BeaconProposalFetchFailed { ids } => {
                self.drive_fetch::<BeaconProposalBinding>(FetchInput::Failed { ids });
            }

            // ── Certified header (gossip → BLS verify → state machine) ──
            ShardScopedInput::CommittedBlockGossipReceived {
                certified_header,
                sender,
                public_key,
                sender_signature,
            } => self.handle_committed_block_gossip_received(
                certified_header,
                sender,
                public_key,
                sender_signature,
            ),

            // ── Periodic fetch / sync tick ─────────────────────────────
            ShardScopedInput::FetchTick => self.handle_fetch_tick(),

            // ── QC-only commit prep callbacks ──────────────────────────
            ShardScopedInput::QcOnlyCommitPrepared {
                certified,
                source,
                witness,
            } => {
                self.handle_qc_only_commit_prepared(certified, source, witness);
            }
            ShardScopedInput::QcOnlyCommitDiverged(div) => {
                handle_qc_only_commit_diverged(&div);
            }
        }
    }

    /// Fan a shard-scoped protocol event out to every hosted vnode in
    /// this shard and dispatch each vnode's resulting actions.
    ///
    /// Every same-shard vnode independently applies the event at the
    /// shard's cached `now` and produces its own signed actions.
    pub(crate) fn dispatch_event(&mut self, event: ProtocolEvent) {
        let count = self.vnodes.len();
        if count == 0 {
            return;
        }
        let now = self.now;
        // Clone for every recipient except the last; move into the last
        // so we don't pay a final clone whose result is immediately
        // dropped.
        for vnode_idx in 0..count - 1 {
            let ev = event.clone();
            let actions = self.vnode_mut(vnode_idx).state.handle(now, ev);
            self.drain_actions(vnode_idx, actions);
        }
        let actions = self.vnode_mut(count - 1).state.handle(now, event);
        self.drain_actions(count - 1, actions);
    }

    /// Dispatch a `Vec<Action>` produced by a vnode's state machine.
    /// Bumps the step's action counter, processes each action with the
    /// emitting vnode's signing context, and flushes pending block
    /// commits at the tail.
    pub(crate) fn drain_actions(&mut self, vnode_idx: usize, actions: Vec<Action>) {
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(vnode_idx, action);
        }
        self.flush_block_commits();
    }

    /// Set this shard's cached wall-clock time. Production calls this
    /// from the shard's pinned thread; sim drives every hosted shard's
    /// time via [`NodeHost::set_time`].
    ///
    /// [`NodeHost::set_time`]: crate::host::NodeHost::set_time
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Install `genesis` on every hosted vnode and commit it through
    /// the normal pipeline — the same sequence the startup runners
    /// perform for a network genesis, used pre-spawn by a split child's
    /// flip with the deterministic
    /// [`Block::split_child_genesis`](hyperscale_types::Block::split_child_genesis).
    /// The storage's adoption already points the JMT at the genesis
    /// version, so the commit's genesis arm re-records that height.
    ///
    /// Returns the timer ops the genesis commit produced — chiefly the
    /// consensus pacemaker's [`TimerId::ViewChange`] arm. The caller spawns
    /// the loop after this returns, so it must hand these back as the loop's
    /// initial timer ops; otherwise the first `run_step` clears them and the
    /// shard never arms its pacemaker (the startup runner threads the
    /// equivalent ops through `initial_timer_ops`).
    pub fn install_genesis(&mut self, genesis: &Block) -> Vec<TimerOp> {
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(
            genesis.clone(),
        ));
        let now = self.now;
        for vnode_idx in 0..self.vnodes.len() {
            let actions = self
                .vnode_mut(vnode_idx)
                .state
                .initialize_genesis(now, genesis);
            self.drain_actions(vnode_idx, actions);
        }
        self.step(ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::BlockCommitted { certified },
        )));

        self.seed_genesis_substate_frontier(genesis);
        std::mem::take(&mut self.pending_timer_ops)
    }

    /// Seed every vnode's reshape-trigger count frontier from the genesis
    /// store count. Genesis substates (engine bootstrap + funded accounts)
    /// never appear as a commit delta, so without this the frontier reads
    /// zero until the first delta-bearing block and a non-zero reshape
    /// threshold misfires (a quiet shard below `merge_bytes` triggers a
    /// spurious merge). The engine genesis already committed the substates
    /// before either genesis path reaches here, so the count is readable.
    pub(crate) fn seed_genesis_substate_frontier(&mut self, genesis: &Block) {
        let genesis_count = self
            .io
            .storage
            .substate_bytes_at(genesis.height())
            .unwrap_or(0);
        for vnode_idx in 0..self.vnodes.len() {
            self.vnode_mut(vnode_idx)
                .state
                .seed_substate_bytes_frontier(genesis.height(), genesis_count);
        }
    }

    /// Process one [`ShardScopedInput`] end-to-end: clear per-step
    /// scratch, dispatch the input (which also refreshes this shard's
    /// `FetchTick` timer), then drain accumulated outputs.
    ///
    /// Production's per-shard pinned thread calls this; sim still goes
    /// through [`NodeHost::step`] for the global event queue.
    ///
    /// [`NodeHost::step`]: crate::host::NodeHost::step
    pub fn run_step(&mut self, input: ShardScopedInput) -> StepOutput {
        self.clear_scratch();
        self.step(input);
        self.take_output()
    }

    /// Clear per-step scratch so the next step's drained output reflects
    /// only that step. Called by both this loop's [`Self::run_step`] and the
    /// whole-host [`NodeHost::step`](crate::host::NodeHost::step) before
    /// dispatch; centralizing it keeps the two drivers' scratch contract in
    /// one place.
    pub(crate) fn clear_scratch(&mut self) {
        self.pending_timer_ops.clear();
        self.emitted_statuses.clear();
        self.pending_participation_changes.clear();
        self.actions_generated = 0;
    }

    /// Drain this step's accumulated scratch into a [`StepOutput`]. The
    /// counterpart to [`Self::clear_scratch`]; both drivers drain through
    /// here so the scratch field set lives in one place.
    pub(crate) fn take_output(&mut self) -> StepOutput {
        StepOutput {
            emitted_statuses: std::mem::take(&mut self.emitted_statuses),
            actions_generated: std::mem::replace(&mut self.actions_generated, 0),
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
            participation_changes: std::mem::take(&mut self.pending_participation_changes),
        }
    }

    /// Flush this shard's batch accumulators whose deadlines have
    /// expired at `now`.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        if self.io.mempool.validation_batch.is_expired(now) {
            self.flush_validation_batch();
        }
        if self.io.consensus.certified_header_batch.is_expired(now) {
            self.flush_certified_header_verifications();
        }
        let expired_dsts: Vec<ShardId> = self
            .io
            .mempool
            .outbound_gossip_batches
            .iter()
            .filter_map(|(dst, batch)| batch.is_expired(now).then_some(*dst))
            .collect();
        for dst in expired_dsts {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Flush every pending batch on this shard regardless of deadline.
    /// Used at shutdown and by the sim harness between events.
    pub fn flush_all_batches(&mut self) {
        self.flush_block_commits();
        self.flush_validation_batch();
        self.flush_certified_header_verifications();
        let dsts: Vec<ShardId> = self
            .io
            .mempool
            .outbound_gossip_batches
            .keys()
            .copied()
            .collect();
        for dst in dsts {
            self.flush_tx_gossip_batch(dst);
        }
    }

    /// Nearest batch deadline on this shard, if any — the production
    /// loop uses it to bound `recv_timeout` so the per-shard wake-up
    /// fires when its earliest batch expires.
    #[must_use]
    pub fn nearest_batch_deadline(&self) -> Option<LocalTimestamp> {
        [
            self.io.mempool.validation_batch.deadline(),
            self.io.consensus.certified_header_batch.deadline(),
        ]
        .into_iter()
        .chain(
            self.io
                .mempool
                .outbound_gossip_batches
                .values()
                .map(BatchAccumulator::deadline),
        )
        .flatten()
        .min()
    }
}
