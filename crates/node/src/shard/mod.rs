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
pub(crate) mod boundary_pins;
pub(crate) mod caches;
pub(crate) mod commit;
pub(crate) mod consensus;
pub(crate) mod cross_shard;
pub(crate) mod crossing_index;
pub(crate) mod instances;
pub(crate) mod io;
pub(crate) mod mempool;
pub(crate) mod packages;
pub(crate) mod phase_times;
pub(crate) mod verify;

// The driver shell: dispatch, lifecycle, metrics, the generic
// fetch/timer plumbing, and the consensus/beacon-sink driver glue.
mod actions;
mod beacon_sink;
mod fetch_dispatch;
mod lifecycle;
pub use lifecycle::{installed_network_genesis_block, network_genesis_block};
mod metrics;
mod protocol_event;
mod slowest_seat;
mod timer;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
pub(crate) use fetch_dispatch::FetchTicker;
use hyperscale_core::{Action, ParticipationChange, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Executor, LocalCells};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, PendingChain, RecoveredState, ShardStorage, TickChain};
use hyperscale_types::{
    Address, Block, CertifiedBlock, Hash, LocalTimestamp, ShardId, SubstateKey, TopologySnapshot,
    TransactionStatus, TxHash, ValidatorId, Verified,
};
pub use io::ShardIo;

use crate::batch_accumulator::BatchAccumulator;
use crate::beacon::{BeaconBlockSync, BeaconCandidateCache, BeaconProposalCache};
pub use crate::event::{
    EventPriority, FetchFailureKind, HostEvent, PoolScopedInput, ProcessScopedInput,
    ShardScopedInput,
};
use crate::fetch::Release;
use crate::process::ProcessIo;
use crate::shard::commit::PreparedCommitMap;
use crate::vnode::{SeatVnodeGroup, Vnode, VnodeSeat, seat_vnode_into_group};

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
    pub(crate) executor: Arc<Executor>,
    pub(crate) network: Arc<N>,
    /// Process-level serve cache for beacon proposals — fed by the
    /// `BuildAndBroadcastBeaconProposal` handler and the wire
    /// notification handler, read by the `GetBeaconProposalRequest`
    /// responder. No coordinator touches it.
    pub(crate) beacon_proposal_cache: Arc<BeaconProposalCache>,
    /// Process-level serve cache for ratify candidates — fed by the
    /// candidate broadcast and verify handlers, read by the
    /// `GetBeaconCandidateRequest` responder.
    pub(crate) beacon_candidate_cache: Arc<BeaconCandidateCache>,
    /// Process-level beacon store, threaded to the ratify-vote sign
    /// handler as its durable-register seam.
    pub(crate) beacon_storage: Arc<dyn BeaconStorage>,
    /// Behind its own `Arc` so the stores can be shared with the engine
    /// without the engine holding the handles that hold the engine.
    pub(crate) per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
}

/// The committed cells this node serves, across every shard it hosts.
///
/// A component's record lives in a cell under the component's own
/// prefix, so at most one hosted store can hold any given key and asking
/// each in turn answers without a topology lookup — and answers nothing
/// where the prefix belongs to a shard this node does not serve, which
/// is exactly the case the fetch covers.
pub(crate) struct HostedCells<S: ShardStorage> {
    per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
}

impl<S: ShardStorage> HostedCells<S> {
    pub(crate) const fn new(
        per_shard: Arc<ArcSwap<HashMap<ShardId, ShardDispatchHandles<S>>>>,
    ) -> Self {
        Self { per_shard }
    }
}

impl<S: ShardStorage> LocalCells for HostedCells<S> {
    fn committed_cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.per_shard.load().values().find_map(|handles| {
            let storage = &handles.storage;
            // The committed tip, never a pending one: the caches this
            // stands behind are grown by commits, and a pending block
            // two nodes disagree about would derive an envelope two
            // ways.
            storage
                .get_substate_at_height(key, storage.jmt_height())
                .flatten()
        })
    }
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
    pub(crate) tick_chain: Arc<TickChain<S>>,
    pub(crate) prepared_commits: Arc<Mutex<PreparedCommitMap>>,
}

impl<S: ShardStorage> Clone for ShardDispatchHandles<S> {
    fn clone(&self) -> Self {
        Self {
            storage: Arc::clone(&self.storage),
            pending_chain: Arc::clone(&self.pending_chain),
            tick_chain: Arc::clone(&self.tick_chain),
            prepared_commits: Arc::clone(&self.prepared_commits),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// Whose timer a [`TimerOp`] names, and so whom its fire reaches.
///
/// Every vnode arms its own pacemaker, proposal and beacon timers, and
/// vnodes co-hosted on one loop arm the same [`TimerId`]s against their own
/// deadlines. Keyed by its loop alone, one vnode's arm would replace
/// another's pending fire: the other vnode, woken before its own deadline,
/// finds nothing due and waits on a fire nobody set. A seat's timer is its
/// own, and its fire reaches it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerOwner {
    /// A hosted shard's loop itself: its fetch tick.
    Loop(ShardId),
    /// One vnode seated on a hosted shard's loop.
    Seat(ShardId, ValidatorId),
    /// One shard-less follower in the host's pool.
    Follower(ValidatorId),
}

/// A timer operation buffered by a loop driver for the runner to process.
///
/// The runner's timer driver keys handles by `(TimerOwner, TimerId)`, and
/// the firing path ([`timer_event`]) addresses the envelope to the owner.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`HostEvent`] the runner
/// pushes onto its event channel.
///
/// The envelope is addressed to the timer's owner: a loop's fetch tick to
/// its shard, a seat's timer to that vnode alone, a follower's to that
/// follower alone.
#[must_use]
pub fn timer_event(id: &TimerId, owner: TimerOwner) -> HostEvent {
    let event = match id {
        TimerId::ViewChange => ProtocolEvent::ViewChangeTimer,
        TimerId::Cleanup => ProtocolEvent::CleanupTimer,
        TimerId::SoloProposal => ProtocolEvent::SoloProposalTimer,
        TimerId::ProposalFetch => ProtocolEvent::ProposalFetchTimer,
        TimerId::FetchTick => {
            return match owner {
                TimerOwner::Loop(shard) | TimerOwner::Seat(shard, _) => {
                    HostEvent::shard(shard, ShardScopedInput::FetchTick)
                }
                TimerOwner::Follower(_) => HostEvent::beacon_fetch_tick(),
            };
        }
        TimerId::BeaconCommitteeStart => ProtocolEvent::BeaconCommitteeStartTimer,
        TimerId::BeaconRatifyTrigger => ProtocolEvent::BeaconRatifyTimer,
        TimerId::BeaconSpcView => ProtocolEvent::BeaconSpcViewTimer,
        TimerId::BeaconSpcInputDwell => ProtocolEvent::BeaconSpcInputDwellTimer,
    };
    match owner {
        TimerOwner::Loop(shard) => HostEvent::protocol(shard, event),
        TimerOwner::Seat(shard, validator) => HostEvent::shard(
            shard,
            ShardScopedInput::SeatTimer {
                validator,
                event: Box::new(event),
            },
        ),
        TimerOwner::Follower(validator) => HostEvent::Beacon(PoolScopedInput::FollowerTimer {
            validator,
            event: Box::new(event),
        }),
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
    pub(crate) emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted via [`Action::ReconfigureParticipation`]
    /// during this step. The runner reconfigures physical shard
    /// membership from these — they are requests to the process layer,
    /// not state-machine state.
    pub participation_changes: Vec<ParticipationChange>,
    /// Validators whose queued seat the loop admitted during this step.
    /// Each now drives its beacon from the shard, so any pool follower
    /// it carried retires.
    pub seated: Vec<ValidatorId>,
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
        self.seated.extend(other.seated);
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
    pub(crate) now: LocalTimestamp,
    /// This shard's `FetchTick` timer, armed while any fetch has work.
    pub(crate) fetch_tick: FetchTicker,
    /// Per-step scratch: timer set/cancel operations emitted during the
    /// step. Cleared at step entry; drained into the returned
    /// [`StepOutput`] for the runner to translate into timer-driver
    /// calls.
    pub(crate) pending_timer_ops: Vec<TimerOp>,
    /// Per-step scratch: `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into [`StepOutput`].
    pub(crate) emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Per-step scratch: placement deltas emitted via
    /// `Action::ReconfigureParticipation`. Drained into [`StepOutput`].
    pub(crate) pending_participation_changes: Vec<ParticipationChange>,
    /// Per-step scratch: count of actions this shard's vnodes produced
    /// during the step. Drained into [`StepOutput`] for the runner's
    /// metrics; reset at step entry.
    pub(crate) actions_generated: usize,
    /// Per-step scratch: validators whose seat was admitted during the
    /// step. Drained into [`StepOutput`].
    pub(crate) seated: Vec<ValidatorId>,
    /// Seats waiting for the store to come to rest at the last height
    /// the loop fanned out. See [`Self::admit_seats`].
    pub(crate) pending_seats: Vec<VnodeSeat>,
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Sender for this shard's own event channel — the destination for
    /// every callback this loop spawns (block-commit completions, fetch
    /// results, signature-verify outcomes) and every protocol event it pushes
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
        self.admit_seats();
        self.follow_slowest_seat();
        self.update_fetch_tick_timer();
    }

    /// Queue `validator`'s seat on this running loop, admitting it at
    /// once if the store is already at rest. A seat for a validator the
    /// loop already carries or queues is dropped. Returns the output of
    /// the admission under [`Self::run_step`]'s contract.
    pub fn seat_vnode(&mut self, seat: VnodeSeat) -> StepOutput {
        self.clear_scratch();
        let validator = seat.validator;
        if !self.carries(validator) && !self.pending_seats.iter().any(|s| s.validator == validator)
        {
            self.pending_seats.push(seat);
            self.admit_seats();
            self.follow_slowest_seat();
            self.update_fetch_tick_timer();
        }
        self.take_output()
    }

    /// Take `validator` off this loop, whether seated or still queued.
    /// Returns whether the loop carried it.
    ///
    /// # Panics
    ///
    /// Panics if `validator` is the loop's last seated vnode: the last
    /// seat leaves with its loop.
    pub fn remove_vnode(&mut self, validator: ValidatorId) -> bool {
        let queued = self.pending_seats.len();
        self.pending_seats.retain(|s| s.validator != validator);
        if self.pending_seats.len() != queued {
            return true;
        }
        let Some(index) = self.vnodes.iter().position(|v| v.validator_id == validator) else {
            return false;
        };
        assert!(
            self.vnodes.len() > 1,
            "the last seat on shard {:?} leaves with its loop",
            self.shard
        );
        self.vnodes.remove(index);
        self.io.consensus.seat_frontiers.forget(validator);
        self.share_host_seats();
        true
    }

    /// Tell every seated vnode which validators this loop seats, so each
    /// knows a quorum among them forms without crossing the network.
    pub(crate) fn share_host_seats(&mut self) {
        let seats: Vec<ValidatorId> = self.vnodes.iter().map(|v| v.validator_id).collect();
        for vnode in &mut self.vnodes {
            vnode.state.set_host_seats(&seats);
        }
    }

    /// Whether `validator` holds a seated vnode on this loop.
    fn carries(&self, validator: ValidatorId) -> bool {
        self.vnodes.iter().any(|v| v.validator_id == validator)
    }

    /// Admit every queued seat once the store is at rest at the last
    /// height the loop fanned out.
    ///
    /// Each vnode's shard coordinator commits on its own, and the loop
    /// fans every height's `BlockCommitted` out to all of them once. A
    /// joiner restored at exactly that height has missed no fan-out and
    /// receives every later one with its siblings, so it seats as a
    /// restart does. Restored anywhere below, it would never hear the
    /// heights between: their commits skip at the pipeline's flushed
    /// frontier. The store is read only while no flush can move it.
    fn admit_seats(&mut self) {
        if self.pending_seats.is_empty()
            || !self.io.block_commit.is_quiet()
            || self.io.storage.committed_height() != self.io.block_commit.broadcast_height()
        {
            return;
        }
        let recovered = self.io.storage.load_recovered_state(self.shard);
        let stores = self.io.caches.group_stores();
        let beacon_storage = Arc::clone(&self.process.beacon_storage);
        for seat in std::mem::take(&mut self.pending_seats) {
            let init = seat_vnode_into_group(
                SeatVnodeGroup {
                    config: seat.config,
                    beacon_storage: beacon_storage.as_ref(),
                    now: self.now,
                    shard: self.shard,
                    recovered: &recovered,
                    vnodes: vec![(seat.validator, seat.signer)],
                },
                &stores,
            )
            .pop()
            .expect("one seat in, one vnode out");
            self.io.consensus.seat_frontiers.forget(seat.validator);
            self.vnodes.push(init.into_vnode());
            self.share_host_seats();
            let vnode_idx = self.vnodes.len() - 1;
            let now = self.now;
            let actions = self
                .vnode_mut(vnode_idx)
                .state
                .handle(now, committed_state_restored(&recovered));
            self.drain_actions(vnode_idx, actions);
            self.seated.push(seat.validator);
        }
        // Before the next commit dates a version: the seat replays from
        // below where its siblings' execution has already released.
        self.hold_execution_baselines(recovered.committed_height);
    }

    #[allow(clippy::too_many_lines)] // single dispatch over ShardScopedInput variants
    fn dispatch_input(&mut self, input: ShardScopedInput) {
        match input {
            // ── Transaction validation pipeline ────────────────────────
            ShardScopedInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(tx);
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
            ShardScopedInput::ProposalReceived { proposal } => {
                self.handle_proposal_received(*proposal);
            }
            ShardScopedInput::ProposalFetched { proposal } => {
                self.handle_proposal_fetched(*proposal);
            }
            ShardScopedInput::Protocol(event) => match *event {
                ProtocolEvent::BlockPersisted { height, .. } => self.handle_block_persisted(height),
                other => self.handle_protocol_passthrough(other),
            },
            ShardScopedInput::SeatTimer { validator, event } => {
                self.dispatch_to_seat(validator, *event);
            }

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
            ShardScopedInput::CommitProofResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
            } => {
                self.handle_commit_proof_response_received(
                    source_shard,
                    from_height,
                    count,
                    headers,
                );
            }

            // ── Fetch protocol ─────────────────────────────────────────
            ShardScopedInput::FetchFailed(ids) => self.release_fetch(ids, Release::Failed),
            ShardScopedInput::FetchUnroutable(ids) => self.release_fetch(ids, Release::Unroutable),
            ShardScopedInput::FetchFulfilled(ids) => self.release_fetch(ids, Release::Admitted),
            ShardScopedInput::TransactionsFetched { batch } => {
                self.handle_fetched_txs_for_validation(batch);
            }
            ShardScopedInput::PackageArtifactsFetched { artifacts } => {
                self.handle_package_artifacts_fetched(artifacts);
            }
            ShardScopedInput::PackagesInstalled { packages } => {
                self.handle_packages_installed(&packages);
            }
            ShardScopedInput::RecordsWanted { wanted } => {
                self.defer_for_records(wanted);
            }
            ShardScopedInput::InstanceRecordsFetched { records } => {
                self.handle_instance_records_fetched(records);
            }

            // ── Certified header (gossip → signature verify → state machine) ──
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

            // ── Shard fork proof (self-authenticating gossip → verify) ──
            ShardScopedInput::ShardForkProofGossipReceived { proof } => {
                self.handle_shard_fork_proof_gossip_received(&proof);
            }

            // ── Shard double-vote pair (self-authenticating gossip → verify) ──
            ShardScopedInput::ShardVoteEquivocationGossipReceived { evidence } => {
                self.handle_shard_vote_equivocation_gossip_received(&evidence);
            }

            // ── Periodic fetch / sync tick ─────────────────────────────
            ShardScopedInput::FetchTick => self.handle_fetch_tick(),

            // ── QC-only commit prep callbacks ──────────────────────────
            ShardScopedInput::QcOnlyCommitPrepared {
                certified,
                source,
                witness,
                committee_anchor,
            } => {
                self.handle_qc_only_commit_prepared(certified, source, witness, committee_anchor);
            }
            ShardScopedInput::QcOnlyCommitDiverged(div) => {
                self.handle_qc_only_commit_diverged(&div);
            }
        }
    }

    /// Fan a shard-scoped protocol event out to every hosted vnode in
    /// this shard and dispatch each vnode's resulting actions.
    ///
    /// Every same-shard vnode independently applies the event at the
    /// shard's cached `now` and produces its own signed actions.
    pub(crate) fn dispatch_event(&mut self, event: ProtocolEvent) {
        // A block this node commits is one it must run, so the code its
        // members name is wanted here. Admission asked for whatever it
        // could not derive; this asks for what it derived and cannot yet
        // run — a node holding the metadata but not the compiled code,
        // and a node that synced past the admission that would have
        // asked, both reach a committed member the same way.
        //
        // A transaction that routes nowhere here names no code to ask
        // for: what it runs is behind the records it names, so those are
        // what this asks the shards holding them for, and the code
        // follows once they seat a derivation.
        if let ProtocolEvent::BlockCommitted { certified, .. } = &event {
            self.io
                .block_commit
                .note_broadcast(certified.block().height());
            let mut packages: Vec<Hash> = Vec::new();
            let mut records: Vec<Address> = Vec::new();
            for tx in certified.block().transactions().iter() {
                let tx = tx.as_unverified();
                if tx.is_routed() {
                    packages.extend(tx.packages().iter().copied());
                } else if let Some(wanted) = self.unrouted_wants(tx) {
                    records.extend(wanted.instances);
                    packages.extend(wanted.packages);
                }
            }
            if !records.is_empty() {
                self.fetch_instance_records(records);
            }
            if !packages.is_empty() {
                self.fetch_wanted_packages(packages);
            }
        }
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

    /// Feed `event` to the one seated vnode `validator`, if it is still on
    /// this loop.
    fn dispatch_to_seat(&mut self, validator: ValidatorId, event: ProtocolEvent) {
        let Some(vnode_idx) = self.vnodes.iter().position(|v| v.validator_id == validator) else {
            return;
        };
        let now = self.now;
        let actions = self.vnode_mut(vnode_idx).state.handle(now, event);
        self.drain_actions(vnode_idx, actions);
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
    /// the normal pipeline, pre-spawn: a split child's flip with the
    /// deterministic [`Block::split_child_genesis`], or a fresh store on
    /// a never-crossed genesis shard with its [`network_genesis_block`].
    /// The store already holds the genesis state at the genesis version, so
    /// the commit's genesis arm re-records that height.
    ///
    /// Returns the timer ops the genesis commit produced — chiefly the
    /// consensus pacemaker's [`TimerId::ViewChange`] arm. The caller spawns
    /// the loop after this returns, so it must hand these back as the loop's
    /// initial timer ops; otherwise the first `run_step` clears them and the
    /// shard never arms its pacemaker.
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
        // A genesis block has no parent to anchor its committee on; its own
        // anchor is the chain origin's, the committee anchor of block one.
        let committee_anchor = genesis.header().parent_qc().weighted_timestamp();
        self.step(ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::BlockCommitted {
                certified,
                committee_anchor,
            },
        )));

        self.seed_genesis_substate_frontier(genesis);
        std::mem::take(&mut self.pending_timer_ops)
    }

    /// Resume a runtime-seated shard's consensus from its recovered
    /// committed state — the non-genesis counterpart of
    /// [`Self::install_genesis`]. Feeds every vnode the committed-state
    /// restore, which arms the pacemaker and cleanup timers and latches a
    /// proposal attempt. A joiner seated onto a live shard would pick
    /// those up from the committee's gossip, but a committee seated onto
    /// a quiet chain — a halt recovery's fresh committee — hears nothing,
    /// so without this its vnodes never propose or time out.
    ///
    /// Returns the timer ops under the same caller contract as
    /// [`Self::install_genesis`].
    pub fn resume_committed(&mut self, recovered: &RecoveredState) -> Vec<TimerOp> {
        self.step(ShardScopedInput::Protocol(Box::new(
            committed_state_restored(recovered),
        )));
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
        self.seated.clear();
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
            seated: std::mem::take(&mut self.seated),
        }
    }

    /// Flush this shard's batch accumulators whose deadlines have
    /// expired at `now`.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        if self.io.mempool.validation_batch.is_expired(now) {
            self.flush_validation_batch();
        }
        self.sweep_deferred_records(now);
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
    pub(crate) fn flush_all_batches(&mut self) {
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

/// The committed-state restore for a recovered store — the one event both
/// resume paths feed ([`ShardLoop::resume_committed`] pre-spawn on the
/// pinned loop, [`NodeHost::resume_shard_committed`] through the host
/// step), so what "resuming from recovered state" means is written once.
///
/// [`NodeHost::resume_shard_committed`]: crate::host::NodeHost::resume_shard_committed
pub(crate) fn committed_state_restored(recovered: &RecoveredState) -> ProtocolEvent {
    ProtocolEvent::CommittedStateRestored {
        height: recovered.committed_height,
        hash: recovered.committed_hash,
        qc: recovered.latest_qc.clone(),
    }
}
