//! Unified I/O loop for action processing.
//!
//! `IoLoop` handles ALL actions from `NodeStateMachine`, dispatching them via
//! generic trait methods (Network, Dispatch, Storage) and concrete types for
//! timer ops and event delivery. Both production and simulation runners construct
//! an `IoLoop` with their concrete trait implementations.
//!
//! # Driving modes
//!
//! - **Production**: `IoLoop::run()` blocks on a crossbeam channel, processing
//!   events as they arrive from tokio bridge tasks.
//! - **Simulation**: The harness calls `IoLoop::step()` per event, then drains
//!   buffered outputs (timer ops, events, sync I/O).
//!
//! # Batching
//!
//! `IoLoop` batches execution-layer broadcasts and crypto verification for
//! efficiency. Batch deadlines are tracked as logical time (`Duration`) so both
//! production (wall clock) and simulation (logical clock) use the same paths.

mod actions;
mod event;
mod fetch_io;
mod lifecycle;
mod metrics;
mod network_handlers;
mod status;
mod step;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
pub use event::{
    EventPriority, FetchFailureKind, ProcessScopedInput, ShardEvent, ShardScopedInput,
};
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, RadixExecutor, TransactionValidation};
use hyperscale_network::Network;
use hyperscale_storage::{PendingChain, Storage};
use hyperscale_types::{LocalTimestamp, ShardGroupId, TopologySnapshot, TransactionStatus, TxHash};
pub use metrics::{MetricsSnapshot, ShardMetrics, VnodeMetrics, record_metrics};
use quick_cache::sync::Cache as QuickCache;
pub use status::{NodeStatusSnapshot, ShardStatus, VnodeStatus};

use crate::NodeStateMachine;
use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;
use crate::shard::ShardIo;
use crate::shard::block_commit::{BlockCommitCoordinator, PreparedCommitMap};
use crate::shard::caches::SharedCaches;
use crate::shard::fetch::binding::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::shard::fetch::{FetchHost, FetchInput};
use crate::shard::phase_times::TxPhaseTimesCache;
use crate::shard::sync::SyncHost;
use crate::vnode::{Vnode, VnodeInit};

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the `io_loop` when `Action::TopologyChanged` is processed.
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
/// the right entry from the emitting vnode's shard.
pub(super) struct DispatchHandles<S: Storage, N, E: Engine> {
    pub(super) executor: E,
    pub(super) network: Arc<N>,
    pub(super) per_shard: HashMap<ShardGroupId, ShardDispatchHandles<S>>,
}

/// Per-shard subset of [`DispatchHandles`]. One entry per hosted shard.
pub(super) struct ShardDispatchHandles<S: Storage> {
    pub(super) pending_chain: Arc<PendingChain<S>>,
    pub(super) prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by `IoLoop` for the runner to process.
///
/// `shard` is the hosted shard that owns the timer. Shard-scoped timers
/// (`ViewChange`, `Cleanup`) use it for both keying (so cross-shard
/// hosting doesn't collide `ViewChange` handles) and event routing
/// ([`timer_event`] produces a `ShardScopedInput::Protocol` for the right
/// shard). Process-scoped timers (`FetchTick`) push with a sentinel —
/// the `IoLoop` holds the canonical `FetchTick` op on its own buffer
/// and the firing path ignores `shard`.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Hosted shard that owns this timer.
        shard: ShardGroupId,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Hosted shard that owns this timer.
        shard: ShardGroupId,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`ShardEvent`] the runner
/// pushes onto its event channel.
///
/// Shard-scoped timers tag the envelope with `shard` so the resulting
/// `ShardScopedInput::Protocol` routes to the right hosted shard;
/// `FetchTick` is process-scoped.
#[must_use]
pub fn timer_event(id: &TimerId, shard: ShardGroupId) -> ShardEvent {
    match id {
        TimerId::ViewChange => ShardEvent::protocol(shard, ProtocolEvent::ViewChangeTimer),
        TimerId::Cleanup => ShardEvent::protocol(shard, ProtocolEvent::CleanupTimer),
        TimerId::FetchTick => ShardEvent::process(ProcessScopedInput::FetchTick),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Event push helpers
// ═══════════════════════════════════════════════════════════════════════

/// Push a shard-scoped input into the I/O loop's event channel.
///
/// Off-thread closures and `IoLoop` methods both use this to feed
/// results back to the next `step()`. The channel is unbounded; send
/// failure is silently ignored by design (the only failure mode is the
/// receiver having been dropped at shutdown, in which case there's
/// nothing to do).
pub(crate) fn push_shard_input(
    tx: &Sender<ShardEvent>,
    shard: ShardGroupId,
    input: ShardScopedInput,
) {
    let _ = tx.send(ShardEvent::shard(shard, input));
}

/// Push a [`ProtocolEvent`] (wrapped in
/// [`ShardScopedInput::Protocol`]) into the I/O loop's event channel.
/// The receiver fans the event across every hosted vnode in `shard`.
/// See [`push_shard_input`] for the drop-on-shutdown convention.
pub(crate) fn push_protocol_event(
    tx: &Sender<ShardEvent>,
    shard: ShardGroupId,
    event: ProtocolEvent,
) {
    let _ = tx.send(ShardEvent::protocol(shard, event));
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `IoLoop::step()`.
///
/// `IoLoop` now handles all sync/fetch I/O and block-commit dispatch
/// internally via the `Network` and `Dispatch` traits. The runner only
/// processes emitted transaction statuses and timer operations.
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
}

// ═══════════════════════════════════════════════════════════════════════
// ShardGroup — per-shard I/O state plus the vnodes that share it
// ═══════════════════════════════════════════════════════════════════════

/// One hosted shard: its [`ShardIo`] plus every [`Vnode`] that participates
/// in this shard's consensus.
///
/// Same-shard vnodes share the [`ShardIo`] (one storage, one fetch host,
/// one mempool body store, etc.); cross-shard vnodes live in different
/// `ShardGroup`s. A vnode's shard is implied by which group it lives in —
/// the `Vnode` itself carries no `shard` field.
pub struct ShardGroup<S: Storage> {
    /// Per-shard I/O state shared by every vnode in `vnodes`.
    pub io: ShardIo<S>,
    /// Vnodes participating in this shard's consensus. Driven in order
    /// during each `step()` iteration; same-shard vnodes see identical
    /// inbound events and produce per-validator votes.
    pub vnodes: Vec<Vnode>,
}

// ═══════════════════════════════════════════════════════════════════════
// IoLoop
// ═══════════════════════════════════════════════════════════════════════

/// Unified I/O loop that processes all actions from the state machine.
///
/// Generic over:
/// - `S`: Storage (umbrella bound — see [`Storage`])
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
/// - `E`: Engine (transaction execution — defaults to `RadixExecutor`)
pub struct IoLoop<S, N, D, E: Engine = RadixExecutor>
where
    S: Storage,
    D: Dispatch,
{
    /// Per-shard groups, each owning that shard's [`ShardIo`] plus the
    /// [`Vnode`]s participating in its consensus. One entry per shard
    /// this host carries.
    ///
    /// State machines are driven exclusively from the pinned thread via
    /// `shards[shard].vnodes[i].state.handle()`. All `ProtocolEvent`
    /// ingestion and `Action` emission happen here; off-thread closures
    /// never touch them.
    shards: HashMap<ShardGroupId, ShardGroup<S>>,

    /// Transaction executor. Cloned (cheaply) into the block-commit
    /// closure on each drain — `Engine` requires `Clone`, so this is
    /// held by value rather than behind an `Arc`.
    executor: E,

    /// Network sender plus the registry of inbound gossip / request
    /// handlers installed at `init` time. `Arc` so handler closures
    /// and dispatch jobs can broadcast / reply without re-entering
    /// the pinned thread.
    network: Arc<N>,

    /// Thread-pool scheduler for off-thread work (crypto verify,
    /// tx validation, block-commit persistence, fetch-serve). Each
    /// `dispatch.spawn` site routes results back via `event_sender`.
    dispatch: D,

    /// Channel back to the pinned-thread event loop.
    ///
    /// Off-thread work spawned via `dispatch.spawn(pool, ...)` returns
    /// results here as [`ShardEvent`] envelopes (a `NodeInput` plus its
    /// hosted-shard tag), which the next pinned-thread `step()`
    /// iteration drains. Two routing rules for the payload:
    ///
    /// - **State-machine consumers** (BFT / execution / mempool — anything
    ///   driven by `state.handle()`) ride
    ///   `ShardScopedInput::Protocol(ProtocolEvent::*)`. Examples: gossip BLS
    ///   verification emits `RemoteHeaderReceived`; block-commit drain
    ///   emits `BlockCommitted` / `BlockPersisted`.
    /// - **`IoLoop`-only consumers** (validation pipeline, sync
    ///   delivery, fetch retry — anything handled in `step()` directly
    ///   without entering the state machine) ride a dedicated top-level
    ///   `NodeInput` variant. Examples: `TransactionValidated`,
    ///   `SyncBlockValidated`, `*FetchFailed`.
    ///
    /// Failure handling is pattern-specific and intentional: drop on
    /// byzantine input (gossip), emit a typed failure variant when the
    /// `IoLoop` has cleanup to do (`TransactionValidationsFailed`,
    /// `SyncBlockValidationFailed`), abort on storage faults
    /// (block-commit). Sends go through [`push_shard_input`] /
    /// [`push_protocol_event`] so the "drop on shutdown" convention
    /// has one named home.
    event_sender: Sender<ShardEvent>,

    /// Lock-free topology snapshot shared with network handler closures
    /// and delegated dispatch jobs. The pinned thread is the sole writer
    /// (via `Action::TopologyChanged`); all other readers `.load()` for
    /// an atomic snapshot. The state machine owns its own copy — this
    /// field exists for off-thread consumers that can't reach into it.
    topology_snapshot: SharedTopologySnapshot,

    /// See [`DispatchHandles`]. Cloned once per delegated-action dispatch.
    dispatch_handles: Arc<DispatchHandles<S, N, E>>,

    /// Stateless transaction validator (signature + format + EC checks).
    /// `Arc` so it can be cloned into the `tx_validation` pool closure
    /// on each batch flush.
    tx_validator: Arc<TransactionValidation>,

    /// Last time a "transaction finalization exceeded 10s" warning was emitted.
    /// Rate-limited to avoid flooding logs during cross-shard latency spikes.
    last_slow_tx_warn: LocalTimestamp,

    /// Per-tx phase-time stamps for the slow-tx finalization log. Populated
    /// from `EmitTransactionStatus` and `RecordTxEcCreated` actions; entries
    /// are dropped on terminal status.
    tx_phase_times: TxPhaseTimesCache,

    /// Per-step scratch: timer set/cancel operations emitted during the
    /// step. Both shard-scoped timers (`ViewChange`, `Cleanup` — pushed
    /// from `Action::SetTimer` / `CancelTimer` arms) and process-scoped
    /// timers (`FetchTick` — pushed from the fetch tick refresh) land
    /// here. Cleared at the top of [`Self::step`]; drained into the
    /// returned [`StepOutput`] for the runner to translate into actual
    /// timer-driver calls.
    pending_timer_ops: Vec<TimerOp>,

    /// Per-step scratch: `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into [`StepOutput`] for
    /// the runner to forward to RPC subscribers.
    emitted_statuses: Vec<(TxHash, TransactionStatus)>,

    /// Per-step scratch: count of actions produced by every vnode's
    /// state machine during the step. Drained into [`StepOutput`] for
    /// the runner's metrics; reset at the top of [`Self::step`].
    actions_generated: usize,

    /// Size cap for new tx-gossip accumulators. Consulted lazily by
    /// `enqueue_tx_for_gossip` when it inserts a new per-destination-shard
    /// accumulator into a `ShardIo`'s `tx_gossip_batches`.
    tx_gossip_max: usize,

    /// Time window for new tx-gossip accumulators. Same role as
    /// `tx_gossip_max`.
    tx_gossip_window: Duration,

    /// Process-wide wall-clock cache. Pushed lazily into a vnode's state
    /// machine right before `state.handle()` so each handle observes the
    /// runner's most recent `set_time`. Replaces the previous pattern of
    /// V identical `now` values updated in a per-iteration loop.
    now: LocalTimestamp,
}

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Create a new `IoLoop` hosting one or more `Vnode`s, possibly
    /// across multiple shards.
    ///
    /// `storages` carries one storage handle per hosted shard. The set
    /// of hosted shards is derived from `vnodes` (each vnode's
    /// `local_shard()`); `storages` must cover all of them.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty, or if any hosted shard lacks a
    /// matching entry in `storages`.
    // `config: NodeConfig` is taken by value: every caller hands over a fresh
    // config and we destructure sub-configs via `.clone()`, so a `&NodeConfig`
    // would just force the body to clone each subfield.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
    pub fn new(
        vnodes: Vec<VnodeInit>,
        mut storages: HashMap<ShardGroupId, S>,
        executor: E,
        network: N,
        dispatch: D,
        event_sender: Sender<ShardEvent>,
        topology_snapshot: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        assert!(!vnodes.is_empty(), "IoLoop requires at least one Vnode");

        // Distinct shards this host carries, derived from the supplied
        // vnodes. Used to allocate one `ShardIo` per shard.
        let hosted_shards: HashSet<ShardGroupId> = vnodes
            .iter()
            .map(|v| v.state.topology().local_shard())
            .collect();

        let b = &config.batch;
        let network = Arc::new(network);

        // Build one `ShardGroup` per hosted shard, owning both the
        // shard's `ShardIo` and the vnodes participating in it. The
        // representative vnode for each shard supplies the initial-
        // persisted height and the inbound-serving caches — same-shard
        // vnodes admit identical transactions and provisions by
        // determinism, so any same-shard vnode's stores are consistent
        // (each shard's vnodes still hold their own copies inside their
        // state machines).
        let mut shards: HashMap<ShardGroupId, ShardGroup<S>> = HashMap::new();
        let mut per_shard_dispatch: HashMap<ShardGroupId, ShardDispatchHandles<S>> = HashMap::new();

        // Group incoming `VnodeInit`s by their declared local shard, so
        // we can construct each `ShardGroup` with its full `Vec<Vnode>`
        // in one pass.
        let mut by_shard: HashMap<ShardGroupId, Vec<VnodeInit>> = HashMap::new();
        for init in vnodes {
            let shard = init.state.topology().local_shard();
            by_shard.entry(shard).or_default().push(init);
        }

        for shard in &hosted_shards {
            let inits = by_shard
                .remove(shard)
                .expect("hosted shard derived from vnodes — at least one vnode exists for it");
            let rep = inits.first().expect("group non-empty by construction");
            let initial_persisted_height = rep.state.bft().committed_height();
            let caches = SharedCaches::new(
                Arc::clone(rep.state.provisions().store()),
                Arc::clone(rep.state.mempool().tx_store()),
                Arc::clone(rep.state.execution().exec_cert_store()),
                Arc::clone(rep.state.execution().finalized_wave_store()),
            );
            let storage = storages
                .remove(shard)
                .unwrap_or_else(|| panic!("IoLoop: missing storage for hosted shard {shard:?}"));
            let storage = Arc::new(storage);
            let pending_chain = Arc::new(PendingChain::new(Arc::clone(&storage)));
            let block_commit = BlockCommitCoordinator::new(*shard, initial_persisted_height);
            per_shard_dispatch.insert(
                *shard,
                ShardDispatchHandles {
                    pending_chain: Arc::clone(&pending_chain),
                    prepared_commits: block_commit.prepared_commits_handle(),
                },
            );
            let vnodes: Vec<Vnode> = inits
                .into_iter()
                .map(|init| Vnode {
                    validator_id: init.state.topology().local_validator_id(),
                    state: init.state,
                    signing_key: init.signing_key,
                })
                .collect();
            shards.insert(
                *shard,
                ShardGroup {
                    io: ShardIo {
                        storage,
                        pending_chain,
                        block_commit,
                        caches,
                        fetches: FetchHost::new(&config),
                        syncs: SyncHost::new(&config),
                        pending_validation: HashSet::new(),
                        locally_submitted: HashSet::new(),
                        validation_batch: BatchAccumulator::new(
                            b.tx_validation_max,
                            b.tx_validation_window,
                        ),
                        committed_header_batch: BatchAccumulator::new(
                            b.committed_header_max,
                            b.committed_header_window,
                        ),
                        tx_gossip_batches: std::collections::BTreeMap::new(),
                    },
                    vnodes,
                },
            );
        }

        let dispatch_handles = Arc::new(DispatchHandles {
            executor: executor.clone(),
            network: Arc::clone(&network),
            per_shard: per_shard_dispatch,
        });
        Self {
            shards,
            executor,
            network,
            dispatch,
            event_sender,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            last_slow_tx_warn: LocalTimestamp::ZERO,
            tx_phase_times: TxPhaseTimesCache::default(),
            pending_timer_ops: Vec::new(),
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            tx_gossip_max: b.tx_gossip_max,
            tx_gossip_window: b.tx_gossip_window,
            now: LocalTimestamp::ZERO,
        }
    }

    // ─── Time ────────────────────────────────────────────────────────────

    /// Set the cached process-wide wall-clock time.
    ///
    /// Must be called before `step()`. The value is pushed into a
    /// vnode's state machine just-in-time in [`Self::dispatch_event`] so
    /// each `state.handle()` observes the latest tick without paying
    /// for V identical writes per runner iteration.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Current cached wall-clock time.
    pub(super) const fn now(&self) -> LocalTimestamp {
        self.now
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Number of vnodes hosted in `shard`, or `0` if `shard` isn't hosted.
    #[must_use]
    pub fn vnodes_len(&self, shard: ShardGroupId) -> usize {
        self.shards.get(&shard).map_or(0, |g| g.vnodes.len())
    }

    /// Access the state machine of the vnode at index `vnode_idx` within
    /// `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    pub fn vnode_state(&self, shard: ShardGroupId, vnode_idx: usize) -> &NodeStateMachine {
        &self.shard_group(shard).vnodes[vnode_idx].state
    }

    /// Mutably access the state machine of the vnode at index `vnode_idx`
    /// within `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    pub fn vnode_state_mut(
        &mut self,
        shard: ShardGroupId,
        vnode_idx: usize,
    ) -> &mut NodeStateMachine {
        &mut self.shard_group_mut(shard).vnodes[vnode_idx].state
    }

    /// Hosted shards (one entry per `ShardGroup`). Used by call sites
    /// that fan out across every shard this host carries — batch flushes,
    /// fetch ticks, metrics aggregation.
    pub fn hosted_shards(&self) -> impl Iterator<Item = ShardGroupId> + '_ {
        self.shards.keys().copied()
    }

    /// Internal: per-shard group (io + vnodes). Most callers prefer the
    /// narrower `shard_io` / `vnode` helpers; reach for this when you
    /// need both halves in the same borrow.
    pub(super) fn shard_group(&self, shard: ShardGroupId) -> &ShardGroup<S> {
        self.shards
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this IoLoop"))
    }

    /// Internal: mutable per-shard group.
    pub(super) fn shard_group_mut(&mut self, shard: ShardGroupId) -> &mut ShardGroup<S> {
        self.shards
            .get_mut(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this IoLoop"))
    }

    /// Internal: immutable per-shard vnode by index.
    pub(super) fn vnode(&self, shard: ShardGroupId, vnode_idx: usize) -> &Vnode {
        &self.shard_group(shard).vnodes[vnode_idx]
    }

    /// Internal: mutable per-shard vnode by index.
    pub(super) fn vnode_mut(&mut self, shard: ShardGroupId, vnode_idx: usize) -> &mut Vnode {
        &mut self.shard_group_mut(shard).vnodes[vnode_idx]
    }

    /// Shared `ShardIo` for `shard`. The single per-shard accessor;
    /// fields like `storage`, `caches`, `fetches`, `syncs`, `block_commit`,
    /// `pending_chain` are read directly off the returned reference.
    pub fn shard_io(&self, shard: ShardGroupId) -> &ShardIo<S> {
        &self.shard_group(shard).io
    }

    /// Mutable `ShardIo` for `shard`. Use over multiple `_mut` calls
    /// when the borrow needs to span field-level reads and mutations
    /// (e.g. block-commit flush reading `&storage` while mutating
    /// `&mut block_commit`).
    pub(super) fn shard_io_mut(&mut self, shard: ShardGroupId) -> &mut ShardIo<S> {
        &mut self.shard_group_mut(shard).io
    }

    /// Access the network.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Look up the latest emitted status for a transaction across every
    /// hosted shard.
    ///
    /// Returns the most recent status notification for the given transaction
    /// hash, if any status has been emitted on any hosted shard. Unlike the
    /// per-step `StepOutput::emitted_statuses`, this cache persists across
    /// steps and survives mempool eviction.
    pub fn tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.shards
            .values()
            .find_map(|group| group.io.caches.tx_status.get(hash))
    }

    /// Per-shard transaction status caches.
    ///
    /// Each cache is an `Arc<QuickCache>` so external consumers (e.g. RPC
    /// handlers) can share lock-free reads across threads. RPC layers
    /// typically hold the full set so a single-hash lookup can fan out
    /// across every hosted shard without re-entering the pinned thread.
    pub fn tx_status_caches(
        &self,
    ) -> HashMap<ShardGroupId, Arc<QuickCache<TxHash, TransactionStatus>>> {
        self.shards
            .iter()
            .map(|(shard, group)| (*shard, Arc::clone(&group.io.caches.tx_status)))
            .collect()
    }

    // ─── Event Processing ───────────────────────────────────────────────

    /// Process a single event through the state machine and handle all resulting actions.
    ///
    /// Returns a [`StepOutput`] containing emitted transaction statuses and timer
    /// operations. Sync/fetch I/O is handled internally via the Network trait.
    ///
    /// # Caller protocol
    ///
    /// After each call to `step()`, the runner should:
    /// 1. Flush batches — either [`Self::flush_all_batches`] (simulation) or
    ///    [`Self::flush_expired_batches`] (production, with wall-clock time)
    /// 2. Process `timer_ops` from the returned [`StepOutput`]
    /// 3. Process `emitted_statuses` from the returned [`StepOutput`]
    /// 4. Drain any events produced through the event channel (simulation only —
    ///    production receives these via its crossbeam channel receivers)
    ///
    #[allow(clippy::too_many_lines)] // single dispatch over ShardEvent; one arm per variant
    pub fn step(&mut self, event: ShardEvent) -> StepOutput {
        self.pending_timer_ops.clear();
        self.emitted_statuses.clear();
        self.actions_generated = 0;

        match event {
            ShardEvent::Shard(shard, input) => self.step_shard_input(shard, input),
            ShardEvent::Process(input) => self.step_process_input(input),
        }

        self.drain_pending_output()
    }

    /// Dispatch a shard-scoped input. Companion to [`Self::step`]; one
    /// arm per [`ShardScopedInput`] variant.
    #[allow(clippy::too_many_lines)] // single dispatch over ShardScopedInput; one arm per variant
    fn step_shard_input(&mut self, shard: ShardGroupId, input: ShardScopedInput) {
        match input {
            // ── Transaction validation pipeline ────────────────────────
            ShardScopedInput::TransactionGossipReceived { tx } => {
                self.handle_gossip_received_tx_for_validation(shard, tx);
            }
            ShardScopedInput::TransactionValidated { tx } => {
                self.handle_transaction_validated(shard, tx);
            }
            ShardScopedInput::TransactionValidationsFailed { hashes } => {
                self.handle_transaction_validations_failed(shard, &hashes);
            }
            ShardScopedInput::Protocol(event) => match *event {
                ProtocolEvent::BlockPersisted { height } => {
                    self.handle_block_persisted(shard, height);
                }
                other => self.handle_protocol_passthrough(shard, other),
            },

            // ── Sync protocol ──────────────────────────────────────────
            ShardScopedInput::BlockSyncResponseReceived { height, block } => {
                self.handle_block_sync_response_received(shard, height, block);
            }
            ShardScopedInput::BlockSyncFetchFailed { height, kind } => {
                self.handle_block_sync_fetch_failed(shard, height, kind);
            }
            ShardScopedInput::SyncBlockValidated { height, certified } => {
                self.handle_sync_block_validated(shard, height, *certified);
            }
            ShardScopedInput::SyncBlockValidationFailed { height, reason } => {
                self.handle_sync_block_validation_failed(shard, height, reason);
            }
            ShardScopedInput::RemoteHeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
            } => {
                self.handle_remote_headers_response_received(
                    shard,
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
                self.handle_remote_headers_fetch_failed(
                    shard,
                    source_shard,
                    from_height,
                    count,
                    kind,
                );
            }

            // ── Fetch protocol ─────────────────────────────────────────
            ShardScopedInput::TransactionsFetchFailed { hashes } => {
                self.drive_fetch::<TransactionBinding>(shard, FetchInput::Failed { ids: hashes });
                self.update_fetch_tick_timer();
            }
            ShardScopedInput::ProvisionsFetchFailed {
                source_shard,
                block_height,
            } => {
                self.drive_fetch::<ProvisionBinding>(
                    shard,
                    FetchInput::Failed {
                        ids: vec![(source_shard, shard, block_height)],
                    },
                );
                self.update_fetch_tick_timer();
            }
            ShardScopedInput::ExecCertFetchFailed { hashes } => {
                self.drive_fetch::<ExecCertBinding>(shard, FetchInput::Failed { ids: hashes });
                self.update_fetch_tick_timer();
            }
            ShardScopedInput::LocalProvisionsFetchFailed { hashes } => {
                self.drive_fetch::<LocalProvisionBinding>(
                    shard,
                    FetchInput::Failed { ids: hashes },
                );
                self.update_fetch_tick_timer();
            }
            ShardScopedInput::FinalizedWavesFetchFailed { ids } => {
                self.drive_fetch::<FinalizedWaveBinding>(shard, FetchInput::Failed { ids });
                self.update_fetch_tick_timer();
            }

            // ── Committed header (gossip → BLS verify → state machine) ──
            ShardScopedInput::CommittedBlockGossipReceived {
                committed_header,
                sender,
                public_key,
                sender_signature,
            } => self.handle_committed_block_gossip_received(
                shard,
                committed_header,
                sender,
                public_key,
                sender_signature,
            ),
        }
    }

    /// Dispatch a process-scoped input. Companion to [`Self::step`];
    /// one arm per [`ProcessScopedInput`] variant.
    fn step_process_input(&mut self, input: ProcessScopedInput) {
        match input {
            ProcessScopedInput::SubmitTransaction { tx } => {
                self.handle_submit_transaction(&tx);
            }
            ProcessScopedInput::FetchTick => self.handle_fetch_tick(),
        }
    }

    /// Drain accumulated step outputs (statuses, timer ops, action
    /// count) without processing an event.
    ///
    /// Used after [`Self::drain_actions`] to collect outputs produced
    /// by directly-dispatched action vecs (genesis init, sync-output
    /// continuations).
    pub fn drain_pending_output(&mut self) -> StepOutput {
        StepOutput {
            emitted_statuses: std::mem::take(&mut self.emitted_statuses),
            actions_generated: std::mem::replace(&mut self.actions_generated, 0),
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
        }
    }

    /// Fan a shard-scoped protocol event out to every hosted vnode in
    /// `shard` and dispatch each vnode's resulting actions.
    ///
    /// Every same-shard vnode independently applies the event at the
    /// `IoLoop`'s cached `now` and produces its own signed actions.
    /// No-op when `shard` isn't hosted.
    pub(super) fn dispatch_event(&mut self, shard: ShardGroupId, event: ProtocolEvent) {
        let count = self.shards.get(&shard).map_or(0, |g| g.vnodes.len());
        if count == 0 {
            return;
        }
        let now = self.now;
        // Clone for every recipient except the last; move into the last
        // so we don't pay a final clone whose result is immediately
        // dropped.
        for vnode_idx in 0..count - 1 {
            let ev = event.clone();
            let actions = self.vnode_mut(shard, vnode_idx).state.handle(now, ev);
            self.drain_actions(shard, vnode_idx, actions);
        }
        let actions = self.vnode_mut(shard, count - 1).state.handle(now, event);
        self.drain_actions(shard, count - 1, actions);
    }

    /// Dispatch a `Vec<Action>` produced by a vnode's state machine.
    /// Bumps the step's action counter, processes each action with the
    /// emitting vnode's signing context, and flushes pending block
    /// commits at the tail (the flush is the load-bearing part — easy
    /// to forget when copy-pasting the loop inline).
    ///
    /// Called by [`Self::dispatch_event`] after `state.handle()`, by
    /// [`Self::initialize_shard_genesis`] for genesis init, and
    /// by the sync-output dispatch helpers.
    pub(super) fn drain_actions(
        &mut self,
        shard: ShardGroupId,
        vnode_idx: usize,
        actions: Vec<Action>,
    ) {
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(shard, vnode_idx, action);
        }
        self.flush_block_commits(shard);
    }

    /// Flush any batch accumulators whose deadlines have expired across
    /// every hosted shard.
    ///
    /// Call this with the current time before processing events. In production,
    /// the loop calls this with wall-clock time. In simulation, the harness
    /// calls it with logical time.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        let hosted: Vec<ShardGroupId> = self.hosted_shards().collect();
        for shard in hosted {
            let sio = self.shard_io(shard);
            if sio.validation_batch.is_expired(now) {
                self.flush_validation_batch(shard);
            }
            if self.shard_io(shard).committed_header_batch.is_expired(now) {
                self.flush_committed_header_verifications(shard);
            }
            let expired_dst_shards: Vec<ShardGroupId> = self
                .shard_io(shard)
                .tx_gossip_batches
                .iter()
                .filter_map(|(dst, batch)| batch.is_expired(now).then_some(*dst))
                .collect();
            for dst in expired_dst_shards {
                self.flush_tx_gossip_batch(shard, dst);
            }
        }
    }

    /// Get the nearest batch deadline across every hosted shard, if any.
    ///
    /// Used by the production `run()` loop for `recv_timeout()` and by the
    /// simulation harness to know when to schedule a flush.
    pub fn nearest_batch_deadline(&self) -> Option<LocalTimestamp> {
        self.shards
            .values()
            .flat_map(|g| {
                let tx_gossip_min =
                    g.io.tx_gossip_batches
                        .values()
                        .filter_map(BatchAccumulator::deadline)
                        .min();
                [
                    g.io.validation_batch.deadline(),
                    g.io.committed_header_batch.deadline(),
                    tx_gossip_min,
                ]
            })
            .flatten()
            .min()
    }

    /// Flush ALL pending batches across every hosted shard immediately,
    /// regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        let hosted: Vec<ShardGroupId> = self.hosted_shards().collect();
        for shard in &hosted {
            self.flush_block_commits(*shard);
            self.flush_validation_batch(*shard);
            self.flush_committed_header_verifications(*shard);
            let dst_shards: Vec<ShardGroupId> = self
                .shard_io(*shard)
                .tx_gossip_batches
                .keys()
                .copied()
                .collect();
            for dst in dst_shards {
                self.flush_tx_gossip_batch(*shard, dst);
            }
        }
    }
}
