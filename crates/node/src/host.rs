//! Top-level node composition: [`NodeHost`].
//!
//! `NodeHost` bundles `Arc<ProcessIo>` (process-scoped resources) plus
//! one [`ShardLoop`] per hosted shard. It owns the event-routing seam:
//! [`NodeHost::step`] dispatches `HostEvent::Shard` to the targeted
//! `ShardLoop::step` and `HostEvent::Process` to cross-shard handlers
//! (transaction submission fan-out, fetch tick) that need access to
//! every hosted shard.
//!
//! Two runners drive a `NodeHost`, each built via [`NodeHost::new`].
//! Production decomposes it with [`NodeHost::into_parts`] and runs each
//! [`ShardLoop`] (and the host's pool) on its own pinned thread via
//! [`ShardLoop::run_step`]; simulation keeps the whole host and drives it
//! single-threaded over a global event queue through [`NodeHost::step`],
//! which fans a `HostEvent::Process` out across every hosted shard.
//! Production also calls `step` once at startup for the genesis commit,
//! before it decomposes the host. Both paths share `ShardLoop::step` for
//! dispatch and the same `clear_scratch` / `take_output` scratch lifecycle,
//! so the two drivers cannot drift.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{ProcessExecutionCache, RadixExecutor, TransactionValidation};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, PendingChain, ShardStorage};
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, LocalTimestamp, NetworkDefinition, ShardId,
    TransactionStatus, TxHash, ValidatorId, Verified,
};

use crate::NodeStateMachine;
use crate::beacon::{
    BeaconBlockSync, BeaconFetchState, BeaconProposalCache, beacon_block_sync_config,
};
use crate::config::NodeConfig;
use crate::pool_loop::PoolLoop;
use crate::process::{ProcessIo, register_shard_request_handlers};
use crate::shard::caches::SharedCaches;
use crate::shard::commit::{BlockCommitCoordinator, BoundaryMemo};
use crate::shard::consensus::{BlockSyncInput, ConsensusState};
use crate::shard::cross_shard::CrossShardState;
use crate::shard::mempool::MempoolState;
use crate::shard::phase_times::TxPhaseTimesCache;
use crate::shard::{
    DispatchHandles, HostEvent, ProcessScopedInput, ShardDispatchHandles, ShardIo, ShardLoop,
    SharedTopologySnapshot, StepOutput,
};
use crate::vnode::{Vnode, VnodeInit};

/// Output of [`NodeHost::into_parts`].
///
/// The shared process-scoped resources, the per-shard drivers keyed by
/// hosted shard id, and the host's shard-less beacon-follower pool (present
/// only when the host carries followers).
pub type NodeHostParts<S, N, D> = (
    Arc<ProcessIo<S, N, D>>,
    BTreeMap<ShardId, ShardLoop<S, N, D>>,
    Option<PoolLoop<S, N, D>>,
);

/// The deterministic product of one shard's genesis ceremony, returned by
/// [`NodeHost::build_shard_genesis`].
///
/// The caller commits `certified` itself: production steps `BlockCommitted`
/// inline, while simulation schedules it only after wiring the network, so
/// the shared ceremony stops short of the commit.
pub struct ShardGenesis {
    /// The genesis block built and persisted into the shard's vnodes.
    pub block: Block,
    /// The certified genesis block to feed `ProtocolEvent::BlockCommitted`.
    pub certified: Arc<Verified<CertifiedBlock>>,
    /// Output drained from the genesis install (timer sets, statuses).
    pub setup_output: StepOutput,
}

/// Top-level node composition: process-scoped resources plus one
/// [`ShardLoop`] per hosted shard.
///
/// Generic over:
/// - `S`: `ShardStorage` (umbrella bound — see [`ShardStorage`])
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
pub struct NodeHost<S, N, D>
where
    S: ShardStorage,
    D: Dispatch,
{
    /// One [`ShardLoop`] per hosted shard. State machines are driven
    /// exclusively through these — all `ProtocolEvent` ingestion and
    /// `Action` emission happen via per-shard `step()` dispatch.
    /// Ordered so that whole-host sweeps (step, drains, batch flushes)
    /// visit shards deterministically regardless of join order.
    pub(crate) shards: BTreeMap<ShardId, ShardLoop<S, N, D>>,

    /// The host's shard-less, beacon-following vnodes, present only when the
    /// host carries any. Driven for beacon events routed via
    /// [`HostEvent::Beacon`](crate::event::HostEvent::Beacon).
    pub(crate) pool: Option<PoolLoop<S, N, D>>,

    /// Process-scoped shared resources: network adapter, dispatch pool,
    /// tx validator, topology snapshot, dispatch handles, event sender.
    /// Cloned `Arc::clone(&self.process)` is handed to every hosted
    /// `ShardLoop` so off-thread closures can capture it cheaply.
    pub(crate) process: Arc<ProcessIo<S, N, D>>,

    /// Process-wide wall-clock cache. Pushed into every hosted shard's
    /// own `now` via [`Self::set_time`] so off-thread handlers can read
    /// a consistent stamp without coordinating with this top-level cache.
    now: LocalTimestamp,

    /// Node configuration retained so shards added at runtime build
    /// their `ShardIo` and batch accumulators with the same knobs the
    /// startup shards got.
    config: NodeConfig,
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Create a new `NodeHost` hosting one or more `Vnode`s, possibly
    /// across multiple shards.
    ///
    /// `storages` carries one storage handle per hosted shard. The set
    /// of hosted shards is derived from `vnodes` (each vnode's
    /// `local_shard()`); `storages` must cover all of them.
    ///
    /// `beacon_event_sender` is the channel a shard-less host's beacon
    /// follower routes committed-block gossip to; it carries no traffic on
    /// a host that runs no follower pool.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty, or if any hosted shard lacks a
    /// matching entry in `storages`.
    // `config: NodeConfig` is taken by value: every caller hands over a fresh
    // config and we destructure sub-configs via `.clone()`, so a `&NodeConfig`
    // would just force the body to clone each subfield.
    #[allow(
        clippy::too_many_arguments,
        clippy::needless_pass_by_value,
        clippy::too_many_lines
    )] // two-pass construction: build shard io, then process, then assemble
    pub fn new(
        vnodes: Vec<VnodeInit>,
        mut storages: HashMap<ShardId, S>,
        beacon_storage: Arc<dyn BeaconStorage>,
        beacon_network: NetworkDefinition,
        executor: RadixExecutor,
        network: N,
        dispatch: D,
        shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>>,
        beacon_event_sender: Sender<HostEvent>,
        topology_snapshot: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        assert!(!vnodes.is_empty(), "NodeHost requires at least one Vnode");

        let network = Arc::new(network);

        // First pass: build ShardIo + Vec<Vnode> for each shard, plus the
        // per-shard dispatch handles map. ShardLoop construction is deferred
        // to a second pass because each ShardLoop needs an Arc<ProcessIo>
        // that can only be built after dispatch_handles is finalized.
        let mut shard_builds: HashMap<ShardId, (ShardIo<S>, Vec<Vnode>)> = HashMap::new();
        let mut per_shard_dispatch: HashMap<ShardId, ShardDispatchHandles<S>> = HashMap::new();

        // Split the vnodes into per-shard groups (seated) and the
        // beacon-follower pool (`shard: None`). The hosted-shard set — one
        // `ShardIo` apiece — is exactly the seated groups' keys.
        let mut by_shard: HashMap<ShardId, Vec<VnodeInit>> = HashMap::new();
        let mut pool_inits: Vec<VnodeInit> = Vec::new();
        for init in vnodes {
            match init.state.seated_shard() {
                Some(shard) => by_shard.entry(shard).or_default().push(init),
                None => pool_inits.push(init),
            }
        }
        let hosted_shards: HashSet<ShardId> = by_shard.keys().copied().collect();

        for shard in &hosted_shards {
            let inits = by_shard
                .remove(shard)
                .expect("hosted shard derived from vnodes — at least one vnode exists for it");
            let storage = storages
                .remove(shard)
                .unwrap_or_else(|| panic!("NodeHost: missing storage for hosted shard {shard:?}"));
            let (io, handles) = build_shard_io(*shard, &inits, storage, &config);
            per_shard_dispatch.insert(*shard, handles);
            let vnodes: Vec<Vnode> = inits.into_iter().map(VnodeInit::into_vnode).collect();
            shard_builds.insert(*shard, (io, vnodes));
        }

        let execution_cache = Arc::new(ProcessExecutionCache::new(hosted_shards.clone()));
        let dispatch_handles = Arc::new(DispatchHandles {
            executor,
            network: Arc::clone(&network),
            execution_cache,
            beacon_proposal_cache: Arc::new(BeaconProposalCache::new(beacon_network)),
            beacon_storage: Arc::clone(&beacon_storage),
            per_shard: ArcSwap::from_pointee(per_shard_dispatch),
        });
        assert_eq!(
            shard_event_senders.len(),
            hosted_shards.len(),
            "shard_event_senders must have one entry per hosted shard"
        );
        for shard in &hosted_shards {
            assert!(
                shard_event_senders.contains_key(shard),
                "shard_event_senders missing entry for hosted shard {shard:?}"
            );
        }
        let process = Arc::new(ProcessIo::new(
            network,
            dispatch,
            shard_event_senders,
            beacon_event_sender,
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            beacon_storage,
        ));

        // Second pass: assemble ShardLoops with cloned Arc<ProcessIo>.
        let shards: BTreeMap<ShardId, ShardLoop<S, N, D>> = shard_builds
            .into_iter()
            .map(|(shard, (io, vnodes))| {
                let shard_loop = ShardLoop {
                    shard,
                    event_tx: process.shard_sender(shard),
                    process: Arc::clone(&process),
                    io,
                    beacon_block: BeaconBlockSync::new(beacon_block_sync_config()),
                    vnodes,
                    now: LocalTimestamp::ZERO,
                    pending_timer_ops: Vec::new(),
                    emitted_statuses: Vec::new(),
                    pending_participation_changes: Vec::new(),
                    actions_generated: 0,
                };
                (shard, shard_loop)
            })
            .collect();

        // The beacon-follower pool, present only when the host carries
        // shard-less vnodes.
        let pool = (!pool_inits.is_empty()).then(|| {
            PoolLoop::new(
                Arc::clone(&process),
                pool_inits.into_iter().map(VnodeInit::into_vnode).collect(),
            )
        });
        // Route committed beacon blocks to the pool only while one exists to
        // fold them; the sim drives the pool through this channel directly,
        // and the production runner re-asserts the flag when it (re)spawns
        // the pool thread after `into_parts`.
        process.set_beacon_route_active(pool.is_some());

        Self {
            shards,
            pool,
            process,
            now: LocalTimestamp::ZERO,
            config,
        }
    }

    /// Begin hosting `shard` at runtime: install its event sender,
    /// build its `ShardIo` + dispatch handles, include it in the
    /// network's hosted set, seat its `ShardLoop`, and register its
    /// request handlers. The caller supplies the shard's vnodes (state
    /// machines constructed for that shard), its opened storage, and
    /// the event sender whose receiver the runner drains.
    ///
    /// Events for the shard may queue on the channel from the moment
    /// the sender is installed; they're processed once the loop steps.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty, targets mixed shards, or names a
    /// shard this host already serves.
    pub fn add_shard(&mut self, vnodes: Vec<VnodeInit>, storage: S, sender: Sender<HostEvent>) {
        let shard = vnodes
            .first()
            .expect("add_shard requires at least one vnode")
            .state
            .shard_id();
        assert!(
            !self.shards.contains_key(&shard),
            "shard {shard:?} already hosted"
        );
        let mut shard_loop = attach_shard(&self.process, &self.config, vnodes, storage, sender);
        shard_loop.set_time(self.now);
        self.shards.insert(shard, shard_loop);
    }

    /// Stop hosting `shard`: exclude it from the network's hosted set,
    /// drop its request handlers, event sender, and dispatch handles,
    /// and return its `ShardLoop` for the caller to drain or drop.
    /// Inbound traffic for the shard is rejected from the moment the
    /// maps swap; events already queued die with the channel receiver.
    ///
    /// Returns `None` if the shard isn't hosted.
    pub fn remove_shard(&mut self, shard: ShardId) -> Option<ShardLoop<S, N, D>> {
        let shard_loop = self.shards.remove(&shard)?;
        detach_shard(&self.process, shard);
        Some(shard_loop)
    }

    /// Consume the host and yield its constituent parts: the shared
    /// process-scoped resources, one [`ShardLoop`] per hosted shard, and the
    /// shard-less beacon-follower pool (if any).
    ///
    /// The production runner uses this to move each `ShardLoop` (and the
    /// `PoolLoop`) onto its own pinned thread while keeping the
    /// `Arc<ProcessIo>` shared across them. Simulation never calls this — sim
    /// drives the whole host single-threaded via [`Self::step`].
    #[must_use]
    pub fn into_parts(self) -> NodeHostParts<S, N, D> {
        (self.process, self.shards, self.pool)
    }

    /// Borrow the shared process-scoped resources. Callers `Arc::clone`
    /// the returned handle for RPC submission closures and other
    /// off-thread consumers that need lock-free topology / sender access
    /// without consuming the host.
    #[must_use]
    pub const fn process(&self) -> &Arc<ProcessIo<S, N, D>> {
        &self.process
    }

    // ─── Time ────────────────────────────────────────────────────────────

    /// Set the cached process-wide wall-clock time, propagated into every
    /// hosted shard so `state.handle(now, _)` calls observe the latest
    /// tick.
    pub fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        for sl in self.shards.values_mut() {
            sl.set_time(now);
        }
        if let Some(pool) = &mut self.pool {
            pool.set_time(now);
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Number of vnodes hosted in `shard`, or `0` if `shard` isn't hosted.
    #[must_use]
    pub fn vnodes_len(&self, shard: ShardId) -> usize {
        self.shards.get(&shard).map_or(0, |g| g.vnodes.len())
    }

    /// Number of shard-less, beacon-following vnodes in the host's pool.
    #[must_use]
    pub fn pooled_len(&self) -> usize {
        self.pool.as_ref().map_or(0, PoolLoop::len)
    }

    /// Whether the host's pool is running a beacon-block catch-up sync. The
    /// simulation harness polls this to keep the pool's retry tick armed;
    /// production's pool thread reads it directly off its `PoolLoop`.
    #[must_use]
    pub fn pool_is_syncing(&self) -> bool {
        self.pool.as_ref().is_some_and(PoolLoop::is_beacon_syncing)
    }

    /// Remove `validator`'s shard-less follower vnode from the host's pool,
    /// once it has been seated onto a shard (the seat rebuilt its
    /// `BeaconCoordinator` from the host's warm beacon storage). No-op if
    /// the host runs no pool or holds no such follower. Leaves an empty pool
    /// in place — its beacon channel simply carries no further work.
    pub fn drop_pooled_vnode(&mut self, validator: ValidatorId) {
        if let Some(pool) = &mut self.pool {
            pool.vnodes.retain(|v| v.validator_id != validator);
        }
        // An emptied pool no longer needs the beacon channel; stop routing so
        // the host doesn't fold blocks into a pool with no followers.
        self.process.set_beacon_route_active(self.has_active_pool());
    }

    /// Add a shard-less beacon follower to the host's pool, creating the
    /// pool if the host had none. Used when a validator drains off its last
    /// shard and keeps following the beacon (see
    /// [`seat_follower`](crate::seat_follower)).
    pub fn add_pooled_vnode(&mut self, init: VnodeInit) {
        let vnode = init.into_vnode();
        match &mut self.pool {
            Some(pool) => pool.vnodes.push(vnode),
            None => self.pool = Some(PoolLoop::new(Arc::clone(&self.process), vec![vnode])),
        }
        // The host now drives a pool; route committed beacon blocks to it.
        self.process.set_beacon_route_active(true);
    }

    /// Whether the host holds a pool with at least one follower — the
    /// condition under which committed beacon blocks should route to it.
    fn has_active_pool(&self) -> bool {
        self.pool.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// Whether this host runs a vnode for `validator` on any hosted shard.
    /// Drives the drain-to-pool decision: a departing validator still on
    /// another shard keeps that shard's coordinator and needs no follower.
    #[must_use]
    pub fn hosts_validator(&self, validator: ValidatorId) -> bool {
        self.shards
            .values()
            .any(|sl| sl.vnodes.iter().any(|v| v.validator_id == validator))
    }

    /// Access the state machine of the vnode at index `vnode_idx` within
    /// `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    #[must_use]
    pub fn vnode_state(&self, shard: ShardId, vnode_idx: usize) -> &NodeStateMachine {
        &self.shard_loop(shard).vnodes[vnode_idx].state
    }

    /// Mutably access the state machine of the vnode at index `vnode_idx`
    /// within `shard`'s group.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted or `vnode_idx` is out of range.
    pub(crate) fn vnode_state_mut(
        &mut self,
        shard: ShardId,
        vnode_idx: usize,
    ) -> &mut NodeStateMachine {
        &mut self.shard_loop_mut(shard).vnodes[vnode_idx].state
    }

    /// Hosted shards (one entry per `ShardLoop`). Used by call sites
    /// that fan out across every shard this host carries — batch flushes,
    /// fetch ticks, metrics aggregation.
    pub fn hosted_shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.shards.keys().copied()
    }

    /// Internal: per-shard loop (process handle + io + vnodes + scratch).
    pub(crate) fn shard_loop(&self, shard: ShardId) -> &ShardLoop<S, N, D> {
        self.shards
            .get(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this NodeHost"))
    }

    /// Internal: mutable per-shard loop.
    pub(crate) fn shard_loop_mut(&mut self, shard: ShardId) -> &mut ShardLoop<S, N, D> {
        self.shards
            .get_mut(&shard)
            .unwrap_or_else(|| panic!("shard {shard:?} not hosted by this NodeHost"))
    }

    /// Internal: immutable per-shard vnode by index.
    pub(crate) fn vnode(&self, shard: ShardId, vnode_idx: usize) -> &Vnode {
        &self.shard_loop(shard).vnodes[vnode_idx]
    }

    /// Shared `ShardIo` for `shard`. The single per-shard accessor;
    /// fields like `storage`, `caches`, `fetches`, `syncs`, `block_commit`,
    /// `pending_chain` are read directly off the returned reference.
    #[must_use]
    pub fn shard_io(&self, shard: ShardId) -> &ShardIo<S> {
        &self.shard_loop(shard).io
    }

    /// Access the network.
    #[must_use]
    pub fn network(&self) -> &N {
        &self.process.network
    }

    /// Process-shared beacon storage handle.
    #[must_use]
    pub fn beacon_storage(&self) -> &Arc<dyn BeaconStorage> {
        &self.process.beacon_storage
    }

    /// Look up the latest merged status for a transaction.
    ///
    /// Reads the process-wide [`TxStatusCache`], which every hosted
    /// shard writes into. Unlike the per-step
    /// `StepOutput::emitted_statuses`, this cache persists across steps
    /// and survives mempool eviction.
    ///
    /// [`TxStatusCache`]: crate::process::TxStatusCache
    #[must_use]
    pub fn tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.process.tx_status.get(hash).map(|(status, _)| status)
    }

    // ─── Event Processing ───────────────────────────────────────────────

    /// Process a single event through the state machine and handle all
    /// resulting actions.
    ///
    /// Returns a [`StepOutput`] containing emitted transaction statuses
    /// and timer operations. Sync/fetch I/O is handled internally via
    /// the `Network` trait.
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
    pub fn step(&mut self, event: HostEvent) -> StepOutput {
        for sl in self.shards.values_mut() {
            sl.clear_scratch();
        }
        if let Some(pool) = &mut self.pool {
            pool.clear_scratch();
        }

        match event {
            HostEvent::Shard(shard, input) => {
                // Silently drop events whose shard isn't hosted by this host.
                if let Some(sl) = self.shards.get_mut(&shard) {
                    sl.step(input);
                }
            }
            HostEvent::Process(input) => self.step_process_input(input),
            HostEvent::Beacon(input) => {
                // Drop beacon events on a host with no pooled vnodes.
                if let Some(pool) = &mut self.pool {
                    pool.dispatch_event(input);
                }
            }
        }

        self.drain_pending_output()
    }

    /// Dispatch a process-scoped input. Companion to [`Self::step`];
    /// one arm per [`ProcessScopedInput`] variant.
    fn step_process_input(&mut self, input: ProcessScopedInput) {
        match input {
            ProcessScopedInput::SubmitTransaction { tx } => {
                self.handle_submit_transaction(&tx);
            }
        }
    }

    /// Drain accumulated step outputs (statuses, timer ops, action
    /// count) from every hosted shard's scratch.
    ///
    /// Used by [`Self::step`] at end of step and by lifecycle code that
    /// produces actions outside a normal step (genesis init, sync-output
    /// continuations).
    pub fn drain_pending_output(&mut self) -> StepOutput {
        let mut out = StepOutput::default();
        for sl in self.shards.values_mut() {
            out.merge(sl.take_output());
        }
        if let Some(pool) = &mut self.pool {
            out.merge(pool.take_output());
        }
        out
    }

    /// Flush any batch accumulators whose deadlines have expired across
    /// every hosted shard.
    ///
    /// Call this with the current time before processing events. In production,
    /// the loop calls this with wall-clock time. In simulation, the harness
    /// calls it with logical time.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        for sl in self.shards.values_mut() {
            sl.flush_expired_batches(now);
        }
    }

    /// Get the nearest batch deadline across every hosted shard, if any.
    ///
    /// Used by the production `run()` loop for `recv_timeout()` and by the
    /// simulation harness to know when to schedule a flush.
    pub fn nearest_batch_deadline(&self) -> Option<LocalTimestamp> {
        self.shards
            .values()
            .filter_map(ShardLoop::nearest_batch_deadline)
            .min()
    }

    /// Flush ALL pending batches across every hosted shard immediately,
    /// regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        for sl in self.shards.values_mut() {
            sl.flush_all_batches();
        }
    }
}

/// Wire a runtime-joined shard into the process-scoped maps and build
/// its `ShardLoop`.
///
/// Installs the event sender, builds the `ShardIo` + dispatch handles,
/// grows the execution cache and network hosted sets, seats each
/// vnode's beacon-signing claim, and registers the shard's request
/// handlers. Returns the loop for the caller to drive —
/// `NodeHost::add_shard` seats it in the host's map (the sim step
/// path); the production supervisor moves it onto a pinned thread.
///
/// # Panics
///
/// Panics if `vnodes` is empty or targets mixed shards.
pub fn attach_shard<S, N, D>(
    process: &Arc<ProcessIo<S, N, D>>,
    config: &NodeConfig,
    vnodes: Vec<VnodeInit>,
    storage: S,
    sender: Sender<HostEvent>,
) -> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    let shard = vnodes
        .first()
        .expect("attach_shard requires at least one vnode")
        .state
        .shard_id();
    assert!(
        vnodes.iter().all(|v| v.state.shard_id() == shard),
        "attach_shard vnodes must all target one shard"
    );

    process.insert_shard_sender(shard, sender.clone());
    let (io, handles) = build_shard_io(shard, &vnodes, storage, config);
    process.dispatch_handles.insert_shard(shard, handles);
    process
        .dispatch_handles
        .execution_cache
        .add_hosted_shard(shard);
    process.network.subscribe_shard(shard);

    let shard_loop = ShardLoop {
        shard,
        event_tx: sender,
        process: Arc::clone(process),
        io,
        beacon_block: BeaconBlockSync::new(beacon_block_sync_config()),
        vnodes: vnodes.into_iter().map(VnodeInit::into_vnode).collect(),
        now: LocalTimestamp::ZERO,
        pending_timer_ops: Vec::new(),
        emitted_statuses: Vec::new(),
        pending_participation_changes: Vec::new(),
        actions_generated: 0,
    };
    register_shard_request_handlers(process, &shard_loop.io, shard);
    shard_loop
}

/// Reverse of [`attach_shard`]: unwire a shard from the process maps.
///
/// Call once the shard's loop has stopped stepping (the sim path drops
/// the loop; the production supervisor joins the thread first). Inbound
/// traffic for the shard is rejected from the moment the maps swap. The
/// dead vnodes' beacon signing needs no hand-off — the view-claim fence
/// lets each validator's surviving vnode claim the next SPC view on its
/// own dispatch.
pub fn detach_shard<S, N, D>(process: &Arc<ProcessIo<S, N, D>>, shard: ShardId)
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    process.network.unsubscribe_shard(shard);
    process.remove_shard_sender(shard);
    process.dispatch_handles.remove_shard(shard);
    process
        .dispatch_handles
        .execution_cache
        .remove_hosted_shard(shard);
}

/// Build one shard's `ShardIo` plus its dispatch-handle entry from the
/// shard's vnode group and opened storage. Shared by host construction
/// and runtime shard addition so both paths produce identically wired
/// shards.
fn build_shard_io<S: ShardStorage>(
    shard: ShardId,
    inits: &[VnodeInit],
    storage: S,
    config: &NodeConfig,
) -> (ShardIo<S>, ShardDispatchHandles<S>) {
    let rep = inits.first().expect("shard group has at least one vnode");
    let initial_persisted_height = rep.state.shard_coordinator().committed_height();
    let caches = SharedCaches::new(
        Arc::clone(rep.state.provisions_coordinator().store()),
        Arc::clone(rep.state.provisions_coordinator().verified_headers()),
        Arc::clone(rep.state.mempool_coordinator().tx_store()),
        Arc::clone(rep.state.execution_coordinator().exec_cert_store()),
        Arc::clone(rep.state.execution_coordinator().finalized_wave_store()),
    );
    let storage = Arc::new(storage);
    let pending_chain = Arc::new(PendingChain::new(Arc::clone(&storage)));
    let mut block_commit = BlockCommitCoordinator::new(shard, initial_persisted_height);
    {
        // Seed the boundary memo from the committed tip so the
        // first post-restart commit can adjudicate its parent.
        let seed = storage
            .get_certified_header(initial_persisted_height)
            .map(|certified| {
                let header = certified.header();
                BoundaryMemo {
                    hash: header.hash(),
                    height: header.height(),
                    parent_qc_wt: header.parent_qc().weighted_timestamp(),
                }
            });
        // The chain's epoch duration, read from the projected
        // schedule (sourced from the folded `BeaconState`'s chain
        // config) — never from node-local configuration, which
        // could silently diverge from the chain the beacon fold
        // actually runs.
        let epoch_duration_ms = rep
            .state
            .beacon_coordinator()
            .topology_schedule()
            .epoch_duration_ms();
        let pin_storage = Arc::clone(&storage);
        block_commit.set_boundary_trigger(
            epoch_duration_ms,
            Arc::new(move |height| {
                if let Err(error) = pin_storage.pin_boundary(height) {
                    tracing::warn!(
                        shard = ?shard,
                        %height,
                        error,
                        "epoch boundary pin failed; this node won't serve this boundary"
                    );
                }
            }),
            seed,
        );
    }
    let handles = ShardDispatchHandles {
        storage: Arc::clone(&storage),
        pending_chain: Arc::clone(&pending_chain),
        prepared_commits: block_commit.prepared_commits_handle(),
    };
    let mut io = ShardIo {
        storage,
        pending_chain,
        block_commit,
        caches,
        consensus: ConsensusState::new(config),
        cross_shard: CrossShardState::new(config),
        mempool: MempoolState::new(config),
        beacon_fetch: BeaconFetchState::new(config),
        tx_phase_times: TxPhaseTimesCache::default(),
        last_slow_tx_warn: LocalTimestamp::ZERO,
    };
    // Seed the block-sync watermark at the recovered tip so the first
    // sync after a restart — or a runtime join's tail sync after a
    // snap-sync import — fetches from `committed + 1` instead of
    // re-pulling the whole chain from genesis for the coordinator to
    // filter as already committed.
    if initial_persisted_height > BlockHeight::GENESIS {
        let outputs = io.consensus.block_sync.handle(BlockSyncInput::Admitted {
            scope: (),
            height: initial_persisted_height,
        });
        debug_assert!(
            outputs.is_empty(),
            "seeding an idle sync FSM must not emit work"
        );
    }
    (io, handles)
}
