//! Top-level node composition: [`NodeHost`].
//!
//! `NodeHost` bundles `Arc<ProcessIo>` (process-scoped resources) plus
//! one [`ShardLoop`] per hosted shard. It owns the event-routing seam:
//! [`Self::step`] dispatches `ShardEvent::Shard` to the targeted
//! `ShardLoop::step` and `ShardEvent::Process` to cross-shard handlers
//! (transaction submission fan-out, fetch tick) that need access to
//! every hosted shard.
//!
//! Production and simulation runners both build a `NodeHost` via
//! [`Self::new`] and drive it through [`Self::step`] / [`Self::set_time`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{ProcessExecutionCache, RadixExecutor, TransactionValidation};
use hyperscale_network::Network;
use hyperscale_storage::{BeaconStorage, PendingChain, ShardStorage};
use hyperscale_types::{LocalTimestamp, ShardId, TransactionStatus, TxHash};
use quick_cache::sync::Cache as QuickCache;

use crate::NodeStateMachine;
use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;
use crate::process_io::{ProcessIo, register_shard_request_handlers};
use crate::shard_io::ShardIo;
use crate::shard_io::block_commit::BlockCommitCoordinator;
use crate::shard_io::caches::SharedCaches;
use crate::shard_io::fetch::FetchHost;
use crate::shard_io::phase_times::TxPhaseTimesCache;
use crate::shard_io::sync::SyncHost;
use crate::shard_loop::{
    DispatchHandles, ProcessScopedInput, ShardDispatchHandles, ShardEvent, ShardLoop,
    SharedTopologySnapshot, StepOutput,
};
use crate::vnode::{Vnode, VnodeInit};

/// Output of [`NodeHost::into_parts`]: shared process-scoped resources
/// plus the per-shard drivers, keyed by hosted shard id.
pub type NodeHostParts<S, N, D> = (
    Arc<ProcessIo<S, N, D>>,
    HashMap<ShardId, ShardLoop<S, N, D>>,
);

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
    pub(crate) shards: HashMap<ShardId, ShardLoop<S, N, D>>,

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
        beacon_proposal_pool: Arc<BeaconProposalPool>,
        executor: RadixExecutor,
        network: N,
        dispatch: D,
        shard_event_senders: HashMap<ShardId, Sender<ShardEvent>>,
        topology_snapshot: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        assert!(!vnodes.is_empty(), "NodeHost requires at least one Vnode");

        // Distinct shards this host carries, derived from the supplied
        // vnodes. Used to allocate one `ShardIo` per shard.
        let hosted_shards: HashSet<ShardId> = vnodes.iter().map(|v| v.state.shard_id()).collect();

        let b = &config.batch;
        let network = Arc::new(network);

        // First pass: build ShardIo + Vec<Vnode> for each shard, plus the
        // per-shard dispatch handles map. ShardLoop construction is deferred
        // to a second pass because each ShardLoop needs an Arc<ProcessIo>
        // that can only be built after dispatch_handles is finalized.
        let mut shard_builds: HashMap<ShardId, (ShardIo<S>, Vec<Vnode>)> = HashMap::new();
        let mut per_shard_dispatch: HashMap<ShardId, ShardDispatchHandles<S>> = HashMap::new();

        let mut by_shard: HashMap<ShardId, Vec<VnodeInit>> = HashMap::new();
        for init in vnodes {
            let shard = init.state.shard_id();
            by_shard.entry(shard).or_default().push(init);
        }

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
            topology_snapshot,
            dispatch_handles,
            tx_validator,
            beacon_storage,
            beacon_proposal_pool,
        ));

        // Second pass: assemble ShardLoops with cloned Arc<ProcessIo>.
        let tx_gossip_max = b.tx_gossip_max;
        let tx_gossip_window = b.tx_gossip_window;
        let shards: HashMap<ShardId, ShardLoop<S, N, D>> = shard_builds
            .into_iter()
            .map(|(shard, (io, vnodes))| {
                let shard_loop = ShardLoop {
                    shard,
                    event_tx: process.shard_sender(shard),
                    process: Arc::clone(&process),
                    io,
                    vnodes,
                    now: LocalTimestamp::ZERO,
                    pending_timer_ops: Vec::new(),
                    emitted_statuses: Vec::new(),
                    actions_generated: 0,
                    outbound_gossip_batches: std::collections::BTreeMap::new(),
                    tx_gossip_max,
                    tx_gossip_window,
                };
                (shard, shard_loop)
            })
            .collect();

        Self {
            shards,
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
    pub fn add_shard(&mut self, vnodes: Vec<VnodeInit>, storage: S, sender: Sender<ShardEvent>) {
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
    /// process-scoped resources and one [`ShardLoop`] per hosted shard.
    ///
    /// The production runner uses this to move each `ShardLoop` onto its
    /// own pinned thread while keeping the `Arc<ProcessIo>` shared across
    /// them. Simulation never calls this — sim drives the whole host
    /// single-threaded via [`Self::step`].
    #[must_use]
    pub fn into_parts(self) -> NodeHostParts<S, N, D> {
        (self.process, self.shards)
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
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Number of vnodes hosted in `shard`, or `0` if `shard` isn't hosted.
    #[must_use]
    pub fn vnodes_len(&self, shard: ShardId) -> usize {
        self.shards.get(&shard).map_or(0, |g| g.vnodes.len())
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
    pub fn vnode_state_mut(&mut self, shard: ShardId, vnode_idx: usize) -> &mut NodeStateMachine {
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

    /// Look up the latest emitted status for a transaction across every
    /// hosted shard.
    ///
    /// Returns the most recent status notification for the given transaction
    /// hash, if any status has been emitted on any hosted shard. Unlike the
    /// per-step `StepOutput::emitted_statuses`, this cache persists across
    /// steps and survives mempool eviction.
    #[must_use]
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
    #[must_use]
    pub fn tx_status_caches(&self) -> HashMap<ShardId, Arc<QuickCache<TxHash, TransactionStatus>>> {
        self.shards
            .iter()
            .map(|(shard, group)| (*shard, Arc::clone(&group.io.caches.tx_status)))
            .collect()
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
    #[allow(clippy::too_many_lines)] // single dispatch over ShardEvent; one arm per variant
    pub fn step(&mut self, event: ShardEvent) -> StepOutput {
        for sl in self.shards.values_mut() {
            sl.pending_timer_ops.clear();
            sl.emitted_statuses.clear();
            sl.actions_generated = 0;
        }

        match event {
            ShardEvent::Shard(shard, input) => {
                // Silently drop events whose shard isn't hosted by this host.
                if let Some(sl) = self.shards.get_mut(&shard) {
                    sl.step(input);
                }
            }
            ShardEvent::Process(input) => self.step_process_input(input),
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
        let mut out = StepOutput {
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            timer_ops: Vec::new(),
        };
        for sl in self.shards.values_mut() {
            out.emitted_statuses.append(&mut sl.emitted_statuses);
            out.actions_generated += std::mem::replace(&mut sl.actions_generated, 0);
            out.timer_ops.append(&mut sl.pending_timer_ops);
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
/// grows the execution cache and network hosted sets, and registers
/// the shard's request handlers. Returns the loop for the caller to
/// drive — `NodeHost::add_shard` seats it in the host's map (the sim
/// step path); the production supervisor moves it onto a pinned
/// thread.
///
/// # Panics
///
/// Panics if `vnodes` is empty or targets mixed shards.
pub fn attach_shard<S, N, D>(
    process: &Arc<ProcessIo<S, N, D>>,
    config: &NodeConfig,
    vnodes: Vec<VnodeInit>,
    storage: S,
    sender: Sender<ShardEvent>,
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

    let b = &config.batch;
    let shard_loop = ShardLoop {
        shard,
        event_tx: sender,
        process: Arc::clone(process),
        io,
        vnodes: vnodes.into_iter().map(VnodeInit::into_vnode).collect(),
        now: LocalTimestamp::ZERO,
        pending_timer_ops: Vec::new(),
        emitted_statuses: Vec::new(),
        actions_generated: 0,
        outbound_gossip_batches: std::collections::BTreeMap::new(),
        tx_gossip_max: b.tx_gossip_max,
        tx_gossip_window: b.tx_gossip_window,
    };
    register_shard_request_handlers(process, &shard_loop.io, shard);
    shard_loop
}

/// Reverse of [`attach_shard`]: unwire a shard from the process maps.
///
/// Call once the shard's loop has stopped stepping (the sim path drops
/// the loop; the production supervisor joins the thread first).
/// Inbound traffic for the shard is rejected from the moment the maps
/// swap.
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
                (
                    header.hash(),
                    header.height(),
                    header.parent_qc().weighted_timestamp(),
                )
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
        pending_chain: Arc::clone(&pending_chain),
        prepared_commits: block_commit.prepared_commits_handle(),
    };
    let b = &config.batch;
    let io = ShardIo {
        storage,
        pending_chain,
        block_commit,
        caches,
        fetches: FetchHost::new(config),
        syncs: SyncHost::new(config),
        pending_validation: HashSet::new(),
        locally_submitted: HashSet::new(),
        validation_batch: BatchAccumulator::new(b.tx_validation_max, b.tx_validation_window),
        certified_header_batch: BatchAccumulator::new(
            b.certified_header_max,
            b.certified_header_window,
        ),
        tx_phase_times: TxPhaseTimesCache::default(),
        last_slow_tx_warn: LocalTimestamp::ZERO,
    };
    (io, handles)
}
