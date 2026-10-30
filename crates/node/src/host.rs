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
//! [`ShardLoop`] (and the host's beacon loop) on its own pinned thread via
//! [`ShardLoop::run_step`]; simulation keeps the whole host and drives it
//! single-threaded over a global event queue through [`NodeHost::step`],
//! which fans a `HostEvent::Process` out across every hosted shard.
//! Both paths share `ShardLoop::step` for dispatch and the same
//! `clear_scratch` / `take_output` scratch lifecycle, so the two drivers
//! cannot drift.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::Sender;
use hyperscale_beacon::BeaconFold;
use hyperscale_beacon::coordinator::LocalChainAnchors;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{CodeAvailability, Executor};
use hyperscale_network::Network;
use hyperscale_shard::ShardStats;
use hyperscale_storage::{
    BeaconChainReader, BeaconStorage, PendingChain, RecoveredState, ShardStorage, TickChain,
};
use hyperscale_types::{
    Block, BlockHeight, CertifiedBlock, Derivation, Epoch, LocalTimestamp, ShardId, Signer,
    TransactionStatus, TxHash, ValidatorId, Verified,
};

use crate::NodeStateMachine;
use crate::beacon::{BeaconCandidateCache, BeaconProposalCache};
use crate::beacon_loop::{BeaconLoop, resume_fold};
use crate::config::NodeConfig;
use crate::event::Registration;
use crate::process::{ProcessIo, register_shard_request_handlers};
use crate::replica::{ReplicaConfig, build_replica};
use crate::shard::boundary_pins::BoundaryPins;
use crate::shard::caches::SharedCaches;
use crate::shard::commit::{BlockCommitCoordinator, BoundaryMemo};
use crate::shard::consensus::{BlockSyncInput, ConsensusState};
use crate::shard::cross_shard::CrossShardState;
use crate::shard::crossing_index::ChainCrossings;
use crate::shard::mempool::MempoolState;
use crate::shard::phase_times::TxPhaseTimesCache;
use crate::shard::{
    DispatchHandles, FetchTicker, HostEvent, HostedRecords, ProcessScopedInput,
    ShardDispatchHandles, ShardIo, ShardLoop, SharedTopologySnapshot, StepOutput,
};

/// Output of [`NodeHost::into_parts`].
///
/// The shared process-scoped resources, the per-shard drivers keyed by
/// hosted shard id, and the host's beacon loop.
pub(crate) type NodeHostParts<S, N, D> = (
    Arc<ProcessIo<S, N, D>>,
    BTreeMap<ShardId, ShardLoop<S, N, D>>,
    BeaconLoop<S, N, D>,
);

/// The deterministic product of one shard's genesis ceremony, returned by
/// [`NodeHost::build_shard_genesis`].
///
/// The caller commits `certified` itself, which lets the simulation
/// schedule the commit only after wiring the network.
pub struct ShardGenesis {
    /// The genesis block built and persisted into the shard's replica.
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
    /// One [`ShardLoop`] per hosted shard. Replicas are driven
    /// exclusively through these — all `ProtocolEvent` ingestion and
    /// `Action` emission happen via per-shard `step()` dispatch.
    /// Ordered so that whole-host sweeps (step, drains, batch flushes)
    /// visit shards deterministically regardless of join order.
    pub(crate) shards: BTreeMap<ShardId, ShardLoop<S, N, D>>,

    /// The host's beacon loop, driven for beacon events routed via
    /// [`HostEvent::Beacon`](crate::event::HostEvent::Beacon).
    pub(crate) beacon: BeaconLoop<S, N, D>,

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

/// The process-scoped resources a [`NodeHost`] is built over.
pub struct HostResources<N, D> {
    /// The host's beacon chain store; it holds at least the genesis pair.
    pub beacon_storage: Arc<dyn BeaconStorage>,
    /// The engine every hosted replica executes through.
    pub executor: Arc<Executor>,
    /// The network the host sends through and registers its handlers on.
    pub network: N,
    /// The pool the host's actions are dispatched onto.
    pub dispatch: D,
    /// Each startup chain's event channel, one per chain.
    pub shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>>,
    /// The beacon loop's channel: beacon gossip, what the replicas report,
    /// and the outcomes of its own dispatched actions and fetches.
    pub beacon_event_sender: Sender<HostEvent>,
    /// The topology snapshot the host publishes for off-thread readers.
    pub topology_snapshot: SharedTopologySnapshot,
}

/// One chain a host runs: the shard, its opened store and the state it
/// recovered, and the validators its replica signs for.
pub struct HostedChain<'a, S> {
    /// The chain's shard.
    pub shard: ShardId,
    /// The chain's opened store.
    pub storage: S,
    /// The state the store recovered; the caller keeps it to resume the
    /// loop from.
    pub recovered: &'a RecoveredState,
    /// `(validator, signer)` per validator attached to the replica.
    pub signers: Vec<(ValidatorId, Arc<dyn Signer>)>,
}

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Create a `NodeHost` over its beacon storage, running `chains` from
    /// startup and a beacon participant for each of `identities`.
    ///
    /// The beacon loop and its fold are built first, from beacon storage,
    /// with `now` as their clock. Each startup chain then registers with
    /// the fold, and its replica is built with no signer from the schedule
    /// the registration hands back, so a chain anchored below the fold's
    /// floor widens the schedule before its first event. Each of the
    /// chain's signers then attaches as the loop's first step.
    ///
    /// # Panics
    ///
    /// Panics if `resources` holds an event sender for a shard other than
    /// `chains`', or if beacon storage holds no committed block.
    pub fn new(
        replica_config: &ReplicaConfig,
        resources: HostResources<N, D>,
        chains: Vec<HostedChain<'_, S>>,
        identities: Vec<(ValidatorId, Arc<dyn Signer>)>,
        config: NodeConfig,
        now: LocalTimestamp,
    ) -> Self {
        assert!(
            resources.shard_event_senders.keys().copied().eq(chains
                .iter()
                .map(|chain| chain.shard)
                .collect::<BTreeSet<_>>()),
            "shard_event_senders must have exactly one entry per startup chain"
        );
        let fold = resume_fold(
            resources.beacon_storage.as_ref(),
            Arc::clone(&replica_config.verifier),
            replica_config.beacon_network.clone(),
            replica_config.beacon_config_hash,
            now,
        );
        reseed_code(
            &resources.executor,
            &chains,
            resources.beacon_storage.as_ref(),
        );
        let process = build_process(replica_config, resources, &fold);

        let mut beacon = BeaconLoop::new(Arc::clone(&process), fold, &config);
        for (validator, signer) in identities {
            beacon.add_participant(validator, signer);
        }

        let mut per_shard_dispatch: HashMap<ShardId, ShardDispatchHandles<S>> = HashMap::new();
        let mut shards: BTreeMap<ShardId, ShardLoop<S, N, D>> = BTreeMap::new();
        let mut built = Vec::new();
        for chain in chains {
            let sender = process.shard_event_senders.load()[&chain.shard].clone();
            let registration = beacon.register(
                chain.shard,
                chain_anchors(chain.recovered),
                chain.recovered.committed_height,
                sender.clone(),
            );
            let replica = build_replica(
                replica_config,
                chain.shard,
                chain.recovered,
                (Arc::clone(&registration.schedule), registration.epoch),
                chain.storage.jmt_height(),
            );
            let (io, handles) = build_shard_io(
                chain.shard,
                &replica,
                chain.storage,
                &process.topology_snapshot,
                &config,
                &registration,
            );
            per_shard_dispatch.insert(chain.shard, handles);
            built.push((
                chain.shard,
                sender,
                io,
                replica,
                chain.signers,
                registration,
            ));
        }
        // Attaching a startup signer dispatches what it owes at once, which
        // reads its shard's dispatch handles.
        process
            .dispatch_handles
            .per_shard
            .store(Arc::new(per_shard_dispatch));
        for (shard, sender, io, replica, signers, registration) in built {
            let shard_loop = assemble_loop(&process, sender, io, replica, signers, &registration);
            shards.insert(shard, shard_loop);
        }

        Self {
            shards,
            beacon,
            process,
            now,
            config,
        }
    }

    /// Begin hosting `chain` at runtime: register it with the beacon loop,
    /// build its replica from the schedule the registration hands back,
    /// and wire its `ShardLoop` in with `chain`'s signers attached (see
    /// [`attach_shard`]).
    ///
    /// Events for the shard may queue on the channel from the moment
    /// the sender is installed; they're processed once the loop steps.
    ///
    /// # Panics
    ///
    /// Panics if the host already serves `chain`'s shard.
    pub fn add_shard(
        &mut self,
        config: &ReplicaConfig,
        chain: HostedChain<'_, S>,
        sender: Sender<HostEvent>,
    ) {
        let shard = chain.shard;
        assert!(
            !self.shards.contains_key(&shard),
            "shard {shard:?} already hosted"
        );
        let registration = self.beacon.register(
            shard,
            chain_anchors(chain.recovered),
            chain.recovered.committed_height,
            sender.clone(),
        );
        let mut shard_loop = attach_shard(
            &self.process,
            &self.config,
            config,
            &registration,
            chain,
            sender,
        );
        shard_loop.set_time(self.now);
        self.shards.insert(shard, shard_loop);
    }

    /// Attach `validator` to `shard`'s replica, signing with `signer` (see
    /// [`ShardLoop::attach_signer`]).
    ///
    /// # Panics
    ///
    /// Panics if `shard` isn't hosted.
    pub fn attach_signer(
        &mut self,
        shard: ShardId,
        validator: ValidatorId,
        signer: Arc<dyn Signer>,
    ) -> StepOutput {
        self.shard_loop_mut(shard).attach_signer(validator, signer)
    }

    /// Detach `validator` from `shard`'s replica, which keeps following
    /// the chain. Returns whether it was attached.
    ///
    /// # Panics
    ///
    /// Panics if `shard` isn't hosted.
    pub fn detach_signer(&mut self, shard: ShardId, validator: ValidatorId) -> bool {
        self.shard_loop_mut(shard).detach_signer(validator)
    }

    /// Stop hosting `shard`: close every signer's gate, deregister its
    /// chain from the beacon loop, exclude it from the network's hosted
    /// set, and drop its request handlers, event sender, and dispatch
    /// handles. Inbound traffic for the shard is rejected from the moment
    /// the maps swap; events already queued die with the channel receiver.
    ///
    /// Returns its `ShardLoop` for the caller to drop or take the store
    /// from. The loop must not step again: an action it dispatches looks up
    /// the dispatch handles this drops, and panics.
    ///
    /// Returns `None` if the shard isn't hosted.
    pub fn remove_shard(&mut self, shard: ShardId) -> Option<ShardLoop<S, N, D>> {
        let shard_loop = self.shards.remove(&shard)?;
        shard_loop.shut_down();
        self.beacon.deregister(shard_loop.chain);
        detach_shard(&self.process, shard);
        Some(shard_loop)
    }

    /// Run `validator`'s beacon participation on this host from now on.
    /// Its startup timers land in the beacon loop's timer scratch; the
    /// caller drains them via [`Self::drain_pending_output`].
    pub fn add_participant(&mut self, validator: ValidatorId, signer: Arc<dyn Signer>) {
        self.beacon.add_participant(validator, signer);
    }

    /// Stop running `validator`'s beacon participation on this host. Its
    /// release gate is closed when this returns. Returns whether the host
    /// ran it.
    pub fn remove_participant(&mut self, validator: ValidatorId) -> bool {
        self.beacon.remove_participant(validator)
    }

    /// The identities this host runs a beacon participant for.
    pub fn participants(&self) -> impl Iterator<Item = ValidatorId> + '_ {
        self.beacon.validators()
    }

    /// The shard of every chain registered with this host's fold, one
    /// entry per registration.
    #[must_use]
    pub fn registered_chains(&self) -> Vec<ShardId> {
        self.beacon
            .fold()
            .chains()
            .map(|(_, chain)| chain.shard)
            .collect()
    }

    /// The oldest epoch whose window this host's fold retains.
    #[must_use]
    pub fn oldest_retained_epoch(&self) -> Option<Epoch> {
        self.beacon
            .fold()
            .schedule()
            .retained_epochs()
            .map(|(oldest, _)| oldest)
    }

    /// Consume the host and yield its constituent parts: the shared
    /// process-scoped resources, one [`ShardLoop`] per hosted shard, and the
    /// beacon loop.
    ///
    /// The production runner uses this to move each `ShardLoop` (and the
    /// `BeaconLoop`) onto its own pinned thread while keeping the
    /// `Arc<ProcessIo>` shared across them. Simulation drives the whole
    /// host single-threaded via [`Self::step`], and takes it apart only
    /// when its process crashes, to keep the stores it leaves on disk.
    #[must_use]
    pub fn into_parts(self) -> NodeHostParts<S, N, D> {
        (self.process, self.shards, self.beacon)
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
        self.beacon.set_time(now);
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// The validators attached to `shard`'s replica, in id order; empty
    /// if `shard` isn't hosted.
    #[must_use]
    pub fn signers(&self, shard: ShardId) -> Vec<ValidatorId> {
        self.shards
            .get(&shard)
            .map_or_else(Vec::new, |shard_loop| shard_loop.signers().collect())
    }

    /// Shard consensus statistics of `shard`'s replica, or `None` if
    /// `shard` isn't hosted.
    #[must_use]
    pub fn shard_stats(&self, shard: ShardId) -> Option<ShardStats> {
        self.shards
            .get(&shard)
            .map(|shard_loop| shard_loop.replica.shard_coordinator().stats())
    }

    /// Whether any replica this host runs has `validator` attached, a
    /// retained terminated loop's included. An identity attached to no
    /// replica may move between hosts.
    #[must_use]
    pub fn hosts_validator(&self, validator: ValidatorId) -> bool {
        self.shards
            .values()
            .any(|shard_loop| shard_loop.signers.contains_key(&validator))
    }

    /// `shard`'s replica.
    ///
    /// # Panics
    /// Panics if `shard` isn't hosted.
    #[must_use]
    pub fn replica(&self, shard: ShardId) -> &NodeStateMachine {
        &self.shard_loop(shard).replica
    }

    /// Hosted shards (one entry per `ShardLoop`). Used by call sites
    /// that fan out across every shard this host carries — batch flushes,
    /// fetch ticks, metrics aggregation.
    pub fn hosted_shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.shards.keys().copied()
    }

    /// Internal: per-shard loop (process handle + io + replica + scratch).
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

    /// This host's derivation, held by its engine.
    #[must_use]
    pub fn derivation(&self) -> Arc<dyn Derivation> {
        self.process.derivation()
    }

    /// This host's code availability, held by the same engine.
    #[must_use]
    pub fn code(&self) -> Arc<dyn CodeAvailability> {
        self.process.code()
    }

    /// Look up the latest merged status for a transaction: what a hosted
    /// shard reported for its own leg.
    ///
    /// Reads the process-wide [`TxStatusCache`], which every hosted
    /// shard writes into. Unlike the per-step
    /// `StepOutput::emitted_statuses`, this cache persists across steps
    /// and survives mempool eviction.
    ///
    /// [`TxStatusCache`]: crate::process::TxStatusCache
    #[must_use]
    pub fn tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.tx_status_entry(hash).map(|(status, _)| status)
    }

    /// The merged status for `hash` together with the hosted shard whose
    /// leg it is.
    #[must_use]
    pub fn tx_status_entry(&self, hash: &TxHash) -> Option<(TransactionStatus, ShardId)> {
        self.process.tx_status.get(hash)
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
    /// 1. Flush expired batches with [`Self::flush_expired_batches`], and
    ///    wake again at [`Self::nearest_batch_deadline`]
    /// 2. Process `timer_ops` from the returned [`StepOutput`]
    /// 3. Process `emitted_statuses` from the returned [`StepOutput`]
    /// 4. Drain any events produced through the event channel (simulation only —
    ///    production receives these via its crossbeam channel receivers)
    pub fn step(&mut self, event: HostEvent) -> StepOutput {
        for sl in self.shards.values_mut() {
            sl.clear_scratch();
        }
        self.beacon.clear_scratch();

        match event {
            HostEvent::Shard(shard, input) => {
                // Silently drop events whose shard isn't hosted by this host.
                if let Some(sl) = self.shards.get_mut(&shard) {
                    sl.step(input);
                }
            }
            HostEvent::Process(input) => self.step_process_input(input),
            HostEvent::Beacon(input) => self.beacon.dispatch_event(input),
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
        out.merge(self.beacon.take_output());
        out
    }

    /// Flush any batch accumulators whose deadlines have expired across
    /// every hosted shard.
    ///
    /// Call this with the host's current time after each step and at each
    /// batch deadline.
    pub fn flush_expired_batches(&mut self, now: LocalTimestamp) {
        for sl in self.shards.values_mut() {
            sl.flush_expired_batches(now);
        }
    }

    /// Get the nearest batch deadline across every hosted shard, if any.
    ///
    /// The time a runner wakes the host to flush: production bounds its
    /// `recv_timeout()` with it, and the simulation schedules a wake.
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

/// The process-scoped half of a host built over `resources`, publishing
/// the schedule `fold` resumed.
fn build_process<S, N, D>(
    replica_config: &ReplicaConfig,
    resources: HostResources<N, D>,
    fold: &BeaconFold,
) -> Arc<ProcessIo<S, N, D>>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    let HostResources {
        beacon_storage,
        executor,
        network,
        dispatch,
        shard_event_senders,
        beacon_event_sender,
        topology_snapshot,
    } = resources;
    let network = Arc::new(network);
    // The stores this host has open, shared with the engine so a record
    // its caches dropped — or a restart never seated — is read back from
    // disk rather than asked of a peer that would answer with what is
    // already on this node's own disk. Filled as each chain is wired.
    let per_shard = Arc::new(ArcSwap::from_pointee(HashMap::new()));
    executor.install_store(Arc::new(HostedRecords::new(
        Arc::clone(&per_shard),
        Arc::clone(&beacon_storage),
    )));
    let dispatch_handles = Arc::new(DispatchHandles {
        executor,
        network: Arc::clone(&network),
        beacon_proposal_cache: Arc::new(BeaconProposalCache::new(
            replica_config.beacon_network.clone(),
            Arc::clone(&beacon_storage) as Arc<dyn BeaconChainReader>,
        )),
        beacon_candidate_cache: Arc::new(BeaconCandidateCache::new()),
        beacon_storage: Arc::clone(&beacon_storage),
        per_shard,
    });
    Arc::new(ProcessIo::new(
        network,
        Arc::clone(&replica_config.verifier),
        dispatch,
        shard_event_senders,
        beacon_event_sender,
        topology_snapshot,
        (
            fold.state().current_epoch,
            Arc::new(fold.schedule().clone()),
        ),
        dispatch_handles,
        beacon_storage,
    ))
}

/// Reseed published code from each store's package index — the boot half
/// of commit-time absorption, so a restarted host executes calls to
/// packages published before the restart — and foreign code the node
/// fetched on beacon facts, the same reconciliation from the node-level
/// cache.
fn reseed_code<S: ShardStorage>(
    executor: &Executor,
    chains: &[HostedChain<'_, S>],
    beacon_storage: &dyn BeaconStorage,
) {
    let artifacts = chains
        .iter()
        .flat_map(|chain| chain.storage.package_artifacts())
        .chain(beacon_storage.fetched_packages());
    for artifact in artifacts {
        executor.install_artifact(&artifact);
    }
}

/// The anchors a recovered chain's committed tip carries.
#[must_use]
pub fn chain_anchors(recovered: &RecoveredState) -> LocalChainAnchors {
    LocalChainAnchors {
        committee: recovered.committee_anchor_wt(),
        block: recovered.block_anchor_wt(),
    }
}

/// Assemble a shard's loop over its built `io` and `replica`, and attach
/// each of `signers` as its first step.
fn assemble_loop<S, N, D>(
    process: &Arc<ProcessIo<S, N, D>>,
    event_tx: Sender<HostEvent>,
    io: ShardIo<S>,
    replica: NodeStateMachine,
    signers: Vec<(ValidatorId, Arc<dyn Signer>)>,
    registration: &Registration,
) -> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    let mut shard_loop = ShardLoop {
        shard: replica.shard_id(),
        chain: registration.token,
        event_tx,
        process: Arc::clone(process),
        io,
        replica,
        signers: BTreeMap::new(),
        now: LocalTimestamp::ZERO,
        fetch_tick: FetchTicker::default(),
        pending_timer_ops: Vec::new(),
        emitted_statuses: Vec::new(),
        actions_generated: 0,
        attached: Vec::new(),
        reseat: false,
        answer_follow: None,
    };
    for (validator, signer) in signers {
        shard_loop.attach(validator, signer);
    }
    shard_loop
}

/// Wire a runtime-joined chain into the process-scoped maps and build its
/// `ShardLoop`.
///
/// The chain is already registered with the beacon loop, and its replica
/// is built here from the schedule `registration` handed back. Installs
/// the event sender, builds the `ShardIo` + dispatch handles, grows the
/// network hosted sets, registers the shard's request handlers, and
/// attaches `chain`'s signers. Returns the loop for the caller to drive —
/// `NodeHost::add_shard` keeps it in the host's map (the sim step path);
/// the production supervisor moves it onto a pinned thread.
pub fn attach_shard<S, N, D>(
    process: &Arc<ProcessIo<S, N, D>>,
    config: &NodeConfig,
    replica_config: &ReplicaConfig,
    registration: &Registration,
    chain: HostedChain<'_, S>,
    sender: Sender<HostEvent>,
) -> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    let HostedChain {
        shard,
        storage,
        recovered,
        signers,
    } = chain;
    let replica = build_replica(
        replica_config,
        shard,
        recovered,
        (Arc::clone(&registration.schedule), registration.epoch),
        storage.jmt_height(),
    );
    process.insert_shard_sender(shard, sender.clone());
    let (io, handles) = build_shard_io(
        shard,
        &replica,
        storage,
        &process.topology_snapshot,
        config,
        registration,
    );
    process.dispatch_handles.insert_shard(shard, handles);
    process.network.subscribe_shard(shard);

    let shard_loop = assemble_loop(process, sender, io, replica, signers, registration);
    register_shard_request_handlers(process, &shard_loop.io, shard);
    process.release_parked_submissions();
    shard_loop
}

/// Reverse of [`attach_shard`]: unwire a shard from the process maps.
///
/// Call once the shard's loop has stopped stepping (the sim path drops
/// the loop; the production supervisor joins the thread first). Inbound
/// traffic for the shard is rejected from the moment the maps swap.
pub fn detach_shard<S, N, D>(process: &Arc<ProcessIo<S, N, D>>, shard: ShardId)
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    process.network.unsubscribe_shard(shard);
    process.remove_shard_sender(shard);
    process.dispatch_handles.remove_shard(shard);
    process.release_parked_submissions();
}

/// Build one shard's `ShardIo` plus its dispatch-handle entry from the
/// shard's replica and opened storage. Shared by host construction and
/// runtime shard addition so both paths produce identically wired shards.
fn build_shard_io<S: ShardStorage>(
    shard: ShardId,
    replica: &NodeStateMachine,
    storage: S,
    topology: &SharedTopologySnapshot,
    config: &NodeConfig,
    registration: &Registration,
) -> (ShardIo<S>, ShardDispatchHandles<S>) {
    let initial_persisted_height = replica.shard_coordinator().committed_height();
    // The block-commit gate keys persistence ordering off the store's tree
    // version — the height its JMT actually holds — which neither the
    // coordinator's committed height nor its own consensus tip reliably
    // gives when the loop is built. A composed split or merge child installs
    // genesis state before its coordinator folds it (coordinator height lags
    // the tree); a snap-synced recovery member imports state at the anchor
    // with no consensus blocks yet (consensus tip lags the tree). The tree
    // version leads both, and it is exactly the parent the loop's first
    // block writes over, so seeding the gate below it would wedge the loop;
    // the sync FSM and boundary memo still key off the coordinator height.
    let tree_height = storage.jmt_height();
    let caches = SharedCaches::new(replica);
    let storage = Arc::new(storage);
    // The chain's own origin, which the committed-window walks floor on
    // exactly as the block-sync watermark below does: a split child or
    // merge parent continues its predecessor's height line, and heights
    // beneath that line exist on no chain here.
    let pending_chain = Arc::new(PendingChain::new(
        Arc::clone(&storage),
        replica.shard_coordinator().chain_origin().genesis_height,
    ));
    // The replica asks its crossing questions of this chain's persisted
    // tip, now that the chain is open.
    caches
        .crossing_index
        .bind(Arc::new(ChainCrossings(Arc::clone(&pending_chain))));
    let tick_chain = Arc::new(TickChain::new(Arc::clone(&storage)));
    // No run of this process stated the rows the store holds stated.
    tick_chain.seed_stated(replica.shard_coordinator().member_rows());
    // Held from the first commit on: a restart replays from below the
    // tip, and the first commit dates a version before any persists.
    tick_chain.prune_persisted(
        tree_height,
        replica.execution_coordinator().baseline_floor(),
    );
    let mut block_commit = BlockCommitCoordinator::new(shard, tree_height);
    let boundary_pins = Arc::new(BoundaryPins::new(
        Arc::clone(&storage),
        shard,
        &registration.chain_config,
        Arc::clone(topology),
    ));
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
                    terminal: header.settled_txs_root().is_some(),
                }
            });
        // The chain's epoch grid, read from the projected schedule
        // (sourced from the folded `BeaconState`'s chain config) —
        // never from node-local configuration, which could silently
        // diverge from the chain the beacon fold actually runs.
        let windows = replica.schedule().windows();
        let pins = Arc::clone(&boundary_pins);
        block_commit.set_boundary_trigger(windows, Arc::new(move |height| pins.pin(height)), seed);
    }
    let handles = ShardDispatchHandles {
        storage: Arc::clone(&storage),
        pending_chain: Arc::clone(&pending_chain),
        tick_chain: Arc::clone(&tick_chain),
        prepared_commits: block_commit.prepared_commits_handle(),
    };
    let mut io = ShardIo {
        storage,
        pending_chain,
        tick_chain,
        block_commit,
        boundary_pins,
        caches,
        consensus: ConsensusState::new(config),
        cross_shard: CrossShardState::new(config),
        mempool: MempoolState::new(config),
        tx_phase_times: TxPhaseTimesCache::default(),
        last_slow_tx_warn: LocalTimestamp::ZERO,
        floor_pins: None,
    };
    // Seed the block-sync watermark at the recovered tip so the first
    // sync after a restart — or a runtime join's tail sync after a
    // snap-sync import — fetches from `committed + 1` instead of
    // re-pulling the whole chain from genesis for the coordinator to
    // filter as already committed.
    //
    // Floored at the chain's origin, which a reshape seat needs and the
    // recovered tip cannot supply: a split child or merge parent boots
    // with its coordinator still at genesis and folds its own genesis
    // block a moment later, through a path that admits no height. No
    // block below that origin exists on this chain anywhere, so a sync
    // starting from the network genesis asks every peer for heights none
    // of them can ever serve, and never completes.
    let sync_floor =
        initial_persisted_height.max(replica.shard_coordinator().chain_origin().genesis_height);
    if sync_floor > BlockHeight::GENESIS {
        let outputs = io.consensus.block_sync.handle(BlockSyncInput::Admitted {
            scope: (),
            height: sync_floor,
        });
        debug_assert!(
            outputs.is_empty(),
            "seeding an idle sync FSM must not emit work"
        );
    }
    (io, handles)
}
