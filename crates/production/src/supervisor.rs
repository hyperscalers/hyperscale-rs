//! Runtime shard membership for the production runner.
//!
//! [`ShardSupervisor`] owns every pinned shard thread after startup and
//! executes membership changes off those threads (a thread can't safely
//! spawn or join its siblings): a [`ShardCommand::Join`] opens the
//! shard's storage, builds its vnode state machines from the host's
//! beacon chain, wires the process-scoped maps via
//! [`attach_shard`], and spawns the pinned thread; a
//! [`ShardCommand::Leave`] releases one vnode's membership and tears
//! the shard down — shutdown signal, thread join, map unwire, storage
//! drop — only when the last local vnode leaves.
//!
//! Membership is refcounted per shard because a host runs several
//! vnodes and `NodeHost` dedups shard participation: two co-hosted
//! vnodes on one shard share storage and a thread, and a departing one
//! must not tear the other down.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crossbeam::channel::{Receiver, Sender, unbounded};
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::Network;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::bootstrap::merge_flip::merge_genesis_from_terminals;
use hyperscale_node::bootstrap::observer::observer_ready_signal;
use hyperscale_node::bootstrap::split_flip::split_genesis_from_terminal;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::pool_loop::PoolLoop;
use hyperscale_node::process::ProcessIo;
use hyperscale_node::shard::HostEvent;
use hyperscale_node::{
    NodeConfig, SeatFollower, SeatVnodeGroup, TimerOp, VnodeInit, seat_follower, seat_vnode_group,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BoundaryStore, ImportLeaf, RecoveredState, ShardChainReader};
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::{
    Block, BlockHeight, Bls12381G1PrivateKey, GenesisConfigHash, NetworkDefinition, ShardAnchor,
    ShardId, SplitAdoption, StateRoot, ValidatorId,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::bootstrap::{
    bootstrap_observer_state, bootstrap_shard_state, collect_half_leaves,
    collect_half_leaves_local, fetch_certified_terminal, follow_observer_store,
};
use crate::rpc::RpcPublishers;
use crate::runner::{
    PoolLoopConfig, ProdPoolLoop, ProdShardLoop, ShardChannels, ShardLoopConfig, VnodeConfig,
    consensus_clock, spawn_pool_loop, spawn_shard_loop,
};

/// The process-scoped resource bundle as the production runner types it.
type ProdProcessIo = ProcessIo<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Opens (or creates) one shard's `RocksDB` storage at the host's
/// data-dir convention. Supplied by the validator binary, which owns
/// the directory layout.
pub type StorageFactory =
    Arc<dyn Fn(ShardId) -> Result<Arc<RocksDbShardStorage>, String> + Send + Sync>;

/// Resolves one shard's storage directory at the host's data-dir
/// convention — the location [`StorageFactory`] opens.
///
/// Exposed separately so a split flip can seed the directory from a
/// parent checkpoint before the open. Supplied by the validator binary
/// alongside the factory.
pub type StorageDirResolver = Arc<dyn Fn(ShardId) -> PathBuf + Send + Sync>;

/// A runtime shard-membership change, executed by [`ShardSupervisor`].
#[derive(Clone)]
pub enum ShardCommand {
    /// Begin hosting a shard with the given local vnodes. The first
    /// join for a shard brings up storage, thread, and subscriptions;
    /// a join for an already-hosted shard is rejected — a shard's
    /// vnodes join together, in one command.
    Join {
        /// Shard to host.
        shard: ShardId,
        /// Local vnodes participating in the shard's consensus. Every
        /// entry's `local_shard` must equal `shard`.
        vnodes: Vec<VnodeConfig>,
        /// Present when the shard is a freshly split child this host
        /// was pre-staffed for: the store adopts along the marked path
        /// (parent-half checkpoint hard-link or observer store) instead
        /// of snap-syncing, once the parent chain's certified crossing
        /// and the beacon's child anchor are observable.
        adoption: Option<SplitAdoption>,
    },
    /// Release one local vnode's membership in `shard`. The shard's
    /// thread, subscriptions, and storage are torn down when the last
    /// local vnode leaves.
    Leave {
        /// Shard to release one membership of.
        shard: ShardId,
    },
    /// Begin a reshape-observer duty: open a store rooted at `child`'s
    /// prefix, sync the child's span from `via`'s committee, and
    /// broadcast the ready signal on completion. The synced store
    /// stays on disk for the boundary handoff.
    Observe {
        /// The splitting shard whose committee serves and carries the
        /// observer.
        via: ShardId,
        /// The pending child the observer syncs.
        child: ShardId,
        /// The local vnode holding the observer seat.
        validator: ValidatorId,
        /// Its signing key, for the self-signed ready signal.
        signing_key: Arc<Bls12381G1PrivateKey>,
    },
    /// Abandon an observer duty — the seat was released without
    /// executing. Aborts an in-flight sync; a completed one just drops
    /// its registry entry.
    Unobserve {
        /// The pending child whose duty ends.
        child: ShardId,
    },
    /// Begin (or extend) a reshape-keeper duty: broadcast the ready
    /// signal on `own_child`'s committee, then build the merged `parent`
    /// store from both terminated halves at the boundary. The keeper keeps
    /// running `own_child` until the merge executes; the prepared parent
    /// store waits for the placement delta. A host holding keeper seats on
    /// both children sends one `Keep` per child — they coalesce into one
    /// duty that builds the parent store once and seats both on it.
    Keep {
        /// The merged parent the keeper reforms.
        parent: ShardId,
        /// The child this seat runs and re-asserts readiness for.
        own_child: ShardId,
        /// The local vnode holding the keeper seat.
        validator: ValidatorId,
        /// Its signing key, for the self-signed ready signal.
        signing_key: Arc<Bls12381G1PrivateKey>,
    },
    /// Abandon one keeper seat — its merge was cancelled for this
    /// validator. The duty's task is aborted only when its last member
    /// leaves; a prepared duty just drops its registry entry.
    Unkeep {
        /// The merged parent whose seat ends.
        parent: ShardId,
        /// The local vnode whose seat ends.
        validator: ValidatorId,
    },
}

/// A finished snap-sync bootstrap, ready for the supervisor to seat:
/// the imported storage verified against the attested anchor, plus the
/// recovered state the shard's state machines boot from.
pub struct CompletedBootstrap {
    shard: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
}

/// A settled split-child adoption: the child store on disk is pointed
/// at its adopted subtree with the deterministic genesis derived and
/// verified against the beacon's child anchor; seating installs the
/// genesis and starts consensus.
pub struct CompletedAdoption {
    child: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    genesis: Block,
    recovered: RecoveredState,
}

/// A completed observer sync: the child-rooted store holds the child's
/// span as of `root`, and the ready signal is broadcast. The duty task
/// holds the store open and keeps following the splitting shard's chain
/// toward the boundary handoff.
pub struct CompletedObservation {
    child: ShardId,
    root: StateRoot,
    substate_bytes: u64,
}

/// An observer duty's boundary handoff, prepared: the followed store is
/// adopted at the child's genesis with the deterministic genesis
/// derived and verified against the beacon's child anchor. Seating
/// waits only for the placement delta's vnodes.
pub struct PreparedObserverFlip {
    child: ShardId,
    storage: Arc<RocksDbShardStorage>,
    genesis: Block,
    recovered: RecoveredState,
}

/// A keeper duty's boundary handoff, prepared: the merged parent store is
/// built from both terminated halves and adopted at the deterministic
/// merged genesis, verified against the beacon's composed parent anchor.
/// Seating waits only for the placement delta's vnodes.
pub struct PreparedMergeFlip {
    parent: ShardId,
    storage: Arc<RocksDbShardStorage>,
    genesis: Block,
    recovered: RecoveredState,
}

/// A background-work completion fed back into the supervisor by the
/// runner's select loop. All blocking membership work (storage opens,
/// thread joins) and async snap-sync bootstraps land here, so every
/// membership state transition runs on the runner's loop.
pub enum SupervisorEvent {
    /// A join's blocking storage open finished.
    Opened {
        /// Shard the join targets.
        shard: ShardId,
        /// The join's vnodes, threaded through the open.
        vnodes: Vec<VnodeConfig>,
        /// The opened storage and its recovered state, or the open
        /// failure.
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    },
    /// A snap-sync bootstrap settled (`Err` carries the failed shard).
    Bootstrapped(Result<CompletedBootstrap, ShardId>),
    /// An observer duty settled (`Err` carries the failed child).
    Observed(Result<CompletedObservation, ShardId>),
    /// A split child's store adoption settled (`Err` carries the failed
    /// child).
    SplitAdopted(Result<Box<CompletedAdoption>, ShardId>),
    /// An observer duty's boundary handoff settled (`Err` carries the
    /// failed child).
    ObserverPrepared(Result<Box<PreparedObserverFlip>, ShardId>),
    /// A keeper duty's boundary handoff settled (`Err` carries the failed
    /// merged parent).
    KeeperPrepared(Result<Box<PreparedMergeFlip>, ShardId>),
    /// A departing shard's thread joined; the unwire can finish.
    TornDown {
        /// Shard whose thread exited.
        shard: ShardId,
        /// The departed vnodes' validator ids, for the RPC scrub.
        validator_ids: Vec<u64>,
    },
}

/// One observer duty, keyed by its pending child in
/// [`ShardSupervisor::observers`].
struct ObserverDuty {
    /// The splitting shard serving the sync.
    via: ShardId,
    /// The local vnode holding the seat.
    validator: ValidatorId,
    /// The duty task — the sync, then the stay-current follow of the
    /// splitting shard's chain, then the boundary handoff's adoption.
    /// Aborted by `Unobserve`; `None` once the handoff is prepared.
    task: Option<JoinHandle<()>>,
    /// The imported child subtree root, once the sync completes (the
    /// follow keeps the store current with the parent from there).
    synced: Option<StateRoot>,
    /// The prepared boundary handoff, once the follow reaches the
    /// parent's crossing — waiting for the placement delta to seat it.
    prepared: Option<Box<PreparedObserverFlip>>,
}

/// One local keeper seat within a [`KeeperDuty`]: a validator and the
/// child it runs and re-asserts readiness for. A host packs more than
/// one when its vnodes land in both children's keeper draws — they share
/// the parent store the duty builds, but each signals readiness on its
/// own child's committee.
#[derive(Clone)]
struct KeeperMember {
    /// The local vnode holding the seat.
    validator: ValidatorId,
    /// The child this member runs and re-asserts readiness for.
    own_child: ShardId,
    /// Its signing key, for the self-signed ready signal.
    signing_key: Arc<Bls12381G1PrivateKey>,
}

/// One keeper duty, keyed by its merging parent in
/// [`ShardSupervisor::keepers`]. A single host may hold keeper seats on
/// both children of the merge; they coalesce into one duty that builds
/// the merged parent store once and seats every local member on it.
struct KeeperDuty {
    /// The local keeper seats, shared with the duty task so a member
    /// added by a later `Keep` is picked up on the next re-assert round
    /// and one removed by `Unkeep` stops being signalled. The merge
    /// pairs both halves, so the set fills as each child's `Keep` lands.
    members: Arc<Mutex<Vec<KeeperMember>>>,
    /// The duty task — re-asserts readiness for every member, then the
    /// boundary handoff that builds the merged parent store once.
    /// Aborted when the last member leaves; `None` once prepared.
    task: Option<JoinHandle<()>>,
    /// The prepared boundary handoff, once both halves have terminated
    /// and the merged store is built — waiting for the placement delta.
    prepared: Option<Box<PreparedMergeFlip>>,
    /// Set once a merge-execution `Join` lands for this parent: every
    /// member seats on the shared store as soon as it is prepared.
    seat_requested: bool,
}

/// The merging children's local stores a keeper holds, if any. A host
/// running both children carries both — the boundary handoff then builds
/// the merged parent entirely from local reads, with no boundary sync.
struct ChildStores {
    left: Option<Arc<RocksDbShardStorage>>,
    right: Option<Arc<RocksDbShardStorage>>,
}

/// One hosted shard's runtime: its pinned thread plus the handles the
/// supervisor needs to stop it.
struct ShardThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
    /// Local vnodes participating in this shard. The shard tears down
    /// when this reaches zero.
    vnode_count: usize,
    /// Hosted vnodes' validator ids, recorded so teardown can scrub
    /// their slots from the validator-keyed RPC state maps.
    validator_ids: Vec<u64>,
}

/// The host's pinned pool thread plus the handle to stop it, and the
/// follower validators it currently drives — a membership change rebuilds
/// the pool with the adjusted set.
struct PoolThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
    /// Validators currently followed by the pool. A drain off the last
    /// shard adds one; a seat removes one; the pool tears down at zero.
    validators: Vec<ValidatorId>,
}

/// Owns the per-shard pinned threads and executes runtime membership
/// changes. Lives on the runner's tokio loop — never on a shard thread.
pub struct ShardSupervisor {
    process: Arc<ProdProcessIo>,
    node_config: NodeConfig,
    shard_config: ShardConsensusConfig,
    mempool_config: MempoolConfig,
    provision_config: ProvisionConfig,
    beacon_network: NetworkDefinition,
    beacon_config_hash: GenesisConfigHash,
    tokio_handle: TokioHandle,
    publishers: RpcPublishers,
    /// Per-shard `RocksDB` handles, shared with the runner's GC tick.
    storages: Arc<Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>,
    storage_factory: StorageFactory,
    storage_dir: StorageDirResolver,
    /// Replicated into every fresh store this supervisor opens — a
    /// post-genesis joiner or observer store must carry the engine
    /// bootstrap on its substate side before its span imports.
    engine_bootstrap: EngineBootstrap,
    /// Cloned into every spawned shard loop's config so placement
    /// deltas reach the runner's reconfiguration loop.
    participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    shards: HashMap<ShardId, ShardThread>,
    /// Shards whose join is parked on background work — the off-loop
    /// storage open or an in-flight snap-sync bootstrap — mapped to the
    /// count of vnodes still pending. Guards against a second `Join`
    /// racing a double import; a `Leave` meanwhile decrements,
    /// abandoning the join at zero.
    bootstrapping: HashMap<ShardId, usize>,
    /// Observer duties, in flight or complete, keyed by pending child.
    observers: HashMap<ShardId, ObserverDuty>,
    /// Split joins that arrived while their observer duty's boundary
    /// handoff was still preparing, seated by the
    /// [`SupervisorEvent::ObserverPrepared`] handler.
    pending_observer_joins: HashMap<ShardId, Vec<VnodeConfig>>,
    /// Keeper duties, in flight or prepared, keyed by merging parent. A
    /// duty coalesces every local keeper seat for its parent, so a host
    /// holding seats on both children seats them together on one store.
    keepers: HashMap<ShardId, KeeperDuty>,
    /// Beacon epoch length, for the keeper's deterministic merged-genesis
    /// cut derivation. Matches the beacon's own chain config.
    epoch_duration_ms: u64,
    /// Genesis instant (ms since the Unix epoch) the consensus clock is
    /// measured against, from `BeaconChainConfig::genesis_timestamp_ms`.
    /// Threaded into every shard the supervisor seats so a runtime join
    /// shares the runner's clock origin.
    genesis_offset_ms: u64,
    /// Shards whose teardown is parked on the off-loop thread join.
    /// A `Join` arriving meanwhile queues in [`Self::pending_joins`].
    draining: HashSet<ShardId>,
    /// Joins that arrived while their shard was draining, replayed by
    /// the [`SupervisorEvent::TornDown`] handler. Dropping them instead
    /// would lose the placement delta until restart.
    pending_joins: HashMap<ShardId, Vec<VnodeConfig>>,
    /// Background-work completions land here; the runner's select loop
    /// drains the paired receiver into [`Self::on_event`].
    events_tx: mpsc::UnboundedSender<SupervisorEvent>,
    /// Receiver side, taken by the runner's `run()` loop.
    events_rx: Option<mpsc::UnboundedReceiver<SupervisorEvent>>,
    /// The host's pinned beacon-follower pool thread, present only while the
    /// host carries shard-less followers. A drain off the last shard builds
    /// one; seating its last follower tears it down.
    pool: Option<PoolThread>,
    /// The host's beacon-event channel receiver, cloned into each pool
    /// thread the supervisor spawns. The host-level gossip handler pushes
    /// committed beacon blocks onto the paired sender.
    beacon_event_rx: Receiver<HostEvent>,
    /// Signing keys for the host's local validators, used to build a
    /// follower when a validator drains off its last shard. A follower
    /// never signs, but the bundle carries the real key for the later seat.
    vnode_keys: HashMap<ValidatorId, Arc<Bls12381G1PrivateKey>>,
}

impl ShardSupervisor {
    #[allow(clippy::too_many_arguments)] // construction threads every runner-owned handle once
    pub(crate) fn new(
        process: Arc<ProdProcessIo>,
        shard_config: ShardConsensusConfig,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        beacon_network: NetworkDefinition,
        beacon_config_hash: GenesisConfigHash,
        tokio_handle: TokioHandle,
        publishers: RpcPublishers,
        storages: Arc<Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
        engine_bootstrap: EngineBootstrap,
        participation_tx: mpsc::UnboundedSender<ParticipationChange>,
        epoch_duration_ms: u64,
        genesis_offset_ms: u64,
        beacon_event_rx: Receiver<HostEvent>,
        vnode_keys: HashMap<ValidatorId, Arc<Bls12381G1PrivateKey>>,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Self {
            process,
            node_config: NodeConfig::default(),
            shard_config,
            mempool_config,
            provision_config,
            beacon_network,
            beacon_config_hash,
            tokio_handle,
            publishers,
            storages,
            storage_factory,
            storage_dir,
            engine_bootstrap,
            participation_tx,
            genesis_offset_ms,
            shards: HashMap::new(),
            bootstrapping: HashMap::new(),
            observers: HashMap::new(),
            pending_observer_joins: HashMap::new(),
            keepers: HashMap::new(),
            epoch_duration_ms,
            draining: HashSet::new(),
            pending_joins: HashMap::new(),
            pool: None,
            beacon_event_rx,
            vnode_keys,
            events_tx,
            events_rx: Some(events_rx),
        }
    }

    /// Take the background-event receiver. The runner's `run()` loop
    /// drains it into [`Self::on_event`].
    pub(crate) const fn take_events_rx(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<SupervisorEvent>> {
        self.events_rx.take()
    }

    /// Settle one background-work completion.
    pub(crate) fn on_event(&mut self, event: SupervisorEvent) {
        match event {
            SupervisorEvent::Opened {
                shard,
                vnodes,
                outcome,
            } => self.on_opened(shard, vnodes, outcome),
            SupervisorEvent::Bootstrapped(done) => self.finish_join(done),
            SupervisorEvent::Observed(done) => self.finish_observation(done),
            SupervisorEvent::SplitAdopted(done) => self.finish_adoption(done),
            SupervisorEvent::ObserverPrepared(done) => self.finish_observer_preparation(done),
            SupervisorEvent::KeeperPrepared(done) => self.finish_keeper_preparation(done),
            SupervisorEvent::TornDown {
                shard,
                validator_ids,
            } => self.on_torn_down(shard, &validator_ids),
        }
    }

    /// Spawn a startup shard's pinned thread and record it. Used by the
    /// runner for the shards composed into the `NodeHost` at build time,
    /// which arrive with their channels and genesis timer ops already
    /// prepared.
    pub(crate) fn spawn_recorded(
        &mut self,
        shard_loop: ProdShardLoop,
        channels: ShardChannels,
        initial_timer_ops: Vec<TimerOp>,
        vnode_count: usize,
    ) {
        let shard = shard_loop.shard;
        let shutdown_tx = channels.shutdown_tx.clone();
        let validator_ids = shard_loop
            .vnodes
            .iter()
            .map(|v| v.validator_id.inner())
            .collect();
        for vnode in &shard_loop.vnodes {
            self.process.assign_beacon_signer(vnode.validator_id, shard);
        }
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                vnode_count,
                validator_ids,
            },
        );
    }

    /// Spawn the host's beacon-follower pool thread from a pre-built
    /// `PoolLoop` — the startup pooled host (a registered-but-unseated
    /// validator). A pool already running is left in place.
    pub(crate) fn install_pool(&mut self, pool: ProdPoolLoop) {
        if self.pool.is_some() {
            warn!("install_pool called while a pool thread already runs; ignored");
            return;
        }
        self.start_pool_thread(pool);
    }

    /// Spawn a pinned thread for `pool`, recording its handle and follower
    /// set. The thread drains a clone of the host's beacon channel; the
    /// host-level gossip handler pushes committed beacon blocks onto the
    /// paired sender.
    fn start_pool_thread(&mut self, pool: ProdPoolLoop) {
        let validators: Vec<ValidatorId> = pool.vnodes.iter().map(|v| v.validator_id).collect();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let cfg = PoolLoopConfig {
            beacon_rx: self.beacon_event_rx.clone(),
            shutdown_rx,
            participation_tx: self.participation_tx.clone(),
            genesis_offset_ms: self.genesis_offset_ms,
        };
        let join = spawn_pool_loop(pool, cfg);
        self.pool = Some(PoolThread {
            join,
            shutdown_tx,
            validators,
        });
        // The thread is now draining the host's beacon channel; let the
        // host-level gossip handler route committed blocks to it.
        self.process.set_beacon_route_active(true);
    }

    /// Stop the pool thread if one runs, joining it.
    fn teardown_pool(&mut self) {
        if let Some(pt) = self.pool.take() {
            // Stop routing before the drain ends so the channel can't back
            // up between the shutdown signal and the thread's exit.
            self.process.set_beacon_route_active(false);
            let _ = pt.shutdown_tx.send(());
            if pt.join.join().is_err() {
                warn!("Pool thread panicked before teardown");
            }
        }
    }

    /// Rebuild the pool thread to follow exactly `validators`: tear the
    /// current thread down, and — unless the set is now empty — build a
    /// fresh follower per validator from the host's warm beacon storage and
    /// spawn a new thread. Tearing down and rebuilding (rather than mutating
    /// a running thread) keeps the follower set a single owned value; a
    /// follower resumes cheaply from the warm storage tip.
    fn rebuild_pool(&mut self, validators: &[ValidatorId]) {
        self.teardown_pool();
        if validators.is_empty() {
            return;
        }
        let vnodes: Vec<_> = validators
            .iter()
            .filter_map(|&validator| self.build_follower(validator))
            .map(VnodeInit::into_vnode)
            .collect();
        if vnodes.is_empty() {
            return;
        }
        let pool = PoolLoop::new(Arc::clone(&self.process), vnodes);
        self.start_pool_thread(pool);
    }

    /// Build one shard-less follower for `validator` from the host's warm
    /// beacon storage. `None` when the validator has no local signing key
    /// (it isn't ours to follow for).
    fn build_follower(&self, validator: ValidatorId) -> Option<VnodeInit> {
        let signing_key = self.vnode_keys.get(&validator).cloned().or_else(|| {
            warn!(
                validator = validator.inner(),
                "No local signing key for a drained validator; not following it"
            );
            None
        })?;
        Some(seat_follower(SeatFollower {
            beacon_storage: self.process.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: consensus_clock(self.genesis_offset_ms),
            validator,
            signing_key,
        }))
    }

    /// Begin following the beacon for `validator` in the pool — it drained
    /// off its last shard and would otherwise go dark, never raising its own
    /// re-seat trigger. No-op if it is already a follower.
    fn follow_in_pool(&mut self, validator: ValidatorId) {
        let mut validators = self
            .pool
            .as_ref()
            .map(|p| p.validators.clone())
            .unwrap_or_default();
        if validators.contains(&validator) {
            return;
        }
        validators.push(validator);
        self.rebuild_pool(&validators);
        info!(
            validator = validator.inner(),
            "Following the beacon in the pool after draining off the last shard"
        );
    }

    /// Drop `validator` from the pool — it was seated onto a shard, so its
    /// shard vnode now drives its beacon. No-op if it isn't a follower; the
    /// pool thread tears down once its last follower leaves.
    fn unfollow_in_pool(&mut self, validator: ValidatorId) {
        let Some(pool) = self.pool.as_ref() else {
            return;
        };
        if !pool.validators.contains(&validator) {
            return;
        }
        let validators: Vec<ValidatorId> = pool
            .validators
            .iter()
            .copied()
            .filter(|&v| v != validator)
            .collect();
        self.rebuild_pool(&validators);
    }

    /// Whether `validator` runs a vnode on any shard this host still hosts.
    fn validator_on_any_shard(&self, validator: ValidatorId) -> bool {
        let id = validator.inner();
        self.shards.values().any(|t| t.validator_ids.contains(&id))
    }

    /// Execute one membership command.
    pub(crate) fn handle(&mut self, command: ShardCommand) {
        match command {
            ShardCommand::Join {
                shard,
                vnodes,
                adoption,
            } => match adoption {
                Some(adoption) => self.join_split_child(shard, &vnodes, adoption),
                None => self.join(shard, &vnodes),
            },
            ShardCommand::Leave { shard } => self.leave(shard),
            ShardCommand::Observe {
                via,
                child,
                validator,
                signing_key,
            } => self.observe(via, child, validator, &signing_key),
            ShardCommand::Unobserve { child } => self.unobserve(child),
            ShardCommand::Keep {
                parent,
                own_child,
                validator,
                signing_key,
            } => self.keep(parent, own_child, validator, &signing_key),
            ShardCommand::Unkeep { parent, validator } => self.unkeep(parent, validator),
        }
    }

    /// Bring up `shard`: open its storage off this loop, then continue
    /// in [`Self::on_opened`] — seat directly for a retained store or a
    /// genesis replay, or snap-sync against the beacon-attested anchor
    /// first. A join for a shard still tearing down queues and replays
    /// once the teardown finishes.
    fn join(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.shards.contains_key(&shard) || self.bootstrapping.contains_key(&shard) {
            warn!(shard = ?shard, "Join rejected: shard already hosted or bootstrapping");
            return;
        }
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != shard) {
            warn!(shard = ?shard, "Join rejected: vnodes must be non-empty and target the shard");
            return;
        }
        if self.draining.contains(&shard) {
            info!(shard = ?shard, "Join queued behind the shard's in-flight teardown");
            if self.pending_joins.insert(shard, vnodes.to_vec()).is_some() {
                warn!(shard = ?shard, "Replaced an earlier queued join for the shard");
            }
            return;
        }

        // A merge keeper duty owns this parent: the merge has executed, so
        // seat every local member from the boundary handoff's store (or
        // park until it finishes building) instead of snap-syncing. The
        // duty's members drive the seating; this join's vnode is one of
        // them, so it needs no separate handling.
        if self.keepers.contains_key(&shard) {
            self.seat_or_park_keeper(shard);
            return;
        }

        // The RocksDB open (and a previously-used store's recovery
        // read) can stall on disk; run it off the loop and continue in
        // `on_opened`. The `bootstrapping` entry blocks double joins
        // and lets a `Leave` during the open release memberships.
        self.bootstrapping.insert(shard, vnodes.len());
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = factory(shard).map(|storage| {
                let recovered = storage.load_recovered_state();
                // A brand-new store (no commits, no imported JMT) gets
                // the engine bootstrap before the snap-sync import or
                // the from-genesis replay populates it.
                if recovered.committed_height == BlockHeight::GENESIS
                    && recovered.jmt_root.is_none()
                {
                    engine_bootstrap.replicate_into(storage.as_ref());
                }
                (storage, recovered)
            });
            // Send failure means the runner is shutting down; the join
            // dies with it.
            let _ = events.send(SupervisorEvent::Opened {
                shard,
                vnodes,
                outcome,
            });
        });
    }

    /// Bring up a freshly split child this host was pre-staffed for.
    ///
    /// Both adoption paths first wait for the flip to become actionable:
    /// the beacon's child anchor projecting (the fold consumed the
    /// parent's terminal contribution) and, for a parent-half member,
    /// the locally hosted parent chain reaching its terminal commit.
    /// The parent half then seeds the child directory from a checkpoint
    /// hard-link and adopts the subtree; an observer's synced store
    /// cannot yet follow the parent to its crossing, so its stale store
    /// is wiped and the join falls back to a snap-sync bootstrap against
    /// the now-projected child anchor.
    fn join_split_child(
        &mut self,
        child: ShardId,
        vnodes: &[VnodeConfig],
        adoption: SplitAdoption,
    ) {
        if self.shards.contains_key(&child) || self.bootstrapping.contains_key(&child) {
            warn!(shard = ?child, "Split join rejected: child already hosted or bootstrapping");
            return;
        }
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != child) {
            warn!(shard = ?child, "Split join rejected: vnodes must be non-empty and target the child");
            return;
        }
        self.bootstrapping.insert(child, vnodes.len());
        let vnodes = vnodes.to_vec();
        match adoption {
            SplitAdoption::ParentHalf { parent } => {
                let process = Arc::clone(&self.process);
                let events = self.events_tx.clone();
                let factory = Arc::clone(&self.storage_factory);
                let storage_dir = Arc::clone(&self.storage_dir);
                let parent_storage = self
                    .storages
                    .lock()
                    .expect("storages lock")
                    .get(&parent)
                    .cloned();
                let Some(parent_storage) = parent_storage else {
                    warn!(shard = ?child, ?parent, "Split join without a hosted parent store; abandoned");
                    self.bootstrapping.remove(&child);
                    return;
                };
                self.tokio_handle.spawn(async move {
                    let anchor = wait_for_child_anchor(&process, child).await;
                    let done = spawn_blocking(move || {
                        adopt_from_parent(&parent_storage, &factory, &storage_dir, child, &anchor)
                            .map(|(storage, genesis, recovered)| {
                                Box::new(CompletedAdoption {
                                    child,
                                    vnodes,
                                    storage,
                                    genesis,
                                    recovered,
                                })
                            })
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("adoption task panicked: {e}")));
                    let done = done.map_err(|error| {
                        warn!(shard = ?child, error, "Split adoption failed; join abandoned");
                        child
                    });
                    // Send failure means the runner is shutting down.
                    let _ = events.send(SupervisorEvent::SplitAdopted(done));
                });
            }
            SplitAdoption::Observer { .. } => {
                if let Some(duty) = self.observers.get_mut(&child) {
                    if let Some(prepared) = duty.prepared.take() {
                        self.observers.remove(&child);
                        self.bootstrapping.remove(&child);
                        if self.shards.contains_key(&child) {
                            warn!(shard = ?child, "Observer flip for an already-hosted shard; dropped");
                            return;
                        }
                        self.seat_shard_with_genesis(
                            child,
                            &vnodes,
                            prepared.storage,
                            &prepared.recovered,
                            Some(&prepared.genesis),
                        );
                    } else {
                        // The duty is still following the parent to its
                        // crossing; the join parks and
                        // `finish_observer_preparation` seats it.
                        info!(shard = ?child, "Split join parked on the observer duty's boundary handoff");
                        self.pending_observer_joins.insert(child, vnodes);
                    }
                    return;
                }
                // No duty survives for the child — it failed or was
                // abandoned — so the flip falls back to a fresh
                // snap-sync against the now-projected child anchor.
                self.spawn_observer_fallback(child, vnodes);
            }
        }
    }

    /// The observer flip's fallback: no followed store exists, so the
    /// stale directory is wiped and the join snap-syncs fresh against
    /// the child anchor — correct, slower.
    fn spawn_observer_fallback(&self, child: ShardId, vnodes: Vec<VnodeConfig>) {
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let dir = (self.storage_dir)(child);
        self.tokio_handle.spawn(async move {
            let _anchor = wait_for_child_anchor(&process, child).await;
            let done = spawn_blocking(move || -> Result<Arc<RocksDbShardStorage>, String> {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("stale observer store wipe: {e}"))?;
                }
                let storage = factory(child)?;
                engine_bootstrap.replicate_into(storage.as_ref());
                Ok(storage)
            })
            .await
            .unwrap_or_else(|e| Err(format!("observer reopen task panicked: {e}")));
            let done = match done {
                Ok(storage) => {
                    match bootstrap_shard_state(process.network(), process.topology(), &storage, child)
                        .await
                    {
                        Ok(recovered) => Ok(CompletedBootstrap {
                            shard: child,
                            vnodes,
                            storage,
                            recovered,
                        }),
                        Err(error) => {
                            warn!(shard = ?child, error, "Observer flip bootstrap failed; join abandoned");
                            Err(child)
                        }
                    }
                }
                Err(error) => {
                    warn!(shard = ?child, error, "Observer flip reopen failed; join abandoned");
                    Err(child)
                }
            };
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Bootstrapped(done));
        });
    }

    /// Settle an observer duty's boundary handoff: seat a parked join
    /// with the prepared store, stash the preparation for a join still
    /// to come, or — on failure — fall back to a fresh snap-sync for a
    /// parked join.
    fn finish_observer_preparation(&mut self, done: Result<Box<PreparedObserverFlip>, ShardId>) {
        match done {
            Ok(prepared) => {
                let child = prepared.child;
                if !self.observers.contains_key(&child) {
                    info!(shard = ?child, "Observer handoff prepared for an abandoned duty; dropped");
                    return;
                }
                if let Some(vnodes) = self.pending_observer_joins.remove(&child) {
                    self.observers.remove(&child);
                    let Some(pending) = self.bootstrapping.remove(&child) else {
                        info!(shard = ?child, "Observer handoff prepared for an abandoned join; dropped");
                        return;
                    };
                    if self.shards.contains_key(&child) {
                        warn!(shard = ?child, "Observer handoff prepared for an already-hosted shard; dropped");
                        return;
                    }
                    self.seat_shard_with_genesis(
                        child,
                        &vnodes[..pending.min(vnodes.len())],
                        prepared.storage,
                        &prepared.recovered,
                        Some(&prepared.genesis),
                    );
                } else {
                    let duty = self
                        .observers
                        .get_mut(&child)
                        .expect("duty presence checked above");
                    duty.task = None;
                    duty.prepared = Some(prepared);
                }
            }
            Err(child) => {
                // The follow or adoption failed closed; the handoff
                // falls back to a fresh snap-sync. A parked join runs it
                // now; otherwise the join takes the fallback path when
                // it arrives (the duty entry is gone).
                self.observers.remove(&child);
                if let Some(vnodes) = self.pending_observer_joins.remove(&child) {
                    self.spawn_observer_fallback(child, vnodes);
                }
            }
        }
    }

    /// Settle a finished split adoption: install the derived genesis on
    /// the seated child and start consensus, or clear the bootstrapping
    /// entry so a later placement delta can retry.
    fn finish_adoption(&mut self, done: Result<Box<CompletedAdoption>, ShardId>) {
        let child = match &done {
            Ok(done) => done.child,
            Err(child) => *child,
        };
        let Some(pending) = self.bootstrapping.remove(&child) else {
            info!(shard = ?child, "Adoption finished for an abandoned join; dropped");
            return;
        };
        let Ok(done) = done else {
            // Failure already logged by the adoption task.
            return;
        };
        if self.shards.contains_key(&child) {
            warn!(shard = ?child, "Adoption completed for an already-hosted shard; dropped");
            return;
        }
        self.seat_shard_with_genesis(
            child,
            &done.vnodes[..pending.min(done.vnodes.len())],
            done.storage,
            &done.recovered,
            Some(&done.genesis),
        );
    }

    /// Continue a join whose storage open finished.
    ///
    /// Three paths by what the store and the beacon offer:
    /// - **retained storage** (committed height > 0) — seat directly;
    ///   normal block sync covers the tail;
    /// - **fresh store, attested anchor** — snap-sync bootstrap off
    ///   this loop (a tokio task), seated via [`Self::finish_join`]
    ///   when the import verifies against the anchor;
    /// - **fresh store, no anchor** — seat directly and replay from
    ///   genesis through block sync.
    fn on_opened(
        &mut self,
        shard: ShardId,
        mut vnodes: Vec<VnodeConfig>,
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    ) {
        let Some(pending) = self.bootstrapping.get(&shard).copied() else {
            info!(shard = ?shard, "Storage opened for an abandoned join; dropped");
            return;
        };
        let (storage, recovered) = match outcome {
            Ok(opened) => opened,
            Err(error) => {
                self.bootstrapping.remove(&shard);
                warn!(shard = ?shard, error, "Join rejected: storage open failed");
                return;
            }
        };
        // Leaves during the open released memberships from the tail.
        vnodes.truncate(pending);

        let fresh_store = recovered.committed_height == BlockHeight::GENESIS;
        let anchor = self.process.topology().load().boundary(shard);
        if fresh_store && anchor.is_some() {
            let process = Arc::clone(&self.process);
            let events = self.events_tx.clone();
            self.tokio_handle.spawn(async move {
                let done = match bootstrap_shard_state(
                    process.network(),
                    process.topology(),
                    &storage,
                    shard,
                )
                .await
                {
                    Ok(recovered) => Ok(CompletedBootstrap {
                        shard,
                        vnodes,
                        storage,
                        recovered,
                    }),
                    Err(error) => {
                        warn!(shard = ?shard, error, "Shard bootstrap failed; join abandoned");
                        Err(shard)
                    }
                };
                // Send failure means the runner is shutting down; the
                // join dies with it.
                let _ = events.send(SupervisorEvent::Bootstrapped(done));
            });
            return;
        }
        self.bootstrapping.remove(&shard);
        self.seat_shard(shard, &vnodes, storage, &recovered);
    }

    /// Settle a finished bootstrap: seat the shard on success, clear
    /// the bootstrapping entry on failure (so a later placement delta
    /// can retry the join), drop the outcome when every pending vnode
    /// left during the bootstrap. Runs on the runner's loop via the
    /// completion channel — never on the bootstrap task.
    fn finish_join(&mut self, done: Result<CompletedBootstrap, ShardId>) {
        let shard = match &done {
            Ok(done) => done.shard,
            Err(shard) => *shard,
        };
        let Some(pending) = self.bootstrapping.remove(&shard) else {
            info!(shard = ?shard, "Bootstrap finished for an abandoned join; dropped");
            return;
        };
        let Ok(done) = done else {
            // Failure already logged by the bootstrap task.
            return;
        };
        if self.shards.contains_key(&shard) {
            warn!(shard = ?shard, "Bootstrap completed for an already-hosted shard; dropped");
            return;
        }
        self.seat_shard(
            shard,
            &done.vnodes[..pending],
            done.storage,
            &done.recovered,
        );
    }

    /// Begin an observer duty: open a fresh child-rooted store and run
    /// the duty pipeline off this loop — the child-span sync and ready
    /// signal ([`Self::finish_observation`]), then the stay-current
    /// follow of the splitting shard's chain to its crossing and the
    /// boundary handoff's adoption
    /// ([`Self::finish_observer_preparation`]).
    fn observe(
        &mut self,
        via: ShardId,
        child: ShardId,
        validator: ValidatorId,
        signing_key: &Arc<Bls12381G1PrivateKey>,
    ) {
        if self.observers.contains_key(&child) {
            warn!(?child, "Observe rejected: duty already running");
            return;
        }
        if self.shards.contains_key(&child) {
            warn!(?child, "Observe rejected: child already hosted");
            return;
        }
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let dir = (self.storage_dir)(child);
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let beacon_network = self.beacon_network.clone();
        let signing_key = Arc::clone(signing_key);
        let epoch_duration_ms = self.epoch_duration_ms;
        let task = self.tokio_handle.spawn(async move {
            // A leftover directory — an abandoned earlier duty or a
            // failed flip — holds state synced against a stale anchor;
            // a fresh duty starts from a fresh store.
            let opened = spawn_blocking(move || -> Result<Arc<RocksDbShardStorage>, String> {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("stale observer store wipe: {e}"))?;
                }
                let storage = factory(child)?;
                engine_bootstrap.replicate_into(storage.as_ref());
                Ok(storage)
            })
            .await;
            let storage = match opened {
                Ok(Ok(storage)) => storage,
                Ok(Err(error)) => {
                    warn!(?child, error, "Observer duty rejected: storage open failed");
                    let _ = events.send(SupervisorEvent::Observed(Err(child)));
                    return;
                }
                Err(error) => {
                    warn!(?child, %error, "Observer duty's storage open panicked");
                    let _ = events.send(SupervisorEvent::Observed(Err(child)));
                    return;
                }
            };
            let (anchor, root, substate_bytes) = match bootstrap_observer_state(
                process.network(),
                process.topology(),
                &storage,
                via,
                child,
            )
            .await
            {
                Ok(synced) => synced,
                Err(error) => {
                    warn!(?via, ?child, error, "Observer duty failed");
                    let _ = events.send(SupervisorEvent::Observed(Err(child)));
                    return;
                }
            };
            // Sync complete: tell the splitting shard's committee, where
            // the signal classifies as a ReshapeReady witness leaf and
            // folds into the split's readiness gate.
            let identity = ObserverReadyIdentity {
                beacon_network,
                validator,
                signing_key,
                epoch_duration_ms,
            };
            reassert_observer_ready(&process, &identity, via, anchor);
            // Send failure means the runner is shutting down; the duty
            // dies with it.
            let _ = events.send(SupervisorEvent::Observed(Ok(CompletedObservation {
                child,
                root,
                substate_bytes,
            })));

            // Stay current: follow the parent's chain to its crossing,
            // re-asserting the ready signal each round, then adopt the
            // followed store for the boundary handoff.
            let done =
                prepare_observer_flip(&process, &identity, storage, via, child, anchor, root)
                    .await
                    .map_err(|error| {
                        warn!(?via, ?child, error, "Observer boundary handoff failed");
                        child
                    });
            let _ = events.send(SupervisorEvent::ObserverPrepared(done));
        });
        self.observers.insert(
            child,
            ObserverDuty {
                via,
                validator,
                task: Some(task),
                synced: None,
                prepared: None,
            },
        );
    }

    /// Settle a finished observer duty. A failure drops the registry
    /// entry — re-admission of the split re-issues the duty.
    fn finish_observation(&mut self, done: Result<CompletedObservation, ShardId>) {
        match done {
            Ok(observation) => {
                let Some(duty) = self.observers.get_mut(&observation.child) else {
                    info!(
                        child = ?observation.child,
                        "Observation completed for an abandoned duty; dropped"
                    );
                    return;
                };
                info!(
                    via = ?duty.via,
                    child = ?observation.child,
                    validator = duty.validator.inner(),
                    root = ?observation.root,
                    substates = observation.substate_bytes,
                    "Observer duty complete; ready signal broadcast"
                );
                // The duty task continues into the stay-current follow;
                // its handle stays for `Unobserve` to abort.
                duty.synced = Some(observation.root);
            }
            Err(child) => {
                self.observers.remove(&child);
            }
        }
    }

    /// Abandon an observer duty: abort an in-flight sync, drop the
    /// registry entry. The child store's directory stays on disk.
    fn unobserve(&mut self, child: ShardId) {
        let Some(duty) = self.observers.remove(&child) else {
            warn!(?child, "Unobserve rejected: no duty for the child");
            return;
        };
        if let Some(task) = duty.task {
            task.abort();
        }
        info!(
            via = ?duty.via,
            ?child,
            validator = duty.validator.inner(),
            synced = duty.synced.is_some(),
            "Observer duty abandoned"
        );
    }

    /// Enrol a keeper seat for `parent`: re-broadcast the ready signal on
    /// `own_child`'s committee (where it classifies as a `ReshapeReady`
    /// witness leaf and folds into the merge readiness gate), and — for
    /// the first seat — build the merged parent store at the boundary.
    /// A host holding seats on both children enrols a member per child;
    /// they share one duty, one parent store, and one boundary handoff,
    /// each member signalling readiness on its own child's committee.
    fn keep(
        &mut self,
        parent: ShardId,
        own_child: ShardId,
        validator: ValidatorId,
        signing_key: &Arc<Bls12381G1PrivateKey>,
    ) {
        if self.shards.contains_key(&parent) {
            warn!(?parent, "Keep rejected: merged parent already hosted");
            return;
        }
        let member = KeeperMember {
            validator,
            own_child,
            signing_key: Arc::clone(signing_key),
        };
        // A second local seat on the same merge joins the running duty:
        // the next re-assert round signals for it, and it seats on the
        // shared parent store the first member's handoff builds.
        if let Some(duty) = self.keepers.get(&parent) {
            {
                let mut members = duty.members.lock().expect("keeper members lock");
                if !members.iter().any(|m| m.validator == validator) {
                    members.push(member);
                }
            }
            return;
        }

        let members = Arc::new(Mutex::new(vec![member]));
        // Grab whichever children's stores this host runs (one or both);
        // the boundary handoff reads each terminated half from the local
        // store when present and snap-syncs it only when it doesn't.
        let (left, right) = parent.children();
        let child_stores = {
            let storages = self.storages.lock().expect("storages lock");
            ChildStores {
                left: storages.get(&left).cloned(),
                right: storages.get(&right).cloned(),
            }
        };
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let beacon_network = self.beacon_network.clone();
        let factory = Arc::clone(&self.storage_factory);
        let storage_dir = Arc::clone(&self.storage_dir);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let epoch_duration_ms = self.epoch_duration_ms;
        let task_members = Arc::clone(&members);
        let task = self.tokio_handle.spawn(async move {
            // Re-assert each member's ready signal on its own child's
            // committee until the merge executes (the parent anchor
            // composes). The keeper seat promotes into the active
            // reshape-keeper window only a window after pairing, so a
            // single early signal classifies as a plain Ready leaf and
            // never fires the gate; re-signing each round lands a
            // recognized ReshapeReady once the seat is active. `unkeep`
            // aborts this task once its last member leaves.
            loop {
                let topology = process.topology().load_full();
                let snapshot: Vec<KeeperMember> =
                    task_members.lock().expect("keeper members lock").clone();
                for member in &snapshot {
                    let Some(anchor) = topology.boundary(member.own_child) else {
                        continue;
                    };
                    let signal = observer_ready_signal(
                        &beacon_network,
                        member.validator,
                        &member.signing_key,
                        anchor,
                        epoch_duration_ms,
                    );
                    let recipients: Vec<ValidatorId> = topology
                        .committee_for_shard(member.own_child)
                        .iter()
                        .copied()
                        .filter(|&v| v != member.validator)
                        .collect();
                    process
                        .network()
                        .notify(&recipients, &ReadySignalNotification::new(signal));
                }
                if process.topology().load().boundary(parent).is_some() {
                    break;
                }
                sleep(KEEPER_READY_REASSERT_INTERVAL).await;
            }

            // Boundary handoff: build the merged parent store from both
            // terminated halves and adopt the deterministic genesis.
            let done = prepare_merge_flip(
                &process,
                child_stores,
                &factory,
                &storage_dir,
                &engine_bootstrap,
                parent,
                epoch_duration_ms,
            )
            .await
            .map_err(|error| {
                warn!(?parent, error, "Keeper boundary handoff failed");
                parent
            });
            let _ = events.send(SupervisorEvent::KeeperPrepared(done));
        });
        self.keepers.insert(
            parent,
            KeeperDuty {
                members,
                task: Some(task),
                prepared: None,
                seat_requested: false,
            },
        );
    }

    /// Abandon one keeper seat: drop the member, and tear the duty down
    /// only when its last member leaves (aborting an in-flight build).
    /// Any half-built parent directory is wiped by a later re-`Keep` or
    /// the fallback join's fresh open.
    fn unkeep(&mut self, parent: ShardId, validator: ValidatorId) {
        let Some(duty) = self.keepers.get(&parent) else {
            warn!(?parent, "Unkeep rejected: no duty for the parent");
            return;
        };
        let empty = {
            let mut members = duty.members.lock().expect("keeper members lock");
            members.retain(|m| m.validator != validator);
            members.is_empty()
        };
        if !empty {
            info!(
                ?parent,
                validator = validator.inner(),
                "Keeper seat abandoned; duty continues for its other members"
            );
            return;
        }
        let duty = self
            .keepers
            .remove(&parent)
            .expect("presence checked above");
        if let Some(task) = duty.task {
            task.abort();
        }
        info!(?parent, "Keeper duty abandoned: last member left");
    }

    /// Settle a keeper duty's boundary handoff: seat every local member on
    /// the prepared parent store if the merge has executed, stash the
    /// preparation until it does, or — on failure — fall back to a fresh
    /// snap-sync for a merge that already executed.
    fn finish_keeper_preparation(&mut self, done: Result<Box<PreparedMergeFlip>, ShardId>) {
        match done {
            Ok(prepared) => {
                let parent = prepared.parent;
                let Some(duty) = self.keepers.get_mut(&parent) else {
                    info!(
                        ?parent,
                        "Keeper handoff prepared for an abandoned duty; dropped"
                    );
                    return;
                };
                duty.task = None;
                duty.prepared = Some(prepared);
                if duty.seat_requested {
                    self.seat_keeper_members(parent);
                }
            }
            Err(parent) => {
                // The build failed closed; drop the duty. If the merge
                // already executed, the members fall back to a fresh
                // snap-sync against the parent's committee (other keepers
                // that succeeded serve it). Otherwise the entry just
                // drops; a join still to come takes the normal path.
                let Some(duty) = self.keepers.remove(&parent) else {
                    return;
                };
                if duty.seat_requested {
                    let vnodes = keeper_vnodes(&duty, parent);
                    self.join(parent, &vnodes);
                }
            }
        }
    }

    /// A merge-execution `Join` landed for `parent`: seat every local
    /// member on the keeper duty's prepared parent store now, or record
    /// the request so the boundary handoff seats them when it finishes.
    fn seat_or_park_keeper(&mut self, parent: ShardId) {
        let duty = self
            .keepers
            .get_mut(&parent)
            .expect("keeper presence checked by the caller");
        duty.seat_requested = true;
        if duty.prepared.is_some() {
            self.seat_keeper_members(parent);
        } else {
            info!(
                ?parent,
                "Merge join parked on the keeper duty's boundary handoff"
            );
        }
    }

    /// Seat every local member of a prepared keeper duty on the one merged
    /// parent store and retire the duty.
    fn seat_keeper_members(&mut self, parent: ShardId) {
        let duty = self.keepers.remove(&parent).expect("keeper presence");
        if let Some(task) = &duty.task {
            task.abort();
        }
        if self.shards.contains_key(&parent) {
            warn!(?parent, "Keeper flip for an already-hosted shard; dropped");
            return;
        }
        let vnodes = keeper_vnodes(&duty, parent);
        let prepared = duty.prepared.expect("prepared checked by the caller");
        self.seat_shard_with_genesis(
            parent,
            &vnodes,
            prepared.storage,
            &prepared.recovered,
            Some(&prepared.genesis),
        );
    }

    /// Wire a shard's vnodes into the process maps and spawn its pinned
    /// thread, booting the state machines from `recovered`.
    fn seat_shard(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
    ) {
        self.seat_shard_with_genesis(shard, vnodes, storage, recovered, None);
    }

    /// [`Self::seat_shard`] with an optional pre-spawn genesis install —
    /// a split child's flip commits its derived genesis through the
    /// freshly attached loop before the thread spawns, exactly the
    /// startup runners' network-genesis sequence.
    fn seat_shard_with_genesis(
        &mut self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        storage: Arc<RocksDbShardStorage>,
        recovered: &RecoveredState,
        genesis: Option<&Block>,
    ) {
        let inits = self.build_vnode_inits(shard, vnodes, recovered);
        let vnode_count = inits.len();
        // Seat the beacon-signing registry before the loop can emit:
        // first assign wins, so a flip child or relocation joiner whose
        // validator already signs elsewhere is born passive.
        for cfg in vnodes {
            self.process.assign_beacon_signer(cfg.validator_id, shard);
        }

        let (timer_tx, timer_rx) = unbounded();
        let (callback_tx, callback_rx) = unbounded();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let mut shard_loop = attach_shard(
            &self.process,
            &self.node_config,
            inits,
            SharedStorage::new(Arc::clone(&storage)),
            callback_tx,
        );
        shard_loop.set_time(consensus_clock(self.genesis_offset_ms));
        // The genesis commit arms the pacemaker; capture its timer ops so the
        // spawned loop arms them as its initial ops rather than dropping them.
        let initial_timer_ops =
            genesis.map_or_else(Vec::new, |genesis| shard_loop.install_genesis(genesis));

        self.storages
            .lock()
            .expect("storages lock")
            .insert(shard, storage);

        let channels = ShardChannels {
            timer_tx,
            timer_rx,
            callback_rx,
            shutdown_tx: shutdown_tx.clone(),
            shutdown_rx,
        };
        let validator_ids = vnodes.iter().map(|v| v.validator_id.inner()).collect();
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                vnode_count,
                validator_ids,
            },
        );
        // A seated validator now drives its beacon from this shard's thread,
        // so retire its pool follower if it had one (it drained here from a
        // prior shard, or started pooled and was just drawn into a committee).
        for cfg in vnodes {
            self.unfollow_in_pool(cfg.validator_id);
        }
        info!(shard = ?shard, vnodes = vnode_count, "Shard joined at runtime");
    }

    /// Release one vnode's membership; tear the shard down at zero. A
    /// leave that lands while the shard's join is still bootstrapping
    /// releases a pending membership instead, abandoning the join when
    /// the last one goes.
    fn leave(&mut self, shard: ShardId) {
        if let Some(pending) = self.bootstrapping.get_mut(&shard) {
            *pending -= 1;
            let remaining = *pending;
            if remaining == 0 {
                self.bootstrapping.remove(&shard);
                info!(shard = ?shard, "Last pending vnode left during bootstrap; join abandoned");
            } else {
                info!(
                    shard = ?shard,
                    remaining,
                    "Vnode left during bootstrap; join continues for remaining vnodes"
                );
            }
            return;
        }
        let Some(entry) = self.shards.get_mut(&shard) else {
            warn!(shard = ?shard, "Leave rejected: shard not hosted");
            return;
        };
        entry.vnode_count = entry.vnode_count.saturating_sub(1);
        if entry.vnode_count > 0 {
            info!(
                shard = ?shard,
                remaining = entry.vnode_count,
                "Vnode left; shard stays up for remaining local vnodes"
            );
            return;
        }
        let entry = self
            .shards
            .remove(&shard)
            .expect("entry fetched above still present");
        let _ = entry.shutdown_tx.send(());
        // The thread join waits out an in-flight shard step; run it off
        // the loop and finish the unwire in `on_torn_down`.
        self.draining.insert(shard);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            if entry.join.join().is_err() {
                warn!(shard = ?shard, "Shard thread panicked before teardown");
            }
            // Send failure means the runner is shutting down; the
            // teardown finishes with it.
            let _ = events.send(SupervisorEvent::TornDown {
                shard,
                validator_ids: entry.validator_ids,
            });
        });
    }

    /// Finish a teardown whose thread joined: unwire the process maps,
    /// drop the storage handle, scrub the RPC slots, and replay any
    /// join that queued behind the drain.
    fn on_torn_down(&mut self, shard: ShardId, validator_ids: &[u64]) {
        detach_shard(&self.process, shard);
        self.storages.lock().expect("storages lock").remove(&shard);
        self.scrub_rpc_state(shard, validator_ids);
        self.draining.remove(&shard);
        // The thread is joined — the dead vnodes can never emit again.
        // Releasing their seats lets each validator's surviving vnode
        // claim beacon signing at the funnel's epoch fence.
        for id in validator_ids {
            self.process
                .release_beacon_signer(ValidatorId::new(*id), shard);
        }
        info!(shard = ?shard, "Shard left and torn down");
        // A departed validator that runs no other shard would go dark — no
        // vnode to fold the beacon and raise its own re-seat trigger. Keep
        // it following in the pool instead; the host's beacon storage stays
        // warm for the eventual re-seat. A relocation that already seated
        // the destination leaves the validator on that shard, so it is not
        // pooled; a race that pools it is undone when the seat lands.
        for &id in validator_ids {
            let validator = ValidatorId::new(id);
            if !self.validator_on_any_shard(validator) {
                self.follow_in_pool(validator);
            }
        }
        if let Some(vnodes) = self.pending_joins.remove(&shard) {
            self.join(shard, &vnodes);
        }
    }

    /// Remove a departed shard's slots from the shared RPC state maps.
    /// Each slot is otherwise written only by the shard's own (now
    /// joined) thread, so a stale entry would persist forever — worst
    /// case a mempool slot frozen at `at_pending_limit: true` vetoing
    /// every RPC submission. A vnode still hosted elsewhere (relocation
    /// overlap) republishes its mempool slot on that shard's next tick.
    fn scrub_rpc_state(&self, shard: ShardId, validator_ids: &[u64]) {
        let shard_key = shard.inner();
        if let Some(ref rpc_status) = self.publishers.node_status {
            let mut updated = (**rpc_status.load()).clone();
            updated.vnodes.retain(|v| v.shard != shard_key);
            rpc_status.store(Arc::new(updated));
        }
        if let Some(ref sync_status) = self.publishers.sync_status {
            let mut updated = (**sync_status.load()).clone();
            updated.shards.remove(&shard_key);
            sync_status.store(Arc::new(updated));
        }
        if let Some(ref mempool_snapshot) = self.publishers.mempool {
            let mut updated = (**mempool_snapshot.load()).clone();
            for id in validator_ids {
                updated.vnodes.remove(id);
            }
            mempool_snapshot.store(Arc::new(updated));
        }
    }

    /// Stop every shard thread: fan the shutdown signals first so the
    /// threads wind down in parallel, then join them all. The pool thread,
    /// if any, is stopped alongside them.
    pub(crate) fn shutdown_all(&mut self) {
        self.teardown_pool();
        for (shard, entry) in &self.shards {
            if entry.shutdown_tx.send(()).is_err() {
                tracing::debug!(shard = ?shard, "Shard already exited");
            }
        }
        for (_, entry) in self.shards.drain() {
            if let Err(e) = entry.join.join() {
                warn!("Shard thread panicked: {e:?}");
            }
        }
    }

    fn loop_config(
        &self,
        channels: ShardChannels,
        initial_timer_ops: Vec<TimerOp>,
    ) -> ShardLoopConfig {
        ShardLoopConfig {
            timer_tx: channels.timer_tx,
            timer_rx: channels.timer_rx,
            callback_rx: channels.callback_rx,
            shutdown_rx: channels.shutdown_rx,
            tokio_handle: self.tokio_handle.clone(),
            initial_timer_ops,
            participation_tx: Some(self.participation_tx.clone()),
            publishers: self.publishers.clone(),
            genesis_offset_ms: self.genesis_offset_ms,
        }
    }

    /// Build one `VnodeInit` per joining vnode via [`seat_vnode_group`],
    /// resuming from the host's committed beacon chain and booting from
    /// `recovered`.
    fn build_vnode_inits(
        &self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        recovered: &RecoveredState,
    ) -> Vec<VnodeInit> {
        seat_vnode_group(SeatVnodeGroup {
            beacon_storage: self.process.beacon_storage().as_ref(),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: consensus_clock(self.genesis_offset_ms),
            shard,
            recovered,
            shard_config: &self.shard_config,
            mempool_config: self.mempool_config.clone(),
            provision_config: self.provision_config,
            vnodes: vnodes
                .iter()
                .map(|cfg| (cfg.validator_id, Arc::clone(&cfg.signing_key)))
                .collect(),
        })
    }
}

/// Cadence at which an observer re-asserts its ready signal while it waits
/// for the split to execute — one round per second, matching the merge
/// keeper. The signal's weighted-time window spans two epochs, so a
/// sub-epoch cadence always keeps a live signal in front of the committee.
const OBSERVER_READY_REASSERT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Identity an observer re-asserts its ready signal under, retained for the
/// duty's lifetime so each round re-signs against the freshest anchor.
struct ObserverReadyIdentity {
    beacon_network: NetworkDefinition,
    validator: ValidatorId,
    signing_key: Arc<Bls12381G1PrivateKey>,
    epoch_duration_ms: u64,
}

/// Broadcast an observer's ready signal to the splitting shard's committee,
/// windowed from `anchor`. The signal classifies as a `ReshapeReady`
/// witness leaf there and folds into the split's readiness gate. Re-asserted
/// each round by the observer duty: a freshly drawn observer reaches the
/// committee before its head reflects the cohort, so a single early signal is
/// dropped — re-signing lands once the head catches up.
fn reassert_observer_ready(
    process: &ProdProcessIo,
    identity: &ObserverReadyIdentity,
    via: ShardId,
    anchor: ShardAnchor,
) {
    let signal = observer_ready_signal(
        &identity.beacon_network,
        identity.validator,
        &identity.signing_key,
        anchor,
        identity.epoch_duration_ms,
    );
    let recipients: Vec<ValidatorId> = process
        .topology()
        .load()
        .committee_for_shard(via)
        .iter()
        .copied()
        .filter(|&v| v != identity.validator)
        .collect();
    process
        .network()
        .notify(&recipients, &ReadySignalNotification::new(signal));
}

/// The boundary handoff's preparation, run at the tail of the observer
/// duty task: follow the splitting parent to its crossing, then adopt
/// the followed store at the derived genesis and verify it against the
/// beacon-anchored root.
async fn prepare_observer_flip(
    process: &ProdProcessIo,
    identity: &ObserverReadyIdentity,
    storage: Arc<RocksDbShardStorage>,
    via: ShardId,
    child: ShardId,
    anchor: ShardAnchor,
    root: StateRoot,
) -> Result<Box<PreparedObserverFlip>, String> {
    // Follow the parent to its crossing, re-asserting the ready signal each
    // round meanwhile. A freshly drawn observer sits in the splitting shard's
    // lookahead committee only a window after the draw, so a single early
    // signal — which a cold follower emits the instant its child span
    // finishes syncing — reaches the committee before its head reflects the
    // cohort and is dropped on the floor. Re-signing against the freshest
    // anchor lands a recognized `ReshapeReady` once the head catches up, well
    // inside the readiness TTL (mirrors the merge keeper's re-assertion).
    let (genesis, origin, _) = {
        let follow = follow_observer_store(
            process.network(),
            process.topology(),
            &storage,
            via,
            child,
            anchor,
            root,
        );
        tokio::pin!(follow);
        loop {
            tokio::select! {
                followed = &mut follow => break followed?,
                () = sleep(OBSERVER_READY_REASSERT_INTERVAL) => {
                    if let Some(fresh) = process.topology().load().boundary(via) {
                        reassert_observer_ready(process, identity, via, fresh);
                    }
                }
            }
        }
    };
    spawn_blocking(move || {
        let adopted = storage
            .adopt_followed_child(origin, &genesis)
            .map_err(|e| format!("followed adoption: {e}"))?;
        if adopted != genesis.header().state_root() {
            return Err(format!(
                "followed root {adopted:?} does not match the child anchor {:?}",
                genesis.header().state_root(),
            ));
        }
        let substate_bytes = storage
            .substate_bytes_at_version(origin.genesis_height.inner())
            .unwrap_or(0);
        let recovered = RecoveredState {
            substate_bytes,
            chain_origin: origin,
            ..RecoveredState::default()
        };
        Ok(Box::new(PreparedObserverFlip {
            child,
            storage,
            genesis,
            recovered,
        }))
    })
    .await
    .unwrap_or_else(|e| Err(format!("observer adoption task panicked: {e}")))
}

/// The merged parent's local vnode configs, one per keeper member.
fn keeper_vnodes(duty: &KeeperDuty, parent: ShardId) -> Vec<VnodeConfig> {
    duty.members
        .lock()
        .expect("keeper members lock")
        .iter()
        .map(|m| VnodeConfig {
            validator_id: m.validator,
            local_shard: parent,
            signing_key: Arc::clone(&m.signing_key),
        })
        .collect()
}

/// Collect a terminated merge child's half: serve it from `store` (the
/// local store this host already ran the child to) off the async loop via
/// `spawn_blocking`, falling back to a network sync only when the host
/// doesn't hold the store or it no longer pins the terminal boundary. A
/// host running both children reads both halves locally, so its boundary
/// handoff never competes for the terminated children's serving
/// committees.
async fn collect_child_half(
    process: &ProdProcessIo,
    store: Option<Arc<RocksDbShardStorage>>,
    child: ShardId,
    anchor: ShardAnchor,
) -> Result<Vec<ImportLeaf>, String> {
    if let Some(storage) = store {
        match spawn_blocking(move || collect_half_leaves_local(&storage, child, anchor)).await {
            Ok(Ok(leaves)) => return Ok(leaves),
            Ok(Err(error)) => warn!(
                ?child,
                error, "Local child half read failed; syncing it over the network"
            ),
            Err(e) => return Err(format!("local child read task panicked: {e}")),
        }
    }
    collect_half_leaves(process.network(), process.topology(), child).await
}

/// Build a merge keeper's parent store and adopt its genesis for the
/// boundary handoff.
///
/// Waits for the beacon to compose the merged parent anchor (both
/// children terminated, the fold seeded the parent's genesis record),
/// fetches both children's certified terminals to derive the
/// deterministic merged genesis, reads each terminated half from the
/// local child store when the host runs it (snap-syncing only the halves
/// it doesn't), and unions both into a fresh parent-rooted store — the
/// import rebuilds the merged tree with the composed root by
/// construction. Adoption then records the genesis as the committed tip,
/// fail-closed if the built root or the adopted root disagrees with the
/// beacon's composed anchor.
#[allow(clippy::too_many_arguments)] // threads the process IO, the local child stores, and the store-build handles
async fn prepare_merge_flip(
    process: &ProdProcessIo,
    child_stores: ChildStores,
    factory: &StorageFactory,
    storage_dir: &StorageDirResolver,
    engine_bootstrap: &EngineBootstrap,
    parent: ShardId,
    epoch_duration_ms: u64,
) -> Result<Box<PreparedMergeFlip>, String> {
    let anchor = wait_for_child_anchor(process, parent).await;
    let (left, right) = parent.children();
    // A merge child's terminal record anchors at its crossing block's own
    // height — the beacon stores that block's hash and height directly —
    // so the certified terminal is the block at the anchor height itself,
    // not one below it (the split convention, where a child genesis sits
    // one above the parent terminal).
    let left_anchor = wait_for_child_anchor(process, left).await;
    let right_anchor = wait_for_child_anchor(process, right).await;
    let (left_header, left_qc) =
        fetch_certified_terminal(process.network(), left, left_anchor.height).await;
    let (right_header, right_qc) =
        fetch_certified_terminal(process.network(), right, right_anchor.height).await;
    let (genesis, origin) = merge_genesis_from_terminals(
        parent,
        (&left_header, &left_qc),
        (&right_header, &right_qc),
        epoch_duration_ms,
        &anchor,
    )?;

    let left_leaves = collect_child_half(process, child_stores.left, left, left_anchor).await?;
    let right_leaves = collect_child_half(process, child_stores.right, right, right_anchor).await?;

    let factory = Arc::clone(factory);
    let storage_dir = Arc::clone(storage_dir);
    let engine_bootstrap = engine_bootstrap.clone();
    spawn_blocking(move || {
        let dir = storage_dir(parent);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| format!("stale keeper store wipe: {e}"))?;
        }
        let storage = factory(parent)?;
        engine_bootstrap.replicate_into(storage.as_ref());
        let mut leaves = left_leaves;
        leaves.extend(right_leaves);
        let merged = storage
            .import_boundary_state(origin.genesis_height, leaves)
            .map_err(|e| format!("merged half union import: {e}"))?;
        if merged != anchor.state_root {
            return Err(format!(
                "merged root {merged:?} does not match the beacon anchor {:?}",
                anchor.state_root,
            ));
        }
        let adopted = storage
            .adopt_merge_parent(origin, &genesis)
            .map_err(|e| format!("merge adoption: {e}"))?;
        if adopted != anchor.state_root {
            return Err(format!(
                "adopted merged root {adopted:?} does not match the beacon anchor {:?}",
                anchor.state_root,
            ));
        }
        let substate_bytes = storage
            .substate_bytes_at_version(origin.genesis_height.inner())
            .unwrap_or(0);
        let recovered = RecoveredState {
            substate_bytes,
            chain_origin: origin,
            ..RecoveredState::default()
        };
        Ok(Box::new(PreparedMergeFlip {
            parent,
            storage,
            genesis,
            recovered,
        }))
    })
    .await
    .unwrap_or_else(|e| Err(format!("merge adoption task panicked: {e}")))
}

/// Poll the process topology until the beacon's child anchor projects —
/// the fold has consumed the parent's terminal contribution and seeded
/// the child's genesis record. The flip cannot act sooner: the anchor
/// carries the adopted root and the deterministic genesis hash the
/// adoption verifies against.
async fn wait_for_child_anchor(process: &ProdProcessIo, child: ShardId) -> ShardAnchor {
    loop {
        if let Some(anchor) = process.topology().load().boundary(child) {
            return anchor;
        }
        sleep(ANCHOR_POLL_INTERVAL).await;
    }
}

/// How often the flip re-checks for the child anchor and the parent's
/// terminal commit. The wait spans the parent's coast (a couple of
/// block intervals) plus one beacon fold.
const ANCHOR_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

/// How often a keeper re-signs and re-broadcasts its ready signal while
/// waiting for the merge to execute. Frequent enough to land a recognized
/// `ReshapeReady` soon after the keeper seat promotes, refreshed against
/// the own-child anchor as the child chain advances.
const KEEPER_READY_REASSERT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The parent-half adoption, blocking: wait is done; seed the child
/// directory from a parent checkpoint, open it at the child prefix,
/// adopt the subtree, and derive + verify the deterministic genesis
/// from the parent chain's terminal pair.
fn adopt_from_parent(
    parent_storage: &RocksDbShardStorage,
    factory: &StorageFactory,
    storage_dir: &StorageDirResolver,
    child: ShardId,
    anchor: &ShardAnchor,
) -> Result<(Arc<RocksDbShardStorage>, Block, RecoveredState), String> {
    // The anchor's height is the child genesis height — one past the
    // parent's terminal block — and the parent commits exactly one
    // block past its terminal (the coast block certifying it), so the
    // local parent chain is ready when its tip reaches the anchor.
    let deadline = std::time::Instant::now() + PARENT_TERMINAL_WAIT;
    while parent_storage.committed_height() < anchor.height {
        if std::time::Instant::now() > deadline {
            return Err("parent chain never reached its terminal commit".to_string());
        }
        std::thread::sleep(ANCHOR_POLL_INTERVAL);
    }
    let terminal_height = anchor
        .height
        .prev()
        .ok_or("child anchor at the absolute height floor")?;
    let terminal = parent_storage
        .get_block(terminal_height)
        .ok_or("parent chain holds no terminal block below the anchor")?;
    let (genesis, origin) = split_genesis_from_terminal(
        child,
        terminal.block().header(),
        terminal.qc_verified(),
        anchor,
    )?;

    parent_storage
        .checkpoint_into(&storage_dir(child))
        .map_err(|e| format!("child checkpoint: {e}"))?;
    let storage = factory(child)?;
    let adopted = storage
        .adopt_split_child(origin, &genesis)
        .map_err(|e| format!("child adoption: {e}"))?;
    if adopted != anchor.state_root {
        return Err(format!(
            "adopted subtree root {adopted:?} does not match the beacon anchor {:?}",
            anchor.state_root,
        ));
    }
    let substate_bytes = storage
        .substate_bytes_at_version(origin.genesis_height.inner())
        .unwrap_or(0);
    let recovered = RecoveredState {
        substate_bytes,
        chain_origin: origin,
        ..RecoveredState::default()
    };
    Ok((storage, genesis, recovered))
}

/// Upper bound on waiting for the locally hosted parent chain to commit
/// its crossing once the beacon anchor projects. The anchor implies the
/// crossing is certified network-wide; a local chain further behind
/// than this is wedged and the join should fail (a later placement
/// delta retries).
const PARENT_TERMINAL_WAIT: std::time::Duration = std::time::Duration::from_secs(60);
