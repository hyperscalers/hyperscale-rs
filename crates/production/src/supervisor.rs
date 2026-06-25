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
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::pool_loop::PoolLoop;
use hyperscale_node::process::ProcessIo;
use hyperscale_node::reshape::adopt::verified_recovered_state;
use hyperscale_node::reshape::observer::observer_ready_signal;
use hyperscale_node::reshape::orchestrator::{
    AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeOrchestrator, ReshapeRequest,
};
use hyperscale_node::reshape::view::ReshapeView;
use hyperscale_node::shard::HostEvent;
use hyperscale_node::{
    NodeConfig, SeatFollower, SeatVnodeGroup, TimerOp, VnodeInit, seat_follower, seat_vnode_group,
    serve_state_range_request,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BoundaryStore, ImportLeaf, RecoveredState, ShardChainReader};
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::network::notification::ReadySignalNotification;
use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::{
    Block, BlockHeight, Bls12381G1PrivateKey, ChainOrigin, GenesisConfigHash, NetworkDefinition,
    RoutingCommittees, ShardAnchor, ShardId, SplitAdoption, StateRoot, StoredReceipt,
    TopologySnapshot, ValidatorId,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::bootstrap::bootstrap_shard_state;
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

/// A reshape duty's in-flight store, held by the supervisor between the
/// orchestrator's [`ReshapeRequest::OpenStore`] and its
/// [`ReshapeRequest::Seat`]: the open store the duty imports and adopts
/// into, the recovered state its state machines boot from (rebuilt at the
/// adopt), and the derived genesis the seat installs.
struct BootstrappingStore {
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
    genesis: Option<Block>,
}

/// One reshape io result fed back into the orchestrator's pump. The io
/// callbacks (network responses, off-loop store work) push these onto the
/// supervisor's event channel; [`ShardSupervisor::on_reshape_io`] updates
/// the in-flight [`BootstrappingStore`] cache and translates each into the
/// orchestrator's [`ReshapeEvent`] — the layer the orchestrator's `step`
/// consumes, which carries no store handles of its own.
pub enum ReshapeIo {
    /// A reshape store open settled: the open store and its recovered
    /// state, cached for the duty, or the open failure.
    Opened {
        /// The duty's store shard.
        shard: ShardId,
        /// The opened store and recovered state, or the open failure.
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    },
    /// A reshape fetch returned a response.
    Fetched {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed.
        from: ShardId,
        /// The response.
        kind: FetchedKind,
    },
    /// A reshape fetch failed at the transport level.
    FetchFailed {
        /// The duty the fetch belonged to.
        duty: ShardId,
        /// The shard the fetch addressed.
        from: ShardId,
        /// What failed, for re-arming.
        kind: FetchKind,
    },
    /// A boundary import completed with the resulting store root.
    Imported {
        /// The store shard.
        shard: ShardId,
        /// The imported root.
        root: StateRoot,
    },
    /// A followed-block application completed with the resulting store
    /// root.
    Applied {
        /// The store shard.
        shard: ShardId,
        /// The applied root.
        root: StateRoot,
    },
    /// A genesis adoption settled (root already verified against the
    /// anchor); carries the recovered state the seat boots from.
    Adopted {
        /// The store shard.
        shard: ShardId,
        /// The recovered state rebuilt over the adopted genesis.
        recovered: RecoveredState,
    },
    /// A parent-half seed could not run yet — the local parent is still behind
    /// the terminal crossing — so the seed should be re-armed.
    SeedDeferred {
        /// The split child whose seed is deferred.
        child: ShardId,
    },
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
    /// A reshape orchestrator io result settled.
    Reshape(ReshapeIo),
    /// A departing shard's thread joined; the unwire can finish.
    TornDown {
        /// Shard whose thread exited.
        shard: ShardId,
        /// The departed vnodes' validator ids, for the RPC scrub.
        validator_ids: Vec<u64>,
    },
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
    /// The sans-io reshape orchestrator — discovers this host's observer
    /// and keeper duties from the committed-state projection and sequences
    /// them. The supervisor pumps it on a timer and on every placement
    /// change, performing the io it returns.
    reshape: ReshapeOrchestrator,
    /// In-flight reshape stores, keyed by the duty's store shard (a
    /// splitting child or a merging parent), held between the
    /// orchestrator's open and seat requests. Seated stores move into
    /// [`Self::storages`].
    reshape_stores: HashMap<ShardId, BootstrappingStore>,
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
            reshape: ReshapeOrchestrator::new(
                vnode_keys.keys().copied().collect(),
                epoch_duration_ms,
            ),
            reshape_stores: HashMap::new(),
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
            SupervisorEvent::Reshape(io) => self.on_reshape_io(io),
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
                // The orchestrator discovers and seats both split adoption paths
                // from the committed projection — an observer from its synced
                // store, a parent half from its cloned local parent — so the
                // placement-delta join is a no-op for either.
                Some(SplitAdoption::ParentHalf { .. } | SplitAdoption::Observer { .. }) => {
                    info!(shard = ?shard, "Split adoption join ignored; the orchestrator seats it");
                }
                None => self.join(shard, &vnodes),
            },
            ShardCommand::Leave { shard } => self.leave(shard),
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

        // A reshape duty owns seating this shard — a merge's keepers
        // reforming the parent, surfaced as an ordinary join when the
        // merge executes. The orchestrator seats them from the prepared
        // store, so the placement-delta join is a no-op here.
        if self.reshape.is_seating(shard) {
            info!(shard = ?shard, "Join superseded by an active reshape duty; the orchestrator seats it");
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

    /// Pump the reshape orchestrator one step: feed back the io results in
    /// `events`, let it re-discover this host's duties from the committed
    /// topology projection, and perform the io it returns. Idempotent; the
    /// runner ticks it on a timer and on every placement change.
    pub(crate) fn reshape_step(&mut self, events: Vec<ReshapeEvent>) {
        let requests = {
            let topology = self.process.topology().load_full();
            let view = ReshapeView::new(&topology);
            self.reshape.step(&view, events)
        };
        for request in requests {
            self.dispatch_reshape(request);
        }
    }

    /// Perform one reshape io request, answering with a
    /// [`SupervisorEvent::Reshape`] the runner loop feeds back through
    /// [`Self::on_reshape_io`].
    fn dispatch_reshape(&mut self, request: ReshapeRequest) {
        match request {
            ReshapeRequest::OpenStore { shard } => self.reshape_open_store(shard),
            ReshapeRequest::SeedFromParent { parent, child } => {
                self.reshape_seed_from_parent(parent, child);
            }
            ReshapeRequest::Fetch { duty, from, kind } => self.reshape_fetch(duty, from, kind),
            ReshapeRequest::ImportBoundary {
                shard,
                height,
                leaves,
            } => self.reshape_import(shard, height, leaves),
            ReshapeRequest::ApplyFollow {
                shard,
                height,
                receipts,
            } => self.reshape_apply(shard, height, receipts),
            ReshapeRequest::BroadcastReady {
                validator,
                anchor,
                recipients,
            } => self.reshape_broadcast(validator, anchor, &recipients),
            ReshapeRequest::Adopt {
                shard,
                kind,
                origin,
                genesis,
            } => self.reshape_adopt(shard, kind, origin, *genesis),
            ReshapeRequest::Seat { shard } => self.reshape_seat(shard),
        }
    }

    /// Open (wiping any stale directory) a reshape duty's store off the
    /// loop, replicating the engine bootstrap into the fresh store, and
    /// answer with [`ReshapeIo::Opened`].
    fn reshape_open_store(&self, shard: ShardId) {
        let factory = Arc::clone(&self.storage_factory);
        let engine_bootstrap = self.engine_bootstrap.clone();
        let dir = (self.storage_dir)(shard);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = (|| -> Result<(Arc<RocksDbShardStorage>, RecoveredState), String> {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("stale reshape store wipe: {e}"))?;
                }
                let storage = factory(shard)?;
                // The directory was just wiped, so the store is fresh: it must
                // carry the engine bootstrap on its substate side before the
                // duty's child-span or merged-union import, or the seated shard
                // would lack the global engine nodes (the transaction tracker,
                // the consensus manager) every transaction reads.
                engine_bootstrap.replicate_into(storage.as_ref());
                let recovered = storage.load_recovered_state();
                Ok((storage, recovered))
            })();
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Opened {
                shard,
                outcome,
            }));
        });
    }

    /// Seed a parent half's `child` store by checkpoint-cloning the host's own
    /// retained `parent` store onto the child subtree, once that parent chain
    /// has committed through the terminal crossing. Answers with
    /// [`ReshapeIo::Opened`] when the clone lands, or [`ReshapeIo::SeedDeferred`]
    /// while the local parent is still behind (or its store is gone). The
    /// checkpoint hard-links, so the clone shares the engine bootstrap and the
    /// parent's substates without copying.
    fn reshape_seed_from_parent(&self, parent: ShardId, child: ShardId) {
        let events = self.events_tx.clone();
        let Some(anchor) = self.process.topology().load().boundary(child) else {
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
            return;
        };
        let parent_storage = self
            .storages
            .lock()
            .expect("storages lock")
            .get(&parent)
            .cloned();
        let Some(parent_storage) = parent_storage else {
            warn!(shard = ?child, ?parent, "Reshape seed without a hosted parent store; deferred");
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
            return;
        };
        let factory = Arc::clone(&self.storage_factory);
        let dir = (self.storage_dir)(child);
        self.tokio_handle.spawn_blocking(move || {
            // The anchor's height is the child genesis height; the parent commits
            // one block past its terminal (the coast certifying it), so the local
            // chain is ready for the clone once its tip reaches the anchor.
            if parent_storage.committed_height() < anchor.height {
                let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::SeedDeferred { child }));
                return;
            }
            let outcome = (|| -> Result<(Arc<RocksDbShardStorage>, RecoveredState), String> {
                if dir.exists() {
                    std::fs::remove_dir_all(&dir)
                        .map_err(|e| format!("stale child store wipe: {e}"))?;
                }
                parent_storage
                    .checkpoint_into(&dir)
                    .map_err(|e| format!("child checkpoint: {e}"))?;
                let storage = factory(child)?;
                let recovered = storage.load_recovered_state();
                Ok((storage, recovered))
            })();
            // Send failure means the runner is shutting down.
            let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Opened {
                shard: child,
                outcome,
            }));
        });
    }

    /// Issue one reshape fetch against `from`'s committee, answering with
    /// [`ReshapeIo::Fetched`] on success or [`ReshapeIo::FetchFailed`] on a
    /// transport error. `from` resolves to its committee through the live
    /// topology.
    fn reshape_fetch(&self, duty: ShardId, from: ShardId, kind: FetchKind) {
        let events = self.events_tx.clone();
        match kind {
            FetchKind::StateRange { sub_range, request } => {
                // A merge keeper co-hosts the terminating halves it collects, so
                // serve their ranges from the local store: a half's committee
                // dissolves at the merge boundary, and a network fetch would just
                // hammer the drained shard's torn-down request protocol.
                let local = self
                    .storages
                    .lock()
                    .expect("storages lock")
                    .get(&from)
                    .cloned();
                let Some(storage) = local else {
                    Self::network_state_range(
                        self.process.network(),
                        &events,
                        duty,
                        from,
                        sub_range,
                        request,
                    );
                    return;
                };
                let network = Arc::clone(self.process.network());
                self.tokio_handle.spawn_blocking(move || {
                    let response = serve_state_range_request(&storage, &request);
                    if response.chunk.is_some() {
                        let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Fetched {
                            duty,
                            from,
                            kind: FetchedKind::StateRange {
                                sub_range,
                                response: Box::new(response),
                            },
                        }));
                    } else {
                        // The local store no longer pins the boundary; fall back
                        // to the shard's committee.
                        Self::network_state_range(
                            &network, &events, duty, from, sub_range, request,
                        );
                    }
                });
            }
            FetchKind::Block { request } => {
                let on_fail = request.clone();
                self.process.network().request(
                    from,
                    None,
                    request,
                    None,
                    Box::new(move |result| {
                        let io = result.map_or_else(
                            |_| ReshapeIo::FetchFailed {
                                duty,
                                from,
                                kind: FetchKind::Block { request: on_fail },
                            },
                            |response| ReshapeIo::Fetched {
                                duty,
                                from,
                                kind: FetchedKind::Block {
                                    response: Box::new(response),
                                },
                            },
                        );
                        let _ = events.send(SupervisorEvent::Reshape(io));
                        ResponseVerdict::Accept
                    }),
                );
            }
        }
    }

    /// Request one reshape state range from `from`'s committee, answering with a
    /// [`ReshapeIo`]. The fallback when a duty's source isn't co-hosted locally.
    fn network_state_range(
        network: &Arc<Libp2pNetwork>,
        events: &mpsc::UnboundedSender<SupervisorEvent>,
        duty: ShardId,
        from: ShardId,
        sub_range: usize,
        request: GetStateRangeRequest,
    ) {
        let on_fail = request.clone();
        let events = events.clone();
        network.request(
            from,
            None,
            request,
            None,
            Box::new(move |result| {
                let io = result.map_or_else(
                    |_| ReshapeIo::FetchFailed {
                        duty,
                        from,
                        kind: FetchKind::StateRange {
                            sub_range,
                            request: on_fail,
                        },
                    },
                    |response| ReshapeIo::Fetched {
                        duty,
                        from,
                        kind: FetchedKind::StateRange {
                            sub_range,
                            response: Box::new(response),
                        },
                    },
                );
                let _ = events.send(SupervisorEvent::Reshape(io));
                ResponseVerdict::Accept
            }),
        );
    }

    /// Write a reshape duty's boundary leaves into its store off the loop,
    /// answering with [`ReshapeIo::Imported`].
    fn reshape_import(&self, shard: ShardId, height: BlockHeight, leaves: Vec<ImportLeaf>) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape import for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.import_boundary_state(height, leaves) {
                Ok(root) => {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Imported {
                        shard,
                        root,
                    }));
                }
                Err(error) => warn!(shard = ?shard, %error, "Reshape boundary import failed"),
            }
        });
    }

    /// Apply a followed parent block's writes into a reshape duty's store
    /// off the loop, answering with [`ReshapeIo::Applied`].
    fn reshape_apply(&self, shard: ShardId, height: BlockHeight, receipts: Vec<StoredReceipt>) {
        let Some(storage) = self
            .reshape_stores
            .get(&shard)
            .map(|s| Arc::clone(&s.storage))
        else {
            warn!(shard = ?shard, "Reshape follow apply for an unopened store; dropped");
            return;
        };
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            match storage.follow_block_writes(height, &receipts) {
                Ok(root) => {
                    let _ =
                        events.send(SupervisorEvent::Reshape(ReshapeIo::Applied { shard, root }));
                }
                Err(error) => warn!(shard = ?shard, %error, "Reshape follow apply failed"),
            }
        });
    }

    /// Sign `validator`'s ready signal anchored at `anchor` and notify the
    /// reshape committee `recipients`. No response — the orchestrator
    /// re-asserts each step until the gate fires.
    fn reshape_broadcast(
        &self,
        validator: ValidatorId,
        anchor: ShardAnchor,
        recipients: &[ValidatorId],
    ) {
        let Some(signing_key) = self.vnode_keys.get(&validator) else {
            warn!(
                validator = validator.inner(),
                "Reshape ready signal for a validator without a local key; ignored"
            );
            return;
        };
        let signal = observer_ready_signal(
            &self.beacon_network,
            validator,
            signing_key,
            anchor,
            self.epoch_duration_ms,
        );
        self.process
            .network()
            .notify(recipients, &ReadySignalNotification::new(signal));
    }

    /// Adopt a reshape duty's derived genesis off the loop —
    /// `adopt_followed_child` for a split observer's followed store,
    /// `adopt_merge_parent` for a merge keeper's union — verifying the
    /// adopted root against the beacon-attested anchor and rebuilding the
    /// recovered state the seat boots from. Answers with
    /// [`ReshapeIo::Adopted`]; a verification failure logs and strands the
    /// duty (the seat never fires).
    fn reshape_adopt(
        &mut self,
        shard: ShardId,
        kind: AdoptKind,
        origin: ChainOrigin,
        genesis: Block,
    ) {
        let Some(storage) = self.reshape_stores.get_mut(&shard).map(|entry| {
            entry.genesis = Some(genesis.clone());
            Arc::clone(&entry.storage)
        }) else {
            warn!(shard = ?shard, "Reshape adopt for an unopened store; dropped");
            return;
        };
        // A merge verifies against the beacon's composed parent anchor; a
        // split observer verifies against its derived genesis root (itself
        // reproduced from the parent terminal and the child anchor).
        let anchor_root = self
            .process
            .topology()
            .load()
            .boundary(shard)
            .map(|a| a.state_root);
        let events = self.events_tx.clone();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = (|| -> Result<RecoveredState, String> {
                let (adopted, expected) = match kind {
                    AdoptKind::Split => (
                        storage
                            .adopt_followed_child(origin, &genesis)
                            .map_err(|e| format!("followed adoption: {e}"))?,
                        genesis.header().state_root(),
                    ),
                    AdoptKind::ParentHalf => (
                        storage
                            .adopt_split_child(origin, &genesis)
                            .map_err(|e| format!("split child adoption: {e}"))?,
                        anchor_root.ok_or("split child anchor no longer projects")?,
                    ),
                    AdoptKind::Merge => (
                        storage
                            .adopt_merge_parent(origin, &genesis)
                            .map_err(|e| format!("merge adoption: {e}"))?,
                        anchor_root.ok_or("merge parent anchor no longer projects")?,
                    ),
                };
                let substate_bytes = storage
                    .substate_bytes_at_version(origin.genesis_height.inner())
                    .unwrap_or(0);
                verified_recovered_state(adopted, expected, origin, substate_bytes)
            })();
            match outcome {
                Ok(recovered) => {
                    let _ = events.send(SupervisorEvent::Reshape(ReshapeIo::Adopted {
                        shard,
                        recovered,
                    }));
                }
                Err(error) => {
                    warn!(shard = ?shard, error, "Reshape adoption failed; duty stranded");
                }
            }
        });
    }

    /// Seat a prepared reshape duty: install its derived genesis and start
    /// consensus for every local committee member of `shard`, from the
    /// store the duty adopted into. The orchestrator owns this seating, so
    /// the placement-delta join for the same shard is suppressed.
    fn reshape_seat(&mut self, shard: ShardId) {
        let Some(BootstrappingStore {
            storage,
            recovered,
            genesis,
        }) = self.reshape_stores.remove(&shard)
        else {
            warn!(shard = ?shard, "Reshape seat for an unprepared store; dropped");
            return;
        };
        if self.shards.contains_key(&shard) {
            warn!(shard = ?shard, "Reshape seat for an already-hosted shard; dropped");
            return;
        }
        let topology = self.process.topology().load_full();
        let vnodes: Vec<VnodeConfig> = topology
            .committee_for_shard(shard)
            .iter()
            .filter_map(|validator| {
                self.vnode_keys
                    .get(validator)
                    .map(|signing_key| VnodeConfig {
                        validator_id: *validator,
                        local_shard: shard,
                        signing_key: Arc::clone(signing_key),
                    })
            })
            .collect();
        if vnodes.is_empty() {
            warn!(shard = ?shard, "Reshape seat with no local committee members; dropped");
            return;
        }
        self.seat_shard_with_genesis(shard, &vnodes, storage, &recovered, genesis.as_ref());
    }

    /// Settle one reshape io result: update the duty's [`BootstrappingStore`]
    /// cache, then translate the result into the orchestrator's
    /// [`ReshapeEvent`] and pump it back through [`Self::reshape_step`].
    fn on_reshape_io(&mut self, io: ReshapeIo) {
        let event = match io {
            ReshapeIo::Opened { shard, outcome } => match outcome {
                Ok((storage, recovered)) => {
                    self.reshape_stores.insert(
                        shard,
                        BootstrappingStore {
                            storage,
                            recovered,
                            genesis: None,
                        },
                    );
                    ReshapeEvent::Opened { shard }
                }
                Err(error) => {
                    warn!(shard = ?shard, error, "Reshape store open failed; duty stranded");
                    return;
                }
            },
            ReshapeIo::Fetched { duty, from, kind } => ReshapeEvent::Fetched { duty, from, kind },
            ReshapeIo::FetchFailed { duty, from, kind } => {
                ReshapeEvent::FetchFailed { duty, from, kind }
            }
            ReshapeIo::Imported { shard, root } => ReshapeEvent::Imported { shard, root },
            ReshapeIo::Applied { shard, root } => ReshapeEvent::Applied { shard, root },
            ReshapeIo::Adopted { shard, recovered } => {
                if let Some(entry) = self.reshape_stores.get_mut(&shard) {
                    entry.recovered = recovered;
                }
                ReshapeEvent::Adopted { shard }
            }
            ReshapeIo::SeedDeferred { child } => ReshapeEvent::SeedDeferred { child },
        };
        self.reshape_step(vec![event]);
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
        self.tear_down(shard);
    }

    /// Tear a hosted shard's thread down and unwire it off the loop:
    /// signal shutdown, drop the entry, and join the thread off-loop,
    /// finishing the unwire in [`Self::on_torn_down`]. Shared by the
    /// explicit per-vnode [`Self::leave`] at zero count and the
    /// reshape-tick routable-expiry reconcile.
    fn tear_down(&mut self, shard: ShardId) {
        let Some(entry) = self.shards.remove(&shard) else {
            return;
        };
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

    /// Reconcile hosted shards against the committed routing window: tear
    /// down a shard once no local validator holds a consensus role in it
    /// (absent from the active committee) and none sits in its routing
    /// committee (no serve obligation — the shard aged out of the routable
    /// window, or the validator rotated off a still-live shard).
    ///
    /// The active-committee guard keeps a shard up through its current
    /// window even after a lookahead delta moved the validator on in
    /// routing; the routing guard keeps a dissolved shard served for as
    /// long as a fetch can still resolve this host among its peers, so a
    /// merge keeper that does not co-host a merging child can still
    /// snap-sync it. Run on the reshape tick, binding serving and routing
    /// to one committed lifetime in place of a fixed drain grace.
    pub(crate) fn reconcile_teardown(&mut self) {
        let topology = self.process.topology().load();
        let routing = self.process.network().routing_committees();
        let host_ids: HashSet<ValidatorId> = self.vnode_keys.keys().copied().collect();
        let expired: Vec<ShardId> = self
            .shards
            .keys()
            .copied()
            .filter(|&shard| shard_retired(shard, &topology, &routing, &host_ids))
            .collect();
        for shard in expired {
            info!(
                shard = ?shard,
                "Shard aged out of the routable window; tearing down"
            );
            self.tear_down(shard);
        }
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

/// Whether a hosted shard has aged out of this host's serving duty: no
/// local validator holds a consensus role in it (absent from the active
/// committee) and none sits in its routing committee (no serve
/// obligation).
///
/// The active-committee guard keeps a shard up through its current window
/// even after a lookahead delta has moved the validator on in the routing
/// view; the routing guard keeps a dissolved shard served for as long as
/// a fetch can still resolve this host among its peers. Both false means
/// the shard is still wanted — it retires only when neither holds, so
/// serving and routing share the one committed lifetime.
fn shard_retired(
    shard: ShardId,
    topology: &TopologySnapshot,
    routing: &RoutingCommittees,
    host_ids: &HashSet<ValidatorId>,
) -> bool {
    let in_active = topology
        .committee_for_shard(shard)
        .iter()
        .any(|v| host_ids.contains(v));
    let in_routing = routing
        .get(&shard)
        .is_some_and(|committee| committee.iter().any(|v| host_ids.contains(v)));
    !in_active && !in_routing
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use hyperscale_types::{
        NetworkDefinition, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
        ValidatorInfo, ValidatorSet, generate_bls_keypair,
    };

    use super::shard_retired;

    const HOST: ValidatorId = ValidatorId::new(1);

    /// A head snapshot carrying `committees` as each shard's active
    /// membership — a complete sibling set so the trie is well-formed.
    fn head(committees: HashMap<ShardId, Vec<ValidatorId>>) -> TopologySnapshot {
        let ids: BTreeSet<ValidatorId> = committees.values().flatten().copied().collect();
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&validator_id| ValidatorInfo {
                validator_id,
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            committees,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        )
    }

    fn routing(entries: &[(ShardId, Vec<ValidatorId>)]) -> RoutingCommittees {
        entries.iter().cloned().collect()
    }

    /// A live shard the host rotated off — gone from both its active and
    /// its routing committee — retires.
    #[test]
    fn retires_a_shard_absent_from_active_and_routing() {
        let shard = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let others = vec![ValidatorId::new(2), ValidatorId::new(3)];
        let topology = head(HashMap::from([
            (shard, others.clone()),
            (sibling, vec![ValidatorId::new(4)]),
        ]));
        let routing = routing(&[(shard, others)]);
        assert!(shard_retired(
            shard,
            &topology,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A merge child gone from the head but retained in routing with the
    /// host among its terminal committee stays served — the keeper-fetch
    /// case the fix exists for.
    #[test]
    fn keeps_a_dissolved_shard_the_host_still_routes() {
        let child = ShardId::leaf(2, 2);
        let topology = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = routing(&[(child, vec![HOST, ValidatorId::new(2)])]);
        assert!(!shard_retired(
            child,
            &topology,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// The host still sits in the active committee — kept even after the
    /// routing lookahead has moved it on, so the current window is served
    /// to its end.
    #[test]
    fn keeps_a_shard_with_an_active_consensus_role() {
        let shard = ShardId::leaf(1, 0);
        let topology = head(HashMap::from([
            (shard, vec![HOST, ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![ValidatorId::new(4)]),
        ]));
        // The lookahead already moved the host off in routing.
        let routing = routing(&[(shard, vec![ValidatorId::new(2), ValidatorId::new(3)])]);
        assert!(!shard_retired(
            shard,
            &topology,
            &routing,
            &HashSet::from([HOST])
        ));
    }

    /// A dissolved shard aged out of routing entirely retires.
    #[test]
    fn retires_a_shard_evicted_from_routing() {
        let child = ShardId::leaf(2, 2);
        let topology = head(HashMap::from([
            (ShardId::leaf(1, 0), vec![ValidatorId::new(2)]),
            (ShardId::leaf(1, 1), vec![HOST]),
        ]));
        let routing = RoutingCommittees::new();
        assert!(shard_retired(
            child,
            &topology,
            &routing,
            &HashSet::from([HOST])
        ));
    }
}
