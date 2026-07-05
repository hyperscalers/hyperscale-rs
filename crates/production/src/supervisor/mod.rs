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

use crossbeam::channel::{Receiver, Sender};
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::process::ProcessIo;
use hyperscale_node::reshape::PreparedStore;
use hyperscale_node::reshape::orchestrator::{ReshapeOrchestrator, ReshapeRequest};
use hyperscale_node::shard::HostEvent;
use hyperscale_node::{NodeConfig, TimerOp};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::{
    Bls12381G1PrivateKey, GenesisConfigHash, NetworkDefinition, ShardId, ValidatorId,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::warn;

use crate::rpc::RpcPublishers;
use crate::runner::{ProdShardLoop, ShardChannels, ShardLoopConfig, VnodeConfig, spawn_shard_loop};

mod membership;
mod pool;
mod reshape;

use membership::CompletedBootstrap;
use pool::PoolThread;
use reshape::ReshapeIo;

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
    },
    /// Release one local vnode's membership in `shard`. The shard's
    /// thread, subscriptions, and storage are torn down when the last
    /// local vnode leaves.
    Leave {
        /// Shard to release one membership of.
        shard: ShardId,
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
    reshape_stores: HashMap<ShardId, PreparedStore<Arc<RocksDbShardStorage>>>,
    /// Reshape store-prep requests (`OpenStore` / `SeedFromParent`) held while
    /// an ordinary placement-delta join is still opening the same shard's store
    /// directory, keyed by that store shard. A reshape duty owns its successor's
    /// store, but a join that slipped past the `reshape_owns` suppression (a
    /// lagging topology snapshot) may already be mid-open; holding the prep until
    /// that join's open lands and is abandoned keeps the two off the same
    /// `RocksDB` directory, whose exclusive lock would otherwise fail the second
    /// open. Re-dispatched from [`Self::reshape_step`] once the join clears.
    pending_reshape_prep: HashMap<ShardId, ReshapeRequest>,
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
            reshape: ReshapeOrchestrator::new(vnode_keys.keys().copied().collect()),
            reshape_stores: HashMap::new(),
            pending_reshape_prep: HashMap::new(),
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

    /// Execute one membership command.
    pub(crate) fn handle(&mut self, command: ShardCommand) {
        match command {
            ShardCommand::Join { shard, vnodes } => self.join(shard, &vnodes),
            ShardCommand::Leave { shard } => self.leave(shard),
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
}
