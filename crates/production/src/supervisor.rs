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
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use crossbeam::channel::{Sender, unbounded};
use hyperscale_beacon::coordinator::{BeaconCoordinator, retention_floor};
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::process_io::ProcessIo;
use hyperscale_node::shard_loop::ShardEvent;
use hyperscale_node::{NodeConfig, NodeStateMachine, TimerOp, VnodeInit};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::{BeaconState, BlockHeight, GenesisConfigHash, NetworkDefinition, ShardId};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::bootstrap::bootstrap_shard_state;
use crate::rpc::{MempoolSnapshot, NodeStatusState};
use crate::runner::{
    ProdShardLoop, ShardChannels, ShardLoopConfig, VnodeConfig, spawn_shard_loop, wall_clock_local,
};
use crate::status::SyncStatus;

/// The process-scoped resource bundle as the production runner types it.
type ProdProcessIo = ProcessIo<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Opens (or creates) one shard's `RocksDB` storage at the host's
/// data-dir convention. Supplied by the validator binary, which owns
/// the directory layout; without one, `Join` commands are rejected.
pub type StorageFactory =
    Arc<dyn Fn(ShardId) -> Result<Arc<RocksDbShardStorage>, String> + Send + Sync>;

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

/// A finished snap-sync bootstrap, ready for the supervisor to seat:
/// the imported storage verified against the attested anchor, plus the
/// recovered state the shard's state machines boot from.
pub struct CompletedBootstrap {
    shard: ShardId,
    vnodes: Vec<VnodeConfig>,
    storage: Arc<RocksDbShardStorage>,
    recovered: RecoveredState,
}

/// One hosted shard's runtime: its pinned thread plus the handles the
/// supervisor needs to stop it.
struct ShardThread {
    join: std::thread::JoinHandle<()>,
    shutdown_tx: Sender<()>,
    /// Keeps the shard's callback channel alive for off-thread senders.
    #[allow(dead_code)]
    callback_tx: Sender<ShardEvent>,
    /// Local vnodes participating in this shard. The shard tears down
    /// when this reaches zero.
    vnode_count: usize,
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
    rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
    mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
    /// Per-shard `RocksDB` handles, shared with the runner's GC tick.
    storages: Arc<Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>,
    storage_factory: Option<StorageFactory>,
    /// Cloned into every spawned shard loop's config so placement
    /// deltas reach the runner's reconfiguration loop.
    participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    shards: HashMap<ShardId, ShardThread>,
    /// Shards whose join is parked on an in-flight snap-sync bootstrap.
    /// Guards against a second `Join` racing a double import.
    bootstrapping: HashSet<ShardId>,
    /// Completed bootstraps land here; the runner's select loop drains
    /// the paired receiver and calls [`Self::finish_join`].
    bootstrap_done_tx: mpsc::UnboundedSender<CompletedBootstrap>,
    /// Receiver side, taken by the runner's `run()` loop.
    bootstrap_done_rx: Option<mpsc::UnboundedReceiver<CompletedBootstrap>>,
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
        rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
        sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
        mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
        storages: Arc<Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>,
        storage_factory: Option<StorageFactory>,
        participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    ) -> Self {
        let (bootstrap_done_tx, bootstrap_done_rx) = mpsc::unbounded_channel();
        Self {
            process,
            node_config: NodeConfig::default(),
            shard_config,
            mempool_config,
            provision_config,
            beacon_network,
            beacon_config_hash,
            tokio_handle,
            rpc_status,
            sync_status,
            mempool_snapshot,
            storages,
            storage_factory,
            participation_tx,
            shards: HashMap::new(),
            bootstrapping: HashSet::new(),
            bootstrap_done_tx,
            bootstrap_done_rx: Some(bootstrap_done_rx),
        }
    }

    /// Take the bootstrap-completion receiver. The runner's `run()`
    /// loop drains it and hands each completion to
    /// [`Self::finish_join`].
    pub(crate) const fn take_bootstrap_done_rx(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<CompletedBootstrap>> {
        self.bootstrap_done_rx.take()
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
        let callback_tx = channels.callback_tx.clone();
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                callback_tx,
                vnode_count,
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

    /// Bring up `shard`: open storage, bootstrap its state when the
    /// store is fresh and the beacon attests an anchor, build vnode
    /// state machines from the host's beacon chain, wire the process
    /// maps, spawn the thread.
    ///
    /// Three paths by what the store and the beacon offer:
    /// - **retained storage** (committed height > 0) — seat directly;
    ///   normal block sync covers the tail;
    /// - **fresh store, attested anchor** — snap-sync bootstrap off
    ///   this loop (a tokio task), seated via [`Self::finish_join`]
    ///   when the import verifies against the anchor;
    /// - **fresh store, no anchor** — seat directly and replay from
    ///   genesis through block sync.
    fn join(&mut self, shard: ShardId, vnodes: &[VnodeConfig]) {
        if self.shards.contains_key(&shard) || self.bootstrapping.contains(&shard) {
            warn!(shard = ?shard, "Join rejected: shard already hosted or bootstrapping");
            return;
        }
        if vnodes.is_empty() || vnodes.iter().any(|v| v.local_shard != shard) {
            warn!(shard = ?shard, "Join rejected: vnodes must be non-empty and target the shard");
            return;
        }
        let Some(factory) = &self.storage_factory else {
            warn!(shard = ?shard, "Join rejected: no storage factory configured");
            return;
        };
        let storage = match factory(shard) {
            Ok(storage) => storage,
            Err(error) => {
                warn!(shard = ?shard, error, "Join rejected: storage open failed");
                return;
            }
        };

        let recovered = storage.load_recovered_state();
        let fresh_store = recovered.committed_height == BlockHeight::GENESIS;
        let anchor = self.process.topology().load().boundary(shard);
        if fresh_store && anchor.is_some() {
            self.bootstrapping.insert(shard);
            let process = Arc::clone(&self.process);
            let done_tx = self.bootstrap_done_tx.clone();
            let vnodes = vnodes.to_vec();
            self.tokio_handle.spawn(async move {
                match bootstrap_shard_state(process.network(), process.topology(), &storage, shard)
                    .await
                {
                    Ok(recovered) => {
                        // Send failure means the runner is shutting
                        // down; the join dies with it.
                        let _ = done_tx.send(CompletedBootstrap {
                            shard,
                            vnodes,
                            storage,
                            recovered,
                        });
                    }
                    Err(error) => {
                        warn!(shard = ?shard, error, "Shard bootstrap failed; join abandoned");
                    }
                }
            });
            return;
        }
        self.seat_shard(shard, vnodes, storage, &recovered);
    }

    /// Seat a bootstrap-completed shard. Runs on the runner's loop via
    /// the completion channel — never on the bootstrap task.
    pub(crate) fn finish_join(&mut self, done: CompletedBootstrap) {
        self.bootstrapping.remove(&done.shard);
        if self.shards.contains_key(&done.shard) {
            warn!(shard = ?done.shard, "Bootstrap completed for an already-hosted shard; dropped");
            return;
        }
        self.seat_shard(done.shard, &done.vnodes, done.storage, &done.recovered);
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
        let inits = self.build_vnode_inits(shard, vnodes, recovered);
        let vnode_count = inits.len();

        let (timer_tx, timer_rx) = unbounded();
        let (callback_tx, callback_rx) = unbounded();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let mut shard_loop = attach_shard(
            &self.process,
            &self.node_config,
            inits,
            SharedStorage::new(Arc::clone(&storage)),
            callback_tx.clone(),
        );
        shard_loop.set_time(wall_clock_local());

        self.storages
            .lock()
            .expect("storages lock")
            .insert(shard, storage);

        let channels = ShardChannels {
            timer_tx,
            timer_rx,
            callback_tx: callback_tx.clone(),
            callback_rx,
            shutdown_tx: shutdown_tx.clone(),
            shutdown_rx,
        };
        let cfg = self.loop_config(channels, Vec::new());
        let join = spawn_shard_loop(shard_loop, cfg);
        self.shards.insert(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                callback_tx,
                vnode_count,
            },
        );
        info!(shard = ?shard, vnodes = vnode_count, "Shard joined at runtime");
    }

    /// Release one vnode's membership; tear the shard down at zero.
    fn leave(&mut self, shard: ShardId) {
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
        if entry.join.join().is_err() {
            warn!(shard = ?shard, "Shard thread panicked before teardown");
        }
        detach_shard(&self.process, shard);
        self.storages.lock().expect("storages lock").remove(&shard);
        info!(shard = ?shard, "Shard left and torn down");
    }

    /// Stop every shard thread: fan the shutdown signals first so the
    /// threads wind down in parallel, then join them all.
    pub(crate) fn shutdown_all(&mut self) {
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
            rpc_status: self.rpc_status.clone(),
            sync_status: self.sync_status.clone(),
            mempool_snapshot: self.mempool_snapshot.clone(),
        }
    }

    /// Build one `VnodeInit` per joining vnode: a fresh beacon
    /// coordinator resumed from the host's committed beacon chain, and
    /// a `NodeStateMachine` booted from `recovered` — loaded from
    /// retained storage, synthesized from a snap-synced anchor, or
    /// default for a genesis replay. Fresh per-shard stores are shared
    /// across the group.
    fn build_vnode_inits(
        &self,
        shard: ShardId,
        vnodes: &[VnodeConfig],
        recovered: &RecoveredState,
    ) -> Vec<VnodeInit> {
        let beacon_storage = self.process.beacon_storage();
        let (latest_block, latest_state) = beacon_storage
            .latest_committed()
            .expect("beacon chain is non-empty after the startup genesis commit");
        let boot_floor = retention_floor(
            &latest_state,
            recovered.committee_anchor_ts(),
            wall_clock_local(),
        );
        let beacon_history: Vec<BeaconState> = beacon_storage
            .states_since(boot_floor)
            .into_iter()
            .map(|state| state.as_ref().clone())
            .collect();

        let provision_store = Arc::new(ProvisionStore::new());
        let tx_store = Arc::new(TxStore::new());
        let exec_cert_store = Arc::new(ExecCertStore::new());
        let finalized_wave_store = Arc::new(FinalizedWaveStore::new());

        vnodes
            .iter()
            .map(|cfg| {
                let beacon_coordinator = BeaconCoordinator::new(
                    Arc::clone(&latest_block),
                    beacon_history.clone(),
                    cfg.validator_id,
                    shard,
                    recovered.committee_anchor_ts(),
                    self.beacon_network.clone(),
                    self.beacon_config_hash,
                    Arc::clone(self.process.beacon_proposal_pool()),
                );
                let state = NodeStateMachine::new(
                    cfg.validator_id,
                    shard,
                    &self.shard_config,
                    recovered.clone(),
                    beacon_coordinator,
                    self.mempool_config.clone(),
                    self.provision_config,
                    Arc::clone(&provision_store),
                    Arc::clone(&tx_store),
                    Arc::clone(&exec_cert_store),
                    Arc::clone(&finalized_wave_store),
                );
                VnodeInit {
                    state,
                    signing_key: Arc::clone(&cfg.signing_key),
                }
            })
            .collect()
    }
}
