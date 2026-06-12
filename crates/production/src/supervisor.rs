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

use crossbeam::channel::{Sender, unbounded};
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::Network;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::bootstrap::observer::observer_ready_signal;
use hyperscale_node::bootstrap::split_flip::split_genesis_from_terminal;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::process_io::ProcessIo;
use hyperscale_node::{NodeConfig, SeatVnodeGroup, TimerOp, VnodeInit, seat_vnode_group};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{RecoveredState, ShardChainReader};
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

use crate::bootstrap::{bootstrap_observer_state, bootstrap_shard_state};
use crate::rpc::RpcPublishers;
use crate::runner::{
    ProdShardLoop, ShardChannels, ShardLoopConfig, VnodeConfig, spawn_shard_loop, wall_clock_local,
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

/// A finished observer duty: the child-rooted store on disk holds the
/// child's span as of `root`, and the ready signal is broadcast. The
/// store handle is dropped — the boundary handoff reopens it from disk.
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

pub struct CompletedObservation {
    child: ShardId,
    root: StateRoot,
    substate_count: u64,
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
    /// The duty task while the sync is in flight; aborted by
    /// `Unobserve`. `None` once complete.
    task: Option<JoinHandle<()>>,
    /// The imported child subtree root, once complete. The synced
    /// store itself lives on disk, closed until the boundary handoff
    /// reopens it.
    synced: Option<StateRoot>,
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
        participation_tx: mpsc::UnboundedSender<ParticipationChange>,
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
            participation_tx,
            shards: HashMap::new(),
            bootstrapping: HashMap::new(),
            observers: HashMap::new(),
            draining: HashSet::new(),
            pending_joins: HashMap::new(),
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

        // The RocksDB open (and a previously-used store's recovery
        // read) can stall on disk; run it off the loop and continue in
        // `on_opened`. The `bootstrapping` entry blocks double joins
        // and lets a `Leave` during the open release memberships.
        self.bootstrapping.insert(shard, vnodes.len());
        let factory = Arc::clone(&self.storage_factory);
        let events = self.events_tx.clone();
        let vnodes = vnodes.to_vec();
        self.tokio_handle.spawn_blocking(move || {
            let outcome = factory(shard).map(|storage| {
                let recovered = storage.load_recovered_state();
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
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let factory = Arc::clone(&self.storage_factory);
        let storage_dir = Arc::clone(&self.storage_dir);
        let vnodes = vnodes.to_vec();
        match adoption {
            SplitAdoption::ParentHalf { parent } => {
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
                self.tokio_handle.spawn(async move {
                    let _anchor = wait_for_child_anchor(&process, child).await;
                    let dir = storage_dir(child);
                    let done = spawn_blocking(move || {
                        // The observer synced the child's span at an
                        // earlier parent anchor; without following the
                        // parent to its crossing the store is stale, and
                        // a fresh snap-sync against the child anchor is
                        // the correct (if slower) path. Wipe and re-open.
                        if dir.exists() {
                            std::fs::remove_dir_all(&dir)
                                .map_err(|e| format!("stale observer store wipe: {e}"))?;
                        }
                        factory(child)
                    })
                    .await
                    .unwrap_or_else(|e| Err(format!("observer reopen task panicked: {e}")));
                    let done = match done {
                        Ok(storage) => {
                            match bootstrap_shard_state(
                                process.network(),
                                process.topology(),
                                &storage,
                                child,
                            )
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

    /// Begin an observer duty: open the child-rooted store and run the
    /// sync + ready-signal pipeline off this loop. The duty completes
    /// in [`Self::finish_observation`].
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
        let factory = Arc::clone(&self.storage_factory);
        let process = Arc::clone(&self.process);
        let events = self.events_tx.clone();
        let beacon_network = self.beacon_network.clone();
        let signing_key = Arc::clone(signing_key);
        let task = self.tokio_handle.spawn(async move {
            let opened = spawn_blocking(move || factory(child)).await;
            let done = match opened {
                Ok(Ok(storage)) => {
                    match bootstrap_observer_state(
                        process.network(),
                        process.topology(),
                        &storage,
                        via,
                        child,
                    )
                    .await
                    {
                        Ok((anchor, root, substate_count)) => {
                            // Sync complete: tell the splitting shard's
                            // committee, where the signal classifies as
                            // a ReshapeReady witness leaf and folds
                            // into the split's readiness gate.
                            let signal = observer_ready_signal(
                                &beacon_network,
                                validator,
                                &signing_key,
                                anchor,
                            );
                            let recipients: Vec<ValidatorId> = process
                                .topology()
                                .load()
                                .committee_for_shard(via)
                                .iter()
                                .copied()
                                .filter(|&v| v != validator)
                                .collect();
                            process
                                .network()
                                .notify(&recipients, &ReadySignalNotification::new(signal));
                            Ok(CompletedObservation {
                                child,
                                root,
                                substate_count,
                            })
                        }
                        Err(error) => {
                            warn!(?via, ?child, error, "Observer duty failed");
                            Err(child)
                        }
                    }
                }
                Ok(Err(error)) => {
                    warn!(?child, error, "Observer duty rejected: storage open failed");
                    Err(child)
                }
                Err(error) => {
                    warn!(?child, %error, "Observer duty's storage open panicked");
                    Err(child)
                }
            };
            // Send failure means the runner is shutting down; the duty
            // dies with it.
            let _ = events.send(SupervisorEvent::Observed(done));
        });
        self.observers.insert(
            child,
            ObserverDuty {
                via,
                validator,
                task: Some(task),
                synced: None,
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
                    substates = observation.substate_count,
                    "Observer duty complete; ready signal broadcast"
                );
                duty.task = None;
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
        shard_loop.set_time(wall_clock_local());
        if let Some(genesis) = genesis {
            shard_loop.install_genesis(genesis);
        }

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
        let cfg = self.loop_config(channels, Vec::new());
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
        info!(shard = ?shard, "Shard left and torn down");
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
            publishers: self.publishers.clone(),
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
            proposal_pool: Arc::clone(self.process.beacon_proposal_pool()),
            beacon_network: self.beacon_network.clone(),
            beacon_config_hash: self.beacon_config_hash,
            now: wall_clock_local(),
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
    let coast = parent_storage
        .get_block(anchor.height)
        .ok_or("parent chain holds no coast block at the anchor height")?;
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
        coast.block().header(),
        anchor,
    )?;

    parent_storage
        .checkpoint_into(&storage_dir(child))
        .map_err(|e| format!("child checkpoint: {e}"))?;
    let storage = factory(child)?;
    let adopted = storage
        .adopt_split_child(origin)
        .map_err(|e| format!("child adoption: {e}"))?;
    if adopted != anchor.state_root {
        return Err(format!(
            "adopted subtree root {adopted:?} does not match the beacon anchor {:?}",
            anchor.state_root,
        ));
    }
    let substate_count = storage
        .substate_count_at_version(origin.genesis_height.inner())
        .unwrap_or(0);
    let recovered = RecoveredState {
        substate_count,
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
