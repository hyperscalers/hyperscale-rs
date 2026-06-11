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

use crossbeam::channel::{Sender, unbounded};
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::host::{attach_shard, detach_shard};
use hyperscale_node::process_io::ProcessIo;
use hyperscale_node::{NodeConfig, SeatVnodeGroup, TimerOp, VnodeInit, seat_vnode_group};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::{BlockHeight, GenesisConfigHash, NetworkDefinition, ShardId};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::bootstrap::bootstrap_shard_state;
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
            participation_tx,
            shards: HashMap::new(),
            bootstrapping: HashMap::new(),
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
            callback_tx,
        );
        shard_loop.set_time(wall_clock_local());

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
