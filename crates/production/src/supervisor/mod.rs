//! Runtime shard membership for the production runner.
//!
//! [`ShardSupervisor`] owns every pinned shard thread after startup and
//! executes membership changes off those threads (a thread can't safely
//! spawn or join its siblings): a [`ShardCommand::Join`] opens the
//! shard's storage, builds its replica from the host's beacon chain with
//! the joining validators attached as signers, wires the process-scoped
//! maps via [`attach_shard`], and spawns the pinned thread; a
//! `ShardCommand::Leave` detaches one validator's signer and tears
//! the shard down — shutdown signal, thread join, map unwire, storage
//! drop — only when the last local validator leaves.
//!
//! Membership is refcounted per shard because a host runs several
//! validators and one replica per shard: two local validators on one
//! shard are two signers on one replica, and a departing one must not
//! tear the other down. A join for a shard already running attaches its
//! validators to that thread's replica over a [`ShardControl`] channel,
//! and a validator that loses its role in a shard that stays up is
//! detached the same way.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crossbeam::channel::Receiver;
use hyperscale_core::ParticipationChange;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_iroh::{AddVnodeError, IrohNetwork};
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::event::{BeaconScopedInput, HostEvent, Registration, TimerOp};
use hyperscale_node::reshape::{PreparedStores, ReshapeCompletion, ReshapeOrchestrator};
use hyperscale_node::{NodeConfig, ProcessIo};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    Block, GenesisConfigHash, NetworkDefinition, ShardId, Signer, ValidatorId, Verifier,
};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::warn;

use crate::rpc::RpcPublishers;
use crate::runner::{LocalValidator, VnodeConfig, wall_clock_local};
use crate::shard_thread::{ProdShardLoop, ShardChannels, ShardLoopConfig, spawn_shard_loop};

mod beacon;
mod membership;
mod reshape;
mod seats;

use beacon::BeaconThread;
use hyperscale_node::seating::Replaced;
use membership::CompletedBootstrap;
use seats::{SeatTable, ShardThread};

/// The process-scoped resource bundle as the production runner types it.
type ProdProcessIo = ProcessIo<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

/// Opens (or creates) one shard's `RocksDB` storage at a directory.
/// Supplied by the validator binary, which owns the storage config.
pub type StorageFactory =
    Arc<dyn Fn(&Path, ShardId) -> Result<Arc<RocksDbShardStorage>, String> + Send + Sync>;

/// Resolves one shard's storage directory at the host's data-dir
/// convention — the location a seat opens through [`StorageFactory`].
///
/// A split flip seeds the directory from a parent checkpoint before the
/// open, and a rebuild stages a replacement beside it. Supplied by the
/// validator binary alongside the factory.
pub type StorageDirResolver = Arc<dyn Fn(ShardId) -> PathBuf + Send + Sync>;

/// The directory `shard`'s store lives at under `root`.
///
/// One convention for every open (startup seats, runtime joins, split-flip
/// seeding), so a restart reopens what an earlier seat created. Depth
/// qualifies the name:
/// trie paths alone collide across depths once shards split (a child
/// `leaf(2, 0)` and its parent `leaf(1, 0)` share the path value 0).
#[must_use]
pub fn shard_data_dir(root: &Path, shard: ShardId) -> PathBuf {
    root.join(format!("shard-d{}p{}", shard.depth(), shard.path()))
}

/// Why a running host would not take on a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddValidatorError {
    /// The host already runs it.
    #[error("validator {} is already hosted", .0.inner())]
    Hosted(ValidatorId),
    /// The host runs as many validators as one bind attests.
    #[error("the host runs as many validators as it can attest")]
    Full,
    /// The topology holds another key for the validator.
    #[error("validator {}'s key is not the one the network holds", .0.inner())]
    KeyMismatch(ValidatorId),
}

/// A runtime shard-membership change, executed by [`ShardSupervisor`].
#[derive(Clone)]
pub enum ShardCommand {
    /// Begin hosting a shard with the given local validators. The first
    /// join for a shard brings up storage, thread, and subscriptions;
    /// a join for a shard already running attaches the validators its
    /// replica does not yet carry.
    Join {
        /// Shard to host.
        shard: ShardId,
        /// Hosted validators participating in the shard's consensus, by
        /// id; the supervisor holds their signing keys. An id this host
        /// does not hold is ignored.
        validators: Vec<ValidatorId>,
    },
    /// Release one local validator's membership in `shard`. The shard's
    /// thread, subscriptions, and storage are torn down when the last
    /// local validator leaves.
    #[cfg(feature = "test-utils")]
    Leave {
        /// Shard to release the membership of.
        shard: ShardId,
        /// The validator leaving it.
        validator: ValidatorId,
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
        /// The join's validators, threaded through the open.
        vnodes: Vec<VnodeConfig>,
        /// The opened storage and its recovered state, or the open
        /// failure.
        outcome: Result<(Arc<RocksDbShardStorage>, RecoveredState), String>,
    },
    /// A snap-sync bootstrap settled (`Err` carries the failed shard).
    Bootstrapped(Result<CompletedBootstrap, ShardId>),
    /// A running shard's rebuild settled its staging store.
    Rebuilt {
        /// Which rebuild settled, so a completion a teardown or a later
        /// rebuild superseded is dropped.
        rebuild: u64,
        /// The store staged at the attested anchor, or the shard whose
        /// rebuild failed.
        outcome: Result<CompletedBootstrap, ShardId>,
        /// Why the store it replaces is replaced.
        replaced: Replaced,
    },
    /// A reshape orchestrator io result settled.
    Reshape(ReshapeCompletion<Arc<RocksDbShardStorage>>),
    /// A shard loop attached a validator to its replica.
    Attached {
        /// Shard whose replica it attached to.
        shard: ShardId,
        /// The validator now attached there.
        validator: ValidatorId,
    },
    /// A shard loop's store needs a height beneath every serving peer's
    /// chain floor: block sync cannot carry it forward.
    Reseat {
        /// Shard whose store fell behind.
        shard: ShardId,
    },
    /// A chain's registration with the host's beacon loop came back.
    Registered {
        /// Shard the registration is for.
        shard: ShardId,
        /// Which seat of the shard registered, so a reply for one a later
        /// seat superseded is released.
        seat: u64,
        /// The token, schedule and chain config the loop handed back.
        registration: Registration,
    },
    /// A departing shard's thread joined; the unwire can finish.
    TornDown {
        /// Shard whose thread exited.
        shard: ShardId,
        /// The departed validators' ids, for the RPC scrub.
        validator_ids: Vec<u64>,
    },
}

/// What a seated loop's consensus starts from.
#[derive(Clone, Copy)]
pub enum LoopStart<'a> {
    /// A fresh store: commit this genesis block.
    Genesis(&'a Block),
    /// A store that committed a chain: restore from what it recovered.
    Resume(&'a RecoveredState),
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
    /// Verifies the commit proofs a split child's follower assembles from
    /// the parent chain it tails.
    verifier: Arc<dyn Verifier>,
    tokio_handle: TokioHandle,
    publishers: RpcPublishers,
    /// Per-shard `RocksDB` handles, shared with the runner's GC tick.
    storages: Arc<Mutex<BTreeMap<ShardId, Arc<RocksDbShardStorage>>>>,
    storage_factory: StorageFactory,
    storage_dir: StorageDirResolver,
    /// Replicated into every fresh store this supervisor opens — a
    /// post-genesis joiner or observer store must carry the engine
    /// bootstrap on its substate side before its span imports — and the
    /// genesis config a fresh store on a never-crossed genesis shard
    /// installs.
    engine_bootstrap: EngineBootstrap,
    /// Cloned into every spawned shard loop's config so placement
    /// deltas reach the runner's reconfiguration loop.
    participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    /// Every shard's seat here, in whichever phase it holds.
    seats: SeatTable,
    /// The sans-io reshape orchestrator — discovers this host's observer
    /// and keeper duties from the committed-state projection and sequences
    /// them. The supervisor pumps it on a timer and on every placement
    /// change, performing the io it returns.
    reshape: ReshapeOrchestrator,
    /// In-flight reshape stores, keyed by the duty's store shard (a
    /// splitting child or a merging parent), held between the
    /// orchestrator's open and seat requests. Seated stores move into
    /// [`Self::storages`].
    reshape_stores: PreparedStores<Arc<RocksDbShardStorage>>,
    /// Beacon epoch length, for the keeper's deterministic merged-genesis
    /// cut derivation. Matches the beacon's own chain config.
    epoch_duration_ms: u64,
    /// Background-work completions land here; the runner's select loop
    /// drains the paired receiver into [`Self::on_event`].
    events_tx: mpsc::UnboundedSender<SupervisorEvent>,
    /// Receiver side, taken by the runner's `run()` loop.
    events_rx: Option<mpsc::UnboundedReceiver<SupervisorEvent>>,
    /// The host's pinned beacon thread. Every host runs one from startup
    /// until shutdown.
    beacon: Option<BeaconThread>,
    /// The host's beacon-event channel receiver, handed to the beacon
    /// thread.
    beacon_event_rx: Receiver<HostEvent>,
    /// Signing keys for the host's local validators.
    vnode_keys: HashMap<ValidatorId, Arc<dyn Signer>>,
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
        verifier: Arc<dyn Verifier>,
        tokio_handle: TokioHandle,
        publishers: RpcPublishers,
        storages: Arc<Mutex<BTreeMap<ShardId, Arc<RocksDbShardStorage>>>>,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
        engine_bootstrap: EngineBootstrap,
        participation_tx: mpsc::UnboundedSender<ParticipationChange>,
        epoch_duration_ms: u64,
        beacon_event_rx: Receiver<HostEvent>,
        vnode_keys: HashMap<ValidatorId, Arc<dyn Signer>>,
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
            verifier,
            tokio_handle,
            publishers,
            storages,
            storage_factory,
            storage_dir,
            engine_bootstrap,
            participation_tx,
            seats: SeatTable::default(),
            reshape: ReshapeOrchestrator::new(vnode_keys.keys().copied().collect()),
            reshape_stores: PreparedStores::new(),
            epoch_duration_ms,
            beacon: None,
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
            SupervisorEvent::Rebuilt {
                rebuild,
                outcome,
                replaced,
            } => self.on_rebuilt(rebuild, outcome, replaced),
            SupervisorEvent::Reshape(io) => self.on_reshape_io(io),
            SupervisorEvent::Attached { shard, validator } => self.on_attached(shard, validator),
            SupervisorEvent::Reseat { shard } => self.reseat(shard),
            SupervisorEvent::Registered {
                shard,
                seat,
                registration,
            } => self.on_registered(shard, seat, &registration),
            SupervisorEvent::TornDown {
                shard,
                validator_ids,
            } => self.on_torn_down(shard, &validator_ids),
        }
    }

    /// Start a seated shard's consensus and spawn its pinned thread,
    /// recording it. Every loop starts here: the shards a host resumes at
    /// startup, and every runtime seat.
    ///
    /// The genesis commit, or the committed-state restore, runs on the
    /// loop before its thread spawns. Either arms the pacemaker, cleanup
    /// and beacon timers and latches a proposal attempt; the restore also
    /// replays what execution owes from the recovered chain. A loop whose
    /// committee has no member elsewhere hears nothing to start it, so
    /// without this its signers never propose or time out.
    pub(crate) fn start_loop(
        &mut self,
        mut shard_loop: ProdShardLoop,
        channels: ShardChannels,
        start: LoopStart<'_>,
    ) {
        shard_loop.set_time(wall_clock_local());
        let initial_timer_ops = match start {
            LoopStart::Genesis(genesis) => shard_loop.install_genesis(genesis),
            LoopStart::Resume(recovered) => shard_loop.resume_committed(recovered),
        };
        let shard = shard_loop.shard;
        let shutdown_tx = channels.shutdown_tx.clone();
        let control_tx = channels.control_tx.clone();
        let validator_ids = shard_loop.signers().map(ValidatorId::inner).collect();
        let cfg = self.loop_config(channels, initial_timer_ops);
        let join = spawn_shard_loop(shard_loop, cfg);
        self.seats.run(
            shard,
            ShardThread {
                join,
                shutdown_tx,
                control_tx,
                queued: Vec::new(),
                validator_ids,
            },
        );
    }

    /// Execute one membership command.
    pub(crate) fn handle(&mut self, command: ShardCommand) {
        match command {
            ShardCommand::Join { shard, validators } => {
                let vnodes = self.hosted(shard, &validators);
                if !vnodes.is_empty() {
                    self.join(shard, &vnodes);
                }
            }
            #[cfg(feature = "test-utils")]
            ShardCommand::Leave { shard, validator } => self.leave(shard, validator),
        }
    }

    /// Host `validator` from now on, on the running host: the transport
    /// attests it and hands its record to every linked host, the supervisor
    /// holds its key, and the beacon loop runs its participation, in that
    /// order, so nothing it signs leaves before the transport carries it.
    /// Seating follows from its placement, as for any hosted validator.
    ///
    /// # Errors
    ///
    /// [`AddValidatorError`] if the host already runs it, runs as many as
    /// one bind attests, or the topology holds another key for it.
    pub(crate) fn add_validator(
        &mut self,
        validator: LocalValidator,
    ) -> Result<(), AddValidatorError> {
        let LocalValidator {
            validator_id,
            signer,
        } = validator;
        if self.vnode_keys.contains_key(&validator_id) {
            return Err(AddValidatorError::Hosted(validator_id));
        }
        if self
            .process
            .topology_snapshot()
            .load()
            .public_key(validator_id)
            .is_some_and(|key| key != signer.public_key())
        {
            return Err(AddValidatorError::KeyMismatch(validator_id));
        }
        self.process
            .network()
            .add_vnode((validator_id, Arc::clone(&signer)))
            .map_err(|error| match error {
                AddVnodeError::Hosted(id) => AddValidatorError::Hosted(id),
                AddVnodeError::Full => AddValidatorError::Full,
            })?;
        self.vnode_keys.insert(validator_id, Arc::clone(&signer));
        self.reshape.add_me(validator_id);
        let _ = self.process.beacon_event_sender().send(HostEvent::Beacon(
            BeaconScopedInput::AddParticipant {
                validator: validator_id,
                signer,
            },
        ));
        tracing::info!(
            validator = validator_id.inner(),
            "Validator added to the running host"
        );
        Ok(())
    }

    /// The hosted validators among `validators`, seated on `shard` with
    /// their signing keys.
    fn hosted(&self, shard: ShardId, validators: &[ValidatorId]) -> Vec<VnodeConfig> {
        validators
            .iter()
            .filter_map(|&validator_id| {
                let Some(signer) = self.vnode_keys.get(&validator_id) else {
                    warn!(
                        validator = validator_id.inner(),
                        "A join names a validator this host holds no key for; ignored"
                    );
                    return None;
                };
                Some(VnodeConfig {
                    validator_id,
                    local_shard: shard,
                    signer: Arc::clone(signer),
                })
            })
            .collect()
    }

    /// Act on a beacon-detected placement delta for one of this host's
    /// validators: log it and wake the reshape orchestrator to re-poll the
    /// committed view, since a placement change often accompanies the
    /// cohort/keeper draws and boundary seedings its duties gate on.
    ///
    /// No join or leave is issued here. [`Self::reconcile_seats`] carries
    /// out the seat changes
    /// [`reconcile`](hyperscale_node::seating::reconcile) plans, the plan
    /// the simulation carries out too: it seats every placed validator and
    /// tears a shard down once it leaves both this host's active committee
    /// and its routing committee. The observer
    /// and keeper deltas drive nothing either: the orchestrator
    /// self-determines those duties from the committed projection.
    pub(crate) fn on_participation_change(&mut self, change: &ParticipationChange) {
        tracing::info!(
            validator = change.validator.inner(),
            join = ?change.join,
            leave = ?change.leave,
            observe = ?change.observe,
            keep = ?change.keep,
            effective_epoch = change.effective_epoch.inner(),
            "Beacon placement change detected"
        );
        self.reshape_step(Vec::new());
    }

    /// Stop every shard thread: fan the shutdown signals first so the
    /// threads wind down in parallel, then join them all. The beacon
    /// thread is stopped alongside them.
    pub(crate) fn shutdown_all(&mut self) {
        self.teardown_beacon_loop();
        let (running, draining) = self.seats.drain_all();
        for (shard, entry) in &running {
            if entry.shutdown_tx.send(()).is_err() {
                tracing::debug!(shard = ?shard, "Shard already exited");
            }
        }
        for entry in running.into_values() {
            if let Err(e) = entry.join.join() {
                warn!("Shard thread panicked: {e:?}");
            }
        }
        for draining in draining {
            let join = draining
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(join) = join
                && let Err(e) = join.join()
            {
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
            inputs: channels.inputs,
            shutdown_rx: channels.shutdown_rx,
            control_rx: channels.control_rx,
            tokio_handle: self.tokio_handle.clone(),
            initial_timer_ops,
            participation_tx: self.participation_tx.clone(),
            supervisor_tx: self.events_tx.clone(),
            publishers: self.publishers.clone(),
        }
    }
}
