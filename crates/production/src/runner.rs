//! Production runner: one pinned `std::thread` per hosted shard plus
//! the shared tokio runtime.
//!
//! Each shard's thread owns its own [`ShardLoop`], its own
//! `ProdTimerManager`, and its timer, input and shutdown channels,
//! drained timers first. Process-scoped
//! resources (`Arc<ProcessIo>`: network adapter, dispatch pool, tx
//! validator, topology snapshot) are cloned across every shard thread.
//!
//! The tokio runtime handles the iroh transport, the RPC server (which invokes the
//! [`TxSubmissionSender`] closure synchronously), the per-shard
//! `ProdTimerManager`s' `sleep` tasks, and the per-host metrics + GC
//! tick. Inbound network messages land on the addressed shard's bounded
//! network lane and dispatch callbacks on its internal lane; RPC
//! submissions fan out via [`ProcessIo::compute_submit_fanout`] into the
//! relevant shards' internal lanes.
//!
//! [`ShardLoop`]: hyperscale_node::shard::ShardLoop
//! [`TxSubmissionSender`]: crate::rpc::TxSubmissionSender
//! [`ProcessIo::compute_submit_fanout`]: hyperscale_node::process::ProcessIo::compute_submit_fanout

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use crossbeam::channel::unbounded;
use hyperscale_beacon::genesis::{build_genesis, seed_founding_members};
use hyperscale_core::ParticipationChange;
use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
use hyperscale_engine::genesis::{genesis_seats, seat_pool};
use hyperscale_engine::{ExecutionMode, Executor, GenesisConfig, PreviewGrants};
use hyperscale_mempool::MempoolConfig;
use hyperscale_metrics::{set_network_peers, set_pool_queue_depths};
use hyperscale_metrics_prometheus::install;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_network_iroh::{IrohAdapter, IrohConfig, IrohNetwork, NetworkError};
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::seating::{ShardSigners, boot_routing, departed_to_serve, plan_seats};
use hyperscale_node::shard::{HostEvent, ShardInbox};
use hyperscale_node::{
    HostResources, HostedChain, NodeConfig, NodeHost, ReplicaConfig, SharedTopologySnapshot,
    TxStatusCache,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
#[cfg(feature = "test-utils")]
use hyperscale_types::Derivation;
use hyperscale_types::{
    BeaconChainConfig, GenesisValidators, LocalTimestamp, NetworkDefinition, ShardId, Signer,
    StakePoolSeat, Transaction, ValidatorId,
};
use thiserror::Error;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::block_in_place;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, error, info};

use crate::rpc::TxSubmissionSender;
use crate::rpc::state::{PreviewSender, RpcPublishers};
use crate::shard_thread::ShardChannels;
use crate::supervisor::{
    AddValidatorError, LoopStart, ShardCommand, ShardSupervisor, StorageDirResolver, StorageFactory,
};
use crate::transport::{NetworkBuildArgs, NetworkStack, build_network_stack};

// ═══════════════════════════════════════════════════════════════════════════
// RunnerError
// ═══════════════════════════════════════════════════════════════════════════

/// Errors from the production runner.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// Catch-all setup or send failure (e.g. missing builder field).
    #[error("Send error: {0}")]
    SendError(String),
    /// The beacon thread ended while the node ran. Every chain the host
    /// runs takes its schedule from it, so the node stops.
    #[error("Beacon loop exited while the node ran")]
    BeaconLoopExited,
    /// Underlying network backend error.
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
}

// ═══════════════════════════════════════════════════════════════════════════
// ShutdownHandle
// ═══════════════════════════════════════════════════════════════════════════

/// Handle for shutting down a running `ProductionRunner`.
///
/// When dropped, signals the runner to exit gracefully.
#[derive(Debug)]
pub struct ShutdownHandle {
    tx: Option<oneshot::Sender<()>>,
}

impl ShutdownHandle {
    /// Trigger shutdown (consumes the handle).
    pub fn shutdown(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// A command to the running host, executed on the runner's loop.
pub enum RunnerCommand {
    /// A shard-membership change.
    #[cfg(feature = "test-utils")]
    Shard(ShardCommand),
    /// Take on another validator; the reply says whether it did.
    AddValidator {
        /// The validator and its signing key.
        validator: LocalValidator,
        /// Where the outcome goes.
        reply: oneshot::Sender<Result<(), AddValidatorError>>,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// VnodeConfig
// ═══════════════════════════════════════════════════════════════════════════

/// One hosted validator's identity + per-validator state inputs.
///
/// A [`ProductionRunner`] hosts a `Vec<VnodeConfig>` alongside a single
/// `Arc<TopologySnapshot>` shared across every shard loop. Entries mapped to
/// the same `local_shard` share one `NodeHost`, one network endpoint, one
/// `ShardIo` and one replica, each attached to it as a signer with its own
/// signing key.
#[derive(Clone)]
pub struct VnodeConfig {
    /// This vnode's validator identity.
    pub validator_id: ValidatorId,
    /// This vnode's home shard.
    pub local_shard: ShardId,
    /// Signing identity for this validator's votes, proposals, and the
    /// per-session validator-bind attestation. Held by `Arc` so the same
    /// allocation is shared between the bind service, the state machine,
    /// and delegated dispatch closures.
    pub signer: Arc<dyn Signer>,
}

impl LocalValidator {
    /// Validator `validator_id`, signing with the BLS key its 32-byte seed
    /// makes.
    #[must_use]
    pub fn from_seed(validator_id: ValidatorId, seed: &[u8; 32]) -> Self {
        Self {
            validator_id,
            signer: Arc::new(BlsSigner::from_seed(seed)),
        }
    }
}

/// One validator a host runs, as supplied to the runner at startup.
///
/// Shard participation is **not** named here — it is a projection of beacon
/// state, so the runner derives it: a validator the committed beacon state
/// places `OnShard` is seated on that shard (its storage opened via the
/// factory); one that is `Pooled` (or otherwise unseated) is seated nowhere
/// until committed placement seats it. Every one of them runs a beacon
/// participant on the host's beacon loop. A host takes on another one while
/// it runs through [`RunnerCommand::AddValidator`]. `VnodeConfig` (which
/// does carry a shard) is the shape the supervisor seats a validator in once
/// its target shard is known.
#[derive(Clone)]
pub struct LocalValidator {
    /// The validator identity this host runs.
    pub validator_id: ValidatorId,
    /// Signing identity for votes, proposals, and the validator-bind
    /// attestation. `Arc` so the bind service, state machine, and dispatch
    /// closures share one allocation.
    pub signer: Arc<dyn Signer>,
}

// ═══════════════════════════════════════════════════════════════════════════
// ProductionRunnerBuilder
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for constructing a [`ProductionRunner`].
///
/// Required fields are passed directly to [`ProductionRunner::builder`];
/// optional fields are set via `&mut self` chained setters and then [`Self::build`]
/// is called.
///
/// Required fields (taken at construction):
/// - `validators` - One [`LocalValidator`] per validator this host runs.
///   Shard participation is not supplied; the runner derives each
///   validator's seat (or pool membership) from the committed beacon state
///   and opens any seated shard's storage via `storage_factory`.
/// - `genesis_validators` - The validator placement the genesis beacon chain is
///   built from; the initial [`TopologySnapshot`] is projected from that
///   genesis state and seeded into the `ProcessIo`'s `ArcSwap`.
/// - `shard_config` - Consensus configuration parameters
/// - `network` - iroh configuration for peer-to-peer communication
/// - `storage_factory` - Opens a shard's storage (at startup for a derived
///   seat, and at runtime for a beacon-driven join).
///
/// Optional fields:
/// - `dispatch` - Dispatch implementation (defaults to auto-configured)
pub struct ProductionRunnerBuilder {
    validators: Vec<LocalValidator>,
    genesis_validators: GenesisValidators,
    shard_config: ShardConsensusConfig,
    beacon_storage: Arc<dyn BeaconStorage>,
    network_config: IrohConfig,
    dispatch: Option<Arc<PooledDispatch>>,
    /// Opens a runtime-joined shard's `RocksDB` storage.
    storage_factory: StorageFactory,
    /// Resolves a shard's storage directory for split-flip seeding.
    storage_dir: StorageDirResolver,
    publishers: RpcPublishers,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<GenesisConfig>,
    /// Mempool configuration.
    mempool_config: MempoolConfig,
    /// Provision coordinator configuration.
    provision_config: ProvisionConfig,
    /// Beacon chain sizing knobs (epoch duration, reshape thresholds,
    /// committee and shard sizing). `None` uses
    /// [`BeaconChainConfig::default`].
    beacon_chain_config: Option<BeaconChainConfig>,
}

impl ProductionRunnerBuilder {
    /// Create a new builder with the required fields. Optional fields use
    /// their defaults until overridden via the setter methods.
    ///
    /// # Panics
    ///
    /// Panics if `validators` is empty.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // storage + identity threading
    pub(crate) fn new(
        validators: Vec<LocalValidator>,
        genesis_validators: GenesisValidators,
        shard_config: ShardConsensusConfig,
        beacon_storage: Arc<dyn BeaconStorage>,
        network_config: IrohConfig,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
    ) -> Self {
        assert!(
            !validators.is_empty(),
            "ProductionRunnerBuilder needs at least one validator"
        );
        Self {
            validators,
            genesis_validators,
            shard_config,
            beacon_storage,
            network_config,
            dispatch: None,
            publishers: RpcPublishers::default(),
            genesis_config: None,
            // Harness default: the routing overlay runs in production
            // tests; the validator binary always overrides this from its
            // config file, where the overlay defaults off.
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
            beacon_chain_config: None,
            storage_factory,
            storage_dir,
        }
    }

    /// Set the dispatch implementation (optional, defaults to auto-configured pools).
    #[must_use]
    pub fn dispatch(mut self, dispatch: Arc<PooledDispatch>) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// Set the mempool configuration.
    #[must_use]
    pub const fn mempool_config(mut self, config: MempoolConfig) -> Self {
        self.mempool_config = config;
        self
    }

    /// Set the provision coordinator configuration.
    #[must_use]
    pub const fn provision_config(mut self, config: ProvisionConfig) -> Self {
        self.provision_config = config;
        self
    }

    /// Set the beacon chain configuration (epoch duration, reshape
    /// thresholds, committee and shard sizing). Defaults to
    /// [`BeaconChainConfig::default`] when unset; the reshape suite uses
    /// this to enable a trigger and shorten epochs.
    #[must_use]
    pub const fn beacon_chain_config(mut self, config: BeaconChainConfig) -> Self {
        self.beacon_chain_config = Some(config);
        self
    }

    /// Set the genesis configuration for initial state.
    #[must_use]
    pub fn genesis_config(mut self, config: GenesisConfig) -> Self {
        self.genesis_config = Some(config);
        self
    }

    /// Build the production runner.
    ///
    /// Creates all channels, the `NodeHost`, networking adapters, and supporting
    /// infrastructure. The `NodeHost` is held in an `Option` so it can be moved
    /// to the pinned thread when `run()` is called.
    ///
    /// Must be called from within a tokio runtime context — the iroh adapter
    /// and request manager capture `Handle::current()`.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::SendError`] if dispatch initialization fails,
    /// or [`RunnerError::NetworkError`] if the endpoint fails to bind.
    #[allow(clippy::too_many_lines)] // straight-line construction; further splits add no clarity
    pub fn build(self) -> Result<ProductionRunner, RunnerError> {
        // Install the Prometheus metrics backend before anything records metrics.
        install();

        let validators = self.validators;
        // Per-validator signing keys, retained so a committed placement can
        // seat the moved validator.
        let vnode_keys: HashMap<ValidatorId, Arc<dyn Signer>> = validators
            .iter()
            .map(|v| (v.validator_id, Arc::clone(&v.signer)))
            .collect();
        let genesis_validators = self.genesis_validators;
        let shard_config = self.shard_config;
        let network_config = self.network_config;
        let chain_config = self.beacon_chain_config.unwrap_or_default();
        let dispatch = match self.dispatch {
            Some(pools) => pools,
            None => Arc::new(
                PooledDispatch::new(ThreadPoolConfig::minimal(), TokioHandle::current())
                    .map_err(|e| RunnerError::SendError(e.to_string()))?,
            ),
        };

        // Genesis: build the beacon chain from the validator placement.
        let beacon_network = genesis_validators.network.clone();
        let seat_list: Vec<StakePoolSeat> = genesis_seats(
            &self
                .genesis_config
                .as_ref()
                .map_or_default(|config| config.pools.clone()),
        );
        let boot = build_genesis(&genesis_validators, chain_config, &seat_list, seat_pool);
        // Warm-restart: resume the beacon coordinator from the latest
        // committed (block, state) in storage. On an empty store, commit the
        // genesis pair first so fresh-start and restart converge on the same
        // load — the coordinator's resume epoch is whatever state it's handed.
        boot.commit_if_empty(self.beacon_storage.as_ref());
        let beacon_config_hash = boot.config_hash;
        let (_, beacon_state) = self
            .beacon_storage
            .latest_committed()
            .expect("beacon chain is non-empty after the genesis commit above");

        // The host starts on the topology its committed beacon state projects
        // — the head the host's beacon loop resumes on, derived in the same
        // `BeaconState → derive_topology_snapshot` direction the runtime fold
        // publishes. Routing, validator keys, and seating all read it before
        // the first fold of this run.
        let shared_topology =
            Arc::new(beacon_state.derive_topology_snapshot(beacon_network.clone()));
        let topology_snapshot: SharedTopologySnapshot =
            Arc::new(ArcSwap::from(Arc::clone(&shared_topology)));

        // Extract initial validator keys for network-layer bind verification.
        let initial_validator_keys: Arc<ValidatorKeyMap> = Arc::new(
            shared_topology
                .global_validator_set()
                .validators
                .iter()
                .map(|v| (v.validator_id, v.public_key))
                .collect(),
        );

        // `Arc::clone` lets the bind service and the state machine share the
        // single key allocation each validator carries.
        let bind_vnodes: Vec<(ValidatorId, Arc<dyn Signer>)> = validators
            .iter()
            .map(|v| (v.validator_id, Arc::clone(&v.signer)))
            .collect();

        // Participation is a projection of the committed beacon state; the
        // operator names no shard. Each placed shard's storage opens through
        // the same factory a runtime join uses. A store that committed past
        // genesis on its own shard's chain resumes here; any other is a join
        // like any other. A split child's clone of its parent that the
        // reshape never adopted is the reshape duty's to seed again, or the
        // join's to wipe; otherwise the supervisor seats a store on the
        // network genesis it installed, installs that genesis on a fresh
        // store of a never-crossed genesis shard, snap-syncs against an
        // attested anchor, or parks until one is seatable — so its
        // validators follow the beacon on the beacon loop until that join seats
        // them. A validator routing still names on a live shard resumes
        // there too, as a running host keeps it seated.
        let now = wall_clock_local();
        let routing = boot_routing(self.beacon_storage.as_ref(), &beacon_network, now);
        let plan = plan_seats(
            &beacon_state,
            &routing,
            &bind_vnodes,
            |shard| (self.storage_dir)(shard).exists(),
            |shard| {
                (self.storage_factory)(&(self.storage_dir)(shard), shard)
                    .map_err(|e| RunnerError::SendError(format!("open storage for {shard:?}: {e}")))
            },
        )?;
        let placed = plan.placed_shards();
        let mut storages: BTreeMap<ShardId, Arc<RocksDbShardStorage>> = BTreeMap::new();
        let mut seated_by_shard: BTreeMap<ShardId, ShardSigners> = BTreeMap::new();
        for (shard, (store, vnodes)) in plan.resumed {
            storages.insert(shard, store);
            seated_by_shard.insert(shard, vnodes);
        }
        let fresh_seats: BTreeMap<ShardId, Vec<ValidatorId>> = plan
            .joins
            .into_iter()
            .map(|(shard, vnodes)| (shard, vnodes.into_iter().map(|(id, _)| id).collect()))
            .collect();
        // The network's genesis config: replicated into every fresh store
        // the supervisor opens for a post-genesis join or observer duty,
        // and installed whole by a fresh store on a never-crossed genesis
        // shard, so every store's substate side agrees.
        let mut bootstrap_config = self.genesis_config.clone().unwrap_or_default();
        bootstrap_config.pools = seat_list;
        // Each seated pool's founding members, read off the beacon's own
        // folded genesis state: the contract's record of who a pool
        // operates has to agree with the beacon's from the first block,
        // and this is where both exist.
        seed_founding_members(&boot.state, &mut bootstrap_config.pools, seat_pool);
        let engine_bootstrap = EngineBootstrap {
            config: bootstrap_config,
        };
        // The VM engine's world seats the same pools a genesis install
        // writes, and holds the derivation this node's replicas resolve
        // envelopes through.
        let executor: Arc<Executor> = Arc::new(Executor::with_genesis(
            &engine_bootstrap.config.pools,
            &engine_bootstrap.config.packages,
            ExecutionMode::Serial,
        ));

        // Seated validators boot from their own shard's recovered state;
        // every held key runs a beacon participant.
        let replica_config = ReplicaConfig {
            verifier: Arc::new(BlsVerifier),
            derivation: executor.derivation(),
            code: Arc::clone(&executor) as _,
            beacon_network: beacon_network.clone(),
            beacon_config_hash,
            shard_config: shard_config.clone(),
            mempool_config: self.mempool_config.clone(),
            provision_config: self.provision_config,
        };
        let mut resumed: BTreeMap<ShardId, RecoveredState> = BTreeMap::new();
        for shard in seated_by_shard.keys() {
            resumed.insert(*shard, storages[shard].load_recovered_state(*shard));
        }

        let mut local_shards: BTreeSet<ShardId> = seated_by_shard.keys().copied().collect();
        // A shard this host ran before a cut still holds what its
        // counterparts read from it — the settled sets an abandonment record
        // is held to, the terminal evidence a successor derives from — and
        // routing names its ex-members for as long as the beacon keeps its
        // boundary. A running host keeps such a shard's loop up, with a
        // signer for every local validator still named in one of its window
        // roles, until the supervisor's teardown reconcile retires it; a
        // restart resumes the same loop from the store on disk, under the
        // same rule and against the routing the process boots on. A store
        // no local validator still serves from is left closed. Without this
        // a restart inside the window leaves a counterpart asking for a set
        // nobody answers until the evidence expires, and the legs it would
        // abandon stay in their records.
        let departed = departed_to_serve(
            &beacon_state.boundaries,
            &placed,
            |shard| (self.storage_dir)(shard).exists(),
            &shared_topology,
            &routing,
            &bind_vnodes,
        );
        for (shard, serving) in departed {
            info!(
                ?shard,
                vnodes = serving.len(),
                "Serving a departed shard's store from disk"
            );
            let store = (self.storage_factory)(&(self.storage_dir)(shard), shard)
                .map_err(|e| RunnerError::SendError(format!("open storage for {shard:?}: {e}")))?;
            resumed.insert(shard, store.load_recovered_state(shard));
            seated_by_shard.insert(shard, serving);
            storages.insert(shard, store);
            local_shards.insert(shard);
        }
        let local_shards = local_shards;

        // Build each hosted shard's channels so the per-shard inboxes
        // inside `ProcessIo` point at that shard's own input lanes.
        // `ShardChannels` carries the receiving ends; the supervisor keeps
        // the shutdown sender alive for the shard's lifetime.
        let mut shard_channels: BTreeMap<ShardId, ShardChannels> = BTreeMap::new();
        let mut shard_callback_txs: BTreeMap<ShardId, ShardInbox> = BTreeMap::new();
        for shard in &local_shards {
            let (channels, callback_tx) = ShardChannels::new();
            shard_callback_txs.insert(*shard, callback_tx);
            shard_channels.insert(*shard, channels);
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // A handle per shard for `NodeHost::new`; the runner keeps its own
        // handles for GC and metrics, and the recovered states to resume
        // each loop from.
        let chains: Vec<HostedChain<'_, RocksDbShardStorage>> = seated_by_shard
            .into_iter()
            .map(|(shard, signers)| HostedChain {
                shard,
                storage: (*storages[&shard]).clone(),
                recovered: &resumed[&shard],
                signers,
            })
            .collect();
        let identities: Vec<(ValidatorId, Arc<dyn Signer>)> = bind_vnodes.clone();

        let NetworkStack { adapter, network } = build_network_stack(NetworkBuildArgs {
            network_config,
            network: NetworkDefinition::simulator(),
            local_shards: local_shards.clone(),
            bind_vnodes,
            initial_validator_keys,
            topology_snapshot: topology_snapshot.clone(),
            verifier: Arc::new(BlsVerifier),
        })?;

        // Each shard's `shard_event_senders` entry is that shard's own
        // pinned-thread inbox — callbacks, network handlers, and RPC
        // fanout for that shard land on its thread directly.
        let shard_event_senders: BTreeMap<ShardId, ShardInbox> = shard_callback_txs
            .iter()
            .map(|(s, tx)| (*s, tx.clone()))
            .collect();
        // Beacon channel for the host's beacon loop: beacon gossip, what
        // the replicas report, and the loop's own continuations and fetch
        // answers arrive on it; the supervisor hands the receiver to the
        // beacon thread.
        let (beacon_event_tx, beacon_event_rx) = unbounded::<HostEvent>();
        let host = NodeHost::new(
            &replica_config,
            HostResources {
                beacon_storage: self.beacon_storage,
                executor,
                network,
                dispatch: (*dispatch).clone(),
                shard_event_senders,
                beacon_event_sender: beacon_event_tx,
                topology_snapshot: topology_snapshot.clone(),
            },
            chains,
            identities,
            NodeConfig::default(),
            now,
        );

        let tx_status = Arc::clone(host.process().tx_status());

        let storages = Arc::new(std::sync::Mutex::new(storages));
        let (reconfigure_tx, reconfigure_rx) = mpsc::channel(16);
        let (participation_tx, participation_rx) = mpsc::unbounded_channel();
        let supervisor = ShardSupervisor::new(
            Arc::clone(host.process()),
            shard_config,
            self.mempool_config,
            self.provision_config,
            beacon_network,
            beacon_config_hash,
            Arc::new(BlsVerifier),
            TokioHandle::current(),
            self.publishers.clone(),
            Arc::clone(&storages),
            self.storage_factory,
            self.storage_dir,
            engine_bootstrap,
            participation_tx,
            chain_config.epoch_duration_ms,
            beacon_event_rx,
            vnode_keys,
        );

        Ok(ProductionRunner {
            host: Some(host),
            shard_channels: Some(shard_channels),
            supervisor: Some(supervisor),
            reconfigure_tx,
            reconfigure_rx: Some(reconfigure_rx),
            participation_rx: Some(participation_rx),
            network: adapter,
            topology_snapshot,
            storages,
            dispatch,
            publishers: self.publishers,
            local_shards,
            resumed,
            fresh_seats,
            tx_status,
            shutdown_rx: Some(shutdown_rx),
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ProductionRunner
// ═══════════════════════════════════════════════════════════════════════════

/// Production runner: one pinned `std::thread` per hosted shard plus
/// the shared tokio runtime.
///
/// Each shard's thread owns its own [`ShardLoop`] driving that shard's
/// state machine, storage I/O, and dispatch fan-out. The tokio runtime
/// handles async I/O routing, RPC transaction submission, sync/fetch
/// management, and the per-host metrics + GC tick.
///
/// [`ShardLoop`]: hyperscale_node::shard::ShardLoop
pub struct ProductionRunner {
    /// The composed [`NodeHost`], wrapped in `Option` because it's
    /// decomposed via `into_parts()` and moved onto the per-shard
    /// threads at `run()` time. `None` thereafter.
    host: Option<ProdHost>,

    /// Per-shard receivers (timer + callback + shutdown), built at
    /// construction and consumed when `run()` spawns the shard threads.
    shard_channels: Option<BTreeMap<ShardId, ShardChannels>>,

    /// Owns the pinned shard threads from `run()` onward and executes
    /// runtime membership commands.
    supervisor: Option<ShardSupervisor>,

    /// Command channel into the running host; cloned out via
    /// [`Self::reconfigure_handle`].
    reconfigure_tx: mpsc::Sender<RunnerCommand>,
    /// Receiver drained by `run()`'s select loop.
    reconfigure_rx: Option<mpsc::Receiver<RunnerCommand>>,
    /// Placement deltas the host's beacon loop emits for its validators.
    /// `run()`'s select loop hands each to the supervisor, which holds
    /// their signing keys.
    participation_rx: Option<mpsc::UnboundedReceiver<ParticipationChange>>,

    /// Network adapter: the host's connections, shared with the
    /// [`Network`](hyperscale_network::Network) the node sends through.
    network: Arc<IrohAdapter>,
    /// Network topology snapshot (lock-free `ArcSwap`, updated on topology changes).
    topology_snapshot: SharedTopologySnapshot,
    /// Per-shard `RocksDB` handles for the JMT GC tick and storage
    /// metrics, shared with the supervisor, which inserts and removes
    /// entries as shards join and leave.
    storages: Arc<std::sync::Mutex<BTreeMap<ShardId, Arc<RocksDbShardStorage>>>>,
    /// Thread pool dispatch.
    dispatch: Arc<PooledDispatch>,
    /// Every shard this runner hosts at startup.
    local_shards: BTreeSet<ShardId>,
    /// What each hosted shard's store recovered at startup, which its
    /// loop resumes consensus from once it runs.
    resumed: BTreeMap<ShardId, RecoveredState>,
    /// Seats whose store opened fresh at startup, joined through the
    /// supervisor once it runs.
    fresh_seats: BTreeMap<ShardId, Vec<ValidatorId>>,

    /// Shared RPC publishers; the metrics tick stamps peer counts into
    /// the status slots.
    publishers: RpcPublishers,

    /// Process-wide transaction status cache, shared from `NodeHost`
    /// for lock-free RPC queries. Every hosted shard writes into it;
    /// shard membership changes don't touch it.
    tx_status: Arc<TxStatusCache>,

    /// Shutdown signal receiver (external shutdown request).
    shutdown_rx: Option<oneshot::Receiver<()>>,
    /// Shutdown handle sender (returned to caller via `shutdown_handle()`).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ProductionRunner {
    /// Create a new builder for constructing a production runner. The
    /// required fields are taken at construction; optional fields are then
    /// set via the builder's setters before calling
    /// [`ProductionRunnerBuilder::build`].
    #[must_use]
    #[allow(clippy::too_many_arguments)] // storage handles threaded explicitly
    pub fn builder(
        validators: Vec<LocalValidator>,
        genesis_validators: GenesisValidators,
        shard_config: ShardConsensusConfig,
        beacon_storage: Arc<dyn BeaconStorage>,
        network_config: IrohConfig,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
    ) -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new(
            validators,
            genesis_validators,
            shard_config,
            beacon_storage,
            network_config,
            storage_factory,
            storage_dir,
        )
    }

    /// Get a reference to the network adapter.
    #[must_use]
    pub const fn network(&self) -> &Arc<IrohAdapter> {
        &self.network
    }

    /// The topology snapshot the host's shards and supervisor read.
    #[cfg(feature = "test-utils")]
    #[must_use]
    pub const fn topology_snapshot(&self) -> &SharedTopologySnapshot {
        &self.topology_snapshot
    }

    /// What the host publishes: its status, sync and mempool readouts, the
    /// beacon thread's observations and header ring, and its imports.
    pub(crate) fn publishers(&self) -> RpcPublishers {
        self.publishers.clone()
    }

    /// Get the process-wide transaction status cache shared from
    /// `NodeHost`. Same instance every shard thread writes into;
    /// passed directly to the RPC server for lock-free status lookups.
    #[must_use]
    pub fn tx_status_cache(&self) -> Arc<TxStatusCache> {
        Arc::clone(&self.tx_status)
    }

    /// The derivation this host's replicas resolve envelopes through, held
    /// by its engine, which learns every instance and package its chains
    /// commit.
    ///
    /// # Panics
    ///
    /// Panics if `run()` has already consumed the host.
    #[cfg(feature = "test-utils")]
    #[must_use]
    pub fn derivation(&self) -> Arc<dyn Derivation> {
        self.host
            .as_ref()
            .expect("host must exist for derivation")
            .process()
            .derivation()
    }

    /// Build a transaction-submission closure for RPC handlers.
    ///
    /// The closure captures `Arc<ProcessIo>` plus the per-shard event
    /// senders; each invocation reads the lock-free topology snapshot,
    /// computes the touched-shard fanout via
    /// [`ProcessIo::compute_submit_fanout`], and pushes the resulting
    /// `AdmitTransaction` / `AdmitAndGossipTransaction` /
    /// `GossipTransaction` envelopes onto the relevant per-shard
    /// channels. Returns `true` on success, `false` only when every
    /// per-shard channel is closed (shutdown).
    ///
    /// [`ProcessIo::compute_submit_fanout`]: hyperscale_node::process::ProcessIo::compute_submit_fanout
    /// # Panics
    ///
    /// Panics if `run()` has already consumed the host. The closure
    /// captures the `Arc<ProcessIo>` at call time, so build it before
    /// taking the loop.
    #[must_use]
    pub fn tx_submission_sender(&self) -> TxSubmissionSender {
        let process = Arc::clone(
            self.host
                .as_ref()
                .expect("host must exist for tx_submission_sender")
                .process(),
        );
        Arc::new(move |routable: Arc<Transaction>| process.submit_transaction(&routable))
    }

    /// A closure that asks a hosted shard what a transaction would do.
    ///
    /// The RPC counterpart of [`Self::tx_submission_sender`], and its
    /// opposite in every way that matters: it commits nothing, gossips
    /// nothing, and runs the whole VM on the caller's own thread rather
    /// than on a shard driver. Callers run it on a blocking worker for
    /// that reason, and the driver never sees it.
    ///
    /// # Panics
    ///
    /// Panics if `run()` has already consumed the host, as
    /// [`Self::tx_submission_sender`] does and for the same reason.
    #[must_use]
    pub fn preview_sender(&self) -> PreviewSender {
        let process = Arc::clone(
            self.host
                .as_ref()
                .expect("host must exist for preview_sender")
                .process(),
        );
        Arc::new(move |tx: &Transaction| process.preview_transaction(tx, PreviewGrants::default()))
    }

    /// Take the shutdown handle.
    ///
    /// Returns a handle that when dropped triggers graceful shutdown.
    /// Can only be called once; subsequent calls return `None`.
    pub fn shutdown_handle(&mut self) -> Option<ShutdownHandle> {
        self.shutdown_tx
            .take()
            .map(|tx| ShutdownHandle { tx: Some(tx) })
    }

    // ═══════════════════════════════════════════════════════════════════
    // Main Run Loop
    // ═══════════════════════════════════════════════════════════════════

    /// Run the production node.
    ///
    /// 1. Registers the host's inbound network handlers
    /// 2. Extracts the `NodeHost` and channel receivers for the pinned threads
    /// 3. Spawns a pinned thread per resumed shard, the beacon loop, and
    ///    the supervisor joins for the seats whose store opened fresh
    /// 4. Runs a minimal loop for metrics collection and shutdown handling
    /// 5. On shutdown, signals the pinned threads and joins them
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::BeaconLoopExited`] when the beacon thread
    /// ends, by a panic, before the shutdown signal; the runner then shuts
    /// down as it would on the signal.
    ///
    /// # Panics
    ///
    /// Panics if `run` is called twice on the same runner (the `NodeHost` and
    /// channel receivers have already been moved to the pinned thread).
    pub async fn run(mut self) -> Result<(), RunnerError> {
        let config = self.dispatch.config();
        info!(
            shards = ?self.local_shards,
            consensus_threads = config.consensus_threads,
            throughput_threads = config.throughput_threads,
            pin_cores = config.pin_cores,
            "Starting production runner (per-shard thread architecture)"
        );

        let (mut supervisor, mut beacon_exited) = self.start_threads();

        // ── 4. Metrics + maintenance + reconfiguration + shutdown loop.
        let mut metrics_tick = interval(Duration::from_secs(1));
        metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Paces the reshape orchestrator: every tick re-polls the committed
        // view and re-asserts in-window ready signals (the orchestrator emits
        // a fresh signal each step, so this cadence is the re-assert cadence).
        let mut reshape_tick = interval(Duration::from_secs(1));
        reshape_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_gc = Instant::now();
        let gc_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut shutdown_rx = self.shutdown_rx.take().expect("shutdown_rx already taken");
        let mut reconfigure_rx = self
            .reconfigure_rx
            .take()
            .expect("reconfigure_rx already taken");
        let mut participation_rx = self
            .participation_rx
            .take()
            .expect("participation_rx already taken");
        let mut supervisor_events_rx = supervisor
            .take_events_rx()
            .expect("supervisor events_rx already taken");

        let mut outcome = Ok(());
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = &mut beacon_exited => {
                    error!("Beacon thread exited while the node ran; shutting down");
                    outcome = Err(RunnerError::BeaconLoopExited);
                    break;
                }
                command = reconfigure_rx.recv() => match command {
                    #[cfg(feature = "test-utils")]
                    Some(RunnerCommand::Shard(command)) => supervisor.handle(command),
                    Some(RunnerCommand::AddValidator { validator, reply }) => {
                        let _ = reply.send(supervisor.add_validator(validator));
                    }
                    None => {}
                },
                change = participation_rx.recv() => {
                    if let Some(change) = change {
                        supervisor.on_participation_change(&change);
                    }
                }
                event = supervisor_events_rx.recv() => {
                    if let Some(event) = event {
                        supervisor.on_event(event);
                    }
                }
                _ = metrics_tick.tick() => {
                    self.collect_metrics();
                    if !gc_in_flight.load(std::sync::atomic::Ordering::Relaxed)
                        && last_gc.elapsed() >= GC_INTERVAL
                    {
                        last_gc = Instant::now();
                        self.schedule_jmt_gc(&gc_in_flight);
                    }
                }
                _ = reshape_tick.tick() => {
                    // Drive the reshape duties before reconciling seats: discovery
                    // marks a reshape-seated shard as in-flight this same tick, so
                    // the join backstop skips it rather than racing a redundant
                    // snap-sync against the orchestrator's seat.
                    supervisor.reshape_tick();
                    supervisor.reconcile_seats();
                }
            }
        }

        // ── 5. Fan shutdown to every shard thread in parallel, joining them
        // without holding up this runtime's other work, then close every
        // connection so the peers see this host leave.
        info!("Sending shutdown to shard threads");
        block_in_place(|| supervisor.shutdown_all());
        self.network.shutdown().await;

        info!("Production runner stopped");
        outcome
    }

    /// Start the pinned threads: wire the inbound handlers, resume each
    /// hosted shard on its own thread, start the beacon thread, and join
    /// the seats whose store opened fresh. Returns the supervisor that
    /// owns the threads and the receiver that hears the beacon thread end.
    fn start_threads(&mut self) -> (ShardSupervisor, oneshot::Receiver<()>) {
        // ── 1. Wire the inbound handlers while NodeHost still owns the loops.
        let mut host = self
            .host
            .take()
            .expect("host already taken (run called twice?)");
        host.register_inbound_handlers();

        // ── 2. Decompose NodeHost into Arc<ProcessIo> + per-shard ShardLoops.
        let (_process, shards, beacon) = host.into_parts();

        let mut shard_channels = self
            .shard_channels
            .take()
            .expect("shard_channels already taken");

        // ── 3. Resume each hosted shard from its recovered state on its own
        // pinned thread, recorded in the supervisor so runtime membership
        // commands can stop them.
        let mut supervisor = self.supervisor.take().expect("supervisor already taken");
        let mut resumed = std::mem::take(&mut self.resumed);
        for (shard, shard_loop) in shards {
            let channels = shard_channels
                .remove(&shard)
                .expect("channels allocated for every hosted shard");
            let recovered = resumed
                .remove(&shard)
                .expect("every hosted shard recovered its store at build");
            supervisor.start_loop(shard_loop, channels, LoopStart::Resume(&recovered));
        }

        // Every host runs its beacon loop, with a participant for every key
        // it holds, seated or not.
        let beacon_exited = supervisor.install_beacon_loop(beacon);
        for (shard, validators) in std::mem::take(&mut self.fresh_seats) {
            supervisor.handle(ShardCommand::Join { shard, validators });
        }
        (supervisor, beacon_exited)
    }

    /// Command channel into the running host. Send [`RunnerCommand`]s to
    /// add or drop shard participation, or to take on another validator, at
    /// runtime; they execute on the runner's tokio loop, off the shard
    /// threads.
    #[must_use]
    pub fn reconfigure_handle(&self) -> mpsc::Sender<RunnerCommand> {
        self.reconfigure_tx.clone()
    }

    // ═══════════════════════════════════════════════════════════════════
    // Metrics Collection
    // ═══════════════════════════════════════════════════════════════════

    /// Collect and export metrics.
    ///
    /// Called every 1 second from the metrics loop. Collects pool queue depths,
    /// peer count, and cleans up stale RPC tracking entries.
    fn collect_metrics(&self) {
        // ── Thread pool queue depths ─────────────────────────────────────
        set_pool_queue_depths(
            self.dispatch.queue_depth(DispatchPool::Consensus),
            self.dispatch.queue_depth(DispatchPool::Throughput),
        );

        // ── Peer count ───────────────────────────────────────────────────
        let peer_count = self.network.cached_peer_count();
        set_network_peers(peer_count);

        // ── Update RPC status with peer count + live shard count ─────────
        let rpc_status = &self.publishers.node_status;
        let current = rpc_status.load();
        let num_shards = self.topology_snapshot.load().num_shards();
        if current.connected_peers != peer_count || current.num_shards != num_shards {
            let mut updated = (**current).clone();
            updated.connected_peers = peer_count;
            updated.num_shards = num_shards;
            rpc_status.store(Arc::new(updated));
        }

        // ── Update sync_peers on the sync status (only runner has the adapter) ──
        let sync_status = &self.publishers.sync_status;
        let current = sync_status.load();
        if current.sync_peers != peer_count {
            let mut updated = (**current).clone();
            updated.sync_peers = peer_count;
            sync_status.store(Arc::new(updated));
        }
    }

    /// Dispatch per-shard JMT + state-history GC off the tokio runtime.
    /// `in_flight` serializes runs so a slow disk can't stack concurrent
    /// passes on top of each other.
    fn schedule_jmt_gc(&self, in_flight: &Arc<std::sync::atomic::AtomicBool>) {
        in_flight.store(true, std::sync::atomic::Ordering::Relaxed);
        let storages: Vec<(ShardId, Arc<RocksDbShardStorage>)> = self
            .storages
            .lock()
            .expect("storages lock")
            .iter()
            .map(|(s, st)| (*s, Arc::clone(st)))
            .collect();
        let gc_flag = Arc::clone(in_flight);
        TokioHandle::current().spawn_blocking(move || {
            for (shard, storage) in storages {
                let deleted = storage.run_jmt_gc();
                if deleted > 0 {
                    debug!(shard = ?shard, deleted, "JMT garbage collection completed");
                }
                let history_deleted = storage.run_state_history_gc();
                if history_deleted > 0 {
                    debug!(shard = ?shard, history_deleted, "State-history GC completed");
                }
                let heights_deleted = storage.run_chain_gc(shard);
                if heights_deleted > 0 {
                    debug!(shard = ?shard, heights_deleted, "Chain GC completed");
                }
            }
            gc_flag.store(false, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

/// Concrete `NodeHost` type for the production runner.
type ProdHost = NodeHost<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

const GC_INTERVAL: Duration = Duration::from_secs(30);

/// Mint the `host`'s monotonic local clock as a `LocalTimestamp` (ms since
/// UNIX epoch). Used to set the state machine's clock before each step.
/// Same epoch as `WeightedTimestamp` so the proposer-skew comparison works
/// without unit conversion. NTP back-steps are absorbed by saturating
/// arithmetic on `LocalTimestamp`.
pub fn wall_clock_local() -> LocalTimestamp {
    let ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    LocalTimestamp::from_millis(ms)
}
