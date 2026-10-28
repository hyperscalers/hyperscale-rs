//! Production runner: one pinned `std::thread` per hosted shard plus
//! the shared tokio runtime.
//!
//! Each shard's thread owns its own [`ShardLoop`], its own
//! `ProdTimerManager`, and a (timer, callback, shutdown) channel triple
//! drained in priority order (`timer_rx > callback_rx`). Process-scoped
//! resources (`Arc<ProcessIo>`: network adapter, dispatch pool, tx
//! validator, topology snapshot) are cloned across every shard thread.
//!
//! The tokio runtime handles the iroh transport, the RPC server (which invokes the
//! [`TxSubmissionSender`] closure synchronously), the per-shard
//! `ProdTimerManager`s' `sleep` tasks, and the per-host metrics + GC
//! tick. Inbound network messages and dispatch callbacks land on the
//! addressed shard's callback channel; RPC submissions fan out via
//! [`ProcessIo::compute_submit_fanout`] into the relevant shards'
//! callback channels.
//!
//! [`ShardLoop`]: hyperscale_node::shard::ShardLoop
//! [`TxSubmissionSender`]: crate::rpc::TxSubmissionSender
//! [`ProcessIo::compute_submit_fanout`]: hyperscale_node::process::ProcessIo::compute_submit_fanout

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, Sender, after, never, unbounded};
use hex::encode as hex_encode;
use hyperscale_beacon::genesis::{build_genesis, seed_founding_members};
use hyperscale_core::{ParticipationChange, TimerId};
use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
use hyperscale_engine::genesis::{founding_pool, genesis_seats, seat_pool};
use hyperscale_engine::{ExecutionMode, Executor, GenesisConfig, PreviewGrants};
use hyperscale_mempool::MempoolConfig;
use hyperscale_metrics::{set_network_peers, set_pool_queue_depths, set_shard_channel_depths};
use hyperscale_metrics_prometheus::install;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_network_iroh::{IrohAdapter, IrohConfig, IrohNetwork, NetworkError};
use hyperscale_node::beacon_loop::BeaconLoop;
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::shard::{
    BeaconScopedInput, HostEvent, ShardLoop, StepOutput, ThreadShardLoop, TimerOp, TimerOwner,
    timer_event,
};
use hyperscale_node::startup::{ShardSigners, boot_routing, departed_to_serve, plan_seats};
use hyperscale_node::{
    HostedChain, NodeConfig, NodeHost, ReplicaConfig, SharedTopologySnapshot, TxStatusCache,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    BeaconChainConfig, Derivation, GenesisConfigHash, GenesisValidators, LocalTimestamp,
    MAX_UNSETTLED_TXS, NetworkDefinition, ShardId, Signer, StakePoolSeat, Transaction, TxsInFlight,
    ValidatorId,
};
use thiserror::Error;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, block_in_place};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, error, info, warn};

use crate::observe::{HeaderRing, Importing, Observation, Observations, Observer};
use crate::rpc::state::{PreviewSender, RpcPublishers, VnodeMempoolSnapshot};
use crate::rpc::{
    MempoolSnapshot, NodeStatusState, TxSubmissionSender, VnodeMempoolStats, VnodeStatusEntry,
};
use crate::status::SyncStatus;
use crate::supervisor::{
    LoopStart, ShardCommand, ShardSupervisor, StorageDirResolver, StorageFactory, SupervisorEvent,
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
/// until a placement delta seats it. Every one of them runs a beacon
/// participant on the host's beacon loop. `VnodeConfig` (which
/// does carry a shard) is the runtime-join shape the supervisor builds from a
/// `ParticipationChange`, where the target shard is known.
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
/// Required fields are passed directly to
/// [`ProductionRunner::builder`](crate::ProductionRunner::builder); optional
/// fields are set via `&mut self` chained setters and then [`Self::build`]
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
/// - `channel_capacity` - Event channel capacity (defaults to 10,000)
pub struct ProductionRunnerBuilder {
    validators: Vec<LocalValidator>,
    genesis_validators: GenesisValidators,
    shard_config: ShardConsensusConfig,
    beacon_storage: Arc<dyn BeaconStorage>,
    network_config: IrohConfig,
    dispatch: Option<Arc<PooledDispatch>>,
    channel_capacity: usize,
    /// Opens a runtime-joined shard's `RocksDB` storage.
    storage_factory: StorageFactory,
    /// Resolves a shard's storage directory for split-flip seeding.
    storage_dir: StorageDirResolver,
    publishers: RpcPublishers,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<GenesisConfig>,
    /// Network definition for transaction validation.
    /// Defaults to simulator network if not set.
    network_definition: Option<NetworkDefinition>,
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
            channel_capacity: 10_000,
            publishers: RpcPublishers::default(),
            genesis_config: None,
            network_definition: None,
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

    /// Set the network definition for transaction validation.
    #[must_use]
    pub fn network_definition(mut self, network: NetworkDefinition) -> Self {
        self.network_definition = Some(network);
        self
    }

    /// Set the dispatch implementation (optional, defaults to auto-configured pools).
    #[must_use]
    pub fn dispatch(mut self, dispatch: Arc<PooledDispatch>) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// Set the event channel capacity (default: 10,000).
    #[must_use]
    pub const fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
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

    /// Wire in the shared `NodeStatusState` so the runner publishes RPC status snapshots.
    #[must_use]
    pub fn rpc_status(mut self, status: Arc<ArcSwap<NodeStatusState>>) -> Self {
        self.publishers.node_status = Some(status);
        self
    }

    /// Wire in the shared mempool snapshot so the runner publishes mempool stats.
    #[must_use]
    pub fn mempool_snapshot(mut self, snapshot: Arc<ArcSwap<MempoolSnapshot>>) -> Self {
        self.publishers.mempool = Some(snapshot);
        self
    }

    /// Wire in the shared sync status so the runner publishes sync progress.
    #[must_use]
    pub fn sync_status(mut self, status: Arc<ArcSwap<SyncStatus>>) -> Self {
        self.publishers.sync_status = Some(status);
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
        // Per-validator signing keys, retained so a placement delta can be
        // translated into a `ShardCommand::Join` for the moved validator.
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
        let boot = build_genesis(
            &genesis_validators,
            chain_config,
            &seat_list,
            founding_pool(&seat_list),
        );
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
        let now = consensus_clock(chain_config.genesis_timestamp_ms);
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
        let mut fresh_seats: BTreeMap<ShardId, Vec<VnodeConfig>> = BTreeMap::new();
        for (shard, vnodes) in plan.joins {
            fresh_seats.insert(
                shard,
                vnodes
                    .into_iter()
                    .map(|(validator_id, signer)| VnodeConfig {
                        validator_id,
                        local_shard: shard,
                        signer,
                    })
                    .collect(),
            );
        }
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

        // Build one (timer / callback / shutdown) channel triple per
        // hosted shard so the per-shard event senders inside `ProcessIo`
        // can point at each shard's own callback channel. `ShardChannels`
        // carries both ends; the supervisor keeps the shutdown/callback
        // senders alive for the shard's lifetime.
        let mut shard_channels: BTreeMap<ShardId, ShardChannels> = BTreeMap::new();
        let mut shard_callback_txs: BTreeMap<ShardId, Sender<HostEvent>> = BTreeMap::new();
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
        let network_definition = self
            .network_definition
            .unwrap_or_else(NetworkDefinition::simulator);

        let NetworkStack { adapter, network } = build_network_stack(NetworkBuildArgs {
            network_config,
            network: network_definition,
            local_shards: local_shards.clone(),
            bind_vnodes,
            initial_validator_keys,
            topology_snapshot: topology_snapshot.clone(),
            verifier: Arc::new(BlsVerifier),
        })?;

        // Each shard's `shard_event_senders` entry points at that
        // shard's own pinned-thread callback channel — callbacks,
        // network handlers, and RPC fanout for that shard land on its
        // thread directly.
        let shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>> = shard_callback_txs
            .iter()
            .map(|(s, tx)| (*s, tx.clone()))
            .collect();
        // Beacon channel for the host's beacon loop: beacon gossip, what
        // the replicas report, and the loop's own continuations and fetch
        // answers arrive on it; the supervisor hands the receiver to the
        // beacon thread.
        let (beacon_event_tx, beacon_event_rx) = unbounded::<HostEvent>();
        let host = NodeHost::new(
            replica_config,
            chains,
            identities,
            self.beacon_storage,
            executor,
            network,
            (*dispatch).clone(),
            shard_event_senders,
            beacon_event_tx,
            topology_snapshot.clone(),
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
            chain_config.genesis_timestamp_ms,
            beacon_event_rx,
            vnode_keys.clone(),
        );

        Ok(ProductionRunner {
            host: Some(host),
            shard_channels: Some(shard_channels),
            supervisor: Some(supervisor),
            reconfigure_tx,
            reconfigure_rx: Some(reconfigure_rx),
            participation_rx: Some(participation_rx),
            vnode_keys,
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

    /// Command channel into the supervisor; cloned out via
    /// [`Self::reconfigure_handle`].
    reconfigure_tx: mpsc::Sender<ShardCommand>,
    /// Receiver drained by `run()`'s select loop.
    reconfigure_rx: Option<mpsc::Receiver<ShardCommand>>,
    /// Placement deltas emitted by the hosted shard loops, forwarded off
    /// their threads. `run()`'s select
    /// loop translates each into [`ShardCommand`]s for the supervisor.
    participation_rx: Option<mpsc::UnboundedReceiver<ParticipationChange>>,
    /// Per-validator signing keys for every validator this runner was built
    /// with, keyed for the placement-delta translation.
    vnode_keys: HashMap<ValidatorId, Arc<dyn Signer>>,

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
    fresh_seats: BTreeMap<ShardId, Vec<VnodeConfig>>,

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

    /// Get a reference to the dispatch implementation.
    #[must_use]
    pub const fn dispatch(&self) -> &Arc<PooledDispatch> {
        &self.dispatch
    }

    /// Get a reference to the network adapter.
    #[must_use]
    pub const fn network(&self) -> &Arc<IrohAdapter> {
        &self.network
    }

    /// The topology snapshot the host's shards and supervisor read.
    #[must_use]
    pub const fn topology_snapshot(&self) -> &SharedTopologySnapshot {
        &self.topology_snapshot
    }

    /// The certified headers the beacon thread keeps, the last hour per
    /// shard, summarised against the committees that signed them.
    #[must_use]
    pub fn header_ring(&self) -> Arc<HeaderRing> {
        Arc::clone(&self.publishers.headers)
    }

    /// Bytes staged by each snap-sync import in progress.
    #[must_use]
    pub fn importing(&self) -> Arc<Importing> {
        Arc::clone(&self.publishers.importing)
    }

    /// What the beacon thread has seen, as of its latest step; `None` until
    /// its first.
    #[must_use]
    pub fn observe(&self) -> watch::Receiver<Option<Arc<Observation>>> {
        self.publishers.observations.subscribe()
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
                command = reconfigure_rx.recv() => {
                    if let Some(command) = command {
                        supervisor.handle(command);
                    }
                }
                change = participation_rx.recv() => {
                    if let Some(change) = change {
                        self.apply_participation_change(&mut supervisor, &change);
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
                    supervisor.reconcile_teardown();
                    // Drive the reshape duties before reconciling joins: discovery
                    // marks a reshape-seated shard as in-flight this same tick, so
                    // the join backstop skips it rather than racing a redundant
                    // snap-sync against the orchestrator's seat.
                    supervisor.reshape_tick();
                    supervisor.reconcile_joins();
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
        for (shard, vnodes) in std::mem::take(&mut self.fresh_seats) {
            supervisor.handle(ShardCommand::Join { shard, vnodes });
        }
        (supervisor, beacon_exited)
    }

    /// Command channel into the shard supervisor. Send
    /// [`ShardCommand`]s to add or drop shard participation at runtime;
    /// they execute on the runner's tokio loop, off the shard threads.
    #[must_use]
    pub fn reconfigure_handle(&self) -> mpsc::Sender<ShardCommand> {
        self.reconfigure_tx.clone()
    }

    /// Translate a beacon-detected placement delta into supervisor
    /// commands for the moved validator. A join starts the shard's
    /// bootstrap immediately — the delta arrives a full epoch before
    /// the window opens, and the validator votes only once ready. A leave
    /// needs no command here: the reshape tick's
    /// [`ShardSupervisor::reconcile_teardown`] tears a shard down once it
    /// leaves both this host's active committee and its routing committee,
    /// so serving outlasts a departing window for exactly as long as the
    /// shard stays routable — covering a replacement's snap-sync and a
    /// merge keeper's cross-child fetch from one committed lifetime.
    ///
    /// The observer and keeper deltas (`observe`/`keep`) drive nothing
    /// here — the reshape orchestrator self-determines those duties from
    /// the committed topology projection — so this only wakes the
    /// orchestrator to re-poll and dispatches the join the placement
    /// surfaces. The orchestrator owns observer and keeper seating, so the
    /// supervisor suppresses an observer split join and a merge-execution
    /// join (see [`ShardSupervisor::handle`]).
    fn apply_participation_change(
        &self,
        supervisor: &mut ShardSupervisor,
        change: &ParticipationChange,
    ) {
        info!(
            validator = change.validator.inner(),
            join = ?change.join,
            leave = ?change.leave,
            observe = ?change.observe,
            keep = ?change.keep,
            effective_epoch = change.effective_epoch.inner(),
            "Beacon placement change detected"
        );
        // Wake the orchestrator to re-poll the committed view: a placement
        // change often accompanies the cohort/keeper draws and boundary
        // seedings its duties gate on. A `leave` needs no action here — the
        // reshape tick's `reconcile_teardown` retires the shard once it
        // ages out of this host's active and routing committees.
        supervisor.reshape_step(Vec::new());
        let Some(shard) = change.join else {
            return;
        };
        let Some(signer) = self.vnode_keys.get(&change.validator) else {
            warn!(
                validator = change.validator.inner(),
                "Placement change for a validator without a local signing key; ignored"
            );
            return;
        };
        supervisor.handle(ShardCommand::Join {
            shard,
            vnodes: vec![VnodeConfig {
                validator_id: change.validator,
                local_shard: shard,
                signer: Arc::clone(signer),
            }],
        });
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
        if let Some(ref rpc_status) = self.publishers.node_status {
            let current = rpc_status.load();
            let num_shards = self.topology_snapshot.load().num_shards();
            if current.connected_peers != peer_count || current.num_shards != num_shards {
                let mut updated = (**current).clone();
                updated.connected_peers = peer_count;
                updated.num_shards = num_shards;
                rpc_status.store(Arc::new(updated));
            }
        }

        // ── Update sync_peers on the sync status (only runner has the adapter) ──
        if let Some(ref sync_status) = self.publishers.sync_status {
            let current = sync_status.load();
            if current.sync_peers != peer_count {
                let mut updated = (**current).clone();
                updated.sync_peers = peer_count;
                sync_status.store(Arc::new(updated));
            }
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

/// Concrete `ShardLoop` type for the production runner.
pub type ProdShardLoop = ShardLoop<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

/// Per-shard receivers driving a single shard's pinned thread. Built
/// during construction and consumed when [`ProductionRunner::run`]
/// hands the bundle to [`run_shard_loop`].
pub struct ShardChannels {
    pub(crate) timer_tx: Sender<HostEvent>,
    pub(crate) timer_rx: Receiver<HostEvent>,
    pub(crate) callback_rx: Receiver<HostEvent>,
    pub(crate) shutdown_tx: Sender<()>,
    pub(crate) shutdown_rx: Receiver<()>,
    pub(crate) control_tx: Sender<ShardControl>,
    pub(crate) control_rx: Receiver<ShardControl>,
}

/// A change to a running shard loop's signers, sent by the supervisor to
/// the shard's thread.
pub enum ShardControl {
    /// Attach a validator to the loop's replica, signing with its key; the
    /// loop reports it as [`SupervisorEvent::Attached`].
    Attach(ValidatorId, Arc<dyn Signer>),
    /// Detach a validator from the loop's replica, which keeps running.
    Detach(ValidatorId),
}

impl ShardChannels {
    /// Allocate one shard's channel triple. Returns the callback sender
    /// alongside — it goes into the process-scoped event-sender maps so
    /// callbacks, network handlers, and RPC fanout land on the shard's
    /// thread.
    pub(crate) fn new() -> (Self, Sender<HostEvent>) {
        let (timer_tx, timer_rx) = unbounded();
        let (callback_tx, callback_rx) = unbounded();
        let (shutdown_tx, shutdown_rx) = unbounded();
        let (control_tx, control_rx) = unbounded();
        (
            Self {
                timer_tx,
                timer_rx,
                callback_rx,
                shutdown_tx,
                shutdown_rx,
                control_tx,
                control_rx,
            },
            callback_tx,
        )
    }
}

/// Manages tokio-based timers for one shard's pinned event loop.
///
/// Spawns async sleep tasks via the tokio handle that fire timer events
/// into the crossbeam timer channel. Every op a shard loop emits is the
/// loop's own.
struct ProdTimerManager {
    tokio_handle: TokioHandle,
    timer_tx: Sender<HostEvent>,
    active: BTreeMap<(TimerOwner, TimerId), JoinHandle<()>>,
}

impl ProdTimerManager {
    const fn new(tokio_handle: TokioHandle, timer_tx: Sender<HostEvent>) -> Self {
        Self {
            tokio_handle,
            timer_tx,
            active: BTreeMap::new(),
        }
    }

    fn process_op(&mut self, op: TimerOp) {
        match op {
            TimerOp::Set {
                owner,
                id,
                duration,
            } => {
                let key = (owner, id.clone());
                if let Some(handle) = self.active.remove(&key) {
                    handle.abort();
                }
                let timer_tx = self.timer_tx.clone();
                let timer_id = id;
                let handle = self.tokio_handle.spawn(async move {
                    sleep(duration).await;
                    let _ = timer_tx.send(timer_event(&timer_id, owner));
                });
                self.active.insert(key, handle);
            }
            TimerOp::Cancel { owner, id } => {
                if let Some(handle) = self.active.remove(&(owner, id)) {
                    handle.abort();
                }
            }
        }
    }
}

impl Drop for ProdTimerManager {
    fn drop(&mut self) {
        for handle in std::mem::take(&mut self.active).into_values() {
            handle.abort();
        }
    }
}

const METRICS_INTERVAL: Duration = Duration::from_secs(1);
const GC_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

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

/// The chain's consensus clock: [`wall_clock_local`] measured relative to
/// the genesis instant (`BeaconChainConfig::genesis_timestamp_ms`).
///
/// Weighted-time and the synthetic beacon epoch clock are anchored at
/// `epoch × epoch_duration_ms` from zero, so the state machine must be fed
/// a `now` that also starts near zero at genesis (`Epoch::GENESIS`).
/// Subtracting the genesis instant puts the runner in the same small-`now`
/// regime the simulator runs in; the beacon then paces one epoch at a time
/// instead of trying to cascade through every epoch since the Unix epoch.
/// The default offset of zero leaves the clock at raw wall-clock.
pub fn consensus_clock(genesis_offset_ms: u64) -> LocalTimestamp {
    LocalTimestamp::from_millis(
        wall_clock_local()
            .as_millis()
            .saturating_sub(genesis_offset_ms),
    )
}

/// Per-shard pinned-thread configuration.
pub struct ShardLoopConfig {
    pub(crate) timer_tx: Sender<HostEvent>,
    pub(crate) timer_rx: Receiver<HostEvent>,
    pub(crate) callback_rx: Receiver<HostEvent>,
    pub(crate) shutdown_rx: Receiver<()>,
    /// Signer changes from the supervisor.
    pub(crate) control_rx: Receiver<ShardControl>,
    pub(crate) tokio_handle: TokioHandle,
    pub(crate) initial_timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted by this shard's replica, forwarded to
    /// the runner's reconfiguration loop.
    pub(crate) participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    /// The supervisor's event channel, told of every signer the loop
    /// attaches.
    pub(crate) supervisor_tx: mpsc::UnboundedSender<SupervisorEvent>,
    /// Shared RPC publishers. Each shard's thread writes its own slots
    /// on the metrics tick (per-signer status entries, its sync-status
    /// key, and its signers' mempool snapshots); concurrent shards
    /// racing on the same `ArcSwap` lose at most one second of
    /// staleness on their slot.
    pub(crate) publishers: RpcPublishers,
    /// Genesis instant (ms since the Unix epoch) the consensus clock is
    /// measured against, from `BeaconChainConfig::genesis_timestamp_ms`.
    /// Zero leaves the loop on raw wall-clock.
    pub(crate) genesis_offset_ms: u64,
}

/// Drive one shard's [`ShardLoop`] on its pinned thread. Blocks until
/// the shard's shutdown signal fires.
///
/// Priority cascade: `timer_rx` (scheduled view-change / cleanup /
/// fetch tick fires) before `control_rx` (signer changes) before
/// `callback_rx` (off-thread results, inbound network deliveries, RPC
/// fanout). When all are empty the cascade
/// blocks on `select!` with a timeout drawn from the shard's nearest
/// batch deadline so the shard wakes precisely when its earliest
/// expiring batch is due.
///
/// However the thread exits, a panic included, the loop releases its
/// chain's registration with the host's beacon loop as it drops, before
/// the supervisor's join of this thread lets anything read its store as
/// replaced.
fn run_shard_loop(shard_loop: ProdShardLoop, config: ShardLoopConfig) {
    let mut shard_loop = ThreadShardLoop::from(shard_loop);
    drive_shard_loop(&mut shard_loop, config);
}

fn drive_shard_loop(shard_loop: &mut ProdShardLoop, mut config: ShardLoopConfig) {
    let shard = shard_loop.shard;
    info!(shard = ?shard, "Shard event loop starting");

    let mut timer_mgr = ProdTimerManager::new(config.tokio_handle.clone(), config.timer_tx.clone());
    for op in std::mem::take(&mut config.initial_timer_ops) {
        timer_mgr.process_op(op);
    }

    let mut last_metrics = Instant::now();

    loop {
        if config.shutdown_rx.try_recv().is_ok() {
            info!(shard = ?shard, "Shard event loop received shutdown signal");
            break;
        }

        let now = consensus_clock(config.genesis_offset_ms);
        shard_loop.set_time(now);

        let event = 'recv: {
            if let Ok(e) = config.timer_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(control) = config.control_rx.try_recv() {
                apply_shard_control(shard_loop, &config, &mut timer_mgr, control);
                break 'recv None;
            }
            if let Ok(e) = config.callback_rx.try_recv() {
                break 'recv Some(e);
            }

            let timeout = shard_loop
                .nearest_batch_deadline()
                .map_or(DEFAULT_TIMEOUT, |deadline| deadline.saturating_sub(now));

            crossbeam::channel::select! {
                recv(config.shutdown_rx) -> _ => {
                    info!(shard = ?shard, "Shard event loop received shutdown signal (select)");
                    return;
                }
                recv(config.timer_rx) -> e => e.ok(),
                recv(config.control_rx) -> control => {
                    if let Ok(control) = control {
                        apply_shard_control(shard_loop, &config, &mut timer_mgr, control);
                    }
                    None
                }
                recv(config.callback_rx) -> e => e.ok(),
                default(timeout) => None,
            }
        };

        if let Some(event) = event {
            let input = match event {
                HostEvent::Shard(s, input) if s == shard => input,
                HostEvent::Shard(other, _) => {
                    warn!(received_shard = ?other, this_shard = ?shard, "Dropping cross-shard event");
                    continue;
                }
                HostEvent::Process(_) => {
                    warn!(shard = ?shard, "Dropping process-scoped event on shard channel");
                    continue;
                }
                HostEvent::Beacon(_) => {
                    // Beacon-loop traffic runs on the beacon thread, never on
                    // a shard's thread.
                    warn!(shard = ?shard, "Dropping beacon-loop event on shard channel");
                    continue;
                }
            };
            // The wait may have outlasted the stamp taken before it: a
            // timer due now is handled at now, not before its deadline.
            shard_loop.set_time(consensus_clock(config.genesis_offset_ms));
            let output = shard_loop.run_step(input);
            apply_step_output(shard, output, &config, &mut timer_mgr);
        }

        shard_loop.flush_expired_batches(consensus_clock(config.genesis_offset_ms));

        // Per-shard prometheus emission + RPC status writes. Process-wide
        // pool and peer gauges are emitted from the runner's tokio tick.
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();
            shard_loop.record_prometheus();
            set_shard_channel_depths(
                shard.inner(),
                config.callback_rx.len(),
                config.timer_rx.len(),
            );
            update_shard_rpc_state(shard_loop, &config);
        }
    }

    info!(shard = ?shard, "Shard event loop exiting");
}

/// Carry out one of the supervisor's signer changes on the shard's
/// thread.
fn apply_shard_control(
    shard_loop: &mut ProdShardLoop,
    config: &ShardLoopConfig,
    timer_mgr: &mut ProdTimerManager,
    control: ShardControl,
) {
    shard_loop.set_time(consensus_clock(config.genesis_offset_ms));
    match control {
        ShardControl::Attach(validator, signer) => {
            let output = shard_loop.attach_signer(validator, signer);
            apply_step_output(shard_loop.shard, output, config, timer_mgr);
        }
        ShardControl::Detach(validator) => {
            if shard_loop.detach_signer(validator) {
                scrub_mempool_slot(config, validator);
            }
        }
    }
}

/// Hand one step's output to the timer manager, the runner and the
/// supervisor. Send failures mean the runner is shutting down.
fn apply_step_output(
    shard: ShardId,
    output: StepOutput,
    config: &ShardLoopConfig,
    timer_mgr: &mut ProdTimerManager,
) {
    for op in output.timer_ops {
        timer_mgr.process_op(op);
    }
    for change in output.participation_changes {
        let _ = config.participation_tx.send(change);
    }
    for validator in output.attached {
        let _ = config
            .supervisor_tx
            .send(SupervisorEvent::Attached { shard, validator });
    }
    for shard in output.reseats {
        let _ = config.supervisor_tx.send(SupervisorEvent::Reseat { shard });
    }
}

/// Drop a validator's mempool slot once it detaches from this shard's
/// replica. The slot is keyed by validator alone and written only by the
/// threads whose replica it is attached to, so a departed one would
/// otherwise hold a stale snapshot, and one still attached on another
/// shard republishes it on that shard's next tick.
fn scrub_mempool_slot(config: &ShardLoopConfig, validator: ValidatorId) {
    if let Some(ref mempool_snapshot) = config.publishers.mempool {
        mempool_snapshot.rcu(|current| {
            let mut updated = (**current).clone();
            updated.vnodes.remove(&validator.inner());
            Arc::new(updated)
        });
    }
}

/// Write this shard's contribution into the shared RPC state. Each slot is
/// keyed by `shard_id.inner()`, and the writes go through `ArcSwap::rcu` so a
/// co-hosted shard's thread (or the supervisor's `scrub_rpc_state`)
/// interleaving on the same `ArcSwap` can't drop this shard's update — the
/// compare-and-retry re-applies it against the concurrent winner.
fn update_shard_rpc_state(shard_loop: &ProdShardLoop, config: &ShardLoopConfig) {
    let shard_key = shard_loop.shard.inner();

    // ── /status: one entry per attached signer ─────────────────────
    let state = shard_loop.replica();
    let mempool = state.mempool_coordinator();
    let pending = mempool.pending_count();
    let in_flight = state.shard_coordinator().committed_in_flight();
    if let Some(ref rpc_status) = config.publishers.node_status {
        rpc_status.rcu(|current| {
            let mut updated = (**current).clone();
            updated.vnodes.retain(|v| v.shard != shard_key);
            for validator in shard_loop.signers() {
                updated.vnodes.push(VnodeStatusEntry {
                    validator_id: validator.inner(),
                    shard: shard_key,
                    block_height: state.shard_coordinator().committed_height().inner(),
                    view: state.shard_coordinator().view().inner(),
                    state_root_hash: hex_encode(state.last_committed_jmt_root().as_bytes()),
                    mempool: VnodeMempoolStats {
                        pending_count: pending,
                        in_flight_count: in_flight,
                        total_count: mempool.len(),
                    },
                });
            }
            updated.vnodes.sort_by_key(|v| (v.shard, v.validator_id));
            Arc::new(updated)
        });
    }

    // ── /sync: per-shard block-sync state ──────────────────────────
    if let Some(ref sync_status) = config.publishers.sync_status {
        let block_sync = shard_loop.io.block_sync_status();
        sync_status.rcu(|current| {
            let mut updated = (**current).clone();
            updated.shards.insert(shard_key, block_sync.clone());
            Arc::new(updated)
        });
    }

    // ── Mempool: the replica's snapshot under each attached signer,
    // feeding RPC submission backpressure.
    if let Some(ref mempool_snapshot) = config.publishers.mempool {
        let remote_congestion_threshold = TxsInFlight::new(MAX_UNSETTLED_TXS * 4 / 5);
        mempool_snapshot.rcu(|current| {
            let mut updated = (**current).clone();
            for validator in shard_loop.signers() {
                updated.vnodes.insert(
                    validator.inner(),
                    VnodeMempoolSnapshot {
                        pending_count: pending,
                        in_flight_count: in_flight,
                        total_count: mempool.len(),
                        updated_at: Some(Instant::now()),
                        accepting_rpc_transactions: in_flight < MAX_UNSETTLED_TXS,
                        at_pending_limit: mempool.at_pending_limit(),
                        remote_shard_in_flight: state
                            .remote_headers_coordinator()
                            .remote_shard_in_flight(),
                        remote_congestion_threshold,
                    },
                );
            }
            Arc::new(updated)
        });
    }
}

/// Spawn one shard's pinned thread. No core affinity — modern Linux
/// CFS keeps long-lived CPU-bound threads cache-warm without explicit
/// pinning, and the per-shard model already isolates each shard's
/// scheduling from the others.
pub fn spawn_shard_loop(
    shard_loop: ProdShardLoop,
    config: ShardLoopConfig,
) -> std::thread::JoinHandle<()> {
    let shard = shard_loop.shard;
    std::thread::Builder::new()
        .name(format!("shard-loop-{}", shard.inner()))
        .spawn(move || run_shard_loop(shard_loop, config))
        .expect("failed to spawn shard-loop thread")
}

/// Concrete `BeaconLoop` type for the production runner.
pub type ProdBeaconLoop = BeaconLoop<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

/// Configuration for a host's pinned beacon thread — the sibling of
/// [`ShardLoopConfig`]. The beacon loop runs no shard consensus, so there
/// are no batches: it drains beacon traffic, what the replicas report and
/// the chains' registrations, and surfaces the seat triggers its
/// participants raise.
pub struct BeaconLoopConfig {
    /// Beacon gossip, what the replicas report, the chains' registrations,
    /// and the loop's own continuations and fetch answers.
    pub(crate) beacon_rx: Receiver<HostEvent>,
    /// Stops the beacon thread on teardown.
    pub(crate) shutdown_rx: Receiver<()>,
    /// Placement deltas the participants surface (their own seat
    /// triggers), forwarded to the runner's reconfiguration loop.
    pub(crate) participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    /// Genesis instant the consensus clock is measured against.
    pub(crate) genesis_offset_ms: u64,
    /// Where each step's reported headers are summarised and kept.
    pub(crate) headers: Arc<HeaderRing>,
    /// Where each step's observation is published.
    pub(crate) observations: Observations,
    /// The genesis this host's network started from, stamped on every
    /// observation.
    pub(crate) genesis: GenesisConfigHash,
}

/// Apply one beacon step's output: fold its timer ops into the loop's
/// deadline table (keyed by the timer's owner and its [`TimerId`]) and
/// forward its placement deltas to the runner's reconfiguration loop.
fn apply_beacon_step_output(
    deadlines: &mut BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    participation_tx: &mpsc::UnboundedSender<ParticipationChange>,
    now: LocalTimestamp,
    output: StepOutput,
) {
    for op in output.timer_ops {
        match op {
            TimerOp::Set {
                owner: owner @ (TimerOwner::Participant(_) | TimerOwner::Beacon),
                id,
                duration,
            } => {
                let fire = now
                    .as_millis()
                    .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
                deadlines.insert((owner, id), LocalTimestamp::from_millis(fire));
            }
            TimerOp::Cancel {
                owner: owner @ (TimerOwner::Participant(_) | TimerOwner::Beacon),
                id,
            } => {
                deadlines.remove(&(owner, id));
            }
            TimerOp::Set { .. } | TimerOp::Cancel { .. } => {
                warn!("Beacon loop emitted a shard-owned timer op; dropping");
            }
        }
    }
    for change in output.participation_changes {
        // Send failure means the runner is shutting down.
        let _ = participation_tx.send(change);
    }
}

/// Drive a host's [`BeaconLoop`] on its pinned thread, blocking until the
/// shutdown signal fires. Dropping the loop on the way out, by a return or
/// by a panic unwinding the thread, closes every participant's release
/// gate. The loop only consumes beacon events ([`HostEvent::Beacon`]); shard /
/// process envelopes never reach this channel and there is no batch
/// flushing. Its timers live in a thread-local deadline table: every
/// participant's beacon timer chain fires here, and the loop's own fetch
/// tick retries its held fetches.
fn run_beacon_loop(mut beacon: ProdBeaconLoop, config: BeaconLoopConfig) {
    info!("Beacon event loop starting");
    drive_beacon_loop(&mut beacon, config);
    info!("Beacon event loop exiting");
}

fn drive_beacon_loop(beacon: &mut ProdBeaconLoop, config: BeaconLoopConfig) {
    let BeaconLoopConfig {
        beacon_rx,
        shutdown_rx,
        participation_tx,
        genesis_offset_ms,
        headers,
        observations,
        genesis,
    } = config;
    let mut observer = Observer::new(genesis, headers, observations);

    let mut deadlines: BTreeMap<(TimerOwner, TimerId), LocalTimestamp> = BTreeMap::new();

    // The participants armed their beacon startup timers at construction,
    // but a genesis ceremony on this host may already have drained that
    // scratch into ops this thread never sees. Re-arming is idempotent
    // (replace at the table, identical durations), so arm-and-drain
    // unconditionally.
    let now = consensus_clock(genesis_offset_ms);
    beacon.set_time(now);
    let startup = beacon.startup_output();
    apply_beacon_step_output(&mut deadlines, &participation_tx, now, startup);
    observe_step(&mut observer, beacon);

    loop {
        if shutdown_rx.try_recv().is_ok() {
            info!("Beacon event loop received shutdown signal");
            return;
        }
        let now = consensus_clock(genesis_offset_ms);
        beacon.set_time(now);

        // Fire due timers: each fire re-enters the loop as its owner's
        // input, and its re-arms fold back into the table.
        for input in take_due_beacon_timers(&mut deadlines, now) {
            let output = beacon.run_step(input);
            apply_beacon_step_output(&mut deadlines, &participation_tx, now, output);
            observe_step(&mut observer, beacon);
        }

        let wake = beacon_wake(&deadlines, now);
        let event = crossbeam::channel::select! {
            recv(shutdown_rx) -> _ => {
                info!("Beacon event loop received shutdown signal (select)");
                return;
            }
            recv(beacon_rx) -> e => e.ok(),
            recv(wake) -> _ => None,
        };
        // The select blocks until the wake; re-read the clock so the step
        // and the deadlines its re-arms produce measure from the wake, not
        // the pre-sleep instant.
        let now = consensus_clock(genesis_offset_ms);
        beacon.set_time(now);
        // A timer wake fires at the loop top; a stray non-beacon envelope
        // is dropped.
        let Some(HostEvent::Beacon(input)) = event else {
            continue;
        };
        let output = beacon.run_step(input);
        apply_beacon_step_output(&mut deadlines, &participation_tx, now, output);
        observe_step(&mut observer, beacon);
    }
}

/// Hand the step's adopted epochs and reported headers to the observer.
fn observe_step(observer: &mut Observer, beacon: &mut ProdBeaconLoop) {
    let adopted = beacon.take_adopted();
    let admitted = beacon.take_admitted();
    observer.step(adopted, admitted, beacon.beacon_state(), beacon.schedule());
}

/// Remove every beacon timer due at `now` from the table, returning the
/// input each fire feeds the loop.
fn take_due_beacon_timers(
    deadlines: &mut BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    now: LocalTimestamp,
) -> Vec<BeaconScopedInput> {
    let (due, pending): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(deadlines)
        .into_iter()
        .partition(|(_, fire)| fire.as_millis() <= now.as_millis());
    *deadlines = pending;
    due.into_keys()
        .filter_map(|(owner, id)| match timer_event(&id, owner) {
            HostEvent::Beacon(input) => Some(input),
            _ => None,
        })
        .collect()
}

/// What the beacon thread's select wakes on besides an event: the nearest
/// deadline in the table, or nothing at all while the table is empty.
fn beacon_wake(
    deadlines: &BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    now: LocalTimestamp,
) -> Receiver<Instant> {
    deadlines.values().min().map_or_else(never, |fire| {
        after(Duration::from_millis(
            fire.as_millis().saturating_sub(now.as_millis()),
        ))
    })
}

/// Spawn the host's beacon thread, mirroring [`spawn_shard_loop`]. The
/// thread holds `exited` until it ends, by a return or by a panic
/// unwinding it, so its receiver hears of the end either way.
pub fn spawn_beacon_loop(
    beacon: ProdBeaconLoop,
    config: BeaconLoopConfig,
    exited: oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("beacon-loop".to_string())
        .spawn(move || {
            let _exited = exited;
            run_beacon_loop(beacon, config);
        })
        .expect("failed to spawn beacon-loop thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing armed the beacon thread waits on events alone; the
    /// loop's fetch tick, once armed, wakes it when due and fires as the
    /// loop's own tick.
    #[test]
    fn the_beacon_fetch_tick_arms_the_threads_wake_and_fires_on_the_loop() {
        let mut deadlines = BTreeMap::new();
        let (participation_tx, _participation_rx) = mpsc::unbounded_channel();
        let now = LocalTimestamp::from_millis(1_000);
        assert!(
            beacon_wake(&deadlines, now).try_recv().is_err(),
            "nothing armed: no wake",
        );

        let interval = Duration::from_secs(3_600);
        let mut armed = StepOutput::default();
        armed.timer_ops.push(TimerOp::Set {
            owner: TimerOwner::Beacon,
            id: TimerId::FetchTick,
            duration: interval,
        });
        apply_beacon_step_output(&mut deadlines, &participation_tx, now, armed);
        assert!(
            beacon_wake(&deadlines, now).try_recv().is_err(),
            "an armed tick not yet due does not wake the thread",
        );
        assert!(take_due_beacon_timers(&mut deadlines, now).is_empty());

        let due = LocalTimestamp::from_millis(1_000 + 3_600_000);
        assert!(
            beacon_wake(&deadlines, due).try_recv().is_ok(),
            "a due tick wakes the thread at once",
        );
        assert!(matches!(
            take_due_beacon_timers(&mut deadlines, due).as_slice(),
            [BeaconScopedInput::FetchTick],
        ));
        assert!(deadlines.is_empty(), "a fired tick leaves the table");
    }
}
