//! Production runner: one pinned `std::thread` per hosted shard plus
//! the shared tokio runtime.
//!
//! Each shard's thread owns its own [`ShardLoop`], its own
//! `ProdTimerManager`, and a (timer, callback, shutdown) channel triple
//! drained in priority order (`timer_rx > callback_rx`). Process-scoped
//! resources (`Arc<ProcessIo>`: network adapter, dispatch pool, tx
//! validator, topology snapshot) are cloned across every shard thread.
//!
//! The tokio runtime handles libp2p, the RPC server (which invokes the
//! [`TxSubmissionSender`] closure synchronously), the per-shard
//! `ProdTimerManager`s' `sleep` tasks, and the per-host metrics + GC
//! tick. Inbound libp2p events and dispatch callbacks land on the
//! addressed shard's callback channel; RPC submissions fan out via
//! [`ProcessIo::compute_submit_fanout`] into the relevant shards'
//! callback channels.
//!
//! [`ShardLoop`]: hyperscale_node::shard_loop::ShardLoop
//! [`TxSubmissionSender`]: crate::rpc::TxSubmissionSender
//! [`ProcessIo::compute_submit_fanout`]: hyperscale_node::process_io::ProcessIo::compute_submit_fanout

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, Sender, unbounded};
use hex::encode as hex_encode;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_core::{KeepDelta, ObserveDelta, ParticipationChange, ProtocolEvent, TimerId};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
use hyperscale_engine::{GenesisConfig, NetworkDefinition, RadixExecutor, TransactionValidation};
use hyperscale_mempool::MempoolConfig;
use hyperscale_metrics::{set_libp2p_peers, set_pool_queue_depths};
use hyperscale_metrics_prometheus::install;
use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_network_libp2p::{
    Libp2pAdapter, Libp2pConfig, Libp2pNetwork, NetworkError, RequestManager, RequestManagerConfig,
    RequestStreamPool, generate_random_keypair,
};
use hyperscale_node::bootstrap::EngineBootstrap;
use hyperscale_node::shard_loop::{ShardEvent, ShardLoop, TimerOp, timer_event};
use hyperscale_node::{
    NodeConfig, NodeHost, SeatVnodeGroup, SharedTopologySnapshot, TxStatusCache, VnodeInit,
    seat_vnode_group,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, ShardChainReader};
use hyperscale_storage_rocksdb::{RocksDbShardStorage, SharedStorage};
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, Block, BlockHeight, Bls12381G1PrivateKey,
    CertifiedBeaconBlock, CertifiedBlock, ChainOrigin, GenesisPool, GenesisValidator,
    InFlightCount, LocalTimestamp, MAX_TX_IN_FLIGHT, MIN_STAKE_FLOOR, NodeId, Randomness,
    RoutableTransaction, ShardId, ShardTrie, Stake, StakePoolId, TopologySnapshot, ValidatorId,
    Verified, genesis_config_hash,
};
use libp2p::identity::Keypair;
use radix_common::types::ComponentAddress;
use thiserror::Error;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, spawn};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, info, warn};

use crate::drain::{DRAIN_GRACE, DRAIN_POLL_INTERVAL, drain_after_window_close};
use crate::rpc::state::{RpcPublishers, VnodeMempoolSnapshot};
use crate::rpc::{
    MempoolSnapshot, NodeStatusState, TxSubmissionSender, VnodeMempoolStats, VnodeStatusEntry,
};
use crate::status::{ShardSyncState, SyncStatus};
use crate::supervisor::{ShardCommand, ShardSupervisor, StorageDirResolver, StorageFactory};

// ═══════════════════════════════════════════════════════════════════════════
// RunnerError
// ═══════════════════════════════════════════════════════════════════════════

/// Errors from the production runner.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The event channel into the pinned thread was closed.
    #[error("Event channel closed")]
    ChannelClosed,
    /// A pending request was dropped before completion.
    #[error("Request dropped")]
    RequestDropped,
    /// Catch-all setup or send failure (e.g. missing builder field).
    #[error("Send error: {0}")]
    SendError(String),
    /// Underlying libp2p network error.
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
/// `Arc<TopologySnapshot>` shared across every vnode. Same-shard hosting
/// (V > 1 with every entry mapped to the same `local_shard`) collapses onto
/// one `NodeHost`, one libp2p peer, and one `ShardIo`, with per-vnode signing
/// keys and per-vnode `NodeStateMachine`s.
#[derive(Clone)]
pub struct VnodeConfig {
    /// This vnode's validator identity.
    pub validator_id: ValidatorId,
    /// This vnode's home shard.
    pub local_shard: ShardId,
    /// BLS signing key for this validator's votes, proposals, and the
    /// per-session validator-bind attestation. Held by `Arc` so the same
    /// allocation is shared between the bind service, the state machine,
    /// and delegated dispatch closures.
    pub signing_key: Arc<Bls12381G1PrivateKey>,
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
/// - `vnodes` - One [`VnodeConfig`] per hosted validator. Vnodes may
///   target different shards; the host derives its `local_shards` set
///   from the supplied vnodes.
/// - `topology` - Identity-agnostic [`TopologySnapshot`] shared across every
///   hosted vnode and seeded into the `ProcessIo`'s `ArcSwap`.
/// - `shard_config` - Consensus configuration parameters
/// - `storages` - One `RocksDB` storage per hosted shard. Every shard
///   referenced by a vnode must have a matching entry.
/// - `network` - libp2p configuration for peer-to-peer communication
/// - `storage_factory` - Opens storage for shards joined at runtime
///   (beacon-driven placement changes).
///
/// Optional fields:
/// - `dispatch` - Dispatch implementation (defaults to auto-configured)
/// - `channel_capacity` - Event channel capacity (defaults to 10,000)
pub struct ProductionRunnerBuilder {
    vnodes: Vec<VnodeConfig>,
    topology: Arc<TopologySnapshot>,
    shard_config: ShardConsensusConfig,
    storages: HashMap<ShardId, Arc<RocksDbShardStorage>>,
    beacon_storage: Arc<dyn BeaconStorage>,
    network_config: Libp2pConfig,
    dispatch: Option<Arc<PooledDispatch>>,
    channel_capacity: usize,
    /// Opens a runtime-joined shard's `RocksDB` storage.
    storage_factory: StorageFactory,
    /// Resolves a shard's storage directory for split-flip seeding.
    storage_dir: StorageDirResolver,
    publishers: RpcPublishers,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<GenesisConfig>,
    /// Radix network definition for transaction validation.
    /// Defaults to simulator network if not set.
    network_definition: Option<NetworkDefinition>,
    /// Mempool configuration.
    mempool_config: MempoolConfig,
    /// Provision coordinator configuration.
    provision_config: ProvisionConfig,
}

impl ProductionRunnerBuilder {
    /// Create a new builder with the required fields. Optional fields use
    /// their defaults until overridden via the setter methods.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // storage + identity threading
    pub fn new(
        vnodes: Vec<VnodeConfig>,
        topology: Arc<TopologySnapshot>,
        shard_config: ShardConsensusConfig,
        storages: HashMap<ShardId, Arc<RocksDbShardStorage>>,
        beacon_storage: Arc<dyn BeaconStorage>,
        network_config: Libp2pConfig,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
    ) -> Self {
        assert!(
            !vnodes.is_empty(),
            "ProductionRunnerBuilder needs at least one vnode"
        );
        Self {
            vnodes,
            topology,
            shard_config,
            storages,
            beacon_storage,
            network_config,
            dispatch: None,
            channel_capacity: 10_000,
            publishers: RpcPublishers::default(),
            genesis_config: None,
            network_definition: None,
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
            storage_factory,
            storage_dir,
        }
    }

    /// Set the Radix network definition for transaction validation.
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
    /// Must be called from within a tokio runtime context — the libp2p adapter
    /// and request manager capture `Handle::current()`.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::SendError`] if dispatch initialization fails,
    /// or [`RunnerError::NetworkError`] if libp2p setup fails.
    #[allow(clippy::too_many_lines)] // straight-line construction; further splits add no clarity
    pub fn build(self) -> Result<ProductionRunner, RunnerError> {
        // Install the Prometheus metrics backend before anything records metrics.
        install();

        let vnode_configs = self.vnodes;
        // Per-vnode signing keys, retained so a placement delta can be
        // translated into a `ShardCommand::Join` for the moved vnode.
        let vnode_keys: HashMap<ValidatorId, Arc<Bls12381G1PrivateKey>> = vnode_configs
            .iter()
            .map(|v| (v.validator_id, Arc::clone(&v.signing_key)))
            .collect();
        let shared_topology = self.topology;
        let shard_config = self.shard_config;
        let storages = self.storages;
        let network_config = self.network_config;
        let dispatch = match self.dispatch {
            Some(pools) => pools,
            None => Arc::new(
                PooledDispatch::new(ThreadPoolConfig::minimal(), TokioHandle::current())
                    .map_err(|e| RunnerError::SendError(e.to_string()))?,
            ),
        };

        let ed25519_keypair = generate_random_keypair();

        // Derive the hosted shard set from the vnodes; every shard
        // referenced by a vnode must have a matching storage entry.
        let local_shards: HashSet<ShardId> =
            vnode_configs.iter().map(|cfg| cfg.local_shard).collect();
        for shard in &local_shards {
            assert!(
                storages.contains_key(shard),
                "ProductionRunnerBuilder: missing storage for hosted shard {shard:?}"
            );
        }
        // Recovery reads from a single shard's storage. Pick the first
        // hosted shard arbitrarily — every hosted storage exposes the
        // same `RecoveredState` shape.
        let recovery_shard = vnode_configs[0].local_shard;
        let recovery_storage = Arc::clone(
            storages
                .get(&recovery_shard)
                .expect("hosted shard derived from vnodes"),
        );

        let topology: SharedTopologySnapshot =
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
        // single key allocation each `VnodeConfig` carries.
        let bind_vnodes: Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)> = vnode_configs
            .iter()
            .map(|cfg| (cfg.validator_id, Arc::clone(&cfg.signing_key)))
            .collect();

        // Build one (timer / callback / shutdown) channel triple per
        // hosted shard up front so the per-shard event senders inside
        // `ProcessIo` can point at each shard's own callback channel.
        // `ShardChannels` carries both ends; the supervisor keeps the
        // shutdown/callback senders alive for the shard's lifetime.
        let mut shard_channels: HashMap<ShardId, ShardChannels> = HashMap::new();
        let mut shard_callback_txs: HashMap<ShardId, Sender<ShardEvent>> = HashMap::new();
        for shard in &local_shards {
            let (timer_tx, timer_rx) = unbounded();
            let (callback_tx, callback_rx) = unbounded();
            let (shutdown_tx, shutdown_rx) = unbounded();
            shard_callback_txs.insert(*shard, callback_tx.clone());
            shard_channels.insert(
                *shard,
                ShardChannels {
                    timer_tx,
                    timer_rx,
                    callback_rx,
                    shutdown_tx,
                    shutdown_rx,
                },
            );
        }
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let recovered = recovery_storage.load_recovered_state();

        // Beacon genesis: one config + derived (block, state) reused
        // across every per-vnode `BeaconCoordinator`. All validators
        // land in a single pool; the first
        // `chain_config.beacon_committee_size` form the beacon
        // committee. Shard committees mirror the topology snapshot's
        // view so the beacon-state placement agrees with tx-routing.
        let (beacon_genesis_block, beacon_genesis_state, beacon_config_hash, beacon_network) = {
            let network = NetworkDefinition::simulator();
            let pool_id = StakePoolId::new(0);
            let validators_set = shared_topology.global_validator_set();
            let initial_validators: Vec<GenesisValidator> = validators_set
                .validators
                .iter()
                .map(|v| GenesisValidator {
                    id: v.validator_id,
                    pool: pool_id,
                    pubkey: v.public_key,
                })
                .collect();
            let n = u128::from(initial_validators.len() as u64);
            let initial_pools = vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(n * MIN_STAKE_FLOOR.attos()),
            }];
            let chain_config = BeaconChainConfig::default();
            let beacon_committee_size = initial_validators
                .len()
                .min(chain_config.beacon_committee_size as usize);
            let initial_beacon_committee: Vec<ValidatorId> = initial_validators
                .iter()
                .take(beacon_committee_size)
                .map(|v| v.id)
                .collect();
            let initial_shard_committees: BTreeMap<ShardId, Vec<ValidatorId>> = shared_topology
                .shard_trie()
                .leaves()
                .map(|s| (s, shared_topology.committee_for_shard(s).to_vec()))
                .collect();
            let config = BeaconGenesisConfig {
                chain_config,
                initial_validators,
                initial_pools,
                initial_beacon_committee,
                initial_shard_committees,
                initial_randomness: Randomness::new([0x42; 32]),
            };
            let state = Arc::new(build_genesis_beacon_state(&config));
            let config_hash = genesis_config_hash(&config, &network);
            let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
            (block, state, config_hash, network)
        };

        // Warm-restart: resume the beacon coordinator from the latest
        // committed (block, state) in storage. On an empty store, commit the
        // genesis pair first so fresh-start and restart converge on the same
        // load — the coordinator's resume epoch is whatever state it's handed.
        if self.beacon_storage.latest_committed_epoch().is_none() {
            self.beacon_storage
                .commit_beacon_block(&beacon_genesis_block, &beacon_genesis_state);
        }

        let mut vnodes_by_shard: BTreeMap<ShardId, Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)>> =
            BTreeMap::new();
        for cfg in vnode_configs {
            vnodes_by_shard
                .entry(cfg.local_shard)
                .or_default()
                .push((cfg.validator_id, cfg.signing_key));
        }
        let vnode_inits: Vec<VnodeInit> = vnodes_by_shard
            .into_iter()
            .flat_map(|(shard, vnodes)| {
                seat_vnode_group(SeatVnodeGroup {
                    beacon_storage: self.beacon_storage.as_ref(),
                    beacon_network: beacon_network.clone(),
                    beacon_config_hash,
                    now: wall_clock_local(),
                    shard,
                    recovered: &recovered,
                    shard_config: &shard_config,
                    mempool_config: self.mempool_config.clone(),
                    provision_config: self.provision_config,
                    vnodes,
                })
            })
            .collect();

        // Wrap each per-shard `RocksDbShardStorage` in a `SharedStorage` for
        // `NodeHost::new`'s `HashMap<ShardId, S>` argument; the
        // runner keeps the bare `Arc<RocksDbShardStorage>`s alive for GC +
        // metrics.
        let shared_storages: HashMap<ShardId, SharedStorage> = storages
            .iter()
            .map(|(shard, st)| (*shard, SharedStorage::new(Arc::clone(st))))
            .collect();
        let network_definition = self
            .network_definition
            .unwrap_or_else(NetworkDefinition::simulator);
        let tx_validator = Arc::new(TransactionValidation::new(network_definition.clone()));

        let NetworkStack {
            adapter,
            libp2p_network,
        } = build_network_stack(NetworkBuildArgs {
            network_config,
            network: network_definition.clone(),
            ed25519_keypair,
            local_shards: local_shards.clone(),
            bind_vnodes,
            initial_validator_keys,
            topology: topology.clone(),
        })?;

        // The bootstrap identity replicated into every fresh store the
        // supervisor opens for a post-genesis join or observer duty —
        // the same network + genesis config the startup genesis path
        // installs, so the substate sides agree across stores.
        let engine_bootstrap = EngineBootstrap {
            network: network_definition.clone(),
            config: self
                .genesis_config
                .clone()
                .unwrap_or_else(GenesisConfig::production),
        };
        let executor = RadixExecutor::new(network_definition);

        // Each shard's `shard_event_senders` entry points at that
        // shard's own pinned-thread callback channel — callbacks,
        // network handlers, and RPC fanout for that shard land on its
        // thread directly.
        let shard_event_senders: BTreeMap<ShardId, Sender<ShardEvent>> = shard_callback_txs
            .iter()
            .map(|(s, tx)| (*s, tx.clone()))
            .collect();
        let host = NodeHost::new(
            vnode_inits,
            shared_storages,
            self.beacon_storage,
            beacon_network.clone(),
            executor,
            libp2p_network,
            (*dispatch).clone(),
            shard_event_senders,
            topology.clone(),
            NodeConfig::default(),
            tx_validator,
        );

        let tx_status = Arc::clone(host.process().tx_status());

        // Per-shard vnode counts seed the supervisor's membership
        // refcounts for the startup shards.
        let shard_vnode_counts: HashMap<ShardId, usize> = host
            .hosted_shards()
            .map(|shard| (shard, host.vnodes_len(shard)))
            .collect();

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
            TokioHandle::current(),
            self.publishers.clone(),
            Arc::clone(&storages),
            self.storage_factory,
            self.storage_dir,
            engine_bootstrap,
            participation_tx,
            BeaconChainConfig::default().epoch_duration_ms,
        );

        Ok(ProductionRunner {
            host: Some(host),
            shard_channels: Some(shard_channels),
            shard_vnode_counts,
            supervisor: Some(supervisor),
            reconfigure_tx,
            reconfigure_rx: Some(reconfigure_rx),
            participation_rx: Some(participation_rx),
            vnode_keys,
            network: adapter,
            topology_snapshot: topology,
            storages,
            dispatch,
            publishers: self.publishers,
            genesis_config: self.genesis_config,
            local_shards,
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
/// [`ShardLoop`]: hyperscale_node::shard_loop::ShardLoop
pub struct ProductionRunner {
    /// The composed [`NodeHost`], wrapped in `Option` because it's
    /// decomposed via `into_parts()` and moved onto the per-shard
    /// threads at `run()` time. `None` thereafter.
    host: Option<ProdHost>,

    /// Per-shard receivers (timer + callback + shutdown), built at
    /// construction and consumed when `run()` spawns the shard threads.
    shard_channels: Option<HashMap<ShardId, ShardChannels>>,

    /// Per-shard local vnode counts at startup, seeding the
    /// supervisor's membership refcounts.
    shard_vnode_counts: HashMap<ShardId, usize>,

    /// Owns the pinned shard threads from `run()` onward and executes
    /// runtime membership commands.
    supervisor: Option<ShardSupervisor>,

    /// Command channel into the supervisor; cloned out via
    /// [`Self::reconfigure_handle`].
    reconfigure_tx: mpsc::Sender<ShardCommand>,
    /// Receiver drained by `run()`'s select loop.
    reconfigure_rx: Option<mpsc::Receiver<ShardCommand>>,
    /// Placement deltas emitted by the hosted vnodes' beacon
    /// coordinators, forwarded off the shard threads. `run()`'s select
    /// loop translates each into [`ShardCommand`]s for the supervisor.
    participation_rx: Option<mpsc::UnboundedReceiver<ParticipationChange>>,
    /// Per-validator signing keys for every vnode this runner was built
    /// with, keyed for the placement-delta translation.
    vnode_keys: HashMap<ValidatorId, Arc<Bls12381G1PrivateKey>>,

    /// Libp2p network adapter (shared with `InboundRouter`, `RequestManager`).
    network: Arc<Libp2pAdapter>,
    /// Network topology snapshot (lock-free `ArcSwap`, updated on topology changes).
    topology_snapshot: SharedTopologySnapshot,
    /// Per-shard `RocksDB` handles for the JMT GC tick and storage
    /// metrics, shared with the supervisor, which inserts and removes
    /// entries as shards join and leave.
    storages: Arc<std::sync::Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>,
    /// Thread pool dispatch.
    dispatch: Arc<PooledDispatch>,
    /// Every shard this runner hosts vnodes for at startup.
    local_shards: HashSet<ShardId>,

    /// Shared RPC publishers; the metrics tick stamps peer counts into
    /// the status slots.
    publishers: RpcPublishers,

    /// Optional genesis configuration for initial state.
    genesis_config: Option<GenesisConfig>,

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
        vnodes: Vec<VnodeConfig>,
        topology: Arc<TopologySnapshot>,
        shard_config: ShardConsensusConfig,
        storages: HashMap<ShardId, Arc<RocksDbShardStorage>>,
        beacon_storage: Arc<dyn BeaconStorage>,
        network_config: Libp2pConfig,
        storage_factory: StorageFactory,
        storage_dir: StorageDirResolver,
    ) -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new(
            vnodes,
            topology,
            shard_config,
            storages,
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
    pub const fn network(&self) -> &Arc<Libp2pAdapter> {
        &self.network
    }

    /// Get the process-wide transaction status cache shared from
    /// `NodeHost`. Same instance every shard thread writes into;
    /// passed directly to the RPC server for lock-free status lookups.
    #[must_use]
    pub fn tx_status_cache(&self) -> Arc<TxStatusCache> {
        Arc::clone(&self.tx_status)
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
    /// [`ProcessIo::compute_submit_fanout`]: hyperscale_node::process_io::ProcessIo::compute_submit_fanout
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
        Arc::new(move |routable: Arc<RoutableTransaction>| process.submit_transaction(&routable))
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
    // Genesis Initialization
    // ═══════════════════════════════════════════════════════════════════

    /// Initialize genesis if this is a fresh start.
    ///
    /// Checks if we have any committed blocks. If not, creates a genesis block
    /// and initializes the state machine (which sets up the initial proposal timer).
    ///
    /// This MUST be called before the `NodeHost` is moved to the pinned thread,
    /// since it needs mutable access to the `NodeHost`.
    fn maybe_initialize_genesis(&mut self) -> Vec<TimerOp> {
        let host = self.host.as_mut().expect("host must exist for genesis");

        // Multi-shard genesis: run the genesis ceremony for every
        // hosted shard. Each shard has its own RocksDB store, its own
        // committed height, and its own genesis block.
        let mut timer_ops = Vec::new();
        let local_shards: Vec<ShardId> = host.hosted_shards().collect();
        let topology = Arc::clone(&self.topology_snapshot);
        // The host's `GenesisConfig` enumerates every account across every
        // hosted shard. Each shard's storage only gets the accounts whose
        // address hashes to that shard, so genesis doesn't reapply other
        // shards' state into the wrong store. Single-shard hosts (the
        // historical default) end up running an identity filter.
        let shared_genesis_config = self.genesis_config.take();
        for shard in local_shards {
            let height = host.shard_io(shard).storage.committed_height();
            if height > BlockHeight::GENESIS {
                info!(
                    shard = ?shard,
                    "Existing blocks found, skipping genesis initialization for shard"
                );
                continue;
            }
            info!(shard = ?shard, "No committed blocks - initializing genesis for shard");

            let genesis_config = shared_genesis_config
                .clone()
                .map_or_else(GenesisConfig::production, |cfg| {
                    filter_genesis_for_shard(cfg, shard, topology.load().shard_trie())
                });
            info!(
                shard = ?shard,
                xrd_balances = genesis_config.xrd_balances.len(),
                "Running genesis"
            );
            let genesis_jmt_root = host.install_engine_genesis(shard, &genesis_config);

            info!(
                shard = ?shard,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            let first_validator = topology
                .load()
                .committee_for_shard(shard)
                .first()
                .copied()
                .unwrap_or(ValidatorId::new(0));

            let genesis_block =
                Block::genesis(shard, first_validator, genesis_jmt_root, ChainOrigin::ROOT);

            let genesis_hash = genesis_block.hash();
            info!(
                shard = ?shard,
                genesis_hash = ?genesis_hash,
                proposer = ?first_validator,
                "Created genesis block"
            );

            host.initialize_shard_genesis(&genesis_block);
            host.flush_all_batches();

            let genesis_output = host.drain_pending_output();
            timer_ops.extend(genesis_output.timer_ops);

            // Sync the state machine with the JMT state genesis just
            // installed — vnodes were created with zero state.
            let genesis_certified = Arc::new(Verified::<CertifiedBlock>::genesis(
                shard,
                first_validator,
                genesis_block.header().state_root(),
                ChainOrigin::ROOT,
            ));
            let genesis_commit_output = host.step(ShardEvent::protocol(
                shard,
                ProtocolEvent::BlockCommitted {
                    certified: genesis_certified,
                },
            ));

            info!(
                shard = ?shard,
                genesis_jmt_root = ?genesis_jmt_root,
                actions = genesis_commit_output.actions_generated,
                "Updated state machine with genesis JMT state"
            );

            timer_ops.extend(genesis_commit_output.timer_ops);
            host.flush_all_batches();
        }

        host.register_inbound_handlers();
        timer_ops
    }

    // ═══════════════════════════════════════════════════════════════════
    // Main Run Loop
    // ═══════════════════════════════════════════════════════════════════

    /// Run the production node.
    ///
    /// 1. Initializes genesis via `NodeHost` (before spawning pinned thread)
    /// 2. Extracts the `NodeHost` and channel receivers for the pinned thread
    /// 3. Spawns the pinned thread running the `NodeHost` event loop
    /// 4. Runs a minimal loop for metrics collection and shutdown handling
    /// 5. On shutdown, signals the pinned thread and joins it
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`; the signature exists so callers can
    /// `?` it alongside other fallible startup steps without churn.
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

        // ── 1. Initialize genesis while NodeHost still owns the ShardLoops.
        let initial_timer_ops = self.maybe_initialize_genesis();

        // ── 2. Decompose NodeHost into Arc<ProcessIo> + per-shard ShardLoops.
        let host = self
            .host
            .take()
            .expect("host already taken (run called twice?)");
        let (_process, shards) = host.into_parts();

        let mut shard_channels = self
            .shard_channels
            .take()
            .expect("shard_channels already taken");

        // Split genesis-emitted timer ops by shard.
        let mut timer_ops_by_shard: HashMap<ShardId, Vec<TimerOp>> = HashMap::new();
        for op in initial_timer_ops {
            let shard = match &op {
                TimerOp::Set { shard, .. } | TimerOp::Cancel { shard, .. } => *shard,
            };
            timer_ops_by_shard.entry(shard).or_default().push(op);
        }

        // ── 3. Spawn one pinned thread per hosted shard, recorded in the
        // supervisor so runtime membership commands can stop them.
        let mut supervisor = self.supervisor.take().expect("supervisor already taken");
        for (shard, shard_loop) in shards {
            let channels = shard_channels
                .remove(&shard)
                .expect("channels allocated for every hosted shard");
            let initial_timer_ops = timer_ops_by_shard.remove(&shard).unwrap_or_default();
            let vnode_count = self.shard_vnode_counts.get(&shard).copied().unwrap_or(1);
            supervisor.spawn_recorded(shard_loop, channels, initial_timer_ops, vnode_count);
        }

        // ── 4. Metrics + maintenance + reconfiguration + shutdown loop.
        let mut metrics_tick = interval(Duration::from_secs(1));
        metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
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

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received");
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
            }
        }

        // ── 5. Fan shutdown to every shard thread in parallel.
        info!("Sending shutdown to shard threads");
        supervisor.shutdown_all();

        info!("Production runner stopped");
        Ok(())
    }

    /// Command channel into the shard supervisor. Send
    /// [`ShardCommand`]s to add or drop shard participation at runtime;
    /// they execute on the runner's tokio loop, off the shard threads.
    #[must_use]
    pub fn reconfigure_handle(&self) -> mpsc::Sender<ShardCommand> {
        self.reconfigure_tx.clone()
    }

    /// Translate a beacon-detected placement delta into supervisor
    /// commands for the moved vnode. A join starts the shard's
    /// bootstrap immediately — the delta arrives a full epoch before
    /// the window opens, and the vnode votes only once ready. A leave
    /// drains gracefully: the shard keeps serving until the validator's
    /// window observably closes plus the DA retention grace, so its
    /// replacement can snap-sync from it during the overlap.
    /// Dispatch a merge-keeper delta to the supervisor: begin a keeper
    /// duty (deriving the keeper's own child as the non-sibling child of
    /// the merging parent) or abandon one. A keeper carries no join/leave
    /// — it stays on its child until the merge executes — so this is its
    /// only signal until the placement delta.
    fn dispatch_keep(&self, supervisor: &mut ShardSupervisor, change: &ParticipationChange) {
        match change.keep {
            Some(KeepDelta::Begin { parent, sibling }) => {
                if let Some(signing_key) = self.vnode_keys.get(&change.validator) {
                    let (left, right) = parent.children();
                    let own_child = if sibling == left { right } else { left };
                    supervisor.handle(ShardCommand::Keep {
                        parent,
                        sibling,
                        own_child,
                        validator: change.validator,
                        signing_key: Arc::clone(signing_key),
                    });
                } else {
                    warn!(
                        validator = change.validator.inner(),
                        "Keeper seat for a validator without a local signing key; ignored"
                    );
                }
            }
            Some(KeepDelta::Abandon { parent }) => {
                supervisor.handle(ShardCommand::Unkeep { parent });
            }
            None => {}
        }
    }

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
        self.dispatch_keep(supervisor, change);
        match change.observe {
            Some(ObserveDelta::Begin { via, child }) => {
                if let Some(signing_key) = self.vnode_keys.get(&change.validator) {
                    supervisor.handle(ShardCommand::Observe {
                        via,
                        child,
                        validator: change.validator,
                        signing_key: Arc::clone(signing_key),
                    });
                } else {
                    warn!(
                        validator = change.validator.inner(),
                        "Observer seat for a validator without a local signing key; ignored"
                    );
                }
            }
            Some(ObserveDelta::Abandon { child, .. }) => {
                supervisor.handle(ShardCommand::Unobserve { child });
            }
            None => {}
        }
        if let Some(shard) = change.leave {
            let topology = self.topology_snapshot.clone();
            let reconfigure = self.reconfigure_tx.clone();
            let validator = change.validator;
            spawn(async move {
                if drain_after_window_close(
                    &topology,
                    validator,
                    shard,
                    DRAIN_GRACE,
                    DRAIN_POLL_INTERVAL,
                )
                .await
                {
                    info!(
                        ?shard,
                        validator = validator.inner(),
                        "Drain complete; leaving shard"
                    );
                    // Send failure means the runner is shutting down.
                    let _ = reconfigure.send(ShardCommand::Leave { shard }).await;
                } else {
                    info!(
                        ?shard,
                        validator = validator.inner(),
                        "Drain cancelled; validator re-entered the committee"
                    );
                }
            });
        }
        let Some(shard) = change.join else {
            return;
        };
        let Some(signing_key) = self.vnode_keys.get(&change.validator) else {
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
                signing_key: Arc::clone(signing_key),
            }],
            adoption: change.split_adoption,
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
        set_libp2p_peers(peer_count);

        // ── Update RPC status with peer count ────────────────────────────
        if let Some(ref rpc_status) = self.publishers.node_status {
            let current = rpc_status.load();
            if current.connected_peers != peer_count {
                let mut updated = (**current).clone();
                updated.connected_peers = peer_count;
                rpc_status.store(Arc::new(updated));
            }
        }

        // ── Update sync_peers on the sync status (only runner has Libp2pNetwork) ──
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
            }
            gc_flag.store(false, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Network stack construction helper
// ═══════════════════════════════════════════════════════════════════════════

struct NetworkBuildArgs {
    network_config: Libp2pConfig,
    /// Radix network identity, bound into BLS-signed bind handshake
    /// messages so a signature collected on one network can't validate
    /// on another.
    network: NetworkDefinition,
    ed25519_keypair: Keypair,
    /// Shards hosted by this host. Drives per-shard request stream
    /// protocols and gossipsub subscriptions on the adapter.
    local_shards: HashSet<ShardId>,
    /// One `(validator_id, signing_key)` per hosted vnode. The bind
    /// service attests as every entry on each handshake.
    bind_vnodes: Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)>,
    initial_validator_keys: Arc<ValidatorKeyMap>,
    /// Topology snapshot shared with `Libp2pNetwork` for shard-based
    /// peer resolution on outbound `Network::request` calls.
    topology: SharedTopologySnapshot,
}

struct NetworkStack {
    adapter: Arc<Libp2pAdapter>,
    libp2p_network: Libp2pNetwork,
}

fn build_network_stack(args: NetworkBuildArgs) -> Result<NetworkStack, RunnerError> {
    let registry = Arc::new(HandlerRegistry::new(
        args.local_shards.iter().copied().collect(),
    ));

    let adapter = Libp2pAdapter::new(
        args.network_config,
        args.network,
        args.ed25519_keypair,
        args.bind_vnodes,
        args.local_shards,
        registry.clone(),
        args.initial_validator_keys,
    )?;

    let request_pool = Arc::new(RequestStreamPool::new(
        adapter.clone(),
        TokioHandle::current(),
    ));
    let request_manager = Arc::new(RequestManager::new(
        request_pool,
        RequestManagerConfig::default(),
    ));

    let libp2p_network = Libp2pNetwork::new(
        adapter.clone(),
        request_manager,
        TokioHandle::current(),
        registry,
        args.topology,
    );

    Ok(NetworkStack {
        adapter,
        libp2p_network,
    })
}

/// Concrete `NodeHost` type for the production runner.
type ProdHost = NodeHost<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Concrete `ShardLoop` type for the production runner.
pub type ProdShardLoop = ShardLoop<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Per-shard receivers driving a single shard's pinned thread. Built
/// during construction and consumed when [`ProductionRunner::run`]
/// hands the bundle to [`run_shard_loop`].
pub struct ShardChannels {
    pub(crate) timer_tx: Sender<ShardEvent>,
    pub(crate) timer_rx: Receiver<ShardEvent>,
    pub(crate) callback_rx: Receiver<ShardEvent>,
    pub(crate) shutdown_tx: Sender<()>,
    pub(crate) shutdown_rx: Receiver<()>,
}

/// Manages tokio-based timers for one shard's pinned event loop.
///
/// Spawns async sleep tasks via the tokio handle that fire timer events
/// into the crossbeam timer channel.
struct ProdTimerManager {
    tokio_handle: TokioHandle,
    timer_tx: Sender<ShardEvent>,
    active: HashMap<(ShardId, TimerId), JoinHandle<()>>,
}

impl ProdTimerManager {
    fn new(tokio_handle: TokioHandle, timer_tx: Sender<ShardEvent>) -> Self {
        Self {
            tokio_handle,
            timer_tx,
            active: HashMap::new(),
        }
    }

    fn process_op(&mut self, op: TimerOp) {
        match op {
            TimerOp::Set {
                shard,
                id,
                duration,
            } => {
                let key = (shard, id.clone());
                if let Some(handle) = self.active.remove(&key) {
                    handle.abort();
                }
                let timer_tx = self.timer_tx.clone();
                let timer_id = id;
                let handle = self.tokio_handle.spawn(async move {
                    sleep(duration).await;
                    let _ = timer_tx.send(timer_event(&timer_id, shard));
                });
                self.active.insert(key, handle);
            }
            TimerOp::Cancel { shard, id } => {
                if let Some(handle) = self.active.remove(&(shard, id)) {
                    handle.abort();
                }
            }
        }
    }
}

impl Drop for ProdTimerManager {
    fn drop(&mut self) {
        for (_, handle) in self.active.drain() {
            handle.abort();
        }
    }
}

const METRICS_INTERVAL: Duration = Duration::from_secs(1);
const GC_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Drop `xrd_balance` entries whose address doesn't hash to `shard`. The
/// network-wide [`GenesisConfig`] enumerates accounts across every shard;
/// installing it verbatim into one shard's storage would create accounts
/// that consensus on that shard never owns.
fn filter_genesis_for_shard(
    mut config: GenesisConfig,
    shard: ShardId,
    shard_trie: &ShardTrie,
) -> GenesisConfig {
    config
        .xrd_balances
        .retain(|(address, _)| shard_for_address(address, shard_trie) == shard);
    config
}

/// Compute the shard a [`ComponentAddress`] belongs to, by longest-prefix
/// match against the active partition.
fn shard_for_address(address: &ComponentAddress, shard_trie: &ShardTrie) -> ShardId {
    let radix_node_id = address.into_node_id();
    let det_node_id = NodeId(
        radix_node_id.0[..30]
            .try_into()
            .expect("NodeId is 30 bytes"),
    );
    shard_trie.shard_for(&det_node_id)
}

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

/// Per-shard pinned-thread configuration.
pub struct ShardLoopConfig {
    pub(crate) timer_tx: Sender<ShardEvent>,
    pub(crate) timer_rx: Receiver<ShardEvent>,
    pub(crate) callback_rx: Receiver<ShardEvent>,
    pub(crate) shutdown_rx: Receiver<()>,
    pub(crate) tokio_handle: TokioHandle,
    pub(crate) initial_timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted by this shard's vnodes, forwarded to
    /// the runner's reconfiguration loop. `None` in tests that drive a
    /// loop without a runner.
    pub(crate) participation_tx: Option<mpsc::UnboundedSender<ParticipationChange>>,
    /// Shared RPC publishers. Each shard's thread writes its own slots
    /// on the metrics tick (per-vnode status entries, its sync-status
    /// key, and its vnodes' mempool snapshots); concurrent shards
    /// racing on the same `ArcSwap` lose at most one second of
    /// staleness on their slot.
    pub(crate) publishers: RpcPublishers,
}

/// Drive one shard's [`ShardLoop`] on its pinned thread. Blocks until
/// the shard's shutdown signal fires.
///
/// Priority cascade: `timer_rx` (scheduled view-change / cleanup /
/// fetch tick fires) before `callback_rx` (off-thread results, inbound
/// network deliveries, RPC fanout). When both are empty the cascade
/// blocks on `select!` with a timeout drawn from the shard's nearest
/// batch deadline so the shard wakes precisely when its earliest
/// expiring batch is due.
fn run_shard_loop(mut shard_loop: ProdShardLoop, mut config: ShardLoopConfig) {
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

        let now = wall_clock_local();
        shard_loop.set_time(now);

        let event = 'recv: {
            if let Ok(e) = config.timer_rx.try_recv() {
                break 'recv Some(e);
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
                recv(config.callback_rx) -> e => e.ok(),
                default(timeout) => None,
            }
        };

        if let Some(event) = event {
            let input = match event {
                ShardEvent::Shard(s, input) if s == shard => input,
                ShardEvent::Shard(other, _) => {
                    warn!(received_shard = ?other, this_shard = ?shard, "Dropping cross-shard event");
                    continue;
                }
                ShardEvent::Process(_) => {
                    warn!(shard = ?shard, "Dropping process-scoped event on shard channel");
                    continue;
                }
            };
            let output = shard_loop.run_step(input);
            for op in output.timer_ops {
                timer_mgr.process_op(op);
            }
            if let Some(tx) = &config.participation_tx {
                for change in output.reconfigurations {
                    // Send failure means the runner is shutting down.
                    let _ = tx.send(change);
                }
            }
        }

        shard_loop.flush_expired_batches(wall_clock_local());

        // Per-shard prometheus emission + RPC status writes. Process-wide
        // memory + RocksDB gauges are emitted from the runner's tokio
        // tick after summing across shards.
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();
            shard_loop.record_prometheus();
            update_shard_rpc_state(&shard_loop, &config);
        }
    }

    info!(shard = ?shard, "Shard event loop exiting");
}

/// Write this shard's contribution into the shared RPC state. Each slot
/// is keyed by `shard_id.inner()` so concurrent shard threads touching
/// the same `ArcSwap` only race on the map metadata — losing a single
/// 1-second cycle when two shards interleave their load-modify-store,
/// not the values themselves.
fn update_shard_rpc_state(shard_loop: &ProdShardLoop, config: &ShardLoopConfig) {
    let shard_key = shard_loop.shard.inner();

    // ── /status: per-vnode entries ─────────────────────────────────
    if let Some(ref rpc_status) = config.publishers.node_status {
        let current = rpc_status.load();
        let mut updated = (**current).clone();
        updated.vnodes.retain(|v| v.shard != shard_key);
        for vnode in &shard_loop.vnodes {
            let state = &vnode.state;
            let mempool = state.mempool_coordinator();
            let contention = mempool.lock_contention_stats();
            #[allow(clippy::cast_possible_truncation)] // pool sizes fit usize
            let (pending, in_flight) = (
                contention.pending_count as usize,
                contention.in_flight_count as usize,
            );
            updated.vnodes.push(VnodeStatusEntry {
                validator_id: vnode.validator_id.inner(),
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
        rpc_status.store(Arc::new(updated));
    }

    // ── /sync: per-shard block-sync state ──────────────────────────
    if let Some(ref sync_status) = config.publishers.sync_status {
        let block_sync = shard_loop.io.syncs.block.block_sync_status();
        let current = sync_status.load();
        let mut updated = (**current).clone();
        updated.shards.insert(
            shard_key,
            ShardSyncState {
                state: block_sync.state.clone(),
                current_height: block_sync.current_height,
                target_height: block_sync.target_height,
                blocks_behind: block_sync.blocks_behind,
                pending_fetches: block_sync.pending_fetches,
                queued_heights: block_sync.queued_heights,
            },
        );
        sync_status.store(Arc::new(updated));
    }

    // ── Mempool: per-vnode snapshots feeding RPC submission backpressure.
    // Each vnode owns its own `MempoolCoordinator`; same-shard vnodes
    // converge by determinism but their instantaneous counts can
    // differ, so the backpressure check iterates every entry rather
    // than picking a per-shard representative.
    if let Some(ref mempool_snapshot) = config.publishers.mempool {
        #[allow(clippy::cast_possible_truncation)] // pool size derived from a fixed const
        let remote_congestion_threshold = InFlightCount::new((MAX_TX_IN_FLIGHT * 4 / 5) as u32);
        let current = mempool_snapshot.load();
        let mut updated = (**current).clone();
        for vnode in &shard_loop.vnodes {
            let state = &vnode.state;
            let mempool = state.mempool_coordinator();
            let contention = mempool.lock_contention_stats();
            #[allow(clippy::cast_possible_truncation)]
            let (pending, in_flight) = (
                contention.pending_count as usize,
                contention.in_flight_count as usize,
            );
            updated.vnodes.insert(
                vnode.validator_id.inner(),
                VnodeMempoolSnapshot {
                    pending_count: pending,
                    in_flight_count: in_flight,
                    total_count: mempool.len(),
                    updated_at: Some(Instant::now()),
                    accepting_rpc_transactions: !mempool.at_in_flight_limit(),
                    at_pending_limit: mempool.at_pending_limit(),
                    remote_shard_in_flight: state
                        .remote_headers_coordinator()
                        .remote_shard_in_flight(),
                    remote_congestion_threshold,
                },
            );
        }
        mempool_snapshot.store(Arc::new(updated));
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
