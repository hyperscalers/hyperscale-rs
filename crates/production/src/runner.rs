//! Production runner implementation.
//!
//! # Architecture
//!
//! The production runner uses a **pinned thread** architecture:
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │  Core 0 (pinned std::thread)                                         │
//!  │  ┌────────────────────────────────────────────────────────────────┐  │
//!  │  │  IoLoop<SharedStorage, Libp2pNetwork, PooledDispatch>          │  │
//!  │  │    - State machine event processing                            │  │
//!  │  │    - Storage I/O (RocksDB)                                     │  │
//!  │  │    - Action handling (timers, broadcasts, crypto dispatch)     │  │
//!  │  │    - Transaction validation batching via Dispatch              │  │
//!  │  │    - RPC SubmitTransaction handling (gossip + validate)        │  │
//!  │  │    - Batched message sending, batched crypto verification      │  │
//!  │  └────────────────────────────────────────────────────────────────┘  │
//!  │       ↑ crossbeam channels (all events) ↑                            │
//!  └──────────────────────────────────────────────────────────────────────┘
//!
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │  Tokio runtime (multi-threaded)                                      │
//!  │                                                                      │
//!  │  Background tasks:                                                   │
//!  │    - Libp2p adapter (gossipsub, streams) → crossbeam directly        │
//!  │    - InboundRouter (peer fetch requests)                             │
//!  │    - RPC server (sends Event::SubmitTransaction → crossbeam)         │
//!  │    - ProdTimerManager (tokio sleep → crossbeam timer events)         │
//!  │    - Metrics collection loop                                         │
//!  └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Channel topology
//!
//! ```text
//! Libp2p adapter ──crossbeam──→ pinned thread (IoLoop)
//! RPC server     ──crossbeam──→ pinned thread (Event::SubmitTransaction)
//! Dispatch       ──crossbeam──→ pinned thread (crypto/validation callbacks)
//! ProdTimerManager ──crossbeam──→ pinned thread (timer events)
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use core_affinity::{get_core_ids, set_for_current};
use crossbeam::channel::{Receiver, Sender, unbounded};
use hex::encode as hex_encode;
use hyperscale_bft::BftConfig;
use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};
use hyperscale_engine::{GenesisConfig, NetworkDefinition, RadixExecutor, TransactionValidation};
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_metrics::{
    ChannelDepths, set_channel_depths, set_libp2p_peers, set_pool_queue_depths,
};
use hyperscale_metrics_prometheus::install;
use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_network_libp2p::{
    Libp2pAdapter, Libp2pConfig, Libp2pNetwork, NetworkError, RequestManager, RequestManagerConfig,
    RequestStreamPool, generate_random_keypair,
};
use hyperscale_node::io_loop::{
    IoLoop, NodeStatusSnapshot, ShardEvent, TimerOp, record_metrics, timer_event,
};
use hyperscale_node::{NodeConfig, NodeStateMachine, SharedTopologySnapshot, VnodeInit};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_storage::ChainReader;
use hyperscale_storage_rocksdb::{RocksDbStorage, SharedStorage};
use hyperscale_topology::TopologyCoordinator;
use hyperscale_types::{
    Block, BlockHeight, Bls12381G1PrivateKey, CertifiedBlock, LocalTimestamp, QuorumCertificate,
    ShardGroupId, TransactionStatus, TxHash, ValidatorId,
};
use libp2p::identity::Keypair;
use quick_cache::sync::Cache as QuickCache;
use thiserror::Error;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, info, warn};

use crate::rpc::{MempoolSnapshot, NodeStatusState};
use crate::status::SyncStatus;

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
/// A [`ProductionRunner`] hosts a `Vec<VnodeConfig>`. Same-shard hosting
/// (V > 1 with every entry mapped to the same `local_shard()`) collapses
/// onto one `IoLoop`, one libp2p peer, and one `ShardIo`, with per-vnode
/// signing keys and per-vnode `NodeStateMachine`s.
pub struct VnodeConfig {
    /// Per-validator topology view. Provides this vnode's `validator_id`,
    /// `local_shard`, and the shard committee membership it participates in.
    pub topology: TopologyCoordinator,
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
/// - `bft_config` - Consensus configuration parameters
/// - `storages` - One `RocksDB` storage per hosted shard. Every shard
///   referenced by a vnode must have a matching entry.
/// - `network` - libp2p configuration for peer-to-peer communication
///
/// Optional fields:
/// - `dispatch` - Dispatch implementation (defaults to auto-configured)
/// - `channel_capacity` - Event channel capacity (defaults to 10,000)
pub struct ProductionRunnerBuilder {
    vnodes: Vec<VnodeConfig>,
    bft_config: BftConfig,
    storages: HashMap<ShardGroupId, Arc<RocksDbStorage>>,
    network_config: Libp2pConfig,
    dispatch: Option<Arc<PooledDispatch>>,
    channel_capacity: usize,
    rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
    sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
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
    pub fn new(
        vnodes: Vec<VnodeConfig>,
        bft_config: BftConfig,
        storages: HashMap<ShardGroupId, Arc<RocksDbStorage>>,
        network_config: Libp2pConfig,
    ) -> Self {
        assert!(
            !vnodes.is_empty(),
            "ProductionRunnerBuilder needs at least one vnode"
        );
        Self {
            vnodes,
            bft_config,
            storages,
            network_config,
            dispatch: None,
            channel_capacity: 10_000,
            rpc_status: None,
            mempool_snapshot: None,
            sync_status: None,
            genesis_config: None,
            network_definition: None,
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
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
        self.rpc_status = Some(status);
        self
    }

    /// Wire in the shared mempool snapshot so the runner publishes mempool stats.
    #[must_use]
    pub fn mempool_snapshot(mut self, snapshot: Arc<ArcSwap<MempoolSnapshot>>) -> Self {
        self.mempool_snapshot = Some(snapshot);
        self
    }

    /// Wire in the shared sync status so the runner publishes sync progress.
    #[must_use]
    pub fn sync_status(mut self, status: Arc<ArcSwap<SyncStatus>>) -> Self {
        self.sync_status = Some(status);
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
    /// Creates all channels, the `IoLoop`, networking adapters, and supporting
    /// infrastructure. The `IoLoop` is held in an `Option` so it can be moved
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
        let bft_config = self.bft_config;
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
        let local_shards: HashSet<ShardGroupId> = vnode_configs
            .iter()
            .map(|cfg| cfg.topology.snapshot().local_shard())
            .collect();
        for shard in &local_shards {
            assert!(
                storages.contains_key(shard),
                "ProductionRunnerBuilder: missing storage for hosted shard {shard:?}"
            );
        }
        // The runner needs a single representative shard for status,
        // metrics, and genesis bookkeeping until those become per-shard
        // surfaces.
        let primary_shard = vnode_configs[0].topology.snapshot().local_shard();
        let primary_storage = Arc::clone(
            storages
                .get(&primary_shard)
                .expect("primary shard checked above"),
        );

        // The shared snapshot drives off-thread handlers that read
        // shard-level info only. We seed it with the first vnode's
        // snapshot; per-vnode snapshots are taken inside dispatch.
        let topology: SharedTopologySnapshot = Arc::new(ArcSwap::from(Arc::clone(
            vnode_configs[0].topology.snapshot(),
        )));

        // Extract initial validator keys for network-layer bind verification.
        let initial_validator_keys: Arc<ValidatorKeyMap> = Arc::new(
            vnode_configs[0]
                .topology
                .snapshot()
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
            .map(|cfg| {
                let vid = cfg.topology.snapshot().local_validator_id();
                (vid, Arc::clone(&cfg.signing_key))
            })
            .collect();

        let (xb_timer_tx, xb_timer_rx) = unbounded();
        let (xb_callback_tx, xb_callback_rx) = unbounded();
        let (xb_consensus_tx, xb_consensus_rx) = unbounded();
        let (xb_shutdown_tx, xb_shutdown_rx) = unbounded();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Recovery state is read from the primary shard's storage.
        let recovered = primary_storage.load_recovered_state();
        let provision_store = Arc::new(ProvisionStore::new());

        // One `TxStore` + `ExecCertStore` + `FinalizedWaveStore` per
        // hosted shard, shared across every same-shard vnode and into the
        // `IoLoop`'s `SharedCaches`. Determinism guarantees same-shard
        // vnodes admit identical sets, but co-owning the stores makes the
        // canonical view explicit and gives the request/sync handlers one
        // place to read.
        let tx_stores: HashMap<ShardGroupId, Arc<TxStore>> = local_shards
            .iter()
            .map(|s| (*s, Arc::new(TxStore::new())))
            .collect();
        let exec_cert_stores: HashMap<ShardGroupId, Arc<ExecCertStore>> = local_shards
            .iter()
            .map(|s| (*s, Arc::new(ExecCertStore::new())))
            .collect();
        let finalized_wave_stores: HashMap<ShardGroupId, Arc<FinalizedWaveStore>> = local_shards
            .iter()
            .map(|s| (*s, Arc::new(FinalizedWaveStore::new())))
            .collect();

        let vnode_inits: Vec<VnodeInit> = vnode_configs
            .into_iter()
            .map(|cfg| {
                let shard = cfg.topology.snapshot().local_shard();
                let tx_store = Arc::clone(
                    tx_stores
                        .get(&shard)
                        .expect("hosted shard derived from vnodes"),
                );
                let exec_cert_store = Arc::clone(
                    exec_cert_stores
                        .get(&shard)
                        .expect("hosted shard derived from vnodes"),
                );
                let finalized_wave_store = Arc::clone(
                    finalized_wave_stores
                        .get(&shard)
                        .expect("hosted shard derived from vnodes"),
                );
                let state = NodeStateMachine::new(
                    cfg.topology,
                    &bft_config,
                    recovered.clone(),
                    self.mempool_config.clone(),
                    self.provision_config,
                    Arc::clone(&provision_store),
                    tx_store,
                    exec_cert_store,
                    finalized_wave_store,
                );
                VnodeInit {
                    state,
                    signing_key: cfg.signing_key,
                }
            })
            .collect();

        // Wrap each per-shard `RocksDbStorage` in a `SharedStorage` for
        // the io-loop's `HashMap<ShardGroupId, S>` argument; the runner
        // keeps the bare `Arc<RocksDbStorage>`s alive for GC + metrics.
        let shared_storages: HashMap<ShardGroupId, SharedStorage> = storages
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
            ed25519_keypair,
            local_shards: local_shards.clone(),
            bind_vnodes,
            initial_validator_keys,
            topology: topology.clone(),
        })?;

        let executor = RadixExecutor::new(network_definition);

        let io_loop = IoLoop::new(
            vnode_inits,
            shared_storages,
            executor,
            libp2p_network,
            (*dispatch).clone(),
            xb_callback_tx.clone(),
            topology.clone(),
            NodeConfig::default(),
            tx_validator,
        );

        // The status RPC surface exposes the primary shard's cache.
        let tx_status_caches = io_loop.tx_status_caches();
        let tx_status_cache = Arc::clone(
            tx_status_caches
                .get(&primary_shard)
                .expect("primary shard hosted by IoLoop"),
        );

        Ok(ProductionRunner {
            io_loop: Some(io_loop),
            xb_timer_tx,
            xb_consensus_tx,
            xb_callback_tx,
            xb_shutdown_tx,
            xb_timer_rx: Some(xb_timer_rx),
            xb_callback_rx: Some(xb_callback_rx),
            xb_consensus_rx: Some(xb_consensus_rx),
            xb_shutdown_rx: Some(xb_shutdown_rx),
            network: adapter,
            topology_snapshot: topology,
            storages,
            primary_storage,
            dispatch,
            rpc_status: self.rpc_status,
            mempool_snapshot: self.mempool_snapshot,
            sync_status: self.sync_status,
            genesis_config: self.genesis_config,
            primary_shard,
            local_shards,
            tx_status_cache,
            shutdown_rx: Some(shutdown_rx),
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ProductionRunner
// ═══════════════════════════════════════════════════════════════════════════

/// Production runner with `IoLoop` on a pinned thread.
///
/// The state machine (`IoLoop`) runs on a dedicated thread pinned to core 0.
/// All state machine processing, storage I/O, action handling, and gossip cert
/// verification happen on that thread. The tokio runtime handles async I/O
/// routing, RPC transaction handling, sync/fetch management, and metrics.
pub struct ProductionRunner {
    /// The `IoLoop`, wrapped in `Option` because it's moved to the pinned thread.
    /// `None` after `run()` extracts it.
    io_loop: Option<ProdIoLoop>,

    /// Timer events to pinned thread (for external timer injection if needed).
    #[allow(dead_code)]
    xb_timer_tx: Sender<ShardEvent>,
    /// Consensus events to pinned thread (from libp2p adapter routing).
    xb_consensus_tx: Sender<ShardEvent>,
    /// Kept alive solely to prevent the crossbeam callback channel from closing.
    #[allow(dead_code)]
    xb_callback_tx: Sender<ShardEvent>,
    /// Shutdown signal to pinned thread.
    xb_shutdown_tx: Sender<()>,

    /// Timer receiver (moved to `PinnedLoopConfig`).
    xb_timer_rx: Option<Receiver<ShardEvent>>,
    /// Callback receiver (moved to `PinnedLoopConfig`).
    xb_callback_rx: Option<Receiver<ShardEvent>>,
    /// Consensus receiver (moved to `PinnedLoopConfig`).
    xb_consensus_rx: Option<Receiver<ShardEvent>>,
    /// Shutdown receiver (moved to `PinnedLoopConfig`).
    xb_shutdown_rx: Option<Receiver<()>>,

    /// Libp2p network adapter (shared with `InboundRouter`, `RequestManager`).
    network: Arc<Libp2pAdapter>,
    /// Network topology snapshot (lock-free `ArcSwap`, updated on topology changes).
    topology_snapshot: SharedTopologySnapshot,
    /// One `RocksDB` storage per hosted shard. The runner keeps these
    /// alive for periodic JMT GC and storage-memory metrics.
    #[allow(dead_code)]
    storages: HashMap<ShardGroupId, Arc<RocksDbStorage>>,
    /// Primary storage handle (`storages[primary_shard]`) used by
    /// single-storage code paths (genesis bookkeeping, JMT GC, storage
    /// memory metrics).
    primary_storage: Arc<RocksDbStorage>,
    /// Thread pool dispatch.
    dispatch: Arc<PooledDispatch>,
    /// Primary shard for status / RPC / single-storage operations.
    primary_shard: ShardGroupId,
    /// Every shard this runner hosts vnodes for.
    #[allow(dead_code)]
    local_shards: HashSet<ShardGroupId>,

    /// Shared RPC `NodeStatusState` updated by the metrics tick.
    rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    /// Shared mempool snapshot updated by the metrics tick.
    mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
    /// Shared sync status updated by the metrics tick.
    sync_status: Option<Arc<ArcSwap<SyncStatus>>>,

    /// Optional genesis configuration for initial state.
    genesis_config: Option<GenesisConfig>,

    /// Transaction status cache, shared from `IoLoop` for lock-free RPC queries.
    tx_status_cache: Arc<QuickCache<TxHash, TransactionStatus>>,

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
    pub fn builder(
        vnodes: Vec<VnodeConfig>,
        bft_config: BftConfig,
        storages: HashMap<ShardGroupId, Arc<RocksDbStorage>>,
        network_config: Libp2pConfig,
    ) -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new(vnodes, bft_config, storages, network_config)
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

    /// Get the runner's primary shard ID — the shard whose status,
    /// metrics, and genesis bookkeeping the runner surfaces to its
    /// callers.
    #[must_use]
    pub const fn primary_shard(&self) -> ShardGroupId {
        self.primary_shard
    }

    /// Get the transaction status cache shared from `IoLoop`.
    ///
    /// This `Arc<QuickCache>` is the same instance used by `IoLoop` on the
    /// pinned thread. It can be passed directly to the RPC server for
    /// lock-free status queries.
    #[must_use]
    pub fn tx_status_cache(&self) -> Arc<QuickCache<TxHash, TransactionStatus>> {
        Arc::clone(&self.tx_status_cache)
    }

    /// Get a crossbeam sender for submitting consensus events.
    ///
    /// Events sent through this sender are forwarded to the pinned `IoLoop`
    /// thread via the crossbeam consensus channel.
    #[must_use]
    pub fn event_sender(&self) -> Sender<ShardEvent> {
        self.xb_consensus_tx.clone()
    }

    /// Get a sender for RPC transaction submissions.
    ///
    /// Returns a crossbeam channel sender that feeds directly into the `IoLoop`.
    /// RPC handlers wrap transactions in `Event::SubmitTransaction` before sending.
    /// `IoLoop` handles gossip, validation, and mempool dispatch.
    #[must_use]
    pub fn tx_submission_sender(&self) -> Sender<ShardEvent> {
        self.xb_consensus_tx.clone()
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
    /// This MUST be called before the `IoLoop` is moved to the pinned thread,
    /// since it needs mutable access to the `IoLoop`.
    fn maybe_initialize_genesis(&mut self) -> Vec<TimerOp> {
        let io_loop = self
            .io_loop
            .as_mut()
            .expect("io_loop must exist for genesis");

        // Multi-shard genesis: run the genesis ceremony for every
        // hosted shard. Each shard has its own RocksDB store, its own
        // committed height, and its own genesis block.
        let mut timer_ops = Vec::new();
        let local_shards: Vec<ShardGroupId> = io_loop.hosted_shards().collect();
        let topology = Arc::clone(&self.topology_snapshot);
        // `GenesisConfig::production` is shared across hosted shards, so one
        // `take()` covers every shard.
        let mut shared_genesis_config: Option<GenesisConfig> = self.genesis_config.take();
        for shard in local_shards {
            let height = io_loop.shard_io(shard).storage.committed_height();
            if height > BlockHeight::GENESIS {
                info!(
                    shard = ?shard,
                    "Existing blocks found, skipping genesis initialization for shard"
                );
                continue;
            }
            info!(shard = ?shard, "No committed blocks - initializing genesis for shard");

            let genesis_config = shared_genesis_config
                .take()
                .unwrap_or_else(GenesisConfig::production);
            info!(
                shard = ?shard,
                xrd_balances = genesis_config.xrd_balances.len(),
                "Running genesis"
            );
            let genesis_jmt_root = io_loop.install_engine_genesis(shard, &genesis_config);

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

            let genesis_block = Block::genesis(shard, first_validator, genesis_jmt_root);

            let genesis_hash = genesis_block.hash();
            info!(
                shard = ?shard,
                genesis_hash = ?genesis_hash,
                proposer = ?first_validator,
                "Created genesis block"
            );

            io_loop.initialize_shard_genesis(&genesis_block);
            io_loop.flush_all_batches();

            let genesis_output = io_loop.drain_pending_output();
            timer_ops.extend(genesis_output.timer_ops);

            // Sync the state machine with the JMT state genesis just
            // installed — vnodes were created with zero state.
            let genesis_qc = {
                let __qc = QuorumCertificate::genesis(shard);
                QuorumCertificate::new(
                    genesis_block.hash(),
                    __qc.shard_group_id(),
                    __qc.height(),
                    __qc.parent_block_hash(),
                    __qc.round(),
                    __qc.signers().clone(),
                    __qc.aggregated_signature(),
                    __qc.weighted_timestamp(),
                )
            };
            let genesis_certified =
                Arc::new(CertifiedBlock::new_unchecked(genesis_block, genesis_qc));
            let genesis_commit_output = io_loop.step(ShardEvent::protocol(
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
            io_loop.flush_all_batches();
        }

        io_loop.register_inbound_handlers();
        timer_ops
    }

    // ═══════════════════════════════════════════════════════════════════
    // Main Run Loop
    // ═══════════════════════════════════════════════════════════════════

    /// Run the production node.
    ///
    /// 1. Initializes genesis via `IoLoop` (before spawning pinned thread)
    /// 2. Extracts the `IoLoop` and channel receivers for the pinned thread
    /// 3. Spawns the pinned thread running the `IoLoop` event loop
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
    /// Panics if `run` is called twice on the same runner (the `IoLoop` and
    /// channel receivers have already been moved to the pinned thread).
    pub async fn run(mut self) -> Result<(), RunnerError> {
        let config = self.dispatch.config();
        info!(
            shards = ?self.local_shards,
            crypto_threads = config.crypto_threads,
            execution_threads = config.execution_threads,
            pin_cores = config.pin_cores,
            "Starting production runner (IoLoop architecture)"
        );

        // ── 1. Initialize genesis before spawning pinned thread ──────────
        let initial_timer_ops = self.maybe_initialize_genesis();

        // ── 2. Extract IoLoop and channel receivers for pinned thread ───
        let io_loop = self
            .io_loop
            .take()
            .expect("io_loop already taken (run called twice?)");

        let pinned_config = PinnedLoopConfig {
            timer_tx: self.xb_timer_tx.clone(),
            timer_rx: self.xb_timer_rx.take().expect("timer_rx already taken"),
            callback_rx: self
                .xb_callback_rx
                .take()
                .expect("callback_rx already taken"),
            consensus_rx: self
                .xb_consensus_rx
                .take()
                .expect("consensus_rx already taken"),
            shutdown_rx: self
                .xb_shutdown_rx
                .take()
                .expect("shutdown_rx already taken"),
            tokio_handle: TokioHandle::current(),
            initial_timer_ops,
            rpc_status: self.rpc_status.clone(),
            sync_status: self.sync_status.clone(),
            mempool_snapshot: self.mempool_snapshot.clone(),
            primary_storage: Arc::clone(&self.primary_storage),
        };

        // ── 3. Spawn pinned thread ───────────────────────────────────────
        let loop_handle = spawn_pinned_loop(io_loop, pinned_config);

        // ── 4. Metrics + shutdown loop ───────────────────────────────────
        let mut metrics_tick = interval(Duration::from_secs(1));
        metrics_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut shutdown_rx = self.shutdown_rx.take().expect("shutdown_rx already taken");

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received");
                    break;
                }
                _ = metrics_tick.tick() => {
                    self.collect_metrics();
                }
            }
        }

        // ── 6. Shutdown pinned thread ────────────────────────────────────
        info!("Sending shutdown to pinned thread");
        let _ = self.xb_shutdown_tx.send(());

        // Wait for the pinned thread to exit.
        if let Err(e) = loop_handle.join() {
            warn!("Pinned thread panicked: {:?}", e);
        }

        info!("Production runner stopped");
        Ok(())
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
            self.dispatch.queue_depth(DispatchPool::ConsensusCrypto),
            self.dispatch.queue_depth(DispatchPool::Crypto),
            self.dispatch.queue_depth(DispatchPool::TxValidation),
            self.dispatch.queue_depth(DispatchPool::Execution),
        );

        // ── Peer count ───────────────────────────────────────────────────
        let peer_count = self.network.cached_peer_count();
        set_libp2p_peers(peer_count);

        // ── Update RPC status with peer count ────────────────────────────
        if let Some(ref rpc_status) = self.rpc_status {
            let current = rpc_status.load();
            if current.connected_peers != peer_count {
                let mut updated = (**current).clone();
                updated.connected_peers = peer_count;
                rpc_status.store(Arc::new(updated));
            }
        }

        // ── Update sync_peers on the sync status (only runner has Libp2pNetwork) ──
        if let Some(ref sync_status) = self.sync_status {
            let current = sync_status.load();
            if current.sync_peers != peer_count {
                let mut updated = (**current).clone();
                updated.sync_peers = peer_count;
                sync_status.store(Arc::new(updated));
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Network stack construction helper
// ═══════════════════════════════════════════════════════════════════════════

struct NetworkBuildArgs {
    network_config: Libp2pConfig,
    ed25519_keypair: Keypair,
    /// Shards hosted by this host. Drives per-shard request stream
    /// protocols and gossipsub subscriptions on the adapter.
    local_shards: HashSet<ShardGroupId>,
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
    let registry = Arc::new(HandlerRegistry::new());

    let adapter = Libp2pAdapter::new(
        args.network_config,
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

/// Concrete `IoLoop` type for the production runner.
type ProdIoLoop = IoLoop<SharedStorage, Libp2pNetwork, PooledDispatch>;

/// Configuration for the pinned event loop.
struct PinnedLoopConfig {
    timer_tx: Sender<ShardEvent>,
    timer_rx: Receiver<ShardEvent>,
    callback_rx: Receiver<ShardEvent>,
    consensus_rx: Receiver<ShardEvent>,
    shutdown_rx: Receiver<()>,
    tokio_handle: TokioHandle,
    initial_timer_ops: Vec<TimerOp>,
    rpc_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
    mempool_snapshot: Option<Arc<ArcSwap<MempoolSnapshot>>>,
    /// Primary `RocksDbStorage` used by the pinned loop's periodic
    /// metrics dispatch and JMT GC.
    primary_storage: Arc<RocksDbStorage>,
}

/// Manages tokio-based timers for the production pinned event loop.
///
/// Spawns async sleep tasks via the tokio handle that fire timer events
/// into the crossbeam timer channel.
struct ProdTimerManager {
    tokio_handle: TokioHandle,
    timer_tx: Sender<ShardEvent>,
    active: HashMap<(ShardGroupId, TimerId), JoinHandle<()>>,
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

/// Mint the `io_loop`'s monotonic local clock as a `LocalTimestamp` (ms since
/// UNIX epoch). Used to set the state machine's clock before each step.
/// Same epoch as `WeightedTimestamp` so the proposer-skew comparison works
/// without unit conversion. NTP back-steps are absorbed by saturating
/// arithmetic on `LocalTimestamp`.
fn wall_clock_local() -> LocalTimestamp {
    let ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    LocalTimestamp::from_millis(ms)
}

/// Push a [`NodeStatusSnapshot`] into the shared RPC state objects.
///
/// Surfaces one status per node via [`NodeStatusSnapshot::primary`].
fn update_rpc_state(config: &PinnedLoopConfig, snapshot: &NodeStatusSnapshot) {
    let Some((shard, vnode)) = snapshot.primary() else {
        return;
    };

    if let Some(ref rpc_status) = config.rpc_status {
        let current = rpc_status.load();
        rpc_status.store(Arc::new(NodeStatusState {
            block_height: vnode.committed_height.inner(),
            view: vnode.view,
            state_root_hash: hex_encode(vnode.state_root.as_bytes()),
            // Preserve fields set by other writers (runner sets connected_peers)
            validator_id: current.validator_id,
            shard: current.shard,
            num_shards: current.num_shards,
            connected_peers: current.connected_peers,
        }));
    }

    if let Some(ref sync_status) = config.sync_status {
        let current = sync_status.load();
        sync_status.store(Arc::new(SyncStatus {
            state: shard.block_sync.state.clone(),
            current_height: shard.block_sync.current_height,
            target_height: shard.block_sync.target_height,
            blocks_behind: shard.block_sync.blocks_behind,
            // Preserve sync_peers set by runner's collect_metrics
            sync_peers: current.sync_peers,
            pending_fetches: shard.block_sync.pending_fetches,
            queued_heights: shard.block_sync.queued_heights,
        }));
    }

    if let Some(ref mempool_snapshot) = config.mempool_snapshot {
        mempool_snapshot.store(Arc::new(MempoolSnapshot {
            pending_count: vnode.mempool_pending,
            in_flight_count: vnode.mempool_in_flight,
            total_count: vnode.mempool_total,
            accepting_rpc_transactions: vnode.accepting_rpc_transactions,
            at_pending_limit: vnode.at_pending_limit,
            remote_shard_in_flight: vnode.remote_shard_in_flight.clone(),
            remote_congestion_threshold: vnode.remote_congestion_threshold,
            updated_at: Some(Instant::now()),
        }));
    }
}

/// Run the `IoLoop` on a pinned thread. Blocks until shutdown.
///
/// Drains the three crossbeam channels via `try_recv` in priority order
/// (`timer_rx` > `callback_rx` > `consensus_rx`). When all are empty,
/// blocks on `crossbeam::select!` with a timeout derived from the nearest
/// batch deadline. Block commit and other I/O work is dispatched by
/// `IoLoop` via `Dispatch::spawn(Io, ..)`; this loop only drives event
/// flow.
fn run_pinned_loop(mut io_loop: ProdIoLoop, mut config: PinnedLoopConfig) {
    info!("Pinned event loop starting");

    let mut timer_mgr = ProdTimerManager::new(config.tokio_handle.clone(), config.timer_tx.clone());

    // Process timer ops from genesis initialization (e.g. ViewChange timer).
    for op in std::mem::take(&mut config.initial_timer_ops) {
        timer_mgr.process_op(op);
    }

    let mut last_metrics = Instant::now();
    let mut last_gc = Instant::now();
    let gc_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        // ── Shutdown check ──
        if config.shutdown_rx.try_recv().is_ok() {
            info!("Pinned event loop received shutdown signal");
            break;
        }

        // ── Set wall-clock time ──
        let now = wall_clock_local();
        io_loop.set_time(now);

        // ── Priority try_recv cascade ──
        let event = 'recv: {
            if let Ok(e) = config.timer_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(e) = config.callback_rx.try_recv() {
                break 'recv Some(e);
            }
            if let Ok(e) = config.consensus_rx.try_recv() {
                break 'recv Some(e);
            }

            // Nothing ready — block with timeout from nearest batch deadline
            let timeout = io_loop
                .nearest_batch_deadline()
                .map_or(DEFAULT_TIMEOUT, |deadline| deadline.saturating_sub(now));

            crossbeam::channel::select! {
                recv(config.shutdown_rx) -> _ => {
                    info!("Pinned event loop received shutdown signal (select)");
                    return;
                }
                recv(config.timer_rx) -> e => e.ok(),
                recv(config.callback_rx) -> e => e.ok(),
                recv(config.consensus_rx) -> e => e.ok(),
                default(timeout) => None,
            }
        };

        // ── Process event ──
        if let Some(event) = event {
            let output = io_loop.step(event);

            // Process timer operations from this step. Block commit and
            // other I/O are dispatched by io_loop itself via
            // `Dispatch::spawn(Io, ..)` — they do not surface here.
            for op in output.timer_ops {
                timer_mgr.process_op(op);
            }
        }

        // ── Flush expired batches ──
        io_loop.flush_expired_batches(wall_clock_local());

        // ── Periodic metrics + RPC status snapshot ──
        if last_metrics.elapsed() >= METRICS_INTERVAL {
            last_metrics = Instant::now();

            // Capture cheap snapshot on pinned thread, dispatch expensive
            // recording (RocksDB queries + prometheus calls) off-thread.
            let snapshot = io_loop.metrics_snapshot();
            let channel_depths = ChannelDepths {
                callback: config.callback_rx.len(),
                consensus: config.consensus_rx.len(),
                validated_tx: 0,
                rpc_tx: 0,
                status: 0,
                sync_request: 0,
                tx_request: 0,
                cert_request: 0,
            };
            let storage = Arc::clone(&config.primary_storage);
            config.tokio_handle.spawn_blocking(move || {
                record_metrics(snapshot, &*storage);
                set_channel_depths(&channel_depths);
            });

            // Push status snapshot to shared RPC state.
            update_rpc_state(&config, &io_loop.status_snapshot());
        }

        // ── Periodic JMT GC (off main thread) ──
        if !gc_in_flight.load(std::sync::atomic::Ordering::Relaxed)
            && last_gc.elapsed() >= GC_INTERVAL
        {
            last_gc = Instant::now();
            gc_in_flight.store(true, std::sync::atomic::Ordering::Relaxed);
            let storage = Arc::clone(&config.primary_storage);
            let gc_flag = gc_in_flight.clone();
            config.tokio_handle.spawn_blocking(move || {
                let deleted = storage.run_jmt_gc();
                if deleted > 0 {
                    debug!(deleted, "JMT garbage collection completed");
                }
                let history_deleted = storage.run_state_history_gc();
                if history_deleted > 0 {
                    debug!(history_deleted, "State-history GC completed");
                }
                gc_flag.store(false, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    info!("Pinned event loop exiting");
}

/// Spawn the `IoLoop` on a dedicated thread pinned to core 0.
fn spawn_pinned_loop(io_loop: ProdIoLoop, config: PinnedLoopConfig) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("io-loop".to_string())
        .spawn(move || {
            // Try to pin to core 0
            if let Some(core_ids) = get_core_ids()
                && let Some(&core_id) = core_ids.first()
            {
                if set_for_current(core_id) {
                    info!(?core_id, "Pinned io-loop thread to core");
                } else {
                    warn!("Failed to pin io-loop thread to core 0");
                }
            }

            run_pinned_loop(io_loop, config);
        })
        .expect("failed to spawn io-loop thread")
}
