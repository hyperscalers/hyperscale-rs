//! Production runner implementation.
//!
//! # Architecture
//!
//! The production runner uses a **pinned thread** architecture:
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │  Core 0 (pinned std::thread)                                        │
//!  │  ┌────────────────────────────────────────────────────────────────┐  │
//!  │  │  NodeLoop<SharedStorage, ProdNetwork, PooledDispatch>         │  │
//!  │  │    - State machine event processing                           │  │
//!  │  │    - Storage I/O (RocksDB)                                    │  │
//!  │  │    - Action handling (timers, broadcasts, crypto dispatch)    │  │
//!  │  │    - Transaction validation batching via Dispatch              │  │
//!  │  │    - RPC SubmitTransaction handling (gossip + validate)       │  │
//!  │  │    - Batched message sending, batched crypto verification     │  │
//!  │  └────────────────────────────────────────────────────────────────┘  │
//!  │       ↑ crossbeam channels (all events) ↑                           │
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
//! Libp2p adapter ──crossbeam──→ pinned thread (NodeLoop)
//! RPC server     ──crossbeam──→ pinned thread (Event::SubmitTransaction)
//! Dispatch       ──crossbeam──→ pinned thread (crypto/validation callbacks)
//! ProdTimerManager ──crossbeam──→ pinned thread (timer events)
//! ```

use crate::event_loop::{spawn_pinned_loop, PinnedLoopConfig, ProdNodeLoop};
use crate::rpc::{MempoolSnapshot, NodeStatusState, TransactionStatusCache};
use hyperscale_bft::BftConfig;
use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_engine::{NetworkDefinition, RadixExecutor};
use hyperscale_mempool::MempoolConfig;
use hyperscale_metrics as metrics;
use hyperscale_network_libp2p::ProdNetwork;
use hyperscale_network_libp2p::{
    compute_peer_id_for_validator, spawn_inbound_router, InboundRouterHandle, Libp2pAdapter,
    Libp2pConfig, Libp2pKeypair, NetworkError,
};
use hyperscale_storage::{
    CommittableSubstateDatabase, ConsensusStore, DatabaseUpdates, DbPartitionKey, DbSortKey,
    DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use hyperscale_storage_rocksdb::{RocksDbStorage, SharedStorage};
use hyperscale_types::BlockHeight;
use quick_cache::sync::Cache as QuickCache;

use hyperscale_core::Event;
use hyperscale_node::node_loop::{NodeLoop, TimerOp};
use hyperscale_node::sync_protocol::SyncProtocol;
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    Block, BlockHeader, Bls12381G1PrivateKey, Hash, QuorumCertificate, RoutableTransaction,
    ShardGroupId, Topology, TransactionCertificate, ValidatorId,
};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::sync::RwLock as TokioRwLock;
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════════════════════
// GenesisMutWrapper — bridges RocksDB &self commit with Radix Engine &mut self
// ═══════════════════════════════════════════════════════════════════════════

/// Wrapper that bridges `RocksDbStorage`'s `&self` commit with the Radix Engine's
/// `&mut self` `CommittableSubstateDatabase` trait, used only for genesis execution.
///
/// Takes `&RocksDbStorage` (accessed via `SharedStorage` deref) because the
/// production runner wraps storage in `SharedStorage` (newtype over `Arc<RocksDbStorage>`)
/// for shared ownership between the pinned thread and async tasks.
struct GenesisMutWrapper<'a>(&'a RocksDbStorage);

impl SubstateDatabase for GenesisMutWrapper<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.0.get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        self.0
            .list_raw_values_from_db_key(partition_key, from_sort_key)
    }
}

impl CommittableSubstateDatabase for GenesisMutWrapper<'_> {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.0.commit(updates).expect("genesis commit failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RunnerError
// ═══════════════════════════════════════════════════════════════════════════

/// Errors from the production runner.
#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("Event channel closed")]
    ChannelClosed,
    #[error("Request dropped")]
    RequestDropped,
    #[error("Send error: {0}")]
    SendError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
}

// ═══════════════════════════════════════════════════════════════════════════
// ShutdownHandle
// ═══════════════════════════════════════════════════════════════════════════

/// Handle for shutting down a running ProductionRunner.
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
// ProductionRunnerBuilder
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for constructing a [`ProductionRunner`].
///
/// Required fields:
/// - `topology` - Network topology defining validators and shards
/// - `signing_key` - BLS keypair for signing votes and proposals
/// - `bft_config` - Consensus configuration parameters
/// - `storage` - RocksDB storage for persistence and crash recovery
/// - `network` - libp2p configuration for peer-to-peer communication
///
/// Optional fields:
/// - `dispatch` - Dispatch implementation (defaults to auto-configured)
/// - `channel_capacity` - Event channel capacity (defaults to 10,000)
pub struct ProductionRunnerBuilder {
    topology: Option<Arc<dyn Topology>>,
    signing_key: Option<Bls12381G1PrivateKey>,
    bft_config: Option<BftConfig>,
    dispatch: Option<Arc<PooledDispatch>>,
    storage: Option<Arc<RocksDbStorage>>,
    network_config: Option<Libp2pConfig>,
    ed25519_keypair: Option<Libp2pKeypair>,
    channel_capacity: usize,
    /// Optional RPC status state to update on block commits and view changes.
    rpc_status: Option<Arc<TokioRwLock<NodeStatusState>>>,
    /// Optional transaction status cache for RPC queries.
    tx_status_cache: Option<Arc<TokioRwLock<TransactionStatusCache>>>,
    /// Optional mempool snapshot for RPC queries.
    mempool_snapshot: Option<Arc<TokioRwLock<MempoolSnapshot>>>,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<hyperscale_engine::GenesisConfig>,
    /// Radix network definition for transaction validation.
    /// Defaults to simulator network if not set.
    network_definition: Option<NetworkDefinition>,
    /// Maximum transactions for speculative execution (in-flight + cached).
    speculative_max_txs: usize,
    /// Rounds to pause speculation after a view change.
    view_change_cooldown_rounds: u64,
    /// Mempool configuration.
    mempool_config: MempoolConfig,
}

impl Default for ProductionRunnerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductionRunnerBuilder {
    /// Create a new builder with default channel capacity.
    pub fn new() -> Self {
        Self {
            topology: None,
            signing_key: None,
            bft_config: None,
            dispatch: None,
            storage: None,
            network_config: None,
            ed25519_keypair: None,
            channel_capacity: 10_000,
            rpc_status: None,
            tx_status_cache: None,
            mempool_snapshot: None,
            genesis_config: None,
            network_definition: None,
            speculative_max_txs: 500,
            view_change_cooldown_rounds: 3,
            mempool_config: MempoolConfig::default(),
        }
    }

    /// Set the Radix network definition for transaction validation.
    pub fn network_definition(mut self, network: NetworkDefinition) -> Self {
        self.network_definition = Some(network);
        self
    }

    /// Set the network topology.
    pub fn topology(mut self, topology: Arc<dyn Topology>) -> Self {
        self.topology = Some(topology);
        self
    }

    /// Set the BLS signing key for votes and proposals.
    pub fn signing_key(mut self, key: Bls12381G1PrivateKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set the BFT consensus configuration.
    pub fn bft_config(mut self, config: BftConfig) -> Self {
        self.bft_config = Some(config);
        self
    }

    /// Set the dispatch implementation (optional, defaults to auto-configured pools).
    pub fn dispatch(mut self, dispatch: Arc<PooledDispatch>) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// Set the RocksDB storage for persistence and crash recovery.
    pub fn storage(mut self, storage: Arc<RocksDbStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the network configuration and Ed25519 keypair for libp2p.
    pub fn network(mut self, config: Libp2pConfig, keypair: Libp2pKeypair) -> Self {
        self.network_config = Some(config);
        self.ed25519_keypair = Some(keypair);
        self
    }

    /// Set the event channel capacity (default: 10,000).
    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    /// Set the maximum transactions for speculative execution (in-flight + cached).
    pub fn speculative_max_txs(mut self, max_txs: usize) -> Self {
        self.speculative_max_txs = max_txs;
        self
    }

    /// Set the number of rounds to pause speculation after a view change.
    pub fn view_change_cooldown_rounds(mut self, rounds: u64) -> Self {
        self.view_change_cooldown_rounds = rounds;
        self
    }

    /// Set the mempool configuration.
    pub fn mempool_config(mut self, config: MempoolConfig) -> Self {
        self.mempool_config = config;
        self
    }

    /// Set the RPC status state to update on block commits and view changes.
    pub fn rpc_status(mut self, status: Arc<TokioRwLock<NodeStatusState>>) -> Self {
        self.rpc_status = Some(status);
        self
    }

    /// Set the transaction status cache for RPC queries.
    pub fn tx_status_cache(mut self, cache: Arc<TokioRwLock<TransactionStatusCache>>) -> Self {
        self.tx_status_cache = Some(cache);
        self
    }

    /// Set the mempool snapshot for RPC queries.
    pub fn mempool_snapshot(mut self, snapshot: Arc<TokioRwLock<MempoolSnapshot>>) -> Self {
        self.mempool_snapshot = Some(snapshot);
        self
    }

    /// Set the genesis configuration for initial state.
    pub fn genesis_config(mut self, config: hyperscale_engine::GenesisConfig) -> Self {
        self.genesis_config = Some(config);
        self
    }

    /// Build the production runner.
    ///
    /// Creates all channels, the NodeLoop, networking adapters, and supporting
    /// infrastructure. The NodeLoop is held in an `Option` so it can be moved
    /// to the pinned thread when `run()` is called.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing or if network setup fails.
    pub async fn build(self) -> Result<ProductionRunner, RunnerError> {
        // Install the Prometheus metrics backend before anything records metrics.
        hyperscale_metrics_prometheus::install();

        // ── Extract required fields ──────────────────────────────────────

        let topology = self
            .topology
            .ok_or_else(|| RunnerError::SendError("topology is required".into()))?;
        let signing_key = self
            .signing_key
            .ok_or_else(|| RunnerError::SendError("signing_key is required".into()))?;
        let bft_config = self
            .bft_config
            .ok_or_else(|| RunnerError::SendError("bft_config is required".into()))?;
        let dispatch = match self.dispatch {
            Some(pools) => pools,
            None => {
                Arc::new(PooledDispatch::auto().map_err(|e| RunnerError::SendError(e.to_string()))?)
            }
        };
        let storage = self
            .storage
            .ok_or_else(|| RunnerError::SendError("storage is required".into()))?;
        let network_config = self
            .network_config
            .ok_or_else(|| RunnerError::SendError("network is required".into()))?;
        let ed25519_keypair = self
            .ed25519_keypair
            .ok_or_else(|| RunnerError::SendError("network keypair is required".into()))?;

        let validator_id = topology.local_validator_id();
        let local_shard = topology.local_shard();

        // Clone signing key bytes BEFORE passing to state machine (which consumes it).
        // Bls12381G1PrivateKey doesn't impl Clone, so we round-trip through bytes.
        let key_bytes = signing_key.to_bytes();
        let node_loop_signing_key =
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

        // ── Crossbeam channels (→ pinned thread) ───────────────────────
        //
        // These are the inputs to the pinned NodeLoop thread. Crossbeam unbounded
        // channels are chosen because they are lock-free and sync-safe.
        let (xb_timer_tx, xb_timer_rx) = crossbeam::channel::unbounded();
        let (xb_callback_tx, xb_callback_rx) = crossbeam::channel::unbounded();
        let (xb_consensus_tx, xb_consensus_rx) = crossbeam::channel::unbounded();
        let (xb_shutdown_tx, xb_shutdown_rx) = crossbeam::channel::unbounded();

        // ── Shutdown oneshot ─────────────────────────────────────────────
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // ── Load crash recovery state ────────────────────────────────────
        let recovered = storage.load_recovered_state();

        // ── Create NodeStateMachine ──────────────────────────────────────
        let state = NodeStateMachine::with_speculative_config(
            0, // node_index not meaningful in production
            topology.clone(),
            signing_key,
            bft_config,
            recovered,
            self.speculative_max_txs,
            self.view_change_cooldown_rounds,
            self.mempool_config,
        );

        // ── Create SharedStorage ────────────────────────────────────────
        let shared_storage = SharedStorage::new(Arc::clone(&storage));

        // ── Create ProdNetwork ───────────────────────────────────────────
        //
        // Wraps the Libp2p adapter for use by NodeLoop's action handler.
        // encode_to_wire + adapter.publish() is sync-safe (non-blocking send).
        // Note: We create the adapter below, then wrap it.
        // ProdNetwork is created after the adapter.

        // ── Use configured network definition or default ─────────────────
        let network_definition = self
            .network_definition
            .unwrap_or_else(NetworkDefinition::simulator);

        // ── Create transaction validator ─────────────────────────────────
        let tx_validator = Arc::new(hyperscale_engine::TransactionValidation::new(
            network_definition.clone(),
        ));

        // ── Register gossip handlers via HandlerRegistry ────────────────
        //
        // The HandlerRegistry dispatches decoded gossip messages to typed
        // handlers. Each handler constructs an Event and sends it via the
        // consensus crossbeam channel to the pinned NodeLoop thread.
        let gossip_registry = Arc::new(hyperscale_network::HandlerRegistry::new());
        hyperscale_node::gossip_dispatch::register_gossip_handlers(
            &gossip_registry,
            xb_consensus_tx.clone(),
        );

        // ── Create codec pool handle ─────────────────────────────────────
        let codec_pool_handle =
            hyperscale_network_libp2p::CodecPoolHandle::new(dispatch.clone(), gossip_registry);

        // ── Create Libp2p network adapter ────────────────────────────────
        let adapter = Libp2pAdapter::new(
            network_config,
            ed25519_keypair,
            validator_id,
            local_shard,
            codec_pool_handle,
        )
        .await?;

        // Subscribe to local shard topics.
        adapter.subscribe_shard(local_shard).await?;

        // Register ALL validators from the global set for peer validation.
        // Cross-shard transactions are gossiped between shards, so we need
        // all validators, not just local committee.
        for validator in &topology.global_validator_set().validators {
            let peer_id = compute_peer_id_for_validator(&validator.public_key);
            adapter
                .register_validator(validator.validator_id, peer_id)
                .await;
        }

        // ── Create RequestManager ────────────────────────────────────────
        let request_manager = Arc::new(hyperscale_network_libp2p::RequestManager::new(
            adapter.clone(),
            hyperscale_network_libp2p::RequestManagerConfig::default(),
        ));

        // ── Now create ProdNetwork wrapping the adapter ──────────────────
        //
        // ProdNetwork owns the RequestManager for generic request-response.
        // It SBOR-encodes requests, frames them with type_id, and dispatches
        // through the RequestManager's retry/peer-selection logic.
        let prod_network = ProdNetwork::new(
            adapter.clone(),
            request_manager.clone(),
            topology.clone(),
            tokio::runtime::Handle::current(),
        );

        // ── Create RadixExecutor ─────────────────────────────────────────
        let executor = RadixExecutor::new(network_definition);

        // ── Create SyncProtocol for NodeLoop ─────────────────────────────
        let sync_protocol = SyncProtocol::new(hyperscale_node::SyncConfig::default());

        // ── Create NodeLoop ──────────────────────────────────────────────
        //
        // The NodeLoop owns the state machine, storage, executor, network,
        // dispatch, and event sender. It processes ALL actions from the
        // state machine on the pinned thread. Timer ops are returned in
        // StepOutput and managed by ProdTimerManager on the pinned thread.

        let node_loop = NodeLoop::new(
            state,
            shared_storage,
            executor,
            prod_network,
            (*dispatch).clone(),
            xb_callback_tx.clone(),
            node_loop_signing_key,
            topology.clone(),
            local_shard,
            validator_id,
            sync_protocol,
            tx_validator.clone(),
        );

        // ── Get cache handles from NodeLoop ──────────────────────────────
        //
        // Caches live inside NodeLoop. Get Arc clones before moving to pinned thread.
        // These are shared with InboundRouter for serving peer fetch requests.
        let recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>> =
            Arc::clone(node_loop.cert_cache());
        let recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>> =
            Arc::clone(node_loop.tx_cache());

        // ── Spawn InboundRouter ──────────────────────────────────────────
        //
        // Handles all inbound requests (block sync, tx fetch, cert fetch) from peers.
        // Hot data is served from in-memory caches, falling back to RocksDB.
        // The InboundHandler lives in the node crate; the transport router
        // in network-libp2p is generic over InboundRequestHandler.
        let inbound_handler = hyperscale_node::InboundHandler::new(
            hyperscale_node::InboundHandlerConfig::default(),
            storage.clone(),
            recently_received_txs.clone(),
            recently_built_certs.clone(),
        );
        let inbound_router = spawn_inbound_router(adapter.clone(), inbound_handler);

        // ── Build ProductionRunner ───────────────────────────────────────

        Ok(ProductionRunner {
            node_loop: Some(node_loop),
            xb_timer_tx,
            xb_consensus_tx,
            xb_callback_tx: xb_callback_tx.clone(),
            xb_shutdown_tx,
            xb_timer_rx: Some(xb_timer_rx),
            xb_callback_rx: Some(xb_callback_rx),
            xb_consensus_rx: Some(xb_consensus_rx),
            xb_shutdown_rx: Some(xb_shutdown_rx),
            network: adapter,
            topology,
            storage,
            dispatch,
            inbound_router,
            rpc_status: self.rpc_status,
            tx_status_cache: self.tx_status_cache,
            mempool_snapshot: self.mempool_snapshot,
            genesis_config: self.genesis_config,
            local_shard,
            recently_received_txs,
            recently_built_certs,
            shutdown_rx: Some(shutdown_rx),
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ProductionRunner
// ═══════════════════════════════════════════════════════════════════════════

/// Production runner with NodeLoop on a pinned thread.
///
/// The state machine (NodeLoop) runs on a dedicated thread pinned to core 0.
/// All state machine processing, storage I/O, action handling, and gossip cert
/// verification happen on that thread. The tokio runtime handles async I/O
/// routing, RPC transaction handling, sync/fetch management, and metrics.
pub struct ProductionRunner {
    // ── NodeLoop (moved to pinned thread on run()) ───────────────────────
    /// The NodeLoop, wrapped in Option because it's moved to the pinned thread.
    /// `None` after `run()` extracts it.
    node_loop: Option<ProdNodeLoop>,

    // ── Crossbeam senders (async → pinned thread) ────────────────────────
    /// Timer events to pinned thread (for external timer injection if needed).
    #[allow(dead_code)]
    xb_timer_tx: crossbeam::channel::Sender<Event>,
    /// Consensus events to pinned thread (from Libp2p adapter routing).
    xb_consensus_tx: crossbeam::channel::Sender<Event>,
    /// Callback events to pinned thread (from bridge tasks, direct sends).
    #[allow(dead_code)] // Kept alive to prevent crossbeam channel closure
    xb_callback_tx: crossbeam::channel::Sender<Event>,
    /// Shutdown signal to pinned thread.
    xb_shutdown_tx: crossbeam::channel::Sender<()>,

    // ── Crossbeam receivers (extracted for PinnedLoopConfig) ─────────────
    /// Timer receiver (moved to PinnedLoopConfig).
    xb_timer_rx: Option<crossbeam::channel::Receiver<Event>>,
    /// Callback receiver (moved to PinnedLoopConfig).
    xb_callback_rx: Option<crossbeam::channel::Receiver<Event>>,
    /// Consensus receiver (moved to PinnedLoopConfig).
    xb_consensus_rx: Option<crossbeam::channel::Receiver<Event>>,
    /// Shutdown receiver (moved to PinnedLoopConfig).
    xb_shutdown_rx: Option<crossbeam::channel::Receiver<()>>,

    // ── Infrastructure ───────────────────────────────────────────────────
    /// Libp2p network adapter (shared with InboundRouter, RequestManager).
    network: Arc<Libp2pAdapter>,
    /// Network topology.
    topology: Arc<dyn Topology>,
    /// RocksDB storage (for InboundRouter and genesis).
    #[allow(dead_code)]
    storage: Arc<RocksDbStorage>,
    /// Thread pool dispatch.
    dispatch: Arc<PooledDispatch>,
    /// Handle for the InboundRouter task.
    #[allow(dead_code)]
    inbound_router: InboundRouterHandle,
    /// Local shard for network broadcasts.
    local_shard: ShardGroupId,

    // ── RPC state ────────────────────────────────────────────────────────
    /// Optional RPC status state.
    rpc_status: Option<Arc<TokioRwLock<NodeStatusState>>>,
    /// Optional transaction status cache for RPC queries.
    tx_status_cache: Option<Arc<TokioRwLock<TransactionStatusCache>>>,
    /// Optional mempool snapshot for RPC queries.
    #[allow(dead_code)]
    mempool_snapshot: Option<Arc<TokioRwLock<MempoolSnapshot>>>,

    // ── Genesis ──────────────────────────────────────────────────────────
    /// Optional genesis configuration for initial state.
    genesis_config: Option<hyperscale_engine::GenesisConfig>,

    // ── Caches ───────────────────────────────────────────────────────────
    /// LRU cache of recently received transactions (via gossip or RPC).
    /// Shared with InboundRouter for serving peer fetch requests from memory.
    #[allow(dead_code)] // Kept alive to maintain Arc reference for InboundRouter
    recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
    /// LRU cache of recently built certificates.
    /// Shared with InboundRouter for serving peer fetch requests from memory.
    #[allow(dead_code)]
    recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,

    // ── Shutdown ─────────────────────────────────────────────────────────
    /// Shutdown signal receiver (external shutdown request).
    shutdown_rx: Option<oneshot::Receiver<()>>,
    /// Shutdown handle sender (returned to caller via shutdown_handle()).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ProductionRunner {
    /// Create a new builder for constructing a production runner.
    pub fn builder() -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new()
    }

    /// Get a reference to the dispatch implementation.
    pub fn dispatch(&self) -> &Arc<PooledDispatch> {
        &self.dispatch
    }

    /// Get a reference to the network adapter.
    pub fn network(&self) -> &Arc<Libp2pAdapter> {
        &self.network
    }

    /// Get the local shard ID.
    pub fn local_shard(&self) -> ShardGroupId {
        self.local_shard
    }

    /// Get a crossbeam sender for submitting consensus events.
    ///
    /// Events sent through this sender are forwarded to the pinned NodeLoop
    /// thread via the crossbeam consensus channel.
    pub fn event_sender(&self) -> crossbeam::channel::Sender<Event> {
        self.xb_consensus_tx.clone()
    }

    /// Get a sender for RPC transaction submissions.
    ///
    /// Returns a crossbeam channel sender that feeds directly into the NodeLoop.
    /// RPC handlers wrap transactions in `Event::SubmitTransaction` before sending.
    /// NodeLoop handles gossip, validation, and mempool dispatch.
    pub fn tx_submission_sender(&self) -> crossbeam::channel::Sender<Event> {
        self.xb_consensus_tx.clone()
    }

    /// Take the shutdown handle.
    ///
    /// Returns a handle that when dropped triggers graceful shutdown.
    /// Can only be called once; subsequent calls return None.
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
    /// This MUST be called before the NodeLoop is moved to the pinned thread,
    /// since it needs mutable access to the NodeLoop.
    fn maybe_initialize_genesis(&mut self) -> Vec<TimerOp> {
        let node_loop = self
            .node_loop
            .as_mut()
            .expect("node_loop must exist for genesis");

        // Check if we already have committed blocks
        let height = node_loop.storage().committed_height();
        let has_blocks = height.0 > 0;

        if has_blocks {
            info!("Existing blocks found, skipping genesis initialization");
            return Vec::new();
        }

        info!(
            shard = ?self.local_shard,
            "No committed blocks - initializing genesis"
        );

        // Run Radix Engine genesis to set up initial state.
        // Uses GenesisMutWrapper to bridge RocksDbStorage's &self commit()
        // with the Radix Engine's &mut self CommittableSubstateDatabase trait.
        let genesis_config = self.genesis_config.take();
        let result = node_loop.with_storage_and_executor(|storage, executor| {
            // SharedStorage derefs to &RocksDbStorage.
            let mut wrapper = GenesisMutWrapper(storage);
            if let Some(config) = genesis_config {
                info!(
                    xrd_balances = config.xrd_balances.len(),
                    "Running genesis with custom configuration"
                );
                executor.run_genesis_with_config(&mut wrapper, config)
            } else {
                executor.run_genesis(&mut wrapper)
            }
        });

        if let Err(e) = result {
            panic!("Radix Engine genesis failed: {e:?}");
        }

        // Get the JMT state AFTER genesis bootstrap.
        use hyperscale_storage::SubstateStore;
        let genesis_jmt_version = node_loop.storage().state_version();
        let genesis_jmt_root = node_loop.storage().state_root_hash();

        info!(
            genesis_jmt_version,
            genesis_jmt_root = ?genesis_jmt_root,
            "JMT state after genesis bootstrap"
        );

        // Create genesis block.
        let first_validator = self
            .topology
            .committee_for_shard(self.local_shard)
            .first()
            .copied()
            .unwrap_or(ValidatorId(0));

        let genesis_header = BlockHeader {
            height: BlockHeight(0),
            parent_hash: Hash::from_bytes(&[0u8; 32]),
            parent_qc: QuorumCertificate::genesis(),
            proposer: first_validator,
            timestamp: 0,
            round: 0,
            is_fallback: false,
            state_root: genesis_jmt_root,
            state_version: genesis_jmt_version,
            transaction_root: Hash::ZERO,
        };

        let genesis_block = Block {
            header: genesis_header,
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        };

        let genesis_hash = genesis_block.hash();
        info!(
            genesis_hash = ?genesis_hash,
            proposer = ?first_validator,
            "Created genesis block"
        );

        // Initialize state machine with genesis (this sets up proposal timer).
        let actions = node_loop.state_mut().initialize_genesis(genesis_block);
        info!(num_actions = actions.len(), "Genesis returned actions");

        // Process actions through NodeLoop (timers, etc.).
        node_loop.handle_actions(actions);
        node_loop.flush_all_batches();

        // Drain timer ops from genesis actions (includes ProposalTimer).
        let genesis_output = node_loop.drain_pending_output();
        let mut timer_ops = genesis_output.timer_ops;

        // CRITICAL: Update state machine with the genesis JMT state.
        // The state machine was created BEFORE genesis bootstrap ran, so it has
        // stale/zero state. We need to sync it with the actual JMT state from
        // genesis so future blocks compute state_root from the correct base.
        let genesis_commit_output = node_loop.step(Event::StateCommitComplete {
            height: 0,
            state_version: genesis_jmt_version,
            state_root: genesis_jmt_root,
        });

        info!(
            genesis_jmt_version,
            genesis_jmt_root = ?genesis_jmt_root,
            actions = genesis_commit_output.actions_generated,
            "Updated state machine with genesis JMT state"
        );

        // Collect any additional timer ops from the commit step.
        timer_ops.extend(genesis_commit_output.timer_ops);

        // Flush any batches from the genesis commit step.
        node_loop.flush_all_batches();

        timer_ops
    }

    // ═══════════════════════════════════════════════════════════════════
    // Main Run Loop
    // ═══════════════════════════════════════════════════════════════════

    /// Run the production node.
    ///
    /// 1. Initializes genesis via NodeLoop (before spawning pinned thread)
    /// 2. Extracts the NodeLoop and channel receivers for the pinned thread
    /// 3. Spawns the pinned thread running the NodeLoop event loop
    /// 4. Runs a minimal loop for metrics collection and shutdown handling
    /// 5. On shutdown, signals the pinned thread and joins it
    pub async fn run(mut self) -> Result<(), RunnerError> {
        let config = self.dispatch.config();
        info!(
            shard = ?self.local_shard,
            crypto_threads = config.crypto_threads,
            execution_threads = config.execution_threads,
            io_threads = config.io_threads,
            pin_cores = config.pin_cores,
            "Starting production runner (NodeLoop architecture)"
        );

        // ── 1. Initialize genesis before spawning pinned thread ──────────
        let initial_timer_ops = self.maybe_initialize_genesis();

        // ── 2. Extract NodeLoop and channel receivers for pinned thread ───
        let node_loop = self
            .node_loop
            .take()
            .expect("node_loop already taken (run called twice?)");

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
            tx_status_cache: self.tx_status_cache.clone(),
            tokio_handle: tokio::runtime::Handle::current(),
            initial_timer_ops,
        };

        // ── 3. Spawn pinned thread ───────────────────────────────────────
        let loop_handle = spawn_pinned_loop(node_loop, pinned_config);

        // ── 4. Metrics + shutdown loop ───────────────────────────────────
        let mut metrics_tick = tokio::time::interval(Duration::from_secs(1));
        metrics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
        metrics::set_pool_queue_depths(
            self.dispatch.consensus_crypto_queue_depth(),
            self.dispatch.crypto_queue_depth(),
            self.dispatch.tx_validation_queue_depth(),
            self.dispatch.execution_queue_depth(),
        );

        // ── Peer count ───────────────────────────────────────────────────
        let peer_count = self.network.cached_peer_count();
        metrics::set_libp2p_peers(peer_count);

        // ── Update RPC status with peer count ────────────────────────────
        if let Some(ref rpc_status) = self.rpc_status {
            if let Ok(mut status) = rpc_status.try_write() {
                status.connected_peers = peer_count;
            }
        }
    }
}
