//! Production runner implementation.

use crate::action_dispatcher::{
    spawn_action_dispatcher, ActionDispatcherContext, ActionDispatcherHandle, DispatchableAction,
};
use crate::fetch_handler::{spawn_fetch_handler, FetchHandlerConfig, FetchHandlerHandle};
use crate::network::{
    compute_peer_id_for_validator, InboundSyncRequest, Libp2pAdapter, Libp2pConfig, NetworkError,
};
use crate::rpc::{MempoolSnapshot, NodeStatusState, TransactionStatusCache};
use crate::storage::RocksDbStorage;
use crate::sync::{SyncConfig, SyncManager};
use crate::thread_pools::ThreadPoolManager;
use crate::timers::TimerManager;
use hyperscale_bft::BftConfig;
use hyperscale_engine::{NetworkDefinition, RadixExecutor};
use hyperscale_mempool::MempoolConfig;
use hyperscale_types::BlockHeight;

use hyperscale_core::{Action, Event, OutboundMessage, StateMachine};
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    Block, BlockHeader, BlockMetadata, BlockVote, CommitmentProof, Hash, KeyPair, PublicKey,
    QuorumCertificate, RoutableTransaction, ShardGroupId, Signature, SignerBitfield,
    StateVoteBlock, Topology, TransactionCertificate, ValidatorId,
};
use libp2p::identity;
use sbor::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock as TokioRwLock;
use tokio::sync::{mpsc, oneshot};
use tracing::{span, Level};

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

/// Maximum batch sizes for time-windowed operations.
/// These limits cap p99 latency by preventing unbounded batch growth under load.
/// Values are tuned to balance throughput (larger batches = better amortization)
/// against latency (smaller batches = faster completion).
mod batch_limits {
    /// Block votes: consensus-critical, lighter preprocessing. 128 matches ValidationBatcher.
    pub const MAX_BLOCK_VOTES: usize = 128;
    /// State votes: same crypto pattern as block votes, 20ms window needs tighter cap.
    pub const MAX_STATE_VOTES: usize = 64;
    /// State certs: parallel key aggregation benefits from ~core-count batches.
    pub const MAX_STATE_CERTS: usize = 64;
    /// Cross-shard execution: heavy per-item work, memory pressure from provisions.
    pub const MAX_CROSS_SHARD_EXECUTIONS: usize = 32;
}

/// Pending block vote verifications that can be batched.
///
/// Collects verification actions and processes them together using
/// batch verification for better performance (2-8x speedup for large batches).
///
/// Note: State votes are batched separately with a longer window (20ms vs 5ms)
/// since they are less latency-sensitive than consensus block votes.
#[derive(Default)]
struct PendingBlockVotes {
    /// Block votes waiting for verification (public key and signing message included).
    votes: Vec<(BlockVote, PublicKey, Vec<u8>)>,
}

impl PendingBlockVotes {
    fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    fn len(&self) -> usize {
        self.votes.len()
    }

    fn is_full(&self) -> bool {
        self.votes.len() >= batch_limits::MAX_BLOCK_VOTES
    }
}

/// Pending state vote verifications with a longer batching window.
///
/// State votes (cross-shard execution) are less latency-sensitive than block votes,
/// so we use a longer batching window (20ms) to accumulate more signatures and
/// get better batch verification throughput.
#[derive(Default)]
struct PendingStateVotes {
    /// State votes waiting for verification.
    votes: Vec<(StateVoteBlock, PublicKey)>,
}

impl PendingStateVotes {
    fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    fn take(&mut self) -> Vec<(StateVoteBlock, PublicKey)> {
        std::mem::take(&mut self.votes)
    }

    fn is_full(&self) -> bool {
        self.votes.len() >= batch_limits::MAX_STATE_VOTES
    }
}

/// Pending cross-shard executions that can be batched.
///
/// Accumulates ExecuteCrossShardTransaction actions and executes them in parallel
/// using rayon's par_iter for better throughput.
#[derive(Default)]
struct PendingCrossShardExecutions {
    /// Cross-shard transactions waiting for execution.
    requests: Vec<hyperscale_core::CrossShardExecutionRequest>,
}

impl PendingCrossShardExecutions {
    fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    fn take(&mut self) -> Vec<hyperscale_core::CrossShardExecutionRequest> {
        std::mem::take(&mut self.requests)
    }

    fn is_full(&self) -> bool {
        self.requests.len() >= batch_limits::MAX_CROSS_SHARD_EXECUTIONS
    }
}

/// Pending state certificate verifications with batching window.
///
/// State certificates have aggregated BLS signatures that are expensive to verify
/// (~1.5ms each). By batching them with a 15ms window, we can use BLS batch
/// verification which is ~40% faster than individual verification.
#[derive(Default)]
struct PendingStateCerts {
    /// State certificates waiting for verification.
    /// Each entry contains: (certificate, public_keys for the shard)
    certs: Vec<(hyperscale_types::StateCertificate, Vec<PublicKey>)>,
}

impl PendingStateCerts {
    fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    fn take(&mut self) -> Vec<(hyperscale_types::StateCertificate, Vec<PublicKey>)> {
        std::mem::take(&mut self.certs)
    }

    fn is_full(&self) -> bool {
        self.certs.len() >= batch_limits::MAX_STATE_CERTS
    }
}

/// Pending verification of a gossiped TransactionCertificate.
///
/// When we receive a TransactionCertificate via gossip, we verify each embedded
/// StateCertificate's BLS signature before persisting. This tracks the verification
/// progress for a single certificate.
struct PendingGossipCertVerification {
    /// The certificate being verified.
    certificate: TransactionCertificate,
    /// Shards still awaiting verification callback.
    pending_shards: std::collections::HashSet<ShardGroupId>,
    /// Whether any verification has failed.
    failed: bool,
    /// When this verification started (for TTL cleanup).
    created_at: std::time::Instant,
}

/// Maximum age for pending gossip certificate verifications before cleanup.
/// If verification callbacks don't arrive within this time, the entry is removed.
/// This is short (30s) since verification should complete in milliseconds.
const PENDING_GOSSIP_CERT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum age for RPC-submitted transaction tracking before cleanup.
/// If a transaction doesn't finalize within this time, it's removed from tracking
/// to prevent unbounded memory growth. This is generous (10 minutes) to allow
/// for slow cross-shard transactions.
const RPC_SUBMITTED_TX_TIMEOUT: Duration = Duration::from_secs(600);

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
/// - `thread_pools` - Thread pool manager (defaults to auto-configured)
/// - `channel_capacity` - Event channel capacity (defaults to 10,000)
///
/// # Example
///
/// ```no_run
/// use hyperscale_production::{ProductionRunner, Libp2pConfig, RocksDbStorage, RocksDbConfig};
/// use hyperscale_bft::BftConfig;
/// use hyperscale_types::KeyPair;
/// use libp2p::identity;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create required dependencies
/// let topology = todo!("Create topology from genesis or config");
/// let signing_key = KeyPair::generate_bls();
/// let bft_config = BftConfig::default();
/// let storage = RocksDbStorage::open_with_config(
///     "/tmp/hyperscale-db",
///     RocksDbConfig::default(),
/// )?;
/// let network_config = Libp2pConfig::default();
/// let ed25519_keypair = identity::Keypair::generate_ed25519();
///
/// // Build the runner
/// let runner = ProductionRunner::builder()
///     .topology(topology)
///     .signing_key(signing_key)
///     .bft_config(bft_config)
///     .storage(Arc::new(storage))
///     .network(network_config, ed25519_keypair)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct ProductionRunnerBuilder {
    topology: Option<Arc<dyn Topology>>,
    signing_key: Option<KeyPair>,
    bft_config: Option<BftConfig>,
    thread_pools: Option<Arc<ThreadPoolManager>>,
    storage: Option<Arc<RocksDbStorage>>,
    network_config: Option<Libp2pConfig>,
    ed25519_keypair: Option<identity::Keypair>,
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
            thread_pools: None,
            storage: None,
            network_config: None,
            ed25519_keypair: None,
            channel_capacity: 10_000,
            rpc_status: None,
            tx_status_cache: None,
            mempool_snapshot: None,
            genesis_config: None,
            network_definition: None,
            speculative_max_txs: 500, // Default, matches hyperscale_execution::DEFAULT_SPECULATIVE_MAX_TXS
            view_change_cooldown_rounds: 3, // Default, matches hyperscale_execution::DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS
        }
    }

    /// Set the Radix network definition for transaction validation.
    ///
    /// This determines which network's transaction format to validate against.
    /// Defaults to simulator network if not set.
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
    pub fn signing_key(mut self, key: KeyPair) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set the BFT consensus configuration.
    pub fn bft_config(mut self, config: BftConfig) -> Self {
        self.bft_config = Some(config);
        self
    }

    /// Set the thread pool manager (optional, defaults to auto-configured pools).
    pub fn thread_pools(mut self, pools: Arc<ThreadPoolManager>) -> Self {
        self.thread_pools = Some(pools);
        self
    }

    /// Set the RocksDB storage for persistence and crash recovery.
    ///
    /// RocksDB is internally thread-safe, so no external lock is needed.
    pub fn storage(mut self, storage: Arc<RocksDbStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the network configuration and Ed25519 keypair for libp2p.
    pub fn network(mut self, config: Libp2pConfig, keypair: identity::Keypair) -> Self {
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
    ///
    /// Higher values allow more aggressive speculation but use more memory.
    /// Default: 500
    pub fn speculative_max_txs(mut self, max_txs: usize) -> Self {
        self.speculative_max_txs = max_txs;
        self
    }

    /// Set the number of rounds to pause speculation after a view change.
    ///
    /// Higher values reduce wasted work during instability but may reduce hit rate.
    /// Default: 3
    pub fn view_change_cooldown_rounds(mut self, rounds: u64) -> Self {
        self.view_change_cooldown_rounds = rounds;
        self
    }

    /// Set the RPC status state to update on block commits and view changes.
    ///
    /// When set, the runner will update `block_height`, `view`, and `connected_peers`
    /// fields as consensus progresses.
    pub fn rpc_status(mut self, status: Arc<TokioRwLock<NodeStatusState>>) -> Self {
        self.rpc_status = Some(status);
        self
    }

    /// Set the transaction status cache for RPC queries.
    ///
    /// When set, the runner will update transaction statuses as they progress
    /// through the mempool and execution pipeline.
    pub fn tx_status_cache(mut self, cache: Arc<TokioRwLock<TransactionStatusCache>>) -> Self {
        self.tx_status_cache = Some(cache);
        self
    }

    /// Set the mempool snapshot for RPC queries.
    ///
    /// When set, the runner will periodically update mempool statistics.
    pub fn mempool_snapshot(mut self, snapshot: Arc<TokioRwLock<MempoolSnapshot>>) -> Self {
        self.mempool_snapshot = Some(snapshot);
        self
    }

    /// Set the genesis configuration for initial state.
    ///
    /// When set, the runner will use this configuration to bootstrap the Radix Engine
    /// state with initial XRD balances and other genesis parameters.
    pub fn genesis_config(mut self, config: hyperscale_engine::GenesisConfig) -> Self {
        self.genesis_config = Some(config);
        self
    }

    /// Build the production runner.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing or if network setup fails.
    pub async fn build(self) -> Result<ProductionRunner, RunnerError> {
        // Extract required fields
        let topology = self
            .topology
            .ok_or_else(|| RunnerError::SendError("topology is required".into()))?;
        let signing_key = self
            .signing_key
            .ok_or_else(|| RunnerError::SendError("signing_key is required".into()))?;
        let bft_config = self
            .bft_config
            .ok_or_else(|| RunnerError::SendError("bft_config is required".into()))?;
        let thread_pools = match self.thread_pools {
            Some(pools) => pools,
            None => Arc::new(
                ThreadPoolManager::auto().map_err(|e| RunnerError::SendError(e.to_string()))?,
            ),
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

        // Separate channels for different event priorities:
        // - timer_tx/rx: Critical priority - Timer events (proposal, cleanup)
        //   These MUST never be blocked by network floods. Small dedicated channel.
        // - callback_tx/rx: Highest priority - Internal events (crypto/execution callbacks)
        //   These are results of in-flight work and must be processed immediately to
        //   unblock consensus progress (e.g., vote signature verified -> can count vote)
        // - consensus_tx/rx: High priority BFT events (votes, proposals, QCs)
        // - validated_tx_tx/rx: Validated transactions from batcher (unbounded - don't block crypto pool)
        //   Gossip-received transactions flow through here after validation
        // - rpc_tx_tx/rx: RPC-submitted transactions (unbounded - don't block RPC handlers)
        //   These need gossip before validation, unlike gossip-received transactions
        // - status_tx/rx: Transaction status updates (non-consensus-critical)
        // This prevents transaction floods from starving consensus events
        let (timer_tx, timer_rx) = mpsc::channel(16); // Small channel, just for timers
        let (callback_tx, callback_rx) = mpsc::unbounded_channel(); // Unbounded - thread pools must never block
        let (consensus_tx, consensus_rx) = mpsc::channel(self.channel_capacity);
        let (validated_tx_tx, validated_tx_rx) = mpsc::unbounded_channel(); // Unbounded - batcher must never block
        let (rpc_tx_tx, rpc_tx_rx) = mpsc::unbounded_channel(); // Unbounded - RPC must never block
        let (status_tx, status_rx) = mpsc::channel(self.channel_capacity);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let validator_id = topology.local_validator_id();
        let local_shard = topology.local_shard();

        // Load RecoveredState from storage for crash recovery
        let recovered = storage.load_recovered_state();

        // Clone signing key for runner's state vote signing (state machine also needs it)
        let runner_signing_key = signing_key.clone();

        // NodeIndex is a simulation concept - production uses 0
        let state = NodeStateMachine::with_speculative_config(
            0, // node_index not meaningful in production
            topology.clone(),
            signing_key,
            bft_config,
            recovered,
            self.speculative_max_txs,
            self.view_change_cooldown_rounds,
            MempoolConfig::default(),
        );
        let timer_manager = TimerManager::new(timer_tx);

        // Use configured network definition or default to simulator
        let network_definition = self
            .network_definition
            .unwrap_or_else(NetworkDefinition::simulator);

        // Create transaction validator for signature verification
        let tx_validator = Arc::new(hyperscale_engine::TransactionValidation::new(
            network_definition.clone(),
        ));

        // Create the shared transaction validation batcher
        // This is used by both network gossip and RPC submissions for:
        // 1. Deduplication - skip already-seen transactions
        // 2. Batching - collect transactions over time window for parallel validation
        // Output goes to validated_tx_tx (unbounded) to avoid blocking crypto pool threads
        let tx_validation_handle = crate::validation_batcher::spawn_tx_validation_batcher(
            crate::validation_batcher::ValidationBatcherConfig::default(),
            tx_validator.clone(),
            thread_pools.clone(),
            validated_tx_tx,
        );

        // Create network adapter with shared transaction validation batcher
        let (network, sync_request_rx, tx_request_rx, cert_request_rx) = Libp2pAdapter::new(
            network_config,
            ed25519_keypair,
            validator_id,
            local_shard,
            consensus_tx.clone(),
            tx_validation_handle.clone(),
        )
        .await?;

        // Subscribe to local shard topics
        network.subscribe_shard(local_shard).await?;

        // Register known validators for peer validation
        // This allows us to validate that messages come from known validators.
        // We register ALL validators from the global validator set because:
        // 1. Cross-shard transactions are gossiped between shards
        // 2. Validators may receive messages forwarded from other shards
        // Note: We use global_validator_set() instead of committee_for_shard() because
        // StaticTopology::with_local_shard() only populates the local shard's committee.
        for validator in &topology.global_validator_set().validators {
            let peer_id = compute_peer_id_for_validator(&validator.public_key);
            network
                .register_validator(validator.validator_id, peer_id)
                .await;
        }

        // Create sync manager (uses consensus channel for sync events)
        // The topology is passed directly - SyncManager queries it for committee members
        let sync_manager = SyncManager::new(
            SyncConfig::default(),
            network.clone(),
            storage.clone(),
            consensus_tx.clone(),
            topology.clone(),
        );

        // Create fetch manager for transactions and certificates
        let mut fetch_manager = crate::fetch::FetchManager::new(
            crate::fetch::FetchConfig::default(),
            network.clone(),
            storage.clone(),
            consensus_tx.clone(),
        );

        // Register local committee members with fetch manager (excluding self)
        // (fetch only happens within shard, so we only need local committee)
        for &vid in topology.committee_for_shard(local_shard).iter() {
            // Don't register self - we can't fetch from ourselves
            if vid == validator_id {
                continue;
            }
            if let Some(pk) = topology.public_key(vid) {
                let peer_id = compute_peer_id_for_validator(&pk);
                fetch_manager.register_committee_member(vid, peer_id);
            }
        }

        // Create executor
        let executor = Arc::new(RadixExecutor::new(network_definition));

        // Create message batcher for execution layer messages
        // This batches state votes, certificates, and provisions to reduce network overhead
        let message_batcher = crate::message_batcher::spawn_message_batcher(
            crate::message_batcher::MessageBatcherConfig::default(),
            network.clone(),
        );

        // Spawn dedicated fetch handler task.
        // This handles all inbound fetch requests (transactions/certificates) by
        // reading directly from RocksDB storage. Hot data is served from RocksDB's
        // block cache for performance.
        let fetch_handler = spawn_fetch_handler(
            FetchHandlerConfig::default(),
            storage.clone(),
            network.clone(),
            tx_request_rx,
            cert_request_rx,
        );

        // Spawn action dispatcher task for fire-and-forget network I/O.
        // Network broadcasts are moved off the event loop to prevent blocking.
        let action_dispatcher = spawn_action_dispatcher(ActionDispatcherContext {
            network: network.clone(),
            message_batcher: message_batcher.clone(),
        });
        let dispatch_tx = action_dispatcher.tx.clone();

        Ok(ProductionRunner {
            timer_rx,
            callback_rx,
            callback_tx,
            consensus_rx,
            consensus_tx,
            validated_tx_rx,
            rpc_tx_rx,
            rpc_tx_tx,
            status_rx,
            status_tx,
            state,
            start_time: Instant::now(),
            epoch_start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before UNIX epoch"),
            thread_pools,
            timer_manager,
            network,
            sync_manager,
            fetch_manager,
            local_shard,
            topology,
            storage,
            executor,
            tx_validator,
            tx_validation_handle,
            rpc_status: self.rpc_status,
            tx_status_cache: self.tx_status_cache,
            mempool_snapshot: self.mempool_snapshot,
            genesis_config: self.genesis_config,
            sync_request_rx,
            shutdown_rx,
            shutdown_tx: Some(shutdown_tx),
            pending_state_votes: PendingStateVotes::default(),
            state_vote_deadline: None,
            pending_cross_shard_executions: PendingCrossShardExecutions::default(),
            cross_shard_execution_deadline: None,
            pending_state_certs: PendingStateCerts::default(),
            state_cert_deadline: None,
            signing_key: runner_signing_key,
            message_batcher,
            fetch_handler,
            dispatch_tx,
            action_dispatcher,
            rpc_submitted_txs: std::collections::HashMap::new(),
            pending_gossip_cert_verifications: std::collections::HashMap::new(),
        })
    }
}

/// Production runner with async I/O.
///
/// Uses the event aggregator pattern: a single task owns the state machine
/// and receives events via an mpsc channel.
///
/// # Thread Pool Configuration
///
/// The runner uses configurable thread pools for different workloads:
/// - **Crypto Pool**: BLS signature verification (CPU-bound)
/// - **Execution Pool**: Transaction execution via Radix Engine (CPU/memory)
/// - **I/O Pool**: Network, storage, timers (tokio runtime)
///
/// Use [`ProductionRunner::builder()`] to construct a runner with all required
/// dependencies.
pub struct ProductionRunner {
    /// Receives critical-priority timer events (proposal, cleanup).
    /// Dedicated channel ensures timers are never blocked by network floods.
    timer_rx: mpsc::Receiver<Event>,
    /// Receives highest-priority callback events (crypto verification, execution results).
    /// These are Internal priority events that unblock in-flight consensus work.
    /// Unbounded channel ensures thread pools never block waiting to send results.
    callback_rx: mpsc::UnboundedReceiver<Event>,
    /// Clone this to send callback events from crypto/execution thread pools.
    /// Unbounded to prevent thread pool deadlocks - backpressure should be at work dispatch, not result return.
    callback_tx: mpsc::UnboundedSender<Event>,
    /// Receives high-priority consensus events (BFT network messages).
    consensus_rx: mpsc::Receiver<Event>,
    /// Clone this to send consensus events from network.
    consensus_tx: mpsc::Sender<Event>,
    /// Receives validated transactions from the batcher (unbounded to avoid blocking crypto pool).
    /// Gossip-received transactions flow through here after validation.
    validated_tx_rx: mpsc::UnboundedReceiver<Event>,
    /// Receives RPC-submitted transactions (unbounded to avoid blocking RPC handlers).
    /// These need to be gossiped before validation, unlike gossip-received transactions.
    rpc_tx_rx: mpsc::UnboundedReceiver<Arc<RoutableTransaction>>,
    /// Sender for RPC transaction submissions - exposed via tx_submission_sender().
    rpc_tx_tx: mpsc::UnboundedSender<Arc<RoutableTransaction>>,
    /// Receives background status events (TransactionStatusChanged, TransactionExecuted).
    /// These are non-consensus-critical and processed opportunistically.
    status_rx: mpsc::Receiver<Event>,
    /// Clone this to send status events.
    status_tx: mpsc::Sender<Event>,
    /// The state machine (owned, not shared).
    state: NodeStateMachine,
    /// Start time for uptime calculation (node-local, not used for consensus timestamps).
    start_time: Instant,
    /// Unix epoch time when the node started, for wall-clock time calculation.
    /// This is used for consensus timestamps to ensure nodes agree on time even if
    /// they start at different moments.
    epoch_start_time: Duration,
    /// Thread pool manager for crypto and execution workloads.
    thread_pools: Arc<ThreadPoolManager>,
    /// Timer manager for setting/cancelling timers.
    timer_manager: TimerManager,
    /// Network adapter for libp2p communication.
    network: Arc<Libp2pAdapter>,
    /// Sync manager for fetching blocks from peers.
    sync_manager: SyncManager,
    /// Fetch manager for fetching transactions and certificates from peers.
    fetch_manager: crate::fetch::FetchManager,
    /// Local shard for network broadcasts.
    local_shard: ShardGroupId,
    /// Network topology (needed for cross-shard execution).
    topology: Arc<dyn Topology>,
    /// Block storage for persistence and crash recovery.
    /// RocksDB is internally thread-safe, so no external lock is needed.
    storage: Arc<RocksDbStorage>,
    /// Transaction executor.
    executor: Arc<RadixExecutor>,
    /// Transaction validator for signature verification.
    tx_validator: Arc<hyperscale_engine::TransactionValidation>,
    /// Handle for the shared transaction validation batcher.
    /// Used by both network gossip and RPC for dedup + batched validation.
    tx_validation_handle: crate::validation_batcher::ValidationBatcherHandle,
    /// Optional RPC status state to update on block commits.
    rpc_status: Option<Arc<TokioRwLock<NodeStatusState>>>,
    /// Optional transaction status cache for RPC queries.
    tx_status_cache: Option<Arc<TokioRwLock<TransactionStatusCache>>>,
    /// Optional mempool snapshot for RPC queries.
    mempool_snapshot: Option<Arc<TokioRwLock<MempoolSnapshot>>>,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<hyperscale_engine::GenesisConfig>,
    /// Inbound sync request channel (from network adapter).
    sync_request_rx: mpsc::UnboundedReceiver<InboundSyncRequest>,
    /// Shutdown signal receiver.
    shutdown_rx: oneshot::Receiver<()>,
    /// Shutdown handle sender (stored to return to caller).
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Pending state votes accumulated for batch verification.
    /// State votes use a longer batching window (20ms) than block votes (5ms).
    pending_state_votes: PendingStateVotes,
    /// Deadline for flushing pending state votes. None if no votes pending.
    state_vote_deadline: Option<tokio::time::Instant>,
    /// Pending cross-shard executions accumulated for batch parallel execution.
    /// Uses a short batching window (5ms) to balance latency vs throughput.
    pending_cross_shard_executions: PendingCrossShardExecutions,
    /// Deadline for flushing pending cross-shard executions. None if none pending.
    cross_shard_execution_deadline: Option<tokio::time::Instant>,
    /// Pending state certificates accumulated for batch signature verification.
    /// Uses a 15ms batching window - state certs are the highest volume crypto operation.
    pending_state_certs: PendingStateCerts,
    /// Deadline for flushing pending state certificates. None if none pending.
    state_cert_deadline: Option<tokio::time::Instant>,
    /// Signing key for state vote signing (cloned from state machine).
    signing_key: KeyPair,
    /// Message batcher for execution layer messages (votes, certificates, provisions).
    /// Accumulates items and flushes periodically to reduce network overhead.
    /// Note: Now primarily used by action dispatcher, kept here for direct access if needed.
    #[allow(dead_code)]
    message_batcher: crate::message_batcher::MessageBatcherHandle,
    /// Handle for the dedicated fetch handler task.
    /// Processes inbound fetch requests from other validators.
    #[allow(dead_code)]
    fetch_handler: FetchHandlerHandle,
    /// Sender for dispatching fire-and-forget actions to the action dispatcher task.
    /// Network broadcasts, timer management, and non-critical writes go through this.
    /// Unbounded to prevent dropping critical consensus messages under load.
    dispatch_tx: mpsc::UnboundedSender<DispatchableAction>,
    /// Handle for the dedicated action dispatcher task.
    #[allow(dead_code)]
    action_dispatcher: ActionDispatcherHandle,
    /// Transaction hashes that were submitted via RPC (locally) with submission time.
    /// Used to track which transactions should contribute to latency metrics.
    /// Transactions are added when received via RPC, removed when finalized.
    /// Old entries are cleaned up periodically to prevent unbounded growth.
    rpc_submitted_txs: std::collections::HashMap<hyperscale_types::Hash, std::time::Instant>,
    /// Pending verifications for gossiped TransactionCertificates.
    /// Maps tx_hash -> verification state. When all shards verified, certificate is
    /// persisted and GossipedCertificateVerified event sent to state machine.
    pending_gossip_cert_verifications:
        std::collections::HashMap<Hash, PendingGossipCertVerification>,
}

impl ProductionRunner {
    /// Create a new builder for constructing a production runner.
    ///
    /// All fields are required - see [`ProductionRunnerBuilder`] for details.
    pub fn builder() -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new()
    }

    /// Get wall-clock time as a Duration since UNIX epoch.
    ///
    /// This uses the system clock to ensure all nodes agree on timestamps,
    /// regardless of when they started. This is critical for BFT timestamp
    /// validation which checks that proposer timestamps are within acceptable
    /// bounds of the validator's local time.
    fn wall_clock_time(&self) -> Duration {
        // Use cached epoch_start_time + elapsed for better monotonicity within a session,
        // while still being based on wall-clock time across nodes.
        self.epoch_start_time + self.start_time.elapsed()
    }

    /// Get a reference to the thread pool manager.
    pub fn thread_pools(&self) -> &Arc<ThreadPoolManager> {
        &self.thread_pools
    }

    /// Get a reference to the network adapter.
    pub fn network(&self) -> &Arc<Libp2pAdapter> {
        &self.network
    }

    /// Get the local shard ID.
    pub fn local_shard(&self) -> ShardGroupId {
        self.local_shard
    }

    /// Get a sender for submitting consensus events.
    ///
    /// This is the high-priority channel for BFT messages.
    /// For transaction submission, use `transaction_sender()` instead.
    pub fn event_sender(&self) -> mpsc::Sender<Event> {
        self.consensus_tx.clone()
    }

    /// Get the transaction validator for signature verification.
    pub fn tx_validator(&self) -> Arc<hyperscale_engine::TransactionValidation> {
        self.tx_validator.clone()
    }

    /// Get a sender for RPC transaction submissions.
    ///
    /// Transactions submitted through this channel will be:
    /// 1. Gossiped to all relevant shards (RPC submissions need gossip)
    /// 2. Validated via the shared batcher
    /// 3. Dispatched to the mempool
    ///
    /// This is the correct path for RPC-submitted transactions.
    /// Network gossip uses the validation batcher directly (no gossip needed).
    pub fn tx_submission_sender(&self) -> mpsc::UnboundedSender<Arc<RoutableTransaction>> {
        self.rpc_tx_tx.clone()
    }

    /// Get the transaction validation batcher handle.
    ///
    /// This handle is used by network gossip for dedup + batched validation.
    /// RPC submissions should use `tx_submission_sender()` instead, which
    /// handles gossip before validation.
    pub fn tx_validation_handle(&self) -> crate::validation_batcher::ValidationBatcherHandle {
        self.tx_validation_handle.clone()
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

    /// Get a mutable reference to the sync manager.
    pub fn sync_manager_mut(&mut self) -> &mut SyncManager {
        &mut self.sync_manager
    }

    /// Check if sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.sync_manager.is_syncing()
    }

    /// Initialize genesis if this is a fresh start.
    ///
    /// Checks if we have any committed blocks. If not, creates a genesis block
    /// and initializes the state machine, which sets up the initial proposal timer.
    fn maybe_initialize_genesis(&mut self) {
        // Check if we already have committed blocks
        let (height, _, _) = self.storage.get_chain_metadata();
        let has_blocks = height.0 > 0;

        if has_blocks {
            tracing::info!("Existing blocks found, skipping genesis initialization");
            return;
        }

        tracing::info!(
            shard = ?self.local_shard,
            "No committed blocks - initializing genesis"
        );

        // Run Radix Engine genesis to set up initial state
        // SAFETY: RocksDB is internally thread-safe. We use unsafe to get &mut
        // because the CommittableSubstateDatabase trait requires it, but RocksDB
        // doesn't actually need exclusive access.
        let result = unsafe {
            let storage_mut = self.storage.as_mut();
            if let Some(config) = self.genesis_config.take() {
                tracing::info!(
                    xrd_balances = config.xrd_balances.len(),
                    "Running genesis with custom configuration"
                );
                self.executor.run_genesis_with_config(storage_mut, config)
            } else {
                self.executor.run_genesis(storage_mut)
            }
        };
        if let Err(e) = result {
            tracing::warn!(error = ?e, "Radix Engine genesis failed (may be OK for testing)");
        }

        // Create genesis block
        // The first validator in the committee is the proposer for genesis
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
        };

        let genesis_block = Block {
            header: genesis_header,
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        };

        let genesis_hash = genesis_block.hash();
        tracing::info!(
            genesis_hash = ?genesis_hash,
            proposer = ?first_validator,
            "Created genesis block"
        );

        // Initialize state machine with genesis (this sets up proposal timer)
        let actions = self.state.initialize_genesis(genesis_block);

        tracing::info!(num_actions = actions.len(), "Genesis returned actions");

        // Process the actions (should be SetTimer for proposal)
        for action in actions {
            self.process_action_sync(action);
        }
    }

    /// Process an action synchronously (for genesis initialization).
    fn process_action_sync(&mut self, action: Action) {
        match action {
            Action::SetTimer { id, duration } => {
                tracing::info!(timer_id = ?id, duration_ms = ?duration.as_millis(), "Setting timer from genesis");
                self.timer_manager.set_timer(id, duration);
            }
            Action::CancelTimer { id } => {
                self.timer_manager.cancel_timer(id);
            }
            _ => {
                tracing::debug!(action = ?action, "Ignoring action during genesis init");
            }
        }
    }

    /// Run the main event loop.
    ///
    /// This should be spawned as a task. It runs until the event channel closes.
    ///
    /// The state machine runs on the current thread (the caller should ensure
    /// this is pinned to a dedicated core if desired). Crypto and execution
    /// work is dispatched to the configured thread pools.
    ///
    /// # Priority Handling
    ///
    /// Uses `biased` select for priority ordering - higher priority channels
    /// are always checked first, but all channels get processed when ready.
    pub async fn run(mut self) -> Result<(), RunnerError> {
        let config = self.thread_pools.config();
        tracing::info!(
            node_index = self.state.node_index(),
            shard = ?self.state.shard(),
            crypto_threads = config.crypto_threads,
            execution_threads = config.execution_threads,
            io_threads = config.io_threads,
            pin_cores = config.pin_cores,
            "Starting production runner"
        );

        // Initialize genesis if this is a fresh start (no committed blocks)
        self.maybe_initialize_genesis();

        // Sync tick interval (100ms)
        let mut sync_tick = tokio::time::interval(Duration::from_millis(100));
        sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Metrics tick interval (1 second)
        let mut metrics_tick = tokio::time::interval(Duration::from_secs(1));
        metrics_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            // Use biased select for priority ordering:
            // 1. Shutdown (always first)
            // 2. Timers (Critical priority - dedicated channel, never blocked by network)
            // 3. Callbacks (Internal priority - crypto/execution results that unblock our consensus)
            // 4. Consensus (Network priority - BFT messages from network)
            // 5. Transactions (Client priority - submissions, gossip)
            // 6. Sync requests (background)
            // 7. Status events (non-critical)
            // 8. Ticks (periodic maintenance)
            //
            // NOTE: Fetch requests (cert/tx) are now handled by a dedicated fetch handler task
            // that reads from SharedReadState with lock-free DashMap lookups. This achieves
            // P99 < 10ms response times without blocking the main event loop.
            tokio::select! {
                biased;

                // SHUTDOWN: Always check shutdown first (highest priority)
                _ = &mut self.shutdown_rx => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // METRICS: Check early to avoid starvation under load (non-blocking, fast)
                _ = metrics_tick.tick() => {
                    // Update thread pool queue depths (non-blocking)
                    crate::metrics::set_pool_queue_depths(
                        self.thread_pools.consensus_crypto_queue_depth(),
                        self.thread_pools.crypto_queue_depth(),
                        self.thread_pools.tx_validation_queue_depth(),
                        self.thread_pools.execution_queue_depth(),
                    );

                    // Update event channel depths (non-blocking)
                    // Note: tx_request and cert_request channels are now owned by fetch handler task
                    crate::metrics::set_channel_depths(&crate::metrics::ChannelDepths {
                        callback: self.callback_rx.len(),
                        consensus: self.consensus_rx.len(),
                        validated_tx: self.validated_tx_rx.len(),
                        rpc_tx: self.rpc_tx_rx.len(),
                        status: self.status_rx.len(),
                        sync_request: self.sync_request_rx.len(),
                        tx_request: 0, // Handled by dedicated fetch handler task
                        cert_request: 0, // Handled by dedicated fetch handler task
                    });

                    // Update sync status (non-blocking)
                    crate::metrics::set_sync_status(
                        self.sync_manager.blocks_behind(),
                        self.sync_manager.is_syncing(),
                    );

                    // Update fetch status (non-blocking)
                    let fetch_status = self.fetch_manager.status();
                    crate::metrics::set_fetch_in_flight(fetch_status.in_flight_requests);

                    // Update peer count using cached value (non-blocking)
                    let peer_count = self.network.cached_peer_count();
                    crate::metrics::set_libp2p_peers(peer_count);

                    // Update RPC status with peer count (non-blocking: skip if contended)
                    if let Some(ref rpc_status) = self.rpc_status {
                        if let Ok(mut status) = rpc_status.try_write() {
                            status.connected_peers = peer_count;
                        }
                    }

                    // Update BFT metrics (view changes, round)
                    let bft_stats = self.state.bft().stats();
                    crate::metrics::set_bft_stats(&bft_stats);

                    // Update speculative execution metrics
                    let (started, hits, late_hits, misses, invalidated) =
                        self.state.execution_mut().take_speculative_metrics();
                    if started > 0 {
                        crate::metrics::record_speculative_execution_started(started);
                    }
                    for _ in 0..hits {
                        crate::metrics::record_speculative_execution_cache_hit();
                    }
                    for _ in 0..late_hits {
                        crate::metrics::record_speculative_execution_late_hit();
                    }
                    for _ in 0..misses {
                        crate::metrics::record_speculative_execution_cache_miss();
                    }
                    for _ in 0..invalidated {
                        crate::metrics::record_speculative_execution_invalidated();
                    }

                    // Update mempool snapshot for RPC queries (non-blocking: skip if contended)
                    if let Some(ref snapshot) = self.mempool_snapshot {
                        let mempool = self.state.mempool();
                        let stats = mempool.lock_contention_stats();
                        let total = mempool.len();

                        // RPC back-pressure: reject when hard-limit is reached
                        let accepting = !mempool.at_in_flight_hard_limit();

                        // Update Prometheus metrics
                        crate::metrics::set_mempool_size(total);
                        crate::metrics::set_lock_contention_from_stats(&stats);

                        // Backpressure metrics - use mempool's view of in-flight TXs
                        let in_flight = mempool.in_flight();
                        crate::metrics::set_in_flight(in_flight);
                        crate::metrics::set_backpressure_active(mempool.at_in_flight_limit());

                        if let Ok(mut snap) = snapshot.try_write() {
                            snap.pending_count = stats.pending_count as usize;
                            snap.committed_count = stats.committed_count as usize;
                            snap.executed_count = stats.executed_count as usize;
                            snap.blocked_count = stats.blocked_count as usize;
                            snap.total_count = total;
                            snap.updated_at = Some(std::time::Instant::now());
                            snap.accepting_rpc_transactions = accepting;
                        }
                    }

                    // Clean up old RPC-submitted transaction entries to prevent unbounded growth.
                    // Transactions that don't finalize within RPC_SUBMITTED_TX_TIMEOUT are removed.
                    let now = std::time::Instant::now();
                    let before_count = self.rpc_submitted_txs.len();
                    self.rpc_submitted_txs
                        .retain(|_, submitted_at| now.duration_since(*submitted_at) < RPC_SUBMITTED_TX_TIMEOUT);
                    let cleaned = before_count - self.rpc_submitted_txs.len();
                    if cleaned > 0 {
                        tracing::debug!(
                            cleaned,
                            remaining = self.rpc_submitted_txs.len(),
                            "Cleaned up stale RPC-submitted transaction tracking"
                        );
                    }

                    // Clean up stale pending gossip certificate verifications.
                    // These can leak if verification callbacks never arrive (e.g., thread pool issues).
                    // Each entry holds a full TransactionCertificate (~2-10KB), so this is critical.
                    let before_gossip = self.pending_gossip_cert_verifications.len();
                    self.pending_gossip_cert_verifications.retain(|tx_hash, pending| {
                        let expired = now.duration_since(pending.created_at) >= PENDING_GOSSIP_CERT_TIMEOUT;
                        if expired {
                            tracing::warn!(
                                ?tx_hash,
                                pending_shards = pending.pending_shards.len(),
                                age_secs = now.duration_since(pending.created_at).as_secs(),
                                "Cleaning up stale pending gossip cert verification"
                            );
                        }
                        !expired
                    });
                    let cleaned_gossip = before_gossip - self.pending_gossip_cert_verifications.len();
                    if cleaned_gossip > 0 {
                        tracing::warn!(
                            cleaned_gossip,
                            remaining = self.pending_gossip_cert_verifications.len(),
                            "Cleaned up stale pending gossip cert verifications - possible crypto pool issue"
                        );
                    }
                }

                // CRITICAL PRIORITY: Timer events (proposal, cleanup)
                // Timers have their own dedicated channel to ensure they are NEVER blocked
                // by network floods. This is critical for liveness - if timers stop firing,
                // the validator cannot make progress.
                Some(event) = self.timer_rx.recv() => {
                    // Update time
                    let now = self.wall_clock_time();
                    self.state.set_time(now);

                    // Process timer event (span created by state.handle())
                    let actions = self.dispatch_event(event).await;

                    for action in actions {
                        if let Err(e) = self.process_action(action).await {
                            tracing::error!(error = ?e, "Error processing action from timer");
                        }
                    }
                }

                // NOTE: Fetch requests (cert_request_rx, tx_request_rx) are now handled by
                // the dedicated fetch handler task using SharedReadState for lock-free reads.
                // This eliminates event loop blocking and achieves P99 < 10ms response times.

                // HIGH PRIORITY: Callback events (crypto/execution results)
                // These unblock our own in-flight consensus work.
                //
                // IMPORTANT: ProvisioningComplete events come through this channel and
                // produce ExecuteCrossShardTransaction actions. These must be accumulated
                // for batch parallel execution, not sent directly to process_action().
                Some(event) = self.callback_rx.recv() => {
                    // Update time
                    let now = self.wall_clock_time();
                    self.state.set_time(now);

                    // Dispatch event through unified handler (span created by state.handle())
                    let actions = self.dispatch_event(event).await;

                    // Process actions, accumulating cross-shard executions and vote signings for batching
                    for action in actions {
                        match action {
                            Action::ExecuteCrossShardTransaction { tx_hash, transaction, provisions } => {
                                // Accumulate cross-shard executions for batch parallel execution
                                if self.pending_cross_shard_executions.is_empty() {
                                    // Start the 5ms deadline on first cross-shard execution
                                    self.cross_shard_execution_deadline = Some(
                                        tokio::time::Instant::now() + Duration::from_millis(5)
                                    );
                                }
                                self.pending_cross_shard_executions.requests.push(
                                    hyperscale_core::CrossShardExecutionRequest {
                                        tx_hash,
                                        transaction,
                                        provisions,
                                    }
                                );
                                // Flush early if batch is full to cap p99 latency
                                if self.pending_cross_shard_executions.is_full() {
                                    let requests = self.pending_cross_shard_executions.take();
                                    self.cross_shard_execution_deadline = None;
                                    self.dispatch_cross_shard_executions(requests);
                                }
                            }
                            other => {
                                if let Err(e) = self.process_action(other).await {
                                    tracing::error!(error = ?e, "Error processing action from callback");
                                }
                            }
                        }
                    }
                }

                // HIGH PRIORITY: Handle incoming consensus events (BFT network messages)
                event = self.consensus_rx.recv() => {
                    match event {
                        Some(event) => {
                            // Update time
                            let now = self.wall_clock_time();
                            self.state.set_time(now);

                            // Handle TransactionCertificateReceived - verify before persisting.
                            // This is a certificate gossiped from another validator. We verify all
                            // embedded StateCertificate BLS signatures before persisting to prevent
                            // malicious peers from filling our storage with invalid certificates.
                            if let Event::TransactionCertificateReceived { certificate } = &event {
                                let tx_hash = certificate.transaction_hash;

                                // Skip if already verified or in storage
                                if self.pending_gossip_cert_verifications.contains_key(&tx_hash) {
                                    continue;
                                }
                                if self.storage.get_certificate(&tx_hash).is_some() {
                                    continue;
                                }

                                // Collect shards that need verification
                                let pending_shards: std::collections::HashSet<ShardGroupId> =
                                    certificate.shard_proofs.keys().copied().collect();

                                if pending_shards.is_empty() {
                                    // Empty certificate (no shard proofs) - persist directly
                                    // This shouldn't happen in practice but handle it gracefully
                                    self.persist_and_notify_gossiped_certificate(certificate.clone());
                                    continue;
                                }

                                // Track pending verification
                                self.pending_gossip_cert_verifications.insert(
                                    tx_hash,
                                    PendingGossipCertVerification {
                                        certificate: certificate.clone(),
                                        pending_shards: pending_shards.clone(),
                                        failed: false,
                                        created_at: std::time::Instant::now(),
                                    },
                                );

                                // Spawn verification for each StateCertificate on crypto pool
                                for (shard_id, state_cert) in &certificate.shard_proofs {
                                    let committee = self.topology.committee_for_shard(*shard_id);
                                    let public_keys: Vec<PublicKey> = committee
                                        .iter()
                                        .filter_map(|&vid| self.topology.public_key(vid))
                                        .collect();

                                    if public_keys.len() != committee.len() {
                                        tracing::warn!(
                                            tx_hash = ?tx_hash,
                                            shard = shard_id.0,
                                            "Could not resolve all public keys for gossiped certificate"
                                        );
                                        // Mark as failed
                                        if let Some(pending) =
                                            self.pending_gossip_cert_verifications.get_mut(&tx_hash)
                                        {
                                            pending.failed = true;
                                            pending.pending_shards.remove(shard_id);
                                        }
                                        continue;
                                    }

                                    let cert = state_cert.clone();
                                    let shard = *shard_id;
                                    let callback_tx = self.callback_tx.clone();

                                    self.thread_pools.spawn_crypto(move || {
                                        let valid =
                                            verify_state_certificate_signature(&cert, &public_keys);
                                        let _ = callback_tx.send(
                                            Event::GossipedCertificateSignatureVerified {
                                                tx_hash,
                                                shard,
                                                valid,
                                            },
                                        );
                                    });
                                }

                                // Don't dispatch to state machine yet - wait for verification
                                continue;
                            }

                            // Handle GossipedCertificateSignatureVerified callbacks
                            if let Event::GossipedCertificateSignatureVerified {
                                tx_hash,
                                shard,
                                valid,
                            } = &event
                            {
                                if let Some(pending) =
                                    self.pending_gossip_cert_verifications.get_mut(tx_hash)
                                {
                                    if !valid {
                                        pending.failed = true;
                                        tracing::warn!(
                                            tx_hash = ?tx_hash,
                                            shard = shard.0,
                                            "Gossiped certificate signature verification failed"
                                        );
                                    }
                                    pending.pending_shards.remove(shard);

                                    // Check if all shards verified
                                    if pending.pending_shards.is_empty() {
                                        let pending = self
                                            .pending_gossip_cert_verifications
                                            .remove(tx_hash)
                                            .unwrap();

                                        if !pending.failed {
                                            // All verified - persist and notify state machine
                                            self.persist_and_notify_gossiped_certificate(
                                                pending.certificate,
                                            );
                                        }
                                        // If failed, just drop - don't persist invalid certificate
                                    }
                                }
                                continue;
                            }

                            // Process event synchronously (span created by state.handle())
                            // Note: Runner I/O requests (StartSync, FetchTransactions, FetchCertificates)
                            // are now Actions emitted by the state machine and handled in process_action().
                            let actions = self.state.handle(event);

                            // Collect block vote verifications for batching (5ms window).
                            // State votes are accumulated separately with a longer window (20ms).
                            let mut pending_block_votes = PendingBlockVotes::default();

                            for action in actions {
                                match action {
                                    Action::VerifyVoteSignature { vote, public_key, signing_message } => {
                                        pending_block_votes.votes.push((vote, public_key, signing_message));
                                    }
                                    Action::VerifyStateVoteSignature { vote, public_key } => {
                                        // Add to accumulated state votes with longer batching window
                                        if self.pending_state_votes.is_empty() {
                                            // Start the 20ms deadline on first state vote
                                            self.state_vote_deadline = Some(
                                                tokio::time::Instant::now() + Duration::from_millis(20)
                                            );
                                        }
                                        self.pending_state_votes.votes.push((vote, public_key));
                                        // Flush early if batch is full to cap p99 latency
                                        if self.pending_state_votes.is_full() {
                                            let votes = self.pending_state_votes.take();
                                            self.state_vote_deadline = None;
                                            self.dispatch_state_vote_verifications(votes);
                                        }
                                    }
                                    Action::VerifyStateCertificateSignature { certificate, public_keys } => {
                                        // Add to accumulated state certs with 15ms batching window
                                        if self.pending_state_certs.is_empty() {
                                            self.state_cert_deadline = Some(
                                                tokio::time::Instant::now() + Duration::from_millis(15)
                                            );
                                        }
                                        self.pending_state_certs.certs.push((certificate, public_keys));
                                        // Flush early if batch is full to cap p99 latency
                                        if self.pending_state_certs.is_full() {
                                            let certs = self.pending_state_certs.take();
                                            self.state_cert_deadline = None;
                                            self.dispatch_state_cert_verifications(certs);
                                        }
                                    }
                                    // Note: ExecuteCrossShardTransaction only comes from ProvisioningComplete
                                    // which routes through the callback channel, not the consensus channel.
                                    other => {
                                        if let Err(e) = self.process_action(other).await {
                                            tracing::error!(error = ?e, "Error processing action");
                                        }
                                    }
                                }
                            }

                            // Try to collect more block vote verifications from queued consensus events.
                            // First drain any immediately available events.
                            while let Ok(more_event) = self.consensus_rx.try_recv() {
                                // Update time for each event
                                let now = self.wall_clock_time();
                                self.state.set_time(now);

                                let more_actions = self.state.handle(more_event);

                                for action in more_actions {
                                    match action {
                                        Action::VerifyVoteSignature { vote, public_key, signing_message } => {
                                            pending_block_votes.votes.push((vote, public_key, signing_message));
                                        }
                                        Action::VerifyStateVoteSignature { vote, public_key } => {
                                            if self.pending_state_votes.is_empty() {
                                                self.state_vote_deadline = Some(
                                                    tokio::time::Instant::now() + Duration::from_millis(20)
                                                );
                                            }
                                            self.pending_state_votes.votes.push((vote, public_key));
                                            if self.pending_state_votes.is_full() {
                                                let votes = self.pending_state_votes.take();
                                                self.state_vote_deadline = None;
                                                self.dispatch_state_vote_verifications(votes);
                                            }
                                        }
                                        Action::VerifyStateCertificateSignature { certificate, public_keys } => {
                                            if self.pending_state_certs.is_empty() {
                                                self.state_cert_deadline = Some(
                                                    tokio::time::Instant::now() + Duration::from_millis(15)
                                                );
                                            }
                                            self.pending_state_certs.certs.push((certificate, public_keys));
                                            if self.pending_state_certs.is_full() {
                                                let certs = self.pending_state_certs.take();
                                                self.state_cert_deadline = None;
                                                self.dispatch_state_cert_verifications(certs);
                                            }
                                        }
                                        other => {
                                            if let Err(e) = self.process_action(other).await {
                                                tracing::error!(error = ?e, "Error processing action");
                                            }
                                        }
                                    }
                                }
                            }

                            // If we have pending block vote verifications, wait briefly for more to arrive.
                            // This allows votes that arrive close together to be batched,
                            // improving verification throughput (batch BLS verification is faster).
                            // The 5ms delay is small relative to the ~300ms block interval.
                            // Note: State votes use a separate 20ms window handled by a dedicated select branch.
                            //
                            // NOTE: Fetch requests are now handled by the dedicated fetch handler task,
                            // so we don't need to interleave them here. This simplifies the loop.
                            if !pending_block_votes.is_empty() {
                                let batch_deadline = tokio::time::Instant::now() + Duration::from_millis(5);
                                loop {
                                    match tokio::time::timeout_at(batch_deadline, self.consensus_rx.recv()).await {
                                        Ok(Some(more_event)) => {
                                            // Update time for each event
                                            let now = self.wall_clock_time();
                                            self.state.set_time(now);

                                            let more_actions = self.state.handle(more_event);

                                            for action in more_actions {
                                                match action {
                                                    Action::VerifyVoteSignature { vote, public_key, signing_message } => {
                                                        pending_block_votes.votes.push((vote, public_key, signing_message));
                                                    }
                                                    Action::VerifyStateVoteSignature { vote, public_key } => {
                                                        if self.pending_state_votes.is_empty() {
                                                            self.state_vote_deadline = Some(
                                                                tokio::time::Instant::now() + Duration::from_millis(20)
                                                            );
                                                        }
                                                        self.pending_state_votes.votes.push((vote, public_key));
                                                        if self.pending_state_votes.is_full() {
                                                            let votes = self.pending_state_votes.take();
                                                            self.state_vote_deadline = None;
                                                            self.dispatch_state_vote_verifications(votes);
                                                        }
                                                    }
                                                    Action::VerifyStateCertificateSignature { certificate, public_keys } => {
                                                        if self.pending_state_certs.is_empty() {
                                                            self.state_cert_deadline = Some(
                                                                tokio::time::Instant::now() + Duration::from_millis(15)
                                                            );
                                                        }
                                                        self.pending_state_certs.certs.push((certificate, public_keys));
                                                        if self.pending_state_certs.is_full() {
                                                            let certs = self.pending_state_certs.take();
                                                            self.state_cert_deadline = None;
                                                            self.dispatch_state_cert_verifications(certs);
                                                        }
                                                    }
                                                    other => {
                                                        if let Err(e) = self.process_action(other).await {
                                                            tracing::error!(error = ?e, "Error processing action");
                                                        }
                                                    }
                                                }
                                            }

                                            // Break early if block votes batch is full
                                            if pending_block_votes.is_full() {
                                                break;
                                            }
                                        }
                                        Ok(None) => {
                                            // Channel closed
                                            break;
                                        }
                                        Err(_) => {
                                            // Timeout reached, proceed with current batch
                                            break;
                                        }
                                    }
                                }
                            }

                            // Dispatch collected block vote verifications
                            self.dispatch_block_vote_verifications(pending_block_votes);
                        }
                        None => {
                            // Channel closed, exit loop
                            break;
                        }
                    }
                }

                // STATE VOTE BATCHING: Flush accumulated state votes when deadline expires.
                // State votes use a longer batching window (20ms) than block votes (5ms)
                // because they are less latency-sensitive - they don't block consensus progress,
                // only cross-shard certificate formation.
                _ = async {
                    match self.state_vote_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if self.state_vote_deadline.is_some() => {
                    let votes = self.pending_state_votes.take();
                    let batch_size = votes.len();
                    self.state_vote_deadline = None;

                    if !votes.is_empty() {
                        tracing::debug!(
                            batch_size,
                            "Flushing state vote batch after 20ms window"
                        );
                        self.dispatch_state_vote_verifications(votes);
                    }
                }

                // CROSS-SHARD EXECUTION BATCHING: Flush accumulated executions when deadline expires.
                // Uses a short batching window (5ms) to balance latency vs throughput.
                // These are executed in parallel using rayon's par_iter.
                _ = async {
                    match self.cross_shard_execution_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if self.cross_shard_execution_deadline.is_some() => {
                    let requests = self.pending_cross_shard_executions.take();
                    let batch_size = requests.len();
                    self.cross_shard_execution_deadline = None;

                    if !requests.is_empty() {
                        tracing::debug!(
                            batch_size,
                            "Flushing cross-shard execution batch after 5ms window"
                        );
                        self.dispatch_cross_shard_executions(requests);
                    }
                }

                // STATE CERTIFICATE BATCHING: Flush accumulated state certs when deadline expires.
                // Uses a 15ms batching window - state certs are the highest volume crypto operation
                // and benefit significantly from batch BLS verification (~40% faster).
                _ = async {
                    match self.state_cert_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if self.state_cert_deadline.is_some() => {
                    let certs = self.pending_state_certs.take();
                    let batch_size = certs.len();
                    self.state_cert_deadline = None;

                    if !certs.is_empty() {
                        tracing::debug!(
                            batch_size,
                            "Flushing state cert batch after 15ms window"
                        );
                        self.dispatch_state_cert_verifications(certs);
                    }
                }

                // Handle validated transactions from batcher (unbounded channel)
                // These are transactions that passed crypto validation in the batcher.
                // Process before direct submissions since they've already been validated.
                Some(event) = self.validated_tx_rx.recv() => {
                    // Filter out transactions that are already in terminal state
                    if let Event::TransactionGossipReceived { ref tx } = event {
                        if let Some(ref cache) = self.tx_status_cache {
                            if let Ok(cache_guard) = cache.try_read() {
                                if let Some(cached) = cache_guard.get(&tx.hash()) {
                                    if cached.status.is_final() {
                                        tracing::trace!(
                                            tx_hash = ?tx.hash(),
                                            status = %cached.status,
                                            "Ignoring validated tx for already-finalized transaction"
                                        );
                                        continue;
                                    }
                                }
                            }
                        }

                        // Eagerly store transaction in RocksDB so peers can fetch it
                        // before block commit. This is idempotent - storing twice is safe.
                        let storage = self.storage.clone();
                        let tx_clone = Arc::clone(tx);
                        tokio::spawn(async move {
                            storage.put_transaction(&tx_clone);
                        });
                    }

                    let now = self.wall_clock_time();
                    self.state.set_time(now);

                    // Span created by state.handle()
                    let actions = self.state.handle(event);

                    for action in actions {
                        if let Err(e) = self.process_action(action).await {
                            tracing::error!(error = ?e, "Error processing validated tx action");
                        }
                    }
                }

                // Handle RPC-submitted transactions
                // These need to be gossiped to all relevant shards BEFORE validation,
                // unlike gossip-received transactions which are already gossiped.
                Some(tx) = self.rpc_tx_rx.recv() => {
                    let tx_hash = tx.hash();
                    let tx_span = span!(
                        Level::DEBUG,
                        "handle_rpc_tx",
                        tx_hash = ?tx_hash,
                        node = self.state.node_index(),
                        shard = ?self.state.shard(),
                    );
                    let _tx_guard = tx_span.enter();

                    // Track this as an RPC-submitted transaction for latency metrics
                    self.rpc_submitted_txs.insert(tx_hash, std::time::Instant::now());

                    // Step 1: Gossip to all relevant shards FIRST
                    // This ensures other validators see the transaction even if we fail later
                    let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(&tx));
                    for shard in self.topology.all_shards_for_transaction(&tx) {
                        let mut message = OutboundMessage::TransactionGossip(Box::new(gossip.clone()));
                        message.inject_trace_context();
                        if let Err(e) = self.network.broadcast_shard(shard, &message).await {
                            tracing::warn!(
                                ?shard,
                                tx_hash = ?tx.hash(),
                                error = ?e,
                                "Failed to gossip RPC transaction to shard"
                            );
                        }
                    }

                    // Step 2: Submit to batcher for validation
                    // After validation, it will come back through validated_tx_rx
                    // and get dispatched to the state machine
                    if !self.tx_validation_handle.submit(tx) {
                        tracing::debug!("RPC transaction deduplicated or batcher closed");
                    }
                }

                // Handle inbound sync requests from peers
                // Drain all pending requests to minimize response latency.
                Some(request) = self.sync_request_rx.recv() => {
                    // Handle the first request
                    self.handle_inbound_sync_request(request);

                    // Drain any additional pending requests
                    while let Ok(request) = self.sync_request_rx.try_recv() {
                        self.handle_inbound_sync_request(request);
                    }
                }

                // Periodic sync and fetch manager tick
                // This drives outbound sync/fetch operations, so give it some priority
                _ = sync_tick.tick() => {
                    let tick_span = span!(Level::TRACE, "sync_tick");
                    let _tick_guard = tick_span.enter();

                    // Tick both managers to process pending fetches
                    self.sync_manager.tick().await;
                    self.fetch_manager.tick().await;

                    // Process sync backfills - trigger fetches for missing data
                    self.sync_manager.tick_backfills();
                    for (block_hash, proposer, missing_txs, missing_certs) in
                        self.sync_manager.get_pending_backfill_fetches()
                    {
                        if !missing_txs.is_empty() {
                            self.fetch_manager
                                .request_transactions(block_hash, proposer, missing_txs);
                        }
                        if !missing_certs.is_empty() {
                            self.fetch_manager
                                .request_certificates(block_hash, proposer, missing_certs);
                        }
                    }
                }

                // Transaction status updates (non-consensus-critical)
                // These update mempool status for RPC queries but don't affect consensus
                Some(event) = self.status_rx.recv() => {
                    // Update time
                    let now = self.wall_clock_time();
                    self.state.set_time(now);

                    // Process status event (span created by state.handle())
                    let actions = self.state.handle(event);

                    for action in actions {
                        if let Err(e) = self.process_action(action).await {
                            tracing::error!(error = ?e, "Error processing status action");
                        }
                    }
                }
            }
        }

        tracing::info!("Production runner stopped");
        Ok(())
    }

    /// Process an action.
    async fn process_action(&mut self, action: Action) -> Result<(), RunnerError> {
        match action {
            // Network I/O - dispatch to action dispatcher task (fire-and-forget)
            // This prevents network latency from blocking the event loop.
            Action::BroadcastToShard { shard, mut message } => {
                // Inject trace context for cross-shard messages (no-op if feature disabled)
                message.inject_trace_context();

                // Dispatch to action dispatcher (unbounded channel - never blocks or drops)
                let _ = self
                    .dispatch_tx
                    .send(DispatchableAction::BroadcastToShard { shard, message });
            }

            Action::BroadcastGlobal { mut message } => {
                // Inject trace context for cross-shard messages (no-op if feature disabled)
                message.inject_trace_context();

                // Dispatch to action dispatcher (unbounded channel - never blocks or drops)
                let _ = self
                    .dispatch_tx
                    .send(DispatchableAction::BroadcastGlobal { message });
            }

            // Domain-specific execution broadcasts - dispatch to action dispatcher
            // The batcher accumulates items and flushes periodically to reduce network overhead.
            // These are critical cross-shard messages - log errors if dispatch fails.
            Action::BroadcastStateVote { shard, vote } => {
                if self
                    .dispatch_tx
                    .send(DispatchableAction::QueueStateVote {
                        shard,
                        vote: vote.clone(),
                    })
                    .is_err()
                {
                    tracing::error!(
                        shard = shard.0,
                        tx_hash = ?vote.transaction_hash,
                        "CRITICAL: Failed to dispatch state vote - dispatcher channel closed"
                    );
                    crate::metrics::increment_dispatch_failures("state_vote");
                }
            }

            Action::BroadcastStateCertificate { shard, certificate } => {
                if self
                    .dispatch_tx
                    .send(DispatchableAction::QueueStateCertificate {
                        shard,
                        certificate: certificate.clone(),
                    })
                    .is_err()
                {
                    tracing::error!(
                        shard = shard.0,
                        tx_hash = ?certificate.transaction_hash,
                        "CRITICAL: Failed to dispatch state certificate - dispatcher channel closed"
                    );
                    crate::metrics::increment_dispatch_failures("state_certificate");
                }
            }

            Action::BroadcastStateProvision { shard, provision } => {
                if self
                    .dispatch_tx
                    .send(DispatchableAction::QueueStateProvision {
                        shard,
                        provision: provision.clone(),
                    })
                    .is_err()
                {
                    tracing::error!(
                        shard = shard.0,
                        tx_hash = ?provision.transaction_hash,
                        "CRITICAL: Failed to dispatch state provision - dispatcher channel closed"
                    );
                    crate::metrics::increment_dispatch_failures("state_provision");
                }
            }

            // Timers via timer manager
            Action::SetTimer { id, duration } => {
                self.timer_manager.set_timer(id, duration);
            }

            Action::CancelTimer { id } => {
                self.timer_manager.cancel_timer(id);
            }

            // Block vote verification on CONSENSUS crypto pool (liveness-critical)
            Action::VerifyVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                let event_tx = self.callback_tx.clone();
                // Block votes are liveness-critical - use dedicated consensus crypto pool
                self.thread_pools.spawn_consensus_crypto(move || {
                    let start = std::time::Instant::now();
                    // Verify vote signature against domain-separated message
                    let valid = public_key.verify(&signing_message, &vote.signature);
                    crate::metrics::record_signature_verification_latency(
                        "vote",
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    event_tx
                        .send(Event::VoteSignatureVerified { vote, valid })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            Action::VerifyAndAggregateProvisions {
                tx_hash,
                source_shard,
                block_height,
                entries,
                provisions,
                public_keys,
                committee_size,
            } => {
                let event_tx = self.callback_tx.clone();
                let topology = self.topology.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();

                    // All provisions for the same (tx, source_shard) sign the SAME message.
                    // This enables an optimized verification path:
                    // 1. Aggregate all signatures into one
                    // 2. Aggregate all public keys into one
                    // 3. Single pairing check: e(agg_sig, G2) == e(agg_pk, H(msg))
                    //
                    // This is O(1) pairings instead of O(N), a massive speedup.
                    // We only fall back to individual verification if the aggregate fails
                    // (indicating a Byzantine validator submitted a bad signature).

                    let signatures: Vec<Signature> =
                        provisions.iter().map(|p| p.signature.clone()).collect();

                    // Happy path: try aggregate verification first (single pairing)
                    let message = provisions
                        .first()
                        .map(|p| p.signing_message())
                        .unwrap_or_default();

                    let all_valid = PublicKey::batch_verify_bls_same_message(
                        &message,
                        &signatures,
                        &public_keys,
                    );

                    let (verified_provisions, commitment_proof) = if all_valid {
                        // Fast path: all signatures valid, build proof directly
                        let mut signers = SignerBitfield::new(committee_size);
                        for provision in &provisions {
                            if let Some(idx) = topology
                                .committee_index_for_shard(source_shard, provision.validator_id)
                            {
                                signers.set(idx);
                            }
                        }

                        let aggregated_signature = Signature::aggregate_bls(&signatures)
                            .unwrap_or_else(|_| Signature::zero());

                        let proof = CommitmentProof::new(
                            tx_hash,
                            source_shard,
                            signers,
                            aggregated_signature,
                            block_height,
                            entries,
                        );

                        (provisions.clone(), Some(proof))
                    } else {
                        // Slow path: aggregate verification failed, find valid signatures
                        // This only happens with Byzantine behavior (rare)
                        tracing::warn!(
                            tx_hash = %tx_hash,
                            source_shard = source_shard.0,
                            provision_count = provisions.len(),
                            "Aggregate provision verification failed, falling back to individual"
                        );

                        let mut verified = Vec::new();
                        let mut valid_sigs = Vec::new();
                        let mut signer_indices = Vec::new();

                        for (provision, pk) in provisions.iter().zip(public_keys.iter()) {
                            if pk.verify(&message, &provision.signature) {
                                verified.push(provision.clone());
                                valid_sigs.push(provision.signature.clone());
                                if let Some(idx) = topology
                                    .committee_index_for_shard(source_shard, provision.validator_id)
                                {
                                    signer_indices.push(idx);
                                }
                            } else {
                                crate::metrics::record_signature_verification_failure();
                                tracing::warn!(
                                    tx_hash = %tx_hash,
                                    validator = provision.validator_id.0,
                                    "Invalid provision signature"
                                );
                            }
                        }

                        let proof = if !valid_sigs.is_empty() {
                            let mut signers = SignerBitfield::new(committee_size);
                            for idx in &signer_indices {
                                signers.set(*idx);
                            }

                            let aggregated_signature = Signature::aggregate_bls(&valid_sigs)
                                .unwrap_or_else(|_| Signature::zero());

                            Some(CommitmentProof::new(
                                tx_hash,
                                source_shard,
                                signers,
                                aggregated_signature,
                                block_height,
                                entries,
                            ))
                        } else {
                            None
                        };

                        (verified, proof)
                    };

                    crate::metrics::record_signature_verification_latency(
                        "provision_batch_verify_aggregate",
                        start.elapsed().as_secs_f64(),
                    );

                    event_tx
                        .send(Event::ProvisionsVerifiedAndAggregated {
                            tx_hash,
                            source_shard,
                            verified_provisions,
                            commitment_proof,
                        })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            Action::AggregateStateCertificate {
                tx_hash,
                shard,
                merkle_root,
                votes,
                read_nodes,
                voting_power,
                committee_size,
            } => {
                let event_tx = self.callback_tx.clone();
                let topology = self.topology.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();

                    // Deduplicate votes by validator to avoid aggregating the same signature multiple times
                    let mut seen_validators = std::collections::HashSet::new();
                    let unique_votes: Vec<_> = votes
                        .iter()
                        .filter(|vote| seen_validators.insert(vote.validator))
                        .collect();

                    // Aggregate BLS signatures from unique votes only
                    let bls_signatures: Vec<_> = unique_votes
                        .iter()
                        .filter_map(|vote| match &vote.signature {
                            hyperscale_types::Signature::Bls12381(_) => {
                                Some(vote.signature.clone())
                            }
                            _ => None,
                        })
                        .collect();

                    let aggregated_signature = if !bls_signatures.is_empty() {
                        Signature::aggregate_bls(&bls_signatures)
                            .unwrap_or_else(|_| Signature::zero())
                    } else {
                        Signature::zero()
                    };

                    // Create signer bitfield
                    // Use topology to get correct committee index for the shard.
                    // Validator IDs are global but committee indices are per-shard.
                    let mut signers = SignerBitfield::new(committee_size);

                    for vote in &unique_votes {
                        if let Some(idx) = topology.committee_index_for_shard(shard, vote.validator)
                        {
                            signers.set(idx);
                        }
                    }

                    let success = votes.first().map(|v| v.success).unwrap_or(false);

                    let certificate = hyperscale_types::StateCertificate {
                        transaction_hash: tx_hash,
                        shard_group_id: shard,
                        read_nodes,
                        state_writes: vec![],
                        outputs_merkle_root: merkle_root,
                        success,
                        aggregated_signature,
                        signers,
                        voting_power: voting_power.0,
                    };

                    crate::metrics::record_signature_verification_latency(
                        "state_cert_aggregation",
                        start.elapsed().as_secs_f64(),
                    );

                    event_tx
                        .send(Event::StateCertificateAggregated {
                            tx_hash,
                            certificate,
                        })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            Action::VerifyStateVoteSignature { vote, public_key } => {
                let event_tx = self.callback_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Use centralized signing message (must match ExecutionState::create_vote)
                    let msg = vote.signing_message();

                    let valid = public_key.verify(&msg, &vote.signature);
                    crate::metrics::record_signature_verification_latency(
                        "state_vote",
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    event_tx
                        .send(Event::StateVoteSignatureVerified { vote, valid })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                // NOTE: State certs should normally be batched via the event loop's
                // pending_state_certs accumulator. This fallback handles any certs
                // that come through process_action (e.g., from callback channel events).
                if self.pending_state_certs.is_empty() {
                    self.state_cert_deadline =
                        Some(tokio::time::Instant::now() + Duration::from_millis(15));
                }
                self.pending_state_certs
                    .certs
                    .push((certificate, public_keys));
                // Flush early if batch is full to cap p99 latency
                if self.pending_state_certs.is_full() {
                    let certs = self.pending_state_certs.take();
                    self.state_cert_deadline = None;
                    self.dispatch_state_cert_verifications(certs);
                }
            }

            Action::VerifyQcSignature {
                qc,
                public_keys,
                block_hash,
                signing_message,
            } => {
                let event_tx = self.callback_tx.clone();
                // QC verification is LIVENESS-CRITICAL - use consensus crypto pool
                self.thread_pools.spawn_consensus_crypto(move || {
                    let start = std::time::Instant::now();
                    // Get signer keys based on QC's signer bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| qc.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        // No signers - invalid QC (genesis is handled before action is emitted)
                        false
                    } else {
                        // Verify aggregated BLS signature against domain-separated message
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => {
                                aggregated_pk.verify(&signing_message, &qc.aggregated_signature)
                            }
                            Err(_) => false,
                        }
                    };

                    crate::metrics::record_signature_verification_latency(
                        "qc",
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    event_tx
                        .send(Event::QcSignatureVerified { block_hash, valid })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            // QC building (BLS signature aggregation) on CONSENSUS crypto pool (liveness-critical)
            Action::BuildQuorumCertificate {
                block_hash,
                height,
                round,
                parent_block_hash,
                votes,
                signers,
                voting_power,
                timestamp_weight_sum,
            } => {
                let event_tx = self.callback_tx.clone();
                // QC building is liveness-critical - use dedicated consensus crypto pool
                self.thread_pools.spawn_consensus_crypto(move || {
                    let start = std::time::Instant::now();

                    // Extract signatures in sorted order (votes are pre-sorted by committee index)
                    let signatures: Vec<Signature> =
                        votes.iter().map(|(_, v)| v.signature.clone()).collect();

                    // Aggregate BLS signatures
                    let qc = match Signature::aggregate_bls(&signatures) {
                        Ok(aggregated_signature) => {
                            // Compute stake-weighted timestamp
                            let weighted_timestamp_ms = if voting_power.0 == 0 {
                                0
                            } else {
                                (timestamp_weight_sum / voting_power.0 as u128) as u64
                            };

                            Some(QuorumCertificate {
                                block_hash,
                                height,
                                parent_block_hash,
                                round,
                                aggregated_signature,
                                signers,
                                voting_power,
                                weighted_timestamp_ms,
                            })
                        }
                        Err(e) => {
                            tracing::warn!("Failed to aggregate BLS signatures for QC: {}", e);
                            None
                        }
                    };

                    crate::metrics::record_signature_verification_latency(
                        "qc_build",
                        start.elapsed().as_secs_f64(),
                    );

                    event_tx
                        .send(Event::QuorumCertificateBuilt { block_hash, qc })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            // Note: View change verification actions removed - using HotStuff-2 implicit rounds

            // Transaction execution on dedicated execution thread pool
            // NOTE: Execution is READ-ONLY. State writes are collected in the results
            // and committed later when TransactionCertificate is included in a block.
            // After execution, signs votes and broadcasts + sends to state machine directly,
            // avoiding a round-trip through the state machine for signing.
            Action::ExecuteTransactions {
                block_hash: _,
                transactions,
                state_root: _,
            } => {
                let event_tx = self.callback_tx.clone();
                let dispatch_tx = self.dispatch_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();
                let thread_pools = self.thread_pools.clone();
                let signing_key = self.signing_key.clone();
                let local_shard = self.local_shard;
                let validator_id = self.topology.local_validator_id();

                self.thread_pools.spawn_execution(move || {
                    let start = std::time::Instant::now();
                    // Execute transactions in parallel using all execution pool threads.
                    // Each transaction gets its own storage snapshot for isolated execution.
                    // RocksDB snapshots are thread-safe and support concurrent reads.
                    let results: Vec<hyperscale_types::ExecutionResult> =
                        thread_pools.execution_pool().install(|| {
                            use rayon::prelude::*;
                            transactions
                                .par_iter()
                                .map(|tx| {
                                    match executor.execute_single_shard(&*storage, std::slice::from_ref(tx)) {
                                        Ok(output) => {
                                            if let Some(r) = output.results().first() {
                                                hyperscale_types::ExecutionResult {
                                                    transaction_hash: r.tx_hash,
                                                    success: r.success,
                                                    state_root: r.outputs_merkle_root,
                                                    writes: r.state_writes.clone(),
                                                    error: r.error.clone(),
                                                }
                                            } else {
                                                hyperscale_types::ExecutionResult {
                                                    transaction_hash: tx.hash(),
                                                    success: false,
                                                    state_root: hyperscale_types::Hash::ZERO,
                                                    writes: vec![],
                                                    error: Some("No execution result".to_string()),
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(tx_hash = ?tx.hash(), error = %e, "Transaction execution failed");
                                            hyperscale_types::ExecutionResult {
                                                transaction_hash: tx.hash(),
                                                success: false,
                                                state_root: hyperscale_types::Hash::ZERO,
                                                writes: vec![],
                                                error: Some(format!("{}", e)),
                                            }
                                        }
                                    }
                                })
                                .collect()
                        });
                    crate::metrics::record_execution_latency(start.elapsed().as_secs_f64());

                    // Sign votes for each execution result. The runner handles:
                    // 1. Signing (done here)
                    // 2. Broadcasting (via dispatch_tx)
                    // 3. Local handling (via StateVoteReceived to state machine)
                    for result in results {
                        let message = hyperscale_types::exec_vote_message(
                            &result.transaction_hash,
                            &result.state_root,
                            local_shard,
                            result.success,
                        );
                        let signature = signing_key.sign(&message);

                        let vote = StateVoteBlock {
                            transaction_hash: result.transaction_hash,
                            shard_group_id: local_shard,
                            state_root: result.state_root,
                            success: result.success,
                            validator: validator_id,
                            signature,
                        };

                        // Broadcast to shard peers via message batcher
                        let _ = dispatch_tx.send(DispatchableAction::QueueStateVote {
                            shard: local_shard,
                            vote: vote.clone(),
                        });

                        // Send to state machine for local handling (skips verification for own votes)
                        event_tx
                            .send(Event::StateVoteReceived { vote })
                            .expect(
                                "callback channel closed - Loss of this event would cause a deadlock",
                            );
                    }
                });
            }

            // Speculative execution of single-shard transactions before block commit.
            // Uses the same execution path as ExecuteTransactions but returns a different event.
            // Results are cached and used when the block commits (if still valid).
            Action::SpeculativeExecute {
                block_hash,
                transactions,
            } => {
                let event_tx = self.callback_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();
                let thread_pools = self.thread_pools.clone();

                self.thread_pools.spawn_execution(move || {
                    let start = std::time::Instant::now();
                    // Execute transactions in parallel using all execution pool threads.
                    let results: Vec<(hyperscale_types::Hash, hyperscale_types::ExecutionResult)> =
                        thread_pools.execution_pool().install(|| {
                            use rayon::prelude::*;
                            transactions
                                .par_iter()
                                .map(|tx| {
                                    let tx_hash = tx.hash();
                                    let result =
                                        match executor.execute_single_shard(&*storage, std::slice::from_ref(tx))
                                        {
                                            Ok(output) => {
                                                if let Some(r) = output.results().first() {
                                                    hyperscale_types::ExecutionResult {
                                                        transaction_hash: r.tx_hash,
                                                        success: r.success,
                                                        state_root: r.outputs_merkle_root,
                                                        writes: r.state_writes.clone(),
                                                        error: r.error.clone(),
                                                    }
                                                } else {
                                                    hyperscale_types::ExecutionResult {
                                                        transaction_hash: tx_hash,
                                                        success: false,
                                                        state_root: hyperscale_types::Hash::ZERO,
                                                        writes: vec![],
                                                        error: Some(
                                                            "No execution result".to_string(),
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(tx_hash = ?tx_hash, error = %e, "Speculative execution failed");
                                                hyperscale_types::ExecutionResult {
                                                    transaction_hash: tx_hash,
                                                    success: false,
                                                    state_root: hyperscale_types::Hash::ZERO,
                                                    writes: vec![],
                                                    error: Some(format!("{}", e)),
                                                }
                                            }
                                        };
                                    (tx_hash, result)
                                })
                                .collect()
                        });
                    crate::metrics::record_speculative_execution_latency(
                        start.elapsed().as_secs_f64(),
                    );

                    event_tx
                        .send(Event::SpeculativeExecutionComplete {
                            block_hash,
                            results,
                        })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            // Cross-shard transaction execution is handled by the event loop's batching mechanism.
            // The ExecuteCrossShardTransaction action is accumulated and executed in parallel batches.
            // See dispatch_cross_shard_executions() for the parallel execution implementation.
            Action::ExecuteCrossShardTransaction { .. } => {
                // This should never be reached - the action is intercepted in the event loop
                // and accumulated for batch execution.
                tracing::error!("ExecuteCrossShardTransaction reached process_action - should be handled by event loop batching");
            }

            // Sign already-executed results (e.g., speculative execution cache hits).
            // Signs votes and broadcasts + sends StateVoteReceived for local handling.
            Action::SignExecutionResults { results } => {
                let event_tx = self.callback_tx.clone();
                let dispatch_tx = self.dispatch_tx.clone();
                let signing_key = self.signing_key.clone();
                let local_shard = self.local_shard;
                let validator_id = self.topology.local_validator_id();

                self.thread_pools.spawn_execution(move || {
                    for result in results {
                        let message = hyperscale_types::exec_vote_message(
                            &result.transaction_hash,
                            &result.state_root,
                            local_shard,
                            result.success,
                        );
                        let signature = signing_key.sign(&message);

                        let vote = StateVoteBlock {
                            transaction_hash: result.transaction_hash,
                            shard_group_id: local_shard,
                            state_root: result.state_root,
                            success: result.success,
                            validator: validator_id,
                            signature,
                        };

                        // Broadcast to shard peers via message batcher
                        let _ = dispatch_tx.send(DispatchableAction::QueueStateVote {
                            shard: local_shard,
                            vote: vote.clone(),
                        });

                        // Send to state machine for local handling
                        event_tx
                            .send(Event::StateVoteReceived { vote })
                            .expect("callback channel closed");
                    }
                });
            }

            // Merkle computation on execution pool (can be parallelized internally)
            // Note: This action is currently not emitted by any state machine.
            Action::ComputeMerkleRoot { tx_hash, writes } => {
                let event_tx = self.callback_tx.clone();

                self.thread_pools.spawn_execution(move || {
                    // Simple merkle root computation using hash chain
                    // A proper implementation would use a sparse Merkle tree
                    let root = if writes.is_empty() {
                        hyperscale_types::Hash::ZERO
                    } else {
                        // Sort writes for determinism
                        let mut sorted = writes;
                        sorted.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

                        // Hash chain
                        let mut data = Vec::new();
                        for (node_id, value) in &sorted {
                            data.extend_from_slice(&node_id.0);
                            data.extend_from_slice(value);
                        }
                        hyperscale_types::Hash::from_bytes(&data)
                    };
                    event_tx
                        .send(Event::MerkleRootComputed { tx_hash, root })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            // Internal events are routed based on criticality:
            // - Status events (TransactionStatusChanged, TransactionExecuted) go to status channel
            // - All other internal events (QC formed, block committed, etc.) go to callback channel
            //   for highest priority processing
            Action::EnqueueInternal { event } => {
                let is_status_event = matches!(
                    &event,
                    Event::TransactionStatusChanged { .. } | Event::TransactionExecuted { .. }
                );

                if is_status_event {
                    // Non-consensus-critical: route to status channel
                    self.status_tx
                        .send(event)
                        .await
                        .map_err(|e| RunnerError::SendError(e.to_string()))?;
                } else {
                    // Consensus-critical internal event: route to callback channel
                    // This ensures internal events (QC formed, block ready, etc.) are
                    // processed before new network events
                    self.callback_tx
                        .send(event)
                        .map_err(|e| RunnerError::SendError(e.to_string()))?;
                }
            }

            Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally: _,
            } => {
                tracing::debug!(?tx_hash, ?status, cross_shard, "Transaction status update");

                // Record transaction metrics for terminal states, but only for transactions
                // that were submitted via RPC to THIS node. This avoids polluting latency
                // metrics with transactions received via gossip/sync which would have
                // artificially high latencies on lagging nodes.
                //
                // Note: We use rpc_submitted_txs instead of the submitted_locally field
                // because the field tracks mempool insertion, not RPC origin. In production,
                // RPC transactions go through gossip before reaching the mempool, so
                // submitted_locally would always be false.
                if status.is_final() {
                    // Check if this was an RPC-submitted transaction
                    if let Some(_submitted_at) = self.rpc_submitted_txs.remove(&tx_hash) {
                        // Calculate latency from submission to finalization
                        let now = self.state.now();
                        let latency_secs = now.saturating_sub(added_at).as_secs_f64();
                        crate::metrics::record_transaction_finalized(latency_secs, cross_shard);
                    }
                }

                // Update transaction status cache for RPC queries
                if let Some(ref cache) = self.tx_status_cache {
                    let cache = cache.clone();
                    let status_clone = status.clone();
                    // Use spawn to avoid blocking - cache update is fast but we don't want
                    // to await on the write lock in the hot path
                    tokio::spawn(async move {
                        let mut cache = cache.write().await;
                        cache.update(tx_hash, status_clone);
                    });
                }
            }

            Action::EmitCommittedBlock { block } => {
                let height = block.header.height.0;
                let current_view = self.state.bft().view();
                tracing::info!(
                    block_hash = ?block.hash(),
                    height = height,
                    view = current_view,
                    "Block committed"
                );

                // Record block committed metric.
                // For now, we don't have the proposal timestamp available here,
                // so we pass 0.0 for latency. The block height gauge is still useful.
                crate::metrics::record_block_committed(height, 0.0);

                // Record livelock metrics for deferrals in this block.
                for _deferral in &block.deferred {
                    crate::metrics::record_livelock_deferral();
                    crate::metrics::record_livelock_cycle_detected();
                }

                // Update deferred transaction count gauge.
                let livelock_stats = self.state.livelock().stats();
                crate::metrics::set_livelock_deferred_count(livelock_stats.pending_deferrals);

                // Update sync manager's committed height - critical for correct sync behavior.
                // If sync completes, notify the state machine so it can resume view changes.
                if let Some(sync_height) = self.sync_manager.set_committed_height(height) {
                    tracing::info!(
                        sync_height,
                        committed_height = height,
                        "Sync completed, sending SyncComplete event to resume consensus"
                    );
                    let sync_complete_event = Event::SyncComplete {
                        height: sync_height,
                    };
                    // SyncComplete handler just clears the syncing flag and resets timeout,
                    // it doesn't return any actions that need processing.
                    let _ = self.state.handle(sync_complete_event);
                }

                // Update RPC status with new block height and view
                if let Some(ref rpc_status) = self.rpc_status {
                    let rpc_status = rpc_status.clone();
                    tokio::spawn(async move {
                        let mut status = rpc_status.write().await;
                        status.block_height = height;
                        status.view = current_view;
                    });
                }
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Storage writes
            // ═══════════════════════════════════════════════════════════════════════
            Action::PersistBlock { block, qc } => {
                // Fire-and-forget block persistence - not latency critical
                // RocksDB is internally thread-safe, no lock needed
                //
                // Uses denormalized storage: block metadata stored separately from
                // transactions and certificates. This eliminates duplication and
                // enables storage-backed fetch requests.
                let storage = self.storage.clone();
                let height = block.height();
                tokio::spawn(async move {
                    storage.put_block_denormalized(&block, &qc);
                    // Update chain metadata
                    storage.set_chain_metadata(height, None, None);
                    // Prune old votes - we no longer need votes at or below committed height
                    storage.prune_own_votes(height.0);
                });
            }

            Action::PersistTransactionCertificate { certificate } => {
                // Commit certificate + state writes atomically
                // This is durability-critical: we await completion
                let storage = self.storage.clone();
                let local_shard = self.local_shard;

                // Extract writes for local shard from the certificate's shard_proofs
                let writes: Vec<_> = certificate
                    .shard_proofs
                    .get(&local_shard)
                    .map(|cert| cert.state_writes.clone())
                    .unwrap_or_default();

                // Run on blocking thread since RocksDB write is sync I/O
                // RocksDB is internally thread-safe, no lock needed
                let cert_for_persist = certificate.clone();
                tokio::task::spawn_blocking(move || {
                    storage.commit_certificate_with_writes(&cert_for_persist, &writes);
                })
                .await
                .ok();

                // After persisting, gossip certificate to same-shard peers.
                // This ensures other validators have the certificate before the proposer
                // includes it in a block, avoiding fetch delays that can cause backpressure.
                let gossip = hyperscale_messages::TransactionCertificateGossip::new(certificate);
                let _ = self.dispatch_tx.send(DispatchableAction::BroadcastToShard {
                    shard: local_shard,
                    message: OutboundMessage::TransactionCertificateGossip(gossip),
                });
            }

            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard,
                message,
            } => {
                // **BFT Safety Critical**: Must persist before broadcasting vote
                // Prevents equivocation after crash/restart.
                //
                // Fire-and-forget pattern with callback:
                // 1. Spawn blocking task for RocksDB write
                // 2. After persist completes, dispatch broadcast to action dispatcher
                // 3. Main event loop continues immediately (no blocking)
                let storage = self.storage.clone();
                let dispatch_tx = self.dispatch_tx.clone();

                tokio::task::spawn_blocking(move || {
                    // Persist vote (sync write with WAL)
                    storage.put_own_vote(height.0, round, block_hash);

                    // After persist completes, send broadcast to action dispatcher
                    // This ensures persist-before-broadcast ordering without blocking the event loop
                    let _ =
                        dispatch_tx.send(DispatchableAction::BroadcastToShard { shard, message });
                });
                // Note: No .await - we don't block the event loop
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Storage reads - RocksDB is internally thread-safe, no lock needed
            // Results go to callback channel as they unblock consensus progress
            // ═══════════════════════════════════════════════════════════════════════
            Action::FetchStateEntries { tx_hash, nodes } => {
                let event_tx = self.callback_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();

                tokio::task::spawn_blocking(move || {
                    let entries = executor.fetch_state_entries(&*storage, &nodes);
                    event_tx
                        .send(Event::StateEntriesFetched { tx_hash, entries })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            Action::FetchBlock { height } => {
                let event_tx = self.callback_tx.clone();
                let storage = self.storage.clone();

                tokio::task::spawn_blocking(move || {
                    let block = storage.get_block(height).map(|(b, _qc)| b);
                    event_tx.send(Event::BlockFetched { height, block }).expect(
                        "callback channel closed - Loss of this event would cause a deadlock",
                    );
                });
            }

            Action::FetchChainMetadata => {
                let event_tx = self.callback_tx.clone();
                let storage = self.storage.clone();

                tokio::task::spawn_blocking(move || {
                    let (height, hash, qc) = storage.get_chain_metadata();
                    event_tx
                        .send(Event::ChainMetadataFetched { height, hash, qc })
                        .expect(
                            "callback channel closed - Loss of this event would cause a deadlock",
                        );
                });
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Global Consensus Actions (TODO: implement when GlobalConsensusState exists)
            // ═══════════════════════════════════════════════════════════════════════
            Action::ProposeGlobalBlock { epoch, height, .. } => {
                tracing::trace!(?epoch, ?height, "ProposeGlobalBlock - not yet implemented");
            }
            Action::BroadcastGlobalBlockVote {
                block_hash, shard, ..
            } => {
                tracing::trace!(
                    ?block_hash,
                    ?shard,
                    "BroadcastGlobalBlockVote - not yet implemented"
                );
            }
            Action::TransitionEpoch {
                from_epoch,
                to_epoch,
                ..
            } => {
                tracing::debug!(
                    ?from_epoch,
                    ?to_epoch,
                    "TransitionEpoch - not yet implemented"
                );
            }
            Action::MarkValidatorReady { epoch, shard } => {
                tracing::debug!(?epoch, ?shard, "MarkValidatorReady - not yet implemented");
            }
            Action::InitiateShardSplit {
                source_shard,
                new_shard,
                split_point,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    split_point,
                    "InitiateShardSplit - not yet implemented"
                );
            }
            Action::CompleteShardSplit {
                source_shard,
                new_shard,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    "CompleteShardSplit - not yet implemented"
                );
            }
            Action::InitiateShardMerge {
                shard_a,
                shard_b,
                merged_shard,
            } => {
                tracing::info!(
                    ?shard_a,
                    ?shard_b,
                    ?merged_shard,
                    "InitiateShardMerge - not yet implemented"
                );
            }
            Action::CompleteShardMerge { merged_shard } => {
                tracing::info!(?merged_shard, "CompleteShardMerge - not yet implemented");
            }
            Action::PersistEpochConfig { .. } => {
                tracing::debug!("PersistEpochConfig - not yet implemented");
            }
            Action::FetchEpochConfig { epoch } => {
                tracing::debug!(?epoch, "FetchEpochConfig - not yet implemented");
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Runner I/O Requests (network fetches)
            // These are requests from the state machine for the runner to perform
            // network I/O. Results are delivered back as Events.
            // ═══════════════════════════════════════════════════════════════════════
            Action::StartSync {
                target_height,
                target_hash,
            } => {
                self.sync_manager.start_sync(target_height, target_hash);
            }

            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                // Delegate to FetchManager for parallel, retry-capable fetching
                self.fetch_manager
                    .request_transactions(block_hash, proposer, tx_hashes);
            }

            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                // Delegate to FetchManager for parallel, retry-capable fetching
                self.fetch_manager
                    .request_certificates(block_hash, proposer, cert_hashes);
            }
        }

        Ok(())
    }

    /// Dispatch block vote verifications to the CONSENSUS crypto thread pool.
    ///
    /// Block votes are LIVENESS-CRITICAL and use the dedicated consensus crypto pool
    /// to ensure they are never blocked by general crypto work (provisions, state votes).
    /// This is essential for forming QCs within the view_change_timeout (default 3s).
    ///
    /// Block votes use a short batching window (5ms) since they are latency-sensitive
    /// for consensus progress.
    ///
    /// Results are sent back as individual events to maintain compatibility
    /// with the state machine's expectations.
    fn dispatch_block_vote_verifications(&self, pending: PendingBlockVotes) {
        if pending.is_empty() {
            return;
        }

        let event_tx = self.callback_tx.clone();
        let batch_size = pending.len();

        // Use dedicated consensus crypto pool - never blocked by provisions/state votes
        self.thread_pools.spawn_consensus_crypto(move || {
            let start = std::time::Instant::now();

            // Separate by key type for appropriate batch verification
            let mut ed25519_votes: Vec<(BlockVote, PublicKey, Vec<u8>)> = Vec::new();
            let mut bls_votes: Vec<(BlockVote, PublicKey, Vec<u8>)> = Vec::new();

            for (vote, pk, msg) in pending.votes {
                match &pk {
                    PublicKey::Ed25519(_) => ed25519_votes.push((vote, pk, msg)),
                    PublicKey::Bls12381(_) => bls_votes.push((vote, pk, msg)),
                }
            }

            // Process Ed25519 block votes using batch verification
            if !ed25519_votes.is_empty() {
                let messages: Vec<&[u8]> =
                    ed25519_votes.iter().map(|(_, _, m)| m.as_slice()).collect();
                let signatures: Vec<Signature> = ed25519_votes
                    .iter()
                    .map(|(v, _, _)| v.signature.clone())
                    .collect();
                let pubkeys: Vec<PublicKey> =
                    ed25519_votes.iter().map(|(_, pk, _)| pk.clone()).collect();

                let batch_valid =
                    PublicKey::batch_verify_ed25519(&messages, &signatures, &pubkeys);

                if batch_valid {
                    for (vote, _, _) in ed25519_votes {
                        event_tx
                            .send(Event::VoteSignatureVerified { vote, valid: true })
                            .expect("callback channel closed - Loss of this event would cause a deadlock");
                    }
                } else {
                    // Fallback to individual verification to find which ones failed
                    for (vote, pk, msg) in ed25519_votes {
                        let valid = pk.verify(&msg, &vote.signature);
                        if !valid {
                            crate::metrics::record_signature_verification_failure();
                        }
                        event_tx
                            .send(Event::VoteSignatureVerified { vote, valid })
                            .expect("callback channel closed - Loss of this event would cause a deadlock");
                    }
                }
            }

            // Process BLS block votes using same-message batch verification.
            // Votes for the same block (same height, round, block_hash) share the same signing
            // message, so we can use aggregate signature verification: O(1) pairings instead of O(n).
            // This is a significant optimization during consensus when multiple validators
            // vote on the same block.
            if !bls_votes.is_empty() {
                use std::collections::HashMap;

                // Group votes by signing message (votes for same block have same message)
                let mut by_message: HashMap<Vec<u8>, Vec<(BlockVote, PublicKey)>> = HashMap::new();
                for (vote, pk, msg) in bls_votes {
                    by_message.entry(msg).or_default().push((vote, pk));
                }

                for (message, votes_for_block) in by_message {
                    if votes_for_block.len() >= 2 {
                        // Use same-message batch verification (aggregate signatures)
                        let signatures: Vec<Signature> = votes_for_block
                            .iter()
                            .map(|(v, _)| v.signature.clone())
                            .collect();
                        let pubkeys: Vec<PublicKey> = votes_for_block
                            .iter()
                            .map(|(_, pk)| pk.clone())
                            .collect();

                        let batch_valid = PublicKey::batch_verify_bls_same_message(
                            &message,
                            &signatures,
                            &pubkeys,
                        );

                        if batch_valid {
                            for (vote, _) in votes_for_block {
                                event_tx
                                    .send(Event::VoteSignatureVerified { vote, valid: true })
                                    .expect("callback channel closed");
                            }
                        } else {
                            // Batch failed - fall back to individual verification to find bad ones
                            for (vote, pk) in votes_for_block {
                                let valid = pk.verify(&message, &vote.signature);
                                if !valid {
                                    crate::metrics::record_signature_verification_failure();
                                }
                                event_tx
                                    .send(Event::VoteSignatureVerified { vote, valid })
                                    .expect("callback channel closed");
                            }
                        }
                    } else {
                        // Single vote for this block - verify individually
                        let (vote, pk) = votes_for_block.into_iter().next().unwrap();
                        let valid = pk.verify(&message, &vote.signature);
                        if !valid {
                            crate::metrics::record_signature_verification_failure();
                        }
                        event_tx
                            .send(Event::VoteSignatureVerified { vote, valid })
                            .expect("callback channel closed");
                    }
                }
            }

            crate::metrics::record_signature_verification_latency(
                "block_vote",
                start.elapsed().as_secs_f64(),
            );

            if batch_size > 1 {
                tracing::debug!(
                    batch_size,
                    "Batch verified block vote signatures"
                );
            }
        });
    }

    /// Dispatch state vote verifications to the crypto thread pool.
    ///
    /// State votes use a longer batching window (20ms) than block votes since they
    /// are less latency-sensitive - they don't block consensus progress, only
    /// cross-shard certificate formation. The longer window allows more signatures
    /// to accumulate for better batch verification throughput.
    ///
    /// Results are sent back as individual events to maintain compatibility
    /// with the state machine's expectations.
    fn dispatch_state_vote_verifications(&self, votes: Vec<(StateVoteBlock, PublicKey)>) {
        if votes.is_empty() {
            return;
        }

        let event_tx = self.callback_tx.clone();
        let batch_size = votes.len();

        self.thread_pools.spawn_crypto(move || {
            let start = std::time::Instant::now();

            // Build signing messages for state votes (must match ExecutionState::create_vote)
            let votes_with_msgs: Vec<(StateVoteBlock, PublicKey, Vec<u8>)> = votes
                .into_iter()
                .map(|(vote, pk)| {
                    let mut msg = Vec::with_capacity(9 + 32 + 32 + 8 + 1); // Pre-allocate exact size
                    msg.extend_from_slice(b"EXEC_VOTE");
                    msg.extend_from_slice(vote.transaction_hash.as_bytes());
                    msg.extend_from_slice(vote.state_root.as_bytes());
                    msg.extend_from_slice(&vote.shard_group_id.0.to_le_bytes());
                    msg.push(if vote.success { 1 } else { 0 });
                    (vote, pk, msg)
                })
                .collect();

            let mut ed25519_votes: Vec<(StateVoteBlock, PublicKey, Vec<u8>)> = Vec::new();
            let mut bls_votes: Vec<(StateVoteBlock, PublicKey, Vec<u8>)> = Vec::new();

            for (vote, pk, msg) in votes_with_msgs {
                match &pk {
                    PublicKey::Ed25519(_) => ed25519_votes.push((vote, pk, msg)),
                    PublicKey::Bls12381(_) => bls_votes.push((vote, pk, msg)),
                }
            }

            // Process Ed25519 state votes using batch verification
            if !ed25519_votes.is_empty() {
                let messages: Vec<&[u8]> =
                    ed25519_votes.iter().map(|(_, _, m)| m.as_slice()).collect();
                let signatures: Vec<Signature> = ed25519_votes
                    .iter()
                    .map(|(v, _, _)| v.signature.clone())
                    .collect();
                let pubkeys: Vec<PublicKey> =
                    ed25519_votes.iter().map(|(_, pk, _)| pk.clone()).collect();

                let batch_valid =
                    PublicKey::batch_verify_ed25519(&messages, &signatures, &pubkeys);

                if batch_valid {
                    for (vote, _, _) in ed25519_votes {
                        event_tx
                            .send(Event::StateVoteSignatureVerified { vote, valid: true })
                            .expect("callback channel closed - Loss of this event would cause a deadlock");
                    }
                } else {
                    for (vote, pk, msg) in ed25519_votes {
                        let valid = pk.verify(&msg, &vote.signature);
                        if !valid {
                            crate::metrics::record_signature_verification_failure();
                        }
                        event_tx
                            .send(Event::StateVoteSignatureVerified { vote, valid })
                            .expect("callback channel closed - Loss of this event would cause a deadlock");
                    }
                }
            }

            // Process BLS state votes using blst's native batch verification.
            // Uses random linear combination to batch verify different messages efficiently.
            // The longer batching window (20ms) means we typically have larger batches here,
            // making batch verification more beneficial.
            if !bls_votes.is_empty() {
                let messages: Vec<&[u8]> =
                    bls_votes.iter().map(|(_, _, m)| m.as_slice()).collect();
                let signatures: Vec<Signature> = bls_votes
                    .iter()
                    .map(|(v, _, _)| v.signature.clone())
                    .collect();
                let pubkeys: Vec<PublicKey> =
                    bls_votes.iter().map(|(_, pk, _)| pk.clone()).collect();

                let results = PublicKey::batch_verify_bls_different_messages(
                    &messages,
                    &signatures,
                    &pubkeys,
                );

                for ((vote, _, _), valid) in bls_votes.into_iter().zip(results) {
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    event_tx
                        .send(Event::StateVoteSignatureVerified { vote, valid })
                        .expect("callback channel closed - Loss of this event would cause a deadlock");
                }
            }

            crate::metrics::record_signature_verification_latency(
                "state_vote",
                start.elapsed().as_secs_f64(),
            );

            if batch_size > 1 {
                tracing::debug!(
                    batch_size,
                    "Batch verified state vote signatures (20ms window)"
                );
            }
        });
    }

    /// Dispatch state certificate verifications to the crypto thread pool.
    ///
    /// State certificates contain aggregated BLS signatures that are expensive to verify.
    /// By batching them with a 15ms window, we can use BLS batch verification which is
    /// ~40% faster than individual verification. This is the highest volume crypto operation.
    ///
    /// The verification process:
    /// 1. For each certificate, aggregate signer public keys based on bitfield (parallel with rayon)
    /// 2. Batch verify all (aggregated_pk, message, aggregated_sig) tuples
    /// 3. Send individual results back as events
    fn dispatch_state_cert_verifications(
        &self,
        certs: Vec<(hyperscale_types::StateCertificate, Vec<PublicKey>)>,
    ) {
        if certs.is_empty() {
            return;
        }

        let event_tx = self.callback_tx.clone();
        let batch_size = certs.len();

        self.thread_pools.spawn_crypto(move || {
            use rayon::prelude::*;

            let start = std::time::Instant::now();

            // Step 1: Pre-process certificates in parallel - aggregate signer keys and build messages
            // This is the expensive part that benefits from parallelization
            let prepared: Vec<_> = certs
                .into_par_iter()
                .map(|(cert, public_keys)| {
                    let msg = cert.signing_message();

                    // Get signer keys based on bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| cert.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    // Pre-aggregate the public keys
                    let aggregated_pk = if signer_keys.is_empty() {
                        None // Will check for zero signature
                    } else {
                        PublicKey::aggregate_bls(&signer_keys).ok()
                    };

                    (cert, msg, aggregated_pk)
                })
                .collect();

            // Step 2: Batch verify all signatures
            // Separate into verifiable (have aggregated_pk) and special cases (empty signers)
            let mut verifiable: Vec<(hyperscale_types::StateCertificate, Vec<u8>, PublicKey)> =
                Vec::new();
            let mut zero_sig_certs: Vec<hyperscale_types::StateCertificate> = Vec::new();
            let mut failed_aggregation: Vec<hyperscale_types::StateCertificate> = Vec::new();

            for (cert, msg, maybe_pk) in prepared {
                match maybe_pk {
                    Some(pk) => verifiable.push((cert, msg, pk)),
                    None => {
                        // No signers - check if it's a valid zero signature case
                        if cert.aggregated_signature == Signature::zero() {
                            zero_sig_certs.push(cert);
                        } else {
                            failed_aggregation.push(cert);
                        }
                    }
                }
            }

            // Batch verify the aggregated signatures
            let verification_results = if !verifiable.is_empty() {
                let messages: Vec<&[u8]> =
                    verifiable.iter().map(|(_, m, _)| m.as_slice()).collect();
                let signatures: Vec<Signature> = verifiable
                    .iter()
                    .map(|(c, _, _)| c.aggregated_signature.clone())
                    .collect();
                let pubkeys: Vec<PublicKey> =
                    verifiable.iter().map(|(_, _, pk)| pk.clone()).collect();

                PublicKey::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys)
            } else {
                vec![]
            };

            // Step 3: Send results
            // Verified certs
            for ((cert, _, _), valid) in verifiable.into_iter().zip(verification_results) {
                if !valid {
                    crate::metrics::record_signature_verification_failure();
                }
                let _ = event_tx.send(Event::StateCertificateSignatureVerified {
                    certificate: cert,
                    valid,
                });
            }

            // Zero signature certs (valid)
            for cert in zero_sig_certs {
                let _ = event_tx.send(Event::StateCertificateSignatureVerified {
                    certificate: cert,
                    valid: true,
                });
            }

            // Failed aggregation certs (invalid)
            for cert in failed_aggregation {
                crate::metrics::record_signature_verification_failure();
                let _ = event_tx.send(Event::StateCertificateSignatureVerified {
                    certificate: cert,
                    valid: false,
                });
            }

            crate::metrics::record_signature_verification_latency(
                "state_cert",
                start.elapsed().as_secs_f64(),
            );

            if batch_size > 1 {
                tracing::debug!(
                    batch_size,
                    "Batch verified state cert signatures (15ms window)"
                );
            }
        });
    }

    /// Dispatch cross-shard executions to the execution thread pool.
    ///
    /// Executes all transactions in parallel using rayon's par_iter for maximum throughput.
    /// Each transaction is executed with its provisioned state from other shards.
    /// After execution, signs votes and broadcasts + sends to state machine directly,
    /// avoiding a round-trip through the state machine for signing.
    fn dispatch_cross_shard_executions(
        &self,
        requests: Vec<hyperscale_core::CrossShardExecutionRequest>,
    ) {
        if requests.is_empty() {
            return;
        }

        let event_tx = self.callback_tx.clone();
        let dispatch_tx = self.dispatch_tx.clone();
        let storage = self.storage.clone();
        let executor = self.executor.clone();
        let topology = self.topology.clone();
        let local_shard = self.local_shard;
        let thread_pools = self.thread_pools.clone();
        let batch_size = requests.len();
        let signing_key = self.signing_key.clone();
        let validator_id = topology.local_validator_id();

        self.thread_pools.spawn_execution(move || {
            let start = std::time::Instant::now();

            // Execute all transactions in parallel using rayon.
            // Each transaction gets its own storage snapshot for isolated execution.
            // RocksDB snapshots are thread-safe and support concurrent reads.
            let results: Vec<hyperscale_types::ExecutionResult> =
                thread_pools.execution_pool().install(|| {
                    use rayon::prelude::*;
                    requests
                        .par_iter()
                        .map(|req| {
                            // Determine which nodes are local to this shard
                            let is_local_node =
                                |node_id: &hyperscale_types::NodeId| -> bool {
                                    topology.shard_for_node_id(node_id) == local_shard
                                };

                            match executor.execute_cross_shard(
                                &*storage,
                                std::slice::from_ref(&req.transaction),
                                &req.provisions,
                                is_local_node,
                            ) {
                                Ok(output) => {
                                    if let Some(r) = output.results().first() {
                                        hyperscale_types::ExecutionResult {
                                            transaction_hash: r.tx_hash,
                                            success: r.success,
                                            state_root: r.outputs_merkle_root,
                                            writes: r.state_writes.clone(),
                                            error: r.error.clone(),
                                        }
                                    } else {
                                        hyperscale_types::ExecutionResult {
                                            transaction_hash: req.tx_hash,
                                            success: false,
                                            state_root: hyperscale_types::Hash::ZERO,
                                            writes: vec![],
                                            error: Some("No execution result".to_string()),
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(tx_hash = ?req.tx_hash, error = %e, "Cross-shard execution failed");
                                    hyperscale_types::ExecutionResult {
                                        transaction_hash: req.tx_hash,
                                        success: false,
                                        state_root: hyperscale_types::Hash::ZERO,
                                        writes: vec![],
                                        error: Some(format!("{}", e)),
                                    }
                                }
                            }
                        })
                        .collect()
                });

            crate::metrics::record_execution_latency(start.elapsed().as_secs_f64());

            if batch_size > 1 {
                tracing::debug!(
                    batch_size,
                    "Batch executed cross-shard transactions (5ms window)"
                );
            }

            // Sign votes for each execution result. The runner handles:
            // 1. Signing (done here)
            // 2. Broadcasting (via dispatch_tx)
            // 3. Local handling (via StateVoteReceived to state machine)
            for result in results {
                let message = hyperscale_types::exec_vote_message(
                    &result.transaction_hash,
                    &result.state_root,
                    local_shard,
                    result.success,
                );
                let signature = signing_key.sign(&message);

                let vote = StateVoteBlock {
                    transaction_hash: result.transaction_hash,
                    shard_group_id: local_shard,
                    state_root: result.state_root,
                    success: result.success,
                    validator: validator_id,
                    signature,
                };

                // Broadcast to shard peers via message batcher
                let _ = dispatch_tx.send(DispatchableAction::QueueStateVote {
                    shard: local_shard,
                    vote: vote.clone(),
                });

                // Send to state machine for local handling (skips verification for own votes)
                event_tx
                    .send(Event::StateVoteReceived { vote })
                    .expect("callback channel closed - Loss of this event would cause a deadlock");
            }
        });
    }

    /// Persist a verified gossiped certificate and notify the state machine.
    ///
    /// Called after all StateCertificate signatures in a gossiped TransactionCertificate
    /// have been verified. Persists to storage and sends GossipedCertificateVerified
    /// to the state machine to cancel local certificate building.
    fn persist_and_notify_gossiped_certificate(&self, certificate: TransactionCertificate) {
        let storage = self.storage.clone();
        let local_shard = self.local_shard;
        let callback_tx = self.callback_tx.clone();

        // Extract writes for local shard
        let writes: Vec<_> = certificate
            .shard_proofs
            .get(&local_shard)
            .map(|c| c.state_writes.clone())
            .unwrap_or_default();

        let cert_for_persist = certificate.clone();

        // Fire-and-forget persist (don't block event loop)
        tokio::task::spawn_blocking(move || {
            storage.commit_certificate_with_writes(&cert_for_persist, &writes);
        });

        // Notify state machine to cancel local building and add to finalized
        let _ = callback_tx.send(Event::GossipedCertificateVerified { certificate });
    }

    /// Submit a transaction.
    ///
    /// The transaction is gossiped to all relevant shards and then submitted
    /// to the validation batcher for crypto verification. The transaction status
    /// can be queried via the RPC status cache.
    pub async fn submit_transaction(&mut self, tx: RoutableTransaction) -> Result<(), RunnerError> {
        let tx = std::sync::Arc::new(tx);

        // Gossip to all relevant shards first
        let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(&tx));
        for shard in self.topology.all_shards_for_transaction(&tx) {
            let mut message = OutboundMessage::TransactionGossip(Box::new(gossip.clone()));
            message.inject_trace_context();
            if let Err(e) = self.network.broadcast_shard(shard, &message).await {
                tracing::warn!(
                    ?shard,
                    error = ?e,
                    "Failed to gossip transaction to shard"
                );
            }
        }

        // Submit to batcher for validation
        self.tx_validation_handle.submit(tx);
        Ok(())
    }

    /// Handle an inbound sync request from a peer.
    ///
    /// Looks up the requested block from denormalized storage (reconstructing from
    /// block metadata + transactions + certificates) and sends the response.
    ///
    /// The storage read is performed on a blocking thread pool to avoid blocking
    /// the main event loop. RocksDB reads for large blocks can take several ms.
    ///
    /// Response format: `(Option<Block>, Option<QC>, Option<BlockMetadata>)`
    /// - `(Some(block), Some(qc), None)` = complete block with all data
    /// - `(None, None, Some(metadata))` = metadata only (txs/certs must be fetched)
    /// - `(None, None, None)` = block not found at this height
    fn handle_inbound_sync_request(&self, request: InboundSyncRequest) {
        let storage = self.storage.clone();
        let network = self.network.clone();

        // Spawn on blocking thread pool to avoid blocking the main event loop.
        // RocksDB reads are synchronous I/O that can take ms for large blocks.
        tokio::task::spawn_blocking(move || {
            use crate::storage::SyncBlockData;

            let height = BlockHeight(request.height);
            let channel_id = request.channel_id;

            tracing::debug!(
                peer = %request.peer,
                height = request.height,
                channel_id = channel_id,
                "Handling inbound sync request"
            );

            // Look up block from storage - returns Complete, MetadataOnly, or None
            let response = match storage.get_block_for_sync(height) {
                Some(SyncBlockData::Complete(block, qc)) => {
                    // Full block available - encode as (Some(block), Some(qc), None)
                    match sbor::basic_encode(&(Some(&block), Some(&qc), None::<BlockMetadata>)) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::warn!(height = request.height, error = ?e, "Failed to encode block response");
                            sbor::basic_encode(&(
                                None::<Block>,
                                None::<QuorumCertificate>,
                                None::<BlockMetadata>,
                            ))
                            .unwrap_or_default()
                        }
                    }
                }
                Some(SyncBlockData::MetadataOnly(metadata)) => {
                    // Metadata only - encode as (None, None, Some(metadata))
                    tracing::debug!(
                        height = request.height,
                        tx_count = metadata.tx_hashes.len(),
                        cert_count = metadata.cert_hashes.len(),
                        "Returning metadata-only sync response"
                    );
                    match sbor::basic_encode(&(
                        None::<Block>,
                        None::<QuorumCertificate>,
                        Some(&metadata),
                    )) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::warn!(height = request.height, error = ?e, "Failed to encode metadata response");
                            sbor::basic_encode(&(
                                None::<Block>,
                                None::<QuorumCertificate>,
                                None::<BlockMetadata>,
                            ))
                            .unwrap_or_default()
                        }
                    }
                }
                None => {
                    tracing::trace!(height = request.height, "Block not found for sync request");
                    // Not found - encode as (None, None, None)
                    sbor::basic_encode(&(
                        None::<Block>,
                        None::<QuorumCertificate>,
                        None::<BlockMetadata>,
                    ))
                    .unwrap_or_default()
                }
            };

            // Send response via network adapter
            if let Err(e) = network.send_block_response(channel_id, response) {
                tracing::warn!(
                    height = request.height,
                    channel_id = channel_id,
                    error = ?e,
                    "Failed to send block response"
                );
            }
        });
    }

    // NOTE: handle_inbound_transaction_request and handle_inbound_certificate_request
    // are now handled by the dedicated fetch handler task in fetch_handler.rs,
    // which reads directly from RocksDB storage for reliable access to historical data.

    /// Dispatch an event to the state machine.
    ///
    /// All events are now passed directly to the state machine. Runner I/O requests
    /// (sync, transaction fetch, certificate fetch) are now Actions emitted by the
    /// state machine and handled in process_action().
    async fn dispatch_event(&mut self, event: Event) -> Vec<Action> {
        self.state.handle(event)
    }
}

/// Verify a StateCertificate's aggregated BLS signature.
///
/// This is the same verification logic used for fetched certificates and gossiped
/// certificates. Checks that the aggregated signature from the signers bitfield
/// matches the signing message.
fn verify_state_certificate_signature(
    certificate: &hyperscale_types::StateCertificate,
    public_keys: &[PublicKey],
) -> bool {
    let msg = certificate.signing_message();

    // Get signer keys based on bitfield
    let signer_keys: Vec<_> = public_keys
        .iter()
        .enumerate()
        .filter(|(i, _)| certificate.signers.is_set(*i))
        .map(|(_, pk)| pk.clone())
        .collect();

    if signer_keys.is_empty() {
        // No signers - valid only if zero signature (single-validator or genesis case)
        certificate.aggregated_signature == Signature::zero()
    } else {
        // Verify aggregated BLS signature
        match PublicKey::aggregate_bls(&signer_keys) {
            Ok(aggregated_pk) => aggregated_pk.verify(&msg, &certificate.aggregated_signature),
            Err(_) => false,
        }
    }
}
