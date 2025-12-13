//! Production runner implementation.

use crate::network::{
    compute_peer_id_for_validator, InboundSyncRequest, InboundTransactionRequest, Libp2pAdapter,
    Libp2pConfig, NetworkError,
};
use crate::rpc::{MempoolSnapshot, NodeStatusState, TransactionStatusCache};
use crate::storage::RocksDbStorage;
use crate::sync::{SyncConfig, SyncManager};
use crate::thread_pools::ThreadPoolManager;
use crate::timers::TimerManager;
use hyperscale_bft::BftConfig;
use hyperscale_engine::{NetworkDefinition, RadixExecutor};
use hyperscale_types::BlockHeight;

use hyperscale_core::{Action, Event, StateMachine};
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    Block, BlockHeader, BlockVote, Hash, KeyPair, PublicKey, QuorumCertificate,
    RoutableTransaction, ShardGroupId, Signature, StateVoteBlock, Topology, ValidatorId,
    ViewChangeVote,
};
use libp2p::identity;
use parking_lot::RwLock;
use sbor::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock as TokioRwLock;
use tokio::sync::{mpsc, oneshot};
use tracing::{instrument, span, Level, Span};

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

/// Pending signature verifications that can be batched.
///
/// Collects verification actions and processes them together using
/// batch verification for better performance (2-8x speedup for large batches).
#[derive(Default)]
struct PendingVerifications {
    /// Block votes waiting for verification (public key and signing message included).
    block_votes: Vec<(BlockVote, PublicKey, Vec<u8>)>,
    /// View change votes waiting for verification.
    view_change_votes: Vec<(ViewChangeVote, PublicKey, Vec<u8>)>,
    /// State votes waiting for verification (cross-shard execution).
    state_votes: Vec<(StateVoteBlock, PublicKey)>,
}

impl PendingVerifications {
    fn is_empty(&self) -> bool {
        self.block_votes.is_empty()
            && self.view_change_votes.is_empty()
            && self.state_votes.is_empty()
    }

    fn total_count(&self) -> usize {
        self.block_votes.len() + self.view_change_votes.len() + self.state_votes.len()
    }
}

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
/// use parking_lot::RwLock;
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
///     .storage(Arc::new(RwLock::new(storage)))
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
    storage: Option<Arc<RwLock<RocksDbStorage>>>,
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
    pub fn storage(mut self, storage: Arc<RwLock<RocksDbStorage>>) -> Self {
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
        // - consensus_tx/rx: High priority BFT events (votes, proposals, QCs, timers)
        // - transaction_tx/rx: Transaction ingestion (gossip, submissions)
        // - status_tx/rx: Transaction status updates (non-consensus-critical)
        // This prevents transaction floods from starving consensus events
        let (consensus_tx, consensus_rx) = mpsc::channel(self.channel_capacity);
        let (transaction_tx, transaction_rx) = mpsc::channel(self.channel_capacity);
        let (status_tx, status_rx) = mpsc::channel(self.channel_capacity);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let validator_id = topology.local_validator_id();
        let local_shard = topology.local_shard();

        // Load RecoveredState from storage for crash recovery
        let recovered = {
            let storage_guard = storage.read();
            storage_guard.load_recovered_state()
        };

        // NodeIndex is a simulation concept - production uses 0
        let state = NodeStateMachine::new(
            0, // node_index not meaningful in production
            topology.clone(),
            signing_key,
            bft_config,
            recovered,
        );
        let timer_manager = TimerManager::new(consensus_tx.clone());

        // Use configured network definition or default to simulator
        let network_definition = self
            .network_definition
            .unwrap_or_else(NetworkDefinition::simulator);

        // Create transaction validator for signature verification
        let tx_validator = Arc::new(hyperscale_engine::TransactionValidation::new(
            network_definition.clone(),
        ));

        // Create network adapter with transaction validation
        // Pass both channels - consensus for BFT messages, transaction for mempool
        let (network, sync_request_rx, tx_request_rx) = Libp2pAdapter::new(
            network_config,
            ed25519_keypair,
            validator_id,
            local_shard,
            consensus_tx.clone(),
            transaction_tx.clone(),
            tx_validator.clone(),
        )
        .await?;

        // Subscribe to local shard topics
        network.subscribe_shard(local_shard).await?;

        // Register known validators for peer validation
        // This allows us to validate that messages come from known validators
        for &validator_id in topology.local_committee().iter() {
            if let Some(public_key) = topology.public_key(validator_id) {
                let peer_id = compute_peer_id_for_validator(&public_key);
                network.register_validator(validator_id, peer_id).await;
            }
        }

        // Create sync manager (uses consensus channel for sync events)
        let sync_manager =
            SyncManager::new(SyncConfig::default(), network.clone(), consensus_tx.clone());

        // Create executor
        let executor = Arc::new(RadixExecutor::new(network_definition));

        Ok(ProductionRunner {
            consensus_rx,
            consensus_tx,
            transaction_rx,
            transaction_tx,
            status_rx,
            status_tx,
            state,
            start_time: Instant::now(),
            thread_pools,
            timer_manager,
            network,
            sync_manager,
            local_shard,
            topology,
            storage,
            executor,
            tx_validator,
            rpc_status: self.rpc_status,
            tx_status_cache: self.tx_status_cache,
            mempool_snapshot: self.mempool_snapshot,
            genesis_config: self.genesis_config,
            sync_request_rx,
            tx_request_rx,
            shutdown_rx,
            shutdown_tx: Some(shutdown_tx),
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
    /// Receives high-priority consensus events (BFT, timers, internal callbacks).
    consensus_rx: mpsc::Receiver<Event>,
    /// Clone this to send consensus events from timers, verification callbacks, etc.
    consensus_tx: mpsc::Sender<Event>,
    /// Receives low-priority transaction events (submissions, gossip).
    transaction_rx: mpsc::Receiver<Event>,
    /// Clone this to send transaction events (used by submit_transaction).
    transaction_tx: mpsc::Sender<Event>,
    /// Receives background status events (TransactionStatusChanged, TransactionExecuted).
    /// These are non-consensus-critical and processed opportunistically.
    status_rx: mpsc::Receiver<Event>,
    /// Clone this to send status events.
    status_tx: mpsc::Sender<Event>,
    /// The state machine (owned, not shared).
    state: NodeStateMachine,
    /// Start time for calculating elapsed duration.
    start_time: Instant,
    /// Thread pool manager for crypto and execution workloads.
    thread_pools: Arc<ThreadPoolManager>,
    /// Timer manager for setting/cancelling timers.
    timer_manager: TimerManager,
    /// Network adapter for libp2p communication.
    network: Arc<Libp2pAdapter>,
    /// Sync manager for fetching blocks from peers.
    sync_manager: SyncManager,
    /// Local shard for network broadcasts.
    local_shard: ShardGroupId,
    /// Network topology (needed for cross-shard execution).
    topology: Arc<dyn Topology>,
    /// Block storage for persistence and crash recovery.
    storage: Arc<RwLock<RocksDbStorage>>,
    /// Transaction executor.
    executor: Arc<RadixExecutor>,
    /// Transaction validator for signature verification.
    tx_validator: Arc<hyperscale_engine::TransactionValidation>,
    /// Optional RPC status state to update on block commits.
    rpc_status: Option<Arc<TokioRwLock<NodeStatusState>>>,
    /// Optional transaction status cache for RPC queries.
    tx_status_cache: Option<Arc<TokioRwLock<TransactionStatusCache>>>,
    /// Optional mempool snapshot for RPC queries.
    mempool_snapshot: Option<Arc<TokioRwLock<MempoolSnapshot>>>,
    /// Optional genesis configuration for initial state.
    genesis_config: Option<hyperscale_engine::GenesisConfig>,
    /// Inbound sync request channel (from network adapter).
    sync_request_rx: mpsc::Receiver<InboundSyncRequest>,
    /// Inbound transaction fetch request channel (from network adapter).
    tx_request_rx: mpsc::Receiver<InboundTransactionRequest>,
    /// Shutdown signal receiver.
    shutdown_rx: oneshot::Receiver<()>,
    /// Shutdown handle sender (stored to return to caller).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ProductionRunner {
    /// Create a new builder for constructing a production runner.
    ///
    /// All fields are required - see [`ProductionRunnerBuilder`] for details.
    pub fn builder() -> ProductionRunnerBuilder {
        ProductionRunnerBuilder::new()
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

    /// Get a sender for submitting events.
    pub fn event_sender(&self) -> mpsc::Sender<Event> {
        self.consensus_tx.clone()
    }

    /// Get the transaction validator for signature verification.
    pub fn tx_validator(&self) -> Arc<hyperscale_engine::TransactionValidation> {
        self.tx_validator.clone()
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
        let has_blocks = {
            let storage = self.storage.read();
            let (height, _, _) = storage.get_chain_metadata();
            height.0 > 0
        };

        if has_blocks {
            tracing::info!("Existing blocks found, skipping genesis initialization");
            return;
        }

        tracing::info!(
            shard = ?self.local_shard,
            "No committed blocks - initializing genesis"
        );

        // Run Radix Engine genesis to set up initial state
        {
            let mut storage = self.storage.write();
            let result = if let Some(config) = self.genesis_config.take() {
                tracing::info!(
                    xrd_balances = config.xrd_balances.len(),
                    "Running genesis with custom configuration"
                );
                self.executor.run_genesis_with_config(&mut *storage, config)
            } else {
                self.executor.run_genesis(&mut *storage)
            };
            if let Err(e) = result {
                tracing::warn!(error = ?e, "Radix Engine genesis failed (may be OK for testing)");
            }
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
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
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
    /// Consensus events (from gossipsub) are prioritized over sync requests:
    /// - Uses `biased` select to always check consensus channel first
    /// - Drains up to `CONSENSUS_BATCH_SIZE` events before checking sync
    /// - Ensures consensus stays responsive under sync load
    pub async fn run(mut self) -> Result<(), RunnerError> {
        // Maximum consensus events to process before checking sync (10:1 ratio)
        const CONSENSUS_BATCH_SIZE: usize = 10;

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

        // Track consecutive consensus events for batch limiting
        let mut consensus_batch_count: usize = 0;

        loop {
            // Use biased select for priority: consensus events are always checked first.
            // After CONSENSUS_BATCH_SIZE events, we yield to lower-priority work.
            // Transaction events are processed only when consensus channel is empty.
            tokio::select! {
                biased;

                // SHUTDOWN: Always check shutdown first (highest priority)
                _ = &mut self.shutdown_rx => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // HIGH PRIORITY: Handle incoming consensus events (BFT, timers, internal)
                // Only check this branch if we haven't hit the batch limit
                event = self.consensus_rx.recv(), if consensus_batch_count < CONSENSUS_BATCH_SIZE => {
                    match event {
                        Some(event) => {
                            consensus_batch_count += 1;

                            // Create span for event handling
                            let event_type = event.type_name();
                            let event_span = span!(
                                Level::INFO,
                                "handle_event",
                                event.type = %event_type,
                                node = self.state.node_index(),
                                shard = ?self.state.shard(),
                                otel.kind = "INTERNAL",
                            );
                            let _event_guard = event_span.enter();

                            // Update time
                            let now = self.start_time.elapsed();
                            self.state.set_time(now);

                            // Check for SyncNeeded - handle specially
                            let sync_target = if let Event::SyncNeeded { target_height, target_hash } = &event {
                                Some((*target_height, *target_hash))
                            } else {
                                None
                            };

                            // Check for TransactionFetchNeeded - handle specially
                            let tx_fetch_info = if let Event::TransactionFetchNeeded {
                                block_hash,
                                proposer,
                                missing_tx_hashes,
                            } = &event
                            {
                                Some((*block_hash, *proposer, missing_tx_hashes.clone()))
                            } else {
                                None
                            };

                            // Process event synchronously (fast)
                            let actions = {
                                let sm_span = span!(Level::DEBUG, "state_machine.handle");
                                let _sm_guard = sm_span.enter();
                                self.state.handle(event)
                            };

                            // Record action count
                            Span::current().record("actions.count", actions.len());

                            if !actions.is_empty() {
                                tracing::info!(
                                    event_type = %event_type,
                                    num_actions = actions.len(),
                                    "Event produced actions"
                                );
                            }

                            // Collect signature verifications for batching, process others immediately
                            let mut pending = PendingVerifications::default();

                            for action in actions {
                                match action {
                                    Action::VerifyVoteSignature { vote, public_key, signing_message } => {
                                        pending.block_votes.push((vote, public_key, signing_message));
                                    }
                                    Action::VerifyViewChangeVoteSignature { vote, public_key, signing_message } => {
                                        pending.view_change_votes.push((vote, public_key, signing_message));
                                    }
                                    Action::VerifyStateVoteSignature { vote, public_key } => {
                                        pending.state_votes.push((vote, public_key));
                                    }
                                    other => {
                                        if let Err(e) = self.process_action(other).await {
                                            tracing::error!(error = ?e, "Error processing action");
                                        }
                                    }
                                }
                            }

                            // Try to collect more verifications from queued consensus events
                            // This drains any immediately available events to maximize batch size
                            while let Ok(more_event) = self.consensus_rx.try_recv() {
                                consensus_batch_count += 1;

                                // Update time for each event
                                let now = self.start_time.elapsed();
                                self.state.set_time(now);

                                let more_actions = self.state.handle(more_event);

                                for action in more_actions {
                                    match action {
                                        Action::VerifyVoteSignature { vote, public_key, signing_message } => {
                                            pending.block_votes.push((vote, public_key, signing_message));
                                        }
                                        Action::VerifyViewChangeVoteSignature { vote, public_key, signing_message } => {
                                            pending.view_change_votes.push((vote, public_key, signing_message));
                                        }
                                        Action::VerifyStateVoteSignature { vote, public_key } => {
                                            pending.state_votes.push((vote, public_key));
                                        }
                                        other => {
                                            if let Err(e) = self.process_action(other).await {
                                                tracing::error!(error = ?e, "Error processing action");
                                            }
                                        }
                                    }
                                }

                                // Respect batch limit
                                if consensus_batch_count >= CONSENSUS_BATCH_SIZE {
                                    break;
                                }
                            }

                            // Dispatch collected verifications as batches
                            self.dispatch_batched_verifications(pending);

                            // If this was a sync request, start the sync manager
                            if let Some((target_height, target_hash)) = sync_target {
                                self.sync_manager.start_sync(target_height, target_hash);
                            }

                            // If this was a transaction fetch request, fetch from proposer
                            if let Some((block_hash, proposer, missing_tx_hashes)) = tx_fetch_info {
                                self.handle_transaction_fetch_needed(block_hash, proposer, missing_tx_hashes).await;
                            }
                        }
                        None => {
                            // Channel closed, exit loop
                            break;
                        }
                    }
                }

                // LOW PRIORITY: Handle transaction events (submissions, gossip)
                // Only processed when consensus channel is empty or after batch limit
                Some(event) = self.transaction_rx.recv() => {
                    let event_type = event.type_name();
                    let event_span = span!(
                        Level::INFO,
                        "handle_event",
                        event.type = %event_type,
                        node = self.state.node_index(),
                        shard = ?self.state.shard(),
                        otel.kind = "INTERNAL",
                    );
                    let _event_guard = event_span.enter();

                    // Update time
                    let now = self.start_time.elapsed();
                    self.state.set_time(now);

                    // Process transaction event
                    let actions = self.state.handle(event);

                    if !actions.is_empty() {
                        tracing::info!(
                            event_type = %event_type,
                            num_actions = actions.len(),
                            "Event produced actions"
                        );
                    }

                    for action in actions {
                        if let Err(e) = self.process_action(action).await {
                            tracing::error!(error = ?e, "Error processing action");
                        }
                    }

                    // Reset batch counter after processing transactions
                    consensus_batch_count = 0;
                }

                // HIGH PRIORITY: Handle inbound transaction fetch requests from peers
                // These are needed for active consensus, so process before sync
                Some(request) = self.tx_request_rx.recv() => {
                    let tx_span = span!(
                        Level::DEBUG,
                        "handle_tx_request",
                        peer = %request.peer,
                        block_hash = ?request.block_hash,
                        tx_count = request.tx_hashes.len(),
                        channel_id = request.channel_id,
                    );
                    let _tx_guard = tx_span.enter();

                    self.handle_inbound_transaction_request(request);
                    // Reset batch counter - we yielded, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }

                // LOW PRIORITY: Handle inbound sync requests from peers
                // This branch is checked when consensus is idle OR after batch limit hit
                Some(request) = self.sync_request_rx.recv() => {
                    let sync_span = span!(
                        Level::DEBUG,
                        "handle_sync_request",
                        peer = %request.peer,
                        height = request.height,
                        channel_id = request.channel_id,
                    );
                    let _sync_guard = sync_span.enter();

                    self.handle_inbound_sync_request(request);
                    // Reset batch counter - we yielded to sync, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }

                // MEDIUM PRIORITY: Periodic sync manager tick
                // This drives outbound sync fetches, so give it some priority
                _ = sync_tick.tick() => {
                    let tick_span = span!(Level::TRACE, "sync_tick");
                    let _tick_guard = tick_span.enter();

                    self.sync_manager.tick().await;
                    // Reset batch counter - we yielded, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }

                // LOW PRIORITY: Transaction status updates (non-consensus-critical)
                // These update mempool status for RPC queries but don't affect consensus
                Some(event) = self.status_rx.recv() => {
                    let event_type = event.type_name();
                    let event_span = span!(
                        Level::DEBUG,
                        "handle_status_event",
                        event.type = %event_type,
                    );
                    let _event_guard = event_span.enter();

                    // Update time
                    let now = self.start_time.elapsed();
                    self.state.set_time(now);

                    // Process status event (updates mempool state)
                    let actions = self.state.handle(event);

                    for action in actions {
                        if let Err(e) = self.process_action(action).await {
                            tracing::error!(error = ?e, "Error processing status action");
                        }
                    }

                    // Reset batch counter - we yielded, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }

                // LOW PRIORITY: Periodic metrics update (1 second)
                // IMPORTANT: This branch must NOT block on async operations to avoid
                // delaying consensus processing. Use non-blocking variants only.
                _ = metrics_tick.tick() => {
                    // Update thread pool queue depths (non-blocking)
                    crate::metrics::set_pool_queue_depths(
                        self.thread_pools.crypto_queue_depth(),
                        self.thread_pools.execution_queue_depth(),
                    );

                    // Update sync status (non-blocking)
                    crate::metrics::set_sync_status(
                        self.sync_manager.blocks_behind(),
                        self.sync_manager.is_syncing(),
                    );

                    // Update peer count using cached value (non-blocking)
                    // The cache is updated by the network event loop on connection changes
                    let peer_count = self.network.cached_peer_count();
                    crate::metrics::set_libp2p_peers(peer_count);

                    // Update RPC status with peer count (non-blocking: skip if contended)
                    if let Some(ref rpc_status) = self.rpc_status {
                        if let Ok(mut status) = rpc_status.try_write() {
                            status.connected_peers = peer_count;
                        }
                        // If lock is contended, skip this update - RPC is reading
                    }

                    // Update mempool snapshot for RPC queries (non-blocking: skip if contended)
                    if let Some(ref snapshot) = self.mempool_snapshot {
                        let stats = self.state.mempool().lock_contention_stats();
                        let total = self.state.mempool().len();
                        if let Ok(mut snap) = snapshot.try_write() {
                            snap.pending_count = stats.pending_count as usize;
                            snap.blocked_count = stats.blocked_count as usize;
                            // executing = total - pending - blocked (approximately)
                            snap.executing_count = total.saturating_sub(stats.pending_count as usize)
                                .saturating_sub(stats.blocked_count as usize);
                            snap.total_count = total;
                            snap.updated_at = Some(std::time::Instant::now());
                        }
                        // If lock is contended, skip this update - RPC is reading
                    }

                    // Reset batch counter - we yielded, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }
            }
        }

        tracing::info!("Production runner stopped");
        Ok(())
    }

    /// Process an action.
    #[instrument(skip(self), fields(action.type = %action.type_name()))]
    async fn process_action(&mut self, action: Action) -> Result<(), RunnerError> {
        match action {
            // Network I/O - broadcast via gossipsub topics
            Action::BroadcastToShard { shard, mut message } => {
                // Inject trace context for cross-shard messages (no-op if feature disabled)
                message.inject_trace_context();

                self.network.broadcast_shard(shard, &message).await?;
                tracing::debug!(?shard, msg_type = message.type_name(), "Broadcast to shard");
            }

            Action::BroadcastGlobal { mut message } => {
                // Inject trace context for cross-shard messages (no-op if feature disabled)
                message.inject_trace_context();

                self.network.broadcast_global(&message).await?;
                tracing::debug!(msg_type = message.type_name(), "Broadcast globally");
            }

            // Timers via timer manager
            Action::SetTimer { id, duration } => {
                self.timer_manager.set_timer(id, duration);
            }

            Action::CancelTimer { id } => {
                self.timer_manager.cancel_timer(id);
            }

            // Crypto verification on dedicated crypto thread pool
            Action::VerifyVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Verify vote signature against domain-separated message
                    let valid = public_key.verify(&signing_message, &vote.signature);
                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx.blocking_send(Event::VoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyProvisionSignature {
                provision,
                public_key,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Use centralized signing message (must match ExecutionState::sign_provision)
                    let msg = provision.signing_message();

                    let valid = public_key.verify(&msg, &provision.signature);
                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx
                        .blocking_send(Event::ProvisionSignatureVerified { provision, valid });
                });
            }

            Action::VerifyStateVoteSignature { vote, public_key } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Use centralized signing message (must match ExecutionState::create_vote)
                    let msg = vote.signing_message();

                    let valid = public_key.verify(&msg, &vote.signature);
                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ =
                        event_tx.blocking_send(Event::StateVoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Use centralized signing message - StateCertificates aggregate signatures
                    // from StateVoteBlocks, so they use the same EXEC_VOTE domain tag.
                    let msg = certificate.signing_message();

                    // Get signer keys based on bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| certificate.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        // No signers - valid only if zero signature (single-shard case)
                        certificate.aggregated_signature == hyperscale_types::Signature::zero()
                    } else {
                        // Verify aggregated BLS signature
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => {
                                aggregated_pk.verify(&msg, &certificate.aggregated_signature)
                            }
                            Err(_) => false,
                        }
                    };

                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx.blocking_send(Event::StateCertificateSignatureVerified {
                        certificate,
                        valid,
                    });
                });
            }

            Action::VerifyQcSignature {
                qc,
                public_keys,
                block_hash,
                signing_message,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
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
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ =
                        event_tx.blocking_send(Event::QcSignatureVerified { block_hash, valid });
                });
            }

            Action::VerifyViewChangeVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    let valid = public_key.verify(&signing_message, &vote.signature);
                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx
                        .blocking_send(Event::ViewChangeVoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyViewChangeHighestQc {
                vote,
                public_keys,
                signing_message,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Get signer keys based on the highest_qc's signer bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| vote.highest_qc.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        false
                    } else {
                        // Verify against domain-separated signing message
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => aggregated_pk
                                .verify(&signing_message, &vote.highest_qc.aggregated_signature),
                            Err(_) => false,
                        }
                    };

                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ =
                        event_tx.blocking_send(Event::ViewChangeHighestQcVerified { vote, valid });
                });
            }

            Action::VerifyViewChangeCertificateSignature {
                certificate,
                public_keys,
                signing_message,
            } => {
                let event_tx = self.consensus_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let start = std::time::Instant::now();
                    // Verify aggregated BLS signature on the view change certificate
                    // The public_keys are pre-filtered by the state machine based on the signer bitfield
                    let valid = if public_keys.is_empty() {
                        false
                    } else {
                        match hyperscale_types::PublicKey::aggregate_bls(&public_keys) {
                            Ok(aggregated_pk) => aggregated_pk
                                .verify(&signing_message, &certificate.aggregated_signature),
                            Err(_) => false,
                        }
                    };

                    crate::metrics::record_signature_verification_latency(
                        start.elapsed().as_secs_f64(),
                    );
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx.blocking_send(Event::ViewChangeCertificateSignatureVerified {
                        certificate,
                        valid,
                    });
                });
            }

            // Transaction execution on dedicated execution thread pool
            // NOTE: Execution is READ-ONLY. State writes are collected in the results
            // and committed later when TransactionCertificate is included in a block.
            Action::ExecuteTransactions {
                block_hash,
                transactions,
                state_root: _,
            } => {
                let event_tx = self.consensus_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();

                self.thread_pools.spawn_execution(move || {
                    // Execute transactions with READ lock - execution is read-only
                    let storage_guard = storage.read();
                    let results = match executor
                        .execute_single_shard(&*storage_guard, &transactions)
                    {
                        Ok(output) => output
                            .results()
                            .iter()
                            .map(|r| hyperscale_types::ExecutionResult {
                                transaction_hash: r.tx_hash,
                                success: r.success,
                                state_root: r.outputs_merkle_root,
                                writes: r.state_writes.clone(),
                                error: r.error.clone(),
                            })
                            .collect(),
                        Err(e) => {
                            tracing::warn!(?block_hash, error = %e, "Transaction execution failed");
                            transactions
                                .iter()
                                .map(|tx| hyperscale_types::ExecutionResult {
                                    transaction_hash: tx.hash(),
                                    success: false,
                                    state_root: hyperscale_types::Hash::ZERO,
                                    writes: vec![],
                                    error: Some(format!("{}", e)),
                                })
                                .collect()
                        }
                    };

                    let _ = event_tx.blocking_send(Event::TransactionsExecuted {
                        block_hash,
                        results,
                    });
                });
            }

            // Cross-shard transaction execution with provisions
            // NOTE: Execution is READ-ONLY. State writes are collected in the results
            // and committed later when TransactionCertificate is included in a block.
            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                let event_tx = self.consensus_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();
                let topology = self.topology.clone();
                let local_shard = self.local_shard;

                self.thread_pools.spawn_execution(move || {
                    // Determine which nodes are local to this shard
                    let is_local_node = |node_id: &hyperscale_types::NodeId| -> bool {
                        topology.shard_for_node_id(node_id) == local_shard
                    };

                    // Execute with provisions - READ lock since execution is read-only
                    let storage_guard = storage.read();
                    let result = match executor.execute_cross_shard(
                        &*storage_guard,
                        &[transaction],
                        &provisions,
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
                                    transaction_hash: tx_hash,
                                    success: false,
                                    state_root: hyperscale_types::Hash::ZERO,
                                    writes: vec![],
                                    error: Some("No execution result".to_string()),
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(?tx_hash, error = %e, "Cross-shard execution failed");
                            hyperscale_types::ExecutionResult {
                                transaction_hash: tx_hash,
                                success: false,
                                state_root: hyperscale_types::Hash::ZERO,
                                writes: vec![],
                                error: Some(format!("{}", e)),
                            }
                        }
                    };

                    let _ = event_tx
                        .blocking_send(Event::CrossShardTransactionExecuted { tx_hash, result });
                });
            }

            // Merkle computation on execution pool (can be parallelized internally)
            // Note: This action is currently not emitted by any state machine.
            Action::ComputeMerkleRoot { tx_hash, writes } => {
                let event_tx = self.consensus_tx.clone();

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
                    let _ = event_tx.blocking_send(Event::MerkleRootComputed { tx_hash, root });
                });
            }

            // Internal events are routed based on criticality:
            // - Status events (TransactionStatusChanged, TransactionExecuted) go to status channel
            // - All other internal events (QC formed, block committed, etc.) go to consensus channel
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
                    // Consensus-critical: route to consensus channel
                    self.consensus_tx
                        .send(event)
                        .await
                        .map_err(|e| RunnerError::SendError(e.to_string()))?;
                }
            }

            Action::EmitTransactionStatus { tx_hash, status } => {
                tracing::debug!(?tx_hash, ?status, "Transaction status update");

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
                let storage = self.storage.clone();
                let height = block.height();
                tokio::spawn(async move {
                    let guard = storage.write();
                    guard.put_block(height, &block, &qc);
                    // Update chain metadata
                    guard.set_chain_metadata(height, None, None);
                    // Prune old votes - we no longer need votes at or below committed height
                    guard.prune_own_votes(height.0);
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
                    .map(|p| p.state_writes.clone())
                    .unwrap_or_default();

                // Run on blocking thread since RocksDB write is sync
                tokio::task::spawn_blocking(move || {
                    let mut guard = storage.write();
                    guard.commit_certificate_with_writes(&certificate, &writes);
                })
                .await
                .ok();
            }

            Action::PersistOwnVote {
                height,
                round,
                block_hash,
            } => {
                // **BFT Safety Critical**: Must persist before broadcasting vote
                // Prevents equivocation after crash/restart
                let storage = self.storage.clone();

                // Use spawn_blocking since we need sync writes for BFT safety
                // We await completion to ensure vote is persisted before returning
                tokio::task::spawn_blocking(move || {
                    let guard = storage.read();
                    guard.put_own_vote(height.0, round, block_hash);
                })
                .await
                .ok();
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Storage reads - delegate to async storage, send callback event
            // ═══════════════════════════════════════════════════════════════════════
            Action::FetchStateEntries { tx_hash, nodes } => {
                let event_tx = self.consensus_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();

                tokio::task::spawn_blocking(move || {
                    let guard = storage.read();
                    let entries = executor.fetch_state_entries(&*guard, &nodes);
                    let _ = event_tx.blocking_send(Event::StateEntriesFetched { tx_hash, entries });
                });
            }

            Action::FetchBlock { height } => {
                let event_tx = self.consensus_tx.clone();
                let storage = self.storage.clone();

                tokio::task::spawn_blocking(move || {
                    let guard = storage.read();
                    let block = guard.get_block(height).map(|(b, _qc)| b);
                    let _ = event_tx.blocking_send(Event::BlockFetched { height, block });
                });
            }

            Action::FetchChainMetadata => {
                let event_tx = self.consensus_tx.clone();
                let storage = self.storage.clone();

                tokio::task::spawn_blocking(move || {
                    let guard = storage.read();
                    let (height, hash, qc) = guard.get_chain_metadata();
                    let _ =
                        event_tx.blocking_send(Event::ChainMetadataFetched { height, hash, qc });
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
        }

        Ok(())
    }

    /// Dispatch batched signature verifications to the crypto thread pool.
    ///
    /// This method takes collected verifications and processes them in a single
    /// crypto thread pool task, using batch verification when possible for better
    /// performance (2-8x speedup for batches of 8+ signatures).
    ///
    /// Results are sent back as individual events to maintain compatibility
    /// with the state machine's expectations.
    fn dispatch_batched_verifications(&self, pending: PendingVerifications) {
        if pending.is_empty() {
            return;
        }

        let event_tx = self.consensus_tx.clone();
        let batch_size = pending.total_count();

        self.thread_pools.spawn_crypto(move || {
            let start = std::time::Instant::now();

            // === BLOCK VOTES ===
            if !pending.block_votes.is_empty() {
                // Separate by key type for appropriate batch verification
                let mut ed25519_votes: Vec<(BlockVote, PublicKey, Vec<u8>)> = Vec::new();
                let mut bls_votes: Vec<(BlockVote, PublicKey, Vec<u8>)> = Vec::new();

                for (vote, pk, msg) in pending.block_votes {
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
                            let _ = event_tx
                                .blocking_send(Event::VoteSignatureVerified { vote, valid: true });
                        }
                    } else {
                        // Fallback to individual verification to find which ones failed
                        for (vote, pk, msg) in ed25519_votes {
                            let valid = pk.verify(&msg, &vote.signature);
                            if !valid {
                                crate::metrics::record_signature_verification_failure();
                            }
                            let _ = event_tx
                                .blocking_send(Event::VoteSignatureVerified { vote, valid });
                        }
                    }
                }

                // Process BLS block votes individually (different messages)
                for (vote, pk, msg) in bls_votes {
                    let valid = pk.verify(&msg, &vote.signature);
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx.blocking_send(Event::VoteSignatureVerified { vote, valid });
                }
            }

            // === VIEW CHANGE VOTES ===
            if !pending.view_change_votes.is_empty() {
                let mut ed25519_votes: Vec<(ViewChangeVote, PublicKey, Vec<u8>)> = Vec::new();
                let mut bls_votes: Vec<(ViewChangeVote, PublicKey, Vec<u8>)> = Vec::new();

                for (vote, pk, msg) in pending.view_change_votes {
                    match &pk {
                        PublicKey::Ed25519(_) => ed25519_votes.push((vote, pk, msg)),
                        PublicKey::Bls12381(_) => bls_votes.push((vote, pk, msg)),
                    }
                }

                // Process Ed25519 view change votes using batch verification
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
                            let _ =
                                event_tx.blocking_send(Event::ViewChangeVoteSignatureVerified {
                                    vote,
                                    valid: true,
                                });
                        }
                    } else {
                        for (vote, pk, msg) in ed25519_votes {
                            let valid = pk.verify(&msg, &vote.signature);
                            if !valid {
                                crate::metrics::record_signature_verification_failure();
                            }
                            let _ =
                                event_tx.blocking_send(Event::ViewChangeVoteSignatureVerified {
                                    vote,
                                    valid,
                                });
                        }
                    }
                }

                // Process BLS view change votes individually
                for (vote, pk, msg) in bls_votes {
                    let valid = pk.verify(&msg, &vote.signature);
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ = event_tx
                        .blocking_send(Event::ViewChangeVoteSignatureVerified { vote, valid });
                }
            }

            // === STATE VOTES (cross-shard execution) ===
            if !pending.state_votes.is_empty() {
                // Build signing messages for state votes (must match ExecutionState::create_vote)
                let votes_with_msgs: Vec<(StateVoteBlock, PublicKey, Vec<u8>)> = pending
                    .state_votes
                    .into_iter()
                    .map(|(vote, pk)| {
                        let mut msg = Vec::new();
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
                            let _ = event_tx.blocking_send(Event::StateVoteSignatureVerified {
                                vote,
                                valid: true,
                            });
                        }
                    } else {
                        for (vote, pk, msg) in ed25519_votes {
                            let valid = pk.verify(&msg, &vote.signature);
                            if !valid {
                                crate::metrics::record_signature_verification_failure();
                            }
                            let _ = event_tx
                                .blocking_send(Event::StateVoteSignatureVerified { vote, valid });
                        }
                    }
                }

                // Process BLS state votes individually
                for (vote, pk, msg) in bls_votes {
                    let valid = pk.verify(&msg, &vote.signature);
                    if !valid {
                        crate::metrics::record_signature_verification_failure();
                    }
                    let _ =
                        event_tx.blocking_send(Event::StateVoteSignatureVerified { vote, valid });
                }
            }

            // Record batch metrics
            let elapsed = start.elapsed().as_secs_f64();
            crate::metrics::record_signature_verification_latency(elapsed);

            if batch_size > 1 {
                tracing::debug!(
                    batch_size,
                    elapsed_ms = elapsed * 1000.0,
                    "Batch verified signatures"
                );
            }
        });
    }

    /// Submit a transaction.
    ///
    /// The transaction status can be queried via the RPC status cache.
    /// Transactions are sent to the low-priority transaction channel to avoid
    /// starving consensus events during high transaction load.
    pub async fn submit_transaction(&mut self, tx: RoutableTransaction) -> Result<(), RunnerError> {
        self.transaction_tx
            .send(Event::SubmitTransaction {
                tx: std::sync::Arc::new(tx),
            })
            .await
            .map_err(|e| RunnerError::SendError(e.to_string()))
    }

    /// Handle an inbound sync request from a peer.
    ///
    /// Looks up the requested block from storage and sends the response
    /// back via the network adapter.
    fn handle_inbound_sync_request(&self, request: InboundSyncRequest) {
        let height = BlockHeight(request.height);
        let channel_id = request.channel_id;

        tracing::debug!(
            peer = %request.peer,
            height = request.height,
            channel_id = channel_id,
            "Handling inbound sync request"
        );

        // Look up block from storage
        let response = if let Some((block, qc)) = self.storage.read().get_block(height) {
            // Encode the response as SBOR: (Some(block), Some(qc))
            match sbor::basic_encode(&(Some(&block), Some(&qc))) {
                Ok(data) => data,
                Err(e) => {
                    tracing::warn!(height = request.height, error = ?e, "Failed to encode block response");
                    // Send empty response on encoding failure
                    sbor::basic_encode(&(None::<()>, None::<()>)).unwrap_or_default()
                }
            }
        } else {
            tracing::trace!(height = request.height, "Block not found for sync request");
            // Send "not found" response
            sbor::basic_encode(&(None::<()>, None::<()>)).unwrap_or_default()
        };

        // Send response via network adapter
        if let Err(e) = self.network.send_block_response(channel_id, response) {
            tracing::warn!(
                height = request.height,
                channel_id = channel_id,
                error = ?e,
                "Failed to send block response"
            );
        }
    }

    /// Handle a TransactionFetchNeeded event - fetch missing transactions from the proposer.
    ///
    /// Makes an outbound request to the proposer to get the missing transactions,
    /// then delivers them to the state machine via TransactionFetchReceived.
    async fn handle_transaction_fetch_needed(
        &self,
        block_hash: Hash,
        proposer: ValidatorId,
        missing_tx_hashes: Vec<Hash>,
    ) {
        use hyperscale_messages::response::GetTransactionsResponse;

        tracing::info!(
            block_hash = ?block_hash,
            proposer = ?proposer,
            missing_count = missing_tx_hashes.len(),
            "Fetching missing transactions from proposer"
        );

        // Get the peer ID for the proposer
        let Some(peer_id) = self.network.peer_for_validator(proposer).await else {
            tracing::warn!(
                proposer = ?proposer,
                "Cannot fetch transactions: proposer peer ID not known"
            );
            return;
        };

        // Make the request to the proposer
        match self
            .network
            .request_transactions(peer_id, block_hash, missing_tx_hashes.clone())
            .await
        {
            Ok(response_bytes) => {
                // Decode the response
                match sbor::basic_decode::<GetTransactionsResponse>(&response_bytes) {
                    Ok(response) => {
                        let tx_count = response.count();
                        tracing::info!(
                            block_hash = ?block_hash,
                            received = tx_count,
                            requested = missing_tx_hashes.len(),
                            "Received transactions from proposer"
                        );

                        if tx_count > 0 {
                            // Send to state machine
                            let event = Event::TransactionFetchReceived {
                                block_hash,
                                transactions: response.into_transactions(),
                            };

                            if let Err(e) = self.consensus_tx.send(event).await {
                                tracing::error!(error = ?e, "Failed to send TransactionFetchReceived event");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            block_hash = ?block_hash,
                            error = ?e,
                            "Failed to decode transaction fetch response"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    block_hash = ?block_hash,
                    proposer = ?proposer,
                    error = ?e,
                    "Failed to fetch transactions from proposer"
                );
            }
        }
    }

    /// Handle an inbound transaction fetch request from a peer.
    ///
    /// Looks up requested transactions from mempool and sends them back.
    fn handle_inbound_transaction_request(&self, request: InboundTransactionRequest) {
        use hyperscale_messages::response::GetTransactionsResponse;

        let channel_id = request.channel_id;

        tracing::debug!(
            peer = %request.peer,
            block_hash = ?request.block_hash,
            tx_count = request.tx_hashes.len(),
            channel_id = channel_id,
            "Handling inbound transaction request"
        );

        // Look up transactions from mempool
        let mempool = self.state.mempool();
        let mut found_transactions = Vec::new();

        for tx_hash in &request.tx_hashes {
            if let Some(tx) = mempool.get_transaction(tx_hash) {
                found_transactions.push(tx);
            }
        }

        tracing::debug!(
            block_hash = ?request.block_hash,
            requested = request.tx_hashes.len(),
            found = found_transactions.len(),
            "Responding to transaction fetch request"
        );

        // Encode the response
        let response = GetTransactionsResponse::new(found_transactions);
        let response_bytes = match sbor::basic_encode(&response) {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to encode transaction response");
                sbor::basic_encode(&GetTransactionsResponse::empty()).unwrap_or_default()
            }
        };

        // Send response via network adapter
        if let Err(e) = self
            .network
            .send_transaction_response(channel_id, response_bytes)
        {
            tracing::warn!(
                block_hash = ?request.block_hash,
                channel_id = channel_id,
                error = ?e,
                "Failed to send transaction response"
            );
        }
    }
}
