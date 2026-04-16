//! Unified I/O loop for action processing.
//!
//! `IoLoop` handles ALL actions from `NodeStateMachine`, dispatching them via
//! generic trait methods (Network, Dispatch, Storage) and concrete types for
//! timer ops and event delivery. Both production and simulation runners construct
//! an `IoLoop` with their concrete trait implementations.
//!
//! # Driving modes
//!
//! - **Production**: `IoLoop::run()` blocks on a crossbeam channel, processing
//!   events as they arrive from tokio bridge tasks.
//! - **Simulation**: The harness calls `IoLoop::step()` per event, then drains
//!   buffered outputs (timer ops, events, sync I/O).
//!
//! # Batching
//!
//! IoLoop batches execution-layer broadcasts and crypto verification for
//! efficiency. Batch deadlines are tracked as logical time (`Duration`) so both
//! production (wall clock) and simulation (logical clock) use the same paths.

mod actions;
mod batches;
mod handlers;
mod protocols;
mod verify;

use crate::batch_accumulator::BatchAccumulator;
use crate::config::NodeConfig;
use crate::protocol::execution_cert_fetch::{ExecCertFetchInput, ExecCertFetchProtocol};
use crate::protocol::finalized_wave_fetch::{FinalizedWaveFetchInput, FinalizedWaveFetchProtocol};
use crate::protocol::header_fetch::{HeaderFetchInput, HeaderFetchProtocol};
use crate::protocol::local_provision_fetch::{
    LocalProvisionFetchInput, LocalProvisionFetchProtocol,
};
use crate::protocol::provision_fetch::{ProvisionFetchInput, ProvisionFetchProtocol};
use crate::protocol::sync::{SyncInput, SyncProtocol, SyncStatus};
use crate::protocol::transaction_fetch::{TransactionFetchInput, TransactionFetchProtocol};
use crate::NodeStateMachine;
use arc_swap::ArcSwap;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{Engine, RadixExecutor, TransactionValidation};
use hyperscale_messages::TransactionGossip;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{ChainReader, ChainWriter, SubstateStore};
use hyperscale_types::{
    Block, Bls12381G1PrivateKey, Bls12381G1PublicKey, CommittedBlockHeader, ExecutionCertificate,
    FinalizedWave, Hash, Provision, QuorumCertificate, RoutableTransaction, ShardGroupId,
    TopologySnapshot, ValidatorId, WaveId,
};
use quick_cache::sync::Cache as QuickCache;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Prepared commit cache: `block_hash → (block_height, prepared_commit)`.
type PreparedCommitMap<S> =
    HashMap<Hash, (u64, <S as hyperscale_storage::ChainWriter>::PreparedCommit)>;

/// A block commit waiting to be flushed to storage.
///
/// All blocks — consensus and sync — go through the same commit pipeline:
/// VerifyStateRoot → PreparedCommit → commit_prepared_blocks.
pub(crate) struct PendingCommit {
    pub block: Arc<Block>,
    pub qc: Arc<QuorumCertificate>,
    /// Provision batches referenced by this block. Carried inline from
    /// `Action::CommitBlock` through to the downstream `BlockCommitted`
    /// event, so consumers never rely on a lookup against the
    /// ProvisionCoordinator cache.
    pub provisions: Vec<Arc<Provision>>,
    /// Whether `BlockCommitted` was already fired immediately
    /// in `accumulate_block_commit` (true) or deferred due to
    /// backpressure (false). The flush closure uses this to
    /// decide whether to send `BlockCommitted` after persistence.
    pub committed_notified: bool,
}

/// Lock-free shared topology snapshot for handler closures and dispatch.
///
/// Updated by the io_loop when `Action::TopologyChanged` is processed.
/// Handler closures call `.load()` to get the current snapshot atomically.
pub type SharedTopologySnapshot = Arc<ArcSwap<TopologySnapshot>>;

/// Shared execution certificate cache for fallback serving.
type ExecCertCache = Arc<Mutex<HashMap<(Hash, WaveId), Arc<ExecutionCertificate>>>>;

/// Default certificate cache capacity.
const DEFAULT_CERT_CACHE_SIZE: usize = 10_000;
/// Default transaction cache capacity.
const DEFAULT_TX_CACHE_SIZE: usize = 50_000;
/// Default provision batch cache capacity (for serving fetch requests).
const DEFAULT_PROVISION_CACHE_SIZE: usize = 256;
/// Default transaction status cache capacity.
const DEFAULT_TX_STATUS_CACHE_SIZE: usize = 100_000;
/// A committed header pending sender-signature verification.
type CommittedHeaderVerificationItem = (
    CommittedBlockHeader,
    ValidatorId,
    Bls12381G1PublicKey,
    hyperscale_types::Bls12381G2Signature,
);

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by IoLoop for the runner to process.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set { id: TimerId, duration: Duration },
    /// Cancel a previously set timer.
    Cancel { id: TimerId },
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `IoLoop::step()`.
///
/// IoLoop now handles all sync/fetch I/O internally via the Network trait.
/// The runner processes emitted transaction statuses and timer operations.
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub emitted_statuses: Vec<(Hash, hyperscale_types::TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
    /// Block commit task prepared by `flush_block_commits`. The runner decides
    /// where to execute: production uses `tokio::spawn_blocking`, simulation
    /// runs inline.
    pub commit_task: Option<Box<dyn FnOnce() + Send>>,
}

// ═══════════════════════════════════════════════════════════════════════
// NodeStatusSnapshot — periodic status for external APIs
// ═══════════════════════════════════════════════════════════════════════

/// Snapshot of node state for external status APIs.
///
/// Produced by [`IoLoop::status_snapshot()`] on the periodic metrics tick.
/// The production runner maps this into its RPC shared state types.
#[derive(Debug, Clone)]
pub struct NodeStatusSnapshot {
    pub committed_height: u64,
    pub view: u64,
    pub state_root: Hash,
    pub sync: SyncStatus,
    pub mempool_pending: usize,
    /// Block committed, being executed.
    pub mempool_committed: usize,
    /// Execution done, awaiting certificate.
    pub mempool_executed: usize,
    pub mempool_total: usize,
    pub accepting_rpc_transactions: bool,
    pub at_pending_limit: bool,
    /// Per-remote-shard in-flight counts from latest verified headers.
    pub remote_shard_in_flight: HashMap<ShardGroupId, u32>,
    /// Threshold for rejecting transactions due to remote shard congestion (80% of max_in_flight).
    pub remote_congestion_threshold: u32,
}

// ═══════════════════════════════════════════════════════════════════════
// MetricsSnapshot — cheap state capture for off-thread recording
// ═══════════════════════════════════════════════════════════════════════

/// Lightweight snapshot of io_loop state for metrics recording.
///
/// All fields are plain integers collected via `.len()` calls on the pinned
/// thread. The expensive work (RocksDB property queries, prometheus recording)
/// happens off-thread via [`record_metrics`].
pub struct MetricsSnapshot {
    pub bft_round: u64,
    pub view_changes: u64,
    pub mempool_size: usize,
    pub contention_ratio: f64,
    pub in_flight: usize,
    pub backpressure_active: bool,
    pub blocks_behind: u64,
    pub is_syncing: bool,
    pub fetch_transaction: usize,
    pub fetch_provision: usize,
    pub fetch_local_provision: usize,
    pub fetch_exec_cert: usize,
    pub fetch_header: usize,
    pub fetch_finalized_wave: usize,
    pub memory: metrics::MemoryMetrics,
}

/// Record a [`MetricsSnapshot`] to the metrics backend.
///
/// This performs the prometheus `set_*` calls (76 label lookups) plus
/// the RocksDB property queries for storage memory usage. Designed to
/// run off the pinned thread via `spawn_blocking`.
pub fn record_metrics<S: ChainWriter>(snapshot: MetricsSnapshot, storage: &S) {
    metrics::set_bft_round(snapshot.bft_round);
    metrics::set_view_changes(snapshot.view_changes);
    metrics::set_mempool_size(snapshot.mempool_size);
    metrics::set_lock_contention(snapshot.contention_ratio);
    metrics::set_in_flight(snapshot.in_flight);
    metrics::set_backpressure_active(snapshot.backpressure_active);
    metrics::set_sync_status(snapshot.blocks_behind, snapshot.is_syncing);
    metrics::set_fetch_in_flight("transaction", snapshot.fetch_transaction);
    metrics::set_fetch_in_flight("provision", snapshot.fetch_provision);
    metrics::set_fetch_in_flight("local_provision", snapshot.fetch_local_provision);
    metrics::set_fetch_in_flight("exec_cert", snapshot.fetch_exec_cert);
    metrics::set_fetch_in_flight("header", snapshot.fetch_header);
    metrics::set_fetch_in_flight("finalized_wave", snapshot.fetch_finalized_wave);

    // RocksDB property queries — potentially slow under compaction pressure.
    let (rocksdb_bc, rocksdb_mt) = storage.memory_usage_bytes();
    let mut memory = snapshot.memory;
    memory.rocksdb_block_cache_usage_bytes = rocksdb_bc;
    memory.rocksdb_memtable_usage_bytes = rocksdb_mt;
    metrics::set_memory_metrics(&memory);
}

// ═══════════════════════════════════════════════════════════════════════
// IoLoop
// ═══════════════════════════════════════════════════════════════════════

/// Unified I/O loop that processes all actions from the state machine.
///
/// Generic over:
/// - `S`: Storage (ChainWriter + SubstateStore + ChainReader)
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
/// - `E`: Engine (transaction execution — defaults to `RadixExecutor`)
pub struct IoLoop<S, N, D, E: Engine = RadixExecutor>
where
    S: ChainWriter + SubstateStore + ChainReader,
    D: Dispatch,
{
    // Core components
    state: NodeStateMachine,
    storage: Arc<S>,
    executor: E,
    network: Arc<N>,
    dispatch: D,
    event_sender: crossbeam::channel::Sender<NodeInput>,

    // Identity
    signing_key: Arc<Bls12381G1PrivateKey>,
    topology: SharedTopologySnapshot,
    local_shard: ShardGroupId,
    validator_id: ValidatorId,
    num_shards: u64,

    // Prepared commit cache (shared with dispatch closures).
    // Stores (block_height, prepared_commit) so stale entries can be pruned
    // when they outlive the block they were prepared for.
    prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,

    /// Chain-anchored pending state. Indexed by block hash; reads happen
    /// through `PendingChain::view_at(parent_hash)` which walks the
    /// parent chain back to the committed tip. Orphaned blocks are not
    /// ancestors and are structurally invisible to anchored views.
    /// See `.plans/_unify-overlays.md`.
    pending_chain: Arc<hyperscale_storage::PendingChain<S>>,

    // In-memory caches (shared with inbound router in production)
    tx_cache: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
    provision_cache: Arc<QuickCache<Hash, Arc<Provision>>>,
    finalized_wave_cache: Arc<QuickCache<Hash, Arc<FinalizedWave>>>,

    // Sync protocol
    sync_protocol: SyncProtocol,

    // Fetch protocol (transaction/certificate fetching with chunking and retry)
    transaction_fetch_protocol: TransactionFetchProtocol,

    // Local provision fetch protocol (intra-shard provision batch fetching)
    local_provision_fetch_protocol: LocalProvisionFetchProtocol,

    // Finalized wave fetch protocol (intra-shard wave data fetching)
    finalized_wave_fetch_protocol: FinalizedWaveFetchProtocol,

    // Provision fetch protocol (cross-shard provision fetching with peer rotation)
    provision_fetch_protocol: ProvisionFetchProtocol,

    // Execution certificate fetch protocol (cross-shard exec cert fetching with peer rotation)
    exec_cert_fetch_protocol: ExecCertFetchProtocol,

    // Committed block header fetch protocol (cross-shard header fetching with peer rotation)
    header_fetch_protocol: HeaderFetchProtocol,

    // Transaction validation
    tx_validator: Arc<TransactionValidation>,
    pending_validation: HashSet<Hash>,
    locally_submitted: HashSet<Hash>,

    // Batch accumulators
    validation_batch: BatchAccumulator<Arc<RoutableTransaction>>,
    committed_header_batch: BatchAccumulator<CommittedHeaderVerificationItem>,

    // Block commit accumulator — collects CommitBlock
    // actions within a single feed_event/handle_actions batch, then spawns
    // a single closure on the execution pool to commit them sequentially.
    // This keeps JVT writes off the pinned IoLoop thread while preserving
    // commit ordering.
    pending_block_commits: Vec<PendingCommit>,

    /// Highest block height durably persisted to RocksDB. Updated when
    /// `BlockPersisted` arrives. Used for backpressure: if consensus gets
    /// too far ahead of persistence, we defer `BlockCommitted` until the
    /// disk write completes (bounding memory and crash-recovery window).
    persisted_height: u64,

    // Guard against out-of-order block commits across separate flushes.
    // When an async commit closure is in flight on the execution pool, new
    // blocks accumulate in `pending_block_commits` instead of spawning a
    // second closure (Rayon doesn't guarantee FIFO ordering of spawned tasks).
    // The closure clears this flag before sending its final event, so the
    // subsequent `feed_event` → `flush_block_commits` drains the backlog.
    commit_in_flight: Arc<AtomicBool>,

    // Transaction status cache — retains the latest status for every transaction
    // that has emitted a status notification. Bounded LRU cache shared (via Arc)
    // with external consumers (e.g. RPC handlers in production).
    tx_status_cache: Arc<QuickCache<Hash, hyperscale_types::TransactionStatus>>,

    /// Last time a "transaction finalization exceeded 10s" warning was emitted.
    /// Rate-limited to avoid flooding logs during cross-shard latency spikes.
    last_slow_tx_warn: std::time::Duration,

    // Execution certificate cache for fallback serving.
    // Shared with request handler thread. Keyed by (wave_id_hash, wave_id).
    exec_cert_cache: ExecCertCache,

    // Pending commit task — prepared by flush_block_commits, spawned by the runner.
    // Production uses tokio::spawn_blocking; simulation runs inline.
    pending_commit_task: Option<Box<dyn FnOnce() + Send>>,

    // Accumulated outputs from this step (for caller to drain)
    emitted_statuses: Vec<(Hash, hyperscale_types::TransactionStatus)>,
    actions_generated: usize,
    pending_timer_ops: Vec<TimerOp>,
}

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: ChainWriter + SubstateStore + ChainReader + hyperscale_storage::JmtTreeReader + Send + Sync,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Create a new IoLoop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: NodeStateMachine,
        storage: S,
        executor: E,
        network: N,
        dispatch: D,
        event_sender: crossbeam::channel::Sender<NodeInput>,
        signing_key: Bls12381G1PrivateKey,
        topology: SharedTopologySnapshot,
        config: NodeConfig,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        let topo = topology.load();
        let local_shard = topo.local_shard();
        let validator_id = topo.local_validator_id();
        let initial_persisted_height = state.bft().committed_height();
        let b = &config.batch;
        let sync_protocol = SyncProtocol::new(config.sync.clone());
        let transaction_fetch_protocol =
            TransactionFetchProtocol::new(config.transaction_fetch.clone());
        let local_provision_fetch_protocol = LocalProvisionFetchProtocol::new(Default::default());
        let finalized_wave_fetch_protocol = FinalizedWaveFetchProtocol::new(Default::default());
        let provision_fetch_protocol = ProvisionFetchProtocol::new(config.provision_fetch.clone());
        let exec_cert_fetch_protocol = ExecCertFetchProtocol::new(config.exec_cert_fetch.clone());
        let header_fetch_protocol =
            HeaderFetchProtocol::new(crate::protocol::header_fetch::HeaderFetchConfig::default());
        let storage = Arc::new(storage);
        let pending_chain = Arc::new(hyperscale_storage::PendingChain::new(Arc::clone(&storage)));
        Self {
            state,
            storage,
            executor,
            network: Arc::new(network),
            dispatch,
            event_sender,
            signing_key: Arc::new(signing_key),
            topology,
            local_shard,
            validator_id,
            num_shards: topo.num_shards(),
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            pending_chain,
            tx_cache: Arc::new(QuickCache::new(DEFAULT_TX_CACHE_SIZE)),
            provision_cache: Arc::new(QuickCache::new(DEFAULT_PROVISION_CACHE_SIZE)),
            finalized_wave_cache: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            tx_validator,
            pending_validation: HashSet::new(),
            locally_submitted: HashSet::new(),
            sync_protocol,
            transaction_fetch_protocol,
            local_provision_fetch_protocol,
            finalized_wave_fetch_protocol,
            provision_fetch_protocol,
            exec_cert_fetch_protocol,
            header_fetch_protocol,
            validation_batch: BatchAccumulator::new(b.tx_validation_max, b.tx_validation_window),
            committed_header_batch: BatchAccumulator::new(
                b.committed_header_max,
                b.committed_header_window,
            ),
            pending_block_commits: Vec::new(),
            // At startup, everything committed is also persisted on disk.
            persisted_height: initial_persisted_height,
            commit_in_flight: Arc::new(AtomicBool::new(false)),
            exec_cert_cache: Arc::new(Mutex::new(HashMap::new())),
            tx_status_cache: Arc::new(QuickCache::new(DEFAULT_TX_STATUS_CACHE_SIZE)),
            last_slow_tx_warn: std::time::Duration::ZERO,
            pending_commit_task: None,
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            pending_timer_ops: Vec::new(),
        }
    }

    /// Rebuild derived topology state from a topology snapshot.
    /// Called after storing a new topology via `Action::TopologyChanged`.
    fn rebuild_topology_cache_from(&mut self, topology: &hyperscale_types::TopologySnapshot) {
        self.local_shard = topology.local_shard();
        self.validator_id = topology.local_validator_id();
        self.num_shards = topology.num_shards();
    }

    // ─── Time ────────────────────────────────────────────────────────────

    /// Set the state machine's current time.
    ///
    /// Must be called before `step()` to keep the state machine's clock
    /// in sync with the driving environment.
    pub fn set_time(&mut self, now: Duration) {
        self.state.set_time(now);
    }

    // ─── Genesis ─────────────────────────────────────────────────────────

    /// Process actions from genesis initialization.
    ///
    /// `NodeStateMachine::initialize_genesis()` returns actions (timer sets)
    /// that must be processed through the IoLoop's action handler.
    pub fn handle_actions(&mut self, actions: Vec<Action>) {
        for action in actions {
            self.process_action(action);
        }
        self.flush_block_commits();
    }

    /// Access storage mutably and executor simultaneously.
    ///
    /// Needed for operations like genesis that require both references.
    /// Rust's borrow checker can't split borrows through separate method calls.
    ///
    /// After the closure returns (releasing sole Arc ownership), the inbound
    /// request handler is automatically registered with the network.
    ///
    /// # Genesis initialization ordering
    ///
    /// Runners must follow this sequence:
    /// 1. **Engine genesis** via `with_storage_and_executor()` — requires sole Arc
    ///    ownership, then registers the inbound handler automatically
    /// 2. **State-machine genesis** via `state_mut().initialize_genesis()` followed by
    ///    `handle_actions()`, `flush_all_batches()`, and a `BlockCommitted` event
    ///
    pub fn with_storage_and_executor<R>(&mut self, f: impl FnOnce(&S, &E) -> R) -> R {
        let result = f(&self.storage, &self.executor);

        // Register handlers after genesis so the network layer can serve requests.
        self.register_request_handler();
        self.register_gossip_handlers();
        self.register_notification_handlers();

        result
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Access the state machine.
    pub fn state(&self) -> &NodeStateMachine {
        &self.state
    }

    /// Mutably access the state machine.
    pub fn state_mut(&mut self) -> &mut NodeStateMachine {
        &mut self.state
    }

    /// Access the storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Access the network.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Look up the latest emitted status for a transaction.
    ///
    /// Returns the most recent status notification for the given transaction
    /// hash, if any status has been emitted. Unlike the per-step
    /// `StepOutput::emitted_statuses`, this cache persists across steps and
    /// survives mempool eviction.
    pub fn tx_status(&self, hash: &Hash) -> Option<hyperscale_types::TransactionStatus> {
        self.tx_status_cache.get(hash)
    }

    /// Access the transaction status cache.
    ///
    /// The cache is an `Arc<QuickCache>` so it can be shared with external
    /// consumers (e.g. RPC handlers) across threads without locking.
    pub fn tx_status_cache(&self) -> &Arc<QuickCache<Hash, hyperscale_types::TransactionStatus>> {
        &self.tx_status_cache
    }

    // ─── Event Processing ───────────────────────────────────────────────

    /// Process a single event through the state machine and handle all resulting actions.
    ///
    /// Returns a [`StepOutput`] containing emitted transaction statuses and timer
    /// operations. Sync/fetch I/O is handled internally via the Network trait.
    ///
    /// # Caller protocol
    ///
    /// After each call to `step()`, the runner should:
    /// 1. Flush batches — either [`flush_all_batches()`] (simulation) or
    ///    [`flush_expired_batches()`] (production, with wall-clock time)
    /// 2. Process `timer_ops` from the returned [`StepOutput`]
    /// 3. Process `emitted_statuses` from the returned [`StepOutput`]
    /// 4. Drain any events produced through the event channel (simulation only —
    ///    production receives these via its crossbeam channel receivers)
    pub fn step(&mut self, event: NodeInput) -> StepOutput {
        self.emitted_statuses.clear();
        self.actions_generated = 0;
        self.pending_timer_ops.clear();

        match event {
            // ── Transaction validation pipeline ────────────────────────
            //
            // TransactionGossipReceived and SubmitTransaction are routed
            // through the validation batch pipeline. Validated transactions
            // re-enter as TransactionValidated, which is converted into
            // TransactionGossipReceived for the state machine.
            NodeInput::TransactionValidated {
                tx,
                submitted_locally,
            } => {
                let tx_hash = tx.hash();
                self.pending_validation.remove(&tx_hash);
                let is_local = submitted_locally || self.locally_submitted.remove(&tx_hash);
                self.tx_cache.insert(tx_hash, Arc::clone(&tx));
                self.actions_generated = 0;
                self.feed_event(ProtocolEvent::TransactionGossipReceived {
                    tx,
                    submitted_locally: is_local,
                });
            }

            // Clean up tracking sets for transactions that failed validation.
            NodeInput::TransactionValidationsFailed { hashes } => {
                for hash in &hashes {
                    self.pending_validation.remove(hash);
                    self.locally_submitted.remove(hash);
                }
            }

            // Intercept gossip-received transactions for validation.
            NodeInput::Protocol(ProtocolEvent::TransactionGossipReceived { tx, .. }) => {
                let tx_hash = tx.hash();
                if self.tx_cache.get(&tx_hash).is_none()
                    && !self.state.mempool().is_tombstoned(&tx_hash)
                {
                    self.pending_validation.insert(tx_hash);
                    self.queue_validation(tx);
                }
            }

            NodeInput::SubmitTransaction { tx } => {
                let tx_hash = tx.hash();

                // Gossip to all relevant shards (reads + writes).
                let shards: std::collections::BTreeSet<ShardGroupId> = tx
                    .declared_reads
                    .iter()
                    .chain(tx.declared_writes.iter())
                    .map(|node_id| hyperscale_types::shard_for_node(node_id, self.num_shards))
                    .collect();
                for shard in shards {
                    let gossip = TransactionGossip::from_arc(Arc::clone(&tx));
                    self.network.broadcast_to_shard(shard, &gossip);
                }

                // Track as locally submitted for latency metrics.
                self.locally_submitted.insert(tx_hash);

                // Queue for validation if not already in pipeline or cached.
                if !self.pending_validation.contains(&tx_hash)
                    && self.tx_cache.get(&tx_hash).is_none()
                {
                    self.pending_validation.insert(tx_hash);
                    self.queue_validation(tx);
                }
            }

            // ── Sync protocol ──────────────────────────────────────────
            NodeInput::SyncBlockResponseReceived {
                height,
                block,
                execution_certificates: _,
            } => {
                // Check 1: receipt_root verification (synchronous).
                // Verify block body matches the QC-attested header.
                let certificate_root_valid = match *block {
                    Some((ref b, _)) if !b.certificates.is_empty() => {
                        let computed = hyperscale_types::compute_certificate_root(&b.certificates);
                        if computed != b.header.certificate_root {
                            tracing::warn!(
                                height,
                                ?computed,
                                expected = ?b.header.certificate_root,
                                "Sync: certificate_root mismatch — rejecting response"
                            );
                            false
                        } else {
                            true
                        }
                    }
                    _ => true, // Empty block or no block — no root to check
                };

                if !certificate_root_valid {
                    let _ = self
                        .event_sender
                        .send(NodeInput::SyncBlockFetchFailed { height });
                } else {
                    let outputs = self
                        .sync_protocol
                        .handle(SyncInput::BlockResponseReceived { height, block });
                    self.process_sync_outputs(outputs);
                }
            }

            NodeInput::SyncBlockFetchFailed { height } => {
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockFetchFailed { height });
                self.process_sync_outputs(outputs);
            }

            // ── Fetch protocol ─────────────────────────────────────────
            NodeInput::TransactionReceived {
                block_hash,
                transactions,
            } => {
                let outputs = self.transaction_fetch_protocol.handle(
                    TransactionFetchInput::TransactionsReceived {
                        block_hash,
                        transactions,
                    },
                );
                self.process_transaction_fetch_outputs(outputs);
            }

            NodeInput::FetchTransactionsFailed { block_hash, hashes } => {
                let outputs = self
                    .transaction_fetch_protocol
                    .handle(TransactionFetchInput::FetchFailed { block_hash, hashes });
                self.process_transaction_fetch_outputs(outputs);
                // Tick to retry pending fetches.
                let tick_outputs = self
                    .transaction_fetch_protocol
                    .handle(TransactionFetchInput::Tick);
                self.process_transaction_fetch_outputs(tick_outputs);
            }

            NodeInput::FetchTick => {
                let outputs = self
                    .transaction_fetch_protocol
                    .handle(TransactionFetchInput::Tick);
                self.process_transaction_fetch_outputs(outputs);
                // Also tick the local provision fetch protocol.
                let local_prov_outputs = self
                    .local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::Tick);
                self.process_local_provision_fetch_outputs(local_prov_outputs);
                // Also tick the finalized wave fetch protocol.
                let wave_outputs = self
                    .finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Tick);
                self.process_finalized_wave_fetch_outputs(wave_outputs);
                // Also tick the provision fetch protocol.
                let prov_outputs =
                    self.provision_fetch_protocol
                        .handle(ProvisionFetchInput::Tick {
                            now: std::time::Instant::now(),
                        });
                self.process_provision_fetch_outputs(prov_outputs);
                // Also tick the exec cert fetch protocol.
                let cert_outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Tick {
                        now: std::time::Instant::now(),
                        committed_height: self.state.bft().committed_height(),
                    });
                self.process_exec_cert_fetch_outputs(cert_outputs);
                // Also tick the header fetch protocol.
                let header_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick {
                    now: std::time::Instant::now(),
                });
                self.process_header_fetch_outputs(header_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Provision fetch protocol ──────────────────────────────
            NodeInput::ProvisionFetchReceived { batch } => {
                let source_shard = batch.source_shard;
                let block_height = batch.block_height;
                let outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Received {
                        source_shard,
                        block_height,
                        batch,
                    });
                self.process_provision_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::ProvisionFetchFailed {
                source_shard,
                block_height,
            } => {
                let outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Failed {
                        source_shard,
                        block_height,
                    });
                self.process_provision_fetch_outputs(outputs);
                // Tick to retry with next peer immediately.
                let tick_outputs =
                    self.provision_fetch_protocol
                        .handle(ProvisionFetchInput::Tick {
                            now: std::time::Instant::now(),
                        });
                self.process_provision_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Execution certificate fetch protocol ─────────────────
            NodeInput::ExecCertFetchReceived {
                source_shard,
                block_height,
                certificates,
            } => {
                let outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Received {
                        source_shard,
                        block_height,
                        certificates,
                    });
                self.process_exec_cert_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::ExecCertFetchFailed {
                source_shard,
                block_height,
            } => {
                let outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Failed {
                        source_shard,
                        block_height,
                    });
                self.process_exec_cert_fetch_outputs(outputs);
                // Tick to retry with next peer immediately.
                let tick_outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Tick {
                        now: std::time::Instant::now(),
                        committed_height: self.state.bft().committed_height(),
                    });
                self.process_exec_cert_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Committed block header fetch protocol ────────────────
            NodeInput::HeaderFetchReceived {
                source_shard,
                from_height,
                header,
            } => {
                let outputs = self
                    .header_fetch_protocol
                    .handle(HeaderFetchInput::Received {
                        source_shard,
                        from_height,
                        header: Box::new(header),
                    });
                self.process_header_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::HeaderFetchFailed {
                source_shard,
                from_height,
            } => {
                let outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Failed {
                    source_shard,
                    from_height,
                });
                self.process_header_fetch_outputs(outputs);
                // Tick to retry with next peer immediately.
                let tick_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick {
                    now: std::time::Instant::now(),
                });
                self.process_header_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Committed header validated (sender sig verified) ────────
            NodeInput::CommittedHeaderValidated {
                committed_header,
                sender,
            } => {
                self.feed_event(ProtocolEvent::RemoteBlockCommitted {
                    committed_header,
                    sender,
                });
            }

            // ── Committed block gossip (pre-filtered) ─────────────────
            //
            // Handler closure already verified sender's committee membership
            // and resolved the public key. Queue for batched BLS verification.
            NodeInput::CommittedBlockGossipReceived {
                committed_header,
                sender,
                public_key,
                sender_signature,
            } => {
                let item: CommittedHeaderVerificationItem =
                    (committed_header, sender, public_key, sender_signature);
                if self.committed_header_batch.push(item, self.state.now()) {
                    self.flush_committed_header_verifications();
                }
            }

            // ── Local provision fetch protocol ────────────────────────
            NodeInput::LocalProvisionReceived {
                block_hash,
                batches,
            } => {
                let outputs = self.local_provision_fetch_protocol.handle(
                    LocalProvisionFetchInput::Received {
                        block_hash,
                        batches,
                    },
                );
                self.process_local_provision_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::LocalProvisionFetchFailed { block_hash, hashes } => {
                let outputs = self
                    .local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::Failed { block_hash, hashes });
                self.process_local_provision_fetch_outputs(outputs);
                // Tick to retry pending fetches.
                let tick_outputs = self
                    .local_provision_fetch_protocol
                    .handle(LocalProvisionFetchInput::Tick);
                self.process_local_provision_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Provision ready (from execution pool) ─────────────────
            //
            // The FetchAndBroadcastProvision delegated action built provisions
            // grouped by target shard. Broadcast one batch per shard.
            NodeInput::ProvisionReady {
                batches,
                block_timestamp,
            } => {
                self.broadcast_provisions(batches, block_timestamp);
            }

            // ── Finalized wave fetch ─────────────────────────────────
            NodeInput::FinalizedWaveReceived { block_hash, waves } => {
                let outputs = self
                    .finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Received { block_hash, waves });
                self.process_finalized_wave_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::FinalizedWaveFetchFailed { block_hash, hashes } => {
                let outputs = self
                    .finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Failed { block_hash, hashes });
                self.process_finalized_wave_fetch_outputs(outputs);
                // Tick to retry pending fetches.
                let tick_outputs = self
                    .finalized_wave_fetch_protocol
                    .handle(FinalizedWaveFetchInput::Tick);
                self.process_finalized_wave_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            // ── Protocol events → state machine ────────────────────────
            NodeInput::Protocol(ProtocolEvent::BlockPersisted { height }) => {
                // Update persistence tracking before forwarding to state machine.
                if height > self.persisted_height {
                    self.persisted_height = height;
                }
                // Drop pending state for blocks now persisted to RocksDB.
                self.pending_chain.prune(height);
                self.feed_event(ProtocolEvent::BlockPersisted { height });
            }
            NodeInput::Protocol(pe) => {
                self.feed_event(pe);
            }
        }

        self.drain_pending_output()
    }

    /// Drain accumulated outputs (statuses, timer ops) without processing an event.
    ///
    /// Used after `handle_actions()` to collect outputs produced by those actions.
    pub fn drain_pending_output(&mut self) -> StepOutput {
        StepOutput {
            emitted_statuses: std::mem::take(&mut self.emitted_statuses),
            actions_generated: self.actions_generated,
            timer_ops: std::mem::take(&mut self.pending_timer_ops),
            commit_task: self.pending_commit_task.take(),
        }
    }

    /// Feed a protocol event to the state machine and process all resulting actions.
    ///
    /// This is the common pattern used throughout IoLoop: route an event through
    /// the state machine, then dispatch each resulting action.
    fn feed_event(&mut self, event: ProtocolEvent) {
        let actions = self.state.handle(event);
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(action);
        }
        self.flush_block_commits();
    }

    /// Flush any batch accumulators whose deadlines have expired.
    ///
    /// Call this with the current time before processing events. In production,
    /// the loop calls this with wall-clock time. In simulation, the harness
    /// calls it with logical time.
    pub fn flush_expired_batches(&mut self, now: Duration) {
        if self.validation_batch.is_expired(now) {
            self.flush_validation_batch();
        }
        if self.committed_header_batch.is_expired(now) {
            self.flush_committed_header_verifications();
        }
    }

    /// Get the nearest batch deadline, if any.
    ///
    /// Used by the production `run()` loop for `recv_timeout()` and by the
    /// simulation harness to know when to schedule a flush.
    pub fn nearest_batch_deadline(&self) -> Option<Duration> {
        [
            self.validation_batch.deadline(),
            self.committed_header_batch.deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // ─── Provision Broadcasting ────────────────────────────────────────

    /// Sign and broadcast provision batches to target shard committees.
    ///
    /// Signing is dispatched to the crypto pool to avoid blocking the io_loop.
    pub(crate) fn broadcast_provisions(
        &self,
        batches: Vec<(
            hyperscale_types::ShardGroupId,
            hyperscale_types::Provision,
            Vec<hyperscale_types::ValidatorId>,
        )>,
        block_timestamp: u64,
    ) {
        let signing_key = Arc::clone(&self.signing_key);
        let network = Arc::clone(&self.network);
        let local_shard = self.local_shard;
        let validator_id = self.validator_id;

        self.dispatch.spawn_crypto(move || {
            for (shard, batch, recipients) in batches {
                let block_height = batch.block_height;
                let source_shard = batch.source_shard;
                let proof = batch.proof.clone();
                let provisions: Vec<hyperscale_types::StateProvision> = batch
                    .transactions
                    .into_iter()
                    .map(|tx| hyperscale_types::StateProvision {
                        transaction_hash: tx.tx_hash,
                        target_shard: shard,
                        source_shard,
                        block_height,
                        block_timestamp,
                        entries: std::sync::Arc::new(tx.entries),
                    })
                    .collect();
                if provisions.is_empty() {
                    continue;
                }
                let msg = hyperscale_types::state_provision_batch_message(
                    local_shard,
                    shard,
                    block_height,
                    &provisions,
                );
                let sig = signing_key.sign_v1(&msg);
                let notification = hyperscale_messages::StateProvisionNotification::new(
                    provisions,
                    proof,
                    validator_id,
                    sig,
                );
                network.notify(&recipients, &notification);
            }
        });
    }

    // ─── Metrics ────────────────────────────────────────────────────────

    /// Collect and export metrics from the state machine.
    ///
    /// Capture a lightweight metrics snapshot from state machine internals.
    ///
    /// Only reads `.len()` / `.stats()` from subsystems — no locks, no I/O,
    /// no prometheus calls. The caller dispatches [`record_metrics`] off-thread
    /// to do the expensive work (RocksDB queries, prometheus recording).
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let bft_stats = self.state.bft().stats();
        let mempool = self.state.mempool();
        let contention = mempool.lock_contention_stats();
        let fetch_status = self.transaction_fetch_protocol.status();

        let bft_mem = self.state.bft().memory_stats();
        let exec_mem = self.state.execution().memory_stats();
        let mempool_mem = self.state.mempool().memory_stats();
        let prov_mem = self.state.provisions().memory_stats();
        let rh_mem = self.state.remote_headers().memory_stats();

        MetricsSnapshot {
            bft_round: bft_stats.current_round,
            view_changes: bft_stats.view_changes,
            mempool_size: mempool.len(),
            contention_ratio: contention.contention_ratio(),
            in_flight: mempool.in_flight(),
            backpressure_active: mempool.at_in_flight_limit(),
            blocks_behind: self.sync_protocol.blocks_behind(),
            is_syncing: self.sync_protocol.is_syncing(),
            fetch_transaction: fetch_status.in_flight_operations,
            fetch_provision: self.provision_fetch_protocol.in_flight_count(),
            fetch_local_provision: self.local_provision_fetch_protocol.in_flight_count(),
            fetch_exec_cert: self.exec_cert_fetch_protocol.in_flight_count(),
            fetch_header: self.header_fetch_protocol.in_flight_count(),
            fetch_finalized_wave: self.finalized_wave_fetch_protocol.in_flight_count(),
            memory: metrics::MemoryMetrics {
                // BFT
                bft_pending_blocks: bft_mem.pending_blocks,
                bft_vote_sets: bft_mem.vote_sets,
                bft_certified_blocks: bft_mem.certified_blocks,
                bft_pending_commits: bft_mem.pending_commits,
                bft_pending_commits_awaiting_data: bft_mem.pending_commits_awaiting_data,
                bft_remote_headers: bft_mem.remote_headers,
                bft_voted_heights: bft_mem.voted_heights,
                bft_received_votes_by_height: bft_mem.received_votes_by_height,
                bft_committed_tx_lookup: bft_mem.committed_tx_lookup,
                bft_recently_committed_txs: bft_mem.recently_committed_txs,
                bft_recently_committed_certs: bft_mem.recently_committed_certs,
                bft_pending_qc_verifications: bft_mem.pending_qc_verifications,
                bft_verified_qcs: bft_mem.verified_qcs,
                bft_pending_state_root_verifications: bft_mem.pending_state_root_verifications,
                bft_buffered_synced_blocks: bft_mem.buffered_synced_blocks,
                bft_pending_synced_block_verifications: bft_mem.pending_synced_block_verifications,
                // Execution
                exec_cache_entries: exec_mem.receipt_cache,
                exec_finalized_wave_certificates: exec_mem.finalized_wave_certificates,
                exec_pending_provisioning: exec_mem.pending_provisioning,
                exec_accumulators: exec_mem.accumulators,
                exec_vote_trackers: exec_mem.vote_trackers,
                exec_early_votes: exec_mem.early_votes,
                exec_wave_certificate_trackers: exec_mem.wave_certificate_trackers,
                exec_expected_exec_certs: exec_mem.expected_exec_certs,
                exec_verified_provisions: exec_mem.verified_provisions,
                exec_required_provision_shards: exec_mem.required_provision_shards,
                exec_received_provision_shards: exec_mem.received_provision_shards,
                exec_waves_with_ec: exec_mem.waves_with_ec,
                exec_pending_vote_retries: exec_mem.pending_vote_retries,
                exec_wave_assignments: exec_mem.wave_assignments,
                exec_pending_wave_receipts: exec_mem.pending_wave_receipts,
                exec_early_execution_results: exec_mem.early_execution_results,
                exec_early_wave_attestations: exec_mem.early_wave_attestations,
                exec_early_committed_provisions: exec_mem.early_committed_provisions,
                exec_fulfilled_exec_certs: exec_mem.fulfilled_exec_certs,
                // Mempool
                mempool_pool: mempool_mem.pool,
                mempool_ready: mempool_mem.ready,
                mempool_tombstones: mempool_mem.tombstones,
                mempool_recently_evicted: mempool_mem.recently_evicted,
                mempool_locked_nodes: mempool_mem.locked_nodes,
                mempool_in_flight_heights: mempool_mem.in_flight_heights,
                mempool_deferred_by_nodes: mempool_mem.deferred_by_nodes,
                mempool_txs_deferred_by_node: mempool_mem.txs_deferred_by_node,
                mempool_ready_txs_by_node: mempool_mem.ready_txs_by_node,
                // Remote Headers
                rh_pending_headers: rh_mem.pending_headers,
                rh_verified_headers: rh_mem.verified_headers,
                rh_expected_headers: rh_mem.expected_headers,
                // Provision
                prov_verified_remote_headers: prov_mem.verified_remote_headers,
                prov_pending_provisions: prov_mem.pending_provisions,
                prov_verified_batches: prov_mem.verified_batches,
                prov_expected_provisions: prov_mem.expected_provisions,
                prov_batches_by_hash: prov_mem.batches_by_hash,
                prov_queued_provision_batches: prov_mem.queued_provision_batches,
                prov_committed_batch_tombstones: prov_mem.committed_batch_tombstones,
                // Storage — filled in by record_metrics off-thread.
                rocksdb_block_cache_usage_bytes: 0,
                rocksdb_memtable_usage_bytes: 0,
            },
        }
    }

    /// Capture a snapshot of node state for external status APIs.
    pub fn status_snapshot(&self) -> NodeStatusSnapshot {
        let state_root = self.state.last_committed_jvt_root();
        let mempool = self.state.mempool();
        let contention = mempool.lock_contention_stats();

        NodeStatusSnapshot {
            committed_height: self.state.bft().committed_height(),
            view: self.state.bft().view(),
            state_root,
            sync: self.sync_protocol.status(),
            mempool_pending: contention.pending_count as usize,
            mempool_committed: contention.committed_count as usize,
            mempool_executed: contention.executed_count as usize,
            mempool_total: mempool.len(),
            accepting_rpc_transactions: !mempool.at_in_flight_limit(),
            at_pending_limit: mempool.at_pending_limit(),
            remote_shard_in_flight: self.state.remote_headers().remote_shard_in_flight(),
            remote_congestion_threshold: (mempool.config().max_in_flight as f64 * 0.8) as u32,
        }
    }

    /// Flush ALL pending batches immediately, regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        self.flush_block_commits();
        self.flush_validation_batch();
        self.flush_committed_header_verifications();
    }
}
