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
use crate::protocol::fetch::{FetchInput, FetchKind, FetchProtocol};
use crate::protocol::header_fetch::{HeaderFetchInput, HeaderFetchProtocol};
use crate::protocol::inclusion_proof_fetch::{
    InclusionProofFetchInput, InclusionProofFetchProtocol,
};
use crate::protocol::provision_fetch::{ProvisionFetchInput, ProvisionFetchProtocol};
use crate::protocol::sync::{SyncInput, SyncProtocol, SyncStatus};
use crate::NodeStateMachine;
use arc_swap::ArcSwap;
use hyperscale_core::{Action, NodeInput, ProtocolEvent, StateMachine, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{RadixExecutor, TransactionValidation};
use hyperscale_messages::TransactionGossip;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::{
    Block, Bls12381G1PrivateKey, Bls12381G1PublicKey, CommittedBlockHeader, ExecutionCertificate,
    Hash, QuorumCertificate, RoutableTransaction, ShardGroupId, TopologySnapshot,
    TransactionCertificate, ValidatorId, WaveId,
};
use quick_cache::sync::Cache as QuickCache;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
}

// ═══════════════════════════════════════════════════════════════════════
// IoLoop
// ═══════════════════════════════════════════════════════════════════════

/// Unified I/O loop that processes all actions from the state machine.
///
/// Generic over:
/// - `S`: Storage (CommitStore + SubstateStore + ConsensusStore)
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
pub struct IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore,
    D: Dispatch,
{
    // Core components
    state: NodeStateMachine,
    storage: Arc<S>,
    executor: RadixExecutor,
    network: N,
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
    #[allow(clippy::type_complexity)]
    prepared_commits: Arc<Mutex<HashMap<Hash, (u64, S::PreparedCommit)>>>,

    // In-memory caches (shared with inbound router in production)
    cert_cache: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    tx_cache: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,

    // Sync protocol
    sync_protocol: SyncProtocol,

    // Fetch protocol (transaction/certificate fetching with chunking and retry)
    fetch_protocol: FetchProtocol,

    // Provision fetch protocol (cross-shard provision fetching with peer rotation)
    provision_fetch_protocol: ProvisionFetchProtocol,

    // Inclusion proof fetch protocol (livelock tx inclusion proof fetching with peer rotation)
    inclusion_proof_fetch_protocol: InclusionProofFetchProtocol,

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

    // Block commit accumulator — collects EmitCommittedBlock actions within a
    // single feed_event/handle_actions batch, then spawns a single closure on
    // the execution pool to commit them sequentially. This keeps JVT writes
    // off the pinned IoLoop thread while preserving commit ordering.
    pending_block_commits: Vec<(Block, QuorumCertificate)>,

    // Guard against out-of-order block commits across separate flushes.
    // When an async commit closure is in flight on the execution pool, new
    // blocks accumulate in `pending_block_commits` instead of spawning a
    // second closure (Rayon doesn't guarantee FIFO ordering of spawned tasks).
    // The closure clears this flag before sending its final event, so the
    // subsequent `feed_event` → `flush_block_commits` drains the backlog.
    commit_in_flight: Arc<AtomicBool>,

    // Receipt bundle accumulator — collects StoreReceiptBundles within an
    // event cycle, then spawns storage writes on the execution pool so
    // SBOR-encoding + RocksDB writes don't block the IoLoop thread.
    pending_receipt_bundles: Vec<hyperscale_types::ReceiptBundle>,

    // Transaction status cache — retains the latest status for every transaction
    // that has emitted a status notification. Bounded LRU cache shared (via Arc)
    // with external consumers (e.g. RPC handlers in production).
    tx_status_cache: Arc<QuickCache<Hash, hyperscale_types::TransactionStatus>>,

    // Execution certificate cache for fallback serving.
    // Shared with request handler thread. Keyed by (block_hash, wave_id).
    exec_cert_cache: ExecCertCache,

    // Cached local shard peers (committee excluding self) — avoids per-call allocation.
    cached_local_peers: Vec<ValidatorId>,

    // Accumulated outputs from this step (for caller to drain)
    emitted_statuses: Vec<(Hash, hyperscale_types::TransactionStatus)>,
    actions_generated: usize,
    pending_timer_ops: Vec<TimerOp>,
}

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    /// Create a new IoLoop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: NodeStateMachine,
        storage: S,
        executor: RadixExecutor,
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
        let cached_local_peers: Vec<ValidatorId> = topo
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != validator_id)
            .copied()
            .collect();
        let b = &config.batch;
        let sync_protocol = SyncProtocol::new(config.sync.clone());
        let fetch_protocol = FetchProtocol::new(config.fetch.clone());
        let provision_fetch_protocol = ProvisionFetchProtocol::new(config.provision_fetch.clone());
        let inclusion_proof_fetch_protocol =
            InclusionProofFetchProtocol::new(config.inclusion_proof_fetch.clone());
        let exec_cert_fetch_protocol = ExecCertFetchProtocol::new(config.exec_cert_fetch.clone());
        let header_fetch_protocol =
            HeaderFetchProtocol::new(crate::protocol::header_fetch::HeaderFetchConfig::default());
        Self {
            state,
            storage: Arc::new(storage),
            executor,
            network,
            dispatch,
            event_sender,
            signing_key: Arc::new(signing_key),
            topology,
            local_shard,
            validator_id,
            num_shards: topo.num_shards(),
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            cert_cache: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            tx_cache: Arc::new(QuickCache::new(DEFAULT_TX_CACHE_SIZE)),
            tx_validator,
            pending_validation: HashSet::new(),
            locally_submitted: HashSet::new(),
            sync_protocol,
            fetch_protocol,
            provision_fetch_protocol,
            inclusion_proof_fetch_protocol,
            exec_cert_fetch_protocol,
            header_fetch_protocol,
            validation_batch: BatchAccumulator::new(b.tx_validation_max, b.tx_validation_window),
            committed_header_batch: BatchAccumulator::new(
                b.committed_header_max,
                b.committed_header_window,
            ),
            pending_block_commits: Vec::new(),
            commit_in_flight: Arc::new(AtomicBool::new(false)),
            pending_receipt_bundles: Vec::new(),
            exec_cert_cache: Arc::new(Mutex::new(HashMap::new())),
            cached_local_peers,
            tx_status_cache: Arc::new(QuickCache::new(DEFAULT_TX_STATUS_CACHE_SIZE)),
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            pending_timer_ops: Vec::new(),
        }
    }

    /// Rebuild derived topology state (`local_shard`, `cached_local_peers`)
    /// from a topology snapshot. Called after storing a new topology via
    /// `Action::TopologyChanged`.
    fn rebuild_topology_cache_from(&mut self, topology: &hyperscale_types::TopologySnapshot) {
        self.local_shard = topology.local_shard();
        self.validator_id = topology.local_validator_id();
        self.num_shards = topology.num_shards();
        self.cached_local_peers = topology
            .committee_for_shard(self.local_shard)
            .iter()
            .filter(|&&v| v != self.validator_id)
            .copied()
            .collect();
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
    ///    `handle_actions()`, `flush_all_batches()`, and a `StateCommitComplete` event
    ///
    /// # Panics
    ///
    /// Panics if the storage `Arc` has been cloned (e.g., by handler registration
    /// or dispatch closures), since `Arc::get_mut` requires sole ownership.
    pub fn with_storage_and_executor<R>(
        &mut self,
        f: impl FnOnce(&mut S, &RadixExecutor) -> R,
    ) -> R {
        let storage = Arc::get_mut(&mut self.storage).expect(
            "with_storage_and_executor must be called before any spawned closures clone the Arc",
        );
        let result = f(storage, &self.executor);

        // Now sole ownership is released — register handlers.
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

    /// Mutably access the storage (for initialization/setup).
    pub fn storage_mut(&mut self) -> &mut S {
        Arc::get_mut(&mut self.storage)
            .expect("storage_mut must be called before any spawned closures clone the Arc")
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
                ledger_receipts,
            } => {
                // Store receipts from sync peer BEFORE processing the block.
                // Syncing nodes didn't execute locally, so local_execution is None.
                // state_changes already populated by remote peer.
                let bundles: Vec<hyperscale_types::ReceiptBundle> = ledger_receipts
                    .iter()
                    .map(|entry| hyperscale_types::ReceiptBundle {
                        tx_hash: entry.tx_hash,
                        ledger_receipt: std::sync::Arc::new(entry.receipt.clone()),
                        local_execution: None,
                        database_updates: None,
                    })
                    .collect();
                self.pending_receipt_bundles.extend(bundles);
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockResponseReceived { height, block });
                self.process_sync_outputs(outputs);
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
                let outputs = self
                    .fetch_protocol
                    .handle(FetchInput::TransactionsReceived {
                        block_hash,
                        transactions,
                    });
                self.process_fetch_outputs(outputs);
            }

            NodeInput::FetchTransactionsFailed { block_hash, hashes } => {
                let outputs = self.fetch_protocol.handle(FetchInput::FetchFailed {
                    block_hash,
                    kind: FetchKind::Transaction,
                    hashes,
                });
                self.process_fetch_outputs(outputs);
                // Tick to retry pending fetches.
                let tick_outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(tick_outputs);
            }

            NodeInput::FetchTick => {
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                // Also tick the provision fetch protocol.
                let prov_outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Tick);
                self.process_provision_fetch_outputs(prov_outputs);
                // Also tick the inclusion proof fetch protocol.
                let proof_outputs = self
                    .inclusion_proof_fetch_protocol
                    .handle(InclusionProofFetchInput::Tick);
                self.process_inclusion_proof_fetch_outputs(proof_outputs);
                // Also tick the exec cert fetch protocol.
                let cert_outputs = self
                    .exec_cert_fetch_protocol
                    .handle(ExecCertFetchInput::Tick);
                self.process_exec_cert_fetch_outputs(cert_outputs);
                // Also tick the header fetch protocol.
                let header_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick);
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

            // ── Inclusion proof fetch protocol (livelock) ─────────────
            NodeInput::InclusionProofFetchReceived {
                winner_tx_hash,
                reason,
                source_shard,
                source_block_height,
                proof,
            } => {
                let outputs = self.inclusion_proof_fetch_protocol.handle(
                    InclusionProofFetchInput::Received {
                        winner_tx_hash,
                        reason,
                        source_shard,
                        source_block_height,
                        proof,
                    },
                );
                self.process_inclusion_proof_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            NodeInput::InclusionProofFetchFailed { winner_tx_hash } => {
                let outputs = self
                    .inclusion_proof_fetch_protocol
                    .handle(InclusionProofFetchInput::Failed { winner_tx_hash });
                self.process_inclusion_proof_fetch_outputs(outputs);
                // Tick to retry immediately.
                let tick_outputs = self
                    .inclusion_proof_fetch_protocol
                    .handle(InclusionProofFetchInput::Tick);
                self.process_inclusion_proof_fetch_outputs(tick_outputs);
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
                let tick_outputs = self
                    .provision_fetch_protocol
                    .handle(ProvisionFetchInput::Tick);
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
                    .handle(ExecCertFetchInput::Tick);
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
                let tick_outputs = self.header_fetch_protocol.handle(HeaderFetchInput::Tick);
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

            // ── Provisions ready (from execution pool) ─────────────────
            //
            // The FetchAndBroadcastProvisions delegated action built provisions
            // grouped by target shard. Broadcast one batch per shard.
            NodeInput::ProvisionsReady {
                batches,
                block_timestamp,
            } => {
                self.broadcast_provisions(batches, block_timestamp);
            }

            // ── Protocol events → state machine ────────────────────────
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
    /// Used by both `ProvisionsReady` (from delegated action) and
    /// `SendProvisions` (from speculative cache hit).
    pub(crate) fn broadcast_provisions(
        &self,
        batches: Vec<(
            hyperscale_types::ShardGroupId,
            hyperscale_types::ProvisionBatch,
            Vec<hyperscale_types::ValidatorId>,
        )>,
        block_timestamp: u64,
    ) {
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
                self.local_shard,
                shard,
                block_height,
                &provisions,
            );
            let sig = self.signing_key.sign_v1(&msg);
            let notification = hyperscale_messages::StateProvisionsNotification::new(
                provisions,
                proof,
                self.validator_id,
                sig,
            );
            self.network.notify(&recipients, &notification);
        }
    }

    // ─── Metrics ────────────────────────────────────────────────────────

    /// Collect and export metrics from the state machine.
    ///
    /// Called periodically (every ~1s) by the driving loop. Reads state from
    /// BFT, mempool, execution, livelock, sync, and fetch subsystems and
    /// emits them via the `hyperscale_metrics` facade. In production the
    /// Prometheus backend records them; in simulation the no-op backend
    /// discards them at zero cost.
    pub fn collect_metrics(&mut self) {
        // ── BFT ──
        let bft_stats = self.state.bft().stats();
        metrics::set_bft_round(bft_stats.current_round);
        metrics::set_view_changes(bft_stats.view_changes);

        // ── Speculative execution ──
        let (started, hits, late_hits, misses, invalidated) =
            self.state.execution_mut().take_speculative_metrics();
        if started > 0 {
            metrics::record_speculative_execution_started(started);
        }
        if hits > 0 {
            metrics::record_speculative_execution_cache_hit(hits);
        }
        if late_hits > 0 {
            metrics::record_speculative_execution_late_hit(late_hits);
        }
        if misses > 0 {
            metrics::record_speculative_execution_cache_miss(misses);
        }
        if invalidated > 0 {
            metrics::record_speculative_execution_invalidated(invalidated);
        }

        // ── Mempool ──
        let mempool = self.state.mempool();
        let total = mempool.len();
        let contention = mempool.lock_contention_stats();
        metrics::set_mempool_size(total);
        metrics::set_lock_contention(contention.contention_ratio());
        let in_flight = mempool.in_flight();
        metrics::set_in_flight(in_flight);
        metrics::set_backpressure_active(mempool.at_in_flight_limit());

        // ── Sync ──
        metrics::set_sync_status(
            self.sync_protocol.blocks_behind(),
            self.sync_protocol.is_syncing(),
        );

        // ── Fetch ──
        let fetch_status = self.fetch_protocol.status();
        metrics::set_fetch_in_flight(fetch_status.in_flight_operations);

        // ── Livelock ──
        let livelock_stats = self.state.livelock().stats();
        metrics::set_livelock_pending_abort_intents(livelock_stats.pending_abort_intents);

        // ── Memory ──
        let bft_mem = self.state.bft().memory_stats();
        let exec_mem = self.state.execution().memory_stats();
        let mempool_mem = self.state.mempool().memory_stats();
        let prov_mem = self.state.provisions().memory_stats();
        let rh_mem = self.state.remote_headers().memory_stats();
        let (rocksdb_bc, rocksdb_mt) = self.storage.memory_usage_bytes();

        metrics::set_memory_metrics(&metrics::MemoryMetrics {
            // BFT
            bft_pending_blocks: bft_mem.pending_blocks,
            bft_vote_sets: bft_mem.vote_sets,
            bft_certified_blocks: bft_mem.certified_blocks,
            bft_pending_commits: bft_mem.pending_commits,
            bft_remote_headers: bft_mem.remote_headers,
            bft_pending_qc_verifications: bft_mem.pending_qc_verifications,
            bft_verified_qcs: bft_mem.verified_qcs,
            bft_pending_state_root_verifications: bft_mem.pending_state_root_verifications,
            bft_buffered_synced_blocks: bft_mem.buffered_synced_blocks,
            // Execution
            exec_cache_entries: exec_mem.cache_entries,
            exec_finalized_certificates: exec_mem.finalized_certificates,
            exec_pending_provisioning: exec_mem.pending_provisioning,
            exec_accumulators: exec_mem.accumulators,
            exec_vote_trackers: exec_mem.vote_trackers,
            exec_early_votes: exec_mem.early_votes,
            exec_certificate_trackers: exec_mem.certificate_trackers,
            exec_speculative_results: exec_mem.speculative_results,
            exec_expected_exec_certs: exec_mem.expected_exec_certs,
            exec_speculative_provision_in_flight: exec_mem.speculative_provision_in_flight,
            exec_speculative_provision_results: exec_mem.speculative_provision_results,
            exec_pending_provision_commits: exec_mem.pending_provision_commits,
            // Mempool
            mempool_pool: mempool_mem.pool,
            mempool_ready: mempool_mem.ready,
            mempool_tombstones: mempool_mem.tombstones,
            mempool_recently_evicted: mempool_mem.recently_evicted,
            mempool_locked_nodes: mempool_mem.locked_nodes,
            mempool_in_flight_heights: mempool_mem.in_flight_heights,
            // Remote Headers
            rh_pending_headers: rh_mem.pending_headers,
            rh_verified_headers: rh_mem.verified_headers,
            rh_expected_headers: rh_mem.expected_headers,
            // Provisions
            prov_registered_txs: prov_mem.registered_txs,
            prov_verified_remote_headers: prov_mem.verified_remote_headers,
            prov_pending_provisions: prov_mem.pending_provisions,
            prov_verified_batches: prov_mem.verified_batches,
            prov_expected_provisions: prov_mem.expected_provisions,
            // Livelock
            livelock_tombstones: livelock_stats.active_tombstones,
            livelock_pending_proof_fetches: livelock_stats.pending_proof_fetches,
            livelock_pending_abort_intents: livelock_stats.pending_abort_intents,
            livelock_tracked_txs: livelock_stats.tracked_transactions,
            // Storage
            jvt_node_cache_entries: self.storage.node_cache_len(),
            rocksdb_block_cache_usage_bytes: rocksdb_bc,
            rocksdb_memtable_usage_bytes: rocksdb_mt,
        });
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
        }
    }

    /// Flush ALL pending batches immediately, regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        self.flush_block_commits();

        // When commit_in_flight is true, flush_block_commits returns
        // without draining receipts — flush them independently here.
        self.flush_pending_receipts();

        self.flush_validation_batch();
        self.flush_committed_header_verifications();
    }
}
