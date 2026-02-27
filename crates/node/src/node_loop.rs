//! Unified node loop for action processing.
//!
//! `NodeLoop` handles ALL actions from `NodeStateMachine`, dispatching them via
//! generic trait methods (Network, Dispatch, Storage) and concrete types for
//! timer ops and event delivery. Both production and simulation runners construct
//! a `NodeLoop` with their concrete trait implementations.
//!
//! # Driving modes
//!
//! - **Production**: `NodeLoop::run()` blocks on a crossbeam channel, processing
//!   events as they arrive from tokio bridge tasks.
//! - **Simulation**: The harness calls `NodeLoop::step()` per event, then drains
//!   buffered outputs (timer ops, events, sync I/O).
//!
//! # Batching
//!
//! NodeLoop batches execution-layer broadcasts and crypto verification for
//! efficiency. Batch deadlines are tracked as logical time (`Duration`) so both
//! production (wall clock) and simulation (logical clock) use the same paths.

use crate::action_handler::{self, ActionContext, DispatchPool};
use crate::batch_accumulator::{BatchAccumulator, ShardedBatchAccumulator};
use crate::fetch_protocol::{FetchConfig, FetchInput, FetchKind, FetchOutput, FetchProtocol};
use crate::sync_protocol::{SyncInput, SyncOutput, SyncProtocol, SyncStatus};
use crate::NodeStateMachine;
use hyperscale_core::{
    Action, CrossShardExecutionRequest, Event, ProtocolEvent, StateMachine, TimerId,
};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::{RadixExecutor, TransactionValidation};
use hyperscale_messages::{
    StateCertificateBatch, StateProvisionBatch, StateVoteBatch, TransactionCertificateGossip,
    TransactionGossip,
};
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Hash, RoutableTransaction, ShardGroupId,
    StateCertificate, StateVoteBlock, Topology, TransactionCertificate, ValidatorId,
};
use quick_cache::sync::Cache as QuickCache;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Default certificate cache capacity.
const DEFAULT_CERT_CACHE_SIZE: usize = 10_000;
/// Default transaction cache capacity.
const DEFAULT_TX_CACHE_SIZE: usize = 50_000;
/// Default transaction status cache capacity.
const DEFAULT_TX_STATUS_CACHE_SIZE: usize = 100_000;
/// Maximum age for pending gossip certificate verifications before cleanup.
const PENDING_GOSSIP_CERT_TIMEOUT: Duration = Duration::from_secs(30);

/// Pending verification of a gossiped TransactionCertificate.
///
/// When we receive a TransactionCertificate via gossip, we verify each embedded
/// StateCertificate's BLS signature before persisting. This tracks the verification
/// progress for a single certificate.
struct PendingGossipVerification {
    /// The certificate being verified.
    certificate: Arc<TransactionCertificate>,
    /// Shards still awaiting verification callback.
    pending_shards: HashSet<ShardGroupId>,
    /// Whether any verification has failed.
    failed: bool,
    /// When this verification started (logical time from state.now()).
    created_at: Duration,
}

// ═══════════════════════════════════════════════════════════════════════
// Batching configuration
// ═══════════════════════════════════════════════════════════════════════

/// Maximum items in a cross-shard execution batch before forced flush.
const BATCH_MAX_CROSS_SHARD_EXECUTIONS: usize = 256;
/// Batch window for cross-shard executions.
const BATCH_WINDOW_CROSS_SHARD_EXECUTIONS: Duration = Duration::from_millis(5);

/// Maximum items in a state vote verification batch before forced flush.
const BATCH_MAX_STATE_VOTES: usize = 64;
/// Batch window for state vote verification.
const BATCH_WINDOW_STATE_VOTES: Duration = Duration::from_millis(20);

/// Maximum items in a state cert verification batch before forced flush.
const BATCH_MAX_STATE_CERTS: usize = 64;
/// Batch window for state certificate verification.
const BATCH_WINDOW_STATE_CERTS: Duration = Duration::from_millis(15);

/// Maximum items in a broadcast state vote batch before forced flush.
const BATCH_MAX_BROADCAST_STATE_VOTES: usize = 64;
/// Batch window for broadcast state votes.
const BATCH_WINDOW_BROADCAST_STATE_VOTES: Duration = Duration::from_millis(15);

/// Maximum items in a broadcast state cert batch before forced flush.
const BATCH_MAX_BROADCAST_STATE_CERTS: usize = 64;
/// Batch window for broadcast state certificates.
const BATCH_WINDOW_BROADCAST_STATE_CERTS: Duration = Duration::from_millis(15);

/// Maximum items in a broadcast state provision batch before forced flush.
const BATCH_MAX_BROADCAST_PROVISIONS: usize = 64;
/// Batch window for broadcast state provisions.
const BATCH_WINDOW_BROADCAST_PROVISIONS: Duration = Duration::from_millis(15);

/// Maximum transactions in a validation batch before forced flush.
const BATCH_MAX_TX_VALIDATION: usize = 128;
/// Batch window for transaction validation.
const BATCH_WINDOW_TX_VALIDATION: Duration = Duration::from_millis(20);

/// A single state-vote verification item: (tx_hash, votes with public keys and voting power).
type StateVoteVerificationItem = (Hash, Vec<(StateVoteBlock, Bls12381G1PublicKey, u64)>);

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// A timer operation buffered by NodeLoop for the runner to process.
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

/// Output from processing a single event via `NodeLoop::step()`.
///
/// NodeLoop now handles all sync/fetch I/O internally via the Network trait.
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
/// Produced by [`NodeLoop::status_snapshot()`] on the periodic metrics tick.
/// The production runner maps this into its RPC shared state types.
#[derive(Debug, Clone)]
pub struct NodeStatusSnapshot {
    pub committed_height: u64,
    pub view: u64,
    pub state_version: u64,
    pub state_root: Hash,
    pub sync: SyncStatus,
    pub mempool_pending: usize,
    /// Block committed, being executed.
    pub mempool_committed: usize,
    /// Execution done, awaiting certificate.
    pub mempool_executed: usize,
    pub mempool_total: usize,
    /// Waiting for winner.
    pub mempool_deferred: usize,
    pub accepting_rpc_transactions: bool,
    pub at_pending_limit: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// NodeLoop
// ═══════════════════════════════════════════════════════════════════════

/// Unified node loop that processes all actions from the state machine.
///
/// Generic over:
/// - `S`: Storage (CommitStore + SubstateStore + ConsensusStore)
/// - `N`: Network (message sending)
/// - `D`: Dispatch (thread pool work scheduling)
pub struct NodeLoop<S, N, D>
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
    event_sender: crossbeam::channel::Sender<Event>,

    // Identity
    signing_key: Arc<Bls12381G1PrivateKey>,
    topology: Arc<dyn Topology>,
    local_shard: ShardGroupId,
    validator_id: ValidatorId,

    // Prepared commit cache (shared with dispatch closures)
    prepared_commits: Arc<Mutex<HashMap<Hash, S::PreparedCommit>>>,

    // In-memory caches (shared with InboundRouter in production)
    cert_cache: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    tx_cache: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,

    // Gossip certificate verification tracking
    pending_gossip_verifications: HashMap<Hash, PendingGossipVerification>,

    // Sync protocol
    sync_protocol: SyncProtocol,

    // Fetch protocol (transaction/certificate fetching with chunking and retry)
    fetch_protocol: FetchProtocol,

    // Transaction validation
    tx_validator: Arc<TransactionValidation>,
    pending_validation: HashSet<Hash>,
    locally_submitted: HashSet<Hash>,

    // Batch accumulators
    validation_batch: BatchAccumulator<Arc<RoutableTransaction>>,
    cross_shard_batch: BatchAccumulator<CrossShardExecutionRequest>,
    state_vote_batch: BatchAccumulator<StateVoteVerificationItem>,
    state_cert_batch: BatchAccumulator<(StateCertificate, Vec<Bls12381G1PublicKey>)>,
    broadcast_vote_batch: ShardedBatchAccumulator<StateVoteBlock>,
    broadcast_cert_batch: ShardedBatchAccumulator<Arc<StateCertificate>>,
    broadcast_provision_batch: ShardedBatchAccumulator<hyperscale_types::StateProvision>,

    // Transaction status cache — retains the latest status for every transaction
    // that has emitted a status notification. Bounded LRU cache shared (via Arc)
    // with external consumers (e.g. RPC handlers in production).
    tx_status_cache: Arc<QuickCache<Hash, hyperscale_types::TransactionStatus>>,

    // Accumulated outputs from this step (for caller to drain)
    emitted_statuses: Vec<(Hash, hyperscale_types::TransactionStatus)>,
    actions_generated: usize,
    pending_timer_ops: Vec<TimerOp>,
}

impl<S, N, D> NodeLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    /// Create a new NodeLoop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: NodeStateMachine,
        storage: S,
        executor: RadixExecutor,
        network: N,
        dispatch: D,
        event_sender: crossbeam::channel::Sender<Event>,
        signing_key: Bls12381G1PrivateKey,
        topology: Arc<dyn Topology>,
        sync_protocol: SyncProtocol,
        tx_validator: Arc<TransactionValidation>,
    ) -> Self {
        let local_shard = topology.local_shard();
        let validator_id = topology.local_validator_id();
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
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            cert_cache: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            tx_cache: Arc::new(QuickCache::new(DEFAULT_TX_CACHE_SIZE)),
            pending_gossip_verifications: HashMap::new(),
            tx_validator,
            pending_validation: HashSet::new(),
            locally_submitted: HashSet::new(),
            sync_protocol,
            fetch_protocol: FetchProtocol::new(FetchConfig::default()),
            validation_batch: BatchAccumulator::new(
                BATCH_MAX_TX_VALIDATION,
                BATCH_WINDOW_TX_VALIDATION,
            ),
            cross_shard_batch: BatchAccumulator::new(
                BATCH_MAX_CROSS_SHARD_EXECUTIONS,
                BATCH_WINDOW_CROSS_SHARD_EXECUTIONS,
            ),
            state_vote_batch: BatchAccumulator::new(
                BATCH_MAX_STATE_VOTES,
                BATCH_WINDOW_STATE_VOTES,
            ),
            state_cert_batch: BatchAccumulator::new(
                BATCH_MAX_STATE_CERTS,
                BATCH_WINDOW_STATE_CERTS,
            ),
            broadcast_vote_batch: ShardedBatchAccumulator::new(
                BATCH_MAX_BROADCAST_STATE_VOTES,
                BATCH_WINDOW_BROADCAST_STATE_VOTES,
            ),
            broadcast_cert_batch: ShardedBatchAccumulator::new(
                BATCH_MAX_BROADCAST_STATE_CERTS,
                BATCH_WINDOW_BROADCAST_STATE_CERTS,
            ),
            broadcast_provision_batch: ShardedBatchAccumulator::new(
                BATCH_MAX_BROADCAST_PROVISIONS,
                BATCH_WINDOW_BROADCAST_PROVISIONS,
            ),
            tx_status_cache: Arc::new(QuickCache::new(DEFAULT_TX_STATUS_CACHE_SIZE)),
            emitted_statuses: Vec::new(),
            actions_generated: 0,
            pending_timer_ops: Vec::new(),
        }
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
    /// that must be processed through the NodeLoop's action handler.
    pub fn handle_actions(&mut self, actions: Vec<Action>) {
        for action in actions {
            self.process_action(action);
        }
    }

    /// Access storage mutably and executor simultaneously.
    ///
    /// Needed for operations like genesis that require both references.
    /// Rust's borrow checker can't split borrows through separate method calls.
    ///
    /// # Genesis initialization ordering
    ///
    /// Runners must follow this sequence:
    /// 1. **Engine genesis** via `with_storage_and_executor()` (requires sole Arc ownership)
    /// 2. **Handler registration** using [`storage_arc()`], [`tx_cache()`], [`cert_cache()`],
    ///    and [`event_sender()`] (clones the Arc, so must happen after step 1)
    /// 3. **State-machine genesis** via `state_mut().initialize_genesis()` followed by
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
        f(storage, &self.executor)
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

    /// Access the event sender.
    pub fn event_sender(&self) -> &crossbeam::channel::Sender<Event> {
        &self.event_sender
    }

    /// Access the network.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Access the certificate cache.
    pub fn cert_cache(&self) -> &Arc<QuickCache<Hash, Arc<TransactionCertificate>>> {
        &self.cert_cache
    }

    /// Access the transaction cache.
    pub fn tx_cache(&self) -> &Arc<QuickCache<Hash, Arc<RoutableTransaction>>> {
        &self.tx_cache
    }

    /// Get a shared reference to the storage (Arc clone).
    ///
    /// Used by the simulation harness to construct an `InboundHandler` that
    /// shares the same storage instance as this NodeLoop (same pattern as
    /// production, where both NodeLoop and InboundRouter share `Arc<Storage>`).
    pub fn storage_arc(&self) -> Arc<S> {
        Arc::clone(&self.storage)
    }

    /// Access the sync protocol.
    pub fn sync_protocol(&self) -> &SyncProtocol {
        &self.sync_protocol
    }

    /// Mutably access the sync protocol.
    pub fn sync_protocol_mut(&mut self) -> &mut SyncProtocol {
        &mut self.sync_protocol
    }

    /// Access the dispatch.
    pub fn dispatch(&self) -> &D {
        &self.dispatch
    }

    /// Access the executor.
    pub fn executor(&self) -> &RadixExecutor {
        &self.executor
    }

    /// Access the signing key.
    pub fn signing_key(&self) -> &Bls12381G1PrivateKey {
        &self.signing_key
    }

    /// Access the topology.
    pub fn topology(&self) -> &Arc<dyn Topology> {
        &self.topology
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
    pub fn step(&mut self, event: Event) -> StepOutput {
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
            Event::TransactionValidated {
                tx,
                submitted_locally,
            } => {
                let tx_hash = tx.hash();
                self.pending_validation.remove(&tx_hash);
                let is_local = submitted_locally || self.locally_submitted.remove(&tx_hash);
                self.tx_cache.insert(tx_hash, Arc::clone(&tx));
                let pe = ProtocolEvent::TransactionGossipReceived {
                    tx,
                    submitted_locally: is_local,
                };
                let actions = self.state.handle(pe);
                self.actions_generated = actions.len();
                for action in actions {
                    self.process_action(action);
                }
            }

            // Intercept gossip-received transactions for validation.
            Event::Protocol(ProtocolEvent::TransactionGossipReceived { tx, .. }) => {
                let tx_hash = tx.hash();
                if self.tx_cache.get(&tx_hash).is_none()
                    && !self.state.mempool().is_tombstoned(&tx_hash)
                {
                    self.pending_validation.insert(tx_hash);
                    self.queue_validation(tx);
                }
            }

            Event::SubmitTransaction { tx } => {
                let tx_hash = tx.hash();

                // Gossip to all relevant shards.
                for shard in self.topology.all_shards_for_transaction(&tx) {
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

            Event::TransactionCertificateReceived { certificate } => {
                self.handle_gossiped_certificate(certificate);
            }

            Event::GossipedCertificateSignatureVerified {
                tx_hash,
                shard,
                valid,
            } => {
                self.handle_gossip_cert_result(tx_hash, shard, valid);
            }

            // ── Sync protocol ──────────────────────────────────────────
            Event::SyncBlockResponseReceived { height, block } => {
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockResponseReceived { height, block });
                self.process_sync_outputs(outputs);
            }

            Event::SyncBlockFetchFailed { height } => {
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockFetchFailed { height });
                self.process_sync_outputs(outputs);
            }

            // ── Fetch protocol ─────────────────────────────────────────
            Event::TransactionReceived {
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

            Event::CertificateReceived {
                block_hash,
                certificates,
            } => {
                let outputs = self
                    .fetch_protocol
                    .handle(FetchInput::CertificatesReceived {
                        block_hash,
                        certificates,
                    });
                self.process_fetch_outputs(outputs);
            }

            Event::FetchTransactionsFailed { block_hash, hashes } => {
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

            Event::FetchCertificatesFailed { block_hash, hashes } => {
                let outputs = self.fetch_protocol.handle(FetchInput::FetchFailed {
                    block_hash,
                    kind: FetchKind::Certificate,
                    hashes,
                });
                self.process_fetch_outputs(outputs);
                // Tick to retry pending fetches.
                let tick_outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(tick_outputs);
                self.update_fetch_tick_timer();
            }

            Event::FetchTick => {
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }

            // ── Protocol events → state machine ────────────────────────
            Event::Protocol(pe) => {
                // Broadcast self-generated state votes returning from dispatch.
                // Votes from peers arrive via network gossip.
                if let ProtocolEvent::StateVoteReceived { ref vote } = pe {
                    if vote.validator == self.validator_id {
                        self.accumulate_broadcast_vote(self.local_shard, vote.clone());
                    }
                }

                let actions = self.state.handle(pe);
                self.actions_generated = actions.len();
                for action in actions {
                    self.process_action(action);
                }
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

    /// Flush any batch accumulators whose deadlines have expired.
    ///
    /// Call this with the current time before processing events. In production,
    /// the loop calls this with wall-clock time. In simulation, the harness
    /// calls it with logical time.
    pub fn flush_expired_batches(&mut self, now: Duration) {
        if self.validation_batch.is_expired(now) {
            self.flush_validation_batch();
        }
        if self.cross_shard_batch.is_expired(now) {
            self.flush_cross_shard_executions();
        }
        if self.state_vote_batch.is_expired(now) {
            self.flush_state_vote_verifications();
        }
        if self.state_cert_batch.is_expired(now) {
            self.flush_state_cert_verifications();
        }
        if self.broadcast_vote_batch.is_expired(now) {
            self.flush_broadcast_votes();
        }
        if self.broadcast_cert_batch.is_expired(now) {
            self.flush_broadcast_certs();
        }
        if self.broadcast_provision_batch.is_expired(now) {
            self.flush_broadcast_provisions();
        }

        // Clean up stale pending gossip cert verifications.
        let before = self.pending_gossip_verifications.len();
        self.pending_gossip_verifications.retain(|_, pending| {
            now.saturating_sub(pending.created_at) < PENDING_GOSSIP_CERT_TIMEOUT
        });
        let cleaned = before - self.pending_gossip_verifications.len();
        if cleaned > 0 {
            warn!(
                cleaned,
                remaining = self.pending_gossip_verifications.len(),
                "Cleaned up stale pending gossip cert verifications"
            );
        }
    }

    /// Get the nearest batch deadline, if any.
    ///
    /// Used by the production `run()` loop for `recv_timeout()` and by the
    /// simulation harness to know when to schedule a flush.
    pub fn nearest_batch_deadline(&self) -> Option<Duration> {
        [
            self.validation_batch.deadline(),
            self.cross_shard_batch.deadline(),
            self.state_vote_batch.deadline(),
            self.state_cert_batch.deadline(),
            self.broadcast_vote_batch.deadline(),
            self.broadcast_cert_batch.deadline(),
            self.broadcast_provision_batch.deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    // ─── Action Processing ──────────────────────────────────────────────

    /// Process a single action from the state machine.
    fn process_action(&mut self, action: Action) {
        match action {
            // ═══════════════════════════════════════════════════════════
            // Timers
            // ═══════════════════════════════════════════════════════════
            Action::SetTimer { id, duration } => {
                self.pending_timer_ops.push(TimerOp::Set { id, duration });
            }
            Action::CancelTimer { id } => {
                self.pending_timer_ops.push(TimerOp::Cancel { id });
            }

            // ═══════════════════════════════════════════════════════════
            // Internal events
            // ═══════════════════════════════════════════════════════════
            Action::Continuation(pe) => {
                let _ = self.event_sender.send(Event::Protocol(pe));
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — immediate (non-batched)
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastBlockHeader { shard, header } => {
                self.network.broadcast_to_shard(shard, &*header);
            }
            Action::BroadcastBlockVote { shard, vote } => {
                self.network.broadcast_to_shard(shard, &vote);
            }
            Action::BroadcastTransaction { shard, gossip } => {
                self.network.broadcast_to_shard(shard, &*gossip);
            }
            Action::BroadcastTransactionCertificate { shard, gossip } => {
                self.network.broadcast_to_shard(shard, &gossip);
            }

            // ═══════════════════════════════════════════════════════════
            // Network broadcasts — batched
            // ═══════════════════════════════════════════════════════════
            Action::BroadcastStateVote { shard, vote } => {
                self.accumulate_broadcast_vote(shard, vote);
            }
            Action::BroadcastStateCertificate { shard, certificate } => {
                self.accumulate_broadcast_cert(shard, certificate);
            }
            Action::BroadcastStateProvision { shard, provision } => {
                self.accumulate_broadcast_provision(shard, provision);
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated work — batched (accumulated for batch dispatch)
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndAggregateStateVotes { tx_hash, votes } => {
                self.accumulate_state_vote_verification((tx_hash, votes));
            }
            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                self.accumulate_state_cert_verification(certificate, public_keys);
            }
            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                self.accumulate_cross_shard_execution(tx_hash, transaction, provisions);
            }

            // ═══════════════════════════════════════════════════════════
            // Delegated work — immediate dispatch
            // ═══════════════════════════════════════════════════════════
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyCycleProof { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::BuildProposal { .. }
            | Action::AggregateStateCertificate { .. }
            | Action::VerifyAndAggregateProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::SpeculativeExecute { .. }
            | Action::ComputeMerkleRoot { .. } => {
                self.dispatch_delegated_action(action);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage writes
            // ═══════════════════════════════════════════════════════════
            Action::PersistBlock { block, qc } => {
                let height = block.header.height;
                ConsensusStore::put_block(&*self.storage, height, &block, &qc);
            }
            Action::PersistTransactionCertificate { certificate } => {
                // Populate cert cache before persisting — serves peer fetch requests
                // from memory even if storage write hasn't completed.
                self.cert_cache
                    .insert(certificate.transaction_hash, Arc::new(certificate.clone()));
                self.storage.store_certificate(&certificate);
                // Gossip cross-shard certificates to local shard peers.
                if certificate.shard_proofs.len() > 1 {
                    let gossip = TransactionCertificateGossip::new(certificate);
                    self.network.broadcast_to_shard(self.local_shard, &gossip);
                }
            }
            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard,
                vote,
            } => {
                // BFT Safety: persist vote BEFORE broadcasting.
                self.storage.put_own_vote(height.0, round, block_hash);
                trace!(
                    height = height.0,
                    round,
                    block_hash = ?block_hash,
                    "Persisted own vote"
                );
                // Now broadcast.
                self.network.broadcast_to_shard(shard, &vote);
            }

            // ═══════════════════════════════════════════════════════════
            // Storage reads (dispatched to execution pool)
            // ═══════════════════════════════════════════════════════════
            Action::FetchStateEntries { tx_hash, nodes } => {
                let storage = &*self.storage;
                let entries = self.executor.fetch_state_entries(storage, &nodes);
                trace!(
                    ?tx_hash,
                    nodes = nodes.len(),
                    entries = entries.len(),
                    "Fetched state entries"
                );
                let _ =
                    self.event_sender
                        .send(Event::Protocol(ProtocolEvent::StateEntriesFetched {
                            tx_hash,
                            entries,
                        }));
            }
            Action::FetchBlock { height } => {
                let block = self.storage.get_block(height);
                let _ = self
                    .event_sender
                    .send(Event::Protocol(ProtocolEvent::BlockFetched {
                        height,
                        block: block.map(|(b, _)| b),
                    }));
            }
            Action::FetchChainMetadata => {
                let height = self.storage.committed_height();
                let hash = self.storage.committed_hash();
                let qc = self.storage.latest_qc();
                let _ =
                    self.event_sender
                        .send(Event::Protocol(ProtocolEvent::ChainMetadataFetched {
                            height,
                            hash,
                            qc,
                        }));
            }

            // ═══════════════════════════════════════════════════════════
            // Block commit
            // ═══════════════════════════════════════════════════════════
            Action::EmitCommittedBlock { block, qc } => {
                let block_hash = block.hash();
                let height = block.header.height;
                debug!(height = height.0, ?block_hash, "Block committed");

                // Block commit latency: time from proposal timestamp to now.
                let now_ms = self.state.now().as_millis() as u64;
                let commit_latency_secs =
                    (now_ms.saturating_sub(block.header.timestamp)) as f64 / 1000.0;
                metrics::record_block_committed(height.0, commit_latency_secs);
                metrics::set_block_height(height.0);
                metrics::set_txs_with_commitment_proof(block.commitment_proofs.len());

                // Livelock metrics for deferrals in this block.
                for _deferral in &block.deferred {
                    metrics::record_livelock_deferral();
                    metrics::record_livelock_cycle_detected();
                }
                metrics::set_livelock_deferred_count(
                    self.state.livelock().stats().pending_deferrals,
                );

                let prepared = self.prepared_commits.lock().unwrap().remove(&block_hash);

                if let Some(commit_event) = action_handler::commit_block(
                    &*self.storage,
                    &block,
                    block_hash,
                    height,
                    &qc,
                    self.local_shard,
                    prepared,
                ) {
                    let _ = self.event_sender.send(commit_event);
                }

                // Feed committed height to sync protocol.
                let outputs = self
                    .sync_protocol
                    .handle(SyncInput::BlockCommitted { height: height.0 });
                self.process_sync_outputs(outputs);
            }

            // ═══════════════════════════════════════════════════════════
            // Notifications
            // ═══════════════════════════════════════════════════════════
            Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally,
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                // Only record latency metrics for locally-submitted transactions to
                // avoid polluting latency histograms with transactions received via
                // gossip/sync which would have artificially high latencies on lagging
                // nodes.
                if status.is_final() && submitted_locally {
                    let now = self.state.now();
                    let latency_secs = now.saturating_sub(added_at).as_secs_f64();
                    metrics::record_transaction_finalized(latency_secs, cross_shard);
                }
                self.tx_status_cache.insert(tx_hash, status.clone());
                self.emitted_statuses.push((tx_hash, status));
            }

            // ═══════════════════════════════════════════════════════════
            // Sync/Fetch (protocol state machine + runner I/O)
            // ═══════════════════════════════════════════════════════════
            Action::StartSync {
                target_height,
                target_hash,
            } => {
                let outputs = self.sync_protocol.handle(SyncInput::StartSync {
                    target_height,
                    target_hash,
                });
                self.process_sync_outputs(outputs);
            }
            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                // Feed to FetchProtocol for chunking and concurrency management.
                self.fetch_protocol.handle(FetchInput::RequestTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                });
                // Immediately tick to spawn pending fetch operations.
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                // Feed to FetchProtocol for chunking and concurrency management.
                self.fetch_protocol.handle(FetchInput::RequestCertificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                });
                // Immediately tick to spawn pending fetch operations.
                let outputs = self.fetch_protocol.handle(FetchInput::Tick);
                self.process_fetch_outputs(outputs);
                self.update_fetch_tick_timer();
            }
            Action::CancelFetch { block_hash } => {
                self.fetch_protocol
                    .handle(FetchInput::CancelFetch { block_hash });
            }

            // ═══════════════════════════════════════════════════════════
            // Global consensus (not yet implemented)
            // ═══════════════════════════════════════════════════════════
            Action::ProposeGlobalBlock { epoch, height, .. } => {
                trace!(?epoch, ?height, "ProposeGlobalBlock - not yet implemented");
            }
            Action::BroadcastGlobalBlockVote {
                block_hash, shard, ..
            } => {
                trace!(
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
                debug!(
                    ?from_epoch,
                    ?to_epoch,
                    "TransitionEpoch - not yet implemented"
                );
            }
            Action::MarkValidatorReady { epoch, shard } => {
                debug!(?epoch, ?shard, "MarkValidatorReady - not yet implemented");
            }
            Action::InitiateShardSplit {
                source_shard,
                new_shard,
                split_point,
            } => {
                trace!(
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
                trace!(
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
                trace!(
                    ?shard_a,
                    ?shard_b,
                    ?merged_shard,
                    "InitiateShardMerge - not yet implemented"
                );
            }
            Action::CompleteShardMerge { merged_shard } => {
                trace!(?merged_shard, "CompleteShardMerge - not yet implemented");
            }
            Action::PersistEpochConfig { .. } => {
                debug!("PersistEpochConfig - not yet implemented");
            }
            Action::FetchEpochConfig { epoch } => {
                debug!(?epoch, "FetchEpochConfig - not yet implemented");
            }
        }
    }

    // ─── Delegated Work ─────────────────────────────────────────────────

    /// Dispatch a delegated action to the appropriate thread pool.
    ///
    /// Spawns the work as a fire-and-forget closure. Results return via the
    /// `event_sender` channel and are processed on a future `step()` call.
    /// With `SyncDispatch` (simulation), `spawn_*` runs inline so events
    /// enter the channel immediately and are drained by the harness.
    fn dispatch_delegated_action(&mut self, action: Action) {
        let is_speculative = matches!(action, Action::SpeculativeExecute { .. });
        let is_execution = is_speculative || matches!(action, Action::ExecuteTransactions { .. });
        let pool = action_handler::dispatch_pool_for(&action)
            .expect("dispatch_delegated_action called for delegated actions only");

        // Clone cheap shared state for the 'static spawn closure.
        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let topology = Arc::clone(&self.topology);
        let signing_key = Arc::clone(&self.signing_key);
        let dispatch = self.dispatch.clone();
        let local_shard = self.local_shard;
        let validator_id = self.validator_id;
        let prepared_commits = Arc::clone(&self.prepared_commits);
        let event_tx = self.event_sender.clone();

        let spawn_fn = move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                topology: &*topology,
                signing_key: &signing_key,
                local_shard,
                validator_id,
                dispatch: &dispatch,
            };
            if let Some(result) = action_handler::handle_delegated_action(action, &ctx) {
                if is_execution {
                    let elapsed = start.elapsed().as_secs_f64();
                    if is_speculative {
                        metrics::record_speculative_execution_latency(elapsed);
                    } else {
                        metrics::record_execution_latency(elapsed);
                    }
                }
                if let Some((hash, prepared)) = result.prepared_commit {
                    prepared_commits.lock().unwrap().insert(hash, prepared);
                }
                for event in result.events {
                    let _ = event_tx.send(event);
                }
            }
        };

        match pool {
            DispatchPool::ConsensusCrypto => self.dispatch.spawn_consensus_crypto(spawn_fn),
            DispatchPool::Crypto => self.dispatch.spawn_crypto(spawn_fn),
            DispatchPool::Execution => self.dispatch.spawn_execution(spawn_fn),
        }
    }

    /// Process SyncProtocol outputs internally.
    ///
    /// DeliverBlock and SyncComplete are fed directly to the state machine
    /// (no round-trip through the runner). FetchBlock uses the Network trait.
    fn process_sync_outputs(&mut self, outputs: Vec<SyncOutput>) {
        for output in outputs {
            match output {
                SyncOutput::FetchBlock { height } => {
                    use hyperscale_messages::request::GetBlockRequest;
                    let es = self.event_sender.clone();
                    self.network.request(
                        None,
                        GetBlockRequest {
                            height: hyperscale_types::BlockHeight(height),
                        },
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let block = match (resp.block, resp.qc) {
                                    (Some(b), Some(q)) => Some((b, q)),
                                    _ => None,
                                };
                                let _ = es.send(Event::SyncBlockResponseReceived {
                                    height,
                                    block: Box::new(block),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(Event::SyncBlockFetchFailed { height });
                            }
                        }),
                    );
                }
                SyncOutput::DeliverBlock { block, qc } => {
                    metrics::record_sync_block_received_by_bft();
                    metrics::record_sync_block_submitted_for_verification();
                    let actions = self.state.handle(ProtocolEvent::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                    });
                    self.actions_generated += actions.len();
                    for action in actions {
                        self.process_action(action);
                    }
                }
                SyncOutput::SyncComplete { height } => {
                    let actions = self.state.handle(ProtocolEvent::SyncComplete { height });
                    self.actions_generated += actions.len();
                    for action in actions {
                        self.process_action(action);
                    }
                }
            }
        }
    }

    /// Process FetchProtocol outputs.
    ///
    /// FetchTransactions/FetchCertificates use the Network trait to make requests.
    /// DeliverTransactions/DeliverCertificates feed events directly to the state machine.
    fn process_fetch_outputs(&mut self, outputs: Vec<FetchOutput>) {
        for output in outputs {
            match output {
                FetchOutput::FetchTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                } => {
                    use hyperscale_messages::request::GetTransactionsRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = tx_hashes.clone();
                    self.network.request(
                        Some(proposer),
                        GetTransactionsRequest::new(block_hash, tx_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let _ = es.send(Event::TransactionReceived {
                                    block_hash: bh,
                                    transactions: resp.into_transactions(),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(Event::FetchTransactionsFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                FetchOutput::FetchCertificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                } => {
                    use hyperscale_messages::request::GetCertificatesRequest;
                    let es = self.event_sender.clone();
                    let bh = block_hash;
                    let hs = cert_hashes.clone();
                    self.network.request(
                        Some(proposer),
                        GetCertificatesRequest::new(block_hash, cert_hashes),
                        Box::new(move |result| match result {
                            Ok(resp) => {
                                let _ = es.send(Event::CertificateReceived {
                                    block_hash: bh,
                                    certificates: resp.into_certificates(),
                                });
                            }
                            Err(_) => {
                                let _ = es.send(Event::FetchCertificatesFailed {
                                    block_hash: bh,
                                    hashes: hs,
                                });
                            }
                        }),
                    );
                }
                FetchOutput::DeliverTransactions {
                    block_hash,
                    transactions,
                } => {
                    let actions = self.state.handle(ProtocolEvent::TransactionFetchDelivered {
                        block_hash,
                        transactions,
                    });
                    self.actions_generated += actions.len();
                    for action in actions {
                        self.process_action(action);
                    }
                }
                FetchOutput::DeliverCertificates {
                    block_hash,
                    certificates,
                } => {
                    // Persist fetched certificates to storage so they survive restarts.
                    for cert in &certificates {
                        self.storage.store_certificate(cert);
                    }
                    let actions = self.state.handle(ProtocolEvent::CertificateFetchDelivered {
                        block_hash,
                        certificates,
                    });
                    self.actions_generated += actions.len();
                    for action in actions {
                        self.process_action(action);
                    }
                }
            }
        }
    }

    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Set or cancel the periodic fetch tick timer based on protocol state.
    ///
    /// When the fetch protocol has pending work, a recurring timer fires
    /// `Event::FetchTick` to retry deferred or failed fetch operations.
    /// When all fetches are complete, the timer is cancelled.
    fn update_fetch_tick_timer(&mut self) {
        let status = self.fetch_protocol.status();
        if status.pending_tx_blocks > 0 || status.pending_cert_blocks > 0 {
            self.pending_timer_ops.push(TimerOp::Set {
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            });
        } else {
            self.pending_timer_ops.push(TimerOp::Cancel {
                id: TimerId::FetchTick,
            });
        }
    }

    // ─── Transaction Validation Batching ──────────────────────────────

    /// Queue a transaction for batch validation.
    fn queue_validation(&mut self, tx: Arc<RoutableTransaction>) {
        if self.validation_batch.push(tx, self.state.now()) {
            self.flush_validation_batch();
        }
    }

    /// Flush the validation batch, dispatching to the tx_validation pool.
    ///
    /// Valid transactions are sent back as `TransactionGossipReceived` events
    /// through the event channel. NodeLoop recognises them via `pending_validation`
    /// and passes them through to the state machine.
    fn flush_validation_batch(&mut self) {
        let batch = self.validation_batch.take();
        if batch.is_empty() {
            return;
        }

        let validator = self.tx_validator.clone();
        let event_tx = self.event_sender.clone();
        let dispatch = self.dispatch.clone();
        self.dispatch.spawn_tx_validation(move || {
            // Validate in parallel across all tx_validation pool threads,
            // then send results sequentially to preserve ordering.
            let results: Vec<bool> =
                dispatch.map_tx_validation(&batch, |tx| validator.validate_transaction(tx).is_ok());

            for (tx, valid) in batch.into_iter().zip(results) {
                if valid {
                    let _ = event_tx.send(Event::TransactionValidated {
                        tx,
                        submitted_locally: false, // NodeLoop sets from locally_submitted
                    });
                }
            }
        });
    }

    /// Flush a batch of cross-shard executions to the execution pool.
    fn flush_cross_shard_executions(&mut self) {
        let requests = self.cross_shard_batch.take();
        if requests.is_empty() {
            return;
        }

        let storage = Arc::clone(&self.storage);
        let executor = self.executor.clone();
        let topology = Arc::clone(&self.topology);
        let signing_key = Arc::clone(&self.signing_key);
        let dispatch = self.dispatch.clone();
        let local_shard = self.local_shard;
        let validator_id = self.validator_id;
        let event_tx = self.event_sender.clone();

        self.dispatch.spawn_execution(move || {
            let start = std::time::Instant::now();
            let ctx = ActionContext {
                storage: &*storage,
                executor: &executor,
                topology: &*topology,
                signing_key: &signing_key,
                local_shard,
                validator_id,
                dispatch: &dispatch,
            };
            let events = action_handler::handle_cross_shard_batch(&requests, &ctx);
            metrics::record_execution_latency(start.elapsed().as_secs_f64());
            for event in events {
                let _ = event_tx.send(event);
            }
        });
    }

    /// Flush a batch of state vote verifications.
    fn flush_state_vote_verifications(&mut self) {
        let items = self.state_vote_batch.take();
        if items.is_empty() {
            return;
        }

        // Dispatch each item individually through handle_delegated_action.
        // In production, these would be batched into a single BLS verify call.
        // For now, process individually.
        for (tx_hash, votes) in items {
            let action = Action::VerifyAndAggregateStateVotes { tx_hash, votes };
            self.dispatch_delegated_action(action);
        }
    }

    /// Flush a batch of state certificate verifications.
    fn flush_state_cert_verifications(&mut self) {
        let items = self.state_cert_batch.take();
        if items.is_empty() {
            return;
        }

        for (certificate, public_keys) in items {
            let action = Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            };
            self.dispatch_delegated_action(action);
        }
    }

    // ─── Gossip Certificate Verification ─────────────────────────────────

    /// Handle a gossiped TransactionCertificate.
    ///
    /// Verifies each embedded StateCertificate's BLS signature before persisting
    /// to prevent malicious peers from filling storage with invalid certificates.
    fn handle_gossiped_certificate(&mut self, certificate: TransactionCertificate) {
        let tx_hash = certificate.transaction_hash;

        // Fast path: skip if we built this certificate locally (O(1) cache check).
        if self.cert_cache.get(&tx_hash).is_some() {
            return;
        }

        // Skip if already in verification pipeline.
        if self.pending_gossip_verifications.contains_key(&tx_hash) {
            return;
        }

        // Skip if already persisted in storage.
        if self.storage.get_certificate(&tx_hash).is_some() {
            return;
        }

        // Collect shards that need verification.
        let pending_shards: HashSet<ShardGroupId> =
            certificate.shard_proofs.keys().copied().collect();

        let certificate = Arc::new(certificate);

        if pending_shards.is_empty() {
            // Empty certificate (no shard proofs) - persist directly.
            self.persist_and_notify_gossiped_certificate(certificate);
            return;
        }

        let now = self.state.now();

        // Track pending verification.
        self.pending_gossip_verifications.insert(
            tx_hash,
            PendingGossipVerification {
                certificate: Arc::clone(&certificate),
                pending_shards,
                failed: false,
                created_at: now,
            },
        );

        // Dispatch BLS signature verification for each shard proof.
        for (shard_id, state_cert) in &certificate.shard_proofs {
            let committee = self.topology.committee_for_shard(*shard_id);
            let public_keys: Vec<Bls12381G1PublicKey> = committee
                .iter()
                .filter_map(|&vid| self.topology.public_key(vid))
                .collect();

            if public_keys.len() != committee.len() {
                warn!(
                    tx_hash = ?tx_hash,
                    shard = shard_id.0,
                    "Could not resolve all public keys for gossiped certificate"
                );
                if let Some(pending) = self.pending_gossip_verifications.get_mut(&tx_hash) {
                    pending.failed = true;
                    pending.pending_shards.remove(shard_id);
                    if pending.pending_shards.is_empty() {
                        self.pending_gossip_verifications.remove(&tx_hash);
                    }
                }
                continue;
            }

            let es = self.event_sender.clone();
            let shard = *shard_id;
            let cert = state_cert.clone();

            self.dispatch.spawn_crypto(move || {
                let start = std::time::Instant::now();
                let valid = hyperscale_execution::handlers::verify_state_certificate_signature(
                    &cert,
                    &public_keys,
                );
                metrics::record_signature_verification_latency(
                    "bls_state_cert",
                    start.elapsed().as_secs_f64(),
                );
                if !valid {
                    metrics::record_signature_verification_failure();
                }
                let _ = es.send(Event::GossipedCertificateSignatureVerified {
                    tx_hash,
                    shard,
                    valid,
                });
            });
        }
    }

    /// Handle a gossip cert verification result from the crypto pool.
    fn handle_gossip_cert_result(&mut self, tx_hash: Hash, shard: ShardGroupId, valid: bool) {
        if let Some(pending) = self.pending_gossip_verifications.get_mut(&tx_hash) {
            if !valid {
                pending.failed = true;
                warn!(
                    tx_hash = ?tx_hash,
                    shard = shard.0,
                    "Gossiped certificate signature verification failed"
                );
            }
            pending.pending_shards.remove(&shard);

            if pending.pending_shards.is_empty() {
                let pending = self.pending_gossip_verifications.remove(&tx_hash).unwrap();

                if !pending.failed {
                    self.persist_and_notify_gossiped_certificate(pending.certificate);
                }
            }
        }
    }

    /// Persist a verified gossiped certificate and notify the state machine.
    fn persist_and_notify_gossiped_certificate(
        &mut self,
        certificate: Arc<TransactionCertificate>,
    ) {
        let tx_hash = certificate.transaction_hash;

        // Populate cert cache.
        self.cert_cache.insert(tx_hash, Arc::clone(&certificate));

        // Persist to storage.
        self.storage.store_certificate(&certificate);

        // Feed GossipedCertificateVerified directly to state machine.
        let actions = self
            .state
            .handle(ProtocolEvent::GossipedCertificateVerified { certificate });
        self.actions_generated += actions.len();
        for action in actions {
            self.process_action(action);
        }
    }

    // ─── Batch Accumulation ─────────────────────────────────────────────

    fn accumulate_cross_shard_execution(
        &mut self,
        tx_hash: Hash,
        transaction: Arc<hyperscale_types::RoutableTransaction>,
        provisions: Vec<hyperscale_types::StateProvision>,
    ) {
        let req = CrossShardExecutionRequest {
            tx_hash,
            transaction,
            provisions,
        };
        if self.cross_shard_batch.push(req, self.state.now()) {
            self.flush_cross_shard_executions();
        }
    }

    fn accumulate_state_vote_verification(&mut self, item: StateVoteVerificationItem) {
        let weight = item.1.len();
        if self
            .state_vote_batch
            .push_weighted(item, weight, self.state.now())
        {
            self.flush_state_vote_verifications();
        }
    }

    fn accumulate_state_cert_verification(
        &mut self,
        certificate: StateCertificate,
        public_keys: Vec<Bls12381G1PublicKey>,
    ) {
        if self
            .state_cert_batch
            .push((certificate, public_keys), self.state.now())
        {
            self.flush_state_cert_verifications();
        }
    }

    fn accumulate_broadcast_vote(&mut self, shard: ShardGroupId, vote: StateVoteBlock) {
        if self
            .broadcast_vote_batch
            .push(shard, vote, self.state.now())
        {
            self.flush_broadcast_votes();
        }
    }

    fn accumulate_broadcast_cert(&mut self, shard: ShardGroupId, cert: Arc<StateCertificate>) {
        if self
            .broadcast_cert_batch
            .push(shard, cert, self.state.now())
        {
            self.flush_broadcast_certs();
        }
    }

    fn accumulate_broadcast_provision(
        &mut self,
        shard: ShardGroupId,
        provision: hyperscale_types::StateProvision,
    ) {
        if self
            .broadcast_provision_batch
            .push(shard, provision, self.state.now())
        {
            self.flush_broadcast_provisions();
        }
    }

    // ─── Batch Flushing ─────────────────────────────────────────────────

    fn flush_broadcast_votes(&mut self) {
        for (shard, votes) in self.broadcast_vote_batch.take() {
            if !votes.is_empty() {
                let batch = StateVoteBatch::new(votes);
                self.network.broadcast_to_shard(shard, &batch);
            }
        }
    }

    fn flush_broadcast_certs(&mut self) {
        for (shard, certs) in self.broadcast_cert_batch.take() {
            if !certs.is_empty() {
                let owned: Vec<StateCertificate> =
                    certs.into_iter().map(Arc::unwrap_or_clone).collect();
                let batch = StateCertificateBatch::new(owned);
                self.network.broadcast_to_shard(shard, &batch);
            }
        }
    }

    fn flush_broadcast_provisions(&mut self) {
        for (shard, provisions) in self.broadcast_provision_batch.take() {
            if !provisions.is_empty() {
                let batch = StateProvisionBatch::new(provisions);
                self.network.broadcast_to_shard(shard, &batch);
            }
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
        metrics::set_lock_contention(contention.deferred_count, contention.contention_ratio());
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
        metrics::set_livelock_deferred_count(self.state.livelock().stats().pending_deferrals);

        // ── Gossip cert verification tracking ──
        metrics::set_pending_gossiped_cert_batch_size(self.pending_gossip_verifications.len());
    }

    /// Capture a snapshot of node state for external status APIs.
    pub fn status_snapshot(&self) -> NodeStatusSnapshot {
        let (_, state_version, state_root) = self.state.last_committed_state();
        let mempool = self.state.mempool();
        let contention = mempool.lock_contention_stats();

        NodeStatusSnapshot {
            committed_height: self.state.bft().committed_height(),
            view: self.state.bft().view(),
            state_version,
            state_root,
            sync: self.sync_protocol.status(),
            mempool_pending: contention.pending_count as usize,
            mempool_committed: contention.committed_count as usize,
            mempool_executed: contention.executed_count as usize,
            mempool_total: mempool.len(),
            mempool_deferred: contention.deferred_count as usize,
            accepting_rpc_transactions: !mempool.at_in_flight_hard_limit(),
            at_pending_limit: mempool.at_pending_limit(),
        }
    }

    /// Flush ALL pending batches immediately, regardless of deadlines.
    ///
    /// Called during shutdown or when immediate delivery is needed.
    pub fn flush_all_batches(&mut self) {
        self.flush_validation_batch();
        self.flush_cross_shard_executions();
        self.flush_state_vote_verifications();
        self.flush_state_cert_verifications();
        self.flush_broadcast_votes();
        self.flush_broadcast_certs();
        self.flush_broadcast_provisions();
    }
}
