//! Mempool state.

use hyperscale_core::{Action, FinalizationPhaseTimes, TransactionStatus};
use hyperscale_types::{
    Block, BlockHeight, Hash, NodeId, ReadyTransactions, RoutableTransaction, TopologySnapshot,
    TransactionDecision,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Default minimum dwell time for transactions before they become eligible for block inclusion.
///
/// Allows time for transaction gossip to propagate across validators before proposal,
/// improving batching and fairness.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(150);

/// Number of blocks to retain evicted transactions for peer fetch requests.
/// This allows slow validators to catch up and fetch transactions from peers
/// even after the transaction has been evicted from the active pool.
const TRANSACTION_RETENTION_BLOCKS: u64 = 50;

/// How many blocks to retain tombstones in the mempool (gossip deduplication).
const TOMBSTONE_RETENTION_BLOCKS: u64 = 500;

/// Default backpressure limit.
///
/// This limits how many transactions can be in-flight (holding state locks) at once.
/// When at this limit, no new transactions are proposed.
///
/// Set to 3× the block transaction limit to allow a full pipeline of blocks
/// (commit → execute → certify) without stalling proposal of new transactions.
pub const DEFAULT_IN_FLIGHT_LIMIT: usize = 12288;

/// Default limit on pending transactions for RPC backpressure.
///
/// When the number of Pending transactions exceeds this limit, new RPC submissions
/// are rejected. This is approximately 2 blocks worth of transactions (at 4096 TXs/block),
/// preventing the mempool from growing unboundedly when transaction arrival rate
/// exceeds processing capacity.
pub const DEFAULT_MAX_PENDING: usize = 8192;

/// Mempool configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolConfig {
    /// Maximum transactions allowed in-flight (holding state locks).
    ///
    /// When at this limit, no new transactions are proposed and RPC submissions
    /// are rejected. Controls execution/crypto verification pressure.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,

    /// Maximum pending transactions before RPC backpressure kicks in.
    ///
    /// When the number of Pending transactions exceeds this limit, new RPC submissions
    /// are rejected. This prevents unbounded mempool growth when arrival rate exceeds
    /// processing capacity. Set to approximately a few blocks worth of transactions.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,

    /// Minimum time a transaction must spend in the mempool before it can be selected
    /// for block inclusion. Transactions that have not yet met this dwell time are
    /// skipped during proposal selection but remain in the ready set.
    ///
    /// Set to zero to disable (default).
    #[serde(default = "default_min_dwell_time")]
    pub min_dwell_time: Duration,
}

fn default_max_in_flight() -> usize {
    DEFAULT_IN_FLIGHT_LIMIT
}

fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

fn default_min_dwell_time() -> Duration {
    DEFAULT_MIN_DWELL_TIME
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_IN_FLIGHT_LIMIT,
            max_pending: DEFAULT_MAX_PENDING,
            min_dwell_time: DEFAULT_MIN_DWELL_TIME,
        }
    }
}

/// Lock contention statistics from the mempool.
#[derive(Clone, Copy, Debug, Default)]
pub struct LockContentionStats {
    /// Number of nodes currently locked by in-flight transactions.
    pub locked_nodes: u64,
    /// Number of transactions in Pending status.
    pub pending_count: u64,
    /// Number of pending transactions that conflict with locked nodes.
    pub pending_deferred: u64,
    /// Number of transactions in Committed status (block committed, being executed).
    pub committed_count: u64,
    /// Number of transactions in Executed status (execution done, awaiting certificate).
    pub executed_count: u64,
}

impl LockContentionStats {
    /// Contention ratio: what fraction of pending transactions are deferred.
    pub fn contention_ratio(&self) -> f64 {
        if self.pending_count > 0 {
            self.pending_deferred as f64 / self.pending_count as f64
        } else {
            0.0
        }
    }
}

/// Mempool memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolMemoryStats {
    pub pool: usize,
    pub ready: usize,
    pub tombstones: usize,
    pub recently_evicted: usize,
    pub locked_nodes: usize,
    pub in_flight_heights: usize,
    pub deferred_by_nodes: usize,
    pub txs_deferred_by_node: usize,
    pub ready_txs_by_node: usize,
}

/// Entry in the transaction pool.
#[derive(Debug)]
struct PoolEntry {
    tx: Arc<RoutableTransaction>,
    status: TransactionStatus,
    added_at: Duration,
    /// Whether this is a cross-shard transaction (cached at insertion time).
    cross_shard: bool,
    /// Whether this transaction was submitted locally (via RPC) vs received via gossip/fetch.
    /// Only locally-submitted transactions should contribute to latency metrics.
    submitted_locally: bool,
    /// Timestamp when the block containing this tx was committed.
    committed_at_time: Option<Duration>,
    /// Timestamp when cross-shard provisions arrived for this tx.
    provisioned_at_time: Option<Duration>,
    /// Timestamp when all txs in the wave became ready (all provisioned/aborted).
    wave_ready_at_time: Option<Duration>,
    /// Timestamp when the local execution certificate was created.
    ec_created_at_time: Option<Duration>,
    /// Timestamp when the wave certificate was created (all shards reported ECs).
    executed_at_time: Option<Duration>,
}

/// Entry in the ready set.
///
/// Contains cached information needed for ready_transactions() to avoid
/// re-computing properties on each call.
#[derive(Debug, Clone)]
struct ReadyEntry {
    tx: Arc<RoutableTransaction>,
    added_at: Duration,
}

/// Mempool state machine.
///
/// Handles transaction lifecycle from submission to completion.
/// Uses `BTreeMap` for the pool to maintain hash ordering, which allows
/// ready_transactions() to iterate in sorted order without sorting.
///
/// # Incremental Ready Set
///
/// To avoid O(n) scans on every `ready_transactions()` call, we maintain
/// a pre-computed ready set that is updated incrementally.
///
/// Transactions are added to this set when they become ready (Pending status,
/// no conflicts with locked nodes) and removed when they are no longer ready
/// (status changes, conflicts arise, or evicted).
pub struct MempoolState {
    /// Transaction pool sorted by hash (BTreeMap for ordered iteration).
    pool: BTreeMap<Hash, PoolEntry>,

    /// Tombstones for transactions that have reached terminal states.
    /// Prevents re-adding completed/aborted/retried transactions via gossip.
    /// Maps: tx_hash -> block_height when tombstoned (for cleanup)
    tombstones: HashMap<Hash, BlockHeight>,

    /// Recently evicted transactions kept for peer fetch requests.
    /// Maps tx_hash -> (transaction, eviction_height).
    /// Transactions are moved here when evicted, then pruned after
    /// TRANSACTION_RETENTION_BLOCKS to allow slow peers to fetch them.
    recently_evicted: HashMap<Hash, (Arc<RoutableTransaction>, BlockHeight)>,

    /// Cached set of locked nodes (incrementally maintained).
    /// A node is locked if any transaction that declares it is in Committed or Executed status.
    /// This avoids O(n) scan on every ready_transactions() call.
    /// Note: Only one transaction can lock a node at a time (enforced by ready_transactions filtering).
    locked_nodes_cache: HashSet<NodeId>,

    /// Cached count of committed transactions (incrementally maintained).
    /// This avoids O(n) scan on every lock_contention_stats() call.
    committed_count: usize,

    /// Cached count of executed transactions (incrementally maintained).
    /// This avoids O(n) scan on every lock_contention_stats() call.
    executed_count: usize,

    // ========== Incremental Ready Set ==========
    //
    // This set is maintained incrementally to provide O(1) ready_transactions().
    // Invariants:
    // 1. A transaction is in exactly one of: ready, deferred_by_nodes, or none
    //    (if not Pending or not in pool).
    // 2. ready contains only Pending transactions with no locked node conflicts.
    // 3. deferred_by_nodes contains Pending transactions deferred by locked nodes.
    /// Ready transactions (subject to backpressure limit).
    /// BTreeMap maintains hash order for deterministic iteration.
    ready: BTreeMap<Hash, ReadyEntry>,

    /// Pending transactions deferred by locked nodes.
    /// Maps tx_hash -> set of blocking node IDs.
    /// When all blocking nodes are released, tx is promoted to a ready set.
    deferred_by_nodes: HashMap<Hash, HashSet<NodeId>>,

    /// Reverse index: node_id -> set of tx_hashes deferred by that node.
    /// Enables efficient promotion when a node is unlocked.
    txs_deferred_by_node: HashMap<NodeId, HashSet<Hash>>,

    /// Reverse index: node_id -> set of tx_hashes in ready sets that declare that node.
    /// Enables O(1) blocking when a node becomes locked.
    ready_txs_by_node: HashMap<NodeId, HashSet<Hash>>,

    /// In-flight transactions indexed by committed_at height.
    /// Enables efficient timeout scanning: only entries at old heights are checked.
    in_flight_by_height: BTreeMap<BlockHeight, Vec<Hash>>,

    /// Current time.
    now: Duration,

    /// Current committed block height (for retry transaction creation).
    current_height: BlockHeight,

    /// Configuration for mempool behavior.
    config: MempoolConfig,
}

impl std::fmt::Debug for MempoolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MempoolState")
            .field("pool_size", &self.pool.len())
            .field("ready", &self.ready.len())
            .field("deferred_by_nodes", &self.deferred_by_nodes.len())
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl Default for MempoolState {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolState {
    /// Create a new mempool state machine with default config.
    pub fn new() -> Self {
        Self::with_config(MempoolConfig::default())
    }

    /// Create a new mempool state machine with custom config.
    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            pool: BTreeMap::new(),
            tombstones: HashMap::new(),
            recently_evicted: HashMap::new(),
            locked_nodes_cache: HashSet::new(),
            committed_count: 0,
            executed_count: 0,
            ready: BTreeMap::new(),
            deferred_by_nodes: HashMap::new(),
            txs_deferred_by_node: HashMap::new(),
            ready_txs_by_node: HashMap::new(),
            in_flight_by_height: BTreeMap::new(),
            now: Duration::ZERO,
            current_height: BlockHeight(0),
            config,
        }
    }

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, topology, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
    ) -> Vec<Action> {
        let hash = tx.hash();

        // Check for duplicate
        if let Some(entry) = self.pool.get(&hash) {
            return vec![Action::EmitTransactionStatus {
                tx_hash: hash,
                status: TransactionStatus::Pending, // Already exists
                added_at: entry.added_at,
                cross_shard: entry.cross_shard,
                submitted_locally: entry.submitted_locally,
                phase_times: None,
            }];
        }

        // Reject if tombstoned (already completed/aborted)
        if self.is_tombstoned(&hash) {
            tracing::debug!(tx_hash = ?hash, "Rejecting tombstoned transaction submission");
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(topology.num_shards());
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(&tx),
                status: TransactionStatus::Pending,
                added_at: self.now,
                cross_shard,
                submitted_locally: true, // Submitted via RPC
                committed_at_time: None,
                provisioned_at_time: None,
                wave_ready_at_time: None,
                ec_created_at_time: None,
                executed_at_time: None,
            },
        );

        // Add to ready tracking
        self.add_to_ready_tracking(hash, &tx, cross_shard, self.now);

        tracing::info!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via submit");

        // Note: Broadcasting is handled by NodeStateMachine which broadcasts to all
        // involved shards. Mempool just manages state.
        vec![Action::EmitTransactionStatus {
            tx_hash: hash,
            status: TransactionStatus::Pending,
            added_at: self.now,
            cross_shard,
            submitted_locally: true,
            phase_times: None,
        }]
    }

    /// Handle transaction received via gossip (or validated RPC submission).
    ///
    /// `submitted_locally` is `true` when the transaction originated from this
    /// node's RPC endpoint and was validated through the batcher.  The flag is
    /// propagated to `PoolEntry` so that finalization metrics are recorded only
    /// on the submitting node.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        let hash = tx.hash();

        // Ignore if already have it or if tombstoned (completed/aborted)
        if self.pool.contains_key(&hash) || self.is_tombstoned(&hash) {
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(topology.num_shards());
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(&tx),
                status: TransactionStatus::Pending,
                added_at: self.now,
                cross_shard,
                submitted_locally,
                committed_at_time: None,
                provisioned_at_time: None,
                wave_ready_at_time: None,
                ec_created_at_time: None,
                executed_at_time: None,
            },
        );

        // Add to ready tracking
        self.add_to_ready_tracking(hash, &tx, cross_shard, self.now);

        tracing::debug!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via gossip");

        // No events emitted — gossip acceptance is silent to avoid flooding
        // the consensus channel under high transaction load.
        vec![]
    }

    /// Evict a transaction that has reached a terminal state.
    ///
    /// This removes the transaction from the pool and moves it to the
    /// recently_evicted cache so slow peers can still fetch it. The cache
    /// is pruned after TRANSACTION_RETENTION_BLOCKS.
    ///
    /// Also adds the transaction to the tombstone set to prevent it from
    /// being re-added via gossip. Terminal states include:
    /// - Completed (certificate committed)
    /// - Aborted (explicitly aborted)
    fn evict_terminal(&mut self, tx_hash: Hash) {
        // Remove locked nodes and update counters if this transaction was holding locks
        let info_to_unlock = self.pool.get(&tx_hash).and_then(|entry| {
            if entry.status.holds_state_lock() {
                Some((Arc::clone(&entry.tx), entry.status.clone()))
            } else {
                None
            }
        });
        if let Some((tx, status)) = info_to_unlock {
            self.remove_locked_nodes(&tx);
            let committed_at = match status {
                TransactionStatus::Committed(h) => {
                    self.committed_count = self.committed_count.saturating_sub(1);
                    Some(h)
                }
                TransactionStatus::Executed { committed_at, .. } => {
                    self.executed_count = self.executed_count.saturating_sub(1);
                    Some(committed_at)
                }
                _ => None,
            };
            if let Some(h) = committed_at {
                if let Some(hashes) = self.in_flight_by_height.get_mut(&h) {
                    hashes.retain(|hash| *hash != tx_hash);
                    if hashes.is_empty() {
                        self.in_flight_by_height.remove(&h);
                    }
                }
            }
        }

        // Remove from ready tracking
        self.remove_from_ready_tracking(&tx_hash);

        // Move transaction to recently_evicted cache instead of discarding
        if let Some(entry) = self.pool.remove(&tx_hash) {
            self.recently_evicted
                .insert(tx_hash, (entry.tx, self.current_height));
        }
        self.tombstones.insert(tx_hash, self.current_height);
    }

    /// Check if a transaction hash is tombstoned (reached terminal state).
    pub fn is_tombstoned(&self, tx_hash: &Hash) -> bool {
        self.tombstones.contains_key(tx_hash)
    }

    /// Prune recently evicted transactions older than TRANSACTION_RETENTION_BLOCKS.
    fn prune_recently_evicted(&mut self) {
        let cutoff = self
            .current_height
            .0
            .saturating_sub(TRANSACTION_RETENTION_BLOCKS);
        self.recently_evicted
            .retain(|_, (_, height)| height.0 > cutoff);
    }

    /// Process a committed block - update statuses and finalize transactions.
    ///
    /// This handles:
    /// 1. Mark committed transactions
    /// 2. Process certificates → mark completed
    /// 3. Process aborts → update status to terminal
    #[instrument(skip(self, block), fields(
        height = block.header.height.0,
        tx_count = block.transaction_count()
    ))]
    pub fn on_block_committed_full(
        &mut self,
        topology: &TopologySnapshot,
        block: &Block,
    ) -> Vec<Action> {
        let height = block.header.height;
        let mut actions = Vec::new();

        self.current_height = height;

        // Prune old entries from recently_evicted cache
        self.prune_recently_evicted();

        // Ensure all committed transactions are in the mempool.
        // This handles the case where we fetched transactions to vote on a block
        // but didn't receive them via gossip. We need them in the mempool for
        // status tracking (execution status updates).
        for tx in block.transactions.iter() {
            let hash = tx.hash();
            if !self.pool.contains_key(&hash) {
                let cross_shard = tx.is_cross_shard(topology.num_shards());
                self.pool.insert(
                    hash,
                    PoolEntry {
                        tx: Arc::clone(tx),
                        status: TransactionStatus::Pending, // Will be updated by execution
                        added_at: self.now,
                        cross_shard,
                        submitted_locally: false, // Fetched for block processing
                        committed_at_time: None,
                        provisioned_at_time: None,
                        wave_ready_at_time: None,
                        ec_created_at_time: None,
                        executed_at_time: None,
                    },
                );
                tracing::debug!(
                    tx_hash = ?hash,
                    height = height.0,
                    "Added committed transaction to mempool"
                );
            }
        }

        // Update transaction status to Committed and add locks.
        // This must happen synchronously to prevent the same transactions from being
        // re-proposed before the status update is processed.
        for tx in block.transactions.iter() {
            let hash = tx.hash();
            if let Some(entry) = self.pool.get_mut(&hash) {
                // Only update if still Pending (avoid overwriting later states during sync)
                if matches!(entry.status, TransactionStatus::Pending) {
                    let added_at = entry.added_at;
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;
                    entry.status = TransactionStatus::Committed(height);
                    entry.committed_at_time = Some(self.now);
                    // Remove from ready tracking (no longer Pending)
                    self.remove_from_ready_tracking(&hash);
                    // Add locks for committed transactions and update counter
                    self.add_locked_nodes(tx);
                    self.committed_count += 1;
                    self.in_flight_by_height
                        .entry(height)
                        .or_default()
                        .push(hash);
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: hash,
                        status: TransactionStatus::Committed(height),
                        added_at,
                        cross_shard,
                        submitted_locally,
                        phase_times: None,
                    });
                }
            }
        }

        // Track committed abort intents so we stop re-proposing them.
        // Terminal state is still reached exclusively via TC commit below —
        // Process wave certificates — derive per-tx decisions.
        // Wave certs don't carry per-tx info directly. The node state machine
        // should call on_certificate_committed for each tx with the correct
        // decision derived from wave certificate execution certificates.
        // For blocks received via sync (no FinalizedWave), wave cert processing
        // is skipped — synced nodes don't need to emit per-tx status updates.
        // TODO: Wire up per-tx decisions from node state machine.
        let _ = &block.certificates; // acknowledge we know about them

        actions
    }

    /// Handle a certificate committed in a block.
    ///
    /// Marks the transaction as completed (terminal state).
    /// Called by the node state machine with per-tx decisions derived from
    /// the wave certificate's execution certificates.
    pub fn on_certificate_committed(
        &mut self,
        _topology: &TopologySnapshot,
        tx_hash: Hash,
        decision: TransactionDecision,
        _height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get(&tx_hash) {
            let added_at = entry.added_at;
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;
            let phase_times = Some(FinalizationPhaseTimes {
                added_at: entry.added_at,
                committed_at: entry.committed_at_time,
                provisioned_at: entry.provisioned_at_time,
                wave_ready_at: entry.wave_ready_at_time,
                ec_created_at: entry.ec_created_at_time,
                executed_at: entry.executed_at_time,
                completed_at: self.now,
            });

            let status = match decision {
                TransactionDecision::Accept | TransactionDecision::Reject => {
                    TransactionStatus::Completed(decision)
                }
                TransactionDecision::Aborted => {
                    TransactionStatus::Completed(TransactionDecision::Aborted)
                }
            };

            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status,
                added_at,
                cross_shard,
                submitted_locally,
                phase_times,
            });

            // Release locks and evict — same for all terminal states
            self.evict_terminal(tx_hash);
        }

        actions
    }

    /// Mark transactions as committed when block is committed (legacy method).
    #[deprecated(note = "Use on_block_committed_full instead")]
    pub fn on_block_committed(&mut self, tx_hashes: &[Hash], height: BlockHeight) {
        for hash in tx_hashes {
            // Check if we need to add locked nodes (clone tx first to avoid borrow issues)
            let should_add_locks = self
                .pool
                .get(hash)
                .is_some_and(|entry| !entry.status.holds_state_lock());
            let tx_clone = self.pool.get(hash).map(|e| Arc::clone(&e.tx));

            if should_add_locks {
                if let Some(tx) = tx_clone {
                    self.add_locked_nodes(&tx);
                    self.committed_count += 1;
                    self.in_flight_by_height
                        .entry(height)
                        .or_default()
                        .push(*hash);
                }
            }

            if let Some(entry) = self.pool.get_mut(hash) {
                entry.status = TransactionStatus::Committed(height);
            }
        }
    }

    /// Record when a cross-shard transaction's provisions arrived.
    pub fn on_transaction_provisioned(&mut self, tx_hash: Hash) {
        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            entry.provisioned_at_time = Some(self.now);
        }
    }

    /// Record when the local execution certificate was created for a wave's txs.
    pub fn on_ec_created(&mut self, tx_hashes: &[Hash]) {
        for tx_hash in tx_hashes {
            if let Some(entry) = self.pool.get_mut(tx_hash) {
                entry.ec_created_at_time = Some(self.now);
            }
        }
    }

    /// Record when all transactions in a wave became ready.
    pub fn on_wave_ready(&mut self, tx_hashes: &[Hash]) {
        for tx_hash in tx_hashes {
            if let Some(entry) = self.pool.get_mut(tx_hash) {
                entry.wave_ready_at_time = Some(self.now);
            }
        }
    }

    /// Mark a transaction as executed (execution complete, certificate created).
    ///
    /// Called when ExecutionState finalizes a wave certificate.
    #[instrument(skip(self), fields(tx_hash = ?tx_hash, accepted = accepted))]
    pub fn on_transaction_executed(
        &mut self,
        _topology: &TopologySnapshot,
        tx_hash: Hash,
        accepted: bool,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            let decision = if accepted {
                TransactionDecision::Accept
            } else {
                TransactionDecision::Reject
            };
            let added_at = entry.added_at;
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;

            // Extract committed_at height before transitioning to Executed.
            // This is needed for timeout tracking - cross-shard transactions can get
            // stuck in Executed state if certificate inclusion fails on another shard.
            let committed_at = match entry.status {
                TransactionStatus::Committed(height) => {
                    self.committed_count = self.committed_count.saturating_sub(1);
                    self.executed_count += 1;
                    height
                }
                // If already Executed (idempotent call), preserve existing committed_at
                TransactionStatus::Executed { committed_at, .. } => committed_at,
                // Unexpected state - use current height as fallback
                _ => self.current_height,
            };

            entry.status = TransactionStatus::Executed {
                decision,
                committed_at,
            };
            entry.executed_at_time = Some(self.now);
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Executed {
                    decision,
                    committed_at,
                },
                added_at,
                cross_shard,
                submitted_locally,
                phase_times: None,
            });
        }

        actions
    }

    /// Mark a transaction as completed (certificate committed in block).
    ///
    /// This is a terminal state - the transaction is evicted from mempool.
    pub fn mark_completed(&mut self, tx_hash: &Hash, decision: TransactionDecision) -> Vec<Action> {
        if let Some(entry) = self.pool.get(tx_hash) {
            let added_at = entry.added_at;
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;
            let phase_times = Some(FinalizationPhaseTimes {
                added_at: entry.added_at,
                committed_at: entry.committed_at_time,
                provisioned_at: entry.provisioned_at_time,
                wave_ready_at: entry.wave_ready_at_time,
                ec_created_at: entry.ec_created_at_time,
                executed_at: entry.executed_at_time,
                completed_at: self.now,
            });
            // Evict from pool and tombstone - terminal state
            self.evict_terminal(*tx_hash);
            return vec![Action::EmitTransactionStatus {
                tx_hash: *tx_hash,
                status: TransactionStatus::Completed(decision),
                added_at,
                cross_shard,
                submitted_locally,
                phase_times,
            }];
        }
        vec![]
    }

    /// Update transaction status to a new state.
    ///
    /// This is used by the execution state machine to update status during
    /// the transaction lifecycle (Committed, Executed, etc.).
    ///
    /// Returns an action to emit the status update if the transition was valid.
    pub fn update_status(&mut self, tx_hash: &Hash, new_status: TransactionStatus) -> Vec<Action> {
        if let Some(entry) = self.pool.get_mut(tx_hash) {
            // Case 1: Idempotent update - already in the target state
            if entry.status == new_status {
                tracing::trace!(
                    tx_hash = ?tx_hash,
                    status = %entry.status,
                    "Ignoring duplicate status update"
                );
                return vec![];
            }

            // Case 2: Valid transition - apply it
            if entry.status.can_transition_to(&new_status) {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    from = %entry.status,
                    to = %new_status,
                    "Transaction status transition"
                );

                // Update locked nodes cache and counters based on status transition
                let old_status = entry.status.clone();
                let was_holding = old_status.holds_state_lock();
                let will_hold = new_status.holds_state_lock();
                let tx = Arc::clone(&entry.tx);
                let cross_shard = entry.cross_shard;

                if !was_holding && will_hold {
                    // Acquiring lock - transaction becomes in-flight
                    self.add_locked_nodes(&tx);
                }
                if was_holding && !will_hold {
                    // Releasing lock (shouldn't happen - locks held until terminal)
                    self.remove_locked_nodes(&tx);
                }

                // Update status counters
                match (&old_status, &new_status) {
                    // Entering Committed
                    (_, TransactionStatus::Committed(_))
                        if !matches!(old_status, TransactionStatus::Committed(_)) =>
                    {
                        self.committed_count += 1;
                    }
                    // Leaving Committed
                    (TransactionStatus::Committed(_), _)
                        if !matches!(new_status, TransactionStatus::Committed(_)) =>
                    {
                        self.committed_count = self.committed_count.saturating_sub(1);
                    }
                    _ => {}
                }
                match (&old_status, &new_status) {
                    // Entering Executed
                    (_, TransactionStatus::Executed { .. })
                        if !matches!(old_status, TransactionStatus::Executed { .. }) =>
                    {
                        self.executed_count += 1;
                    }
                    // Leaving Executed
                    (TransactionStatus::Executed { .. }, _)
                        if !matches!(new_status, TransactionStatus::Executed { .. }) =>
                    {
                        self.executed_count = self.executed_count.saturating_sub(1);
                    }
                    _ => {}
                }

                // Re-borrow entry after calling helper methods
                let entry = self.pool.get_mut(tx_hash).unwrap();
                let added_at = entry.added_at;
                let submitted_locally = entry.submitted_locally;
                let phase_times = if new_status.is_final() {
                    Some(FinalizationPhaseTimes {
                        added_at: entry.added_at,
                        committed_at: entry.committed_at_time,
                        provisioned_at: entry.provisioned_at_time,
                        wave_ready_at: entry.wave_ready_at_time,
                        ec_created_at: entry.ec_created_at_time,
                        executed_at: entry.executed_at_time,
                        completed_at: self.now,
                    })
                } else {
                    None
                };
                entry.status = new_status.clone();
                return vec![Action::EmitTransactionStatus {
                    tx_hash: *tx_hash,
                    status: new_status,
                    added_at,
                    cross_shard,
                    submitted_locally,
                    phase_times,
                }];
            }

            // Case 3: Invalid transition - determine if stale or truly invalid
            if new_status.ordinal() < entry.status.ordinal() {
                // Stale update: we've already progressed past this state.
                // This can happen due to message reordering in distributed systems.
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    current = %entry.status,
                    stale = %new_status,
                    "Ignoring stale status update (already progressed past this state)"
                );
            } else {
                // Truly invalid transition - this indicates a bug in the state machine
                tracing::warn!(
                    tx_hash = ?tx_hash,
                    from = %entry.status,
                    to = %new_status,
                    "Invalid transaction status transition"
                );
            }
        }
        vec![]
    }

    /// Add a transaction's nodes to the locked set.
    /// Called when a transaction transitions TO a lock-holding state (Committed/Executed).
    ///
    /// Also blocks any ready transactions that conflict with the newly locked nodes.
    fn add_locked_nodes(&mut self, tx: &RoutableTransaction) {
        for node in tx.all_declared_nodes() {
            let is_new = self.locked_nodes_cache.insert(*node);
            if is_new {
                // Block any ready transactions that conflict with this newly locked node
                self.block_transactions_for_node(*node);
            }
        }
    }

    /// Remove a transaction's nodes from the locked set.
    /// Called when a transaction transitions FROM a lock-holding state (evicted).
    ///
    /// Also promotes any blocked transactions that were waiting on these nodes.
    fn remove_locked_nodes(&mut self, tx: &RoutableTransaction) {
        for node in tx.all_declared_nodes() {
            if self.locked_nodes_cache.remove(node) {
                // Promote any deferred transactions that were waiting on this node
                self.promote_transactions_for_node(*node);
            }
        }
    }

    // ========== Incremental Ready Set Operations ==========

    /// Add a transaction to ready tracking when it becomes Pending.
    ///
    /// Determines if the transaction is deferred by locked nodes. If deferred,
    /// adds to deferred_by_nodes. If ready, adds to the appropriate ready set.
    ///
    /// Special case: Retry transactions are not blocked by locks held by their
    /// original transaction. When a retry T' arrives, it supersedes T, so T's
    /// locks should not prevent T' from being proposed.
    fn add_to_ready_tracking(
        &mut self,
        hash: Hash,
        tx: &Arc<RoutableTransaction>,
        cross_shard: bool,
        added_at: Duration,
    ) {
        // Find all nodes that block this transaction: nodes locked by in-flight
        // transactions OR already claimed by another transaction in the ready set.
        // The ready-set check prevents conflicting transactions from being proposed
        // in the same block.
        let blocking_nodes: HashSet<NodeId> = tx
            .all_declared_nodes()
            .filter(|node| {
                self.locked_nodes_cache.contains(node) || self.ready_txs_by_node.contains_key(node)
            })
            .copied()
            .collect();

        if !blocking_nodes.is_empty() {
            // Transaction is deferred by one or more locked nodes
            for node in &blocking_nodes {
                self.txs_deferred_by_node
                    .entry(*node)
                    .or_default()
                    .insert(hash);
            }
            self.deferred_by_nodes.insert(hash, blocking_nodes);
            return;
        }

        // Transaction is not deferred - add to appropriate ready set
        self.add_to_ready_set(hash, tx, cross_shard, added_at);
    }

    /// Add a transaction to the ready set.
    ///
    /// Precondition: transaction must not be deferred by any locked nodes.
    fn add_to_ready_set(
        &mut self,
        hash: Hash,
        tx: &Arc<RoutableTransaction>,
        _cross_shard: bool,
        added_at: Duration,
    ) {
        let ready_entry = ReadyEntry {
            tx: Arc::clone(tx),
            added_at,
        };

        // Add to reverse index for O(1) blocking when nodes become locked
        for node in tx.all_declared_nodes() {
            self.ready_txs_by_node
                .entry(*node)
                .or_default()
                .insert(hash);
        }

        self.ready.insert(hash, ready_entry);
    }

    /// Remove a transaction from all ready tracking structures.
    ///
    /// Called when a transaction is no longer Pending (committed, evicted, etc.).
    fn remove_from_ready_tracking(&mut self, hash: &Hash) {
        // Remove from ready set and clean reverse index
        if let Some(entry) = self.ready.remove(hash) {
            let freed_nodes: Vec<NodeId> = entry.tx.all_declared_nodes().copied().collect();
            self.remove_from_ready_txs_by_node(hash, &entry.tx);
            // Promote transactions that were deferred by this ready-set TX's nodes
            for node in freed_nodes {
                self.promote_transactions_for_node(node);
            }
        }

        // Remove from deferred tracking
        if let Some(blocking_nodes) = self.deferred_by_nodes.remove(hash) {
            for node in blocking_nodes {
                if let Some(deferred_txs) = self.txs_deferred_by_node.get_mut(&node) {
                    deferred_txs.remove(hash);
                    if deferred_txs.is_empty() {
                        self.txs_deferred_by_node.remove(&node);
                    }
                }
            }
        }
    }

    /// Helper to remove a transaction from the ready_txs_by_node reverse index.
    fn remove_from_ready_txs_by_node(&mut self, hash: &Hash, tx: &RoutableTransaction) {
        for node in tx.all_declared_nodes() {
            if let Some(txs) = self.ready_txs_by_node.get_mut(node) {
                txs.remove(hash);
                if txs.is_empty() {
                    self.ready_txs_by_node.remove(node);
                }
            }
        }
    }

    /// Block ready transactions when a node becomes locked.
    ///
    /// Moves transactions from ready sets to deferred_by_nodes if they conflict
    /// with the newly locked node.
    ///
    /// Uses the ready_txs_by_node reverse index for O(transactions_touching_node)
    /// instead of O(total_ready_set_size).
    fn block_transactions_for_node(&mut self, node: NodeId) {
        // Get all ready transactions that touch this node via reverse index
        let Some(tx_hashes) = self.ready_txs_by_node.remove(&node) else {
            return; // No ready transactions touch this node
        };

        // Move each transaction from its ready set to deferred
        for hash in tx_hashes {
            // Remove from ready set
            let removed_entry = self.ready.remove(&hash);

            if let Some(entry) = removed_entry {
                // Clean remaining nodes from ready_txs_by_node (except the one we already removed)
                for other_node in entry.tx.all_declared_nodes() {
                    if *other_node != node {
                        if let Some(txs) = self.ready_txs_by_node.get_mut(other_node) {
                            txs.remove(&hash);
                            if txs.is_empty() {
                                self.ready_txs_by_node.remove(other_node);
                            }
                        }
                    }
                }

                // Add to deferred tracking
                self.deferred_by_nodes.entry(hash).or_default().insert(node);
                self.txs_deferred_by_node
                    .entry(node)
                    .or_default()
                    .insert(hash);
            }
        }
    }

    /// Promote deferred transactions when a node becomes unlocked.
    ///
    /// Checks all transactions deferred by this node. If they are no longer
    /// deferred by any locked nodes, promotes them to the appropriate ready set.
    fn promote_transactions_for_node(&mut self, node: NodeId) {
        // Get transactions deferred by this node
        let Some(deferred_txs) = self.txs_deferred_by_node.remove(&node) else {
            return;
        };

        // Collect transactions to promote (to avoid borrow checker issues)
        let mut to_promote: Vec<(Hash, Arc<RoutableTransaction>, bool, Duration)> = Vec::new();

        let mut deferred_txs: Vec<Hash> = deferred_txs.into_iter().collect();
        deferred_txs.sort();
        for tx_hash in deferred_txs {
            if let Some(blocking_nodes) = self.deferred_by_nodes.get_mut(&tx_hash) {
                // Remove this node from the blocking set
                blocking_nodes.remove(&node);

                // If no more blockers, collect for promotion
                if blocking_nodes.is_empty() {
                    self.deferred_by_nodes.remove(&tx_hash);

                    // Get transaction info from pool
                    if let Some(entry) = self.pool.get(&tx_hash) {
                        if entry.status == TransactionStatus::Pending {
                            to_promote.push((
                                tx_hash,
                                Arc::clone(&entry.tx),
                                entry.cross_shard,
                                entry.added_at,
                            ));
                        }
                    }
                }
            }
        }

        // Promote collected transactions through the full ready-tracking path
        // so they're checked against remaining locked and ready-set conflicts.
        for (hash, tx, cross_shard, added_at) in to_promote {
            self.add_to_ready_tracking(hash, &tx, cross_shard, added_at);
        }
    }

    /// Get transactions ready for inclusion in a block with backpressure support.
    ///
    /// Returns transactions sorted by hash (ascending) for determinism.
    /// All transactions are subject to the same backpressure limit.
    ///
    /// Backpressure rules:
    /// - At hard limit, NO transactions are proposed
    /// - Otherwise, transactions are returned up to `max_count`, capped by headroom
    ///   to the hard limit
    ///
    /// The backpressure limit is based on how many transactions are currently holding
    /// state locks (Committed or Executed status). This controls execution and crypto
    /// verification pressure across the system.
    ///
    /// Parameters:
    /// - `max_count`: Maximum total transactions
    /// - `pending_commit_tx_count`: Transactions about to be committed (INCREASES in-flight)
    /// - `pending_commit_cert_count`: Certificates about to be committed (DECREASES in-flight)
    ///
    /// The effective in-flight is: current + pending_txs - pending_certs
    ///
    /// # Performance
    ///
    /// This method is O(min(ready_set_size, max_count)) instead of O(pool_size) because
    /// it reads from a pre-computed ready set that is maintained incrementally.
    pub fn ready_transactions(
        &self,
        max_count: usize,
        pending_commit_tx_count: usize,
        pending_commit_cert_count: usize,
    ) -> ReadyTransactions {
        // Certificates reduce in-flight (transactions complete), txs increase it
        let effective_in_flight = self
            .in_flight()
            .saturating_add(pending_commit_tx_count)
            .saturating_sub(pending_commit_cert_count);
        let at_limit = effective_in_flight >= self.config.max_in_flight;

        if at_limit {
            return ReadyTransactions::default();
        }

        // Cap max_count to stay within limit
        let room = self
            .config
            .max_in_flight
            .saturating_sub(effective_in_flight);
        let max_count = max_count.min(room);

        let mut result = ReadyTransactions::default();

        // Iterate ready set in hash order (BTreeMap guarantees this)
        let min_dwell = self.config.min_dwell_time;
        for entry in self.ready.values() {
            if result.transactions.len() >= max_count {
                break;
            }
            // Skip transactions that haven't met minimum dwell time
            if self.now.saturating_sub(entry.added_at) < min_dwell {
                continue;
            }
            result.transactions.push(Arc::clone(&entry.tx));
        }

        result
    }

    /// Get lock contention statistics.
    ///
    /// Returns counts of:
    /// - `locked_nodes`: Number of nodes currently locked by in-flight transactions
    /// - `pending_count`: Number of transactions in Pending status
    /// - `pending_deferred`: Number of pending transactions that conflict with locked nodes
    /// - `committed_count`: Number of transactions in Committed status
    /// - `executed_count`: Number of transactions in Executed status
    ///
    /// All stats are O(1) via cached counters and ready sets.
    pub fn lock_contention_stats(&self) -> LockContentionStats {
        let locked_nodes = self.locked_nodes_cache.len() as u64;

        // Pending counts are O(1) from ready set
        let ready_count = self.ready.len();
        let pending_deferred = self.deferred_by_nodes.len() as u64;
        let pending_count = (ready_count + self.deferred_by_nodes.len()) as u64;

        LockContentionStats {
            locked_nodes,
            pending_count,
            pending_deferred,
            committed_count: self.committed_count as u64,
            executed_count: self.executed_count as u64,
        }
    }

    /// Count transactions currently holding state locks (in-flight).
    ///
    /// This counts all transactions in Committed or Executed status,
    /// which are actively holding state locks and consuming execution/crypto resources.
    ///
    /// Used for backpressure to control overall system load.
    ///
    /// This is O(1) as it returns a cached count maintained incrementally
    /// when transaction status changes or transactions are evicted.
    pub fn in_flight(&self) -> usize {
        self.committed_count + self.executed_count
    }

    /// Check if we're at the in-flight limit.
    ///
    /// At this limit, no new transactions are proposed.
    pub fn at_in_flight_limit(&self) -> bool {
        self.in_flight() >= self.config.max_in_flight
    }

    /// Check whether accepting a block would unacceptably increase in-flight load.
    ///
    /// Returns `true` if the block should be rejected. Blocks that reduce or
    /// maintain the current in-flight count are always accepted, even when over
    /// the limit — this prevents deadlock when certificate-heavy blocks would
    /// relieve backpressure.
    pub fn would_exceed_in_flight(&self, new_tx_count: usize, cert_count: usize) -> bool {
        let current = self.in_flight();
        let projected = current
            .saturating_add(new_tx_count)
            .saturating_sub(cert_count);
        let would_exceed = projected > self.config.max_in_flight;
        let would_increase = projected > current;
        would_exceed && would_increase
    }

    /// Get the number of pending transactions.
    ///
    /// Returns the count of transactions in Pending status (waiting to be
    /// included in a block). This is O(n) as it counts pool entries.
    pub fn pending_count(&self) -> usize {
        self.pool
            .values()
            .filter(|e| matches!(e.status, TransactionStatus::Pending))
            .count()
    }

    /// Check if we're at the pending transaction limit for RPC backpressure.
    ///
    /// When at this limit, new RPC transaction submissions are rejected to
    /// prevent unbounded mempool growth when arrival rate exceeds processing.
    pub fn at_pending_limit(&self) -> bool {
        self.pending_count() >= self.config.max_pending
    }

    /// Get the mempool configuration.
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Check if we have a transaction.
    pub fn has_transaction(&self, hash: &Hash) -> bool {
        self.pool.contains_key(hash)
    }

    /// Get a transaction Arc by hash.
    ///
    /// Checks both the active pool and the recently_evicted cache
    /// (for peer fetch requests of transactions that have completed).
    pub fn get_transaction(&self, hash: &Hash) -> Option<Arc<RoutableTransaction>> {
        // First check active pool
        if let Some(entry) = self.pool.get(hash) {
            return Some(Arc::clone(&entry.tx));
        }
        // Fall back to recently evicted cache
        self.recently_evicted
            .get(hash)
            .map(|(tx, _)| Arc::clone(tx))
    }

    /// Get transaction status.
    pub fn status(&self, hash: &Hash) -> Option<TransactionStatus> {
        self.pool.get(hash).map(|e| e.status.clone())
    }

    /// Get mempool memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> MempoolMemoryStats {
        MempoolMemoryStats {
            pool: self.pool.len(),
            ready: self.ready.len(),
            tombstones: self.tombstones.len(),
            recently_evicted: self.recently_evicted.len(),
            locked_nodes: self.locked_nodes_cache.len(),
            in_flight_heights: self.in_flight_by_height.len(),
            deferred_by_nodes: self.deferred_by_nodes.len(),
            txs_deferred_by_node: self.txs_deferred_by_node.len(),
            ready_txs_by_node: self.ready_txs_by_node.len(),
        }
    }

    /// Get the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Get all incomplete transactions (not yet finalized or completed).
    ///
    /// Returns tuples of (hash, status, transaction Arc) for analysis.
    pub fn incomplete_transactions(
        &self,
    ) -> Vec<(Hash, TransactionStatus, Arc<RoutableTransaction>)> {
        self.pool
            .iter()
            .filter(|(_, entry)| {
                !matches!(
                    entry.status,
                    TransactionStatus::Executed { .. } | TransactionStatus::Completed(_)
                )
            })
            .map(|(hash, entry)| (*hash, entry.status.clone(), Arc::clone(&entry.tx)))
            .collect()
    }

    /// Clean up old tombstones using the default retention window.
    pub fn cleanup_default_tombstones(&mut self, current_height: BlockHeight) -> usize {
        self.cleanup_old_tombstones(current_height, TOMBSTONE_RETENTION_BLOCKS)
    }

    /// Clean up old tombstones and completed winners to prevent unbounded memory growth.
    ///
    /// Tombstones are kept for `retention_blocks` after creation to ensure gossip
    /// propagation has completed. After that, they can be safely removed since any
    /// late-arriving gossip for a very old transaction is likely stale anyway.
    ///
    /// # Parameters
    /// - `current_height`: The current block height
    /// - `retention_blocks`: Number of blocks to retain tombstones after creation
    ///
    /// # Returns
    /// Number of tombstones cleaned up
    pub fn cleanup_old_tombstones(
        &mut self,
        current_height: BlockHeight,
        retention_blocks: u64,
    ) -> usize {
        let cutoff = current_height.0.saturating_sub(retention_blocks);
        let before_count = self.tombstones.len();

        self.tombstones.retain(|_, height| height.0 > cutoff);

        before_count - self.tombstones.len()
    }

    /// Get the number of tombstones currently tracked.
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        generate_bls_keypair, test_utils::test_transaction, Block, BlockHeader, FinalizedWave,
        QuorumCertificate, ShardGroupId, ValidatorId, ValidatorInfo, ValidatorSet, WaveCertificate,
        WaveId,
    };
    use std::collections::BTreeSet;

    fn make_test_topology() -> TopologySnapshot {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(ValidatorId(0), 1, validator_set)
    }

    fn make_test_block(
        height: u64,
        transactions: Vec<RoutableTransaction>,
        wave_certs: Vec<WaveCertificate>,
    ) -> Block {
        Block {
            header: BlockHeader {
                shard_group_id: ShardGroupId(0),
                height: BlockHeight(height),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                transaction_root: Hash::ZERO,
                certificate_root: Hash::ZERO,
                local_receipt_root: Hash::ZERO,
                provision_root: Hash::ZERO,
                waves: vec![],
                in_flight: 0,
            },
            transactions: transactions.into_iter().map(Arc::new).collect(),
            certificates: wave_certs
                .into_iter()
                .map(|wc| {
                    Arc::new(FinalizedWave {
                        certificate: Arc::new(wc),
                        receipts: vec![],
                    })
                })
                .collect(),
        }
    }

    #[allow(dead_code)]
    fn make_test_wave_certificate(height: u64) -> WaveCertificate {
        WaveCertificate {
            wave_id: WaveId::new(ShardGroupId(0), height, BTreeSet::new()),
            execution_certificates: vec![],
        }
    }

    #[test]
    fn test_abort_updates_status() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        // Submit and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));

        let commit_block = make_test_block(1, vec![tx], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        // Process a certificate with decision=Aborted (the only terminal state trigger)
        let actions = mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Aborted,
            BlockHeight(35),
        );

        // Should have emitted Completed(Aborted) status
        let aborted_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash: h, status: TransactionStatus::Completed(TransactionDecision::Aborted), .. } if *h == tx_hash)
        });
        assert!(
            aborted_action.is_some(),
            "Should have emitted Completed(Aborted) status"
        );

        // Transaction should be evicted from pool (terminal state)
        assert!(
            mempool.status(&tx_hash).is_none(),
            "Transaction should be evicted from pool after Aborted"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tombstone Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_completed_transaction_is_tombstoned() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and commit the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        let commit_block = make_test_block(1, vec![tx], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        // Commit the certificate
        mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Accept,
            BlockHeight(2),
        );

        // Transaction should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_gossip() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        let commit_block = make_test_block(1, vec![tx.clone()], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Accept,
            BlockHeight(2),
        );

        // Verify it's tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(&topology, Arc::new(tx.clone()), false);
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_submit() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        let commit_block = make_test_block(1, vec![tx.clone()], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Accept,
            BlockHeight(2),
        );

        // Try to re-submit - should be rejected (no status emitted)
        let actions = mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_aborted_transaction_is_tombstoned() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and commit the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        let commit_block = make_test_block(1, vec![tx.clone()], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        // Commit a certificate with Aborted decision — the only terminal state trigger
        mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Aborted,
            BlockHeight(2),
        );

        // Transaction should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(&topology, Arc::new(tx.clone()), false);
        assert!(actions.is_empty(), "Aborted tx should be rejected");
    }

    #[test]
    fn test_tombstone_cleanup() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        // Create and complete several transactions at different heights
        for i in 1..=5 {
            let tx = test_transaction(i);
            let tx_hash = tx.hash();

            mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
            let commit_block = make_test_block(i as u64, vec![tx], vec![]);
            mempool.on_block_committed_full(&topology, &commit_block);

            mempool.on_certificate_committed(
                &topology,
                tx_hash,
                TransactionDecision::Accept,
                BlockHeight(i as u64 + 100),
            );
        }

        // Should have 5 tombstones
        assert_eq!(mempool.tombstone_count(), 5);

        // Cleanup with short retention - should remove some
        let cleaned = mempool.cleanup_old_tombstones(BlockHeight(110), 5);
        assert!(cleaned > 0, "Should have cleaned up some tombstones");

        // Cleanup with long retention - should remove all remaining
        let _cleaned = mempool.cleanup_old_tombstones(BlockHeight(200), 5);
        assert_eq!(mempool.tombstone_count(), 0);
    }

    #[test]
    fn test_tombstone_prevents_resurrection_during_sync() {
        // Scenario: During sync, we receive blocks in rapid succession.
        // A transaction completes in block N, but gossip from block N-1
        // arrives afterwards trying to re-add it.

        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Commit the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));
        let commit_block = make_test_block(10, vec![tx.clone()], vec![]);
        mempool.on_block_committed_full(&topology, &commit_block);

        // Complete the transaction
        mempool.on_certificate_committed(
            &topology,
            tx_hash,
            TransactionDecision::Accept,
            BlockHeight(11),
        );

        // Pool should be empty
        assert_eq!(mempool.len(), 0);

        // Simulate late-arriving gossip
        let _actions = mempool.on_transaction_gossip(&topology, Arc::new(tx.clone()), false);

        // Pool should still be empty - tombstone prevented resurrection
        assert_eq!(mempool.len(), 0);
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    #[test]
    fn test_mark_completed_creates_tombstone() {
        let topology = make_test_topology();
        let mut mempool = MempoolState::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit the transaction
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));

        // Mark as completed directly
        mempool.mark_completed(&tx_hash, TransactionDecision::Accept);

        // Should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));
        assert!(mempool.status(&tx_hash).is_none());

        // Should reject gossip
        let actions = mempool.on_transaction_gossip(&topology, Arc::new(tx.clone()), false);
        assert!(actions.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RPC Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_config_defaults() {
        let config = MempoolConfig::default();
        assert_eq!(config.max_in_flight, DEFAULT_IN_FLIGHT_LIMIT);
    }

    // =========================================================================
    // Backpressure Tests
    // =========================================================================

    /// Create a mempool config with a low in-flight limit for testing.
    fn make_mempool_config_with_limit(limit: usize) -> MempoolConfig {
        MempoolConfig {
            max_in_flight: limit,
            max_pending: DEFAULT_MAX_PENDING,
            min_dwell_time: Duration::ZERO,
        }
    }

    /// Put a mempool at the backpressure limit by adding committed transactions.
    fn put_mempool_at_limit(mempool: &mut MempoolState, topology: &TopologySnapshot) {
        let limit = mempool.config.max_in_flight;

        // Add TXs and mark them as Committed to hold locks
        for i in 0..limit {
            let tx = test_transaction(100 + i as u8);
            let tx_hash = tx.hash();
            mempool.on_submit_transaction(topology, Arc::new(tx));
            // Mark as Committed so it holds state locks
            mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));
        }

        assert!(
            mempool.at_in_flight_limit(),
            "Mempool should be at in-flight limit after adding {} committed TXs",
            limit
        );
    }

    /// Create a topology with 2 shards for cross-shard testing
    fn make_cross_shard_topology() -> TopologySnapshot {
        let validators: Vec<_> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        // 2 shards
        TopologySnapshot::new(ValidatorId(0), 2, validator_set)
    }

    /// Create a cross-shard transaction (writes to nodes in different shards)
    fn test_cross_shard_transaction(seed: u8) -> RoutableTransaction {
        use hyperscale_types::shard_for_node;
        use hyperscale_types::test_utils::test_node;

        // Find two seeds that map to different shards with 2 shards
        // We'll search for a pair starting from the given seed
        let node1 = test_node(seed);
        let shard1 = shard_for_node(&node1, 2);

        // Find a different shard
        let mut node2_seed = seed.wrapping_add(1);
        loop {
            let node2 = test_node(node2_seed);
            let shard2 = shard_for_node(&node2, 2);
            if shard1 != shard2 {
                break;
            }
            node2_seed = node2_seed.wrapping_add(1);
            if node2_seed == seed {
                panic!("Could not find nodes in different shards");
            }
        }

        // Create cross-shard transaction
        hyperscale_types::test_utils::test_transaction_with_nodes(
            &[seed, seed + 1, seed + 2],
            vec![test_node(seed)],                        // read from one shard
            vec![test_node(seed), test_node(node2_seed)], // write to both shards
        )
    }

    #[test]
    fn test_backpressure_allows_txns_below_limit() {
        // Use a limit that leaves room
        let config = make_mempool_config_with_limit(10);
        let mut mempool = MempoolState::with_config(config);
        let topology = make_cross_shard_topology();

        // Add a single-shard transaction
        let single_shard_tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(single_shard_tx.clone()));

        // Add a cross-shard transaction
        let cross_shard_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(&topology, Arc::new(cross_shard_tx.clone()));

        // Below limit: all TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(ready.len(), 2, "All TXs should be allowed below limit");
    }

    #[test]
    fn test_backpressure_rejects_all_at_limit() {
        let config = make_mempool_config_with_limit(2);
        let mut mempool = MempoolState::with_config(config);
        let topology = make_cross_shard_topology();

        // Put mempool at the in-flight limit
        put_mempool_at_limit(&mut mempool, &topology);
        assert!(mempool.at_in_flight_limit());

        // Add a transaction
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()));

        // At limit: no TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0);
        assert!(
            ready.is_empty(),
            "No TXs should be returned at in-flight limit"
        );
    }

    #[test]
    fn test_backpressure_not_at_limit_allows_all_txns() {
        let topology = make_cross_shard_topology();
        let config = MempoolConfig {
            min_dwell_time: Duration::ZERO,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolState::with_config(config);

        // Mempool is not at limit (nothing committed)
        assert!(!mempool.at_in_flight_limit());

        // Add a single-shard transaction
        let single_tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(single_tx.clone()));

        // Add a cross-shard transaction
        let cross_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(&topology, Arc::new(cross_tx.clone()));

        // Not at limit: all TXs should be allowed
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_in_flight_counts_all_txns() {
        let topology = make_cross_shard_topology();
        let mut mempool = MempoolState::new();

        assert_eq!(mempool.in_flight(), 0);

        // Add a single-shard TX and commit it - SHOULD count (all TXs count now)
        let single_tx = test_transaction(200);
        let single_hash = single_tx.hash();
        mempool.on_submit_transaction(&topology, Arc::new(single_tx));
        mempool.update_status(&single_hash, TransactionStatus::Committed(BlockHeight(1)));
        assert_eq!(
            mempool.in_flight(),
            1,
            "Committed single-shard TX should count"
        );

        // Add a cross-shard TX in Pending - should NOT count (not holding locks)
        let cross_tx = test_cross_shard_transaction(1);
        let cross_hash = cross_tx.hash();
        mempool.on_submit_transaction(&topology, Arc::new(cross_tx));
        assert_eq!(mempool.in_flight(), 1, "Pending TX should not count");

        // Commit the cross-shard TX - should count
        mempool.update_status(&cross_hash, TransactionStatus::Committed(BlockHeight(1)));
        assert_eq!(mempool.in_flight(), 2, "All committed TXs should count");

        // Execute the cross-shard TX - should still count (Executed holds locks)
        mempool.update_status(
            &cross_hash,
            TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                committed_at: BlockHeight(1),
            },
        );
        assert_eq!(mempool.in_flight(), 2, "Executed TX should still count");

        // Complete the cross-shard TX - should NOT count anymore
        mempool.update_status(
            &cross_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
        );
        assert_eq!(mempool.in_flight(), 1, "Completed TX should not count");

        // Execute then complete the single-shard TX
        mempool.update_status(
            &single_hash,
            TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                committed_at: BlockHeight(1),
            },
        );
        assert_eq!(
            mempool.in_flight(),
            1,
            "Executed single-shard TX still counts"
        );

        mempool.update_status(
            &single_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
        );
        assert_eq!(mempool.in_flight(), 0, "All completed");
    }

    // =========================================================================
    // Minimum Dwell Time Tests
    // =========================================================================

    #[test]
    fn test_dwell_time_zero_selects_immediately() {
        let config = MempoolConfig {
            min_dwell_time: Duration::ZERO,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolState::with_config(config);
        let topology = make_test_topology();

        mempool.set_time(Duration::from_secs(10));
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx));

        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            1,
            "Zero dwell time should select immediately"
        );
    }

    #[test]
    fn test_dwell_time_default_150ms() {
        // Default config has 150ms dwell time
        let mut mempool = MempoolState::new();
        let topology = make_test_topology();

        mempool.set_time(Duration::from_secs(10));
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx));

        // At t=10.1s — not yet eligible (100ms < 150ms)
        mempool.set_time(Duration::from_millis(10_100));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            0,
            "Should not select before 150ms default dwell"
        );

        // At t=10.15s — eligible (150ms >= 150ms)
        mempool.set_time(Duration::from_millis(10_150));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            1,
            "Should select after 150ms default dwell"
        );
    }

    #[test]
    fn test_dwell_time_filters_recent_transactions() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(500),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolState::with_config(config);
        let topology = make_test_topology();

        // Submit at t=10s
        mempool.set_time(Duration::from_secs(10));
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx));

        // Still at t=10s — dwell time not met
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            0,
            "Should not select before dwell time"
        );

        // Advance to t=10.3s — still not enough
        mempool.set_time(Duration::from_millis(10_300));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            0,
            "Should not select before dwell time elapses"
        );

        // Advance to t=10.5s — exactly at dwell time
        mempool.set_time(Duration::from_millis(10_500));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(
            ready.transactions.len(),
            1,
            "Should select after dwell time elapses"
        );
    }

    #[test]
    fn test_dwell_time_mixed_eligibility() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(200),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolState::with_config(config);
        let topology = make_test_topology();

        // Submit tx1 at t=1s
        mempool.set_time(Duration::from_secs(1));
        let tx1 = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx1));

        // Submit tx2 at t=1.3s
        mempool.set_time(Duration::from_millis(1_300));
        let tx2 = test_transaction(2);
        mempool.on_submit_transaction(&topology, Arc::new(tx2));

        // At t=1.2s — tx1 has 200ms dwell (eligible), tx2 not yet submitted
        // Actually we already submitted tx2 at 1.3s, so check at 1.4s:
        // tx1 added at 1.0s, now 1.4s → 400ms dwell (eligible)
        // tx2 added at 1.3s, now 1.4s → 100ms dwell (not eligible)
        mempool.set_time(Duration::from_millis(1_400));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(ready.transactions.len(), 1, "Only tx1 should be eligible");

        // At t=1.5s — both eligible
        mempool.set_time(Duration::from_millis(1_500));
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(ready.transactions.len(), 2, "Both should be eligible");
    }
}
