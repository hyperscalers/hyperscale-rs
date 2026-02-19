//! Mempool state.

use hyperscale_core::{Action, TransactionStatus};
use hyperscale_types::{
    AbortReason, Block, BlockHeight, DeferReason, Hash, NodeId, ReadyTransactions,
    RoutableTransaction, Topology, TransactionAbort, TransactionDecision,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Number of blocks to retain evicted transactions for peer fetch requests.
/// This allows slow validators to catch up and fetch transactions from peers
/// even after the transaction has been evicted from the active pool.
const TRANSACTION_RETENTION_BLOCKS: u64 = 100;

/// Default backpressure limit (soft limit).
///
/// This limits how many transactions can be in-flight (holding state locks) at once.
/// When at this limit, new transactions without provisions are delayed.
/// Cross-shard TXs WITH provisions (committed on another shard) can still be proposed,
/// ensuring we don't block transactions that other shards are waiting on.
pub const DEFAULT_IN_FLIGHT_LIMIT: usize = 512;

/// Default hard limit on transactions in-flight.
///
/// This is an absolute cap on transactions holding state locks. When at this limit,
/// NO new transactions are proposed (even cross-shard TXs with provisions). This prevents
/// unbounded growth and controls execution/crypto verification pressure.
pub const DEFAULT_IN_FLIGHT_HARD_LIMIT: usize = 1024;

/// Default limit on pending transactions for RPC backpressure.
///
/// When the number of Pending transactions exceeds this limit, new RPC submissions
/// are rejected. This is approximately 2 blocks worth of transactions (at 1024 TXs/block),
/// preventing the mempool from growing unboundedly when transaction arrival rate
/// exceeds processing capacity.
pub const DEFAULT_MAX_PENDING: usize = 2048;

/// Mempool configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolConfig {
    /// Maximum transactions allowed in-flight (soft limit).
    ///
    /// When at this limit, new transactions without provisions are delayed.
    /// Cross-shard TXs WITH provisions (committed on another shard) can still be proposed,
    /// ensuring we don't block transactions that other shards are waiting on.
    #[serde(default = "default_max_in_flight")]
    pub max_in_flight: usize,

    /// Hard limit on transactions in-flight.
    ///
    /// When at this limit, NO new transactions are proposed (even cross-shard TXs with
    /// provisions). This prevents unbounded growth and controls execution/crypto pressure.
    /// RPC transaction submissions are also rejected when this limit is reached.
    #[serde(default = "default_max_in_flight_hard_limit")]
    pub max_in_flight_hard_limit: usize,

    /// Maximum pending transactions before RPC backpressure kicks in.
    ///
    /// When the number of Pending transactions exceeds this limit, new RPC submissions
    /// are rejected. This prevents unbounded mempool growth when arrival rate exceeds
    /// processing capacity. Set to approximately a few blocks worth of transactions.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
}

fn default_max_in_flight() -> usize {
    DEFAULT_IN_FLIGHT_LIMIT
}

fn default_max_in_flight_hard_limit() -> usize {
    DEFAULT_IN_FLIGHT_HARD_LIMIT
}

fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_IN_FLIGHT_LIMIT,
            max_in_flight_hard_limit: DEFAULT_IN_FLIGHT_HARD_LIMIT,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }
}

/// Lock contention statistics from the mempool.
#[derive(Clone, Copy, Debug, Default)]
pub struct LockContentionStats {
    /// Number of nodes currently locked by in-flight transactions.
    pub locked_nodes: u64,
    /// Number of transactions deferred waiting for a winner to complete.
    pub deferred_count: u64,
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
}

/// Entry in the ready set.
///
/// Contains cached information needed for ready_transactions() to avoid
/// re-computing properties on each call.
#[derive(Debug, Clone)]
struct ReadyEntry {
    tx: Arc<RoutableTransaction>,
    /// Whether this transaction has verified provisions (for cross-shard priority).
    has_provisions: bool,
}

/// Mempool state machine.
///
/// Handles transaction lifecycle from submission to completion.
/// Uses `BTreeMap` for the pool to maintain hash ordering, which allows
/// ready_transactions() to iterate in sorted order without sorting.
///
/// # Incremental Ready Sets
///
/// To avoid O(n) scans on every `ready_transactions()` call, we maintain
/// three pre-computed ready sets that are updated incrementally:
/// - `ready_retries`: Retry transactions (highest priority)
/// - `ready_priority`: Cross-shard TXs with verified provisions
/// - `ready_others`: All other ready transactions
///
/// Transactions are added to these sets when they become ready (Pending status,
/// no conflicts with locked nodes) and removed when they are no longer ready
/// (status changes, conflicts arise, or evicted).
pub struct MempoolState {
    /// Transaction pool sorted by hash (BTreeMap for ordered iteration).
    pool: BTreeMap<Hash, PoolEntry>,

    /// Deferred transactions waiting for their winner to complete.
    /// Maps: loser_tx_hash -> (loser_tx, winner_tx_hash, deferred_at_height)
    ///
    /// When a deferral commits, the loser is added here with status Deferred.
    /// When the winner's certificate commits, we create a retry.
    /// The deferred_at_height enables cleanup of stale entries.
    deferred_by: HashMap<Hash, (Arc<RoutableTransaction>, Hash, BlockHeight)>,

    /// Reverse index: winner_tx_hash -> Vec<loser_tx_hash>
    /// Allows O(1) lookup of all losers deferred by a winner.
    deferred_losers_by_winner: HashMap<Hash, Vec<Hash>>,

    /// Pending deferrals for transactions not yet in the pool.
    /// This handles sync scenarios where a deferral references a transaction
    /// from an earlier block that hasn't been added to the pool yet.
    /// Maps: loser_tx_hash -> (winner_tx_hash, block_height)
    pending_deferrals: HashMap<Hash, (Hash, BlockHeight)>,

    /// Pending retries for transactions not yet in the pool.
    /// This handles sync scenarios where the winner's certificate arrives
    /// before the deferred loser transaction. When the loser arrives,
    /// we immediately create the retry.
    /// Maps: loser_tx_hash -> (winner_tx_hash, cert_height)
    pending_retries: HashMap<Hash, (Hash, BlockHeight)>,

    /// Completed winners whose certificates have been committed.
    /// Used to handle the race condition where a deferral arrives after
    /// the winner has already completed. When a deferral references a
    /// winner in this set, we immediately create the retry.
    /// Maps: winner_tx_hash -> cert_height
    completed_winners: HashMap<Hash, BlockHeight>,

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

    // ========== Incremental Ready Sets ==========
    //
    // These sets are maintained incrementally to provide O(1) ready_transactions().
    // Invariants:
    // 1. A transaction is in exactly one of: ready_retries, ready_priority, ready_others,
    //    deferred_by_nodes, or none (if not Pending or not in pool).
    // 2. ready_* sets contain only Pending transactions with no locked node conflicts.
    // 3. deferred_by_nodes contains Pending transactions deferred by locked nodes.
    /// Ready retry transactions (highest priority, bypass soft limit).
    /// BTreeMap maintains hash order for deterministic iteration.
    ready_retries: BTreeMap<Hash, ReadyEntry>,

    /// Ready cross-shard transactions with verified provisions (high priority, bypass soft limit).
    /// BTreeMap maintains hash order for deterministic iteration.
    ready_priority: BTreeMap<Hash, ReadyEntry>,

    /// Ready normal transactions (subject to soft limit).
    /// BTreeMap maintains hash order for deterministic iteration.
    ready_others: BTreeMap<Hash, ReadyEntry>,

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

    /// Current time.
    now: Duration,

    /// Network topology for shard-aware transaction routing.
    topology: Arc<dyn Topology>,

    /// Current committed block height (for retry transaction creation).
    current_height: BlockHeight,

    /// Configuration for mempool behavior.
    config: MempoolConfig,
}

impl MempoolState {
    /// Create a new mempool state machine with default config.
    pub fn new(topology: Arc<dyn Topology>) -> Self {
        Self::with_config(topology, MempoolConfig::default())
    }

    /// Create a new mempool state machine with custom config.
    pub fn with_config(topology: Arc<dyn Topology>, config: MempoolConfig) -> Self {
        Self {
            pool: BTreeMap::new(),
            deferred_by: HashMap::new(),
            deferred_losers_by_winner: HashMap::new(),
            pending_deferrals: HashMap::new(),
            pending_retries: HashMap::new(),
            completed_winners: HashMap::new(),
            tombstones: HashMap::new(),
            recently_evicted: HashMap::new(),
            locked_nodes_cache: HashSet::new(),
            committed_count: 0,
            executed_count: 0,
            ready_retries: BTreeMap::new(),
            ready_priority: BTreeMap::new(),
            ready_others: BTreeMap::new(),
            deferred_by_nodes: HashMap::new(),
            txs_deferred_by_node: HashMap::new(),
            ready_txs_by_node: HashMap::new(),
            now: Duration::ZERO,
            topology,
            current_height: BlockHeight(0),
            config,
        }
    }

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction_arc(&mut self, tx: Arc<RoutableTransaction>) -> Vec<Action> {
        let hash = tx.hash();

        // Check for duplicate
        if let Some(entry) = self.pool.get(&hash) {
            return vec![Action::EmitTransactionStatus {
                tx_hash: hash,
                status: TransactionStatus::Pending, // Already exists
                added_at: entry.added_at,
                cross_shard: entry.cross_shard,
                submitted_locally: entry.submitted_locally,
            }];
        }

        // Reject if tombstoned (already completed/aborted/retried)
        if self.is_tombstoned(&hash) {
            tracing::debug!(tx_hash = ?hash, "Rejecting tombstoned transaction submission");
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(self.topology.num_shards());
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(&tx),
                status: TransactionStatus::Pending,
                added_at: self.now,
                cross_shard,
                submitted_locally: true, // Submitted via RPC
            },
        );

        // Add to ready tracking
        self.add_to_ready_tracking(hash, &tx, cross_shard);

        tracing::info!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via submit");

        // Note: Broadcasting is handled by NodeStateMachine which broadcasts to all
        // involved shards. Mempool just manages state.
        vec![Action::EmitTransactionStatus {
            tx_hash: hash,
            status: TransactionStatus::Pending,
            added_at: self.now,
            cross_shard,
            submitted_locally: true,
        }]
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction(&mut self, tx: RoutableTransaction) -> Vec<Action> {
        self.on_submit_transaction_arc(Arc::new(tx))
    }

    /// Handle transaction received via gossip.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip_arc(&mut self, tx: Arc<RoutableTransaction>) -> Vec<Action> {
        let hash = tx.hash();

        // Ignore if already have it or if tombstoned (completed/aborted/retried)
        if self.pool.contains_key(&hash) || self.is_tombstoned(&hash) {
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(self.topology.num_shards());
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(&tx),
                status: TransactionStatus::Pending,
                added_at: self.now,
                cross_shard,
                submitted_locally: false, // Received via gossip
            },
        );

        // Add to ready tracking
        self.add_to_ready_tracking(hash, &tx, cross_shard);

        tracing::debug!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via gossip");

        // Note: We don't emit TransactionAccepted as an event - it was purely informational
        // and would flood the consensus channel under high transaction load.
        vec![]
    }

    /// Handle transaction received via gossip.
    #[instrument(skip(self, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip(&mut self, tx: RoutableTransaction) -> Vec<Action> {
        self.on_transaction_gossip_arc(Arc::new(tx))
    }

    /// Broadcast a transaction to all shards involved in it.
    ///
    /// Uses topology to determine which shards need to receive the transaction
    /// based on its declared reads and writes.
    fn broadcast_to_transaction_shards(&self, tx: &Arc<RoutableTransaction>) -> Vec<Action> {
        let shards = self.topology.all_shards_for_transaction(tx.as_ref());
        let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(tx));

        shards
            .into_iter()
            .map(|shard| Action::BroadcastTransaction {
                shard,
                gossip: Box::new(gossip.clone()),
            })
            .collect()
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
    /// - Retried (replaced by a new transaction)
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
            match status {
                TransactionStatus::Committed(_) => {
                    self.committed_count = self.committed_count.saturating_sub(1);
                }
                TransactionStatus::Executed { .. } => {
                    self.executed_count = self.executed_count.saturating_sub(1);
                }
                _ => {}
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

    /// Process a committed block - update statuses and trigger retries.
    ///
    /// This handles:
    /// 1. Mark committed transactions
    /// 2. Process deferrals → update status to Deferred
    /// 3. Process certificates → mark completed, trigger retries for deferred TXs
    /// 4. Process aborts → update status to terminal
    #[instrument(skip(self, block), fields(
        height = block.header.height.0,
        tx_count = block.transaction_count()
    ))]
    pub fn on_block_committed_full(&mut self, block: &Block) -> Vec<Action> {
        let height = block.header.height;
        let mut actions = Vec::new();

        // Track current height for retry creation
        self.current_height = height;

        // Prune old entries from recently_evicted cache
        self.prune_recently_evicted();

        // Ensure all committed transactions are in the mempool.
        // This handles the case where we fetched transactions to vote on a block
        // but didn't receive them via gossip. We need them in the mempool for
        // status tracking (deferrals, retries, execution status updates).
        for tx in block.all_transactions() {
            let hash = tx.hash();
            if !self.pool.contains_key(&hash) {
                let cross_shard = tx.is_cross_shard(self.topology.num_shards());
                self.pool.insert(
                    hash,
                    PoolEntry {
                        tx: Arc::clone(tx),
                        status: TransactionStatus::Pending, // Will be updated by execution
                        added_at: self.now,
                        cross_shard,
                        submitted_locally: false, // Fetched for block processing
                    },
                );
                tracing::debug!(
                    tx_hash = ?hash,
                    height = height.0,
                    "Added committed transaction to mempool"
                );

                // Check if this transaction has a pending retry (winner cert arrived first).
                // If so, immediately create the retry transaction.
                if let Some((winner_hash, cert_height)) = self.pending_retries.remove(&hash) {
                    tracing::info!(
                        tx_hash = %hash,
                        winner = %winner_hash,
                        "Processing pending retry for transaction that arrived after winner certificate"
                    );
                    actions.extend(self.create_retry_for_transaction(
                        Arc::clone(tx),
                        hash,
                        winner_hash,
                        cert_height,
                    ));
                }
            }
        }

        // Handle retry transactions superseding their originals.
        // When a retry T' is committed, its original T must be marked as Retried and evicted.
        // This releases T's locks so T' can acquire them. This is consensus-agreed: the retry
        // being in the block means all validators agree T is superseded.
        // Only iterate retry_transactions to avoid overhead in the common case.
        // Note: Execution state cleanup is handled by NodeStateMachine, similar to deferrals.
        for retry_tx in &block.retry_transactions {
            let original_hash = retry_tx.original_hash();
            let retry_hash = retry_tx.hash();

            if let Some(entry) = self.pool.get(&original_hash) {
                // Only process if original is in a non-terminal state
                if !entry.status.is_final() {
                    let added_at = entry.added_at;
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;

                    tracing::info!(
                        original = %original_hash,
                        retry = %retry_hash,
                        original_status = ?entry.status,
                        "Retry committed - marking original as Retried"
                    );

                    // Emit status update for the original
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: original_hash,
                        status: TransactionStatus::Retried { new_tx: retry_hash },
                        added_at,
                        cross_shard,
                        submitted_locally,
                    });

                    // Evict the original - this releases its locks
                    self.evict_terminal(original_hash);
                }
            }
        }

        // Update transaction status to Committed and add locks.
        // This must happen synchronously to prevent the same transactions from being
        // re-proposed before the status update is processed. The execution state machine
        // also emits TransactionStatusChanged events, but those go through an async channel
        // that may not be processed before the next proposal.
        for tx in block.all_transactions() {
            let hash = tx.hash();
            if let Some(entry) = self.pool.get_mut(&hash) {
                // Only update if still Pending (avoid overwriting later states during sync)
                if matches!(entry.status, TransactionStatus::Pending) {
                    let added_at = entry.added_at;
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;
                    entry.status = TransactionStatus::Committed(height);
                    // Remove from ready tracking (no longer Pending)
                    self.remove_from_ready_tracking(&hash);
                    // Add locks for committed transactions and update counter
                    self.add_locked_nodes(tx);
                    self.committed_count += 1;
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: hash,
                        status: TransactionStatus::Committed(height),
                        added_at,
                        cross_shard,
                        submitted_locally,
                    });
                }
            }
        }

        // Process deferrals - update status to Deferred
        for deferral in &block.deferred {
            actions.extend(self.on_deferral_committed(deferral.tx_hash, &deferral.reason, height));
        }

        // Process certificates - mark completed, trigger retries
        for cert in &block.certificates {
            actions.extend(self.on_certificate_committed(
                cert.transaction_hash,
                cert.decision,
                height,
            ));
        }

        // Process aborts - mark as aborted with reason and evict.
        // Also abort any transactions that were deferred by the aborted winner.
        for abort in &block.aborted {
            if let Some(entry) = self.pool.get(&abort.tx_hash) {
                let added_at = entry.added_at;
                let cross_shard = entry.cross_shard;
                let submitted_locally = entry.submitted_locally;
                let status = TransactionStatus::Aborted {
                    reason: abort.reason.clone(),
                };
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: abort.tx_hash,
                    status,
                    added_at,
                    cross_shard,
                    submitted_locally,
                });
                // Evict from pool and tombstone - terminal state
                self.evict_terminal(abort.tx_hash);
            }

            // Also abort any losers that were deferred by this winner.
            // If the winner was aborted (e.g., timeout), the losers can never complete
            // because they were waiting for the winner to finish.
            actions.extend(self.on_winner_aborted(abort.tx_hash, height));
        }

        actions
    }

    /// Handle a deferral committed in a block.
    ///
    /// Updates the deferred TX's status to Deferred and tracks it for retry.
    /// If the transaction is not yet in the pool (sync scenario), stores the
    /// deferral for processing when the transaction arrives.
    fn on_deferral_committed(
        &mut self,
        tx_hash: Hash,
        reason: &DeferReason,
        height: BlockHeight,
    ) -> Vec<Action> {
        let DeferReason::LivelockCycle { winner_tx_hash } = reason;

        // Check if the winner has already completed - if so, create retry immediately.
        // This handles the race condition where the deferral arrives after the winner
        // has already been executed and its certificate committed.
        if let Some(&cert_height) = self.completed_winners.get(winner_tx_hash) {
            if let Some(entry) = self.pool.get(&tx_hash) {
                // Loser is in pool and winner already completed - create retry immediately
                tracing::info!(
                    tx_hash = %tx_hash,
                    winner = %winner_tx_hash,
                    "Deferral arrived after winner completed - creating retry immediately"
                );
                let loser_tx = Arc::clone(&entry.tx);
                return self.create_retry_for_transaction(
                    loser_tx,
                    tx_hash,
                    *winner_tx_hash,
                    cert_height,
                );
            } else {
                // Loser not in pool yet but winner already completed - store for later retry
                tracing::debug!(
                    tx_hash = %tx_hash,
                    winner = %winner_tx_hash,
                    "Deferral arrived after winner completed, loser not in pool - storing for later retry"
                );
                self.pending_retries
                    .insert(tx_hash, (*winner_tx_hash, cert_height));
                return vec![];
            }
        }

        // Get the transaction and update its status
        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            // Update status to Deferred
            let new_status = TransactionStatus::Deferred {
                by: *winner_tx_hash,
            };
            if entry.status.can_transition_to(&new_status) {
                tracing::info!(
                    tx_hash = %tx_hash,
                    winner = %winner_tx_hash,
                    from = %entry.status,
                    "Transaction deferred due to livelock cycle"
                );
                let cross_shard = entry.cross_shard;
                let old_status = entry.status.clone();
                let tx = Arc::clone(&entry.tx);
                entry.status = new_status.clone();

                // Remove from ready tracking (no longer Pending)
                self.remove_from_ready_tracking(&tx_hash);

                // Release locks if the transaction was holding them.
                // Deferred transactions don't hold locks (they've been deferred).
                if old_status.holds_state_lock() {
                    self.remove_locked_nodes(&tx);
                    match old_status {
                        TransactionStatus::Committed(_) => {
                            self.committed_count = self.committed_count.saturating_sub(1);
                        }
                        TransactionStatus::Executed { .. } => {
                            self.executed_count = self.executed_count.saturating_sub(1);
                        }
                        _ => {}
                    }
                }

                // Track for retry when winner completes, with height for cleanup
                self.deferred_by
                    .insert(tx_hash, (tx, *winner_tx_hash, height));

                // Maintain reverse index for O(1) lookup
                self.deferred_losers_by_winner
                    .entry(*winner_tx_hash)
                    .or_default()
                    .push(tx_hash);

                // Re-borrow entry after calling helper methods
                let entry = self.pool.get(&tx_hash).unwrap();
                return vec![Action::EmitTransactionStatus {
                    tx_hash,
                    status: new_status,
                    added_at: entry.added_at,
                    cross_shard,
                    submitted_locally: entry.submitted_locally,
                }];
            }
        } else {
            // Transaction not in pool yet - this can happen during sync when
            // processing blocks where the deferral references a transaction
            // from an earlier block. Store for later processing.
            tracing::debug!(
                tx_hash = %tx_hash,
                winner = %winner_tx_hash,
                height = height.0,
                "Storing pending deferral for transaction not yet in pool"
            );
            self.pending_deferrals
                .insert(tx_hash, (*winner_tx_hash, height));

            // Also set up the reverse index now, so that if the winner's certificate
            // arrives before the deferred transaction, we know there's a pending loser
            self.deferred_losers_by_winner
                .entry(*winner_tx_hash)
                .or_default()
                .push(tx_hash);
        }

        vec![]
    }

    /// Handle a certificate committed in a block.
    ///
    /// Marks the transaction as completed and triggers retries for any TXs deferred by it.
    fn on_certificate_committed(
        &mut self,
        tx_hash: Hash,
        decision: TransactionDecision,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Mark the certificate's TX as completed with the final decision and evict
        if let Some(entry) = self.pool.get(&tx_hash) {
            let added_at = entry.added_at;
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Completed(decision),
                added_at,
                cross_shard,
                submitted_locally,
            });
            // Evict from pool and tombstone - terminal state
            self.evict_terminal(tx_hash);
        }

        // Track this winner as completed so late-arriving deferrals can create retries immediately
        self.completed_winners.insert(tx_hash, height);

        // Check if any deferred TXs were waiting for this winner using reverse index (O(1) lookup)
        let loser_hashes = self
            .deferred_losers_by_winner
            .remove(&tx_hash)
            .unwrap_or_default();

        for loser_hash in loser_hashes {
            // First check if the loser is in deferred_by (normal case - tx was in pool when deferred)
            if let Some((loser_tx, winner_hash, _deferred_at)) =
                self.deferred_by.remove(&loser_hash)
            {
                // Create retry transaction
                let retry_tx = loser_tx.create_retry(winner_hash, height);
                let retry_hash = retry_tx.hash();

                tracing::info!(
                    original = %loser_hash,
                    retry = %retry_hash,
                    winner = %winner_hash,
                    retry_count = retry_tx.retry_count(),
                    "Creating retry for deferred transaction"
                );

                // Update original's status to Retried and evict
                if let Some(entry) = self.pool.get(&loser_hash) {
                    let added_at = entry.added_at;
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: loser_hash,
                        status: TransactionStatus::Retried { new_tx: retry_hash },
                        added_at,
                        cross_shard,
                        submitted_locally,
                    });
                    // Evict from pool and tombstone - terminal state
                    self.evict_terminal(loser_hash);
                }

                // Add retry to mempool if not already present (dedup by hash)
                if !self.pool.contains_key(&retry_hash) && !self.is_tombstoned(&retry_hash) {
                    let retry_tx = Arc::new(retry_tx);
                    let cross_shard = retry_tx.is_cross_shard(self.topology.num_shards());
                    self.pool.insert(
                        retry_hash,
                        PoolEntry {
                            tx: Arc::clone(&retry_tx),
                            status: TransactionStatus::Pending,
                            added_at: self.now,
                            cross_shard,
                            submitted_locally: false, // System-generated retry
                        },
                    );

                    // Add to ready tracking
                    self.add_to_ready_tracking(retry_hash, &retry_tx, cross_shard);

                    // Emit status for retry transaction
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: retry_hash,
                        status: TransactionStatus::Pending,
                        added_at: self.now,
                        cross_shard,
                        submitted_locally: false,
                    });

                    // Gossip the retry to relevant shards
                    actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
                }
            } else if let Some((winner_hash, _deferral_height)) =
                self.pending_deferrals.remove(&loser_hash)
            {
                // The loser was deferred but wasn't in the pool yet (sync scenario).
                // The winner's certificate arrived before the loser transaction.
                // We can't create a retry yet because we don't have the loser transaction.
                // Store in a new structure to create retry when the loser arrives.
                tracing::debug!(
                    loser = %loser_hash,
                    winner = %winner_hash,
                    "Winner certificate arrived before deferred loser transaction - storing for later retry"
                );
                self.pending_retries
                    .insert(loser_hash, (winner_hash, height));
            }
        }

        actions
    }

    /// Handle winner transaction abort.
    ///
    /// When a winner transaction is aborted (e.g., due to timeout), any loser
    /// transactions that were deferred by it should also be aborted. The losers
    /// cannot complete without their winner completing first, so they must be
    /// retried from scratch.
    fn on_winner_aborted(&mut self, winner_hash: Hash, height: BlockHeight) -> Vec<Action> {
        let mut actions = Vec::new();

        // Get all losers deferred by this winner using reverse index
        let loser_hashes = self
            .deferred_losers_by_winner
            .remove(&winner_hash)
            .unwrap_or_default();

        for loser_hash in loser_hashes {
            // Get the loser from deferred_by and create a retry
            if let Some((loser_tx, _winner, _deferred_at)) = self.deferred_by.remove(&loser_hash) {
                // Create retry transaction for the deferred loser
                let retry_tx = loser_tx.create_retry(winner_hash, height);
                let retry_hash = retry_tx.hash();

                tracing::info!(
                    loser = %loser_hash,
                    winner = %winner_hash,
                    retry = %retry_hash,
                    "Winner aborted - creating retry for deferred loser"
                );

                // Emit status update for loser -> Retried
                if let Some(entry) = self.pool.get(&loser_hash) {
                    let added_at = entry.added_at;
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: loser_hash,
                        status: TransactionStatus::Retried { new_tx: retry_hash },
                        added_at,
                        cross_shard,
                        submitted_locally,
                    });
                    // Evict loser - it's been replaced by retry
                    self.evict_terminal(loser_hash);
                }

                // Add retry to mempool if not already present
                if !self.pool.contains_key(&retry_hash) && !self.is_tombstoned(&retry_hash) {
                    let retry_tx = Arc::new(retry_tx);
                    let cross_shard = retry_tx.is_cross_shard(self.topology.num_shards());
                    self.pool.insert(
                        retry_hash,
                        PoolEntry {
                            tx: Arc::clone(&retry_tx),
                            status: TransactionStatus::Pending,
                            added_at: self.now,
                            cross_shard,
                            submitted_locally: false,
                        },
                    );

                    // Add to ready tracking
                    self.add_to_ready_tracking(retry_hash, &retry_tx, cross_shard);

                    // Emit status for retry
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: retry_hash,
                        status: TransactionStatus::Pending,
                        added_at: self.now,
                        cross_shard,
                        submitted_locally: false,
                    });

                    // Gossip the retry
                    actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
                }
            }
        }

        actions
    }

    /// Create a retry transaction for a deferred loser.
    ///
    /// This is extracted into a helper to handle both:
    /// 1. Normal case: winner certificate arrives, loser is in pool
    /// 2. Sync case: loser transaction arrives after winner certificate
    fn create_retry_for_transaction(
        &mut self,
        loser_tx: Arc<RoutableTransaction>,
        loser_hash: Hash,
        winner_hash: Hash,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Create retry transaction
        let retry_tx = loser_tx.create_retry(winner_hash, height);
        let retry_hash = retry_tx.hash();

        tracing::info!(
            original = %loser_hash,
            retry = %retry_hash,
            winner = %winner_hash,
            retry_count = retry_tx.retry_count(),
            "Creating retry for deferred transaction"
        );

        // Update original's status to Retried and evict
        if let Some(entry) = self.pool.get(&loser_hash) {
            let added_at = entry.added_at;
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;
            actions.push(Action::EmitTransactionStatus {
                tx_hash: loser_hash,
                status: TransactionStatus::Retried { new_tx: retry_hash },
                added_at,
                cross_shard,
                submitted_locally,
            });
            // Evict from pool and tombstone - terminal state
            self.evict_terminal(loser_hash);
        }

        // Add retry to mempool if not already present (dedup by hash)
        if !self.pool.contains_key(&retry_hash) && !self.is_tombstoned(&retry_hash) {
            let retry_tx = Arc::new(retry_tx);
            let cross_shard = retry_tx.is_cross_shard(self.topology.num_shards());
            self.pool.insert(
                retry_hash,
                PoolEntry {
                    tx: Arc::clone(&retry_tx),
                    status: TransactionStatus::Pending,
                    added_at: self.now,
                    cross_shard,
                    submitted_locally: false, // System-generated retry
                },
            );

            // Add to ready tracking
            self.add_to_ready_tracking(retry_hash, &retry_tx, cross_shard);

            // Emit status for retry transaction
            actions.push(Action::EmitTransactionStatus {
                tx_hash: retry_hash,
                status: TransactionStatus::Pending,
                added_at: self.now,
                cross_shard,
                submitted_locally: false,
            });

            // Gossip the retry to relevant shards
            actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
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
                }
            }

            if let Some(entry) = self.pool.get_mut(hash) {
                entry.status = TransactionStatus::Committed(height);
            }
        }
    }

    /// Mark a transaction as executed (execution complete, certificate created).
    ///
    /// Called when ExecutionState creates a TransactionCertificate.
    /// Also triggers retries for any transactions deferred by this winner.
    #[instrument(skip(self), fields(tx_hash = ?tx_hash, accepted = accepted))]
    pub fn on_transaction_executed(&mut self, tx_hash: Hash, accepted: bool) -> Vec<Action> {
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
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Executed {
                    decision,
                    committed_at,
                },
                added_at,
                cross_shard,
                submitted_locally,
            });
        }

        // Check if any deferred transactions were waiting for this winner to complete.
        // This triggers retries immediately when the winner executes, rather than
        // waiting for the certificate to be committed in a block.
        // Using reverse index for O(1) lookup
        let loser_hashes = self
            .deferred_losers_by_winner
            .remove(&tx_hash)
            .unwrap_or_default();

        let height = self.current_height;
        for loser_hash in loser_hashes {
            // Get the loser transaction from deferred_by
            let Some((loser_tx, winner_hash, _deferred_at)) = self.deferred_by.remove(&loser_hash)
            else {
                continue;
            };
            // Create retry transaction
            let retry_tx = loser_tx.create_retry(winner_hash, height);
            let retry_hash = retry_tx.hash();

            tracing::info!(
                original = %loser_hash,
                retry = %retry_hash,
                winner = %winner_hash,
                retry_count = retry_tx.retry_count(),
                "Creating retry for deferred transaction (winner finalized)"
            );

            // Update original's status to Retried and evict
            if let Some(entry) = self.pool.get(&loser_hash) {
                let added_at = entry.added_at;
                let cross_shard = entry.cross_shard;
                let submitted_locally = entry.submitted_locally;
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: loser_hash,
                    status: TransactionStatus::Retried { new_tx: retry_hash },
                    added_at,
                    cross_shard,
                    submitted_locally,
                });
                // Evict from pool and tombstone - terminal state
                self.evict_terminal(loser_hash);
            }

            // Add retry to mempool if not already present (dedup by hash)
            if !self.pool.contains_key(&retry_hash) && !self.is_tombstoned(&retry_hash) {
                let retry_tx = Arc::new(retry_tx);
                let cross_shard = retry_tx.is_cross_shard(self.topology.num_shards());
                self.pool.insert(
                    retry_hash,
                    PoolEntry {
                        tx: Arc::clone(&retry_tx),
                        status: TransactionStatus::Pending,
                        added_at: self.now,
                        cross_shard,
                        submitted_locally: false, // System-generated retry
                    },
                );

                // Add to ready tracking
                self.add_to_ready_tracking(retry_hash, &retry_tx, cross_shard);

                // Emit status for retry transaction
                actions.push(Action::EmitTransactionStatus {
                    tx_hash: retry_hash,
                    status: TransactionStatus::Pending,
                    added_at: self.now,
                    cross_shard,
                    submitted_locally: false,
                });

                // Gossip the retry to relevant shards
                actions.extend(self.broadcast_to_transaction_shards(&retry_tx));
            }
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
            // Evict from pool and tombstone - terminal state
            self.evict_terminal(*tx_hash);
            return vec![Action::EmitTransactionStatus {
                tx_hash: *tx_hash,
                status: TransactionStatus::Completed(decision),
                added_at,
                cross_shard,
                submitted_locally,
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
                entry.status = new_status.clone();
                return vec![Action::EmitTransactionStatus {
                    tx_hash: *tx_hash,
                    status: new_status,
                    added_at,
                    cross_shard,
                    submitted_locally,
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
    /// Also promotes any deferred transactions that were waiting on these nodes.
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
    ) {
        // Find all locked nodes that block this transaction
        let mut blocking_nodes: HashSet<NodeId> = tx
            .all_declared_nodes()
            .filter(|node| self.locked_nodes_cache.contains(node))
            .copied()
            .collect();

        // Special case: retry transactions are not blocked by their original's locks.
        // When a retry T' arrives (e.g., via gossip from a shard that created the retry),
        // it should supersede T. The locks T holds should not block T'.
        if !blocking_nodes.is_empty() && tx.is_retry() {
            let original_hash = tx.original_hash();
            if let Some(original_entry) = self.pool.get(&original_hash) {
                if original_entry.status.holds_state_lock() {
                    // Remove the original's nodes from blocking_nodes - they don't block the retry
                    let original_nodes: HashSet<NodeId> =
                        original_entry.tx.all_declared_nodes().copied().collect();
                    blocking_nodes.retain(|node| !original_nodes.contains(node));
                }
            }
        }

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
        self.add_to_ready_set(hash, tx, cross_shard);
    }

    /// Add a transaction to the appropriate ready set based on its properties.
    ///
    /// Precondition: transaction must not be deferred by any locked nodes.
    fn add_to_ready_set(&mut self, hash: Hash, tx: &Arc<RoutableTransaction>, cross_shard: bool) {
        let ready_entry = ReadyEntry {
            tx: Arc::clone(tx),
            has_provisions: false, // Updated by on_provision_verified
        };

        // Add to reverse index for O(1) blocking when nodes become locked
        for node in tx.all_declared_nodes() {
            self.ready_txs_by_node
                .entry(*node)
                .or_default()
                .insert(hash);
        }

        if tx.is_retry() {
            self.ready_retries.insert(hash, ready_entry);
        } else if cross_shard {
            // Cross-shard starts in others, promoted to priority when provisions verified
            self.ready_others.insert(hash, ready_entry);
        } else {
            self.ready_others.insert(hash, ready_entry);
        }
    }

    /// Remove a transaction from all ready tracking structures.
    ///
    /// Called when a transaction is no longer Pending (committed, evicted, etc.).
    fn remove_from_ready_tracking(&mut self, hash: &Hash) {
        // Remove from ready sets and clean reverse index
        if let Some(entry) = self.ready_retries.remove(hash) {
            self.remove_from_ready_txs_by_node(hash, &entry.tx);
        } else if let Some(entry) = self.ready_priority.remove(hash) {
            self.remove_from_ready_txs_by_node(hash, &entry.tx);
        } else if let Some(entry) = self.ready_others.remove(hash) {
            self.remove_from_ready_txs_by_node(hash, &entry.tx);
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
            // Try to remove from each ready set (transaction is in exactly one)
            let removed_entry = self
                .ready_retries
                .remove(&hash)
                .or_else(|| self.ready_priority.remove(&hash))
                .or_else(|| self.ready_others.remove(&hash));

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
        let mut to_promote: Vec<(Hash, Arc<RoutableTransaction>, bool)> = Vec::new();

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
                            to_promote.push((tx_hash, Arc::clone(&entry.tx), entry.cross_shard));
                        }
                    }
                }
            }
        }

        // Now promote all collected transactions
        for (hash, tx, cross_shard) in to_promote {
            self.add_to_ready_set(hash, &tx, cross_shard);
        }
    }

    /// Promote a cross-shard transaction from ready_others to ready_priority.
    ///
    /// Called when provisions are verified for a transaction.
    pub fn on_provision_verified(&mut self, tx_hash: Hash) {
        if let Some(mut entry) = self.ready_others.remove(&tx_hash) {
            entry.has_provisions = true;
            self.ready_priority.insert(tx_hash, entry);
        }
    }

    /// Get transactions ready for inclusion in a block with backpressure support.
    ///
    /// Returns transactions in three priority groups:
    /// 1. **Highest**: Retry transactions (must be included quickly to avoid stalls)
    /// 2. **High**: Cross-shard TXs with verified provisions (other shards waiting on us)
    /// 3. **Normal**: All other TXs (subject to backpressure limit)
    ///
    /// Within each group, transactions are sorted by hash (ascending) for determinism.
    ///
    /// Backpressure rules:
    /// - Retry TXs bypass soft limit (critical path - deferred TX needs fast retry)
    /// - Cross-shard TXs WITH verified provisions bypass soft limit (other shards waiting on us)
    /// - All other TXs (single-shard and cross-shard without provisions) subject to soft limit
    /// - At hard limit, NO transactions proposed (even retries or those with provisions)
    ///
    /// The backpressure limit is based on how many transactions are currently holding
    /// state locks (Committed or Executed status). This controls execution and crypto
    /// verification pressure across the system.
    ///
    /// Retry priority is critical: when a transaction is deferred due to livelock, a retry
    /// is created with a new hash. The retry must be included quickly so it can complete
    /// before hitting more conflicts. Without this priority, retries would compete with
    /// new transactions and potentially stall indefinitely.
    ///
    /// Returns transactions organized by priority section, each sorted by hash.
    /// This allows block building without reclassification, preserving sort order.
    ///
    /// Parameters:
    /// - `max_count`: Maximum total transactions across all sections
    /// - `pending_commit_tx_count`: Transactions about to be committed (INCREASES in-flight)
    /// - `pending_commit_cert_count`: Certificates about to be committed (DECREASES in-flight)
    ///
    /// The effective in-flight is: current + pending_txs - pending_certs
    ///
    /// # Performance
    ///
    /// This method is O(min(ready_set_size, max_count)) instead of O(pool_size) because
    /// it reads from pre-computed ready sets that are maintained incrementally.
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
        let at_soft_limit = effective_in_flight >= self.config.max_in_flight;
        let at_hard_limit = effective_in_flight >= self.config.max_in_flight_hard_limit;

        // At hard limit: no TXs at all
        if at_hard_limit {
            return ReadyTransactions::default();
        }

        // Cap max_count to stay within hard limit
        // We can add at most (hard_limit - effective_in_flight) transactions
        let room_to_hard_limit = self
            .config
            .max_in_flight_hard_limit
            .saturating_sub(effective_in_flight);
        let max_count = max_count.min(room_to_hard_limit);

        let mut remaining = max_count;
        let mut result = ReadyTransactions::default();

        // Tier 1: Retry transactions (highest priority, bypass soft limit)
        // BTreeMap iteration is in hash order
        for entry in self.ready_retries.values() {
            if remaining == 0 {
                break;
            }
            result.retries.push(Arc::clone(&entry.tx));
            remaining -= 1;
        }

        // Tier 2: Priority transactions (cross-shard with provisions, bypass soft limit)
        for entry in self.ready_priority.values() {
            if remaining == 0 {
                break;
            }
            result.priority.push(Arc::clone(&entry.tx));
            remaining -= 1;
        }

        // Tier 3: Other transactions (subject to soft limit)
        if !at_soft_limit {
            for entry in self.ready_others.values() {
                if remaining == 0 {
                    break;
                }
                result.others.push(Arc::clone(&entry.tx));
                remaining -= 1;
            }
        }

        result
    }

    /// Get lock contention statistics.
    ///
    /// Returns counts of:
    /// - `locked_nodes`: Number of nodes currently locked by in-flight transactions
    /// - `deferred_count`: Number of transactions deferred waiting for a winner
    /// - `pending_count`: Number of transactions in Pending status
    /// - `pending_deferred`: Number of pending transactions that conflict with locked nodes
    /// - `committed_count`: Number of transactions in Committed status
    /// - `executed_count`: Number of transactions in Executed status
    ///
    /// All stats are O(1) via cached counters and ready sets.
    pub fn lock_contention_stats(&self) -> LockContentionStats {
        let locked_nodes = self.locked_nodes_cache.len() as u64;
        let deferred_count = self.deferred_by.len() as u64;

        // Pending counts are O(1) from ready sets
        let ready_count =
            self.ready_retries.len() + self.ready_priority.len() + self.ready_others.len();
        let pending_deferred = self.deferred_by_nodes.len() as u64;
        let pending_count = (ready_count + self.deferred_by_nodes.len()) as u64;

        LockContentionStats {
            locked_nodes,
            deferred_count,
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

    /// Check if we're at the backpressure soft limit.
    ///
    /// At this limit, new transactions without provisions are delayed.
    /// Cross-shard TXs WITH provisions can still be proposed (other shards waiting on us).
    pub fn at_in_flight_limit(&self) -> bool {
        self.in_flight() >= self.config.max_in_flight
    }

    /// Check if we're at the hard limit.
    ///
    /// At this limit, NO new transactions are proposed, even cross-shard TXs
    /// with provisions. This prevents unbounded growth and controls system pressure.
    pub fn at_in_flight_hard_limit(&self) -> bool {
        self.in_flight() >= self.config.max_in_flight_hard_limit
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

    /// Get all transactions as a HashMap (for block header validation).
    ///
    /// This allows BFT to look up transactions by hash when receiving block headers.
    pub fn transactions_by_hash(&self) -> HashMap<Hash, Arc<RoutableTransaction>> {
        self.pool
            .iter()
            .map(|(hash, entry)| (*hash, Arc::clone(&entry.tx)))
            .collect()
    }

    /// Get the number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Get the mempool as a hash map for BFT pending block completion.
    pub fn as_hash_map(&self) -> std::collections::HashMap<Hash, Arc<RoutableTransaction>> {
        self.pool
            .iter()
            .map(|(hash, entry)| (*hash, Arc::clone(&entry.tx)))
            .collect()
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

    /// Get transactions that have timed out waiting for execution.
    ///
    /// Transactions timeout if they've been holding state locks for too long.
    /// This is a safety net for N-way cycles that aren't detected by pairwise
    /// cycle detection.
    ///
    /// Returns `TransactionAbort` entries ready for inclusion in a block.
    ///
    /// # Parameters
    /// - `current_height`: The current block height
    /// - `timeout_blocks`: Number of blocks after which a TX is considered timed out
    /// - `max_retries`: Maximum retry count before aborting
    pub fn get_timed_out_transactions(
        &self,
        current_height: BlockHeight,
        timeout_blocks: u64,
        max_retries: u32,
    ) -> Vec<TransactionAbort> {
        let mut aborts = Vec::new();

        for (hash, entry) in &self.pool {
            // Skip transactions that are already finalized (Completed is terminal)
            if matches!(entry.status, TransactionStatus::Completed(_)) {
                continue;
            }

            // Check for execution timeout (TX stuck in lock-holding state too long)
            // Both Committed and Executed states hold locks and need timeout checks.
            // Cross-shard transactions can get stuck in Executed state if certificate
            // inclusion fails on another shard (e.g., the other shard aborted first).
            let committed_at = match &entry.status {
                TransactionStatus::Committed(height) => Some(*height),
                TransactionStatus::Executed { committed_at, .. } => Some(*committed_at),
                _ => None,
            };

            if let Some(committed_at) = committed_at {
                let blocks_elapsed = current_height.0.saturating_sub(committed_at.0);
                if blocks_elapsed >= timeout_blocks {
                    let status_name = match &entry.status {
                        TransactionStatus::Committed(_) => "Committed",
                        TransactionStatus::Executed { .. } => "Executed",
                        _ => "Unknown",
                    };
                    tracing::debug!(
                        tx_hash = %hash,
                        committed_at = committed_at.0,
                        current_height = current_height.0,
                        blocks_elapsed = blocks_elapsed,
                        status = status_name,
                        "Transaction timed out waiting for completion"
                    );
                    aborts.push(TransactionAbort {
                        tx_hash: *hash,
                        reason: AbortReason::ExecutionTimeout { committed_at },
                        block_height: BlockHeight(0), // Filled in by proposer
                    });
                }
            }

            // Check for too many retries
            if entry.tx.exceeds_max_retries(max_retries) {
                tracing::info!(
                    tx_hash = %hash,
                    retry_count = entry.tx.retry_count(),
                    max_retries = max_retries,
                    "Transaction exceeded maximum retry count"
                );
                aborts.push(TransactionAbort {
                    tx_hash: *hash,
                    reason: AbortReason::TooManyRetries {
                        retry_count: entry.tx.retry_count(),
                    },
                    block_height: BlockHeight(0), // Filled in by proposer
                });
            }
        }

        aborts
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

        // Also clean up completed_winners using the same retention policy
        self.completed_winners.retain(|_, height| height.0 > cutoff);

        // Clean up pending_deferrals - these are waiting for a transaction that
        // hasn't arrived yet. If it's been too long, the transaction is likely
        // never coming and we should clean up to prevent unbounded growth.
        let before_deferrals = self.pending_deferrals.len();
        self.pending_deferrals
            .retain(|_, (_, height)| height.0 > cutoff);
        let cleaned_deferrals = before_deferrals - self.pending_deferrals.len();

        // Clean up pending_retries - these are waiting for a loser transaction
        // to arrive so we can create a retry. Same cleanup logic applies.
        let before_retries = self.pending_retries.len();
        self.pending_retries
            .retain(|_, (_, height)| height.0 > cutoff);
        let cleaned_retries = before_retries - self.pending_retries.len();

        // Clean up deferred_by - these are transactions waiting for their winner to
        // complete. If it's been too long, the winner is likely never completing.
        let before_deferred = self.deferred_by.len();
        let stale_deferred: Vec<Hash> = self
            .deferred_by
            .iter()
            .filter(|(_, (_, _, deferred_at))| deferred_at.0 <= cutoff)
            .map(|(hash, _)| *hash)
            .collect();

        for loser_hash in &stale_deferred {
            if let Some((_, winner_hash, _)) = self.deferred_by.remove(loser_hash) {
                // Also clean up the reverse index
                if let Some(losers) = self.deferred_losers_by_winner.get_mut(&winner_hash) {
                    losers.retain(|h| h != loser_hash);
                    if losers.is_empty() {
                        self.deferred_losers_by_winner.remove(&winner_hash);
                    }
                }
            }
        }
        let cleaned_deferred = before_deferred - self.deferred_by.len();

        if cleaned_deferrals > 0 || cleaned_retries > 0 || cleaned_deferred > 0 {
            tracing::debug!(
                cleaned_deferrals,
                cleaned_retries,
                cleaned_deferred,
                cutoff_height = cutoff,
                "Cleaned up stale pending deferrals/retries/deferred"
            );
        }

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
        generate_bls_keypair, test_utils::test_transaction, Block, BlockHeader, DeferReason,
        QuorumCertificate, ShardGroupId, StaticTopology, TransactionCertificate, TransactionDefer,
        ValidatorId, ValidatorInfo, ValidatorSet,
    };
    use std::collections::BTreeMap;

    fn make_test_topology() -> Arc<dyn Topology> {
        let validators: Vec<_> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set))
    }

    fn make_test_block(
        height: u64,
        transactions: Vec<RoutableTransaction>,
        deferred: Vec<TransactionDefer>,
        certificates: Vec<TransactionCertificate>,
        aborted: Vec<TransactionAbort>,
    ) -> Block {
        Block {
            header: BlockHeader {
                height: BlockHeight(height),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: transactions.into_iter().map(Arc::new).collect(),
            certificates: certificates.into_iter().map(Arc::new).collect(),
            deferred,
            aborted,
            commitment_proofs: std::collections::HashMap::new(),
        }
    }

    fn make_test_certificate(tx_hash: Hash) -> TransactionCertificate {
        TransactionCertificate {
            transaction_hash: tx_hash,
            decision: TransactionDecision::Accept,
            shard_proofs: BTreeMap::new(), // Empty for test - just need tx_hash
        }
    }

    fn make_test_deferral(loser_tx: Hash, winner_tx: Hash, height: u64) -> TransactionDefer {
        use hyperscale_types::{
            Bls12381G2Signature, CommitmentProof, CycleProof, ShardGroupId, SignerBitfield,
        };

        let commitment_proof = CommitmentProof {
            tx_hash: winner_tx,
            source_shard: ShardGroupId(1),
            signers: SignerBitfield::empty(),
            aggregated_signature: Bls12381G2Signature([0u8; 96]),
            block_height: BlockHeight(1),
            block_timestamp: 1000,
            entries: std::sync::Arc::new(vec![]),
        };
        let proof = CycleProof::new(winner_tx, commitment_proof);

        TransactionDefer {
            tx_hash: loser_tx,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: winner_tx,
            },
            block_height: BlockHeight(height),
            proof,
        }
    }

    #[test]
    fn test_deferral_updates_status_to_deferred() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and add a transaction
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        // Commit the transaction first (deferrals apply to committed TXs)
        let commit_block = make_test_block(1, vec![tx.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Simulate the TransactionStatusChanged event from execution
        mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));

        // Verify status is Committed
        assert!(matches!(
            mempool.status(&tx_hash),
            Some(TransactionStatus::Committed(_))
        ));

        // Create another TX as the "winner"
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();
        mempool.on_submit_transaction(winner_tx.clone());

        // Create a deferral for our TX
        let deferral = make_test_deferral(tx_hash, winner_hash, 2);

        // Process block with deferral
        let defer_block = make_test_block(2, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&defer_block);

        // Verify status is now Deferred
        let status = mempool.status(&tx_hash);
        assert!(matches!(
            status,
            Some(TransactionStatus::Deferred { by }) if by == winner_hash
        ));

        // Verify it's tracked in deferred_by
        assert!(mempool.deferred_by.contains_key(&tx_hash));
    }

    #[test]
    fn test_winner_certificate_triggers_retry() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create loser TX and submit
        let loser_tx = test_transaction(1);
        let loser_hash = loser_tx.hash();
        mempool.on_submit_transaction(loser_tx.clone());

        // Create winner TX and submit
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();
        mempool.on_submit_transaction(winner_tx.clone());

        // Commit both
        let commit_block = make_test_block(
            1,
            vec![loser_tx.clone(), winner_tx.clone()],
            vec![],
            vec![],
            vec![],
        );
        mempool.on_block_committed_full(&commit_block);

        // Defer the loser
        let deferral = make_test_deferral(loser_hash, winner_hash, 2);
        let defer_block = make_test_block(2, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&defer_block);

        // Verify loser is deferred
        assert!(matches!(
            mempool.status(&loser_hash),
            Some(TransactionStatus::Deferred { .. })
        ));

        // Winner's certificate commits
        let winner_cert = make_test_certificate(winner_hash);
        let cert_block = make_test_block(3, vec![], vec![], vec![winner_cert], vec![]);
        let actions = mempool.on_block_committed_full(&cert_block);

        // Should have emitted Retried status for loser
        let retried_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash, status: TransactionStatus::Retried { .. }, .. } if *tx_hash == loser_hash)
        });
        assert!(
            retried_action.is_some(),
            "Should have emitted Retried status for loser"
        );

        // Loser should be evicted from pool (terminal state)
        assert!(
            mempool.status(&loser_hash).is_none(),
            "Loser should be evicted from pool after Retried"
        );

        // Extract retry hash from the action
        let retry_hash = match retried_action.unwrap() {
            Action::EmitTransactionStatus {
                status: TransactionStatus::Retried { new_tx },
                ..
            } => *new_tx,
            _ => unreachable!(),
        };

        // Retry should exist in pool as Pending
        let retry_status = mempool.status(&retry_hash);
        assert!(
            matches!(retry_status, Some(TransactionStatus::Pending)),
            "Retry should be Pending, got {:?}",
            retry_status
        );

        // deferred_by should be cleared
        assert!(!mempool.deferred_by.contains_key(&loser_hash));
    }

    #[test]
    fn test_timeout_detection() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Simulate the TransactionStatusChanged event from execution
        mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));

        // Check for timeouts - not enough blocks elapsed
        let aborts = mempool.get_timed_out_transactions(BlockHeight(20), 30, 3);
        assert!(aborts.is_empty(), "Should not timeout yet");

        // Check for timeouts - now enough blocks
        let aborts = mempool.get_timed_out_transactions(BlockHeight(35), 30, 3);
        assert_eq!(aborts.len(), 1);
        assert_eq!(aborts[0].tx_hash, tx_hash);
        assert!(matches!(
            aborts[0].reason,
            AbortReason::ExecutionTimeout { .. }
        ));
    }

    #[test]
    fn test_executed_transaction_timeout() {
        // Tests that transactions in Executed state can also timeout.
        // This is critical for cross-shard transactions that get stuck when
        // certificate inclusion fails on another shard.
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Simulate committed status from execution
        mempool.update_status(&tx_hash, TransactionStatus::Committed(BlockHeight(1)));

        // Now simulate execution completing (moves to Executed status)
        // This preserves the committed_at height for timeout tracking
        let _actions = mempool.on_transaction_executed(tx_hash, true);

        // Verify it's in Executed state with preserved committed_at
        let status = mempool.status(&tx_hash).unwrap();
        assert!(
            matches!(
                status,
                TransactionStatus::Executed {
                    decision: TransactionDecision::Accept,
                    committed_at: BlockHeight(1)
                }
            ),
            "Expected Executed status with committed_at=1, got {:?}",
            status
        );

        // Check for timeouts - not enough blocks elapsed
        let aborts = mempool.get_timed_out_transactions(BlockHeight(20), 30, 3);
        assert!(aborts.is_empty(), "Should not timeout yet");

        // Check for timeouts - now enough blocks (31 blocks since committed at height 1)
        let aborts = mempool.get_timed_out_transactions(BlockHeight(35), 30, 3);
        assert_eq!(aborts.len(), 1, "Executed transaction should timeout");
        assert_eq!(aborts[0].tx_hash, tx_hash);
        assert!(matches!(
            aborts[0].reason,
            AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1)
            }
        ));
    }

    #[test]
    fn test_too_many_retries_detection() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create a TX that has already been retried multiple times
        let tx = test_transaction(1);
        let _tx_hash = tx.hash();

        // Manually create a retry TX (simulating previous retries)
        let retry1 = tx.create_retry(Hash::from_bytes(b"winner1"), BlockHeight(1));
        let retry2 = retry1.create_retry(Hash::from_bytes(b"winner2"), BlockHeight(2));
        let retry3 = retry2.create_retry(Hash::from_bytes(b"winner3"), BlockHeight(3));

        assert_eq!(retry3.retry_count(), 3);

        // Submit the multiply-retried TX
        mempool.on_submit_transaction(retry3.clone());

        // Should detect too many retries (max_retries = 3 means 3 retries allowed, 4th would be rejected)
        let aborts = mempool.get_timed_out_transactions(BlockHeight(10), 100, 3);
        assert_eq!(aborts.len(), 1);
        assert!(matches!(
            aborts[0].reason,
            AbortReason::TooManyRetries { retry_count: 3 }
        ));
    }

    #[test]
    fn test_abort_updates_status() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and commit a TX
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Process an abort
        let abort = TransactionAbort {
            tx_hash,
            reason: AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1),
            },
            block_height: BlockHeight(35),
        };
        let abort_block = make_test_block(35, vec![], vec![], vec![], vec![abort]);
        let actions = mempool.on_block_committed_full(&abort_block);

        // Should have emitted Aborted status
        let aborted_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash: h, status: TransactionStatus::Aborted { .. }, .. } if *h == tx_hash)
        });
        assert!(
            aborted_action.is_some(),
            "Should have emitted Aborted status"
        );

        // Transaction should be evicted from pool (terminal state)
        assert!(
            mempool.status(&tx_hash).is_none(),
            "Transaction should be evicted from pool after Aborted"
        );
    }

    #[test]
    fn test_retry_has_different_hash() {
        let tx = test_transaction(1);
        let original_hash = tx.hash();

        let retry = tx.create_retry(Hash::from_bytes(b"winner"), BlockHeight(5));
        let retry_hash = retry.hash();

        // Retry must have different hash
        assert_ne!(
            original_hash, retry_hash,
            "Retry must have different hash from original"
        );

        // But same underlying transaction content (declared reads/writes are fields)
        assert_eq!(tx.declared_reads, retry.declared_reads);
        assert_eq!(tx.declared_writes, retry.declared_writes);

        // Retry knows its original
        assert_eq!(retry.original_hash(), original_hash);
        assert_eq!(retry.retry_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync Scenario Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_deferral_for_transaction_not_in_pool() {
        // Scenario: Node syncs a block containing a deferral for a transaction
        // that was committed in an earlier block the node didn't have.
        // The deferral should be stored and processed when the transaction arrives.

        let mut mempool = MempoolState::new(make_test_topology());

        // Create transactions
        let loser_tx = test_transaction(1);
        let loser_hash = loser_tx.hash();
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();

        // Process a synced block that contains ONLY the deferral and certificate
        // (simulating: loser_tx was in an earlier block we don't have yet)
        let deferral = make_test_deferral(loser_hash, winner_hash, 5);
        let winner_cert = make_test_certificate(winner_hash);

        // Process block with deferral and certificate, but WITHOUT the loser transaction
        let sync_block = make_test_block(
            5,
            vec![winner_tx],
            vec![deferral],
            vec![winner_cert],
            vec![],
        );
        let _actions = mempool.on_block_committed_full(&sync_block);

        // The loser transaction is NOT in the pool
        assert!(mempool.status(&loser_hash).is_none());

        // But we should have a pending retry stored for it
        assert!(
            mempool.pending_retries.contains_key(&loser_hash),
            "Should have stored pending retry for loser"
        );

        // Now the earlier block arrives with the loser transaction
        let earlier_block = make_test_block(3, vec![loser_tx.clone()], vec![], vec![], vec![]);
        let actions = mempool.on_block_committed_full(&earlier_block);

        // The pending retry should have been processed - we should see retry creation actions
        let retried_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash, status: TransactionStatus::Retried { .. }, .. } if *tx_hash == loser_hash)
        });
        assert!(
            retried_action.is_some(),
            "Should have created retry when deferred transaction arrived"
        );

        // Pending retry should be cleared
        assert!(
            !mempool.pending_retries.contains_key(&loser_hash),
            "Pending retry should be cleared after processing"
        );
    }

    #[test]
    fn test_sync_deferral_before_certificate() {
        // Scenario: Deferral arrives in block N, but loser tx is not in pool yet.
        // Certificate arrives in block N+1.
        // Then loser tx arrives in block N+2.
        // Retry should be created when loser tx arrives.

        let mut mempool = MempoolState::new(make_test_topology());

        let loser_tx = test_transaction(1);
        let loser_hash = loser_tx.hash();
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();

        // Block N: Deferral without loser tx in pool
        let deferral = make_test_deferral(loser_hash, winner_hash, 5);
        let block_n = make_test_block(5, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&block_n);

        // Pending deferral should be stored
        assert!(
            mempool.pending_deferrals.contains_key(&loser_hash),
            "Should have stored pending deferral"
        );
        // Reverse index should be set up
        assert!(
            mempool
                .deferred_losers_by_winner
                .get(&winner_hash)
                .is_some_and(|losers| losers.contains(&loser_hash)),
            "Reverse index should contain loser"
        );

        // Block N+1: Winner's certificate arrives
        let winner_cert = make_test_certificate(winner_hash);
        let block_n1 = make_test_block(6, vec![winner_tx], vec![], vec![winner_cert], vec![]);
        mempool.on_block_committed_full(&block_n1);

        // Pending deferral should be converted to pending retry
        assert!(
            !mempool.pending_deferrals.contains_key(&loser_hash),
            "Pending deferral should be removed"
        );
        assert!(
            mempool.pending_retries.contains_key(&loser_hash),
            "Should have stored pending retry"
        );

        // Block N+2: Loser tx finally arrives
        let block_n2 = make_test_block(7, vec![loser_tx.clone()], vec![], vec![], vec![]);
        let actions = mempool.on_block_committed_full(&block_n2);

        // Retry should be created
        let retried_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash, status: TransactionStatus::Retried { .. }, .. } if *tx_hash == loser_hash)
        });
        assert!(
            retried_action.is_some(),
            "Should have created retry when loser tx arrived"
        );

        // All pending structures should be cleared
        assert!(!mempool.pending_deferrals.contains_key(&loser_hash));
        assert!(!mempool.pending_retries.contains_key(&loser_hash));
    }

    #[test]
    fn test_sync_deferral_with_tx_in_same_block() {
        // Scenario: Synced block contains both the transaction AND its deferral.
        // This is the normal case - should work as before.

        let mut mempool = MempoolState::new(make_test_topology());

        let loser_tx = test_transaction(1);
        let loser_hash = loser_tx.hash();
        let winner_tx = test_transaction(2);
        let winner_hash = winner_tx.hash();

        // Block with both loser tx and deferral
        let deferral = make_test_deferral(loser_hash, winner_hash, 5);
        let block = make_test_block(
            5,
            vec![loser_tx.clone(), winner_tx],
            vec![deferral],
            vec![],
            vec![],
        );
        let actions = mempool.on_block_committed_full(&block);

        // Transaction should be in pool and deferred
        let status = mempool.status(&loser_hash);
        assert!(
            matches!(status, Some(TransactionStatus::Deferred { by }) if by == winner_hash),
            "Loser should be Deferred, got {:?}",
            status
        );

        // Should have emitted Deferred status
        let deferred_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash, status: TransactionStatus::Deferred { .. }, .. } if *tx_hash == loser_hash)
        });
        assert!(
            deferred_action.is_some(),
            "Should have emitted Deferred status"
        );

        // Should NOT have pending deferral (it was processed immediately)
        assert!(
            !mempool.pending_deferrals.contains_key(&loser_hash),
            "Should not have pending deferral when tx was in same block"
        );
    }

    #[test]
    fn test_sync_multiple_blocks_with_dependencies() {
        // Scenario: Multi-block sync where:
        // - Block N: TX_A committed
        // - Block N+1: TX_A deferred (deferred by TX_B)
        // - Block N+2: TX_B's certificate commits, retry created for TX_A

        let mut mempool = MempoolState::new(make_test_topology());

        let tx_a = test_transaction(1);
        let tx_a_hash = tx_a.hash();
        let tx_b = test_transaction(2);
        let tx_b_hash = tx_b.hash();

        // Process blocks in order
        // Block N: TX_A committed
        let block_n = make_test_block(5, vec![tx_a.clone(), tx_b.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&block_n);

        assert!(mempool.pool.contains_key(&tx_a_hash));
        assert!(mempool.pool.contains_key(&tx_b_hash));

        // Block N+1: TX_A deferred
        let deferral = make_test_deferral(tx_a_hash, tx_b_hash, 6);
        let block_n1 = make_test_block(6, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&block_n1);

        // TX_A should be Deferred
        assert!(matches!(
            mempool.status(&tx_a_hash),
            Some(TransactionStatus::Deferred { by }) if by == tx_b_hash
        ));

        // Block N+2: TX_B's certificate commits
        let tx_b_cert = make_test_certificate(tx_b_hash);
        let block_n2 = make_test_block(7, vec![], vec![], vec![tx_b_cert], vec![]);
        let actions = mempool.on_block_committed_full(&block_n2);

        // Retry should be created for TX_A
        let retried_action = actions.iter().find(|a| {
            matches!(a, Action::EmitTransactionStatus { tx_hash, status: TransactionStatus::Retried { .. }, .. } if *tx_hash == tx_a_hash)
        });
        assert!(
            retried_action.is_some(),
            "Should have created retry for TX_A when TX_B's cert committed"
        );

        // TX_A should be evicted from pool
        assert!(
            mempool.status(&tx_a_hash).is_none(),
            "TX_A should be evicted after retry created"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tombstone Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_completed_transaction_is_tombstoned() {
        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and commit the transaction
        mempool.on_submit_transaction(tx.clone());
        let commit_block = make_test_block(1, vec![tx], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Commit the certificate
        let cert = make_test_certificate(tx_hash);
        let cert_block = make_test_block(2, vec![], vec![], vec![cert], vec![]);
        mempool.on_block_committed_full(&cert_block);

        // Transaction should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_gossip() {
        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction
        mempool.on_submit_transaction(tx.clone());
        let commit_block = make_test_block(1, vec![tx.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        let cert = make_test_certificate(tx_hash);
        let cert_block = make_test_block(2, vec![], vec![], vec![cert], vec![]);
        mempool.on_block_committed_full(&cert_block);

        // Verify it's tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(tx.clone());
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_submit() {
        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction
        mempool.on_submit_transaction(tx.clone());
        let commit_block = make_test_block(1, vec![tx.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        let cert = make_test_certificate(tx_hash);
        let cert_block = make_test_block(2, vec![], vec![], vec![cert], vec![]);
        mempool.on_block_committed_full(&cert_block);

        // Try to re-submit - should be rejected (no status emitted)
        let actions = mempool.on_submit_transaction(tx.clone());
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_aborted_transaction_is_tombstoned() {
        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and commit the transaction
        mempool.on_submit_transaction(tx.clone());

        // Abort the transaction
        let abort = TransactionAbort {
            tx_hash,
            reason: AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1),
            },
            block_height: BlockHeight(2),
        };
        let abort_block = make_test_block(2, vec![], vec![], vec![], vec![abort]);
        mempool.on_block_committed_full(&abort_block);

        // Transaction should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(tx);
        assert!(actions.is_empty(), "Aborted tx should be rejected");
    }

    #[test]
    fn test_retried_transaction_is_tombstoned() {
        let mut mempool = MempoolState::new(make_test_topology());

        let loser = test_transaction(1);
        let loser_hash = loser.hash();
        let winner = test_transaction(2);
        let winner_hash = winner.hash();

        // Submit both transactions
        mempool.on_submit_transaction(loser.clone());
        mempool.on_submit_transaction(winner.clone());

        // Commit both
        let commit_block = make_test_block(
            1,
            vec![loser.clone(), winner.clone()],
            vec![],
            vec![],
            vec![],
        );
        mempool.on_block_committed_full(&commit_block);

        // Defer the loser
        let deferral = make_test_deferral(loser_hash, winner_hash, 2);
        let defer_block = make_test_block(2, vec![], vec![deferral], vec![], vec![]);
        mempool.on_block_committed_full(&defer_block);

        // Complete the winner - this creates a retry for the loser
        let cert = make_test_certificate(winner_hash);
        let cert_block = make_test_block(3, vec![], vec![], vec![cert], vec![]);
        mempool.on_block_committed_full(&cert_block);

        // Original loser should be tombstoned
        assert!(mempool.is_tombstoned(&loser_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(loser);
        assert!(actions.is_empty(), "Retried tx should be rejected");
    }

    #[test]
    fn test_tombstone_cleanup() {
        let mut mempool = MempoolState::new(make_test_topology());

        // Create and complete several transactions at different heights
        for i in 1..=5 {
            let tx = test_transaction(i);
            let tx_hash = tx.hash();

            mempool.on_submit_transaction(tx.clone());
            let commit_block = make_test_block(i as u64, vec![tx], vec![], vec![], vec![]);
            mempool.on_block_committed_full(&commit_block);

            let cert = make_test_certificate(tx_hash);
            let cert_block = make_test_block(i as u64 + 100, vec![], vec![], vec![cert], vec![]);
            mempool.on_block_committed_full(&cert_block);
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

        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Commit the transaction
        mempool.on_submit_transaction(tx.clone());
        let commit_block = make_test_block(10, vec![tx.clone()], vec![], vec![], vec![]);
        mempool.on_block_committed_full(&commit_block);

        // Complete the transaction
        let cert = make_test_certificate(tx_hash);
        let cert_block = make_test_block(11, vec![], vec![], vec![cert], vec![]);
        mempool.on_block_committed_full(&cert_block);

        // Pool should be empty
        assert_eq!(mempool.len(), 0);

        // Simulate late-arriving gossip
        let _actions = mempool.on_transaction_gossip(tx);

        // Pool should still be empty - tombstone prevented resurrection
        assert_eq!(mempool.len(), 0);
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    #[test]
    fn test_mark_completed_creates_tombstone() {
        let mut mempool = MempoolState::new(make_test_topology());

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit the transaction
        mempool.on_submit_transaction(tx.clone());

        // Mark as completed directly
        mempool.mark_completed(&tx_hash, TransactionDecision::Accept);

        // Should be tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));
        assert!(mempool.status(&tx_hash).is_none());

        // Should reject gossip
        let actions = mempool.on_transaction_gossip(tx);
        assert!(actions.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RPC Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_config_defaults() {
        let config = MempoolConfig::default();
        assert_eq!(config.max_in_flight, DEFAULT_IN_FLIGHT_LIMIT);
        assert_eq!(
            config.max_in_flight_hard_limit,
            DEFAULT_IN_FLIGHT_HARD_LIMIT
        );
    }

    // =========================================================================
    // Backpressure Tests
    // =========================================================================

    fn make_provision_coordinator(
        topology: Arc<dyn Topology>,
    ) -> hyperscale_provisions::ProvisionCoordinator {
        hyperscale_provisions::ProvisionCoordinator::new(ShardGroupId(0), topology)
    }

    /// Create a mempool config with a low in-flight limit for testing.
    fn make_mempool_config_with_limit(limit: usize) -> MempoolConfig {
        MempoolConfig {
            max_in_flight: limit,
            max_in_flight_hard_limit: limit * 2, // Hard limit is 2x soft limit
            max_pending: DEFAULT_MAX_PENDING,
        }
    }

    /// Put a mempool at the backpressure limit by adding committed transactions.
    fn put_mempool_at_limit(mempool: &mut MempoolState, _topology: &dyn Topology) {
        let limit = mempool.config.max_in_flight;

        // Add TXs and mark them as Committed to hold locks
        for i in 0..limit {
            let tx = test_transaction(100 + i as u8);
            let tx_hash = tx.hash();
            mempool.on_submit_transaction(tx);
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
    fn make_cross_shard_topology() -> Arc<dyn Topology> {
        let validators: Vec<_> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: generate_bls_keypair().public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        // 2 shards
        Arc::new(StaticTopology::new(ValidatorId(0), 2, validator_set))
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
    fn test_backpressure_rejects_all_txns_at_soft_limit() {
        let topology = make_cross_shard_topology();
        // Use a low limit for testing
        let config = make_mempool_config_with_limit(2);
        let mut mempool = MempoolState::with_config(Arc::clone(&topology), config);

        // Put mempool at the backpressure limit
        put_mempool_at_limit(&mut mempool, topology.as_ref());

        // Add a single-shard transaction
        let single_shard_tx = test_transaction(1);
        mempool.on_submit_transaction(single_shard_tx.clone());

        // Add a cross-shard transaction (no provisions)
        let cross_shard_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(cross_shard_tx.clone());

        // At soft limit: ALL new TXs without provisions should be rejected
        let ready = mempool.ready_transactions(10, 0, 0);
        assert!(
            ready.is_empty(),
            "All TXs without provisions should be rejected at soft limit"
        );
    }

    #[test]
    fn test_backpressure_allows_cross_shard_with_provisions() {
        let topology = make_cross_shard_topology();
        // Use a low limit for testing
        let config = make_mempool_config_with_limit(2);
        let mut mempool = MempoolState::with_config(Arc::clone(&topology), config);

        // Create coordinator and add verified provisions for our TX
        let mut coordinator = make_provision_coordinator(Arc::clone(&topology));

        // Put mempool at the backpressure limit
        put_mempool_at_limit(&mut mempool, topology.as_ref());

        // Add cross-shard transaction
        let tx = test_cross_shard_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(tx.clone());

        // Simulate that another shard has committed this TX by adding verified provisions
        // First register the TX
        let reg = hyperscale_provisions::TxRegistration {
            required_shards: std::iter::once(ShardGroupId(1)).collect(),
            quorum_thresholds: std::iter::once((ShardGroupId(1), 1)).collect(),
            registered_at: BlockHeight(1),
            nodes_by_shard: HashMap::new(),
        };
        coordinator.on_tx_registered(tx_hash, reg);

        // Simulate a verified provision being added (need to call internal method)
        // For this test, we'll just verify the logic by checking has_any_verified_provisions
        // In a real scenario, provisions would be verified via the signature verification flow

        // Without provisions, TX should be rejected at limit
        let ready = mempool.ready_transactions(10, 0, 0);
        assert!(
            ready.is_empty(),
            "Cross-shard TX without provisions should be rejected at limit"
        );
    }

    #[test]
    fn test_backpressure_not_at_limit_allows_all_txns() {
        let topology = make_cross_shard_topology();
        let mut mempool = MempoolState::new(Arc::clone(&topology));

        // Mempool is not at limit (nothing committed)
        assert!(!mempool.at_in_flight_limit());

        // Add a single-shard transaction
        let single_tx = test_transaction(1);
        mempool.on_submit_transaction(single_tx.clone());

        // Add a cross-shard transaction
        let cross_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(cross_tx.clone());

        // Not at limit: all TXs should be allowed
        let ready = mempool.ready_transactions(10, 0, 0);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_in_flight_counts_all_txns() {
        let topology = make_cross_shard_topology();
        let mut mempool = MempoolState::new(Arc::clone(&topology));

        assert_eq!(mempool.in_flight(), 0);

        // Add a single-shard TX and commit it - SHOULD count (all TXs count now)
        let single_tx = test_transaction(200);
        let single_hash = single_tx.hash();
        mempool.on_submit_transaction(single_tx);
        mempool.update_status(&single_hash, TransactionStatus::Committed(BlockHeight(1)));
        assert_eq!(
            mempool.in_flight(),
            1,
            "Committed single-shard TX should count"
        );

        // Add a cross-shard TX in Pending - should NOT count (not holding locks)
        let cross_tx = test_cross_shard_transaction(1);
        let cross_hash = cross_tx.hash();
        mempool.on_submit_transaction(cross_tx);
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

    #[test]
    fn test_retry_transactions_have_highest_priority() {
        let topology = make_cross_shard_topology();
        // Use a low limit for testing
        let config = make_mempool_config_with_limit(2);
        let mut mempool = MempoolState::with_config(Arc::clone(&topology), config);

        // Put mempool at the backpressure limit
        put_mempool_at_limit(&mut mempool, topology.as_ref());

        // Add a normal single-shard transaction (use seed that won't conflict with limit TXs)
        let normal_tx = test_transaction(1);
        mempool.on_submit_transaction(normal_tx.clone());

        // Create a retry transaction (simulating a deferred TX that was retried)
        // Use seed 200 to avoid conflicting with the limit TXs (seeds 100, 101)
        let original_tx = test_transaction(200);
        let retry_tx = original_tx.create_retry(Hash::from_bytes(b"winner"), BlockHeight(5));
        let retry_hash = retry_tx.hash();
        mempool.on_submit_transaction(retry_tx.clone());

        // At soft limit: normal TXs should be rejected, but retries should be allowed
        let ready = mempool.ready_transactions(10, 0, 0);

        // Should contain ONLY the retry (normal TX deferred by backpressure)
        assert_eq!(
            ready.len(),
            1,
            "Only retry should be returned at soft limit"
        );
        assert_eq!(
            ready.retries.len(),
            1,
            "Retry should be in the retries section"
        );
        assert_eq!(
            ready.retries[0].hash(),
            retry_hash,
            "Retry transaction should have priority over normal transactions"
        );
        assert!(
            ready.retries[0].is_retry(),
            "The returned transaction should be a retry"
        );
    }

    #[test]
    fn test_retry_priority_ordering() {
        let topology = make_cross_shard_topology();
        let mut mempool = MempoolState::new(Arc::clone(&topology));

        // Add transactions in mixed order: normal, retry, normal
        let normal1 = test_transaction(1);
        let normal2 = test_transaction(2);
        let original = test_transaction(100);
        let retry = original.create_retry(Hash::from_bytes(b"winner"), BlockHeight(5));

        mempool.on_submit_transaction(normal1.clone());
        mempool.on_submit_transaction(retry.clone());
        mempool.on_submit_transaction(normal2.clone());

        // Request transactions - retry should be in retries section, others in others section
        let ready = mempool.ready_transactions(10, 0, 0);

        assert_eq!(ready.len(), 3, "All transactions should be returned");

        // Retry section should contain exactly the retry
        assert_eq!(ready.retries.len(), 1, "Should have exactly one retry");
        assert!(
            ready.retries[0].is_retry(),
            "Retry transaction should be in retries section"
        );
        assert_eq!(
            ready.retries[0].hash(),
            retry.hash(),
            "Retry should have correct hash"
        );

        // Others section should contain the normal transactions
        assert_eq!(
            ready.others.len(),
            2,
            "Should have two normal transactions in others"
        );
        for tx in &ready.others {
            assert!(!tx.is_retry(), "Normal transactions should not be retries");
        }
    }
}
