//! Mempool state.

use crate::lock_tracker::LockTracker;
use crate::ready_set::ReadySet;
use crate::tombstones::TombstoneStore;
use hyperscale_core::{Action, TransactionStatus};
use hyperscale_types::{
    BlockHeight, BloomFilter, CertifiedBlock, DEFAULT_FPR, LocalTimestamp, NodeId,
    RoutableTransaction, TopologySnapshot, TransactionDecision, TxHash, WeightedTimestamp,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Default minimum dwell time for transactions before they become eligible for block inclusion.
///
/// Allows time for transaction gossip to propagate across validators before proposal,
/// improving batching and fairness.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(150);

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
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // ratio is a monitoring readout, precision loss is irrelevant
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
    /// Transactions held in the main pool.
    pub pool: usize,
    /// Transactions currently in the ready set.
    pub ready: usize,
    /// Tombstone entries (terminal-state dedup).
    pub tombstones: usize,
    /// Recently-evicted transaction bodies cached for late fetches.
    pub recently_evicted: usize,
    /// Nodes currently locked by in-flight transactions.
    pub locked_nodes: usize,
    /// Distinct nodes with at least one deferred transaction.
    pub deferred_by_nodes: usize,
    /// Total transaction-node entries in the deferred index.
    pub txs_deferred_by_node: usize,
    /// Total transaction-node entries in the ready index.
    pub ready_txs_by_node: usize,
}

/// Entry in the transaction pool.
#[derive(Debug)]
struct PoolEntry {
    tx: Arc<RoutableTransaction>,
    status: TransactionStatus,
    /// Whether this is a cross-shard transaction (cached at insertion time).
    cross_shard: bool,
    /// Whether this transaction was submitted locally (via RPC) vs received via gossip/fetch.
    /// Only locally-submitted transactions should contribute to latency metrics.
    submitted_locally: bool,
    /// Local time at first admission to the pool. Held only so that a tx
    /// promoted from the deferred set back into the ready set keeps its
    /// original dwell anchor — without this, every blocker release would
    /// reset the dwell clock and a chronically-deferred tx could be
    /// starved indefinitely. *Not* a telemetry stamp; phase-time tracking
    /// for the slow-tx finalization log lives in the `io_loop`'s
    /// `tx_phase_times` side cache.
    admitted_at: LocalTimestamp,
}

/// Mempool state machine.
///
/// Handles transaction lifecycle from submission to completion.
/// Uses `BTreeMap` for the pool to maintain hash ordering, which allows
/// `ready_transactions()` to iterate in sorted order without sorting.
///
/// # Incremental Ready Set
///
/// To avoid O(n) scans on every `ready_transactions()` call, we maintain
/// a pre-computed ready set that is updated incrementally.
///
/// Transactions are added to this set when they become ready (Pending status,
/// no conflicts with locked nodes) and removed when they are no longer ready
/// (status changes, conflicts arise, or evicted).
pub struct MempoolCoordinator {
    /// Transaction pool sorted by hash (`BTreeMap` for ordered iteration).
    pool: BTreeMap<TxHash, PoolEntry>,

    /// Terminal-state dedup + recently-evicted body cache. Tombstones stop
    /// gossip from re-adding completed/aborted transactions; the evicted
    /// cache retains bodies so slow peers can still fetch them.
    tombstones: TombstoneStore,

    /// Node-level state locks + in-flight counters. A node is locked while
    /// any transaction touching it is in a lock-holding status; the counters
    /// feed backpressure and contention stats.
    locks: LockTracker,

    /// Incremental ready/deferred tracking for Pending transactions.
    /// Every Pending tx is in exactly one of: the ready set (eligible for
    /// block inclusion), the deferred set (blocked by a locked node or a
    /// ready-set conflict), or neither (removed).
    ready: ReadySet,

    /// Current committed block height (for retry transaction creation).
    current_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. "Now" reference for retention windows that must be deterministic
    /// across validators and independent of block production rate.
    current_ts: WeightedTimestamp,

    /// Configuration for mempool behavior.
    config: MempoolConfig,
}

impl std::fmt::Debug for MempoolCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MempoolCoordinator")
            .field("pool_size", &self.pool.len())
            .field("ready", &self.ready.ready_count())
            .field("deferred", &self.ready.deferred_count())
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl Default for MempoolCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolCoordinator {
    /// Create a new mempool state machine with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(MempoolConfig::default())
    }

    /// Create a new mempool state machine with custom config.
    #[must_use]
    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            pool: BTreeMap::new(),
            tombstones: TombstoneStore::new(),
            locks: LockTracker::new(),
            ready: ReadySet::new(),
            current_height: BlockHeight(0),
            current_ts: WeightedTimestamp::ZERO,
            config,
        }
    }

    /// Handle transaction submission from client.
    #[instrument(skip(self, topology, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let hash = tx.hash();

        // Check for duplicate
        if let Some(entry) = self.pool.get(&hash) {
            return vec![Action::EmitTransactionStatus {
                tx_hash: hash,
                status: TransactionStatus::Pending, // Already exists
                cross_shard: entry.cross_shard,
                submitted_locally: entry.submitted_locally,
            }];
        }

        // Reject if tombstoned (already completed/aborted)
        if self.is_tombstoned(&hash) {
            tracing::debug!(tx_hash = ?hash, "Rejecting tombstoned transaction submission");
            return vec![];
        }

        // Reject if already past `validity_range.end_timestamp_exclusive`.
        // Same expression the proposer/validator apply, just at the
        // admission boundary so expired txs never enter the pool.
        if tx.validity_range.end_timestamp_exclusive <= self.current_ts {
            tracing::debug!(
                tx_hash = ?hash,
                end_ms = tx.validity_range.end_timestamp_exclusive.as_millis(),
                now_ms = self.current_ts.as_millis(),
                "Rejecting expired transaction submission"
            );
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(topology.num_shards());
        // Add to ready tracking before moving tx into the pool entry.
        self.add_to_ready_tracking(hash, &tx, now);
        self.pool.insert(
            hash,
            PoolEntry {
                tx,
                status: TransactionStatus::Pending,
                cross_shard,
                submitted_locally: true, // Submitted via RPC
                admitted_at: now,
            },
        );

        tracing::info!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via submit");

        // Note: Broadcasting is handled by NodeStateMachine which broadcasts to all
        // involved shards. Mempool just manages state.
        vec![Action::EmitTransactionStatus {
            tx_hash: hash,
            status: TransactionStatus::Pending,
            cross_shard,
            submitted_locally: true,
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
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let hash = tx.hash();

        // Ignore if already have it or if tombstoned (completed/aborted)
        if self.pool.contains_key(&hash) || self.is_tombstoned(&hash) {
            return vec![];
        }

        // Reject if past expiry — same admission rule as the RPC submit path.
        if tx.validity_range.end_timestamp_exclusive <= self.current_ts {
            tracing::trace!(
                tx_hash = ?hash,
                end_ms = tx.validity_range.end_timestamp_exclusive.as_millis(),
                now_ms = self.current_ts.as_millis(),
                "Dropping expired gossiped transaction"
            );
            return vec![];
        }

        let cross_shard = tx.is_cross_shard(topology.num_shards());
        // Add to ready tracking before moving tx into the pool entry.
        self.add_to_ready_tracking(hash, &tx, now);
        self.pool.insert(
            hash,
            PoolEntry {
                tx,
                status: TransactionStatus::Pending,
                cross_shard,
                submitted_locally,
                admitted_at: now,
            },
        );

        tracing::trace!(tx_hash = ?hash, pool_size = self.pool.len(), "Transaction added to mempool via gossip");

        // No events emitted — gossip acceptance is silent to avoid flooding
        // the consensus channel under high transaction load.
        vec![]
    }

    /// Evict a transaction that has reached a terminal state.
    ///
    /// This removes the transaction from the pool and moves it to the
    /// `recently_evicted` cache so slow peers can still fetch it. The cache
    /// is pruned after `TRANSACTION_RETENTION`.
    ///
    /// Also adds the transaction to the tombstone set to prevent it from
    /// being re-added via gossip. Terminal states include:
    /// - Completed (certificate committed)
    /// - Aborted (explicitly aborted)
    fn evict_terminal(&mut self, topology: &TopologySnapshot, tx_hash: TxHash) {
        // Remove locked nodes and update counters if this transaction was holding locks
        let info_to_unlock = self.pool.get(&tx_hash).and_then(|entry| {
            if entry.status.holds_state_lock() {
                Some((Arc::clone(&entry.tx), entry.status.clone()))
            } else {
                None
            }
        });
        if let Some((tx, status)) = info_to_unlock {
            self.remove_locked_nodes(topology, &tx);
            match status {
                TransactionStatus::Committed(_) => self.locks.dec_committed(),
                TransactionStatus::Executed { .. } => self.locks.dec_executed(),
                _ => {}
            }
        }

        // Remove from ready tracking
        self.remove_from_ready_tracking(&tx_hash);

        // Move transaction body into the evicted cache so slow peers can
        // still fetch it, and tombstone the hash to block re-insertion.
        // Both entries expire at the tx's `end_timestamp_exclusive` —
        // past that, validity check rejects re-submission anyway.
        if let Some(entry) = self.pool.remove(&tx_hash) {
            let end = entry.tx.validity_range.end_timestamp_exclusive;
            self.tombstones.evict(entry.tx);
            self.tombstones.tombstone(tx_hash, end);
        } else {
            // No body — tombstone with whatever expiry we can reconstruct.
            // In practice this branch is unreachable today (callers always
            // tombstone via `evict_terminal` after a successful pool lookup),
            // but the safety net stays so a future caller can't accidentally
            // tombstone a hash with no expiry. Use `current_ts` so the entry
            // is dropped on the very next prune sweep.
            self.tombstones.tombstone(tx_hash, self.current_ts);
        }
    }

    /// Check if a transaction hash is tombstoned (reached terminal state).
    #[must_use]
    pub fn is_tombstoned(&self, tx_hash: &TxHash) -> bool {
        self.tombstones.is_tombstoned(tx_hash)
    }

    /// Drop evicted-cache entries past their `end_timestamp_exclusive`.
    fn prune_recently_evicted(&mut self) {
        self.tombstones.prune_evicted(self.current_ts);
    }

    /// Process a committed block - update statuses and finalize transactions.
    ///
    /// This handles:
    /// 1. Mark committed transactions
    /// 2. Process certificates → mark completed
    /// 3. Process aborts → update status to terminal
    #[instrument(skip(self, certified), fields(
        height = certified.block.height().0,
        tx_count = certified.block.transaction_count()
    ))]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let block = &certified.block;
        let height = block.height();
        let mut actions = Vec::new();

        self.current_height = height;
        self.current_ts = certified.qc.weighted_timestamp;

        // Prune old entries from recently_evicted cache
        self.prune_recently_evicted();

        // Ensure all committed transactions are in the mempool.
        // This handles the case where we fetched transactions to vote on a block
        // but didn't receive them via gossip. We need them in the mempool for
        // status tracking (execution status updates).
        for tx in block.transactions() {
            let hash = tx.hash();
            let num_shards = topology.num_shards();
            self.pool.entry(hash).or_insert_with(|| {
                tracing::debug!(
                    tx_hash = ?hash,
                    height = height.0,
                    "Added committed transaction to mempool"
                );
                PoolEntry {
                    tx: Arc::clone(tx),
                    status: TransactionStatus::Pending, // Will be updated by execution
                    cross_shard: tx.is_cross_shard(num_shards),
                    submitted_locally: false, // Fetched for block processing
                    // Block-committed entries skip the dwell path entirely
                    // (next loop transitions them straight to Committed +
                    // takes locks), so the anchor is never read.
                    admitted_at: LocalTimestamp::ZERO,
                }
            });
        }

        // Update transaction status to Committed and add locks.
        // This must happen synchronously to prevent the same transactions from being
        // re-proposed before the status update is processed.
        for tx in block.transactions() {
            let hash = tx.hash();
            if let Some(entry) = self.pool.get_mut(&hash) {
                // Only update if still Pending (avoid overwriting later states during sync)
                if matches!(entry.status, TransactionStatus::Pending) {
                    let cross_shard = entry.cross_shard;
                    let submitted_locally = entry.submitted_locally;
                    entry.status = TransactionStatus::Committed(height);
                    // Remove from ready tracking (no longer Pending)
                    self.remove_from_ready_tracking(&hash);
                    // Add locks for committed transactions and update counter
                    self.add_locked_nodes(topology, tx);
                    self.locks.inc_committed();
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: hash,
                        status: TransactionStatus::Committed(height),
                        cross_shard,
                        submitted_locally,
                    });
                }
            }
        }

        // Per-tx terminal state from committed wave certificates. Decisions are
        // derived from each FinalizedWave directly, so this works identically
        // for consensus and sync commit paths.
        for fw in block.certificates() {
            for (tx_hash, decision) in fw.tx_decisions() {
                if matches!(decision, TransactionDecision::Aborted) {
                    hyperscale_metrics::record_transaction_aborted();
                }
                actions.extend(self.process_certificate_committed(topology, tx_hash, decision));
            }
        }

        actions
    }

    /// Mark a transaction as terminal in response to a committed wave certificate.
    ///
    /// Called from `on_block_committed` once per tx in `block.certificates`.
    /// Emits the terminal status update and evicts/tombstones the entry.
    fn process_certificate_committed(
        &mut self,
        topology: &TopologySnapshot,
        tx_hash: TxHash,
        decision: TransactionDecision,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get(&tx_hash) {
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;

            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Completed(decision),
                cross_shard,
                submitted_locally,
            });

            // Release locks and evict — same for all terminal states
            self.evict_terminal(topology, tx_hash);
        }

        actions
    }

    /// Record that local ECs were just formed for these transactions.
    /// Pure telemetry — emits a `RecordTxEcCreated` action that the `io_loop`
    /// stamps into its phase-time side cache for the slow-tx finalization
    /// log. State-machine state isn't touched.
    #[must_use]
    pub fn on_ec_created(&self, tx_hashes: &[TxHash]) -> Vec<Action> {
        if tx_hashes.is_empty() {
            return vec![];
        }
        vec![Action::RecordTxEcCreated {
            tx_hashes: tx_hashes.to_vec(),
        }]
    }

    /// Mark a transaction as executed (execution complete, certificate created).
    ///
    /// Called when `ExecutionCoordinator` finalizes a wave certificate.
    #[instrument(skip(self, _topology), fields(tx_hash = ?tx_hash, accepted = accepted))]
    pub fn on_transaction_executed(
        &mut self,
        _topology: &TopologySnapshot,
        tx_hash: TxHash,
        accepted: bool,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get_mut(&tx_hash) {
            let decision = if accepted {
                TransactionDecision::Accept
            } else {
                TransactionDecision::Reject
            };
            let cross_shard = entry.cross_shard;
            let submitted_locally = entry.submitted_locally;

            // Extract committed_at height before transitioning to Executed.
            // This is needed for timeout tracking - cross-shard transactions can get
            // stuck in Executed state if certificate inclusion fails on another shard.
            let committed_at = match entry.status {
                TransactionStatus::Committed(height) => {
                    self.locks.dec_committed();
                    self.locks.inc_executed();
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
                cross_shard,
                submitted_locally,
            });
        }

        actions
    }

    /// Add a transaction's nodes to the locked set.
    /// Called when a transaction transitions TO a lock-holding state (Committed/Executed).
    ///
    /// Also blocks any ready transactions that conflict with the newly locked nodes.
    ///
    /// Scoped to local-shard nodes. A cross-shard tx's remote nodes are not
    /// owned by this shard's state machine; their lifetime is gated by the
    /// peer shard's wave finalization, which can stall independently. Locking
    /// them here would permanently defer future local cross-shard txs that
    /// share those remote nodes, cascading the stall.
    fn add_locked_nodes(&mut self, topology: &TopologySnapshot, tx: &RoutableTransaction) {
        let local_shard = topology.local_shard();
        let newly_locked = self.locks.lock_nodes(
            tx.all_declared_nodes()
                .filter(|node| topology.shard_for_node_id(node) == local_shard)
                .copied(),
        );
        for node in newly_locked {
            self.ready.block_node(node);
        }
    }

    /// Remove a transaction's nodes from the locked set.
    /// Called when a transaction transitions FROM a lock-holding state (evicted).
    ///
    /// Also promotes any blocked transactions that were waiting on these nodes.
    /// Scoped to local-shard nodes; mirrors [`Self::add_locked_nodes`].
    fn remove_locked_nodes(&mut self, topology: &TopologySnapshot, tx: &RoutableTransaction) {
        let local_shard = topology.local_shard();
        let newly_unlocked = self.locks.unlock_nodes(
            tx.all_declared_nodes()
                .filter(|node| topology.shard_for_node_id(node) == local_shard)
                .copied(),
        );
        for node in newly_unlocked {
            self.promote_transactions_for_node(node);
        }
    }

    /// Add a transaction to ready tracking when it becomes Pending. The
    /// store decides whether it lands in the ready or deferred set based on
    /// currently-locked and already-claimed nodes.
    fn add_to_ready_tracking(
        &mut self,
        hash: TxHash,
        tx: &Arc<RoutableTransaction>,
        added_at: LocalTimestamp,
    ) {
        self.ready.add(hash, Arc::clone(tx), added_at, &self.locks);
    }

    /// Remove a transaction from ready tracking. If the tx was in the ready
    /// set, cascade-promote any deferred tx whose only blocker was the
    /// ready-set claim.
    fn remove_from_ready_tracking(&mut self, hash: &TxHash) {
        let freed_nodes = self.ready.remove(hash);
        for node in freed_nodes {
            self.promote_transactions_for_node(node);
        }
    }

    /// Remove `node` from the blocker set of every deferred tx, re-adding
    /// any tx whose last blocker was this node back through the store so it
    /// gets re-checked against remaining locks and ready-set claims.
    fn promote_transactions_for_node(&mut self, node: NodeId) {
        let mut promotable = self.ready.promotable_for_node(node);
        promotable.sort();
        let mut to_readd: Vec<(TxHash, Arc<RoutableTransaction>, LocalTimestamp)> = Vec::new();
        for tx_hash in promotable {
            if let Some(entry) = self.pool.get(&tx_hash)
                && entry.status == TransactionStatus::Pending
            {
                to_readd.push((tx_hash, Arc::clone(&entry.tx), entry.admitted_at));
            }
        }
        for (hash, tx, added_at) in to_readd {
            self.ready.add(hash, tx, added_at, &self.locks);
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
    /// The effective in-flight is: `current + pending_txs - pending_certs`
    ///
    /// # Performance
    ///
    /// This method is `O(min(ready_set_size, max_count))` instead of `O(pool_size)` because
    /// it reads from a pre-computed ready set that is maintained incrementally.
    #[must_use]
    pub fn ready_transactions(
        &self,
        max_count: usize,
        pending_commit_tx_count: usize,
        pending_commit_cert_count: usize,
        now: LocalTimestamp,
    ) -> Vec<Arc<RoutableTransaction>> {
        // Certificates reduce in-flight (transactions complete), txs increase it
        let effective_in_flight = self
            .in_flight()
            .saturating_add(pending_commit_tx_count)
            .saturating_sub(pending_commit_cert_count);
        let at_limit = effective_in_flight >= self.config.max_in_flight;

        if at_limit {
            return Vec::new();
        }

        // Cap max_count to stay within limit
        let room = self
            .config
            .max_in_flight
            .saturating_sub(effective_in_flight);
        let max_count = max_count.min(room);

        self.ready
            .iter_ready(self.config.min_dwell_time, now)
            .take(max_count)
            .collect()
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
    /// All stats are `O(1)` via cached counters and ready sets.
    #[must_use]
    pub fn lock_contention_stats(&self) -> LockContentionStats {
        let locked_nodes = self.locks.locked_nodes_count() as u64;

        // Pending counts are O(1) from ready set
        let ready_count = self.ready.ready_count();
        let deferred_count = self.ready.deferred_count();
        let pending_deferred = deferred_count as u64;
        let pending_count = (ready_count + deferred_count) as u64;

        LockContentionStats {
            locked_nodes,
            pending_count,
            pending_deferred,
            committed_count: self.locks.committed_count() as u64,
            executed_count: self.locks.executed_count() as u64,
        }
    }

    /// Count transactions currently holding state locks (in-flight).
    ///
    /// This counts all transactions in Committed or Executed status,
    /// which are actively holding state locks and consuming execution/crypto resources.
    ///
    /// Used for backpressure to control overall system load.
    ///
    /// This is `O(1)` as it returns a cached count maintained incrementally
    /// when transaction status changes or transactions are evicted.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.locks.in_flight()
    }

    /// Check if we're at the in-flight limit.
    ///
    /// At this limit, no new transactions are proposed.
    #[must_use]
    pub fn at_in_flight_limit(&self) -> bool {
        self.in_flight() >= self.config.max_in_flight
    }

    /// Check whether accepting a block would unacceptably increase in-flight load.
    ///
    /// Returns `true` if the block should be rejected. Blocks that reduce or
    /// maintain the current in-flight count are always accepted, even when over
    /// the limit — this prevents deadlock when certificate-heavy blocks would
    /// relieve backpressure.
    #[must_use]
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
    /// Every `Pending` pool entry lives in exactly one of the ready or
    /// deferred sets, so the sum of those counts is equivalent and `O(1)`.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.ready.ready_count() + self.ready.deferred_count()
    }

    /// Check if we're at the pending transaction limit for RPC backpressure.
    ///
    /// When at this limit, new RPC transaction submissions are rejected to
    /// prevent unbounded mempool growth when arrival rate exceeds processing.
    #[must_use]
    pub fn at_pending_limit(&self) -> bool {
        self.pending_count() >= self.config.max_pending
    }

    /// Get the mempool configuration.
    #[must_use]
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Check if we have a transaction.
    #[must_use]
    pub fn has_transaction(&self, hash: &TxHash) -> bool {
        self.pool.contains_key(hash)
    }

    /// Get a transaction Arc by hash.
    ///
    /// Checks the active pool first, then the evicted-body cache, so peer
    /// fetch requests for transactions that have already reached a terminal
    /// state can still be served.
    #[must_use]
    pub fn get_transaction(&self, hash: &TxHash) -> Option<Arc<RoutableTransaction>> {
        if let Some(entry) = self.pool.get(hash) {
            return Some(Arc::clone(&entry.tx));
        }
        self.tombstones.get_evicted(hash)
    }

    /// Get transaction status.
    #[must_use]
    pub fn status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.pool.get(hash).map(|e| e.status.clone())
    }

    /// Build a bloom filter over every transaction hash we can resolve
    /// locally — both live pool entries and recently-evicted bodies. A sync
    /// requester attaches this to `GetBlockRequest` so the responder can
    /// elide transaction bodies already known to the requester.
    ///
    /// Returns `None` when the combined set is too large to size a filter
    /// within the configured [`MAX_BITS`](hyperscale_types::MAX_BITS) cap;
    /// callers treat this as "send no inventory, accept the full response."
    #[must_use]
    pub fn tx_bloom_snapshot(&self) -> Option<BloomFilter<TxHash>> {
        let n = self.pool.len() + self.tombstones.len_evicted();
        let mut bf = BloomFilter::with_capacity(n, DEFAULT_FPR)?;
        for hash in self.pool.keys() {
            bf.insert(hash);
        }
        for hash in self.tombstones.recently_evicted_hashes() {
            bf.insert(hash);
        }
        Some(bf)
    }

    /// Get mempool memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> MempoolMemoryStats {
        MempoolMemoryStats {
            pool: self.pool.len(),
            ready: self.ready.ready_count(),
            tombstones: self.tombstones.len_tombstones(),
            recently_evicted: self.tombstones.len_evicted(),
            locked_nodes: self.locks.locked_nodes_count(),
            deferred_by_nodes: self.ready.deferred_count(),
            txs_deferred_by_node: self.ready.txs_deferred_by_node_len(),
            ready_txs_by_node: self.ready.ready_txs_by_node_len(),
        }
    }

    /// Get the number of transactions in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Check if the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Get all incomplete transactions (not yet finalized or completed).
    ///
    /// Returns tuples of (hash, status, transaction Arc) for analysis.
    #[must_use]
    pub fn incomplete_transactions(
        &self,
    ) -> Vec<(TxHash, TransactionStatus, Arc<RoutableTransaction>)> {
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

    /// Drop tombstones whose `end_timestamp_exclusive <= current_ts`.
    ///
    /// Past `end_timestamp_exclusive`, the validator-side validity check
    /// rejects any re-submission of the tx, so the tombstone is no longer
    /// load-bearing for correctness — it becomes a pure perf optimisation.
    /// Anchored on `current_ts` (updated in `on_block_committed`).
    ///
    /// Returns the number of tombstones dropped.
    pub fn cleanup_expired_tombstones(&mut self) -> usize {
        self.tombstones.prune_tombstones(self.current_ts)
    }

    /// Drop `Pending` pool entries whose `end_timestamp_exclusive <= current_ts`.
    ///
    /// Pending txs hold no state locks (locks are taken on `Committed` /
    /// `Executed`), so removal is safe without going through the
    /// terminal-eviction path. Re-submission past expiry is rejected at
    /// admission, so no tombstone is needed either.
    ///
    /// The proposer-side filter already skips expired txs at selection
    /// time; this sweep is what keeps the pool from accumulating dead
    /// pending entries when expiry outpaces selection (e.g. a transient
    /// stall in cross-shard EC delivery delays inclusion past the window).
    ///
    /// Returns the number of pending entries dropped.
    pub fn cleanup_expired_pending(&mut self) -> usize {
        let now = self.current_ts;
        let expired: Vec<TxHash> = self
            .pool
            .iter()
            .filter(|(_, entry)| matches!(entry.status, TransactionStatus::Pending))
            .filter(|(_, entry)| entry.tx.validity_range.end_timestamp_exclusive <= now)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.pool.remove(hash);
            self.remove_from_ready_tracking(hash);
        }
        expired.len()
    }

    /// Get the number of tombstones currently tracked.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len_tombstones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_test_helpers::{TestCommittee, make_finalized_wave};
    use hyperscale_types::{
        FinalizedWave, ShardGroupId, ValidatorId, test_utils::test_transaction,
    };

    fn make_test_topology() -> TopologySnapshot {
        TestCommittee::new(4, 42).topology_snapshot(0, 1)
    }

    /// Nominal block spacing used by tests to synthesize `weighted_timestamp_ms`
    /// from block heights. Ratios against retention constants preserve the
    /// "block count" intuition when reading test scenarios.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    /// Assemble a certified single-tx block carrying one finalized-wave
    /// decision, with its QC timestamp stamped from the block height.
    fn certified_commit_block(
        height: BlockHeight,
        tx: RoutableTransaction,
        fw: FinalizedWave,
    ) -> CertifiedBlock {
        let block = hyperscale_test_helpers::make_live_block(
            ShardGroupId(0),
            height,
            1_234_567_890,
            ValidatorId(0),
            vec![Arc::new(tx)],
            vec![Arc::new(fw)],
        );
        hyperscale_test_helpers::certify(block, height.0 * TEST_BLOCK_INTERVAL_MS)
    }

    #[test]
    fn test_abort_updates_status() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();

        // Submit a TX, then commit a block whose FinalizedWave aborts it.
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);

        let certified = certified_commit_block(
            BlockHeight(1),
            tx,
            make_finalized_wave(BlockHeight(1), tx_hash, TransactionDecision::Aborted),
        );
        let actions = mempool.on_block_committed(&topology, &certified);

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
    // Bloom-inventory snapshot
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn tx_bloom_snapshot_covers_pool_and_recently_evicted() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();

        // A submitted-but-not-yet-committed tx lands in pool.
        let tx_live = test_transaction(1);
        let tx_live_hash = tx_live.hash();
        mempool.on_submit_transaction(&topology, Arc::new(tx_live.clone()), LocalTimestamp::ZERO);

        // A second tx commits and gets evicted to recently_evicted.
        let tx_done = test_transaction(2);
        let tx_done_hash = tx_done.hash();
        mempool.on_submit_transaction(&topology, Arc::new(tx_done.clone()), LocalTimestamp::ZERO);
        let certified = certified_commit_block(
            BlockHeight(1),
            tx_done.clone(),
            make_finalized_wave(BlockHeight(1), tx_done_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology, &certified);

        let bf = mempool.tx_bloom_snapshot().expect("sizing ok");
        assert!(bf.contains(&tx_live_hash));
        assert!(bf.contains(&tx_done_hash));

        let absent = test_transaction(3).hash();
        assert!(!bf.contains(&absent));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Tombstone Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tombstoned_transaction_rejected_on_gossip() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction (commit + Accept wave cert in one block).
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);
        let certified = certified_commit_block(
            BlockHeight(1),
            tx.clone(),
            make_finalized_wave(BlockHeight(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology, &certified);

        // Verify it's tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(
            &topology,
            Arc::new(tx.clone()),
            false,
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_submit() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction (commit + Accept wave cert in one block).
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);
        let certified = certified_commit_block(
            BlockHeight(1),
            tx.clone(),
            make_finalized_wave(BlockHeight(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology, &certified);

        // Try to re-submit - should be rejected (no status emitted)
        let actions =
            mempool.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a mempool config with a low in-flight limit for testing.
    fn make_mempool_config_with_limit(limit: usize) -> MempoolConfig {
        MempoolConfig {
            max_in_flight: limit,
            max_pending: DEFAULT_MAX_PENDING,
            min_dwell_time: Duration::ZERO,
        }
    }

    /// Put a mempool at the backpressure limit by submitting `max_in_flight`
    /// transactions and committing a block that contains them all — which
    /// transitions every tx to `Committed` so they hold state locks.
    fn put_mempool_at_limit(mempool: &mut MempoolCoordinator, topology: &TopologySnapshot) {
        let limit = mempool.config.max_in_flight;
        let txs: Vec<Arc<RoutableTransaction>> = (0..limit)
            .map(|i| Arc::new(test_transaction(100 + u8::try_from(i).unwrap_or(u8::MAX))))
            .collect();
        for tx in &txs {
            mempool.on_submit_transaction(topology, Arc::clone(tx), LocalTimestamp::ZERO);
        }
        let block = hyperscale_test_helpers::make_live_block(
            ShardGroupId(0),
            BlockHeight(1),
            1_234_567_890,
            ValidatorId(0),
            txs,
            vec![],
        );
        mempool.on_block_committed(
            topology,
            &hyperscale_test_helpers::certify(block, TEST_BLOCK_INTERVAL_MS),
        );

        assert!(
            mempool.at_in_flight_limit(),
            "Mempool should be at in-flight limit after adding {limit} committed TXs",
        );
    }

    /// Create a topology with 2 shards for cross-shard testing
    fn make_cross_shard_topology() -> TopologySnapshot {
        TestCommittee::new(8, 42).topology_snapshot(0, 2)
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
            assert!(
                node2_seed != seed,
                "Could not find nodes in different shards"
            );
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
        let mut mempool = MempoolCoordinator::with_config(config);
        let topology = make_cross_shard_topology();

        // Add a single-shard transaction
        let single_shard_tx = test_transaction(1);
        mempool.on_submit_transaction(
            &topology,
            Arc::new(single_shard_tx.clone()),
            LocalTimestamp::ZERO,
        );

        // Add a cross-shard transaction
        let cross_shard_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(
            &topology,
            Arc::new(cross_shard_tx.clone()),
            LocalTimestamp::ZERO,
        );

        // Below limit: all TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::ZERO);
        assert_eq!(ready.len(), 2, "All TXs should be allowed below limit");
    }

    #[test]
    fn test_backpressure_rejects_all_at_limit() {
        let config = make_mempool_config_with_limit(2);
        let mut mempool = MempoolCoordinator::with_config(config);
        let topology = make_cross_shard_topology();

        // Put mempool at the in-flight limit
        put_mempool_at_limit(&mut mempool, &topology);
        assert!(mempool.at_in_flight_limit());

        // Add a transaction
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx.clone()), LocalTimestamp::ZERO);

        // At limit: no TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::ZERO);
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
        let mut mempool = MempoolCoordinator::with_config(config);

        // Mempool is not at limit (nothing committed)
        assert!(!mempool.at_in_flight_limit());

        // Add a single-shard transaction
        let single_tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(single_tx.clone()), LocalTimestamp::ZERO);

        // Add a cross-shard transaction
        let cross_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(&topology, Arc::new(cross_tx.clone()), LocalTimestamp::ZERO);

        // Not at limit: all TXs should be allowed
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::ZERO);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_in_flight_counts_all_txns() {
        let topology = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new();

        assert_eq!(mempool.in_flight(), 0);

        let single_tx = test_transaction(200);
        let single_hash = single_tx.hash();
        let cross_tx = test_cross_shard_transaction(1);
        let cross_hash = cross_tx.hash();
        mempool.on_submit_transaction(&topology, Arc::new(single_tx.clone()), LocalTimestamp::ZERO);
        mempool.on_submit_transaction(&topology, Arc::new(cross_tx.clone()), LocalTimestamp::ZERO);
        assert_eq!(mempool.in_flight(), 0, "Pending TXs do not count");

        // Block 1 commits both txs — both transition Pending → Committed.
        let block1 = hyperscale_test_helpers::make_live_block(
            ShardGroupId(0),
            BlockHeight(1),
            1_000,
            ValidatorId(0),
            vec![Arc::new(single_tx), Arc::new(cross_tx)],
            vec![],
        );
        mempool.on_block_committed(&topology, &hyperscale_test_helpers::certify(block1, 1_000));
        assert_eq!(mempool.in_flight(), 2, "Committed TXs hold state locks");

        // Execution completes for the cross-shard tx — Executed still holds locks.
        mempool.on_transaction_executed(&topology, cross_hash, true);
        assert_eq!(mempool.in_flight(), 2, "Executed TX still holds locks");

        // Block 2 carries the wave cert for the cross-shard tx — completes it.
        let block2 = hyperscale_test_helpers::make_live_block(
            ShardGroupId(0),
            BlockHeight(2),
            2_000,
            ValidatorId(0),
            vec![],
            vec![Arc::new(make_finalized_wave(
                BlockHeight(2),
                cross_hash,
                TransactionDecision::Accept,
            ))],
        );
        mempool.on_block_committed(&topology, &hyperscale_test_helpers::certify(block2, 2_000));
        assert_eq!(mempool.in_flight(), 1, "Completed TX releases its lock");

        // Execute then finalize the single-shard tx.
        mempool.on_transaction_executed(&topology, single_hash, true);
        assert_eq!(mempool.in_flight(), 1);

        let block3 = hyperscale_test_helpers::make_live_block(
            ShardGroupId(0),
            BlockHeight(3),
            3_000,
            ValidatorId(0),
            vec![],
            vec![Arc::new(make_finalized_wave(
                BlockHeight(3),
                single_hash,
                TransactionDecision::Accept,
            ))],
        );
        mempool.on_block_committed(&topology, &hyperscale_test_helpers::certify(block3, 3_000));
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
        let mut mempool = MempoolCoordinator::with_config(config);
        let topology = make_test_topology();

        let now = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx), now);

        let ready = mempool.ready_transactions(10, 0, 0, now);
        assert_eq!(ready.len(), 1, "Zero dwell time should select immediately");
    }

    #[test]
    fn test_dwell_time_default_150ms() {
        // Default config has 150ms dwell time
        let mut mempool = MempoolCoordinator::new();
        let topology = make_test_topology();

        let submitted_at = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx), submitted_at);

        // At t=10.1s — not yet eligible (100ms < 150ms)
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_100));
        assert_eq!(
            ready.len(),
            0,
            "Should not select before 150ms default dwell"
        );

        // At t=10.15s — eligible (150ms >= 150ms)
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_150));
        assert_eq!(ready.len(), 1, "Should select after 150ms default dwell");
    }

    #[test]
    fn test_dwell_time_filters_recent_transactions() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(500),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(config);
        let topology = make_test_topology();

        // Submit at t=10s
        let submitted_at = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx), submitted_at);

        // Still at t=10s — dwell time not met
        let ready = mempool.ready_transactions(10, 0, 0, submitted_at);
        assert_eq!(ready.len(), 0, "Should not select before dwell time");

        // Advance to t=10.3s — still not enough
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_300));
        assert_eq!(
            ready.len(),
            0,
            "Should not select before dwell time elapses"
        );

        // Advance to t=10.5s — exactly at dwell time
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_500));
        assert_eq!(ready.len(), 1, "Should select after dwell time elapses");
    }

    #[test]
    fn test_dwell_time_mixed_eligibility() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(200),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(config);
        let topology = make_test_topology();

        // Submit tx1 at t=1s
        let tx1 = test_transaction(1);
        mempool.on_submit_transaction(&topology, Arc::new(tx1), LocalTimestamp::from_millis(1_000));

        // Submit tx2 at t=1.3s
        let tx2 = test_transaction(2);
        mempool.on_submit_transaction(&topology, Arc::new(tx2), LocalTimestamp::from_millis(1_300));

        // At t=1.4s — tx1 has 400ms dwell (eligible), tx2 has 100ms (not eligible).
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(1_400));
        assert_eq!(ready.len(), 1, "Only tx1 should be eligible");

        // At t=1.5s — both eligible
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(1_500));
        assert_eq!(ready.len(), 2, "Both should be eligible");
    }

    // ─── validity-window admission + pending sweep ──────────────────────

    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<RoutableTransaction> {
        use hyperscale_types::test_utils::test_notarized_transaction_v1;
        use hyperscale_types::{TimestampRange, routable_from_notarized_v1};
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(WeightedTimestamp::ZERO, WeightedTimestamp(end_ms));
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"))
    }

    /// Force-set `current_ts` for tests that need to control the admission /
    /// sweep clock without going through a full block commit.
    fn set_current_ts(mempool: &mut MempoolCoordinator, ts: WeightedTimestamp) {
        mempool.current_ts = ts;
    }

    #[test]
    fn rpc_submit_rejects_expired_transaction() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();
        set_current_ts(&mut mempool, WeightedTimestamp(2_000));

        let tx = tx_with_end(1, 1_000); // expired well before now
        let actions =
            mempool.on_submit_transaction(&topology, Arc::clone(&tx), LocalTimestamp::ZERO);
        assert!(actions.is_empty(), "expired tx should be silently rejected");
        assert!(
            mempool.status(&tx.hash()).is_none(),
            "expired tx must not enter the pool"
        );
    }

    #[test]
    fn gossip_drops_expired_transaction() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();
        set_current_ts(&mut mempool, WeightedTimestamp(2_000));

        let tx = tx_with_end(1, 1_000);
        let actions =
            mempool.on_transaction_gossip(&topology, Arc::clone(&tx), false, LocalTimestamp::ZERO);
        assert!(actions.is_empty());
        assert!(mempool.status(&tx.hash()).is_none());
    }

    #[test]
    fn rpc_submit_admits_in_window_transaction() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();
        set_current_ts(&mut mempool, WeightedTimestamp(500));

        let tx = tx_with_end(1, 1_000); // end_exclusive > now
        mempool.on_submit_transaction(&topology, Arc::clone(&tx), LocalTimestamp::ZERO);
        assert!(matches!(
            mempool.status(&tx.hash()),
            Some(TransactionStatus::Pending)
        ));
    }

    #[test]
    fn cleanup_expired_pending_drops_only_past_expiry_entries() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();
        set_current_ts(&mut mempool, WeightedTimestamp(500));

        let early = tx_with_end(1, 1_000); // alive
        let later = tx_with_end(2, 60_000); // alive
        mempool.on_submit_transaction(&topology, Arc::clone(&early), LocalTimestamp::ZERO);
        mempool.on_submit_transaction(&topology, Arc::clone(&later), LocalTimestamp::ZERO);
        assert_eq!(mempool.len(), 2);

        // Advance past `early`'s end_exclusive but not `later`'s.
        set_current_ts(&mut mempool, WeightedTimestamp(1_500));
        let dropped = mempool.cleanup_expired_pending();
        assert_eq!(dropped, 1);
        assert!(mempool.status(&early.hash()).is_none());
        assert!(matches!(
            mempool.status(&later.hash()),
            Some(TransactionStatus::Pending)
        ));
    }

    #[test]
    fn cleanup_expired_pending_does_not_tombstone_dropped_entries() {
        let topology = make_test_topology();
        let mut mempool = MempoolCoordinator::new();
        set_current_ts(&mut mempool, WeightedTimestamp(500));

        let tx = tx_with_end(1, 1_000);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(&topology, Arc::clone(&tx), LocalTimestamp::ZERO);

        set_current_ts(&mut mempool, WeightedTimestamp(1_500));
        let dropped = mempool.cleanup_expired_pending();
        assert_eq!(dropped, 1);

        // Pending sweep does not tombstone — re-submission is rejected by
        // the admission check, not by the tombstone set. Confirm both: the
        // tombstone set stays empty, AND a fresh submission past expiry is
        // rejected via the admission path.
        assert!(!mempool.is_tombstoned(&tx_hash));
        let actions =
            mempool.on_submit_transaction(&topology, Arc::clone(&tx), LocalTimestamp::ZERO);
        assert!(actions.is_empty(), "re-submission past expiry rejected");
        assert!(mempool.status(&tx_hash).is_none());
    }
}
