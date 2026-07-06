//! Mempool coordinator: admission, eligibility, and lifecycle of pending
//! transactions.
//!
//! Owns the per-validator transaction pool and the bookkeeping that surrounds
//! it: a [`TxStore`] of pending transactions, a [`ReadySet`] of admission-
//! eligible candidates, a [`LockTracker`] that tracks transactions holding
//! state locks (the in-flight set), a [`TombstoneStore`] for recently
//! decided hashes, and an [`ExpectedTxs`] sub-machine that backfills
//! cross-shard transactions referenced by remote provisions before their
//! source-shard gossip arrives.
//!
//! # Backpressure
//!
//! Two limits gate proposal and ingress:
//! - [`MAX_TX_IN_FLIGHT`] (a protocol constant in `hyperscale-types`) caps
//!   simultaneous lock-holding transactions, preventing the execution
//!   pipeline from being overrun. Not operator-tunable: the right value
//!   is fully determined by block size × pipeline depth.
//! - [`MempoolConfig::max_pending`] caps RPC-submitted pending transactions
//!   so that arrival rate exceeding processing capacity translates to
//!   rejected submissions rather than unbounded memory growth. Operator-
//!   tunable: deployments with different RAM budgets pick different values.
//!
//! # Cross-shard DA
//!
//! Cross-shard transactions referenced by remote provisions must be locally
//! retrievable to participate in execution. `ExpectedTxs` waits an
//! [`EXPECTED_TX_GRACE`] window for source-shard gossip; past the grace
//! period it falls back to a BFT-weighted fetch from the source committee,
//! and drops entries past `RETENTION_HORIZON`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchAbandon, FetchRequest, ProtocolEvent};
use hyperscale_metrics::{record_expected_tx_dropped, record_transaction_aborted};
use hyperscale_types::{
    BlockHeight, CertifiedBlock, LocalTimestamp, MAX_TX_IN_FLIGHT, MessageClass, NodeId,
    QuiesceCut, RETENTION_HORIZON, RoutableTransaction, ShardId, TopologySnapshot,
    TransactionDecision, TransactionStatus, TxHash, Verified, WAVE_TIMEOUT, WeightedTimestamp,
};
use serde::Deserialize;
use tracing::instrument;

use crate::expected_txs::{EXPECTED_TX_GRACE, ExpectedTxs};
use crate::lock_tracker::LockTracker;
use crate::ready_set::ReadySet;
use crate::tombstones::TombstoneStore;
use crate::tx_store::TxStore;

/// Default minimum dwell time for transactions before they become eligible for block inclusion.
///
/// Allows time for transaction gossip to propagate across validators before proposal,
/// improving batching and fairness.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(150);

/// Default RPC-pending backpressure limit (≈ 2× block size).
pub const DEFAULT_MAX_PENDING: usize = 8192;

/// Operator-recommended quiesce margin for cross-shard transactions.
///
/// A full cross-shard 2PC round ([`WAVE_TIMEOUT`]) plus headroom, so a
/// cross-shard transaction selected before a split's cut settles on every
/// shard by the terminal block. Shipped disabled (zero) in
/// [`MempoolConfig::default`] so the whole reshape feature is dormant
/// until configured (matching `ReshapeThresholds::DISABLED`) and
/// simulations keep producing boundary straddlers for the counterpart
/// abort backstop to sweep.
pub const DEFAULT_QUIESCE_CROSS_SHARD_MARGIN: Duration =
    Duration::from_secs(WAVE_TIMEOUT.as_secs() + 6);

/// Operator-recommended quiesce margin for single-shard transactions.
///
/// A few block intervals, enough for a single-shard transaction selected
/// before a split's cut to finalize by the terminal block. Disabled
/// (zero) in [`MempoolConfig::default`].
pub const DEFAULT_QUIESCE_SINGLE_SHARD_MARGIN: Duration = Duration::from_secs(2);

/// Mempool configuration. Operator-tunable knobs only.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolConfig {
    /// Maximum pending transactions before RPC backpressure kicks in.
    ///
    /// When the number of Pending transactions exceeds this limit, new RPC submissions
    /// are rejected. This prevents unbounded mempool growth when arrival rate exceeds
    /// processing capacity. Gossip-arrived transactions are not gated by this — only
    /// the public RPC entry point is.
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,

    /// Minimum time a transaction must spend in the mempool before it can be selected
    /// for block inclusion. Transactions that have not yet met this dwell time are
    /// skipped during proposal selection but remain in the ready set.
    ///
    /// Set to zero to disable (default).
    #[serde(default = "default_min_dwell_time")]
    pub min_dwell_time: Duration,

    /// Split-boundary quiesce margin for cross-shard transactions. In a
    /// shard's final epoch before a split, the proposer stops selecting a
    /// cross-shard transaction once the chain anchor plus this margin
    /// reaches the cut, so it can't be selected too late to settle on
    /// every shard before the terminal block. Zero disables quiesce (the
    /// default — straddlers then fall to the counterpart abort backstop);
    /// [`DEFAULT_QUIESCE_CROSS_SHARD_MARGIN`] is the operator recommendation.
    #[serde(default = "default_quiesce_cross_shard_margin")]
    pub quiesce_cross_shard_margin: Duration,

    /// Split-boundary quiesce margin for single-shard transactions. Sized
    /// to a few block intervals (single-shard work finalizes far faster
    /// than a 2PC round). Zero disables quiesce (the default);
    /// [`DEFAULT_QUIESCE_SINGLE_SHARD_MARGIN`] is the operator recommendation.
    #[serde(default = "default_quiesce_single_shard_margin")]
    pub quiesce_single_shard_margin: Duration,
}

const fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

const fn default_min_dwell_time() -> Duration {
    DEFAULT_MIN_DWELL_TIME
}

const fn default_quiesce_cross_shard_margin() -> Duration {
    Duration::ZERO
}

const fn default_quiesce_single_shard_margin() -> Duration {
    Duration::ZERO
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            min_dwell_time: DEFAULT_MIN_DWELL_TIME,
            quiesce_cross_shard_margin: Duration::ZERO,
            quiesce_single_shard_margin: Duration::ZERO,
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
    /// Number of transactions in Committed status (holding state locks).
    pub in_flight_count: u64,
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
    /// Nodes currently locked by in-flight transactions.
    pub locked_nodes: usize,
    /// Distinct nodes with at least one deferred transaction.
    pub deferred_by_nodes: usize,
    /// Total transaction-node entries in the deferred index.
    pub txs_deferred_by_node: usize,
    /// Total transaction-node entries in the ready index.
    pub ready_txs_by_node: usize,
}

/// Entry in the transaction pool. Carries the body alongside admission
/// metadata. The same `Arc` is also held by the shared [`TxStore`] so
/// the network worker can serve fetches without touching the mempool;
/// in-mempool reads go through this field directly.
#[derive(Debug)]
struct PoolEntry {
    tx: Arc<Verified<RoutableTransaction>>,
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

    /// Shared content-addressed body store mirroring the bodies held by
    /// live pool entries plus those still inside the tombstone retention
    /// window. The mempool itself reads bodies via [`PoolEntry::tx`]; the
    /// store exists so the network worker thread (serving inbound
    /// `transaction.request`s) can read bodies concurrently without
    /// touching the state machine.
    tx_store: Arc<TxStore>,

    /// Terminal-state dedup. Tombstones stop gossip from re-adding
    /// completed/aborted transactions; their lifetime gates body retention
    /// in [`Self::tx_store`].
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

    /// Cross-shard txs the mempool has been told to expect via verified
    /// provisions bundles, but has not yet seen on the wire (gossip / submit
    /// / block inclusion). Cleared on admission, on block-include race, or
    /// on retention-horizon orphan sweep — the latter two emit
    /// `Action::AbandonFetch` so any in-flight fetch is cancelled. Also
    /// consulted to drive grace-window fetch fallback.
    expected_txs: ExpectedTxs,

    /// Configuration for mempool behavior.
    config: MempoolConfig,

    /// This validator's home shard. Filters declared-node iterators to
    /// local nodes only at lock-tracking time.
    local_shard: ShardId,
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

impl MempoolCoordinator {
    /// Create a new mempool state machine with default config and a fresh
    /// (private) [`TxStore`]. Most production callers want
    /// [`Self::with_tx_store`] so the body store can be shared with the
    /// network worker thread.
    #[must_use]
    pub fn new(local_shard: ShardId) -> Self {
        Self::with_config(local_shard, MempoolConfig::default())
    }

    /// Create a new mempool state machine with custom config and a fresh
    /// (private) [`TxStore`]. See [`Self::with_tx_store`] for the shared
    /// variant.
    #[must_use]
    pub fn with_config(local_shard: ShardId, config: MempoolConfig) -> Self {
        Self::with_tx_store(local_shard, config, Arc::new(TxStore::new()))
    }

    /// Create a new mempool state machine that shares its body store with
    /// the rest of the I/O loop. The same `Arc<TxStore>` should be held in
    /// the I/O loop's `caches` so inbound transaction-fetch handlers can
    /// serve bodies without acquiring a mempool lock.
    #[must_use]
    pub fn with_tx_store(
        local_shard: ShardId,
        config: MempoolConfig,
        tx_store: Arc<TxStore>,
    ) -> Self {
        Self {
            pool: BTreeMap::new(),
            tx_store,
            tombstones: TombstoneStore::new(),
            locks: LockTracker::new(),
            ready: ReadySet::new(),
            current_height: BlockHeight::new(0),
            current_ts: WeightedTimestamp::ZERO,
            expected_txs: ExpectedTxs::new(),
            config,
            local_shard,
        }
    }

    /// Reference to the shared body store. Callers that need to read
    /// bodies (e.g. the network worker thread) clone the Arc out and use
    /// it directly to avoid taking a mempool lock.
    #[must_use]
    pub const fn tx_store(&self) -> &Arc<TxStore> {
        &self.tx_store
    }

    /// Try to admit a single transaction. Returns `(was_newly_admitted,
    /// cross_shard)`. Source-agnostic: callers append the appropriate
    /// `Continuation(TransactionsAdmitted)` and any source-specific actions.
    fn admit_internal(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: &Arc<Verified<RoutableTransaction>>,
        submitted_locally: bool,
        now: LocalTimestamp,
    ) -> Option<bool> {
        let hash = tx.hash();

        if self.pool.contains_key(&hash) || self.is_tombstoned(&hash) {
            return None;
        }

        // Reject if past `validity_range.end_timestamp_exclusive`. Same
        // expression the proposer/validator apply, enforced at the admission
        // boundary so expired txs never enter the pool.
        if tx.validity_range().end_timestamp_exclusive <= self.current_ts {
            tracing::debug!(
                tx_hash = ?hash,
                end_ms = tx.validity_range().end_timestamp_exclusive.as_millis(),
                now_ms = self.current_ts.as_millis(),
                "Rejecting expired transaction"
            );
            return None;
        }

        let cross_shard = topology_snapshot.is_cross_shard_transaction(tx);
        self.add_to_ready_tracking(hash, tx, now);
        self.tx_store.insert(Arc::clone(tx));
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(tx),
                status: TransactionStatus::Pending,
                cross_shard,
                submitted_locally,
                admitted_at: now,
            },
        );
        // Tx is in the pool — any pending cross-shard expectation is satisfied,
        // regardless of which source originally signaled it.
        self.expected_txs.forget(&hash);

        Some(cross_shard)
    }

    /// RPC submit path. Emits `EmitTransactionStatus` for the client
    /// regardless of dedup, plus `Continuation(TransactionsAdmitted)` when
    /// the tx is newly admitted.
    #[instrument(skip(self, topology_snapshot, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_submit_transaction(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: Arc<Verified<RoutableTransaction>>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let hash = tx.hash();

        if let Some(entry) = self.pool.get(&hash) {
            return vec![Action::EmitTransactionStatus {
                tx_hash: hash,
                status: TransactionStatus::Pending,
                cross_shard: entry.cross_shard,
                submitted_locally: entry.submitted_locally,
            }];
        }

        match self.admit_internal(topology_snapshot, &tx, true, now) {
            Some(cross_shard) => {
                tracing::info!(
                    tx_hash = ?hash,
                    pool_size = self.pool.len(),
                    "Transaction admitted via RPC submit"
                );
                vec![
                    Action::EmitTransactionStatus {
                        tx_hash: hash,
                        status: TransactionStatus::Pending,
                        cross_shard,
                        submitted_locally: true,
                    },
                    Action::Continuation(ProtocolEvent::TransactionsAdmitted { txs: vec![tx] }),
                ]
            }
            None => vec![],
        }
    }

    /// Gossip path (or validated RPC submission, post-validation). Silent
    /// on dedup; emits `Continuation(TransactionsAdmitted)` when the tx is
    /// newly admitted.
    #[instrument(skip(self, topology_snapshot, tx), fields(tx_hash = ?tx.hash()))]
    pub fn on_transaction_gossip(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: Arc<Verified<RoutableTransaction>>,
        submitted_locally: bool,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        match self.admit_internal(topology_snapshot, &tx, submitted_locally, now) {
            Some(_) => {
                tracing::trace!(
                    tx_hash = ?tx.hash(),
                    pool_size = self.pool.len(),
                    "Transaction admitted via gossip"
                );
                vec![Action::Continuation(ProtocolEvent::TransactionsAdmitted {
                    txs: vec![tx],
                })]
            }
            None => vec![],
        }
    }

    /// Fetch-response path. Iterates [`Self::admit_internal`] for each tx and
    /// emits one batched `Continuation(TransactionsAdmitted)` for the
    /// admitted subset (empty `Vec<Action>` if nothing was admitted).
    pub fn on_fetched_transactions(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        txs: Vec<Arc<Verified<RoutableTransaction>>>,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        let mut admitted = Vec::with_capacity(txs.len());
        // Hashes that admission rejected (dup / tombstoned / expired) but
        // were tracked as expected. The tx is provably moot — retrying
        // serves nothing and re-fetching every block until
        // `RETENTION_HORIZON` saturates the fetch FSM. Forget the
        // expectation and abandon any in-flight retry.
        let mut moot: Vec<TxHash> = Vec::new();
        for tx in txs {
            let hash = tx.hash();
            if self
                .admit_internal(topology_snapshot, &tx, false, now)
                .is_some()
            {
                admitted.push(tx);
            } else if self.expected_txs.forget(&hash) {
                moot.push(hash);
            }
        }
        let mut actions = Vec::new();
        if !moot.is_empty() {
            actions.push(Action::AbandonFetch(FetchAbandon::Transactions {
                ids: moot,
            }));
        }
        if !admitted.is_empty() {
            actions.push(Action::Continuation(ProtocolEvent::TransactionsAdmitted {
                txs: admitted,
            }));
        }
        actions
    }

    /// Number of distinct tx hashes the mempool is currently expecting via
    /// verified provisions but has not yet seen on the wire. A tx referenced
    /// by N source shards counts once.
    #[must_use]
    pub fn pending_expected_count(&self) -> usize {
        self.expected_txs.len()
    }

    /// Timestamp of the first sighting for an expected tx, if any. Used by
    /// the horizon sweep and by tests asserting lifecycle.
    #[must_use]
    pub fn expected_tx_first_seen_ts(&self, tx_hash: &TxHash) -> Option<WeightedTimestamp> {
        self.expected_txs.first_seen_ts(tx_hash)
    }

    /// Source shard recorded for an expected tx, if any. First sighting wins;
    /// later signals from other shards are ignored.
    #[must_use]
    pub fn expected_tx_source(&self, tx_hash: &TxHash) -> Option<ShardId> {
        self.expected_txs.source(tx_hash)
    }

    /// Eager-fetch every expected cross-shard tx, independent of block commit.
    /// The grace-driven fetch in [`Self::on_block_committed`] stops firing when
    /// the shard stalls on the missing txs; a commit-independent driver (the
    /// cleanup timer) flushes through here to break the deadlock.
    #[must_use]
    pub fn flush_expected_txs(&self) -> Vec<Action> {
        self.expected_txs
            .flush_all()
            .into_iter()
            .map(|(source_shard, ids)| {
                Action::Fetch(FetchRequest::Transactions {
                    ids,
                    shard: source_shard,
                    preferred: None,
                    class: Some(MessageClass::Recovery),
                })
            })
            .collect()
    }

    /// Evict a transaction that has reached a terminal state.
    ///
    /// Removes the pool entry and tombstones the hash so it can't be
    /// re-admitted. The body stays in [`Self::tx_store`] until the
    /// tombstone-window prune sweep runs ([`Self::prune_tombstones`]),
    /// keeping slow peers' fetches answerable until the validity range
    /// expires. Terminal states include:
    /// - Completed (certificate committed)
    /// - Aborted (explicitly aborted)
    fn evict_terminal(&mut self, topology_snapshot: &TopologySnapshot, tx_hash: TxHash) {
        let Some(entry) = self.pool.remove(&tx_hash) else {
            return;
        };

        if entry.status.holds_state_lock() {
            self.remove_locked_nodes(topology_snapshot, &entry.tx);
            if matches!(entry.status, TransactionStatus::Committed(_)) {
                self.locks.dec_in_flight();
            }
        }

        self.remove_from_ready_tracking(&tx_hash);

        // Tombstone the hash so it can't be re-admitted. Body stays in
        // `tx_store` so peers can still fetch by hash; both expire on the
        // same `end_timestamp_exclusive` via `prune_tombstones`.
        self.tombstones
            .tombstone(tx_hash, entry.tx.validity_range().end_timestamp_exclusive);
    }

    /// Check if a transaction hash is tombstoned (reached terminal state).
    #[must_use]
    pub fn is_tombstoned(&self, tx_hash: &TxHash) -> bool {
        self.tombstones.is_tombstoned(tx_hash)
    }

    /// Drive one transaction to `Completed(Aborted)`: drop it from the
    /// pool, release its locks if it was in flight, tombstone it, and
    /// return its terminal status action. `None` for a hash not in the
    /// pool (already terminal).
    ///
    /// Lock release is deliberately unfiltered (every declared node, not
    /// just the ones the current topology routes locally): at a reshape
    /// boundary the head trie has already re-routed this shard's nodes to
    /// its children, so a topology-filtered release would miss exactly the
    /// locks the aborted chain took, and a terminated chain's lock set
    /// dies with it regardless. A tx that never reached `Committed` holds
    /// no in-flight lock, so the release is skipped for it.
    fn abort_one(&mut self, tx_hash: TxHash) -> Option<Action> {
        let entry = self.pool.remove(&tx_hash)?;
        if matches!(entry.status, TransactionStatus::Committed(_)) {
            let newly_unlocked = self
                .locks
                .unlock_nodes(entry.tx.all_declared_nodes().copied());
            for node in newly_unlocked {
                self.promote_transactions_for_node(node);
            }
            self.locks.dec_in_flight();
        }
        self.remove_from_ready_tracking(&tx_hash);
        self.tombstones
            .tombstone(tx_hash, entry.tx.validity_range().end_timestamp_exclusive);
        record_transaction_aborted();
        Some(Action::EmitTransactionStatus {
            tx_hash,
            status: TransactionStatus::Completed(TransactionDecision::Aborted),
            cross_shard: entry.cross_shard,
            submitted_locally: entry.submitted_locally,
        })
    }

    /// Drive every in-flight (`Committed`) transaction to
    /// `Completed(Aborted)` via [`Self::abort_one`]. Called once when the
    /// local chain terminates at a reshape boundary: finalization is a
    /// wave certificate in a later block, and a terminated chain commits
    /// no later block, so an in-flight tx here is permanently undecidable —
    /// abort is its terminal state.
    pub fn abort_in_flight(&mut self) -> Vec<Action> {
        let mut in_flight: Vec<TxHash> = self
            .pool
            .iter()
            .filter(|(_, entry)| matches!(entry.status, TransactionStatus::Committed(_)))
            .map(|(hash, _)| *hash)
            .collect();
        in_flight.sort_unstable();

        let mut actions = Vec::with_capacity(in_flight.len());
        for tx_hash in in_flight {
            actions.extend(self.abort_one(tx_hash));
        }
        actions
    }

    /// Drive a specific set of transactions to `Completed(Aborted)` via
    /// [`Self::abort_one`] — the counterpart abort sweep on a surviving
    /// shard, once a terminated partner's settled set proves the
    /// transaction's cross-shard half will never finalize. Hashes not in
    /// the pool (already terminal) are skipped.
    pub fn abort_transactions(&mut self, tx_hashes: &[TxHash]) -> Vec<Action> {
        let mut sorted: Vec<TxHash> = tx_hashes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut actions = Vec::with_capacity(sorted.len());
        for tx_hash in sorted {
            actions.extend(self.abort_one(tx_hash));
        }
        actions
    }

    /// Process a committed block - update statuses and finalize transactions.
    ///
    /// This handles:
    /// 1. Mark committed transactions
    /// 2. Process certificates → mark completed
    /// 3. Process aborts → update status to terminal
    #[instrument(skip(self, certified), fields(
        height = certified.block().height().inner(),
        tx_count = certified.block().transaction_count()
    ))]
    #[allow(clippy::too_many_lines)] // sequential orchestration: block-include, expected-tx sweep, certificate processing
    pub fn on_block_committed(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let block = certified.block();
        let height = block.height();
        let mut actions = Vec::new();

        self.current_height = height;
        self.current_ts = block.header().parent_qc().weighted_timestamp();

        // Ensure all committed transactions are in the mempool.
        // This handles the case where we fetched transactions to vote on a block
        // but didn't receive them via gossip. We need them in the mempool for
        // status tracking (execution status updates).
        let mut abandoned_tx_fetches: Vec<TxHash> = Vec::new();
        for tx in block.transactions().iter() {
            let hash = tx.hash();
            // Prefer the marker the wrapper already carries; fall back to
            // the BFT-transitive `from_persisted` gate for sync-loaded
            // blocks whose `Verifiable` entries decoded as Unverified.
            let verified: Arc<Verified<RoutableTransaction>> = match (**tx).clone().into_verified()
            {
                Ok(v) => Arc::new(v),
                Err(raw) => Arc::new(Verified::<RoutableTransaction>::from_persisted(raw)),
            };
            self.pool.entry(hash).or_insert_with(|| {
                tracing::debug!(
                    tx_hash = ?hash,
                    height = height.inner(),
                    "Added committed transaction to mempool"
                );
                self.tx_store.insert(Arc::clone(&verified));
                PoolEntry {
                    tx: verified,
                    status: TransactionStatus::Pending, // Will be updated by execution
                    cross_shard: topology_snapshot.is_cross_shard_transaction(tx),
                    submitted_locally: false, // Fetched for block processing
                    // Block-committed entries skip the dwell path entirely
                    // (next loop transitions them straight to Committed +
                    // takes locks), so the anchor is never read.
                    admitted_at: LocalTimestamp::ZERO,
                }
            });
            // Block inclusion is the strongest possible signal that the tx
            // exists; any cross-shard expectation is satisfied. If a fetch
            // was racing the commit, cancel it explicitly — `forget` returns
            // `true` exactly when an expected entry was actively cleared.
            if self.expected_txs.forget(&hash) {
                abandoned_tx_fetches.push(hash);
            }
        }
        if !abandoned_tx_fetches.is_empty() {
            actions.push(Action::AbandonFetch(FetchAbandon::Transactions {
                ids: abandoned_tx_fetches,
            }));
        }

        // Update transaction status to Committed and add locks.
        // This must happen synchronously to prevent the same transactions from being
        // re-proposed before the status update is processed.
        for tx in block.transactions().iter() {
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
                    self.add_locked_nodes(topology_snapshot, tx);
                    self.locks.inc_in_flight();
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash: hash,
                        status: TransactionStatus::Committed(height),
                        cross_shard,
                        submitted_locally,
                    });
                }
            }
        }

        // Record cross-shard txs we now expect to see on the wire (gossip,
        // submit, or — failing both within the grace window — fetch). Skipped
        // for txs already in pool (gossip already won); per-(tx, source) dedup
        // is handled by `ExpectedTxs::record`.
        for provision in block.provisions() {
            let source_shard = provision.source_shard();
            for entry in provision.transactions().iter() {
                let tx_hash = entry.tx_hash;
                if self.pool.contains_key(&tx_hash) {
                    continue;
                }
                self.expected_txs
                    .record(tx_hash, source_shard, self.current_ts);
            }
        }

        // Fire fetches for entries whose grace window has elapsed. Re-emitted
        // every block past grace; the fetch protocol dedupes in-flight ids
        // and handles peer rotation. In-flights drain on admission
        // (gossip / submit `Continuation(TransactionsAdmitted)`) and on the
        // explicit `Action::AbandonFetch` emitted from the block-include
        // race and retention-horizon paths below.
        for (source_shard, ids) in self
            .expected_txs
            .due_for_fetch(self.current_ts, EXPECTED_TX_GRACE)
        {
            // Routability is the network's call: it resolves the source
            // committee against the terminal-clamped routing map, so a split
            // parent draining out of the head is still reachable. Emitting
            // here and letting an unroutable shard fall to `PeerUnreachable`
            // + the retention-horizon drop is sounder than gating on the
            // head committee, which a drained source no longer carries.
            tracing::debug!(
                ?source_shard,
                missing_count = ids.len(),
                height = height.inner(),
                "Mempool fetching expected cross-shard txs past grace window"
            );
            actions.push(Action::Fetch(FetchRequest::Transactions {
                ids,
                shard: source_shard,
                preferred: None,
                class: Some(MessageClass::Recovery),
            }));
        }

        // Hard horizon: any expected-tx that survived grace + every realistic
        // fetch retry past `RETENTION_HORIZON` is provably moot — every wave
        // that needed it has long since timed out via WAVE_TIMEOUT. Drop with
        // warn + metric; non-zero rate here means cross-shard DA failed.
        // Each dropped hash is also handed to `AbandonFetch` so the io_loop's
        // `TransactionBinding` clears any in-flight retry — without this the
        // fetch protocol keeps requesting forever.
        let dropped = self
            .expected_txs
            .drop_past_horizon(self.current_ts, RETENTION_HORIZON);
        if !dropped.is_empty() {
            let mut abandoned: Vec<TxHash> = Vec::with_capacity(dropped.len());
            for (tx_hash, source_shard) in dropped {
                tracing::warn!(
                    ?tx_hash,
                    ?source_shard,
                    height = height.inner(),
                    "Expected cross-shard tx dropped past RETENTION_HORIZON without DA"
                );
                record_expected_tx_dropped();
                abandoned.push(tx_hash);
            }
            actions.push(Action::AbandonFetch(FetchAbandon::Transactions {
                ids: abandoned,
            }));
        }

        // Per-tx terminal state from committed wave certificates. Decisions are
        // derived from each FinalizedWave directly, so this works identically
        // for consensus and sync commit paths.
        for fw in block.certificates().iter() {
            for (tx_hash, decision) in fw.tx_decisions() {
                if matches!(decision, TransactionDecision::Aborted) {
                    record_transaction_aborted();
                }
                actions.extend(self.process_certificate_committed(
                    topology_snapshot,
                    tx_hash,
                    decision,
                ));
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
        topology_snapshot: &TopologySnapshot,
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
            self.evict_terminal(topology_snapshot, tx_hash);
        }

        actions
    }

    /// Record that local ECs were just formed for these transactions.
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
    fn add_locked_nodes(&mut self, topology_snapshot: &TopologySnapshot, tx: &RoutableTransaction) {
        let local_shard = self.local_shard;
        let newly_locked = self.locks.lock_nodes(
            tx.all_declared_nodes()
                .filter(|node| topology_snapshot.shard_for_node_id(node) == local_shard)
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
    fn remove_locked_nodes(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: &RoutableTransaction,
    ) {
        let local_shard = self.local_shard;
        let newly_unlocked = self.locks.unlock_nodes(
            tx.all_declared_nodes()
                .filter(|node| topology_snapshot.shard_for_node_id(node) == local_shard)
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
        tx: &Arc<Verified<RoutableTransaction>>,
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
        let mut to_readd: Vec<(TxHash, Arc<Verified<RoutableTransaction>>, LocalTimestamp)> =
            Vec::new();
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
        quiesce: Option<QuiesceCut>,
    ) -> Vec<Arc<Verified<RoutableTransaction>>> {
        // Certificates reduce in-flight (transactions complete), txs increase it
        let effective_in_flight = self
            .in_flight()
            .saturating_add(pending_commit_tx_count)
            .saturating_sub(pending_commit_cert_count);
        let at_limit = effective_in_flight >= MAX_TX_IN_FLIGHT;

        if at_limit {
            return Vec::new();
        }

        // Cap max_count to stay within limit
        let room = MAX_TX_IN_FLIGHT.saturating_sub(effective_in_flight);
        let max_count = max_count.min(room);

        // Split-boundary quiesce is inert with both margins zero (the
        // default) — drop the per-transaction classification entirely.
        let quiesce = quiesce.filter(|_| {
            !self.config.quiesce_cross_shard_margin.is_zero()
                || !self.config.quiesce_single_shard_margin.is_zero()
        });

        self.ready
            .iter_ready(self.config.min_dwell_time, now)
            .filter(|tx| self.passes_quiesce(tx, quiesce))
            .take(max_count)
            .collect()
    }

    /// Whether `tx` may still be selected under the split-boundary quiesce.
    ///
    /// With no pending cut, always selectable. Otherwise the transaction
    /// is held once the proposer's anchor plus the per-class margin reaches
    /// the cut — cross-shard work gets the wider margin (a full 2PC round)
    /// since it needs every shard to settle before the terminal block,
    /// single-shard the narrower one. Classification reads the
    /// admission-time `cross_shard` flag, which already captures whether
    /// the transaction's declared nodes reach a remote shard.
    fn passes_quiesce(
        &self,
        tx: &Arc<Verified<RoutableTransaction>>,
        quiesce: Option<QuiesceCut>,
    ) -> bool {
        let Some(cut) = quiesce else {
            return true;
        };
        let cross_shard = self
            .pool
            .get(&tx.hash())
            .is_some_and(|entry| entry.cross_shard);
        let margin = if cross_shard {
            self.config.quiesce_cross_shard_margin
        } else {
            self.config.quiesce_single_shard_margin
        };
        cut.now_wt.plus(margin) < cut.cut_wt
    }

    /// Get lock contention statistics.
    ///
    /// Returns counts of:
    /// - `locked_nodes`: Number of nodes currently locked by in-flight transactions
    /// - `pending_count`: Number of transactions in Pending status
    /// - `pending_deferred`: Number of pending transactions that conflict with locked nodes
    /// - `in_flight_count`: Number of transactions in Committed status (holding locks)
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
            in_flight_count: self.locks.in_flight() as u64,
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
    pub const fn in_flight(&self) -> usize {
        self.locks.in_flight()
    }

    /// Check if we're at the in-flight limit.
    ///
    /// At this limit, no new transactions are proposed.
    #[must_use]
    pub const fn at_in_flight_limit(&self) -> bool {
        self.in_flight() >= MAX_TX_IN_FLIGHT
    }

    /// Check whether accepting a block would unacceptably increase in-flight load.
    ///
    /// Returns `true` if the block should be rejected. Blocks that reduce or
    /// maintain the current in-flight count are always accepted, even when over
    /// the limit — this prevents deadlock when certificate-heavy blocks would
    /// relieve backpressure.
    #[must_use]
    pub const fn would_exceed_in_flight(&self, new_tx_count: usize, cert_count: usize) -> bool {
        let current = self.in_flight();
        let projected = current
            .saturating_add(new_tx_count)
            .saturating_sub(cert_count);
        let would_exceed = projected > MAX_TX_IN_FLIGHT;
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
    pub const fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Check if we have a transaction.
    #[must_use]
    pub fn has_transaction(&self, hash: &TxHash) -> bool {
        self.pool.contains_key(hash)
    }

    /// Get a transaction body by hash. Delegates to [`TxStore`] so the
    /// answer covers both live pool entries and tombstone-window bodies
    /// (terminal-state txs whose body we still hold for slow peers).
    #[must_use]
    pub fn get_transaction(&self, hash: &TxHash) -> Option<Arc<Verified<RoutableTransaction>>> {
        self.tx_store.get(hash)
    }

    /// Get transaction status.
    #[must_use]
    pub fn status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.pool.get(hash).map(|e| e.status.clone())
    }

    /// Get mempool memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> MempoolMemoryStats {
        MempoolMemoryStats {
            pool: self.pool.len(),
            ready: self.ready.ready_count(),
            tombstones: self.tombstones.len_tombstones(),
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

    /// Get all incomplete transactions (not yet completed).
    ///
    /// Returns tuples of (hash, status, transaction Arc) for analysis.
    #[must_use]
    pub fn incomplete_transactions(
        &self,
    ) -> Vec<(
        TxHash,
        TransactionStatus,
        Arc<Verified<RoutableTransaction>>,
    )> {
        self.pool
            .iter()
            .filter(|(_, entry)| !matches!(entry.status, TransactionStatus::Completed(_)))
            .map(|(hash, entry)| (*hash, entry.status.clone(), Arc::clone(&entry.tx)))
            .collect()
    }

    /// Drop tombstones whose `end_timestamp_exclusive <= current_ts`, and
    /// drop the matching bodies from [`Self::tx_store`]. Past
    /// `end_timestamp_exclusive`, the validator-side validity check
    /// rejects any re-submission, so the tombstone is no longer
    /// load-bearing for correctness and the body is no longer fetchable.
    /// Anchored on `current_ts` (updated in `on_block_committed`).
    ///
    /// Returns the number of tombstones dropped.
    pub fn cleanup_expired_tombstones(&mut self) -> usize {
        let removed = self.tombstones.prune_tombstones(self.current_ts);
        let count = removed.len();
        if !removed.is_empty() {
            self.tx_store.evict(removed);
        }
        count
    }

    /// Drop `Pending` pool entries whose `end_timestamp_exclusive <= current_ts`.
    ///
    /// Pending txs hold no state locks (locks are taken on `Committed` /
    /// `Executed`), so removal is safe without going through the
    /// terminal-eviction path. Re-submission past expiry is rejected at
    /// admission, so no tombstone is needed either; we also drop the body
    /// from [`Self::tx_store`] since nothing else needs it.
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
            .filter(|(_, entry)| entry.tx.validity_range().end_timestamp_exclusive <= now)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.pool.remove(hash);
            self.remove_from_ready_tracking(hash);
        }
        if !expired.is_empty() {
            self.tx_store.evict(expired.iter().copied());
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
    use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
    use hyperscale_metrics_memory::MemoryRecorder;
    use hyperscale_types::test_utils::{
        TestCommittee, certify, make_finalized_wave, make_live_block, test_node, test_transaction,
        test_transaction_with_nodes,
    };
    use hyperscale_types::{BoundedVec, Verified};

    /// Test-only convenience: wrap any `RoutableTransaction` in a
    /// `Verified` witness via the test-only gate.
    fn verified(tx: RoutableTransaction) -> Verified<RoutableTransaction> {
        Verified::new_unchecked_for_test(tx)
    }
    use hyperscale_types::{
        Block, FinalizedWave, MAX_TXS_PER_BLOCK, MerkleInclusionProof, ProvisionEntry, Provisions,
        ShardId, ValidatorId,
    };

    use super::*;

    fn make_test_topology() -> TopologySnapshot {
        TestCommittee::new(4, 42).topology_snapshot(1)
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
        let block = make_live_block(
            ShardId::ROOT,
            height,
            1_234_567_890,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
            vec![Arc::new(fw.into())],
        );
        certify(block, height.inner() * TEST_BLOCK_INTERVAL_MS)
    }

    /// Build a `CertifiedBlock` whose body carries one `Provisions` bundle
    /// from `source_shard` referencing `tx_hashes`. No transactions in the
    /// block body itself (the bundle is the cross-shard signal).
    fn certified_block_with_provisions(
        height: BlockHeight,
        source_shard: ShardId,
        tx_hashes: &[TxHash],
    ) -> CertifiedBlock {
        let transactions = tx_hashes
            .iter()
            .map(|h| ProvisionEntry::new(*h, vec![], vec![], vec![]))
            .collect();
        let provision = Provisions::new(
            source_shard,
            ShardId::ROOT,
            height,
            MerkleInclusionProof::dummy(),
            transactions,
        );
        let block = match make_live_block(
            ShardId::ROOT,
            height,
            1_234_567_890,
            ValidatorId::new(0),
            vec![],
            vec![],
        ) {
            Block::Live {
                header,
                transactions,
                certificates,
                ..
            } => Block::Live {
                header,
                transactions,
                certificates,
                provisions: Arc::new(vec![Arc::new(provision.into())].into()),
                ready_signals: Arc::new(BoundedVec::new()),
                reshape_trigger: None,
            },
            sealed @ Block::Sealed { .. } => sealed,
        };
        certify(block, height.inner() * TEST_BLOCK_INTERVAL_MS)
    }

    #[test]
    fn provisions_record_expected_txs_for_unseen_hashes() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let already_seen = test_transaction(1);
        let already_seen_hash = already_seen.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(already_seen)),
            LocalTimestamp::ZERO,
        );

        let unseen_hash = test_transaction(2).hash();

        let certified = certified_block_with_provisions(
            BlockHeight::new(5),
            ShardId::leaf(2, 1),
            &[already_seen_hash, unseen_hash],
        );
        mempool.on_block_committed(&topology_snapshot, &certified);

        assert_eq!(mempool.pending_expected_count(), 1);
        let expected_ts = WeightedTimestamp::from_millis(5 * TEST_BLOCK_INTERVAL_MS);
        assert_eq!(
            mempool.expected_tx_first_seen_ts(&unseen_hash),
            Some(expected_ts)
        );
        assert_eq!(
            mempool.expected_tx_source(&unseen_hash),
            Some(ShardId::leaf(2, 1))
        );
        assert!(
            mempool
                .expected_tx_first_seen_ts(&already_seen_hash)
                .is_none(),
            "txs already in pool are not expected-tracked"
        );
    }

    #[test]
    fn first_sighting_wins_across_sources_and_repeats() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        // Earliest sighting at H=3 from shard 1.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(
                BlockHeight::new(3),
                ShardId::leaf(2, 1),
                &[unseen_hash],
            ),
        );
        // Same source at a later height — no-op.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(
                BlockHeight::new(7),
                ShardId::leaf(2, 1),
                &[unseen_hash],
            ),
        );
        // A different source at a later height — also no-op (first sighting wins).
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(
                BlockHeight::new(7),
                ShardId::leaf(2, 2),
                &[unseen_hash],
            ),
        );

        assert_eq!(mempool.pending_expected_count(), 1);
        assert_eq!(
            mempool.expected_tx_first_seen_ts(&unseen_hash),
            Some(WeightedTimestamp::from_millis(3 * TEST_BLOCK_INTERVAL_MS))
        );
        assert_eq!(
            mempool.expected_tx_source(&unseen_hash),
            Some(ShardId::leaf(2, 1))
        );
    }

    #[test]
    fn gossip_arrival_drops_expected_entry() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Provision arrives first, mempool starts expecting the tx.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::leaf(2, 1), &[tx_hash]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);

        // Gossip arrives — expectation cleared.
        mempool.on_transaction_gossip(
            &topology_snapshot,
            Arc::new(verified(tx)),
            false,
            LocalTimestamp::ZERO,
        );
        assert_eq!(mempool.pending_expected_count(), 0);
    }

    #[test]
    fn rpc_submit_drops_expected_entry() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::leaf(2, 1), &[tx_hash]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);

        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx)),
            LocalTimestamp::ZERO,
        );
        assert_eq!(mempool.pending_expected_count(), 0);
    }

    #[test]
    fn block_inclusion_drops_expected_entry() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::leaf(2, 1), &[tx_hash]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);

        // A later block on this shard includes the tx body — block-include
        // path admits it bypassing the gossip/submit `admit_internal` path,
        // so the cleanup site there is exercised independently.
        let certified = certified_commit_block(
            BlockHeight::new(2),
            tx,
            make_finalized_wave(BlockHeight::new(2), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);
        assert_eq!(mempool.pending_expected_count(), 0);
    }

    #[test]
    fn no_fetch_emitted_within_grace_window() {
        // TEST_BLOCK_INTERVAL_MS = 500; grace = 2_000ms. First sighting at
        // H=1 (ts=500); H=4 (ts=2_000) → elapsed 1_500ms < 2_000ms.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[unseen_hash]),
        );
        let actions = mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(4), ShardId::ROOT, &[]),
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Fetch(FetchRequest::Transactions { .. }))),
            "Fetch should not fire within grace window"
        );
        assert_eq!(mempool.pending_expected_count(), 1);
    }

    #[test]
    fn fetch_emitted_after_grace_window_targets_source_committee() {
        // First sighting at H=1 (ts=500); H=5 (ts=2_500) → elapsed 2_000ms.
        let topology_snapshot = make_test_topology();
        let source = ShardId::ROOT;
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), source, &[unseen_hash]),
        );
        let actions = mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(5), source, &[]),
        );

        let fetch = actions
            .iter()
            .find_map(|a| match a {
                Action::Fetch(FetchRequest::Transactions { ids, preferred, .. }) => {
                    Some((ids, preferred))
                }
                _ => None,
            })
            .expect("fetch action emitted past grace");
        assert_eq!(fetch.0, &vec![unseen_hash]);
        assert_eq!(*fetch.1, None);
    }

    #[test]
    fn fetch_uses_first_sighting_source_only() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        // First sighting wins: shard 0 at H=1 owns the entry. Shard 1's later
        // signal at H=2 is ignored, so the fetch must target shard 0's
        // committee even though shard 1 also referenced it.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[unseen_hash]),
        );
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(
                BlockHeight::new(2),
                ShardId::leaf(2, 1),
                &[unseen_hash],
            ),
        );
        let actions = mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(5), ShardId::ROOT, &[]),
        );

        let fetches: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Fetch(FetchRequest::Transactions { ids, preferred, .. }) => {
                    Some((ids, preferred))
                }
                _ => None,
            })
            .collect();
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].0, &vec![unseen_hash]);
        assert_eq!(*fetches[0].1, None);
    }

    #[test]
    fn entry_dropped_past_retention_horizon_emits_metric() {
        // RETENTION_HORIZON ≈ 5min + 24s. Sighting at H=1 (ts=500ms); commit
        // far past horizon at H=700 (ts=350_000ms) — well over 324_000ms.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        let recorder = MemoryRecorder::new();
        let arc: Arc<dyn MetricsRecorder> = Arc::new(recorder.clone());
        with_scoped_recorder(arc, || {
            mempool.on_block_committed(
                &topology_snapshot,
                &certified_block_with_provisions(
                    BlockHeight::new(1),
                    ShardId::ROOT,
                    &[unseen_hash],
                ),
            );
            assert_eq!(mempool.pending_expected_count(), 1);
            assert_eq!(recorder.counter("expected_tx_dropped", None), 0);

            mempool.on_block_committed(
                &topology_snapshot,
                &certified_block_with_provisions(BlockHeight::new(700), ShardId::ROOT, &[]),
            );
            assert_eq!(mempool.pending_expected_count(), 0);
            assert_eq!(recorder.counter("expected_tx_dropped", None), 1);
        });
    }

    #[test]
    fn entry_retained_within_retention_horizon() {
        // H=100 (ts=50_000ms) is well past grace (2_000ms) but well under
        // RETENTION_HORIZON (~324_000ms). Entry should still be tracked, and
        // a fetch is emitted but no drop.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[unseen_hash]),
        );
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(100), ShardId::ROOT, &[]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);
    }

    #[test]
    fn drop_past_horizon_emits_abandon_fetch() {
        // Same setup as `entry_dropped_past_retention_horizon_emits_metric`,
        // but assert the explicit AbandonFetch action so any in-flight fetch
        // is cancelled rather than retried forever.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let unseen_hash = test_transaction(1).hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[unseen_hash]),
        );
        let actions = mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(700), ShardId::ROOT, &[]),
        );

        let abandoned: Vec<TxHash> = actions
            .iter()
            .filter_map(|a| match a {
                Action::AbandonFetch(FetchAbandon::Transactions { ids }) => Some(ids.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            abandoned,
            vec![unseen_hash],
            "Expected AbandonFetch for retention-horizon-orphaned tx, got actions: {actions:?}"
        );
    }

    #[test]
    fn block_include_emits_abandon_fetch_for_expected_tx() {
        // Race: a tx is recorded as expected via provisions on H=1, then
        // arrives via block inclusion on H=2 *without* having gone through
        // gossip/submit admission. The block-include forget site clears the
        // expected entry; the in-flight fetch (if any) must be cancelled
        // explicitly because no `TransactionsAdmitted` continuation fires
        // on this path.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::leaf(2, 1), &[tx_hash]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);

        let certified = certified_commit_block(
            BlockHeight::new(2),
            tx,
            make_finalized_wave(BlockHeight::new(2), tx_hash, TransactionDecision::Accept),
        );
        let actions = mempool.on_block_committed(&topology_snapshot, &certified);

        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::Transactions { ids }) if ids == &[tx_hash]
            )),
            "Expected AbandonFetch for block-included expected tx, got: {actions:?}"
        );
    }

    #[test]
    fn fetched_but_rejected_tx_clears_expected_state() {
        // Regression: when a fetched cross-shard tx is rejected by
        // admission (validity expired / tombstoned / dup), its hash must
        // be forgotten from `expected_txs` and abandoned in the fetch
        // FSM. Otherwise `due_for_fetch` re-emits `Action::Fetch` for the
        // same hash on every subsequent block commit, saturating the
        // fetch FSM until RETENTION_HORIZON ages it out — visible in
        // production as "tx fetch rises to the absolute resource limit"
        // whenever execution falls behind enough for tx validity to
        // elapse before delivery.
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Block H=1 records the expectation.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[tx_hash]),
        );
        assert_eq!(mempool.pending_expected_count(), 1);

        // Advance current_ts past the tx's validity window. `test_validity_range`
        // ends at 60_000ms; TEST_BLOCK_INTERVAL_MS=500 → past validity at H≥121.
        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(125), ShardId::ROOT, &[]),
        );

        // Source committee delivers the tx body — but admission rejects
        // because the tx is past its validity window.
        let actions = mempool.on_fetched_transactions(
            &topology_snapshot,
            vec![Arc::new(verified(tx))],
            LocalTimestamp::ZERO,
        );

        assert_eq!(
            mempool.pending_expected_count(),
            0,
            "rejected tx must be cleared from expected_txs so the next \
             block doesn't re-fire a fetch for it"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::Transactions { ids }) if ids == &[tx_hash]
            )),
            "rejected tx must emit AbandonFetch so any in-flight retry \
             is cancelled, got: {actions:?}"
        );
    }

    #[test]
    fn fetch_stops_after_admission_clears_expectation() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(1), ShardId::ROOT, &[tx_hash]),
        );
        mempool.on_transaction_gossip(
            &topology_snapshot,
            Arc::new(verified(tx)),
            false,
            LocalTimestamp::ZERO,
        );

        let actions = mempool.on_block_committed(
            &topology_snapshot,
            &certified_block_with_provisions(BlockHeight::new(5), ShardId::ROOT, &[]),
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Fetch(FetchRequest::Transactions { .. }))),
            "no fetch after admission cleared expectation"
        );
    }

    #[test]
    fn test_abort_updates_status() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        // Submit a TX, then commit a block whose FinalizedWave aborts it.
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );

        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx,
            make_finalized_wave(BlockHeight::new(1), tx_hash, TransactionDecision::Aborted),
        );
        let actions = mempool.on_block_committed(&topology_snapshot, &certified);

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

    /// A terminated chain commits no later block, so its in-flight
    /// transactions can never be decided: the terminal sweep aborts
    /// them — terminal status emitted, locks released, entry
    /// tombstoned, in-flight count zeroed.
    #[test]
    fn abort_in_flight_drives_committed_txs_terminal() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction_with_nodes(b"straddler", vec![test_node(7)], vec![test_node(8)]);
        let tx_hash = tx.hash();

        // Commit the tx with no deciding wave certificate: in flight,
        // holding its declared-node locks.
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            1_234_567_890,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block, TEST_BLOCK_INTERVAL_MS));
        assert_eq!(mempool.in_flight(), 1);
        assert!(mempool.lock_contention_stats().locked_nodes > 0);

        let actions = mempool.abort_in_flight();
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::EmitTransactionStatus {
                    tx_hash: h,
                    status: TransactionStatus::Completed(TransactionDecision::Aborted),
                    ..
                } if *h == tx_hash
            )),
            "sweep must emit the terminal abort status"
        );
        assert_eq!(mempool.in_flight(), 0);
        assert_eq!(mempool.lock_contention_stats().locked_nodes, 0);
        assert!(mempool.status(&tx_hash).is_none());
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    #[test]
    fn abort_transactions_releases_only_the_named_txs() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let doomed = test_transaction_with_nodes(b"doomed", vec![test_node(7)], vec![test_node(8)]);
        let doomed_hash = doomed.hash();
        let kept = test_transaction_with_nodes(b"kept", vec![test_node(9)], vec![test_node(10)]);
        let kept_hash = kept.hash();

        // Both commit with no deciding wave certificate: in flight, holding
        // their declared-node locks.
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            1_234_567_890,
            ValidatorId::new(0),
            vec![Arc::new(doomed), Arc::new(kept)],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block, TEST_BLOCK_INTERVAL_MS));
        assert_eq!(mempool.in_flight(), 2);

        let actions = mempool.abort_transactions(&[doomed_hash]);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::EmitTransactionStatus {
                    tx_hash: h,
                    status: TransactionStatus::Completed(TransactionDecision::Aborted),
                    ..
                } if *h == doomed_hash
            )),
            "the named tx is driven to terminal abort",
        );
        assert_eq!(
            mempool.in_flight(),
            1,
            "only the named tx releases its slot"
        );
        assert!(mempool.is_tombstoned(&doomed_hash));
        assert!(
            matches!(
                mempool.status(&kept_hash),
                Some(TransactionStatus::Committed(_))
            ),
            "the unnamed tx keeps its locks and in-flight slot",
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bloom-inventory snapshot
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn tx_store_bloom_snapshot_covers_pool_and_tombstone_window() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        // A submitted-but-not-yet-committed tx lands in pool.
        let tx_live = test_transaction(1);
        let tx_live_hash = tx_live.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx_live)),
            LocalTimestamp::ZERO,
        );

        // A second tx commits and gets tombstoned. Body stays in TxStore
        // until the tombstone retention window elapses.
        let tx_done = test_transaction(2);
        let tx_done_hash = tx_done.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx_done.clone())),
            LocalTimestamp::ZERO,
        );
        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx_done,
            make_finalized_wave(
                BlockHeight::new(1),
                tx_done_hash,
                TransactionDecision::Accept,
            ),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);

        let bf = mempool.tx_store().tx_bloom_snapshot().expect("sizing ok");
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
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction (commit + Accept wave cert in one block).
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );
        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx.clone(),
            make_finalized_wave(BlockHeight::new(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);

        // Verify it's tombstoned
        assert!(mempool.is_tombstoned(&tx_hash));

        // Try to re-add via gossip - should be rejected
        let actions = mempool.on_transaction_gossip(
            &topology_snapshot,
            Arc::new(verified(tx)),
            false,
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    #[test]
    fn test_tombstoned_transaction_rejected_on_submit() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let tx = test_transaction(1);
        let tx_hash = tx.hash();

        // Submit and complete the transaction (commit + Accept wave cert in one block).
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );
        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx.clone(),
            make_finalized_wave(BlockHeight::new(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);

        // Try to re-submit - should be rejected (no status emitted)
        let actions = mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx)),
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty(), "Tombstoned tx should be rejected");

        // Should still not be in pool
        assert!(mempool.status(&tx_hash).is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a `RoutableTransaction` whose write set is a single
    /// index-derived `NodeId`, so callers can mint up to `MAX_TX_IN_FLIGHT`
    /// distinct, non-conflicting txs by feeding sequential indices.
    fn unique_test_tx(idx: usize) -> RoutableTransaction {
        let seed = idx.to_le_bytes();
        let mut node = [0u8; 30];
        node[..seed.len()].copy_from_slice(&seed);
        test_transaction_with_nodes(&seed, vec![], vec![NodeId(node)])
    }

    /// Fill a mempool to [`MAX_TX_IN_FLIGHT`] by submitting that many
    /// distinct transactions and committing them across enough blocks to
    /// stay within `MAX_TXS_PER_BLOCK` per block — every tx transitions
    /// to `Committed`, holding a state lock.
    fn put_mempool_at_limit(
        mempool: &mut MempoolCoordinator,
        topology_snapshot: &TopologySnapshot,
    ) {
        let txs: Vec<Arc<RoutableTransaction>> = (0..MAX_TX_IN_FLIGHT)
            .map(|i| Arc::new(unique_test_tx(i)))
            .collect();
        for tx in &txs {
            mempool.on_submit_transaction(
                topology_snapshot,
                Arc::new(verified((**tx).clone())),
                LocalTimestamp::ZERO,
            );
        }
        for (i, chunk) in txs.chunks(MAX_TXS_PER_BLOCK).enumerate() {
            let block = make_live_block(
                ShardId::leaf(1, 0),
                BlockHeight::new(u64::try_from(i + 1).unwrap()),
                1_234_567_890,
                ValidatorId::new(0),
                chunk.to_vec(),
                vec![],
            );
            mempool.on_block_committed(topology_snapshot, &certify(block, TEST_BLOCK_INTERVAL_MS));
        }

        assert!(
            mempool.at_in_flight_limit(),
            "mempool should be at in-flight limit after committing {MAX_TX_IN_FLIGHT} txs",
        );
    }

    /// Create a topology with 2 shards for cross-shard testing
    fn make_cross_shard_topology() -> TopologySnapshot {
        TestCommittee::new(8, 42).topology_snapshot(2)
    }

    /// Create a cross-shard transaction (writes to nodes in different shards)
    fn test_cross_shard_transaction(seed: u8) -> RoutableTransaction {
        use hyperscale_types::test_utils::test_node;
        use hyperscale_types::uniform_shard_for_node;

        // Find two seeds that map to different shards with 2 shards
        // We'll search for a pair starting from the given seed
        let node1 = test_node(seed);
        let shard1 = uniform_shard_for_node(&node1, 2);

        // Find a different shard
        let mut node2_seed = seed.wrapping_add(1);
        loop {
            let node2 = test_node(node2_seed);
            let shard2 = uniform_shard_for_node(&node2, 2);
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
        test_transaction_with_nodes(
            &[seed, seed + 1, seed + 2],
            vec![test_node(seed)],                        // read from one shard
            vec![test_node(seed), test_node(node2_seed)], // write to both shards
        )
    }

    #[test]
    fn ready_transactions_quiesce_holds_cross_shard_but_keeps_single_shard() {
        let topology_snapshot = make_cross_shard_topology();
        let config = MempoolConfig {
            quiesce_cross_shard_margin: DEFAULT_QUIESCE_CROSS_SHARD_MARGIN,
            quiesce_single_shard_margin: DEFAULT_QUIESCE_SINGLE_SHARD_MARGIN,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::leaf(1, 0), config);

        let cross = test_cross_shard_transaction(10);
        let single = unique_test_tx(99);
        let cross_hash = cross.hash();
        let single_hash = single.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(cross)),
            LocalTimestamp::ZERO,
        );
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(single)),
            LocalTimestamp::ZERO,
        );

        // Past the dwell time so both are eligible.
        let now = LocalTimestamp::from_millis(500);

        // No pending split → no quiesce, both selectable.
        assert_eq!(
            mempool.ready_transactions(10, 0, 0, now, None).len(),
            2,
            "without a cut the quiesce is inert",
        );

        // A cut 10s out: the cross-shard margin (a full 2PC round) reaches
        // it, so the cross-shard tx is held; the single-shard margin (a few
        // block intervals) does not, so the single-shard tx is kept.
        let cut = QuiesceCut {
            now_wt: WeightedTimestamp::from_millis(0),
            cut_wt: WeightedTimestamp::from_millis(10_000),
        };
        let selected: Vec<TxHash> = mempool
            .ready_transactions(10, 0, 0, now, Some(cut))
            .iter()
            .map(|tx| tx.hash())
            .collect();
        assert!(
            selected.contains(&single_hash),
            "single-shard tx stays selectable 10s before the cut",
        );
        assert!(
            !selected.contains(&cross_hash),
            "cross-shard tx is held — a 2PC round can't settle before the cut",
        );
    }

    #[test]
    fn ready_transactions_quiesce_inert_with_zero_margins() {
        // The simulation default: zero margins keep every transaction
        // selectable right up to the cut, so reshape tests keep producing
        // boundary straddlers for the abort backstop.
        let topology_snapshot = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));
        let cross = test_cross_shard_transaction(10);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(cross)),
            LocalTimestamp::ZERO,
        );

        let now = LocalTimestamp::from_millis(500);
        let cut = QuiesceCut {
            now_wt: WeightedTimestamp::from_millis(9_999),
            cut_wt: WeightedTimestamp::from_millis(10_000),
        };
        assert_eq!(
            mempool.ready_transactions(10, 0, 0, now, Some(cut)).len(),
            1,
            "zero margins disable quiesce even at the cut",
        );
    }

    #[test]
    fn test_backpressure_allows_txns_below_limit() {
        // A few txs is far below MAX_TX_IN_FLIGHT, so ready_transactions
        // returns them all once they've dwelled long enough.
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));
        let topology_snapshot = make_cross_shard_topology();
        let submit_at = LocalTimestamp::ZERO;
        let read_at = submit_at.plus(DEFAULT_MIN_DWELL_TIME + Duration::from_millis(1));

        // Add a single-shard transaction
        let single_shard_tx = test_transaction(1);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(single_shard_tx)),
            submit_at,
        );

        // Add a cross-shard transaction
        let cross_shard_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(cross_shard_tx)),
            submit_at,
        );

        // Below limit: all TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0, read_at, None);
        assert_eq!(ready.len(), 2, "All TXs should be allowed below limit");
    }

    #[test]
    fn test_backpressure_rejects_all_at_limit() {
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));
        let topology_snapshot = make_cross_shard_topology();

        // Put mempool at the in-flight limit
        put_mempool_at_limit(&mut mempool, &topology_snapshot);
        assert!(mempool.at_in_flight_limit());

        // Add a transaction
        let tx = test_transaction(1);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx)),
            LocalTimestamp::ZERO,
        );

        // At limit: no TXs should be returned
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::ZERO, None);
        assert!(
            ready.is_empty(),
            "No TXs should be returned at in-flight limit"
        );
    }

    #[test]
    fn test_backpressure_not_at_limit_allows_all_txns() {
        let topology_snapshot = make_cross_shard_topology();
        let config = MempoolConfig {
            min_dwell_time: Duration::ZERO,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::leaf(1, 0), config);

        // Mempool is not at limit (nothing committed)
        assert!(!mempool.at_in_flight_limit());

        // Add a single-shard transaction
        let single_tx = test_transaction(1);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(single_tx)),
            LocalTimestamp::ZERO,
        );

        // Add a cross-shard transaction
        let cross_tx = test_cross_shard_transaction(50);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(cross_tx)),
            LocalTimestamp::ZERO,
        );

        // Not at limit: all TXs should be allowed
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::ZERO, None);
        assert_eq!(ready.len(), 2);
    }

    #[test]
    fn test_in_flight_counts_all_txns() {
        let topology_snapshot = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));

        assert_eq!(mempool.in_flight(), 0);

        let single_tx = test_transaction(200);
        let single_hash = single_tx.hash();
        let cross_tx = test_cross_shard_transaction(1);
        let cross_hash = cross_tx.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(single_tx.clone())),
            LocalTimestamp::ZERO,
        );
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(cross_tx.clone())),
            LocalTimestamp::ZERO,
        );
        assert_eq!(mempool.in_flight(), 0, "Pending TXs do not count");

        // Block 1 commits both txs — both transition Pending → Committed.
        let block1 = make_live_block(
            ShardId::leaf(1, 0),
            BlockHeight::new(1),
            1_000,
            ValidatorId::new(0),
            vec![Arc::new(single_tx), Arc::new(cross_tx)],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block1, 1_000));
        assert_eq!(mempool.in_flight(), 2, "Committed TXs hold state locks");

        // Block 2 carries the wave cert for the cross-shard tx — completes it.
        let block2 = make_live_block(
            ShardId::leaf(1, 0),
            BlockHeight::new(2),
            2_000,
            ValidatorId::new(0),
            vec![],
            vec![Arc::new(
                make_finalized_wave(BlockHeight::new(2), cross_hash, TransactionDecision::Accept)
                    .into(),
            )],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block2, 2_000));
        assert_eq!(mempool.in_flight(), 1, "Completed TX releases its lock");

        let block3 = make_live_block(
            ShardId::leaf(1, 0),
            BlockHeight::new(3),
            3_000,
            ValidatorId::new(0),
            vec![],
            vec![Arc::new(
                make_finalized_wave(
                    BlockHeight::new(3),
                    single_hash,
                    TransactionDecision::Accept,
                )
                .into(),
            )],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block3, 3_000));
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
        let mut mempool = MempoolCoordinator::with_config(ShardId::ROOT, config);
        let topology_snapshot = make_test_topology();

        let now = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), now);

        let ready = mempool.ready_transactions(10, 0, 0, now, None);
        assert_eq!(ready.len(), 1, "Zero dwell time should select immediately");
    }

    #[test]
    fn test_dwell_time_default_150ms() {
        // Default config has 150ms dwell time
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        let topology_snapshot = make_test_topology();

        let submitted_at = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), submitted_at);

        // At t=10.1s — not yet eligible (100ms < 150ms)
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_100), None);
        assert_eq!(
            ready.len(),
            0,
            "Should not select before 150ms default dwell"
        );

        // At t=10.15s — eligible (150ms >= 150ms)
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_150), None);
        assert_eq!(ready.len(), 1, "Should select after 150ms default dwell");
    }

    #[test]
    fn test_dwell_time_filters_recent_transactions() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(500),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::ROOT, config);
        let topology_snapshot = make_test_topology();

        // Submit at t=10s
        let submitted_at = LocalTimestamp::from_millis(10_000);
        let tx = test_transaction(1);
        mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), submitted_at);

        // Still at t=10s — dwell time not met
        let ready = mempool.ready_transactions(10, 0, 0, submitted_at, None);
        assert_eq!(ready.len(), 0, "Should not select before dwell time");

        // Advance to t=10.3s — still not enough
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_300), None);
        assert_eq!(
            ready.len(),
            0,
            "Should not select before dwell time elapses"
        );

        // Advance to t=10.5s — exactly at dwell time
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(10_500), None);
        assert_eq!(ready.len(), 1, "Should select after dwell time elapses");
    }

    #[test]
    fn test_dwell_time_mixed_eligibility() {
        let config = MempoolConfig {
            min_dwell_time: Duration::from_millis(200),
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::ROOT, config);
        let topology_snapshot = make_test_topology();

        // Submit tx1 at t=1s
        let tx1 = test_transaction(1);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx1)),
            LocalTimestamp::from_millis(1_000),
        );

        // Submit tx2 at t=1.3s
        let tx2 = test_transaction(2);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx2)),
            LocalTimestamp::from_millis(1_300),
        );

        // At t=1.4s — tx1 has 400ms dwell (eligible), tx2 has 100ms (not eligible).
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(1_400), None);
        assert_eq!(ready.len(), 1, "Only tx1 should be eligible");

        // At t=1.5s — both eligible
        let ready = mempool.ready_transactions(10, 0, 0, LocalTimestamp::from_millis(1_500), None);
        assert_eq!(ready.len(), 2, "Both should be eligible");
    }

    // ─── validity-window admission + pending sweep ──────────────────────

    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<Verified<RoutableTransaction>> {
        use hyperscale_types::test_utils::test_notarized_transaction_v1;
        use hyperscale_types::{TimestampRange, routable_from_notarized_v1};
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(end_ms),
        );
        Arc::new(verified(
            routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"),
        ))
    }

    /// Force-set `current_ts` for tests that need to control the admission /
    /// sweep clock without going through a full block commit.
    fn set_current_ts(mempool: &mut MempoolCoordinator, ts: WeightedTimestamp) {
        mempool.current_ts = ts;
    }

    #[test]
    fn rpc_submit_rejects_expired_transaction() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(2_000));

        let tx = tx_with_end(1, 1_000); // expired well before now
        let actions = mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::clone(&tx),
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty(), "expired tx should be silently rejected");
        assert!(
            mempool.status(&tx.hash()).is_none(),
            "expired tx must not enter the pool"
        );
    }

    #[test]
    fn gossip_drops_expired_transaction() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(2_000));

        let tx = tx_with_end(1, 1_000);
        let actions = mempool.on_transaction_gossip(
            &topology_snapshot,
            Arc::clone(&tx),
            false,
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty());
        assert!(mempool.status(&tx.hash()).is_none());
    }

    #[test]
    fn rpc_submit_admits_in_window_transaction() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(500));

        let tx = tx_with_end(1, 1_000); // end_exclusive > now
        mempool.on_submit_transaction(&topology_snapshot, Arc::clone(&tx), LocalTimestamp::ZERO);
        assert!(matches!(
            mempool.status(&tx.hash()),
            Some(TransactionStatus::Pending)
        ));
    }

    #[test]
    fn cleanup_expired_pending_drops_only_past_expiry_entries() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(500));

        let early = tx_with_end(1, 1_000); // alive
        let later = tx_with_end(2, 60_000); // alive
        mempool.on_submit_transaction(&topology_snapshot, Arc::clone(&early), LocalTimestamp::ZERO);
        mempool.on_submit_transaction(&topology_snapshot, Arc::clone(&later), LocalTimestamp::ZERO);
        assert_eq!(mempool.len(), 2);

        // Advance past `early`'s end_exclusive but not `later`'s.
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(1_500));
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
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(500));

        let tx = tx_with_end(1, 1_000);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(&topology_snapshot, Arc::clone(&tx), LocalTimestamp::ZERO);

        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(1_500));
        let dropped = mempool.cleanup_expired_pending();
        assert_eq!(dropped, 1);

        // Pending sweep does not tombstone — re-submission is rejected by
        // the admission check, not by the tombstone set. Confirm both: the
        // tombstone set stays empty, AND a fresh submission past expiry is
        // rejected via the admission path.
        assert!(!mempool.is_tombstoned(&tx_hash));
        let actions = mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::clone(&tx),
            LocalTimestamp::ZERO,
        );
        assert!(actions.is_empty(), "re-submission past expiry rejected");
        assert!(mempool.status(&tx_hash).is_none());
    }
}
