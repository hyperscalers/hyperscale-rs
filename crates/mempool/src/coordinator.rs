//! Mempool coordinator: admission, eligibility, and lifecycle of pending
//! transactions.
//!
//! Owns the per-validator transaction pool and the bookkeeping that surrounds
//! it: a [`TxStore`] of pending transactions, a [`TombstoneStore`] for
//! recently decided hashes, and an [`ExpectedTxs`] sub-machine that backfills
//! cross-shard transactions referenced by remote provisions before their
//! source-shard gossip arrives.
//!
//! Nothing here decides who conflicts with whom. Two transactions reaching
//! one cell are both offered; execution composes them into a batch and
//! sequences them there, under a compatibility rule the mempool cannot see
//! and would only approximate.
//!
//! # Backpressure
//!
//! Two limits gate proposal and ingress:
//! - [`MAX_UNSETTLED_TXS`] (a protocol constant in `hyperscale-types`) caps
//!   how many transactions this shard's chain may hold committed and
//!   unsettled at once, so a shard that is not settling admits less until
//!   it does. A count rather than a weight, because every block is already
//!   capped per dimension on its own content. Not operator-tunable: every
//!   replica has to price the same headroom off the same chain content, and
//!   the figure selection reads comes from the parent header rather than
//!   from local state.
//! - [`MempoolConfig::max_pending`] caps RPC-submitted pending transactions
//!   so that arrival rate exceeding processing capacity translates to
//!   rejected submissions rather than unbounded memory growth. Operator-
//!   tunable: deployments with different RAM budgets pick different values.
//! - [`MempoolConfig::max_pool`] is the ceiling on the pool itself,
//!   whatever a transaction arrived by. What ordinarily bounds the pool is
//!   the admission deadline, which is read against the committed clock —
//!   and that clock only moves on commit. A shard that cannot commit
//!   therefore sweeps nothing and expires nothing while gossip keeps
//!   arriving, which is exactly when the node is under stress. The
//!   ceiling refuses rather than evicts, and a transaction it refuses is
//!   still reachable: what a block names is fetched, and the fetch path
//!   is not subject to it.
//!
//! # Cross-shard DA
//!
//! Cross-shard transactions referenced by remote provisions must be locally
//! retrievable to participate in execution. `ExpectedTxs` waits an
//! [`EXPECTED_TX_GRACE`] window for source-shard gossip; past the grace
//! period it falls back to a BFT-weighted fetch from the source committee,
//! and drops entries past `RETENTION_HORIZON`.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchIds, FetchRequest, ProtocolEvent};
use hyperscale_engine::legs::Classified;
use hyperscale_metrics::{
    record_expected_tx_dropped, record_transaction_aborted, record_transaction_rejected,
};
use hyperscale_types::{
    BlockHeight, CertifiedBlock, CompletedRecovery, Deadline, DeclaredWork, ForkFence,
    LocalTimestamp, MAX_TXS_PER_BLOCK, MAX_UNSETTLED_TXS, MessageClass, RETENTION_HORIZON, ShardId,
    ShardTrie, TopologySnapshot, Transaction, TransactionDecision, TransactionStatus, TxHash,
    TxResolution, Verified, WeightedTimestamp, Window, budget_admits_block, caps_admit_transaction,
};
use serde::Deserialize;
use tracing::instrument;

use crate::expected_txs::{EXPECTED_TX_GRACE, ExpectedTxs};
use crate::tombstones::TombstoneStore;
use crate::tx_store::TxStore;

/// Default minimum dwell time for transactions before they become eligible for block inclusion.
///
/// Allows time for transaction gossip to propagate across validators before proposal,
/// improving batching and fairness.
pub const DEFAULT_MIN_DWELL_TIME: Duration = Duration::from_millis(150);

/// Default RPC-pending backpressure limit (≈ 2× block size).
pub const DEFAULT_MAX_PENDING: usize = 8192;

/// Default ceiling on pool entries, eight full blocks' worth — four times
/// the RPC backpressure limit, so it bites only where that limit is not
/// the thing doing the bounding.
pub const DEFAULT_MAX_POOL: usize = 8 * MAX_TXS_PER_BLOCK;

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

    /// Ceiling on pool entries however they arrived — the memory bound,
    /// where `max_pending` is the backpressure knob.
    ///
    /// Unlike `max_pending` this one gates gossip as well as submission,
    /// because gossip is the path that keeps arriving while the committed
    /// clock — the only thing that expires a pool entry — is stopped. A
    /// transaction refused here is not lost to consensus: the fetch path
    /// that answers what a block names is exempt.
    #[serde(default = "default_max_pool")]
    pub max_pool: usize,

    /// Minimum time a transaction must spend in the mempool before it can be selected
    /// for block inclusion. Transactions that have not yet met this dwell time are
    /// skipped during proposal selection but remain in the ready set.
    ///
    /// Set to zero to disable (default).
    #[serde(default = "default_min_dwell_time")]
    pub min_dwell_time: Duration,
}

const fn default_max_pending() -> usize {
    DEFAULT_MAX_PENDING
}

const fn default_max_pool() -> usize {
    DEFAULT_MAX_POOL
}

const fn default_min_dwell_time() -> Duration {
    DEFAULT_MIN_DWELL_TIME
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            max_pool: DEFAULT_MAX_POOL,
            min_dwell_time: DEFAULT_MIN_DWELL_TIME,
        }
    }
}

/// How a transaction reached admission — which decides whether the
/// pool's ceiling applies to it.
#[derive(Debug, Clone, Copy)]
enum Offered {
    /// Nobody here asked for it: gossip, or an RPC submission. Arrival is
    /// driven from outside and unbounded, and a refusal costs nothing
    /// that cannot be recovered — what a block names is fetched.
    Unbidden,
    /// A fetch answering an id this node asked for. Bounded already by
    /// what it asked for, and refusing it would strand the block or the
    /// tick that asked.
    Asked,
}

/// Mempool memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolMemoryStats {
    /// Transactions held in the main pool.
    pub pool: usize,
    /// Pool entries still awaiting inclusion.
    pub pending: usize,
    /// Tombstone entries (terminal-state dedup).
    pub tombstones: usize,
}

impl MempoolMemoryStats {
    /// Every readout as a `(field, value)` pair for the metrics backend.
    ///
    /// The destructure is the drift guard: a field added above does not
    /// compile here until it is given a gauge.
    #[must_use]
    pub fn gauges(&self) -> Vec<(&'static str, usize)> {
        let Self {
            pool,
            pending,
            tombstones,
        } = *self;
        vec![
            ("pool", pool),
            ("pending", pending),
            ("tombstones", tombstones),
        ]
    }
}

/// Entry in the transaction pool. Carries the body alongside admission
/// metadata. The same `Arc` is also held by the shared [`TxStore`] so
/// the network worker can serve fetches without touching the mempool;
/// in-mempool reads go through this field directly.
#[derive(Debug)]
struct PoolEntry {
    tx: Arc<Verified<Transaction>>,
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
    /// The last instant this shard could still include the transaction:
    /// its validity end, or the delivery window's close where this shard
    /// may only be delivering for it. What the pool, the tombstone and
    /// the body are retained to.
    admissible_until: WeightedTimestamp,
    /// The core's verdict on a divided transaction, heard off its
    /// certificates before this shard's own leg finalized here. The
    /// terminal lands when it does.
    verdict: Option<TransactionDecision>,
}

/// Mempool state machine.
///
/// Handles transaction lifecycle from submission to completion.
///
/// The pool is a `BTreeMap` so hash order is the iteration order, and hash
/// order is the order transactions are offered in: selection walks the
/// pool once, filters, ranks what is left by the priority its sender
/// burned, and takes each entry the drain and the caps still have room
/// for. There is no index beside it — eligibility is a property of the
/// entry the walk is already holding, so a set maintained alongside would
/// have to be invalidated by every commit, settlement and fence for a scan
/// the pool's own bound already keeps small, and the ranking is a sort of
/// what the walk produced.
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

    /// Cross-shard transactions parked outside contention until their
    /// engagement evidence — the payer shard's bundle — arrives. Value is
    /// the payer shard the evidence must come from. A parked transaction
    /// is pooled, fetchable, and reported `Pending`, but holds no ready
    /// slot and no conflict keys, so a payer that never commits cannot
    /// camp this shard's keys through the deferral set.
    parked_engagement: HashMap<TxHash, ShardId>,

    /// Engagement evidence observed before its transaction arrived —
    /// `tx → (payer shard, deadline)`. Consulted at admission so the
    /// bundle-before-transaction arrival order does not park an already
    /// engaged transaction; entries expire on the retention tier.
    engagement_seen: HashMap<TxHash, (ShardId, WeightedTimestamp)>,

    /// Configuration for mempool behavior.
    config: MempoolConfig,

    /// This validator's home shard — the projection target for the
    /// declared keys admission reads off a transaction.
    local_shard: ShardId,

    /// Gossip-timed fork fences. While engaged, admission rejects any
    /// transaction touching a fenced shard — no point starting cross-shard
    /// work bound to a committee that is provably forked. A liveness
    /// quiesce only; safety rests on the provision fence. Held until the
    /// shard's recovery completes, so mid-recovery txs can't flow back in
    /// and stall on fenced provisions.
    fork_fence: ForkFence,

    /// The dispatch seam's clock reading, pushed by [`Self::set_time`]
    /// before each handler runs. Consumed by the deferral statistics only;
    /// admission and selection read the timestamps their handlers receive.
    now: LocalTimestamp,
}

impl std::fmt::Debug for MempoolCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MempoolCoordinator")
            .field("pool_size", &self.pool.len())
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
            current_height: BlockHeight::new(0),
            current_ts: WeightedTimestamp::ZERO,
            expected_txs: ExpectedTxs::new(),
            parked_engagement: HashMap::new(),
            engagement_seen: HashMap::new(),
            config,
            local_shard,
            fork_fence: ForkFence::new(),
            now: LocalTimestamp::ZERO,
        }
    }

    /// Push the dispatch seam's clock reading, before any handler runs.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Reference to the shared body store. Callers that need to read
    /// bodies (e.g. the network worker thread) clone the Arc out and use
    /// it directly to avoid taking a mempool lock.
    #[must_use]
    pub const fn tx_store(&self) -> &Arc<TxStore> {
        &self.tx_store
    }

    /// Try to admit a single transaction. Returns `(was_newly_admitted,
    /// cross_shard)`. Source-agnostic beyond `offered`: callers append the
    /// appropriate `Continuation(TransactionsAdmitted)` and any
    /// source-specific actions.
    fn admit_internal(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: &Arc<Verified<Transaction>>,
        offered: Offered,
        submitted_locally: bool,
        now: LocalTimestamp,
    ) -> Option<bool> {
        let hash = tx.hash();

        if self.pool.contains_key(&hash) || self.is_tombstoned(&hash) {
            return None;
        }

        // The ceiling, above the deadline rule below: that rule reads the
        // committed clock, which a shard that cannot commit does not
        // advance, so nothing here expires for as long as the halt lasts
        // while gossip keeps arriving.
        if matches!(offered, Offered::Unbidden) && self.pool.len() >= self.config.max_pool {
            record_transaction_rejected("pool_full");
            tracing::debug!(
                tx_hash = ?hash,
                pool = self.pool.len(),
                "Refusing an offered transaction — the pool is at its ceiling"
            );
            return None;
        }

        // Reject once nothing here could include it: past its validity
        // end, or past the delivery window where this shard may only be
        // delivering. The proposer applies the exact rule; this is the
        // admission boundary that keeps dead entries out of the pool.
        let cross_shard = topology_snapshot.is_cross_shard_transaction(tx);
        let admissible_until = self.admissible_until(topology_snapshot, tx, cross_shard);
        if admissible_until <= self.current_ts {
            tracing::debug!(
                tx_hash = ?hash,
                until_ms = admissible_until.as_millis(),
                now_ms = self.current_ts.as_millis(),
                "Rejecting expired transaction"
            );
            return None;
        }

        // The declared vector enters the block's caps at face value, so
        // a transaction past its own ceiling in any dimension is refused
        // here rather than allowed to own a block's whole allowance for
        // one signature.
        if !caps_admit_transaction(tx.work()) {
            tracing::debug!(
                tx_hash = ?hash,
                work = ?tx.work(),
                "Rejecting transaction declaring more than the protocol admits of one"
            );
            return None;
        }

        // And the fee ceiling its sender signed, against the table in
        // force at this node's head. A filter and not the verdict: what
        // decides admissibility is the table the block's own window
        // names, judged where the block is built, and this node's head
        // is a different reading of it across a fold.
        //
        // Which is why it only declines to pool and never evicts. A
        // reading taken at the wrong anchor may keep out what no block
        // at the current level could carry — cheaply, and on every shard,
        // since the table is network-wide and a counterpart reads the
        // same figure as the payer outside that window. What it must not
        // do is delete: an entry the level outgrew is reclaimed by its
        // own deadline, where nothing has to guess which window was
        // right.
        let price = tx.price(&topology_snapshot.prices());
        if price > tx.body().max_fee {
            tracing::debug!(
                tx_hash = ?hash,
                price,
                max_fee = tx.body().max_fee,
                "Rejecting transaction whose ceiling the table has outgrown"
            );
            return None;
        }

        // Fork-fence quiesce: reject a tx touching a shard under a local
        // fork fence. Starting cross-shard work bound to a provably-forked
        // committee only wastes a round — the provisions it would need are
        // fenced anyway. Skipped entirely when no fence is engaged (the
        // ordinary case), so honest admission pays nothing.
        if !self.fork_fence.is_empty()
            && self
                .fork_fence
                .iter()
                .any(|(s, _)| topology_snapshot.involves_shard(s, tx))
        {
            tracing::debug!(
                tx_hash = ?hash,
                "Rejecting transaction bound to a fork-fenced shard"
            );
            return None;
        }

        // A cross-shard transaction at a non-payer shard enters
        // contention only once its engagement evidence exists.
        if let Some(payer_shard) = self.engagement_park_target(topology_snapshot, tx, cross_shard) {
            self.parked_engagement.insert(hash, payer_shard);
        }
        self.tx_store.insert(Arc::clone(tx));
        self.pool.insert(
            hash,
            PoolEntry {
                tx: Arc::clone(tx),
                status: TransactionStatus::Pending,
                cross_shard,
                submitted_locally,
                admitted_at: now,
                admissible_until,
                verdict: None,
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
        tx: Arc<Verified<Transaction>>,
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

        match self.admit_internal(topology_snapshot, &tx, Offered::Unbidden, true, now) {
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
        tx: Arc<Verified<Transaction>>,
        submitted_locally: bool,
        now: LocalTimestamp,
    ) -> Vec<Action> {
        match self.admit_internal(
            topology_snapshot,
            &tx,
            Offered::Unbidden,
            submitted_locally,
            now,
        ) {
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
        txs: Vec<Arc<Verified<Transaction>>>,
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
                .admit_internal(topology_snapshot, &tx, Offered::Asked, false, now)
                .is_some()
            {
                admitted.push(tx);
            } else if self.expected_txs.forget(&hash) {
                moot.push(hash);
            }
        }
        let mut actions = Vec::new();
        if !moot.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::Transactions(moot)));
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
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(ids),
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
    fn evict_terminal(&mut self, tx_hash: TxHash) {
        let Some(entry) = self.pool.remove(&tx_hash) else {
            return;
        };

        // Tombstone the hash so it can't be re-admitted. Body stays in
        // `tx_store` so peers can still fetch by hash; both expire on the
        // same instant via `prune_tombstones`.
        self.tombstones.tombstone(tx_hash, entry.admissible_until);
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
    /// Lock release filters declared keys to the local shard, like its
    /// lock/unlock siblings — only locally-routed keys were ever locked.
    /// At a reshape boundary the head trie may have re-routed keys this
    /// chain locked; skipping them is sound because a terminated chain's
    fn abort_one(&mut self, tx_hash: TxHash) -> Option<Action> {
        let entry = self.pool.remove(&tx_hash)?;
        self.tombstones.tombstone(tx_hash, entry.admissible_until);
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
    /// finalization in a later block, and a terminated chain commits
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

    /// Engage the gossip-timed fork-fence quiesce for `shard`: stop admitting
    /// transactions that touch it. Idempotent; a liveness measure only. See
    /// [`ForkFence::engage`] for the tightening and replay rules.
    pub fn engage_fork_fence(
        &mut self,
        shard: ShardId,
        fork_height: BlockHeight,
        completed: &BTreeMap<ShardId, CompletedRecovery>,
    ) {
        self.fork_fence.engage(shard, fork_height, completed);
    }

    /// Process a committed block: admit what it includes, mark it
    /// committed, and sweep the cross-shard expectations it satisfies or
    /// outlives.
    ///
    /// What the block's finalizations settle about the transactions
    /// they name arrives separately, through [`Self::on_resolutions`]:
    /// a finalization's name means different things on different
    /// entries, and the execution ledger is what knows which.
    #[instrument(skip(self, certified), fields(
        height = certified.block().height().inner(),
        tx_count = certified.block().transaction_count()
    ))]
    #[allow(clippy::too_many_lines)] // sequential orchestration: block-include, status marking, expected-tx sweep
    pub fn on_block_committed(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let block = certified.block();
        let height = block.height();
        let mut actions = Vec::new();

        self.current_height = height;
        // A deadline clock, by the rule
        // [`WeightedTimestamp::advanced_by_commit`] states: the admission
        // gate, the expiry sweep and the tombstone prune all key off this,
        // and an artifact a clock running backwards lets through is one
        // this pool already decided about.
        self.current_ts = self
            .current_ts
            .advanced_by_commit(block.header().parent_qc().weighted_timestamp());

        // A gossip-timed fork fence holds until the attested recovery for
        // its shard completes — clearing on the fold would reopen admission
        // for the whole recovery window, letting cross-shard txs take locks
        // and stall on fenced provisions.
        if !self.fork_fence.is_empty() {
            self.fork_fence
                .clear_completed(topology_snapshot.completed_recoveries());
        }

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
            let verified: Arc<Verified<Transaction>> = match (**tx).clone().into_verified() {
                Ok(v) => Arc::new(v),
                Err(raw) => Arc::new(Verified::<Transaction>::from_persisted(raw)),
            };
            let cross_shard = topology_snapshot.is_cross_shard_transaction(tx);
            let admissible_until = self.admissible_until(topology_snapshot, tx, cross_shard);
            self.pool.entry(hash).or_insert_with(|| {
                tracing::debug!(
                    tx_hash = ?hash,
                    height = height.inner(),
                    "Added committed transaction to mempool"
                );
                self.tx_store.insert(Arc::clone(&verified));
                PoolEntry {
                    admissible_until,
                    tx: verified,
                    status: TransactionStatus::Pending, // Will be updated by execution
                    cross_shard,
                    submitted_locally: false, // Fetched for block processing
                    // Block-committed entries skip the dwell path entirely
                    // (next loop transitions them straight to Committed +
                    // takes locks), so the anchor is never read.
                    admitted_at: LocalTimestamp::ZERO,
                    verdict: None,
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
            actions.push(Action::AbandonFetch(FetchIds::Transactions(
                abandoned_tx_fetches,
            )));
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
            for entry in provision.transactions() {
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
            actions.push(Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::Transactions(ids),
                shard: source_shard,
                preferred: None,
                class: Some(MessageClass::Recovery),
            }));
        }

        // Hard horizon: any expected-tx that survived grace + every realistic
        // fetch retry past `RETENTION_HORIZON` is provably moot — every tick
        // that needed it has long since timed out via MAX_FINALIZATION_DELAY. Drop with
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
            actions.push(Action::AbandonFetch(FetchIds::Transactions(abandoned)));
        }

        self.prune_engagement_state();

        actions
    }

    /// Apply what the execution coordinator settled about each
    /// transaction — off a committed block's finalizations, or off a
    /// core's certificates.
    ///
    /// A decision of this shard's chain is terminal wherever the entry
    /// stands. A leg finalizing here is its own state, and the
    /// transaction stays pending its core's verdict; that verdict is
    /// terminal once the leg has finalized, and is held for it
    /// otherwise, since a replica behind on its own chain can hear the
    /// core before it commits the leg. Nothing is said of a transaction
    /// the pool no longer holds.
    pub fn on_resolutions(&mut self, resolutions: &[(TxHash, TxResolution)]) -> Vec<Action> {
        let mut actions = Vec::new();
        for &(tx_hash, resolution) in resolutions {
            match resolution {
                TxResolution::Decided(decision) => actions.extend(self.complete(tx_hash, decision)),
                TxResolution::LegFinalized => {
                    let Some(entry) = self.pool.get_mut(&tx_hash) else {
                        continue;
                    };
                    // A shard with legs on both sides of the core runs
                    // them as two members, and the second finalizes
                    // into the state the first already reported.
                    if matches!(entry.status, TransactionStatus::LegFinalized) {
                        continue;
                    }
                    entry.status = TransactionStatus::LegFinalized;
                    actions.push(Action::EmitTransactionStatus {
                        tx_hash,
                        status: TransactionStatus::LegFinalized,
                        cross_shard: entry.cross_shard,
                        submitted_locally: entry.submitted_locally,
                    });
                    if let Some(verdict) = entry.verdict {
                        actions.extend(self.complete(tx_hash, verdict));
                    }
                }
                TxResolution::CoreDecided(decision) => {
                    let Some(entry) = self.pool.get_mut(&tx_hash) else {
                        continue;
                    };
                    if matches!(entry.status, TransactionStatus::LegFinalized) {
                        actions.extend(self.complete(tx_hash, decision));
                    } else {
                        entry.verdict = Some(decision);
                    }
                }
            }
        }
        actions
    }

    /// Drive a transaction to `Completed(decision)`: emit the terminal
    /// status and evict and tombstone the entry.
    fn complete(&mut self, tx_hash: TxHash, decision: TransactionDecision) -> Vec<Action> {
        let mut actions = Vec::new();

        if let Some(entry) = self.pool.get(&tx_hash) {
            if matches!(decision, TransactionDecision::Aborted) {
                record_transaction_aborted();
            }
            actions.push(Action::EmitTransactionStatus {
                tx_hash,
                status: TransactionStatus::Completed(decision),
                cross_shard: entry.cross_shard,
                submitted_locally: entry.submitted_locally,
            });

            self.evict_terminal(tx_hash);
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
    /// peer shard's finalization, which can stall independently. Locking
    /// them here would permanently defer future local cross-shard txs that
    /// share those remote nodes, cascading the stall.
    /// Remove a transaction's nodes from the locked set.
    /// Called when a transaction transitions FROM a lock-holding state (evicted).
    ///
    /// Also promotes any blocked transactions that were waiting on these nodes.
    /// Scoped to local-shard nodes; mirrors [`Self::add_locked_nodes`].
    /// Add a transaction to ready tracking when it becomes Pending. The
    /// store decides whether it lands in the ready or deferred set based on
    /// currently-locked and already-claimed nodes.
    /// The payer shard a cross-shard transaction must show engagement
    /// evidence from before entering contention, or `None` when the
    /// The last instant this shard could still include `tx`.
    ///
    /// Its validity end, except where this shard only delivers for it —
    /// frozen divided against the head trie with this shard outside the
    /// core and every leg here a delivery — which is admissible to the
    /// delivery window's close. The proposer reads the same predicate
    /// against its block's own anchor, so what this widens is
    /// retention: the body and the tombstone are held while a delivery
    /// could still be composed from them, and for nothing else.
    fn admissible_until(
        &self,
        topology_snapshot: &TopologySnapshot,
        tx: &Transaction,
        cross_shard: bool,
    ) -> WeightedTimestamp {
        let validity_end = tx.validity_range().end_timestamp_exclusive;
        let delivers = cross_shard
            && Classified::freeze(tx.legs(), tx.owners(), topology_snapshot.shard_trie())
                .only_delivers_at(self.local_shard);
        if delivers {
            Window::Delivery.of(Deadline::of(validity_end)).end
        } else {
            validity_end
        }
    }

    /// transaction is immediately ready: not VM, not cross-shard, this
    /// shard is the payer's, or the evidence already arrived.
    fn engagement_park_target(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        tx: &Arc<Verified<Transaction>>,
        cross_shard: bool,
    ) -> Option<ShardId> {
        if !cross_shard {
            return None;
        }
        let payer_shard = topology_snapshot
            .shard_trie()
            .shard_for_prefix(tx.body().fee_payer);
        if payer_shard == self.local_shard {
            return None;
        }
        let engaged = self
            .engagement_seen
            .get(&tx.hash())
            .is_some_and(|(seen, _)| *seen == payer_shard);
        if engaged {
            self.engagement_seen.remove(&tx.hash());
            return None;
        }
        Some(payer_shard)
    }

    /// Record engagement evidence: a verified or committed bundle from
    /// `source` naming `tx_hashes`. Promotes matching parked transactions
    /// into contention; evidence for transactions not yet admitted is
    /// remembered until the retention tier expires it, covering the
    /// bundle-before-transaction arrival order.
    pub fn on_engagement_evidence(
        &mut self,
        source: ShardId,
        tx_hashes: impl IntoIterator<Item = TxHash>,
    ) {
        let deadline = self.current_ts.plus(RETENTION_HORIZON);
        for hash in tx_hashes {
            match self.parked_engagement.get(&hash) {
                Some(&payer_shard) if payer_shard == source => {
                    // Unparked: a Pending entry no longer parked is
                    // selectable by construction.
                    self.parked_engagement.remove(&hash);
                }
                Some(_) => {}
                None => {
                    if !self.pool.contains_key(&hash) && !self.is_tombstoned(&hash) {
                        self.engagement_seen
                            .entry(hash)
                            .or_insert((source, deadline));
                    }
                }
            }
        }
    }

    /// The number of transactions parked awaiting engagement evidence.
    #[must_use]
    pub fn parked_count(&self) -> usize {
        self.parked_engagement.len()
    }

    /// Drop parked entries whose transaction left `Pending` and remembered
    /// evidence past its deadline.
    fn prune_engagement_state(&mut self) {
        let pool = &self.pool;
        self.parked_engagement.retain(|hash, _| {
            pool.get(hash)
                .is_some_and(|entry| entry.status == TransactionStatus::Pending)
        });
        let now = self.current_ts;
        self.engagement_seen
            .retain(|_, (_, deadline)| *deadline > now);
    }

    /// The transactions this shard offers for the next block, in hash
    /// order, as many as the drain has places for and the block's caps
    /// admit over their shares on this shard.
    ///
    /// Availability decides who is eligible — admitted, past its dwell,
    /// not parked on engagement evidence — and nothing here decides who
    /// conflicts with whom. Two transactions touching one cell are both
    /// offered; execution composes them into one batch and sequences
    /// them there.
    ///
    /// `in_flight` is what the chain says this shard still holds, read
    /// off the parent header rather than from local state, so every
    /// replica prices the same headroom. `max_count` is the wire cap on
    /// a block's transaction list. `trie` places each transaction's
    /// shares, so the caps are judged the way admission judges them.
    ///
    /// `engaged` answers whether a cross-shard transaction's payer
    /// evidence rides the proposal being built, which the pool cannot
    /// see: [`Self::parked_engagement`] holds one until the evidence is
    /// *observed*, where a proposer needs it in the bundle it is about
    /// to send or already absorbed, and both readings live in the
    /// coordinators the node owns. It enters here rather than filtering
    /// the result because a transaction the proposer cannot carry has
    /// still taken a place and a share of the budget by then, and
    /// nothing refills behind it — so a shard acting as counterpart for
    /// traffic whose bundles have not landed would offer a block far
    /// under its own caps while eligible transactions sat unoffered.
    /// Priority sharpens it: an unengaged transaction that paid takes
    /// the place of a lighter one that could actually go.
    ///
    /// # Performance
    ///
    /// `O(pool_size × log pool_size)`: every eligible entry is collected
    /// and ranked before any is taken, because the ranking is over the
    /// whole eligible set and no prefix of it answers who paid most.
    /// The fill that follows stops at the count, but the walk before it
    /// cannot.
    #[must_use]
    pub fn ready_transactions(
        &self,
        max_count: usize,
        in_flight: u64,
        trie: &ShardTrie,
        now: LocalTimestamp,
        engaged: impl Fn(&Arc<Verified<Transaction>>) -> bool,
    ) -> Vec<Arc<Verified<Transaction>>> {
        // The drain is a count: a shard that is not settling admits
        // fewer until it does, and none at the budget.
        let Some(places) = MAX_UNSETTLED_TXS.checked_sub(in_flight) else {
            return Vec::new();
        };
        let room = max_count.min(usize::try_from(places).unwrap_or(usize::MAX));

        let min_dwell = self.config.min_dwell_time;
        // Priority decides who is offered and hash decides the order
        // they are offered in. The eligible entries are sorted rather
        // than held in an index beside the pool, for the reason the pool
        // holds none: the walk already visits every entry to judge
        // eligibility, and a set maintained alongside would have to be
        // invalidated by every commit, settlement and fence.
        let mut candidates: Vec<(Reverse<u32>, TxHash, &PoolEntry)> = self
            .pool
            .iter()
            .filter(|(hash, entry)| {
                matches!(entry.status, TransactionStatus::Pending)
                    && !self.parked_engagement.contains_key(*hash)
                    && now.saturating_sub(entry.admitted_at) >= min_dwell
                    && engaged(&entry.tx)
            })
            .map(|(hash, entry)| (Reverse(entry.tx.body().priority_bp), *hash, entry))
            .collect();
        candidates.sort_unstable_by_key(|(priority, hash, _)| (*priority, *hash));

        let mut filled = DeclaredWork::ZERO;
        let mut selected: Vec<(TxHash, Arc<Verified<Transaction>>)> = Vec::new();
        for (_, hash, entry) in candidates {
            if selected.len() >= room {
                break;
            }
            // The caps decide how far down the list the offer goes. A
            // transaction too heavy for what is left in any dimension is
            // passed over rather than ending selection — otherwise one
            // outsized envelope would stall every lighter one behind it
            // until the block cleared.
            let classified = Classified::freeze(entry.tx.legs(), entry.tx.owners(), trie);
            let next = filled.saturating_add(classified.local_work(&entry.tx, self.local_shard));
            if !budget_admits_block(&next) {
                continue;
            }
            filled = next;
            selected.push((hash, Arc::clone(&entry.tx)));
        }
        // Offered in hash order whatever anyone paid: a priority buys a
        // place in the block and never a position in it, so the block a
        // proposer builds is the block every voter checks the ordering
        // of.
        selected.sort_unstable_by_key(|(hash, _)| *hash);
        selected.into_iter().map(|(_, tx)| tx).collect()
    }

    /// The number of transactions still awaiting inclusion, parked ones
    /// included — they occupy the pool whether or not they are currently
    /// selectable.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pool
            .values()
            .filter(|entry| matches!(entry.status, TransactionStatus::Pending))
            .count()
    }

    /// Transactions still awaiting inclusion whose validity window opened
    /// before `wt`. Parked ones included: a reshape successor refuses
    /// them all until it can prove them absent from what its predecessor
    /// committed, so being unselectable for another reason doesn't make
    /// the question moot.
    #[must_use]
    pub fn pending_opening_before(&self, wt: WeightedTimestamp) -> Vec<TxHash> {
        self.pool
            .iter()
            .filter(|(_, entry)| {
                matches!(entry.status, TransactionStatus::Pending)
                    && entry.tx.validity_range().start_timestamp_inclusive < wt
            })
            .map(|(hash, _)| *hash)
            .collect()
    }

    /// Check if we're at the pending transaction limit for RPC backpressure.
    ///
    /// When at this limit, new RPC transaction submissions are rejected to
    /// prevent unbounded mempool growth when arrival rate exceeds processing.
    #[must_use]
    pub fn at_pending_limit(&self) -> bool {
        self.pending_count() >= self.config.max_pending
    }

    /// Seed the committed frontier a restart resumes at.
    ///
    /// The admission gate compares a transaction's admissibility deadline
    /// against [`Self::current_ts`], and the only other thing that moves
    /// that clock is a commit. Left at zero the comparison is vacuous, so
    /// a restarted node admits every gossiped transaction — expired ones
    /// included — until its first commit lands. Execution's commit
    /// frontier seeds from the same recovered tip for the same reason.
    pub const fn seed_committed(&mut self, height: BlockHeight, ts: WeightedTimestamp) {
        self.current_height = height;
        self.current_ts = ts;
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
    pub fn get_transaction(&self, hash: &TxHash) -> Option<Arc<Verified<Transaction>>> {
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
            pending: self.pending_count(),
            tombstones: self.tombstones.len_tombstones(),
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
    ) -> Vec<(TxHash, TransactionStatus, Arc<Verified<Transaction>>)> {
        self.pool
            .iter()
            .filter(|(_, entry)| !matches!(entry.status, TransactionStatus::Completed(_)))
            .map(|(hash, entry)| (*hash, entry.status.clone(), Arc::clone(&entry.tx)))
            .collect()
    }

    /// Drop tombstones whose own deadline has passed `current_ts`, and
    /// drop the matching bodies from [`Self::tx_store`]. The deadline is
    /// the `admissible_until` that let the transaction in — its validity
    /// end, or the close of the delivery window that end opens where this
    /// shard only delivers for it — so a tombstone stops refusing exactly
    /// where admission stops taking it. Past that the validator-side
    /// validity check rejects any re-submission, so the tombstone is no
    /// longer load-bearing for correctness and the body is no longer
    /// fetchable. Anchored on `current_ts` (updated in
    /// `on_block_committed`).
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

    /// Drop the pool entries nothing here can still include or decide:
    /// `Pending` ones past what this shard could include them by, and
    /// `LegFinalized` ones past the horizon at which the execution
    /// ledger gives up the reclaim that would have decided them.
    ///
    /// Neither holds a state lock, so removal is safe without going
    /// through the terminal-eviction path. Re-submission past expiry is
    /// rejected at admission, so no tombstone is needed either; the body
    /// goes from [`Self::tx_store`] since nothing else needs it.
    ///
    /// The proposer-side filter already skips expired txs at selection
    /// time; this sweep is what keeps the pool from accumulating dead
    /// entries when expiry outpaces selection (e.g. a transient stall in
    /// cross-shard EC delivery delays inclusion past the window).
    ///
    /// It is also what reclaims a ceiling the price level outgrew. The
    /// level is judged where a block is built, against that block's own
    /// window, and the pool holds no window — so a pool that evicted on
    /// its head's reading would delete what the chain would still carry
    /// across a fold, for a transaction whose deadline reclaims it
    /// anyway. Admission filters on the head; only expiry deletes.
    ///
    /// Returns the number of entries dropped.
    pub fn cleanup_expired_pending(&mut self) -> usize {
        let now = self.current_ts;
        let expired: Vec<TxHash> = self
            .pool
            .iter()
            .filter(|(_, entry)| match entry.status {
                TransactionStatus::Pending => entry.admissible_until <= now,
                TransactionStatus::LegFinalized => {
                    Window::LegEntry.of(Deadline::of_transaction(&entry.tx)).end <= now
                }
                TransactionStatus::Committed(_) | TransactionStatus::Completed(_) => false,
            })
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.pool.remove(hash);
        }
        if !expired.is_empty() {
            self.tx_store.evict(expired.iter().copied());
        }
        self.prune_engagement_state();
        expired.len()
    }

    /// Everything still awaiting inclusion that a successor could still
    /// include: the pool's `Pending` entries whose validity window has
    /// not closed.
    ///
    /// [`Self::abort_in_flight`] terminalises what the chain committed;
    /// this is the rest. A `Pending` entry holds no locks, no tick and no
    /// certificate — it was never included — so it carries none of the
    /// state that makes an in-flight transaction impossible to move, and
    /// re-offering it costs a client the resubmission it would otherwise
    /// have to make itself.
    ///
    /// Read rather than drained: the pool dies with the chain either way,
    /// and leaving it intact keeps the engagement bookkeeping the entries
    /// participate in untouched.
    #[must_use]
    pub fn pending_for_handback(&self) -> Vec<Arc<Transaction>> {
        let now = self.current_ts;
        self.pool
            .values()
            .filter(|entry| matches!(entry.status, TransactionStatus::Pending))
            .filter(|entry| entry.admissible_until > now)
            .map(|entry| Arc::new((**entry.tx).clone()))
            .collect()
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
        TestCommittee, certify, install_stub_protocol_statics, make_finalization, make_live_block,
        stub_transaction, stub_transaction_declaring, test_prefix, test_principal,
        test_transaction, test_transaction_at_priority, test_transaction_with_prefixes,
        test_validity_range,
    };
    use hyperscale_types::{Address, MAX_BLOCK_COMPUTE, PrincipalAddr, Verified, WitnessSources};

    /// Test-only convenience: wrap any `Transaction` in a
    /// `Verified` witness via the test-only gate.
    fn verified(tx: Transaction) -> Verified<Transaction> {
        Verified::new_unchecked_for_test(tx)
    }
    use hyperscale_types::{
        Block, Finalization, MerkleInclusionProof, ProvisionEntry, Provisions, ShardId, ValidatorId,
    };

    use super::*;

    fn make_test_topology() -> TopologySnapshot {
        TestCommittee::new(4, 42).topology_snapshot(1)
    }

    /// Nominal block spacing used by tests to synthesize `weighted_timestamp_ms`
    /// from block heights. Ratios against retention constants preserve the
    /// "block count" intuition when reading test scenarios.
    const TEST_BLOCK_INTERVAL_MS: u64 = 500;

    /// Assemble a certified single-tx block carrying one finalization
    /// decision, with its QC timestamp stamped from the block height.
    fn certified_commit_block(
        height: BlockHeight,
        tx: Transaction,
        fw: Finalization,
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
            .map(|h| ProvisionEntry::new(*h, vec![]))
            .collect();
        let provision = Provisions::new(
            source_shard,
            ShardId::ROOT,
            height,
            WeightedTimestamp::ZERO,
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
                provisions: Arc::new(vec![Arc::new(provision.into())]),
                abandonment_records: Arc::new(Vec::new()),
                state_claims: Arc::new(Vec::new()),
                witness_sources: Arc::new(WitnessSources::empty()),
            },
            sealed @ Block::Sealed { .. } => sealed,
        };
        certify(block, height.inner() * TEST_BLOCK_INTERVAL_MS)
    }

    /// A block whose anchor sits below the one already committed does not
    /// move the pool's clock backwards.
    ///
    /// The admission gate, the expiry sweep and the tombstone prune all
    /// read this clock, and a transaction the pool already decided about
    /// comes back to life if it runs backwards. Sync-admitted blocks
    /// commit on QC attestation with no local vote, so the per-block
    /// floor the vote path enforces was never asked of them.
    #[test]
    fn the_pools_clock_does_not_run_backwards() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let committed = |height: u64, wt_ms: u64| {
            certify(
                make_live_block(
                    ShardId::ROOT,
                    BlockHeight::new(height),
                    1_234_567_890,
                    ValidatorId::new(0),
                    vec![],
                    vec![],
                ),
                wt_ms,
            )
        };

        mempool.on_block_committed(&topology_snapshot, &committed(1, 9_000));
        assert_eq!(mempool.current_ts, WeightedTimestamp::from_millis(9_000));

        mempool.on_block_committed(&topology_snapshot, &committed(2, 4_000));
        assert_eq!(
            mempool.current_ts,
            WeightedTimestamp::from_millis(9_000),
            "a regressed anchor holds the clock where it is",
        );

        mempool.on_block_committed(&topology_snapshot, &committed(3, 11_000));
        assert_eq!(
            mempool.current_ts,
            WeightedTimestamp::from_millis(11_000),
            "and it still advances",
        );
    }

    /// The pool's ceiling refuses what nobody here asked for, and lets
    /// through what this node fetched.
    ///
    /// What ordinarily bounds the pool is the admission deadline, read
    /// against the committed clock — and a shard that cannot commit does
    /// not advance that clock, so a halt sweeps nothing while gossip
    /// keeps arriving. A refusal costs nothing that cannot be recovered,
    /// which is why the fetch path answering what a block names is
    /// exempt.
    #[test]
    fn the_pools_ceiling_refuses_gossip_and_admits_a_fetch() {
        let topology_snapshot = make_test_topology();
        let config = MempoolConfig {
            max_pool: 2,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::ROOT, config);

        for seed in 1..=2u8 {
            assert!(
                !mempool
                    .on_transaction_gossip(
                        &topology_snapshot,
                        Arc::new(verified(test_transaction(seed))),
                        false,
                        LocalTimestamp::ZERO,
                    )
                    .is_empty(),
                "the pool is under its ceiling"
            );
        }
        assert_eq!(mempool.pool.len(), 2);

        let over = Arc::new(verified(test_transaction(3)));
        assert!(
            mempool
                .on_transaction_gossip(
                    &topology_snapshot,
                    Arc::clone(&over),
                    false,
                    LocalTimestamp::ZERO,
                )
                .is_empty(),
            "gossip past the ceiling is refused"
        );
        assert_eq!(mempool.pool.len(), 2, "and nothing held is evicted for it");

        let fetched =
            mempool.on_fetched_transactions(&topology_snapshot, vec![over], LocalTimestamp::ZERO);
        assert!(
            fetched.iter().any(|action| matches!(
                action,
                Action::Continuation(ProtocolEvent::TransactionsAdmitted { .. })
            )),
            "a transaction this node asked for is admitted whatever the pool holds, got {fetched:?}"
        );
        assert_eq!(mempool.pool.len(), 3);
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
            make_finalization(BlockHeight::new(2), tx_hash, TransactionDecision::Accept),
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
            !actions.iter().any(|a| matches!(
                a,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(..),
                    ..
                })
            )),
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
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(ids),
                    preferred,
                    ..
                }) => Some((ids, preferred)),
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
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(ids),
                    preferred,
                    ..
                }) => Some((ids, preferred)),
                _ => None,
            })
            .collect();
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].0, &vec![unseen_hash]);
        assert_eq!(*fetches[0].1, None);
    }

    #[test]
    fn entry_dropped_past_retention_horizon_emits_metric() {
        // Sighting at H=1 (ts=500ms); commit at H=700 (ts=350_000ms), far
        // past `RETENTION_HORIZON` behind it.
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
        // `RETENTION_HORIZON`. Entry should still be tracked, and a fetch is
        // emitted but no drop.
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
                Action::AbandonFetch(FetchIds::Transactions(ids)) => Some(ids.clone()),
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
            make_finalization(BlockHeight::new(2), tx_hash, TransactionDecision::Accept),
        );
        let actions = mempool.on_block_committed(&topology_snapshot, &certified);

        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchIds::Transactions(ids)) if ids == &[tx_hash]
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
                Action::AbandonFetch(FetchIds::Transactions(ids)) if ids == &[tx_hash]
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
            !actions.iter().any(|a| matches!(
                a,
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(..),
                    ..
                })
            )),
            "no fetch after admission cleared expectation"
        );
    }

    #[test]
    fn test_abort_updates_status() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        // Submit a TX, then commit a block whose Finalization aborts it.
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
            make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Aborted),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);
        let actions = mempool
            .on_resolutions(&[(tx_hash, TxResolution::Decided(TransactionDecision::Aborted))]);

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

        let tx = test_transaction_with_prefixes(b"straddler", &[test_prefix(7)], &[test_prefix(8)]);
        let tx_hash = tx.hash();

        // Commit the tx with no deciding finalization: in flight,
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
        assert!(mempool.status(&tx_hash).is_none());
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    /// The status emitted for `tx_hash` by `actions`, if any.
    fn emitted(actions: &[Action], tx_hash: TxHash) -> Vec<TransactionStatus> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::EmitTransactionStatus {
                    tx_hash: h, status, ..
                } if *h == tx_hash => Some(status.clone()),
                _ => None,
            })
            .collect()
    }

    /// A leg's own finalization is the leg's state and not the
    /// transaction's terminal: the entry stays, untombstoned, until the
    /// core's verdict ends it.
    #[test]
    fn a_legs_finalization_is_its_own_state_and_the_cores_verdict_ends_it() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            1_000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block, 1_000));

        let actions = mempool.on_resolutions(&[(tx_hash, TxResolution::LegFinalized)]);
        assert_eq!(
            emitted(&actions, tx_hash),
            vec![TransactionStatus::LegFinalized]
        );
        assert_eq!(
            mempool.status(&tx_hash),
            Some(TransactionStatus::LegFinalized),
            "the entry stays for the verdict"
        );
        assert!(!mempool.is_tombstoned(&tx_hash));
        assert!(
            mempool
                .ready_transactions(10, 0, &ShardTrie::single(), LocalTimestamp::ZERO, |_| true)
                .is_empty(),
            "and is never offered again"
        );

        let actions = mempool.on_resolutions(&[(
            tx_hash,
            TxResolution::CoreDecided(TransactionDecision::Accept),
        )]);
        assert_eq!(
            emitted(&actions, tx_hash),
            vec![TransactionStatus::Completed(TransactionDecision::Accept)]
        );
        assert!(mempool.status(&tx_hash).is_none());
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    /// A core's verdict can reach a replica before that replica commits
    /// its own leg's finalization: it is held, and lands the moment the
    /// leg finalizes.
    #[test]
    fn a_cores_verdict_heard_before_the_leg_finalized_waits_for_it() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        let tx = test_transaction(2);
        let tx_hash = tx.hash();
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            1_000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block, 1_000));

        let actions = mempool.on_resolutions(&[(
            tx_hash,
            TxResolution::CoreDecided(TransactionDecision::Reject),
        )]);
        assert!(emitted(&actions, tx_hash).is_empty(), "held for the leg");
        assert_eq!(
            mempool.status(&tx_hash),
            Some(TransactionStatus::Committed(BlockHeight::new(1)))
        );

        let actions = mempool.on_resolutions(&[(tx_hash, TxResolution::LegFinalized)]);
        assert_eq!(
            emitted(&actions, tx_hash),
            vec![
                TransactionStatus::LegFinalized,
                TransactionStatus::Completed(TransactionDecision::Reject)
            ]
        );
        assert!(mempool.is_tombstoned(&tx_hash));
    }

    /// A leg nothing ever decides goes at the horizon the execution
    /// ledger gives its reclaim up at, and not before.
    #[test]
    fn a_finalized_leg_nobody_decides_goes_at_its_horizon() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        let end_ms = 60_000;
        let tx = tx_with_end(3, end_ms);
        let tx_hash = tx.hash();
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(1),
            1_000,
            ValidatorId::new(0),
            vec![Arc::new((**tx).clone())],
            vec![],
        );
        mempool.on_block_committed(&topology_snapshot, &certify(block, 1_000));
        mempool.on_resolutions(&[(tx_hash, TxResolution::LegFinalized)]);

        let horizon = Window::LegEntry
            .of(Deadline::of(WeightedTimestamp::from_millis(end_ms)))
            .end;
        set_current_ts(&mut mempool, horizon.minus(Duration::from_millis(1)));
        assert_eq!(mempool.cleanup_expired_pending(), 0);
        assert!(mempool.has_transaction(&tx_hash));
        set_current_ts(&mut mempool, horizon);
        assert_eq!(mempool.cleanup_expired_pending(), 1);
        assert!(!mempool.has_transaction(&tx_hash));
    }

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
            make_finalization(
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

        // Submit and complete the transaction (commit + Accept finalization in one block).
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );
        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx.clone(),
            make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);
        mempool.on_resolutions(&[(tx_hash, TxResolution::Decided(TransactionDecision::Accept))]);

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

        // Submit and complete the transaction (commit + Accept finalization in one block).
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx.clone())),
            LocalTimestamp::ZERO,
        );
        let certified = certified_commit_block(
            BlockHeight::new(1),
            tx.clone(),
            make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept),
        );
        mempool.on_block_committed(&topology_snapshot, &certified);
        mempool.on_resolutions(&[(tx_hash, TxResolution::Decided(TransactionDecision::Accept))]);

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

    /// Create a topology with 2 shards for cross-shard testing
    fn make_cross_shard_topology() -> TopologySnapshot {
        TestCommittee::new(8, 42).topology_snapshot(2)
    }

    /// Create a cross-shard transaction (writes prefixes in different shards)
    fn test_cross_shard_transaction(seed: u8) -> Transaction {
        use hyperscale_types::ShardTrie;
        use hyperscale_types::test_utils::test_prefix;

        let trie = ShardTrie::uniform_from_count(2);
        let shard1 = trie.shard_for_prefix(test_prefix(seed));

        let mut other_seed = seed.wrapping_add(1);
        loop {
            if trie.shard_for_prefix(test_prefix(other_seed)) != shard1 {
                break;
            }
            other_seed = other_seed.wrapping_add(1);
            assert!(
                other_seed != seed,
                "Could not find prefixes in different shards"
            );
        }

        test_transaction_with_prefixes(
            &[seed, seed + 1, seed + 2],
            &[test_prefix(seed)],                          // read from one shard
            &[test_prefix(seed), test_prefix(other_seed)], // write to both shards
        )
    }

    #[test]
    fn test_backpressure_allows_txns_below_limit() {
        // A few txs is far below the work budget, so ready_transactions
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
        let ready = mempool.ready_transactions(10, 0, &ShardTrie::single(), read_at, |_| true);
        assert_eq!(ready.len(), 2, "All TXs should be allowed below limit");
    }

    #[test]
    fn test_backpressure_rejects_all_at_limit() {
        let topology_snapshot = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));

        let tx = test_transaction(1);
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx)),
            LocalTimestamp::ZERO,
        );

        // The drain the chain reports is already at the cap.
        let ready =
            mempool.ready_transactions(10, 0, &ShardTrie::single(), LocalTimestamp::ZERO, |_| true);
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
        let ready =
            mempool.ready_transactions(10, 0, &ShardTrie::single(), LocalTimestamp::ZERO, |_| true);
        assert_eq!(ready.len(), 2);
    }

    /// A priority buys a place in the block and never a position in it.
    ///
    /// With room for fewer than the pool holds, what is offered is the
    /// transactions whose senders burned the higher multiplier — and
    /// what they are offered in is hash order, which is the order every
    /// voter checks.
    #[test]
    fn a_priority_selects_inclusion_and_never_order() {
        let mut mempool = MempoolCoordinator::with_config(
            ShardId::ROOT,
            MempoolConfig {
                min_dwell_time: Duration::ZERO,
                ..MempoolConfig::default()
            },
        );
        let topology_snapshot = make_test_topology();
        let now = LocalTimestamp::from_millis(10_000);
        for (seed, priority_bp) in [(1u8, 0u32), (2, 500), (3, 0), (4, 500)] {
            let tx = test_transaction_at_priority(seed, priority_bp);
            mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), now);
        }

        let ready = mempool.ready_transactions(2, 0, &ShardTrie::single(), now, |_| true);
        assert_eq!(ready.len(), 2, "the room the caller named");
        assert!(
            ready.iter().all(|tx| tx.body().priority_bp == 500),
            "the higher multipliers are the ones offered"
        );
        assert!(
            ready[0].hash() < ready[1].hash(),
            "and they are offered in hash order"
        );
    }

    /// A transaction the proposer cannot carry yet takes no place and
    /// no budget, however much it paid.
    ///
    /// The offer is what a block is built from and nothing refills
    /// behind it, so an unengaged entry filtered after selection would
    /// leave the block short by one — and a priority it paid would buy
    /// it the place it then wasted, which is the extraction priority is
    /// supposed not to sell.
    #[test]
    fn an_unengaged_transaction_costs_no_place() {
        let mut mempool = MempoolCoordinator::with_config(
            ShardId::ROOT,
            MempoolConfig {
                min_dwell_time: Duration::ZERO,
                ..MempoolConfig::default()
            },
        );
        let topology_snapshot = make_test_topology();
        let now = LocalTimestamp::from_millis(10_000);
        // The one that paid most is the one the proposer cannot carry.
        let unengaged = test_transaction_at_priority(1, 5_000);
        let unengaged_hash = unengaged.hash();
        mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(unengaged)), now);
        for seed in 2u8..=4 {
            let tx = test_transaction_at_priority(seed, 0);
            mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), now);
        }

        let ready = mempool.ready_transactions(2, 0, &ShardTrie::single(), now, |tx| {
            tx.hash() != unengaged_hash
        });
        assert_eq!(
            ready.len(),
            2,
            "the room the caller named is filled with transactions it can carry"
        );
        assert!(
            ready.iter().all(|tx| tx.hash() != unengaged_hash),
            "and the one it cannot is not among them"
        );

        // Withheld by engagement and by nothing else: the same pool
        // offers it first the moment its evidence lands.
        let engaged = mempool.ready_transactions(2, 0, &ShardTrie::single(), now, |_| true);
        assert!(
            engaged.iter().any(|tx| tx.hash() == unengaged_hash),
            "what it paid still buys the place once it can be carried"
        );
    }

    /// Equal priorities fall to hash, so a pool nobody outbid in is
    /// offered exactly as it was before priority existed.
    #[test]
    fn equal_priorities_fall_to_hash() {
        let mut mempool = MempoolCoordinator::with_config(
            ShardId::ROOT,
            MempoolConfig {
                min_dwell_time: Duration::ZERO,
                ..MempoolConfig::default()
            },
        );
        let topology_snapshot = make_test_topology();
        let now = LocalTimestamp::from_millis(10_000);
        let mut hashes: Vec<TxHash> = Vec::new();
        for seed in 1u8..=4 {
            let tx = test_transaction_at_priority(seed, 250);
            hashes.push(tx.hash());
            mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(tx)), now);
        }
        hashes.sort_unstable();

        let ready = mempool.ready_transactions(2, 0, &ShardTrie::single(), now, |_| true);
        assert_eq!(
            ready.iter().map(|tx| tx.hash()).collect::<Vec<_>>(),
            hashes[..2],
            "the lowest hashes, as they were offered before priority existed"
        );
    }

    /// A moved table keeps a ceiling it outgrew out of the pool, and
    /// takes nothing out of it.
    ///
    /// The level is judged where a block is built, against that block's
    /// own window; the pool holds no window, so its reading is the
    /// head's and is a different one across a fold. That makes it fit to
    /// decline and unfit to delete — an entry already pooled is left for
    /// its own deadline, which needs no guess about which window was
    /// right. On every shard, since the table is network-wide and a
    /// counterpart reads the same figure as the payer.
    #[test]
    fn a_moved_table_declines_a_ceiling_it_outgrew_and_evicts_nothing() {
        use hyperscale_types::PriceTable;

        let topology_snapshot = make_test_topology();
        let raised = topology_snapshot.clone().with_prices(PriceTable {
            compute: PriceTable::GENESIS.compute * 1_000_000,
            ..PriceTable::GENESIS
        });
        let now = LocalTimestamp::from_millis(10_000);

        // Pooled under a table its ceiling covers, then the level moves.
        // Dwell out of the way, so what decides the offer is the price.
        let ready_at_once = MempoolConfig {
            min_dwell_time: Duration::ZERO,
            ..MempoolConfig::default()
        };
        let mut mempool = MempoolCoordinator::with_config(ShardId::ROOT, ready_at_once.clone());
        let pooled = test_transaction(1);
        let pooled_hash = pooled.hash();
        mempool.on_submit_transaction(&topology_snapshot, Arc::new(verified(pooled)), now);
        assert!(mempool.has_transaction(&pooled_hash));

        let certified = certified_block_with_provisions(BlockHeight::new(6), ShardId::ROOT, &[]);
        mempool.on_block_committed(&raised, &certified);
        assert!(
            mempool.has_transaction(&pooled_hash),
            "a commit at the moved table evicts nothing the pool already holds"
        );
        assert_eq!(
            mempool
                .ready_transactions(10, 0, &ShardTrie::single(), now, |_| true)
                .len(),
            1,
            "and what it holds is still offered; the block's own window decides it"
        );

        // Arriving at the moved level is what gets declined, and the
        // decision is about the level alone — the same bytes are
        // admissible again once it comes down.
        let mut fresh = MempoolCoordinator::with_config(ShardId::ROOT, ready_at_once);
        fresh.on_submit_transaction(&raised, Arc::new(verified(test_transaction(1))), now);
        assert!(
            !fresh.has_transaction(&pooled_hash),
            "a transaction no block at this level could carry is not pooled"
        );
        fresh.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(test_transaction(1))),
            now,
        );
        assert!(
            fresh.has_transaction(&pooled_hash),
            "and no tombstone holds it out when the level comes down"
        );
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

        let ready = mempool.ready_transactions(10, 0, &ShardTrie::single(), now, |_| true);
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
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(10_100),
            |_| true,
        );
        assert_eq!(
            ready.len(),
            0,
            "Should not select before 150ms default dwell"
        );

        // At t=10.15s — eligible (150ms >= 150ms)
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(10_150),
            |_| true,
        );
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
        let ready = mempool.ready_transactions(10, 0, &ShardTrie::single(), submitted_at, |_| true);
        assert_eq!(ready.len(), 0, "Should not select before dwell time");

        // Advance to t=10.3s — still not enough
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(10_300),
            |_| true,
        );
        assert_eq!(
            ready.len(),
            0,
            "Should not select before dwell time elapses"
        );

        // Advance to t=10.5s — exactly at dwell time
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(10_500),
            |_| true,
        );
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
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(1_400),
            |_| true,
        );
        assert_eq!(ready.len(), 1, "Only tx1 should be eligible");

        // At t=1.5s — both eligible
        let ready = mempool.ready_transactions(
            10,
            0,
            &ShardTrie::single(),
            LocalTimestamp::from_millis(1_500),
            |_| true,
        );
        assert_eq!(ready.len(), 2, "Both should be eligible");
    }

    // ─── validity-window admission + pending sweep ──────────────────────

    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<Verified<Transaction>> {
        use hyperscale_types::TimestampRange;
        use hyperscale_types::test_utils::{stub_transaction, test_prefix};
        let range = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(end_ms),
        );
        Arc::new(verified(stub_transaction(
            test_principal(seed),
            &[test_prefix(seed)],
            1_000,
            range,
        )))
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

    /// A fresh coordinator's clock sits at zero, where the admission
    /// gate's `admissible_until <= current_ts` is vacuous and every
    /// expired transaction gossiped at it is admitted. Only a commit
    /// moves that clock, so between a restart and the first commit the
    /// pool is wide open — unless the restart seeds it.
    #[test]
    fn an_unseeded_clock_admits_an_expired_transaction_and_a_seeded_one_does_not() {
        let topology_snapshot = make_test_topology();
        let tx = tx_with_end(1, 1_000);

        let mut fresh = MempoolCoordinator::new(ShardId::ROOT);
        fresh.on_transaction_gossip(
            &topology_snapshot,
            Arc::clone(&tx),
            false,
            LocalTimestamp::ZERO,
        );
        assert!(
            fresh.status(&tx.hash()).is_some(),
            "the vacuous gate this seeding exists to close",
        );

        let mut seeded = MempoolCoordinator::new(ShardId::ROOT);
        seeded.seed_committed(BlockHeight::new(42), WeightedTimestamp::from_millis(2_000));
        seeded.on_transaction_gossip(
            &topology_snapshot,
            Arc::clone(&tx),
            false,
            LocalTimestamp::ZERO,
        );
        assert!(seeded.status(&tx.hash()).is_none());
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

    /// The handback carries what the terminal sweep cannot reach: pool
    /// entries that were never included, and only while a successor could
    /// still include them.
    #[test]
    fn pending_for_handback_offers_only_live_uncommitted_entries() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(500));

        let alive = tx_with_end(1, 60_000);
        let expiring = tx_with_end(2, 1_000);
        for tx in [&alive, &expiring] {
            mempool.on_submit_transaction(&topology_snapshot, Arc::clone(tx), LocalTimestamp::ZERO);
        }

        let mut offered: Vec<TxHash> = mempool
            .pending_for_handback()
            .iter()
            .map(|tx| tx.hash())
            .collect();
        offered.sort_unstable();
        let mut expected = vec![alive.hash(), expiring.hash()];
        expected.sort_unstable();
        assert_eq!(offered, expected);

        // Past `expiring`'s window a successor could not include it either,
        // so offering it back would only cost the successor an admission
        // it immediately drops.
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(1_500));
        assert_eq!(
            mempool
                .pending_for_handback()
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            vec![alive.hash()],
        );
    }

    /// A committed entry is the sweep's business, not the handback's — it
    /// has a decision coming, or an abort standing in for one.
    #[test]
    fn pending_for_handback_leaves_committed_entries_to_the_sweep() {
        let topology_snapshot = make_test_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        set_current_ts(&mut mempool, WeightedTimestamp::from_millis(500));

        let tx = tx_with_end(1, 60_000);
        mempool.on_submit_transaction(&topology_snapshot, Arc::clone(&tx), LocalTimestamp::ZERO);
        mempool
            .pool
            .get_mut(&tx.hash())
            .expect("just admitted")
            .status = TransactionStatus::Committed(BlockHeight::new(1));

        assert!(mempool.pending_for_handback().is_empty());
        assert_eq!(mempool.abort_in_flight().len(), 1);
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

    #[test]
    fn fork_fence_quiesce_rejects_txs_touching_the_fenced_shard() {
        let topology_snapshot = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));

        // A tx writing to a node, and that node's shard.
        let prefix = test_prefix(7);
        let fenced_shard = topology_snapshot.shard_for_prefix(prefix);
        let tx = test_transaction_with_prefixes(&[7], &[], &[prefix]);
        let hash = tx.hash();

        // With the fence engaged for that shard, admission is rejected — no
        // point starting cross-shard work bound to a forked committee.
        mempool.engage_fork_fence(fenced_shard, BlockHeight::new(5), &BTreeMap::new());
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx)),
            LocalTimestamp::ZERO,
        );
        assert!(
            mempool.status(&hash).is_none(),
            "a tx touching the fenced shard must not admit"
        );

        // A tx on a different, unfenced shard admits normally.
        let mut seed = 8u8;
        let other = loop {
            let p = test_prefix(seed);
            if topology_snapshot.shard_for_prefix(p) != fenced_shard {
                break p;
            }
            seed = seed.wrapping_add(1);
            assert!(seed != 7, "could not find a prefix off the fenced shard");
        };
        let tx2 = test_transaction_with_prefixes(&[seed], &[], &[other]);
        let hash2 = tx2.hash();
        mempool.on_submit_transaction(
            &topology_snapshot,
            Arc::new(verified(tx2)),
            LocalTimestamp::ZERO,
        );
        assert!(
            mempool.status(&hash2).is_some(),
            "a tx off the fenced shard admits"
        );
    }

    #[test]
    fn fork_fence_holds_admission_until_the_recovery_completes() {
        use hyperscale_types::{Epoch, RecoveryCause, ShardRecovery};

        let topology_snapshot = make_cross_shard_topology();
        let mut mempool = MempoolCoordinator::new(ShardId::leaf(1, 0));

        let prefix = test_prefix(7);
        let fenced_shard = topology_snapshot.shard_for_prefix(prefix);
        mempool.engage_fork_fence(fenced_shard, BlockHeight::new(5), &BTreeMap::new());

        let submit = |mempool: &mut MempoolCoordinator, seed: u8| {
            let tx = test_transaction_with_prefixes(&[seed], &[], &[prefix]);
            let hash = tx.hash();
            mempool.on_submit_transaction(
                &topology_snapshot,
                Arc::new(verified(tx)),
                LocalTimestamp::ZERO,
            );
            hash
        };

        // The recovery folds — the fence must hold through the whole
        // recovery window, or txs flow back in, take locks, and stall on
        // provisions the recovery fence still rejects.
        let recovering = topology_snapshot.clone().with_pending_recoveries(
            std::iter::once((
                fenced_shard,
                ShardRecovery {
                    cause: RecoveryCause::Fork,
                    rotated_at: Epoch::new(2),
                    retained: Vec::new(),
                    attested_frontier: BlockHeight::new(4),
                },
            ))
            .collect(),
        );
        let block = make_live_block(
            ShardId::leaf(1, 0),
            BlockHeight::new(1),
            1_234_567_890,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        mempool.on_block_committed(&recovering, &certify(block, TEST_BLOCK_INTERVAL_MS));
        let mid_window = submit(&mut mempool, 7);
        assert!(
            mempool.status(&mid_window).is_none(),
            "a folded-but-incomplete recovery must not reopen admission"
        );

        // The recovery completes — the fence clears and admission reopens.
        let recovered = topology_snapshot.clone().with_completed_recoveries(
            std::iter::once((
                fenced_shard,
                CompletedRecovery {
                    rotated_at: Epoch::new(2),
                    attested_frontier: BlockHeight::new(4),
                },
            ))
            .collect(),
        );
        let block = make_live_block(
            ShardId::leaf(1, 0),
            BlockHeight::new(2),
            1_234_567_890,
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        mempool.on_block_committed(&recovered, &certify(block, 2 * TEST_BLOCK_INTERVAL_MS));
        let after = submit(&mut mempool, 8);
        assert!(
            mempool.status(&after).is_some(),
            "a completed recovery reopens admission"
        );
    }

    // ─── Engagement parking ─────────────────────────────────────────────

    /// A signed stub transaction whose derived owners are exactly
    /// `owners`, paying from `payer`.
    fn stub_vm(payer: PrincipalAddr, owners: &[Address]) -> Arc<Verified<Transaction>> {
        install_stub_protocol_statics();
        Arc::new(verified(stub_transaction(
            payer,
            owners,
            1_000,
            test_validity_range(),
        )))
    }

    /// A shard that is not settling admits less until it does.
    ///
    /// The drain the chain reports is what selection has left to fill,
    /// so a backlog does not merely slow proposals down — it shrinks
    /// them, and stops them entirely at the budget. The count bounds a
    /// flood of minimal transactions the same way: each takes one place
    /// whatever it declared.
    #[test]
    fn a_backlogged_shard_admits_less_until_it_drains() {
        let topology = TestCommittee::new(4, 42).topology_snapshot(1);
        let trie = topology.shard_trie();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);

        let owners: Vec<PrincipalAddr> = (0..8u8).map(|i| test_principal(0x40 + i)).collect();
        for owner in &owners {
            let tx = stub_vm(*owner, &[owner.address()]);
            mempool.on_transaction_gossip(&topology, tx, false, LocalTimestamp::ZERO);
        }
        let now = LocalTimestamp::from_millis(1_000);

        // An idle chain offers everything the block can hold.
        let idle = mempool.ready_transactions(10, 0, trie, now, |_| true);
        assert_eq!(idle.len(), 8, "an undrained budget selects freely");

        // Three places from the budget, only three are offered.
        let squeezed = mempool.ready_transactions(10, MAX_UNSETTLED_TXS - 3, trie, now, |_| true);
        assert_eq!(
            squeezed.len(),
            3,
            "selection fills exactly the places the drain left"
        );

        // At the budget it offers nothing, whatever is pooled.
        assert!(
            mempool
                .ready_transactions(10, MAX_UNSETTLED_TXS, trie, now, |_| true)
                .is_empty(),
            "a shard at its budget admits nothing until the drain clears"
        );
    }

    /// The caps bind on the block's own content: a transaction whose
    /// share would carry the block past a cap is passed over while the
    /// count still has room, and the ones behind it that fit are still
    /// offered.
    #[test]
    fn a_transaction_over_a_cap_is_passed_over_while_the_count_has_room() {
        let topology = TestCommittee::new(4, 42).topology_snapshot(1);
        let trie = topology.shard_trie();
        let mut mempool = MempoolCoordinator::new(ShardId::ROOT);
        // Each declares a thirty-second of the block's compute, so the
        // caps admit thirty-two of forty where the count would admit
        // them all.
        let heavy = MAX_BLOCK_COMPUTE / 32;
        let owners: Vec<PrincipalAddr> = (0..40u8).map(|i| test_principal(0x80 + i)).collect();
        for owner in &owners {
            install_stub_protocol_statics();
            let tx = Arc::new(verified(stub_transaction_declaring(
                *owner,
                &[],
                &[],
                &[owner.address()],
                1_000,
                vec![heavy],
                test_validity_range(),
            )));
            mempool.on_transaction_gossip(&topology, tx, false, LocalTimestamp::ZERO);
        }
        let now = LocalTimestamp::from_millis(1_000);
        let offered = mempool.ready_transactions(100, 0, trie, now, |_| true);
        let filled = offered.iter().fold(DeclaredWork::ZERO, |total, tx| {
            total.saturating_add(
                Classified::freeze(tx.legs(), tx.owners(), trie).local_work(tx, ShardId::ROOT),
            )
        });
        assert!(
            budget_admits_block(&filled),
            "what is offered fits the caps"
        );
        assert!(
            offered.len() < owners.len() && offered.len() >= 30,
            "the compute cap, not the count, decided: {} offered",
            offered.len()
        );
        // With room for one more place than the caps admit, the count
        // is not what stopped selection.
        let places = u64::try_from(offered.len()).expect("fits") + 1;
        assert_eq!(
            mempool
                .ready_transactions(100, MAX_UNSETTLED_TXS - places, trie, now, |_| true)
                .len(),
            offered.len()
        );
    }

    #[test]
    fn cross_shard_tx_parks_until_engagement_evidence() {
        let topology = TestCommittee::new(4, 42).topology_snapshot(2);
        let local = ShardId::leaf(1, 0);
        let payer_shard = ShardId::leaf(1, 1);
        let mut mempool = MempoolCoordinator::new(local);

        // A clear top bit routes to leaf(1, 0); a set one to leaf(1, 1).
        let local_owner = test_principal(0x01);
        let payer_owner = test_principal(0x81);
        let parked = stub_vm(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let parked_hash = parked.hash();
        mempool.on_transaction_gossip(&topology, Arc::clone(&parked), false, LocalTimestamp::ZERO);

        // Pooled and reported Pending, but outside contention.
        assert_eq!(mempool.parked_count(), 1);
        assert!(
            mempool
                .ready_transactions(
                    10,
                    0,
                    &ShardTrie::single(),
                    LocalTimestamp::from_millis(1_000),
                    |_| true
                )
                .is_empty()
        );

        // A conflicting local leg is not deferred behind the parked one:
        // the parked transaction holds no claim on their shared key.
        let local_leg = stub_vm(local_owner, &[local_owner.address()]);
        let local_hash = local_leg.hash();
        mempool.on_transaction_gossip(
            &topology,
            Arc::clone(&local_leg),
            false,
            LocalTimestamp::ZERO,
        );
        let ready: Vec<TxHash> = mempool
            .ready_transactions(
                10,
                0,
                &ShardTrie::single(),
                LocalTimestamp::from_millis(1_000),
                |_| true,
            )
            .iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(ready, vec![local_hash]);

        // Evidence from the wrong shard promotes nothing.
        mempool.on_engagement_evidence(local, [parked_hash]);
        assert_eq!(mempool.parked_count(), 1);

        // The payer's bundle unparks the transaction. Nothing arbitrates
        // their shared key any more — both legs are selectable, and the
        // batch they land in is what sequences them.
        mempool.on_engagement_evidence(payer_shard, [parked_hash]);
        assert_eq!(mempool.parked_count(), 0);
        let mut ready: Vec<TxHash> = mempool
            .ready_transactions(
                10,
                0,
                &ShardTrie::single(),
                LocalTimestamp::from_millis(1_000),
                |_| true,
            )
            .iter()
            .map(|tx| tx.hash())
            .collect();
        ready.sort_unstable();
        let mut expected = vec![local_hash, parked_hash];
        expected.sort_unstable();
        assert_eq!(ready, expected);
    }

    #[test]
    fn engagement_evidence_before_arrival_admits_straight_to_ready() {
        let topology = TestCommittee::new(4, 42).topology_snapshot(2);
        let local = ShardId::leaf(1, 0);
        let payer_shard = ShardId::leaf(1, 1);
        let mut mempool = MempoolCoordinator::new(local);

        let local_owner = test_principal(0x02);
        let payer_owner = test_principal(0x91);
        let tx = stub_vm(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let hash = tx.hash();

        mempool.on_engagement_evidence(payer_shard, [hash]);
        mempool.on_transaction_gossip(&topology, Arc::clone(&tx), false, LocalTimestamp::ZERO);

        assert_eq!(mempool.parked_count(), 0);
        let ready: Vec<TxHash> = mempool
            .ready_transactions(
                10,
                0,
                &ShardTrie::single(),
                LocalTimestamp::from_millis(1_000),
                |_| true,
            )
            .iter()
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(ready, vec![hash]);
    }
}
