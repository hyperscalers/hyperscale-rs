//! Block commit accumulation, persistence backpressure, and async flush.
//!
//! `BlockCommitCoordinator` owns the state machine that turns
//! `Action::CommitBlock` / `Action::CommitBlockByQcOnly` into a single,
//! ordered, fsync-batched write to `RocksDB`:
//!
//! 1. **Accumulate** — dedup against already-pending and already-persisted
//!    blocks; record the immediate-notify decision based on persistence lag.
//! 2. **Flush** — once per `feed_event`, drain the backlog into one closure
//!    that runs on the execution pool: prune stale prepared commits, sort by
//!    height (parents before children), call `commit_prepared_blocks` once,
//!    then emit deferred `BlockCommitted` events and a final `BlockPersisted`.
//!
//! The coordinator does not feed events to the state machine; the `io_loop`
//! drives that based on the [`AccumulateDecision`] returned from
//! [`BlockCommitCoordinator::accumulate`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crossbeam::channel::Sender;
use hyperscale_core::{CommitSource, PreparedBlock, ProtocolEvent};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::{record_block_committed, set_block_height};
use hyperscale_storage::{ChainEntry, PendingChain, ShardChainWriter, ShardStorage};
use hyperscale_types::{
    BeaconWitnessCommit, BlockHash, BlockHeight, CertifiedBlock, ConsensusReceipt, EpochWindows,
    FinalizedWave, LocalTimestamp, PreparedCommit, ShardId, StateRoot, SyncHint, Verifiable,
    Verified, WeightedTimestamp, local_settled_wave_ids,
};
use tracing::debug;

use crate::shard::{HostEvent, push_protocol_event};

/// Handle to the assembled `Verified<CertifiedBlock>` that the
/// `io_loop` forwards to `BlockCommitted`. Cloned `Arc` to the commit
/// just enqueued in the pending backlog.
pub type NotifyHandle = Arc<Verified<CertifiedBlock>>;

/// Prepared commit cache: `block_hash → (block_height, prepared_commit)`.
///
/// Shared between the coordinator and the delegated-action dispatch closures
/// that produce prepared commits asynchronously on the consensus crypto pool.
pub type PreparedCommitMap = HashMap<BlockHash, (BlockHeight, PreparedCommit)>;

/// Whether a queued QC-only commit needs JMT recomputation or can
/// reuse a `PreparedCommit` already in the cache. Set when the shard
/// enqueues the commit via [`BlockCommitCoordinator::decide_qc_only`].
#[derive(Debug)]
pub enum QcOnlyKind {
    /// `prepared_commits` already holds an entry for this block (the
    /// consensus path produced it via `VerifyStateRoot`). The queue
    /// head handler runs `accept_block_commit` directly — no pool
    /// dispatch needed.
    AlreadyPrepared,
    /// No cached `PreparedCommit`; the queue head handler dispatches
    /// [`run_qc_only_prep`] to the consensus-crypto pool.
    NeedsPrep,
}

/// A QC-only commit waiting on the single in-flight slot. Every
/// `Action::CommitBlockByQcOnly` other than the already-persisted skip
/// path enters the FIFO so commits drain in arrival order — the
/// flush pipeline asserts strict height contiguity and any reordering
/// (sync-burst sibling preps racing each other, an already-prepared
/// child overtaking a queued parent) trips that assertion.
pub struct QcOnlyPending {
    /// Block + certifying QC, with the full
    /// [`Verified<CertifiedBlock>`] predicate established upstream.
    pub certified: Arc<Verified<CertifiedBlock>>,
    /// Parent's state root (base for the JMT recomputation). Unused
    /// when `kind == AlreadyPrepared`.
    pub parent_state_root: StateRoot,
    /// Parent's height (JMT parent version). Unused when
    /// `kind == AlreadyPrepared`.
    pub parent_block_height: BlockHeight,
    /// How this node learned the certifying QC.
    pub source: CommitSource,
    /// Whether this entry needs the pool to run JMT prep or can
    /// reuse a cached `PreparedCommit`.
    pub kind: QcOnlyKind,
    /// Beacon-witness leaves to fold into the eventual block commit;
    /// the coordinator carries them across the JMT-prep slot so the
    /// `PendingCommit` queued for `flush` has the same data the
    /// original `Action::CommitBlockByQcOnly` supplied.
    pub witness: BeaconWitnessCommit,
}

/// Outcome of [`BlockCommitCoordinator::decide_qc_only`]. The shard runs
/// these branches on the pinned thread before deciding whether to claim
/// the in-flight JMT-prep slot.
#[derive(Debug)]
pub enum QcOnlyDecision {
    /// Block height is at or below the persisted tip — already on disk,
    /// nothing to do.
    Skip,
    /// A consensus-path `VerifyStateRoot` already cached the
    /// `PreparedCommit` for this block; skip JMT recomputation and
    /// enqueue straight into the standard commit pipeline.
    AlreadyPrepared,
    /// No cached prep — the shard should claim the QC-only slot and
    /// dispatch [`run_qc_only_prep`] to the consensus-crypto pool.
    NeedsPrep,
}

/// Diagnostic carried back to the shard when [`run_qc_only_prep`]
/// detects a computed-vs-canonical state-root mismatch. The shard
/// translates this into a
/// [`crate::event::ShardScopedInput::QcOnlyCommitDiverged`] and panics
/// on the pinned thread — the divergence is operator-fatal (the local
/// parent state diverged from canonical) and block-by-block recovery
/// cannot repair it.
#[derive(Debug, Clone)]
pub struct QcOnlyDivergence {
    /// Height being committed.
    pub block_height: BlockHeight,
    /// Hash of the committing block.
    pub block_hash: BlockHash,
    /// Parent's state root the prep ran against.
    pub parent_state_root: StateRoot,
    /// Parent's height the prep ran against.
    pub parent_block_height: BlockHeight,
    /// State root the block's header claimed.
    pub expected_root: StateRoot,
    /// State root our local prep produced.
    pub computed_root: StateRoot,
    /// How this node learned the certifying QC.
    pub source: CommitSource,
}

/// Run the JMT prep for a QC-only commit on the calling thread. Intended
/// for the closure dispatched by the shard to the consensus-crypto
/// pool — the caller pre-resolves the fast-path skips via
/// [`BlockCommitCoordinator::decide_qc_only`] and only invokes this for
/// blocks that need actual recomputation.
///
/// On success the prepared commit is inserted into `prepared_commits`
/// and the JMT snapshot + receipts go into `pending_chain` so the next
/// child block can see them. On state-root mismatch the function
/// returns the diagnostic without mutating either store; the shard
/// translates it into a `QcOnlyCommitDiverged` callback and panics.
///
/// # Errors
///
/// Returns [`QcOnlyDivergence`] when the computed state root doesn't
/// match the block header's `state_root` — operator-fatal as documented
/// on [`QcOnlyDivergence`].
pub fn run_qc_only_prep<S>(
    pending_chain: &Arc<PendingChain<S>>,
    prepared_commits: &Arc<Mutex<PreparedCommitMap>>,
    pending: &QcOnlyPending,
) -> Result<(), Box<QcOnlyDivergence>>
where
    S: ShardStorage,
{
    let block = pending.certified.block();
    let block_hash = block.hash();
    let height = block.height();

    // Build view anchored at parent — includes prior synced blocks'
    // JMT snapshots so chained verification can find parent nodes.
    let view = pending_chain.view_at(
        block.header().parent_block_hash(),
        pending.parent_block_height,
    );
    let pending_snapshots = view.pending_snapshots().to_vec();

    let finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>> = block.certificates().to_vec();
    let (computed_root, jmt_snapshot, prepared) = view.prepare_block_commit(
        pending.parent_state_root,
        pending.parent_block_height,
        &finalized_waves,
        height,
        &pending_snapshots,
        // `None` → the view drains its own base-read cache internally.
        None,
    );

    // The sync-block ingress validator rejects peer-shipped divergent
    // receipts before shard consensus sees the block; and `WaveState`'s divergence
    // detector keeps locally-produced bad receipts out of `finalized`.
    // A mismatch here means our local parent state itself diverged from
    // canonical — a JMT or commit-batch bug, or pre-existing corruption
    // in `StateCf`. Block-by-block sync can't repair this; the operator
    // must restore from a state snapshot or wipe-and-resync from genesis.
    let expected_root = block.header().state_root();
    if computed_root != expected_root {
        return Err(Box::new(QcOnlyDivergence {
            block_height: height,
            block_hash,
            parent_state_root: pending.parent_state_root,
            parent_block_height: pending.parent_block_height,
            expected_root,
            computed_root,
            source: pending.source,
        }));
    }

    let receipts: Vec<Arc<ConsensusReceipt>> = finalized_waves
        .iter()
        .flat_map(|fw| fw.consensus_receipts())
        .collect();
    let parent_block_hash = block.header().parent_block_hash();
    let settled_waves = local_settled_wave_ids(finalized_waves.iter(), block.header().shard_id());
    pending_chain.insert(
        block_hash,
        ChainEntry {
            parent_block_hash,
            height,
            receipts,
            settled_waves,
            jmt_snapshot,
            certified_block: None,
            certified_uncommitted: None,
        },
    );
    prepared_commits
        .lock()
        .unwrap()
        .insert(block_hash, (height, prepared));

    debug!(
        height = height.inner(),
        ?block_hash,
        "Synced block prepared, queued for persist"
    );

    Ok(())
}

/// Build the `commit_prepared` closure passed into [`ActionContext`].
///
/// Captures the shard's `pending_chain` and `prepared_commits` Arcs
/// once at dispatch time so the closure can be moved into the
/// off-thread action handler without holding `&DispatchHandles`. The
/// closure inserts the JMT snapshot into `pending_chain` (so child
/// blocks' state-root verifications can resolve through the overlay)
/// and stashes the prepared commit for the next flush.
///
/// [`ActionContext`]: hyperscale_core::ActionContext
pub fn make_commit_prepared<S>(
    pending_chain: Arc<PendingChain<S>>,
    prepared_commits: Arc<Mutex<PreparedCommitMap>>,
) -> impl Fn(PreparedBlock) + Send + Sync + 'static
where
    S: ShardStorage,
{
    move |prep: PreparedBlock| {
        let PreparedBlock {
            block_hash,
            parent_block_hash,
            block_height,
            prepared,
            jmt_snapshot,
            receipts,
            settled_waves,
        } = prep;
        pending_chain.insert(
            block_hash,
            ChainEntry {
                parent_block_hash,
                height: block_height,
                receipts,
                settled_waves,
                jmt_snapshot,
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        prepared_commits
            .lock()
            .unwrap()
            .insert(block_hash, (block_height, prepared));
    }
}

/// A block commit waiting to be flushed to storage.
///
/// All blocks — consensus and sync — go through the same commit pipeline:
/// `VerifyStateRoot` → `PreparedCommit` → `commit_prepared_blocks`.
pub struct PendingCommit {
    /// Block + certifying QC, with the full
    /// [`Verified<CertifiedBlock>`] predicate established upstream.
    pub certified: Arc<Verified<CertifiedBlock>>,
    /// How this node learned the certifying QC. Tagged into metrics so
    /// dashboards can separate aggregator/header/sync commit paths.
    pub source: CommitSource,
    /// Whether `BlockCommitted` was already fired immediately during
    /// accumulation (true) or deferred due to backpressure (false). The
    /// flush closure uses this to decide whether to send `BlockCommitted`
    /// after persistence.
    pub committed_notified: bool,
    /// Beacon-witness leaves to persist atomically with the block.
    /// Sourced from the `Action::CommitBlock` / `Action::CommitBlockByQcOnly`
    /// payload the shard coordinator emits at commit time.
    pub witness: BeaconWitnessCommit,
}

/// Outcome of accumulating a single commit.
pub enum AccumulateDecision {
    /// Block was already persisted or already pending; nothing to do.
    Skip,
    /// Block accepted into the pending backlog.
    Accepted {
        /// Height of the accepted block (used to advance the sync protocol).
        height: BlockHeight,
        /// `Verified<CertifiedBlock>` handle for the accepted commit.
        /// The caller attaches it to `PendingChain` so the shard-
        /// committed-but-not-persisted window is readable by fetch
        /// handlers, then — if `notify_now` — forwards the same handle
        /// to `BlockCommitted`.
        handle: NotifyHandle,
        /// True if the `io_loop` should fire `BlockCommitted` immediately.
        /// False under persistence backpressure: the flush closure fires
        /// the event after the disk write completes instead.
        notify_now: bool,
    },
}

/// A committed block's identity as the candidate epoch-boundary its
/// committing child adjudicates.
#[derive(Clone, Copy)]
pub struct BoundaryMemo {
    /// The candidate's block hash; the child's `parent_qc` must point
    /// here or the linkage is broken and the pin re-anchors.
    pub hash: BlockHash,
    /// Height pinned when the candidate proves to be the crossing.
    pub height: BlockHeight,
    /// The candidate's `parent_qc` weighted timestamp — the low side of
    /// the crossing interval its child adjudicates.
    pub parent_qc_wt: WeightedTimestamp,
}

/// Pins shard state at epoch-boundary blocks for snap-sync serving.
///
/// Detection runs on the crossing block's committing *child*: the beacon
/// reads a boundary's weighted timestamp from the child's `parent_qc`
/// (the canonical, hash-pinned anchor), so the server pins exactly the
/// block the beacon attests. A locally aggregated QC over the boundary
/// block itself can carry a different weighted timestamp and flip the
/// crossing verdict.
struct BoundaryTrigger {
    /// The chain's epoch window length — must match the beacon fold's.
    epoch_duration_ms: u64,
    /// Backend pin (`BoundaryStore::pin_boundary`). Invoked on the I/O
    /// pool between the boundary block's write and its child's, when
    /// storage state is exactly the boundary block's.
    pin: Arc<dyn Fn(BlockHeight) + Send + Sync>,
    /// The last flushed block — the candidate boundary the next flushed
    /// block's `parent_qc` adjudicates. `None` until the first flush
    /// (or unseeded restart); a broken hash linkage (sync-path gap)
    /// skips the pin and re-anchors here.
    last: Option<BoundaryMemo>,
}

pub struct BlockCommitCoordinator {
    /// Shard this coordinator persists for. Stamped onto emitted
    /// `BlockPersisted` events.
    shard: ShardId,

    /// Epoch-boundary pin trigger; `None` leaves boundary pinning off.
    boundary: Option<BoundaryTrigger>,

    /// Prepared commit cache shared with delegated dispatch closures.
    /// Stores `(block_height, prepared_commit)` keyed by block hash so
    /// stale entries can be pruned when they outlive their block.
    prepared_commits: Arc<Mutex<PreparedCommitMap>>,

    /// Block commits accumulated since the last successful flush. Drained
    /// by [`flush`](Self::flush); refilled when commits arrive faster than
    /// persistence completes.
    pending: Vec<PendingCommit>,

    /// Highest block height durably persisted to `RocksDB`. Updated by
    /// [`mark_persisted`](Self::mark_persisted) when `BlockPersisted`
    /// arrives. Drives backpressure: if consensus runs too far ahead,
    /// `BlockCommitted` is deferred until the disk write completes.
    persisted_height: BlockHeight,

    /// Set while an async commit task is running on the I/O pool. Bouncing
    /// this prevents spawning a second task (the I/O pool does not
    /// guarantee FIFO ordering across separate `spawn()` calls). The task
    /// clears the flag before sending its final event so the resulting
    /// `feed_event` → `flush` drains any backlog.
    commit_in_flight: Arc<AtomicBool>,

    /// Pending QC-only commits waiting for the in-flight JMT-prep slot.
    /// Drained head-first; siblings stay in arrival order so child blocks
    /// reach JMT prep only after their parent has populated
    /// `pending_chain`. Sync bursts can stack several here in one shard
    /// step (see `try_apply_verified_synced_blocks`).
    qc_only_queue: VecDeque<QcOnlyPending>,

    /// `true` while one QC-only JMT prep is being computed on the
    /// consensus-crypto pool. The pool task clears this state through
    /// `release_qc_only_slot` on the shard thread once
    /// `QcOnlyCommitPrepared` / `QcOnlyCommitDiverged` arrives, which
    /// also pops the next queue entry if any.
    qc_only_in_flight: bool,
}

impl BlockCommitCoordinator {
    /// Maximum number of blocks consensus can advance ahead of persistence
    /// before falling back to deferred `BlockCommitted` notification.
    pub const MAX_PERSISTENCE_LAG: u64 = 5;

    pub fn new(shard: ShardId, initial_persisted_height: BlockHeight) -> Self {
        Self {
            shard,
            boundary: None,
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            pending: Vec::new(),
            persisted_height: initial_persisted_height,
            commit_in_flight: Arc::new(AtomicBool::new(false)),
            qc_only_queue: VecDeque::new(),
            qc_only_in_flight: false,
        }
    }

    /// Install the epoch-boundary pin trigger.
    ///
    /// `seed` is the committed tip's [`BoundaryMemo`] so the first
    /// post-restart commit can adjudicate its parent; `None` skips at
    /// most the one boundary that lands exactly at the restart gap.
    pub fn set_boundary_trigger(
        &mut self,
        epoch_duration_ms: u64,
        pin: Arc<dyn Fn(BlockHeight) + Send + Sync>,
        seed: Option<BoundaryMemo>,
    ) {
        self.boundary = Some(BoundaryTrigger {
            epoch_duration_ms,
            pin,
            last: seed,
        });
    }

    /// Try to claim the single-in-flight QC-only JMT-prep slot for `pending`.
    /// Returns `Some` if the caller should immediately dispatch the returned
    /// commit to the consensus-crypto pool; `None` if a prep is already
    /// running and `pending` has been queued behind it.
    ///
    /// The slot is released later by [`Self::release_qc_only_slot`] when
    /// the worker's `QcOnlyCommitPrepared` / `QcOnlyCommitDiverged`
    /// callback returns to the shard.
    pub fn try_acquire_qc_only_slot(&mut self, pending: QcOnlyPending) -> Option<QcOnlyPending> {
        if self.qc_only_in_flight {
            self.qc_only_queue.push_back(pending);
            None
        } else {
            self.qc_only_in_flight = true;
            Some(pending)
        }
    }

    /// Release the in-flight QC-only slot once a callback returns. If a
    /// queued commit is waiting, returns it for immediate dispatch and
    /// keeps the slot marked in-flight; otherwise clears the flag.
    pub fn release_qc_only_slot(&mut self) -> Option<QcOnlyPending> {
        debug_assert!(
            self.qc_only_in_flight,
            "release_qc_only_slot called without a prep in flight",
        );
        if let Some(next) = self.qc_only_queue.pop_front() {
            // Slot stays in-flight — caller dispatches `next` straight
            // into the pool.
            Some(next)
        } else {
            self.qc_only_in_flight = false;
            None
        }
    }

    /// Clone the prepared-commit cache handle for use in delegated action
    /// dispatch closures (which insert prepared commits asynchronously).
    pub fn prepared_commits_handle(&self) -> Arc<Mutex<PreparedCommitMap>> {
        Arc::clone(&self.prepared_commits)
    }

    #[cfg(test)]
    const fn persisted_height(&self) -> BlockHeight {
        self.persisted_height
    }

    pub fn mark_persisted(&mut self, height: BlockHeight) {
        if height > self.persisted_height {
            self.persisted_height = height;
        }
    }

    /// Whether a prepared commit has already been cached for this block.
    /// Used by the QC-only commit path to avoid recomputing JMT when the
    /// consensus path beat sync to the prepare step.
    pub fn has_prepared(&self, block_hash: &BlockHash) -> bool {
        self.prepared_commits
            .lock()
            .unwrap()
            .contains_key(block_hash)
    }

    /// Insert a prepared commit produced inline (QC-only sync path).
    #[cfg(test)]
    fn insert_prepared(
        &self,
        block_hash: BlockHash,
        height: BlockHeight,
        prepared: PreparedCommit,
    ) {
        self.prepared_commits
            .lock()
            .unwrap()
            .insert(block_hash, (height, prepared));
    }

    /// Decide what to do with a [`Action::CommitBlockByQcOnly`] arrival
    /// without touching the JMT. Cheap fast-paths the shard thread can
    /// run inline before deciding whether to dispatch the heavy prep.
    ///
    /// [`Action::CommitBlockByQcOnly`]: hyperscale_core::Action::CommitBlockByQcOnly
    pub fn decide_qc_only(&self, block_hash: &BlockHash, height: BlockHeight) -> QcOnlyDecision {
        // Hard skip only if already persisted (consensus path got all
        // the way through). We must still enqueue blocks whose prepared
        // commit was populated by the consensus path but that never
        // had `BlockReadyToCommit` fire — e.g. a self-proposed block
        // whose child arrived via sync rather than consensus, so the
        // 2-chain commit rule never triggered. Dropping the block here
        // leaves its prepared commit orphaned in the cache, and the
        // next block to reach flush trips the strict ordering assert
        // in `commit_block_inner` because its parent was never applied.
        if height <= self.persisted_height {
            return QcOnlyDecision::Skip;
        }

        // If the consensus path already produced the prepared commit, reuse it
        // — recomputing JMT here can produce a transient root mismatch and trip
        // the byzantine-detection assert in `run_qc_only_prep` on a self-inflicted race.
        if self.has_prepared(block_hash) {
            return QcOnlyDecision::AlreadyPrepared;
        }

        QcOnlyDecision::NeedsPrep
    }

    pub const fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn prepared_len(&self) -> usize {
        self.prepared_commits.lock().unwrap().len()
    }

    /// Decide whether to accept a commit and whether to notify immediately.
    ///
    /// **Backpressure**: if persistence lag exceeds [`MAX_PERSISTENCE_LAG`]
    /// blocks, the immediate `BlockCommitted` is suppressed and instead
    /// fires after the disk write completes. This bounds memory usage and
    /// the crash-recovery window.
    ///
    /// [`MAX_PERSISTENCE_LAG`]: Self::MAX_PERSISTENCE_LAG
    pub fn accumulate(
        &mut self,
        mut commit: PendingCommit,
        now: LocalTimestamp,
    ) -> AccumulateDecision {
        let block_hash = commit.certified.block().hash();
        let height = commit.certified.block().height();

        // Skip blocks already persisted by the sync path.
        if height <= self.persisted_height {
            return AccumulateDecision::Skip;
        }

        // Dedup: consensus and sync paths can both reach commit for the same
        // block (e.g. self-proposed block whose child arrived via sync). Push
        // once; the prepared commit is also singular in `prepared_commits`.
        if self
            .pending
            .iter()
            .any(|c| c.certified.block().hash() == block_hash)
        {
            return AccumulateDecision::Skip;
        }

        // Block commit latency: time from proposal timestamp to now. Labeled
        // by `source` so dashboards can separate the three commit paths
        // (aggregator/header/sync), which have materially different latencies
        // under the 2-chain rule.
        let now_ms = now.as_millis();
        #[allow(clippy::cast_precision_loss)] // latency readout for metrics; ms→f64 lossy is fine
        let commit_latency_secs = (now_ms
            .saturating_sub(commit.certified.block().header().timestamp().as_millis()))
            as f64
            / 1000.0;
        record_block_committed(
            self.shard.inner(),
            commit_latency_secs,
            commit.source.as_str(),
        );
        set_block_height(self.shard.inner(), height.inner());

        // Fire BlockCommitted immediately unless persistence is falling
        // too far behind (backpressure). When deferred, flush sends
        // BlockCommitted after the disk write instead.
        let persistence_lag = height.inner().saturating_sub(self.persisted_height.inner());
        let notify_now = persistence_lag <= Self::MAX_PERSISTENCE_LAG;

        if !notify_now {
            tracing::debug!(
                height = height.inner(),
                persisted = self.persisted_height.inner(),
                lag = persistence_lag,
                "Deferring BlockCommitted — persistence backpressure"
            );
        }

        let handle = Arc::clone(&commit.certified);
        commit.committed_notified = notify_now;
        self.pending.push(commit);

        AccumulateDecision::Accepted {
            height,
            handle,
            notify_now,
        }
    }

    /// Drain pending commits into a single async task on the I/O pool.
    ///
    /// Spawns on success; sets `commit_in_flight` so subsequent flushes defer
    /// until the task clears it. If a previous task is still running, all
    /// pending commits remain queued for a future flush.
    ///
    /// Stored receipts are not drained here — they're already embedded in
    /// each `PreparedCommit`. Writing them in a single task guarantees
    /// ordering: the I/O pool does not guarantee FIFO across separate
    /// `spawn()` calls.
    ///
    /// Deferred `BlockCommitted` and `BlockPersisted` events return to
    /// the pinned thread via `event_tx`; see `ProcessIo::shard_event_senders`
    /// for the off-thread → pinned-thread routing convention.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn flush<D: Dispatch>(&mut self, event_tx: &Sender<HostEvent>, dispatch: &D) {
        if self.pending.is_empty() {
            return;
        }

        // Defer if a previous async commit is still running on the exec pool.
        if self.commit_in_flight.load(Ordering::Acquire) {
            return;
        }

        let mut commits = std::mem::take(&mut self.pending);

        // Drop blocks already persisted by the sync path.
        let persisted = self.persisted_height.inner();
        commits.retain(|c| c.certified.block().height().inner() > persisted);
        if commits.is_empty() {
            return;
        }

        // Sort by height to ensure parent blocks are flushed before children.
        // Cascading commits (e.g. QC formation during BlockCommitted processing)
        // can push child blocks into pending before their parent
        // (because the parent's push happens after feed_event returns). Without
        // sorting, the child block (which may lack a PreparedCommit) would defer
        // and block the ready parent, causing a deadlock where BlockPersisted
        // never fires and sync_awaiting_persistence_height is never satisfied.
        commits.sort_by_key(|c| c.certified.block().height().inner());

        // Blocks committed via CommitBlock need the PreparedCommit produced
        // asynchronously by VerifyStateRoot. If it's not ready yet, defer —
        // and defer all later blocks too to preserve height ordering. Blocks
        // that came through CommitBlockByQcOnly already have their
        // PreparedCommit cached inline so they don't hit this path.
        let mut ready_commits: Vec<PendingCommit> = Vec::with_capacity(commits.len());
        let mut prepared_map: Vec<PreparedCommit> = Vec::with_capacity(commits.len());
        {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut deferring = false;
            for commit in commits {
                if !deferring {
                    if let Some(prepared) = cache
                        .remove(&commit.certified.block().hash())
                        .map(|(_, p)| p)
                    {
                        prepared_map.push(prepared);
                        ready_commits.push(commit);
                        continue;
                    }
                    // First miss — flip to deferring so all later blocks
                    // defer too, preserving height ordering.
                    deferring = true;
                    tracing::debug!(
                        height = commit.certified.block().height().inner(),
                        certs = commit.certified.block().certificates().len(),
                        "Deferring block commit — awaiting PreparedCommit from VerifyStateRoot"
                    );
                }
                self.pending.push(commit);
            }

            // Only entries for blocks at or below `persisted_height` are
            // safe to drop: `accumulate` skips those heights, so their prep
            // can never be flushed again. A prep above it may belong to a
            // block still queued behind an earlier deferral — `VerifyStateRoot`
            // can cache it out of order, ahead of the block that gates the
            // flush — and `CommitBlock` never regenerates one, so evicting it
            // early would wedge the commit pipeline at that height.
            let persisted = self.persisted_height;
            let before = cache.len();
            cache.retain(|_, (h, _)| *h > persisted);
            let pruned = before - cache.len();
            if pruned > 0 {
                tracing::debug!(pruned, "Pruned stale prepared_commits entries");
            }
        }

        if ready_commits.is_empty() {
            return;
        }

        // Use the actual notification decision recorded at accumulation time,
        // not a re-derived value that could disagree due to persisted_height drift.
        let already_notified: Vec<bool> =
            ready_commits.iter().map(|c| c.committed_notified).collect();

        // Adjudicate epoch-boundary crossings: each block's `parent_qc`
        // carries the canonical weighted timestamp for its parent, so a
        // commit decides whether the PREVIOUS block was its shard's
        // crossing. The pin runs before this block's storage write, while
        // state is exactly the boundary block's.
        let mut pin_before: Vec<Option<BlockHeight>> = vec![None; ready_commits.len()];
        let pin_hook = self.boundary.as_ref().map(|t| Arc::clone(&t.pin));
        if let Some(trigger) = self.boundary.as_mut() {
            for (i, commit) in ready_commits.iter().enumerate() {
                let block = commit.certified.block();
                let parent_qc = block.header().parent_qc();
                if let Some(last) = trigger.last
                    && parent_qc.block_hash() == last.hash
                    && EpochWindows::new(trigger.epoch_duration_ms)
                        .is_crossing(last.parent_qc_wt, parent_qc.weighted_timestamp())
                {
                    pin_before[i] = Some(last.height);
                }
                trigger.last = Some(BoundaryMemo {
                    hash: block.hash(),
                    height: block.height(),
                    parent_qc_wt: parent_qc.weighted_timestamp(),
                });
            }
        }

        let commits = ready_commits;
        let event_tx = event_tx.clone();
        let in_flight = Arc::clone(&self.commit_in_flight);
        let shard = self.shard;

        self.commit_in_flight.store(true, Ordering::Release);

        dispatch.spawn(DispatchPool::Io, move || {
            let heights: Vec<BlockHeight> = commits
                .iter()
                .map(|c| c.certified.block().height())
                .collect();

            // Wrap commits in Option so we can take() them for deferred notifications.
            let mut commit_slots: Vec<Option<PendingCommit>> =
                commits.into_iter().map(Some).collect();

            // Invoke each closure in height order. Defer fsync for all
            // but the last; the final `FlushNow` covers the entire WAL
            // batch in one sync.
            let total = prepared_map.len();
            for (i, prepared) in prepared_map.into_iter().enumerate() {
                // Pin the parent's epoch-boundary state before this
                // block's write lands on top of it.
                if let (Some(boundary_height), Some(pin)) = (pin_before[i], pin_hook.as_ref()) {
                    pin(boundary_height);
                }
                let commit = commit_slots[i].as_ref().unwrap();
                let hint = if i + 1 == total {
                    SyncHint::FlushNow
                } else {
                    SyncHint::DeferFsync
                };
                let _root = prepared(hint, &commit.certified, &commit.witness);
            }

            // `heights` is non-empty (commits was checked above) and sorted
            // ascending (parallel to the height-sorted commits Vec).
            let max_persisted = *heights
                .last()
                .expect("heights is non-empty after the early return");

            // Send deferred BlockCommitted events for blocks that weren't notified
            // at accumulation time (due to persistence backpressure).
            for (i, _) in heights.iter().enumerate() {
                if !already_notified[i] {
                    let commit = commit_slots[i].take().unwrap();
                    let certified = commit.certified;
                    push_protocol_event(
                        &event_tx,
                        shard,
                        ProtocolEvent::BlockCommitted { certified },
                    );
                }
            }

            // Clear the in-flight flag before sending BlockPersisted. The
            // channel send synchronizes-with recv on the main thread, so
            // the flag is guaranteed visible when the resulting feed_event
            // calls flush to drain any backlog.
            in_flight.store(false, Ordering::Release);

            push_protocol_event(
                &event_tx,
                shard,
                ProtocolEvent::BlockPersisted {
                    height: max_persisted,
                    substate_bytes: 0,
                },
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use crossbeam::channel::{Receiver, unbounded};
    use hyperscale_dispatch_sync::SyncDispatch;
    use hyperscale_types::test_utils::{TestCommittee, make_live_block};
    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHeight, ChainOrigin, Hash, QuorumCertificate, ShardId,
        ValidatorId,
    };

    use super::*;
    use crate::shard::ShardScopedInput;

    /// Shared sink the test closures record their (height, tag) commit
    /// against. Threaded through `make_commit` so the test can assert on
    /// commit order and identity.
    type CommitSink = Arc<Mutex<Vec<(BlockHeight, u64)>>>;

    /// Build a [`PreparedCommit`] closure that records its invocation
    /// into `sink` and returns `StateRoot::ZERO`. Used to drive the
    /// coordinator's flush loop without standing up real storage.
    fn make_mock_prepared(sink: CommitSink, tag: u64) -> PreparedCommit {
        Box::new(
            move |_hint: SyncHint,
                  certified: &Arc<Verified<CertifiedBlock>>,
                  _witness: &BeaconWitnessCommit|
                  -> StateRoot {
                sink.lock().unwrap().push((certified.block().height(), tag));
                StateRoot::ZERO
            },
        )
    }

    fn committed_heights(sink: &CommitSink) -> Vec<u64> {
        sink.lock()
            .unwrap()
            .iter()
            .map(|(h, _)| h.inner())
            .collect()
    }

    fn committed_tags(sink: &CommitSink) -> Vec<u64> {
        sink.lock().unwrap().iter().map(|(_, t)| *t).collect()
    }

    /// Build a `(PendingCommit, prepared_closure)` pair for `height`. Each
    /// height gets a distinct timestamp so block hashes differ.
    fn make_commit(
        committee: &TestCommittee,
        height: BlockHeight,
        source: CommitSource,
        sink: CommitSink,
    ) -> (PendingCommit, PreparedCommit) {
        let block = make_live_block(
            ShardId::ROOT,
            height,
            /* timestamp_ms */ 1_000 + height.inner(),
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let block_hash = block.hash();
        let qc = {
            let __qc = QuorumCertificate::genesis(block.header().shard_id(), ChainOrigin::ROOT);
            QuorumCertificate::new(
                block_hash,
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            )
        };
        let _ = committee; // committee unused here but kept for future signing-required tests
        // SAFETY: synthetic test fixture, no real signature.
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(qc);
        let certified = CertifiedBlock::new_unchecked(block, qc);
        // SAFETY: synthetic test fixture; block-commit-coordinator tests
        // don't exercise the `Verified<CertifiedBlock>` predicate.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            certified,
        ));
        let pending = PendingCommit {
            certified,
            source,
            committed_notified: false,
            witness: BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        };
        let prepared = make_mock_prepared(sink, height.inner());
        (pending, prepared)
    }

    /// Tag generator used by `make_commit_with_tag` for tests that care about
    /// distinguishing two prepared handles for the same height.
    static TAG_GEN: AtomicU64 = AtomicU64::new(10_000);

    fn next_tag() -> u64 {
        TAG_GEN.fetch_add(1, Ordering::Relaxed)
    }

    fn drain_protocol_events(rx: &Receiver<HostEvent>) -> Vec<ProtocolEvent> {
        let mut out = Vec::new();
        while let Ok(HostEvent::Shard(_, ShardScopedInput::Protocol(event))) = rx.try_recv() {
            out.push(*event);
        }
        out
    }

    fn count_committed(events: &[ProtocolEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, ProtocolEvent::BlockCommitted { .. }))
            .count()
    }

    fn last_persisted_height(events: &[ProtocolEvent]) -> Option<BlockHeight> {
        events.iter().rev().find_map(|e| match e {
            ProtocolEvent::BlockPersisted { height, .. } => Some(*height),
            _ => None,
        })
    }

    fn now() -> LocalTimestamp {
        // The accumulator only uses `now` for latency metrics; the value
        // doesn't influence the decisions we assert on.
        LocalTimestamp::from_millis(10_000_000)
    }

    // ── accumulate ────────────────────────────────────────────────────

    fn empty_sink() -> CommitSink {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[test]
    fn accumulate_skips_block_at_or_below_persisted_height() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::new(5));
        let sink = empty_sink();

        for h in [1u64, 5] {
            let (commit, _) = make_commit(
                &committee,
                BlockHeight::new(h),
                CommitSource::Sync,
                Arc::clone(&sink),
            );
            assert!(matches!(
                coord.accumulate(commit, now()),
                AccumulateDecision::Skip
            ));
        }
        assert_eq!(coord.pending_len(), 0);
    }

    #[test]
    fn accumulate_dedups_same_block_hash() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();

        let (first, _) = make_commit(
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        let (dup, _) = make_commit(
            &committee,
            BlockHeight::new(1),
            CommitSource::Sync,
            Arc::clone(&sink),
        );
        // Same height + builder-deterministic header → same hash.
        assert_eq!(first.certified.block().hash(), dup.certified.block().hash());

        assert!(matches!(
            coord.accumulate(first, now()),
            AccumulateDecision::Accepted { .. }
        ));
        assert!(matches!(
            coord.accumulate(dup, now()),
            AccumulateDecision::Skip
        ));
        assert_eq!(coord.pending_len(), 1);
    }

    #[test]
    fn accumulate_notifies_immediately_within_lag_window() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();

        // Heights 1..=MAX_PERSISTENCE_LAG should all notify immediately.
        for h in 1..=BlockCommitCoordinator::MAX_PERSISTENCE_LAG {
            let (commit, _) = make_commit(
                &committee,
                BlockHeight::new(h),
                CommitSource::Aggregator,
                Arc::clone(&sink),
            );
            match coord.accumulate(commit, now()) {
                AccumulateDecision::Accepted {
                    height,
                    notify_now: true,
                    ..
                } => assert_eq!(height, BlockHeight::new(h)),
                _ => panic!("expected immediate notify at height {h}"),
            }
        }
    }

    #[test]
    fn accumulate_defers_notification_when_persistence_lag_exceeded() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();

        let max_lag = BlockCommitCoordinator::MAX_PERSISTENCE_LAG;
        // Anything beyond MAX_PERSISTENCE_LAG should defer the notification.
        let (commit, _) = make_commit(
            &committee,
            BlockHeight::new(max_lag + 1),
            CommitSource::Header,
            sink,
        );
        match coord.accumulate(commit, now()) {
            AccumulateDecision::Accepted {
                notify_now: false, ..
            } => {}
            _ => panic!("expected deferred notify"),
        }
    }

    #[test]
    fn accumulate_records_decision_on_pending_commit() {
        // The notify-now decision must be persisted on the PendingCommit
        // itself so flush sends BlockCommitted later iff we deferred at
        // accumulate time. This guards against a re-derivation bug where
        // a later `mark_persisted` could change the answer mid-flight.
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();

        let max_lag = BlockCommitCoordinator::MAX_PERSISTENCE_LAG;
        let (deferred, _) = make_commit(
            &committee,
            BlockHeight::new(max_lag + 1),
            CommitSource::Header,
            Arc::clone(&sink),
        );
        let (immediate, _) = make_commit(
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            sink,
        );

        let _ = coord.accumulate(deferred, now());
        let _ = coord.accumulate(immediate, now());

        let pending = &coord.pending;
        let h_deferred = pending
            .iter()
            .find(|c| c.certified.block().height() == BlockHeight::new(max_lag + 1))
            .unwrap();
        let h_immediate = pending
            .iter()
            .find(|c| c.certified.block().height() == BlockHeight::new(1))
            .unwrap();
        assert!(!h_deferred.committed_notified);
        assert!(h_immediate.committed_notified);
    }

    // ── mark_persisted ────────────────────────────────────────────────

    #[test]
    fn mark_persisted_is_monotonic() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::new(3));
        coord.mark_persisted(BlockHeight::new(7));
        assert_eq!(coord.persisted_height().inner(), 7);
        // Going backwards must not regress the high-water mark.
        coord.mark_persisted(BlockHeight::new(2));
        assert_eq!(coord.persisted_height().inner(), 7);
    }

    // ── prepared cache helpers ────────────────────────────────────────

    #[test]
    fn has_prepared_and_insert_prepared_roundtrip() {
        let committee = TestCommittee::new(4, 1);
        let coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (commit, prepared) =
            make_commit(&committee, BlockHeight::new(1), CommitSource::Sync, sink);
        let hash = commit.certified.block().hash();

        assert!(!coord.has_prepared(&hash));
        coord.insert_prepared(hash, BlockHeight::new(1), prepared);
        assert!(coord.has_prepared(&hash));
        assert_eq!(coord.prepared_len(), 1);
    }

    // ── flush ─────────────────────────────────────────────────────────

    fn install_prepared(
        coord: &BlockCommitCoordinator,
        hash: BlockHash,
        height: BlockHeight,
        sink: CommitSink,
        tag: u64,
    ) {
        coord.insert_prepared(hash, height, make_mock_prepared(sink, tag));
    }

    fn enqueue(
        coord: &mut BlockCommitCoordinator,
        committee: &TestCommittee,
        height: BlockHeight,
        source: CommitSource,
        sink: CommitSink,
    ) -> BlockHash {
        let (commit, prepared) = make_commit(committee, height, source, sink);
        let hash = commit.certified.block().hash();
        let _ = coord.accumulate(commit, now());
        coord.insert_prepared(hash, height, prepared);
        hash
    }

    #[test]
    fn flush_is_noop_when_pending_is_empty() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        coord.flush(&tx, &dispatch);

        assert!(committed_heights(&sink).is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn flush_writes_blocks_in_height_order_even_when_accumulated_out_of_order() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // Push h=3 before h=1, h=2 — flush must reorder before writing so
        // that JMT parents land before children.
        for h in [3u64, 1, 2] {
            enqueue(
                &mut coord,
                &committee,
                BlockHeight::new(h),
                CommitSource::Aggregator,
                Arc::clone(&sink),
            );
        }

        coord.flush(&tx, &dispatch);

        assert_eq!(committed_heights(&sink), vec![1, 2, 3]);
        // No deferred BlockCommitted (all immediate); BlockPersisted at top.
        let events = drain_protocol_events(&rx);
        assert_eq!(count_committed(&events), 0);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(3)));
    }

    #[test]
    fn flush_drops_blocks_already_persisted_by_sync_path() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(2),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        // Sync races ahead and persists h=1 before flush.
        coord.mark_persisted(BlockHeight::new(1));

        coord.flush(&tx, &dispatch);

        assert_eq!(committed_heights(&sink), vec![2]);
        let events = drain_protocol_events(&rx);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(2)));
    }

    #[test]
    fn flush_defers_when_prepared_commit_missing_for_first_block() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // Accumulate without ever inserting a prepared commit.
        let (commit, _) = make_commit(
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            sink.clone(),
        );
        let _ = coord.accumulate(commit, now());

        coord.flush(&tx, &dispatch);

        assert!(committed_heights(&sink).is_empty());
        assert_eq!(coord.pending_len(), 1, "block must remain pending");
        // No spawned write means no BlockPersisted should have fired.
        let events = drain_protocol_events(&rx);
        assert!(last_persisted_height(&events).is_none());
    }

    #[test]
    fn flush_defers_later_blocks_when_an_earlier_block_is_unprepared() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // h=1 ready
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        // h=2 accumulated but no prepared cached
        let (h2, _) = make_commit(
            &committee,
            BlockHeight::new(2),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        let _ = coord.accumulate(h2, now());
        // h=3 ready
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(3),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );

        coord.flush(&tx, &dispatch);

        // Only h=1 should make it through; h=2 and h=3 stay pending.
        assert_eq!(committed_heights(&sink), vec![1]);
        let pending_heights: Vec<u64> = coord
            .pending
            .iter()
            .map(|c| c.certified.block().height().inner())
            .collect();
        assert!(pending_heights.contains(&2));
        assert!(pending_heights.contains(&3));

        let events = drain_protocol_events(&rx);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(1)));
    }

    #[test]
    fn flush_emits_deferred_block_committed_events_after_persistence() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let max_lag = BlockCommitCoordinator::MAX_PERSISTENCE_LAG;
        let total = max_lag + 2;
        for h in 1..=total {
            enqueue(
                &mut coord,
                &committee,
                BlockHeight::new(h),
                CommitSource::Aggregator,
                Arc::clone(&sink),
            );
        }

        coord.flush(&tx, &dispatch);

        let events = drain_protocol_events(&rx);
        assert_eq!(count_committed(&events), 2, "events: {events:?}");
        assert_eq!(
            last_persisted_height(&events),
            Some(BlockHeight::new(total))
        );
    }

    #[test]
    fn flush_skips_when_a_previous_commit_is_still_in_flight() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        coord.commit_in_flight.store(true, Ordering::Release);

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );

        coord.flush(&tx, &dispatch);

        assert!(committed_heights(&sink).is_empty());
        assert_eq!(coord.pending_len(), 1);
    }

    #[test]
    fn flush_clears_in_flight_flag_so_subsequent_flush_drains_backlog() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        coord.flush(&tx, &dispatch);

        assert!(!coord.commit_in_flight.load(Ordering::Acquire));

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(2),
            CommitSource::Aggregator,
            Arc::clone(&sink),
        );
        coord.flush(&tx, &dispatch);

        assert_eq!(committed_heights(&sink), vec![1, 2]);
    }

    #[test]
    fn flush_consumes_prepared_commits_so_a_repeat_flush_finds_nothing() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let hash = enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
            sink,
        );
        coord.flush(&tx, &dispatch);

        assert!(!coord.has_prepared(&hash));
        assert_eq!(coord.pending_len(), 0);
    }

    #[test]
    fn flush_keeps_qc_only_path_prepared_commit_until_it_is_used() {
        let committee = TestCommittee::new(4, 1);
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let (commit, _) = make_commit(
            &committee,
            BlockHeight::new(1),
            CommitSource::Sync,
            Arc::clone(&sink),
        );
        let hash = commit.certified.block().hash();
        let tag = next_tag();
        install_prepared(&coord, hash, BlockHeight::new(1), Arc::clone(&sink), tag);
        let _ = coord.accumulate(commit, now());

        coord.flush(&tx, &dispatch);

        assert_eq!(committed_heights(&sink), vec![1]);
        assert_eq!(committed_tags(&sink), vec![tag]);
        assert!(!coord.has_prepared(&hash));
    }

    // ── Boundary trigger ─────────────────────────────────────────────────

    use hyperscale_types::{
        BeaconWitnessRoot, Block, BlockHeader, BoundedVec, CertificateRoot, InFlightCount,
        LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, Round, TransactionRoot,
    };

    /// Tag the pin hook pushes into the sink, distinguishing pins from
    /// block commits (which use their height as the tag).
    const PIN_TAG: u64 = u64::MAX;

    /// Epoch window used by the trigger tests.
    const EPOCH_MS: u64 = 1_000;

    fn pin_hook(sink: CommitSink) -> Arc<dyn Fn(BlockHeight) + Send + Sync> {
        Arc::new(move |height| sink.lock().unwrap().push((height, PIN_TAG)))
    }

    fn linked_qc(block_hash: BlockHash, wt_ms: u64) -> QuorumCertificate {
        let g = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        QuorumCertificate::new(
            block_hash,
            g.shard_id(),
            g.height(),
            g.parent_block_hash(),
            g.round(),
            g.signers().clone(),
            g.aggregated_signature(),
            WeightedTimestamp::from_millis(wt_ms),
        )
    }

    /// Build a commit whose header links to `parent_hash` via a
    /// `parent_qc` carrying `parent_qc_wt_ms` — the canonical timestamp
    /// the trigger adjudicates the parent with.
    fn make_linked_commit(
        height: u64,
        parent_hash: BlockHash,
        parent_qc_wt_ms: u64,
        sink: CommitSink,
    ) -> (PendingCommit, PreparedCommit, BlockHash) {
        let header = BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(height),
            parent_hash,
            linked_qc(parent_hash, parent_qc_wt_ms),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000 + height),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        let block = Block::Live {
            header,
            transactions: Arc::new(vec![].into()),
            certificates: Arc::new(vec![].into()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
        };
        let hash = block.hash();
        // SAFETY: synthetic test fixture, no real signature.
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(linked_qc(hash, 0));
        // SAFETY: synthetic test fixture; trigger tests don't exercise
        // the `Verified<CertifiedBlock>` predicate.
        let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            CertifiedBlock::new_unchecked(block, qc),
        ));
        let pending = PendingCommit {
            certified,
            source: CommitSource::Sync,
            committed_notified: false,
            witness: BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        };
        let prepared = make_mock_prepared(sink, height);
        (pending, prepared, hash)
    }

    fn enqueue_linked(
        coord: &mut BlockCommitCoordinator,
        height: u64,
        parent_hash: BlockHash,
        parent_qc_wt_ms: u64,
        sink: CommitSink,
    ) -> BlockHash {
        let (commit, prepared, hash) =
            make_linked_commit(height, parent_hash, parent_qc_wt_ms, sink);
        let _ = coord.accumulate(commit, now());
        coord.insert_prepared(hash, BlockHeight::new(height), prepared);
        hash
    }

    /// The crossing block's child carries the canonical QC; the pin for
    /// the crossing lands between the crossing's write and the child's.
    #[test]
    fn boundary_pin_fires_between_crossing_and_child() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        coord.set_boundary_trigger(EPOCH_MS, pin_hook(Arc::clone(&sink)), None);
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // b1 certified at wt 500, b2 at wt 900 (same epoch window), b3's
        // parent_qc at wt 1100 — past the 1000ms cut b2's parent sat
        // before, making b2 the crossing.
        let b1 = enqueue_linked(&mut coord, 1, BlockHash::ZERO, 500, Arc::clone(&sink));
        let b2 = enqueue_linked(&mut coord, 2, b1, 900, Arc::clone(&sink));
        let _b3 = enqueue_linked(&mut coord, 3, b2, 1_100, Arc::clone(&sink));

        coord.flush(&tx, &dispatch);

        let recorded: Vec<(u64, u64)> = sink
            .lock()
            .unwrap()
            .iter()
            .map(|(h, t)| (h.inner(), *t))
            .collect();
        assert_eq!(recorded, vec![(1, 1), (2, 2), (2, PIN_TAG), (3, 3)]);
    }

    /// The memo survives across flushes: the crossing and its child can
    /// land in different batches.
    #[test]
    fn boundary_pin_fires_across_separate_flushes() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        coord.set_boundary_trigger(EPOCH_MS, pin_hook(Arc::clone(&sink)), None);
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let b1 = enqueue_linked(&mut coord, 1, BlockHash::ZERO, 500, Arc::clone(&sink));
        let b2 = enqueue_linked(&mut coord, 2, b1, 900, Arc::clone(&sink));
        coord.flush(&tx, &dispatch);
        coord.mark_persisted(BlockHeight::new(2));

        let _b3 = enqueue_linked(&mut coord, 3, b2, 1_100, Arc::clone(&sink));
        coord.flush(&tx, &dispatch);

        let pins: Vec<u64> = sink
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t)| *t == PIN_TAG)
            .map(|(h, _)| h.inner())
            .collect();
        assert_eq!(pins, vec![2]);
    }

    /// A broken parent linkage (sync-path gap) skips the pin instead of
    /// adjudicating against the wrong parent.
    #[test]
    fn boundary_pin_skipped_on_broken_parent_linkage() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::GENESIS);
        let sink = empty_sink();
        coord.set_boundary_trigger(EPOCH_MS, pin_hook(Arc::clone(&sink)), None);
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let b1 = enqueue_linked(&mut coord, 1, BlockHash::ZERO, 500, Arc::clone(&sink));
        let _b2 = enqueue_linked(&mut coord, 2, b1, 900, Arc::clone(&sink));
        // b3's parent_qc points at a hash the memo doesn't hold.
        let _b3 = enqueue_linked(&mut coord, 3, BlockHash::ZERO, 1_100, Arc::clone(&sink));

        coord.flush(&tx, &dispatch);

        assert!(sink.lock().unwrap().iter().all(|(_, t)| *t != PIN_TAG));
    }

    /// A seeded memo lets the first post-restart commit adjudicate the
    /// committed tip it builds on.
    #[test]
    fn boundary_pin_fires_from_seeded_memo() {
        let mut coord = BlockCommitCoordinator::new(ShardId::ROOT, BlockHeight::new(2));
        let sink = empty_sink();
        let tip_hash = BlockHash::from_raw(Hash::from_bytes(b"tip"));
        coord.set_boundary_trigger(
            EPOCH_MS,
            pin_hook(Arc::clone(&sink)),
            Some(BoundaryMemo {
                hash: tip_hash,
                height: BlockHeight::new(2),
                parent_qc_wt: WeightedTimestamp::from_millis(900),
            }),
        );
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let _b3 = enqueue_linked(&mut coord, 3, tip_hash, 1_100, Arc::clone(&sink));
        coord.flush(&tx, &dispatch);

        let pins: Vec<u64> = sink
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t)| *t == PIN_TAG)
            .map(|(h, _)| h.inner())
            .collect();
        assert_eq!(pins, vec![2]);
    }
}
