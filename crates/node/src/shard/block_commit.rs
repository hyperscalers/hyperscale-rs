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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crossbeam::channel::Sender;
use hyperscale_core::{CommitSource, PreparedBlock, ProtocolEvent};
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::{record_block_committed, set_block_height};
use hyperscale_storage::{ChainEntry, ChainWriter, PendingChain, Storage};
use hyperscale_types::{
    Block, BlockHash, BlockHeight, CertifiedBlock, ConsensusReceipt, FinalizedWave, LocalTimestamp,
    QuorumCertificate, ShardGroupId, StateRoot,
};
use tracing::{debug, error};

use crate::io_loop::{ShardEvent, push_protocol_event};

/// Block + QC pair handed back to the `io_loop` to build a [`CertifiedBlock`]
/// for immediate `BlockCommitted` delivery. Cloned `Arc` handles to the
/// commit just enqueued in the pending backlog.
pub type NotifyHandles = (Arc<Block>, Arc<QuorumCertificate>);

/// Prepared commit cache: `block_hash → (block_height, prepared_commit)`.
///
/// Shared between the coordinator and the delegated-action dispatch closures
/// that produce prepared commits asynchronously on the consensus crypto pool.
pub type PreparedCommitMap<S> =
    HashMap<BlockHash, (BlockHeight, <S as ChainWriter>::PreparedCommit)>;

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
    prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,
) -> impl Fn(PreparedBlock<S::PreparedCommit>) + Send + Sync + 'static
where
    S: Storage,
{
    move |prep: PreparedBlock<S::PreparedCommit>| {
        let PreparedBlock {
            block_hash,
            parent_block_hash,
            block_height,
            prepared,
            receipts,
        } = prep;
        let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
        pending_chain.insert(
            block_hash,
            ChainEntry {
                parent_block_hash,
                height: block_height,
                receipts,
                jmt_snapshot,
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
    /// Block being committed.
    pub block: Arc<Block>,
    /// Quorum certificate certifying `block`.
    pub qc: Arc<QuorumCertificate>,
    /// How this node learned the certifying QC. Tagged into metrics so
    /// dashboards can separate aggregator/header/sync commit paths.
    pub source: CommitSource,
    /// Whether `BlockCommitted` was already fired immediately during
    /// accumulation (true) or deferred due to backpressure (false). The
    /// flush closure uses this to decide whether to send `BlockCommitted`
    /// after persistence.
    pub committed_notified: bool,
}

/// Outcome of accumulating a single commit.
pub enum AccumulateDecision {
    /// Block was already persisted or already pending; nothing to do.
    Skip,
    /// Block accepted into the pending backlog.
    Accepted {
        /// Height of the accepted block (used to advance the sync protocol).
        height: BlockHeight,
        /// If `Some`, the `io_loop` should fire `BlockCommitted` immediately
        /// with these handles. If `None`, persistence backpressure is active
        /// and the flush closure will fire the event after the disk write
        /// completes.
        notify_now: Option<NotifyHandles>,
    },
}

pub struct BlockCommitCoordinator<S: ChainWriter> {
    /// Shard this coordinator persists for. Stamped onto emitted
    /// `BlockPersisted` events.
    shard: ShardGroupId,

    /// Prepared commit cache shared with delegated dispatch closures.
    /// Stores `(block_height, prepared_commit)` keyed by block hash so
    /// stale entries can be pruned when they outlive their block.
    prepared_commits: Arc<Mutex<PreparedCommitMap<S>>>,

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
}

impl<S> BlockCommitCoordinator<S>
where
    S: ChainWriter + Send + Sync + 'static,
{
    /// Maximum number of blocks consensus can advance ahead of persistence
    /// before falling back to deferred `BlockCommitted` notification.
    pub const MAX_PERSISTENCE_LAG: u64 = 5;

    pub fn new(shard: ShardGroupId, initial_persisted_height: BlockHeight) -> Self {
        Self {
            shard,
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            pending: Vec::new(),
            persisted_height: initial_persisted_height,
            commit_in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Clone the prepared-commit cache handle for use in delegated action
    /// dispatch closures (which insert prepared commits asynchronously).
    pub fn prepared_commits_handle(&self) -> Arc<Mutex<PreparedCommitMap<S>>> {
        Arc::clone(&self.prepared_commits)
    }

    pub const fn persisted_height(&self) -> BlockHeight {
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
    pub fn insert_prepared(
        &self,
        block_hash: BlockHash,
        height: BlockHeight,
        prepared: S::PreparedCommit,
    ) {
        self.prepared_commits
            .lock()
            .unwrap()
            .insert(block_hash, (height, prepared));
    }

    /// Prepare a [`Action::CommitBlockByQcOnly`] block for the standard
    /// commit pipeline. Returns `false` if the block is already persisted
    /// (caller skips the rest of the pipeline), `true` otherwise.
    ///
    /// # Panics
    ///
    /// Panics on local state divergence: a computed-vs-canonical state
    /// root mismatch means local parent state itself diverged from
    /// canonical. Block-by-block sync can't repair this; operator
    /// intervention (restore from snapshot or wipe-and-resync) is
    /// required.
    ///
    /// [`Action::CommitBlockByQcOnly`]: hyperscale_core::Action::CommitBlockByQcOnly
    pub fn prepare_qc_only_commit(
        &self,
        pending_chain: &Arc<PendingChain<S>>,
        block: &Block,
        parent_state_root: StateRoot,
        parent_block_height: BlockHeight,
        source: CommitSource,
    ) -> bool
    where
        S: Storage,
    {
        let block_hash = block.hash();
        let height = block.height();

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
            return false;
        }

        // If the consensus path already produced the prepared commit, reuse it
        // — recomputing JMT here can produce a transient root mismatch and trip
        // the byzantine-detection assert below on a self-inflicted race.
        if self.has_prepared(&block_hash) {
            debug!(
                height = height.inner(),
                ?block_hash,
                "Reusing prepared commit from consensus path"
            );
            return true;
        }

        // Build view anchored at parent — includes prior synced blocks'
        // JMT snapshots so chained verification can find parent nodes.
        let view = pending_chain.view_at(block.header().parent_block_hash());
        let pending_snapshots = view.pending_snapshots().to_vec();

        let finalized_waves: Vec<Arc<FinalizedWave>> = block.certificates().to_vec();
        let (computed_root, prepared) = view.prepare_block_commit(
            parent_state_root,
            parent_block_height,
            &finalized_waves,
            height,
            &pending_snapshots,
            // `None` → the view drains its own base-read cache internally.
            None,
        );

        // The sync-block ingress validator rejects peer-shipped
        // divergent receipts before BFT sees the block, and
        // `WaveState`'s divergence detector keeps locally-produced
        // bad receipts out of `finalized`. A mismatch here means our
        // local parent state itself diverged from canonical — a JMT
        // or commit-batch bug, or pre-existing corruption in
        // `StateCf`. Block-by-block sync can't repair this; the
        // operator must restore from a state snapshot or
        // wipe-and-resync from genesis.
        if computed_root != block.header().state_root() {
            error!(
                height = height.inner(),
                ?block_hash,
                expected_root = ?block.header().state_root(),
                computed_root = ?computed_root,
                ?parent_state_root,
                parent_block_height = parent_block_height.inner(),
                ?source,
                "Local state divergence detected on synced block apply — \
                 parent state does not produce the canonical state root. \
                 Rebuild required: restore from state snapshot or \
                 resync from genesis."
            );
            panic!(
                "Local state divergence at height {}: parent state root \
                 {parent_state_root:?} does not produce canonical state \
                 root {expected:?} (computed {computed:?}). Operator \
                 intervention required.",
                height.inner(),
                expected = block.header().state_root(),
                computed = computed_root,
            );
        }

        let jmt_snapshot = Arc::new(S::jmt_snapshot(&prepared).clone());
        let receipts: Vec<Arc<ConsensusReceipt>> = finalized_waves
            .iter()
            .flat_map(|fw| fw.consensus_receipts())
            .collect();
        pending_chain.insert(
            block_hash,
            ChainEntry {
                parent_block_hash: block.header().parent_block_hash(),
                height,
                receipts,
                jmt_snapshot,
            },
        );

        self.insert_prepared(block_hash, height, prepared);

        debug!(
            height = height.inner(),
            ?block_hash,
            "Synced block prepared, queued for persist"
        );

        true
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
        let block_hash = commit.block.hash();
        let height = commit.block.height();

        // Skip blocks already persisted by the sync path.
        if height <= self.persisted_height {
            return AccumulateDecision::Skip;
        }

        // Dedup: consensus and sync paths can both reach commit for the same
        // block (e.g. self-proposed block whose child arrived via sync). Push
        // once; the prepared commit is also singular in `prepared_commits`.
        if self.pending.iter().any(|c| c.block.hash() == block_hash) {
            return AccumulateDecision::Skip;
        }

        // Block commit latency: time from proposal timestamp to now. Labeled
        // by `source` so dashboards can separate the three commit paths
        // (aggregator/header/sync), which have materially different latencies
        // under the 2-chain rule.
        let now_ms = now.as_millis();
        #[allow(clippy::cast_precision_loss)] // latency readout for metrics; ms→f64 lossy is fine
        let commit_latency_secs =
            (now_ms.saturating_sub(commit.block.header().timestamp().as_millis())) as f64 / 1000.0;
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
        let notify_now_decision = persistence_lag <= Self::MAX_PERSISTENCE_LAG;

        let notify_now = if notify_now_decision {
            Some((Arc::clone(&commit.block), Arc::clone(&commit.qc)))
        } else {
            tracing::debug!(
                height = height.inner(),
                persisted = self.persisted_height.inner(),
                lag = persistence_lag,
                "Deferring BlockCommitted — persistence backpressure"
            );
            None
        };

        commit.committed_notified = notify_now_decision;
        self.pending.push(commit);

        AccumulateDecision::Accepted { height, notify_now }
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
    /// the pinned thread via `event_tx`; see `IoLoop::event_sender`
    /// for the off-thread → pinned-thread routing convention.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn flush<D: Dispatch>(
        &mut self,
        storage: &Arc<S>,
        event_tx: &Sender<ShardEvent>,
        dispatch: &D,
    ) {
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
        commits.retain(|c| c.block.height().inner() > persisted);
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
        commits.sort_by_key(|c| c.block.height().inner());

        // `commits` is non-empty (checked above) and sorted ascending by height.
        let max_committed_height = commits
            .last()
            .expect("commits is non-empty after the early return")
            .block
            .height();

        // Blocks committed via CommitBlock need the PreparedCommit produced
        // asynchronously by VerifyStateRoot. If it's not ready yet, defer —
        // and defer all later blocks too to preserve height ordering. Blocks
        // that came through CommitBlockByQcOnly already have their
        // PreparedCommit cached inline so they don't hit this path.
        let mut ready_commits: Vec<PendingCommit> = Vec::with_capacity(commits.len());
        let mut prepared_map: Vec<S::PreparedCommit> = Vec::with_capacity(commits.len());
        {
            let mut cache = self.prepared_commits.lock().unwrap();
            let mut deferring = false;
            for commit in commits {
                if !deferring {
                    if let Some(prepared) = cache.remove(&commit.block.hash()).map(|(_, p)| p) {
                        prepared_map.push(prepared);
                        ready_commits.push(commit);
                        continue;
                    }
                    // First miss — flip to deferring so all later blocks
                    // defer too, preserving height ordering.
                    deferring = true;
                    tracing::debug!(
                        height = commit.block.height().inner(),
                        certs = commit.block.certificates().len(),
                        "Deferring block commit — awaiting PreparedCommit from VerifyStateRoot"
                    );
                }
                self.pending.push(commit);
            }
            // Prune stale entries that outlived their blocks.
            let before = cache.len();
            cache.retain(|_, (h, _)| *h > max_committed_height);
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

        let commits = ready_commits;
        let storage = Arc::clone(storage);
        let event_tx = event_tx.clone();
        let in_flight = Arc::clone(&self.commit_in_flight);
        let shard = self.shard;

        self.commit_in_flight.store(true, Ordering::Release);

        dispatch.spawn(DispatchPool::Io, move || {
            let mut batch: Vec<(S::PreparedCommit, Arc<Block>, Arc<QuorumCertificate>)> =
                Vec::with_capacity(commits.len());

            let heights: Vec<BlockHeight> = commits.iter().map(|c| c.block.height()).collect();

            // Wrap commits in Option so we can take() them for deferred notifications.
            let mut commit_slots: Vec<Option<PendingCommit>> =
                commits.into_iter().map(Some).collect();

            for (i, prepared) in prepared_map.into_iter().enumerate() {
                let commit = commit_slots[i].as_ref().unwrap();
                batch.push((prepared, Arc::clone(&commit.block), Arc::clone(&commit.qc)));
            }

            let _roots = storage.commit_prepared_blocks(batch);

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
                    let certified = Arc::new(CertifiedBlock::new_unchecked(
                        Arc::unwrap_or_clone(commit.block),
                        Arc::unwrap_or_clone(commit.qc),
                    ));
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
    use hyperscale_storage::tree::CollectedWrites;
    use hyperscale_storage::{BaseReadCache, JmtSnapshot};
    use hyperscale_test_helpers::{TestCommittee, make_live_block};
    use hyperscale_types::{
        BlockHeight, FinalizedWave, QuorumCertificate, ShardGroupId, StateRoot, ValidatorId,
    };

    use super::*;
    use crate::io_loop::ShardScopedInput;

    /// Mock prepared-commit handle. Carries an empty `JmtSnapshot` (the
    /// coordinator only inspects it via `jmt_snapshot()` from action
    /// handlers, never inside `flush`) plus an opaque tag we can assert on
    /// after the spawned closure runs.
    struct MockPrepared {
        snapshot: JmtSnapshot,
        tag: u64,
    }

    /// `ChainWriter` impl that records the order in which heights are committed.
    /// `prepare_block_commit` / `commit_block` are unreachable in these tests
    /// because `BlockCommitCoordinator` only calls `commit_prepared_blocks`.
    #[derive(Default)]
    struct MockStorage {
        committed: Mutex<Vec<(BlockHeight, u64)>>,
    }

    impl MockStorage {
        fn committed_heights(&self) -> Vec<u64> {
            self.committed
                .lock()
                .unwrap()
                .iter()
                .map(|(h, _)| h.inner())
                .collect()
        }

        fn committed_tags(&self) -> Vec<u64> {
            self.committed
                .lock()
                .unwrap()
                .iter()
                .map(|(_, t)| *t)
                .collect()
        }
    }

    impl ChainWriter for MockStorage {
        type PreparedCommit = MockPrepared;

        fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot {
            &prepared.snapshot
        }

        fn prepare_block_commit(
            &self,
            _parent_state_root: StateRoot,
            _parent_block_height: BlockHeight,
            _finalized_waves: &[Arc<FinalizedWave>],
            _block_height: BlockHeight,
            _pending_snapshots: &[Arc<JmtSnapshot>],
            _base_reads: Option<&BaseReadCache>,
        ) -> (StateRoot, Self::PreparedCommit) {
            unreachable!("BlockCommitCoordinator does not call prepare_block_commit");
        }

        #[allow(clippy::significant_drop_tightening)] // batching the lock matches the production write path
        fn commit_prepared_blocks(
            &self,
            blocks: Vec<(Self::PreparedCommit, Arc<Block>, Arc<QuorumCertificate>)>,
        ) -> Vec<StateRoot> {
            let mut committed = self.committed.lock().unwrap();
            let mut roots = Vec::with_capacity(blocks.len());
            for (prepared, block, _qc) in blocks {
                committed.push((block.height(), prepared.tag));
                roots.push(StateRoot::ZERO);
            }
            roots
        }

        fn commit_block(&self, _block: &Arc<Block>, _qc: &Arc<QuorumCertificate>) -> StateRoot {
            unreachable!("BlockCommitCoordinator does not call commit_block");
        }
    }

    fn empty_snapshot(height: BlockHeight) -> JmtSnapshot {
        JmtSnapshot::from_collected_writes(
            CollectedWrites {
                nodes: Vec::new(),
                stale_node_keys: Vec::new(),
            },
            StateRoot::ZERO,
            BlockHeight::GENESIS,
            StateRoot::ZERO,
            height,
        )
    }

    /// Build a `(PendingCommit, prepared_handle)` pair for `height`. Each
    /// height gets a distinct timestamp so block hashes differ.
    fn make_commit(
        committee: &TestCommittee,
        height: BlockHeight,
        source: CommitSource,
    ) -> (PendingCommit, MockPrepared) {
        let block = make_live_block(
            ShardGroupId::new(0),
            height,
            /* timestamp_ms */ 1_000 + height.inner(),
            ValidatorId::new(0),
            vec![],
            vec![],
        );
        let block_hash = block.hash();
        let qc = {
            let __qc = QuorumCertificate::genesis(block.header().shard_group_id());
            QuorumCertificate::new(
                block_hash,
                __qc.shard_group_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            )
        };
        let _ = committee; // committee unused here but kept for future signing-required tests
        let pending = PendingCommit {
            block: Arc::new(block),
            qc: Arc::new(qc),
            source,
            committed_notified: false,
        };
        let prepared = MockPrepared {
            snapshot: empty_snapshot(height),
            tag: height.inner(),
        };
        (pending, prepared)
    }

    /// Tag generator used by `make_commit_with_tag` for tests that care about
    /// distinguishing two prepared handles for the same height.
    static TAG_GEN: AtomicU64 = AtomicU64::new(10_000);

    fn next_tag() -> u64 {
        TAG_GEN.fetch_add(1, Ordering::Relaxed)
    }

    fn drain_protocol_events(rx: &Receiver<ShardEvent>) -> Vec<ProtocolEvent> {
        let mut out = Vec::new();
        while let Ok(ShardEvent::Shard(_, ShardScopedInput::Protocol(event))) = rx.try_recv() {
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

    #[test]
    fn accumulate_skips_block_at_or_below_persisted_height() {
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::new(5));

        for h in [1u64, 5] {
            let (commit, _) = make_commit(&committee, BlockHeight::new(h), CommitSource::Sync);
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
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);

        let (first, _) = make_commit(&committee, BlockHeight::new(1), CommitSource::Aggregator);
        let (dup, _) = make_commit(&committee, BlockHeight::new(1), CommitSource::Sync);
        // Same height + builder-deterministic header → same hash.
        assert_eq!(first.block.hash(), dup.block.hash());

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
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);

        // Heights 1..=MAX_PERSISTENCE_LAG should all notify immediately.
        for h in 1..=BlockCommitCoordinator::<MockStorage>::MAX_PERSISTENCE_LAG {
            let (commit, _) =
                make_commit(&committee, BlockHeight::new(h), CommitSource::Aggregator);
            match coord.accumulate(commit, now()) {
                AccumulateDecision::Accepted {
                    height,
                    notify_now: Some(_),
                } => assert_eq!(height, BlockHeight::new(h)),
                _ => panic!("expected immediate notify at height {h}"),
            }
        }
    }

    #[test]
    fn accumulate_defers_notification_when_persistence_lag_exceeded() {
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);

        let max_lag = BlockCommitCoordinator::<MockStorage>::MAX_PERSISTENCE_LAG;
        // Anything beyond MAX_PERSISTENCE_LAG should defer the notification.
        let (commit, _) = make_commit(
            &committee,
            BlockHeight::new(max_lag + 1),
            CommitSource::Header,
        );
        match coord.accumulate(commit, now()) {
            AccumulateDecision::Accepted {
                notify_now: None, ..
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
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);

        let max_lag = BlockCommitCoordinator::<MockStorage>::MAX_PERSISTENCE_LAG;
        let (deferred, _) = make_commit(
            &committee,
            BlockHeight::new(max_lag + 1),
            CommitSource::Header,
        );
        let (immediate, _) = make_commit(&committee, BlockHeight::new(1), CommitSource::Aggregator);

        let _ = coord.accumulate(deferred, now());
        let _ = coord.accumulate(immediate, now());

        let pending = &coord.pending;
        let h_deferred = pending
            .iter()
            .find(|c| c.block.height() == BlockHeight::new(max_lag + 1))
            .unwrap();
        let h_immediate = pending
            .iter()
            .find(|c| c.block.height() == BlockHeight::new(1))
            .unwrap();
        assert!(!h_deferred.committed_notified);
        assert!(h_immediate.committed_notified);
    }

    // ── mark_persisted ────────────────────────────────────────────────

    #[test]
    fn mark_persisted_is_monotonic() {
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::new(3));
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
        let coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let (commit, prepared) = make_commit(&committee, BlockHeight::new(1), CommitSource::Sync);
        let hash = commit.block.hash();

        assert!(!coord.has_prepared(&hash));
        coord.insert_prepared(hash, BlockHeight::new(1), prepared);
        assert!(coord.has_prepared(&hash));
        assert_eq!(coord.prepared_len(), 1);
    }

    // ── flush ─────────────────────────────────────────────────────────

    fn install_prepared(
        coord: &BlockCommitCoordinator<MockStorage>,
        hash: BlockHash,
        height: BlockHeight,
        tag: u64,
    ) {
        coord.insert_prepared(
            hash,
            height,
            MockPrepared {
                snapshot: empty_snapshot(height),
                tag,
            },
        );
    }

    fn enqueue(
        coord: &mut BlockCommitCoordinator<MockStorage>,
        committee: &TestCommittee,
        height: BlockHeight,
        source: CommitSource,
    ) -> BlockHash {
        let (commit, prepared) = make_commit(committee, height, source);
        let hash = commit.block.hash();
        let _ = coord.accumulate(commit, now());
        coord.insert_prepared(hash, height, prepared);
        hash
    }

    #[test]
    fn flush_is_noop_when_pending_is_empty() {
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        coord.flush(&storage, &tx, &dispatch);

        assert!(storage.committed_heights().is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn flush_writes_blocks_in_height_order_even_when_accumulated_out_of_order() {
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
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
            );
        }

        coord.flush(&storage, &tx, &dispatch);

        assert_eq!(storage.committed_heights(), vec![1, 2, 3]);
        // No deferred BlockCommitted (all immediate); BlockPersisted at top.
        let events = drain_protocol_events(&rx);
        assert_eq!(count_committed(&events), 0);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(3)));
    }

    #[test]
    fn flush_drops_blocks_already_persisted_by_sync_path() {
        // Sync may persist a block between accumulate (which accepted it
        // because persisted_height was lower) and flush (where the height
        // is now stale). The retain step must drop these silently.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
        );
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(2),
            CommitSource::Aggregator,
        );
        // Sync races ahead and persists h=1 before flush.
        coord.mark_persisted(BlockHeight::new(1));

        coord.flush(&storage, &tx, &dispatch);

        assert_eq!(storage.committed_heights(), vec![2]);
        let events = drain_protocol_events(&rx);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(2)));
    }

    #[test]
    fn flush_defers_when_prepared_commit_missing_for_first_block() {
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // Accumulate without ever inserting a prepared commit.
        let (commit, _) = make_commit(&committee, BlockHeight::new(1), CommitSource::Aggregator);
        let _ = coord.accumulate(commit, now());

        coord.flush(&storage, &tx, &dispatch);

        assert!(storage.committed_heights().is_empty());
        assert_eq!(coord.pending_len(), 1, "block must remain pending");
        // No spawned write means no BlockPersisted should have fired.
        let events = drain_protocol_events(&rx);
        assert!(last_persisted_height(&events).is_none());
    }

    #[test]
    fn flush_defers_later_blocks_when_an_earlier_block_is_unprepared() {
        // Height ordering must be preserved across flush boundaries: if h=2
        // is missing its prepared commit, h=3 must wait too — even though its
        // own prepared commit is ready — to keep parents before children.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        // h=1 ready
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
        );
        // h=2 accumulated but no prepared cached
        let (h2, _) = make_commit(&committee, BlockHeight::new(2), CommitSource::Aggregator);
        let _ = coord.accumulate(h2, now());
        // h=3 ready
        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(3),
            CommitSource::Aggregator,
        );

        coord.flush(&storage, &tx, &dispatch);

        // Only h=1 should make it through; h=2 and h=3 stay pending.
        assert_eq!(storage.committed_heights(), vec![1]);
        let pending_heights: Vec<u64> = coord
            .pending
            .iter()
            .map(|c| c.block.height().inner())
            .collect();
        assert!(pending_heights.contains(&2));
        assert!(pending_heights.contains(&3));

        let events = drain_protocol_events(&rx);
        assert_eq!(last_persisted_height(&events), Some(BlockHeight::new(1)));
    }

    #[test]
    fn flush_emits_deferred_block_committed_events_after_persistence() {
        // Pre-stage backpressure: persisted_height stays at 0 while we push
        // commits up through height MAX_PERSISTENCE_LAG + 2. The first few
        // notify immediately; the tail defers and must receive a
        // BlockCommitted from the spawned write closure.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let max_lag = BlockCommitCoordinator::<MockStorage>::MAX_PERSISTENCE_LAG;
        let total = max_lag + 2;
        for h in 1..=total {
            enqueue(
                &mut coord,
                &committee,
                BlockHeight::new(h),
                CommitSource::Aggregator,
            );
        }

        coord.flush(&storage, &tx, &dispatch);

        let events = drain_protocol_events(&rx);
        // Exactly the deferred ones (heights MAX_LAG+1, MAX_LAG+2) come back
        // through the channel — immediate notifies were short-circuited at
        // accumulate time and aren't re-fired.
        assert_eq!(count_committed(&events), 2, "events: {events:?}");
        assert_eq!(
            last_persisted_height(&events),
            Some(BlockHeight::new(total))
        );
    }

    #[test]
    fn flush_skips_when_a_previous_commit_is_still_in_flight() {
        // The in-flight gate is the only thing that prevents two storage
        // writes from racing on the I/O pool, where ordering between
        // separate spawn() calls is not guaranteed.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        coord.commit_in_flight.store(true, Ordering::Release);

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
        );

        coord.flush(&storage, &tx, &dispatch);

        assert!(storage.committed_heights().is_empty());
        assert_eq!(coord.pending_len(), 1);
    }

    #[test]
    fn flush_clears_in_flight_flag_so_subsequent_flush_drains_backlog() {
        // Backlog drains because the spawned closure clears commit_in_flight
        // before sending BlockPersisted; the next feed_event → flush call
        // sees the cleared flag and proceeds.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
        );
        coord.flush(&storage, &tx, &dispatch);

        assert!(!coord.commit_in_flight.load(Ordering::Acquire));

        enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(2),
            CommitSource::Aggregator,
        );
        coord.flush(&storage, &tx, &dispatch);

        assert_eq!(storage.committed_heights(), vec![1, 2]);
    }

    #[test]
    fn flush_consumes_prepared_commits_so_a_repeat_flush_finds_nothing() {
        // The prepared cache is keyed by block hash; once the write spawned,
        // the entry must be gone so a stray re-flush of the same height
        // can't double-write.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let hash = enqueue(
            &mut coord,
            &committee,
            BlockHeight::new(1),
            CommitSource::Aggregator,
        );
        coord.flush(&storage, &tx, &dispatch);

        assert!(!coord.has_prepared(&hash));
        assert_eq!(coord.pending_len(), 0);
    }

    #[test]
    fn flush_keeps_qc_only_path_prepared_commit_until_it_is_used() {
        // QC-only commits insert their PreparedCommit inline (via
        // insert_prepared) rather than asynchronously through VerifyStateRoot.
        // Flush must consume that handle the same way the async path does.
        let committee = TestCommittee::new(4, 1);
        let mut coord =
            BlockCommitCoordinator::<MockStorage>::new(ShardGroupId::new(0), BlockHeight::GENESIS);
        let storage = Arc::new(MockStorage::default());
        let (tx, _rx) = unbounded();
        let dispatch = SyncDispatch::new();

        let (commit, _) = make_commit(&committee, BlockHeight::new(1), CommitSource::Sync);
        let hash = commit.block.hash();
        let tag = next_tag();
        install_prepared(&coord, hash, BlockHeight::new(1), tag);
        let _ = coord.accumulate(commit, now());

        coord.flush(&storage, &tx, &dispatch);

        assert_eq!(storage.committed_heights(), vec![1]);
        assert_eq!(storage.committed_tags(), vec![tag]);
        assert!(!coord.has_prepared(&hash));
    }
}
