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

use crossbeam::channel::Sender;
use hyperscale_core::{CommitSource, NodeInput, ProtocolEvent};
use hyperscale_metrics as metrics;
use hyperscale_storage::ChainWriter;
use hyperscale_types::{
    Block, BlockHash, BlockHeight, CertifiedBlock, LocalTimestamp, QuorumCertificate,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Block + QC pair handed back to the `io_loop` to build a [`CertifiedBlock`]
/// for immediate `BlockCommitted` delivery. Cloned `Arc` handles to the
/// commit just enqueued in the pending backlog.
pub(crate) type NotifyHandles = (Arc<Block>, Arc<QuorumCertificate>);

/// Prepared commit cache: `block_hash → (block_height, prepared_commit)`.
///
/// Shared between the coordinator and the delegated-action dispatch closures
/// that produce prepared commits asynchronously on the consensus crypto pool.
pub(crate) type PreparedCommitMap<S> =
    HashMap<BlockHash, (BlockHeight, <S as ChainWriter>::PreparedCommit)>;

/// A block commit waiting to be flushed to storage.
///
/// All blocks — consensus and sync — go through the same commit pipeline:
/// `VerifyStateRoot` → `PreparedCommit` → `commit_prepared_blocks`.
pub(crate) struct PendingCommit {
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
pub(crate) enum AccumulateDecision {
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

pub(crate) struct BlockCommitCoordinator<S: ChainWriter> {
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

    /// Set while an async commit closure is running on the execution pool.
    /// Bouncing this prevents spawning a second closure (Rayon does not
    /// guarantee FIFO ordering across separate `spawn()` calls). The closure
    /// clears the flag before sending its final event so the resulting
    /// `feed_event` → `flush` drains any backlog.
    commit_in_flight: Arc<AtomicBool>,

    /// Closure prepared by [`flush`](Self::flush), drained by the runner.
    /// Production uses `tokio::spawn_blocking`; simulation runs inline.
    pending_task: Option<Box<dyn FnOnce() + Send>>,
}

impl<S> BlockCommitCoordinator<S>
where
    S: ChainWriter + Send + Sync + 'static,
{
    /// Maximum number of blocks consensus can advance ahead of persistence
    /// before falling back to deferred `BlockCommitted` notification.
    pub const MAX_PERSISTENCE_LAG: u64 = 5;

    pub fn new(initial_persisted_height: BlockHeight) -> Self {
        Self {
            prepared_commits: Arc::new(Mutex::new(HashMap::new())),
            pending: Vec::new(),
            persisted_height: initial_persisted_height,
            commit_in_flight: Arc::new(AtomicBool::new(false)),
            pending_task: None,
        }
    }

    /// Clone the prepared-commit cache handle for use in delegated action
    /// dispatch closures (which insert prepared commits asynchronously).
    pub fn prepared_commits_handle(&self) -> Arc<Mutex<PreparedCommitMap<S>>> {
        Arc::clone(&self.prepared_commits)
    }

    pub fn persisted_height(&self) -> BlockHeight {
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

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn prepared_len(&self) -> usize {
        self.prepared_commits.lock().unwrap().len()
    }

    pub fn drain_task(&mut self) -> Option<Box<dyn FnOnce() + Send>> {
        self.pending_task.take()
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
            (now_ms.saturating_sub(commit.block.header().timestamp.as_millis())) as f64 / 1000.0;
        metrics::record_block_committed(height.0, commit_latency_secs, commit.source.as_str());
        metrics::set_block_height(height.0);

        // Fire BlockCommitted immediately unless persistence is falling
        // too far behind (backpressure). When deferred, flush sends
        // BlockCommitted after the disk write instead.
        let persistence_lag = height.0.saturating_sub(self.persisted_height.0);
        let notify_now_decision = persistence_lag <= Self::MAX_PERSISTENCE_LAG;

        let notify_now = if notify_now_decision {
            Some((Arc::clone(&commit.block), Arc::clone(&commit.qc)))
        } else {
            tracing::debug!(
                height = height.0,
                persisted = self.persisted_height.0,
                lag = persistence_lag,
                "Deferring BlockCommitted — persistence backpressure"
            );
            None
        };

        commit.committed_notified = notify_now_decision;
        self.pending.push(commit);

        AccumulateDecision::Accepted { height, notify_now }
    }

    /// Drain pending commits into a single async closure.
    ///
    /// Spawns the closure on success; sets `commit_in_flight` so subsequent
    /// flushes defer until the closure clears it. If a previous closure is
    /// still running, all pending commits remain queued for a future flush.
    ///
    /// Receipt bundles are not drained here — they're already embedded in
    /// each `PreparedCommit`. Writing them in a single closure guarantees
    /// ordering: Rayon does not guarantee FIFO ordering across separate
    /// `spawn()` calls.
    pub fn flush(&mut self, storage: &Arc<S>, event_tx: &Sender<NodeInput>) {
        if self.pending.is_empty() {
            return;
        }

        // Defer if a previous async commit is still running on the exec pool.
        if self.commit_in_flight.load(Ordering::Acquire) {
            return;
        }

        let mut commits = std::mem::take(&mut self.pending);

        // Drop blocks already persisted by the sync path.
        let persisted = self.persisted_height.0;
        commits.retain(|c| c.block.height().0 > persisted);
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
        commits.sort_by_key(|c| c.block.height().0);

        let max_committed_height = commits
            .iter()
            .map(|c| c.block.height())
            .max()
            .unwrap_or(BlockHeight::GENESIS);

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
                let prepared = if deferring {
                    None
                } else {
                    cache.remove(&commit.block.hash()).map(|(_, p)| p)
                };

                let not_ready = prepared.is_none();

                if deferring || not_ready {
                    if !deferring {
                        tracing::debug!(
                            height = commit.block.height().0,
                            certs = commit.block.certificates().len(),
                            "Deferring block commit — awaiting PreparedCommit from VerifyStateRoot"
                        );
                        deferring = true;
                    }
                    if let Some(p) = prepared {
                        let bh = commit.block.hash();
                        let h = commit.block.height();
                        cache.insert(bh, (h, p));
                    }
                    self.pending.push(commit);
                } else {
                    prepared_map.push(prepared.unwrap());
                    ready_commits.push(commit);
                }
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

        self.commit_in_flight.store(true, Ordering::Release);

        self.pending_task = Some(Box::new(move || {
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

            let max_persisted = heights
                .iter()
                .copied()
                .max()
                .unwrap_or(BlockHeight::GENESIS);

            // Send deferred BlockCommitted events for blocks that weren't notified
            // at accumulation time (due to persistence backpressure).
            for (i, _) in heights.iter().enumerate() {
                if !already_notified[i] {
                    let commit = commit_slots[i].take().unwrap();
                    let certified = CertifiedBlock::new_unchecked(
                        Arc::unwrap_or_clone(commit.block),
                        Arc::unwrap_or_clone(commit.qc),
                    );
                    let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                        certified,
                    }));
                }
            }

            // Clear the in-flight flag before sending BlockPersisted. The
            // channel send synchronizes-with recv on the main thread, so
            // the flag is guaranteed visible when the resulting feed_event
            // calls flush to drain any backlog.
            in_flight.store(false, Ordering::Release);

            let _ = event_tx.send(NodeInput::Protocol(ProtocolEvent::BlockPersisted {
                height: max_persisted,
            }));
        }));
    }
}
