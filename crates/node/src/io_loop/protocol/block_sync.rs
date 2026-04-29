//! Sync protocol state machine.
//!
//! Pure synchronous state machine for block sync. Tracks height queues
//! and validates responses. Does NOT handle peer selection, async dispatch,
//! or banning — those stay in the runner-specific wrapper.
//!
//! # Usage
//!
//! ```text
//! Runner ──► BlockSyncProtocol::handle(BlockSyncInput) ──► Vec<BlockSyncOutput>
//! ```
//!
//! Production: `BlockSyncManager` wraps this, maps outputs to tokio tasks.
//! Simulation: feeds inputs/outputs synchronously via event queue.

use hyperscale_metrics as metrics;
use hyperscale_types::{BlockHeight, CertifiedBlock};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Initial backoff for a deferred height after its first fetch failure.
const DEFERRAL_BASE_MS: u64 = 1_000;
/// Multiplier applied to the previous round's backoff on each subsequent failure.
const DEFERRAL_MULTIPLIER: f64 = 2.0;
/// Backoff cap; subsequent rounds plateau here rather than growing unbounded.
const DEFERRAL_MAX_MS: u64 = 30_000;

/// Per-height deferral state: how many rounds we've backed off and when the
/// next retry is permitted. Default state is "ready immediately" (no rounds,
/// no deadline yet) — `advance_round` is what installs a deadline.
#[derive(Debug, Default)]
struct DeferralBackoff {
    rounds: u32,
    next_retry_at: Option<Instant>,
}

impl DeferralBackoff {
    fn is_ready(&self, now: Instant) -> bool {
        self.next_retry_at.is_none_or(|deadline| now >= deadline)
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap
    )] // backoff ms fits u64 in practice; rounds is small
    fn advance_round(&mut self, now: Instant) {
        self.rounds = self.rounds.saturating_add(1);
        let backoff_ms =
            ((DEFERRAL_BASE_MS as f64) * DEFERRAL_MULTIPLIER.powi(self.rounds as i32 - 1)) as u64;
        let backoff_ms = backoff_ms.min(DEFERRAL_MAX_MS);
        self.next_retry_at = Some(now + Duration::from_millis(backoff_ms));
    }
}

/// Configuration for the sync protocol.
#[derive(Debug, Clone)]
pub struct BlockSyncConfig {
    /// Maximum number of concurrent fetch requests.
    pub max_concurrent_fetches: usize,

    /// Maximum number of heights to queue ahead of committed height.
    /// Creates a sliding window that limits memory usage.
    pub sync_window_size: u64,
}

impl Default for BlockSyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_fetches: 32,
            sync_window_size: 64,
        }
    }
}

/// Current sync state for external APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSyncStateKind {
    /// Not syncing, node is up to date.
    Idle,
    /// Actively fetching and applying blocks.
    Syncing,
}

impl BlockSyncStateKind {
    /// Returns a string representation for metrics/logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Syncing => "syncing",
        }
    }
}

/// Sync status snapshot for external APIs.
#[derive(Debug, Clone, Serialize)]
pub struct BlockSyncStatus {
    /// Current sync state.
    pub state: BlockSyncStateKind,
    /// Current committed height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind target.
    pub blocks_behind: u64,
    /// Number of pending fetch requests.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

impl Default for BlockSyncStatus {
    fn default() -> Self {
        Self {
            state: BlockSyncStateKind::Idle,
            current_height: 0,
            target_height: None,
            blocks_behind: 0,
            pending_fetches: 0,
            queued_heights: 0,
        }
    }
}

/// Inputs to the sync protocol state machine.
#[derive(Debug)]
#[allow(missing_docs)] // variant payloads are self-describing (height, now, block)
pub enum BlockSyncInput {
    /// Start or update sync target.
    StartSync { target_height: BlockHeight },
    /// A block response was received.
    /// `None` means the peer did not have the block.
    BlockResponseReceived {
        height: BlockHeight,
        block: Option<Box<CertifiedBlock>>,
        now: Instant,
    },
    /// A block fetch failed after all retries.
    BlockFetchFailed { height: BlockHeight, now: Instant },
    /// A block was committed by the state machine.
    BlockCommitted { height: BlockHeight },
    /// Periodic tick: promotes deferred heights whose backoff has elapsed
    /// back into the fetch queue.
    Tick { now: Instant },
}

/// Outputs from the sync protocol state machine.
#[derive(Debug)]
#[allow(missing_docs)] // variant payloads are self-describing (height, certified)
pub enum BlockSyncOutput {
    /// Request the runner to fetch a block at this height. `target_height`
    /// is the sync target, passed through to the serving peer so it can
    /// choose between `Block::Live` and `Block::Sealed`. `force_full` is
    /// set after a rehydration miss on this height — the next request
    /// must omit the inventory bloom so the responder cannot elide bodies
    /// the requester couldn't resolve last time.
    FetchBlock {
        height: BlockHeight,
        target_height: BlockHeight,
        force_full: bool,
    },
    /// A validated block is ready to deliver to BFT.
    DeliverBlock { certified: Box<CertifiedBlock> },
    /// Sync is complete (reached target).
    SyncComplete { height: BlockHeight },
}

/// Sync protocol state machine.
///
/// Tracks which heights need fetching and validates responses.
/// The runner drives this by calling `handle()` with inputs and
/// executing the returned outputs.
pub struct BlockSyncProtocol {
    config: BlockSyncConfig,
    sync_target: Option<BlockHeight>,
    committed_height: BlockHeight,
    heights_to_fetch: BinaryHeap<Reverse<BlockHeight>>,
    heights_queued: HashSet<BlockHeight>,
    in_flight: HashSet<BlockHeight>,
    /// Heights whose last fetch failed; held out of `heights_to_fetch`
    /// until their backoff deadline elapses.
    deferred: HashMap<BlockHeight, DeferralBackoff>,
    /// Heights whose previous response failed rehydration. The next fetch
    /// for these heights must omit the inventory bloom so the responder
    /// cannot elide bodies the requester couldn't resolve last time.
    /// Drained when the height is committed or sync completes.
    force_full_refetch: HashSet<BlockHeight>,
}

impl BlockSyncProtocol {
    /// Create a new sync protocol state machine.
    #[must_use]
    pub fn new(config: BlockSyncConfig) -> Self {
        Self {
            config,
            sync_target: None,
            committed_height: BlockHeight::GENESIS,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            in_flight: HashSet::new(),
            deferred: HashMap::new(),
            force_full_refetch: HashSet::new(),
        }
    }

    /// Mark `height` so its next fetch omits the inventory bloom. Called
    /// after a rehydration miss: the responder elided bodies the requester
    /// couldn't resolve, so the next request must allow no elision.
    pub fn mark_force_full_refetch(&mut self, height: BlockHeight) {
        self.force_full_refetch.insert(height);
    }

    /// True if any heights are parked awaiting backoff. Lets the runner
    /// keep its periodic tick alive while the heap may be empty.
    #[must_use]
    pub fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: BlockSyncInput) -> Vec<BlockSyncOutput> {
        match input {
            BlockSyncInput::StartSync { target_height } => self.handle_start_sync(target_height),
            BlockSyncInput::BlockResponseReceived { height, block, now } => {
                self.handle_block_response(height, block.map(|b| *b), now)
            }
            BlockSyncInput::BlockFetchFailed { height, now } => {
                self.handle_block_fetch_failed(height, now)
            }
            BlockSyncInput::BlockCommitted { height } => self.handle_block_committed(height),
            BlockSyncInput::Tick { now } => self.handle_tick(now),
        }
    }

    /// Check if currently syncing.
    #[must_use]
    pub const fn is_syncing(&self) -> bool {
        self.sync_target.is_some()
    }

    /// Number of blocks behind target (for metrics).
    #[must_use]
    pub fn blocks_behind(&self) -> u64 {
        self.sync_target
            .map_or(0, |t| t.0.saturating_sub(self.committed_height.0))
    }

    /// Get current sync status.
    #[must_use]
    pub fn status(&self) -> BlockSyncStatus {
        BlockSyncStatus {
            state: if self.sync_target.is_some() {
                BlockSyncStateKind::Syncing
            } else {
                BlockSyncStateKind::Idle
            },
            current_height: self.committed_height.0,
            target_height: self.sync_target.map(|h| h.0),
            blocks_behind: self
                .sync_target
                .map_or(0, |t| t.0.saturating_sub(self.committed_height.0)),
            pending_fetches: self.in_flight.len(),
            queued_heights: self.heights_queued.len() + self.deferred.len(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(&mut self, target_height: BlockHeight) -> Vec<BlockSyncOutput> {
        if self.sync_target.is_some_and(|t| t >= target_height) {
            return vec![];
        }

        info!(
            target_height = target_height.0,
            committed = self.committed_height.0,
            "Starting sync"
        );

        self.sync_target = Some(target_height);
        self.queue_heights_in_window();
        self.emit_fetch_outputs()
    }

    fn handle_block_response(
        &mut self,
        height: BlockHeight,
        response: Option<CertifiedBlock>,
        now: Instant,
    ) -> Vec<BlockSyncOutput> {
        self.in_flight.remove(&height);

        if let Some(CertifiedBlock { block, qc }) = response {
            // Validate
            if block.height() != height {
                warn!(
                    expected = height.0,
                    got = block.height().0,
                    "Height mismatch in sync response"
                );
                metrics::record_sync_block_filtered("height_mismatch");
                self.defer_height(height, now);
                return self.emit_fetch_outputs();
            }

            let block_hash = block.hash();
            if qc.block_hash != block_hash {
                warn!(height = height.0, "QC block hash mismatch in sync response");
                metrics::record_sync_block_filtered("qc_hash_mismatch");
                self.defer_height(height, now);
                return self.emit_fetch_outputs();
            }

            if qc.height != height {
                warn!(height = height.0, "QC height mismatch in sync response");
                metrics::record_sync_block_filtered("qc_height_mismatch");
                self.defer_height(height, now);
                return self.emit_fetch_outputs();
            }

            trace!(height = height.0, "Valid sync block received");
            metrics::record_sync_block_downloaded();
            metrics::record_sync_block_verified();
            // Block validated end-to-end — drop any prior backoff for this height.
            self.deferred.remove(&height);
            let certified = CertifiedBlock::new_unchecked(block, qc);
            let mut outputs = vec![BlockSyncOutput::DeliverBlock {
                certified: Box::new(certified),
            }];
            outputs.extend(self.emit_fetch_outputs());
            outputs
        } else {
            metrics::record_sync_response_error("empty_response");
            self.defer_height(height, now);
            self.emit_fetch_outputs()
        }
    }

    fn handle_block_fetch_failed(
        &mut self,
        height: BlockHeight,
        now: Instant,
    ) -> Vec<BlockSyncOutput> {
        self.in_flight.remove(&height);
        metrics::record_sync_response_error("fetch_failed");
        self.defer_height(height, now);
        self.emit_fetch_outputs()
    }

    /// Park `height` on its `RetryClock` instead of re-queuing immediately.
    /// A subsequent `Tick` whose `now` clears the deadline promotes it back
    /// to `heights_to_fetch`.
    fn defer_height(&mut self, height: BlockHeight, now: Instant) {
        let clock = self.deferred.entry(height).or_default();
        clock.advance_round(now);
        warn!(
            height = height.0,
            "Sync fetch failed; deferring re-queue for backoff"
        );
    }

    fn handle_tick(&mut self, now: Instant) -> Vec<BlockSyncOutput> {
        // Promote ready heights into the fetch queue, but keep the clock
        // entry — consecutive failures must accumulate rounds, only a
        // successful response clears the entry.
        let promoted: Vec<BlockHeight> = self
            .deferred
            .iter()
            .filter(|(_, clock)| clock.is_ready(now))
            .map(|(h, _)| *h)
            .collect();
        for h in promoted {
            if !self.in_flight.contains(&h) && self.heights_queued.insert(h) {
                self.heights_to_fetch.push(Reverse(h));
            }
        }
        self.emit_fetch_outputs()
    }

    fn handle_block_committed(&mut self, height: BlockHeight) -> Vec<BlockSyncOutput> {
        self.committed_height = height;
        self.remove_heights_at_or_below(height);

        if let Some(target) = self.sync_target {
            metrics::record_sync_block_applied();
            if height >= target {
                info!(height = height.0, target = target.0, "Sync complete");
                self.sync_target = None;
                self.clear_height_queue();
                return vec![BlockSyncOutput::SyncComplete { height: target }];
            }

            // Extend sliding window
            self.queue_heights_in_window();
        }

        self.emit_fetch_outputs()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Height Queue Helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn queue_height(&mut self, height: BlockHeight) {
        if !self.in_flight.contains(&height)
            && !self.deferred.contains_key(&height)
            && self.heights_queued.insert(height)
        {
            self.heights_to_fetch.push(Reverse(height));
        }
    }

    fn pop_next_height(&mut self) -> Option<BlockHeight> {
        while let Some(Reverse(height)) = self.heights_to_fetch.pop() {
            if self.heights_queued.remove(&height) && !self.in_flight.contains(&height) {
                return Some(height);
            }
        }
        None
    }

    fn clear_height_queue(&mut self) {
        self.heights_to_fetch.clear();
        self.heights_queued.clear();
        self.deferred.clear();
        self.force_full_refetch.clear();
    }

    fn remove_heights_at_or_below(&mut self, threshold: BlockHeight) {
        self.heights_queued.retain(|&h| h > threshold);
        self.in_flight.retain(|&h| h > threshold);
        self.deferred.retain(|&h, _| h > threshold);
        self.force_full_refetch.retain(|&h| h > threshold);
    }

    fn queue_heights_in_window(&mut self) {
        let Some(target_height) = self.sync_target else {
            return;
        };

        let first_height = self.committed_height.0 + 1;
        let window_end = if self.config.sync_window_size == 0 {
            target_height.0
        } else {
            (self.committed_height.0 + self.config.sync_window_size).min(target_height.0)
        };

        for height in first_height..=window_end {
            let h = BlockHeight(height);
            if !self.in_flight.contains(&h) {
                self.queue_height(h);
            }
        }
    }

    /// Emit `FetchBlock` outputs for pending heights up to concurrent limit.
    /// Short-circuits when no sync target is set — heights are only queued
    /// after `handle_start_sync`, so a missing target means nothing to
    /// fetch.
    fn emit_fetch_outputs(&mut self) -> Vec<BlockSyncOutput> {
        let Some(target_height) = self.sync_target else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        while self.in_flight.len() < self.config.max_concurrent_fetches {
            if let Some(height) = self.pop_next_height() {
                self.in_flight.insert(height);
                outputs.push(BlockSyncOutput::FetchBlock {
                    height,
                    target_height,
                    force_full: self.force_full_refetch.contains(&height),
                });
            } else {
                break;
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_defaults() {
        let config = BlockSyncConfig::default();
        assert_eq!(config.max_concurrent_fetches, 32);
        assert_eq!(config.sync_window_size, 64);
    }

    #[test]
    fn test_sync_status_default() {
        let status = BlockSyncStatus::default();
        assert_eq!(status.state, BlockSyncStateKind::Idle);
        assert_eq!(status.current_height, 0);
        assert!(status.target_height.is_none());
    }

    #[test]
    fn test_start_sync_emits_fetches() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 4,
            sync_window_size: 10,
        });

        let outputs = protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(5),
        });

        assert!(protocol.is_syncing());
        // Should emit FetchBlock for heights 1..=5
        let fetch_count = outputs
            .iter()
            .filter(|o| matches!(o, BlockSyncOutput::FetchBlock { .. }))
            .count();
        assert_eq!(fetch_count, 4); // limited by max_concurrent_fetches
    }

    #[test]
    fn test_sync_complete() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 32,
            sync_window_size: 64,
        });

        protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(2),
        });

        assert!(protocol.is_syncing());

        // Commit up to target
        let outputs = protocol.handle(BlockSyncInput::BlockCommitted {
            height: BlockHeight(2),
        });

        assert!(!protocol.is_syncing());
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, BlockSyncOutput::SyncComplete { height } if height.0 == 2))
        );
    }

    #[test]
    fn test_failed_fetch_defers_then_requeues_on_tick() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });

        protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(1),
        });

        let t0 = Instant::now();

        // Failure parks the height — no fetch should be re-emitted yet.
        let outputs = protocol.handle(BlockSyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t0,
        });
        assert!(
            outputs
                .iter()
                .all(|o| !matches!(o, BlockSyncOutput::FetchBlock { height, .. } if height.0 == 1)),
            "deferred height must not be re-fetched immediately"
        );
        assert!(protocol.has_deferred());

        // Tick before the deadline — still parked.
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: t0 + Duration::from_millis(100),
        });
        assert!(outputs.is_empty());

        // Tick past the first-round backoff (1s) — height promoted and fetched.
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: t0 + Duration::from_secs(2),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, BlockSyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
        // Clock entry persists across promotion — only a successful response
        // (or commit/clear) drops it, so consecutive failures keep advancing.
        assert!(protocol.has_deferred());
    }

    #[test]
    fn test_repeated_failures_extend_backoff() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });
        protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(1),
        });

        let t0 = Instant::now();
        protocol.handle(BlockSyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t0,
        });
        // Promote at t0+1s.
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: t0 + Duration::from_secs(1),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, BlockSyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );

        // Fail again — second round backoff is 2s.
        let t1 = t0 + Duration::from_secs(1);
        protocol.handle(BlockSyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t1,
        });
        // 1s after second failure: still parked.
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: t1 + Duration::from_millis(1500),
        });
        assert!(
            outputs
                .iter()
                .all(|o| !matches!(o, BlockSyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
        // 2s after second failure: ready.
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: t1 + Duration::from_secs(3),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, BlockSyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
    }

    #[test]
    fn force_full_refetch_propagates_to_next_fetch_output() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 4,
            sync_window_size: 10,
        });

        let outputs = protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(3),
        });

        // Initial fetches: nothing flagged.
        assert!(outputs.iter().all(|o| matches!(
            o,
            BlockSyncOutput::FetchBlock {
                force_full: false,
                ..
            }
        )));

        // Mark height 2; next fetch wave for that height must carry the flag.
        protocol.mark_force_full_refetch(BlockHeight(2));
        let outputs = protocol.handle(BlockSyncInput::BlockFetchFailed {
            height: BlockHeight(2),
            now: Instant::now() + Duration::from_secs(2),
        });
        // Failure parks; tick to promote and re-emit.
        let _ = outputs;
        let outputs = protocol.handle(BlockSyncInput::Tick {
            now: Instant::now() + Duration::from_secs(10),
        });
        let height_2 = outputs.iter().find_map(|o| match o {
            BlockSyncOutput::FetchBlock {
                height, force_full, ..
            } if height.0 == 2 => Some(*force_full),
            _ => None,
        });
        assert_eq!(
            height_2,
            Some(true),
            "force_full must propagate to the re-emitted FetchBlock for height 2"
        );
    }

    #[test]
    fn force_full_refetch_drains_on_commit() {
        let mut protocol = BlockSyncProtocol::new(BlockSyncConfig {
            max_concurrent_fetches: 4,
            sync_window_size: 10,
        });
        let _ = protocol.handle(BlockSyncInput::StartSync {
            target_height: BlockHeight(3),
        });
        protocol.mark_force_full_refetch(BlockHeight(1));
        // Commit past the marked height — drain.
        let _ = protocol.handle(BlockSyncInput::BlockCommitted {
            height: BlockHeight(1),
        });
        assert!(
            !protocol.force_full_refetch.contains(&BlockHeight(1)),
            "commit at height must drop the marker"
        );
    }
}
