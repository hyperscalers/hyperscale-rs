//! Sync protocol state machine.
//!
//! Pure synchronous state machine for block sync. Tracks height queues
//! and validates responses. Does NOT handle peer selection, async dispatch,
//! or banning — those stay in the runner-specific wrapper.
//!
//! # Usage
//!
//! ```text
//! Runner ──► SyncProtocol::handle(SyncInput) ──► Vec<SyncOutput>
//! ```
//!
//! Production: `SyncManager` wraps this, maps outputs to tokio tasks.
//! Simulation: feeds inputs/outputs synchronously via event queue.

use self::retry_clock::RetryClock;
use self::slot_tracker::SlotTracker;
use hyperscale_messages::request::{GetBlockRequest, GetBlockTopUpRequest};
use hyperscale_messages::response::{
    ElidedCertifiedBlock, GetBlockResponse, GetBlockTopUpResponse,
};
use hyperscale_metrics as metrics;
use hyperscale_provisions::ProvisionStore;
use hyperscale_storage::ChainReader;
use hyperscale_types::{BlockHash, BlockHeight, CertifiedBlock, Provisions, WAVE_TIMEOUT};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Configuration for the sync protocol.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum number of concurrent fetch requests.
    pub max_concurrent_fetches: usize,

    /// Maximum number of heights to queue ahead of committed height.
    /// Creates a sliding window that limits memory usage.
    pub sync_window_size: u64,
}

impl Default for SyncConfig {
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
pub enum SyncStateKind {
    /// Not syncing, node is up to date.
    Idle,
    /// Actively fetching and applying blocks.
    Syncing,
}

impl SyncStateKind {
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
pub struct SyncStatus {
    /// Current sync state.
    pub state: SyncStateKind,
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

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: SyncStateKind::Idle,
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
pub enum SyncInput {
    /// Start or update sync target.
    StartSync {
        target_height: BlockHeight,
        target_hash: BlockHash,
    },
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
pub enum SyncOutput {
    /// Request the runner to fetch a block at this height. `target_height`
    /// is the sync target, passed through to the serving peer so it can
    /// choose between `Block::Live` and `Block::Sealed`.
    FetchBlock {
        height: BlockHeight,
        target_height: BlockHeight,
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
pub struct SyncProtocol {
    config: SyncConfig,
    sync_target: Option<(BlockHeight, BlockHash)>,
    committed_height: BlockHeight,
    heights_to_fetch: BinaryHeap<Reverse<BlockHeight>>,
    heights_queued: HashSet<BlockHeight>,
    in_flight: SlotTracker<BlockHeight>,
    /// Heights whose last fetch failed; held out of `heights_to_fetch`
    /// until their `RetryClock` deadline elapses.
    deferred: HashMap<BlockHeight, RetryClock>,
}

impl SyncProtocol {
    /// Create a new sync protocol state machine.
    pub fn new(config: SyncConfig) -> Self {
        let in_flight = SlotTracker::new(config.max_concurrent_fetches);
        Self {
            config,
            sync_target: None,
            committed_height: BlockHeight::GENESIS,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            in_flight,
            deferred: HashMap::new(),
        }
    }

    /// True if any heights are parked awaiting backoff. Lets the runner
    /// keep its periodic tick alive while the heap may be empty.
    pub fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: SyncInput) -> Vec<SyncOutput> {
        match input {
            SyncInput::StartSync {
                target_height,
                target_hash,
            } => self.handle_start_sync(target_height, target_hash),
            SyncInput::BlockResponseReceived { height, block, now } => {
                self.handle_block_response(height, block.map(|b| *b), now)
            }
            SyncInput::BlockFetchFailed { height, now } => {
                self.handle_block_fetch_failed(height, now)
            }
            SyncInput::BlockCommitted { height } => self.handle_block_committed(height),
            SyncInput::Tick { now } => self.handle_tick(now),
        }
    }

    /// Check if currently syncing.
    pub const fn is_syncing(&self) -> bool {
        self.sync_target.is_some()
    }

    /// Number of blocks behind target (for metrics).
    pub fn blocks_behind(&self) -> u64 {
        self.sync_target
            .map_or(0, |(t, _)| t.0.saturating_sub(self.committed_height.0))
    }

    /// Get current sync status.
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            state: if self.sync_target.is_some() {
                SyncStateKind::Syncing
            } else {
                SyncStateKind::Idle
            },
            current_height: self.committed_height.0,
            target_height: self.sync_target.map(|(h, _)| h.0),
            blocks_behind: self
                .sync_target
                .map_or(0, |(t, _)| t.0.saturating_sub(self.committed_height.0)),
            pending_fetches: self.in_flight.in_flight(),
            queued_heights: self.heights_queued.len() + self.deferred.len(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(
        &mut self,
        target_height: BlockHeight,
        target_hash: BlockHash,
    ) -> Vec<SyncOutput> {
        if self.sync_target.is_some_and(|(t, _)| t >= target_height) {
            return vec![];
        }

        info!(
            target_height = target_height.0,
            ?target_hash,
            committed = self.committed_height.0,
            "Starting sync"
        );

        self.sync_target = Some((target_height, target_hash));
        self.queue_heights_in_window();
        self.emit_fetch_outputs()
    }

    fn handle_block_response(
        &mut self,
        height: BlockHeight,
        response: Option<CertifiedBlock>,
        now: Instant,
    ) -> Vec<SyncOutput> {
        self.in_flight.release(&height);

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
            let mut outputs = vec![SyncOutput::DeliverBlock {
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

    fn handle_block_fetch_failed(&mut self, height: BlockHeight, now: Instant) -> Vec<SyncOutput> {
        self.in_flight.release(&height);
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

    fn handle_tick(&mut self, now: Instant) -> Vec<SyncOutput> {
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

    fn handle_block_committed(&mut self, height: BlockHeight) -> Vec<SyncOutput> {
        self.committed_height = height;
        self.remove_heights_at_or_below(height);

        if let Some((target, _)) = self.sync_target {
            metrics::record_sync_block_applied();
            if height >= target {
                info!(height = height.0, target = target.0, "Sync complete");
                self.sync_target = None;
                self.clear_height_queue();
                return vec![SyncOutput::SyncComplete { height: target }];
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
    }

    fn remove_heights_at_or_below(&mut self, threshold: BlockHeight) {
        self.heights_queued.retain(|&h| h > threshold);
        self.in_flight.retain(|&h| h > threshold);
        self.deferred.retain(|&h, _| h > threshold);
    }

    fn queue_heights_in_window(&mut self) {
        let Some((target_height, _)) = self.sync_target else {
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
    fn emit_fetch_outputs(&mut self) -> Vec<SyncOutput> {
        let Some((target_height, _)) = self.sync_target else {
            return Vec::new();
        };
        let mut outputs = Vec::new();
        while self.in_flight.has_capacity() {
            if let Some(height) = self.pop_next_height() {
                self.in_flight.try_acquire(height);
                outputs.push(SyncOutput::FetchBlock {
                    height,
                    target_height,
                });
            } else {
                break;
            }
        }
        outputs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Inbound request serving
// ═══════════════════════════════════════════════════════════════════════

/// Retention margin beyond `WAVE_TIMEOUT` for the serve decision.
///
/// A block's waves are live for `WAVE_TIMEOUT`; a late-syncing peer still
/// needs a rotation budget to fetch provisions, execute, and vote before
/// its rotation deadline passes. Sized to cover one vote-retry rotation.
const SERVE_MARGIN: Duration = Duration::from_secs(12);
const LIVE_WINDOW: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() + SERVE_MARGIN.as_secs());

/// Serve an inbound block sync request.
///
/// Storage always returns `Block::Sealed` — the persisted shape carries no
/// provisions. Whether the requester needs `Block::Live` is a function of
/// the block's own age: if its waves could still be open for execution
/// voting (`block_ts + WAVE_TIMEOUT + margin > tip_ts`), provisions are
/// attached from the local cache. Otherwise the `Sealed` block is served.
///
/// The wave-window check is based on the BFT-authenticated
/// `weighted_timestamp` of the committing QC and the serving peer's own
/// latest QC timestamp — both quantities are deterministic and don't
/// depend on the requester's view.
///
/// On cache miss inside the live window the block is still served as
/// `Sealed`; the requester fetches missing provisions through the cross-shard
/// provision fetch instead of round-robining peers.
pub fn serve_block_request(
    storage: &impl ChainReader,
    provision_store: &ProvisionStore,
    req: &GetBlockRequest,
) -> GetBlockResponse {
    trace!(
        height = req.height.0,
        target_height = req.target_height.0,
        "Handling block sync request"
    );
    let Some(hyperscale_storage::BlockForSync {
        block,
        qc,
        provision_hashes,
    }) = storage.get_block_for_sync(req.height)
    else {
        return GetBlockResponse::not_found();
    };

    let block_ts = qc.weighted_timestamp;
    let tip_ts = storage
        .latest_qc()
        .map_or(block_ts, |q| q.weighted_timestamp);
    let wave_window_open = tip_ts.elapsed_since(block_ts) < LIVE_WINDOW;

    if !wave_window_open || provision_hashes.is_empty() {
        return GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory));
    }

    let resolved: Option<Vec<Arc<Provisions>>> = provision_hashes
        .iter()
        .map(|h| provision_store.get(h))
        .collect();

    if let Some(provisions) = resolved {
        GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &block.into_live(provisions),
            qc,
            &req.inventory,
        ))
    } else {
        // Cache miss inside the live window. Serve Sealed and let the
        // requester pull provisions via the fetch protocol — avoids
        // the peer-rotation retry storm the old `not_found` path caused
        // when provisions had aged out everywhere.
        trace!(
            height = req.height.0,
            "Cache miss for provisions inside live window — serving sealed"
        );
        metrics::record_sync_response_error("provision_cache_miss");
        GetBlockResponse::found(ElidedCertifiedBlock::elide(&block, qc, &req.inventory))
    }
}

/// Serve a top-up request — the requester's rehydration of an earlier
/// elided response missed some bodies (bloom false-positives or local
/// evictions), so it's asking for just those hashes.
///
/// Reads the block from storage and returns only the bodies whose hashes
/// are listed in the request. Hashes we don't have (block evicted, or
/// caller's hash is unknown) are silently omitted — the requester then
/// falls back to a full refetch.
pub fn serve_block_topup_request(
    storage: &impl ChainReader,
    provision_store: &ProvisionStore,
    req: &GetBlockTopUpRequest,
) -> GetBlockTopUpResponse {
    let Some(hyperscale_storage::BlockForSync { block, .. }) =
        storage.get_block_for_sync(req.height)
    else {
        return GetBlockTopUpResponse::empty();
    };

    let transactions = req
        .missing_tx
        .iter()
        .filter_map(|want| {
            block
                .transactions()
                .iter()
                .find(|tx| tx.hash() == *want)
                .map(|tx| (*want, Arc::clone(tx)))
        })
        .collect();

    let certificates = req
        .missing_cert
        .iter()
        .filter_map(|want| {
            block
                .certificates()
                .iter()
                .find(|fw| fw.wave_id_hash() == *want)
                .map(|fw| (*want, Arc::clone(fw)))
        })
        .collect();

    // Provisions never live in the persisted block — they're held only in
    // the in-memory cache, so resolve top-up hits against `provision_store`.
    let provisions = req
        .missing_provision
        .iter()
        .filter_map(|want| provision_store.get(want).map(|p| (*want, p)))
        .collect();

    GetBlockTopUpResponse::new(transactions, certificates, provisions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_fetches, 32);
        assert_eq!(config.sync_window_size, 64);
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert_eq!(status.state, SyncStateKind::Idle);
        assert_eq!(status.current_height, 0);
        assert!(status.target_height.is_none());
    }

    #[test]
    fn test_start_sync_emits_fetches() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 4,
            sync_window_size: 10,
        });

        let outputs = protocol.handle(SyncInput::StartSync {
            target_height: BlockHeight(5),
            target_hash: BlockHash::ZERO,
        });

        assert!(protocol.is_syncing());
        // Should emit FetchBlock for heights 1..=5
        let fetch_count = outputs
            .iter()
            .filter(|o| matches!(o, SyncOutput::FetchBlock { .. }))
            .count();
        assert_eq!(fetch_count, 4); // limited by max_concurrent_fetches
    }

    #[test]
    fn test_sync_complete() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 32,
            sync_window_size: 64,
        });

        protocol.handle(SyncInput::StartSync {
            target_height: BlockHeight(2),
            target_hash: BlockHash::ZERO,
        });

        assert!(protocol.is_syncing());

        // Commit up to target
        let outputs = protocol.handle(SyncInput::BlockCommitted {
            height: BlockHeight(2),
        });

        assert!(!protocol.is_syncing());
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::SyncComplete { height } if height.0 == 2))
        );
    }

    #[test]
    fn test_failed_fetch_defers_then_requeues_on_tick() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });

        protocol.handle(SyncInput::StartSync {
            target_height: BlockHeight(1),
            target_hash: BlockHash::ZERO,
        });

        let t0 = Instant::now();

        // Failure parks the height — no fetch should be re-emitted yet.
        let outputs = protocol.handle(SyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t0,
        });
        assert!(
            outputs
                .iter()
                .all(|o| !matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1)),
            "deferred height must not be re-fetched immediately"
        );
        assert!(protocol.has_deferred());

        // Tick before the deadline — still parked.
        let outputs = protocol.handle(SyncInput::Tick {
            now: t0 + Duration::from_millis(100),
        });
        assert!(outputs.is_empty());

        // Tick past the first-round backoff (1s) — height promoted and fetched.
        let outputs = protocol.handle(SyncInput::Tick {
            now: t0 + Duration::from_secs(2),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
        // Clock entry persists across promotion — only a successful response
        // (or commit/clear) drops it, so consecutive failures keep advancing.
        assert!(protocol.has_deferred());
    }

    #[test]
    fn test_repeated_failures_extend_backoff() {
        let mut protocol = SyncProtocol::new(SyncConfig {
            max_concurrent_fetches: 1,
            sync_window_size: 10,
        });
        protocol.handle(SyncInput::StartSync {
            target_height: BlockHeight(1),
            target_hash: BlockHash::ZERO,
        });

        let t0 = Instant::now();
        protocol.handle(SyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t0,
        });
        // Promote at t0+1s.
        let outputs = protocol.handle(SyncInput::Tick {
            now: t0 + Duration::from_secs(1),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );

        // Fail again — second round backoff is 2s.
        let t1 = t0 + Duration::from_secs(1);
        protocol.handle(SyncInput::BlockFetchFailed {
            height: BlockHeight(1),
            now: t1,
        });
        // 1s after second failure: still parked.
        let outputs = protocol.handle(SyncInput::Tick {
            now: t1 + Duration::from_millis(1500),
        });
        assert!(
            outputs
                .iter()
                .all(|o| !matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
        // 2s after second failure: ready.
        let outputs = protocol.handle(SyncInput::Tick {
            now: t1 + Duration::from_secs(3),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::FetchBlock { height, .. } if height.0 == 1))
        );
    }
}

mod retry_clock {
    //! Per-key exponential-backoff clock used by the sync protocol's
    //! per-height retry deferral.

    use std::time::{Duration, Instant};

    /// Tracks how many retry rounds have elapsed and computes the next
    /// allowed retry deadline using exponential backoff.
    #[derive(Debug)]
    pub struct RetryClock {
        rounds: u32,
        next_retry_at: Option<Instant>,
        base_ms: u64,
        multiplier: f64,
        max_ms: u64,
    }

    impl Default for RetryClock {
        fn default() -> Self {
            Self {
                rounds: 0,
                next_retry_at: None,
                base_ms: 1_000,
                multiplier: 2.0,
                max_ms: 30_000,
            }
        }
    }

    impl RetryClock {
        /// Whether the clock is past its next-retry deadline (or has none yet).
        #[must_use]
        pub fn is_ready(&self, now: Instant) -> bool {
            self.next_retry_at.is_none_or(|deadline| now >= deadline)
        }

        /// Advance to the next retry round, computing the new deadline from the
        /// current round count. Bound by `max_ms`.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            clippy::cast_possible_wrap
        )] // backoff ms fits u64 in practice; rounds is small
        pub fn advance_round(&mut self, now: Instant) {
            self.rounds = self.rounds.saturating_add(1);
            let backoff_ms =
                ((self.base_ms as f64) * self.multiplier.powi(self.rounds as i32 - 1)) as u64;
            let backoff_ms = backoff_ms.min(self.max_ms);
            self.next_retry_at = Some(now + Duration::from_millis(backoff_ms));
        }

        #[cfg(test)]
        pub(super) const fn rounds(&self) -> u32 {
            self.rounds
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fresh_clock_is_ready() {
            let clock = RetryClock::default();
            assert!(clock.is_ready(Instant::now()));
        }

        #[test]
        fn advance_round_sets_deadline() {
            let mut clock = RetryClock::default();
            let t0 = Instant::now();
            clock.advance_round(t0);
            assert!(!clock.is_ready(t0));
            assert!(clock.is_ready(t0 + Duration::from_secs(2)));
        }

        #[test]
        fn rounds_count_increments() {
            let mut clock = RetryClock::default();
            let t0 = Instant::now();
            clock.advance_round(t0);
            clock.advance_round(t0);
            clock.advance_round(t0);
            assert_eq!(clock.rounds(), 3);
        }

        #[test]
        fn backoff_clamps_at_max() {
            let mut clock = RetryClock::default();
            let t0 = Instant::now();
            for _ in 0..20 {
                clock.advance_round(t0);
            }
            assert!(clock.is_ready(t0 + Duration::from_secs(30)));
        }
    }
}

mod slot_tracker {
    //! Cap-enforced set of in-flight keys, used by the sync protocol to
    //! bound concurrent in-flight block fetches and answer membership
    //! queries.

    use std::collections::HashSet;
    use std::hash::Hash;

    #[derive(Debug)]
    pub struct SlotTracker<K: Eq + Hash + Clone> {
        capacity: usize,
        in_flight: HashSet<K>,
    }

    impl<K: Eq + Hash + Clone> SlotTracker<K> {
        /// Build a tracker that allows up to `capacity` concurrent in-flight keys.
        /// `capacity = 0` disables the cap (any number of acquires succeed).
        #[must_use]
        pub fn new(capacity: usize) -> Self {
            Self {
                capacity,
                in_flight: HashSet::new(),
            }
        }

        /// Try to claim a slot for `key`. Returns `true` if the slot was
        /// acquired, `false` if the cap is reached or `key` was already in-flight.
        pub fn try_acquire(&mut self, key: K) -> bool {
            if self.capacity > 0 && self.in_flight.len() >= self.capacity {
                return false;
            }
            self.in_flight.insert(key)
        }

        /// Release the slot held by `key`. Returns `true` if a slot was actually
        /// freed, `false` if `key` wasn't in-flight.
        pub fn release(&mut self, key: &K) -> bool {
            self.in_flight.remove(key)
        }

        /// Whether `key` currently holds a slot.
        #[must_use]
        pub fn contains(&self, key: &K) -> bool {
            self.in_flight.contains(key)
        }

        /// Count of slots currently held.
        #[must_use]
        pub fn in_flight(&self) -> usize {
            self.in_flight.len()
        }

        /// Whether at least one slot is free.
        #[must_use]
        pub fn has_capacity(&self) -> bool {
            self.capacity == 0 || self.in_flight.len() < self.capacity
        }

        /// Drop every key for which `f` returns false.
        pub fn retain<F>(&mut self, mut f: F)
        where
            F: FnMut(&K) -> bool,
        {
            self.in_flight.retain(|k| f(k));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn acquire_and_release_round_trip() {
            let mut s = SlotTracker::<u32>::new(3);
            assert!(s.try_acquire(1));
            assert!(s.try_acquire(2));
            assert_eq!(s.in_flight(), 2);
            assert!(s.contains(&1));

            assert!(s.release(&1));
            assert!(!s.contains(&1));
            assert_eq!(s.in_flight(), 1);
        }

        #[test]
        fn cap_blocks_acquire_when_full() {
            let mut s = SlotTracker::<u32>::new(2);
            assert!(s.try_acquire(1));
            assert!(s.try_acquire(2));
            assert!(!s.try_acquire(3));
            assert_eq!(s.in_flight(), 2);
            assert!(!s.contains(&3));
        }

        #[test]
        fn duplicate_acquire_returns_false() {
            let mut s = SlotTracker::<u32>::new(5);
            assert!(s.try_acquire(1));
            assert!(!s.try_acquire(1));
            assert_eq!(s.in_flight(), 1);
        }

        #[test]
        fn capacity_zero_is_uncapped() {
            let mut s = SlotTracker::<u32>::new(0);
            for k in 0..1000 {
                assert!(s.try_acquire(k));
            }
            assert_eq!(s.in_flight(), 1000);
            assert!(s.has_capacity());
        }

        #[test]
        fn release_unknown_returns_false() {
            let mut s = SlotTracker::<u32>::new(5);
            assert!(!s.release(&42));
        }
    }
}
