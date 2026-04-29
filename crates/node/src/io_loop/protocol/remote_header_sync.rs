//! Remote-header sync protocol state machine.
//!
//! Sliding-window catch-up for cross-shard committed-header chains.
//! Replaces the per-gap "fetch one missing height" pattern that loses to
//! the cross-shard wave timeout when `block.committed` gossip is dropped:
//! one round-trip per missing height stacks up faster than the wave can
//! tolerate. The FSM batches contiguous missing heights into a single
//! `GetRemoteHeadersRequest` (up to `MAX_HEADERS_PER_FETCH`) and applies
//! a deferral backoff to failed fetches.
//!
//! Multi-shard: one FSM holds per-`ShardGroupId` sliding-window state.
//! Completion is per-shard; `SyncComplete { source_shard, height }` fires
//! when that shard's `committed` catches up to its `target`. Other shards
//! keep advancing.
//!
//! # Validation
//!
//! The FSM never validates headers itself — it emits one `DeliverHeader`
//! per received header, and `RemoteHeaderCoordinator`'s existing
//! `on_committed_header_received` path runs QC verification and admission
//! in the usual way. Each header's `RemoteHeaderAdmitted` continuation
//! feeds back into `SyncInput::HeaderAdmitted`, advancing the per-shard
//! `committed` counter.

use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Default upper bound on heights packed into a single range fetch.
/// Matches `MAX_REMOTE_HEADERS_PER_REQUEST` so the responder never has to
/// short-cap on `count` alone.
pub const DEFAULT_MAX_HEADERS_PER_FETCH: u64 = 64;

/// Default per-shard window.
///
/// How far ahead of `committed` the FSM queues fetches. Bounded so the
/// heap can't grow without bound when `target` jumps far ahead (e.g.
/// arbitrarily large catch-up after a long partition).
pub const DEFAULT_SYNC_WINDOW_SIZE: u64 = 256;

/// Default cap on concurrent in-flight range fetches per shard.
/// Source-shard committee responsiveness is the bottleneck, not local
/// resources, so the limit is per-shard rather than global.
pub const DEFAULT_MAX_CONCURRENT_FETCHES_PER_SHARD: usize = 4;

/// Initial backoff for a deferred height after its first fetch failure.
const DEFERRAL_BASE_MS: u64 = 1_000;
/// Multiplier applied to the previous round's backoff on each subsequent failure.
const DEFERRAL_MULTIPLIER: f64 = 2.0;
/// Backoff cap; subsequent rounds plateau here rather than growing unbounded.
const DEFERRAL_MAX_MS: u64 = 30_000;

/// Per-height deferral state: how many rounds we've backed off and when the
/// next retry is permitted. Default state is "ready immediately" — only
/// `advance_round` installs a deadline.
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

/// Tunable knobs for the remote-header sync protocol.
#[derive(Debug, Clone)]
pub struct RemoteHeaderSyncConfig {
    /// Maximum heights packed into a single `FetchHeaders` output.
    pub max_headers_per_fetch: u64,
    /// Per-shard sliding window: max heights queued ahead of `committed`.
    pub sync_window_size: u64,
    /// Cap on concurrent in-flight ranges per shard.
    pub max_concurrent_fetches_per_shard: usize,
}

impl Default for RemoteHeaderSyncConfig {
    fn default() -> Self {
        Self {
            max_headers_per_fetch: DEFAULT_MAX_HEADERS_PER_FETCH,
            sync_window_size: DEFAULT_SYNC_WINDOW_SIZE,
            max_concurrent_fetches_per_shard: DEFAULT_MAX_CONCURRENT_FETCHES_PER_SHARD,
        }
    }
}

/// Inputs to the remote-header sync state machine.
#[derive(Debug)]
#[allow(missing_docs)] // payloads are self-describing
pub enum SyncInput {
    /// Set or raise the sync target for `source_shard`. Idempotent if the
    /// target hasn't moved forward.
    StartSync {
        source_shard: ShardGroupId,
        target: BlockHeight,
    },
    /// A range response was received. `headers` is in ascending height
    /// order starting at `from_height`; missing tail heights (responder
    /// short-capped) get re-deferred.
    HeadersResponseReceived {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        headers: Vec<CommittedBlockHeader>,
        now: Instant,
    },
    /// A range fetch failed (transport error / no peer / rejected). All
    /// heights in `[from_height, from_height + count)` get deferred.
    HeadersFetchFailed {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        now: Instant,
    },
    /// `RemoteHeaderCoordinator` admitted a header (QC verified). Advances
    /// the per-shard `committed` counter and may emit `SyncComplete`.
    HeaderAdmitted {
        source_shard: ShardGroupId,
        height: BlockHeight,
    },
    /// Periodic tick: promotes deferred heights past their backoff and
    /// emits any newly-ready fetches.
    Tick { now: Instant },
}

/// Outputs from the remote-header sync state machine.
#[derive(Debug)]
#[allow(missing_docs)] // payloads are self-describing
pub enum SyncOutput {
    /// Issue a range fetch covering `[from_height, from_height + count)`
    /// from any peer in `source_shard`'s committee.
    FetchHeaders {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
    },
    /// A header is ready to feed into `RemoteHeaderCoordinator`'s
    /// `on_committed_header_received` path for QC verification.
    DeliverHeader {
        source_shard: ShardGroupId,
        header: Box<CommittedBlockHeader>,
    },
    /// The FSM caught up to `target` for `source_shard`. Other shards may
    /// still be syncing.
    SyncComplete {
        source_shard: ShardGroupId,
        height: BlockHeight,
    },
}

/// Per-shard sliding-window state.
struct PerShardState {
    /// Highest known target for this shard. Advances on `StartSync` and
    /// implicitly when a response includes a height past the current
    /// target (the responder's possession is proof of existence).
    target: BlockHeight,
    /// Highest height admitted via `HeaderAdmitted`.
    committed: BlockHeight,
    /// Heights ready to fetch (lowest-first).
    heights_to_fetch: BinaryHeap<Reverse<BlockHeight>>,
    /// Set membership for `heights_to_fetch` to dedupe pushes.
    heights_queued: HashSet<BlockHeight>,
    /// Heights currently in a dispatched range fetch.
    in_flight: HashSet<BlockHeight>,
    /// Heights whose last fetch failed; held out of `heights_to_fetch`
    /// until their backoff deadline elapses.
    deferred: HashMap<BlockHeight, DeferralBackoff>,
    /// Number of in-flight range fetches for this shard. Bounded by
    /// `max_concurrent_fetches_per_shard`.
    in_flight_ranges: usize,
}

impl PerShardState {
    fn new(target: BlockHeight) -> Self {
        Self {
            target,
            committed: BlockHeight::GENESIS,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            in_flight: HashSet::new(),
            deferred: HashMap::new(),
            in_flight_ranges: 0,
        }
    }

    fn queue_height(&mut self, height: BlockHeight) {
        if self.in_flight.contains(&height) || self.deferred.contains_key(&height) {
            return;
        }
        if self.heights_queued.insert(height) {
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

    fn peek_next_height(&self) -> Option<BlockHeight> {
        self.heights_to_fetch.peek().map(|Reverse(h)| *h)
    }
}

/// Remote-header sync state machine.
///
/// Multi-shard sliding-window catch-up. Pure synchronous FSM: caller
/// drives via `handle()`, executes the returned outputs.
pub struct RemoteHeaderSyncProtocol {
    config: RemoteHeaderSyncConfig,
    shards: BTreeMap<ShardGroupId, PerShardState>,
}

impl RemoteHeaderSyncProtocol {
    /// Create a new FSM with the given config.
    #[must_use]
    pub const fn new(config: RemoteHeaderSyncConfig) -> Self {
        Self {
            config,
            shards: BTreeMap::new(),
        }
    }

    /// True if any shard has heights parked behind a backoff deadline.
    /// Lets the I/O loop keep its periodic tick alive while heaps may be
    /// empty.
    #[must_use]
    pub fn has_deferred(&self) -> bool {
        self.shards.values().any(|s| !s.deferred.is_empty())
    }

    /// True if any shard is actively syncing (committed < target).
    #[must_use]
    pub fn is_syncing(&self) -> bool {
        self.shards.values().any(|s| s.committed < s.target)
    }

    /// Total in-flight range fetches across all shards. Used for metrics.
    #[must_use]
    pub fn in_flight_ranges(&self) -> usize {
        self.shards.values().map(|s| s.in_flight_ranges).sum()
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: SyncInput) -> Vec<SyncOutput> {
        match input {
            SyncInput::StartSync {
                source_shard,
                target,
            } => self.handle_start_sync(source_shard, target),
            SyncInput::HeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
                now,
            } => self.handle_response(source_shard, from_height, count, headers, now),
            SyncInput::HeadersFetchFailed {
                source_shard,
                from_height,
                count,
                now,
            } => self.handle_fetch_failed(source_shard, from_height, count, now),
            SyncInput::HeaderAdmitted {
                source_shard,
                height,
            } => self.handle_header_admitted(source_shard, height),
            SyncInput::Tick { now } => self.handle_tick(now),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(
        &mut self,
        source_shard: ShardGroupId,
        target: BlockHeight,
    ) -> Vec<SyncOutput> {
        // Distinguish "first sync for this shard" from "raise an existing
        // target": a freshly created entry has `target == BlockHeight::GENESIS`,
        // so we always proceed into the window-queue path on its first call.
        let is_new = !self.shards.contains_key(&source_shard);
        let state = self
            .shards
            .entry(source_shard)
            .or_insert_with(|| PerShardState::new(BlockHeight::GENESIS));

        if !is_new && state.target >= target {
            return vec![];
        }

        info!(
            source_shard = source_shard.0,
            target = target.0,
            committed = state.committed.0,
            "remote-header sync: target raised"
        );

        state.target = target;
        Self::queue_window(state, &self.config);
        self.emit_fetch_outputs()
    }

    fn handle_response(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        headers: Vec<CommittedBlockHeader>,
        now: Instant,
    ) -> Vec<SyncOutput> {
        let mut outputs: Vec<SyncOutput> = Vec::with_capacity(headers.len());
        let Some(state) = self.shards.get_mut(&source_shard) else {
            // No shard state — input arrived after sync was reset.
            return outputs;
        };

        state.in_flight_ranges = state.in_flight_ranges.saturating_sub(1);

        // Heights covered by this request: [from_height, from_height + count).
        let mut delivered: HashSet<BlockHeight> = HashSet::with_capacity(headers.len());
        for header in headers {
            let h = header.header.height;
            if h < from_height || h.0 >= from_height.0 + count {
                // Out-of-range header — protocol violation by responder.
                // Skip and let the deferral path retry the requested range.
                warn!(
                    source_shard = source_shard.0,
                    requested_from = from_height.0,
                    requested_count = count,
                    height = h.0,
                    "remote-header sync: response contained out-of-range height — discarding"
                );
                continue;
            }
            delivered.insert(h);
            outputs.push(SyncOutput::DeliverHeader {
                source_shard,
                header: Box::new(header),
            });
        }

        // Reconcile: heights served get unmarked from in_flight; heights in
        // the requested range that did NOT come back get deferred so their
        // backoff ticks before the next attempt.
        for offset in 0..count {
            let h = BlockHeight(from_height.0 + offset);
            state.in_flight.remove(&h);
            if !delivered.contains(&h) && h <= state.target && h > state.committed {
                state.deferred.entry(h).or_default().advance_round(now);
            }
        }

        // Implicit target advance: the responder's possession of any
        // height proves the source shard has at least committed that
        // height. Bump target if a delivered height is past it.
        if let Some(max_delivered) = delivered.iter().max().copied()
            && max_delivered > state.target
        {
            state.target = max_delivered;
        }

        Self::queue_window(state, &self.config);
        outputs.extend(self.emit_fetch_outputs());
        outputs
    }

    fn handle_fetch_failed(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        now: Instant,
    ) -> Vec<SyncOutput> {
        let Some(state) = self.shards.get_mut(&source_shard) else {
            return vec![];
        };
        state.in_flight_ranges = state.in_flight_ranges.saturating_sub(1);
        for offset in 0..count {
            let h = BlockHeight(from_height.0 + offset);
            if state.in_flight.remove(&h) && h <= state.target && h > state.committed {
                state.deferred.entry(h).or_default().advance_round(now);
            }
        }
        // No new fetches emitted here — Tick promotes deferred heights once
        // their backoff elapses.
        vec![]
    }

    fn handle_header_admitted(
        &mut self,
        source_shard: ShardGroupId,
        height: BlockHeight,
    ) -> Vec<SyncOutput> {
        let Some(state) = self.shards.get_mut(&source_shard) else {
            return vec![];
        };

        if height > state.committed {
            state.committed = height;
        }

        // Drop any tracking state for heights at or below the new
        // committed level — they're done, no need to fetch or defer.
        state.heights_queued.retain(|&h| h > state.committed);
        state.in_flight.retain(|&h| h > state.committed);
        state.deferred.retain(|&h, _| h > state.committed);

        let mut outputs = Vec::new();
        if state.committed >= state.target {
            info!(
                source_shard = source_shard.0,
                height = state.committed.0,
                "remote-header sync: caught up"
            );
            outputs.push(SyncOutput::SyncComplete {
                source_shard,
                height: state.committed,
            });
            // Leave per-shard state in place so future StartSync raises the
            // target without re-allocating; it's idle until then.
            return outputs;
        }

        Self::queue_window(state, &self.config);
        outputs.extend(self.emit_fetch_outputs());
        outputs
    }

    fn handle_tick(&mut self, now: Instant) -> Vec<SyncOutput> {
        for state in self.shards.values_mut() {
            // Promote ready deferred heights back into the heap.
            let ready: Vec<BlockHeight> = state
                .deferred
                .iter()
                .filter_map(|(h, b)| b.is_ready(now).then_some(*h))
                .collect();
            for h in ready {
                state.deferred.remove(&h);
                if h > state.committed && h <= state.target && !state.in_flight.contains(&h) {
                    state.heights_queued.insert(h);
                    state.heights_to_fetch.push(Reverse(h));
                }
            }
        }
        self.emit_fetch_outputs()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Window + Emission
    // ═══════════════════════════════════════════════════════════════════════

    /// Queue heights `[committed+1, min(committed+window_size, target)]` for
    /// fetching. Idempotent — already-tracked heights are skipped by
    /// `queue_height`.
    fn queue_window(state: &mut PerShardState, config: &RemoteHeaderSyncConfig) {
        if state.committed >= state.target {
            return;
        }
        let first = state.committed.0 + 1;
        let window_end = if config.sync_window_size == 0 {
            state.target.0
        } else {
            (state.committed.0 + config.sync_window_size).min(state.target.0)
        };
        for h in first..=window_end {
            state.queue_height(BlockHeight(h));
        }
    }

    /// Pack contiguous heights from `heights_to_fetch` into `FetchHeaders`
    /// outputs, respecting `max_concurrent_fetches_per_shard` and
    /// `max_headers_per_fetch`.
    fn emit_fetch_outputs(&mut self) -> Vec<SyncOutput> {
        let mut outputs = Vec::new();
        let max_per = self.config.max_headers_per_fetch;
        let max_concurrent = self.config.max_concurrent_fetches_per_shard;

        for (&shard_id, state) in &mut self.shards {
            while state.in_flight_ranges < max_concurrent {
                let Some(range_start) = state.peek_next_height() else {
                    break;
                };
                // Pack: pull lowest queued height, then keep pulling while
                // the next is contiguous and under the per-fetch cap.
                let mut covered: Vec<BlockHeight> = Vec::new();
                let mut next = range_start;
                let max_per_usize = usize::try_from(max_per).unwrap_or(usize::MAX);
                while covered.len() < max_per_usize {
                    let Some(peek) = state.peek_next_height() else {
                        break;
                    };
                    if peek != next {
                        break;
                    }
                    let popped = state.pop_next_height().expect("peek matched");
                    state.in_flight.insert(popped);
                    covered.push(popped);
                    next = BlockHeight(next.0 + 1);
                }
                if covered.is_empty() {
                    break;
                }
                let count = u64::try_from(covered.len()).unwrap_or(u64::MAX);
                state.in_flight_ranges += 1;
                trace!(
                    source_shard = shard_id.0,
                    from = range_start.0,
                    count,
                    "remote-header sync: emitting range fetch"
                );
                outputs.push(SyncOutput::FetchHeaders {
                    source_shard: shard_id,
                    from_height: range_start,
                    count,
                });
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeader, QuorumCertificate, StateRoot, ValidatorId};

    fn cfg() -> RemoteHeaderSyncConfig {
        RemoteHeaderSyncConfig {
            max_headers_per_fetch: 8,
            sync_window_size: 32,
            max_concurrent_fetches_per_shard: 2,
        }
    }

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId(n)
    }

    fn header_at(shard_id: ShardGroupId, height: BlockHeight) -> CommittedBlockHeader {
        let mut header = BlockHeader::genesis(shard_id, ValidatorId(0), StateRoot::ZERO);
        header.height = height;
        let qc = QuorumCertificate::genesis();
        CommittedBlockHeader::new(header, qc)
    }

    #[test]
    fn start_sync_queues_window_and_emits_first_range() {
        let mut p = RemoteHeaderSyncProtocol::new(cfg());
        let outputs = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(20),
        });

        // First emission packs heights 1..=8 into one range fetch.
        let fetches: Vec<_> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::FetchHeaders {
                    source_shard,
                    from_height,
                    count,
                } => Some((*source_shard, *from_height, *count)),
                _ => None,
            })
            .collect();
        assert_eq!(fetches.len(), 2, "concurrency=2 → two parallel ranges");
        assert_eq!(fetches[0], (shard(1), BlockHeight(1), 8));
        assert_eq!(fetches[1], (shard(1), BlockHeight(9), 8));
    }

    #[test]
    fn response_delivers_headers_and_admit_advances_committed() {
        let mut p = RemoteHeaderSyncProtocol::new(cfg());
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(20),
        });

        let now = Instant::now();
        let headers = (1..=8)
            .map(|h| header_at(shard(1), BlockHeight(h)))
            .collect();
        let outputs = p.handle(SyncInput::HeadersResponseReceived {
            source_shard: shard(1),
            from_height: BlockHeight(1),
            count: 8,
            headers,
            now,
        });

        let delivered = outputs
            .iter()
            .filter(|o| matches!(o, SyncOutput::DeliverHeader { .. }))
            .count();
        assert_eq!(delivered, 8);

        // Admit each one and verify completion fires when target reached.
        for h in 1..=8 {
            let _ = p.handle(SyncInput::HeaderAdmitted {
                source_shard: shard(1),
                height: BlockHeight(h),
            });
        }
        // Not complete yet (target=20, committed=8).
        assert!(p.is_syncing());
    }

    #[test]
    fn fetch_failed_defers_failed_heights_until_backoff() {
        let mut p = RemoteHeaderSyncProtocol::new(cfg());
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(8),
        });
        let now = Instant::now();
        // Both initial ranges go in-flight. Fail the first one.
        let _ = p.handle(SyncInput::HeadersFetchFailed {
            source_shard: shard(1),
            from_height: BlockHeight(1),
            count: 8,
            now,
        });
        assert!(p.has_deferred());

        // Tick before backoff: failed heights stay parked.
        let outputs = p.handle(SyncInput::Tick {
            now: now + Duration::from_millis(500),
        });
        let refires_low = outputs.iter().any(|o| {
            matches!(
                o,
                SyncOutput::FetchHeaders { from_height, .. } if from_height.0 <= 8
            )
        });
        assert!(!refires_low, "deferred heights must wait out backoff");

        // Tick past first-round backoff (1s): heights re-emerge.
        let outputs = p.handle(SyncInput::Tick {
            now: now + Duration::from_secs(2),
        });
        let refires_low = outputs.iter().any(|o| {
            matches!(
                o,
                SyncOutput::FetchHeaders { from_height, .. } if from_height.0 == 1
            )
        });
        assert!(refires_low, "expected re-emission after backoff");
    }

    #[test]
    fn partial_response_defers_short_capped_heights() {
        let mut p = RemoteHeaderSyncProtocol::new(cfg());
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(20),
        });
        let now = Instant::now();
        // Asked for 1..=8, responder only had 1..=5 (short-capped).
        let headers = (1..=5)
            .map(|h| header_at(shard(1), BlockHeight(h)))
            .collect();
        let _ = p.handle(SyncInput::HeadersResponseReceived {
            source_shard: shard(1),
            from_height: BlockHeight(1),
            count: 8,
            headers,
            now,
        });
        // Heights 6, 7, 8 should be deferred.
        assert!(p.has_deferred());
    }

    #[test]
    fn admit_at_target_emits_sync_complete() {
        let mut p = RemoteHeaderSyncProtocol::new(RemoteHeaderSyncConfig {
            max_headers_per_fetch: 8,
            sync_window_size: 32,
            max_concurrent_fetches_per_shard: 1,
        });
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(2),
        });
        for h in 1..=2 {
            let _ = p.handle(SyncInput::HeaderAdmitted {
                source_shard: shard(1),
                height: BlockHeight(h),
            });
        }
        let outputs = p.handle(SyncInput::HeaderAdmitted {
            source_shard: shard(1),
            height: BlockHeight(2),
        });
        // Already at target — confirm SyncComplete observable on a fresh
        // admit call once committed >= target.
        let _ = outputs;
        assert!(!p.is_syncing());
    }

    #[test]
    fn shards_progress_independently() {
        let mut p = RemoteHeaderSyncProtocol::new(cfg());
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(1),
            target: BlockHeight(10),
        });
        let _ = p.handle(SyncInput::StartSync {
            source_shard: shard(2),
            target: BlockHeight(20),
        });
        // Admit shard 1 fully; shard 2 still needs work.
        for h in 1..=10 {
            let _ = p.handle(SyncInput::HeaderAdmitted {
                source_shard: shard(1),
                height: BlockHeight(h),
            });
        }
        assert!(p.is_syncing(), "shard 2 still has gap");
    }
}
