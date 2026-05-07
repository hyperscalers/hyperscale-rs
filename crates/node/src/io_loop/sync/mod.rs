//! Sliding-window sync state machines plus inbound serve handlers.
//!
//! The generic [`Sync`] state machine owns scheduling for one or more
//! "scopes" (e.g. a single chain for block-sync; one per remote shard for
//! remote-header-sync). Per-scope it tracks:
//!
//! - `target` — the highest known height to chase
//! - `committed` — the highest height admitted via [`SyncInput::Admitted`]
//! - a [`BlockHeight`] queue of heights waiting to be fetched
//! - which heights are in-flight to the network
//! - which heights are deferred behind an exponential backoff after a
//!   failed fetch
//!
//! Per-payload concerns — wire shape, response decoding, rehydration,
//! payload-private state — live on the binding via [`SyncBinding`] and
//! its associated `State` type.
//!
//! # Module map
//!
//! - [`block`] — block-sync binding (`Sync<BlockSyncBinding>`).
//! - [`remote_header`] — remote-header sync binding
//!   (`Sync<RemoteHeaderSyncBinding>`), one scope per remote shard.
//! - [`block_serve`] / [`remote_header_serve`] — inbound responders for
//!   the range requests the binding-side step layer dispatches.
//! - [`host`] bundles the two sync state machines and exposes
//!   IoLoop-side glue (tick, admission notification, metrics).
//!
//! # Usage
//!
//! ```text
//! Caller ──► Sync::handle(SyncInput) ──► Vec<SyncOutput>
//! ```
//!
//! Each `Output::Fetch { scope, from, count }` is a request to fetch a
//! contiguous range of heights. The caller's binding-side glue translates
//! that into a network round-trip, decodes the response, then feeds the
//! result back through `SyncInput::FetchSucceeded` (with the list of
//! actually-delivered heights) or `SyncInput::FetchFailed` (entire range
//! deferred).
//!
//! Deliveries are surfaced by the binding to its consumer (BFT, the
//! remote-header coordinator, …). The generic only learns that a height
//! has been admitted when the consumer feeds back
//! [`SyncInput::Admitted`].

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::time::{Duration, Instant};

use hyperscale_types::BlockHeight;
use serde::Serialize;
use tracing::{info, trace};

pub mod block;
pub mod block_serve;
pub mod host;
pub mod remote_header;
pub mod remote_header_serve;

pub use host::{SyncHost, SyncMetrics};

/// Initial backoff for a deferred height after its first fetch failure.
const DEFERRAL_BASE_MS: u64 = 1_000;
/// Multiplier applied to the previous round's backoff on each subsequent failure.
const DEFERRAL_MULTIPLIER: f64 = 2.0;
/// Backoff cap; subsequent rounds plateau here rather than growing unbounded.
const DEFERRAL_MAX_MS: u64 = 30_000;

/// How long a delivered-but-unadmitted height stays parked before we
/// give up waiting for the consumer's admission and demote it back to
/// `deferred` for re-fetch. Covers the async gap between
/// [`SyncInput::FetchSucceeded`] and [`SyncInput::Admitted`] — chiefly
/// QC verification on the consensus-crypto pool — while still bounding
/// the wait when admission never lands (e.g. QC verification rejects the
/// delivered header and the binding has no further candidates).
const PENDING_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-height deferral state: how many rounds we've backed off and when the
/// next retry is permitted.
#[derive(Debug, Default)]
struct DeferralBackoff {
    rounds: u32,
    next_retry_at: Option<Instant>,
}

impl DeferralBackoff {
    fn is_ready(&self, now: Instant) -> bool {
        self.next_retry_at.is_none_or(|deadline| now >= deadline)
    }

    fn advance_round(&mut self, now: Instant) {
        self.rounds = self.rounds.saturating_add(1);
        let exp = i32::try_from(self.rounds.saturating_sub(1)).unwrap_or(i32::MAX);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )] // float→u64 truncation is intentional; result is clamped below
        let backoff_ms = ((DEFERRAL_BASE_MS as f64) * DEFERRAL_MULTIPLIER.powi(exp)) as u64;
        let backoff_ms = backoff_ms.min(DEFERRAL_MAX_MS);
        self.next_retry_at = Some(now + Duration::from_millis(backoff_ms));
    }
}

/// Tunable knobs for the sync state machine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum heights packed into a single `Fetch` output. `1` for
    /// per-id payloads (block-sync); larger for range fetches
    /// (remote-header-sync).
    pub max_per_request: u64,
    /// Per-scope sliding window: how far ahead of `committed` heights are
    /// queued for fetching.
    pub window_size: u64,
    /// Cap on concurrent in-flight fetches per scope.
    pub max_concurrent_per_scope: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_per_request: 1,
            window_size: 64,
            max_concurrent_per_scope: 32,
        }
    }
}

/// Per-scope sync status snapshot for external APIs.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ScopeStatus {
    /// Highest known target.
    pub target_height: u64,
    /// Highest admitted height.
    pub current_height: u64,
    /// Number of heights behind target.
    pub blocks_behind: u64,
    /// In-flight fetch ranges.
    pub pending_fetches: usize,
    /// Heights queued or deferred awaiting fetch.
    pub queued_heights: usize,
}

/// Trait carrying the per-binding type info the generic needs.
///
/// `Scope` is the per-instance key (e.g. `()` for single-instance sync,
/// `ShardGroupId` for multi-instance). `State` is binding-private mutable
/// state owned by [`Sync`].
pub trait SyncBinding: 'static {
    /// Scope key. Use `()` for single-instance bindings.
    type Scope: Clone + Ord + Hash + Debug + 'static;

    /// Binding-private mutable state. Use `()` if none is needed.
    type State: Default + 'static;

    /// Stable identifier for tracing / metrics.
    const NAME: &'static str;

    /// Hook fired when a height is admitted. Bindings with per-id
    /// auxiliary state (e.g. block-sync's `force_full_refetch`) clean up
    /// entries at or below `committed` here. Default no-op.
    #[allow(unused_variables)]
    fn on_admitted(state: &mut Self::State, scope: &Self::Scope, committed: BlockHeight) {}

    /// Hook fired when a scope reaches its target and emits `Complete`.
    /// Binding can clear all per-id state at this point. Default no-op.
    #[allow(unused_variables)]
    fn on_complete(state: &mut Self::State, scope: &Self::Scope, height: BlockHeight) {}
}

/// Per-scope sliding-window state.
struct ScopeState {
    /// Highest known target. Advances on [`SyncInput::StartSync`] and
    /// implicitly when a delivered height exceeds the current target
    /// (the responder's possession of a height is proof of existence).
    target: BlockHeight,
    /// Highest admitted height.
    committed: BlockHeight,
    /// Heights ready to fetch (lowest-first).
    heights_to_fetch: BinaryHeap<Reverse<BlockHeight>>,
    /// Membership for `heights_to_fetch` to dedupe pushes.
    heights_queued: HashSet<BlockHeight>,
    /// Heights currently in a dispatched fetch range.
    in_flight: HashSet<BlockHeight>,
    /// Heights whose last fetch failed; held out of `heights_to_fetch`
    /// until their backoff deadline elapses.
    deferred: HashMap<BlockHeight, DeferralBackoff>,
    /// Heights delivered by the network but not yet admitted by the
    /// consumer (admission is async — e.g. cross-shard QC verification
    /// on a thread pool). Held out of `heights_to_fetch` until either
    /// admission lands (drop on `handle_admitted`) or the deadline
    /// elapses (demoted to `deferred` on `handle_tick`). Without this,
    /// `queue_window` would re-queue every just-delivered range and
    /// `emit_fetches` would dispatch a duplicate fetch for the bytes
    /// we just received.
    pending_admission: HashMap<BlockHeight, Instant>,
    /// Number of in-flight fetch ranges for this scope. Bounded by
    /// `max_concurrent_per_scope`.
    in_flight_ranges: usize,
}

impl ScopeState {
    fn new(target: BlockHeight) -> Self {
        Self {
            target,
            committed: BlockHeight::GENESIS,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            in_flight: HashSet::new(),
            deferred: HashMap::new(),
            pending_admission: HashMap::new(),
            in_flight_ranges: 0,
        }
    }

    fn queue_height(&mut self, height: BlockHeight) {
        if self.in_flight.contains(&height)
            || self.deferred.contains_key(&height)
            || self.pending_admission.contains_key(&height)
        {
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

    /// Peek the lowest valid queued height, lazily discarding stale heap
    /// tops left behind by `handle_admitted`'s prune of `heights_queued` /
    /// `in_flight` (`BinaryHeap` has no `retain`). Keeps `peek` and `pop`
    /// applying the same validity filter — without this, `peek` can return
    /// a stale entry that `pop_next_height` then skips, breaking callers
    /// that assume a successful peek implies a successful pop.
    fn peek_next_height(&mut self) -> Option<BlockHeight> {
        while let Some(&Reverse(top)) = self.heights_to_fetch.peek() {
            if self.heights_queued.contains(&top) && !self.in_flight.contains(&top) {
                return Some(top);
            }
            self.heights_to_fetch.pop();
        }
        None
    }
}

pub use hyperscale_core::FetchFailureKind;

/// Inputs to the generic sync state machine.
#[derive(Debug)]
#[allow(missing_docs)] // payloads are self-describing
pub enum SyncInput<B: SyncBinding> {
    /// Set or raise the sync target for `scope`. Idempotent if `target`
    /// hasn't moved forward.
    StartSync {
        scope: B::Scope,
        target: BlockHeight,
    },
    /// A response was received covering `[from, from + count)`.
    /// `delivered_heights` lists the heights actually returned (subset of
    /// the range). Heights in the range that are not in
    /// `delivered_heights` get deferred.
    FetchSucceeded {
        scope: B::Scope,
        from: BlockHeight,
        count: u64,
        delivered_heights: Vec<BlockHeight>,
        now: Instant,
    },
    /// The fetch round-trip failed. Heights are re-queued; whether they
    /// pay an exponential-backoff penalty depends on `kind`.
    FetchFailed {
        scope: B::Scope,
        from: BlockHeight,
        count: u64,
        kind: FetchFailureKind,
        now: Instant,
    },
    /// The consumer admitted a height for `scope` (e.g. via QC verification).
    /// Advances per-scope `committed`; may emit `Complete`.
    Admitted {
        scope: B::Scope,
        height: BlockHeight,
    },
    /// Periodic tick: promotes deferred heights past their backoff and
    /// emits any newly-ready fetches.
    Tick { now: Instant },
}

/// Outputs from the generic sync state machine.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum SyncOutput<B: SyncBinding> {
    /// Issue a fetch covering `[from, from + count)` for `scope`.
    Fetch {
        scope: B::Scope,
        from: BlockHeight,
        count: u64,
    },
    /// `scope` caught up to `height`. Emitted at most once per
    /// caught-up cycle.
    Complete {
        scope: B::Scope,
        height: BlockHeight,
    },
}

/// Generic sliding-window sync state machine.
pub struct Sync<B: SyncBinding> {
    config: SyncConfig,
    scopes: BTreeMap<B::Scope, ScopeState>,
    binding_state: B::State,
}

impl<B: SyncBinding> Sync<B> {
    /// Create a new instance with default binding state.
    #[must_use]
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            scopes: BTreeMap::new(),
            binding_state: B::State::default(),
        }
    }

    /// Read-only access to the binding's private state.
    #[must_use]
    pub const fn binding_state(&self) -> &B::State {
        &self.binding_state
    }

    /// Mutable access to the binding's private state.
    pub const fn binding_state_mut(&mut self) -> &mut B::State {
        &mut self.binding_state
    }

    /// True if any scope has heights parked behind a backoff deadline.
    #[must_use]
    pub fn has_deferred(&self) -> bool {
        self.scopes.values().any(|s| !s.deferred.is_empty())
    }

    /// True if any scope is actively syncing (committed < target).
    #[must_use]
    pub fn is_syncing(&self) -> bool {
        self.scopes.values().any(|s| s.committed < s.target)
    }

    /// Total blocks behind across all scopes — sum of each scope's
    /// `target - committed`. Use for an aggregate gauge across a
    /// multi-scope binding.
    #[must_use]
    pub fn total_blocks_behind(&self) -> u64 {
        self.scopes
            .values()
            .map(|s| s.target.inner().saturating_sub(s.committed.inner()))
            .sum()
    }

    /// Total in-flight fetch ranges across all scopes.
    #[must_use]
    pub fn in_flight_ranges(&self) -> usize {
        self.scopes.values().map(|s| s.in_flight_ranges).sum()
    }

    /// Per-scope target. `None` if the scope has no entry yet.
    #[must_use]
    pub fn target(&self, scope: &B::Scope) -> Option<BlockHeight> {
        self.scopes.get(scope).map(|s| s.target)
    }

    /// Per-scope status snapshot.
    #[must_use]
    pub fn status(&self, scope: &B::Scope) -> ScopeStatus {
        self.scopes
            .get(scope)
            .map(|s| ScopeStatus {
                target_height: s.target.inner(),
                current_height: s.committed.inner(),
                blocks_behind: s.target.inner().saturating_sub(s.committed.inner()),
                pending_fetches: s.in_flight_ranges,
                queued_heights: s.heights_queued.len()
                    + s.deferred.len()
                    + s.pending_admission.len(),
            })
            .unwrap_or_default()
    }

    /// Process an input, returning outputs.
    pub fn handle(&mut self, input: SyncInput<B>) -> Vec<SyncOutput<B>> {
        match input {
            SyncInput::StartSync { scope, target } => self.handle_start_sync(&scope, target),
            SyncInput::FetchSucceeded {
                scope,
                from,
                count,
                delivered_heights,
                now,
            } => self.handle_fetch_succeeded(&scope, from, count, &delivered_heights, now),
            SyncInput::FetchFailed {
                scope,
                from,
                count,
                kind,
                now,
            } => self.handle_fetch_failed(&scope, from, count, kind, now),
            SyncInput::Admitted { scope, height } => self.handle_admitted(&scope, height),
            SyncInput::Tick { now } => self.handle_tick(now),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_start_sync(&mut self, scope: &B::Scope, target: BlockHeight) -> Vec<SyncOutput<B>> {
        // Distinguish "first sync for this scope" from "raise an existing
        // target": a freshly created entry has `target == GENESIS`, so we
        // always proceed into the window-queue path on its first call.
        let is_new = !self.scopes.contains_key(scope);
        let state = self
            .scopes
            .entry(scope.clone())
            .or_insert_with(|| ScopeState::new(BlockHeight::GENESIS));

        if !is_new && state.target >= target {
            return vec![];
        }

        info!(
            binding = B::NAME,
            ?scope,
            target = target.inner(),
            committed = state.committed.inner(),
            "sync: target raised"
        );

        state.target = target;
        Self::queue_window(state, &self.config);
        self.emit_fetches()
    }

    #[allow(clippy::needless_pass_by_value)] // taken by value to mirror SyncInput's owned shape
    fn handle_fetch_succeeded(
        &mut self,
        scope: &B::Scope,
        from: BlockHeight,
        count: u64,
        delivered_heights: &[BlockHeight],
        now: Instant,
    ) -> Vec<SyncOutput<B>> {
        let Some(state) = self.scopes.get_mut(scope) else {
            return Vec::new();
        };
        state.in_flight_ranges = state.in_flight_ranges.saturating_sub(1);

        let delivered: HashSet<BlockHeight> = delivered_heights.iter().copied().collect();
        let pending_deadline = now + PENDING_ADMISSION_TIMEOUT;

        for offset in 0..count {
            let h = BlockHeight::new(from.inner() + offset);
            state.in_flight.remove(&h);
            if delivered.contains(&h) {
                if h > state.committed {
                    // Park until the consumer admits this height (async —
                    // e.g. QC verification on the consensus-crypto pool).
                    // `handle_tick` demotes back to `deferred` if admission
                    // never arrives within `PENDING_ADMISSION_TIMEOUT`.
                    state.pending_admission.insert(h, pending_deadline);
                }
            } else if h <= state.target && h > state.committed {
                state.deferred.entry(h).or_default().advance_round(now);
            }
        }

        // Implicit target advancement: any delivered height past the
        // current target proves the responder has at least committed that
        // height. Cap the jump at one window plus one batch past
        // `committed` so a buggy or malicious responder claiming an
        // arbitrarily high height can't make us chase it — honest peers
        // serving a slightly larger range than requested still fit under
        // the cap.
        if let Some(max_delivered) = delivered.iter().max().copied()
            && max_delivered > state.target
        {
            let cap = BlockHeight::new(
                state
                    .committed
                    .inner()
                    .saturating_add(self.config.window_size)
                    .saturating_add(self.config.max_per_request),
            );
            state.target = max_delivered.min(cap);
        }

        Self::queue_window(state, &self.config);
        self.emit_fetches()
    }

    fn handle_fetch_failed(
        &mut self,
        scope: &B::Scope,
        from: BlockHeight,
        count: u64,
        kind: FetchFailureKind,
        now: Instant,
    ) -> Vec<SyncOutput<B>> {
        let Some(state) = self.scopes.get_mut(scope) else {
            return vec![];
        };
        state.in_flight_ranges = state.in_flight_ranges.saturating_sub(1);
        for offset in 0..count {
            let h = BlockHeight::new(from.inner() + offset);
            if state.in_flight.remove(&h) && h <= state.target && h > state.committed {
                match kind {
                    // The request manager already retried against rotated
                    // peers (per-peer pool backoff + per-request retries
                    // absorbed seconds of waiting). Adding an FSM-level
                    // exponential deferral on top just stalls catch-up while
                    // the source committee is recovering. Re-queue so the
                    // freed slot can be used immediately; the per-peer
                    // backoff layer keeps us off any genuinely dead peer.
                    FetchFailureKind::Exhausted => {
                        state.deferred.remove(&h);
                        state.queue_height(h);
                    }
                    // Empty committee or transport-level fault — no point
                    // retrying immediately. Apply the standard backoff.
                    FetchFailureKind::NoPeers | FetchFailureKind::Transport => {
                        state.deferred.entry(h).or_default().advance_round(now);
                    }
                }
            }
        }
        // The freed slot can carry other ready work immediately — heights
        // past the failed range, ready-deferred entries from earlier
        // failures, or other scopes' queues. Without this, the slot sits
        // idle until the next Tick.
        self.emit_fetches()
    }

    fn handle_admitted(&mut self, scope: &B::Scope, height: BlockHeight) -> Vec<SyncOutput<B>> {
        // Always track the latest committed height for this scope, even if
        // sync hasn't been started yet. Otherwise a future `StartSync`
        // would re-fetch heights the consumer has already admitted.
        let state = self
            .scopes
            .entry(scope.clone())
            .or_insert_with(|| ScopeState::new(BlockHeight::GENESIS));

        // `Complete` should only fire on the transition from "syncing" to
        // "caught up" — i.e. the consumer admitted the height that closes
        // the last gap. Capture whether we were below target *before*
        // advancing committed so a steady-stream of admissions outside an
        // active sync (target == committed) doesn't re-fire Complete.
        let was_syncing = state.committed < state.target;

        if height > state.committed {
            state.committed = height;
        }

        // Drop tracking state for heights at or below the new committed
        // level.
        let committed = state.committed;
        let reached_target = was_syncing && committed >= state.target;
        state.heights_queued.retain(|&h| h > committed);
        state.in_flight.retain(|&h| h > committed);
        state.deferred.retain(|&h, _| h > committed);
        state.pending_admission.retain(|&h, _| h > committed);

        // Binding hook: clean up per-id auxiliary state.
        B::on_admitted(&mut self.binding_state, scope, committed);

        let mut outputs = Vec::new();
        if reached_target {
            info!(
                binding = B::NAME,
                ?scope,
                height = committed.inner(),
                "sync: caught up"
            );
            B::on_complete(&mut self.binding_state, scope, committed);
            outputs.push(SyncOutput::Complete {
                scope: scope.clone(),
                height: committed,
            });
            return outputs;
        }

        Self::queue_window(state, &self.config);
        outputs.extend(self.emit_fetches());
        outputs
    }

    fn handle_tick(&mut self, now: Instant) -> Vec<SyncOutput<B>> {
        for state in self.scopes.values_mut() {
            // Re-queue pending-admission heights whose deadline elapsed.
            // The PENDING_ADMISSION_TIMEOUT wait already absorbs the
            // QC-verification + admission window; if admission never
            // arrived, every candidate sender's QC failed, and the only
            // way forward is to re-fetch and find different senders. An
            // additional `deferred` backoff just delays that.
            let stale: Vec<BlockHeight> = state
                .pending_admission
                .iter()
                .filter_map(|(h, deadline)| (now >= *deadline).then_some(*h))
                .collect();
            for h in stale {
                state.pending_admission.remove(&h);
                if h > state.committed && h <= state.target {
                    state.queue_height(h);
                }
            }

            // Promote ready deferred heights back into the heap.
            let ready: Vec<BlockHeight> = state
                .deferred
                .iter()
                .filter_map(|(h, b)| b.is_ready(now).then_some(*h))
                .collect();
            for h in ready {
                state.deferred.remove(&h);
                if h > state.committed && h <= state.target {
                    // Defer to `queue_height` so dedup against
                    // `heights_queued` / `in_flight` / `deferred` /
                    // `pending_admission` stays in one place — and we
                    // don't double-push if the height is somehow already
                    // tracked.
                    state.queue_height(h);
                }
            }
        }
        self.emit_fetches()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Window + Emission
    // ═══════════════════════════════════════════════════════════════════════

    /// Queue heights `[committed+1, min(committed+window_size, target)]`.
    /// Idempotent — already-tracked heights are skipped.
    fn queue_window(state: &mut ScopeState, config: &SyncConfig) {
        if state.committed >= state.target {
            return;
        }
        let first = state.committed.inner() + 1;
        let window_end = if config.window_size == 0 {
            state.target.inner()
        } else {
            (state.committed.inner() + config.window_size).min(state.target.inner())
        };
        for h in first..=window_end {
            state.queue_height(BlockHeight::new(h));
        }
    }

    /// Pack contiguous heights into `Fetch` outputs, respecting
    /// `max_concurrent_per_scope` and `max_per_request`.
    fn emit_fetches(&mut self) -> Vec<SyncOutput<B>> {
        let mut outputs = Vec::new();
        let max_per = self.config.max_per_request.max(1);
        let max_per_usize = usize::try_from(max_per).unwrap_or(usize::MAX);
        let max_concurrent = self.config.max_concurrent_per_scope;

        for (scope_id, state) in &mut self.scopes {
            while state.in_flight_ranges < max_concurrent {
                let Some(range_start) = state.peek_next_height() else {
                    break;
                };
                // Pack: pull lowest queued height, then keep pulling while
                // the next is contiguous and under the per-request cap.
                let mut covered: Vec<BlockHeight> = Vec::new();
                let mut next = range_start;
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
                    next = BlockHeight::new(next.inner() + 1);
                }
                if covered.is_empty() {
                    break;
                }
                let count = u64::try_from(covered.len()).unwrap_or(u64::MAX);
                state.in_flight_ranges += 1;
                trace!(
                    binding = B::NAME,
                    ?scope_id,
                    from = range_start.inner(),
                    count,
                    "sync: emitting fetch"
                );
                outputs.push(SyncOutput::Fetch {
                    scope: scope_id.clone(),
                    from: range_start,
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

    /// Single-scope binding for testing.
    struct UnitBinding;
    impl SyncBinding for UnitBinding {
        type Scope = ();
        type State = ();
        const NAME: &'static str = "test_unit";
    }

    /// Multi-scope binding for testing.
    struct ShardBinding;
    impl SyncBinding for ShardBinding {
        type Scope = u64;
        type State = ();
        const NAME: &'static str = "test_shard";
    }

    fn cfg_per_id() -> SyncConfig {
        SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 4,
        }
    }

    fn cfg_range() -> SyncConfig {
        SyncConfig {
            max_per_request: 8,
            window_size: 32,
            max_concurrent_per_scope: 2,
        }
    }

    #[test]
    fn start_sync_unit_emits_per_id_fetches() {
        let mut s: Sync<UnitBinding> = Sync::new(cfg_per_id());
        let outputs = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(10),
        });
        // max_per_request=1 → one Fetch per slot, count=1 each.
        let fetches: Vec<_> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::Fetch { from, count, .. } => Some((*from, *count)),
                SyncOutput::Complete { .. } => None,
            })
            .collect();
        assert_eq!(fetches.len(), 4, "concurrency=4 → four parallel fetches");
        assert!(fetches.iter().all(|(_, c)| *c == 1));
    }

    #[test]
    fn start_sync_range_packs_contiguous_heights() {
        let mut s: Sync<ShardBinding> = Sync::new(cfg_range());
        let outputs = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(20),
        });
        // First emission packs heights 1..=8 into one range.
        let first = outputs
            .iter()
            .find_map(|o| match o {
                SyncOutput::Fetch {
                    scope, from, count, ..
                } => Some((*scope, *from, *count)),
                SyncOutput::Complete { .. } => None,
            })
            .expect("expected at least one Fetch");
        assert_eq!(first, (1, BlockHeight::new(1), 8));
    }

    #[test]
    fn admit_advances_committed_and_drops_lower_state() {
        let mut s: Sync<UnitBinding> = Sync::new(cfg_per_id());
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(10),
        });
        // Admit height 3.
        let _ = s.handle(SyncInput::Admitted {
            scope: (),
            height: BlockHeight::new(3),
        });
        let st = s.scopes.get(&()).unwrap();
        assert_eq!(st.committed, BlockHeight::new(3));
        // Heights at or below 3 are dropped from in_flight / queued / deferred.
        assert!(st.heights_queued.iter().all(|&h| h > BlockHeight::new(3)));
        assert!(st.in_flight.iter().all(|&h| h > BlockHeight::new(3)));
    }

    #[test]
    fn admit_to_target_emits_complete() {
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 1,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(2),
        });
        let _ = s.handle(SyncInput::Admitted {
            scope: (),
            height: BlockHeight::new(1),
        });
        let outputs = s.handle(SyncInput::Admitted {
            scope: (),
            height: BlockHeight::new(2),
        });
        assert!(outputs.iter().any(|o| matches!(
            o,
            SyncOutput::Complete { height, .. } if height.inner() == 2
        )));
        assert!(!s.is_syncing());
    }

    #[test]
    fn fetch_failed_defers_all_heights_in_range() {
        // Single height + single slot makes deferral observable end-to-end:
        // initial fetch → fail → backoff → tick promotes → re-emit.
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 1,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(1),
        });
        let now = Instant::now();
        let _ = s.handle(SyncInput::FetchFailed {
            scope: (),
            from: BlockHeight::new(1),
            count: 1,
            kind: FetchFailureKind::Transport,
            now,
        });
        assert!(s.has_deferred());

        // Tick before backoff: failed height stays parked.
        let outputs = s.handle(SyncInput::Tick {
            now: now + Duration::from_millis(500),
        });
        assert!(!outputs.iter().any(|o| matches!(
            o,
            SyncOutput::Fetch { from, .. } if from.inner() == 1
        )));

        // Tick past first-round backoff: re-emerges.
        let outputs = s.handle(SyncInput::Tick {
            now: now + Duration::from_secs(2),
        });
        assert!(outputs.iter().any(|o| matches!(
            o,
            SyncOutput::Fetch { from, .. } if from.inner() == 1
        )));
    }

    #[test]
    fn exhausted_failure_skips_backoff() {
        // When the request manager exhausts retries against rotated peers,
        // it has already absorbed seconds of waiting — the FSM should
        // re-queue the height for immediate retry rather than piling its
        // own exponential deferral on top.
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 1,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(1),
        });
        let now = Instant::now();
        let outputs = s.handle(SyncInput::FetchFailed {
            scope: (),
            from: BlockHeight::new(1),
            count: 1,
            kind: FetchFailureKind::Exhausted,
            now,
        });
        // Height 1 should re-emerge as a Fetch in the same turn — no
        // deferred backoff, no waiting for Tick.
        assert!(
            outputs.iter().any(|o| matches!(
                o,
                SyncOutput::Fetch { from, .. } if from.inner() == 1
            )),
            "Exhausted failure must re-queue immediately"
        );
        assert!(
            !s.has_deferred(),
            "Exhausted failure must not park the height in deferred"
        );
    }

    #[test]
    fn partial_response_defers_short_capped_tail() {
        let mut s: Sync<ShardBinding> = Sync::new(cfg_range());
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(20),
        });
        let now = Instant::now();
        // Asked for 1..=8, responder only had 1..=5.
        let delivered = (1..=5).map(BlockHeight::new).collect::<Vec<_>>();
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 8,
            delivered_heights: delivered,
            now,
        });
        // Heights 6, 7, 8 should be deferred.
        assert!(s.has_deferred());
    }

    #[test]
    fn scopes_progress_independently() {
        let mut s: Sync<ShardBinding> = Sync::new(cfg_range());
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(10),
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: 2,
            target: BlockHeight::new(20),
        });
        // Admit scope 1 fully; scope 2 still has work.
        for h in 1..=10 {
            let _ = s.handle(SyncInput::Admitted {
                scope: 1,
                height: BlockHeight::new(h),
            });
        }
        assert!(s.is_syncing(), "scope 2 still has gap");
    }

    #[test]
    fn binding_state_is_owned_by_sync() {
        struct StatefulBinding;
        #[derive(Default)]
        struct State {
            counter: u32,
        }
        impl SyncBinding for StatefulBinding {
            type Scope = ();
            type State = State;
            const NAME: &'static str = "stateful";
        }

        let mut s: Sync<StatefulBinding> = Sync::new(cfg_per_id());
        assert_eq!(s.binding_state().counter, 0);
        s.binding_state_mut().counter += 1;
        assert_eq!(s.binding_state().counter, 1);
    }

    #[test]
    fn implicit_target_advance_on_delivery_past_target() {
        let mut s: Sync<ShardBinding> = Sync::new(cfg_range());
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(5),
        });
        // Responder volunteered higher heights than we asked for? No —
        // but our recorded `target` should bump if a delivered height
        // exceeds it (e.g. we asked for 1..=5 and got [1,2,3,4,5,6]
        // because the responder serves a slightly larger window). Test
        // by feeding a delivery whose max exceeds current target.
        let now = Instant::now();
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 5,
            delivered_heights: (1..=7).map(BlockHeight::new).collect(),
            now,
        });
        let st = s.scopes.get(&1).unwrap();
        assert_eq!(st.target, BlockHeight::new(7));
    }

    #[test]
    fn implicit_target_advance_caps_at_one_window_past_committed() {
        // A responder volunteering a height far past `committed + window`
        // must not slide our target out into space — honest peers won't,
        // and a malicious one shouldn't be able to make us chase fetches
        // toward a height that doesn't exist.
        let mut s: Sync<ShardBinding> = Sync::new(cfg_range());
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(5),
        });
        // cfg_range: window_size=32, max_per_request=8. Cap from committed=0
        // is 40. Responder claims a height of 100.
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 5,
            delivered_heights: vec![BlockHeight::new(100)],
            now: Instant::now(),
        });
        let st = s.scopes.get(&1).unwrap();
        assert_eq!(
            st.target,
            BlockHeight::new(40),
            "implicit advance should clamp at committed + window + max_per_request"
        );
    }

    #[test]
    fn admissions_before_first_start_sync_advance_committed() {
        // Consumer admits heights before any sync has been requested.
        // A subsequent `StartSync` must start from the current committed
        // height, not from genesis.
        let mut s: Sync<UnitBinding> = Sync::new(cfg_per_id());
        for h in 1..=5 {
            let outputs = s.handle(SyncInput::Admitted {
                scope: (),
                height: BlockHeight::new(h),
            });
            // Pre-sync admissions must not emit Complete (no sync was active).
            assert!(
                !outputs
                    .iter()
                    .any(|o| matches!(o, SyncOutput::Complete { .. }))
            );
        }

        // Now request sync to height 8. Should only fetch heights 6, 7, 8.
        let outputs = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(8),
        });
        let fetched_heights: Vec<u64> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::Fetch { from, .. } => Some(from.inner()),
                SyncOutput::Complete { .. } => None,
            })
            .collect();
        assert_eq!(fetched_heights, vec![6, 7, 8]);
    }

    #[test]
    fn admissions_outside_sync_do_not_fire_complete() {
        // Steady-state admission stream after sync caught up shouldn't
        // re-fire Complete.
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 1,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(2),
        });
        let _ = s.handle(SyncInput::Admitted {
            scope: (),
            height: BlockHeight::new(1),
        });
        let outputs = s.handle(SyncInput::Admitted {
            scope: (),
            height: BlockHeight::new(2),
        });
        // First catch-up: Complete fires.
        assert_eq!(
            outputs
                .iter()
                .filter(|o| matches!(o, SyncOutput::Complete { .. }))
                .count(),
            1
        );
        // Subsequent admissions while idle: no Complete.
        for h in 3..=10 {
            let outputs = s.handle(SyncInput::Admitted {
                scope: (),
                height: BlockHeight::new(h),
            });
            assert!(
                !outputs
                    .iter()
                    .any(|o| matches!(o, SyncOutput::Complete { .. }))
            );
        }
    }

    #[test]
    fn fetch_succeeded_does_not_redispatch_delivered_unadmitted_heights() {
        // Regression: admission is async (e.g. cross-shard QC verification
        // on a thread pool), so between FetchSucceeded and the matching
        // Admitted there's a window during which delivered heights had
        // been "tracked nowhere" — `queue_window` would re-queue them and
        // `emit_fetches` would dispatch a duplicate range fetch for the
        // exact bytes we just received. Pending-admission tracking closes
        // that gap.
        let mut s: Sync<ShardBinding> = Sync::new(SyncConfig {
            max_per_request: 8,
            window_size: 32,
            max_concurrent_per_scope: 2,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(20),
        });
        let now = Instant::now();
        let outputs = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 8,
            delivered_heights: (1..=8).map(BlockHeight::new).collect(),
            now,
        });
        let new_fetches: Vec<(BlockHeight, u64)> = outputs
            .iter()
            .filter_map(|o| match o {
                SyncOutput::Fetch { from, count, .. } => Some((*from, *count)),
                SyncOutput::Complete { .. } => None,
            })
            .collect();
        assert!(
            !new_fetches
                .iter()
                .any(|(from, _)| *from == BlockHeight::new(1)),
            "should not re-dispatch a fetch starting at height 1 — we just got 1..=8 \
             back from the network. Got: {new_fetches:?}"
        );
    }

    #[test]
    fn pending_admission_timeout_requeues_for_immediate_refetch() {
        // If admission never lands (e.g. every candidate sender's QC
        // verification failed), the pending-admission slot must not be
        // permanent — Tick re-queues so the heights re-fetch. The 5s
        // pending-admission window already absorbed the wait; no extra
        // deferral backoff on top.
        let mut s: Sync<ShardBinding> = Sync::new(SyncConfig {
            max_per_request: 8,
            window_size: 32,
            max_concurrent_per_scope: 2,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(8),
        });
        // Drain the initial fetches so we observe Tick's emission below.
        let now = Instant::now();
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 8,
            delivered_heights: (1..=8).map(BlockHeight::new).collect(),
            now,
        });
        // Tick before timeout: still pending, no re-fetch.
        let outputs = s.handle(SyncInput::Tick {
            now: now + Duration::from_secs(1),
        });
        assert!(
            outputs.is_empty(),
            "no re-fetch before pending-admission timeout"
        );
        assert!(!s.has_deferred());

        // Tick past PENDING_ADMISSION_TIMEOUT (5s): heights re-queue and
        // emit_fetches dispatches a new range immediately.
        let outputs = s.handle(SyncInput::Tick {
            now: now + Duration::from_secs(6),
        });
        assert!(
            !s.has_deferred(),
            "timeout should re-queue, not move to deferred"
        );
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::Fetch { from, .. } if from.inner() == 1)),
            "expected immediate re-fetch starting at the lowest re-queued height"
        );
    }

    #[test]
    fn fetch_failed_emits_next_fetch_when_other_work_is_ready() {
        // Freeing an in-flight slot via FetchFailed must not leave the
        // freed slot idle when other heights are queued and ready —
        // otherwise the lag waits for the next Tick to make progress.
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 32,
            max_concurrent_per_scope: 2,
        });
        // Window queues 1..=5; concurrency=2 dispatches heights 1 and 2
        // and leaves 3..=5 in the heap.
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(5),
        });
        // Failing height 1 frees a slot. The freed slot should immediately
        // pull height 3 off the heap rather than waiting for Tick.
        let outputs = s.handle(SyncInput::FetchFailed {
            scope: (),
            from: BlockHeight::new(1),
            count: 1,
            kind: FetchFailureKind::Transport,
            now: Instant::now(),
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, SyncOutput::Fetch { from, .. } if from.inner() == 3)),
            "expected immediate emission for height 3 on slot release"
        );
    }

    #[test]
    fn admit_clears_pending_admission_below_committed() {
        let mut s: Sync<ShardBinding> = Sync::new(SyncConfig {
            max_per_request: 8,
            window_size: 32,
            max_concurrent_per_scope: 2,
        });
        let _ = s.handle(SyncInput::StartSync {
            scope: 1,
            target: BlockHeight::new(8),
        });
        let now = Instant::now();
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: 1,
            from: BlockHeight::new(1),
            count: 8,
            delivered_heights: (1..=8).map(BlockHeight::new).collect(),
            now,
        });
        // Admit half the range; pending entries ≤ committed should drop.
        for h in 1..=4 {
            let _ = s.handle(SyncInput::Admitted {
                scope: 1,
                height: BlockHeight::new(h),
            });
        }
        let st = s.scopes.get(&1).unwrap();
        assert!(
            st.pending_admission
                .keys()
                .all(|&h| h > BlockHeight::new(4))
        );
        assert_eq!(st.pending_admission.len(), 4);
    }

    #[test]
    fn admit_past_queued_window_does_not_panic_on_stale_heap_top() {
        // When consensus admits past every queued height (e.g. fast catch-up
        // via gossip while sync is still draining its window), the heap can
        // retain entries whose heights have already been pruned from
        // `heights_queued` / `in_flight`. `peek_next_height` must self-prune
        // these stale tops so `emit_fetches` does not panic on the next
        // dispatch.
        let mut s: Sync<UnitBinding> = Sync::new(SyncConfig {
            max_per_request: 1,
            window_size: 64,
            max_concurrent_per_scope: 4,
        });

        // StartSync queues 1..=10 and dispatches the first 4 (heap retains
        // 5..=10).
        let _ = s.handle(SyncInput::StartSync {
            scope: (),
            target: BlockHeight::new(10),
        });

        // Consensus admits past the entire queued window. This prunes
        // `heights_queued` and `in_flight` but leaves 5..=10 on the heap.
        for h in 1..=10 {
            let _ = s.handle(SyncInput::Admitted {
                scope: (),
                height: BlockHeight::new(h),
            });
        }

        // FetchSucceeded decrements `in_flight_ranges`, freeing a slot —
        // this forces `emit_fetches` to re-enter its inner loop with a
        // heap full of stale tops, exercising the self-pruning peek.
        let _ = s.handle(SyncInput::FetchSucceeded {
            scope: (),
            from: BlockHeight::new(1),
            count: 1,
            delivered_heights: vec![BlockHeight::new(1)],
            now: Instant::now(),
        });
    }
}
