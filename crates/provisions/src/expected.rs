//! Expected-provisions tracker + fallback-fetch typed effects.
//!
//! Anchors all liveness-driven decisions on the shard consensus-authenticated
//! `weighted_timestamp` of locally committed blocks, not local wall-clock.
//! Two distinct triggers fire fallback fetches:
//!
//! 1. **Timeout**: an entry has been outstanding for longer than
//!    [`PROVISION_FALLBACK_TIMEOUT`] without arriving via gossip. Detected
//!    on each block commit via [`Self::check_timeouts`].
//! 2. **Eager flush**: the coordinator decides urgency overrides patience
//!    (sync completion, execution advance gate stalled). Bypasses the
//!    timeout via [`Self::flush_all`].
//!
//! Both produce [`TimeoutEffect`]s; the coordinator attaches peers from
//! topology and lifts each effect into an `Action::Fetch(FetchRequest::RemoteProvisions)`.
//!
//! The tracker also owns `local_committed_ts` because every other consumer
//! of that value reads it through here (deadline sweeps, receipt-time
//! stamping, etc.) — keeping it co-located with the timestamp-driven
//! sweeps that update it.

use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_core::{Action, FetchRequest};
use hyperscale_types::{BlockHeight, ShardId, ValidatorId, WeightedTimestamp};
use tracing::warn;

/// How long to wait before falling back to peer-fetch for missing
/// provisions. Proposers include provisions inline in `Block::Live` during
/// assembly, so this timeout only triggers when gossip dropped them — in
/// which case we fetch from a shard peer. Measured against the shard consensus-
/// authenticated `weighted_timestamp_ms` of locally committed blocks.
const PROVISION_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

type Key = (ShardId, BlockHeight);

/// Per-entry liveness state for a registered expected provisions value.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    /// Local weighted timestamp when we first expected these provisions.
    /// Liveness baseline for the fallback-fetch timeout — how long *we've*
    /// been waiting. A catch-up jump in `local_committed_ts` can leave this
    /// far behind the source block, which only makes the fetch fire sooner.
    discovered_at: WeightedTimestamp,
    /// Authenticated weighted timestamp of the source block (its parent QC).
    /// Orphan eviction keys on this, not `discovered_at`: a freshly-arrived
    /// header whose source block is recent must survive the
    /// `RETENTION_HORIZON` sweep even when our local clock was lagging at
    /// registration (e.g. a split child still catching up).
    source_block_ts: WeightedTimestamp,
    requested: bool,
    proposer: ValidatorId,
}

/// Lifted into an `Action::Fetch(FetchRequest::RemoteProvisions)` via
/// [`Self::into_fetch_action`] once peers are attached from the topology
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEffect {
    pub source_shard: ShardId,
    pub block_height: BlockHeight,
    pub proposer: ValidatorId,
}

impl TimeoutEffect {
    /// Build the `RemoteProvisions` fetch action: the proposer is preferred,
    /// the rest of the source shard's committee is rotation fallback (picked
    /// by the network layer from the source shard's current committee).
    pub(crate) const fn into_fetch_action(self) -> Action {
        Action::Fetch(FetchRequest::RemoteProvisions {
            source_shard: self.source_shard,
            block_height: self.block_height,
            preferred: Some(self.proposer),
            class: None,
        })
    }
}

/// Liveness tracker for cross-shard provisions we expect but haven't yet
/// verified.
pub struct ExpectedProvisionTracker {
    expected: BTreeMap<Key, ExpectedProvision>,
    local_committed_ts: WeightedTimestamp,
}

impl ExpectedProvisionTracker {
    pub(crate) const fn new() -> Self {
        Self {
            expected: BTreeMap::new(),
            local_committed_ts: WeightedTimestamp::ZERO,
        }
    }

    /// Local committed weighted timestamp — the "now" reference for every
    /// liveness decision. Read by the coordinator when stamping receipts
    /// and deadline-sweeping other sub-machines.
    pub(crate) const fn local_ts(&self) -> WeightedTimestamp {
        self.local_committed_ts
    }

    pub(crate) fn len(&self) -> usize {
        self.expected.len()
    }

    /// Register an expectation for provisions at `(source_shard, block_height)`.
    /// No-op if an expectation is already registered for the same key.
    ///
    /// `source_block_ts` is the source block's authenticated weighted
    /// timestamp (its parent QC), the age anchor for orphan eviction.
    pub(crate) fn register(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        proposer: ValidatorId,
        source_block_ts: WeightedTimestamp,
    ) {
        self.expected
            .entry((source_shard, block_height))
            .or_insert(ExpectedProvision {
                discovered_at: self.local_committed_ts,
                source_block_ts,
                requested: false,
                proposer,
            });
    }

    /// Clear an expectation once provisions verify successfully. Returns
    /// `true` if an entry was removed — the coordinator uses that to drop
    /// the matching header and emit `Action::AbandonFetch` so the in-flight
    /// remote-provision fetch is cancelled.
    pub(crate) fn on_provisions_verified(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
    ) -> bool {
        self.expected
            .remove(&(source_shard, block_height))
            .is_some()
    }

    /// Update the local committed anchor and retro-stamp pre-genesis
    /// entries so liveness decisions don't fire spuriously on the first
    /// commit.
    ///
    /// Remote headers can arrive (and register expectations) while
    /// `local_committed_ts` is still zero; without retro-stamping, every
    /// such entry would report a ~57-year age on the next commit and
    /// trigger a fallback fetch storm.
    pub(crate) fn record_block_committed(&mut self, ts: WeightedTimestamp) {
        let first_commit = self.local_committed_ts == WeightedTimestamp::ZERO;
        self.local_committed_ts = ts;

        if first_commit {
            for expected in self.expected.values_mut() {
                if expected.discovered_at == WeightedTimestamp::ZERO {
                    expected.discovered_at = ts;
                }
            }
        }
    }

    /// Drop expectations whose source block predates `cutoff` — past
    /// `RETENTION_HORIZON` every tx in that block has terminated, so its
    /// provisions can never be needed again. Returns the keys evicted so
    /// the coordinator can clean matching headers.
    ///
    /// Keyed on the source block's authenticated `source_block_ts`, not the
    /// local `discovered_at`: a node that registered while its committed
    /// clock lagged (a split child catching up) would otherwise evict a
    /// still-live expectation whose source block is recent.
    ///
    /// Under nominal operation a header is retained exactly while its
    /// provisions are outstanding; this catches entries that would
    /// otherwise leak indefinitely.
    pub(crate) fn cleanup_orphans(&mut self, cutoff: WeightedTimestamp) -> Vec<Key> {
        if cutoff <= WeightedTimestamp::ZERO {
            return Vec::new();
        }
        let mut dropped = Vec::new();
        self.expected.retain(|key, exp| {
            if exp.source_block_ts >= cutoff {
                true
            } else {
                dropped.push(*key);
                false
            }
        });
        dropped
    }

    /// Drop expectations keyed to `shard` strictly above a pending
    /// recovery's attested frontier, returning the dropped keys so
    /// in-flight fallback fetches can be abandoned. Nothing can fulfil
    /// them: the source content is rejected network-wide.
    pub(crate) fn purge_fenced(&mut self, shard: ShardId, frontier: BlockHeight) -> Vec<Key> {
        let mut dropped = Vec::new();
        self.expected.retain(|&key, _| {
            let (s, h) = key;
            if s == shard && h > frontier {
                dropped.push(key);
                false
            } else {
                true
            }
        });
        dropped
    }

    /// Sweep timed-out expectations and emit a `TimeoutEffect` per entry
    /// that crossed the threshold without being requested. Sets
    /// `requested = true` on each effect so the next sweep skips it.
    pub(crate) fn check_timeouts(&mut self, now: WeightedTimestamp) -> Vec<TimeoutEffect> {
        let mut effects = Vec::new();
        for (&(source_shard, block_height), expected) in &mut self.expected {
            if expected.requested {
                continue;
            }
            if now.elapsed_since(expected.discovered_at) < PROVISION_FALLBACK_TIMEOUT {
                continue;
            }
            warn!(
                source_shard = source_shard.inner(),
                block_height = block_height.inner(),
                age_ms = u64::try_from(now.elapsed_since(expected.discovered_at).as_millis())
                    .unwrap_or(u64::MAX),
                "Provision timeout — requesting missing provisions via fallback"
            );
            expected.requested = true;
            effects.push(TimeoutEffect {
                source_shard,
                block_height,
                proposer: expected.proposer,
            });
        }
        effects
    }

    /// Eager-fetch every outstanding expectation, bypassing the normal
    /// timeout. Called when urgency overrides patience — sync completion
    /// and the execution advance gate stalling on missing data.
    pub(crate) fn flush_all(&mut self) -> Vec<TimeoutEffect> {
        let mut effects = Vec::new();
        for (&(source_shard, block_height), expected) in &mut self.expected {
            if expected.requested {
                continue;
            }
            expected.requested = true;
            effects.push(TimeoutEffect {
                source_shard,
                block_height,
                proposer: expected.proposer,
            });
        }
        effects
    }
}

impl Default for ExpectedProvisionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::RETENTION_HORIZON;

    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    #[test]
    fn fresh_tracker_is_empty() {
        let t = ExpectedProvisionTracker::new();
        assert_eq!(t.len(), 0);
        assert_eq!(t.local_ts(), WeightedTimestamp::ZERO);
    }

    #[test]
    fn register_inserts_expectation() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn register_is_idempotent() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(7),
            ts(1_000),
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn on_provisions_verified_clears_entry() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );
        assert!(t.on_provisions_verified(ShardId::leaf(2, 1), BlockHeight::new(10)));
        assert!(!t.on_provisions_verified(ShardId::leaf(2, 1), BlockHeight::new(10)));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn first_commit_retro_stamps_pregenesis_entries() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );

        // Before any commit, an immediate timeout sweep at a non-zero `now`
        // would fire — the entry's discovered_at is still ZERO. The
        // record_block_committed retro-stamp closes that gap.
        t.record_block_committed(ts(1_000));

        // Now sweep at the same instant: no firings (we just registered).
        let effects = t.check_timeouts(ts(1_000));
        assert!(effects.is_empty());
    }

    #[test]
    fn timeout_emits_effect_after_threshold() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(ts(1_000));
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );

        // Just under threshold: no firings.
        let just_under = ts(1_000
            + u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX)
            - 1);
        assert!(t.check_timeouts(just_under).is_empty());

        // At threshold: one effect.
        let at =
            ts(1_000 + u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
        let effects = t.check_timeouts(at);
        assert_eq!(effects.len(), 1);
        assert_eq!(
            effects[0],
            TimeoutEffect {
                source_shard: ShardId::leaf(2, 1),
                block_height: BlockHeight::new(10),
                proposer: ValidatorId::new(3),
            }
        );

        // Subsequent sweep doesn't re-fire (already requested).
        assert!(t.check_timeouts(at).is_empty());
    }

    #[test]
    fn verified_before_timeout_never_emits() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(ts(1_000));
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );

        // Verify before the timeout fires.
        assert!(t.on_provisions_verified(ShardId::leaf(2, 1), BlockHeight::new(10)));

        let well_past =
            ts(1_000
                + 10 * u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
        assert!(t.check_timeouts(well_past).is_empty());
    }

    #[test]
    fn flush_all_bypasses_timeout() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(ts(1_000));
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );
        t.register(
            ShardId::leaf(2, 2),
            BlockHeight::new(5),
            ValidatorId::new(7),
            ts(1_000),
        );

        let effects = t.flush_all();
        assert_eq!(effects.len(), 2);

        // Subsequent flush_all is a no-op (all requested).
        assert!(t.flush_all().is_empty());
    }

    #[test]
    fn cleanup_orphans_drops_aged_entries() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(ts(1_000));
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );

        // Advance well past RETENTION_HORIZON.
        let far_future =
            ts(1_000 + 2 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.record_block_committed(far_future);

        let cutoff = far_future.minus(RETENTION_HORIZON);
        let dropped = t.cleanup_orphans(cutoff);
        assert_eq!(dropped, vec![(ShardId::leaf(2, 1), BlockHeight::new(10))]);
        assert_eq!(t.len(), 0);
    }

    /// A node whose committed clock lagged at registration (a split child
    /// catching up) stamps a stale `discovered_at`, but the source block is
    /// recent. The orphan sweep must key on `source_block_ts` and retain it,
    /// or the fallback fetch is evicted before it can fire and the dependent
    /// cross-shard wave aborts.
    #[test]
    fn cleanup_orphans_keeps_recent_source_despite_stale_discovery() {
        let mut t = ExpectedProvisionTracker::new();

        // Register while the local clock lags far behind the source block.
        t.record_block_committed(ts(1_000));
        let recent_source =
            ts(1_000 + 2 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            recent_source,
        );

        // Catch up: the cutoff now predates the stale `discovered_at` (1_000)
        // but not the recent source block.
        let now = ts(1_000 + 3 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.record_block_committed(now);
        let cutoff = now.minus(RETENTION_HORIZON);
        assert!(
            cutoff > ts(1_000),
            "cutoff must postdate the stale discovered_at"
        );
        assert!(
            recent_source >= cutoff,
            "source block must postdate the cutoff"
        );

        let dropped = t.cleanup_orphans(cutoff);
        assert!(dropped.is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cleanup_orphans_no_op_when_cutoff_zero() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(
            ShardId::leaf(2, 1),
            BlockHeight::new(10),
            ValidatorId::new(3),
            ts(1_000),
        );
        let dropped = t.cleanup_orphans(WeightedTimestamp::ZERO);
        assert!(dropped.is_empty());
        assert_eq!(t.len(), 1);
    }
}
