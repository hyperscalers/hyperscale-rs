//! Expected-provisions tracker + fallback-fetch typed effects.
//!
//! Anchors all liveness-driven decisions on the BFT-authenticated
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
//! The tracker also owns `local_committed_height` and `local_committed_ts`
//! because every other consumer of those values reads them through here
//! (deadline sweeps, receipt-time stamping, etc.) — keeping them
//! co-located with the timestamp-driven sweeps that update them.

use hyperscale_types::{BlockHeight, ShardGroupId, ValidatorId, WeightedTimestamp};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::warn;

/// How long to wait before falling back to peer-fetch for missing
/// provisions. Proposers include provisions inline in `Block::Live` during
/// assembly, so this timeout only triggers when gossip dropped them — in
/// which case we fetch from a shard peer. Measured against the BFT-
/// authenticated `weighted_timestamp_ms` of locally committed blocks.
const PROVISION_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

type Key = (ShardGroupId, BlockHeight);

/// Per-entry liveness state for a registered expected provisions value.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    /// Local weighted timestamp when we first expected these provisions.
    /// Used as the liveness baseline for both fallback-fetch and orphan
    /// eviction.
    discovered_at: WeightedTimestamp,
    requested: bool,
    proposer: ValidatorId,
}

/// Lifted by the coordinator into an `Action::Fetch(FetchRequest::RemoteProvisions)` once
/// peers are attached from the topology snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEffect {
    pub source_shard: ShardGroupId,
    pub block_height: BlockHeight,
    pub proposer: ValidatorId,
}

/// Liveness tracker for cross-shard provisions we expect but haven't yet
/// verified.
pub struct ExpectedProvisionTracker {
    expected: BTreeMap<Key, ExpectedProvision>,
    local_committed_height: BlockHeight,
    local_committed_ts: WeightedTimestamp,
}

impl ExpectedProvisionTracker {
    pub(crate) const fn new() -> Self {
        Self {
            expected: BTreeMap::new(),
            local_committed_height: BlockHeight(0),
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

    /// Whether an expectation is currently registered for
    /// `(source_shard, block_height)`.
    pub(crate) fn contains(&self, source_shard: ShardGroupId, block_height: BlockHeight) -> bool {
        self.expected.contains_key(&(source_shard, block_height))
    }

    /// Register an expectation for provisions at `(source_shard, block_height)`.
    /// No-op if an expectation is already registered for the same key.
    pub(crate) fn register(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        proposer: ValidatorId,
    ) {
        self.expected
            .entry((source_shard, block_height))
            .or_insert(ExpectedProvision {
                discovered_at: self.local_committed_ts,
                requested: false,
                proposer,
            });
    }

    /// Clear an expectation once provisions verify successfully. Returns
    /// `true` if an entry was removed — the coordinator uses that to drop
    /// the matching header and emit a `CancelProvisionsFetch`.
    pub(crate) fn on_provisions_verified(
        &mut self,
        source_shard: ShardGroupId,
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
    pub(crate) fn record_block_committed(&mut self, height: BlockHeight, ts: WeightedTimestamp) {
        let first_commit = self.local_committed_ts == WeightedTimestamp::ZERO;
        self.local_committed_height = height;
        self.local_committed_ts = ts;

        if first_commit {
            for expected in self.expected.values_mut() {
                if expected.discovered_at == WeightedTimestamp::ZERO {
                    expected.discovered_at = ts;
                }
            }
        }
    }

    /// Drop expectations whose `discovered_at` predates `cutoff` — the
    /// fallback fetch never resolved within `RETENTION_HORIZON`. Returns
    /// the keys evicted so the coordinator can clean matching headers.
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
            if exp.discovered_at >= cutoff {
                true
            } else {
                dropped.push(*key);
                false
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
                source_shard = source_shard.0,
                block_height = block_height.0,
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
    use super::*;
    use hyperscale_types::RETENTION_HORIZON;

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
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn register_is_idempotent() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(7));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn on_provisions_verified_clears_entry() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));
        assert!(t.on_provisions_verified(ShardGroupId(1), BlockHeight(10)));
        assert!(!t.on_provisions_verified(ShardGroupId(1), BlockHeight(10)));
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn first_commit_retro_stamps_pregenesis_entries() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));

        // Before any commit, an immediate timeout sweep at a non-zero `now`
        // would fire — the entry's discovered_at is still ZERO. The
        // record_block_committed retro-stamp closes that gap.
        t.record_block_committed(BlockHeight(1), ts(1_000));

        // Now sweep at the same instant: no firings (we just registered).
        let effects = t.check_timeouts(ts(1_000));
        assert!(effects.is_empty());
    }

    #[test]
    fn timeout_emits_effect_after_threshold() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(BlockHeight(1), ts(1_000));
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));

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
                source_shard: ShardGroupId(1),
                block_height: BlockHeight(10),
                proposer: ValidatorId(3),
            }
        );

        // Subsequent sweep doesn't re-fire (already requested).
        assert!(t.check_timeouts(at).is_empty());
    }

    #[test]
    fn verified_before_timeout_never_emits() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(BlockHeight(1), ts(1_000));
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));

        // Verify before the timeout fires.
        assert!(t.on_provisions_verified(ShardGroupId(1), BlockHeight(10)));

        let well_past =
            ts(1_000
                + 10 * u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
        assert!(t.check_timeouts(well_past).is_empty());
    }

    #[test]
    fn flush_all_bypasses_timeout() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(BlockHeight(1), ts(1_000));
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));
        t.register(ShardGroupId(2), BlockHeight(5), ValidatorId(7));

        let effects = t.flush_all();
        assert_eq!(effects.len(), 2);

        // Subsequent flush_all is a no-op (all requested).
        assert!(t.flush_all().is_empty());
    }

    #[test]
    fn cleanup_orphans_drops_aged_entries() {
        let mut t = ExpectedProvisionTracker::new();
        t.record_block_committed(BlockHeight(1), ts(1_000));
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));

        // Advance well past RETENTION_HORIZON.
        let far_future =
            ts(1_000 + 2 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.record_block_committed(BlockHeight(100), far_future);

        let cutoff = far_future.minus(RETENTION_HORIZON);
        let dropped = t.cleanup_orphans(cutoff);
        assert_eq!(dropped, vec![(ShardGroupId(1), BlockHeight(10))]);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn cleanup_orphans_no_op_when_cutoff_zero() {
        let mut t = ExpectedProvisionTracker::new();
        t.register(ShardGroupId(1), BlockHeight(10), ValidatorId(3));
        let dropped = t.cleanup_orphans(WeightedTimestamp::ZERO);
        assert!(dropped.is_empty());
        assert_eq!(t.len(), 1);
    }
}
