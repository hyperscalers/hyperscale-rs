//! Timeout-driven fallback detection for expected execution certificates.
//!
//! A remote shard's committed block header carries one or more `WaveId`s
//! that target our shard. For each such wave we expect to receive an
//! aggregated execution certificate within a bounded window. If the cert
//! doesn't land in time, we fall back to explicitly fetching it from the
//! source shard's committee.
//!
//! ## Key type
//!
//! Expectations and fulfilments are both keyed by
//! `(source_shard, block_height, wave_id)` — the remote-shard identity of the
//! wave, not any local decomposition.
//!
//! ## Deadlines
//!
//! All deadlines anchor on the committing QC's `weighted_timestamp` (passed
//! in as `now_ts`), so the window is independent of local block production
//! rate and is identical across validators.
//!
//! - `EXEC_CERT_FALLBACK_TIMEOUT`: age at which the first fallback fetch fires.
//! - `EXEC_CERT_RETRY_INTERVAL`: cooldown between repeated fetches once the
//!   first has fired.
//! - `FULFILLED_EXEC_CERT_RETENTION`: how long a fulfilled-entry tombstone
//!   survives, guarding against late-arriving duplicate headers.
//!
//! Retention pruning by source shard (waves that still need an EC from a
//! given remote shard) is orchestrated by the coordinator via
//! [`retain_if_shard_needed`](ExpectedCertTracker::retain_if_shard_needed),
//! because the tracker cannot see the wave set.

use hyperscale_types::{BlockHeight, ShardGroupId, WAVE_TIMEOUT, WaveId, WeightedTimestamp};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// How long to wait before the first fallback request. Anchored on the
/// committing QC's `weighted_timestamp_ms`, so the window stays meaningful
/// regardless of local block production rate. Sized comfortably below
/// `WAVE_TIMEOUT` so fallback fetches rescue missing ECs before the wave
/// aborts.
const EXEC_CERT_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between repeated fallback requests for the same cert.
const EXEC_CERT_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// How long to retain fulfilled entries after the EC landed. Guards against
/// late-arriving duplicate headers re-registering the expectation. Matches
/// `EarlyArrivalBuffer`'s `EC_BUFFER_RETENTION = WAVE_TIMEOUT * 2` so any
/// duplicate still in flight from that path finds its tombstone here.
const FULFILLED_EXEC_CERT_RETENTION: Duration = Duration::from_secs(WAVE_TIMEOUT.as_secs() * 2);

type ExpectedCertKey = (ShardGroupId, BlockHeight, WaveId);

/// Per-expectation bookkeeping.
#[derive(Debug, Clone)]
struct ExpectedEntry {
    /// Local weighted timestamp when we first learned about this cert.
    discovered_at: WeightedTimestamp,
    /// Local weighted timestamp when we last sent a fallback request.
    /// `None` means never requested.
    last_requested_at: Option<WeightedTimestamp>,
}

pub struct ExpectedCertTracker {
    expected: HashMap<ExpectedCertKey, ExpectedEntry>,
    fulfilled: HashMap<ExpectedCertKey, WeightedTimestamp>,
}

impl ExpectedCertTracker {
    pub fn new() -> Self {
        Self {
            expected: HashMap::new(),
            fulfilled: HashMap::new(),
        }
    }

    /// Register an expected EC for `(source_shard, block_height, wave_id)`.
    ///
    /// Idempotent: re-registering an active expectation does not reset the
    /// discovery timestamp. Skipped entirely when the key has already been
    /// marked fulfilled — guards against late-arriving duplicate headers
    /// re-opening a closed expectation.
    pub fn register(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        wave_id: WaveId,
        now_ts: WeightedTimestamp,
    ) {
        let key = (source_shard, block_height, wave_id);
        if self.fulfilled.contains_key(&key) {
            return;
        }
        self.expected.entry(key).or_insert(ExpectedEntry {
            discovered_at: now_ts,
            last_requested_at: None,
        });
    }

    /// Record that the expected EC arrived. Returns `true` if an active
    /// expectation was cleared — the per-id `Continuation(ExecutionCertificateAdmitted)`
    /// drains the matching `exec_cert_fetch` entry so the retry loop stops.
    pub fn mark_fulfilled(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        wave_id: &WaveId,
        now_ts: WeightedTimestamp,
    ) -> bool {
        let key = (source_shard, block_height, wave_id.clone());
        let cleared = self.expected.remove(&key).is_some();
        self.fulfilled.insert(key, now_ts);
        cleared
    }

    /// Drive the timeout state machine. Returns `(wave_id, is_retry)` for
    /// each expectation that has crossed either the initial or the retry
    /// deadline at `now_ts`. Records `last_requested_at = now_ts` on each
    /// returned entry so the retry cooldown starts ticking. Source shard
    /// and block height are derivable from `wave_id` if the caller needs
    /// them.
    pub fn check_timeouts(&mut self, now_ts: WeightedTimestamp) -> Vec<(WaveId, bool)> {
        let mut fetches = Vec::new();
        for ((_, _, wave_id), entry) in &mut self.expected {
            let should_request = match entry.last_requested_at {
                None => now_ts.elapsed_since(entry.discovered_at) >= EXEC_CERT_FALLBACK_TIMEOUT,
                Some(last) => now_ts.elapsed_since(last) >= EXEC_CERT_RETRY_INTERVAL,
            };
            if should_request {
                let is_retry = entry.last_requested_at.is_some();
                entry.last_requested_at = Some(now_ts);
                fetches.push((wave_id.clone(), is_retry));
            }
        }
        fetches
    }

    /// Drop expectations whose source shard is no longer referenced by any
    /// outstanding local wave. The coordinator computes the set from
    /// `WaveRegistry` and passes it in — the tracker has no view of waves.
    pub fn retain_if_shard_needed(&mut self, shards_needed: &HashSet<ShardGroupId>) {
        self.expected
            .retain(|(source_shard, _, _), _| shards_needed.contains(source_shard));
    }

    /// Drop fulfilled tombstones older than the retention window. Pruning
    /// is by fulfillment timestamp, not block height — remote shards'
    /// heights can diverge significantly.
    pub fn prune_fulfilled(&mut self, now_ts: WeightedTimestamp) {
        let cutoff = now_ts.minus(FULFILLED_EXEC_CERT_RETENTION);
        self.fulfilled
            .retain(|_, &mut fulfilled_at| fulfilled_at > cutoff);
    }

    /// Retro-stamp `discovered_at == ZERO` entries with `now_ts`.
    /// Remote headers can register expectations before our first local
    /// commit; without this, every such entry would report a ~57-year age
    /// on the next commit and trigger a fallback fetch storm.
    pub fn retro_stamp_zero_timestamps(&mut self, now_ts: WeightedTimestamp) {
        for entry in self.expected.values_mut() {
            if entry.discovered_at == WeightedTimestamp::ZERO {
                entry.discovered_at = now_ts;
            }
        }
    }

    pub fn expected_len(&self) -> usize {
        self.expected.len()
    }

    pub fn fulfilled_len(&self) -> usize {
        self.fulfilled.len()
    }

    #[cfg(test)]
    fn is_expected(
        &self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        wave_id: &WaveId,
    ) -> bool {
        self.expected
            .contains_key(&(source_shard, block_height, wave_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wave(height: u64) -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(1),
            block_height: BlockHeight(height),
            remote_shards: std::iter::once(ShardGroupId(0)).collect(),
        }
    }

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp(value)
    }

    #[test]
    fn register_inserts_expectation_with_discovery_timestamp() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(1000));

        assert!(t.is_expected(ShardGroupId(1), BlockHeight(5), &w));
        assert_eq!(t.expected_len(), 1);
    }

    #[test]
    fn register_is_idempotent_and_does_not_reset_discovery() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(1000));
        // Second register at a later timestamp; discovery timestamp must
        // stick to the earlier value, otherwise the fallback deadline gets
        // perpetually pushed out.
        t.register(ShardGroupId(1), BlockHeight(5), w, ms(9999));
        let fetches = t.check_timeouts(ms(1000 + 5_000));
        assert_eq!(fetches.len(), 1, "deadline anchors on first register");
    }

    #[test]
    fn register_skipped_when_already_fulfilled() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.mark_fulfilled(ShardGroupId(1), BlockHeight(5), &w, ms(500));
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(1000));

        assert!(!t.is_expected(ShardGroupId(1), BlockHeight(5), &w));
        assert_eq!(t.expected_len(), 0);
    }

    #[test]
    fn mark_fulfilled_returns_true_when_clearing_active_expectation() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(0));

        let cleared = t.mark_fulfilled(ShardGroupId(1), BlockHeight(5), &w, ms(1000));
        assert!(cleared);
        assert_eq!(t.expected_len(), 0);
        assert_eq!(t.fulfilled_len(), 1);
    }

    #[test]
    fn mark_fulfilled_returns_false_when_no_expectation_was_active() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        let cleared = t.mark_fulfilled(ShardGroupId(1), BlockHeight(5), &w, ms(1000));
        assert!(!cleared);
        assert_eq!(t.fulfilled_len(), 1);
    }

    #[test]
    fn check_timeouts_fires_after_initial_window_and_records_request_ts() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w, ms(1_000));

        // Just before the deadline: no fetch.
        let fetches = t.check_timeouts(ms(1_000 + 4_999));
        assert!(fetches.is_empty());

        // Crossing the deadline: exactly one fetch, not a retry.
        let fetches = t.check_timeouts(ms(1_000 + 5_000));
        assert_eq!(fetches.len(), 1);
        assert!(!fetches[0].1);
    }

    #[test]
    fn check_timeouts_respects_retry_interval_after_first_request() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w, ms(0));

        // First fetch fires.
        let _ = t.check_timeouts(ms(5_000));

        // Before retry interval elapses: nothing.
        assert!(t.check_timeouts(ms(5_000 + 9_999)).is_empty());

        // After retry interval: is_retry = true.
        let fetches = t.check_timeouts(ms(5_000 + 10_000));
        assert_eq!(fetches.len(), 1);
        assert!(fetches[0].1);
    }

    #[test]
    fn retain_if_shard_needed_drops_expectations_whose_shard_is_no_longer_tracked() {
        let mut t = ExpectedCertTracker::new();
        let w1 = wave(5);
        let w2 = wave(6);
        t.register(ShardGroupId(1), BlockHeight(5), w1.clone(), ms(0));
        t.register(ShardGroupId(2), BlockHeight(6), w2.clone(), ms(0));

        let needed: HashSet<ShardGroupId> = std::iter::once(ShardGroupId(1)).collect();
        t.retain_if_shard_needed(&needed);

        assert!(t.is_expected(ShardGroupId(1), BlockHeight(5), &w1));
        assert!(!t.is_expected(ShardGroupId(2), BlockHeight(6), &w2));
    }

    #[test]
    fn prune_fulfilled_drops_only_entries_older_than_retention() {
        let mut t = ExpectedCertTracker::new();
        let w_old = wave(5);
        let w_fresh = wave(6);
        // Retention = 60s. Fulfill the old entry at a timestamp that will
        // be cut off once we advance now_ts past 60s.
        t.mark_fulfilled(ShardGroupId(1), BlockHeight(5), &w_old, ms(1_000));
        t.mark_fulfilled(ShardGroupId(1), BlockHeight(6), &w_fresh, ms(50_000));

        // Prune at now_ts = 65_000 → cutoff = 5_000.
        t.prune_fulfilled(ms(65_000));

        assert_eq!(t.fulfilled_len(), 1, "fresh entry survives");
    }

    #[test]
    fn retro_stamp_updates_zero_entries_and_leaves_others_intact() {
        let mut t = ExpectedCertTracker::new();
        let w_zero = wave(5);
        let w_stamped = wave(6);
        // Pre-first-commit entry has discovery timestamp ZERO. A
        // freshly-registered entry at a post-stamp timestamp simulates the
        // ordinary case the retro-stamp must leave alone.
        t.register(ShardGroupId(1), BlockHeight(5), w_zero.clone(), ms(0));
        t.register(
            ShardGroupId(1),
            BlockHeight(6),
            w_stamped.clone(),
            ms(9_000),
        );

        t.retro_stamp_zero_timestamps(ms(10_000));

        // Just short of the 5_000 ms fallback window from the retro-stamp
        // point: neither entry fires. Had the zero-stamped entry NOT been
        // touched, its deadline would have elapsed many seconds ago and a
        // fallback fetch would have already fired.
        assert!(t.check_timeouts(ms(14_000 - 1)).is_empty());

        // Cross the stamped entry's deadline first (registered at 9_000,
        // deadline at 14_000) while the retro-stamped entry is still fresh
        // (its new anchor is 10_000, deadline 15_000).
        let fetches = t.check_timeouts(ms(14_000));
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].0, w_stamped);

        // And finally cross the retro-stamped entry's deadline.
        let fetches = t.check_timeouts(ms(15_000));
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].0, w_zero);
    }

    // ─── Property test ──────────────────────────────────────────────────

    use proptest::prelude::*;

    // For any sequence of register/fulfill events, a key that ends up in
    // the fulfilled set never produces a fallback fetch for itself on any
    // check_timeouts call after fulfillment.
    proptest! {
        #[test]
        fn fulfilled_before_deadline_never_triggers_fallback(
            heights in proptest::collection::vec(0u64..20, 1..10),
            fulfill_indices in proptest::collection::vec(0u64..100, 0..10),
            timeouts in proptest::collection::vec(0u64..100_000, 1..10),
        ) {
            let mut t = ExpectedCertTracker::new();
            let shard = ShardGroupId(1);

            // Register expectations at t=0 so deadlines are all crossed
            // well before the latest poll time.
            let waves: Vec<WaveId> = heights.iter().map(|h| wave(*h)).collect();
            for w in &waves {
                t.register(shard, w.block_height, w.clone(), ms(0));
            }

            // Fulfill a subset BEFORE any deadline could fire. Using ms(1)
            // keeps us well inside the 5_000 ms window.
            for idx in &fulfill_indices {
                let w = &waves[usize::try_from(*idx).unwrap_or(usize::MAX) % waves.len()];
                t.mark_fulfilled(shard, w.block_height, w, ms(1));
            }

            // Run check_timeouts at a range of later timestamps.
            for now_ms in &timeouts {
                let now = ms(*now_ms);
                let fetches = t.check_timeouts(now);
                // Any fetch emitted must correspond to a still-expected key.
                for (wave_id, _) in &fetches {
                    let key = (wave_id.shard_group_id, wave_id.block_height, wave_id.clone());
                    prop_assert!(
                        !t.fulfilled.contains_key(&key),
                        "fallback fetch emitted for a fulfilled key: {:?}",
                        key
                    );
                }
            }
        }
    }
}
