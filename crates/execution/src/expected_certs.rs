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
//!
//! ## Fulfilled-tombstone lifetime
//!
//! **Primary signal — state-based**: each fulfilled entry tracks the
//! `tx_hashes` from the EC's `tx_outcomes` that haven't yet been
//! observed in a finalized local wave. The set drains via
//! [`on_txs_terminated`](ExpectedCertTracker::on_txs_terminated) hooked
//! into `remove_finalized_wave`; when it empties, the EC is exhausted
//! and the tombstone evicts. The wave's participating shards always
//! include our shard (we wouldn't register otherwise), so every tx in
//! the EC reaches a finalized local wave in healthy operation —
//! footprint tracks in-flight work, not gossip windows.
//!
//! **Backstop — time-based**: each entry also carries a deadline
//! (`vote_anchor_ts + RETENTION_HORIZON`), pruned by
//! [`prune_fulfilled`](ExpectedCertTracker::prune_fulfilled). This
//! catches a specific late-arrival race: state-based drain runs at
//! `remove_finalized_wave`, after which the wave is gone. If a
//! duplicate header then arrives within the gossip window, `register`
//! re-creates an expectation, the fallback fetch returns the EC,
//! `mark_fulfilled` re-creates the tombstone — but no future
//! `remove_finalized_wave` will fire for those txs, so the
//! re-registered tombstone's pending-set never drains. The deadline
//! evicts it.
//!
//! Retention pruning by source shard (waves that still need an EC from a
//! given remote shard) is orchestrated by the coordinator via
//! [`retain_if_shard_needed`](ExpectedCertTracker::retain_if_shard_needed),
//! because the tracker cannot see the wave set.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    BlockHeight, ShardGroupId, TxHash, WAVE_TIMEOUT, WaveId, WeightedTimestamp,
};

/// How long to wait before the first fallback request. Anchored on the
/// committing QC's `weighted_timestamp_ms`, so the window stays meaningful
/// regardless of local block production rate. Sized comfortably below
/// `WAVE_TIMEOUT` so fallback fetches rescue missing ECs before the wave
/// aborts.
const EXEC_CERT_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between repeated fallback requests for the same cert.
const EXEC_CERT_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Grace window during which a freshly-registered expectation is retained
/// even when no local wave references its source shard yet. Remote
/// committed-block headers can arrive ahead of the local block that
/// creates the dependent wave; without this window, the registration is
/// silently pruned by `retain_if_shard_needed` and the EC never gets
/// fetched. Sized to comfortably exceed the worst-case lag between
/// receiving the remote header and committing the local block referencing
/// the same cross-shard tx.
const EXPECTED_RETENTION_GRACE: Duration = WAVE_TIMEOUT;

type ExpectedCertKey = (ShardGroupId, BlockHeight, WaveId);

/// Shared key handle: tracker tables hold an `Arc` so the per-tx reverse
/// index can register a key with a refcount bump rather than cloning the
/// `(ShardGroupId, BlockHeight, WaveId)` tuple (and the `WaveId`'s inner
/// `BTreeSet`) once per tx.
type SharedKey = Arc<ExpectedCertKey>;

/// Per-expectation bookkeeping.
#[derive(Debug, Clone)]
struct ExpectedEntry {
    /// Local weighted timestamp when we first learned about this cert.
    discovered_at: WeightedTimestamp,
    /// Local weighted timestamp when we last sent a fallback request.
    /// `None` means never requested.
    last_requested_at: Option<WeightedTimestamp>,
}

/// Per-fulfilled-entry bookkeeping.
#[derive(Debug, Clone)]
struct FulfilledEntry {
    /// Tx hashes from the EC's `tx_outcomes` not yet observed in a
    /// finalized local wave. Empty → entry is exhausted and evicts.
    pending_txs: HashSet<TxHash>,
    /// `vote_anchor_ts + RETENTION_HORIZON`. Backstop for the
    /// late-re-registration race documented in the module-level
    /// fulfilled-tombstone lifetime section.
    deadline: WeightedTimestamp,
}

pub struct ExpectedCertTracker {
    expected: HashMap<SharedKey, ExpectedEntry>,
    fulfilled: HashMap<SharedKey, FulfilledEntry>,
    /// Reverse index `tx_hash → fulfilled keys still awaiting that tx`.
    /// Lets [`on_txs_terminated`](ExpectedCertTracker::on_txs_terminated)
    /// be `O(matched)` rather than `O(num_fulfilled)` per finalized wave.
    by_tx: HashMap<TxHash, HashSet<SharedKey>>,
}

impl ExpectedCertTracker {
    pub fn new() -> Self {
        Self {
            expected: HashMap::new(),
            fulfilled: HashMap::new(),
            by_tx: HashMap::new(),
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
        let key: ExpectedCertKey = (source_shard, block_height, wave_id);
        if self.fulfilled.contains_key(&key) {
            return;
        }
        self.expected.entry(Arc::new(key)).or_insert(ExpectedEntry {
            discovered_at: now_ts,
            last_requested_at: None,
        });
    }

    /// Record that the expected EC arrived. `tx_hashes` is the EC's
    /// `tx_outcomes`'s `tx_hash` set — drained by
    /// [`on_txs_terminated`](Self::on_txs_terminated) as each tx
    /// reaches terminal state in a finalized local wave. `deadline` is
    /// the EC's own `vote_anchor_ts + RETENTION_HORIZON`, used as a
    /// backstop by [`prune_fulfilled`](Self::prune_fulfilled).
    /// Returns `true` if an active expectation was cleared.
    pub fn mark_fulfilled(
        &mut self,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        wave_id: &WaveId,
        tx_hashes: impl IntoIterator<Item = TxHash>,
        deadline: WeightedTimestamp,
    ) -> bool {
        let key: SharedKey = Arc::new((source_shard, block_height, wave_id.clone()));
        let cleared = self.expected.remove(&key).is_some();
        let pending_txs: HashSet<TxHash> = tx_hashes.into_iter().collect();
        for tx in &pending_txs {
            self.by_tx.entry(*tx).or_default().insert(Arc::clone(&key));
        }
        self.fulfilled.insert(
            key,
            FulfilledEntry {
                pending_txs,
                deadline,
            },
        );
        cleared
    }

    /// Drain pending-tx sets for `tx_hashes` that just reached terminal
    /// state (a finalized local wave landed in a committed block). Drops
    /// any fulfilled entry whose pending set becomes empty — the EC is
    /// exhausted and no longer needs a tombstone.
    pub fn on_txs_terminated(&mut self, tx_hashes: impl IntoIterator<Item = TxHash>) {
        for tx in tx_hashes {
            let Some(keys) = self.by_tx.remove(&tx) else {
                continue;
            };
            for key in keys {
                let drop_entry = self.fulfilled.get_mut(&key).is_some_and(|entry| {
                    entry.pending_txs.remove(&tx);
                    entry.pending_txs.is_empty()
                });
                if drop_entry {
                    self.fulfilled.remove(&key);
                }
            }
        }
    }

    /// Backstop sweep: drop fulfilled tombstones whose deadline has
    /// elapsed. Catches the late-re-registration race — see the
    /// module-level fulfilled-tombstone lifetime section. Cleans
    /// `by_tx` reverse-index entries for any txs that were still
    /// pending on the evicted tombstones.
    pub fn prune_fulfilled(&mut self, now_ts: WeightedTimestamp) {
        let by_tx = &mut self.by_tx;
        self.fulfilled.retain(|key, entry| {
            if entry.deadline > now_ts {
                return true;
            }
            for tx in &entry.pending_txs {
                if let Some(keys) = by_tx.get_mut(tx) {
                    keys.remove(key);
                    if keys.is_empty() {
                        by_tx.remove(tx);
                    }
                }
            }
            false
        });
    }

    /// Drive the timeout state machine. Returns `(wave_id, is_retry)` for
    /// each expectation that has crossed either the initial or the retry
    /// deadline at `now_ts`. Records `last_requested_at = now_ts` on each
    /// returned entry so the retry cooldown starts ticking. Source shard
    /// and block height are derivable from `wave_id` if the caller needs
    /// them.
    pub fn check_timeouts(&mut self, now_ts: WeightedTimestamp) -> Vec<(WaveId, bool)> {
        let mut fetches = Vec::new();
        for (key, entry) in &mut self.expected {
            let should_request = match entry.last_requested_at {
                None => now_ts.elapsed_since(entry.discovered_at) >= EXEC_CERT_FALLBACK_TIMEOUT,
                Some(last) => now_ts.elapsed_since(last) >= EXEC_CERT_RETRY_INTERVAL,
            };
            if should_request {
                let is_retry = entry.last_requested_at.is_some();
                entry.last_requested_at = Some(now_ts);
                fetches.push((key.2.clone(), is_retry));
            }
        }
        fetches
    }

    /// Drop expectations whose source shard is no longer referenced by any
    /// outstanding local wave. The coordinator computes the set from
    /// `WaveRegistry` and passes it in — the tracker has no view of waves.
    pub fn retain_if_shard_needed(
        &mut self,
        shards_needed: &HashSet<ShardGroupId>,
        now_ts: WeightedTimestamp,
    ) {
        // Retain expectations whose source shard is still referenced by a
        // local wave OR whose registration is recent enough that the
        // matching local wave may not have been committed yet. Without the
        // grace window, a remote header arriving slightly ahead of the
        // local block that creates the dependent wave is silently pruned
        // and the EC never gets fetched.
        self.expected.retain(|key, entry| {
            shards_needed.contains(&key.0)
                || now_ts.elapsed_since(entry.discovered_at) < EXPECTED_RETENTION_GRACE
        });
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
}

#[cfg(test)]
impl ExpectedCertTracker {
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
    use hyperscale_types::Hash;
    use proptest::collection::vec as prop_vec;

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

    fn tx(seed: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[seed; 32]))
    }

    #[test]
    fn register_skipped_when_already_fulfilled() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(tx(1)),
            ms(500),
        );
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(1000));

        assert!(!t.is_expected(ShardGroupId(1), BlockHeight(5), &w));
        assert_eq!(t.expected_len(), 0);
    }

    #[test]
    fn mark_fulfilled_returns_true_when_clearing_active_expectation() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(0));

        let cleared = t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(tx(1)),
            ms(1000),
        );
        assert!(cleared);
        assert_eq!(t.expected_len(), 0);
        assert_eq!(t.fulfilled_len(), 1);
    }

    #[test]
    fn mark_fulfilled_returns_false_when_no_expectation_was_active() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        let cleared = t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(tx(1)),
            ms(1000),
        );
        assert!(!cleared);
        assert_eq!(t.fulfilled_len(), 1);
    }

    #[test]
    fn on_txs_terminated_drops_entry_when_pending_set_drains() {
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        let tx_a = tx(1);
        let tx_b = tx(2);
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            [tx_a, tx_b],
            ms(60_000),
        );
        assert_eq!(t.fulfilled_len(), 1);

        // Partial drain: entry survives.
        t.on_txs_terminated(std::iter::once(tx_a));
        assert_eq!(t.fulfilled_len(), 1);

        // Final drain: entry evicts.
        t.on_txs_terminated(std::iter::once(tx_b));
        assert_eq!(t.fulfilled_len(), 0);
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
        // Advance past the grace window so the unneeded entry is actually pruned.
        let now = ms(u64::try_from(EXPECTED_RETENTION_GRACE.as_millis()).unwrap() + 1);
        t.retain_if_shard_needed(&needed, now);

        assert!(t.is_expected(ShardGroupId(1), BlockHeight(5), &w1));
        assert!(!t.is_expected(ShardGroupId(2), BlockHeight(6), &w2));
    }

    #[test]
    fn retain_if_shard_needed_keeps_recent_unneeded_expectation() {
        // A remote header can register an expectation before the local block
        // creating the dependent wave commits — the grace window protects
        // that race.
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(0));

        // Within grace window, no local wave references shard 1 yet —
        // expectation must still be retained.
        let needed: HashSet<ShardGroupId> = HashSet::new();
        t.retain_if_shard_needed(&needed, ms(1_000));

        assert!(t.is_expected(ShardGroupId(1), BlockHeight(5), &w));
    }

    #[test]
    fn prune_fulfilled_drops_entries_past_their_deadline() {
        let mut t = ExpectedCertTracker::new();
        let w_old = wave(5);
        let w_fresh = wave(6);
        // Per-entry deadlines. Old entry's deadline has passed by now_ts;
        // fresh entry's deadline is in the future.
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w_old,
            std::iter::once(tx(1)),
            ms(60_000),
        );
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(6),
            &w_fresh,
            std::iter::once(tx(2)),
            ms(70_000),
        );

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

    #[test]
    fn on_txs_terminated_cleans_reverse_index_when_entry_evicts() {
        let mut t = ExpectedCertTracker::new();
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &wave(5),
            std::iter::once(tx(1)),
            ms(60_000),
        );
        assert_eq!(t.by_tx.len(), 1);

        t.on_txs_terminated(std::iter::once(tx(1)));

        assert_eq!(t.fulfilled_len(), 0);
        assert!(t.by_tx.is_empty());
    }

    #[test]
    fn on_txs_terminated_drains_one_of_many_entries_sharing_a_tx() {
        // Two fulfilled entries reference the same tx via `by_tx`.
        // Terminating the shared tx must update both entries' pending sets
        // and only evict the one whose set actually drains.
        let mut t = ExpectedCertTracker::new();
        let shared = tx(1);
        let only_in_first = tx(2);
        let w1 = wave(5);
        let w2 = wave(6);
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w1,
            [shared, only_in_first],
            ms(60_000),
        );
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(6),
            &w2,
            std::iter::once(shared),
            ms(60_000),
        );

        t.on_txs_terminated(std::iter::once(shared));

        assert_eq!(t.fulfilled_len(), 1, "first entry survives");
        assert!(!t.by_tx.contains_key(&shared));
        assert!(t.by_tx.contains_key(&only_in_first));
    }

    #[test]
    fn prune_fulfilled_cleans_reverse_index_for_evicted_entries() {
        let mut t = ExpectedCertTracker::new();
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &wave(5),
            [tx(1), tx(2)],
            ms(1_000),
        );
        assert_eq!(t.by_tx.len(), 2);

        t.prune_fulfilled(ms(2_000));

        assert_eq!(t.fulfilled_len(), 0);
        assert!(t.by_tx.is_empty());
    }

    #[test]
    fn prune_fulfilled_evicts_at_exactly_the_deadline() {
        // Deadline check is `deadline > now_ts` — strictly greater. At
        // equality the entry is dropped.
        let mut t = ExpectedCertTracker::new();
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &wave(5),
            std::iter::once(tx(1)),
            ms(1_000),
        );
        t.prune_fulfilled(ms(1_000));
        assert_eq!(t.fulfilled_len(), 0);
    }

    #[test]
    fn check_timeouts_fires_at_exactly_the_fallback_deadline() {
        let mut t = ExpectedCertTracker::new();
        t.register(ShardGroupId(1), BlockHeight(5), wave(5), ms(0));
        let fetches = t.check_timeouts(ms(5_000));
        assert_eq!(fetches.len(), 1);
        assert!(!fetches[0].1);
    }

    #[test]
    fn check_timeouts_can_mix_initial_and_retry_emissions_in_one_call() {
        let mut t = ExpectedCertTracker::new();
        let w_old = wave(5);
        let w_new = wave(6);
        // Old entry crosses initial deadline at 5_000 then is due for retry
        // at 15_000 (cooldown = 10s). New entry registered at 10_000 crosses
        // its initial deadline at 15_000.
        t.register(ShardGroupId(1), BlockHeight(5), w_old.clone(), ms(0));
        let _ = t.check_timeouts(ms(5_000));
        t.register(ShardGroupId(1), BlockHeight(6), w_new.clone(), ms(10_000));

        let fetches = t.check_timeouts(ms(15_000));
        assert_eq!(fetches.len(), 2);
        let old_is_retry = fetches.iter().find(|(w, _)| *w == w_old).map(|(_, r)| *r);
        let new_is_retry = fetches.iter().find(|(w, _)| *w == w_new).map(|(_, r)| *r);
        assert_eq!(old_is_retry, Some(true));
        assert_eq!(new_is_retry, Some(false));
    }

    #[test]
    fn retain_if_shard_needed_prunes_at_exactly_grace_boundary() {
        // `elapsed_since < EXPECTED_RETENTION_GRACE` — at equality the entry
        // is pruned.
        let mut t = ExpectedCertTracker::new();
        t.register(ShardGroupId(1), BlockHeight(5), wave(5), ms(0));
        let boundary = ms(u64::try_from(EXPECTED_RETENTION_GRACE.as_millis()).unwrap());
        t.retain_if_shard_needed(&HashSet::new(), boundary);
        assert_eq!(t.expected_len(), 0);
    }

    #[test]
    fn mark_fulfilled_overwrites_pending_set_when_called_twice_for_same_key() {
        // Re-fulfillment can occur after the deadline backstop evicts a
        // tombstone and a duplicate EC arrives — the newer call must
        // replace the pending set wholesale rather than merge with stale
        // hashes from the prior fulfillment, otherwise drains will not
        // empty the new set.
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        let original_tx = tx(1);
        let new_tx = tx(2);

        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(original_tx),
            ms(1_000),
        );
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(new_tx),
            ms(70_000),
        );

        // Terminating only the new tx must drain the surviving entry; the
        // original tx is no longer part of the pending set.
        t.on_txs_terminated(std::iter::once(new_tx));
        assert_eq!(t.fulfilled_len(), 0);
    }

    #[test]
    fn mark_fulfilled_with_empty_tx_set_persists_until_deadline() {
        // ECs with empty tx_outcomes leave a tombstone that only the
        // deadline backstop can evict — there's nothing to drain.
        let mut t = ExpectedCertTracker::new();
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &wave(5),
            std::iter::empty(),
            ms(60_000),
        );
        assert_eq!(t.fulfilled_len(), 1);

        t.on_txs_terminated(std::iter::once(tx(1)));
        assert_eq!(t.fulfilled_len(), 1);

        t.prune_fulfilled(ms(60_000));
        assert_eq!(t.fulfilled_len(), 0);
    }

    #[test]
    fn register_succeeds_after_fulfilled_tombstone_drains() {
        // Once on_txs_terminated empties a tombstone, a duplicate header
        // arriving later is allowed to re-register the expectation. The
        // deadline backstop on `prune_fulfilled` exists precisely because
        // this re-registration path can recreate a tombstone whose pending
        // set never drains again.
        let mut t = ExpectedCertTracker::new();
        let w = wave(5);
        t.mark_fulfilled(
            ShardGroupId(1),
            BlockHeight(5),
            &w,
            std::iter::once(tx(1)),
            ms(60_000),
        );
        t.on_txs_terminated(std::iter::once(tx(1)));

        t.register(ShardGroupId(1), BlockHeight(5), w.clone(), ms(70_000));

        assert!(t.is_expected(ShardGroupId(1), BlockHeight(5), &w));
    }

    // ─── Property test ──────────────────────────────────────────────────

    use proptest::prelude::*;

    // For any sequence of register/fulfill events, a key that ends up in
    // the fulfilled set never produces a fallback fetch for itself on any
    // check_timeouts call after fulfillment.
    proptest! {
        #[test]
        fn fulfilled_before_deadline_never_triggers_fallback(
            heights in prop_vec(0u64..20, 1..10),
            fulfill_indices in prop_vec(0u64..100, 0..10),
            timeouts in prop_vec(0u64..100_000, 1..10),
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
                t.mark_fulfilled(
                    shard,
                    w.block_height,
                    w,
                    std::iter::once(tx(1)),
                    ms(60_000),
                );
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
