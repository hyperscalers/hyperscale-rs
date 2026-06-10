//! Process-scope cache of shard-invariant execution outputs.
//!
//! [`ProcessExecutionCache`] memoises the result of
//! [`compute_vm_output`](crate::compute_vm_output) keyed by [`TxHash`].
//! A single `IoLoop` owns one cache; every hosted vnode's action
//! dispatch consults it. Repeated executions of the same transaction
//! — across same-shard vnodes co-hosted in one process and across
//! hosted participating shards for cross-shard transactions — produce
//! a cache hit and skip the Radix VM call entirely.
//!
//! [`ProcessExecutionCache::try_acquire`] also dedupes *in-flight*
//! work: concurrent callers for the same `tx_hash` receive a shared
//! [`OnceLock`] — the first claimant fills it, later callers either
//! peek non-blockingly or block via `get_or_init`, so the VM runs once
//! per tx even when V same-shard vnodes dispatch simultaneously.
//!
//! # Eviction
//!
//! Each entry tracks the hosted shards that still need the result
//! (`participating ∩ hosted` at insertion time). Every committed tx
//! eventually lands in one finalised wave per participating shard;
//! [`Self::on_finalized_wave`] removes a shard's claim, and an entry
//! whose claims reach zero is dropped. A [`RETENTION_HORIZON`]-bounded
//! sweep keyed on the host's most recent committed `WeightedTimestamp`
//! ([`Self::on_block_committed`]) catches entries orphaned by reorgs,
//! mid-flight shard removal, or bookkeeping bugs.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use hyperscale_types::{RETENTION_HORIZON, ShardId, TxHash, WeightedTimestamp};

use crate::receipt::CachedVmOutput;

/// Shared slot returned by [`ProcessExecutionCache::try_acquire`].
///
/// Callers `set` their result if they got [`SlotStatus::Claimed`], or
/// peek / wait on another worker's result if they got
/// [`SlotStatus::Pending`].
pub type CachedSlot = Arc<OnceLock<Arc<CachedVmOutput>>>;

type Slot = CachedSlot;

/// Outcome of [`ProcessExecutionCache::try_acquire`].
///
/// Lets a batch-level scheduler distinguish "value is ready", "I just
/// reserved this slot — I must fill it", and "another worker reserved
/// it — I should come back later". The `Completed` case never appears
/// for a slot the caller is currently filling; `Claimed` and `Pending`
/// both carry the same [`CachedSlot`] so callers can drive it via the
/// underlying `OnceLock`.
pub enum SlotStatus {
    /// Value already cached.
    Completed(Arc<CachedVmOutput>),
    /// Slot freshly reserved for the caller. The caller is the unique
    /// owner of the right to fill it via `slot.set(...)`.
    Claimed(CachedSlot),
    /// Another worker has already reserved this slot. Callers either
    /// `slot.get()` to peek non-blockingly or
    /// `slot.get_or_init(|| ...)` to block (the fallback closure runs
    /// only if the original owner abandoned the slot without setting
    /// a value).
    Pending(CachedSlot),
}

struct Entry {
    value: Slot,
    /// Hosted shards (intersection of `participating` and `hosted_shards`)
    /// that still need to ack this tx via a finalised wave. Empty → evict.
    pending_shards: HashSet<ShardId>,
    /// Set to the cache's `now` at insertion. Compared against
    /// `now - RETENTION_HORIZON` during sweep.
    inserted_at_ts: WeightedTimestamp,
}

/// Cold-path bookkeeping: the inserted-timestamp index and the cache's
/// view of "now". Locked only on new-entry insert and on block-commit
/// sweep; the hot `try_acquire` / `on_finalized_wave` paths touch
/// `entries` (the [`DashMap`]) without going through here.
struct Timeline {
    /// Inserted-timestamp secondary index. Each tx hash is pushed onto
    /// `by_ts[entry.inserted_at_ts]` at insertion so the retention sweep
    /// can drop expired entries in `O(k_expired · log N)` by popping the
    /// front of the map, instead of scanning every entry on every commit.
    ///
    /// May hold stale tx hashes whose primary-map entry was removed via
    /// [`ProcessExecutionCache::on_finalized_wave`], or re-inserted under
    /// a fresher timestamp. The sweep validates each candidate against
    /// the live `inserted_at_ts` before removing from `entries`, so
    /// staleness is harmless — it just delays reclaim of the tx hash
    /// itself by at most `RETENTION_HORIZON`.
    by_ts: BTreeMap<WeightedTimestamp, Vec<TxHash>>,
    /// Most recent committed `WeightedTimestamp` observed via
    /// [`ProcessExecutionCache::on_block_committed`]. Stamped on new
    /// entries and drives the retention sweep.
    now: WeightedTimestamp,
}

/// Lock the timeline mutex, recovering from poisoning. The cache is
/// best-effort metadata; a poisoned mutex from a panicked handler
/// elsewhere doesn't justify tearing the process down.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Process-scope cache keyed by [`TxHash`].
///
/// Primary map (`entries`) is a [`DashMap`] so concurrent
/// `try_acquire` calls from the execution pool only contend on keys
/// that hash to the same shard. The retention index (`timeline`) sits
/// behind a small mutex — it's only touched once per new-entry insert
/// and once per block commit, so its contention is bounded by block
/// rate rather than dispatched-tx rate.
pub struct ProcessExecutionCache {
    /// Shards this process hosts. Used to narrow each tx's participating
    /// shard set down to the slice this cache can actually observe
    /// finalising via [`Self::on_finalized_wave`]. Loaded per acquire;
    /// swapped via [`Self::set_hosted_shards`] when shard participation
    /// changes, with the retention sweep covering entries whose claims
    /// were stamped under the old set.
    hosted_shards: ArcSwap<HashSet<ShardId>>,
    entries: DashMap<TxHash, Entry>,
    timeline: Mutex<Timeline>,
}

impl ProcessExecutionCache {
    /// Create a cache scoped to the given hosted shards. Only shards in
    /// this set can decrement entries via
    /// [`Self::on_finalized_wave`]; the retention sweep cleans up
    /// anything missed.
    #[must_use]
    pub fn new(hosted_shards: HashSet<ShardId>) -> Self {
        Self {
            hosted_shards: ArcSwap::from_pointee(hosted_shards),
            entries: DashMap::new(),
            timeline: Mutex::new(Timeline {
                by_ts: BTreeMap::new(),
                now: WeightedTimestamp::ZERO,
            }),
        }
    }

    /// Replace the hosted-shard set. New entries stamp their pending
    /// claims from the new set on the next acquire; existing entries
    /// keep the claims they were inserted with — a dropped shard can no
    /// longer decrement them, so the retention sweep reaps those.
    pub fn set_hosted_shards(&self, hosted: HashSet<ShardId>) {
        self.hosted_shards.store(Arc::new(hosted));
    }

    /// Add one shard to the hosted set.
    pub fn add_hosted_shard(&self, shard: ShardId) {
        let mut set = (**self.hosted_shards.load()).clone();
        set.insert(shard);
        self.hosted_shards.store(Arc::new(set));
    }

    /// Remove one shard from the hosted set. Entries still claiming the
    /// shard fall to the retention sweep.
    pub fn remove_hosted_shard(&self, shard: ShardId) {
        let mut set = (**self.hosted_shards.load()).clone();
        set.remove(&shard);
        self.hosted_shards.store(Arc::new(set));
    }

    /// Non-blocking slot acquisition keyed by `tx_hash`.
    ///
    /// Returns a [`SlotStatus`] the caller can react to: cache hit,
    /// slot freshly claimed, or slot already in flight on another
    /// worker. The intended consumer is a batch handler that wants to
    /// defer in-flight slots, work on other transactions first, and
    /// only block when nothing else is left.
    ///
    /// `participating` lists every shard the transaction touches. The
    /// cache narrows it to `participating ∩ hosted_shards` for
    /// decrement bookkeeping; shards the host doesn't serve can't
    /// observe their finalisation locally and so don't gate eviction.
    pub fn try_acquire(
        &self,
        tx_hash: TxHash,
        participating: impl IntoIterator<Item = ShardId>,
    ) -> SlotStatus {
        // Fast path: lookup without taking any write lock. The slot is
        // an `Arc<OnceLock<_>>` so we can release the per-key shard
        // guard before peeking at the slot's state.
        if let Some(entry_ref) = self.entries.get(&tx_hash) {
            let slot = Arc::clone(&entry_ref.value);
            drop(entry_ref);
            return slot.get().map_or_else(
                || SlotStatus::Pending(Arc::clone(&slot)),
                |v| SlotStatus::Completed(Arc::clone(v)),
            );
        }

        // Slow path: race to claim the slot. `entry()` takes the
        // per-key shard's write lock for the duration of the match —
        // racing callers either see the winner's slot under
        // `Occupied`, or one of them lands the `Vacant` insert.
        match self.entries.entry(tx_hash) {
            DashEntry::Occupied(occ) => {
                let slot = Arc::clone(&occ.get().value);
                drop(occ);
                slot.get().map_or_else(
                    || SlotStatus::Pending(Arc::clone(&slot)),
                    |v| SlotStatus::Completed(Arc::clone(v)),
                )
            }
            DashEntry::Vacant(vac) => {
                let hosted = self.hosted_shards.load();
                let pending_shards: HashSet<ShardId> = participating
                    .into_iter()
                    .filter(|s| hosted.contains(s))
                    .collect();
                // Stamp `inserted_at_ts` from the same `now` snapshot
                // that publishes the tx hash into `by_ts`, so the
                // retention sweep's equality check can match the
                // entry to its bucket. Nesting the timeline lock
                // inside the per-key shard lock is one-way — the
                // sweep releases the timeline lock before it touches
                // `entries`, so this ordering doesn't deadlock.
                let slot = Arc::new(OnceLock::new());
                let now = {
                    let mut tl = lock(&self.timeline);
                    let now = tl.now;
                    tl.by_ts.entry(now).or_default().push(tx_hash);
                    now
                };
                vac.insert(Entry {
                    value: Arc::clone(&slot),
                    pending_shards,
                    inserted_at_ts: now,
                });
                SlotStatus::Claimed(slot)
            }
        }
    }

    /// Remove `shard` from each named tx's pending-shards set. Entries
    /// that reach an empty set are evicted.
    ///
    /// Called once per [`FinalizedWavesAdmitted`] event on the
    /// admitting shard's `ShardLoop`; the wave's local EC supplies the
    /// shard identity and tx-hash list. Idempotent — calling twice
    /// with the same shard is a no-op.
    pub fn on_finalized_wave(&self, shard: ShardId, tx_hashes: impl IntoIterator<Item = TxHash>) {
        for tx_hash in tx_hashes {
            // Decrement under the per-key shard guard, then release
            // it before calling `remove_if` — re-entering the same
            // shard while holding its guard would deadlock.
            let now_empty = {
                let Some(mut entry) = self.entries.get_mut(&tx_hash) else {
                    continue;
                };
                entry.pending_shards.remove(&shard);
                entry.pending_shards.is_empty()
            };
            if now_empty {
                // Re-check under the per-key guard: a concurrent
                // `try_acquire` after our decrement may have inserted
                // a fresh entry with non-empty `pending_shards`, and
                // we mustn't evict that.
                self.entries
                    .remove_if(&tx_hash, |_, e| e.pending_shards.is_empty());
            }
        }
    }

    /// Advance the cache's view of "now" and sweep entries past the
    /// retention horizon. Called once per accepted block commit with
    /// the QC's `weighted_timestamp`.
    ///
    /// Uses the `by_ts` secondary index to bound work at
    /// `O(k_expired · log N)` — only entries whose insertion bucket has
    /// rotated past the horizon are visited, not the full primary map.
    /// A bucket whose primary-map entry has been re-inserted under a
    /// fresher timestamp is left alone (the equality check guards
    /// against evicting live entries via a stale index pointer).
    pub fn on_block_committed(&self, now: WeightedTimestamp) {
        // Gather expired buckets under the timeline lock, then release
        // it before touching `entries`. `try_acquire`'s vacant arm
        // takes a per-key shard lock and nests the timeline lock
        // inside; if the sweep held the timeline lock while waiting on
        // a shard lock, that nesting would deadlock.
        #[allow(clippy::significant_drop_tightening)] // tl is reused below collect()
        let expired: Vec<(WeightedTimestamp, Vec<TxHash>)> = {
            let mut tl = lock(&self.timeline);
            if now > tl.now {
                tl.now = now;
            }
            let cutoff = now.minus(RETENTION_HORIZON);
            let expired_ts: Vec<WeightedTimestamp> =
                tl.by_ts.range(..=cutoff).map(|(ts, _)| *ts).collect();
            let mut out = Vec::with_capacity(expired_ts.len());
            for ts in expired_ts {
                if let Some(popped) = tl.by_ts.remove(&ts) {
                    out.push((ts, popped));
                }
            }
            out
        };

        for (ts, popped) in expired {
            for tx_hash in popped {
                // `remove_if` does the `inserted_at_ts == ts` check
                // under the per-key shard guard, so a concurrent
                // re-insert under a fresher timestamp survives the
                // sweep — same invariant the previous mutex-held
                // `get` + `remove` pair preserved.
                self.entries
                    .remove_if(&tx_hash, |_, e| e.inserted_at_ts == ts);
            }
        }
    }

    /// Current entry count, including in-flight (uninitialised) slots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_types::{Hash, ShardId, TxHash, WeightedTimestamp};

    use super::*;

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    fn shard(n: u64) -> ShardId {
        ShardId::leaf(3, n)
    }

    fn hosted(shards: &[u64]) -> HashSet<ShardId> {
        shards.iter().copied().map(shard).collect()
    }

    /// Acquire an empty slot for `tx_hash` and fill it with a stub value.
    /// Mirrors what `batch_compute_cached`'s claimant path does in
    /// production: `try_acquire` → Claimed → `slot.set`.
    fn populate(
        cache: &ProcessExecutionCache,
        tx: TxHash,
        participating: impl IntoIterator<Item = ShardId>,
    ) {
        match cache.try_acquire(tx, participating) {
            SlotStatus::Claimed(slot) => {
                let _ = slot.set(Arc::new(CachedVmOutput::failed_for_tests()));
            }
            SlotStatus::Completed(_) | SlotStatus::Pending(_) => {
                panic!("populate called after slot already reserved")
            }
        }
    }

    #[test]
    fn try_acquire_returns_claimed_pending_completed_in_sequence() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let claimed = match cache.try_acquire(tx_hash(1), [shard(0)]) {
            SlotStatus::Claimed(slot) => slot,
            SlotStatus::Pending(_) => panic!("expected Claimed, got Pending"),
            SlotStatus::Completed(_) => panic!("expected Claimed, got Completed"),
        };

        // Pre-fill: a second caller sees Pending.
        let pending_status = cache.try_acquire(tx_hash(1), [shard(0)]);
        assert!(matches!(pending_status, SlotStatus::Pending(_)));

        // Fill: a third caller sees Completed.
        let value = Arc::new(CachedVmOutput::failed_for_tests());
        let set_ok = claimed.set(Arc::clone(&value)).is_ok();
        assert!(set_ok, "first set wins");
        match cache.try_acquire(tx_hash(1), [shard(0)]) {
            SlotStatus::Completed(v) => assert!(Arc::ptr_eq(&v, &value)),
            SlotStatus::Claimed(_) | SlotStatus::Pending(_) => {
                panic!("expected Completed, got non-completed status")
            }
        }
    }

    #[test]
    fn finalized_wave_evicts_when_pending_set_empties() {
        let cache = ProcessExecutionCache::new(hosted(&[0, 1]));
        populate(&cache, tx_hash(1), [shard(0), shard(1)]);
        assert_eq!(cache.len(), 1);

        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert_eq!(cache.len(), 1, "still pending on shard 1");

        cache.on_finalized_wave(shard(1), [tx_hash(1)]);
        assert!(cache.is_empty(), "all hosted-shard claims released");
    }

    #[test]
    fn non_hosted_participation_does_not_block_eviction() {
        // Tx touches shards {0, 5} but host only serves {0}; shard 5
        // never decrements locally, so the single hosted shard owns
        // the entry's lifetime.
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        populate(&cache, tx_hash(1), [shard(0), shard(5)]);
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert!(cache.is_empty());
    }

    /// New entries stamp their pending claims from the hosted set as it
    /// stands at acquire time, so a swapped set governs entries inserted
    /// after it.
    #[test]
    fn hosted_shard_swap_governs_new_entries() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        cache.set_hosted_shards(hosted(&[1]));
        populate(&cache, tx_hash(1), [shard(0), shard(1)]);

        // Shard 0 is no longer hosted — its wave can't decrement.
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert_eq!(cache.len(), 1);
        // Shard 1 owns the entry's lifetime under the new set.
        cache.on_finalized_wave(shard(1), [tx_hash(1)]);
        assert!(cache.is_empty());
    }

    #[test]
    fn finalized_wave_is_idempotent() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        populate(&cache, tx_hash(1), [shard(0)]);
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        // Second call on an already-evicted entry must not panic.
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert!(cache.is_empty());
    }

    #[test]
    fn retention_sweep_evicts_stale_entries() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let early = WeightedTimestamp::from_millis(1_000);
        cache.on_block_committed(early);

        populate(&cache, tx_hash(1), [shard(0)]);
        assert_eq!(cache.len(), 1);

        // Push `now` past inserted_at_ts + RETENTION_HORIZON.
        let far_future = early.plus(RETENTION_HORIZON).plus(Duration::from_secs(1));
        cache.on_block_committed(far_future);
        assert!(cache.is_empty());
    }

    #[test]
    fn retention_sweep_keeps_fresh_entries() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let now = WeightedTimestamp::from_millis(1_000);
        cache.on_block_committed(now);

        populate(&cache, tx_hash(1), [shard(0)]);

        // Advance by less than RETENTION_HORIZON.
        let still_fresh = now.plus(Duration::from_secs(1));
        cache.on_block_committed(still_fresh);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn retention_sweep_spares_reinserted_entries() {
        // A tx hash that's removed via `on_finalized_wave` and re-inserted
        // under a fresher timestamp leaves a stale entry in `by_ts` for
        // the original bucket. When that stale bucket rotates past the
        // horizon, the equality check against the live entry's
        // `inserted_at_ts` must spare the re-inserted slot.
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let early = WeightedTimestamp::from_millis(1_000);
        cache.on_block_committed(early);

        populate(&cache, tx_hash(1), [shard(0)]);
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert!(cache.is_empty());

        // Advance `now` enough that the *new* insertion gets a fresher
        // bucket, but the early bucket is still within the horizon.
        let mid = early.plus(Duration::from_secs(1));
        cache.on_block_committed(mid);
        populate(&cache, tx_hash(1), [shard(0)]);
        assert_eq!(cache.len(), 1);

        // Rotate past the `early` bucket but not past `mid`.
        let after_early = early.plus(RETENTION_HORIZON).plus(Duration::from_millis(1));
        cache.on_block_committed(after_early);
        assert_eq!(
            cache.len(),
            1,
            "re-inserted entry must survive the stale bucket's sweep"
        );

        // Rotate past `mid` as well — the live entry should now go.
        let after_mid = mid.plus(RETENTION_HORIZON).plus(Duration::from_millis(1));
        cache.on_block_committed(after_mid);
        assert!(cache.is_empty());
    }
}
