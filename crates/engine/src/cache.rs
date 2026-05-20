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

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use hyperscale_types::{RETENTION_HORIZON, ShardGroupId, TxHash, WeightedTimestamp};
use indexmap::IndexMap;

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
    pending_shards: HashSet<ShardGroupId>,
    /// Set to the cache's `now` at insertion. Compared against
    /// `now - RETENTION_HORIZON` during sweep.
    inserted_at_ts: WeightedTimestamp,
}

struct Inner {
    entries: IndexMap<TxHash, Entry>,
    /// Most recent committed `WeightedTimestamp` observed via
    /// [`ProcessExecutionCache::on_block_committed`]. Stamped on new
    /// entries and drives the retention sweep.
    now: WeightedTimestamp,
}

/// Lock the inner map, recovering from poisoning. The cache is
/// best-effort metadata; a poisoned mutex from a panicked handler
/// elsewhere doesn't justify tearing the process down.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Process-scope cache keyed by [`TxHash`].
pub struct ProcessExecutionCache {
    /// Shards this process hosts. Used to narrow each tx's participating
    /// shard set down to the slice this cache can actually observe
    /// finalising via [`Self::on_finalized_wave`].
    hosted_shards: HashSet<ShardGroupId>,
    inner: Mutex<Inner>,
}

impl ProcessExecutionCache {
    /// Create a cache scoped to the given hosted shards. Only shards in
    /// this set can decrement entries via
    /// [`Self::on_finalized_wave`]; the retention sweep cleans up
    /// anything missed.
    #[must_use]
    pub fn new(hosted_shards: HashSet<ShardGroupId>) -> Self {
        Self {
            hosted_shards,
            inner: Mutex::new(Inner {
                entries: IndexMap::new(),
                now: WeightedTimestamp::ZERO,
            }),
        }
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
        participating: impl IntoIterator<Item = ShardGroupId>,
    ) -> SlotStatus {
        let mut guard = lock(&self.inner);
        if let Some(entry) = guard.entries.get(&tx_hash) {
            let slot = Arc::clone(&entry.value);
            drop(guard);
            return slot.get().map_or_else(
                || SlotStatus::Pending(Arc::clone(&slot)),
                |v| SlotStatus::Completed(Arc::clone(v)),
            );
        }

        let now = guard.now;
        let pending_shards: HashSet<ShardGroupId> = participating
            .into_iter()
            .filter(|s| self.hosted_shards.contains(s))
            .collect();
        let slot = Arc::new(OnceLock::new());
        guard.entries.insert(
            tx_hash,
            Entry {
                value: Arc::clone(&slot),
                pending_shards,
                inserted_at_ts: now,
            },
        );
        drop(guard);
        SlotStatus::Claimed(slot)
    }

    /// Remove `shard` from each named tx's pending-shards set. Entries
    /// that reach an empty set are evicted.
    ///
    /// Called once per [`FinalizedWavesAdmitted`] event on the
    /// admitting shard's `ShardLoop`; the wave's local EC supplies the
    /// shard identity and tx-hash list. Idempotent — calling twice
    /// with the same shard is a no-op.
    pub fn on_finalized_wave(
        &self,
        shard: ShardGroupId,
        tx_hashes: impl IntoIterator<Item = TxHash>,
    ) {
        let mut guard = lock(&self.inner);
        for tx_hash in tx_hashes {
            let Some(entry) = guard.entries.get_mut(&tx_hash) else {
                continue;
            };
            entry.pending_shards.remove(&shard);
            if entry.pending_shards.is_empty() {
                guard.entries.shift_remove(&tx_hash);
            }
        }
    }

    /// Advance the cache's view of "now" and sweep entries past the
    /// retention horizon. Called once per accepted block commit with
    /// the QC's `weighted_timestamp`.
    pub fn on_block_committed(&self, now: WeightedTimestamp) {
        let mut guard = lock(&self.inner);
        if now > guard.now {
            guard.now = now;
        }
        let cutoff = now.minus(RETENTION_HORIZON);
        guard.entries.retain(|_, e| e.inserted_at_ts > cutoff);
    }

    /// Current entry count, including in-flight (uninitialised) slots.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.inner).entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.inner).entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_types::{Hash, ShardGroupId, TxHash, WeightedTimestamp};

    use super::*;

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId::new(n)
    }

    fn hosted(shards: &[u64]) -> HashSet<ShardGroupId> {
        shards.iter().copied().map(shard).collect()
    }

    /// Acquire an empty slot for `tx_hash` and fill it with a stub value.
    /// Mirrors what `batch_compute_cached`'s claimant path does in
    /// production: `try_acquire` → Claimed → `slot.set`.
    fn populate(
        cache: &ProcessExecutionCache,
        tx: TxHash,
        participating: impl IntoIterator<Item = ShardGroupId>,
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
}
