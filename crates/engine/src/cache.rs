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
//! [`ProcessExecutionCache::get_or_compute`] also dedupes *in-flight*
//! work: concurrent callers for the same `tx_hash` block on a
//! [`OnceLock`] until the first one finishes, so the VM runs once per
//! tx even when V same-shard vnodes dispatch simultaneously.
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

type Slot = Arc<OnceLock<Arc<CachedVmOutput>>>;

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

    /// Look up an entry. Returns the cached value if present *and*
    /// initialised. A `None` return covers both "not in cache" and
    /// "another thread is currently computing this entry"; in the
    /// latter case the caller should fall through to
    /// [`Self::get_or_compute`] to block on the slot.
    #[must_use]
    pub fn get(&self, tx_hash: &TxHash) -> Option<Arc<CachedVmOutput>> {
        let guard = lock(&self.inner);
        guard
            .entries
            .get(tx_hash)
            .and_then(|e| e.value.get().map(Arc::clone))
    }

    /// Get or compute the cached output for `tx_hash`.
    ///
    /// Concurrent callers for the same `tx_hash` block on a shared
    /// [`OnceLock`] — exactly one runs `compute`, the rest pick up
    /// its result. The closure runs outside the cache mutex.
    ///
    /// `participating` lists every shard the transaction touches. The
    /// cache narrows it to `participating ∩ hosted_shards` for
    /// decrement bookkeeping; shards the host doesn't serve can't
    /// observe their finalisation locally and so don't gate eviction.
    pub fn get_or_compute<F>(
        &self,
        tx_hash: TxHash,
        participating: impl IntoIterator<Item = ShardGroupId>,
        compute: F,
    ) -> Arc<CachedVmOutput>
    where
        F: FnOnce() -> CachedVmOutput,
    {
        let slot = {
            let mut guard = lock(&self.inner);
            let now = guard.now;
            let pending_shards: HashSet<ShardGroupId> = participating
                .into_iter()
                .filter(|s| self.hosted_shards.contains(s))
                .collect();
            guard
                .entries
                .entry(tx_hash)
                .or_insert_with(|| Entry {
                    value: Arc::new(OnceLock::new()),
                    pending_shards,
                    inserted_at_ts: now,
                })
                .value
                .clone()
        };
        Arc::clone(slot.get_or_init(|| Arc::new(compute())))
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use hyperscale_types::{Hash, ShardGroupId, TxHash, WeightedTimestamp};

    use super::*;

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    fn failed_compute() -> CachedVmOutput {
        CachedVmOutput::failed_for_tests()
    }

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId::new(n)
    }

    fn hosted(shards: &[u64]) -> HashSet<ShardGroupId> {
        shards.iter().copied().map(shard).collect()
    }

    #[test]
    fn miss_returns_none() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        assert!(cache.get(&tx_hash(7)).is_none());
    }

    #[test]
    fn get_or_compute_runs_closure_on_miss() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_compute = Arc::clone(&counter);
        let _ = cache.get_or_compute(tx_hash(1), [shard(0)], move || {
            counter_for_compute.fetch_add(1, Ordering::SeqCst);
            failed_compute()
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn second_call_hits_without_running_closure() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let first = cache.get_or_compute(tx_hash(1), [shard(0)], failed_compute);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_compute = Arc::clone(&counter);
        let second = cache.get_or_compute(tx_hash(1), [shard(0)], move || {
            counter_for_compute.fetch_add(1, Ordering::SeqCst);
            failed_compute()
        });
        assert_eq!(counter.load(Ordering::SeqCst), 0, "closure should not run");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn concurrent_misses_run_compute_once() {
        let cache = Arc::new(ProcessExecutionCache::new(hosted(&[0])));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                cache.get_or_compute(tx_hash(1), [shard(0)], move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Force enough overlap for races to register.
                    thread::sleep(Duration::from_millis(20));
                    failed_compute()
                })
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            results.push(h.join().unwrap());
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "VM should run exactly once for concurrent misses"
        );
        for r in &results[1..] {
            assert!(Arc::ptr_eq(&results[0], r));
        }
    }

    #[test]
    fn finalized_wave_evicts_when_pending_set_empties() {
        let cache = ProcessExecutionCache::new(hosted(&[0, 1]));
        let _ = cache.get_or_compute(tx_hash(1), [shard(0), shard(1)], failed_compute);
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
        let _ = cache.get_or_compute(tx_hash(1), [shard(0), shard(5)], failed_compute);
        cache.on_finalized_wave(shard(0), [tx_hash(1)]);
        assert!(cache.is_empty());
    }

    #[test]
    fn finalized_wave_is_idempotent() {
        let cache = ProcessExecutionCache::new(hosted(&[0]));
        let _ = cache.get_or_compute(tx_hash(1), [shard(0)], failed_compute);
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

        let _ = cache.get_or_compute(tx_hash(1), [shard(0)], failed_compute);
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

        let _ = cache.get_or_compute(tx_hash(1), [shard(0)], failed_compute);

        // Advance by less than RETENTION_HORIZON.
        let still_fresh = now.plus(Duration::from_secs(1));
        cache.on_block_committed(still_fresh);
        assert_eq!(cache.len(), 1);
    }
}
