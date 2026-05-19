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

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use hyperscale_types::TxHash;
use indexmap::IndexMap;

use crate::receipt::CachedVmOutput;

type Slot = Arc<OnceLock<Arc<CachedVmOutput>>>;

/// Lock the inner map, recovering from poisoning. The cache is
/// best-effort metadata; a poisoned mutex from a panicked handler
/// elsewhere doesn't justify tearing the process down.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Process-scope cache keyed by [`TxHash`].
pub struct ProcessExecutionCache {
    capacity: usize,
    inner: Mutex<IndexMap<TxHash, Slot>>,
}

impl ProcessExecutionCache {
    /// Create a cache that holds at most `capacity` entries. Oldest
    /// entries (by insertion order) are evicted first when full.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(IndexMap::with_capacity(capacity)),
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
            .get(tx_hash)
            .and_then(|slot| slot.get().map(Arc::clone))
    }

    /// Get or compute the cached output for `tx_hash`.
    ///
    /// Concurrent callers for the same `tx_hash` block on a shared
    /// [`OnceLock`] — exactly one runs `compute`, the rest pick up
    /// its result. The closure runs outside the cache mutex.
    pub fn get_or_compute<F>(&self, tx_hash: TxHash, compute: F) -> Arc<CachedVmOutput>
    where
        F: FnOnce() -> CachedVmOutput,
    {
        let slot = {
            let mut guard = lock(&self.inner);
            if !guard.contains_key(&tx_hash) && guard.len() >= self.capacity {
                guard.shift_remove_index(0);
            }
            guard
                .entry(tx_hash)
                .or_insert_with(|| Arc::new(OnceLock::new()))
                .clone()
        };
        Arc::clone(slot.get_or_init(|| Arc::new(compute())))
    }

    /// Current entry count, including in-flight (uninitialised) slots.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.inner).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use hyperscale_types::{Hash, TxHash};

    use super::*;

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[byte]))
    }

    fn failed_compute() -> CachedVmOutput {
        CachedVmOutput::failed_for_tests()
    }

    #[test]
    fn miss_returns_none() {
        let cache = ProcessExecutionCache::new(4);
        assert!(cache.get(&tx_hash(7)).is_none());
    }

    #[test]
    fn get_or_compute_runs_closure_on_miss() {
        let cache = ProcessExecutionCache::new(4);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_compute = Arc::clone(&counter);
        let _ = cache.get_or_compute(tx_hash(1), move || {
            counter_for_compute.fetch_add(1, Ordering::SeqCst);
            failed_compute()
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn second_call_hits_without_running_closure() {
        let cache = ProcessExecutionCache::new(4);
        let first = cache.get_or_compute(tx_hash(1), failed_compute);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_compute = Arc::clone(&counter);
        let second = cache.get_or_compute(tx_hash(1), move || {
            counter_for_compute.fetch_add(1, Ordering::SeqCst);
            failed_compute()
        });
        assert_eq!(counter.load(Ordering::SeqCst), 0, "closure should not run");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn concurrent_misses_run_compute_once() {
        let cache = Arc::new(ProcessExecutionCache::new(4));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                cache.get_or_compute(tx_hash(1), move || {
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
    fn evicts_oldest_when_full() {
        let cache = ProcessExecutionCache::new(2);
        let _ = cache.get_or_compute(tx_hash(1), failed_compute);
        let _ = cache.get_or_compute(tx_hash(2), failed_compute);
        let _ = cache.get_or_compute(tx_hash(3), failed_compute);

        assert!(cache.get(&tx_hash(1)).is_none(), "oldest should be evicted");
        assert!(cache.get(&tx_hash(2)).is_some());
        assert!(cache.get(&tx_hash(3)).is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn reinsert_does_not_evict() {
        let cache = ProcessExecutionCache::new(2);
        let _ = cache.get_or_compute(tx_hash(1), failed_compute);
        let _ = cache.get_or_compute(tx_hash(2), failed_compute);
        let _ = cache.get_or_compute(tx_hash(1), failed_compute);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&tx_hash(1)).is_some());
        assert!(cache.get(&tx_hash(2)).is_some());
    }
}
