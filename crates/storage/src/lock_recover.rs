//! Lock helpers that recover from poison rather than propagating it.
//!
//! Two conditions both need to hold before reaching for these:
//!
//! 1. **Whole-entry mutation only.** The guarded state is mutated
//!    exclusively through `insert` / `write` / `retain` / `replace`. A
//!    panic mid-mutation cannot leave a torn invariant in those
//!    structures, so the post-poison data is internally consistent.
//!
//! 2. **The lock spans test or process boundaries you don't want to
//!    cascade.** In particular: storage backends shared across tests
//!    (`SimStorage`) and pending-state caches that long-lived async
//!    machinery reads through (`PendingChain`). A panic in one test
//!    poisoning a shared `SimStorage` would cascade across every
//!    subsequent test, even ones with nothing to do with the original
//!    fault.
//!
//! When (1) holds but (2) doesn't — e.g. a per-`IoLoop` `Mutex` over a
//! `HashMap` of in-flight requests, or a per-instance commit-coordinator
//! cache — *don't* recover. Those locks see only one holder at a time,
//! so a poison there means *that one holder* panicked. Surface it.
//! Recovery would mask real bugs.
//!
//! Also don't recover for locks protecting partial-update invariants —
//! commit-ordering mutexes, counters mutated between `read()` and
//! `write()`, etc. Those need to fail loudly.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Acquire a read guard, recovering from poison.
pub fn read_or_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Acquire a write guard, recovering from poison.
pub fn write_or_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

/// Acquire a mutex guard, recovering from poison.
pub fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
