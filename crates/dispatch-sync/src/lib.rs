//! Synchronous inline dispatch for deterministic simulation.
//!
//! [`SyncDispatch`] runs all closures inline on the calling thread,
//! ensuring deterministic execution order. Queue depths are always 0.

use hyperscale_dispatch::{Dispatch, DispatchPool};

/// Synchronous dispatch that runs closures inline.
///
/// Used by simulation runners for deterministic execution.
/// All work runs on the calling thread in the order dispatched.
#[derive(Debug, Default, Clone)]
pub struct SyncDispatch;

impl SyncDispatch {
    /// Create a new inline dispatcher (zero-sized; equivalent to `SyncDispatch::default()`).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Dispatch for SyncDispatch {
    fn spawn(&self, _pool: DispatchPool, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn queue_depth(&self, _pool: DispatchPool) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_sync_dispatch_runs_inline() {
        let dispatch = SyncDispatch::new();
        let counter = Arc::new(AtomicUsize::new(0));

        for pool in [
            DispatchPool::ConsensusCrypto,
            DispatchPool::Crypto,
            DispatchPool::TxValidation,
            DispatchPool::Execution,
        ] {
            let c = counter.clone();
            dispatch.spawn(pool, move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_queue_depths_always_zero() {
        let dispatch = SyncDispatch::new();
        for pool in [
            DispatchPool::ConsensusCrypto,
            DispatchPool::Crypto,
            DispatchPool::TxValidation,
            DispatchPool::Execution,
        ] {
            assert_eq!(dispatch.queue_depth(pool), 0);
        }
    }
}
