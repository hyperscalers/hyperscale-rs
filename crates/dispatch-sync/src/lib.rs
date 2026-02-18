//! Synchronous inline dispatch for deterministic simulation.
//!
//! [`SyncDispatch`] runs all closures inline on the calling thread,
//! ensuring deterministic execution order. Queue depths are always 0.

use hyperscale_dispatch::Dispatch;

/// Synchronous dispatch that runs closures inline.
///
/// Used by simulation runners for deterministic execution.
/// All work runs on the calling thread in the order dispatched.
#[derive(Debug, Default)]
pub struct SyncDispatch;

impl SyncDispatch {
    pub fn new() -> Self {
        Self
    }
}

impl Dispatch for SyncDispatch {
    fn spawn_consensus_crypto(&self, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn spawn_crypto(&self, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn try_spawn_crypto(&self, f: impl FnOnce() + Send + 'static) -> bool {
        f();
        true
    }

    fn spawn_tx_validation(&self, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn spawn_execution(&self, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn spawn_codec(&self, f: impl FnOnce() + Send + 'static) {
        f();
    }

    fn consensus_crypto_queue_depth(&self) -> usize {
        0
    }

    fn crypto_queue_depth(&self) -> usize {
        0
    }

    fn tx_validation_queue_depth(&self) -> usize {
        0
    }

    fn execution_queue_depth(&self) -> usize {
        0
    }

    fn codec_queue_depth(&self) -> usize {
        0
    }

    fn map_execution<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        items.iter().map(f).collect()
    }

    fn map_crypto<T, R>(&self, items: &[T], f: impl Fn(&T) -> R + Send + Sync) -> Vec<R>
    where
        T: Sync,
        R: Send,
    {
        items.iter().map(f).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_sync_dispatch_runs_inline() {
        let dispatch = SyncDispatch::new();
        let counter = Arc::new(AtomicUsize::new(0));

        let c = counter.clone();
        dispatch.spawn_consensus_crypto(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        // Runs synchronously — already incremented
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let c = counter.clone();
        dispatch.spawn_crypto(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        let c = counter.clone();
        assert!(dispatch.try_spawn_crypto(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(counter.load(Ordering::SeqCst), 3);

        let c = counter.clone();
        dispatch.spawn_tx_validation(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 4);

        let c = counter.clone();
        dispatch.spawn_execution(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 5);

        let c = counter.clone();
        dispatch.spawn_codec(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(counter.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn test_queue_depths_always_zero() {
        let dispatch = SyncDispatch::new();
        assert_eq!(dispatch.consensus_crypto_queue_depth(), 0);
        assert_eq!(dispatch.crypto_queue_depth(), 0);
        assert_eq!(dispatch.tx_validation_queue_depth(), 0);
        assert_eq!(dispatch.execution_queue_depth(), 0);
        assert_eq!(dispatch.codec_queue_depth(), 0);
    }
}
