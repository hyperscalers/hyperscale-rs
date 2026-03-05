//! Async LZ4 decompression using the shared thread pool.
//!
//! This module provides a handle for offloading LZ4 decompression from the
//! network event loop to a shared thread pool managed by `ThreadPoolManager`.
//!
//! # Architecture
//!
//! ```text
//! Network Event Loop                    Decompress Pool (via ThreadPoolManager)
//! ┌─────────────────┐                  ┌──────────────────┐
//! │ Gossipsub msg   │──decompress────► │ decompress()     │
//! │ (raw bytes)     │   (non-blocking) │ (shared pool)    │
//! └─────────────────┘                  └────────┬─────────┘
//!                                               │
//!                                               ▼
//!                                      ┌──────────────────┐
//!                                      │ LZ4 decompress   │
//!                                      │ → handler()      │
//!                                      └──────────────────┘
//! ```
//!
//! The event loop remains non-blocking — after basic validation (peer, shard)
//! and handler lookup, the pool decompresses and invokes the per-type
//! gossip handler directly.

use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::RawGossipHandler;
use libp2p::PeerId as Libp2pPeerId;
use std::sync::Arc;
use tracing::warn;

/// Handle for async decompression using a dispatch implementation.
///
/// Generic over `D: Dispatch`, defaulting to [`PooledDispatch`] for production.
/// The dispatch implementation determines how work is scheduled (rayon
/// thread pool in production, inline in simulation).
pub(crate) struct DecompressPoolHandle<D: Dispatch = PooledDispatch> {
    dispatch: Arc<D>,
}

impl<D: Dispatch> Clone for DecompressPoolHandle<D> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
        }
    }
}

impl<D: Dispatch> DecompressPoolHandle<D> {
    /// Create a new handle wrapping the dispatch implementation.
    pub(crate) fn new(dispatch: Arc<D>) -> Self {
        Self { dispatch }
    }

    /// Decompress a message asynchronously and forward to the given handler.
    ///
    /// This method returns immediately — the actual decompress work happens on the
    /// dispatch's thread pool. The decompressed payload is forwarded directly to the
    /// per-type gossip handler.
    ///
    /// # Arguments
    ///
    /// * `handler` - The gossip handler for this message type (already looked up)
    /// * `data` - Raw LZ4-compressed message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    pub(crate) fn decompress_async(
        &self,
        handler: Arc<RawGossipHandler>,
        data: Vec<u8>,
        propagation_source: Libp2pPeerId,
    ) {
        self.dispatch.spawn_codec(move || {
            match hyperscale_network::compression::decompress(&data) {
                Ok(payload) => {
                    handler(payload);
                    metrics::record_network_message_received();
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        peer = %propagation_source,
                        "Failed to decompress gossip message"
                    );
                    metrics::record_invalid_message();
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_dispatch_pooled::ThreadPoolConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_handle() -> (
        DecompressPoolHandle,
        Arc<RawGossipHandler>,
        Arc<AtomicUsize>,
        crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        let dispatch = Arc::new(PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = crossbeam::channel::unbounded();
        let counter_clone = counter.clone();
        let handler: Arc<RawGossipHandler> = Arc::new(move |payload: Vec<u8>| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(payload);
        });
        (DecompressPoolHandle::new(dispatch), handler, counter, rx)
    }

    #[test]
    fn test_compress_roundtrip() {
        use hyperscale_network::compression;

        let original = b"hello world";
        let compressed = compression::compress(original);
        let decompressed = compression::decompress(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_async_calls_handler() {
        let (pool, handler, counter, rx) = make_handle();

        let original = b"hello world";
        let compressed = hyperscale_network::compression::compress(original);
        let peer = Libp2pPeerId::random();

        pool.decompress_async(handler, compressed, peer);

        let payload = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(payload, original);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_decompress_async_invalid_data_no_handler_call() {
        let (pool, handler, counter, rx) = make_handle();
        let peer = Libp2pPeerId::random();

        // Send garbage data that can't be decompressed
        pool.decompress_async(handler, vec![0xFF, 0xFE, 0xFD], peer);

        // Handler should not be called (decompress fails)
        let result = rx.recv_timeout(std::time::Duration::from_millis(500));
        assert!(
            result.is_err(),
            "Handler should not be called for invalid data"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_clone_shares_dispatch() {
        let (pool, handler, counter, rx) = make_handle();
        let pool2 = pool.clone();

        let compressed = hyperscale_network::compression::compress(b"from clone");
        let peer = Libp2pPeerId::random();

        pool2.decompress_async(handler, compressed, peer);

        let payload = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(payload, b"from clone");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
