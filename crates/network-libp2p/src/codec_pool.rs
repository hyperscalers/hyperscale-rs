//! Async message decoding using the shared thread pool.
//!
//! This module provides a handle for LZ4 decompression, offloading it from the
//! network event loop to the shared codec thread pool managed by `ThreadPoolManager`.
//!
//! # Architecture
//!
//! ```text
//! Network Event Loop                    Codec Pool (via ThreadPoolManager)
//! ┌─────────────────┐                  ┌─────────────────┐
//! │ Gossipsub msg   │──decode_async───►│ spawn_codec()   │
//! │ (raw bytes)     │   (non-blocking) │ (shared pool)   │
//! └─────────────────┘                  └────────┬────────┘
//!                                               │
//!                                               ▼
//!                                      ┌─────────────────┐
//!                                      │ LZ4 decompress  │
//!                                      │ → handler lookup │
//!                                      │ → on_message()  │
//!                                      └─────────────────┘
//! ```
//!
//! The event loop remains non-blocking — after basic validation (peer, shard)
//! and handler lookup, the codec pool decompresses and invokes the per-type
//! gossip handler directly.

use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::GossipHandler;
use libp2p::PeerId as Libp2pPeerId;
use std::sync::Arc;
use tracing::warn;

/// Handle for async message decoding using a dispatch implementation.
///
/// Generic over `D: Dispatch`, defaulting to [`PooledDispatch`] for production.
/// The dispatch implementation determines how codec work is scheduled (rayon
/// thread pool in production, inline in simulation).
pub(crate) struct CodecPoolHandle<D: Dispatch = PooledDispatch> {
    dispatch: Arc<D>,
}

impl<D: Dispatch> Clone for CodecPoolHandle<D> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
        }
    }
}

impl<D: Dispatch> CodecPoolHandle<D> {
    /// Create a new handle wrapping the dispatch implementation.
    pub(crate) fn new(dispatch: Arc<D>) -> Self {
        Self { dispatch }
    }

    /// Decompress a message asynchronously and forward to the given handler.
    ///
    /// This method returns immediately — the actual decompress work happens on the
    /// dispatch's codec pool. The decompressed payload is forwarded directly to the
    /// per-type gossip handler.
    ///
    /// # Arguments
    ///
    /// * `handler` - The gossip handler for this message type (already looked up)
    /// * `data` - Raw LZ4-compressed message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    pub(crate) fn decode_async(
        &self,
        handler: Arc<dyn GossipHandler>,
        data: Vec<u8>,
        propagation_source: Libp2pPeerId,
    ) {
        self.dispatch
            .spawn_codec(move || match hyperscale_network::wire::decompress(&data) {
                Ok(payload) => {
                    handler.on_message(payload);
                    metrics::record_network_message_received();
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        peer = %propagation_source,
                        "Failed to decompress message in codec pool"
                    );
                    metrics::record_invalid_message();
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_dispatch_pooled::ThreadPoolConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingHandler {
        counter: Arc<AtomicUsize>,
        tx: crossbeam::channel::Sender<Vec<u8>>,
    }

    impl GossipHandler for CountingHandler {
        fn on_message(&self, payload: Vec<u8>) {
            self.counter.fetch_add(1, Ordering::SeqCst);
            let _ = self.tx.send(payload);
        }
    }

    fn make_handle() -> (
        CodecPoolHandle,
        Arc<dyn GossipHandler>,
        Arc<AtomicUsize>,
        crossbeam::channel::Receiver<Vec<u8>>,
    ) {
        let dispatch = Arc::new(PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = crossbeam::channel::unbounded();
        let handler: Arc<dyn GossipHandler> = Arc::new(CountingHandler {
            counter: counter.clone(),
            tx,
        });
        (CodecPoolHandle::new(dispatch), handler, counter, rx)
    }

    #[test]
    fn test_encode_to_wire() {
        use hyperscale_messages::gossip::BlockVoteGossip;
        use hyperscale_types::{
            zero_bls_signature, BlockHeight, BlockVote, Hash, ShardGroupId, ValidatorId,
        };

        let vote = BlockVote {
            block_hash: Hash::from_bytes(&[1u8; 32]),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(1),
            voter: ValidatorId(0),
            round: 0,
            signature: zero_bls_signature(),
            timestamp: 0,
        };
        let gossip = BlockVoteGossip { vote };

        let encoded = hyperscale_network::encode_to_wire(&gossip).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_decode_async_calls_handler() {
        let (pool, handler, counter, rx) = make_handle();

        let original = b"hello world";
        let compressed = hyperscale_network::wire::compress(original);
        let peer = Libp2pPeerId::random();

        pool.decode_async(handler, compressed, peer);

        let payload = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(payload, original);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_decode_async_invalid_data_no_handler_call() {
        let (pool, handler, counter, rx) = make_handle();
        let peer = Libp2pPeerId::random();

        // Send garbage data that can't be decompressed
        pool.decode_async(handler, vec![0xFF, 0xFE, 0xFD], peer);

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

        let compressed = hyperscale_network::wire::compress(b"from clone");
        let peer = Libp2pPeerId::random();

        pool2.decode_async(handler, compressed, peer);

        let payload = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(payload, b"from clone");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
