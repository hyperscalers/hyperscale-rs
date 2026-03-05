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
//!                                      │ → GossipHandler │
//!                                      └─────────────────┘
//! ```
//!
//! The event loop remains non-blocking - after basic validation (peer, shard),
//! decode work is spawned to the shared codec pool which decompresses and
//! forwards the raw payload via the registered [`GossipHandler`].

use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::{GossipHandler, Topic};
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
    handler: Arc<dyn GossipHandler>,
}

impl<D: Dispatch> Clone for CodecPoolHandle<D> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
            handler: self.handler.clone(),
        }
    }
}

impl<D: Dispatch> CodecPoolHandle<D> {
    /// Create a new handle wrapping the dispatch implementation and gossip handler.
    pub(crate) fn new(dispatch: Arc<D>, handler: Arc<dyn GossipHandler>) -> Self {
        Self { dispatch, handler }
    }

    /// Decode a message asynchronously and forward to the registered gossip handler.
    ///
    /// This method returns immediately - the actual decompress work happens on the
    /// dispatch's codec pool. The decompressed payload is forwarded via the
    /// `GossipHandler`, which handles delivery to the IoLoop.
    ///
    /// # Arguments
    ///
    /// * `topic` - The parsed gossipsub topic (determines message type)
    /// * `data` - Raw LZ4-compressed message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    pub(crate) fn decode_async(
        &self,
        topic: Topic,
        data: Vec<u8>,
        propagation_source: Libp2pPeerId,
    ) {
        let message_type = topic.message_type();
        let handler = self.handler.clone();
        self.dispatch
            .spawn_codec(move || match hyperscale_network::wire::decompress(&data) {
                Ok(payload) => {
                    handler.on_gossip(message_type, payload);
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
    use hyperscale_core::NodeInput;
    use hyperscale_dispatch_pooled::ThreadPoolConfig;

    /// Test GossipHandler that forwards to a crossbeam channel.
    struct ChannelHandler {
        tx: crossbeam::channel::Sender<NodeInput>,
    }

    impl GossipHandler for ChannelHandler {
        fn on_gossip(&self, message_type: &'static str, payload: Vec<u8>) {
            let _ = self.tx.send(NodeInput::GossipReceived {
                message_type,
                payload,
            });
        }
    }

    fn make_handle() -> (CodecPoolHandle, crossbeam::channel::Receiver<NodeInput>) {
        let dispatch = Arc::new(PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap());
        let (tx, rx) = crossbeam::channel::unbounded();
        let handler: Arc<dyn GossipHandler> = Arc::new(ChannelHandler { tx });
        (CodecPoolHandle::new(dispatch, handler), rx)
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
    fn test_decode_async_sends_gossip_received() {
        let (handle, event_rx) = make_handle();

        let original = b"hello world";
        let compressed = hyperscale_network::wire::compress(original);
        let topic = Topic::global("test.message");
        let peer = Libp2pPeerId::random();

        handle.decode_async(topic, compressed, peer);

        let event = event_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        match event {
            NodeInput::GossipReceived {
                message_type,
                payload,
            } => {
                assert_eq!(message_type, "test.message");
                assert_eq!(payload, original);
            }
            other => panic!("Expected GossipReceived, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_async_invalid_data_no_event() {
        let (handle, event_rx) = make_handle();

        let topic = Topic::global("test.message");
        let peer = Libp2pPeerId::random();

        // Send garbage data that can't be decompressed
        handle.decode_async(topic, vec![0xFF, 0xFE, 0xFD], peer);

        // Should not receive any event (decompress fails)
        let result = event_rx.recv_timeout(std::time::Duration::from_millis(500));
        assert!(result.is_err(), "Should not receive event for invalid data");
    }

    #[test]
    fn test_clone_shares_handler() {
        let (handle, event_rx) = make_handle();
        let handle2 = handle.clone();

        let compressed = hyperscale_network::wire::compress(b"from clone");
        let topic = Topic::global("test.clone");
        let peer = Libp2pPeerId::random();

        handle2.decode_async(topic, compressed, peer);

        let event = event_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        match event {
            NodeInput::GossipReceived {
                message_type,
                payload,
            } => {
                assert_eq!(message_type, "test.clone");
                assert_eq!(payload, b"from clone");
            }
            other => panic!("Expected GossipReceived, got {:?}", other),
        }
    }
}
