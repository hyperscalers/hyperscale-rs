//! Async message encoding/decoding using the shared thread pool.
//!
//! This module provides a handle for SBOR encoding/decoding operations,
//! offloading them from the network event loop to the shared codec thread pool
//! managed by `ThreadPoolManager`.
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
//!                                      │ LZ4 decompress   │
//!                                      │ → NodeInput chan  │
//!                                      └─────────────────┘
//! ```
//!
//! The event loop remains non-blocking - after basic validation (peer, shard),
//! decode work is spawned to the shared codec pool which decompresses and
//! forwards the raw payload to the NodeLoop via the event channel.

use hyperscale_core::NodeInput;
use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Topic;
use libp2p::PeerId as Libp2pPeerId;
use std::sync::Arc;
use tracing::warn;

/// Handle for async message encoding/decoding using a dispatch implementation.
///
/// Generic over `D: Dispatch`, defaulting to [`PooledDispatch`] for production.
/// The dispatch implementation determines how codec work is scheduled (rayon
/// thread pool in production, inline in simulation).
pub struct CodecPoolHandle<D: Dispatch = PooledDispatch> {
    dispatch: Arc<D>,
    event_tx: crossbeam::channel::Sender<NodeInput>,
}

impl<D: Dispatch> Clone for CodecPoolHandle<D> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
            event_tx: self.event_tx.clone(),
        }
    }
}

impl<D: Dispatch> CodecPoolHandle<D> {
    /// Create a new handle wrapping the dispatch implementation and event sender.
    pub fn new(dispatch: Arc<D>, event_tx: crossbeam::channel::Sender<NodeInput>) -> Self {
        Self { dispatch, event_tx }
    }

    /// Decode a message asynchronously and forward to the NodeLoop event channel.
    ///
    /// This method returns immediately - the actual decompress work happens on the
    /// dispatch's codec pool. The decompressed payload is sent as a
    /// `NodeInput::GossipReceived` to the NodeLoop, which handles SBOR decoding
    /// and type dispatch internally.
    ///
    /// # Arguments
    ///
    /// * `topic` - The parsed gossipsub topic (determines message type)
    /// * `data` - Raw LZ4-compressed message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    pub fn decode_async(&self, topic: Topic, data: Vec<u8>, propagation_source: Libp2pPeerId) {
        let event_tx = self.event_tx.clone();
        self.dispatch.spawn_codec(move || {
            let peer_label = propagation_source.to_string();

            // LZ4 decompress, then forward raw SBOR payload to NodeLoop.
            match hyperscale_network::wire::decompress(&data) {
                Ok(payload) => {
                    let message_type = topic.message_type().to_string();
                    let _ = event_tx.send(NodeInput::GossipReceived {
                        message_type,
                        payload,
                    });
                    metrics::record_network_message_received();
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = %topic,
                        peer = %peer_label,
                        "Failed to decompress message in codec pool"
                    );
                    metrics::record_invalid_message();
                }
            }
        });
    }

    /// Get current codec pool queue depth (for metrics).
    pub fn queue_depth(&self) -> usize {
        self.dispatch.codec_queue_depth()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_dispatch_pooled::ThreadPoolConfig;

    #[test]
    fn test_codec_pool_handle_creation() {
        let dispatch = Arc::new(PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap());
        let (event_tx, _event_rx) = crossbeam::channel::unbounded();
        let handle = CodecPoolHandle::new(dispatch, event_tx);
        assert_eq!(handle.queue_depth(), 0);
    }

    #[test]
    fn test_encode_to_wire() {
        use hyperscale_messages::gossip::BlockVoteGossip;
        use hyperscale_types::{zero_bls_signature, BlockHeight, BlockVote, Hash, ValidatorId};

        let vote = BlockVote {
            block_hash: Hash::from_bytes(&[1u8; 32]),
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
}
