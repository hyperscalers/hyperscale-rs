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
//!                                      │ HandlerRegistry  │
//!                                      │ → Event channel  │
//!                                      └─────────────────┘
//! ```
//!
//! The event loop remains non-blocking - after basic validation (peer, shard),
//! decode work is spawned to the shared codec pool which dispatches through the
//! handler registry.

use hyperscale_dispatch::Dispatch;
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::{HandlerRegistry, Topic};
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
    registry: Arc<HandlerRegistry>,
}

impl<D: Dispatch> Clone for CodecPoolHandle<D> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
            registry: self.registry.clone(),
        }
    }
}

impl<D: Dispatch> CodecPoolHandle<D> {
    /// Create a new handle wrapping the dispatch implementation and handler registry.
    pub fn new(dispatch: Arc<D>, registry: Arc<HandlerRegistry>) -> Self {
        Self { dispatch, registry }
    }

    /// Decode a message asynchronously and dispatch through the handler registry.
    ///
    /// This method returns immediately - the actual decode work happens on the
    /// dispatch's codec pool, and decoded events are sent through the handlers
    /// registered on the `HandlerRegistry`.
    ///
    /// # Arguments
    ///
    /// * `topic` - The parsed gossipsub topic (determines message type)
    /// * `data` - Raw message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    pub fn decode_async(&self, topic: Topic, data: Vec<u8>, propagation_source: Libp2pPeerId) {
        let registry = self.registry.clone();
        self.dispatch.spawn_codec(move || {
            let peer_label = propagation_source.to_string();

            match registry.dispatch_gossip(&topic, &data) {
                Ok(true) => {
                    metrics::record_network_message_received();
                }
                Ok(false) => {
                    warn!(
                        topic = %topic,
                        peer = %peer_label,
                        "No handlers registered for gossip topic"
                    );
                    metrics::record_invalid_message();
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = %topic,
                        peer = %peer_label,
                        "Failed to decode message in codec pool"
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
        let registry = Arc::new(HandlerRegistry::new());
        let handle = CodecPoolHandle::new(dispatch, registry);
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
