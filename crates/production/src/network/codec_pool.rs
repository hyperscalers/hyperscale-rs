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
//!                                      │ Consensus TX    │
//!                                      │ (Event channel) │
//!                                      └─────────────────┘
//! ```
//!
//! The event loop remains non-blocking - after basic validation (peer, shard),
//! decode work is spawned to the shared codec pool which sends results directly to
//! the consensus channel.

use super::codec::{decode_message, encode_message, CodecError};
use super::Topic;
use crate::ThreadPoolManager;
use hyperscale_core::{Event, OutboundMessage};
use hyperscale_metrics as metrics;
use libp2p::PeerId as Libp2pPeerId;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{trace, warn};

/// Handle for async message encoding/decoding using the shared thread pool.
///
/// This wraps a `ThreadPoolManager` and provides convenient methods for
/// spawning codec work on the shared codec thread pool.
#[derive(Clone)]
pub struct CodecPoolHandle {
    thread_pools: Arc<ThreadPoolManager>,
}

impl CodecPoolHandle {
    /// Create a new handle wrapping the thread pool manager.
    pub fn new(thread_pools: Arc<ThreadPoolManager>) -> Self {
        Self { thread_pools }
    }

    /// Decode a message asynchronously and send results to the consensus channel.
    ///
    /// This method returns immediately - the actual decode work happens on the
    /// shared codec thread pool, and decoded events are sent directly to the consensus
    /// channel.
    ///
    /// # Arguments
    ///
    /// * `topic` - The parsed gossipsub topic (determines message type)
    /// * `data` - Raw message bytes from the network
    /// * `propagation_source` - Peer that sent the message (for logging)
    /// * `consensus_tx` - Channel to send decoded events to
    /// * `tx_validation_handle` - Handle for submitting transactions to validation batcher
    pub fn decode_async(
        &self,
        topic: Topic,
        data: Vec<u8>,
        propagation_source: Libp2pPeerId,
        consensus_tx: mpsc::Sender<Event>,
        tx_validation_handle: crate::validation_batcher::ValidationBatcherHandle,
    ) {
        self.thread_pools.spawn_codec(move || {
            let result = decode_message(&topic, &data);

            match result {
                Ok(decoded) => {
                    metrics::record_network_message_received();

                    // Route based on event type
                    for event in decoded.events {
                        match event {
                            Event::TransactionGossipReceived { tx } => {
                                // Submit to batched validator for dedup and parallel validation
                                if !tx_validation_handle.submit(tx) {
                                    trace!(
                                        peer = %propagation_source,
                                        "Transaction deduplicated or batcher closed"
                                    );
                                }
                            }
                            event => {
                                // Consensus messages - send to channel
                                // We're on a rayon thread, so we need to use try_send
                                if consensus_tx.try_send(event).is_err() {
                                    // Channel full or closed - this shouldn't happen often
                                    // since consensus channel is bounded but large
                                    warn!(
                                        peer = %propagation_source,
                                        "Failed to send decoded event to consensus channel"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        topic = %topic,
                        peer = %propagation_source,
                        "Failed to decode message in codec pool"
                    );
                    metrics::record_invalid_message();
                }
            }
        });
    }

    /// Encode a message synchronously.
    ///
    /// Encoding is fast for most messages and happens on the caller's thread.
    /// The codec pool is primarily beneficial for decoding in the event loop.
    pub fn encode_sync(&self, message: &OutboundMessage) -> Result<Vec<u8>, CodecError> {
        encode_message(message)
    }

    /// Get current codec pool queue depth (for metrics).
    pub fn queue_depth(&self) -> usize {
        self.thread_pools.codec_queue_depth()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ThreadPoolConfig;

    #[test]
    fn test_codec_pool_handle_creation() {
        let thread_pools = Arc::new(ThreadPoolManager::new(ThreadPoolConfig::minimal()).unwrap());
        let handle = CodecPoolHandle::new(thread_pools);
        assert_eq!(handle.queue_depth(), 0);
    }

    #[test]
    fn test_encode_sync() {
        use hyperscale_messages::gossip::BlockVoteGossip;
        use hyperscale_types::{zero_bls_signature, BlockHeight, BlockVote, Hash, ValidatorId};

        let thread_pools = Arc::new(ThreadPoolManager::new(ThreadPoolConfig::minimal()).unwrap());
        let handle = CodecPoolHandle::new(thread_pools);

        let vote = BlockVote {
            block_hash: Hash::from_bytes(&[1u8; 32]),
            height: BlockHeight(1),
            voter: ValidatorId(0),
            round: 0,
            signature: zero_bls_signature(),
            timestamp: 0,
        };
        let gossip = BlockVoteGossip { vote };
        let message = OutboundMessage::BlockVote(gossip);

        let encoded = handle.encode_sync(&message).unwrap();
        assert!(!encoded.is_empty());
    }
}
