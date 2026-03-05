//! Gossipsub message handling.
//!
//! Infrastructure events (connections, identify, kademlia) are handled directly
//! in `event_loop.rs`. This module only processes gossipsub application messages.

use super::behaviour::BehaviourEvent;
use crate::codec_pool::CodecPoolHandle;
use hyperscale_metrics as metrics;
use hyperscale_types::ShardGroupId;
use libp2p::{gossipsub, swarm::SwarmEvent};
use std::sync::OnceLock;
use tracing::{debug, warn};

/// Handle a single swarm event — gossipsub messages only.
///
/// Connection lifecycle, identify, and kademlia events are handled in `event_loop.rs`.
pub(super) async fn handle_gossipsub_event(
    event: SwarmEvent<BehaviourEvent>,
    local_shard: ShardGroupId,
    gossip_codec: &OnceLock<CodecPoolHandle>,
) {
    match event {
        // Handle gossipsub messages
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            // Parse topic immediately to determine message type and shard
            // Using .as_str() avoids allocation
            let topic_str = message.topic.as_str();
            let parsed_topic = match hyperscale_network::Topic::parse(topic_str) {
                Some(t) => t,
                None => {
                    warn!(
                        topic = %topic_str,
                        peer = %propagation_source,
                        "Received message with invalid topic format"
                    );
                    metrics::record_invalid_message();
                    return;
                }
            };

            let data_len = message.data.len();

            // Record inbound bandwidth
            metrics::record_libp2p_bandwidth(data_len as u64, 0);

            // Cross-shard messages (allowed from any shard):
            // - state.provision: Sent cross-shard to request state for transactions
            // - execution.certificate.batch: Needed for cross-shard transaction execution
            // - transaction.gossip: Can be routed to appropriate shard

            let msg_type = parsed_topic.message_type();
            let is_shard_local_message =
                matches!(msg_type, "block.header" | "block.vote" | "execution.vote");

            if is_shard_local_message {
                if let Some(topic_shard) = parsed_topic.shard_id() {
                    if topic_shard != local_shard {
                        warn!(
                            topic = %topic_str,
                            topic_shard = topic_shard.0,
                            local_shard = local_shard.0,
                            msg_type = msg_type,
                            "Dropping shard-local message from wrong shard (cross-shard contamination attempt)"
                        );
                        metrics::record_invalid_message();
                        return;
                    }
                }
            }

            // Dispatch decoding to the codec pool (non-blocking).
            // The codec pool handles LZ4 decompression on a separate thread pool,
            // then forwards decompressed payloads via the registered GossipHandler.
            // This prevents large messages (state batches) from blocking the event loop.
            if let Some(codec) = gossip_codec.get() {
                codec.decode_async(parsed_topic, message.data, propagation_source);
            } else {
                warn!("Gossip handler not yet registered, dropping message");
            }
        }

        // Handle subscription events
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
            peer_id,
            topic,
        })) => {
            debug!("Peer {:?} subscribed to topic: {}", peer_id, topic);
        }

        _ => {
            // All other events are handled in event_loop.rs
        }
    }
}
