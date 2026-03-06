//! Gossipsub message handling.
//!
//! Infrastructure events (connections, identify, kademlia) are handled directly
//! in `event_loop.rs`. This module only processes gossipsub application messages.

use super::behaviour::BehaviourEvent;
use hyperscale_metrics as metrics;
use hyperscale_network::HandlerRegistry;
use hyperscale_types::ShardGroupId;
use libp2p::{gossipsub, swarm::SwarmEvent};
use std::sync::Arc;
use tracing::{debug, warn};

/// Handle a single swarm event — gossipsub messages only.
///
/// Connection lifecycle, identify, and kademlia events are handled in `event_loop.rs`.
pub(super) async fn handle_gossipsub_event(
    event: SwarmEvent<BehaviourEvent>,
    local_shard: ShardGroupId,
    registry: &Arc<HandlerRegistry>,
) {
    match event {
        // Handle gossipsub messages
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            // Parse topic immediately to determine message type and shard
            let topic_str = message.topic.as_str();
            let parsed = match hyperscale_network::parse_topic(topic_str) {
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

            // Shard-local messages must come from the local shard's topic.
            let msg_type = parsed.message_type;
            let is_shard_local_message =
                matches!(msg_type, "block.header" | "block.vote" | "execution.vote");

            if is_shard_local_message {
                if let Some(topic_shard) = parsed.shard_id {
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

            // Look up the per-type handler from the registry.
            let handler = match registry.get_gossip(msg_type) {
                Some(h) => h,
                None => {
                    warn!(
                        msg_type = msg_type,
                        "No gossip handler registered for message type, dropping"
                    );
                    return;
                }
            };

            // Spawn decompress + handler off the event loop.
            // LZ4 decompression is fast (~4GB/s) but the handler includes
            // SBOR decode which we don't want to stall the swarm poll on.
            tokio::spawn(async move {
                match hyperscale_network::compression::decompress(&message.data) {
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
