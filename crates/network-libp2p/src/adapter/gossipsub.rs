//! Gossipsub message handling.
//!
//! Infrastructure events (connections, identify, kademlia) are handled directly
//! in `event_loop.rs`. This module only processes gossipsub application messages.

use super::behaviour::BehaviourEvent;
use hyperscale_metrics as metrics;
use hyperscale_network::HandlerRegistry;
use hyperscale_types::ShardGroupId;
use libp2p::{gossipsub, swarm::SwarmEvent, PeerId as Libp2pPeerId};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Validation result sent from the gossipsub handler back to the event loop.
///
/// The event loop drains these and calls `report_message_validation_result`
/// on the gossipsub behaviour, which controls message forwarding and peer scoring.
pub(super) struct ValidationReport {
    pub message_id: gossipsub::MessageId,
    pub propagation_source: Libp2pPeerId,
    pub acceptance: gossipsub::MessageAcceptance,
}

/// Handle a single swarm event — gossipsub messages only.
///
/// Connection lifecycle, identify, and kademlia events are handled in `event_loop.rs`.
///
/// Sends a [`ValidationReport`] for each gossipsub message so the event loop can call
/// `report_message_validation_result`, controlling forwarding and peer scoring.
#[allow(clippy::too_many_lines)] // single dispatch over gossipsub events; sub-events share local state
pub(super) fn handle_gossipsub_event(
    event: SwarmEvent<BehaviourEvent>,
    local_shard: ShardGroupId,
    registry: &Arc<HandlerRegistry>,
    validation_tx: &mpsc::UnboundedSender<ValidationReport>,
) {
    match event {
        // Handle gossipsub messages
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            // Parse topic immediately to determine message type and shard
            let topic_str = message.topic.as_str();
            let Some(parsed) = hyperscale_network::parse_topic(topic_str) else {
                warn!(
                    topic = %topic_str,
                    peer = %propagation_source,
                    "Received message with invalid topic format"
                );
                metrics::record_invalid_message();
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: gossipsub::MessageAcceptance::Reject,
                });
                return;
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
                        let _ = validation_tx.send(ValidationReport {
                            message_id,
                            propagation_source,
                            acceptance: gossipsub::MessageAcceptance::Reject,
                        });
                        return;
                    }
                }
            }

            // Look up the per-type handler from the registry.
            let Some(handler) = registry.get_gossip(msg_type) else {
                warn!(
                    msg_type = msg_type,
                    "No gossip handler registered for message type, dropping"
                );
                // No handler is not the sender's fault — ignore rather than reject.
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: gossipsub::MessageAcceptance::Ignore,
                });
                return;
            };

            // Spawn decompress + handler off the event loop.
            // LZ4 decompression is fast (~4GB/s) but the handler includes
            // SBOR decode which we don't want to stall the swarm poll on.
            let vtx = validation_tx.clone();
            tokio::spawn(async move {
                match hyperscale_network::compression::decompress(&message.data) {
                    Ok(payload) => {
                        let verdict = handler(payload);
                        let acceptance = match verdict {
                            hyperscale_network::GossipVerdict::Accept => {
                                metrics::record_network_message_received();
                                gossipsub::MessageAcceptance::Accept
                            }
                            hyperscale_network::GossipVerdict::Reject => {
                                metrics::record_invalid_message();
                                gossipsub::MessageAcceptance::Reject
                            }
                        };
                        let _ = vtx.send(ValidationReport {
                            message_id,
                            propagation_source,
                            acceptance,
                        });
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            peer = %propagation_source,
                            "Failed to decompress gossip message"
                        );
                        metrics::record_invalid_message();
                        let _ = vtx.send(ValidationReport {
                            message_id,
                            propagation_source,
                            acceptance: gossipsub::MessageAcceptance::Reject,
                        });
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
