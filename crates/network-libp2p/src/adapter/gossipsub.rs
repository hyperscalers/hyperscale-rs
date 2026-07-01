//! Gossipsub message handling.
//!
//! Infrastructure events (connections, identify, kademlia) are handled directly
//! in `event_loop.rs`. This module only processes gossipsub application messages.

use std::sync::Arc;

use hyperscale_metrics::{
    record_gossipsub_validation, record_invalid_message, record_libp2p_bandwidth,
    record_network_message_received,
};
use hyperscale_network::compression::decompress;
use hyperscale_network::{GossipVerdict, HandlerRegistry, parse_topic};
use hyperscale_types::ShardId;
use libp2p::PeerId as Libp2pPeerId;
use libp2p::gossipsub::{Event as GossipsubEvent, MessageAcceptance, MessageId};
use libp2p::swarm::SwarmEvent;
use tokio::spawn;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::behaviour::BehaviourEvent;
use crate::fault_gate::FaultState;

/// Validation result sent from the gossipsub handler back to the event loop.
///
/// The event loop drains these and calls `report_message_validation_result`
/// on the gossipsub behaviour, which controls message forwarding and peer scoring.
pub(super) struct ValidationReport {
    pub message_id: MessageId,
    pub propagation_source: Libp2pPeerId,
    pub acceptance: MessageAcceptance,
}

/// Guards a single message's verdict so gossipsub never leaks peer-scoring
/// state when a handler task panics or is cancelled.
///
/// Every gossipsub message handed up by the swarm must produce exactly one
/// `report_message_validation_result` call downstream — otherwise the
/// behaviour holds onto the message id forever and peer scoring drifts.
/// Construct one of these on entry to the spawned handler task; call
/// [`Self::report`] on the success / Reject paths; the `Drop` impl falls
/// back to `Ignore` if neither fired (panic / future cancel / early
/// return). `Ignore` is the right fallback — it does not penalise the
/// sender or propagate the message.
struct VerdictGuard {
    pending: Option<(MessageId, Libp2pPeerId)>,
    tx: mpsc::UnboundedSender<ValidationReport>,
}

impl VerdictGuard {
    const fn new(
        message_id: MessageId,
        propagation_source: Libp2pPeerId,
        tx: mpsc::UnboundedSender<ValidationReport>,
    ) -> Self {
        Self {
            pending: Some((message_id, propagation_source)),
            tx,
        }
    }

    fn report(&mut self, acceptance: MessageAcceptance) {
        if let Some((message_id, propagation_source)) = self.pending.take() {
            record_gossipsub_validation(acceptance_label(&acceptance));
            let _ = self.tx.send(ValidationReport {
                message_id,
                propagation_source,
                acceptance,
            });
        }
    }
}

impl Drop for VerdictGuard {
    fn drop(&mut self) {
        if let Some((message_id, propagation_source)) = self.pending.take() {
            warn!(
                peer = %propagation_source,
                "Gossip handler task ended without reporting a verdict; sending Ignore"
            );
            record_gossipsub_validation(acceptance_label(&MessageAcceptance::Ignore));
            let _ = self.tx.send(ValidationReport {
                message_id,
                propagation_source,
                acceptance: MessageAcceptance::Ignore,
            });
        }
    }
}

/// Stable string label for the gossipsub validation outcome metric.
const fn acceptance_label(acceptance: &MessageAcceptance) -> &'static str {
    match acceptance {
        MessageAcceptance::Accept => "accept",
        MessageAcceptance::Reject => "reject",
        MessageAcceptance::Ignore => "ignore",
    }
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
    local_shards: &std::collections::HashSet<ShardId>,
    registry: &Arc<HandlerRegistry>,
    validation_tx: &mpsc::UnboundedSender<ValidationReport>,
    fault_gate: &Arc<FaultState>,
) {
    match event {
        // Handle gossipsub messages
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(GossipsubEvent::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            // Parse topic immediately to determine message type and shard
            let topic_str = message.topic.as_str();
            let Some(parsed) = parse_topic(topic_str) else {
                warn!(
                    topic = %topic_str,
                    peer = %propagation_source,
                    "Received message with invalid topic format"
                );
                record_invalid_message();
                record_gossipsub_validation(acceptance_label(&MessageAcceptance::Reject));
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: MessageAcceptance::Reject,
                });
                return;
            };

            let data_len = message.data.len();

            // Record inbound bandwidth
            record_libp2p_bandwidth(data_len as u64, 0);

            let msg_type = parsed.message_type;

            // Fault gate: a matching drop rule or a partition against the origin
            // forces `Ignore`, which suppresses both local delivery and mesh
            // relay. Consulted before the handler spawn so a blocked message
            // never propagates inward.
            if fault_gate.drop_inbound_gossip(propagation_source, msg_type) {
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: MessageAcceptance::Ignore,
                });
                return;
            }

            // Shard-local messages must come from the local shard's topic.
            let is_shard_local_message =
                matches!(msg_type, "block.header" | "block.vote" | "execution.vote");

            if is_shard_local_message
                && let Some(topic_shard) = parsed.shard_id
                && !local_shards.contains(&topic_shard)
            {
                warn!(
                    topic = %topic_str,
                    topic_shard = topic_shard.inner(),
                    msg_type = msg_type,
                    "Dropping shard-local message from non-hosted shard (cross-shard contamination attempt)"
                );
                record_invalid_message();
                record_gossipsub_validation(acceptance_label(&MessageAcceptance::Reject));
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: MessageAcceptance::Reject,
                });
                return;
            }

            // Look up the per-type handler from the registry.
            let Some(handler) = registry.get_gossip(msg_type) else {
                warn!(
                    msg_type = msg_type,
                    "No gossip handler registered for message type, dropping"
                );
                // No handler is not the sender's fault — ignore rather than reject.
                record_gossipsub_validation(acceptance_label(&MessageAcceptance::Ignore));
                let _ = validation_tx.send(ValidationReport {
                    message_id,
                    propagation_source,
                    acceptance: MessageAcceptance::Ignore,
                });
                return;
            };

            // A Global-topic message (no shard in the topic) also reaches a
            // shard-less host's beacon-follower pool through the host-level
            // handler, additively to the per-hosted-shard fan above. Only
            // beacon-block gossip registers one; everything else resolves to
            // `None` and runs exactly as before.
            let topic_shard = parsed.shard_id;
            let host_handler = topic_shard
                .is_none()
                .then(|| registry.get_host_gossip(msg_type))
                .flatten();

            // Spawn decompress + handler off the event loop.
            // LZ4 decompression is fast (~4GB/s) but the handler includes
            // SBOR decode which we don't want to stall the swarm poll on.
            // `VerdictGuard` ensures gossipsub gets exactly one verdict per
            // message even if `handler` panics or the task is cancelled.
            let vtx = validation_tx.clone();
            spawn(async move {
                let mut guard = VerdictGuard::new(message_id, propagation_source, vtx);
                match decompress(&message.data) {
                    Ok(payload) => {
                        // The host-level follower delivers fire and forget;
                        // the per-shard fan owns the forward verdict.
                        if let Some(host_handler) = host_handler {
                            host_handler(payload.clone());
                        }
                        let verdict = handler(payload, topic_shard);
                        let acceptance = match verdict {
                            GossipVerdict::Accept => {
                                record_network_message_received();
                                MessageAcceptance::Accept
                            }
                            GossipVerdict::Reject => {
                                record_invalid_message();
                                MessageAcceptance::Reject
                            }
                        };
                        guard.report(acceptance);
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            peer = %propagation_source,
                            "Failed to decompress gossip message"
                        );
                        record_invalid_message();
                        guard.report(MessageAcceptance::Reject);
                    }
                }
            });
        }

        // Handle subscription events
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(GossipsubEvent::Subscribed {
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
