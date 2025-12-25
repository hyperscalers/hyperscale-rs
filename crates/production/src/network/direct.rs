use super::config::Libp2pConfig;
use crate::metrics;
use crate::network::adapter::SwarmCommand;
use crate::network::NetworkError;
use dashmap::DashMap;
use hyperscale_core::OutboundMessage;
use hyperscale_types::{ShardGroupId, ValidatorId};
use libp2p::PeerId;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Direct validator network for high-performance consensus messaging.
///
/// Bypasses GossipSub for critical path messages (BlockHeader, BlockVote)
/// by sending directly to all committee members via persistent streams (unicast).
#[derive(Debug)]
pub struct DirectValidatorNetwork {
    /// Local validator ID.
    local_validator_id: ValidatorId,

    /// Command channel to the swarm (to send requests).
    swarm_command_tx: mpsc::UnboundedSender<SwarmCommand>,

    /// Map of ValidatorId -> PeerId for looking up destinations.
    /// Shared with the adapter.
    validator_peers: Arc<DashMap<ValidatorId, PeerId>>,

    /// Configuration for direct connections.
    #[allow(dead_code)]
    config: Libp2pConfig,

    /// Cached shard committees (Shard -> Validators).
    shard_committees: RwLock<HashMap<ShardGroupId, Vec<ValidatorId>>>,
}

impl DirectValidatorNetwork {
    /// Create a new direct validator network.
    pub fn new(
        local_validator_id: ValidatorId,
        swarm_command_tx: mpsc::UnboundedSender<SwarmCommand>,
        validator_peers: Arc<DashMap<ValidatorId, PeerId>>,
        config: Libp2pConfig,
    ) -> Self {
        info!(
            "Initializing DirectValidatorNetwork with limit={} timeout={:?}",
            config.direct_connection_limit, config.direct_connection_timeout
        );
        Self {
            local_validator_id,
            swarm_command_tx,
            validator_peers,
            config,
            shard_committees: RwLock::new(HashMap::new()),
        }
    }

    /// Update the committee for a shard.
    pub fn update_committee(&self, shard: ShardGroupId, validators: Vec<ValidatorId>) {
        let mut committees = self.shard_committees.write();
        committees.insert(shard, validators);
    }

    /// Get the committee for a shard.
    pub fn get_committee(&self, shard: ShardGroupId) -> Option<Vec<ValidatorId>> {
        self.shard_committees.read().get(&shard).cloned()
    }

    /// Broadcast a message to all members of a shard committee directly.
    ///
    /// This iterates over the provided committee members and sends the message
    /// to each one individually (unicast), bypassing the GossipSub mesh.
    pub fn broadcast_to_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
        committee: &[ValidatorId],
    ) -> Result<(), NetworkError> {
        let mut sent_count = 0;
        let mut fail_count = 0;

        // Encode once (if possible) - but Libp2pAdapter::broadcast_shard encodes inside.
        // Here we'll leverage a new SwarmCommand::DirectBroadcast or multiple DirectSend.
        // For now, let's assume we use multiple unicast requests.
        // Ideally, we want to encode ONCE.
        // But `SwarmCommand::DirectSend` (which we need to add) would take bytes.

        // Optimization: Encode message once here
        let data = super::codec::encode_message(message)?;
        let topic = super::codec::topic_for_message(message, shard);

        if committee.is_empty() {
            info!(
                msg_type = message.type_name(),
                "Direct broadcast to empty committee (skipping)"
            );
            return Ok(());
        }

        info!(
            msg_type = message.type_name(),
            topic = %topic,
            shard = shard.0,
            recipient_count = committee.len(),
            "Starting direct broadcast"
        );

        for &validator_id in committee {
            // Skip self
            if validator_id == self.local_validator_id {
                continue;
            }

            if let Some(peer_id) = self.validator_peers.get(&validator_id) {
                // Send direct message
                // We use a "fire and forget" style here, or rather, we send to the swarm
                // and let it handle the actual transmission.
                // We need to add `SwarmCommand::SendDirectMessage` to adapter.rs first.
                // For now, let's assume we reuse the Request-Response mechanism
                // BUT we want a 'one-way' stream if possible or just ignore response.
                // Actually `send_request` requires a response.
                //
                // If we want true "Direct Streams" as per proposal ("persistent TCP or QUIC streams"),
                // we should probably use `libp2p`'s `Stream` directly or a `OneShot` protocol.
                //
                // However, `request_response` is simplest to integrate.
                // Let's use `SwarmCommand::SendDirectMessage` which we will implement to use
                // a new `DirectMessage` protocol (fire-and-forget or simple ack).

                // Sending command to swarm is non-blocking (unbounded channel)
                let cmd = SwarmCommand::SendDirectMessage {
                    peer: *peer_id,
                    data: data.clone(),
                };

                if let Err(_e) = self.swarm_command_tx.send(cmd) {
                    warn!(
                        "Failed to queue direct message to validator {:?}",
                        validator_id
                    );
                    // If channel closed, we are shutting down
                    return Err(NetworkError::NetworkShutdown);
                } else {
                    info!(
                        msg_type = message.type_name(),
                        target = %validator_id,
                        peer = %*peer_id,
                        "Sent direct message"
                    );
                    sent_count += 1;
                }
            } else {
                // Validator peer not known yet
                // This is expected during startup or if validator is new
                debug!(
                    validator_id = validator_id.0,
                    "Validator peer ID unknown, skipping direct send"
                );
                fail_count += 1;
            }
        }

        // Detailed logging for significant broadcasts (like blocks)
        if message.type_name().contains("Block") {
            info!(
                msg_type = message.type_name(),
                sent = sent_count,
                missing_peers = fail_count,
                "Direct broadcast completed"
            );
        }

        // Metrics
        metrics::record_direct_message_sent(sent_count);

        Ok(())
    }

    /// Notify when a validator is connected (log it).
    pub fn on_validator_connected(&self, validator_id: ValidatorId, peer_id: PeerId) {
        info!(
            validator_id = validator_id.0,
            peer_id = %peer_id,
            "Direct validator stream connected/available"
        );
    }

    /// Notify when a validator is disconnected.
    pub fn on_validator_disconnected(&self, validator_id: ValidatorId, peer_id: PeerId) {
        warn!(
            validator_id = validator_id.0,
            peer_id = %peer_id,
            "Direct validator stream disconnected"
        );
    }
}
