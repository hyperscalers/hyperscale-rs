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
    /// This collects all target peers and sends them via a single DirectBroadcast
    /// command, enabling parallel sends in one event loop iteration.
    pub fn broadcast_to_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
        committee: &[ValidatorId],
    ) -> Result<(), NetworkError> {
        if committee.is_empty() {
            info!(
                msg_type = message.type_name(),
                "Direct broadcast to empty committee (skipping)"
            );
            return Ok(());
        }

        // Encode message once
        let data = super::codec::encode_direct_message(message)?;
        let topic = super::codec::topic_for_message(message, shard);

        // Collect all target peers
        let mut target_peers = Vec::with_capacity(committee.len());
        let mut missing_count = 0;

        for &validator_id in committee {
            // Skip self
            if validator_id == self.local_validator_id {
                continue;
            }

            if let Some(peer_id) = self.validator_peers.get(&validator_id) {
                target_peers.push(*peer_id);
            } else {
                // Validator peer not known yet
                debug!(
                    validator_id = validator_id.0,
                    "Validator peer ID unknown, skipping direct send"
                );
                missing_count += 1;
            }
        }

        if target_peers.is_empty() {
            debug!(
                msg_type = message.type_name(),
                missing = missing_count,
                "No target peers available for direct broadcast"
            );
            return Ok(());
        }

        // Send single batch command
        let cmd = SwarmCommand::DirectBroadcast {
            peers: target_peers.clone(),
            data,
        };

        if self.swarm_command_tx.send(cmd).is_err() {
            warn!("Failed to queue direct broadcast command (channel closed)");
            return Err(NetworkError::NetworkShutdown);
        }

        info!(
            msg_type = message.type_name(),
            topic = %topic,
            shard = shard.0,
            sent = target_peers.len(),
            missing = missing_count,
            "Direct broadcast queued"
        );

        // Metrics
        metrics::record_direct_message_sent(target_peers.len());

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
