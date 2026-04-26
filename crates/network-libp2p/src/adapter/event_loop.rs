//! Async event loop processing swarm events and priority-ordered commands.
//!
//! Commands are processed in priority order:
//! 1. Critical priority (BFT consensus)
//! 2. Coordination priority (cross-shard execution)
//! 3. Finalization priority (certificate gossip)
//! 4. Propagation priority (transaction gossip)
//! 5. Background priority (sync operations)

use super::behaviour::{Behaviour, BehaviourEvent};
use super::command::{SwarmCommand, MAX_COMMANDS_PER_DRAIN};
use super::gossipsub::ValidationReport;
use crate::config::VersionInteroperabilityMode;
use dashmap::DashMap;
use futures::StreamExt;
use hyperscale_network::HandlerRegistry;
use hyperscale_types::{ShardGroupId, ValidatorId};
use libp2p::{
    gossipsub, identify, kad, swarm::SwarmEvent, Multiaddr, PeerId as Libp2pPeerId, Swarm,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Interval for periodic maintenance tasks in the event loop.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Delay before attempting to reconnect to a disconnected validator.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Interval for periodic Kademlia refresh to discover new peers.
const KADEMLIA_REFRESH_INTERVAL: Duration = Duration::from_mins(1);

/// Parse the hyperscale agent version format: `"hyperscale/<version>"`.
///
/// Returns the version string if the format is valid.
fn parse_hyperscale_version(agent_version: &str) -> Option<&str> {
    agent_version
        .strip_prefix("hyperscale/")
        .filter(|v| !v.is_empty())
}

/// Background event loop that processes swarm events and routes messages.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // single hot loop; splitting would scatter shared swarm state
pub(super) async fn run(
    mut swarm: Swarm<Behaviour>,
    mut critical_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut coordination_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut finalization_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut propagation_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut background_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut shutdown_rx: mpsc::Receiver<()>,
    cached_peer_count: Arc<AtomicUsize>,
    local_shard: ShardGroupId,
    version_interop_mode: VersionInteroperabilityMode,
    registry: Arc<HandlerRegistry>,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    validation_tx: mpsc::UnboundedSender<ValidationReport>,
    mut validation_rx: mpsc::UnboundedReceiver<ValidationReport>,
    bind_trigger_tx: mpsc::UnboundedSender<Libp2pPeerId>,
    bootstrap_peers: Vec<Multiaddr>,
) {
    // Track whether we've bootstrapped Kademlia (do it once after first connection)
    let mut kademlia_bootstrapped = false;

    // Maintenance timer for periodic tasks (reconnection, Kademlia refresh)
    let mut maintenance_interval = tokio::time::interval(MAINTENANCE_INTERVAL);
    maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Track last Kademlia refresh time
    let mut last_kademlia_refresh = std::time::Instant::now();

    // Track validators that need reconnection (peer_id -> scheduled_reconnect_time)
    let mut pending_reconnects: HashMap<Libp2pPeerId, std::time::Instant> = HashMap::new();

    // Track known validator addresses for reconnection
    // (peer_id -> last known address)
    let mut validator_addresses: HashMap<Libp2pPeerId, Multiaddr> = HashMap::new();

    loop {
        tokio::select! {
            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                info!("Shutting down libp2p network event loop");
                break;
            }

            // Periodic maintenance tasks
            _ = maintenance_interval.tick() => {
                let now = std::time::Instant::now();

                // Process pending reconnections
                let reconnects_due: Vec<_> = pending_reconnects
                    .iter()
                    .filter(|(_, scheduled)| now >= **scheduled)
                    .map(|(peer, _)| *peer)
                    .collect();

                for peer in reconnects_due {
                    pending_reconnects.remove(&peer);

                    // Reconnect if we have a known address and are not already connected
                    if !swarm.is_connected(&peer) {
                        if let Some(addr) = validator_addresses.get(&peer) {
                            info!(
                                peer = %peer,
                                addr = %addr,
                                "Attempting to reconnect to peer"
                            );
                            if let Err(e) = swarm.dial(addr.clone()) {
                                warn!(
                                    peer = %peer,
                                    error = ?e,
                                    "Failed to dial peer for reconnection"
                                );
                                // Schedule another reconnect attempt
                                pending_reconnects.insert(peer, now + RECONNECT_DELAY * 2);
                            }
                        } else {
                            // No known address, try to find via Kademlia
                            warn!(peer = %peer, "No known address for peer, relying on Kademlia discovery");
                        }
                    }
                }

                // Re-dial bootstrap peers if Kademlia hasn't bootstrapped yet.
                // Handles the case where bootstrap peers were down at startup.
                if !kademlia_bootstrapped && !bootstrap_peers.is_empty() {
                    for addr in &bootstrap_peers {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!(
                                addr = %addr,
                                error = ?e,
                                "Failed to re-dial bootstrap peer"
                            );
                        }
                    }
                }

                // Periodic Kademlia refresh for peer discovery
                if kademlia_bootstrapped && now.duration_since(last_kademlia_refresh) > KADEMLIA_REFRESH_INTERVAL {
                    // Trigger a random walk to discover new peers
                    let random_peer = Libp2pPeerId::random();
                    swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                    last_kademlia_refresh = now;
                    debug!("Triggered Kademlia refresh for peer discovery");
                }

                // Check connection health
                let connected_count = swarm.connected_peers().count();
                let known_peers = validator_addresses.len();
                if known_peers > 0 && connected_count < known_peers / 2 {
                    warn!(
                        connected = connected_count,
                        known_peers = known_peers,
                        "Low peer connectivity - connected to less than half of known peers"
                    );
                    // Trigger Kademlia bootstrap to find more peers
                    if kademlia_bootstrapped {
                        let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    }
                }
            }

            // Priority-ordered command processing.
            // Each priority level is checked in order, with higher priorities processed first.
            // Within each branch, we also drain higher-priority channels to maintain ordering.

            // Critical priority - BFT consensus messages (highest command priority)
            Some(cmd) = critical_rx.recv() => {
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut critical_rx);
            }

            // Coordination priority - Cross-shard execution messages
            Some(cmd) = coordination_rx.recv() => {
                drain_channel(&mut swarm, &mut critical_rx);
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut coordination_rx);
            }

            // Finalization priority - Certificate gossip
            Some(cmd) = finalization_rx.recv() => {
                drain_higher_priority_commands(
                    &mut swarm,
                    &mut critical_rx,
                    &mut coordination_rx,
                );
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut finalization_rx);
            }

            // Propagation priority - Transaction gossip (mempool)
            Some(cmd) = propagation_rx.recv() => {
                drain_all_higher_priority_commands(
                    &mut swarm,
                    &mut critical_rx,
                    &mut coordination_rx,
                    &mut finalization_rx,
                );
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut propagation_rx);
            }

            // Background priority - Sync operations (lowest priority)
            Some(cmd) = background_rx.recv() => {
                drain_all_higher_priority_commands(
                    &mut swarm,
                    &mut critical_rx,
                    &mut coordination_rx,
                    &mut finalization_rx,
                );
                drain_channel(&mut swarm, &mut propagation_rx);
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut background_rx);
            }

            // Drain gossipsub validation results and report to swarm.
            // This controls message forwarding (Accept) and peer scoring (Reject).
            Some(report) = validation_rx.recv() => {
                swarm.behaviour_mut().gossipsub.report_message_validation_result(
                    &report.message_id,
                    &report.propagation_source,
                    report.acceptance,
                );
            }

            // Handle swarm events
            event = swarm.select_next_some() => {
                // Check if this is a connection event that changes peer count
                let is_connection_event = matches!(
                    &event,
                    SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. }
                );

                // Handle Identify events — version check + trigger validator-bind
                if let SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) = &event {
                    let local_version = option_env!("HYPERSCALE_VERSION").unwrap_or("localdev");

                    if let Some(remote_version) = parse_hyperscale_version(&info.agent_version) {
                        info!(
                            peer = %peer_id,
                            version = %remote_version,
                            protocol_version = %info.protocol_version,
                            "Identified hyperscale peer"
                        );

                        // Version compatibility check
                        if version_interop_mode.check(local_version, remote_version) {
                            // Version OK — trigger the validator-bind protocol.
                            // The bind service will open a stream, exchange BLS-signed
                            // PeerId proofs, and register the ValidatorId → PeerId
                            // mapping on success.
                            let _ = bind_trigger_tx.send(*peer_id);
                        } else {
                            warn!(
                                peer = %peer_id,
                                local_version = %local_version,
                                remote_version = %remote_version,
                                mode = ?version_interop_mode,
                                "Peer version incompatible, disconnecting"
                            );
                            if swarm.disconnect_peer_id(*peer_id).is_err() {
                                warn!(peer = %peer_id, "Failed to disconnect incompatible peer");
                            }
                        }
                    } else {
                        warn!(
                            peer = %peer_id,
                            agent_version = %info.agent_version,
                            "Peer has unrecognised agent version format, disconnecting"
                        );
                        if swarm.disconnect_peer_id(*peer_id).is_err() {
                            warn!(peer = %peer_id, "Failed to disconnect non-hyperscale peer");
                        }
                    }
                }

                // Handle connection established — Kademlia routing + logging
                if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } = &event {
                    let addr = endpoint.get_remote_address().clone();
                    info!(
                        peer = %peer_id,
                        addr = %addr,
                        total_connections = num_established.get(),
                        "Connection established"
                    );

                    // Add peer to Kademlia routing table for peer discovery
                    swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
                    debug!(
                        peer = %peer_id,
                        addr = %addr,
                        "Added peer to Kademlia routing table"
                    );

                    // Track peer addresses for reconnection
                    validator_addresses.insert(*peer_id, addr);
                    // Clear any pending reconnect since we're now connected
                    pending_reconnects.remove(peer_id);

                    // Bootstrap Kademlia after first connection to start peer discovery
                    if !kademlia_bootstrapped {
                        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                            warn!("Failed to bootstrap Kademlia: {:?}", e);
                        } else {
                            info!("Kademlia bootstrap initiated for peer discovery");
                            kademlia_bootstrapped = true;
                        }
                    }
                }

                // Handle connection closed — reconnection scheduling + logging
                if let SwarmEvent::ConnectionClosed { peer_id, cause, num_established, connection_id, .. } = &event {
                    let cause_str = match &cause {
                        Some(e) => format!("{e:?}"),
                        None => "None (graceful)".to_string(),
                    };
                    warn!(
                        peer = %peer_id,
                        connection_id = ?connection_id,
                        cause = %cause_str,
                        remaining_connections = num_established,
                        "Connection closed"
                    );

                    // If this was the last connection to a peer, evict stale
                    // validator_peers entries and schedule reconnection.
                    if *num_established == 0 {
                        // Evict ValidatorId → PeerId mapping for this peer.
                        // DashMap doesn't have reverse lookup, so scan entries.
                        validator_peers.retain(|_vid, pid| *pid != *peer_id);

                        if validator_addresses.contains_key(peer_id) {
                            let reconnect_time = std::time::Instant::now() + RECONNECT_DELAY;
                            info!(
                                peer = %peer_id,
                                reconnect_in_secs = RECONNECT_DELAY.as_secs(),
                                "Peer disconnected, scheduling reconnection"
                            );
                            pending_reconnects.insert(*peer_id, reconnect_time);
                        }
                    }
                }

                // Handle new listen address
                if let SwarmEvent::NewListenAddr { address, .. } = &event {
                    info!("Listening on new address: {}", address);
                }

                // Handle Kademlia events for peer discovery
                if let SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad_event)) = &event {
                    match kad_event {
                        kad::Event::RoutingUpdated { peer, addresses, .. } => {
                            debug!(
                                peer = %peer,
                                num_addresses = addresses.len(),
                                "Kademlia routing table updated"
                            );
                            // Dial newly discovered peers
                            for addr in addresses.iter() {
                                if swarm.dial(addr.clone()).is_ok() {
                                    debug!(addr = %addr, "Dialing peer discovered via Kademlia");
                                }
                            }
                        }
                        kad::Event::OutboundQueryProgressed { result, .. } => {
                            if let kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })) = result {
                                debug!(num_remaining = num_remaining, "Kademlia bootstrap progress");
                            }
                        }
                        _ => {
                            trace!("Kademlia event: {:?}", kad_event);
                        }
                    }
                }

                // Delegate gossipsub messages to the event handler
                super::gossipsub::handle_gossipsub_event(
                    event,
                    local_shard,
                    &registry,
                    &validation_tx,
                );

                // Update cached peer count after connection changes
                if is_connection_event {
                    let count = swarm.connected_peers().count();
                    cached_peer_count.store(count, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Handle a single command from the adapter.
fn handle_command(swarm: &mut Swarm<Behaviour>, cmd: SwarmCommand) {
    match cmd {
        SwarmCommand::Subscribe { topic } => {
            let topic = gossipsub::IdentTopic::new(topic);
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!("Failed to subscribe to topic: {}", e);
            } else {
                info!("Subscribed to gossipsub topic: {}", topic);
            }
        }
        SwarmCommand::Broadcast { topic, data, .. } => {
            let topic_ident = gossipsub::IdentTopic::new(topic);
            let data_len = data.len();

            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic_ident.clone(), data)
            {
                // Duplicate errors are expected - multiple validators create the same
                // certificate and try to gossip it. Gossipsub correctly deduplicates.
                if matches!(e, gossipsub::PublishError::Duplicate) {
                    trace!(topic = %topic_ident, "Gossipsub duplicate (expected, already delivered)");
                } else {
                    // Other errors are significant - messages may be lost
                    warn!(
                        topic = %topic_ident,
                        data_len,
                        error = ?e,
                        peers = swarm.connected_peers().count(),
                        "Failed to publish message to gossipsub topic - message may be lost"
                    );
                    hyperscale_metrics::record_gossipsub_publish_failure(&topic_ident.to_string());
                }
            } else {
                trace!(topic = %topic_ident, data_len, "Published message to gossipsub topic");
            }
        }
        SwarmCommand::Dial { address } => {
            if let Err(e) = swarm.dial(address) {
                warn!("Failed to dial peer: {}", e);
            }
        }
        SwarmCommand::GetListenAddresses { response_tx } => {
            let addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
            let _ = response_tx.send(addrs);
        }
        SwarmCommand::GetConnectedPeers { response_tx } => {
            let peers: Vec<Libp2pPeerId> = swarm.connected_peers().copied().collect();
            let _ = response_tx.send(peers);
        }
    }
}

/// Drain up to [`MAX_COMMANDS_PER_DRAIN`] pending commands from a single channel.
fn drain_channel(swarm: &mut Swarm<Behaviour>, rx: &mut mpsc::UnboundedReceiver<SwarmCommand>) {
    for _ in 0..MAX_COMMANDS_PER_DRAIN {
        match rx.try_recv() {
            Ok(cmd) => handle_command(swarm, cmd),
            Err(_) => break,
        }
    }
}

/// Drain critical and coordination priority commands.
/// Used before processing finalization-level commands.
fn drain_higher_priority_commands(
    swarm: &mut Swarm<Behaviour>,
    critical_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    coordination_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
) {
    drain_channel(swarm, critical_rx);
    drain_channel(swarm, coordination_rx);
}

/// Drain all higher priority commands (critical, coordination, finalization).
/// Used before processing propagation and background level commands.
fn drain_all_higher_priority_commands(
    swarm: &mut Swarm<Behaviour>,
    critical_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    coordination_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    finalization_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
) {
    drain_channel(swarm, critical_rx);
    drain_channel(swarm, coordination_rx);
    drain_channel(swarm, finalization_rx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hyperscale_version_valid() {
        assert_eq!(parse_hyperscale_version("hyperscale/1.0.0"), Some("1.0.0"));
    }

    #[test]
    fn test_parse_hyperscale_version_localdev() {
        assert_eq!(
            parse_hyperscale_version("hyperscale/localdev"),
            Some("localdev")
        );
    }

    #[test]
    fn test_parse_hyperscale_version_with_slashes() {
        // Version part can contain slashes
        assert_eq!(
            parse_hyperscale_version("hyperscale/1.0.0/extra"),
            Some("1.0.0/extra")
        );
    }

    #[test]
    fn test_parse_hyperscale_version_wrong_prefix() {
        assert!(parse_hyperscale_version("other/1.0.0").is_none());
        assert!(parse_hyperscale_version("lighthouse/v5.1.0").is_none());
    }

    #[test]
    fn test_parse_hyperscale_version_empty_or_missing() {
        assert!(parse_hyperscale_version("hyperscale/").is_none());
        assert!(parse_hyperscale_version("hyperscale").is_none());
        assert!(parse_hyperscale_version("").is_none());
    }

    #[test]
    fn test_parse_hyperscale_version_legacy_format() {
        // Old format with embedded ValidatorId now returns vid as part of version
        // (harmless — version check will handle compatibility)
        assert_eq!(
            parse_hyperscale_version("hyperscale/42/1.0.0"),
            Some("42/1.0.0")
        );
    }
}
