//! Async event loop processing swarm events and class-ordered commands.
//!
//! Commands are processed in class order, most-urgent first:
//! 1. Consensus (shard round-blocking)
//! 2. `BlockCompletion` (current-proposal DA gap closure)
//! 3. `CrossShardProgress` (execution & finalization coordination)
//! 4. Recovery (catch-up traffic)
//! 5. Bulk (transaction gossip, fetch-fallback-backed)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::StreamExt;
use hyperscale_metrics::record_gossipsub_publish_failure;
use hyperscale_network::HandlerRegistry;
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId};
use libp2p::gossipsub::{IdentTopic, PublishError};
use libp2p::identify::Event as IdentifyEvent;
use libp2p::kad::{BootstrapOk, Event as KadEvent, QueryResult};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{Multiaddr, PeerId as Libp2pPeerId, Swarm};
use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, trace, warn};

use super::announce::announce_validator_addresses;
use super::behaviour::{Behaviour, BehaviourEvent};
use super::command::{MAX_COMMANDS_PER_DRAIN, SwarmCommand};
use super::gossipsub::ValidationReport;
use crate::address_book::AddressBook;
use crate::config::VersionInteroperabilityMode;
use crate::fault_gate::FaultState;
use crate::validator_bind::LocalVnodeIdentity;

/// Interval for periodic maintenance tasks in the event loop.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Delay before attempting to reconnect to a disconnected validator.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Interval for periodic Kademlia refresh to discover new peers.
const KADEMLIA_REFRESH_INTERVAL: Duration = Duration::from_mins(1);

/// Interval between validator address announcements. Also the worst-case
/// staleness a peer's book carries after this host changes addresses.
const ADDRESS_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum spacing between address-book dial attempts to the same peer, so
/// the maintenance tick doesn't hammer an unreachable one.
const ADDRESS_DIAL_RETRY: Duration = Duration::from_secs(30);

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
    mut consensus_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut block_completion_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut cross_shard_progress_rx: mpsc::UnboundedReceiver<SwarmCommand>,
    mut recovery_rx: mpsc::Receiver<SwarmCommand>,
    mut bulk_rx: mpsc::Receiver<SwarmCommand>,
    mut shutdown_rx: mpsc::Receiver<()>,
    cached_peer_count: Arc<AtomicUsize>,
    local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
    version_interop_mode: VersionInteroperabilityMode,
    registry: Arc<HandlerRegistry>,
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,
    validation_tx: mpsc::UnboundedSender<ValidationReport>,
    mut validation_rx: mpsc::UnboundedReceiver<ValidationReport>,
    bind_trigger_tx: mpsc::UnboundedSender<Libp2pPeerId>,
    bootstrap_peers: Vec<Multiaddr>,
    fault_gate: Arc<FaultState>,
    network: NetworkDefinition,
    local_vnodes: Arc<[LocalVnodeIdentity]>,
    wanted_validators: Arc<ArcSwap<HashSet<ValidatorId>>>,
    address_book: Arc<AddressBook>,
) {
    // Track whether we've bootstrapped Kademlia (do it once after first connection)
    let mut kademlia_bootstrapped = false;

    // Maintenance timer for periodic tasks (reconnection, Kademlia refresh)
    let mut maintenance_interval = interval(MAINTENANCE_INTERVAL);
    maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Periodic self-announcement of this host's validator addresses.
    let mut announce_interval = interval(ADDRESS_ANNOUNCE_INTERVAL);
    announce_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Track last Kademlia refresh time
    let mut last_kademlia_refresh = Instant::now();

    // Track validators that need reconnection (peer_id -> scheduled_reconnect_time)
    let mut pending_reconnects: HashMap<Libp2pPeerId, Instant> = HashMap::new();

    // Track known validator addresses for reconnection
    // (peer_id -> last known address)
    let mut validator_addresses: HashMap<Libp2pPeerId, Multiaddr> = HashMap::new();

    // Last address-book dial attempt per peer, so an unreachable wanted
    // validator is retried at ADDRESS_DIAL_RETRY pace, not every tick.
    let mut recent_dials: HashMap<Libp2pPeerId, Instant> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Shutting down libp2p network event loop");
                break;
            }

            _ = maintenance_interval.tick() => {
                let now = Instant::now();

                let reconnects_due: Vec<_> = pending_reconnects
                    .iter()
                    .filter(|(_, scheduled)| now >= **scheduled)
                    .map(|(peer, _)| *peer)
                    .collect();

                for peer in reconnects_due {
                    pending_reconnects.remove(&peer);

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
                                pending_reconnects.insert(peer, now + RECONNECT_DELAY * 2);
                            }
                        } else {
                            warn!(peer = %peer, "No known address for peer, relying on Kademlia discovery");
                        }
                    }
                }

                // Re-dial bootstrap peers if Kademlia hasn't bootstrapped yet —
                // covers the case where bootstrap peers were down at startup.
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

                // Establish links to wanted-but-unbound validators from the
                // address book. The seat-triggered pass in
                // `update_wanted_validators` covers the common case; this
                // sweep heals its races — a committee seated before the
                // target's announcement arrived, a failed dial — at
                // maintenance pace.
                dial_wanted_validators(
                    &mut swarm,
                    &wanted_validators.load(),
                    &address_book,
                    &validator_peers,
                    &mut recent_dials,
                );

                // Periodic Kademlia random-walk to discover new peers.
                if kademlia_bootstrapped && now.saturating_duration_since(last_kademlia_refresh) > KADEMLIA_REFRESH_INTERVAL {
                    let random_peer = Libp2pPeerId::random();
                    swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                    last_kademlia_refresh = now;
                    debug!("Triggered Kademlia refresh for peer discovery");
                }

                let connected_count = swarm.connected_peers().count();
                let known_peers = validator_addresses.len();
                if known_peers > 0 && connected_count < known_peers / 2 {
                    warn!(
                        connected = connected_count,
                        known_peers = known_peers,
                        "Low peer connectivity - connected to less than half of known peers"
                    );
                    if kademlia_bootstrapped {
                        let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    }
                }
            }

            // Class-ordered command processing.
            // Each class is checked in order; before handling a less-urgent
            // command we drain every more-urgent channel to maintain strict
            // priority.

            // Consensus — shard round-blocking traffic.
            Some(cmd) = consensus_rx.recv() => {
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut consensus_rx);
            }

            // BlockCompletion — current-proposal DA gap closure.
            Some(cmd) = block_completion_rx.recv() => {
                drain_channel(&mut swarm, &mut consensus_rx);
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut block_completion_rx);
            }

            // CrossShardProgress — execution & finalization coordination.
            Some(cmd) = cross_shard_progress_rx.recv() => {
                drain_higher_priority_commands(
                    &mut swarm,
                    &mut consensus_rx,
                    &mut block_completion_rx,
                );
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut cross_shard_progress_rx);
            }

            // Recovery — catch-up traffic.
            Some(cmd) = recovery_rx.recv() => {
                drain_all_higher_priority_commands(
                    &mut swarm,
                    &mut consensus_rx,
                    &mut block_completion_rx,
                    &mut cross_shard_progress_rx,
                );
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut recovery_rx);
            }

            // Bulk — transaction gossip; fetch-fallback-backed and sheddable.
            Some(cmd) = bulk_rx.recv() => {
                drain_all_higher_priority_commands(
                    &mut swarm,
                    &mut consensus_rx,
                    &mut block_completion_rx,
                    &mut cross_shard_progress_rx,
                );
                drain_channel(&mut swarm, &mut recovery_rx);
                handle_command(&mut swarm, cmd);
                drain_channel(&mut swarm, &mut bulk_rx);
            }

            // Announce this host's validator addresses so every node's book
            // can resolve us for by-identity dialing. The first tick fires
            // immediately (usually before any listen address exists — a
            // no-op); NewListenAddr below covers prompt startup announcement.
            _ = announce_interval.tick() => {
                announce_validator_addresses(&mut swarm, &network, &local_vnodes);
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

            event = swarm.select_next_some() => {
                let is_connection_event = matches!(
                    &event,
                    SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. }
                );

                // Identify events drive version compatibility check + validator-bind handshake.
                if let SwarmEvent::Behaviour(BehaviourEvent::Identify(IdentifyEvent::Received { peer_id, info, .. })) = &event {
                    let local_version = option_env!("HYPERSCALE_VERSION").unwrap_or("localdev");

                    if let Some(remote_version) = parse_hyperscale_version(&info.agent_version) {
                        info!(
                            peer = %peer_id,
                            version = %remote_version,
                            protocol_version = %info.protocol_version,
                            "Identified hyperscale peer"
                        );

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
                    let cause_str = cause
                        .as_ref()
                        .map_or_else(|| "None (graceful)".to_string(), |e| format!("{e:?}"));
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
                            let reconnect_time = Instant::now() + RECONNECT_DELAY;
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
                    // Re-announce right away — usually still without mesh
                    // peers at startup, but a runtime address change
                    // propagates without waiting for the periodic tick.
                    announce_validator_addresses(&mut swarm, &network, &local_vnodes);
                }

                // Handle Kademlia events for peer discovery
                if let SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad_event)) = &event {
                    match kad_event {
                        KadEvent::RoutingUpdated { peer, addresses, .. } => {
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
                        KadEvent::OutboundQueryProgressed { result, .. } => {
                            if let QueryResult::Bootstrap(Ok(BootstrapOk { num_remaining, .. })) = result {
                                debug!(num_remaining = num_remaining, "Kademlia bootstrap progress");
                            }
                        }
                        _ => {
                            trace!("Kademlia event: {:?}", kad_event);
                        }
                    }
                }

                // Delegate gossipsub messages to the event handler. The
                // hosted set is loaded per event so shards added or
                // dropped at runtime are filtered correctly.
                super::gossipsub::handle_gossipsub_event(
                    event,
                    &local_shards.load(),
                    &registry,
                    &validation_tx,
                    &fault_gate,
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
            let topic = IdentTopic::new(topic);
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!("Failed to subscribe to topic: {}", e);
            } else {
                info!("Subscribed to gossipsub topic: {}", topic);
            }
        }
        SwarmCommand::Unsubscribe { topic } => {
            let topic = IdentTopic::new(topic);
            if swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                info!("Unsubscribed from gossipsub topic: {}", topic);
            }
        }
        SwarmCommand::Broadcast { topic, data, .. } => {
            let topic_ident = IdentTopic::new(topic);
            let data_len = data.len();

            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic_ident.clone(), data)
            {
                // Duplicate errors are expected - multiple validators create the same
                // certificate and try to gossip it. Gossipsub correctly deduplicates.
                if matches!(e, PublishError::Duplicate) {
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
                    record_gossipsub_publish_failure(&topic_ident.to_string());
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
        SwarmCommand::DialPeer { peer_id, addresses } => {
            dial_peer_at(swarm, peer_id, addresses);
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

/// Dial `peer_id` at `addresses`. The peer-conditioned dial makes this
/// idempotent: an already-connected or already-dialing peer resolves
/// [`DialError::DialPeerConditionFalse`], logged at trace and otherwise a
/// no-op, so callers can re-issue freely.
fn dial_peer_at(swarm: &mut Swarm<Behaviour>, peer_id: Libp2pPeerId, addresses: Vec<Multiaddr>) {
    let opts = DialOpts::peer_id(peer_id).addresses(addresses).build();
    match swarm.dial(opts) {
        Ok(()) => debug!(peer = %peer_id, "Dialing validator from address book"),
        Err(DialError::DialPeerConditionFalse(_)) => {
            trace!(peer = %peer_id, "Dial skipped: already connected or dialing");
        }
        Err(e) => debug!(peer = %peer_id, error = ?e, "Address-book dial failed"),
    }
}

/// One pass of the wanted-validator dial loop: resolve every wanted,
/// unbound validator through the address book and dial it, remembering
/// each attempt so an unreachable peer is retried no more often than
/// [`ADDRESS_DIAL_RETRY`]. Connected peers whose bind is still in flight
/// are skipped — the bind service owns that hand-off.
fn dial_wanted_validators(
    swarm: &mut Swarm<Behaviour>,
    wanted: &HashSet<ValidatorId>,
    address_book: &AddressBook,
    validator_peers: &DashMap<ValidatorId, Libp2pPeerId>,
    recent_dials: &mut HashMap<Libp2pPeerId, Instant>,
) {
    let now = Instant::now();
    recent_dials.retain(|_, attempted| now.duration_since(*attempted) < ADDRESS_DIAL_RETRY);
    for record in address_book.dial_candidates(wanted, validator_peers) {
        if swarm.is_connected(&record.peer_id) || recent_dials.contains_key(&record.peer_id) {
            continue;
        }
        recent_dials.insert(record.peer_id, now);
        dial_peer_at(swarm, record.peer_id, record.addresses);
    }
}

/// `try_recv` shim so [`drain_channel`] can drive both `UnboundedReceiver`
/// (hot lanes) and `Receiver` (sheddable bounded lanes) without a second
/// helper.
trait TryRecvCmd {
    fn try_recv(&mut self) -> Result<SwarmCommand, mpsc::error::TryRecvError>;
}

impl TryRecvCmd for mpsc::UnboundedReceiver<SwarmCommand> {
    fn try_recv(&mut self) -> Result<SwarmCommand, mpsc::error::TryRecvError> {
        Self::try_recv(self)
    }
}

impl TryRecvCmd for mpsc::Receiver<SwarmCommand> {
    fn try_recv(&mut self) -> Result<SwarmCommand, mpsc::error::TryRecvError> {
        Self::try_recv(self)
    }
}

/// Drain up to [`MAX_COMMANDS_PER_DRAIN`] pending commands from a single channel.
fn drain_channel<R: TryRecvCmd>(swarm: &mut Swarm<Behaviour>, rx: &mut R) {
    for _ in 0..MAX_COMMANDS_PER_DRAIN {
        match rx.try_recv() {
            Ok(cmd) => handle_command(swarm, cmd),
            Err(_) => break,
        }
    }
}

/// Drain `Consensus` and `BlockCompletion` commands.
/// Called before processing a `CrossShardProgress`-class command.
fn drain_higher_priority_commands(
    swarm: &mut Swarm<Behaviour>,
    consensus_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    block_completion_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
) {
    drain_channel(swarm, consensus_rx);
    drain_channel(swarm, block_completion_rx);
}

/// Drain all classes more urgent than `Recovery`.
/// Called before processing a `Recovery` or `Bulk` class command.
fn drain_all_higher_priority_commands(
    swarm: &mut Swarm<Behaviour>,
    consensus_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    block_completion_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
    cross_shard_progress_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
) {
    drain_channel(swarm, consensus_rx);
    drain_channel(swarm, block_completion_rx);
    drain_channel(swarm, cross_shard_progress_rx);
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
