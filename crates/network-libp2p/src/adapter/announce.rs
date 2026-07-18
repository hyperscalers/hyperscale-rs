//! Self-announcement of this host's validator addresses.
//!
//! Publishes one signed [`ValidatorAddressGossip`] per hosted vnode on the
//! Global gossip topic, carrying the swarm's externally observed and listen
//! addresses. Every node ingests these into its
//! [`AddressBook`](crate::address_book::AddressBook), which is what lets a
//! committee change dial validators that have never been connected.

use std::time::{SystemTime, UNIX_EPOCH};

use hyperscale_network::Topic;
use hyperscale_network::compression::compress;
use hyperscale_types::network::gossip::{MAX_ANNOUNCED_ADDRESSES, ValidatorAddressGossip};
use hyperscale_types::{NetworkDefinition, NetworkMessage, validator_address_message};
use libp2p::gossipsub::{IdentTopic, PublishError};
use libp2p::{Multiaddr, Swarm};
use sbor::basic_encode;
use tracing::{debug, trace, warn};

use super::behaviour::Behaviour;
use crate::validator_bind::LocalVnodeIdentity;

/// Publish one signed address record per hosted vnode. A no-op until the
/// swarm knows at least one own address; failures are logged and left to
/// the next periodic announce.
pub(super) fn announce_validator_addresses(
    swarm: &mut Swarm<Behaviour>,
    network: &NetworkDefinition,
    vnodes: &[LocalVnodeIdentity],
) {
    // Externally observed addresses first — they are what a remote peer can
    // actually dial when this host listens on a wildcard interface. The
    // literal listen addresses cover the flat-network case (and the local
    // test harness) where nothing observes us from outside.
    let mut addresses: Vec<Multiaddr> = swarm.external_addresses().cloned().collect();
    for addr in swarm.listeners() {
        if !addresses.contains(addr) {
            addresses.push(addr.clone());
        }
    }
    addresses.truncate(MAX_ANNOUNCED_ADDRESSES);
    if addresses.is_empty() {
        return;
    }

    let peer_bytes = swarm.local_peer_id().to_bytes();
    let address_bytes: Vec<Vec<u8>> = addresses.iter().map(Multiaddr::to_vec).collect();
    // Wall-clock milliseconds: orders re-announcements across process
    // restarts, which a per-process counter cannot.
    let sequence = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);

    let topic =
        IdentTopic::new(Topic::global(ValidatorAddressGossip::message_type_id()).to_string());
    for (validator, key) in vnodes {
        let signature = key.sign_v1(&validator_address_message(
            network,
            &peer_bytes,
            &address_bytes,
            sequence,
        ));
        let gossip = ValidatorAddressGossip {
            validator: *validator,
            peer_id: peer_bytes.clone(),
            addresses: address_bytes.clone(),
            sequence,
            signature,
        };
        let data = match basic_encode(&gossip) {
            Ok(bytes) => compress(&bytes),
            Err(e) => {
                warn!(error = ?e, "Failed to encode validator address announcement");
                return;
            }
        };
        match swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            Ok(_) => trace!(
                validator = validator.inner(),
                addresses = addresses.len(),
                "Announced validator addresses"
            ),
            // No mesh peers yet — routine at startup; the periodic announce
            // repeats once the mesh forms.
            Err(PublishError::NoPeersSubscribedToTopic) => debug!(
                validator = validator.inner(),
                "Validator address announce deferred: no gossipsub peers yet"
            ),
            Err(e) => warn!(
                validator = validator.inner(),
                error = ?e,
                "Failed to publish validator address announcement"
            ),
        }
    }
}
