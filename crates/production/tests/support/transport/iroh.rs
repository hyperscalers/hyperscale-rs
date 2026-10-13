//! Harness glue for the iroh backend.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

pub use hyperscale_network_iroh::fault::{DropSpec, HostId, Rewrite, RuleHandle};
pub use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::{EndpointAddr, EndpointId, IrohAdapter, IrohConfig, SecretKey};

/// What another host is given to connect to this one.
pub type Bootstrap = EndpointAddr;

/// How the fault gate names a peer.
pub type PeerKey = EndpointId;

/// What a host keeps to come back as the same peer: its network key.
pub type HostKey = SecretKey;

pub fn new_host_key() -> HostKey {
    SecretKey::generate()
}

/// A loopback configuration bootstrapped to `bootstrap_peers`: no relay
/// and no port mapping, every host at a socket address the others are
/// told.
pub fn test_config(
    key: &HostKey,
    bootstrap_peers: Vec<Bootstrap>,
    simulated_outbound_latency: Duration,
) -> IrohConfig {
    IrohConfig {
        bootstrap_peers,
        simulated_outbound_latency,
        ..IrohConfig::for_testing(key.clone(), (Ipv4Addr::LOCALHOST, 0).into())
    }
}

/// The address another host bootstraps to `adapter` by. The endpoint is
/// bound before the adapter exists, so there is nothing to wait for.
#[allow(clippy::unused_async)] // one signature across backends; the other waits for its listener
pub async fn bootstrap_addr(adapter: &Arc<IrohAdapter>) -> Bootstrap {
    adapter.endpoint_addr()
}

pub fn peer_key(adapter: &IrohAdapter) -> PeerKey {
    adapter.local_endpoint_id()
}
