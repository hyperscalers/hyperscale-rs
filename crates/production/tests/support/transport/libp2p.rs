//! Harness glue for the libp2p backend.

use std::sync::Arc;
use std::time::Duration;

pub use hyperscale_network_libp2p::fault::{DropSpec, HostId, Rewrite, RuleHandle};
pub use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use libp2p::{Multiaddr, PeerId};
use tokio::time::{sleep, timeout};

/// Budget for a freshly built host to surface a listen address.
const LISTEN_ADDR_TIMEOUT: Duration = Duration::from_secs(5);

/// What another host is given to connect to this one.
pub type Bootstrap = Multiaddr;

/// How the fault gate names a peer.
pub type PeerKey = PeerId;

/// What a host keeps to come back as the same peer. This backend takes a
/// fresh transport identity on every start, so there is nothing to keep.
pub struct HostKey;

pub const fn new_host_key() -> HostKey {
    HostKey
}

/// A localhost configuration bootstrapped to `bootstrap_peers`.
pub fn test_config(
    _key: &HostKey,
    bootstrap_peers: Vec<Bootstrap>,
    simulated_outbound_latency: Duration,
) -> Libp2pConfig {
    Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers,
        simulated_outbound_latency,
        ..Default::default()
    }
}

/// The address another host bootstraps to `adapter` by, once it is
/// listening.
pub async fn bootstrap_addr(adapter: &Arc<Libp2pAdapter>) -> Bootstrap {
    timeout(LISTEN_ADDR_TIMEOUT, async {
        loop {
            if let Some(addr) = adapter.listen_addresses().await.into_iter().next() {
                return addr;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the host surfaced a listen address")
}

pub const fn peer_key(adapter: &Libp2pAdapter) -> PeerKey {
    adapter.local_peer_id()
}
