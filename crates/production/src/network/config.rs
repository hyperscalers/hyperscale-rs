//! Network configuration types.

use libp2p::Multiaddr;
use std::time::Duration;

/// Configuration for the libp2p network adapter.
///
/// # Example
///
/// ```
/// use hyperscale_production::network::Libp2pConfig;
/// use std::time::Duration;
///
/// let config = Libp2pConfig::default()
///     .with_request_timeout(Duration::from_secs(60))
///     .with_gossipsub_heartbeat(Duration::from_millis(500));
/// ```
#[derive(Debug, Clone)]
pub struct Libp2pConfig {
    /// Addresses to listen on.
    ///
    /// Default: `/ip4/0.0.0.0/udp/0/quic-v1` (random port, QUIC transport)
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap peer addresses for initial connection.
    ///
    /// Default: empty (no bootstrap peers)
    pub bootstrap_peers: Vec<Multiaddr>,

    /// Timeout for request-response operations (e.g., sync block fetch).
    ///
    /// Default: 30 seconds
    pub request_timeout: Duration,

    /// Maximum message size in bytes.
    ///
    /// Default: 1MB
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval.
    ///
    /// Default: 1 second
    pub gossipsub_heartbeat: Duration,

    /// Idle connection timeout.
    ///
    /// Default: 60 seconds
    pub idle_connection_timeout: Duration,
}

impl Default for Libp2pConfig {
    fn default() -> Self {
        Self {
            // Use QUIC by default with random port
            listen_addresses: vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()],
            bootstrap_peers: vec![],
            request_timeout: Duration::from_secs(30),
            max_message_size: 1024 * 1024, // 1MB
            gossipsub_heartbeat: Duration::from_secs(1),
            idle_connection_timeout: Duration::from_secs(60),
        }
    }
}

impl Libp2pConfig {
    /// Set the listen addresses.
    pub fn with_listen_addresses(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.listen_addresses = addrs;
        self
    }

    /// Set the bootstrap peers.
    pub fn with_bootstrap_peers(mut self, peers: Vec<Multiaddr>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    /// Set the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the maximum message size.
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set the gossipsub heartbeat interval.
    pub fn with_gossipsub_heartbeat(mut self, interval: Duration) -> Self {
        self.gossipsub_heartbeat = interval;
        self
    }

    /// Set the idle connection timeout.
    pub fn with_idle_connection_timeout(mut self, timeout: Duration) -> Self {
        self.idle_connection_timeout = timeout;
        self
    }

    /// Create config for local testing with specified port.
    pub fn for_testing(port: u16) -> Self {
        Self {
            listen_addresses: vec![format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
                .parse()
                .unwrap()],
            bootstrap_peers: vec![],
            request_timeout: Duration::from_secs(5),
            max_message_size: 1024 * 1024, // 1MB
            gossipsub_heartbeat: Duration::from_millis(500),
            idle_connection_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Libp2pConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert_eq!(config.gossipsub_heartbeat, Duration::from_secs(1));
        assert!(!config.listen_addresses.is_empty());
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn test_builder_methods() {
        let config = Libp2pConfig::default()
            .with_request_timeout(Duration::from_secs(60))
            .with_max_message_size(128 * 1024)
            .with_gossipsub_heartbeat(Duration::from_millis(500));

        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.max_message_size, 128 * 1024);
        assert_eq!(config.gossipsub_heartbeat, Duration::from_millis(500));
    }

    #[test]
    fn test_for_testing() {
        let config = Libp2pConfig::for_testing(9000);
        assert_eq!(
            config.listen_addresses[0].to_string(),
            "/ip4/127.0.0.1/udp/9000/quic-v1"
        );
        assert_eq!(config.request_timeout, Duration::from_secs(5));
    }
}
