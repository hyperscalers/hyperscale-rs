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

    /// QUIC keep-alive interval.
    ///
    /// Sends PING frames at this interval to keep connections alive and detect failures.
    /// Should be significantly less than `idle_connection_timeout` to prevent connection drops.
    ///
    /// Default: 15 seconds
    pub keep_alive_interval: Duration,

    /// Whether to enable TCP fallback transport alongside QUIC.
    ///
    /// When enabled, the node will listen on TCP as well as QUIC,
    /// providing fallback connectivity when UDP is blocked.
    ///
    /// Default: true
    pub tcp_fallback_enabled: bool,

    /// TCP fallback port (only used when tcp_fallback_enabled is true).
    ///
    /// Default: None (uses QUIC port + 21500 offset)
    pub tcp_fallback_port: Option<u16>,

    /// Version interoperability mode.
    ///
    /// Default: Strict
    pub version_interop_mode: VersionInteroperabilityMode,

    /// Maximum number of direct validator connections.
    ///
    /// Default: 50
    pub direct_connection_limit: usize,

    /// Timeout for direct validator connection attempts.
    ///
    /// Default: 10 seconds
    pub direct_connection_timeout: Duration,
}

/// Mode for version interoperability checks.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum VersionInteroperabilityMode {
    /// Versions must match exactly.
    #[default]
    Strict,
    /// Major and minor versions must match (e.g. 1.3.0 compatible with 1.3.1).
    Relaxed,
    /// No version check.
    Off,
}

impl VersionInteroperabilityMode {
    /// Check if two versions are compatible according to this mode.
    pub fn check(&self, local_version: &str, remote_version: &str) -> bool {
        match self {
            VersionInteroperabilityMode::Off => true,
            VersionInteroperabilityMode::Strict => local_version == remote_version,
            VersionInteroperabilityMode::Relaxed => {
                // Check if major/minor versions match (e.g., 1.3.x)
                let local_parts: Vec<&str> = local_version.split('.').collect();
                let remote_parts: Vec<&str> = remote_version.split('.').collect();

                if local_parts.len() >= 2 && remote_parts.len() >= 2 {
                    local_parts[0] == remote_parts[0] && local_parts[1] == remote_parts[1]
                } else {
                    // If version format doesn't match expected X.Y.Z, fallback to exact match
                    local_version == remote_version
                }
            }
        }
    }
}

impl Default for Libp2pConfig {
    fn default() -> Self {
        Self {
            // Use QUIC by default with random port
            listen_addresses: vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap()],
            bootstrap_peers: vec![],
            // 5 second timeout for request-response operations.
            // This is the hard backstop - RequestManager handles retry logic above this layer.
            request_timeout: Duration::from_secs(5),
            max_message_size: 1024 * 1024 * 10, // 10MB
            gossipsub_heartbeat: Duration::from_millis(100),
            idle_connection_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(15),
            tcp_fallback_enabled: true,
            tcp_fallback_port: None,
            version_interop_mode: VersionInteroperabilityMode::Relaxed,
            direct_connection_limit: 50,
            direct_connection_timeout: Duration::from_secs(10),
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

    /// Set the QUIC keep-alive interval.
    pub fn with_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    /// Enable or disable TCP fallback transport.
    pub fn with_tcp_fallback(mut self, enabled: bool, port: Option<u16>) -> Self {
        self.tcp_fallback_enabled = enabled;
        self.tcp_fallback_port = port;
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
            keep_alive_interval: Duration::from_secs(10),
            tcp_fallback_enabled: true,
            tcp_fallback_port: None,
            version_interop_mode: VersionInteroperabilityMode::Relaxed,
            direct_connection_limit: 50,
            direct_connection_timeout: Duration::from_secs(5),
        }
    }

    /// Set the version interoperability mode.
    pub fn with_version_interop_mode(mut self, mode: VersionInteroperabilityMode) -> Self {
        self.version_interop_mode = mode;
        self
    }

    /// Set the direct connection limit.
    pub fn with_direct_connection_limit(mut self, limit: usize) -> Self {
        self.direct_connection_limit = limit;
        self
    }

    /// Set the direct connection timeout.
    pub fn with_direct_connection_timeout(mut self, timeout: Duration) -> Self {
        self.direct_connection_timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Libp2pConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(5));
        assert_eq!(config.max_message_size, 1024 * 1024 * 10); // 10MB
        assert_eq!(config.gossipsub_heartbeat, Duration::from_millis(100));
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

    #[test]
    fn test_version_compatibility() {
        // Strict mode
        assert!(VersionInteroperabilityMode::Strict.check("1.0.0", "1.0.0"));
        assert!(!VersionInteroperabilityMode::Strict.check("1.0.0", "1.0.1"));
        assert!(!VersionInteroperabilityMode::Strict.check("1.0.0", "1.1.0"));

        // Relaxed mode
        assert!(VersionInteroperabilityMode::Relaxed.check("1.3.0", "1.3.1"));
        assert!(VersionInteroperabilityMode::Relaxed.check("1.3.0", "1.3.0.1"));
        assert!(VersionInteroperabilityMode::Relaxed.check("1.3.5", "1.3.0"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("1.3.0", "1.4.0"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("1.3.0", "2.3.0"));
        // Fallback for non-semver
        assert!(VersionInteroperabilityMode::Relaxed.check("localdev", "localdev"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("localdev", "other"));

        // Off mode
        assert!(VersionInteroperabilityMode::Off.check("1.0.0", "2.0.0"));
        assert!(VersionInteroperabilityMode::Off.check("anything", "everything"));
    }
}
