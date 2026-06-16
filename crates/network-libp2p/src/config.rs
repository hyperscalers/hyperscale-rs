//! Network configuration types.

use std::time::Duration;

use libp2p::Multiaddr;

/// Configuration for the libp2p network adapter.
///
/// # Example
///
/// ```
/// use hyperscale_network_libp2p::Libp2pConfig;
/// use std::time::Duration;
///
/// let config = Libp2pConfig::default()
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

    /// Maximum message size in bytes.
    ///
    /// Default: 10MB
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval.
    ///
    /// Drives mesh maintenance and lazy IHAVE emission. Does not gate the
    /// fast-path forwarding of received messages, which is event-driven.
    /// At higher RTTs faster heartbeats just churn — the natural cadence
    /// for mesh repair is bounded by the network's round-trip anyway.
    pub gossipsub_heartbeat: Duration,

    /// Number of heartbeats of message history retained in the gossipsub
    /// mcache. Together with `gossipsub_heartbeat` this sets the IWANT
    /// recovery window: a peer that missed a message via the mesh has at
    /// most `gossipsub_heartbeat * gossipsub_history_length` to send IWANT
    /// before the message is evicted.
    pub gossipsub_history_length: usize,

    /// Idle connection timeout.
    ///
    /// Connections are closed after this duration of inactivity. Reduced from 60s
    /// to enable faster dead peer detection - important for shard consensus where
    /// view change timeout is 3-30s and we need quick peer rotation on failure.
    ///
    /// Default: 30 seconds
    pub idle_connection_timeout: Duration,

    /// QUIC keep-alive interval.
    ///
    /// Sends PING frames at this interval to keep connections alive and detect failures.
    /// Should be significantly less than `idle_connection_timeout` to prevent connection drops.
    ///
    /// Default: 15 seconds
    pub keep_alive_interval: Duration,

    /// Version interoperability mode.
    ///
    /// Default: Strict
    pub version_interop_mode: VersionInteroperabilityMode,

    /// Artificial per-message delay applied on every outbound send path
    /// (notifications, requests, and gossipsub publishes) before the frame
    /// hits the wire.
    ///
    /// `Duration::ZERO` (the default) is a no-op, so production is
    /// unaffected. It exists for localhost test clusters where zero network
    /// latency lets consensus race far faster than any real deployment:
    /// injecting a uniform one-way delay makes quorum-certificate formation
    /// pace to round-trips the way real inter-host RTTs do.
    pub simulated_outbound_latency: Duration,
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
    #[must_use]
    pub fn check(&self, local_version: &str, remote_version: &str) -> bool {
        match self {
            Self::Off => true,
            Self::Strict => local_version == remote_version,
            Self::Relaxed => {
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
            max_message_size: 1024 * 1024 * 10, // 10MB
            gossipsub_heartbeat: Duration::from_millis(300),
            gossipsub_history_length: 12,
            idle_connection_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(15),
            version_interop_mode: VersionInteroperabilityMode::Relaxed,
            simulated_outbound_latency: Duration::ZERO,
        }
    }
}

impl Libp2pConfig {
    /// Set the listen addresses.
    #[must_use]
    pub fn with_listen_addresses(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.listen_addresses = addrs;
        self
    }

    /// Set the bootstrap peers.
    #[must_use]
    pub fn with_bootstrap_peers(mut self, peers: Vec<Multiaddr>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    /// Set the maximum message size.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set the gossipsub heartbeat interval.
    #[must_use]
    pub const fn with_gossipsub_heartbeat(mut self, interval: Duration) -> Self {
        self.gossipsub_heartbeat = interval;
        self
    }

    /// Set the gossipsub history length (in heartbeats).
    #[must_use]
    pub const fn with_gossipsub_history_length(mut self, length: usize) -> Self {
        self.gossipsub_history_length = length;
        self
    }

    /// Set the idle connection timeout.
    #[must_use]
    pub const fn with_idle_connection_timeout(mut self, timeout: Duration) -> Self {
        self.idle_connection_timeout = timeout;
        self
    }

    /// Set the QUIC keep-alive interval.
    #[must_use]
    pub const fn with_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    /// Create config for local testing with specified port.
    ///
    /// # Panics
    ///
    /// Panics if the constructed multiaddr fails to parse — only possible
    /// if the `format!` template is broken, which would be caught at test time.
    #[must_use]
    pub fn for_testing(port: u16) -> Self {
        Self {
            listen_addresses: vec![
                format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                    .parse()
                    .unwrap(),
            ],
            bootstrap_peers: vec![],
            max_message_size: 1024 * 1024, // 1MB
            gossipsub_heartbeat: Duration::from_millis(500),
            gossipsub_history_length: 12,
            idle_connection_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            version_interop_mode: VersionInteroperabilityMode::Relaxed,
            simulated_outbound_latency: Duration::ZERO,
        }
    }

    /// Set the version interoperability mode.
    #[must_use]
    pub const fn with_version_interop_mode(mut self, mode: VersionInteroperabilityMode) -> Self {
        self.version_interop_mode = mode;
        self
    }

    /// Set the simulated per-message outbound latency (test clusters only).
    #[must_use]
    pub const fn with_simulated_outbound_latency(mut self, latency: Duration) -> Self {
        self.simulated_outbound_latency = latency;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Libp2pConfig::default();
        assert_eq!(config.max_message_size, 1024 * 1024 * 10); // 10MB
        assert_eq!(config.gossipsub_heartbeat, Duration::from_millis(300));
        assert_eq!(config.gossipsub_history_length, 12);
        assert!(!config.listen_addresses.is_empty());
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn test_builder_methods() {
        let config = Libp2pConfig::default()
            .with_max_message_size(128 * 1024)
            .with_gossipsub_heartbeat(Duration::from_millis(500));

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
