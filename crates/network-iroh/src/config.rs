//! Network configuration types.

use std::net::SocketAddr;
use std::time::Duration;

use clap::ValueEnum;
use iroh::{EndpointAddr, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};

/// Most relays a host names in its signed address record. The endpoint
/// homes on one at a time, so the second is a failover, and more would
/// only widen what a record can make its readers connect to.
pub const MAX_RELAYS: usize = 2;

/// Configuration for the iroh network adapter.
#[derive(Debug, Clone)]
pub struct IrohConfig {
    /// The host's network key: its endpoint identity, stable across
    /// restarts and distinct from every consensus key.
    pub secret_key: SecretKey,

    /// Socket to bind. `None` binds every interface on a free port, in both
    /// address families.
    pub bind_addr: Option<SocketAddr>,

    /// Relays this host homes on, at most [`MAX_RELAYS`]. Empty disables
    /// relaying: the host is then reachable only at its socket addresses.
    pub relays: Vec<RelayUrl>,

    /// Addresses at which this host is known to be reachable from outside,
    /// advertised beside what the endpoint discovers for itself.
    pub external_addrs: Vec<SocketAddr>,

    /// Hosts to connect to at start, before any signed address record has
    /// arrived.
    pub bootstrap_peers: Vec<EndpointAddr>,

    /// Whether to ask the local router for a port mapping.
    pub port_mapping: bool,

    /// Idle time after which a path is abandoned, bounding how long a dead
    /// direct path holds a connection before it falls back to the relay.
    /// `None` keeps the library default.
    pub path_idle_timeout: Option<Duration>,

    /// Interval of the keep alive that holds each path open. `None` keeps
    /// the library default.
    pub path_keep_alive: Option<Duration>,

    /// Version interoperability mode.
    pub version_interop_mode: VersionInteroperabilityMode,

    /// Artificial delay applied on every outbound send path before the
    /// frame is written. `Duration::ZERO` is a no-op, so production is
    /// unaffected; localhost test clusters set it so consensus paces to
    /// round trips the way it does between real hosts.
    pub simulated_outbound_latency: Duration,
}

impl IrohConfig {
    /// A configuration with a fresh network key, no relay, and no peers.
    #[must_use]
    pub const fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            bind_addr: None,
            relays: Vec::new(),
            external_addrs: Vec::new(),
            bootstrap_peers: Vec::new(),
            port_mapping: true,
            path_idle_timeout: None,
            path_keep_alive: None,
            version_interop_mode: VersionInteroperabilityMode::Relaxed,
            simulated_outbound_latency: Duration::ZERO,
        }
    }

    /// A configuration for a host on loopback: one fixed socket, no relay,
    /// no port mapping.
    #[must_use]
    pub fn for_testing(secret_key: SecretKey, bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr: Some(bind_addr),
            port_mapping: false,
            ..Self::new(secret_key)
        }
    }
}

/// Mode for version interoperability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
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
    pub(crate) fn check(self, local_version: &str, remote_version: &str) -> bool {
        match self {
            Self::Off => true,
            Self::Strict => local_version == remote_version,
            Self::Relaxed => {
                let local_parts: Vec<&str> = local_version.split('.').collect();
                let remote_parts: Vec<&str> = remote_version.split('.').collect();

                if local_parts.len() >= 2 && remote_parts.len() >= 2 {
                    local_parts[0] == remote_parts[0] && local_parts[1] == remote_parts[1]
                } else {
                    // A version that is not `X.Y.Z` falls back to exact match.
                    local_version == remote_version
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compatibility_follows_the_mode() {
        assert!(VersionInteroperabilityMode::Strict.check("1.0.0", "1.0.0"));
        assert!(!VersionInteroperabilityMode::Strict.check("1.0.0", "1.0.1"));

        assert!(VersionInteroperabilityMode::Relaxed.check("1.3.0", "1.3.1"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("1.3.0", "1.4.0"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("1.3.0", "2.3.0"));
        assert!(VersionInteroperabilityMode::Relaxed.check("localdev", "localdev"));
        assert!(!VersionInteroperabilityMode::Relaxed.check("localdev", "other"));

        assert!(VersionInteroperabilityMode::Off.check("1.0.0", "2.0.0"));
    }

    #[test]
    fn a_testing_configuration_stays_on_its_socket() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = IrohConfig::for_testing(SecretKey::from_bytes(&[1; 32]), addr);
        assert_eq!(config.bind_addr, Some(addr));
        assert!(!config.port_mapping);
        assert!(config.relays.is_empty());
    }
}
