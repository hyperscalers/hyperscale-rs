//! Network configuration types.

use std::net::SocketAddr;
use std::time::Duration;

use clap::ValueEnum;
use iroh::dns::DnsResolver;
use iroh::tls::CaTlsConfig;
use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use serde::{Deserialize, Serialize};

use crate::path::{RedialBudget, RedialSchedule};

/// Most relays a host names in its signed address record. The endpoint
/// homes on one at a time, so the second is a failover, and more would
/// only widen what a record can make its readers connect to.
///
/// A host may configure more; it homes on the nearest that admits it.
pub const MAX_RELAYS: usize = 2;

/// Idle time after which a path is abandoned. A dead direct path stalls
/// every stream on its connection until this passes and the connection
/// falls back to the relay; an outage shorter than it is ridden out on the
/// direct path. Shorter values also cost more keep alive traffic on every
/// idle connection, through [`PATH_KEEP_ALIVE`].
const PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval of the keep alive that holds each idle path open: under a third
/// of [`PATH_IDLE_TIMEOUT`], so that one lost keep alive does not close a
/// path.
const PATH_KEEP_ALIVE: Duration = Duration::from_millis(1500);

/// Wait before the first re-dial of a peer whose connection is relayed.
/// The library runs at most one hole punch round to a peer every five
/// seconds unless its addresses change, so a shorter wait buys nothing.
const REDIAL_INTERVAL: Duration = Duration::from_secs(5);

/// Longest wait between two re-dials of a relayed peer.
const REDIAL_MAX_INTERVAL: Duration = Duration::from_secs(30);

/// Re-dials of a peer while its connection stays relayed: twelve span about
/// four and a half minutes, after which the library's own check once a
/// minute takes over.
const REDIAL_ATTEMPTS: u32 = 12;

/// Re-dials a host makes or admits at once, across all its peers: enough
/// for the peers it votes with to be re-dialed together.
const REDIAL_BURST: u32 = 8;

/// Time in which a host earns one more re-dial. A re-dial costs about 20 kB
/// through the relay, so a host whose every connection fell back spends at
/// most about 20 kB/s on re-dialing: with the relayed idle cost of 500
/// connections, under the 100 kB/s an idle host may cost.
const REDIAL_REFILL: Duration = Duration::from_secs(1);

/// Configuration for the iroh network adapter.
#[derive(Debug, Clone)]
pub struct IrohConfig {
    /// The host's network key: its endpoint identity, stable across
    /// restarts and distinct from every consensus key.
    pub secret_key: SecretKey,

    /// Socket to bind. `None` binds every interface on a free port, in both
    /// address families.
    pub bind_addr: Option<SocketAddr>,

    /// Relays this host may home on; the endpoint picks the nearest that
    /// admits it. Empty disables relaying: the host is then reachable only
    /// at its socket addresses.
    pub relays: Vec<RelayUrl>,

    /// Certificate authorities the relays' TLS certificates are checked
    /// against, in place of the platform's roots. A relay whose certificate
    /// comes from a private authority needs this.
    pub relay_roots: Option<CaTlsConfig>,

    /// Whether the relays serve QUIC address discovery, through which the
    /// endpoint learns its address as seen from outside. A relay that
    /// serves plain HTTP alone does not.
    pub relay_address_discovery: bool,

    /// Addresses at which this host is known to be reachable from outside,
    /// advertised beside what the endpoint discovers for itself.
    pub external_addrs: Vec<SocketAddr>,

    /// Hosts to connect to at start, before any signed address record has
    /// arrived.
    pub bootstrap_peers: Vec<EndpointAddr>,

    /// Domains whose `_hyperscale` TXT records each name one more bootstrap
    /// peer, in the [`parse_endpoint_addr`] form. They are looked up at
    /// start and again periodically; a failed lookup keeps the peers the
    /// last one found.
    pub bootstrap_domains: Vec<String>,

    /// Resolver the bootstrap domains are looked up with. `None` reads the
    /// host system's DNS configuration.
    pub dns_resolver: Option<DnsResolver>,

    /// Whether to ask the local router for a port mapping.
    pub port_mapping: bool,

    /// Idle time after which a path is abandoned, bounding how long a dead
    /// direct path holds a connection before it falls back to the relay.
    /// The library clamps it to at most 15 seconds.
    pub path_idle_timeout: Duration,

    /// Interval of the keep alive that holds each path open. The library
    /// clamps it to at most 5 seconds.
    pub path_keep_alive: Duration,

    /// When a peer whose connection this host dialed is re-dialed while the
    /// connection is relayed, to bring it back to a direct path.
    pub redial: RedialSchedule,

    /// How much re-dialing the host does across all its peers, made and
    /// admitted together.
    pub redial_budget: RedialBudget,

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
            relay_roots: None,
            relay_address_discovery: true,
            external_addrs: Vec::new(),
            bootstrap_peers: Vec::new(),
            bootstrap_domains: Vec::new(),
            dns_resolver: None,
            port_mapping: true,
            path_idle_timeout: PATH_IDLE_TIMEOUT,
            path_keep_alive: PATH_KEEP_ALIVE,
            redial: RedialSchedule {
                interval: REDIAL_INTERVAL,
                max_interval: REDIAL_MAX_INTERVAL,
                attempts: REDIAL_ATTEMPTS,
            },
            redial_budget: RedialBudget {
                burst: REDIAL_BURST,
                refill: REDIAL_REFILL,
            },
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

/// Parse a host's address from its text form: the endpoint id, `@`, and a
/// comma separated list of ways to reach it, each a socket address or a
/// relay URL.
///
/// ```text
/// <endpoint id>@203.0.113.7:9000,https://relay.example
/// ```
///
/// # Errors
///
/// Returns a description of the first part that does not parse, or of an
/// address that names no way to reach the endpoint.
pub fn parse_endpoint_addr(text: &str) -> Result<EndpointAddr, String> {
    let (id, addrs) = text
        .split_once('@')
        .ok_or_else(|| format!("{text}: expected <endpoint id>@<address>[,<address>...]"))?;
    let id: EndpointId = id
        .parse()
        .map_err(|e| format!("{id}: not an endpoint id: {e}"))?;
    let addrs = addrs
        .split(',')
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .map(TransportAddr::Ip)
                .or_else(|_| addr.parse::<RelayUrl>().map(TransportAddr::Relay))
                .map_err(|_| format!("{addr}: neither a socket address nor a relay URL"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EndpointAddr::from_parts(id, addrs))
}

/// The text form of a host's address, as [`parse_endpoint_addr`] reads it.
#[must_use]
pub fn format_endpoint_addr(addr: &EndpointAddr) -> String {
    let ways: Vec<String> = addr
        .ip_addrs()
        .map(ToString::to_string)
        .chain(addr.relay_urls().map(ToString::to_string))
        .collect();
    format!("{}@{}", addr.id, ways.join(","))
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
    fn a_host_address_survives_its_text_form() {
        let addr = EndpointAddr::new(SecretKey::from_bytes(&[3; 32]).public())
            .with_ip_addr("203.0.113.7:9000".parse().unwrap())
            .with_relay_url("https://relay.example".parse().unwrap());
        let text = format_endpoint_addr(&addr);
        assert_eq!(parse_endpoint_addr(&text), Ok(addr));
    }

    #[test]
    fn text_that_names_no_host_is_refused() {
        let id = SecretKey::from_bytes(&[3; 32]).public();
        assert!(parse_endpoint_addr("203.0.113.7:9000").is_err(), "no id");
        assert!(parse_endpoint_addr("nobody@203.0.113.7:9000").is_err());
        assert!(parse_endpoint_addr(&format!("{id}@not an address")).is_err());
        assert!(parse_endpoint_addr(&format!("{id}@")).is_err());
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
