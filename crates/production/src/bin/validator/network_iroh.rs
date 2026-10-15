//! The validator's network settings on the iroh backend.
//!
//! ```toml
//! [network]
//! listen_addr = "0.0.0.0:9000"
//! relays = ["https://relay-a.example", "https://relay-b.example"]
//! bootstrap_peers = ["<endpoint id>@203.0.113.7:9000,https://relay-a.example"]
//! ```
//!
//! The host's network key is read from `network_key_path`, by default
//! `network.key` in the data directory, and generated there on first start.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hyperscale_network_iroh::{
    IrohConfig, RedialSchedule, RelayUrl, VersionInteroperabilityMode, load_or_generate_secret_key,
    parse_endpoint_addr,
};
use serde::Deserialize;
use tracing::info;

use super::ValidatorConfig;

/// Network configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// Socket to bind, e.g. "0.0.0.0:9000". Unset binds every interface on
    /// a free port.
    pub listen_addr: Option<String>,

    /// Hosts to connect to at start, each as
    /// `<endpoint id>@<address>[,<address>...]`.
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Relays this host homes on, at most two.
    #[serde(default)]
    pub relays: Vec<String>,

    /// Addresses at which this host is known to be reachable from outside.
    #[serde(default)]
    pub external_addrs: Vec<SocketAddr>,

    /// File holding the host's network key.
    pub network_key_path: Option<PathBuf>,

    /// Ask the local router for a port mapping.
    #[serde(default = "default_upnp_enabled")]
    pub upnp_enabled: bool,

    /// Version interoperability mode
    pub version_interop_mode: Option<VersionInteroperabilityMode>,

    /// Idle time after which a path is abandoned, in milliseconds. Unset
    /// keeps the backend's default.
    pub path_idle_timeout_ms: Option<u64>,

    /// Interval of the keep alive that holds each path open, in
    /// milliseconds. Unset keeps the backend's default.
    pub path_keep_alive_ms: Option<u64>,

    /// Wait before the first re-dial of a peer whose connection fell back
    /// to the relay, in milliseconds. Unset keeps the backend's default.
    pub redial_interval_ms: Option<u64>,

    /// Longest wait between two re-dials of a relayed peer, in
    /// milliseconds. Unset keeps the backend's default.
    pub redial_max_interval_ms: Option<u64>,

    /// Re-dials of a peer while its connection stays relayed; zero turns
    /// re-dialing off. Unset keeps the backend's default.
    pub redial_attempts: Option<u32>,
}

const fn default_upnp_enabled() -> bool {
    true
}

/// Build network configuration from TOML config.
pub fn build_network_config(config: &ValidatorConfig) -> Result<IrohConfig> {
    let network = &config.network;
    let key_path = network
        .network_key_path
        .clone()
        .unwrap_or_else(|| config.node.data_dir.join("network.key"));
    let secret_key = load_or_generate_secret_key(&key_path)?;
    info!(endpoint = %secret_key.public(), "Loaded network key");

    let bind_addr = network
        .listen_addr
        .as_ref()
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .with_context(|| format!("Invalid listen address: {addr}"))
        })
        .transpose()?;
    let relays = network
        .relays
        .iter()
        .map(|url| {
            url.parse::<RelayUrl>()
                .with_context(|| format!("Invalid relay URL: {url}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let bootstrap_peers = network
        .bootstrap_peers
        .iter()
        .map(|peer| parse_endpoint_addr(peer).map_err(|e| anyhow!("Invalid bootstrap peer: {e}")))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|peer| peer.id != secret_key.public())
        .collect();

    let defaults = IrohConfig::new(secret_key);
    Ok(IrohConfig {
        bind_addr,
        relays,
        external_addrs: network.external_addrs.clone(),
        bootstrap_peers,
        port_mapping: network.upnp_enabled,
        path_idle_timeout: network
            .path_idle_timeout_ms
            .map_or(defaults.path_idle_timeout, Duration::from_millis),
        path_keep_alive: network
            .path_keep_alive_ms
            .map_or(defaults.path_keep_alive, Duration::from_millis),
        redial: RedialSchedule {
            interval: network
                .redial_interval_ms
                .map_or(defaults.redial.interval, Duration::from_millis),
            max_interval: network
                .redial_max_interval_ms
                .map_or(defaults.redial.max_interval, Duration::from_millis),
            attempts: network.redial_attempts.unwrap_or(defaults.redial.attempts),
        },
        version_interop_mode: network
            .version_interop_mode
            .unwrap_or(VersionInteroperabilityMode::Strict),
        ..defaults
    })
}
