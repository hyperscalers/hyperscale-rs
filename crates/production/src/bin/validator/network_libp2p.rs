//! The validator's network settings on the libp2p backend.
//!
//! ```toml
//! [network]
//! listen_addr = "/ip4/0.0.0.0/udp/9000/quic-v1"
//! bootstrap_peers = []
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};
use hyperscale_network_libp2p::{Libp2pConfig, VersionInteroperabilityMode};
use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use serde::Deserialize;
use tracing::{info, warn};

use super::ValidatorConfig;

/// Network configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    /// QUIC listen address (multiaddr format, e.g., "/ip4/0.0.0.0/udp/9000/quic-v1")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Bootstrap peer addresses
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval in milliseconds
    #[serde(default = "default_gossipsub_heartbeat_ms")]
    pub gossipsub_heartbeat_ms: u64,

    /// Enable `UPnP` port forwarding
    #[serde(default = "default_upnp_enabled")]
    pub upnp_enabled: bool,

    /// Version interoperability mode
    pub version_interop_mode: Option<VersionInteroperabilityMode>,

    /// Idle connection timeout in milliseconds
    #[serde(default = "default_idle_connection_timeout_ms")]
    pub idle_connection_timeout_ms: u64,

    /// QUIC keep-alive interval in milliseconds
    #[serde(default = "default_keep_alive_interval_ms")]
    pub keep_alive_interval_ms: u64,
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/udp/9000/quic-v1".to_string()
}

const fn default_max_message_size() -> usize {
    65536
}

const fn default_gossipsub_heartbeat_ms() -> u64 {
    300
}

const fn default_upnp_enabled() -> bool {
    true
}

const fn default_idle_connection_timeout_ms() -> u64 {
    60_000
}

const fn default_keep_alive_interval_ms() -> u64 {
    15_000
}

/// Build network configuration from TOML config.
pub fn build_network_config(config: &ValidatorConfig) -> Result<Libp2pConfig> {
    let config = &config.network;
    let listen_addr: Multiaddr = config
        .listen_addr
        .parse()
        .with_context(|| format!("Invalid listen address: {}", config.listen_addr))?;

    let listen_addresses = vec![listen_addr];

    // Filter out our own listen addresses from bootstrap peers.
    let bootstrap_peers: Vec<_> = config
        .bootstrap_peers
        .iter()
        .filter_map(|addr| {
            let parsed = addr.parse::<Multiaddr>().ok().or_else(|| {
                warn!("Invalid bootstrap peer address: {}", addr);
                None
            })?;

            // Check if this bootstrap peer matches any of our listen addresses
            // We compare string representations to handle minor formatting differences
            let is_self = listen_addresses.iter().any(|listen| {
                // Check if port and protocol match
                // We're aggressive here: if it looks like us, don't dial it
                listen.to_string() == parsed.to_string()
            });

            if is_self {
                info!("Removing self from bootstrap peers: {}", addr);
                None
            } else {
                Some(parsed)
            }
        })
        .collect();

    Ok(Libp2pConfig::default()
        .with_listen_addresses(listen_addresses)
        .with_bootstrap_peers(bootstrap_peers)
        .with_max_message_size(config.max_message_size)
        .with_gossipsub_heartbeat(Duration::from_millis(config.gossipsub_heartbeat_ms))
        .with_idle_connection_timeout(Duration::from_millis(config.idle_connection_timeout_ms))
        .with_keep_alive_interval(Duration::from_millis(config.keep_alive_interval_ms))
        .with_version_interop_mode(
            config
                .version_interop_mode
                .unwrap_or(VersionInteroperabilityMode::Strict),
        ))
}

/// Setup `UPnP` port forwarding.
#[allow(clippy::too_many_lines)] // mostly nested error logging branches; helpers obscure the flow
pub async fn setup_upnp(config: &NetworkConfig) {
    if !config.upnp_enabled {
        info!("UPnP disabled in configuration");
        return;
    }

    info!("Attempting to setup UPnP port forwarding...");

    // Determine local IP address by connecting to a public DNS (no data is sent)
    // We try multiple reliable DNS servers to ensure robustness
    let dns_servers = ["8.8.8.8:80", "1.1.1.1:80", "9.9.9.9:80"];
    let mut local_ip = None;

    for server in &dns_servers {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if socket.connect(server).is_ok()
                    && let Ok(addr) = socket.local_addr()
                {
                    local_ip = Some(addr.ip());
                    break;
                }
            }
            Err(e) => {
                warn!(
                    "Could not bind socket to determine local IP for UPnP: {}",
                    e
                );
            }
        }
    }

    let Some(local_ip) = local_ip else {
        warn!(
            "Could not determine local IP for UPnP: failed to connect to any external DNS server"
        );
        return;
    };

    // Parse listen address to get the port
    let listen_addr_parsed: Multiaddr = match config.listen_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to parse listen address for UPnP: {}", e);
            return;
        }
    };

    let mut quic_port = None;
    for protocol in &listen_addr_parsed {
        if let Protocol::Udp(port) = protocol {
            quic_port = Some(port);
            break;
        }
    }

    // Use igd-next for UPnP
    match search_gateway(SearchOptions::default()).await {
        Ok(gateway) => {
            let external_ip = match gateway.get_external_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    warn!("Failed to get external IP from UPnP gateway: {}", e);
                    return;
                }
            };
            info!("UPnP Gateway found. External IP: {}", external_ip);

            // Map QUIC port (UDP)
            if let Some(port) = quic_port {
                let local_addr = SocketAddr::new(local_ip, port);
                match gateway
                    .add_port(
                        PortMappingProtocol::UDP,
                        port,
                        local_addr,
                        60 * 60, // 1 hour lease
                        "Hyperscale Validator QUIC",
                    )
                    .await
                {
                    Ok(()) => info!("Successfully mapped QUIC port {} (UDP) via UPnP", port),
                    Err(e) => warn!("Failed to map QUIC port {} (UDP) via UPnP: {}", port, e),
                }
            } else {
                warn!("Could not determine QUIC port from listen address for UPnP");
            }
        }
        Err(e) => {
            warn!(
                "UPnP gateway not found or accessible: {}. Port forwarding may be required manually.",
                e
            );
        }
    }
}
