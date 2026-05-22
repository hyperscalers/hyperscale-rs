//! Swarm construction with QUIC transport configuration.

use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::quic::Config as QuicConfig;
use libp2p::{Swarm, SwarmBuilder};
use tracing::info;

use super::behaviour::Behaviour;
use super::error::NetworkError;
use crate::config::Libp2pConfig;

/// Apply consensus-optimized QUIC settings to a config.
fn apply_quic_tuning(quic_config: &mut QuicConfig, app_config: &Libp2pConfig) {
    // QUIC configuration optimized for shard consensus workloads:
    // - High stream concurrency for parallel sync and cross-shard coordination
    // - Large flow control windows for block transfers
    // - Fast handshake timeout to match our stream timeout ceiling
    // - Aggressive keep-alive for rapid failure detection
    quic_config.max_concurrent_stream_limit = 4096;
    // Handshake timeout: fail fast on unreachable peers during connection setup.
    // Matches our max stream timeout (5s) for consistent timeout behavior.
    quic_config.handshake_timeout = Duration::from_secs(5);
    // Flow control: large windows to avoid stalls during block sync.
    // max_stream_data: 16MB per stream handles large cross-shard provision
    // bodies (multi-MB merkle proofs + tx bundles) without WINDOW_UPDATE
    // round-trips on high-RTT paths.
    quic_config.max_stream_data = 16 * 1024 * 1024;
    // max_connection_data: 64MB aggregate across all streams so several
    // large cross-shard transfers can overlap on one connection without
    // serializing on the connection-level receive window.
    quic_config.max_connection_data = 64 * 1024 * 1024;
    // QUIC keep-alive: sends PING frames at this interval to keep connections alive
    quic_config.keep_alive_interval = app_config.keep_alive_interval;
    // QUIC idle timeout: connections are closed after this duration of inactivity
    // Must be longer than keep_alive_interval to allow keep-alives to work
    quic_config.max_idle_timeout =
        u32::try_from(app_config.idle_connection_timeout.as_millis()).unwrap_or(u32::MAX);
}

/// Build a configured libp2p Swarm with QUIC transport.
pub(super) fn build_swarm(
    config: &Libp2pConfig,
    keypair: Keypair,
    behaviour: Behaviour,
) -> Result<Swarm<Behaviour>, NetworkError> {
    info!("Building swarm with QUIC transport");
    Ok(SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic_config(|mut quic_config| {
            apply_quic_tuning(&mut quic_config, config);
            quic_config
        })
        .with_behaviour(|_| behaviour)
        .map_err(|e| {
            NetworkError::NetworkError(format!("Failed to configure swarm behaviour: {e:?}"))
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(config.idle_connection_timeout)
                .with_max_negotiating_inbound_streams(100)
        })
        .build())
}
