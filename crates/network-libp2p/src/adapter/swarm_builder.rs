//! Swarm construction with QUIC/TCP transport configuration.

use super::behaviour::Behaviour;
use super::error::NetworkError;
use crate::config::Libp2pConfig;
use futures::future::Either;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{OrTransport, Transport};
use libp2p::core::upgrade::Version;
use libp2p::{identity, Swarm, SwarmBuilder};
use std::time::Duration;
use tracing::info;

/// Apply consensus-optimized QUIC settings to a config.
///
/// Used by both the TCP fallback path (which creates `Config::new`) and
/// the QUIC-only path (which receives a mutable Config from `SwarmBuilder`).
fn apply_quic_tuning(quic_config: &mut libp2p::quic::Config, app_config: &Libp2pConfig) {
    // QUIC configuration optimized for BFT consensus workloads:
    // - High stream concurrency for parallel sync and cross-shard coordination
    // - Large flow control windows for block transfers
    // - Fast handshake timeout to match our stream timeout ceiling
    // - Aggressive keep-alive for rapid failure detection
    quic_config.max_concurrent_stream_limit = 4096;
    // Handshake timeout: fail fast on unreachable peers during connection setup.
    // Matches our max stream timeout (5s) for consistent timeout behavior.
    quic_config.handshake_timeout = Duration::from_secs(5);
    // Flow control: large windows to avoid stalls during block sync.
    // max_stream_data: 2MB per stream handles large block transfers without WINDOW_UPDATE round-trips.
    quic_config.max_stream_data = 2 * 1024 * 1024;
    // max_connection_data: 8MB aggregate across all streams for burst sync scenarios.
    quic_config.max_connection_data = 8 * 1024 * 1024;
    // QUIC keep-alive: sends PING frames at this interval to keep connections alive
    quic_config.keep_alive_interval = app_config.keep_alive_interval;
    // QUIC idle timeout: connections are closed after this duration of inactivity
    // Must be longer than keep_alive_interval to allow keep-alives to work
    quic_config.max_idle_timeout = app_config.idle_connection_timeout.as_millis() as u32;
}

/// Build a configured libp2p Swarm with QUIC transport and optional TCP fallback.
pub(super) fn build_swarm(
    config: &Libp2pConfig,
    keypair: identity::Keypair,
    behaviour: Behaviour,
) -> Result<Swarm<Behaviour>, NetworkError> {
    if config.tcp_fallback_enabled {
        info!("Building swarm with QUIC (primary) + TCP (fallback)");

        let mut quic_config = libp2p::quic::Config::new(&keypair);
        apply_quic_tuning(&mut quic_config, config);

        let quic_transport = libp2p::quic::tokio::Transport::new(quic_config)
            .map(|(p, c), _| (p, StreamMuxerBox::new(c)));

        // TCP configuration with Noise + Yamux
        let tcp_transport =
            libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
                .upgrade(Version::V1)
                .authenticate(
                    libp2p::noise::Config::new(&keypair)
                        .map_err(|e| NetworkError::NetworkError(e.to_string()))?,
                )
                .multiplex({
                    let mut config = libp2p::yamux::Config::default();
                    config.set_max_num_streams(4096);
                    // allowing deprecated because replacement (connection-level limits) is not available libp2p 0.56
                    #[allow(deprecated)]
                    {
                        config.set_max_buffer_size(16 * 1024 * 1024);
                        config.set_receive_window_size(16 * 1024 * 1024);
                    }
                    config
                })
                .map(|(p, c), _| (p, StreamMuxerBox::new(c)));

        // Prioritize QUIC by putting it first (Left side of OrTransport)
        let transport =
            OrTransport::new(quic_transport, tcp_transport).map(|either, _| match either {
                Either::Left((peer_id, muxer)) => (peer_id, muxer),
                Either::Right((peer_id, muxer)) => (peer_id, muxer),
            });

        Ok(SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|_| transport)
            .unwrap() // Unwrap Infallible error from transport add
            .with_behaviour(|_| behaviour)
            .map_err(|e| {
                NetworkError::NetworkError(format!("Failed to configure swarm behaviour: {:?}", e))
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(config.idle_connection_timeout)
                    .with_max_negotiating_inbound_streams(100)
            })
            .build())
    } else {
        info!("Building swarm with QUIC only (TCP fallback disabled)");
        Ok(SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic_config(|mut quic_config| {
                apply_quic_tuning(&mut quic_config, config);
                quic_config
            })
            .with_behaviour(|_| behaviour)
            .map_err(|e| {
                NetworkError::NetworkError(format!("Failed to configure swarm behaviour: {:?}", e))
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(config.idle_connection_timeout)
                    .with_max_negotiating_inbound_streams(100)
            })
            .build())
    }
}
