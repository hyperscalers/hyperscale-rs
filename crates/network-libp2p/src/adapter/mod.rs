//! libp2p network adapter for production use.
//!
//! This module provides the core networking implementation using libp2p with:
//! - Gossipsub for efficient broadcast messaging
//! - Kademlia DHT for peer discovery
//! - Request-Response for sync block fetching
//! - QUIC transport for reliable, encrypted connections

mod behaviour;
mod command;
mod core;
mod error;
mod event_loop;
mod gossipsub;
mod identity;
mod swarm_builder;

pub use self::core::Libp2pAdapter;
pub use behaviour::STREAM_PROTOCOL;
pub use error::NetworkError;
pub use identity::{compute_peer_id_for_validator, derive_libp2p_keypair};
