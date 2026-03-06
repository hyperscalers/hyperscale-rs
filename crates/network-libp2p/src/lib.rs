//! Production libp2p network transport.
//!
//! This crate provides the libp2p-based networking layer for the production runner:
//!
//! - **Gossipsub** for efficient broadcast messaging (shard-scoped topics)
//! - **Streams** for request-response (sync/fetch)
//! - **QUIC** transport for reliable, encrypted connections

mod adapter;
mod config;
mod inbound_router;
mod network;
mod request_manager;
mod stream_framing;

pub use adapter::{generate_random_keypair, Libp2pAdapter, NetworkError};
pub use config::{Libp2pConfig, VersionInteroperabilityMode};
pub use network::ProdNetwork;
pub use request_manager::{RequestManager, RequestManagerConfig};
