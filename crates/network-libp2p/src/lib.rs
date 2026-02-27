//! Production libp2p network transport.
//!
//! This crate provides the libp2p-based networking layer for the production runner:
//!
//! - **Gossipsub** for efficient broadcast messaging (shard-scoped topics)
//! - **Streams** for request-response (sync/fetch)
//! - **QUIC** transport for reliable, encrypted connections
//! - **Codec pool** for async SBOR encoding/decoding

mod adapter;
mod codec_pool;
mod config;
mod inbound_router;
mod network;
mod peer_health;
mod request_manager;

pub use adapter::{
    compute_peer_id_for_validator, derive_libp2p_keypair, Libp2pAdapter, NetworkError,
};
pub use codec_pool::CodecPoolHandle;
pub use config::{Libp2pConfig, VersionInteroperabilityMode};
pub use network::ProdNetwork;
pub use request_manager::{RequestManager, RequestManagerConfig};

// Re-export libp2p types used by the production runner
pub use libp2p::identity::Keypair as Libp2pKeypair;
