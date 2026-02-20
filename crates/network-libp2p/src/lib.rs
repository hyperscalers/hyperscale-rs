//! Production libp2p network transport.
//!
//! This crate provides the libp2p-based networking layer for the production runner:
//!
//! - **Gossipsub** for efficient broadcast messaging (shard-scoped topics)
//! - **Streams** for request-response (sync/fetch)
//! - **QUIC** transport for reliable, encrypted connections
//! - **Codec pool** for async SBOR encoding/decoding

pub mod adapter;
pub mod codec_pool;
pub mod config;
pub mod inbound_router;
pub mod network;
pub mod peer_health;
pub mod request_manager;

pub use adapter::{
    compute_peer_id_for_validator, derive_libp2p_keypair, Libp2pAdapter, NetworkError,
};
pub use codec_pool::CodecPoolHandle;
pub use config::{Libp2pConfig, VersionInteroperabilityMode};
pub use inbound_router::{spawn_inbound_router, InboundRouterHandle};
pub use network::ProdNetwork;
pub use peer_health::{PeerHealth, PeerHealthConfig, PeerHealthStats, PeerHealthTracker};
pub use request_manager::{
    RequestError, RequestManager, RequestManagerConfig, RequestManagerStats, RequestPriority,
};

// Re-export shared network types
pub use hyperscale_network::{ProtocolVersion, Topic};

// Re-export libp2p types used by the production runner
pub use libp2p::identity::Keypair as Libp2pKeypair;
pub use libp2p::PeerId;
