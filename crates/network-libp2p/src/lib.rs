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
mod notify_pool;
mod peer_backoff;
mod request_manager;
mod request_pool;
mod stream_framing;
mod validator_bind;

pub use adapter::{Libp2pAdapter, NetworkError, generate_random_keypair};
pub use config::{Libp2pConfig, VersionInteroperabilityMode};
pub use network::Libp2pNetwork;
pub use request_manager::{RequestManager, RequestManagerConfig};
pub use request_pool::{RequestPool, RequestStreamPool};

pub mod fault_gate;
/// Re-export the shared fault vocabulary so test clusters can drive the gate.
#[cfg(feature = "test-utils")]
pub use hyperscale_network::fault;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
