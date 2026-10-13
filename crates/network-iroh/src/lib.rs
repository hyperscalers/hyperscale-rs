//! iroh network transport.
//!
//! Validators reach each other by endpoint identity over QUIC. A relay opens
//! a connection between two hosts behind NAT and coordinates the hole punch;
//! traffic then moves to a direct path, with the relayed path kept as a
//! degraded fallback.
//!
//! Each host pair holds one connection. Notifications travel on one
//! unidirectional stream per class, each request on a stream of its own,
//! and every stream is prioritised by its class.

mod address_book;
mod bind;
mod config;
mod endpoint;
mod error;
mod framing;
mod identity;
mod inbound;
mod network;
mod notify;
pub mod path;
mod peer_backoff;
mod protocol;
mod request;
mod request_manager;

pub use address_book::{AddressBook, IngestOutcome};
pub use bind::LocalVnodeIdentity;
pub use config::{IrohConfig, MAX_RELAYS, VersionInteroperabilityMode};
pub use endpoint::{IrohAdapter, IrohAdapterArgs};
pub use error::NetworkError;
pub use identity::load_or_generate_secret_key;
pub use network::IrohNetwork;
pub use protocol::ALPN;
pub use request::{RequestPool, RequestStreams};
pub use request_manager::{RequestManager, RequestManagerConfig};

pub mod fault_gate;
/// Re-export the shared fault vocabulary so test clusters can drive the gate.
#[cfg(feature = "test-utils")]
pub use hyperscale_network::fault;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
#[cfg(feature = "test-utils")]
pub mod testing;
