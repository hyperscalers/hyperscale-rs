//! iroh network transport.
//!
//! Validators reach each other by endpoint identity over QUIC. A relay opens
//! a connection between two hosts behind NAT and coordinates the hole punch;
//! traffic then moves to a direct path, with the relayed path kept as a
//! degraded fallback.
//!
//! Each host pair holds one connection. Notifications and gossip travel on
//! one unidirectional stream per class, each request on a stream of its
//! own, and every stream is prioritised by its class. Gossip has no
//! overlay: a publisher sends to an audience it works out from the
//! committees.

mod address_book;
mod bind;
mod bind_gate;
mod config;
mod cooldown;
mod deferred;
mod endpoint;
mod error;
mod fanout;
mod framing;
mod identity;
mod inbound;
mod network;
mod notify;
pub mod path;
mod peer;
mod peer_backoff;
mod protocol;
mod record_pace;
mod request;
mod request_manager;
mod serve_budget;

pub use address_book::{AddressBook, IngestOutcome};
pub use bind::LocalVnodeIdentity;
pub use config::{
    IrohConfig, MAX_RELAYS, VersionInteroperabilityMode, format_endpoint_addr, parse_endpoint_addr,
};
pub use endpoint::{IrohAdapter, IrohAdapterArgs, PathTraffic, Traffic};
pub use error::NetworkError;
pub use identity::load_or_generate_secret_key;
/// The endpoint types a host's configuration and address are written in.
pub use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
pub use network::IrohNetwork;
pub use path::{PathKind, PathStatus, Readiness, RedialBudget, RedialSchedule};
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
