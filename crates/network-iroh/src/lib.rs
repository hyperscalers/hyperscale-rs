//! iroh network transport.
//!
//! Validators reach each other by endpoint identity over QUIC. A relay opens
//! a connection between two hosts behind NAT and coordinates the hole punch;
//! traffic then moves to a direct path, with the relayed path kept as a
//! degraded fallback.

mod address_book;
mod bind;
mod config;
mod endpoint;
mod error;
mod framing;
mod identity;
pub mod path;
mod protocol;

pub use address_book::{AddressBook, IngestOutcome};
pub use bind::LocalVnodeIdentity;
pub use config::{IrohConfig, MAX_RELAYS, VersionInteroperabilityMode};
pub use endpoint::{IrohAdapter, IrohAdapterArgs};
pub use error::NetworkError;
pub use identity::load_or_generate_secret_key;
pub use protocol::ALPN;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
#[cfg(feature = "test-utils")]
pub mod testing;
