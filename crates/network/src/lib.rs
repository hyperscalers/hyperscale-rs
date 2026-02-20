//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`traits`]: `Network` trait for typed message sends and listener registration
//! - [`handler_registry`]: Type-erased handler registry for implementations
//! - [`wire`]: LZ4 compress/decompress helpers
//! - [`topic`]: Gossipsub topic builder/parser
//! - [`codec`]: SBOR encode/decode with topic-based dispatch
//!
//! Sync and fetch protocol state machines live in `hyperscale-node`.
//!
//! No async runtime dependency.

pub mod codec;
pub mod handler_registry;
pub mod topic;
pub mod traits;
pub mod wire;

// Re-export key types
pub use codec::{decode_and_route, decode_message, encode_to_wire, CodecError, DecodedMessage};
pub use handler_registry::HandlerRegistry;
pub use topic::{ProtocolVersion, Topic};
pub use traits::{
    BlockResponseCallback, CertificatesResponseCallback, Network, RequestError,
    TransactionsResponseCallback,
};
pub use wire::{compress, decompress, WireError};
