//! Shared network protocol logic.
//!
//! This crate contains transport-independent protocol components:
//!
//! - [`wire`]: LZ4 compress/decompress helpers
//! - [`topic`]: Gossipsub topic builder/parser
//! - [`codec`]: SBOR encode/decode with topic-based dispatch
//! - [`sync_protocol`]: Block sync state machine
//! - [`fetch_protocol`]: Transaction/certificate fetch state machine
//!
//! No async runtime dependency. Each runner (production/simulation) drives
//! the state machines and handles transport-specific I/O.

pub mod codec;
pub mod fetch_protocol;
pub mod sync_protocol;
pub mod topic;
pub mod wire;

// Re-export key types
pub use codec::{
    decode_and_route, decode_message, encode_message, topic_for_message, CodecError, DecodedMessage,
};
pub use fetch_protocol::{
    FetchConfig, FetchInput, FetchKind, FetchOutput, FetchProtocol, FetchStatus,
};
pub use sync_protocol::{
    SyncConfig, SyncInput, SyncOutput, SyncProtocol, SyncStateKind, SyncStatus,
};
pub use topic::{ProtocolVersion, Topic};
pub use wire::{compress, decompress, WireError};
