//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`traits`]: `Network` trait for typed message sends and per-type handler registration
//! - [`registry`]: `HandlerRegistry` for per-message-type handler storage/dispatch
//! - [`wire`]: LZ4 compress/decompress helpers
//! - [`topic`]: Gossipsub topic builder/parser
//! - [`codec`]: Generic SBOR encode/decode with LZ4 compression
//!
//! Sync and fetch protocol state machines live in `hyperscale-node`.
//!
//! No async runtime dependency.

mod codec;
mod registry;
mod topic;
mod traits;
pub mod wire;

// Re-export key types
pub use codec::{encode_to_wire, CodecError};
pub use registry::{HandlerRegistry, RawGossipHandler, RawRequestHandler};
pub use topic::{parse_topic, ParsedTopic, Topic};
pub use traits::{GossipHandler, Network, RequestError, RequestHandler, TopicScope};
pub use wire::{frame_request, parse_request_frame};
