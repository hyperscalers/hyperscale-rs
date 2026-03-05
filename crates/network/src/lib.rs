//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`traits`]: `Network` trait for typed message sends and per-type handler registration
//! - [`registry`]: `HandlerRegistry` for per-message-type handler storage/dispatch
//! - [`compression`]: LZ4 compress/decompress helpers
//! - [`topic`]: Gossipsub topic builder/parser
//! - [`request_frame`]: Type-id prefix framing for request-response dispatch
//!
//! Sync and fetch protocol state machines live in `hyperscale-node`.
//!
//! No async runtime dependency.

pub mod compression;
mod registry;
mod request_frame;
mod topic;
mod traits;

// Re-export key types
pub use compression::CompressionError;
pub use registry::{HandlerRegistry, RawGossipHandler, RawRequestHandler};
pub use request_frame::{frame_request, parse_request_frame, RequestFrameError};
pub use topic::{parse_topic, ParsedTopic, Topic};
pub use traits::{GossipHandler, Network, RequestError, RequestHandler, TopicScope};
