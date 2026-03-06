//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`traits`]: `Network` trait for typed message sends and per-type handler registration
//! - [`registry`]: `HandlerRegistry` for per-message-type handler storage/dispatch
//! - [`compression`]: LZ4 compress/decompress helpers
//! - [`topic`]: Gossipsub topic builder/parser
//!
//! Sync and fetch protocol state machines live in `hyperscale-node`.
//!
//! No async runtime dependency.

pub mod compression;
pub mod registry;
mod topic;
mod traits;

// Re-export key types
pub use compression::CompressionError;
pub use registry::{HandlerRegistry, RawGossipHandler, RawRequestHandler};
pub use topic::{parse_topic, ParsedTopic, Topic};
pub use traits::{GossipHandler, GossipVerdict, Network, RequestError, RequestHandler, TopicScope};
