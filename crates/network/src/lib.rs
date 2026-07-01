//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`compression`]: LZ4 compress/decompress helpers
//! - [`fault`]: portable fault-injection vocabulary; the drop-rule engine behind `test-utils`
//! - [`registry`]: `HandlerRegistry` for per-message-type handler storage/dispatch
//! - [`topic`]: Gossipsub topic builder/parser
//! - [`traits`]: `Network` trait for typed message sends and per-type handler registration

pub mod compression;
pub mod fault;
pub mod registry;
mod topic;
mod traits;

pub use compression::CompressionError;
pub use registry::{
    HandlerRegistry, RawGossipHandler, RawHostGossipHandler, RawNotificationHandler,
    RawRequestHandler,
};
pub use topic::{ParsedTopic, Topic, parse_topic};
pub use traits::{
    GossipHandler, GossipVerdict, Network, NotificationHandler, RequestError, RequestHandler,
    ResponseVerdict, TopicScope, ValidatorKeyMap,
};
