//! Shared network protocol logic.
//!
//! This crate contains transport utilities and the `Network` trait:
//!
//! - [`compression`]: LZ4 compress/decompress helpers
//! - [`deferred`]: items waiting on verdicts that checks settle later
//! - [`fault`]: portable fault-injection vocabulary; the drop-rule engine behind `test-utils`
//! - [`registry`]: `HandlerRegistry` for per-message-type handler storage/dispatch
//! - [`retry`]: the request retry policy and peer health every transport runs
//! - [`stream_backoff`]: the per-stream reconnection backoff every transport holds
//! - [`traits`]: `Network` trait for typed message sends and per-type handler registration

pub mod compression;
pub mod deferred;
pub mod fault;
pub mod registry;
pub mod retry;
pub mod stream_backoff;
mod traits;

pub use compression::CompressionError;
pub use registry::{
    AnswerScore, HandlerRegistry, RawGossipHandler, RawHostGossipHandler, RawNotificationHandler,
    RawRequestHandler,
};
pub use traits::{
    Answerers, Deferral, GossipHandler, GossipScope, Network, NotificationHandler, RequestError,
    RequestHandler, ResponseVerdict, ValidatorKeyMap, Verdict, VerdictKey,
};
