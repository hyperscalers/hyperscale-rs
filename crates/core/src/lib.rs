//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types for the consensus architecture:
//!
//! - [`ProtocolEvent`]: Events processed by the state machine
//! - [`Action`]: All possible outputs from the state machine
//! - [`StateMachine`]: The trait that all state machines implement
//!
//! The I/O-loop-specific input types (`ShardEvent`, `ShardScopedInput`,
//! `ProcessScopedInput`, `FetchFailureKind`, `EventPriority`) live in
//! `hyperscale_node::io_loop`, since they're not part of the
//! deterministic state-machine contract.
//!
//! # Architecture
//!
//! The core is built on a two-level event model:
//!
//! ```text
//! ShardEvent → IoLoop (intercepts I/O events) → ProtocolEvent → StateMachine::handle() → Actions
//! ```
//!
//! The state machine is:
//! - **Synchronous**: No async, no .await
//! - **Deterministic**: Same state + event = same actions
//! - **Pure-ish**: Mutates self, but performs no I/O
//!
//! All I/O is handled by the runner (simulation or production) which:
//! 1. Delivers shard / process inputs to the I/O loop
//! 2. `IoLoop` intercepts I/O events (sync, fetch, validation) and forwards
//!    `ProtocolEvent`s to the state machine
//! 3. Executes the returned actions
//! 4. Converts action results back into shard / process inputs

mod action;
mod action_context;
mod fetch_abandon;
mod fetch_request;
mod protocol_event;
mod timer;
mod traits;

pub use action::{Action, ActionOwner, CrossShardExecutionRequest, ProvisionsRequest};
pub use action_context::{ActionContext, PreparedBlock};
pub use fetch_abandon::FetchAbandon;
pub use fetch_request::FetchRequest;
pub use hyperscale_dispatch::Parallelism;
pub use protocol_event::{CommitSource, ProtocolEvent};
pub use timer::TimerId;
pub use traits::StateMachine;
