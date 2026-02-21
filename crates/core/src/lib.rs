//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types for the consensus architecture:
//!
//! - [`NodeInput`]: All possible inputs to the node loop
//! - [`ProtocolEvent`]: Events processed by the state machine
//! - [`Action`]: All possible outputs from the state machine
//! - [`EventPriority`]: Ordering priority for events at the same timestamp
//! - [`StateMachine`]: The trait that all state machines implement
//!
//! # Architecture
//!
//! The core is built on a two-level event model:
//!
//! ```text
//! NodeInput → NodeLoop (intercepts I/O events) → ProtocolEvent → StateMachine::handle() → Actions
//! ```
//!
//! The state machine is:
//! - **Synchronous**: No async, no .await
//! - **Deterministic**: Same state + event = same actions
//! - **Pure-ish**: Mutates self, but performs no I/O
//!
//! All I/O is handled by the runner (simulation or production) which:
//! 1. Delivers NodeInputs to the node loop
//! 2. NodeLoop intercepts I/O events (sync, fetch, validation) and forwards
//!    ProtocolEvents to the state machine
//! 3. Executes the returned actions
//! 4. Converts action results back into NodeInputs

mod action;
mod input;
mod protocol_event;
mod timer;
mod traits;

pub use action::{Action, CrossShardExecutionRequest, TransactionStatus};
pub use input::{Event, EventPriority, NodeInput};
pub use protocol_event::ProtocolEvent;
pub use timer::{TimerId, TimerScheduler};
pub use traits::{NoOpStateRootComputer, StateMachine, StateRootComputer};
