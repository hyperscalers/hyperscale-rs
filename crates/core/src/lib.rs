//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types for the consensus architecture:
//!
//! - [`NodeInput`]: All possible inputs to the I/O loop
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
//! NodeInput → IoLoop (intercepts I/O events) → ProtocolEvent → StateMachine::handle() → Actions
//! ```
//!
//! The state machine is:
//! - **Synchronous**: No async, no .await
//! - **Deterministic**: Same state + event = same actions
//! - **Pure-ish**: Mutates self, but performs no I/O
//!
//! All I/O is handled by the runner (simulation or production) which:
//! 1. Delivers NodeInputs to the I/O loop
//! 2. IoLoop intercepts I/O events (sync, fetch, validation) and forwards
//!    ProtocolEvents to the state machine
//! 3. Executes the returned actions
//! 4. Converts action results back into NodeInputs

mod action;
mod execution_backend;
mod input;
mod node_config;
mod protocol_event;
pub mod result;
mod timer;
mod traits;
mod validation;

pub use action::{Action, CrossShardExecutionRequest, ProvisionRequest, TransactionStatus};
pub use execution_backend::ExecutionBackend;
pub use input::{EventPriority, NodeInput};
pub use node_config::NodeConfig;
pub use protocol_event::{ProtocolEvent, ProvisionVerificationResult};
pub use result::{ExecutionOutput, SingleTxResult};
pub use timer::{TimerId, TimerScheduler};
pub use traits::StateMachine;
pub use validation::{TransactionValidator, ValidationError};
