//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node. It also contains the transport-independent
//! sync and fetch protocol state machines.

mod action_handler;
mod batch_accumulator;
mod config;
mod fetch_protocol;
mod inbound_handler;
pub mod node_loop;
mod sync_protocol;

mod state;

pub use config::NodeConfig;
pub use node_loop::{NodeStatusSnapshot, TimerOp};
pub use state::NodeStateMachine;
pub use sync_protocol::SyncStateKind;
