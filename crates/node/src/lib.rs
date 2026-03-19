//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node. It also contains the transport-independent
//! sync and fetch protocol state machines.

mod action_handler;
mod batch_accumulator;
mod config;
pub mod io_loop;
mod protocol;
mod state;

pub use config::IoLoopConfig;
pub use hyperscale_core::NodeConfig;
pub use io_loop::{NodeStatusSnapshot, SharedTopologySnapshot, TimerOp};
pub use protocol::sync::SyncStateKind;
pub use state::NodeStateMachine;
