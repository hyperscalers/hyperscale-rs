//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node. It also contains the transport-independent
//! sync and fetch protocol state machines.

mod batch_accumulator;
mod config;
pub mod io_loop;
mod state;

pub use config::NodeConfig;
pub use io_loop::sync::block::BlockSyncStateKind;
pub use io_loop::{NodeStatusSnapshot, SharedTopologySnapshot, TimerOp};
pub use state::NodeStateMachine;
