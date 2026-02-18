//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node.

pub mod action_handler;

mod state;

pub use state::NodeStateMachine;
