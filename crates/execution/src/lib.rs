//! Deterministic execution state machine.
//!
//! This crate implements the transaction execution layer as a pure, synchronous
//! state machine. It handles:
//!
//! - Single-shard transaction execution
//! - Cross-shard coordination (2PC)
//! - State provisioning
//! - Vote aggregation and certificate formation

mod pending;
mod state;
mod trackers;

pub use state::{ExecutionState, DEFAULT_SPECULATIVE_MAX_TXS, DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS};
