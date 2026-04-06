//! Deterministic execution state machine.
//!
//! This crate implements the transaction execution layer as a pure, synchronous
//! state machine. It handles:
//!
//! - Single-shard transaction execution
//! - Cross-shard coordination (atomic execution protocol)
//! - State provisioning
//! - Vote aggregation and certificate formation

pub mod accumulator;
pub mod handlers;

mod state;
mod trackers;

pub use accumulator::ExecutionAccumulator;
pub use state::{
    BlockCommittedOutput, CompletionData, CrossShardRegistration, ExecutionMemoryStats,
    ExecutionState, FinalizedCertEntry, DEFAULT_SPECULATIVE_MAX_TXS,
    DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
};
pub use trackers::VoteTracker;
