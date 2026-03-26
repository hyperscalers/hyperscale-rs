//! Deterministic execution state machine.
//!
//! This crate implements the transaction execution layer as a pure, synchronous
//! state machine. It handles:
//!
//! - Single-shard transaction execution
//! - Cross-shard coordination (atomic execution protocol)
//! - State provisioning
//! - Vote aggregation and certificate formation

pub mod execution_cache;
pub mod handlers;
pub mod wave_accumulator;

mod state;
mod trackers;

pub use execution_cache::ExecutionCache;
pub use state::{
    ExecutionState, WaveCompletionData, DEFAULT_SPECULATIVE_MAX_TXS,
    DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
};
pub use trackers::WaveVoteTracker;
pub use wave_accumulator::WaveAccumulator;
