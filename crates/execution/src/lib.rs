//! Deterministic execution state machine.
//!
//! This crate implements the transaction execution layer as a pure, synchronous
//! state machine. It handles:
//!
//! - Single-shard transaction execution
//! - Cross-shard coordination (atomic execution protocol)
//! - State provisioning
//! - Vote aggregation and certificate formation

pub mod conflict;
pub mod handlers;
pub mod wave_state;

mod state;
mod vote_tracker;

pub use hyperscale_types::FinalizedWave;
pub use state::{CompletionData, ExecutionMemoryStats, ExecutionState};
pub use vote_tracker::VoteTracker;
pub use wave_state::{WaveState, WAVE_TIMEOUT_BLOCKS};
