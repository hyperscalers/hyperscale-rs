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
pub mod conflict;
pub mod handlers;

mod state;
mod trackers;

pub use accumulator::ExecutionAccumulator;
pub use hyperscale_types::FinalizedWave;
pub use state::{
    BlockCommittedOutput, CompletionData, CrossShardRegistration, ExecutionMemoryStats,
    ExecutionState,
};
pub use trackers::{VoteTracker, WaveCertificateTracker};
