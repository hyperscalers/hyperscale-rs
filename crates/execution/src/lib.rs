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

mod coordinator;
mod early_arrivals;
mod expected_certs;
mod finalized_waves;
mod lookups;
mod provisioning;
mod vote_tracker;
mod waves;

pub use coordinator::{CompletionData, ExecutionCoordinator, ExecutionMemoryStats};
pub use hyperscale_types::{FinalizedWave, WAVE_TIMEOUT};
pub use vote_tracker::VoteTracker;
pub use wave_state::WaveState;
