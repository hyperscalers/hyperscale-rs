// Cargo treats each `tests/*.rs` as its own binary, each pulling in
// the full `common` tree. Any helper not used by every binary trips
// per-binary unused/dead-code analysis — silence it here so adding a
// new integration test never forces an unrelated common-helper cleanup.
#![allow(dead_code, unused_imports)]

//! Shared sim helpers + fixtures for shard integration tests.

mod coordinator_sim;
mod fixtures;

pub use coordinator_sim::{ByzantineBehaviour, CapturedCommit, HoldFilter, ShardCoordinatorSim};
pub use fixtures::build_genesis_block;
