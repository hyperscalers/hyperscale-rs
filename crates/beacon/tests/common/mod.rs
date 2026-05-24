// Cargo treats each `tests/*.rs` as its own binary, each pulling in
// the full `common` tree. Any helper not used by every binary trips
// per-binary unused/dead-code analysis — silence it here so adding a
// new integration test never forces an unrelated common-helper cleanup.
#![allow(dead_code, unused_imports)]

//! Shared sim helpers + fixtures for beacon integration tests.
//!
//! Each integration test binary (`tests/pc.rs`, `tests/spc.rs`, ...)
//! pulls helpers from here via `mod common;`. Re-exports are flat — the
//! consuming tests reference `common::Committee`, `common::pc_ctx`, etc.

mod fixtures;
mod pc_sim;
mod spc_sim;

pub use fixtures::{Committee, pc_ctx};
pub use pc_sim::PcSim;
pub use spc_sim::SpcSim;
