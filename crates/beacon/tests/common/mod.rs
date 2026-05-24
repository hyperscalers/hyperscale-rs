//! Shared sim helpers + fixtures for beacon integration tests.
//!
//! Each integration test binary (`tests/pc.rs`, `tests/spc.rs`, ...)
//! pulls helpers from here via `mod common;`. Re-exports are flat — the
//! consuming tests reference `common::Committee`, `common::pc_ctx`, etc.

mod fixtures;

pub use fixtures::{Committee, pc_ctx};
