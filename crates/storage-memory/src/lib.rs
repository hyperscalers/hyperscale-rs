//! # In-Memory Storage
//!
//! In-memory storage implementation for deterministic simulation testing (DST).
//!
//! Uses `im::OrdMap` for O(1) structural-sharing clones, enabling efficient
//! snapshots without copying the entire dataset. This is critical for parallel
//! transaction execution where each transaction needs an isolated view.
//!
//! # JVT Integration
//!
//! Uses `SimTreeStore` for Jellyfish Verkle Tree tracking, providing
//! `jvt_version()` and `state_root_hash()` for state commitment. This ensures
//! simulation has identical JVT behavior to production.

mod commit;
mod consensus;
pub(crate) mod core;
mod snapshot;
mod state;
mod store;
mod tree_store;

#[cfg(test)]
mod tests;

pub use core::SimStorage;
pub use snapshot::SimSnapshot;
