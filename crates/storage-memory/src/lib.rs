//! # In-Memory Storage
//!
//! In-memory storage implementation for deterministic simulation testing (DST).
//!
//! Uses `im::OrdMap` for O(1) structural-sharing clones, enabling efficient
//! snapshots without copying the entire dataset. This is critical for parallel
//! transaction execution where each transaction needs an isolated view.
//!
//! # JMT Integration
//!
//! Uses `SimTreeStore` for Jellyfish Merkle Tree (JMT) tracking, providing
//! `jmt_height()` and `state_root()` for state commitment. This ensures
//! simulation has identical JMT behavior to production.

mod chain_reader;
mod chain_writer;
pub(crate) mod core;
mod snapshot;
mod state;
mod store;
mod tree_store;

#[cfg(test)]
mod tests;

pub use core::SimStorage;
pub use snapshot::SimSnapshot;
