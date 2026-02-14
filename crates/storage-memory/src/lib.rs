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
//! Uses `TypedInMemoryTreeStore` for Jellyfish Merkle Tree tracking, providing
//! `state_version()` and `state_root_hash()` for state commitment. This ensures
//! simulation has identical JMT behavior to production.

mod storage;

pub use storage::{SimSnapshot, SimStorage};
