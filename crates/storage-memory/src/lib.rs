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

pub mod beacon;
pub mod shard;

pub use beacon::core::SimBeaconStorage;
pub use shard::core::SimShardStorage;
pub use shard::snapshot::SimSnapshot;
