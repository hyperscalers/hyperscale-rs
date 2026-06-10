//! # In-Memory Storage
//!
//! In-memory storage implementation for deterministic simulation testing (DST).
//!
//! Substate state and the chain index live in `BTreeMap`s under a single
//! `RwLock`; snapshots are constructed by cloning those maps under the
//! read lock. Sufficient for simulation workloads up to ~tens of
//! thousands of substates per shard — production uses
//! `hyperscale-storage-rocksdb`.
//!
//! # JMT Integration
//!
//! Uses `SimTreeStore` for Jellyfish Merkle Tree (JMT) tracking, providing
//! `jmt_height()` and `state_root()` for state commitment. This ensures
//! simulation has identical JMT behavior to production.

pub mod beacon;
pub mod shard;

pub use beacon::core::SimBeaconStorage;
pub use shard::boundary::SimBoundary;
pub use shard::core::SimShardStorage;
pub use shard::snapshot::SimSnapshot;
