//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JMT Integration
//!
//! Uses Jellyfish Merkle Tree (JMT) for cryptographic state commitment.
//! JMT data is stored in dedicated column families (`jmt_nodes`, `jmt_meta`).
//! On each commit, the JMT is updated and a new state root hash is computed.

mod storage;

pub use storage::{
    CompressionType, RocksDbConfig, RocksDbSnapshot, RocksDbStorage, SharedStorage, StorageError,
};
