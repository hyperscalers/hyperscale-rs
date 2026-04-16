//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JMT Integration
//!
//! Uses a binary Jellyfish Merkle Tree (JMT) with Blake3 hashing for
//! cryptographic state commitment. JMT data is stored in dedicated
//! column families (`jmt_nodes`, `jmt_meta`). On each commit, the JMT is
//! updated and a new state root hash is computed.

mod blocks;
mod chain_reader;
mod chain_writer;
pub(crate) mod column_families;
pub(crate) mod config;
pub(crate) mod core;
mod execution_certs;
mod gc;
pub(crate) mod jmt_snapshot_store;
pub mod jmt_stored;
pub(crate) mod metadata;
mod receipts;
mod recovery;
mod shared;
pub(crate) mod snapshot;
mod store;
pub(crate) mod substate_key;
pub(crate) mod typed_cf;
pub(crate) mod versioned_key;

#[cfg(test)]
mod tests;

pub use config::{CompressionType, RocksDbConfig};
pub use core::{RocksDbStorage, StorageError};
pub use shared::SharedStorage;
pub use snapshot::RocksDbSnapshot;
