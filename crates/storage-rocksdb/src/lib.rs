//! # RocksDB Storage
//!
//! Production storage implementation using RocksDB.
//!
//! All operations are synchronous blocking I/O. Callers in async contexts
//! should use `spawn_blocking` if needed to avoid blocking the runtime.
//!
//! # JVT Integration
//!
//! Uses Jellyfish Verkle Tree (JVT) for cryptographic state commitment.
//! JVT data is stored in dedicated column families (`jmt_nodes`, `jmt_meta`).
//! On each commit, the JVT is updated and a new state root hash is computed.

mod blocks;
pub(crate) mod column_families;
mod commit;
pub(crate) mod config;
mod consensus;
pub(crate) mod core;
mod execution_certs;
mod gc;
pub(crate) mod jvt_snapshot_store;
pub(crate) mod metadata;
mod receipts;
mod recovery;
mod shared;
pub(crate) mod snapshot;
mod store;
pub(crate) mod substate_key;
pub(crate) mod typed_cf;
pub(crate) mod versioned_key;
mod votes;

#[cfg(test)]
mod tests;

pub use config::{CompressionType, RocksDbConfig};
pub use core::{RocksDbStorage, StorageError};
pub use shared::SharedStorage;
pub use snapshot::RocksDbSnapshot;
