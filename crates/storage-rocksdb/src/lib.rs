//! # `RocksDB` Storage
//!
//! Production storage implementation using `RocksDB`.
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

pub mod beacon;
pub(crate) mod config;
pub(crate) mod error;
pub mod shard;
pub(crate) mod typed_cf;

pub use beacon::core::RocksDbBeaconStorage;
pub use config::{CompressionType, RocksDbConfig};
pub use error::StorageError;
pub use shard::core::RocksDbShardStorage;
pub use shard::shared::SharedStorage;
pub use shard::snapshot::RocksDbSnapshot;
