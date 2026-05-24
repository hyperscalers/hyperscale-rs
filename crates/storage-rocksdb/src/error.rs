//! Shared error type for the `RocksDB` backend.
//!
//! Both the shard tier ([`crate::RocksDbShardStorage`]) and the beacon tier
//! ([`crate::RocksDbBeaconStorage`]) surface the same `RocksDB` failures
//! through a single string-wrapped variant — call sites never
//! discriminate beyond "the database returned an error."

/// Error returned by the `RocksDB` backend's fallible entry points.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// `RocksDB` returned an error. Wraps the underlying message so
    /// callers can log it without depending on the `rocksdb` crate.
    #[error("Database error: {0}")]
    DatabaseError(String),
}
