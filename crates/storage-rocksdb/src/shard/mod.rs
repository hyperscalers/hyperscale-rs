//! Shard-side `RocksDB` backend — `RocksDbShardStorage`, its `SharedStorage`
//! Arc wrapper, JMT integration, per-shard column families, GC, and
//! recovery flows.
//!
//! Top-level [`crate::typed_cf`](crate::typed_cf) and
//! [`crate::config`](crate::config) host shared abstractions reused
//! by the parallel beacon-side backend.

pub(crate) mod blocks;
pub(crate) mod chain_reader;
pub(crate) mod chain_writer;
pub(crate) mod checkpoints;
pub(crate) mod column_families;
pub(crate) mod core;
pub(crate) mod execution_certs;
pub(crate) mod gc;
pub(crate) mod jmt_snapshot_store;
pub(crate) mod jmt_stored;
pub(crate) mod metadata;
pub(crate) mod receipts;
pub(crate) mod recovery;
pub(crate) mod shared;
pub(crate) mod snapshot;
pub(crate) mod store;
pub(crate) mod substate_key;
pub(crate) mod versioned_key;

#[cfg(test)]
mod tests;
