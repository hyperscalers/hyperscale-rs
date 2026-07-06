//! Beacon-side `RocksDB` backend — `RocksDbBeaconStorage`, its two
//! column families, and the [`BeaconChainReader`]/[`BeaconChainWriter`]
//! implementations.
//!
//! [`BeaconChainReader`]: hyperscale_storage::BeaconChainReader
//! [`BeaconChainWriter`]: hyperscale_storage::BeaconChainWriter
//!
//! The beacon instance is a separate `RocksDB` database from any
//! per-shard one — different directory, disjoint CF set. Top-level
//! [`crate::config`](crate::config) supplies the shared
//! [`RocksDbConfig`](crate::RocksDbConfig); beacon doesn't reuse
//! [`crate::typed_cf`](crate::typed_cf) because two CFs don't earn the
//! parameterisation.

pub(crate) mod chain_reader;
pub(crate) mod chain_writer;
pub(crate) mod column_families;
pub(crate) mod core;
pub(crate) mod ratify_registers;

#[cfg(test)]
mod tests;
