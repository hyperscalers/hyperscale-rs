//! Shard-side in-memory storage backend — `SimShardStorage`, its snapshot,
//! and the tree-store adapter that mirrors the `RocksDB` JMT semantics
//! for deterministic simulation.
//!
//! Sibling [`crate::beacon`](crate::beacon) hosts the parallel
//! beacon-chain in-memory backend.

pub(crate) mod boundary;
pub(crate) mod chain_reader;
pub(crate) mod chain_writer;
pub(crate) mod core;
pub(crate) mod snapshot;
pub(crate) mod split;
pub(crate) mod state;
pub(crate) mod store;
pub(crate) mod tree_store;
pub(crate) mod vote_registers;

#[cfg(test)]
mod tests;
