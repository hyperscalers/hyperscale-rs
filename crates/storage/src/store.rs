//! Storage traits for Radix Engine execution.
//!
//! This module defines the storage abstraction used by runners to persist Radix state.

use hyperscale_types::{Hash, NodeId};
use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DbSortKey, SubstateDatabase,
};

/// Extension trait for substate storage with snapshots, node listing, and JMT state roots.
///
/// This trait extends Radix's `SubstateDatabase` with additional methods needed
/// for deterministic simulation and state commitment:
/// - `snapshot()` - Create isolated views for parallel execution
/// - `list_substates_for_node()` - Enumerate substates for cross-shard provisioning
/// - `state_version()` / `state_root_hash()` - JMT state commitment
///
/// All implementations use Jellyfish Merkle Tree (JMT) internally to maintain
/// cryptographic state roots. This is handled automatically on each `commit()`.
///
/// Runner storage types (`SimStorage`, `RocksDbStorage`) implement this trait
/// along with `SubstateDatabase` and `CommittableSubstateDatabase`.
pub trait SubstateStore: SubstateDatabase + CommittableSubstateDatabase + Send + Sync {
    /// The snapshot type returned by this storage.
    type Snapshot<'a>: SubstateDatabase + Send + Sync
    where
        Self: 'a;

    /// Create a snapshot for isolated reads.
    ///
    /// Snapshots provide a consistent point-in-time view of the database,
    /// essential for parallel transaction execution where each transaction
    /// needs an isolated view.
    ///
    /// The snapshot borrows from the storage, ensuring the storage outlives
    /// the snapshot. This enables RocksDB's native snapshot feature which
    /// provides true point-in-time isolation from concurrent writes.
    fn snapshot(&self) -> Self::Snapshot<'_>;

    /// List all substates for a given NodeId.
    ///
    /// Returns an iterator of (partition_num, sort_key, value) tuples.
    /// Used by cross-shard provisioning to collect state for other shards.
    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_>;

    /// Current state version.
    ///
    /// This is a monotonically increasing counter that increments on each `commit()`.
    /// Version 0 means no commits have occurred (empty/genesis state).
    fn state_version(&self) -> u64;

    /// Current JMT state root hash.
    ///
    /// Returns the Merkle root of all substates at the current version.
    /// This hash cryptographically commits to the entire state and can be used
    /// for state sync, light client proofs, and cross-validator consistency checks.
    ///
    /// Returns a zero hash if no commits have occurred.
    fn state_root_hash(&self) -> Hash;
}

/// Prefix for all Radix Engine data in storage.
///
/// All Radix substates are stored with this prefix to allow other data
/// (consensus metadata, etc.) to coexist in the same storage backend.
pub const RADIX_PREFIX: &[u8] = b"radix:";
