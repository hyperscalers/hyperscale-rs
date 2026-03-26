//! Storage traits for Radix Engine execution.
//!
//! This module defines the storage abstraction used by runners to persist Radix state.

use hyperscale_types::{Hash, NodeId, SubstateInclusionProof};
use radix_substate_store_interface::interface::{DbSortKey, SubstateDatabase};

/// Extension trait for substate storage with snapshots, node listing, and JVT state roots.
///
/// This trait extends Radix's `SubstateDatabase` with additional methods needed
/// for deterministic simulation and state commitment:
/// - `snapshot()` - Create isolated views for parallel execution
/// - `list_substates_for_node()` - Enumerate substates for cross-shard provisioning
/// - `jvt_version()` / `state_root_hash()` - JVT state commitment
///
/// All implementations use Jellyfish Verkle Tree (JVT) internally to maintain
/// cryptographic state roots, updated on each `commit_block()`.
///
/// Runner storage types (`SimStorage`, `RocksDbStorage`) implement this trait
/// along with `SubstateDatabase`.
pub trait SubstateStore: SubstateDatabase + Send + Sync {
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

    /// Returns the block height of the last committed JVT state.
    ///
    /// This equals the block height because JVT version = block height.
    /// Returns 0 for fresh/genesis state.
    fn jvt_version(&self) -> u64;

    /// Current JVT state root hash.
    ///
    /// Returns the Verkle root of all substates at the current version.
    /// This hash cryptographically commits to the entire state and can be used
    /// for state sync, light client proofs, and cross-validator consistency checks.
    ///
    /// Returns a zero hash if no commits have occurred.
    fn state_root_hash(&self) -> Hash;

    /// List all substates for a node at a specific historical block height (= JVT version).
    ///
    /// Traverses the 3-tier JVT at the given height and looks up raw substate
    /// values from the leaf association table.
    ///
    /// Returns `Some(entries)` on success (may be empty if the node has no
    /// substates at that height), or `None` if the height is unavailable
    /// (e.g. garbage-collected or not yet committed).
    ///
    /// Used by cross-shard provision paths to serve historical state that
    /// can be verified against the original block's `state_root`.
    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>>;

    /// Generate an aggregated verkle inclusion proof for the given storage keys.
    /// Returns `None` if the requested version is unavailable (GC'd or not committed).
    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<SubstateInclusionProof>;
}
