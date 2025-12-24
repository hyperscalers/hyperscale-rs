//! Storage traits for Radix Engine execution.
//!
//! This module defines the storage abstraction used by runners to persist Radix state.
//!
//! # Design
//!
//! Storage is an implementation detail of runners, not the state machine.
//! The state machine emits `Action::ExecuteTransactions` and receives
//! `Event::TransactionsExecuted` - it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimStorage`)
//! - `ProductionRunner` uses RocksDB (`RocksDbStorage`)
//!
//! # Architecture
//!
//! Rather than having our own `Storage` trait that we adapt to Radix's `SubstateDatabase`,
//! runner storage types implement `SubstateDatabase` + `CommittableSubstateDatabase` directly,
//! plus our `SubstateStore` extension trait for snapshots and node listing.

use hyperscale_types::NodeId;
use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DbSortKey, SubstateDatabase,
};

/// Extension trait for substate storage that adds snapshot and node listing capabilities.
///
/// This trait extends Radix's `SubstateDatabase` with additional methods needed
/// for deterministic simulation:
/// - `snapshot()` - Create isolated views for parallel execution
/// - `list_substates_for_node()` - Enumerate substates for cross-shard provisioning
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
}

/// Prefix for all Radix Engine data in storage.
///
/// All Radix substates are stored with this prefix to allow other data
/// (consensus metadata, etc.) to coexist in the same storage backend.
pub const RADIX_PREFIX: &[u8] = b"radix:";

/// Helper functions for key encoding/decoding used by storage implementations.
pub mod keys {
    use super::RADIX_PREFIX;
    use hyperscale_types::NodeId;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

    /// Convert Radix partition key + sort key to storage key.
    pub fn to_storage_key(partition_key: &DbPartitionKey, sort_key: &DbSortKey) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            RADIX_PREFIX.len() + partition_key.node_key.len() + 1 + sort_key.0.len(),
        );
        key.extend_from_slice(RADIX_PREFIX);
        key.extend_from_slice(&partition_key.node_key);
        key.push(partition_key.partition_num);
        key.extend_from_slice(&sort_key.0);
        key
    }

    /// Build storage key prefix for a partition.
    pub fn partition_prefix(partition_key: &DbPartitionKey) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(RADIX_PREFIX.len() + partition_key.node_key.len() + 1);
        prefix.extend_from_slice(RADIX_PREFIX);
        prefix.extend_from_slice(&partition_key.node_key);
        prefix.push(partition_key.partition_num);
        prefix
    }

    /// Compute the exclusive end key for a prefix scan.
    pub fn next_prefix(prefix: &[u8]) -> Vec<u8> {
        let mut next = prefix.to_vec();
        for i in (0..next.len()).rev() {
            if next[i] < 255 {
                next[i] += 1;
                return next;
            }
            next[i] = 0;
        }
        next.push(0);
        next
    }

    /// Build the storage key prefix for a given NodeId.
    pub fn node_prefix(node_id: &NodeId) -> Vec<u8> {
        let radix_node_id = radix_common::types::NodeId(node_id.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
        let mut prefix = Vec::with_capacity(RADIX_PREFIX.len() + db_node_key.len());
        prefix.extend_from_slice(RADIX_PREFIX);
        prefix.extend_from_slice(&db_node_key);
        prefix
    }
}
