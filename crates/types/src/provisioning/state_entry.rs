//! State-related types for cross-shard execution.

use crate::{BlockHeight, Hash, NodeId, ShardGroupId, TxHash};
use sbor::prelude::*;
use std::sync::Arc;

// ============================================================================
// State entry types with pre-computed storage keys
// ============================================================================

/// A state entry with pre-computed storage key for fast engine lookup.
///
/// This type stores the pre-computed storage key that can be used directly for
/// database lookups without any key transformation at the receiving shard.
///
/// The storage key format is: `db_node_key(50) + partition_num(1) + sort_key(var)`
/// where `db_node_key` is the `SpreadPrefixKeyMapper` hash (expensive to compute).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: `db_node_key` (50 bytes) + partition (1 byte) + `sort_key`
    pub storage_key: Vec<u8>,

    /// SBOR-encoded substate value (None if deleted/doesn't exist).
    pub value: Option<Vec<u8>>,
}

/// Hash prefix length in `db_node_key` (`SpreadPrefixKeyMapper` adds 20-byte hash)
const HASH_PREFIX_LEN: usize = 20;

impl StateEntry {
    /// Create a new DB state entry with pre-computed storage key.
    #[must_use]
    pub const fn new(storage_key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
        Self { storage_key, value }
    }

    /// Extract the `NodeId` from the storage key.
    ///
    /// The storage key format is:
    /// - `db_node_key` (50 bytes: 20-byte hash prefix + 30-byte `node_id`)
    /// - `partition_num` (1 byte)
    /// - `sort_key` (variable)
    ///
    /// The `NodeId` is at bytes [20..50] (after hash prefix).
    #[must_use]
    pub fn node_id(&self) -> Option<NodeId> {
        let start = HASH_PREFIX_LEN;
        let end = start + 30;
        if self.storage_key.len() >= end {
            let mut id = [0u8; 30];
            id.copy_from_slice(&self.storage_key[start..end]);
            Some(NodeId(id))
        } else {
            None
        }
    }

    /// Compute hash of this entry for signing/verification.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(self.storage_key.len() + 32);
        data.extend_from_slice(&self.storage_key);

        match &self.value {
            Some(value_bytes) => {
                let value_hash = Hash::from_bytes(value_bytes);
                data.extend_from_slice(value_hash.as_bytes());
            }
            None => {
                data.extend_from_slice(&[0u8; 32]); // ZERO hash for deletion
            }
        }

        Hash::from_bytes(&data)
    }

    /// Create a test entry from a node ID (for testing only).
    ///
    /// Creates a storage key in the correct format so that `node_id()` can extract
    /// the node ID. Uses a dummy hash prefix (zeros) since tests don't need real
    /// `SpreadPrefixKeyMapper` hashes.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_entry(
        node_id: NodeId,
        partition: u8,
        sort_key: &[u8],
        value: Option<Vec<u8>>,
    ) -> Self {
        // Format: hash_prefix (20) + node_id (30) + partition (1) + sort_key
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + sort_key.len());
        storage_key.extend_from_slice(&[0u8; 20]); // Dummy hash prefix
        storage_key.extend_from_slice(&node_id.0); // Node ID
        storage_key.push(partition); // Partition number
        storage_key.extend_from_slice(sort_key); // Sort key
        Self { storage_key, value }
    }
}

/// Per-tx provision view used inside the execution path.
///
/// Built from a [`crate::Provisions`] bundle when it lands at the execution
/// coordinator: each `TxEntries` in the bundle becomes one `StateProvision`
/// keyed to the tx, carrying the bundle's source/target shard and block
/// height alongside the tx's slice of state entries. Not on the wire.
#[derive(Debug, Clone)]
pub struct StateProvision {
    /// Hash of the transaction this provision is for.
    pub transaction_hash: TxHash,

    /// Target shard (the shard executing the transaction).
    pub target_shard: ShardGroupId,

    /// Source shard (the shard providing the state).
    pub source_shard: ShardGroupId,

    /// Block height when this provision was created (anchors merkle proofs).
    pub block_height: BlockHeight,

    /// The state entries with pre-computed storage keys.
    /// Wrapped in Arc for efficient sharing.
    pub entries: Arc<Vec<StateEntry>>,
}

impl PartialEq for StateProvision {
    fn eq(&self, other: &Self) -> bool {
        self.transaction_hash == other.transaction_hash
            && self.target_shard == other.target_shard
            && self.source_shard == other.source_shard
            && self.block_height == other.block_height
            && *self.entries == *other.entries
    }
}

impl Eq for StateProvision {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_state_entry_hash() {
        let entry = StateEntry::test_entry(NodeId([1u8; 30]), 0, b"key", Some(b"value".to_vec()));

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }
}
