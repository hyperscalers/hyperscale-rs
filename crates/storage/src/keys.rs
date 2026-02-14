//! Helper functions for key encoding/decoding used by storage implementations.

use crate::RADIX_PREFIX;
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
///
/// Returns `None` if the prefix is all `0xFF` bytes (no valid exclusive upper bound).
/// In practice this never happens with structured storage keys.
pub fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    debug_assert!(!prefix.is_empty(), "next_prefix called with empty prefix");
    let mut next = prefix.to_vec();
    for i in (0..next.len()).rev() {
        if next[i] < 255 {
            next[i] += 1;
            return Some(next);
        }
        next[i] = 0;
    }
    None
}

/// Build a storage key directly from SubstateWrite fields.
///
/// This is equivalent to converting through `substate_writes_to_database_updates` +
/// `to_storage_key`, but avoids the intermediate `DatabaseUpdates` allocation.
pub fn storage_key_from_write(
    node_id: &NodeId,
    partition: &hyperscale_types::PartitionNumber,
    sort_key: &[u8],
) -> Vec<u8> {
    let radix_node_id = radix_common::types::NodeId(node_id.0);
    let radix_partition = radix_common::types::PartitionNumber(partition.0);

    let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
    let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);

    let partition_key = DbPartitionKey {
        node_key: db_node_key,
        partition_num: db_partition_num,
    };
    let db_sort_key = DbSortKey(sort_key.to_vec());

    to_storage_key(&partition_key, &db_sort_key)
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
