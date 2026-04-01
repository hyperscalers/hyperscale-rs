//! Storage key encoding — the byte-level contract between storage backends
//! and overlay implementations (e.g., provision overlays in the engine).
//!
//! Key layout: `[node_key][partition_num (1B)][sort_key]`
//!
//! Both the RocksDB backend and the engine's provision overlay use these
//! functions to produce compatible keys.

use hyperscale_types::NodeId;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

/// Convert Radix partition key + sort key to a flat storage key.
pub fn to_storage_key(partition_key: &DbPartitionKey, sort_key: &DbSortKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(partition_key.node_key.len() + 1 + sort_key.0.len());
    key.extend_from_slice(&partition_key.node_key);
    key.push(partition_key.partition_num);
    key.extend_from_slice(&sort_key.0);
    key
}

/// Build storage key prefix for a partition (for range scans / overlays).
pub fn partition_prefix(partition_key: &DbPartitionKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(partition_key.node_key.len() + 1);
    prefix.extend_from_slice(&partition_key.node_key);
    prefix.push(partition_key.partition_num);
    prefix
}

/// Compute the exclusive end key for a prefix scan.
///
/// Returns `None` if the prefix is all `0xFF` bytes (no valid exclusive upper bound).
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

// ─── NodeId ↔ db_node_key conversions ────────────────────────────────────────
//
// These use SpreadPrefixKeyMapper to convert between our NodeId type and the
// Radix db_node_key format (20-byte hash prefix + 30-byte NodeId).
// Used by writes.rs for state change extraction and shard filtering.

/// Build the storage key prefix for a given NodeId (for node-level iteration).
pub fn node_prefix(node_id: &NodeId) -> Vec<u8> {
    node_entity_key(node_id)
}

/// Get the db_node_key (entity key) for a NodeId.
pub fn node_entity_key(node_id: &NodeId) -> Vec<u8> {
    let radix_node_id = radix_common::types::NodeId(node_id.0);
    SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id)
}

/// Extract the NodeId from a SpreadPrefixKeyMapper db_node_key.
///
/// DbNodeKey format: 20-byte hash prefix + 30-byte NodeId.
/// Returns None if the key is too short.
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    const HASH_PREFIX_LEN: usize = 20;
    const NODE_ID_LEN: usize = 30;
    if db_node_key.len() < HASH_PREFIX_LEN + NODE_ID_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
    Some(NodeId(id))
}
