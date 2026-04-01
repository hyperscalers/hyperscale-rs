//! Substate key encoding for RocksDB.
//!
//! Constructs the composite byte keys used in the `state` and `versioned_substates`
//! column families. These are RocksDB-specific — the memory storage backend uses
//! native structured keys instead.
//!
//! Key layout: `[node_key (50B)][partition_num (1B)][sort_key (var)]`
//!
//! The `node_key` is a SpreadPrefixKeyMapper-encoded NodeId (hash prefix + NodeId),
//! ensuring even distribution across RocksDB's key space. The partition_num and
//! sort_key are appended directly, preserving lexicographic ordering for prefix scans.

use crate::typed_cf::DbCodec;
use radix_substate_store_interface::db_key_mapper::DatabaseKeyMapper;
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

/// Codec for composite substate keys: `node_key ++ partition_num ++ sort_key`.
#[derive(Default)]
pub(crate) struct SubstateKeyCodec;

impl DbCodec<(DbPartitionKey, DbSortKey)> for SubstateKeyCodec {
    fn encode_to(&self, value: &(DbPartitionKey, DbSortKey), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.node_key);
        buf.push(value.0.partition_num);
        buf.extend_from_slice(&value.1 .0);
    }

    fn decode(&self, bytes: &[u8]) -> (DbPartitionKey, DbSortKey) {
        let (entity_key, partition_num, sort_key) =
            decompose_storage_key(bytes).expect("invalid storage key");
        (
            DbPartitionKey {
                node_key: entity_key.to_vec(),
                partition_num,
            },
            DbSortKey(sort_key.to_vec()),
        )
    }
}

/// Build storage key prefix for a partition (for range scans).
pub(crate) fn partition_prefix(partition_key: &DbPartitionKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(partition_key.node_key.len() + 1);
    prefix.extend_from_slice(&partition_key.node_key);
    prefix.push(partition_key.partition_num);
    prefix
}

/// Build the storage key prefix for a given NodeId (for node-level iteration).
///
/// This is the hash-spread 50-byte representation of the NodeId (same as
/// `node_entity_key` — the entity prefix IS the node prefix).
pub(crate) fn node_prefix(node_id: &hyperscale_types::NodeId) -> Vec<u8> {
    let radix_node_id = radix_common::types::NodeId(node_id.0);
    radix_substate_store_interface::db_key_mapper::SpreadPrefixKeyMapper::to_db_node_key(
        &radix_node_id,
    )
}

/// Get the entity key (db_node_key) for a NodeId. Same as `node_prefix`.
pub(crate) fn node_entity_key(node_id: &hyperscale_types::NodeId) -> Vec<u8> {
    node_prefix(node_id)
}

/// Entity key length in storage keys: 20 bytes hash prefix + 30 bytes NodeId.
const ENTITY_KEY_LEN: usize = 50;

/// Decompose a storage key into its three components.
///
/// Storage key layout: `entity_key(50) + partition_num(1) + sort_key(var)`
fn decompose_storage_key(storage_key: &[u8]) -> Option<(&[u8], u8, &[u8])> {
    let min_len = ENTITY_KEY_LEN + 1;
    if storage_key.len() < min_len {
        return None;
    }
    let entity_key = &storage_key[..ENTITY_KEY_LEN];
    let partition_num = storage_key[ENTITY_KEY_LEN];
    let sort_key = &storage_key[min_len..];
    Some((entity_key, partition_num, sort_key))
}
