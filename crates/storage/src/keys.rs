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

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{NodeId, PartitionNumber};

    fn test_partition_key(node_key: Vec<u8>, partition_num: u8) -> DbPartitionKey {
        DbPartitionKey {
            node_key,
            partition_num,
        }
    }

    #[test]
    fn test_to_storage_key_format() {
        let pk = test_partition_key(vec![1, 2, 3], 5);
        let sk = DbSortKey(vec![10, 20]);
        let key = to_storage_key(&pk, &sk);

        // Key = RADIX_PREFIX + node_key + partition_num + sort_key
        let mut expected = Vec::new();
        expected.extend_from_slice(RADIX_PREFIX);
        expected.extend_from_slice(&[1, 2, 3]);
        expected.push(5);
        expected.extend_from_slice(&[10, 20]);
        assert_eq!(key, expected);
    }

    #[test]
    fn test_to_storage_key_empty_sort_key() {
        let pk = test_partition_key(vec![1, 2, 3], 0);
        let sk = DbSortKey(vec![]);
        let key = to_storage_key(&pk, &sk);

        let mut expected = Vec::new();
        expected.extend_from_slice(RADIX_PREFIX);
        expected.extend_from_slice(&[1, 2, 3]);
        expected.push(0);
        assert_eq!(key, expected);
    }

    #[test]
    fn test_partition_prefix_format() {
        let pk = test_partition_key(vec![10, 20], 7);
        let prefix = partition_prefix(&pk);

        let mut expected = Vec::new();
        expected.extend_from_slice(RADIX_PREFIX);
        expected.extend_from_slice(&[10, 20]);
        expected.push(7);
        assert_eq!(prefix, expected);
    }

    #[test]
    fn test_partition_prefix_is_prefix_of_storage_key() {
        let pk = test_partition_key(vec![1, 2, 3], 5);
        let sk = DbSortKey(vec![10, 20, 30]);
        let prefix = partition_prefix(&pk);
        let key = to_storage_key(&pk, &sk);

        assert!(key.starts_with(&prefix));
        // The remainder after the prefix should be the sort key
        assert_eq!(&key[prefix.len()..], &[10, 20, 30]);
    }

    #[test]
    fn test_next_prefix_basic() {
        assert_eq!(next_prefix(&[1, 2, 3]), Some(vec![1, 2, 4]));
        assert_eq!(next_prefix(&[0]), Some(vec![1]));
        assert_eq!(next_prefix(&[254]), Some(vec![255]));
    }

    #[test]
    fn test_next_prefix_carry() {
        assert_eq!(next_prefix(&[1, 0xFF]), Some(vec![2, 0]));
        assert_eq!(next_prefix(&[1, 0xFF, 0xFF]), Some(vec![2, 0, 0]));
        assert_eq!(next_prefix(&[0, 0xFF]), Some(vec![1, 0]));
    }

    #[test]
    fn test_next_prefix_all_ff() {
        assert_eq!(next_prefix(&[0xFF]), None);
        assert_eq!(next_prefix(&[0xFF, 0xFF]), None);
        assert_eq!(next_prefix(&[0xFF, 0xFF, 0xFF]), None);
    }

    #[test]
    fn test_next_prefix_single_byte() {
        assert_eq!(next_prefix(&[0]), Some(vec![1]));
        assert_eq!(next_prefix(&[127]), Some(vec![128]));
        assert_eq!(next_prefix(&[254]), Some(vec![255]));
        assert_eq!(next_prefix(&[255]), None);
    }

    #[test]
    fn test_storage_key_from_write() {
        let node_id = NodeId([1; 30]);
        let partition = PartitionNumber(3);
        let sort_key = vec![10, 20];
        let key = storage_key_from_write(&node_id, &partition, &sort_key);

        // Must start with RADIX_PREFIX
        assert!(key.starts_with(RADIX_PREFIX));
        // Must end with sort key
        assert!(key.ends_with(&sort_key));
        // The byte just before the sort key must be the partition number's
        // mapped value. SpreadPrefixKeyMapper preserves the partition number,
        // so it should equal the raw value.
        assert_eq!(key[key.len() - sort_key.len() - 1], partition.0);
        // Should be deterministic
        let key2 = storage_key_from_write(&node_id, &partition, &sort_key);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_storage_key_from_write_different_inputs_differ() {
        let base = storage_key_from_write(&NodeId([1; 30]), &PartitionNumber(0), &[10]);
        let diff_node = storage_key_from_write(&NodeId([2; 30]), &PartitionNumber(0), &[10]);
        let diff_part = storage_key_from_write(&NodeId([1; 30]), &PartitionNumber(1), &[10]);
        let diff_sort = storage_key_from_write(&NodeId([1; 30]), &PartitionNumber(0), &[11]);

        assert_ne!(
            base, diff_node,
            "different node should produce different key"
        );
        assert_ne!(
            base, diff_part,
            "different partition should produce different key"
        );
        assert_ne!(
            base, diff_sort,
            "different sort key should produce different key"
        );
    }

    #[test]
    fn test_node_prefix_format() {
        let node_id = NodeId([2; 30]);
        let prefix = node_prefix(&node_id);

        // Must start with RADIX_PREFIX
        assert!(prefix.starts_with(RADIX_PREFIX));
        // Should be deterministic
        let prefix2 = node_prefix(&node_id);
        assert_eq!(prefix, prefix2);
    }

    #[test]
    fn test_node_prefix_is_prefix_of_storage_key() {
        let node_id = NodeId([3; 30]);
        let partition = PartitionNumber(5);
        let sort_key = vec![10, 20];

        let n_prefix = node_prefix(&node_id);
        let s_key = storage_key_from_write(&node_id, &partition, &sort_key);

        assert!(
            s_key.starts_with(&n_prefix),
            "storage key should start with node prefix"
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "next_prefix called with empty prefix")]
    fn test_next_prefix_empty_panics() {
        next_prefix(&[]);
    }

    #[test]
    fn test_different_nodes_have_different_prefixes() {
        let p1 = node_prefix(&NodeId([1; 30]));
        let p2 = node_prefix(&NodeId([2; 30]));
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_storage_key_from_write_matches_to_storage_key() {
        // storage_key_from_write should produce the same result as
        // going through the SpreadPrefixKeyMapper + to_storage_key path
        let node_id = NodeId([5; 30]);
        let partition = PartitionNumber(2);
        let sort_key = vec![10, 20, 30];
        let key = storage_key_from_write(&node_id, &partition, &sort_key);

        // Manually construct via SpreadPrefixKeyMapper + to_storage_key
        let radix_node_id = radix_common::types::NodeId(node_id.0);
        let radix_partition = radix_common::types::PartitionNumber(partition.0);
        let db_node_key =
            radix_substate_store_interface::db_key_mapper::SpreadPrefixKeyMapper::to_db_node_key(
                &radix_node_id,
            );
        let db_partition_num =
            radix_substate_store_interface::db_key_mapper::SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
        let pk = DbPartitionKey {
            node_key: db_node_key,
            partition_num: db_partition_num,
        };
        let sk = DbSortKey(sort_key);
        let expected = to_storage_key(&pk, &sk);

        assert_eq!(key, expected);
    }

    #[test]
    fn test_next_prefix_used_for_range_scan() {
        // Verify that [prefix, next_prefix) correctly bounds all keys with that prefix
        let pk = test_partition_key(vec![1, 2, 3], 5);
        let prefix = partition_prefix(&pk);
        let end = next_prefix(&prefix).unwrap();

        // Keys with sort key should fall within [prefix, end)
        for sk_byte in [0u8, 1, 127, 254, 255] {
            let key = to_storage_key(&pk, &DbSortKey(vec![sk_byte]));
            assert!(key >= prefix, "key should be >= prefix");
            assert!(key < end, "key should be < end");
        }

        // A key for a different partition should be outside the range
        let other_pk = test_partition_key(vec![1, 2, 3], 6);
        let other_key = to_storage_key(&other_pk, &DbSortKey(vec![0]));
        assert!(
            other_key >= end || other_key < prefix,
            "key from different partition should be outside range"
        );
    }
}
