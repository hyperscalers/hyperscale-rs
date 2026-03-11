//! Conversion from SubstateWrites to DatabaseUpdates.

use hyperscale_types::{ShardGroupId, SubstateWrite, TransactionCertificate};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use radix_substate_store_interface::interface::{
    DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use std::sync::Arc;

/// Convert SubstateWrites back to DatabaseUpdates for committing to storage.
///
/// This is the inverse of `extract_substate_writes()`. Used when applying
/// certificate state writes during `PersistTransactionCertificate`.
///
/// # Arguments
///
/// * `writes` - The substate writes to convert (typically from a certificate's shard_proofs)
///
/// # Returns
///
/// A `DatabaseUpdates` structure suitable for JMT and substate storage operations
pub fn substate_writes_to_database_updates(writes: &[SubstateWrite]) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();

    for write in writes {
        let radix_node_id = radix_common::types::NodeId(write.node_id.0);
        let radix_partition = radix_common::types::PartitionNumber(write.partition.0);

        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
        let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
        let db_sort_key = DbSortKey(write.sort_key.clone());

        let node_updates =
            updates
                .node_updates
                .entry(db_node_key)
                .or_insert_with(|| NodeDatabaseUpdates {
                    partition_updates: indexmap::IndexMap::new(),
                });

        let partition_updates = node_updates
            .partition_updates
            .entry(db_partition_num)
            .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            });

        let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates else {
            unreachable!("writes conversion always creates Delta partitions");
        };
        substate_updates.insert(db_sort_key, DatabaseUpdate::Set(write.value.clone()));
    }

    updates
}

/// Merge a slice of per-certificate `DatabaseUpdates` into a single combined update.
///
/// Later certificates take precedence for conflicting keys (last writer wins).
/// This is deterministic: certificates are processed left-to-right.
pub fn merge_database_updates(updates_list: &[DatabaseUpdates]) -> DatabaseUpdates {
    if updates_list.is_empty() {
        return DatabaseUpdates::default();
    }
    if updates_list.len() == 1 {
        return updates_list[0].clone();
    }
    let mut merged = DatabaseUpdates::default();
    for updates in updates_list {
        merge_into(&mut merged, updates);
    }
    merged
}

/// Merge `source` into `target` in place.
///
/// Later entries (from `source`) take precedence for conflicting keys.
pub fn merge_into(target: &mut DatabaseUpdates, source: &DatabaseUpdates) {
    for (entity_key, node_updates) in &source.node_updates {
        merge_node_updates(
            target.node_updates.entry(entity_key.clone()).or_default(),
            node_updates,
        );
    }
}

fn merge_node_updates(target: &mut NodeDatabaseUpdates, source: &NodeDatabaseUpdates) {
    for (partition, part_updates) in &source.partition_updates {
        match target.partition_updates.entry(*partition) {
            indexmap::map::Entry::Vacant(e) => {
                e.insert(part_updates.clone());
            }
            indexmap::map::Entry::Occupied(mut e) => {
                merge_partition_updates(e.get_mut(), part_updates);
            }
        }
    }
}

fn merge_partition_updates(
    target: &mut PartitionDatabaseUpdates,
    source: &PartitionDatabaseUpdates,
) {
    match (target, source) {
        // Delta + Delta: extend substate_updates, source wins for same key.
        (
            PartitionDatabaseUpdates::Delta {
                substate_updates: target_updates,
            },
            PartitionDatabaseUpdates::Delta {
                substate_updates: source_updates,
            },
        ) => {
            target_updates.extend(source_updates.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        // Delta + Reset: source Reset replaces target entirely.
        // Reset + Reset: source Reset replaces target entirely.
        (target, PartitionDatabaseUpdates::Reset { .. }) => {
            *target = source.clone();
        }
        // Reset + Delta: apply delta on top of Reset's values.
        (
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            },
            PartitionDatabaseUpdates::Delta { substate_updates },
        ) => {
            for (sort_key, update) in substate_updates {
                match update {
                    DatabaseUpdate::Set(value) => {
                        new_substate_values.insert(sort_key.clone(), value.clone());
                    }
                    DatabaseUpdate::Delete => {
                        new_substate_values.swap_remove(sort_key);
                    }
                }
            }
        }
    }
}

/// Extract per-certificate state writes for a given local shard.
///
/// For each certificate, extracts the `state_writes` from the shard proof
/// matching `local_shard`. Certificates without a proof for the local shard
/// produce an empty `Vec`.
pub fn extract_writes_per_cert(
    certificates: &[Arc<TransactionCertificate>],
    local_shard: ShardGroupId,
) -> Vec<Vec<SubstateWrite>> {
    certificates
        .iter()
        .map(|cert| {
            cert.shard_proofs
                .get(&local_shard)
                .map(|proof| proof.state_writes.clone())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        make_multi_shard_certificate, make_substate_write, make_test_certificate,
    };
    use hyperscale_types::ShardGroupId;
    use radix_common::prelude::DatabaseUpdate;

    #[test]
    fn test_substate_writes_to_database_updates_single() {
        let writes = vec![make_substate_write(1, 0, vec![10, 20], vec![99, 88])];
        let updates = substate_writes_to_database_updates(&writes);

        assert_eq!(updates.node_updates.len(), 1);
        let (_, node_updates) = updates.node_updates.iter().next().unwrap();
        assert_eq!(node_updates.partition_updates.len(), 1);
        let (_, partition_updates) = node_updates.partition_updates.iter().next().unwrap();
        match partition_updates {
            PartitionDatabaseUpdates::Delta { substate_updates } => {
                assert_eq!(substate_updates.len(), 1);
                let (sort_key, update) = substate_updates.iter().next().unwrap();
                assert_eq!(sort_key.0, vec![10, 20]);
                assert!(matches!(update, DatabaseUpdate::Set(v) if v == &vec![99, 88]));
            }
            _ => panic!("expected Delta partition updates"),
        }
    }

    #[test]
    fn test_substate_writes_to_database_updates_multiple_nodes() {
        let writes = vec![
            make_substate_write(1, 0, vec![10], vec![1]),
            make_substate_write(2, 0, vec![20], vec![2]),
        ];
        let updates = substate_writes_to_database_updates(&writes);
        assert_eq!(updates.node_updates.len(), 2);
    }

    #[test]
    fn test_substate_writes_to_database_updates_same_partition() {
        let writes = vec![
            make_substate_write(1, 0, vec![10], vec![1]),
            make_substate_write(1, 0, vec![20], vec![2]),
        ];
        let updates = substate_writes_to_database_updates(&writes);

        assert_eq!(updates.node_updates.len(), 1);
        let (_, node_updates) = updates.node_updates.iter().next().unwrap();
        assert_eq!(node_updates.partition_updates.len(), 1);
        let (_, partition_updates) = node_updates.partition_updates.iter().next().unwrap();
        match partition_updates {
            PartitionDatabaseUpdates::Delta { substate_updates } => {
                assert_eq!(substate_updates.len(), 2);
            }
            _ => panic!("expected Delta partition updates"),
        }
    }

    #[test]
    fn test_substate_writes_to_database_updates_empty() {
        let updates = substate_writes_to_database_updates(&[]);
        assert!(updates.node_updates.is_empty());
    }

    #[test]
    fn test_substate_writes_to_database_updates_multiple_partitions() {
        let writes = vec![
            make_substate_write(1, 0, vec![10], vec![1]),
            make_substate_write(1, 3, vec![20], vec![2]),
        ];
        let updates = substate_writes_to_database_updates(&writes);

        assert_eq!(updates.node_updates.len(), 1);
        let (_, node_updates) = updates.node_updates.iter().next().unwrap();
        assert_eq!(node_updates.partition_updates.len(), 2);
    }

    #[test]
    fn test_substate_writes_last_write_wins() {
        let writes = vec![
            make_substate_write(1, 0, vec![10], vec![1]),
            make_substate_write(1, 0, vec![10], vec![99]),
        ];
        let updates = substate_writes_to_database_updates(&writes);

        let (_, node_updates) = updates.node_updates.iter().next().unwrap();
        let (_, partition_updates) = node_updates.partition_updates.iter().next().unwrap();
        match partition_updates {
            PartitionDatabaseUpdates::Delta { substate_updates } => {
                assert_eq!(substate_updates.len(), 1);
                let (_, update) = substate_updates.iter().next().unwrap();
                assert!(
                    matches!(update, DatabaseUpdate::Set(v) if v == &vec![99]),
                    "last write should win for duplicate sort keys"
                );
            }
            _ => panic!("expected Delta partition updates"),
        }
    }

    #[test]
    fn test_extract_writes_per_cert_matching_shard() {
        let shard = ShardGroupId(0);
        let writes = vec![make_substate_write(1, 0, vec![10], vec![1])];
        let cert = Arc::new(make_test_certificate(42, shard, writes.clone()));

        let result = extract_writes_per_cert(&[cert], shard);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], writes);
    }

    #[test]
    fn test_extract_writes_per_cert_missing_shard() {
        let cert = Arc::new(make_test_certificate(42, ShardGroupId(0), vec![]));
        let result = extract_writes_per_cert(&[cert], ShardGroupId(99));
        assert_eq!(result.len(), 1);
        assert!(result[0].is_empty());
    }

    #[test]
    fn test_extract_writes_per_cert_mixed() {
        let shard = ShardGroupId(0);
        let other_shard = ShardGroupId(1);
        let writes = vec![make_substate_write(1, 0, vec![10], vec![1])];

        let cert_match = Arc::new(make_test_certificate(1, shard, writes.clone()));
        let cert_miss = Arc::new(make_test_certificate(
            2,
            other_shard,
            vec![make_substate_write(2, 0, vec![20], vec![2])],
        ));

        let result = extract_writes_per_cert(&[cert_match, cert_miss], shard);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], writes);
        assert!(result[1].is_empty());
    }

    #[test]
    fn test_extract_writes_per_cert_empty_certs() {
        let result = extract_writes_per_cert(&[], ShardGroupId(0));
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_writes_per_cert_preserves_order() {
        let shard = ShardGroupId(0);
        let cert1 = Arc::new(make_test_certificate(
            1,
            shard,
            vec![make_substate_write(1, 0, vec![10], vec![1])],
        ));
        let cert2 = Arc::new(make_test_certificate(
            2,
            shard,
            vec![make_substate_write(2, 0, vec![20], vec![2])],
        ));
        let cert3 = Arc::new(make_test_certificate(
            3,
            shard,
            vec![make_substate_write(3, 0, vec![30], vec![3])],
        ));

        let result = extract_writes_per_cert(&[cert1, cert2, cert3], shard);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0][0].value, vec![1]);
        assert_eq!(result[1][0].value, vec![2]);
        assert_eq!(result[2][0].value, vec![3]);
    }

    #[test]
    fn test_extract_writes_per_cert_multi_shard_certificate() {
        // A certificate with proofs for shard 0 AND shard 1.
        // Extracting for shard 0 should return only shard 0's writes.
        let shard0_writes = vec![make_substate_write(1, 0, vec![10], vec![1])];
        let shard1_writes = vec![make_substate_write(2, 0, vec![20], vec![2])];
        let cert = Arc::new(make_multi_shard_certificate(
            1,
            vec![
                (ShardGroupId(0), shard0_writes.clone()),
                (ShardGroupId(1), shard1_writes.clone()),
            ],
        ));

        let result_shard0 = extract_writes_per_cert(std::slice::from_ref(&cert), ShardGroupId(0));
        assert_eq!(result_shard0.len(), 1);
        assert_eq!(result_shard0[0], shard0_writes);

        let result_shard1 = extract_writes_per_cert(std::slice::from_ref(&cert), ShardGroupId(1));
        assert_eq!(result_shard1.len(), 1);
        assert_eq!(result_shard1[0], shard1_writes);

        // Shard 2 has no proof — should return empty writes
        let result_shard2 = extract_writes_per_cert(&[cert], ShardGroupId(2));
        assert_eq!(result_shard2.len(), 1);
        assert!(result_shard2[0].is_empty());
    }

    // Helper to create a Delta DatabaseUpdates with a single node/partition/substate.
    fn make_delta_updates(
        node_key: &[u8],
        partition: u8,
        sort_key: Vec<u8>,
        update: DatabaseUpdate,
    ) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let node_updates = updates.node_updates.entry(node_key.to_vec()).or_default();
        let partition_updates = node_updates
            .partition_updates
            .entry(partition)
            .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            });
        if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
            substate_updates.insert(DbSortKey(sort_key), update);
        }
        updates
    }

    fn make_reset_updates(
        node_key: &[u8],
        partition: u8,
        values: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> DatabaseUpdates {
        let mut new_substate_values = indexmap::IndexMap::new();
        for (k, v) in values {
            new_substate_values.insert(DbSortKey(k), v);
        }
        let mut updates = DatabaseUpdates::default();
        let node_updates = updates.node_updates.entry(node_key.to_vec()).or_default();
        node_updates.partition_updates.insert(
            partition,
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            },
        );
        updates
    }

    fn get_delta_value(
        updates: &DatabaseUpdates,
        node_key: &[u8],
        partition: u8,
        sort_key: &[u8],
    ) -> Option<DatabaseUpdate> {
        let nk: Vec<u8> = node_key.to_vec();
        let pk: u8 = partition;
        let sk = DbSortKey(sort_key.to_vec());
        updates.node_updates.get(&nk).and_then(|n| {
            n.partition_updates.get(&pk).and_then(|p| {
                if let PartitionDatabaseUpdates::Delta { substate_updates } = p {
                    substate_updates.get(&sk).cloned()
                } else {
                    None
                }
            })
        })
    }

    fn get_reset_values(
        updates: &DatabaseUpdates,
        node_key: &[u8],
        partition: u8,
    ) -> Option<indexmap::IndexMap<DbSortKey, Vec<u8>>> {
        let nk: Vec<u8> = node_key.to_vec();
        let pk: u8 = partition;
        updates.node_updates.get(&nk).and_then(|n| {
            n.partition_updates.get(&pk).and_then(|p| {
                if let PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } = p
                {
                    Some(new_substate_values.clone())
                } else {
                    None
                }
            })
        })
    }

    #[test]
    fn test_merge_delta_delta_same_key_last_wins() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![20])
        );
    }

    #[test]
    fn test_merge_delta_delta_disjoint_keys() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![2], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
        assert!(get_delta_value(&merged, b"node1", 0, &[2]).is_some());
    }

    #[test]
    fn test_merge_delta_then_reset_replaces() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_reset_updates(b"node1", 0, vec![(vec![5], vec![50])]);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals.get(&DbSortKey(vec![5])).unwrap(), &vec![50]);
    }

    #[test]
    fn test_merge_reset_then_delta_set() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10])]);
        let u2 = make_delta_updates(b"node1", 0, vec![2], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals.get(&DbSortKey(vec![1])).unwrap(), &vec![10]);
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_reset_then_delta_delete() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10]), (vec![2], vec![20])]);
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Delete);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert!(vals.get(&DbSortKey(vec![1])).is_none());
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_reset_then_reset_replaces() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10])]);
        let u2 = make_reset_updates(b"node1", 0, vec![(vec![2], vec![20])]);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_multi_cert_ordering() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let u3 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![30]));
        let merged = merge_database_updates(&[u1, u2, u3]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![30])
        );
    }

    #[test]
    fn test_merge_with_empty_is_identity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let empty = DatabaseUpdates::default();
        let merged = merge_database_updates(&[u1.clone(), empty]);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
    }

    #[test]
    fn test_merge_different_entities() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node2", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert_eq!(merged.node_updates.len(), 2);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
        assert!(get_delta_value(&merged, b"node2", 0, &[1]).is_some());
    }

    #[test]
    fn test_merge_different_partitions_same_entity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 1, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert_eq!(merged.node_updates.len(), 1);
        let nk: Vec<u8> = b"node1".to_vec();
        let node = merged.node_updates.get(&nk).unwrap();
        assert_eq!(node.partition_updates.len(), 2);
    }

    #[test]
    fn test_merge_delta_set_then_delete() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Delete);
        let merged = merge_database_updates(&[u1, u2]);
        assert!(matches!(
            get_delta_value(&merged, b"node1", 0, &[1]),
            Some(DatabaseUpdate::Delete)
        ));
    }

    #[test]
    fn test_merge_empty_list() {
        let merged = merge_database_updates(&[]);
        assert!(merged.node_updates.is_empty());
    }

    #[test]
    fn test_merge_single_element_is_identity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let merged = merge_database_updates(&[u1.clone()]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![10]),
            "single-element merge should be identity"
        );
    }
}
