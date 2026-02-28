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
/// A `DatabaseUpdates` structure that can be passed to `CommittableSubstateDatabase::commit()`
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

        let result_shard0 = extract_writes_per_cert(&[cert.clone()], ShardGroupId(0));
        assert_eq!(result_shard0.len(), 1);
        assert_eq!(result_shard0[0], shard0_writes);

        let result_shard1 = extract_writes_per_cert(&[cert.clone()], ShardGroupId(1));
        assert_eq!(result_shard1.len(), 1);
        assert_eq!(result_shard1[0], shard1_writes);

        // Shard 2 has no proof — should return empty writes
        let result_shard2 = extract_writes_per_cert(&[cert], ShardGroupId(2));
        assert_eq!(result_shard2.len(), 1);
        assert!(result_shard2[0].is_empty());
    }
}
