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
