//! Execution context for cross-shard transactions.
//!
//! Provides an overlay that combines local storage with provisions from other shards.

use crate::error::ExecutionError;
use hyperscale_types::{Hash, NodeId, PartitionNumber, StateProvision, SubstateWrite};
use radix_common::network::NetworkDefinition;
use radix_common::prelude::DatabaseUpdate;
use radix_engine::transaction::{
    execute_transaction, ExecutionConfig, TransactionReceipt, TransactionResult,
};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_impls::substate_database_overlay::SubstateDatabaseOverlay;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, CreateDatabaseUpdates, DatabaseUpdates, DbSortKey,
    NodeDatabaseUpdates, PartitionDatabaseUpdates, SubstateDatabase,
};
use radix_transactions::prelude::ExecutableTransaction;

/// Pre-processed provisions ready for fast execution.
///
/// Converts StateProvisions into DatabaseUpdates once, avoiding repeated
/// SpreadPrefixKeyMapper computations during execution.
#[derive(Default)]
pub struct PreparedProvisions {
    updates: DatabaseUpdates,
}

impl PreparedProvisions {
    /// Create prepared provisions from raw StateProvisions.
    ///
    /// This pre-computes all DB keys (SpreadPrefixKeyMapper hashes) once,
    /// so they don't need to be recomputed for each transaction execution.
    pub fn from_provisions(provisions: &[&StateProvision]) -> Self {
        let mut updates = DatabaseUpdates::default();

        for provision in provisions {
            if provision.entries.is_empty() {
                continue;
            }

            // Track last node key to avoid redundant HashMap lookups for consecutive
            // entries from the same node (common case)
            let mut last_node_key: Option<Vec<u8>> = None;

            for entry in provision.entries.iter() {
                let radix_node_id = radix_common::types::NodeId(entry.node_id.0);
                let radix_partition = radix_common::types::PartitionNumber(entry.partition.0);

                let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
                let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
                let db_sort_key = DbSortKey(entry.sort_key.clone());

                let update = match &entry.value {
                    None => DatabaseUpdate::Delete,
                    Some(v) if v.is_empty() => DatabaseUpdate::Delete,
                    Some(v) => DatabaseUpdate::Set(v.clone()),
                };

                // Check if we can reuse cached node reference
                let node_changed = last_node_key.as_ref() != Some(&db_node_key);

                if node_changed {
                    // Different node - lookup/create in HashMap
                    let node_updates = updates
                        .node_updates
                        .entry(db_node_key.clone())
                        .or_insert_with(|| NodeDatabaseUpdates {
                            partition_updates: indexmap::IndexMap::new(),
                        });

                    let partition_updates = node_updates
                        .partition_updates
                        .entry(db_partition_num)
                        .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap::IndexMap::new(),
                        });

                    if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates
                    {
                        substate_updates.insert(db_sort_key, update);
                    }

                    last_node_key = Some(db_node_key);
                    // Can't cache mutable reference across loop iterations safely,
                    // but the HashMap lookup is still avoided for consecutive same-node entries
                } else if let Some(ref db_key) = last_node_key {
                    // Same node - use get_mut
                    let node_updates = updates
                        .node_updates
                        .get_mut(db_key)
                        .expect("node should exist");

                    let partition_updates = node_updates
                        .partition_updates
                        .entry(db_partition_num)
                        .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap::IndexMap::new(),
                        });

                    if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates
                    {
                        substate_updates.insert(db_sort_key, update);
                    }
                }
            }
        }

        Self { updates }
    }
}

/// Execution context that combines local storage with provisioned state.
///
/// Uses Radix's `SubstateDatabaseOverlay` to layer provisioned state on top
/// of local storage, enabling cross-shard transaction execution.
pub struct ProvisionedExecutionContext<'a, S: SubstateDatabase> {
    base_store: &'a S,
    provisions: DatabaseUpdates,
}

impl<'a, S: SubstateDatabase> ProvisionedExecutionContext<'a, S> {
    /// Create a new execution context with pre-processed provisions.
    ///
    /// This is more efficient than calling `add_provision` repeatedly because
    /// the DB key computations have already been done in `PreparedProvisions`.
    pub fn with_prepared_provisions(
        base_store: &'a S,
        _network: &'a NetworkDefinition,
        prepared: PreparedProvisions,
    ) -> Self {
        Self {
            base_store,
            provisions: prepared.updates,
        }
    }

    /// Execute a transaction with cached VM modules and config (more efficient).
    pub fn execute_with_cache(
        &self,
        executable: &ExecutableTransaction,
        vm_modules: &DefaultVmModules,
        exec_config: &ExecutionConfig,
    ) -> Result<TransactionReceipt, ExecutionError> {
        let mut overlay = SubstateDatabaseOverlay::new_unmergeable(self.base_store);
        overlay.commit(&self.provisions);

        let receipt = execute_transaction(&overlay, vm_modules, exec_config, executable);

        Ok(receipt)
    }
}

/// Extract state updates from a committed transaction receipt.
pub fn extract_state_updates(receipt: &TransactionReceipt) -> Option<DatabaseUpdates> {
    match &receipt.result {
        TransactionResult::Commit(commit) => Some(commit.state_updates.create_database_updates()),
        TransactionResult::Reject(_) | TransactionResult::Abort(_) => None,
    }
}

/// Check if a transaction receipt represents a successful commit.
pub fn is_commit_success(receipt: &TransactionReceipt) -> bool {
    matches!(&receipt.result, TransactionResult::Commit(_))
}

/// Extract SubstateWrites from a receipt.
pub fn extract_substate_writes(receipt: &TransactionReceipt) -> Vec<SubstateWrite> {
    let Some(updates) = extract_state_updates(receipt) else {
        return Vec::new();
    };

    let mut writes = Vec::new();

    for (db_node_key, node_updates) in &updates.node_updates {
        // Convert DbNodeKey back to NodeId (extract 30-byte suffix after 20-byte hash prefix)
        let node_id = if db_node_key.len() >= 50 {
            let mut id = [0u8; 30];
            id.copy_from_slice(&db_node_key[20..50]);
            NodeId(id)
        } else {
            continue;
        };

        for (partition_num, partition_updates) in &node_updates.partition_updates {
            let partition = PartitionNumber(*partition_num);

            if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
                for (db_sort_key, update) in substate_updates {
                    if let DatabaseUpdate::Set(value) = update {
                        writes.push(SubstateWrite::new(
                            node_id,
                            partition,
                            db_sort_key.0.clone(),
                            value.clone(),
                        ));
                    }
                }
            }
        }
    }

    writes
}

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

        if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
            substate_updates.insert(db_sort_key, DatabaseUpdate::Set(write.value.clone()));
        }
    }

    updates
}

/// Compute merkle root from substate writes.
///
/// Uses a simple hash chain for now. A proper implementation would use
/// a sparse Merkle tree.
pub fn compute_merkle_root(writes: &[SubstateWrite]) -> Hash {
    if writes.is_empty() {
        return Hash::ZERO;
    }

    // Sort writes for determinism
    let mut sorted: Vec<_> = writes.iter().collect();
    sorted.sort_by(|a, b| {
        (&a.node_id.0, a.partition.0, &a.sort_key).cmp(&(&b.node_id.0, b.partition.0, &b.sort_key))
    });

    // Hash chain
    let mut data = Vec::new();
    for write in sorted {
        data.extend_from_slice(&write.node_id.0);
        data.push(write.partition.0);
        data.extend_from_slice(&write.sort_key);
        data.extend_from_slice(&write.value);
    }

    Hash::from_bytes(&data)
}
