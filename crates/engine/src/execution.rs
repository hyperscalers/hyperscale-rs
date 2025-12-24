//! Execution context for cross-shard transactions.
//!
//! Provides an overlay that combines local storage with provisions from other shards.
//!
//! Uses `ProvisionedSnapshot` with pre-computed storage keys (`StateEntry`) for
//! efficient execution. The sending shard computes storage keys once, so the
//! receiving shard can use them directly without expensive hash computations.

use crate::storage::keys;
use hyperscale_types::{Hash, NodeId, PartitionNumber, StateEntry, SubstateWrite};
use radix_common::prelude::DatabaseUpdate;
use radix_engine::transaction::{
    execute_transaction, ExecutionConfig, TransactionReceipt, TransactionResult,
};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use radix_substate_store_interface::interface::{
    CreateDatabaseUpdates, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, SubstateDatabase,
};
use radix_transactions::prelude::ExecutableTransaction;
use std::collections::BTreeMap;

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

// ============================================================================
// Optimized execution path using pre-computed storage keys
// ============================================================================

/// A snapshot with provisions overlaid using pre-computed storage keys.
///
/// This is an optimized alternative to `SubstateDatabaseOverlay` that:
/// - Uses pre-computed storage keys (no `SpreadPrefixKeyMapper` calls)
/// - Uses a flat `BTreeMap` instead of nested maps (faster lookups)
/// - Supports efficient range queries via `BTreeMap::range()`
///
/// # Usage
///
/// ```ignore
/// let entries: Vec<StateEntry> = /* provisions with pre-computed keys */;
/// let snapshot = ProvisionedSnapshot::new(&base_storage, &entries);
/// let receipt = execute_transaction(&snapshot, vm_modules, config, executable);
/// ```
pub struct ProvisionedSnapshot<'a, S> {
    base: &'a S,
    /// Provisions keyed by full storage key.
    /// Value is None for deletions, Some(bytes) for sets.
    provisions: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a, S: SubstateDatabase> ProvisionedSnapshot<'a, S> {
    /// Create a new provisioned snapshot from pre-computed entries.
    ///
    /// Entries should have storage keys pre-computed by the sending shard.
    pub fn new(base: &'a S, entries: &[StateEntry]) -> Self {
        let mut provisions = BTreeMap::new();

        for entry in entries {
            provisions.insert(entry.storage_key.clone(), entry.value.clone());
        }

        Self { base, provisions }
    }

    /// Create from multiple provisions (from different source shards).
    pub fn from_provisions(base: &'a S, provisions_list: &[&[StateEntry]]) -> Self {
        let total_entries: usize = provisions_list.iter().map(|p| p.len()).sum();
        let mut provisions = BTreeMap::new();

        for entries in provisions_list {
            for entry in *entries {
                provisions.insert(entry.storage_key.clone(), entry.value.clone());
            }
        }

        // Shrink if we over-allocated (unlikely with BTreeMap but good practice)
        let _ = total_entries; // suppress unused warning

        Self { base, provisions }
    }

    /// Execute a transaction against this provisioned snapshot.
    pub fn execute(
        &self,
        executable: &ExecutableTransaction,
        vm_modules: &DefaultVmModules,
        exec_config: &ExecutionConfig,
    ) -> TransactionReceipt {
        execute_transaction(self, vm_modules, exec_config, executable)
    }
}

impl<S: SubstateDatabase> SubstateDatabase for ProvisionedSnapshot<'_, S> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        // Build the full storage key
        let key = keys::to_storage_key(partition_key, sort_key);

        // Fast path: check provisions first (BTreeMap lookup is O(log n))
        if let Some(value) = self.provisions.get(&key) {
            // Found in provisions: None means deleted, Some means value
            return value.clone();
        }

        // Fall back to base storage
        self.base
            .get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        // Build prefix for this partition
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();
        let prefix_end = keys::next_prefix(&prefix);

        // Build start key
        let start = match from_sort_key {
            Some(sk) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sk.0);
                s
            }
            None => prefix.clone(),
        };

        // Get base iterator
        let base_iter = self
            .base
            .list_raw_values_from_db_key(partition_key, from_sort_key);

        // Get provision entries in range (provisions are keyed by full storage key)
        let prov_entries: Vec<_> = self
            .provisions
            .range(start.clone()..prefix_end.clone())
            .filter_map(|(k, v)| {
                // Extract sort key from storage key (after prefix)
                if k.len() > prefix_len {
                    let sort_key = DbSortKey(k[prefix_len..].to_vec());
                    // None value means deleted - we need to track this
                    Some((sort_key, v.clone()))
                } else {
                    None
                }
            })
            .collect();

        // If no provisions affect this partition, just return base iterator
        if prov_entries.is_empty() {
            return base_iter;
        }

        // Create a merged iterator that overlays provisions on base
        // Both iterators are sorted by sort_key, so we can merge efficiently
        Box::new(MergedPartitionIterator::new(base_iter, prov_entries))
    }
}

/// Iterator that merges base storage entries with provision overrides.
///
/// Both inputs must be sorted by sort key. Provisions take precedence.
struct MergedPartitionIterator<'a> {
    base: std::iter::Peekable<Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + 'a>>,
    provisions: std::iter::Peekable<std::vec::IntoIter<(DbSortKey, Option<Vec<u8>>)>>,
}

impl<'a> MergedPartitionIterator<'a> {
    fn new(
        base: Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + 'a>,
        provisions: Vec<(DbSortKey, Option<Vec<u8>>)>,
    ) -> Self {
        Self {
            base: base.peekable(),
            provisions: provisions.into_iter().peekable(),
        }
    }
}

impl Iterator for MergedPartitionIterator<'_> {
    type Item = (DbSortKey, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.base.peek(), self.provisions.peek()) {
                // Both have items - compare sort keys
                (Some((base_key, _)), Some((prov_key, _))) => {
                    match base_key.0.cmp(&prov_key.0) {
                        std::cmp::Ordering::Less => {
                            // Base key is smaller - check if it's overridden by a provision
                            // (it's not, since provision key is larger)
                            return self.base.next();
                        }
                        std::cmp::Ordering::Equal => {
                            // Same key - provision takes precedence
                            let _ = self.base.next(); // consume base
                            let (key, value) = self.provisions.next().unwrap();
                            match value {
                                Some(v) => return Some((key, v)),
                                None => continue, // deleted - skip to next
                            }
                        }
                        std::cmp::Ordering::Greater => {
                            // Provision key is smaller - it's a new entry or override
                            let (key, value) = self.provisions.next().unwrap();
                            match value {
                                Some(v) => return Some((key, v)),
                                None => continue, // deleted (didn't exist in base anyway)
                            }
                        }
                    }
                }
                // Only base has items
                (Some(_), None) => {
                    return self.base.next();
                }
                // Only provisions have items
                (None, Some(_)) => {
                    let (key, value) = self.provisions.next().unwrap();
                    match value {
                        Some(v) => return Some((key, v)),
                        None => continue, // deleted
                    }
                }
                // Both exhausted
                (None, None) => return None,
            }
        }
    }
}
