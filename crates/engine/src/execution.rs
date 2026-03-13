//! Execution context for cross-shard transactions.
//!
//! Provides an overlay that combines local storage with provisions from other shards.
//!
//! Uses `ProvisionedSnapshot` with pre-computed storage keys (`StateEntry`) for
//! efficient execution. The sending shard computes storage keys once, so the
//! receiving shard can use them directly without expensive hash computations.

use hyperscale_storage::keys;
use hyperscale_types::{
    ApplicationEvent, FeeSummary, Hash, LedgerTransactionOutcome, LedgerTransactionReceipt,
    LocalTransactionExecution, LogLevel, NodeId, PartitionNumber, StateEntry, SubstateChange,
    SubstateChangeAction, SubstateRef, SubstateWrite,
};
use radix_common::prelude::DatabaseUpdate;
use radix_engine::transaction::{
    execute_transaction, ExecutionConfig, TransactionReceipt, TransactionResult,
};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_interface::interface::{
    CreateDatabaseUpdates, DatabaseUpdates, DbPartitionKey, DbSortKey, PartitionDatabaseUpdates,
    SubstateDatabase,
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

/// Compute a deterministic commitment hash for a set of substate writes.
///
/// This is used for transaction certificates - validators vote on this hash
/// to agree on execution results before the writes are applied to storage.
///
/// Note: This is distinct from `storage.state_root_hash()` which is the JMT
/// root of the entire state tree. This function only hashes the writes from
/// a single transaction for voting purposes.
///
/// Uses a simple hash chain over sorted writes for determinism.
pub fn compute_writes_commitment(writes: &[SubstateWrite]) -> Hash {
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
// Receipt building
// ============================================================================

/// Extract `DatabaseUpdates` from a transaction receipt.
///
/// Returns `DatabaseUpdates::default()` for rejected/aborted transactions.
pub fn extract_database_updates(receipt: &TransactionReceipt) -> DatabaseUpdates {
    extract_state_updates(receipt).unwrap_or_default()
}

/// Build a `LedgerTransactionReceipt` from a Radix Engine receipt.
///
/// The `execution_snapshot` parameter must be the **same snapshot** used for
/// execution. This guarantees previous values are read from the correct
/// state version — no drift possible.
pub fn build_ledger_receipt(
    receipt: &TransactionReceipt,
    execution_snapshot: &impl SubstateDatabase,
) -> LedgerTransactionReceipt {
    match &receipt.result {
        TransactionResult::Commit(commit) => {
            let db_updates = commit.state_updates.create_database_updates();
            let state_changes = extract_state_changes(&db_updates, execution_snapshot);
            let application_events = extract_application_events(commit);
            let outcome = match &commit.outcome {
                radix_engine::transaction::TransactionOutcome::Success(_) => {
                    LedgerTransactionOutcome::Success
                }
                radix_engine::transaction::TransactionOutcome::Failure(_) => {
                    LedgerTransactionOutcome::Failure
                }
            };
            LedgerTransactionReceipt {
                outcome,
                state_changes,
                application_events,
            }
        }
        TransactionResult::Reject(_) | TransactionResult::Abort(_) => {
            LedgerTransactionReceipt::failure()
        }
    }
}

/// Build `LocalTransactionExecution` from a Radix Engine receipt.
pub fn build_local_execution(receipt: &TransactionReceipt) -> LocalTransactionExecution {
    let fee_summary = build_fee_summary(receipt);

    let (log_messages, error_message) = match &receipt.result {
        TransactionResult::Commit(commit) => {
            let logs = commit
                .application_logs
                .iter()
                .map(|(level, msg)| (convert_log_level(level), msg.clone()))
                .collect();
            let error = match &commit.outcome {
                radix_engine::transaction::TransactionOutcome::Failure(err) => {
                    Some(format!("{err:?}"))
                }
                _ => None,
            };
            (logs, error)
        }
        TransactionResult::Reject(reject) => (vec![], Some(format!("{:?}", reject.reason))),
        TransactionResult::Abort(abort) => (vec![], Some(format!("{:?}", abort.reason))),
    };

    LocalTransactionExecution {
        fee_summary,
        log_messages,
        error_message,
    }
}

/// Extract state changes from DatabaseUpdates, reading previous values from the
/// execution snapshot.
pub(crate) fn extract_state_changes(
    db_updates: &DatabaseUpdates,
    snapshot: &impl SubstateDatabase,
) -> Vec<SubstateChange> {
    let mut changes = Vec::new();

    for (db_node_key, node_updates) in &db_updates.node_updates {
        let node_id = if db_node_key.len() >= 50 {
            let mut id = [0u8; 30];
            id.copy_from_slice(&db_node_key[20..50]);
            NodeId(id)
        } else {
            continue;
        };

        for (partition_num, partition_updates) in &node_updates.partition_updates {
            let partition = PartitionNumber(*partition_num);
            let partition_key = DbPartitionKey {
                node_key: db_node_key.clone(),
                partition_num: *partition_num,
            };

            match partition_updates {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    for (db_sort_key, update) in substate_updates {
                        let substate_ref = SubstateRef {
                            node_id,
                            partition,
                            sort_key: db_sort_key.0.clone(),
                        };
                        let previous =
                            snapshot.get_raw_substate_by_db_key(&partition_key, db_sort_key);

                        let action = match update {
                            DatabaseUpdate::Set(new_value) => match previous {
                                Some(prev) => SubstateChangeAction::Update {
                                    previous_value: prev,
                                    new_value: new_value.clone(),
                                },
                                None => SubstateChangeAction::Create {
                                    new_value: new_value.clone(),
                                },
                            },
                            DatabaseUpdate::Delete => SubstateChangeAction::Delete {
                                previous_value: previous.unwrap_or_default(),
                            },
                        };

                        changes.push(SubstateChange {
                            substate_ref,
                            action,
                        });
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // For Reset: all existing values in the partition are deleted,
                    // then new values are set. We emit Delete for old and Create for new.
                    // Reading all old values from the snapshot:
                    let old_values: Vec<_> = snapshot
                        .list_raw_values_from_db_key(&partition_key, None)
                        .collect();
                    for (old_sort_key, old_value) in old_values {
                        // Only emit Delete if the key is NOT in the new set
                        if !new_substate_values.contains_key(&old_sort_key) {
                            changes.push(SubstateChange {
                                substate_ref: SubstateRef {
                                    node_id,
                                    partition,
                                    sort_key: old_sort_key.0,
                                },
                                action: SubstateChangeAction::Delete {
                                    previous_value: old_value,
                                },
                            });
                        }
                    }
                    for (sort_key, new_value) in new_substate_values {
                        let previous =
                            snapshot.get_raw_substate_by_db_key(&partition_key, sort_key);
                        let action = match previous {
                            Some(prev) => SubstateChangeAction::Update {
                                previous_value: prev,
                                new_value: new_value.clone(),
                            },
                            None => SubstateChangeAction::Create {
                                new_value: new_value.clone(),
                            },
                        };
                        changes.push(SubstateChange {
                            substate_ref: SubstateRef {
                                node_id,
                                partition,
                                sort_key: sort_key.0.clone(),
                            },
                            action,
                        });
                    }
                }
            }
        }
    }

    changes
}

/// Extract application events from a committed receipt.
fn extract_application_events(
    commit: &radix_engine::transaction::CommitResult,
) -> Vec<ApplicationEvent> {
    commit
        .application_events
        .iter()
        .map(|(type_id, data)| {
            // SBOR-encode the EventTypeIdentifier for type_id bytes.
            let type_id_bytes = radix_common::data::scrypto::scrypto_encode(type_id)
                .unwrap_or_else(|_| format!("{type_id:?}").into_bytes());
            ApplicationEvent {
                type_id: type_id_bytes,
                data: data.clone(),
            }
        })
        .collect()
}

/// Build a `FeeSummary` from a Radix Engine receipt.
///
/// Fee costs are SBOR-encoded as raw bytes to avoid a direct dependency on
/// the Decimal type in the types crate.
fn build_fee_summary(receipt: &TransactionReceipt) -> FeeSummary {
    let fees = &receipt.fee_summary;
    FeeSummary {
        total_execution_cost: radix_common::data::scrypto::scrypto_encode(
            &fees.total_execution_cost_in_xrd,
        )
        .unwrap_or_default(),
        total_royalty_cost: radix_common::data::scrypto::scrypto_encode(
            &fees.total_royalty_cost_in_xrd,
        )
        .unwrap_or_default(),
        total_storage_cost: radix_common::data::scrypto::scrypto_encode(
            &fees.total_storage_cost_in_xrd,
        )
        .unwrap_or_default(),
        total_tipping_cost: radix_common::data::scrypto::scrypto_encode(
            &fees.total_tipping_cost_in_xrd,
        )
        .unwrap_or_default(),
    }
}

/// Convert Radix Engine log level to our LogLevel.
fn convert_log_level(level: &radix_engine_interface::types::Level) -> LogLevel {
    match level {
        radix_engine_interface::types::Level::Error => LogLevel::Error,
        radix_engine_interface::types::Level::Warn => LogLevel::Warn,
        radix_engine_interface::types::Level::Info => LogLevel::Info,
        radix_engine_interface::types::Level::Debug => LogLevel::Debug,
        radix_engine_interface::types::Level::Trace => LogLevel::Trace,
    }
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
        let prefix_end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        LedgerTransactionOutcome, LogLevel, NodeId, PartitionNumber as HsPartitionNumber,
        SubstateChangeAction,
    };
    use indexmap::indexmap;
    use radix_common::prelude::DatabaseUpdate;
    use radix_engine::transaction::{
        AbortResult, CommitResult, RejectResult, TransactionOutcome, TransactionReceipt,
        TransactionResult,
    };
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    use radix_substate_store_interface::interface::{
        DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    };

    // ─── Mock SubstateDatabase ──────────────────────────────────────────

    /// Minimal SubstateDatabase backed by a BTreeMap keyed on (node_key, partition, sort_key).
    struct MockSnapshot {
        substates: std::collections::BTreeMap<(Vec<u8>, u8, Vec<u8>), Vec<u8>>,
    }

    impl MockSnapshot {
        fn new() -> Self {
            Self {
                substates: std::collections::BTreeMap::new(),
            }
        }

        /// Insert a substate using a hyperscale NodeId, converting to db_node_key internally.
        fn with_substate(
            mut self,
            node_id: [u8; 30],
            partition: u8,
            sort_key: Vec<u8>,
            value: Vec<u8>,
        ) -> Self {
            let db_node_key = make_db_node_key(&node_id);
            self.substates
                .insert((db_node_key, partition, sort_key), value);
            self
        }
    }

    impl SubstateDatabase for MockSnapshot {
        fn get_raw_substate_by_db_key(
            &self,
            partition_key: &DbPartitionKey,
            sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            self.substates
                .get(&(
                    partition_key.node_key.clone(),
                    partition_key.partition_num,
                    sort_key.0.clone(),
                ))
                .cloned()
        }

        fn list_raw_values_from_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    fn make_db_node_key(node_id: &[u8; 30]) -> Vec<u8> {
        let radix_id = radix_common::types::NodeId(*node_id);
        SpreadPrefixKeyMapper::to_db_node_key(&radix_id)
    }

    /// Build DatabaseUpdates with a single Set operation (for Create or Update depending on snapshot).
    fn make_set_updates(
        node_id: [u8; 30],
        partition: u8,
        sort_key: Vec<u8>,
        value: Vec<u8>,
    ) -> DatabaseUpdates {
        let db_node_key = make_db_node_key(&node_id);
        DatabaseUpdates {
            node_updates: indexmap! {
                db_node_key => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        partition => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(sort_key) => DatabaseUpdate::Set(value),
                            }
                        }
                    }
                }
            },
        }
    }

    /// Build DatabaseUpdates with a single Delete operation.
    fn make_delete_updates(node_id: [u8; 30], partition: u8, sort_key: Vec<u8>) -> DatabaseUpdates {
        let db_node_key = make_db_node_key(&node_id);
        DatabaseUpdates {
            node_updates: indexmap! {
                db_node_key => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        partition => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(sort_key) => DatabaseUpdate::Delete,
                            }
                        }
                    }
                }
            },
        }
    }

    /// Build DatabaseUpdates with a Reset partition operation.
    fn make_reset_updates(
        node_id: [u8; 30],
        partition: u8,
        new_values: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> DatabaseUpdates {
        let db_node_key = make_db_node_key(&node_id);
        let new_substate_values = new_values
            .into_iter()
            .map(|(k, v)| (DbSortKey(k), v))
            .collect();
        DatabaseUpdates {
            node_updates: indexmap! {
                db_node_key => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        partition => PartitionDatabaseUpdates::Reset {
                            new_substate_values,
                        }
                    }
                }
            },
        }
    }

    fn make_success_receipt_with_logs(
        logs: Vec<(radix_engine_interface::types::Level, String)>,
    ) -> TransactionReceipt {
        let mut commit = CommitResult::empty_with_outcome(TransactionOutcome::Success(vec![]));
        commit.application_logs = logs;
        TransactionReceipt::empty_with_commit(commit)
    }

    fn make_success_receipt_with_events(
        events: Vec<(radix_engine_interface::types::EventTypeIdentifier, Vec<u8>)>,
    ) -> TransactionReceipt {
        let mut commit = CommitResult::empty_with_outcome(TransactionOutcome::Success(vec![]));
        commit.application_events = events;
        TransactionReceipt::empty_with_commit(commit)
    }

    fn make_reject_receipt() -> TransactionReceipt {
        TransactionReceipt {
            result: TransactionResult::Reject(RejectResult {
                reason: radix_engine::errors::RejectionReason::SuccessButFeeLoanNotRepaid,
            }),
            ..TransactionReceipt::empty_commit_success()
        }
    }

    fn make_abort_receipt() -> TransactionReceipt {
        TransactionReceipt {
            result: TransactionResult::Abort(AbortResult {
                reason: radix_engine::transaction::AbortReason::ConfiguredAbortTriggeredOnFeeLoanRepayment,
            }),
            ..TransactionReceipt::empty_commit_success()
        }
    }

    // ─── Tests: extract_state_changes ───────────────────────────────────

    #[test]
    fn test_extract_state_changes_create() {
        let node_id = [1u8; 30];
        let db_updates = make_set_updates(node_id, 0, vec![42], b"new_value".to_vec());
        // No previous value in snapshot => should classify as Create
        let snapshot = MockSnapshot::new();

        let changes = extract_state_changes(&db_updates, &snapshot);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].substate_ref.node_id, NodeId(node_id));
        assert_eq!(changes[0].substate_ref.partition, HsPartitionNumber(0));
        assert_eq!(changes[0].substate_ref.sort_key, vec![42]);
        match &changes[0].action {
            SubstateChangeAction::Create { new_value } => {
                assert_eq!(new_value, b"new_value");
            }
            other => panic!("Expected Create, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_state_changes_update() {
        let node_id = [2u8; 30];
        let db_updates = make_set_updates(node_id, 3, vec![10], b"new_value".to_vec());
        // Previous value exists => should classify as Update
        let snapshot =
            MockSnapshot::new().with_substate(node_id, 3, vec![10], b"old_value".to_vec());

        let changes = extract_state_changes(&db_updates, &snapshot);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].substate_ref.node_id, NodeId(node_id));
        assert_eq!(changes[0].substate_ref.partition, HsPartitionNumber(3));
        match &changes[0].action {
            SubstateChangeAction::Update {
                previous_value,
                new_value,
            } => {
                assert_eq!(previous_value, b"old_value");
                assert_eq!(new_value, b"new_value");
            }
            other => panic!("Expected Update, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_state_changes_delete() {
        let node_id = [3u8; 30];
        let db_updates = make_delete_updates(node_id, 1, vec![5]);
        let snapshot =
            MockSnapshot::new().with_substate(node_id, 1, vec![5], b"doomed_value".to_vec());

        let changes = extract_state_changes(&db_updates, &snapshot);

        assert_eq!(changes.len(), 1);
        match &changes[0].action {
            SubstateChangeAction::Delete { previous_value } => {
                assert_eq!(previous_value, b"doomed_value");
            }
            other => panic!("Expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_state_changes_delete_missing_previous() {
        let node_id = [4u8; 30];
        let db_updates = make_delete_updates(node_id, 0, vec![7]);
        // No previous value — Delete should produce empty previous_value
        let snapshot = MockSnapshot::new();

        let changes = extract_state_changes(&db_updates, &snapshot);

        assert_eq!(changes.len(), 1);
        match &changes[0].action {
            SubstateChangeAction::Delete { previous_value } => {
                assert!(previous_value.is_empty());
            }
            other => panic!("Expected Delete, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_state_changes_multiple_nodes_and_partitions() {
        let node_a = [10u8; 30];
        let node_b = [20u8; 30];
        let db_node_key_a = make_db_node_key(&node_a);
        let db_node_key_b = make_db_node_key(&node_b);

        let db_updates = DatabaseUpdates {
            node_updates: indexmap! {
                db_node_key_a => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        0 => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(vec![1]) => DatabaseUpdate::Set(b"a1".to_vec()),
                            }
                        },
                        5 => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(vec![2]) => DatabaseUpdate::Set(b"a2".to_vec()),
                            }
                        }
                    }
                },
                db_node_key_b => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        0 => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(vec![3]) => DatabaseUpdate::Delete,
                            }
                        }
                    }
                }
            },
        };
        let snapshot = MockSnapshot::new().with_substate(node_b, 0, vec![3], b"bye".to_vec());

        let changes = extract_state_changes(&db_updates, &snapshot);

        assert_eq!(changes.len(), 3);
        // Verify we got changes for both nodes
        let node_ids: Vec<_> = changes.iter().map(|c| c.substate_ref.node_id).collect();
        assert!(node_ids.contains(&NodeId(node_a)));
        assert!(node_ids.contains(&NodeId(node_b)));
    }

    #[test]
    fn test_extract_state_changes_reset_partition() {
        let node_id = [5u8; 30];
        // Reset partition with one new value, one existing value in snapshot
        let db_updates = make_reset_updates(node_id, 2, vec![(vec![1], b"reset_val".to_vec())]);
        // Existing key [1] in snapshot => Update; old key [99] not in new set => Delete
        // (note: Delete for old keys requires list_raw_values_from_db_key, which our mock
        //  returns empty, so we only get the new values classified as Create/Update)
        let snapshot = MockSnapshot::new().with_substate(node_id, 2, vec![1], b"prev_val".to_vec());

        let changes = extract_state_changes(&db_updates, &snapshot);

        // With empty list_raw_values, we should get 1 change (the new value)
        assert_eq!(changes.len(), 1);
        match &changes[0].action {
            SubstateChangeAction::Update {
                previous_value,
                new_value,
            } => {
                assert_eq!(previous_value, b"prev_val");
                assert_eq!(new_value, b"reset_val");
            }
            other => panic!("Expected Update for existing key in Reset, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_state_changes_empty_updates() {
        let db_updates = DatabaseUpdates::default();
        let snapshot = MockSnapshot::new();
        let changes = extract_state_changes(&db_updates, &snapshot);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_extract_state_changes_invalid_node_key_skipped() {
        // db_node_key shorter than 50 bytes should be skipped (db_node_key_to_node_id returns None)
        let db_updates = DatabaseUpdates {
            node_updates: indexmap! {
                vec![0u8; 10] => NodeDatabaseUpdates {
                    partition_updates: indexmap! {
                        0 => PartitionDatabaseUpdates::Delta {
                            substate_updates: indexmap! {
                                DbSortKey(vec![1]) => DatabaseUpdate::Set(b"val".to_vec()),
                            }
                        }
                    }
                }
            },
        };
        let snapshot = MockSnapshot::new();
        let changes = extract_state_changes(&db_updates, &snapshot);
        assert!(changes.is_empty(), "Malformed node key should be skipped");
    }

    // ─── Tests: build_ledger_receipt ────────────────────────────────────

    #[test]
    fn test_build_ledger_receipt_commit_success() {
        let receipt = TransactionReceipt::empty_commit_success();
        let snapshot = MockSnapshot::new();
        let ledger = build_ledger_receipt(&receipt, &snapshot);

        assert_eq!(ledger.outcome, LedgerTransactionOutcome::Success);
        assert!(ledger.state_changes.is_empty());
        assert!(ledger.application_events.is_empty());
    }

    #[test]
    fn test_build_ledger_receipt_with_events() {
        use radix_engine_interface::types::{Emitter, EventTypeIdentifier};
        let radix_node_id = radix_common::types::NodeId([1u8; 30]);
        let event_id = EventTypeIdentifier(
            Emitter::Method(
                radix_node_id,
                radix_engine_interface::prelude::ModuleId::Main,
            ),
            "TestEvent".to_string(),
        );
        let receipt = make_success_receipt_with_events(vec![
            (event_id.clone(), b"event_data_1".to_vec()),
            (event_id, b"event_data_2".to_vec()),
        ]);
        let snapshot = MockSnapshot::new();
        let ledger = build_ledger_receipt(&receipt, &snapshot);

        assert_eq!(ledger.outcome, LedgerTransactionOutcome::Success);
        assert_eq!(ledger.application_events.len(), 2);
        assert_eq!(ledger.application_events[0].data, b"event_data_1");
        assert_eq!(ledger.application_events[1].data, b"event_data_2");
        // type_id should be SBOR-encoded EventTypeIdentifier (non-empty)
        assert!(!ledger.application_events[0].type_id.is_empty());
    }

    #[test]
    fn test_build_ledger_receipt_reject() {
        let receipt = make_reject_receipt();
        let snapshot = MockSnapshot::new();
        let ledger = build_ledger_receipt(&receipt, &snapshot);

        assert_eq!(ledger, LedgerTransactionReceipt::failure());
        assert_eq!(ledger.outcome, LedgerTransactionOutcome::Failure);
        assert!(ledger.state_changes.is_empty());
        assert!(ledger.application_events.is_empty());
    }

    #[test]
    fn test_build_ledger_receipt_abort() {
        let receipt = make_abort_receipt();
        let snapshot = MockSnapshot::new();
        let ledger = build_ledger_receipt(&receipt, &snapshot);

        assert_eq!(ledger, LedgerTransactionReceipt::failure());
    }

    #[test]
    fn test_build_ledger_receipt_receipt_hash_deterministic() {
        let receipt = TransactionReceipt::empty_commit_success();
        let snapshot = MockSnapshot::new();
        let ledger_a = build_ledger_receipt(&receipt, &snapshot);
        let ledger_b = build_ledger_receipt(&receipt, &snapshot);

        assert_eq!(ledger_a.receipt_hash(), ledger_b.receipt_hash());
    }

    // ─── Tests: build_local_execution ───────────────────────────────────

    #[test]
    fn test_build_local_execution_success_no_error() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_local_execution(&receipt);

        assert!(local.error_message.is_none());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_local_execution_with_logs() {
        use radix_engine_interface::types::Level;
        let receipt = make_success_receipt_with_logs(vec![
            (Level::Info, "hello world".to_string()),
            (Level::Error, "something broke".to_string()),
            (Level::Debug, "debug info".to_string()),
        ]);
        let local = build_local_execution(&receipt);

        assert_eq!(local.log_messages.len(), 3);
        assert_eq!(
            local.log_messages[0],
            (LogLevel::Info, "hello world".to_string())
        );
        assert_eq!(
            local.log_messages[1],
            (LogLevel::Error, "something broke".to_string())
        );
        assert_eq!(
            local.log_messages[2],
            (LogLevel::Debug, "debug info".to_string())
        );
        assert!(local.error_message.is_none());
    }

    #[test]
    fn test_build_local_execution_reject_has_error() {
        let receipt = make_reject_receipt();
        let local = build_local_execution(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_local_execution_abort_has_error() {
        let receipt = make_abort_receipt();
        let local = build_local_execution(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_local_execution_fees_are_encoded() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_local_execution(&receipt);

        // Default fee summary has zero Decimals, which still SBOR-encode to non-empty bytes.
        assert!(
            !local.fee_summary.total_execution_cost.is_empty(),
            "SBOR-encoded zero Decimal should be non-empty"
        );
        assert!(!local.fee_summary.total_royalty_cost.is_empty());
        assert!(!local.fee_summary.total_storage_cost.is_empty());
        assert!(!local.fee_summary.total_tipping_cost.is_empty());
    }

    // ─── Tests: extract_database_updates ────────────────────────────────

    #[test]
    fn test_extract_database_updates_commit_empty() {
        let receipt = TransactionReceipt::empty_commit_success();
        let updates = extract_database_updates(&receipt);

        assert!(updates.node_updates.is_empty());
    }

    #[test]
    fn test_extract_database_updates_reject_returns_default() {
        let receipt = make_reject_receipt();
        let updates = extract_database_updates(&receipt);

        assert!(updates.node_updates.is_empty());
    }

    #[test]
    fn test_extract_database_updates_abort_returns_default() {
        let receipt = make_abort_receipt();
        let updates = extract_database_updates(&receipt);

        assert!(updates.node_updates.is_empty());
    }
}
