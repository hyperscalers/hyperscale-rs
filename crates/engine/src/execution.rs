//! Execution context for cross-shard transactions.
//!
//! Provides an overlay that combines local storage with provisions from other shards.
//!
//! Uses `ProvisionedSnapshot` with pre-computed storage keys (`StateEntry`) for
//! efficient execution. The sending shard computes storage keys once, so the
//! receiving shard can use them directly without expensive hash computations.

use hyperscale_storage::keys;
use hyperscale_types::{
    ApplicationEvent, ExecutionOutput, FeeSummary, LocalReceipt, LogLevel, StateEntry,
    TransactionOutcome,
};
use radix_engine::transaction::{
    execute_transaction, ExecutionConfig, TransactionReceipt, TransactionResult,
};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_interface::interface::{
    CreateDatabaseUpdates, DatabaseUpdates, DbPartitionKey, DbSortKey, SubstateDatabase,
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

/// Check if a transaction receipt committed (state changes applied).
///
/// In Radix Engine, `Commit` means the transaction's state changes were applied
/// (including fee payment). The transaction's own logic may still have failed
/// (`Commit(Failure)`) — use `commit.outcome` to distinguish success from failure.
pub fn is_committed(receipt: &TransactionReceipt) -> bool {
    matches!(&receipt.result, TransactionResult::Commit(_))
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

/// Build a `LocalReceipt` from a Radix Engine receipt.
///
/// Shard filtering is applied here so the receipt is always born with
/// shard-specific `database_updates`. Pass `None` for `shard_context` in
/// single-shard deployments (no filtering needed).
pub fn build_local_receipt<S: radix_substate_store_interface::interface::SubstateDatabase>(
    receipt: &TransactionReceipt,
    storage: &S,
    declared_nodes: &[hyperscale_types::NodeId],
    local_shard: hyperscale_types::ShardGroupId,
    num_shards: u64,
) -> LocalReceipt {
    match &receipt.result {
        TransactionResult::Commit(commit) => {
            let application_events = extract_application_events(commit);
            let outcome = match &commit.outcome {
                radix_engine::transaction::TransactionOutcome::Success(_) => {
                    TransactionOutcome::Success
                }
                radix_engine::transaction::TransactionOutcome::Failure(_) => {
                    TransactionOutcome::Failure
                }
            };
            let mut database_updates = extract_database_updates(receipt);
            if num_shards > 1 {
                database_updates = crate::sharding::filter_updates_for_shard(
                    &database_updates,
                    local_shard,
                    num_shards,
                    storage,
                    declared_nodes,
                );
            }
            LocalReceipt {
                outcome,
                database_updates,
                application_events,
            }
        }
        TransactionResult::Reject(_) | TransactionResult::Abort(_) => LocalReceipt::failure(),
    }
}

/// Build `ExecutionOutput` from a Radix Engine receipt.
pub fn build_execution_output(receipt: &TransactionReceipt) -> ExecutionOutput {
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

    ExecutionOutput {
        fee_summary,
        log_messages,
        error_message,
    }
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
        let mut provisions = BTreeMap::new();

        for entries in provisions_list {
            for entry in *entries {
                provisions.insert(entry.storage_key.clone(), entry.value.clone());
            }
        }

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
    use hyperscale_types::LogLevel;
    use radix_engine::transaction::{
        AbortResult, CommitResult, RejectResult, TransactionOutcome as RadixTransactionOutcome,
        TransactionReceipt, TransactionResult,
    };

    // ─── Helpers ────────────────────────────────────────────────────────

    fn make_success_receipt_with_logs(
        logs: Vec<(radix_engine_interface::types::Level, String)>,
    ) -> TransactionReceipt {
        let mut commit = CommitResult::empty_with_outcome(RadixTransactionOutcome::Success(vec![]));
        commit.application_logs = logs;
        TransactionReceipt::empty_with_commit(commit)
    }

    fn make_success_receipt_with_events(
        events: Vec<(radix_engine_interface::types::EventTypeIdentifier, Vec<u8>)>,
    ) -> TransactionReceipt {
        let mut commit = CommitResult::empty_with_outcome(RadixTransactionOutcome::Success(vec![]));
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

    // ─── Tests: build_local_receipt ────────────────────────────────────

    /// Test helper: build receipt with single-shard defaults (no filtering).
    fn test_build_receipt(receipt: &TransactionReceipt) -> LocalReceipt {
        // num_shards=1 skips filter_updates_for_shard, so storage is never read.
        let empty = hyperscale_storage::empty_substate_database();
        build_local_receipt(receipt, &empty, &[], hyperscale_types::ShardGroupId(0), 1)
    }

    #[test]
    fn test_build_local_receipt_commit_success() {
        let receipt = TransactionReceipt::empty_commit_success();
        let ledger = test_build_receipt(&receipt);

        assert_eq!(ledger.outcome, TransactionOutcome::Success);
        assert!(ledger.database_updates.node_updates.is_empty());
        assert!(ledger.application_events.is_empty());
    }

    #[test]
    fn test_build_local_receipt_with_events() {
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
        let ledger = test_build_receipt(&receipt);

        assert_eq!(ledger.outcome, TransactionOutcome::Success);
        assert_eq!(ledger.application_events.len(), 2);
        assert_eq!(ledger.application_events[0].data, b"event_data_1");
        assert_eq!(ledger.application_events[1].data, b"event_data_2");
        assert!(!ledger.application_events[0].type_id.is_empty());
    }

    #[test]
    fn test_build_local_receipt_reject() {
        let receipt = make_reject_receipt();
        let ledger = test_build_receipt(&receipt);

        assert_eq!(ledger, LocalReceipt::failure());
        assert_eq!(ledger.outcome, TransactionOutcome::Failure);
        assert!(ledger.database_updates.node_updates.is_empty());
        assert!(ledger.application_events.is_empty());
    }

    #[test]
    fn test_build_local_receipt_abort() {
        let receipt = make_abort_receipt();
        let ledger = test_build_receipt(&receipt);

        assert_eq!(ledger, LocalReceipt::failure());
    }

    #[test]
    fn test_build_local_receipt_receipt_hash_deterministic() {
        let receipt = TransactionReceipt::empty_commit_success();
        let ledger_a = test_build_receipt(&receipt);
        let ledger_b = test_build_receipt(&receipt);

        assert_eq!(ledger_a.receipt_hash(), ledger_b.receipt_hash());
    }

    // ─── Tests: build_execution_output ───────────────────────────────────

    #[test]
    fn test_build_execution_output_success_no_error() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_execution_output(&receipt);

        assert!(local.error_message.is_none());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_output_with_logs() {
        use radix_engine_interface::types::Level;
        let receipt = make_success_receipt_with_logs(vec![
            (Level::Info, "hello world".to_string()),
            (Level::Error, "something broke".to_string()),
            (Level::Debug, "debug info".to_string()),
        ]);
        let local = build_execution_output(&receipt);

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
    fn test_build_execution_output_reject_has_error() {
        let receipt = make_reject_receipt();
        let local = build_execution_output(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_output_abort_has_error() {
        let receipt = make_abort_receipt();
        let local = build_execution_output(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_output_fees_are_encoded() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_execution_output(&receipt);

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
