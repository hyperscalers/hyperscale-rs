//! Convert Radix Engine [`TransactionReceipt`]s into our
//! [`LocalReceipt`] / [`ExecutionMetadata`] / [`DatabaseUpdates`] shapes.
//!
//! Everything here is pure post-processing: take a `TransactionReceipt`
//! produced by `execute_transaction` and project out the pieces the
//! state machine needs (database updates, application events, fee
//! summary, log messages, error string). Shard-filtering of writes
//! happens here too, via [`crate::sharding`].

use crate::output::ExecutedTx;
use hyperscale_types::{
    ApplicationEvent, ConsensusReceipt, ExecutionMetadata, FeeSummary, LocalReceipt, LogLevel,
    NodeId, RoutableTransaction, ShardGroupId, TransactionOutcome,
};
use radix_engine::transaction::{TransactionReceipt, TransactionResult};
use radix_substate_store_interface::interface::{
    CreateDatabaseUpdates, DatabaseUpdates, SubstateDatabase,
};

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
pub const fn is_committed(receipt: &TransactionReceipt) -> bool {
    matches!(&receipt.result, TransactionResult::Commit(_))
}

/// Extract `DatabaseUpdates` from a transaction receipt.
///
/// Returns `DatabaseUpdates::default()` for rejected/aborted transactions.
pub fn extract_database_updates(receipt: &TransactionReceipt) -> DatabaseUpdates {
    extract_state_updates(receipt).unwrap_or_default()
}

/// Build a `LocalReceipt` from a Radix Engine receipt.
///
/// Shard filtering is applied here so the receipt is always born with
/// shard-specific `database_updates`. System entity writes (`ConsensusManager`,
/// `TransactionTracker`, Validator) are always filtered regardless of shard count,
/// since their execution order is non-deterministic across validators.
pub fn build_local_receipt<S: SubstateDatabase>(
    receipt: &TransactionReceipt,
    storage: &S,
    declared_nodes: &[NodeId],
    local_shard: ShardGroupId,
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
            database_updates = crate::sharding::filter_updates_for_shard(
                &database_updates,
                local_shard,
                num_shards,
                storage,
                declared_nodes,
            );
            LocalReceipt {
                outcome,
                database_updates,
                application_events,
            }
        }
        TransactionResult::Reject(_) | TransactionResult::Abort(_) => LocalReceipt::failure(),
    }
}

/// Build an [`ExecutedTx`] from a Radix Engine receipt.
///
/// Encapsulates the receipt → executed-tx pipeline:
/// shard-filter local writes, build execution metadata, compute the
/// global `writes_root` from declared-only updates, and assemble the
/// final canonical `receipt_hash`.
///
/// Takes [`SubstateDatabase`] (not [`SubstateStore`]) so callers can
/// pass an execution snapshot. Using the same snapshot as execution
/// keeps `resolve_owned_nodes` consistent with execution-time
/// ownership state — using shared storage would race with concurrent
/// cert commits and cause `receipt_hash` divergence across validators.
pub fn build_executed_tx<S: SubstateDatabase>(
    storage: &S,
    tx: &RoutableTransaction,
    receipt: &TransactionReceipt,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> ExecutedTx {
    if is_committed(receipt) {
        let declared_nodes: Vec<NodeId> = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .copied()
            .collect();
        let local_receipt =
            build_local_receipt(receipt, storage, &declared_nodes, local_shard, num_shards);
        let metadata = build_execution_metadata(receipt);

        // writes_root for GlobalReceipt: declared-only, system-filtered,
        // NOT shard-filtered. Must match the per-shard agreement on the
        // global view of writes.
        let raw_updates = extract_database_updates(receipt);
        let global_updates = crate::sharding::filter_updates_for_global_receipt(
            &raw_updates,
            storage,
            &declared_nodes,
        );
        let writes_root = crate::sharding::compute_writes_root(&global_updates);
        let receipt_hash = local_receipt.global_receipt(writes_root).receipt_hash();

        let consensus = ConsensusReceipt::Succeeded {
            receipt_hash,
            database_updates: local_receipt.database_updates,
            application_events: local_receipt.application_events,
        };
        ExecutedTx::new(tx.hash(), consensus, metadata)
    } else {
        let error = format!("{:?}", receipt.result);
        ExecutedTx::failure(tx.hash(), error)
    }
}

/// Build `ExecutionMetadata` from a Radix Engine receipt.
pub fn build_execution_metadata(receipt: &TransactionReceipt) -> ExecutionMetadata {
    let fee_summary = build_fee_summary(receipt);

    let (log_messages, error_message) = match &receipt.result {
        TransactionResult::Commit(commit) => {
            let logs = commit
                .application_logs
                .iter()
                .map(|(level, msg)| (convert_log_level(*level), msg.clone()))
                .collect();
            let error = match &commit.outcome {
                radix_engine::transaction::TransactionOutcome::Failure(err) => {
                    Some(format!("{err:?}"))
                }
                radix_engine::transaction::TransactionOutcome::Success(_) => None,
            };
            (logs, error)
        }
        TransactionResult::Reject(reject) => (vec![], Some(format!("{:?}", reject.reason))),
        TransactionResult::Abort(abort) => (vec![], Some(format!("{:?}", abort.reason))),
    };

    ExecutionMetadata {
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

/// Convert Radix Engine log level to our `LogLevel`.
const fn convert_log_level(level: radix_engine_interface::types::Level) -> LogLevel {
    match level {
        radix_engine_interface::types::Level::Error => LogLevel::Error,
        radix_engine_interface::types::Level::Warn => LogLevel::Warn,
        radix_engine_interface::types::Level::Info => LogLevel::Info,
        radix_engine_interface::types::Level::Debug => LogLevel::Debug,
        radix_engine_interface::types::Level::Trace => LogLevel::Trace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::LogLevel;
    use radix_engine::transaction::{
        AbortResult, CommitResult, RejectResult, TransactionOutcome as RadixTransactionOutcome,
        TransactionReceipt, TransactionResult,
    };

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

    #[test]
    fn test_build_execution_metadata_success_no_error() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_execution_metadata(&receipt);

        assert!(local.error_message.is_none());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_metadata_with_logs() {
        use radix_engine_interface::types::Level;
        let receipt = make_success_receipt_with_logs(vec![
            (Level::Info, "hello world".to_string()),
            (Level::Error, "something broke".to_string()),
            (Level::Debug, "debug info".to_string()),
        ]);
        let local = build_execution_metadata(&receipt);

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
    fn test_build_execution_metadata_reject_has_error() {
        let receipt = make_reject_receipt();
        let local = build_execution_metadata(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_metadata_abort_has_error() {
        let receipt = make_abort_receipt();
        let local = build_execution_metadata(&receipt);

        assert!(local.error_message.is_some());
        assert!(local.log_messages.is_empty());
    }

    #[test]
    fn test_build_execution_metadata_fees_are_encoded() {
        let receipt = TransactionReceipt::empty_commit_success();
        let local = build_execution_metadata(&receipt);

        // Default fee summary has zero Decimals, which still SBOR-encode to non-empty bytes.
        assert!(
            !local.fee_summary.total_execution_cost.is_empty(),
            "SBOR-encoded zero Decimal should be non-empty"
        );
        assert!(!local.fee_summary.total_royalty_cost.is_empty());
        assert!(!local.fee_summary.total_storage_cost.is_empty());
        assert!(!local.fee_summary.total_tipping_cost.is_empty());
    }

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
