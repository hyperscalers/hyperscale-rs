//! Convert Radix Engine [`TransactionReceipt`]s into our
//! [`ConsensusReceipt`] / [`ExecutionMetadata`] / [`DatabaseUpdates`] shapes.
//!
//! Everything here is pure post-processing: take a `TransactionReceipt`
//! produced by `execute_transaction` and project out the pieces the
//! state machine needs (database updates, application events, fee
//! summary, log messages, error string). Shard-filtering of writes
//! happens here too, via [`crate::sharding`].

use hyperscale_types::{
    ApplicationEvent, ConsensusReceipt, EventData, EventRoot, ExecutionMetadata, FeeSummary,
    GlobalReceipt, Hash, LogLevel, NodeId, RoutableTransaction, ShardGroupId, compute_merkle_root,
};
use radix_engine::transaction::{
    CommitResult, TransactionOutcome, TransactionReceipt, TransactionResult,
};
use radix_engine_interface::types::Level;
use radix_substate_store_interface::interface::{
    CreateDatabaseUpdates, DatabaseUpdates, SubstateDatabase,
};

use crate::output::ExecutedTx;
use crate::sharding::{
    compute_writes_root, filter_updates_for_global_receipt, filter_updates_for_shard,
};

/// Extract `DatabaseUpdates` from a transaction receipt.
///
/// Returns `DatabaseUpdates::default()` for rejected/aborted transactions.
pub fn extract_database_updates(receipt: &TransactionReceipt) -> DatabaseUpdates {
    match &receipt.result {
        TransactionResult::Commit(commit) => commit.state_updates.create_database_updates(),
        TransactionResult::Reject(_) | TransactionResult::Abort(_) => DatabaseUpdates::default(),
    }
}

/// Build an [`ExecutedTx`] from a Radix Engine receipt.
///
/// Encapsulates the receipt → executed-tx pipeline: shard-filter local
/// writes, build execution metadata, compute the global `writes_root`
/// from declared-only updates, and assemble the final canonical
/// `receipt_hash`.
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
    let metadata = build_execution_metadata(receipt);

    let TransactionResult::Commit(commit) = &receipt.result else {
        let error = format!("{:?}", receipt.result);
        return ExecutedTx::failure_with_log(tx.hash(), &error);
    };

    let success = matches!(commit.outcome, TransactionOutcome::Success(_));

    let declared_nodes: Vec<NodeId> = tx
        .declared_reads()
        .iter()
        .chain(tx.declared_writes().iter())
        .copied()
        .collect();

    if !success {
        // Failed receipts carry no consensus payload; metadata still flows.
        return ExecutedTx::new(tx.hash(), ConsensusReceipt::Failed, metadata);
    }

    let application_events = extract_application_events(commit);

    // Walk the commit once. Two views of the same updates feed the
    // success path: shard-filtered for the local consensus payload,
    // declared-only/system-filtered for the global `writes_root` the
    // EC commits to.
    let raw_updates = extract_database_updates(receipt);
    let database_updates = filter_updates_for_shard(
        &raw_updates,
        local_shard,
        num_shards,
        storage,
        &declared_nodes,
    );
    let global_updates = filter_updates_for_global_receipt(&raw_updates, storage, &declared_nodes);
    let writes_root = compute_writes_root(&global_updates);

    let event_hashes: Vec<Hash> = application_events
        .iter()
        .map(ApplicationEvent::hash)
        .collect();
    let event_root = EventRoot::from_raw(compute_merkle_root(&event_hashes));
    let receipt_hash = GlobalReceipt::new(true, event_root, writes_root).receipt_hash();

    let consensus = ConsensusReceipt::Succeeded {
        receipt_hash,
        database_updates,
        application_events,
    };
    ExecutedTx::new(tx.hash(), consensus, metadata)
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
                TransactionOutcome::Failure(err) => Some(format!("{err:?}")),
                TransactionOutcome::Success(_) => None,
            };
            (logs, error)
        }
        TransactionResult::Reject(reject) => (vec![], Some(format!("{:?}", reject.reason))),
        TransactionResult::Abort(abort) => (vec![], Some(format!("{:?}", abort.reason))),
    };

    ExecutionMetadata::new(fee_summary, log_messages, error_message)
}

/// Extract application events from a committed receipt.
fn extract_application_events(commit: &CommitResult) -> Vec<ApplicationEvent> {
    commit
        .application_events
        .iter()
        .map(|(type_id, data)| ApplicationEvent {
            type_id: type_id.clone(),
            data: EventData(data.clone()),
        })
        .collect()
}

/// Build a `FeeSummary` from a Radix Engine receipt.
const fn build_fee_summary(receipt: &TransactionReceipt) -> FeeSummary {
    let fees = &receipt.fee_summary;
    FeeSummary {
        total_execution_cost: Some(fees.total_execution_cost_in_xrd),
        total_royalty_cost: Some(fees.total_royalty_cost_in_xrd),
        total_storage_cost: Some(fees.total_storage_cost_in_xrd),
        total_tipping_cost: Some(fees.total_tipping_cost_in_xrd),
    }
}

/// Convert Radix Engine log level to our `LogLevel`.
const fn convert_log_level(level: Level) -> LogLevel {
    match level {
        Level::Error => LogLevel::Error,
        Level::Warn => LogLevel::Warn,
        Level::Info => LogLevel::Info,
        Level::Debug => LogLevel::Debug,
        Level::Trace => LogLevel::Trace,
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::LogLevel;
    use radix_engine::errors::RejectionReason;
    use radix_engine::transaction::{
        AbortReason, AbortResult, RejectResult, TransactionOutcome as RadixTransactionOutcome,
    };

    use super::*;

    fn make_success_receipt_with_logs(logs: Vec<(Level, String)>) -> TransactionReceipt {
        let mut commit = CommitResult::empty_with_outcome(RadixTransactionOutcome::Success(vec![]));
        commit.application_logs = logs;
        TransactionReceipt::empty_with_commit(commit)
    }

    fn make_reject_receipt() -> TransactionReceipt {
        TransactionReceipt {
            result: TransactionResult::Reject(RejectResult {
                reason: RejectionReason::SuccessButFeeLoanNotRepaid,
            }),
            ..TransactionReceipt::empty_commit_success()
        }
    }

    fn make_abort_receipt() -> TransactionReceipt {
        TransactionReceipt {
            result: TransactionResult::Abort(AbortResult {
                reason: AbortReason::ConfiguredAbortTriggeredOnFeeLoanRepayment,
            }),
            ..TransactionReceipt::empty_commit_success()
        }
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
        let receipt = make_success_receipt_with_logs(vec![
            (Level::Info, "hello world".to_string()),
            (Level::Error, "something broke".to_string()),
            (Level::Debug, "debug info".to_string()),
        ]);
        let local = build_execution_metadata(&receipt);

        assert_eq!(local.log_messages.len(), 3);
        assert_eq!(local.log_messages[0].0, LogLevel::Info);
        assert_eq!(local.log_messages[0].1.as_str(), "hello world");
        assert_eq!(local.log_messages[1].0, LogLevel::Error);
        assert_eq!(local.log_messages[1].1.as_str(), "something broke");
        assert_eq!(local.log_messages[2].0, LogLevel::Debug);
        assert_eq!(local.log_messages[2].1.as_str(), "debug info");
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

        // Real receipts always have populated cost fields — `None` is reserved
        // for the synthetic-failure path (`ExecutionMetadata::empty`).
        assert!(local.fee_summary.total_execution_cost.is_some());
        assert!(local.fee_summary.total_royalty_cost.is_some());
        assert!(local.fee_summary.total_storage_cost.is_some());
        assert!(local.fee_summary.total_tipping_cost.is_some());
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
