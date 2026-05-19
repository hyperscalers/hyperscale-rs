//! Convert Radix Engine [`TransactionReceipt`]s into our
//! [`ConsensusReceipt`] / [`ExecutionMetadata`] / [`DatabaseUpdates`] shapes.
//!
//! Receipt projection runs in two stages:
//!
//! - [`compute_vm_output`] turns a VM receipt into a [`CachedVmOutput`]
//!   — every field is shard-invariant for a given `(tx, receipt)`. This
//!   is the cacheable stage.
//! - [`project_to_shard`] consumes the cached output and a target shard
//!   to produce the final [`ExecutedTx`]. Only the `database_updates`
//!   slice is shard-specific.
//!
//! [`build_executed_tx`] composes the two for callers that don't cache.

use std::collections::{HashMap, HashSet};

use hyperscale_types::{
    ApplicationEvent, ConsensusReceipt, EventData, EventRoot, ExecutionMetadata, FeeSummary,
    GlobalReceipt, GlobalReceiptHash, Hash, LogLevel, NodeId, RoutableTransaction, ShardGroupId,
    TxHash, compute_merkle_root,
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
    resolve_owned_nodes,
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

/// Shard-invariant projection of a Radix Engine receipt.
///
/// Carries everything needed to assemble an [`ExecutedTx`] for any
/// participating shard. The transaction's effective state is canonical
/// across participating shards by way of provisioning, so every field
/// here is identical on every shard that executes the same
/// `(tx, receipt)`. Per-shard `database_updates` is *not* cached — it's
/// re-derived per call from `body.raw_updates` via [`project_to_shard`].
pub struct CachedVmOutput {
    metadata: ExecutionMetadata,
    body: CachedVmOutputBody,
}

#[allow(clippy::large_enum_variant)] // Succeeded is the common case; boxing penalises every hit
enum CachedVmOutputBody {
    /// VM rejected, aborted, or committed a `Failure` outcome.
    Failed,
    /// VM committed a `Success` outcome.
    Succeeded {
        raw_updates: DatabaseUpdates,
        declared_set: HashSet<NodeId>,
        ownership: HashMap<NodeId, NodeId>,
        application_events: Vec<ApplicationEvent>,
        receipt_hash: GlobalReceiptHash,
    },
}

/// Project a Radix Engine receipt into a [`CachedVmOutput`].
///
/// `storage` must match the view execution ran against — the local
/// snapshot for single-shard transactions, the provisioned merged view
/// for cross-shard. `resolve_owned_nodes` walks this view, so anything
/// narrower yields a partial ownership map and a shard-divergent
/// `writes_root`; anything wider races with concurrent cert commits.
pub fn compute_vm_output<S: SubstateDatabase>(
    storage: &S,
    tx: &RoutableTransaction,
    receipt: &TransactionReceipt,
) -> CachedVmOutput {
    let TransactionResult::Commit(commit) = &receipt.result else {
        tracing::warn!(
            tx_hash = ?tx.hash(),
            error = %format_args!("{:?}", receipt.result),
            "transaction execution failed"
        );
        return CachedVmOutput {
            metadata: ExecutionMetadata::empty(),
            body: CachedVmOutputBody::Failed,
        };
    };

    let metadata = build_execution_metadata(receipt);

    if !matches!(commit.outcome, TransactionOutcome::Success(_)) {
        // Failed receipts carry no consensus payload; metadata still flows.
        return CachedVmOutput {
            metadata,
            body: CachedVmOutputBody::Failed,
        };
    }

    let declared_nodes: Vec<NodeId> = tx
        .declared_reads()
        .iter()
        .chain(tx.declared_writes().iter())
        .copied()
        .collect();
    let declared_set: HashSet<NodeId> = declared_nodes.iter().copied().collect();
    let ownership = resolve_owned_nodes(storage, &declared_nodes);

    let application_events = extract_application_events(commit);
    let raw_updates = extract_database_updates(receipt);
    let global_updates = filter_updates_for_global_receipt(&raw_updates, &declared_set, &ownership);
    let writes_root = compute_writes_root(&global_updates);

    let event_hashes: Vec<Hash> = application_events
        .iter()
        .map(ApplicationEvent::hash)
        .collect();
    let event_root = EventRoot::from_raw(compute_merkle_root(&event_hashes));
    let receipt_hash = GlobalReceipt::new(true, event_root, writes_root).receipt_hash();

    CachedVmOutput {
        metadata,
        body: CachedVmOutputBody::Succeeded {
            raw_updates,
            declared_set,
            ownership,
            application_events,
            receipt_hash,
        },
    }
}

/// Build an [`ExecutedTx`] for `local_shard` from a [`CachedVmOutput`].
///
/// Runs the cheap per-shard step: `filter_updates_for_shard` over the
/// cached `raw_updates` + `ownership` + `declared_set`, then assembles
/// the `ExecutedTx`. Safe to call repeatedly with different `local_shard`
/// values against the same cached output.
#[must_use]
pub fn project_to_shard(
    cached: &CachedVmOutput,
    tx_hash: TxHash,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> ExecutedTx {
    match &cached.body {
        CachedVmOutputBody::Failed => {
            ExecutedTx::new(tx_hash, ConsensusReceipt::Failed, cached.metadata.clone())
        }
        CachedVmOutputBody::Succeeded {
            raw_updates,
            declared_set,
            ownership,
            application_events,
            receipt_hash,
        } => {
            let database_updates = filter_updates_for_shard(
                raw_updates,
                local_shard,
                num_shards,
                declared_set,
                ownership,
            );
            let consensus = ConsensusReceipt::Succeeded {
                receipt_hash: *receipt_hash,
                database_updates,
                application_events: application_events.clone(),
            };
            ExecutedTx::new(tx_hash, consensus, cached.metadata.clone())
        }
    }
}

/// Build an [`ExecutedTx`] from a Radix Engine receipt — compose
/// [`compute_vm_output`] + [`project_to_shard`] for callers that don't
/// cache the intermediate.
pub fn build_executed_tx<S: SubstateDatabase>(
    storage: &S,
    tx: &RoutableTransaction,
    receipt: &TransactionReceipt,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> ExecutedTx {
    let cached = compute_vm_output(storage, tx, receipt);
    project_to_shard(&cached, tx.hash(), local_shard, num_shards)
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
