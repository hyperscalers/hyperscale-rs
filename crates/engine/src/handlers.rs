//! Transaction execution handlers with integrated shard filtering.
//!
//! These are the primary entry points for executing transactions. Each function
//! executes via the Radix Engine and returns results filtered for the local shard
//! (system writes removed, internal nodes assigned to their parent's shard).
//!
//! The `execution` crate's handlers delegate to these functions.

use crate::sharding;
use crate::{RadixExecutor, SingleTxResult};
use hyperscale_storage::SubstateStore;
use hyperscale_types::{Hash, RoutableTransaction, ShardGroupId, TxExecutionOutcome, TxOutcome};
use std::sync::Arc;

/// Execute a single-shard transaction with shard filtering.
///
/// Executes via the Radix Engine, then filters the resulting `DatabaseUpdates`
/// to remove system writes and keep only writes belonging to `local_shard`.
pub fn execute_single_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx: &Arc<RoutableTransaction>,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> SingleTxResult {
    let result = match executor.execute_single_shard(storage, std::slice::from_ref(tx)) {
        Ok(output) => {
            if let Some(r) = output.results().first() {
                r.clone()
            } else {
                SingleTxResult::failure(tx.hash(), "No execution result returned")
            }
        }
        Err(e) => {
            tracing::warn!(tx_hash = ?tx.hash(), error = %e, "Transaction execution failed");
            SingleTxResult::failure(tx.hash(), e.to_string())
        }
    };

    let mut result = result;
    if num_shards > 1 {
        result.database_updates = sharding::filter_updates_for_shard(
            &result.database_updates,
            local_shard,
            num_shards,
            storage,
        );
    }
    result
}

/// Execute a cross-shard transaction with provisions and shard filtering.
///
/// Executes via the Radix Engine with the provisioned snapshot overlay,
/// then filters the resulting `DatabaseUpdates` for the local shard.
pub fn execute_cross_shard<S: SubstateStore>(
    executor: &RadixExecutor,
    storage: &S,
    tx_hash: Hash,
    transaction: &Arc<RoutableTransaction>,
    provisions: &[hyperscale_types::StateProvision],
    local_shard: ShardGroupId,
    num_shards: u64,
) -> SingleTxResult {
    let result = match executor.execute_cross_shard(
        storage,
        std::slice::from_ref(transaction),
        provisions,
    ) {
        Ok(output) => {
            if let Some(r) = output.results().first() {
                r.clone()
            } else {
                SingleTxResult::failure(tx_hash, "No cross-shard execution result returned")
            }
        }
        Err(e) => {
            tracing::warn!(?tx_hash, error = %e, "Cross-shard execution failed");
            SingleTxResult::failure(tx_hash, e.to_string())
        }
    };

    let mut result = result;
    if num_shards > 1 {
        result.database_updates = sharding::filter_updates_for_shard(
            &result.database_updates,
            local_shard,
            num_shards,
            storage,
        );
    }
    result
}

/// Extract execution-ready result data from a SingleTxResult.
///
/// Extracts write_nodes and builds a `TxOutcome` for the execution accumulator.
/// Called on the handler thread (after execution, before returning to state machine).
pub fn extract_execution_result(result: &SingleTxResult) -> TxOutcome {
    let write_nodes = sharding::extract_write_nodes(&result.database_updates);
    TxOutcome {
        tx_hash: result.tx_hash,
        outcome: TxExecutionOutcome::Executed {
            receipt_hash: result.receipt_hash,
            success: result.success,
            write_nodes,
        },
    }
}
