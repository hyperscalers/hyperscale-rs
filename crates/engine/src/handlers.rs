//! Transaction execution handlers with integrated shard filtering.
//!
//! These are the primary entry points for executing transactions. Each function
//! executes via the Radix Engine and returns results filtered for the local shard
//! (system writes removed, internal nodes assigned to their parent's shard).
//!
//! The `execution` crate's handlers delegate to these functions.

use crate::executor::Engine;
use crate::SingleTxResult;
use hyperscale_storage::SubstateStore;
use hyperscale_types::{ExecutionOutcome, Hash, RoutableTransaction, ShardGroupId, TxOutcome};
use std::sync::Arc;

/// Execute a single-shard transaction with shard filtering.
///
/// Executes via the engine, then filters the resulting `DatabaseUpdates`
/// to remove system writes and keep only writes belonging to `local_shard`.
pub fn execute_single_shard<S: SubstateStore, E: Engine>(
    executor: &E,
    storage: &S,
    tx: &Arc<RoutableTransaction>,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> SingleTxResult {
    match executor.execute_single_shard(storage, std::slice::from_ref(tx), local_shard, num_shards)
    {
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
    }
}

/// Execute a cross-shard transaction with provisions.
///
/// Executes via the engine with the provisioned snapshot overlay.
/// The receipt's `database_updates` are shard-filtered by the executor.
pub fn execute_cross_shard<S: SubstateStore, E: Engine>(
    executor: &E,
    storage: &S,
    tx_hash: Hash,
    transaction: &Arc<RoutableTransaction>,
    provisions: &[hyperscale_types::StateProvision],
    local_shard: ShardGroupId,
    num_shards: u64,
) -> SingleTxResult {
    match executor.execute_cross_shard(
        storage,
        std::slice::from_ref(transaction),
        provisions,
        local_shard,
        num_shards,
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
    }
}

/// Extract execution-ready result data from a SingleTxResult.
///
/// Builds a `TxOutcome` for the execution accumulator.
/// Called on the handler thread (after execution, before returning to state machine).
pub fn extract_execution_result(result: &SingleTxResult) -> TxOutcome {
    TxOutcome {
        tx_hash: result.tx_hash,
        outcome: ExecutionOutcome::Executed {
            receipt_hash: result.receipt_hash,
            success: result.success,
        },
    }
}
