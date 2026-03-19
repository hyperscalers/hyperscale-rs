//! Concrete `TypeConfig` binding for the Radix implementation.
//!
//! Maps the framework's generic associated types to Radix-specific types:
//! - `Transaction` → `RoutableTransaction`
//! - `ExecutionReceipt` → `LedgerTransactionReceipt`
//! - `StateUpdate` → `DatabaseUpdates`

use std::sync::Arc;

use hyperscale_types::{
    DatabaseUpdates, Hash, LedgerTransactionOutcome, LedgerTransactionReceipt, NodeId,
    RoutableTransaction, ShardGroupId, TypeConfig,
};

/// Radix-specific `TypeConfig` implementation.
///
/// This is the reference (and currently only) implementation. It binds the
/// framework's generic types to the concrete Radix ledger types.
pub struct RadixConfig;

impl TypeConfig for RadixConfig {
    type Transaction = RoutableTransaction;
    type ExecutionReceipt = LedgerTransactionReceipt;
    type StateUpdate = DatabaseUpdates;

    fn transaction_hash(tx: &RoutableTransaction) -> Hash {
        tx.hash()
    }

    fn transaction_reads(tx: &RoutableTransaction) -> Vec<NodeId> {
        tx.declared_reads.clone()
    }

    fn transaction_writes(tx: &RoutableTransaction) -> Vec<NodeId> {
        tx.declared_writes.clone()
    }

    fn receipt_hash(receipt: &LedgerTransactionReceipt) -> Hash {
        receipt.consensus_receipt().receipt_hash()
    }

    fn receipt_success(receipt: &LedgerTransactionReceipt) -> bool {
        receipt.outcome == LedgerTransactionOutcome::Success
    }

    fn merge_state_updates(updates: &[DatabaseUpdates]) -> DatabaseUpdates {
        hyperscale_storage::merge_database_updates(updates)
    }

    fn merge_state_updates_from_arcs(updates: &[Arc<DatabaseUpdates>]) -> DatabaseUpdates {
        hyperscale_storage::merge_database_updates_from_arcs(updates)
    }

    fn filter_state_update_to_shard(
        update: &DatabaseUpdates,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> DatabaseUpdates {
        hyperscale_storage::filter_updates_to_shard(update, local_shard, num_shards)
    }

    fn filter_state_update_to_writes(
        update: &DatabaseUpdates,
        declared_writes: &[NodeId],
    ) -> DatabaseUpdates {
        hyperscale_execution::handlers::filter_to_declared_writes(update, declared_writes)
    }
}
