//! The central genericization trait for the consensus framework.
//!
//! `TypeConfig` defines associated types for transactions, execution receipts,
//! and state updates. Implementations provide a concrete binding (e.g.,
//! `RadixConfig` maps `Transaction` → `RoutableTransaction`).

use std::fmt::Debug;
use std::sync::Arc;

use hyperscale_codec::prelude::{BasicDecode, BasicEncode};

use crate::{
    DatabaseUpdates, Hash, LedgerTransactionOutcome, LedgerTransactionReceipt, NodeId,
    RoutableTransaction, ShardGroupId,
};

/// Core trait that parameterizes the consensus framework over
/// application-specific types.
///
/// Crypto stays concrete (BLS12-381) — only transaction, receipt, and state
/// update types are abstracted.
pub trait TypeConfig: Send + Sync + 'static {
    // ── Transaction ──

    /// Application-level transaction type.
    /// The framework treats this as opaque — it never inspects internals.
    type Transaction: Clone + Debug + Send + Sync + BasicEncode + BasicDecode;

    /// Receipt/result from executing a transaction.
    type ExecutionReceipt: Clone + Send + Sync + BasicEncode + BasicDecode;

    /// State delta produced by execution.
    /// Used in state root computation and cross-shard provisioning.
    type StateUpdate: Clone + Send + Sync;

    // ── Transaction operations ──

    /// Compute the hash of a transaction.
    fn transaction_hash(tx: &Self::Transaction) -> Hash;

    /// Get the read set (node addresses this tx reads from).
    fn transaction_reads(tx: &Self::Transaction) -> Vec<NodeId>;

    /// Get the write set (node addresses this tx writes to).
    fn transaction_writes(tx: &Self::Transaction) -> Vec<NodeId>;

    // ── Receipt operations ──

    /// Compute receipt hash for consensus voting.
    fn receipt_hash(receipt: &Self::ExecutionReceipt) -> Hash;

    /// Whether the receipt indicates success.
    fn receipt_success(receipt: &Self::ExecutionReceipt) -> bool;

    // ── State update operations ──

    /// Merge multiple state updates into one.
    fn merge_state_updates(updates: &[Self::StateUpdate]) -> Self::StateUpdate;

    /// Merge Arc-wrapped state updates into one.
    ///
    /// Default impl clones through Arc; implementations can override for
    /// zero-copy merging.
    fn merge_state_updates_from_arcs(updates: &[Arc<Self::StateUpdate>]) -> Self::StateUpdate {
        let dereffed: Vec<Self::StateUpdate> = updates.iter().map(|a| (**a).clone()).collect();
        Self::merge_state_updates(&dereffed)
    }

    /// Filter state update to entries owned by a specific shard.
    fn filter_state_update_to_shard(
        update: &Self::StateUpdate,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> Self::StateUpdate;

    /// Filter state update to only the entries for declared write addresses.
    fn filter_state_update_to_writes(
        update: &Self::StateUpdate,
        declared_writes: &[NodeId],
    ) -> Self::StateUpdate;
}

/// Internal concrete config used as the default type parameter during migration.
///
/// This allows `Block`, `ReceiptBundle`, etc. to be used without angle brackets
/// while downstream consumers are incrementally parameterized. It binds the
/// same concrete types that were previously hardcoded.
///
/// **Not for external use.** Use `RadixConfig` from `hyperscale-radix-config`
/// for production code.
#[derive(Debug, Clone)]
pub struct ConcreteConfig;

impl TypeConfig for ConcreteConfig {
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

    fn merge_state_updates(_updates: &[DatabaseUpdates]) -> DatabaseUpdates {
        unimplemented!("ConcreteConfig::merge_state_updates — use RadixConfig")
    }

    fn filter_state_update_to_shard(
        _update: &DatabaseUpdates,
        _local_shard: ShardGroupId,
        _num_shards: u64,
    ) -> DatabaseUpdates {
        unimplemented!("ConcreteConfig::filter_state_update_to_shard — use RadixConfig")
    }

    fn filter_state_update_to_writes(
        _update: &DatabaseUpdates,
        _declared_writes: &[NodeId],
    ) -> DatabaseUpdates {
        unimplemented!("ConcreteConfig::filter_state_update_to_writes — use RadixConfig")
    }
}
