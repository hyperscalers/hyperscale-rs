//! The central genericization trait for the consensus framework.
//!
//! `TypeConfig` defines associated types for transactions, execution receipts,
//! and state updates. Implementations provide a concrete binding (e.g.,
//! `RadixConfig` maps `Transaction` → `RoutableTransaction`).

use std::fmt::Debug;
use std::sync::Arc;

use crate::BlockHeight;
use hyperscale_codec::prelude::{BasicDecode, BasicEncode};

use crate::{
    DatabaseUpdates, Hash, LedgerTransactionReceipt, NodeId, RoutableTransaction, ShardGroupId,
};

// ── Trait bounds for associated types ────────────────────────────────────────

/// Operations the consensus framework requires on transaction types.
///
/// Implementations provide hashing, read/write set introspection, retry
/// lifecycle, and cross-shard classification. The framework never inspects
/// transaction internals beyond these methods.
pub trait ConsensusTransaction: Clone + Debug + Send + Sync + BasicEncode + BasicDecode {
    /// Compute the content-addressed hash of this transaction.
    fn tx_hash(&self) -> Hash;

    /// Node addresses this transaction reads from.
    fn reads(&self) -> Vec<NodeId>;

    /// Node addresses this transaction writes to.
    fn writes(&self) -> Vec<NodeId>;

    /// All declared nodes (reads + writes combined).
    fn all_nodes(&self) -> Vec<NodeId> {
        let mut nodes = self.reads();
        nodes.extend(self.writes());
        nodes
    }

    /// Whether this transaction is a retry of a deferred transaction.
    fn is_retry(&self) -> bool;

    /// The original transaction hash (before any retries).
    fn original_hash(&self) -> Hash;

    /// How many times this transaction has been retried.
    fn retry_count(&self) -> u32;

    /// Whether this transaction has exceeded the maximum retry count.
    fn exceeds_max_retries(&self, max_retries: u32) -> bool {
        self.retry_count() >= max_retries
    }

    /// Create a retry of this transaction with new retry metadata.
    fn create_retry(&self, deferred_by: Hash, deferred_at: BlockHeight) -> Self;

    /// Whether this transaction touches multiple shards.
    fn is_cross_shard(&self, num_shards: u64) -> bool {
        let reads = self.reads();
        let writes = self.writes();
        let mut shards = std::collections::BTreeSet::new();
        for node in reads.iter().chain(writes.iter()) {
            shards.insert(crate::shard_for_node(node, num_shards));
        }
        shards.len() > 1
    }
}

/// Operations the consensus framework requires on execution receipt types.
pub trait ConsensusExecutionReceipt: Clone + Send + Sync + BasicEncode + BasicDecode {
    /// Compute the consensus receipt hash (signed over in votes/certificates).
    fn consensus_receipt_hash(&self) -> Hash;

    /// Whether the receipt indicates successful execution.
    fn is_success(&self) -> bool;
}

/// Core trait that parameterizes the consensus framework over
/// application-specific types.
///
/// Transaction and receipt operations live on their respective trait bounds
/// ([`ConsensusTransaction`], [`ConsensusReceipt`]). Only state update
/// operations remain here because `StateUpdate` may be a foreign type
/// where the orphan rule prevents adding a trait impl.
///
/// Crypto stays concrete (BLS12-381).
pub trait TypeConfig: Send + Sync + 'static {
    /// Application-level transaction type.
    type Transaction: ConsensusTransaction;

    /// Receipt/result from executing a transaction.
    type ExecutionReceipt: ConsensusExecutionReceipt;

    /// State delta produced by execution.
    type StateUpdate: Clone + Send + Sync;

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

    fn merge_state_updates(updates: &[DatabaseUpdates]) -> DatabaseUpdates {
        // Delegate to the merge logic in hyperscale_storage at runtime.
        // ConcreteConfig is only used where the storage crate is also available,
        // so this is always reachable. The implementation is provided by the
        // storage crate's free function, called through the RadixConfig path
        // (which has an identical impl). For ConcreteConfig we inline a simple
        // version using DatabaseUpdates' IndexMap structure.
        use radix_substate_store_interface::interface::NodeDatabaseUpdates;
        if updates.is_empty() {
            return DatabaseUpdates::default();
        }
        if updates.len() == 1 {
            return updates[0].clone();
        }
        let mut merged = DatabaseUpdates::default();
        for update in updates {
            for (entity_key, node_updates) in &update.node_updates {
                let target = merged
                    .node_updates
                    .entry(entity_key.clone())
                    .or_insert_with(NodeDatabaseUpdates::default);
                for (partition, part_updates) in &node_updates.partition_updates {
                    target
                        .partition_updates
                        .entry(*partition)
                        .and_modify(|existing| {
                            // Merge: source overwrites target for overlapping keys
                            match (existing, part_updates) {
                                (
                                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta { substate_updates: target_updates },
                                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta { substate_updates: source_updates },
                                ) => {
                                    for (k, v) in source_updates {
                                        target_updates.insert(k.clone(), v.clone());
                                    }
                                }
                                (existing, source) => {
                                    *existing = source.clone();
                                }
                            }
                        })
                        .or_insert_with(|| part_updates.clone());
                }
            }
        }
        merged
    }

    fn filter_state_update_to_shard(
        update: &DatabaseUpdates,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> DatabaseUpdates {
        if num_shards <= 1 {
            return update.clone();
        }
        // Extract NodeId from db_node_key: 20-byte hash prefix + 30-byte NodeId.
        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                let mut bytes = [0u8; NODE_ID_LEN];
                bytes.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
                let node_id = NodeId(bytes);
                if crate::shard_for_node(&node_id, num_shards) == local_shard {
                    filtered
                        .node_updates
                        .insert(db_node_key.clone(), node_updates.clone());
                }
            } else {
                // Keep system/unknown entries
                filtered
                    .node_updates
                    .insert(db_node_key.clone(), node_updates.clone());
            }
        }
        filtered
    }

    fn filter_state_update_to_writes(
        update: &DatabaseUpdates,
        declared_writes: &[NodeId],
    ) -> DatabaseUpdates {
        if declared_writes.is_empty() {
            return update.clone();
        }
        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;
        let allowed: std::collections::HashSet<NodeId> = declared_writes.iter().copied().collect();
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                let mut bytes = [0u8; NODE_ID_LEN];
                bytes.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
                let node_id = NodeId(bytes);
                if allowed.contains(&node_id) {
                    filtered
                        .node_updates
                        .insert(db_node_key.clone(), node_updates.clone());
                }
            } else {
                filtered
                    .node_updates
                    .insert(db_node_key.clone(), node_updates.clone());
            }
        }
        filtered
    }
}
