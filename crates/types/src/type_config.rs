//! The central genericization trait for the consensus framework.
//!
//! `TypeConfig` defines associated types for transactions, execution receipts,
//! and state updates. Implementations provide a concrete binding (e.g.,
//! `RadixConfig` maps `Transaction` → `RoutableTransaction`).

use std::fmt::Debug;
use std::sync::Arc;

use crate::BlockHeight;
use hyperscale_codec::prelude::{BasicDecode, BasicEncode};

use crate::{Hash, NodeId, ShardGroupId};

// ── Trait bounds for associated types ────────────────────────────────────────

/// Operations the consensus framework requires on state update types.
///
/// State updates are the deltas produced by transaction execution. The
/// framework needs to merge, filter, and inspect them without knowing
/// their internal structure.
pub trait ConsensusStateUpdate: Clone + Default + Send + Sync {
    /// Merge multiple state updates into one (last writer wins for conflicts).
    ///
    /// Updates are processed left-to-right; later entries take precedence.
    fn merge(updates: &[Self]) -> Self;

    /// Merge Arc-wrapped state updates into one.
    ///
    /// Default impl clones through Arc; implementations can override for
    /// zero-copy merging.
    fn merge_from_arcs(updates: &[Arc<Self>]) -> Self {
        let dereffed: Vec<Self> = updates.iter().map(|a| (**a).clone()).collect();
        Self::merge(&dereffed)
    }

    /// Filter to entries owned by a specific shard.
    fn filter_to_shard(&self, local_shard: ShardGroupId, num_shards: u64) -> Self;

    /// Filter to entries matching declared write addresses.
    ///
    /// When `declared_writes` is empty, the update is returned unfiltered
    /// (empty means "no write set declared", not "no writes allowed").
    fn filter_to_writes(&self, declared_writes: &[NodeId]) -> Self;

    /// Extract deduplicated, deterministically-ordered NodeIds from this update.
    fn extract_write_nodes(&self) -> Vec<NodeId>;
}

/// Operations the consensus framework requires on transaction types.
///
/// Implementations provide hashing, read/write set introspection, retry
/// lifecycle, and cross-shard classification. The framework never inspects
/// transaction internals beyond these methods.
pub trait ConsensusTransaction: Clone + Debug + Send + Sync + BasicEncode + BasicDecode {
    /// Compute the content-addressed hash of this transaction.
    fn tx_hash(&self) -> Hash;

    /// Node addresses this transaction reads from.
    fn reads(&self) -> &[NodeId];

    /// Node addresses this transaction writes to.
    fn writes(&self) -> &[NodeId];

    /// All declared nodes (reads + writes combined).
    fn all_nodes(&self) -> Vec<NodeId> {
        let mut nodes = self.reads().to_vec();
        nodes.extend_from_slice(self.writes());
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
        let mut shards = std::collections::BTreeSet::new();
        for node in self.reads().iter().chain(self.writes().iter()) {
            shards.insert(crate::shard_for_node(node, num_shards));
        }
        shards.len() > 1
    }
}

/// Operations the consensus framework requires on execution receipt types.
pub trait ConsensusExecutionReceipt:
    Clone + Debug + Send + Sync + BasicEncode + BasicDecode
{
    /// Compute the consensus receipt hash (signed over in votes/certificates).
    fn consensus_receipt_hash(&self) -> Hash;

    /// Whether the receipt indicates successful execution.
    fn is_success(&self) -> bool;

    /// Create a default failure receipt (no state changes or events).
    fn failure() -> Self;
}

/// Core trait that parameterizes the consensus framework over
/// application-specific types.
///
/// Transaction and receipt operations live on their respective trait bounds
/// ([`ConsensusTransaction`], [`ConsensusExecutionReceipt`]).
/// State update operations are static methods here because the orphan rule
/// prevents adding trait impls to foreign types like `DatabaseUpdates`.
///
/// Crypto stays concrete (BLS12-381).
pub trait TypeConfig: Send + Sync + 'static {
    /// Application-level transaction type.
    type Transaction: ConsensusTransaction;

    /// Receipt/result from executing a transaction.
    type ExecutionReceipt: ConsensusExecutionReceipt;

    /// State delta produced by execution.
    type StateUpdate: ConsensusStateUpdate;

    /// Convert a receipt into a state update.
    ///
    /// Used by syncing nodes that receive receipts from peers instead of
    /// executing transactions locally.
    fn receipt_to_state_update(receipt: &Self::ExecutionReceipt) -> Self::StateUpdate;

    /// Enrich a receipt with derived data from the state update before persisting.
    ///
    /// For Radix, this populates `state_changes` on `LedgerTransactionReceipt`
    /// from the `DatabaseUpdates`. Other implementations may be a no-op.
    ///
    /// Default: returns the receipt unchanged.
    fn enrich_receipt_for_storage(
        receipt: &Self::ExecutionReceipt,
        _state_update: &Self::StateUpdate,
    ) -> Self::ExecutionReceipt {
        receipt.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_codec as sbor;

    /// Minimal transaction type proving framework genericity.
    #[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
    struct MockTransaction {
        hash: Hash,
        reads: Vec<NodeId>,
        writes: Vec<NodeId>,
    }

    impl ConsensusTransaction for MockTransaction {
        fn tx_hash(&self) -> Hash {
            self.hash
        }
        fn reads(&self) -> &[NodeId] {
            &self.reads
        }
        fn writes(&self) -> &[NodeId] {
            &self.writes
        }
        fn is_retry(&self) -> bool {
            false
        }
        fn original_hash(&self) -> Hash {
            self.hash
        }
        fn retry_count(&self) -> u32 {
            0
        }
        fn create_retry(&self, _deferred_by: Hash, _deferred_at: BlockHeight) -> Self {
            self.clone()
        }
    }

    /// Minimal receipt type.
    #[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
    struct MockReceipt {
        success: bool,
    }

    impl ConsensusExecutionReceipt for MockReceipt {
        fn consensus_receipt_hash(&self) -> Hash {
            Hash::ZERO
        }
        fn is_success(&self) -> bool {
            self.success
        }
        fn failure() -> Self {
            Self { success: false }
        }
    }

    /// Minimal state update type.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct MockStateUpdate {
        entries: Vec<(NodeId, Vec<u8>)>,
    }

    impl ConsensusStateUpdate for MockStateUpdate {
        fn merge(updates: &[Self]) -> Self {
            let mut merged = Self::default();
            for u in updates {
                merged.entries.extend(u.entries.iter().cloned());
            }
            merged
        }

        fn filter_to_shard(&self, local_shard: ShardGroupId, num_shards: u64) -> Self {
            Self {
                entries: self
                    .entries
                    .iter()
                    .filter(|(node_id, _)| {
                        crate::shard_for_node(node_id, num_shards) == local_shard
                    })
                    .cloned()
                    .collect(),
            }
        }

        fn filter_to_writes(&self, declared_writes: &[NodeId]) -> Self {
            if declared_writes.is_empty() {
                return self.clone();
            }
            let allowed: std::collections::HashSet<NodeId> =
                declared_writes.iter().copied().collect();
            Self {
                entries: self
                    .entries
                    .iter()
                    .filter(|(node_id, _)| allowed.contains(node_id))
                    .cloned()
                    .collect(),
            }
        }

        fn extract_write_nodes(&self) -> Vec<NodeId> {
            self.entries.iter().map(|(id, _)| *id).collect()
        }
    }

    /// Non-Radix TypeConfig proving the framework is generic.
    #[derive(Debug, Clone)]
    struct MockConfig;

    impl TypeConfig for MockConfig {
        type Transaction = MockTransaction;
        type ExecutionReceipt = MockReceipt;
        type StateUpdate = MockStateUpdate;

        fn receipt_to_state_update(_receipt: &MockReceipt) -> MockStateUpdate {
            MockStateUpdate::default()
        }
    }

    #[test]
    fn mock_config_block_compiles() {
        // Prove Block<MockConfig> can be constructed and used.
        use crate::{Block, ValidatorId};

        let block = Block::<MockConfig>::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO);
        assert_eq!(block.header.height, BlockHeight(0));
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn mock_config_type_config_methods() {
        let node_id = NodeId([0u8; 30]);
        let update = MockStateUpdate {
            entries: vec![(node_id, vec![1, 2, 3])],
        };

        // merge
        let merged = MockStateUpdate::merge(&[update.clone(), update.clone()]);
        assert_eq!(merged.entries.len(), 2);

        // extract_write_nodes
        let nodes = update.extract_write_nodes();
        assert_eq!(nodes, vec![node_id]);

        // filter_to_writes
        let filtered = update.filter_to_writes(&[node_id]);
        assert_eq!(filtered.entries.len(), 1);

        // Empty declared_writes = no filtering (pass everything through).
        let unfiltered = update.filter_to_writes(&[]);
        assert_eq!(unfiltered.entries.len(), 1);

        // receipt_to_state_update
        let receipt = MockReceipt { success: true };
        let from_receipt = MockConfig::receipt_to_state_update(&receipt);
        assert!(from_receipt.entries.is_empty());

        // failure
        let fail_receipt = MockReceipt::failure();
        assert!(!fail_receipt.is_success());
    }
}
