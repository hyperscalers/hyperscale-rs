//! Synchronous Radix Engine executor.
//!
//! [`RadixExecutor`] is the production implementation of [`Engine`].
//! Storage is NOT owned by the executor — the runner provides it as a
//! method argument so the same executor can serve multiple snapshots
//! and so the runner can hoist a single snapshot across an entire
//! action batch.
//!
//! All methods are READ-ONLY: results are returned as [`ExecutedTx`]
//! values whose `DatabaseUpdates` the state machine caches and applies
//! later, when the wave's certificate is included in a committed block.

use std::sync::Arc;
use std::time::Instant;

use hyperscale_storage::{SubstateDatabase, SubstateStore};
use hyperscale_types::{
    BlockHeight, NodeId, RoutableTransaction, ShardGroupId, StateEntry, StateProvision,
};
use radix_common::network::NetworkDefinition;
use radix_common::types::NodeId as RadixNodeId;
use radix_engine::transaction::{ExecutionConfig, execute_transaction};
use radix_engine::vm::DefaultVmModules;
use radix_transactions::validation::TransactionValidator;
use tracing::field::Empty;
use tracing::{Level, Span, instrument};

use crate::engine::Engine;
use crate::output::{ExecutedTx, ExecutionOutput};
use crate::provisioned_snapshot::ProvisionedSnapshot;
use crate::receipt::build_executed_tx;

/// Fetch state entries for the given nodes from storage at a specific block height.
///
/// Reads substates at the given `block_height` using historical JMT traversal
/// and the leaf association table. Both data and proofs must come from the same
/// version to pass verification against the block header's `state_root`.
///
/// Returns `None` if the requested version is unavailable (GC'd or not yet
/// committed). Returns `Some(entries)` on success with pre-computed storage
/// keys for efficient cross-shard provisioning.
pub fn fetch_state_entries<S: SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    block_height: BlockHeight,
) -> Option<Vec<StateEntry>> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut entries = Vec::new();

    for node in nodes {
        // Compute the db_node_key once per node (expensive hash computation).
        let radix_node_id = RadixNodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        let substates = storage.list_substates_for_node_at_height(node, block_height)?;

        for (partition_num, db_sort_key, value) in substates {
            // Storage key: db_node_key || partition_num || sort_key
            let mut storage_key = Vec::with_capacity(db_node_key.len() + 1 + db_sort_key.0.len());
            storage_key.extend_from_slice(&db_node_key);
            storage_key.push(partition_num);
            storage_key.extend_from_slice(&db_sort_key.0);

            entries.push(StateEntry::new(storage_key, Some(value)));
        }
    }

    Some(entries)
}

/// Shared executor caches to avoid rebuilding on clone.
///
/// Wrapped in [`Arc`] so cloning [`RadixExecutor`] is cheap.
struct ExecutorCaches {
    /// VM modules — recreating per transaction would dominate small-tx cost.
    vm_modules: DefaultVmModules,
    /// Execution config (pinned to the network's notarized-transaction profile).
    exec_config: ExecutionConfig,
    /// Transaction validator (latest config for the network).
    validator: TransactionValidator,
}

/// Synchronous Radix Engine executor for deterministic execution.
///
/// Storage is NOT owned by the executor; the runner passes it to each
/// method. State machines stay pure; I/O is delegated to runners.
///
/// # Usage
///
/// ```ignore
/// // Runner owns storage.
/// let storage = Arc::new(SimStorage::new());
///
/// // Create executor (no storage parameter).
/// let executor = RadixExecutor::new(network);
///
/// // Bootstrap genesis: build (or reuse the cached) merged updates,
/// // then install them on per-node storage.
/// let merged = hyperscale_engine::prepared_genesis(executor.network(), &config);
/// storage.install_genesis(&merged);
///
/// // Execute a batch.
/// let output = executor.execute_single_shard(&storage, &transactions, shard, num_shards)?;
/// ```
///
/// # Cloning
///
/// Cloning is cheap — only the [`Arc`] around [`ExecutorCaches`] is bumped.
pub struct RadixExecutor {
    network: NetworkDefinition,
    caches: Arc<ExecutorCaches>,
}

impl RadixExecutor {
    /// Create a new executor for the given network.
    ///
    /// VM modules and execution config are cached to avoid per-transaction overhead.
    #[must_use]
    pub fn new(network: NetworkDefinition) -> Self {
        let vm_modules = DefaultVmModules::default();
        let exec_config = ExecutionConfig::for_notarized_transaction(network.clone());
        let validator = TransactionValidator::new_with_latest_config(&network);
        Self {
            network,
            caches: Arc::new(ExecutorCaches {
                vm_modules,
                exec_config,
                validator,
            }),
        }
    }

    /// Network definition this executor runs against.
    #[must_use]
    pub const fn network(&self) -> &NetworkDefinition {
        &self.network
    }

    /// Execute one transaction against a pre-taken snapshot.
    ///
    /// Validation failure produces an [`ExecutedTx::failure`] for that
    /// tx alone — peers in the batch are unaffected.
    fn execute_one<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutedTx {
        // Get-or-validate is cached on RoutableTransaction; avoids
        // re-checking signatures already checked at RPC ingress.
        let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
            return ExecutedTx::failure_with_log(tx.hash(), "Validation failed");
        };
        let executable = validated.clone().create_executable();

        let receipt = execute_transaction(
            snapshot,
            &self.caches.vm_modules,
            &self.caches.exec_config,
            &executable,
        );

        // Same snapshot for receipt filtering — using shared storage
        // would race with concurrent cert commits, producing different
        // filtered DatabaseUpdates and receipt_hash divergence across
        // validators.
        build_executed_tx(snapshot, tx, &receipt, local_shard, num_shards)
    }
}

impl Clone for RadixExecutor {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            caches: Arc::clone(&self.caches),
        }
    }
}

impl Engine for RadixExecutor {
    /// Each transaction is executed against `snapshot`. Caller hoists
    /// one snapshot across the batch — state doesn't change during
    /// execution (commits serialize elsewhere), so reusing a snapshot
    /// is correct and avoids per-tx `storage.snapshot()` +
    /// `read_jmt_metadata` overhead.
    ///
    /// Returns the per-tx [`ExecutedTx`] list. **Does NOT commit** —
    /// `DatabaseUpdates` from execution are cached by the state
    /// machine and applied when the `WaveCertificate` is included in
    /// a committed block.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        tx_count = transactions.len(),
        latency_us = Empty,
    ))]
    fn execute_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutionOutput {
        let start = Instant::now();
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            results.push(self.execute_one(snapshot, tx, local_shard, num_shards));
        }

        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        ExecutionOutput::new(results)
    }

    /// Layers `provisions` on top of `snapshot` via [`ProvisionedSnapshot`]
    /// and executes against the merged view. Provisions carry pre-computed
    /// storage keys from the sending shard for O(log n) lookups without
    /// expensive hash work.
    ///
    /// Same READ-ONLY contract as `execute_single_shard`.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        tx_count = transactions.len(),
        provision_count = provisions.len(),
        latency_us = Empty,
    ))]
    fn execute_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutionOutput {
        let start = Instant::now();
        let mut results = Vec::with_capacity(transactions.len());

        let entry_slices: Vec<&[StateEntry]> =
            provisions.iter().map(|p| p.entries().as_slice()).collect();
        let provisioned = ProvisionedSnapshot::from_provisions(snapshot, &entry_slices);

        for tx in transactions {
            let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
                results.push(ExecutedTx::failure_with_log(tx.hash(), "Validation failed"));
                continue;
            };
            let executable = validated.clone().create_executable();
            let receipt = provisioned.execute(
                &executable,
                &self.caches.vm_modules,
                &self.caches.exec_config,
            );

            // Same snapshot for receipt filtering — `resolve_owned_nodes`
            // must see the same ownership state as the execution.
            results.push(build_executed_tx(
                snapshot,
                tx,
                &receipt,
                local_shard,
                num_shards,
            ));
        }

        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        ExecutionOutput::new(results)
    }

    fn network(&self) -> &NetworkDefinition {
        Self::network(self)
    }
}
