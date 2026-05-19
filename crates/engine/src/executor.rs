//! Synchronous Radix Engine executor.
//!
//! [`RadixExecutor`] runs transactions against a caller-supplied
//! snapshot and returns the shard-invariant [`CachedVmOutput`]. The
//! caller projects it into a per-shard [`ExecutedTx`] via
//! [`project_to_shard`](crate::project_to_shard) and typically
//! memoises the intermediate in
//! [`ProcessExecutionCache`](crate::ProcessExecutionCache).
//!
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
use hyperscale_types::{BlockHeight, NodeId, RoutableTransaction, SubstateEntry};
use radix_common::network::NetworkDefinition;
use radix_common::types::NodeId as RadixNodeId;
use radix_engine::transaction::{ExecutionConfig, execute_transaction};
use radix_engine::vm::DefaultVmModules;
use radix_transactions::validation::TransactionValidator;
use tracing::field::Empty;
use tracing::{Level, Span, instrument};

use crate::provisioned_snapshot::ProvisionedSnapshot;
use crate::receipt::{CachedVmOutput, compute_vm_output};

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
) -> Option<Vec<SubstateEntry>> {
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

            entries.push(SubstateEntry::new(storage_key, Some(value)));
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

    /// Run the VM for a single-shard transaction and return the
    /// [`CachedVmOutput`] — the shard-invariant projection of the
    /// receipt. Caller pairs this with
    /// [`crate::project_to_shard`] to produce an [`ExecutedTx`] for
    /// each participating shard.
    #[instrument(level = Level::DEBUG, skip_all, fields(latency_us = Empty))]
    pub fn compute_vm_output_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
    ) -> CachedVmOutput {
        let start = Instant::now();
        let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
            return CachedVmOutput::validation_failed(tx.hash());
        };
        let executable = validated.clone().create_executable();
        let receipt = execute_transaction(
            snapshot,
            &self.caches.vm_modules,
            &self.caches.exec_config,
            &executable,
        );
        let output = compute_vm_output(snapshot, tx, &receipt);
        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        output
    }

    /// Layers `provisions` on top of `snapshot` via [`ProvisionedSnapshot`]
    /// and executes against the merged view. Provisions carry pre-computed
    /// storage keys from the sending shard for O(log n) lookups without
    /// expensive hash work.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        provision_count = provisions.len(),
        latency_us = Empty,
    ))]
    pub fn compute_vm_output_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
        provisions: &[Arc<Vec<SubstateEntry>>],
    ) -> CachedVmOutput {
        let start = Instant::now();
        let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
            return CachedVmOutput::validation_failed(tx.hash());
        };
        let executable = validated.clone().create_executable();
        let entry_slices: Vec<&[SubstateEntry]> = provisions.iter().map(|p| p.as_slice()).collect();
        let provisioned = ProvisionedSnapshot::from_provisions(snapshot, &entry_slices);
        let receipt = provisioned.execute(
            &executable,
            &self.caches.vm_modules,
            &self.caches.exec_config,
        );
        let output = compute_vm_output(&provisioned, tx, &receipt);
        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        output
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
