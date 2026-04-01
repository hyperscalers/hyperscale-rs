//! Radix Engine executor for deterministic simulation.
//!
//! This module provides synchronous transaction execution that can be called
//! by runners. The executor does NOT own storage - storage is provided by
//! the runner as method arguments.
//!
//! # Design Principle
//!
//! State machines emit `Action::ExecuteTransactions` and receive
//! `ProtocolEvent::ExecutionBatchCompleted`. The runner owns the storage
//! and executor, calling the executor methods to handle these actions.
//!
//! **IMPORTANT**: The executor is READ-ONLY. It does NOT commit state changes
//! to storage. `DatabaseUpdates` from execution are cached by the state machine
//! and applied when a `TransactionCertificate` is included in a committed block.
//! This ensures all validators agree on the state before it's persisted.
//!
//! ```text
//! State Machine → Action::ExecuteTransactions { ... }
//!      ↓
//! Runner (owns storage + executor)
//!      ↓
//!      → executor.execute_single_shard(&storage, &transactions)  // READ-ONLY
//!      ↓
//! Runner → ProtocolEvent::ExecutionBatchCompleted { results, tx_outcomes }
//!      ↓
//! ... voting, certificate creation, block inclusion ...
//!      ↓
//! Block commit applies DatabaseUpdates from execution cache
//! ```

use crate::error::ExecutionError;
use crate::execution::{
    build_ledger_receipt, build_local_execution, extract_database_updates, is_committed,
    ProvisionedSnapshot,
};
use crate::genesis::{GenesisBuilder, GenesisConfig, GenesisError};
use crate::result::{ExecutionOutput, SingleTxResult};
use hyperscale_storage::{CommittableSubstateDatabase, SubstateDatabase, SubstateStore};
use hyperscale_types::{
    DatabaseUpdates, Hash, NodeId, RoutableTransaction, StateEntry, StateProvision,
};
use radix_common::network::NetworkDefinition;
use radix_engine::transaction::{execute_transaction, ExecutionConfig, TransactionReceipt};
use radix_engine::vm::DefaultVmModules;
use radix_transactions::validation::TransactionValidator;
use std::sync::Arc;
use std::time::Instant;
use tracing::{instrument, Level};

/// Fetch state entries for the given nodes from storage at a specific block height (= JVT version).
///
/// Reads substates at the given `block_height` using historical JVT traversal
/// and the leaf association table. Both data and proofs must come from the same
/// version to pass verification against the block header's `state_root`.
///
/// Returns `None` if the requested version is unavailable (GC'd or not yet
/// committed). Returns `Some(entries)` on success with pre-computed storage
/// keys for efficient cross-shard provisioning.
pub fn fetch_state_entries<S: SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    block_height: u64,
) -> Option<Vec<StateEntry>> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut entries = Vec::new();

    for node in nodes {
        // Compute the db_node_key once per node (expensive hash computation)
        let radix_node_id = radix_common::types::NodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        let substates = storage.list_substates_for_node_at_height(node, block_height)?;

        for (partition_num, db_sort_key, value) in substates {
            // Build storage key: db_node_key || partition_num || sort_key
            let mut storage_key = Vec::with_capacity(db_node_key.len() + 1 + db_sort_key.0.len());
            storage_key.extend_from_slice(&db_node_key);
            storage_key.push(partition_num);
            storage_key.extend_from_slice(&db_sort_key.0);

            entries.push(StateEntry::new(storage_key, Some(value)));
        }
    }

    Some(entries)
}

/// Fetch state entries speculatively before block commit.
///
/// Reads substates at `parent_height` (which is committed and passes version
/// guards), then overlays writes from `merged_updates` (certificate writes
/// included in the proposer's block). This allows provision generation to
/// start before the block commits.
///
/// Returns `None` if the parent height is unavailable. Returns `Some(entries)`
/// on success, reflecting the post-certificate state that will exist once the
/// block commits.
pub fn fetch_state_entries_speculative<S: SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    parent_height: u64,
    merged_updates: &DatabaseUpdates,
) -> Option<Vec<StateEntry>> {
    use radix_common::prelude::DatabaseUpdate;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    use radix_substate_store_interface::interface::PartitionDatabaseUpdates;

    let mut entries = Vec::new();

    for node in nodes {
        let radix_node_id = radix_common::types::NodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        // Read substates at parent_height (committed, passes version guard)
        let base_substates = storage.list_substates_for_node_at_height(node, parent_height)?;

        // Check if merged_updates has writes for this node
        let node_updates = merged_updates.node_updates.get(&db_node_key);

        if let Some(node_updates) = node_updates {
            // Build a map of (partition_num, sort_key) → value from base, then overlay
            let mut substate_map: std::collections::BTreeMap<(u8, Vec<u8>), Vec<u8>> =
                std::collections::BTreeMap::new();

            for (partition_num, db_sort_key, value) in &base_substates {
                substate_map.insert((*partition_num, db_sort_key.0.clone()), value.clone());
            }

            // Apply certificate writes on top
            for (&partition_num, partition_updates) in &node_updates.partition_updates {
                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let map_key = (partition_num, sort_key.0.clone());
                            match update {
                                DatabaseUpdate::Set(value) => {
                                    substate_map.insert(map_key, value.clone());
                                }
                                DatabaseUpdate::Delete => {
                                    substate_map.remove(&map_key);
                                }
                            }
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        // Remove all existing entries for this partition
                        substate_map.retain(|(p, _), _| *p != partition_num);
                        // Insert new values
                        for (sort_key, value) in new_substate_values {
                            substate_map.insert((partition_num, sort_key.0.clone()), value.clone());
                        }
                    }
                }
            }

            // Convert back to StateEntry list
            for ((partition_num, sort_key_bytes), value) in substate_map {
                let mut storage_key =
                    Vec::with_capacity(db_node_key.len() + 1 + sort_key_bytes.len());
                storage_key.extend_from_slice(&db_node_key);
                storage_key.push(partition_num);
                storage_key.extend_from_slice(&sort_key_bytes);
                entries.push(StateEntry::new(storage_key, Some(value)));
            }
        } else {
            // No updates for this node — use base substates directly
            for (partition_num, db_sort_key, value) in base_substates {
                let mut storage_key =
                    Vec::with_capacity(db_node_key.len() + 1 + db_sort_key.0.len());
                storage_key.extend_from_slice(&db_node_key);
                storage_key.push(partition_num);
                storage_key.extend_from_slice(&db_sort_key.0);
                entries.push(StateEntry::new(storage_key, Some(value)));
            }
        }
    }

    Some(entries)
}

/// Shared executor caches to avoid rebuilding on clone.
///
/// These are wrapped in Arc so that cloning the executor is cheap.
struct ExecutorCaches {
    /// Cached VM modules to avoid recreating per transaction
    vm_modules: DefaultVmModules,
    /// Cached execution config
    exec_config: ExecutionConfig,
    /// Cached transaction validator to avoid recreating per transaction
    validator: TransactionValidator,
}

/// Synchronous Radix Engine executor for deterministic simulation.
///
/// This executor does NOT own storage. Instead, storage is passed to each
/// method by the runner. This follows the design principle that state machines
/// should be pure and I/O should be delegated to runners.
///
/// # Usage
///
/// ```ignore
/// // Runner owns storage
/// let storage = Arc::new(SimStorage::new());
///
/// // Create executor (no storage parameter)
/// let executor = RadixExecutor::new(network);
///
/// // Run genesis (mutates storage)
/// executor.run_genesis(&storage)?;
///
/// // Execute transactions (reads/writes storage)
/// let output = executor.execute_single_shard(&storage, &transactions)?;
/// ```
///
/// # Simulation vs Production
///
/// - **Simulation**: Calls executor methods inline (synchronous, deterministic)
/// - **Production**: Spawns executor methods on rayon thread pool (async callbacks)
///
/// # Cloning
///
/// Cloning the executor is cheap - it only increments reference counts for
/// the shared caches (VM modules, execution config, validator).
pub struct RadixExecutor {
    network: NetworkDefinition,
    /// Shared caches wrapped in Arc for cheap cloning
    caches: Arc<ExecutorCaches>,
}

impl RadixExecutor {
    /// Create a new executor for the given network.
    ///
    /// The executor does not own storage - storage is passed to each method.
    /// VM modules and execution config are cached to avoid per-transaction overhead.
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

    /// Run genesis bootstrapping on the given storage.
    ///
    /// This initializes the Radix Engine state with system packages, faucet, etc.
    /// Should be called once per simulation before any transactions.
    pub fn run_genesis<S: SubstateDatabase + CommittableSubstateDatabase>(
        &self,
        storage: &mut S,
    ) -> Result<(), GenesisError> {
        GenesisBuilder::new(self.network.clone()).build(storage)?;
        Ok(())
    }

    /// Run genesis with custom configuration.
    pub fn run_genesis_with_config<S: SubstateDatabase + CommittableSubstateDatabase>(
        &self,
        storage: &mut S,
        config: GenesisConfig,
    ) -> Result<(), GenesisError> {
        GenesisBuilder::new(self.network.clone())
            .with_config(config)
            .build(storage)?;
        Ok(())
    }

    /// Execute single-shard transactions (READ-ONLY).
    ///
    /// Optimized path for transactions that only touch local shard state.
    /// Each transaction is executed against a snapshot of the current state.
    ///
    /// **IMPORTANT**: This method does NOT commit state changes. The writes
    /// are returned in the `ExecutionOutput` and should be committed later
    /// when the `TransactionCertificate` is included in a committed block.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        tx_count = transactions.len(),
        latency_us = tracing::field::Empty,
    ))]
    pub fn execute_single_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Result<ExecutionOutput, ExecutionError> {
        let start = Instant::now();
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            let result = self.execute_one(storage, tx.as_ref())?;
            results.push(result);
        }

        tracing::Span::current().record("latency_us", start.elapsed().as_micros() as u64);
        Ok(ExecutionOutput::new(results))
    }

    /// Execute cross-shard transactions with provisions (READ-ONLY).
    ///
    /// Layers provisions on top of local storage and executes transactions.
    /// Provisions contain pre-computed storage keys from other shards.
    ///
    /// **IMPORTANT**: This method does NOT commit state changes. The writes
    /// are returned in the `ExecutionOutput` and should be committed later
    /// when the `TransactionCertificate` is included in a committed block.
    ///
    /// # Performance
    ///
    /// Uses `ProvisionedSnapshot` with pre-computed storage keys for O(log n)
    /// lookups. The sending shard computes storage keys once via
    /// `fetch_db_state_entries()`, avoiding expensive hash computations here.
    #[instrument(level = Level::DEBUG, skip_all, fields(
        tx_count = transactions.len(),
        provision_count = provisions.len(),
        latency_us = tracing::field::Empty,
    ))]
    pub fn execute_cross_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
    ) -> Result<ExecutionOutput, ExecutionError> {
        let start = Instant::now();

        let mut results = Vec::with_capacity(transactions.len());

        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();

        // Create provisioned snapshot from pre-computed storage keys.
        let entry_slices: Vec<&[StateEntry]> =
            provisions.iter().map(|p| p.entries.as_slice()).collect();
        let provisioned = ProvisionedSnapshot::from_provisions(&snapshot, &entry_slices);

        for tx in transactions {
            // Execute using cached VM modules and config
            let validated = tx
                .get_or_validate(&self.caches.validator)
                .ok_or_else(|| ExecutionError::Preparation("Validation failed".to_string()))?;
            let executable = validated.clone().create_executable();
            let receipt = provisioned.execute(
                &executable,
                &self.caches.vm_modules,
                &self.caches.exec_config,
            );

            let result = self.receipt_to_result(tx.hash(), &receipt);

            // NO COMMIT HERE - DatabaseUpdates are cached by the state machine
            // and applied when the TransactionCertificate is included in a block.

            results.push(result);
        }

        tracing::Span::current().record("latency_us", start.elapsed().as_micros() as u64);
        Ok(ExecutionOutput::new(results))
    }

    /// Execute a single transaction (READ-ONLY).
    ///
    /// Executes against a snapshot and returns the result with collected writes.
    /// Does NOT commit to storage - that happens later during certificate persistence.
    fn execute_one<S: SubstateStore>(
        &self,
        storage: &S,
        tx: &RoutableTransaction,
    ) -> Result<SingleTxResult, ExecutionError> {
        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();

        // Get or create validated transaction (cached on RoutableTransaction)
        // This avoids re-validating signatures if already validated at RPC submission
        let validated = tx
            .get_or_validate(&self.caches.validator)
            .ok_or_else(|| ExecutionError::Preparation("Validation failed".to_string()))?;
        let executable = validated.clone().create_executable();

        // Use cached vm_modules and exec_config
        let receipt = execute_transaction(
            &snapshot,
            &self.caches.vm_modules,
            &self.caches.exec_config,
            &executable,
        );

        let result = self.receipt_to_result(tx.hash(), &receipt);

        // NO COMMIT HERE - DatabaseUpdates are cached by the state machine
        // and applied when the TransactionCertificate is included in a block.

        Ok(result)
    }

    /// Convert a receipt to a result.
    fn receipt_to_result(&self, tx_hash: Hash, receipt: &TransactionReceipt) -> SingleTxResult {
        let success = is_committed(receipt);

        if success {
            let database_updates = extract_database_updates(receipt);
            let ledger_receipt = build_ledger_receipt(receipt);
            let local_execution = build_local_execution(receipt);
            let receipt_hash = ledger_receipt.receipt_hash();
            SingleTxResult::success(
                tx_hash,
                receipt_hash,
                ledger_receipt,
                local_execution,
                database_updates,
            )
        } else {
            let error = format!("{:?}", receipt.result);
            SingleTxResult::failure(tx_hash, error)
        }
    }

    /// Fetch state entries for the given nodes from storage at a specific block height (= JVT version).
    ///
    /// Reads substates at the given `block_height` using historical JVT traversal.
    /// Both data and proofs must come from the same version.
    /// Returns `None` if the version is unavailable (GC'd or not yet committed).
    pub fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: u64,
    ) -> Option<Vec<StateEntry>> {
        fetch_state_entries(storage, nodes, block_height)
    }

    /// Get reference to the network definition.
    pub fn network(&self) -> &NetworkDefinition {
        &self.network
    }
}

impl Clone for RadixExecutor {
    fn clone(&self) -> Self {
        // Cheap clone: just increment Arc reference counts for shared caches
        Self {
            network: self.network.clone(),
            caches: Arc::clone(&self.caches),
        }
    }
}
