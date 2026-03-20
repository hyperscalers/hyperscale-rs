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
//! Runner → ProtocolEvent::ExecutionBatchCompleted { votes, results }
//!      ↓
//! ... voting, certificate creation, block inclusion ...
//!      ↓
//! Block commit applies DatabaseUpdates from execution cache
//! ```

use crate::adapter::RadixStorageAdapter;
use crate::error::ExecutionError;
use crate::execution::{
    build_ledger_receipt, build_local_execution, extract_database_updates, is_committed,
    ProvisionedSnapshot,
};
use crate::genesis::{GenesisBuilder, GenesisConfig, GenesisError};
use crate::result::{ExecutionOutput, SingleTxResult};
use hyperscale_core::ExecutionBackend;
use hyperscale_radix_config::RadixConfig;
use hyperscale_storage::{CommittableSubstateDatabase, SubstateDatabase, SubstateStore};
use hyperscale_types::{
    DatabaseUpdates, Hash, LedgerTransactionReceipt, NodeId, RoutableTransaction, StateEntry,
    StateProvision, TypeConfig,
};
use radix_common::network::NetworkDefinition;
use radix_engine::transaction::{execute_transaction, ExecutionConfig, TransactionReceipt};
use radix_engine::vm::DefaultVmModules;
use radix_transactions::validation::TransactionValidator;
use std::sync::Arc;
use std::time::Instant;
use tracing::{instrument, Level};

/// Fetch state entries for the given nodes from storage at a specific block height (= JMT version).
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
    block_height: u64,
) -> Option<Vec<StateEntry>> {
    use hyperscale_storage::RADIX_PREFIX;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut entries = Vec::new();

    for node in nodes {
        // Compute the db_node_key once per node (expensive hash computation)
        let radix_node_id = radix_common::types::NodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        let substates = storage.list_substates_for_node_at_height(node, block_height)?;

        for (partition_num, db_sort_key, value) in substates {
            // Build full storage key
            let mut storage_key =
                Vec::with_capacity(RADIX_PREFIX.len() + db_node_key.len() + 1 + db_sort_key.len());
            storage_key.extend_from_slice(RADIX_PREFIX);
            storage_key.extend_from_slice(&db_node_key);
            storage_key.push(partition_num);
            storage_key.extend_from_slice(&db_sort_key);

            entries.push(StateEntry::new(storage_key, Some(value)));
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
    fn execute_single_shard_inner<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Result<ExecutionOutput<RadixConfig>, ExecutionError> {
        let start = Instant::now();
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            let result = self.execute_one(storage, tx.as_ref())?;
            results.push(result);
        }

        tracing::Span::current().record("latency_us", start.elapsed().as_micros() as u64);
        Ok(ExecutionOutput::<RadixConfig>::new(results))
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
    fn execute_cross_shard_inner<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
    ) -> Result<ExecutionOutput<RadixConfig>, ExecutionError> {
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
        Ok(ExecutionOutput::<RadixConfig>::new(results))
    }

    /// Execute a single transaction (READ-ONLY).
    ///
    /// Executes against a snapshot and returns the result with collected writes.
    /// Does NOT commit to storage - that happens later during certificate persistence.
    fn execute_one<S: SubstateStore>(
        &self,
        storage: &S,
        tx: &RoutableTransaction,
    ) -> Result<SingleTxResult<RadixConfig>, ExecutionError> {
        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();
        let db = RadixStorageAdapter(&snapshot);

        // Get or create validated transaction (cached on RoutableTransaction)
        // This avoids re-validating signatures if already validated at RPC submission
        let validated = tx
            .get_or_validate(&self.caches.validator)
            .ok_or_else(|| ExecutionError::Preparation("Validation failed".to_string()))?;
        let executable = validated.clone().create_executable();

        // Use cached vm_modules and exec_config
        let receipt = execute_transaction(
            &db,
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
    fn receipt_to_result(
        &self,
        tx_hash: Hash,
        receipt: &TransactionReceipt,
    ) -> SingleTxResult<RadixConfig> {
        let success = is_committed(receipt);

        if success {
            let database_updates = extract_database_updates(receipt);
            let ledger_receipt = build_ledger_receipt(receipt);
            let local_execution = build_local_execution(receipt);
            let receipt_hash = ledger_receipt.receipt_hash();
            SingleTxResult::<RadixConfig> {
                tx_hash,
                success: true,
                receipt_hash,
                receipt: ledger_receipt,
                local_execution,
                state_update: database_updates,
                error: None,
            }
        } else {
            let error = format!("{:?}", receipt.result);
            SingleTxResult::failure(tx_hash, error)
        }
    }

    /// Fetch state entries for the given nodes from storage at a specific block height (= JMT version).
    ///
    /// Reads substates at the given `block_height` using historical JMT traversal.
    /// Both data and proofs must come from the same version.
    /// Returns `None` if the version is unavailable (GC'd or not yet committed).
    fn fetch_state_entries_inner<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: u64,
    ) -> Option<Vec<StateEntry>> {
        fetch_state_entries(storage, nodes, block_height)
    }

    /// Execute single-shard transactions (delegates to inner implementation).
    pub fn execute_single_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Result<ExecutionOutput<RadixConfig>, ExecutionError> {
        self.execute_single_shard_inner(storage, transactions)
    }

    /// Execute cross-shard transactions with provisions (delegates to inner implementation).
    pub fn execute_cross_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
    ) -> Result<ExecutionOutput<RadixConfig>, ExecutionError> {
        self.execute_cross_shard_inner(storage, transactions, provisions)
    }

    /// Fetch state entries (delegates to inner implementation).
    pub fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: u64,
    ) -> Option<Vec<StateEntry>> {
        self.fetch_state_entries_inner(storage, nodes, block_height)
    }

    /// Get reference to the network definition.
    pub fn network(&self) -> &NetworkDefinition {
        &self.network
    }
}

impl<C> ExecutionBackend<C> for RadixExecutor
where
    C: TypeConfig<
        Transaction = RoutableTransaction,
        ExecutionReceipt = LedgerTransactionReceipt,
        StateUpdate = DatabaseUpdates,
    >,
{
    type Error = ExecutionError;

    fn execute_single_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Result<ExecutionOutput<C>, Self::Error> {
        self.execute_single_shard_inner(storage, transactions)
            .map(into_config_output)
    }

    fn execute_cross_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
    ) -> Result<ExecutionOutput<C>, Self::Error> {
        self.execute_cross_shard_inner(storage, transactions, provisions)
            .map(into_config_output)
    }

    fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: u64,
    ) -> Option<Vec<StateEntry>> {
        self.fetch_state_entries_inner(storage, nodes, block_height)
    }
}

/// Convert `ExecutionOutput<RadixConfig>` to `ExecutionOutput<C>` for any
/// config whose associated types match the concrete Radix types.
///
/// This is a field-by-field move with no actual data transformation — the
/// associated types (`RoutableTransaction`, `LedgerTransactionReceipt`,
/// `DatabaseUpdates`) are identical on both sides.
fn into_config_output<C>(output: ExecutionOutput<RadixConfig>) -> ExecutionOutput<C>
where
    C: TypeConfig<
        Transaction = RoutableTransaction,
        ExecutionReceipt = LedgerTransactionReceipt,
        StateUpdate = DatabaseUpdates,
    >,
{
    ExecutionOutput::new(
        output
            .results
            .into_iter()
            .map(|r| SingleTxResult::<C> {
                tx_hash: r.tx_hash,
                success: r.success,
                receipt_hash: r.receipt_hash,
                receipt: r.receipt,
                local_execution: r.local_execution,
                state_update: r.state_update,
                error: r.error,
            })
            .collect(),
    )
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
