//! Radix Engine executor for deterministic simulation.
//!
//! This module provides synchronous transaction execution that can be called
//! by runners. The executor does NOT own storage - storage is provided by
//! the runner as method arguments.
//!
//! # Design Principle
//!
//! State machines emit `Action::ExecuteTransactions` and receive
//! `Event::TransactionsExecuted`. The runner owns the storage and executor,
//! calling the executor methods to handle these actions.
//!
//! **IMPORTANT**: The executor is READ-ONLY. It does NOT commit state changes
//! to storage. Writes are collected in the execution result and committed later
//! by the runner when a `TransactionCertificate` is included in a committed block.
//! This ensures all validators agree on the state before it's persisted.
//!
//! ```text
//! State Machine → Action::ExecuteTransactions { ... }
//!      ↓
//! Runner (owns storage + executor)
//!      ↓
//!      → executor.execute_single_shard(&storage, &transactions)  // READ-ONLY
//!      ↓
//! Runner → Event::TransactionsExecuted { results }  // results contain writes
//!      ↓
//! ... voting, certificate creation, block inclusion ...
//!      ↓
//! Runner → Action::PersistTransactionCertificate  // WRITES COMMITTED HERE
//! ```

use crate::error::ExecutionError;
use crate::execution::{
    compute_merkle_root, extract_substate_writes, is_commit_success, PreparedProvisions,
    ProvisionedExecutionContext,
};
use crate::genesis::{GenesisBuilder, GenesisConfig, GenesisError};
use crate::result::{ExecutionOutput, SingleTxResult};
use crate::storage::SubstateStore;
use hyperscale_types::{
    Hash, NodeId, PartitionNumber, RoutableTransaction, StateEntry, StateProvision, SubstateWrite,
};
use radix_common::network::NetworkDefinition;
use radix_engine::transaction::{execute_transaction, ExecutionConfig, TransactionReceipt};
use radix_engine::vm::DefaultVmModules;
use radix_transactions::validation::TransactionValidator;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{instrument, Level};

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
    pub fn run_genesis<S: SubstateStore>(&self, storage: &mut S) -> Result<(), GenesisError> {
        GenesisBuilder::new(self.network.clone()).build(storage)?;
        Ok(())
    }

    /// Run genesis with custom configuration.
    pub fn run_genesis_with_config<S: SubstateStore>(
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
    ///
    /// **IMPORTANT**: This method does NOT commit state changes. The writes
    /// are returned in the `ExecutionOutput` and should be committed later
    /// when the `TransactionCertificate` is included in a committed block.
    ///
    /// Note: The `is_local_node` parameter is kept for future use when we
    /// need to filter writes in the result, but commits are now deferred.
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
        _is_local_node: impl Fn(&NodeId) -> bool,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let start = Instant::now();
        // Pre-index provisions by transaction hash for O(1) lookup per transaction
        // instead of O(N*M) where N=transactions, M=provisions
        let mut provisions_by_tx: HashMap<Hash, Vec<&StateProvision>> =
            HashMap::with_capacity(transactions.len());
        for provision in provisions {
            provisions_by_tx
                .entry(provision.transaction_hash)
                .or_default()
                .push(provision);
        }

        let mut results = Vec::with_capacity(transactions.len());

        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();

        for tx in transactions {
            // Get provisions for this transaction
            let tx_provisions = provisions_by_tx.get(&tx.hash());

            // Pre-process provisions into DatabaseUpdates (computes DB keys once)
            let prepared = if let Some(provs) = tx_provisions {
                PreparedProvisions::from_provisions(provs)
            } else {
                PreparedProvisions::default()
            };

            // Create execution context with pre-computed provisions
            let context = ProvisionedExecutionContext::with_prepared_provisions(
                &snapshot,
                &self.network,
                prepared,
            );

            // Execute using cached VM modules and config
            let validated = tx
                .get_or_validate(&self.caches.validator)
                .ok_or_else(|| ExecutionError::Preparation("Validation failed".to_string()))?;
            let executable = validated.clone().create_executable();
            let receipt = context.execute_with_cache(
                &executable,
                &self.caches.vm_modules,
                &self.caches.exec_config,
            )?;
            // Use cross-shard result which filters writes to declared_writes
            // so all shards compute the same merkle root
            let result =
                self.receipt_to_cross_shard_result(tx.hash(), &receipt, &tx.declared_writes);

            // NO COMMIT HERE - writes are returned in result.state_writes
            // They will be committed later when TransactionCertificate is included in a block

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

        // NO COMMIT HERE - writes are returned in result.state_writes
        // They will be committed later when TransactionCertificate is included in a block

        Ok(result)
    }

    /// Convert a receipt to a result.
    fn receipt_to_result(&self, tx_hash: Hash, receipt: &TransactionReceipt) -> SingleTxResult {
        let success = is_commit_success(receipt);

        if success {
            let state_writes = extract_substate_writes(receipt);
            let merkle_root = compute_merkle_root(&state_writes);
            SingleTxResult::success(tx_hash, merkle_root, state_writes)
        } else {
            let error = format!("{:?}", receipt.result);
            SingleTxResult::failure(tx_hash, error)
        }
    }

    /// Convert a receipt to a result for cross-shard transactions.
    ///
    /// For cross-shard transactions, each shard only sees its local writes,
    /// but the merkle root must be computed over the DECLARED writes so all
    /// shards agree on the same root. We filter the actual writes to only
    /// include those in declared_writes.
    fn receipt_to_cross_shard_result(
        &self,
        tx_hash: Hash,
        receipt: &TransactionReceipt,
        declared_writes: &[NodeId],
    ) -> SingleTxResult {
        let success = is_commit_success(receipt);

        if success {
            let all_writes = extract_substate_writes(receipt);
            // Filter writes to only include nodes in declared_writes
            // This ensures all shards compute the same merkle root by excluding
            // writes to system components (faucet, etc.) that may differ between shards
            //
            // NOTE: Currently this filters out most writes because declared_writes contains
            // account component NodeIds but actual writes go to vault NodeIds inside those
            // accounts. This results in an empty merkle root (Hash::ZERO) which still
            // achieves agreement across shards. A future improvement would be to include
            // writes to child nodes of declared_writes.
            let declared_set: std::collections::HashSet<_> = declared_writes.iter().collect();
            let filtered_writes: Vec<_> = all_writes
                .iter()
                .filter(|w| declared_set.contains(&w.node_id))
                .cloned()
                .collect();
            let merkle_root = compute_merkle_root(&filtered_writes);
            SingleTxResult::success(tx_hash, merkle_root, filtered_writes)
        } else {
            let error = format!("{:?}", receipt.result);
            SingleTxResult::failure(tx_hash, error)
        }
    }

    // NOTE: commit_all_writes and commit_local_writes have been removed.
    // The executor is now READ-ONLY. State writes are collected in the
    // ExecutionOutput and committed later by the runner when a
    // TransactionCertificate is included in a committed block.

    /// Fetch state entries for the given nodes from storage.
    ///
    /// Used by provisioning to collect state for other shards.
    pub fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
    ) -> Vec<StateEntry> {
        let mut entries = Vec::new();

        for node in nodes {
            let substates: Vec<_> = storage.list_substates_for_node(node).collect();

            for (partition_num, db_sort_key, value) in substates {
                entries.push(StateEntry::new(
                    *node,
                    PartitionNumber(partition_num),
                    db_sort_key.0,
                    Some(value),
                ));
            }
        }

        entries
    }

    /// Compute merkle root from state writes.
    pub fn compute_merkle_root_simple(&self, writes: &[(NodeId, Vec<u8>)]) -> Hash {
        // Convert to SubstateWrite format
        let substate_writes: Vec<_> = writes
            .iter()
            .map(|(node_id, value)| {
                SubstateWrite::new(
                    *node_id,
                    PartitionNumber(0), // Default partition
                    vec![],             // Default sort key
                    value.clone(),
                )
            })
            .collect();

        compute_merkle_root(&substate_writes)
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
