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
//! ```text
//! State Machine → Action::ExecuteTransactions { ... }
//!      ↓
//! Runner (owns storage + executor)
//!      ↓
//!      → executor.execute_single_shard(&storage, &transactions)
//!      ↓
//! Runner → Event::TransactionsExecuted { results }
//! ```

use crate::error::ExecutionError;
use crate::execution::{
    compute_merkle_root, extract_substate_writes, is_commit_success, ProvisionedExecutionContext,
};
use crate::genesis::{GenesisBuilder, GenesisConfig, GenesisError};
use crate::result::{ExecutionOutput, SingleTxResult};
use crate::storage::SubstateStore;
use hyperscale_types::{
    Hash, NodeId, PartitionNumber, RoutableTransaction, StateEntry, StateProvision, SubstateWrite,
};
use radix_common::network::NetworkDefinition;
use radix_engine::transaction::{execute_transaction, ExecutionConfig, TransactionReceipt};
use radix_engine::vm::VmModules;
use radix_substate_store_interface::interface::DatabaseUpdates;
use radix_transactions::validation::TransactionValidator;

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
pub struct RadixExecutor {
    network: NetworkDefinition,
}

impl RadixExecutor {
    /// Create a new executor for the given network.
    ///
    /// The executor does not own storage - storage is passed to each method.
    pub fn new(network: NetworkDefinition) -> Self {
        Self { network }
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

    /// Execute single-shard transactions.
    ///
    /// Optimized path for transactions that only touch local shard state.
    /// Each transaction is executed against the current state, and successful
    /// results are committed to storage.
    pub fn execute_single_shard<S: SubstateStore>(
        &self,
        storage: &mut S,
        transactions: &[RoutableTransaction],
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            let result = self.execute_one(storage, tx)?;
            results.push(result);
        }

        Ok(ExecutionOutput::new(results))
    }

    /// Execute cross-shard transactions with provisions.
    ///
    /// Layers provisions on top of local storage, executes, and commits
    /// only local shard state changes.
    pub fn execute_cross_shard<S: SubstateStore>(
        &self,
        storage: &mut S,
        transactions: &[RoutableTransaction],
        provisions: &[StateProvision],
        is_local_node: impl Fn(&NodeId) -> bool,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut results = Vec::with_capacity(transactions.len());

        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();

        for tx in transactions {
            // Create execution context with provisions
            let mut context =
                ProvisionedExecutionContext::new(snapshot.as_ref(), self.network.clone());
            for provision in provisions {
                // Only add provisions relevant to this transaction
                if provision.transaction_hash == tx.hash() {
                    context.add_provision(provision);
                }
            }

            // Execute
            let user_tx = tx.transaction();
            let receipt = context.execute_user_transaction(user_tx)?;
            // Use cross-shard result which filters writes to declared_writes
            // so all shards compute the same merkle root
            let result =
                self.receipt_to_cross_shard_result(tx.hash(), &receipt, &tx.declared_writes);

            // Commit local shard writes if successful
            if result.success {
                self.commit_local_writes(storage, &receipt, &is_local_node);
            }

            results.push(result);
        }

        Ok(ExecutionOutput::new(results))
    }

    /// Execute a single transaction.
    fn execute_one<S: SubstateStore>(
        &self,
        storage: &mut S,
        tx: &RoutableTransaction,
    ) -> Result<SingleTxResult, ExecutionError> {
        // Take a snapshot for isolated execution
        let snapshot = storage.snapshot();

        // Validate and execute
        let validator = TransactionValidator::new_with_latest_config(&self.network);
        let user_tx = tx.transaction();

        let validated = user_tx
            .prepare_and_validate(&validator)
            .map_err(|e| ExecutionError::Preparation(format!("Validation failed: {:?}", e)))?;
        let executable = validated.create_executable();

        let vm_modules = VmModules::default();
        let exec_config = ExecutionConfig::for_notarized_transaction(self.network.clone());

        let receipt =
            execute_transaction(snapshot.as_ref(), &vm_modules, &exec_config, &executable);

        let result = self.receipt_to_result(tx.hash(), &receipt);

        // Commit to live storage if successful
        if result.success {
            self.commit_all_writes(storage, &receipt);
        }

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
            let declared_set: std::collections::HashSet<_> = declared_writes.iter().collect();
            let filtered_writes: Vec<_> = all_writes
                .into_iter()
                .filter(|w| declared_set.contains(&w.node_id))
                .collect();
            let merkle_root = compute_merkle_root(&filtered_writes);
            SingleTxResult::success(tx_hash, merkle_root, filtered_writes)
        } else {
            let error = format!("{:?}", receipt.result);
            SingleTxResult::failure(tx_hash, error)
        }
    }

    /// Commit all state writes to storage.
    fn commit_all_writes<S: SubstateStore>(&self, storage: &mut S, receipt: &TransactionReceipt) {
        use crate::execution::extract_state_updates;

        if let Some(updates) = extract_state_updates(receipt) {
            storage.commit(&updates);
        }
    }

    /// Commit only local shard writes to storage.
    fn commit_local_writes<S: SubstateStore>(
        &self,
        storage: &mut S,
        receipt: &TransactionReceipt,
        is_local_node: impl Fn(&NodeId) -> bool,
    ) {
        use crate::execution::extract_state_updates;

        let Some(updates) = extract_state_updates(receipt) else {
            return;
        };

        // Filter to local shard
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &updates.node_updates {
            if db_node_key.len() >= 50 {
                let mut node_id_bytes = [0u8; 30];
                node_id_bytes.copy_from_slice(&db_node_key[20..50]);
                let node_id = NodeId(node_id_bytes);

                if is_local_node(&node_id) {
                    filtered
                        .node_updates
                        .insert(db_node_key.clone(), node_updates.clone());
                }
            }
        }

        if !filtered.node_updates.is_empty() {
            storage.commit(&filtered);
        }
    }

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
        Self {
            network: self.network.clone(),
        }
    }
}
