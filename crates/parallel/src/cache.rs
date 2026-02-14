//! Simulation cache for expensive computations shared across nodes.
//!
//! When multiple nodes in a shard perform identical operations (signature
//! verification, transaction execution), the result is computed once and
//! shared. This dramatically improves simulation performance at scale.

use dashmap::DashMap;
use hyperscale_engine::RadixExecutor;
use hyperscale_storage::{CommittableSubstateDatabase, RADIX_PREFIX};
use hyperscale_storage_memory::SimStorage;
use hyperscale_types::{
    verify_bls12381_v1, zero_bls_signature, Bls12381G1PublicKey, Bls12381G2Signature, Hash, NodeId,
    RoutableTransaction, StateEntry,
};
use radix_common::network::NetworkDefinition;
use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
use std::sync::{Arc, Mutex};
use tracing::warn;

/// Cache for expensive computations shared across nodes.
///
/// When multiple nodes in a shard perform identical operations (signature
/// verification, transaction execution), the result is computed once and
/// shared. This dramatically improves simulation performance at scale.
///
/// For transaction execution, each shard has one executor and one reference
/// storage. The first node to execute a block uses this shared executor,
/// and results are cached for other nodes in the same shard.
pub struct SimulationCache {
    /// Cache of aggregated signature verifications: key -> valid
    aggregated_sigs: DashMap<Hash, bool>,
    /// Cache of block execution results: (shard_id, block_hash) -> results
    /// Each shard executes independently, but validators within a shard share results.
    block_executions: DashMap<(u64, Hash), Vec<hyperscale_types::ExecutionResult>>,
    /// Cache of cross-shard transaction executions: (shard_id, tx_hash) -> result
    cross_shard_executions: DashMap<(u64, Hash), hyperscale_types::ExecutionResult>,
    /// Per-shard executor (one executor per shard).
    /// Protected by mutex since execution mutates internal Radix state.
    shard_executors: DashMap<u64, Arc<Mutex<RadixExecutor>>>,
    /// Per-shard reference storage for execution.
    /// This is the "canonical" storage used for execution reads.
    shard_storage: DashMap<u64, Arc<Mutex<SimStorage>>>,
}

impl std::fmt::Debug for SimulationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulationCache")
            .field("aggregated_sigs", &self.aggregated_sigs.len())
            .field("block_executions", &self.block_executions.len())
            .field("cross_shard_executions", &self.cross_shard_executions.len())
            .field("shard_executors", &self.shard_executors.len())
            .field("shard_storage", &self.shard_storage.len())
            .finish()
    }
}

impl Default for SimulationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulationCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            aggregated_sigs: DashMap::new(),
            block_executions: DashMap::new(),
            cross_shard_executions: DashMap::new(),
            shard_executors: DashMap::new(),
            shard_storage: DashMap::new(),
        }
    }

    /// Initialize a shard's executor and storage.
    ///
    /// Must be called before any execution for this shard.
    /// Runs Radix Engine genesis on the storage.
    pub fn init_shard(&self, shard_id: u64) {
        self.init_shard_with_balances(shard_id, vec![])
    }

    /// Initialize a shard's executor and storage with funded accounts.
    ///
    /// Must be called before any execution for this shard.
    /// Runs Radix Engine genesis on the storage with the specified XRD balances.
    /// Only accounts relevant to this shard should be passed.
    pub fn init_shard_with_balances(
        &self,
        shard_id: u64,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    ) {
        use hyperscale_engine::GenesisConfig;

        if self.shard_executors.contains_key(&shard_id) {
            return; // Already initialized
        }

        let executor = RadixExecutor::new(NetworkDefinition::simulator());
        let mut storage = SimStorage::new();

        // Run genesis with balances
        let config = GenesisConfig {
            xrd_balances: balances,
            ..GenesisConfig::test_default()
        };

        if let Err(e) = executor.run_genesis_with_config(&mut storage, config) {
            warn!(shard_id, "Radix Engine genesis failed: {:?}", e);
            // Continue anyway - tests may not need full Radix state
        }

        self.shard_executors
            .insert(shard_id, Arc::new(Mutex::new(executor)));
        self.shard_storage
            .insert(shard_id, Arc::new(Mutex::new(storage)));
    }

    /// Commit writes to a shard's reference storage.
    ///
    /// Called when a TransactionCertificate is persisted to apply state changes.
    pub fn commit_writes(&self, shard_id: u64, writes: &[hyperscale_types::SubstateWrite]) {
        if let Some(storage_ref) = self.shard_storage.get(&shard_id) {
            if let Ok(mut storage) = storage_ref.lock() {
                let updates = hyperscale_storage::substate_writes_to_database_updates(writes);
                storage.commit(&updates);
            }
        }
    }

    /// Fetch state entries from a shard's reference storage.
    ///
    /// This is used for cross-shard provisioning - fetching state that needs
    /// to be sent to other shards. Returns `StateEntry` with pre-computed
    /// storage keys for efficient cross-shard execution.
    pub fn fetch_state_entries(&self, shard_id: u64, nodes: &[NodeId]) -> Vec<StateEntry> {
        use hyperscale_storage::SubstateStore;

        let storage_ref = match self.shard_storage.get(&shard_id) {
            Some(s) => s,
            None => {
                warn!(shard_id, "No storage for shard in fetch_state_entries");
                return Vec::new();
            }
        };

        let storage = match storage_ref.lock() {
            Ok(s) => s,
            Err(_) => {
                warn!(shard_id, "Failed to lock storage in fetch_state_entries");
                return Vec::new();
            }
        };

        let mut entries = Vec::new();

        for node_id in nodes {
            // Compute the db_node_key once per node (expensive hash computation)
            let radix_node_id = radix_common::types::NodeId(node_id.0);
            let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

            for (partition_num, db_sort_key, value) in storage.list_substates_for_node(node_id) {
                // Build full storage key
                let mut storage_key = Vec::with_capacity(
                    RADIX_PREFIX.len() + db_node_key.len() + 1 + db_sort_key.0.len(),
                );
                storage_key.extend_from_slice(RADIX_PREFIX);
                storage_key.extend_from_slice(&db_node_key);
                storage_key.push(partition_num);
                storage_key.extend_from_slice(&db_sort_key.0);

                entries.push(StateEntry::new(storage_key, Some(value)));
            }
        }

        entries
    }

    /// Compute a cache key from verification inputs.
    fn sig_cache_key(
        signing_message: &[u8],
        signature: &Bls12381G2Signature,
        signer_keys: &[Bls12381G1PublicKey],
    ) -> Hash {
        use std::hash::{Hash as StdHash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        signing_message.hash(&mut hasher);
        signature.0.hash(&mut hasher);
        for pk in signer_keys {
            pk.to_vec().hash(&mut hasher);
        }
        let h = hasher.finish();
        Hash::from_bytes(&{
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&h.to_le_bytes());
            bytes
        })
    }

    /// Verify an aggregated signature, using cache if available.
    pub fn verify_aggregated(
        &self,
        signer_keys: &[Bls12381G1PublicKey],
        message: &[u8],
        signature: &Bls12381G2Signature,
    ) -> bool {
        let key = Self::sig_cache_key(message, signature, signer_keys);

        // Fast path: check cache without taking entry lock
        if let Some(valid) = self.aggregated_sigs.get(&key) {
            return *valid;
        }

        // Slow path: use entry API to ensure only one thread computes
        // Note: or_insert_with holds write lock during computation, preventing TOCTOU races
        *self.aggregated_sigs.entry(key).or_insert_with(|| {
            if signer_keys.is_empty() {
                *signature == zero_bls_signature()
            } else {
                // Skip PK validation - keys come from trusted topology
                match Bls12381G1PublicKey::aggregate(signer_keys, false) {
                    Ok(aggregated_pk) => verify_bls12381_v1(message, &aggregated_pk, signature),
                    Err(_) => false,
                }
            }
        })
    }

    /// Execute transactions for a block using the shared Radix executor.
    ///
    /// Results are cached per (shard_id, block_hash) so each shard executes
    /// independently but validators within a shard share results.
    pub fn execute_block(
        &self,
        shard_id: u64,
        block_hash: Hash,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<hyperscale_types::ExecutionResult> {
        let key = (shard_id, block_hash);

        // Fast path: check cache without taking entry lock
        if let Some(results) = self.block_executions.get(&key) {
            return results.clone();
        }

        // Slow path: use entry API to ensure only one thread executes
        // Note: or_insert_with holds write lock during execution, preventing TOCTOU races
        self.block_executions
            .entry(key)
            .or_insert_with(|| self.do_execute_block(shard_id, transactions))
            .clone()
    }

    /// Internal: perform block execution using Radix engine.
    fn do_execute_block(
        &self,
        shard_id: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<hyperscale_types::ExecutionResult> {
        let executor_ref = match self.shard_executors.get(&shard_id) {
            Some(e) => e,
            None => {
                warn!(shard_id, "No executor for shard, using mock results");
                return transactions
                    .iter()
                    .map(|tx| hyperscale_types::ExecutionResult {
                        transaction_hash: tx.hash(),
                        success: true,
                        state_root: Hash::ZERO,
                        writes: vec![],
                        error: None,
                    })
                    .collect();
            }
        };

        let storage_ref = match self.shard_storage.get(&shard_id) {
            Some(s) => s,
            None => {
                warn!(shard_id, "No storage for shard, using mock results");
                return transactions
                    .iter()
                    .map(|tx| hyperscale_types::ExecutionResult {
                        transaction_hash: tx.hash(),
                        success: true,
                        state_root: Hash::ZERO,
                        writes: vec![],
                        error: None,
                    })
                    .collect();
            }
        };

        // Lock executor and storage for execution
        let executor = executor_ref.lock().unwrap();
        let storage = storage_ref.lock().unwrap();

        match executor.execute_single_shard(&*storage, transactions) {
            Ok(output) => output
                .results()
                .iter()
                .map(|r| hyperscale_types::ExecutionResult {
                    transaction_hash: r.tx_hash,
                    success: r.success,
                    state_root: r.outputs_merkle_root,
                    writes: r.state_writes.clone(),
                    error: r.error.clone(),
                })
                .collect(),
            Err(e) => {
                warn!(shard_id, "Execution failed: {:?}", e);
                transactions
                    .iter()
                    .map(|tx| hyperscale_types::ExecutionResult {
                        transaction_hash: tx.hash(),
                        success: false,
                        state_root: Hash::ZERO,
                        writes: vec![],
                        error: Some(format!("{:?}", e)),
                    })
                    .collect()
            }
        }
    }

    /// Execute a cross-shard transaction using the shared Radix executor.
    pub fn execute_cross_shard(
        &self,
        shard_id: u64,
        tx_hash: Hash,
        transaction: &Arc<RoutableTransaction>,
        provisions: &[hyperscale_types::StateProvision],
        is_local_node: impl Fn(&NodeId) -> bool,
    ) -> hyperscale_types::ExecutionResult {
        let key = (shard_id, tx_hash);

        // Fast path: check cache without taking entry lock
        if let Some(result) = self.cross_shard_executions.get(&key) {
            return result.clone();
        }

        // Slow path: use entry API to ensure only one thread executes
        // Note: or_insert_with holds write lock during execution, preventing TOCTOU races
        self.cross_shard_executions
            .entry(key)
            .or_insert_with(|| {
                self.do_execute_cross_shard(shard_id, transaction, provisions, &is_local_node)
            })
            .clone()
    }

    /// Internal: perform cross-shard execution using Radix engine.
    fn do_execute_cross_shard(
        &self,
        shard_id: u64,
        transaction: &Arc<RoutableTransaction>,
        provisions: &[hyperscale_types::StateProvision],
        is_local_node: &impl Fn(&NodeId) -> bool,
    ) -> hyperscale_types::ExecutionResult {
        let executor_ref = match self.shard_executors.get(&shard_id) {
            Some(e) => e,
            None => {
                warn!(shard_id, "No executor for shard");
                return hyperscale_types::ExecutionResult {
                    transaction_hash: transaction.hash(),
                    success: true,
                    state_root: Hash::ZERO,
                    writes: vec![],
                    error: None,
                };
            }
        };

        let storage_ref = match self.shard_storage.get(&shard_id) {
            Some(s) => s,
            None => {
                warn!(shard_id, "No storage for shard");
                return hyperscale_types::ExecutionResult {
                    transaction_hash: transaction.hash(),
                    success: true,
                    state_root: Hash::ZERO,
                    writes: vec![],
                    error: None,
                };
            }
        };

        let executor = executor_ref.lock().unwrap();
        let storage = storage_ref.lock().unwrap();

        match executor.execute_cross_shard(
            &*storage,
            std::slice::from_ref(transaction),
            provisions,
            is_local_node,
        ) {
            Ok(output) => {
                if let Some(r) = output.results().first() {
                    hyperscale_types::ExecutionResult {
                        transaction_hash: r.tx_hash,
                        success: r.success,
                        state_root: r.outputs_merkle_root,
                        writes: r.state_writes.clone(),
                        error: r.error.clone(),
                    }
                } else {
                    hyperscale_types::ExecutionResult {
                        transaction_hash: transaction.hash(),
                        success: false,
                        state_root: Hash::ZERO,
                        writes: vec![],
                        error: Some("No execution result".to_string()),
                    }
                }
            }
            Err(e) => {
                warn!(shard_id, "Cross-shard execution failed: {:?}", e);
                hyperscale_types::ExecutionResult {
                    transaction_hash: transaction.hash(),
                    success: false,
                    state_root: Hash::ZERO,
                    writes: vec![],
                    error: Some(format!("{:?}", e)),
                }
            }
        }
    }
}
