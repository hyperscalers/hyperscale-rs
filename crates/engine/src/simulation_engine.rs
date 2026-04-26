//! Caching engine for simulation.
//!
//! [`SimulationEngine`] wraps [`RadixExecutor`] and deduplicates execution:
//! all validators in the same shard share a [`SimExecutionCache`], so the
//! first validator to execute a transaction computes the result and subsequent
//! validators retrieve it from the cache.

use crate::error::ExecutionError;
use crate::executor::Engine;
use crate::genesis::{GenesisConfig, GenesisError};
use crate::result::{ExecutionOutput, SingleTxResult};
use crate::RadixExecutor;
use dashmap::DashMap;
use hyperscale_storage::{CommittableSubstateDatabase, SubstateDatabase, SubstateStore};
use hyperscale_types::{
    BlockHeight, NodeId, RoutableTransaction, ShardGroupId, StateEntry, StateProvision, TxHash,
};
use radix_common::network::NetworkDefinition;
use std::sync::{Arc, OnceLock};

/// Shared execution cache — one per shard group in simulation.
///
/// Key: transaction hash.  Value: `OnceLock` ensuring compute-once semantics.
pub type SimExecutionCache = Arc<DashMap<TxHash, Arc<OnceLock<SingleTxResult>>>>;

/// Caching wrapper around [`RadixExecutor`] for simulation.
///
/// All clones share the same underlying cache (cheap `Arc` increment).
/// The cache is typically shared across all validators in the same shard.
pub struct SimulationEngine {
    inner: RadixExecutor,
    cache: SimExecutionCache,
}

impl SimulationEngine {
    /// Create a new simulation engine wrapping `inner` with a shared `cache`.
    #[must_use]
    pub fn new(inner: RadixExecutor, cache: SimExecutionCache) -> Self {
        Self { inner, cache }
    }

    /// Execute a single transaction, returning a cached result if available.
    fn execute_cached<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &Arc<RoutableTransaction>,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> SingleTxResult {
        let tx_hash = tx.hash();
        let lock = self
            .cache
            .entry(tx_hash)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();

        let result = lock.get_or_init(|| {
            // Cache miss — delegate to the real executor (single-tx batch).
            match self.inner.execute_single_shard(
                snapshot,
                std::slice::from_ref(tx),
                local_shard,
                num_shards,
            ) {
                Ok(output) => output
                    .results
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| SingleTxResult::failure(tx_hash, "No result returned")),
                Err(e) => SingleTxResult::failure(tx_hash, e.to_string()),
            }
        });

        result.clone()
    }

    /// Execute a single cross-shard transaction, returning a cached result if available.
    fn execute_cross_shard_cached<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &Arc<RoutableTransaction>,
        provisions: &[StateProvision],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> SingleTxResult {
        let tx_hash = tx.hash();
        let lock = self
            .cache
            .entry(tx_hash)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();

        let result = lock.get_or_init(|| {
            match self.inner.execute_cross_shard(
                snapshot,
                std::slice::from_ref(tx),
                provisions,
                local_shard,
                num_shards,
            ) {
                Ok(output) => output
                    .results
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| SingleTxResult::failure(tx_hash, "No result returned")),
                Err(e) => SingleTxResult::failure(tx_hash, e.to_string()),
            }
        });

        result.clone()
    }
}

impl Clone for SimulationEngine {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cache: Arc::clone(&self.cache),
        }
    }
}

impl Engine for SimulationEngine {
    fn execute_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut results = Vec::with_capacity(transactions.len());
        for tx in transactions {
            results.push(self.execute_cached(snapshot, tx, local_shard, num_shards));
        }
        Ok(ExecutionOutput::new(results))
    }

    fn execute_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> Result<ExecutionOutput, ExecutionError> {
        let mut results = Vec::with_capacity(transactions.len());
        for tx in transactions {
            results.push(self.execute_cross_shard_cached(
                snapshot,
                tx,
                provisions,
                local_shard,
                num_shards,
            ));
        }
        Ok(ExecutionOutput::new(results))
    }

    fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: BlockHeight,
    ) -> Option<Vec<StateEntry>> {
        self.inner.fetch_state_entries(storage, nodes, block_height)
    }

    fn run_genesis<S: SubstateDatabase + CommittableSubstateDatabase>(
        &self,
        storage: &mut S,
    ) -> Result<(), GenesisError> {
        self.inner.run_genesis(storage)
    }

    fn run_genesis_with_config<S: SubstateDatabase + CommittableSubstateDatabase>(
        &self,
        storage: &mut S,
        config: GenesisConfig,
    ) -> Result<(), GenesisError> {
        self.inner.run_genesis_with_config(storage, config)
    }

    fn network(&self) -> &NetworkDefinition {
        self.inner.network()
    }
}
