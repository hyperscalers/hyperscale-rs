//! Caching engine for simulation.
//!
//! [`SimulationEngine`] wraps [`RadixExecutor`] and deduplicates execution:
//! all validators in the same shard share a [`SimExecutionCache`], so the
//! first validator to execute a transaction computes the result and subsequent
//! validators retrieve it from the cache.

use crate::RadixExecutor;
use crate::engine::Engine;
use crate::output::{ExecutedTx, ExecutionOutput};
use dashmap::DashMap;
use hyperscale_storage::SubstateDatabase;
use hyperscale_types::{RoutableTransaction, ShardGroupId, StateProvision, TxHash};
use radix_common::network::NetworkDefinition;
use std::sync::{Arc, OnceLock};

/// Shared execution cache — one per shard group in simulation.
///
/// Key: transaction hash.  Value: `OnceLock` ensuring compute-once semantics.
pub type SimExecutionCache = Arc<DashMap<TxHash, Arc<OnceLock<ExecutedTx>>>>;

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
    pub const fn new(inner: RadixExecutor, cache: SimExecutionCache) -> Self {
        Self { inner, cache }
    }

    /// Look up `tx_hash` in the shared cache, computing the result on
    /// miss via `compute`. `compute` returns a single-tx batch; the
    /// wrapper unpacks it into one [`ExecutedTx`].
    fn cache_or_compute<F>(&self, tx_hash: TxHash, compute: F) -> ExecutedTx
    where
        F: FnOnce() -> ExecutionOutput,
    {
        let lock = self
            .cache
            .entry(tx_hash)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();

        lock.get_or_init(|| {
            // Engine contract: one result per input tx; we pass one in.
            compute()
                .results
                .into_iter()
                .next()
                .expect("inner Engine returned no result for single-tx input")
        })
        .clone()
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
    ) -> ExecutionOutput {
        let mut results = Vec::with_capacity(transactions.len());
        for tx in transactions {
            results.push(self.cache_or_compute(tx.hash(), || {
                self.inner.execute_single_shard(
                    snapshot,
                    std::slice::from_ref(tx),
                    local_shard,
                    num_shards,
                )
            }));
        }
        ExecutionOutput::new(results)
    }

    fn execute_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[StateProvision],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutionOutput {
        let mut results = Vec::with_capacity(transactions.len());
        for tx in transactions {
            results.push(self.cache_or_compute(tx.hash(), || {
                self.inner.execute_cross_shard(
                    snapshot,
                    std::slice::from_ref(tx),
                    provisions,
                    local_shard,
                    num_shards,
                )
            }));
        }
        ExecutionOutput::new(results)
    }

    fn network(&self) -> &NetworkDefinition {
        self.inner.network()
    }
}
