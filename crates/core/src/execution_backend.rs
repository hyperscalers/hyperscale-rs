//! Execution backend trait.
//!
//! Defines the interface between the consensus framework and the execution layer.
//! The executor does not own storage — storage is provided per call by the runner.

use hyperscale_storage::SubstateStore;
use hyperscale_types::{NodeId, StateEntry, StateProvision, TypeConfig};
use std::sync::Arc;

use crate::result::ExecutionOutput;

/// Execution backend trait.
///
/// The executor does not own storage — storage is provided per call by the runner.
/// This matches the existing architecture where IoLoop owns both storage and executor.
///
/// Storage is a method-level generic (`<S: SubstateStore>`) rather than an associated
/// type, because `RadixExecutor` is a concrete struct that works with any storage impl.
/// An associated type would force one storage type per executor, preventing the same
/// `RadixExecutor` from being used in both simulation (SimStorage) and production
/// (RocksDbStorage).
pub trait ExecutionBackend<C: TypeConfig>: Clone + Send + Sync + 'static {
    /// Error type for execution failures.
    type Error: std::error::Error + Send + 'static;

    /// Execute single-shard transactions against the given storage snapshot.
    fn execute_single_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<C::Transaction>],
    ) -> Result<ExecutionOutput<C>, Self::Error>;

    /// Execute cross-shard transactions with provisions.
    fn execute_cross_shard<S: SubstateStore>(
        &self,
        storage: &S,
        transactions: &[Arc<C::Transaction>],
        provisions: &[StateProvision],
    ) -> Result<ExecutionOutput<C>, Self::Error>;

    /// Fetch state entries for provisioning at a specific block height.
    fn fetch_state_entries<S: SubstateStore>(
        &self,
        storage: &S,
        nodes: &[NodeId],
        block_height: u64,
    ) -> Option<Vec<StateEntry>>;
}
