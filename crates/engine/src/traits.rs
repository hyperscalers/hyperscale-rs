//! Execution backend trait.
//!
//! Defines the interface between the deterministic state machine and the
//! execution layer. The trait abstracts over *how* execution is invoked:
//!
//! - **Simulation**: Inline execution (deterministic, single-threaded)
//! - **Production**: Thread pool execution (parallel, async callback)
//!
//! Both use the real Radix Engine - the difference is the calling convention.

use crate::result::ExecutionOutput;
use hyperscale_types::{StateEntry, Hash, NodeId, RoutableTransaction, StateProvision};

/// Trait for transaction execution backends.
///
/// This trait abstracts over the *calling convention* for execution:
/// - **Inline**: For deterministic simulation (single-threaded, immediate)
/// - **Parallel**: For production (rayon thread pool, async callback)
///
/// Both implementations use the real Radix Engine. The trait just controls
/// *when* and *how* the execution happens, not *what* executes.
///
/// # Synchronous Design
///
/// This trait is synchronous. The deterministic runner handles async concerns:
/// 1. Receives `Action::ExecuteTransactions` from state machine
/// 2. Calls this backend (inline for sim, spawns for prod)
/// 3. Sends `Event::TransactionsExecuted` when complete
///
/// For simulation, steps 2-3 happen synchronously.
/// For production, step 2 spawns a rayon task, step 3 uses a callback.
pub trait ExecutionBackend: Clone + Send + Sync + 'static {
    /// Execute single-shard transactions.
    ///
    /// Optimized path for transactions that only touch local shard state.
    /// No provisioning overhead required.
    ///
    /// # Arguments
    ///
    /// * `transactions` - Batch of transactions to execute
    ///
    /// # Returns
    ///
    /// Execution output containing results for each transaction.
    fn execute_single_shard(&self, transactions: &[RoutableTransaction]) -> ExecutionOutput;

    /// Execute cross-shard transactions with provisions.
    ///
    /// For transactions touching multiple shards, remote state is provided
    /// via provisions. The executor layers these on top of local storage.
    ///
    /// # Arguments
    ///
    /// * `transactions` - Batch of transactions to execute
    /// * `provisions` - State provisions from remote shards
    ///
    /// # Returns
    ///
    /// Execution output with results. State writes filtered to local shard.
    fn execute_cross_shard(
        &self,
        transactions: &[RoutableTransaction],
        provisions: &[StateProvision],
    ) -> ExecutionOutput;

    /// Fetch state entries for the given nodes.
    ///
    /// Used by provisioning to collect state for remote shards.
    /// Returns `StateEntry` with pre-computed storage keys for efficient cross-shard execution.
    fn fetch_state_entries(&self, nodes: &[NodeId]) -> Vec<StateEntry>;

    /// Compute merkle root from state writes.
    ///
    /// Computes a commitment to state modifications for the voting protocol.
    fn compute_merkle_root(&self, writes: &[(NodeId, Vec<u8>)]) -> Hash;
}
