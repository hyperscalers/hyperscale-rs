//! The [`Engine`] trait — abstraction over transaction execution.
//!
//! Two implementations live in this crate:
//! - [`RadixExecutor`](crate::RadixExecutor) — direct Radix Engine execution
//!   used by the production runner.
//! - [`SimulationEngine`](crate::SimulationEngine) — caching wrapper around
//!   `RadixExecutor` used by simulation, so identical executions across
//!   validators in the same shard only run once.
//!
//! All engine methods are READ-ONLY: they execute against a snapshot and
//! return [`ExecutionOutput`], but do not commit. The caller (runner)
//! caches the resulting `DatabaseUpdates` and applies them when the
//! `WaveCertificate` is included in a committed block.

use std::sync::Arc;

use hyperscale_storage::SubstateDatabase;
use hyperscale_types::{RoutableTransaction, ShardGroupId, SubstateEntry};
use radix_common::network::NetworkDefinition;

use crate::output::ExecutionOutput;
use crate::receipt::CachedVmOutput;

/// Trait abstracting transaction execution.
///
/// All methods are READ-ONLY: implementations must not mutate `snapshot`
/// or any externally-visible storage. Results are deterministic given
/// the same `(snapshot, transactions, provisions, local_shard, num_shards)`.
///
/// Per-transaction failures (validation, execution panic, etc.) are
/// reported as [`ExecutedTx::failure`](crate::ExecutedTx::failure)
/// entries in the returned [`ExecutionOutput`]. The trait does not
/// surface batch-fatal errors — every input transaction produces
/// exactly one output entry.
pub trait Engine: Clone + Send + Sync + 'static {
    /// Execute single-shard transactions (READ-ONLY) against a
    /// caller-provided snapshot.
    ///
    /// Snapshot hoisting lets the caller share one rocksdb snapshot
    /// across multiple engine calls in the same action batch — state
    /// doesn't change during execution (commits are serialized
    /// elsewhere), so reusing one snapshot is correct and avoids the
    /// per-tx `storage.snapshot()` + `read_jmt_metadata` overhead.
    fn execute_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutionOutput;

    /// Execute cross-shard transactions with provisions (READ-ONLY).
    ///
    /// Layers `provisions` (state from other shards, with pre-computed
    /// storage keys) on top of `snapshot` and executes against the
    /// merged view. Same snapshot-hoisting contract as
    /// [`execute_single_shard`](Self::execute_single_shard).
    fn execute_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[Arc<Vec<SubstateEntry>>],
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> ExecutionOutput;

    /// Run the VM for a single-shard transaction and return the
    /// [`CachedVmOutput`] — the shard-invariant projection of the
    /// receipt, suitable for storing in a process-scope execution
    /// cache. The caller projects per shard via
    /// [`crate::project_to_shard`].
    fn compute_vm_output_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
    ) -> CachedVmOutput;

    /// Cross-shard counterpart of
    /// [`compute_vm_output_single_shard`](Self::compute_vm_output_single_shard):
    /// builds the provisioned snapshot, runs the VM, projects to
    /// [`CachedVmOutput`].
    fn compute_vm_output_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
        provisions: &[Arc<Vec<SubstateEntry>>],
    ) -> CachedVmOutput;

    /// Reference to the network definition this engine runs against.
    fn network(&self) -> &NetworkDefinition;
}
