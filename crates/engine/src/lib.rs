//! Radix Engine integration.
//!
//! Synchronous transaction execution shared by the production runner
//! and the deterministic simulator. The executor does NOT own storage:
//! the runner owns it and passes a snapshot per call.
//!
//! State machines emit `Action::ExecuteTransactions`; the runner runs
//! the VM via [`RadixExecutor::compute_vm_output_single_shard`] or its
//! cross-shard counterpart, then projects the shard-invariant
//! [`CachedVmOutput`] into the local shard's [`ExecutedTx`] via
//! [`project_to_shard`]. The process-scope [`ProcessExecutionCache`]
//! short-circuits the VM call when same-shard vnodes (or hosted
//! participating shards) replay an already-executed transaction.

#![warn(missing_docs)]

mod cache;
mod executor;
mod genesis;
mod genesis_cache;
mod output;
mod provisioned_snapshot;
mod receipt;
mod validation;

/// Shard assignment and write filtering for Radix Engine `DatabaseUpdates`.
pub mod sharding;

pub use cache::ProcessExecutionCache;
pub use executor::{RadixExecutor, fetch_state_entries};
pub use genesis::GenesisConfig;
pub use genesis_cache::prepared_genesis;
pub use output::ExecutedTx;
// Re-export Radix types needed by engine callers (not storage-related).
pub use radix_common::network::NetworkDefinition;
pub use receipt::{CachedVmOutput, build_executed_tx, compute_vm_output, project_to_shard};
pub use validation::TransactionValidation;
