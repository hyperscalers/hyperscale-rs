//! Radix Engine integration.
//!
//! This crate provides synchronous transaction execution suitable for
//! both deterministic single-threaded simulation and parallel production
//! runners.
//!
//! # Architecture
//!
//! Consensus separates pure state-machine logic from I/O. Transaction
//! execution is computationally expensive and lives in the runner layer:
//! the executor does NOT own storage — the runner owns storage and
//! passes it to the executor.
//!
//! The state machine emits `Action::ExecuteTransactions`; the runner
//! takes a snapshot, dispatches it to the appropriate engine method
//! ([`Engine::execute_single_shard`] for local-only, or
//! [`Engine::execute_cross_shard`] when other-shard provisions are
//! attached), and feeds the resulting [`ExecutedTx`] batch back as
//! `ProtocolEvent::ExecutionBatchCompleted`.
//!
//! # Simulation vs Production
//!
//! - **Simulation**: [`SimulationEngine`] wraps [`RadixExecutor`] with a
//!   per-shard result cache so identical executions across validators
//!   only run once.
//! - **Production**: [`RadixExecutor`] is called directly, typically
//!   dispatched to a rayon thread pool by the runner.
//!
//! Both implement the [`Engine`] trait — callers code against the trait.

#![warn(missing_docs)]

mod cache;
mod engine;
mod executor;
mod genesis;
mod genesis_cache;
mod output;
mod provisioned_snapshot;
mod receipt;
mod simulation;
mod validation;

/// Shard assignment and write filtering for Radix Engine `DatabaseUpdates`.
pub mod sharding;

pub use cache::ProcessExecutionCache;
pub use engine::Engine;
pub use executor::{RadixExecutor, fetch_state_entries};
pub use genesis::GenesisConfig;
pub use genesis_cache::prepared_genesis;
pub use output::{ExecutedTx, ExecutionOutput};
// Re-export Radix types needed by engine callers (not storage-related).
pub use radix_common::network::NetworkDefinition;
pub use receipt::{CachedVmOutput, compute_vm_output, project_to_shard};
pub use simulation::{SimExecutionCache, SimulationEngine};
pub use validation::TransactionValidation;
