//! Radix Engine integration.
//!
//! This crate provides synchronous transaction execution suitable for
//! single-threaded deterministic simulation.
//!
//! # Architecture
//!
//! The consensus separates pure state machine logic from I/O.
//! Transaction execution is computationally expensive and delegated to the
//! runner layer. The executor does NOT own storage - the runner owns storage
//! and passes it to the executor.
//!
//! ```text
//! State Machine                           Runner (owns storage + executor)
//!      │                                    │
//!      ├─► Action::ExecuteTransactions ────►│ calls executor.execute(&storage, ...)
//!      │                                    │
//!      │◄─ ExecutionBatchCompleted      ◄───┤ (returns votes)
//! ```
//!
//! # Simulation vs Production
//!
//! - **Simulation**: Calls executor methods inline (single-threaded, deterministic)
//! - **Production**: Spawns executor methods on rayon thread pool (parallel, async callback)
//!
//! Both use the real Radix Engine - the difference is the calling convention.

#![warn(missing_docs)]

mod error;
mod execution;
mod executor;
mod genesis;
mod result;
mod validation;

/// Transaction execution handlers with integrated shard filtering.
pub mod handlers;
/// Shard assignment and write filtering for Radix Engine DatabaseUpdates.
pub mod sharding;

pub use execution::ProvisionedSnapshot;
pub use executor::{fetch_state_entries, fetch_state_entries_speculative, RadixExecutor};
pub use genesis::GenesisConfig;
pub use hyperscale_types::ExecutionResult;
pub use result::SingleTxResult;
pub use validation::TransactionValidation;

// Re-export Radix types needed by engine callers (not storage-related)
pub use radix_common::network::NetworkDefinition;
