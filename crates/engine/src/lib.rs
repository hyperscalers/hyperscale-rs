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
//!      │◄─ Event::TransactionsExecuted  ◄───┤ (returns results)
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

pub use execution::ProvisionedSnapshot;
pub use executor::RadixExecutor;
pub use genesis::GenesisConfig;
pub use validation::TransactionValidation;

// Re-export Radix types needed by engine callers (not storage-related)
pub use radix_common::network::NetworkDefinition;
