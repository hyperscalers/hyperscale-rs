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
//!      │◄─ Event::TransactionsExecuted ◄───┤ (returns results)
//! ```
//!
//! # Simulation vs Production
//!
//! - **Simulation**: Calls executor methods inline (single-threaded, deterministic)
//! - **Production**: Spawns executor methods on rayon thread pool (parallel, async callback)
//!
//! Both use the real Radix Engine - the difference is the calling convention.
//!
//! # Example
//!
//! ```ignore
//! use hyperscale_engine::{RadixExecutor, ExecutionOutput};
//! use hyperscale_storage::SimStorage;
//!
//! // Runner owns storage
//! let storage = SimStorage::new();
//!
//! // Create executor (no storage parameter)
//! let executor = RadixExecutor::new(NetworkDefinition::simulator());
//!
//! // Run genesis (storage passed by reference)
//! executor.run_genesis(&storage)?;
//!
//! // Execute transactions (storage passed by reference)
//! let output = executor.execute_single_shard(&storage, &transactions)?;
//! ```

#![warn(missing_docs)]

mod error;
mod execution;
mod executor;
mod genesis;
mod result;
mod storage;
mod validation;

pub use execution::{substate_writes_to_database_updates, ProvisionedSnapshot};
pub use executor::RadixExecutor;
pub use genesis::GenesisConfig;
pub use storage::{keys, SubstateStore, RADIX_PREFIX};
pub use validation::TransactionValidation;

// Re-export commonly needed Radix types for storage implementations
pub use radix_common::network::NetworkDefinition;
pub use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
pub use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};
