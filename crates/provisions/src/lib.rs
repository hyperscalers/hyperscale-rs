//! Centralized provision coordination for cross-shard transactions.
//!
//! This crate provides the `ProvisionCoordinator`, which centralizes all provision
//! tracking and verification for cross-shard transactions.
//!
//! ## Provision Flow
//!
//! 1. Source shard proposer broadcasts `StateProvision` batch with JMT inclusion proofs
//! 2. Target shard receives batch, joins with remote block headers
//! 3. `VerifyStateProvisions` validates the QC signature once and merkle proofs per provision
//! 4. Verified provisions are stored and trigger completion events
//!
//! # Components
//!
//! - [`ProvisionCoordinator`] - Main sub-state machine
//! - [`TxRegistration`] - Registration info for cross-shard transactions

mod state;

pub use state::{ProvisionCoordinator, TxRegistration};
