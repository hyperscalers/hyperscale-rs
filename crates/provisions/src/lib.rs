//! Centralized provision coordination for cross-shard transactions.
//!
//! This crate provides the `ProvisionCoordinator`, which centralizes all provision
//! tracking and verification for cross-shard transactions.
//!
//! ## Provision Flow
//!
//! 1. Source shard proposer broadcasts `StateProvision` with JMT inclusion proofs
//! 2. Target shard receives provision, joins with remote block header
//! 3. `VerifyStateProvision` validates the QC signature and merkle proofs
//! 4. Verified provisions are stored and trigger quorum/completion events
//!
//! # Components
//!
//! - [`ProvisionCoordinator`] - Main sub-state machine
//! - [`TxRegistration`] - Registration info for cross-shard transactions

mod state;

pub use state::{ProvisionCoordinator, TxRegistration};
