//! This crate encapsulates the provision coordination logic for cross-shard transactions.
//!
//! It defines the `ProvisionCoordinator`, which manages the tracking, validation,
//! and completion of state provisions exchanged between shards.
//!
//! ## Provision Flow
//!
//! 1. The source shard proposer broadcasts a `StateProvision` batch containing
//!    Jellyfish Merkle Tree (JMT) inclusion proofs.
//! 2. The target shard receives the batch and associates the provisions with
//!    the corresponding remote block headers.
//! 3. `VerifyStateProvision` validates the quorum certificate (QC) signature
//!    once per batch and verifies the Merkle inclusion proof for each provision.
//! 4. Verified provisions are persisted and emit completion events for downstream
//!    transaction execution.
//!
//! # Components
//!
//! - [`ProvisionCoordinator`] - Main sub-state machine

mod state;
mod store;

pub use state::{ProvisionConfig, ProvisionCoordinator, ProvisionMemoryStats};
pub use store::ProvisionStore;
