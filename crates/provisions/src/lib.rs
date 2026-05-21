//! This crate encapsulates the provision coordination logic for cross-shard transactions.
//!
//! It defines the `ProvisionCoordinator`, which manages the tracking, validation,
//! and completion of state provisions exchanged between shards.
//!
//! ## Provision Flow
//!
//! 1. The source shard proposer broadcasts `ProvisionsNotification`
//!    messages carrying `Provisions` bundles with JMT inclusion proofs.
//! 2. The target shard receives them and associates the provisions with
//!    the corresponding remote block headers.
//! 3. `VerifyProvisions` validates the quorum certificate (QC) signature
//!    once per source block and verifies the Merkle inclusion proof per
//!    state entry.
//! 4. Verified provisions are persisted and emit completion events for
//!    downstream transaction execution.

pub mod action_handlers;
mod build;
mod committed_tombstones;
mod coordinator;
mod expected;
mod outbound;
mod pipeline;
mod queue;
mod store;
mod verification;
mod verified_headers;

pub use build::build_provisions;
pub use coordinator::{ProvisionConfig, ProvisionCoordinator, ProvisionMemoryStats};
pub use outbound::{OutboundMemoryStats, OutboundProvisionTracker};
pub use store::ProvisionStore;
pub use verified_headers::VerifiedHeaderBuffer;
