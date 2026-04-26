//! Workload generation for transaction spamming.
//!
//! Provides the `WorkloadGenerator` trait and implementations for various
//! transaction types.

mod funding;
mod transfer;

pub use funding::FundingWorkload;
pub use transfer::TransferWorkload;

use crate::accounts::AccountPool;
use hyperscale_types::RoutableTransaction;
use rand::RngCore;

/// Trait for generating transaction workloads.
///
/// Implementors generate transactions that can be submitted to the network.
/// Uses `&mut dyn RngCore` for dyn-compatibility.
pub trait WorkloadGenerator: Send + Sync {
    /// Generate a single transaction.
    ///
    /// Returns `None` if generation fails (e.g., no suitable accounts available).
    fn generate_one(
        &self,
        accounts: &AccountPool,
        rng: &mut dyn RngCore,
    ) -> Option<RoutableTransaction>;

    /// Generate a batch of transactions.
    fn generate_batch(
        &self,
        accounts: &AccountPool,
        count: usize,
        rng: &mut dyn RngCore,
    ) -> Vec<RoutableTransaction>;
}

/// Error type for workload generation.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    /// Pool didn't yield a sender/recipient pair satisfying the workload constraints.
    #[error("No suitable accounts available")]
    NoAccounts,

    /// Signing the manifest with the sender's private key failed.
    #[error("Transaction signing failed: {0}")]
    SigningFailed(String),

    /// Conversion from notarized v1 transaction to `RoutableTransaction` failed.
    #[error("Transaction conversion failed: {0}")]
    ConversionFailed(String),
}
