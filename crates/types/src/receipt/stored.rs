//! Persisted receipt — a transaction's consensus receipt under its hash.

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{ConsensusReceipt, TxHash};

/// A persisted receipt: the consensus-bound portion, keyed by the
/// transaction it settles.
///
/// The same shape whether this node executed the transaction or received
/// the receipt from a peer: everything a receipt carries is what a
/// finalization's certificates attest, and nothing node-local rides it.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct StoredReceipt {
    /// Primary key in the per-tx receipt store and the join key against
    /// `Finalization` outcomes during validation.
    pub tx_hash: TxHash,
    /// Shared via `Arc` so flowing a receipt through `PendingChain`,
    /// validation, and persistence is `Arc::clone`-cheap rather than
    /// deep-cloning the substate writes.
    pub consensus: Arc<ConsensusReceipt>,
}

impl StoredReceipt {
    /// Pair `consensus` with the transaction it settles.
    #[must_use]
    pub const fn new(tx_hash: TxHash, consensus: Arc<ConsensusReceipt>) -> Self {
        Self { tx_hash, consensus }
    }
}
