//! Consensus-bound portion of an executed transaction's output.
//!
//! [`ConsensusReceipt`] is the part of an execution result that is
//! hash-stable, signed over by the receipt root, and transferable across
//! peers. The local-only portion (logs, errors, fees) lives separately in
//! [`ExecutionMetadata`](crate::ExecutionMetadata) — a node that received a
//! receipt via sync rather than by executing has the consensus part but
//! not the local metadata.
//!
//! The variant tag IS the outcome — there's no separate `Success/Failure`
//! flag and no zero-padded `database_updates`/`application_events` for
//! failed transactions.

use crate::{
    ApplicationEvent, DatabaseUpdates, EventRoot, GlobalReceipt, GlobalReceiptHash, Hash,
    TransactionOutcome, WritesRoot,
};
use std::sync::LazyLock;

/// Canonical receipt hash for any failed transaction.
///
/// All failed transactions hash to the same value — derived from the
/// fixed `(Failure, EventRoot::ZERO, WritesRoot::ZERO)` triple. Cached
/// to avoid recomputing per failure.
pub static FAILED_RECEIPT_HASH: LazyLock<GlobalReceiptHash> = LazyLock::new(|| {
    GlobalReceipt {
        outcome: TransactionOutcome::Failure,
        event_root: EventRoot::ZERO,
        writes_root: WritesRoot::ZERO,
    }
    .receipt_hash()
});

/// The consensus-bound portion of an execution result.
///
/// `Succeeded` carries the shard-filtered database updates and events
/// produced by the transaction, plus the precomputed `receipt_hash`
/// (which depends on a `writes_root` derived from globally-filtered
/// updates not stored here). `Failed` carries no payload — every
/// failure is consensus-equivalent.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub enum ConsensusReceipt {
    /// Engine committed the transaction; state changes applied.
    Succeeded {
        /// Precomputed hash of the corresponding [`GlobalReceipt`].
        ///
        /// Cannot be recomputed from this variant alone — depends on
        /// `writes_root`, which is derived from globally-filtered
        /// (non-shard-filtered) updates not carried here.
        receipt_hash: GlobalReceiptHash,
        /// Shard-filtered substate writes produced by the transaction.
        database_updates: DatabaseUpdates,
        /// Application events emitted during execution.
        application_events: Vec<ApplicationEvent>,
    },
    /// Engine rejected the transaction; no state changes applied.
    Failed,
}

impl ConsensusReceipt {
    /// The consensus receipt hash. For [`Self::Failed`] this is the
    /// canonical [`FAILED_RECEIPT_HASH`].
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        match self {
            Self::Succeeded { receipt_hash, .. } => *receipt_hash,
            Self::Failed => *FAILED_RECEIPT_HASH,
        }
    }

    /// Whether the transaction committed successfully.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    /// Per-shard receipt hash used as a leaf in `local_receipt_root`.
    ///
    /// Includes outcome + `event_root` + `database_updates_hash`. Equivalent
    /// to [`LocalReceipt::receipt_hash`](crate::LocalReceipt::receipt_hash)
    /// applied to the projection of `self`.
    #[must_use]
    pub fn local_receipt_hash(&self) -> Hash {
        self.to_local_receipt().receipt_hash()
    }

    /// Project to the legacy [`LocalReceipt`](crate::LocalReceipt) shape.
    ///
    /// Used at the engine→state-machine boundary during the
    /// `unify-receipt-types` migration. Will be removed once all
    /// consumers consume `ConsensusReceipt` directly.
    #[must_use]
    pub fn to_local_receipt(&self) -> crate::LocalReceipt {
        match self {
            Self::Succeeded {
                database_updates,
                application_events,
                ..
            } => crate::LocalReceipt {
                outcome: TransactionOutcome::Success,
                database_updates: database_updates.clone(),
                application_events: application_events.clone(),
            },
            Self::Failed => crate::LocalReceipt::failure(),
        }
    }
}
