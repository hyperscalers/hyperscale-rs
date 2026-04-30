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
    WritesRoot, compute_merkle_root,
};
use std::sync::LazyLock;

/// Canonical receipt hash for any failed transaction.
///
/// All failed transactions hash to the same value — derived from the
/// fixed `(success=false, EventRoot::ZERO, WritesRoot::ZERO)` triple.
/// Cached to avoid recomputing per failure.
pub static FAILED_RECEIPT_HASH: LazyLock<GlobalReceiptHash> = LazyLock::new(|| {
    GlobalReceipt {
        success: false,
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
    /// Engine committed the tx; carries the precomputed receipt hash and
    /// the writes/events the local shard needs.
    Succeeded {
        /// Precomputed [`GlobalReceiptHash`] — cannot be recomputed from
        /// this variant alone, since it folds in `writes_root` derived
        /// from globally-filtered (not shard-filtered) updates that
        /// aren't carried here.
        receipt_hash: GlobalReceiptHash,
        /// Substate writes filtered to the local shard. The global
        /// `writes_root` on `receipt_hash` covers writes for all shards;
        /// this field is only what the local shard needs to apply.
        database_updates: DatabaseUpdates,
        /// Identical across shards for the same tx — events come from
        /// user logic, which sees the same merged state on every shard.
        application_events: Vec<ApplicationEvent>,
    },
    /// All failures collapse to one variant — the canonical
    /// [`FAILED_RECEIPT_HASH`] is derived at hash time, no payload needed.
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

    /// The shard-filtered database updates, or `None` for `Failed`
    /// (failed transactions produce no writes).
    #[must_use]
    pub const fn database_updates(&self) -> Option<&DatabaseUpdates> {
        match self {
            Self::Succeeded {
                database_updates, ..
            } => Some(database_updates),
            Self::Failed => None,
        }
    }

    /// Per-shard receipt hash used as a leaf in `local_receipt_root`.
    ///
    /// Hashes `outcome_byte || event_root || database_updates_hash`.
    /// `Failed` produces the same hash as a no-write/no-event failure.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of `database_updates` fails — `DatabaseUpdates`
    /// is a closed SBOR type and encoding is infallible in practice.
    #[must_use]
    pub fn local_receipt_hash(&self) -> Hash {
        let (outcome_byte, event_root, database_updates) = match self {
            Self::Succeeded {
                database_updates,
                application_events,
                ..
            } => {
                let event_hashes: Vec<Hash> = application_events
                    .iter()
                    .map(ApplicationEvent::hash)
                    .collect();
                let event_root = compute_merkle_root(&event_hashes);
                ([1u8], event_root, database_updates.clone())
            }
            Self::Failed => ([0u8], Hash::ZERO, DatabaseUpdates::default()),
        };
        let updates_bytes =
            sbor::prelude::basic_encode(&database_updates).expect("encode should not fail");
        let updates_hash = Hash::from_bytes(&updates_bytes);
        Hash::from_parts(&[
            &outcome_byte,
            event_root.as_bytes(),
            updates_hash.as_bytes(),
        ])
    }
}
