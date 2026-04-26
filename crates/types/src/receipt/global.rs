//! Cross-shard agreement receipt (Tier 1).

use crate::{EventRoot, GlobalReceiptHash, Hash, TransactionOutcome, WritesRoot};

/// Cross-shard agreement receipt — ensures validators on different shards
/// executing the same transaction reach the same outcome.
///
/// Contains `writes_root` (merkle root of declared-only, system-filtered global
/// writes — NOT shard-filtered) so cross-shard agreement covers state changes,
/// not just outcome + events.
///
/// This hash is what validators sign over in execution votes.
/// Ephemeral — never written to storage, only lives for EC aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub struct GlobalReceipt {
    /// Whether the engine committed or rejected the transaction.
    pub outcome: TransactionOutcome,
    /// Merkle root of application event hashes.
    pub event_root: EventRoot,
    /// Merkle root of declared-only, system-filtered global database writes.
    ///
    /// Computed from `filter_updates_for_global_receipt()` — includes writes for
    /// ALL shards (not shard-filtered), but excludes system entities and undeclared
    /// writes. This ensures cross-shard validators agree on the same state changes
    /// for declared accounts.
    pub writes_root: WritesRoot,
}

impl GlobalReceipt {
    /// Compute the global receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    ///
    /// # Panics
    ///
    /// Cannot panic: outcome maps to a fixed-size byte and roots are
    /// fixed-size hashes.
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        let outcome_byte = match self.outcome {
            TransactionOutcome::Success => [1u8],
            TransactionOutcome::Failure => [0u8],
        };
        GlobalReceiptHash::from_raw(Hash::from_parts(&[
            &outcome_byte,
            self.event_root.as_raw().as_bytes(),
            self.writes_root.as_raw().as_bytes(),
        ]))
    }
}
