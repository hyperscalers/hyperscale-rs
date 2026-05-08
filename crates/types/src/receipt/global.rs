//! Cross-shard agreement receipt (Tier 1).

use crate::{EventRoot, GlobalReceiptHash, Hash, WritesRoot};

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
    success: bool,
    event_root: EventRoot,
    writes_root: WritesRoot,
}

impl GlobalReceipt {
    /// Build a `GlobalReceipt` from its parts.
    #[must_use]
    pub const fn new(success: bool, event_root: EventRoot, writes_root: WritesRoot) -> Self {
        Self {
            success,
            event_root,
            writes_root,
        }
    }

    /// Whether the engine committed (`true`) or rejected (`false`) the transaction.
    #[must_use]
    pub const fn success(&self) -> bool {
        self.success
    }

    /// Merkle root of application event hashes.
    #[must_use]
    pub const fn event_root(&self) -> EventRoot {
        self.event_root
    }

    /// Merkle root of declared-only, system-filtered global database writes.
    ///
    /// Computed from `filter_updates_for_global_receipt()` — includes writes for
    /// ALL shards (not shard-filtered), but excludes system entities and undeclared
    /// writes. This ensures cross-shard validators agree on the same state changes
    /// for declared accounts.
    #[must_use]
    pub const fn writes_root(&self) -> WritesRoot {
        self.writes_root
    }

    /// Compute the global receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        let outcome_byte = if self.success { [1u8] } else { [0u8] };
        GlobalReceiptHash::from_raw(Hash::from_parts(&[
            &outcome_byte,
            self.event_root.as_raw().as_bytes(),
            self.writes_root.as_raw().as_bytes(),
        ]))
    }
}
