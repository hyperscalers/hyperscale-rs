//! The committed-provision tier of the shard's commit-dedup index.
//!
//! Held apart from the index's other tiers because two coordinators ask
//! the same question of it. The shard asks at admission, refusing a block
//! that re-includes a batch the chain already carries; the provisions
//! coordinator asks at the receipt seam, dropping a re-arrival before a
//! signature-verification job is dispatched for content the chain has.
//! One window answering both, rather than two that must agree.
//!
//! Shared by `Arc` with interior mutability, as the vote fence's
//! [`ProvenAnchors`](hyperscale_types::ProvenAnchors) is. The tier can
//! afford the lock its siblings could not: it is read once per provision
//! batch named by a block manifest and written once per commit, where
//! `tx_retention` is read once per transaction.

use std::collections::HashMap;
use std::sync::RwLock;

use hyperscale_types::{ProvisionHash, RETENTION_HORIZON, WeightedTimestamp};

/// `provision_hash → local_committed_ts + RETENTION_HORIZON`.
///
/// Past the horizon every transaction the batch carried has expired its
/// validity range and terminated everywhere, so no future block can
/// legitimately reference the same content-addressed batch.
#[derive(Debug, Default)]
pub struct CommittedProvisions {
    seen: RwLock<HashMap<ProvisionHash, WeightedTimestamp>>,
}

impl CommittedProvisions {
    /// An empty window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record every hash a block committed at `local_committed_ts`.
    ///
    /// First writer wins: a batch re-registered by a later commit keeps
    /// the deadline of the block that first carried it, so the window
    /// closes on the chain's own clock rather than being extended by a
    /// replay.
    pub fn register(
        &self,
        hashes: impl IntoIterator<Item = ProvisionHash>,
        local_committed_ts: WeightedTimestamp,
    ) {
        let deadline = local_committed_ts.plus(RETENTION_HORIZON);
        let mut seen = self
            .seen
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for hash in hashes {
            seen.entry(hash).or_insert(deadline);
        }
    }

    /// Seed from a recovery walk, which carries each batch's deadline
    /// already computed off the block that committed it.
    pub fn seed(&self, entries: impl IntoIterator<Item = (ProvisionHash, WeightedTimestamp)>) {
        self.seen
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(entries);
    }

    /// Whether the chain already carries this batch.
    #[must_use]
    pub fn contains(&self, hash: &ProvisionHash) -> bool {
        self.seen
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(hash)
    }

    /// Drop every entry whose deadline has passed `now`.
    pub fn prune(&self, now: WeightedTimestamp) {
        self.seen
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, deadline| *deadline > now);
    }

    /// How many batches the window holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the window holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
