//! Committed-provision tombstones anchored on `local_committed_ts`.
//!
//! Mirrors the BFT-side
//! [`CommitDedupIndex::provision_retention`](hyperscale_shard::commit_dedup)
//! window so a late re-arrival of an already-committed batch — gossip
//! retransmit, fetch fall-through, range-sync delivery — is dropped at
//! receipt instead of slipping past the pipeline guards and re-entering
//! the proposer queue. Without this tombstone, `pipeline.verified` and
//! the receipt deadline check both clear at `source_block_ts +
//! RETENTION_HORIZON`, leaving a window where the BFT validator still
//! rejects re-inclusion but nothing stops the local proposer from
//! re-including.
//!
//! Keyed by [`ProvisionHash`] (matching the BFT index's keying) and
//! pruned on every commit by the same `local_committed_ts +
//! RETENTION_HORIZON` deadline the BFT index uses.

use std::collections::HashMap;

use hyperscale_types::{ProvisionHash, RETENTION_HORIZON, WeightedTimestamp};

/// Content-hash → deadline (= `local_committed_ts + RETENTION_HORIZON`).
pub struct CommittedProvisionTombstones {
    seen: HashMap<ProvisionHash, WeightedTimestamp>,
}

impl CommittedProvisionTombstones {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Mark `hash` as committed in a block whose local commit ts was
    /// `local_committed_ts`. Idempotent on the hash — first writer wins,
    /// so re-registration after a buffered commit replay can't shorten
    /// the deadline.
    pub fn register(&mut self, hash: ProvisionHash, local_committed_ts: WeightedTimestamp) {
        let deadline = local_committed_ts.plus(RETENTION_HORIZON);
        self.seen.entry(hash).or_insert(deadline);
    }

    /// True when `hash` is still within its retention deadline.
    pub fn contains(&self, hash: &ProvisionHash) -> bool {
        self.seen.contains_key(hash)
    }

    /// Drop entries past their deadline. `now` is the latest committed
    /// block's weighted timestamp.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        self.seen.retain(|_, deadline| *deadline > now);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Hash;

    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn ph(seed: u8) -> ProvisionHash {
        ProvisionHash::from_raw(Hash::from_bytes(&[seed]))
    }

    #[test]
    fn register_then_contains() {
        let mut t = CommittedProvisionTombstones::new();
        t.register(ph(1), ts(1_000));
        assert!(t.contains(&ph(1)));
        assert!(!t.contains(&ph(2)));
    }

    #[test]
    fn register_is_idempotent_first_writer_wins() {
        let mut t = CommittedProvisionTombstones::new();
        t.register(ph(1), ts(1_000));
        // Later re-registration with a NEWER ts must not extend the
        // deadline backwards, but the first-writer policy also means
        // it can't move forward either — the tombstone keeps its
        // original deadline.
        t.register(ph(1), ts(500));
        assert_eq!(t.len(), 1);
        // Prune at a time past the second (later) registration but
        // before the first registration's deadline: entry survives.
        t.prune(ts(500).plus(RETENTION_HORIZON));
        assert!(t.contains(&ph(1)));
    }

    #[test]
    fn prune_drops_past_deadline() {
        let mut t = CommittedProvisionTombstones::new();
        t.register(ph(1), ts(1_000));
        t.register(ph(2), ts(2_000));

        // At ts=1_000+RETENTION the first entry is on the boundary
        // (deadline > now is the retention predicate, so == drops).
        t.prune(ts(1_000).plus(RETENTION_HORIZON));
        assert!(!t.contains(&ph(1)));
        assert!(t.contains(&ph(2)));

        t.prune(ts(2_000).plus(RETENTION_HORIZON));
        assert!(!t.contains(&ph(2)));
        assert_eq!(t.len(), 0);
    }
}
