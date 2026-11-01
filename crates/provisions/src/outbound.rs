//! Tracks provisions this shard's proposer generated and broadcast to
//! target shards, holding each entry until the target shard's execution
//! certificates acknowledge every transaction it contained.
//!
//! Each registered provisions entry is kept in the shared
//! [`ProvisionStore`]. When a remote shard's `ExecutionCertificate`
//! arrives and we were a source for its tick, the target shard's
//! `tx_outcomes` drain the entry's pending set — `Executed` and `Aborted`
//! are both terminal, so either removes the tx from the pending set.
//! When the pending set empties, the entry is evicted from the store.
//!
//! A hard safety horizon ([`RETENTION_HORIZON`]) force-evicts entries
//! that never reach a terminal EC; this is a bug-bound, not a nominal
//! policy — every firing indicates an upstream liveness failure and is
//! logged at `warn!`. The bound is principled: a tx included at the
//! latest possible moment within its `validity_range` gets `MAX_FINALIZATION_DELAY`
//! to terminate, so any provisions unacked past `MAX_VALIDITY_RANGE +
//! MAX_FINALIZATION_DELAY` reference a tx no shard could still be processing.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, Provision, ProvisionHash, ShardId, TxHash, TxOutcome, Verified, WeightedTimestamp,
};
use tracing::{debug, warn};

use crate::store::ProvisionStore;

/// Snapshot of how much state the outbound tracker is holding onto.
#[allow(missing_docs)] // flat counters; field names are the documentation
#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundMemoryStats {
    pub tracked_provisions: usize,
    pub tracked_tx_entries: usize,
}

struct OutboundEntry {
    target_shard: ShardId,
    source_block_height: BlockHeight,
    pending_txs: BTreeSet<TxHash>,
    /// Hard deadline past which the provisions are provably useless: every
    /// tx in them has expired its `validity_range` and terminated.
    /// Counted from the source block the bundle names, which the bundle
    /// carries and this node built it from — not from a reading of the
    /// local commit clock, which is behind it by however long the
    /// broadcast took and reads zero on a replayed one.
    deadline: WeightedTimestamp,
}

/// Sub-state machine that retains outbound provisions until the target
/// shard confirms every transaction or the safety horizon elapses.
pub struct OutboundProvisionTracker {
    store: Arc<ProvisionStore>,
    /// Provision content hash → outbound tracking metadata.
    entries: HashMap<ProvisionHash, OutboundEntry>,
    /// Reverse index: a tx hash points at every provisions entry still
    /// waiting for it to be acknowledged. One tx can appear in entries
    /// for multiple target shards (e.g. a cross-shard tx that reads state
    /// from several sources but only one target — the tx hash is the
    /// same across them). The set lets a single EC drain every matching
    /// entry in O(matched).
    by_tx: HashMap<TxHash, HashSet<ProvisionHash>>,
}

impl OutboundProvisionTracker {
    /// Build a tracker that shares its provision bodies with `store`.
    pub fn new(store: Arc<ProvisionStore>) -> Self {
        Self {
            store,
            entries: HashMap::new(),
            by_tx: HashMap::new(),
        }
    }

    /// Snapshot of in-memory state for metrics export.
    #[must_use]
    pub fn memory_stats(&self) -> OutboundMemoryStats {
        OutboundMemoryStats {
            tracked_provisions: self.entries.len(),
            tracked_tx_entries: self.by_tx.values().map(HashSet::len).sum(),
        }
    }

    /// Register a part our proposer just broadcast. Inserts into the
    /// shared store (which maintains the `(source_block, target, index)`
    /// index used by cross-shard fast-path serving); idempotent.
    ///
    /// Takes a `Verified` handle — the proposer built the part from a
    /// local JMT view so the merkle predicate holds. The shared
    /// [`ProvisionStore`] holds raw bodies (wire-serving doesn't carry
    /// the marker), so the body is cloned once at the seam.
    pub fn on_broadcast(&mut self, part: &Verified<Provision>) {
        let provision_hash = part.hash();
        if self.entries.contains_key(&provision_hash) {
            return;
        }
        let target_shard = part.target_shard();
        let tx_hash = part.tx_hash();
        self.by_tx
            .entry(tx_hash)
            .or_default()
            .insert(provision_hash);
        self.store.insert_outbound(part.as_ref().clone());
        self.entries.insert(
            provision_hash,
            OutboundEntry {
                target_shard,
                source_block_height: part.block_height(),
                pending_txs: BTreeSet::from([tx_hash]),
                deadline: part.deadline(part.source_block_ts()),
            },
        );

        debug!(
            provision_hash = ?provision_hash,
            target_shard = target_shard.inner(),
            source_block_height = part.block_height().inner(),
            tx_hash = %tx_hash,
            "Tracking outbound provision"
        );
    }

    /// Drain every outbound entry awaiting any of `tx_outcomes` from
    /// `target_shard`. Entries whose pending set empties are evicted from
    /// the shared store.
    pub fn on_ec_observed(&mut self, target_shard: ShardId, tx_outcomes: &[TxOutcome]) {
        let mut to_evict: Vec<ProvisionHash> = Vec::new();

        for outcome in tx_outcomes {
            let Some(hashes) = self.by_tx.get_mut(&outcome.tx_hash()) else {
                continue;
            };
            hashes.retain(|provision_hash| {
                let Some(entry) = self.entries.get_mut(provision_hash) else {
                    return false;
                };
                if entry.target_shard != target_shard {
                    return true;
                }
                entry.pending_txs.remove(&outcome.tx_hash());
                if entry.pending_txs.is_empty() {
                    to_evict.push(*provision_hash);
                }
                false
            });
            if hashes.is_empty() {
                self.by_tx.remove(&outcome.tx_hash());
            }
        }

        for provision_hash in to_evict {
            self.evict(provision_hash, "acknowledged");
        }
    }

    /// Safety sweep: evict outbound entries whose deadline has passed.
    /// Fires with `warn!` — a hit indicates the target shard never produced
    /// a terminal EC (upstream bug).
    ///
    /// # Panics
    ///
    /// Panics if a stale hash collected for eviction is no longer in `entries`.
    /// Unreachable: the hashes are sourced from the same map under `&mut self`.
    pub fn on_block_committed(&mut self, now: WeightedTimestamp) {
        let stale: Vec<ProvisionHash> = self
            .entries
            .iter()
            .filter_map(|(hash, entry)| {
                if now > entry.deadline {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();

        for provision_hash in stale {
            let entry = self
                .entries
                .get(&provision_hash)
                .expect("entry exists by construction");
            warn!(
                provision_hash = ?provision_hash,
                target_shard = entry.target_shard.inner(),
                source_block_height = entry.source_block_height.inner(),
                pending_txs = entry.pending_txs.len(),
                past_deadline_secs = now.elapsed_since(entry.deadline).as_secs(),
                "Evicting outbound provisions past deadline — no terminal EC observed"
            );
            self.evict(provision_hash, "deadline-passed");
        }
    }

    fn evict(&mut self, provision_hash: ProvisionHash, reason: &'static str) {
        let Some(entry) = self.entries.remove(&provision_hash) else {
            return;
        };
        for tx in &entry.pending_txs {
            if let Some(hashes) = self.by_tx.get_mut(tx) {
                hashes.remove(&provision_hash);
                if hashes.is_empty() {
                    self.by_tx.remove(tx);
                }
            }
        }
        self.store.evict(std::iter::once(provision_hash));
        debug!(
            provision_hash = ?provision_hash,
            target_shard = entry.target_shard.inner(),
            reason,
            "Evicted outbound provisions"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_types::{ExecutionOutcome, GlobalReceiptHash, Hash, RETENTION_HORIZON};

    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn tx(label: &[u8]) -> TxHash {
        TxHash::from(Hash::from_bytes(label))
    }

    fn part_to(
        target: ShardId,
        source_block: BlockHeight,
        source_block_ts: WeightedTimestamp,
        tx_hash: TxHash,
    ) -> Verified<Provision> {
        Verified::new_unchecked_for_test(Provision::dummy_at(
            ShardId::leaf(2, 0),
            target,
            source_block,
            source_block_ts,
            tx_hash,
        ))
    }

    fn part(source_block: BlockHeight, tx_hash: TxHash) -> Verified<Provision> {
        part_to(
            ShardId::leaf(2, 1),
            source_block,
            WeightedTimestamp::ZERO,
            tx_hash,
        )
    }

    fn executed(tx_hash: TxHash) -> TxOutcome {
        TxOutcome::new(
            tx_hash,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::ZERO),
            },
        )
    }

    fn aborted(tx_hash: TxHash) -> TxOutcome {
        TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)
    }

    #[test]
    fn on_broadcast_stores_parts_and_tracks_txs() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let first = part(BlockHeight::new(10), tx(b"a"));
        let provision_hash = first.hash();
        tracker.on_broadcast(&first);
        tracker.on_broadcast(&part(BlockHeight::new(10), tx(b"b")));

        assert_eq!(tracker.memory_stats().tracked_provisions, 2);
        assert_eq!(tracker.memory_stats().tracked_tx_entries, 2);
        assert!(store.get(provision_hash).is_some());
        let hit = store.get_outbound(BlockHeight::new(10), ShardId::leaf(2, 1), 0);
        assert!(hit.is_some());
    }

    #[test]
    fn executed_ec_evicts_each_part_it_acknowledges() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let b = tx(b"b");
        let (part_a, part_b) = (part(BlockHeight::new(10), a), part(BlockHeight::new(10), b));
        tracker.on_broadcast(&part_a);
        tracker.on_broadcast(&part_b);

        tracker.on_ec_observed(ShardId::leaf(2, 1), &[executed(a)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert!(store.get(part_a.hash()).is_none());
        assert!(store.get(part_b.hash()).is_some());

        tracker.on_ec_observed(ShardId::leaf(2, 1), &[executed(b)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 0);
        assert!(store.get(part_b.hash()).is_none());
    }

    #[test]
    fn aborted_ec_is_terminal_and_evicts() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let provision = part_to(
            ShardId::leaf(2, 2),
            BlockHeight::new(7),
            WeightedTimestamp::ZERO,
            a,
        );
        let provision_hash = provision.hash();
        tracker.on_broadcast(&provision);

        tracker.on_ec_observed(ShardId::leaf(2, 2), &[aborted(a)]);
        assert!(store.get(provision_hash).is_none());
    }

    #[test]
    fn ec_from_different_target_does_not_drain() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        tracker.on_broadcast(&part(BlockHeight::new(5), a));

        // EC from a different target shard must not acknowledge these provisions.
        tracker.on_ec_observed(ShardId::leaf(2, 2), &[executed(a)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
    }

    #[test]
    fn safety_sweep_evicts_past_retention_max() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));
        tracker.on_block_committed(ts(1_000_000));

        let a = tx(b"a");
        let provisions = part_to(ShardId::leaf(2, 1), BlockHeight::new(5), ts(1_000_000), a);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(&provisions);

        let past_max = RETENTION_HORIZON + Duration::from_secs(1);
        tracker.on_block_committed(ts(
            1_000_000 + u64::try_from(past_max.as_millis()).unwrap_or(u64::MAX)
        ));
        assert!(store.get(provision_hash).is_none());
        assert_eq!(tracker.memory_stats().tracked_provisions, 0);
    }

    /// A replayed block this node proposed re-emits its provision
    /// broadcast before any live commit reaches the tracker, so the
    /// registration runs against a tracker that has seen no block. The
    /// deadline must still come from the bundle's own source block.
    #[test]
    fn deadline_anchors_on_the_bundle_source_block_not_the_tracker_clock() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let source_ts = ts(60_000_000);
        let a = tx(b"a");
        let provisions = part_to(ShardId::leaf(2, 1), BlockHeight::new(5), source_ts, a);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(&provisions);

        // The first live commit, one block past the source. The bundle is
        // a block old, not a retention horizon old.
        tracker.on_block_committed(source_ts.plus(Duration::from_millis(500)));
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert!(
            store.get(provision_hash).is_some(),
            "a bundle one block old must survive the first commit after a restart"
        );
    }

    #[test]
    fn on_broadcast_is_idempotent() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let provisions = part(BlockHeight::new(10), a);
        tracker.on_broadcast(&provisions);
        tracker.on_broadcast(&provisions);
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert_eq!(tracker.memory_stats().tracked_tx_entries, 1);
    }
}
