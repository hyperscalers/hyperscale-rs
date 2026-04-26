//! Tracks provisions this shard's proposer generated and broadcast to
//! target shards, holding each entry until the target shard's execution
//! certificates acknowledge every transaction it contained.
//!
//! Each registered provisions entry is kept in the shared
//! [`ProvisionStore`]. When a remote shard's `ExecutionCertificate`
//! arrives and we were a source for its wave, the target shard's
//! `tx_outcomes` drain the entry's pending set — `Executed` and `Aborted`
//! are both terminal, so either removes the tx from the pending set.
//! When the pending set empties, the entry is evicted from the store.
//!
//! A hard safety horizon ([`RETENTION_HORIZON`]) force-evicts entries
//! that never reach a terminal EC; this is a bug-bound, not a nominal
//! policy — every firing indicates an upstream liveness failure and is
//! logged at `warn!`. The bound is principled: a tx included at the
//! latest possible moment within its `validity_range` gets `WAVE_TIMEOUT`
//! to terminate, so any provisions unacked past `MAX_VALIDITY_RANGE +
//! WAVE_TIMEOUT` reference a tx no shard could still be processing.

use crate::store::ProvisionStore;
use hyperscale_types::{
    BlockHeight, ProvisionHash, Provisions, ShardGroupId, TxHash, TxOutcome, WeightedTimestamp,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundMemoryStats {
    pub tracked_provisions: usize,
    pub tracked_tx_entries: usize,
}

struct OutboundEntry {
    target_shard: ShardGroupId,
    source_block_height: BlockHeight,
    pending_txs: HashSet<TxHash>,
    /// Hard deadline past which the provisions are provably useless: every
    /// tx in them has expired its `validity_range` and terminated.
    /// Computed once at insert from the latest BFT-authenticated
    /// `local_committed_ts` — conservatively ≥ the source block's true ts,
    /// so eviction never fires before the deadline has actually passed.
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
    /// Latest BFT-authenticated weighted timestamp seen on local commits.
    /// Drives the safety-timeout sweep deterministically across validators.
    now: WeightedTimestamp,
}

impl OutboundProvisionTracker {
    pub fn new(store: Arc<ProvisionStore>) -> Self {
        Self {
            store,
            entries: HashMap::new(),
            by_tx: HashMap::new(),
            now: WeightedTimestamp::ZERO,
        }
    }

    pub fn memory_stats(&self) -> OutboundMemoryStats {
        OutboundMemoryStats {
            tracked_provisions: self.entries.len(),
            tracked_tx_entries: self.by_tx.values().map(|s| s.len()).sum(),
        }
    }

    /// Register provisions our proposer just broadcast. Inserts into the
    /// shared store (which maintains the `(source_block, target)` index
    /// used by cross-shard fast-path serving); idempotent.
    pub fn on_broadcast(&mut self, provisions: Arc<Provisions>, target_shard: ShardGroupId) {
        let provision_hash = provisions.hash();
        if self.entries.contains_key(&provision_hash) {
            return;
        }

        let tx_hashes: HashSet<TxHash> = provisions
            .transactions
            .iter()
            .map(|tx| tx.tx_hash)
            .collect();
        if tx_hashes.is_empty() {
            return;
        }

        for tx in &tx_hashes {
            self.by_tx.entry(*tx).or_default().insert(provision_hash);
        }

        self.store
            .insert_outbound(Arc::clone(&provisions), target_shard);

        self.entries.insert(
            provision_hash,
            OutboundEntry {
                target_shard,
                source_block_height: provisions.block_height,
                pending_txs: tx_hashes,
                deadline: provisions.deadline(self.now),
            },
        );

        debug!(
            provision_hash = ?provision_hash,
            target_shard = target_shard.0,
            source_block_height = provisions.block_height.0,
            tx_count = provisions.transactions.len(),
            "Tracking outbound provisions"
        );
    }

    /// Drain every outbound entry awaiting any of `tx_outcomes` from
    /// `target_shard`. Entries whose pending set empties are evicted from
    /// the shared store.
    pub fn on_ec_observed(&mut self, target_shard: ShardGroupId, tx_outcomes: &[TxOutcome]) {
        let mut to_evict: Vec<ProvisionHash> = Vec::new();

        for outcome in tx_outcomes {
            let Some(hashes) = self.by_tx.get_mut(&outcome.tx_hash) else {
                continue;
            };
            hashes.retain(|provision_hash| {
                let Some(entry) = self.entries.get_mut(provision_hash) else {
                    return false;
                };
                if entry.target_shard != target_shard {
                    return true;
                }
                entry.pending_txs.remove(&outcome.tx_hash);
                if entry.pending_txs.is_empty() {
                    to_evict.push(*provision_hash);
                }
                false
            });
            if hashes.is_empty() {
                self.by_tx.remove(&outcome.tx_hash);
            }
        }

        for provision_hash in to_evict {
            self.evict(&provision_hash, "acknowledged");
        }
    }

    /// Safety sweep: evict outbound entries whose deadline has passed.
    /// Fires with `warn!` — a hit indicates the target shard never produced
    /// a terminal EC (upstream bug).
    pub fn on_block_committed(&mut self, now: WeightedTimestamp) {
        self.now = now;

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
                target_shard = entry.target_shard.0,
                source_block_height = entry.source_block_height.0,
                pending_txs = entry.pending_txs.len(),
                past_deadline_secs = now.elapsed_since(entry.deadline).as_secs(),
                "Evicting outbound provisions past deadline — no terminal EC observed"
            );
            self.evict(&provision_hash, "deadline-passed");
        }
    }

    fn evict(&mut self, provision_hash: &ProvisionHash, reason: &'static str) {
        let Some(entry) = self.entries.remove(provision_hash) else {
            return;
        };
        for tx in &entry.pending_txs {
            if let Some(hashes) = self.by_tx.get_mut(tx) {
                hashes.remove(provision_hash);
                if hashes.is_empty() {
                    self.by_tx.remove(tx);
                }
            }
        }
        self.store.evict(std::iter::once(*provision_hash));
        debug!(
            provision_hash = ?provision_hash,
            target_shard = entry.target_shard.0,
            reason,
            "Evicted outbound provisions"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        ExecutionOutcome, GlobalReceiptHash, Hash, MerkleInclusionProof, TxEntries,
        RETENTION_HORIZON,
    };
    use std::time::Duration;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn tx(label: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(label))
    }

    fn make_provisions(source_block: BlockHeight, txs: &[TxHash]) -> Arc<Provisions> {
        let transactions = txs
            .iter()
            .map(|h| TxEntries {
                tx_hash: *h,
                entries: vec![],
                target_nodes: vec![],
            })
            .collect();
        Arc::new(Provisions::new(
            ShardGroupId(0),
            source_block,
            MerkleInclusionProof::dummy(),
            transactions,
        ))
    }

    fn executed(tx_hash: TxHash) -> TxOutcome {
        TxOutcome {
            tx_hash,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::ZERO),
                success: true,
            },
        }
    }

    fn aborted(tx_hash: TxHash) -> TxOutcome {
        TxOutcome {
            tx_hash,
            outcome: ExecutionOutcome::Aborted,
        }
    }

    #[test]
    fn on_broadcast_stores_provisions_and_tracks_txs() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let b = tx(b"b");
        let provisions = make_provisions(BlockHeight(10), &[a, b]);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));

        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert_eq!(tracker.memory_stats().tracked_tx_entries, 2);
        assert!(store.get(&provision_hash).is_some());
        let hits = store.get_outbound(BlockHeight(10), ShardGroupId(1));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn executed_ec_evicts_when_all_txs_drained() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let b = tx(b"b");
        let provisions = make_provisions(BlockHeight(10), &[a, b]);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));

        tracker.on_ec_observed(ShardGroupId(1), &[executed(a)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert!(store.get(&provision_hash).is_some());

        tracker.on_ec_observed(ShardGroupId(1), &[executed(b)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 0);
        assert!(store.get(&provision_hash).is_none());
    }

    #[test]
    fn aborted_ec_is_terminal_and_evicts() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let provisions = make_provisions(BlockHeight(7), &[a]);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(2));

        tracker.on_ec_observed(ShardGroupId(2), &[aborted(a)]);
        assert!(store.get(&provision_hash).is_none());
    }

    #[test]
    fn ec_from_different_target_does_not_drain() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let provisions = make_provisions(BlockHeight(5), &[a]);
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));

        // EC from a different target shard must not acknowledge these provisions.
        tracker.on_ec_observed(ShardGroupId(2), &[executed(a)]);
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
    }

    #[test]
    fn safety_sweep_evicts_past_retention_max() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));
        tracker.on_block_committed(ts(1_000_000));

        let a = tx(b"a");
        let provisions = make_provisions(BlockHeight(5), &[a]);
        let provision_hash = provisions.hash();
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));

        let past_max = RETENTION_HORIZON + Duration::from_secs(1);
        tracker.on_block_committed(ts(1_000_000 + past_max.as_millis() as u64));
        assert!(store.get(&provision_hash).is_none());
        assert_eq!(tracker.memory_stats().tracked_provisions, 0);
    }

    #[test]
    fn on_broadcast_is_idempotent() {
        let store = Arc::new(ProvisionStore::new());
        let mut tracker = OutboundProvisionTracker::new(Arc::clone(&store));

        let a = tx(b"a");
        let provisions = make_provisions(BlockHeight(10), &[a]);
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));
        tracker.on_broadcast(Arc::clone(&provisions), ShardGroupId(1));
        assert_eq!(tracker.memory_stats().tracked_provisions, 1);
        assert_eq!(tracker.memory_stats().tracked_tx_entries, 1);
    }
}
