//! Proposal queue + commit tombstones.
//!
//! Holds verified provisions the local proposer is eligible to include in
//! its next block, filtered at read time by a configured dwell window so
//! peers have a chance to receive/verify the same provisions via gossip.
//!
//! Pairs with a tombstone set: hashes of provisions that have already
//! landed in a locally committed block. The tombstone gates duplicate
//! gossip after commit and lets the receive path reject re-arrivals
//! without re-queueing.
//!
//! All eviction triggers come from the coordinator's `on_block_committed`
//! and `drop_past_deadline`. Pure data structures here — no topology, no
//! time source.

use hyperscale_types::{LocalTimestamp, ProvisionHash, Provisions, WeightedTimestamp};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// A queued provisions entry awaiting block inclusion. `added_at` drives
/// dwell-time filtering; `source_block_ts` anchors deadline-based eviction
/// via [`Provision::deadline`].
#[derive(Debug, Clone)]
struct QueuedProvision {
    provisions: Arc<Provisions>,
    added_at: LocalTimestamp,
    source_block_ts: WeightedTimestamp,
}

/// Proposal queue + tombstone set for committed provisions.
#[derive(Debug)]
pub(crate) struct QueuedProvisionBuffer {
    queue: Vec<QueuedProvision>,
    tombstones: HashMap<ProvisionHash, WeightedTimestamp>,
    min_dwell_time: Duration,
}

impl QueuedProvisionBuffer {
    pub(crate) fn new(min_dwell_time: Duration) -> Self {
        Self {
            queue: Vec::new(),
            tombstones: HashMap::new(),
            min_dwell_time,
        }
    }

    /// Push verified provisions onto the proposal queue.
    pub(crate) fn enqueue(
        &mut self,
        provisions: Arc<Provisions>,
        source_block_ts: WeightedTimestamp,
        added_at: LocalTimestamp,
    ) {
        self.queue.push(QueuedProvision {
            provisions,
            added_at,
            source_block_ts,
        });
    }

    /// Has this provision hash already been committed?
    pub(crate) fn is_tombstoned(&self, hash: &ProvisionHash) -> bool {
        self.tombstones.contains_key(hash)
    }

    /// Tombstone every committed provisions hash and drop any matching
    /// queue entry so the proposer doesn't re-include provisions already
    /// in the chain.
    pub(crate) fn on_block_committed(
        &mut self,
        committed_hashes: &HashSet<ProvisionHash>,
        local_ts: WeightedTimestamp,
    ) {
        if committed_hashes.is_empty() {
            return;
        }
        for h in committed_hashes {
            self.tombstones.insert(*h, local_ts);
        }
        self.queue
            .retain(|q| !committed_hashes.contains(&q.provisions.hash()));
    }

    /// Drop tombstones older than `cutoff`.
    pub(crate) fn prune_tombstones(&mut self, cutoff: WeightedTimestamp) {
        self.tombstones
            .retain(|_, committed_at_ts| *committed_at_ts > cutoff);
    }

    /// Drop queued provisions whose deadline has passed `now`.
    pub(crate) fn drop_past_deadline(&mut self, now: WeightedTimestamp) {
        self.queue
            .retain(|q| q.provisions.deadline(q.source_block_ts) > now);
    }

    /// Provisions eligible for block inclusion at `now`. Skips entries
    /// that haven't satisfied the configured dwell window yet — they stay
    /// in the queue for a later call.
    pub(crate) fn queued(&self, now: LocalTimestamp) -> Vec<Arc<Provisions>> {
        self.queue
            .iter()
            .filter(|q| now.saturating_sub(q.added_at) >= self.min_dwell_time)
            .map(|q| Arc::clone(&q.provisions))
            .collect()
    }

    pub(crate) fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub(crate) fn tombstone_len(&self) -> usize {
        self.tombstones.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeight, Hash, MerkleInclusionProof, ShardGroupId, TxEntries, TxHash,
    };

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn local(ms: u64) -> LocalTimestamp {
        LocalTimestamp::from_millis(ms)
    }

    fn make_provisions(
        seed: u8,
        source_shard: ShardGroupId,
        height: BlockHeight,
    ) -> Arc<Provisions> {
        Arc::new(Provisions::new(
            source_shard,
            height,
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed])),
                entries: vec![],
                target_nodes: vec![],
            }],
        ))
    }

    #[test]
    fn empty_queue_yields_nothing() {
        let buf = QueuedProvisionBuffer::new(Duration::ZERO);
        assert_eq!(buf.queue_len(), 0);
        assert_eq!(buf.tombstone_len(), 0);
        assert!(buf.queued(local(0)).is_empty());
    }

    #[test]
    fn enqueue_then_queued_with_zero_dwell_returns_immediately() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(100));
        assert_eq!(buf.queued(local(100)).len(), 1);
    }

    #[test]
    fn dwell_filter_skips_young_provisions() {
        let mut buf = QueuedProvisionBuffer::new(Duration::from_millis(500));
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(0));
        assert!(buf.queued(local(100)).is_empty());
        assert_eq!(buf.queued(local(500)).len(), 1);
    }

    #[test]
    fn on_block_committed_tombstones_and_prunes() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        let hash = provisions.hash();
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(0));

        let committed: HashSet<_> = [hash].into_iter().collect();
        buf.on_block_committed(&committed, ts(2_000));

        assert!(buf.is_tombstoned(&hash));
        assert_eq!(buf.queue_len(), 0);
    }

    #[test]
    fn prune_tombstones_drops_old_entries() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        let hash = provisions.hash();
        let committed: HashSet<_> = [hash].into_iter().collect();
        buf.on_block_committed(&committed, ts(1_000));
        assert!(buf.is_tombstoned(&hash));

        buf.prune_tombstones(ts(2_000));
        assert!(!buf.is_tombstoned(&hash));
    }

    #[test]
    fn drop_past_deadline_evicts_aged_provisions() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        let source_block_ts = ts(1_000);
        buf.enqueue(Arc::clone(&provisions), source_block_ts, local(0));

        let well_past = ts(1_000 + provisions.deadline(source_block_ts).as_millis() + 1);
        buf.drop_past_deadline(well_past);
        assert_eq!(buf.queue_len(), 0);
    }
}
