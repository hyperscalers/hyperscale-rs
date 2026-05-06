//! Proposal queue for verified provisions awaiting block inclusion.
//!
//! Filtered at read time by a configured dwell window so peers have a
//! chance to receive/verify the same provisions via gossip before the
//! local proposer includes them.
//!
//! Re-admission of already-committed provisions is rejected upstream by
//! BFT (`validate_no_duplicate_provisions`) and at receipt
//! (`deadline <= local_ts`); the queue itself only owns the
//! candidate-set bookkeeping. All eviction triggers come from the
//! coordinator's `on_block_committed` and `drop_past_deadline`. Pure
//! data structures here — no topology, no time source.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{LocalTimestamp, ProvisionHash, Provisions, WeightedTimestamp};

/// A queued provisions entry awaiting block inclusion. `added_at` drives
/// dwell-time filtering; `source_block_ts` anchors deadline-based eviction
/// via [`Provision::deadline`].
#[derive(Debug, Clone)]
struct QueuedProvision {
    provisions: Arc<Provisions>,
    added_at: LocalTimestamp,
    source_block_ts: WeightedTimestamp,
}

/// Proposal queue for verified provisions.
#[derive(Debug)]
pub struct QueuedProvisionBuffer {
    queue: Vec<QueuedProvision>,
    min_dwell_time: Duration,
}

impl QueuedProvisionBuffer {
    pub(crate) const fn new(min_dwell_time: Duration) -> Self {
        Self {
            queue: Vec::new(),
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

    /// Drop committed provisions from the proposer queue so the next
    /// proposal doesn't re-include them.
    pub(crate) fn on_block_committed(&mut self, committed_hashes: &HashSet<ProvisionHash>) {
        if committed_hashes.is_empty() {
            return;
        }
        self.queue
            .retain(|q| !committed_hashes.contains(&q.provisions.hash()));
    }

    /// Drop queued provisions whose deadline has passed `now`.
    pub(crate) fn drop_past_deadline(&mut self, now: WeightedTimestamp) {
        self.queue
            .retain(|q| q.provisions.deadline(q.source_block_ts) > now);
    }

    /// Provisions eligible for block inclusion at `now`. Skips entries
    /// that haven't satisfied the configured dwell window yet — they stay
    /// in the queue for a later call. Also filters past-deadline entries
    /// so a proposer that hasn't committed since the deadline crossed
    /// (e.g. mid-round-timeout) cannot pull stale provisions into a
    /// proposal that peers will reject as missing.
    pub(crate) fn queued(
        &self,
        now: LocalTimestamp,
        weighted_now: WeightedTimestamp,
    ) -> Vec<Arc<Provisions>> {
        self.queue
            .iter()
            .filter(|q| now.saturating_sub(q.added_at) >= self.min_dwell_time)
            .filter(|q| q.provisions.deadline(q.source_block_ts) > weighted_now)
            .map(|q| Arc::clone(&q.provisions))
            .collect()
    }

    pub(crate) const fn queue_len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BlockHeight, Hash, MerkleInclusionProof, ShardGroupId, TxEntries, TxHash,
    };

    use super::*;

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
            ShardGroupId(0),
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
        assert!(buf.queued(local(0), ts(0)).is_empty());
    }

    #[test]
    fn enqueue_then_queued_with_zero_dwell_returns_immediately() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight::new(10));
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(100));
        assert_eq!(buf.queued(local(100), ts(1_000)).len(), 1);
    }

    #[test]
    fn dwell_filter_skips_young_provisions() {
        let mut buf = QueuedProvisionBuffer::new(Duration::from_millis(500));
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight::new(10));
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(0));
        assert!(buf.queued(local(100), ts(1_000)).is_empty());
        assert_eq!(buf.queued(local(500), ts(1_000)).len(), 1);
    }

    #[test]
    fn deadline_filter_skips_past_deadline_provisions() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight::new(10));
        let source_ts = ts(1_000);
        buf.enqueue(Arc::clone(&provisions), source_ts, local(0));
        let live = provisions.deadline(source_ts);
        assert_eq!(
            buf.queued(local(0), live.minus(Duration::from_millis(1)))
                .len(),
            1,
            "before deadline: included"
        );
        assert!(
            buf.queued(local(0), live).is_empty(),
            "at deadline: excluded"
        );
    }

    #[test]
    fn on_block_committed_drops_matching_queue_entries() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight::new(10));
        let hash = provisions.hash();
        buf.enqueue(Arc::clone(&provisions), ts(1_000), local(0));

        let committed: HashSet<_> = std::iter::once(hash).collect();
        buf.on_block_committed(&committed);

        assert_eq!(buf.queue_len(), 0);
    }

    #[test]
    fn drop_past_deadline_evicts_aged_provisions() {
        let mut buf = QueuedProvisionBuffer::new(Duration::ZERO);
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight::new(10));
        let source_block_ts = ts(1_000);
        buf.enqueue(Arc::clone(&provisions), source_block_ts, local(0));

        let well_past = ts(1_000 + provisions.deadline(source_block_ts).as_millis() + 1);
        buf.drop_past_deadline(well_past);
        assert_eq!(buf.queue_len(), 0);
    }
}
