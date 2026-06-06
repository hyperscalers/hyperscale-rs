//! Per-shard buffer for cross-shard artifacts awaiting their committee's epoch.
//!
//! When [`TopologySchedule::at`](crate::TopologySchedule::at) returns `None` for
//! an artifact's weighted timestamp, this node's beacon hasn't committed that
//! epoch yet and the signing committee can't be resolved. Coordinators park the
//! artifact here, keyed by its source shard, and replay every buffered item on
//! `BeaconBlockPersisted` once the beacon catches up.

use std::collections::{HashMap, VecDeque};

use crate::ShardId;

/// Per-shard cap on artifacts buffered awaiting their committee's epoch.
/// Drop-oldest past this bound; a node this far behind re-fetches the dropped
/// artifacts through normal sync regardless. Node-local cache bound, not
/// consensus-critical.
const MAX_AWAITING_TOPOLOGY_PER_SHARD: usize = 256;

/// Bounded per-shard buffer of artifacts whose signing committee this node's
/// beacon hasn't reached yet.
///
/// Generic over the buffered value `V`. The source shard is derived from `V`
/// differently per artifact, so the caller computes it and hands it to
/// [`push`](Self::push); the buffer stays agnostic to `V`'s shape.
/// [`drain`](Self::drain) flattens every per-shard queue for replay and
/// discards the shard key, which replay re-derives.
pub struct AwaitingTopologyBuffer<V> {
    by_shard: HashMap<ShardId, VecDeque<V>>,
}

impl<V> Default for AwaitingTopologyBuffer<V> {
    fn default() -> Self {
        Self {
            by_shard: HashMap::new(),
        }
    }
}

impl<V> AwaitingTopologyBuffer<V> {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer `value` under `shard`, evicting the oldest entries while the
    /// shard's queue exceeds the per-shard cap.
    pub fn push(&mut self, shard: ShardId, value: V) {
        let queue = self.by_shard.entry(shard).or_default();
        queue.push_back(value);
        while queue.len() > MAX_AWAITING_TOPOLOGY_PER_SHARD {
            queue.pop_front();
        }
    }

    /// Remove and return every buffered value across all shards. The shard key
    /// is dropped; replay re-derives it from each value.
    pub fn drain(&mut self) -> Vec<V> {
        self.by_shard.drain().flat_map(|(_, queue)| queue).collect()
    }

    /// Total buffered count across all shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_shard.values().map(VecDeque::len).sum()
    }

    /// Whether no values are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_shard.values().all(VecDeque::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_then_drain_returns_all_values_across_shards() {
        let mut buf: AwaitingTopologyBuffer<u32> = AwaitingTopologyBuffer::new();
        buf.push(ShardId::leaf(1, 0), 1);
        buf.push(ShardId::leaf(1, 0), 2);
        buf.push(ShardId::leaf(1, 1), 3);
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_empty());

        let mut drained = buf.drain();
        drained.sort_unstable();
        assert_eq!(drained, vec![1, 2, 3]);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn push_drops_oldest_past_the_per_shard_cap() {
        let mut buf: AwaitingTopologyBuffer<usize> = AwaitingTopologyBuffer::new();
        let shard = ShardId::leaf(1, 0);
        for i in 0..MAX_AWAITING_TOPOLOGY_PER_SHARD + 5 {
            buf.push(shard, i);
        }
        assert_eq!(buf.len(), MAX_AWAITING_TOPOLOGY_PER_SHARD);

        let mut drained = buf.drain();
        drained.sort_unstable();
        // The first five pushes were evicted; the tail survives.
        assert_eq!(drained.first(), Some(&5));
        assert_eq!(drained.last(), Some(&(MAX_AWAITING_TOPOLOGY_PER_SHARD + 4)));
    }

    #[test]
    fn cap_is_independent_per_shard() {
        let mut buf: AwaitingTopologyBuffer<usize> = AwaitingTopologyBuffer::new();
        for i in 0..MAX_AWAITING_TOPOLOGY_PER_SHARD + 10 {
            buf.push(ShardId::leaf(1, 0), i);
            buf.push(ShardId::leaf(1, 1), i);
        }
        // Each shard is capped on its own; the cap doesn't pool across shards.
        assert_eq!(buf.len(), 2 * MAX_AWAITING_TOPOLOGY_PER_SHARD);
    }
}
