//! Tracker types for cross-shard cycle detection.
//!
//! These trackers maintain the state needed for detecting bidirectional
//! dependencies between shards that could cause livelock.

use hyperscale_types::{Hash, NodeId, ShardGroupId};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Information about a committed cross-shard transaction's remote state needs.
#[derive(Debug, Clone)]
pub struct RemoteStateNeeds {
    /// Which shards this TX needs provisions from.
    pub shards: BTreeSet<ShardGroupId>,
    /// Which specific NodeIds this TX needs from each shard.
    /// Maps shard -> set of NodeIds needed from that shard.
    pub nodes_by_shard: HashMap<ShardGroupId, HashSet<NodeId>>,
}

/// Tracks committed cross-shard transactions for cycle detection.
///
/// When a cross-shard transaction is committed, we need to know which shards
/// it requires provisions from AND which specific nodes (accounts) it needs.
/// This tracker maintains indexes for efficient lookups:
///
/// 1. Given a TX, which shards/nodes does it need provisions from?
/// 2. Given a shard, which TXs need provisions from it?
///
/// The second lookup is critical for cycle detection: when we receive a
/// provision from shard S, we can quickly find all local TXs that need S's
/// state, and check if they have overlapping node dependencies (true cycle).
#[derive(Debug, Default)]
pub struct CommittedCrossShardTracker {
    /// tx_hash -> remote state needs (shards and specific nodes)
    tx_needs: HashMap<Hash, RemoteStateNeeds>,
    /// Reverse index: shard -> tx_hashes that need provisions from it
    shards_needed_by: HashMap<ShardGroupId, HashSet<Hash>>,
}

impl CommittedCrossShardTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a transaction that needs provisions from the given shards with specific nodes.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction hash
    /// * `needs` - The remote state needs (shards and specific nodes)
    pub fn add(&mut self, tx_hash: Hash, needs: RemoteStateNeeds) {
        // Build reverse index
        for &shard in &needs.shards {
            self.shards_needed_by
                .entry(shard)
                .or_default()
                .insert(tx_hash);
        }

        // Store forward mapping
        self.tx_needs.insert(tx_hash, needs);
    }

    /// Remove a transaction (completed, deferred, or aborted).
    ///
    /// Cleans up both the forward and reverse indexes.
    pub fn remove(&mut self, tx_hash: &Hash) {
        if let Some(needs) = self.tx_needs.remove(tx_hash) {
            // Clean up reverse index
            for shard in needs.shards {
                if let Some(txs) = self.shards_needed_by.get_mut(&shard) {
                    txs.remove(tx_hash);
                    if txs.is_empty() {
                        self.shards_needed_by.remove(&shard);
                    }
                }
            }
        }
    }

    /// Get all TXs that need provisions from a specific shard.
    ///
    /// Used during cycle detection: when we receive a provision from shard S,
    /// we check if any of our committed TXs need provisions from S.
    pub fn txs_needing_shard(&self, shard: ShardGroupId) -> Option<&HashSet<Hash>> {
        self.shards_needed_by.get(&shard)
    }

    /// Get the nodes a transaction needs from a specific shard.
    ///
    /// Returns None if the TX isn't tracked or doesn't need anything from that shard.
    pub fn nodes_needed_from_shard(
        &self,
        tx_hash: &Hash,
        shard: ShardGroupId,
    ) -> Option<&HashSet<NodeId>> {
        self.tx_needs
            .get(tx_hash)
            .and_then(|needs| needs.nodes_by_shard.get(&shard))
    }

    /// Check if a transaction is being tracked.
    #[cfg(test)]
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.tx_needs.contains_key(tx_hash)
    }

    /// Get the shards a transaction needs provisions from.
    #[cfg(test)]
    pub fn shards_for_tx(&self, tx_hash: &Hash) -> Option<&BTreeSet<ShardGroupId>> {
        self.tx_needs.get(tx_hash).map(|n| &n.shards)
    }

    /// Get the number of transactions being tracked.
    pub fn len(&self) -> usize {
        self.tx_needs.len()
    }

    /// Check if the tracker is empty (clippy: len_without_is_empty).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tx_needs.is_empty()
    }
}

/// Tracks provisions for cycle detection and deduplication.
///
/// Records which (tx_hash, source_shard) pairs we've seen provisions for.
/// This serves two purposes:
///
/// 1. **Cycle detection**: When we receive a provision from shard S for TX_R,
///    we check if we have any local TXs that need provisions from S's shard.
///    If so, and S's TX needs provisions from us, we have a bidirectional cycle.
///
/// 2. **Deduplication**: We only process the first provision from each (tx, shard)
///    pair for cycle detection purposes. Subsequent provisions are for quorum
///    counting but don't trigger additional cycle checks.
#[derive(Debug, Default)]
pub struct ProvisionTracker {
    /// (tx_hash, source_shard) pairs we've seen.
    /// Only stores first provision per (tx, shard) pair.
    seen: HashSet<(Hash, ShardGroupId)>,
}

impl ProvisionTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a provision. Returns true if this is the first from this (tx, shard).
    ///
    /// The caller should only perform cycle detection if this returns true.
    pub fn add(&mut self, tx_hash: Hash, source_shard: ShardGroupId) -> bool {
        self.seen.insert((tx_hash, source_shard))
    }

    /// Get all TX hashes that have provisions from a specific shard.
    ///
    /// Returns the set of transactions that have received provisions from
    /// the given source shard. Used for cycle detection.
    #[cfg(test)]
    pub fn txs_with_provision_from(&self, source_shard: ShardGroupId) -> Vec<Hash> {
        self.seen
            .iter()
            .filter(|(_, s)| *s == source_shard)
            .map(|(h, _)| *h)
            .collect()
    }

    /// Remove all provisions for a transaction.
    ///
    /// Called when a transaction is completed, deferred, or aborted.
    pub fn remove_tx(&mut self, tx_hash: &Hash) {
        self.seen.retain(|(h, _)| h != tx_hash);
    }

    /// Check if we've seen any provision for a transaction from a specific shard.
    #[cfg(test)]
    pub fn has_provision(&self, tx_hash: Hash, source_shard: ShardGroupId) -> bool {
        self.seen.contains(&(tx_hash, source_shard))
    }

    /// Get the number of (tx, shard) pairs being tracked.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if the tracker is empty (clippy: len_without_is_empty).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(id: u8) -> NodeId {
        let mut bytes = [0u8; 30];
        bytes[0] = id;
        NodeId::from_bytes(&bytes)
    }

    #[test]
    fn test_committed_tracker_basic() {
        let mut tracker = CommittedCrossShardTracker::new();

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);
        let shard2 = ShardGroupId(2);

        let node_a = make_node_id(1);
        let node_b = make_node_id(2);
        let node_c = make_node_id(3);

        // tx1 needs provisions from shard0 (node_a) and shard1 (node_b)
        let needs1 = RemoteStateNeeds {
            shards: [shard0, shard1].into_iter().collect(),
            nodes_by_shard: [
                (shard0, [node_a].into_iter().collect()),
                (shard1, [node_b].into_iter().collect()),
            ]
            .into_iter()
            .collect(),
        };
        tracker.add(tx1, needs1);

        // tx2 needs provisions from shard1 (node_b) and shard2 (node_c)
        let needs2 = RemoteStateNeeds {
            shards: [shard1, shard2].into_iter().collect(),
            nodes_by_shard: [
                (shard1, [node_b].into_iter().collect()),
                (shard2, [node_c].into_iter().collect()),
            ]
            .into_iter()
            .collect(),
        };
        tracker.add(tx2, needs2);

        // Check forward lookups
        assert!(tracker.contains(&tx1));
        assert!(tracker.contains(&tx2));
        assert_eq!(
            tracker.shards_for_tx(&tx1),
            Some(&[shard0, shard1].into_iter().collect())
        );

        // Check reverse lookups
        assert_eq!(
            tracker.txs_needing_shard(shard0),
            Some(&[tx1].into_iter().collect())
        );
        assert_eq!(
            tracker.txs_needing_shard(shard1),
            Some(&[tx1, tx2].into_iter().collect())
        );
        assert_eq!(
            tracker.txs_needing_shard(shard2),
            Some(&[tx2].into_iter().collect())
        );

        // Check node lookups
        assert_eq!(
            tracker.nodes_needed_from_shard(&tx1, shard0),
            Some(&[node_a].into_iter().collect())
        );
        assert_eq!(
            tracker.nodes_needed_from_shard(&tx1, shard1),
            Some(&[node_b].into_iter().collect())
        );
        assert_eq!(
            tracker.nodes_needed_from_shard(&tx2, shard1),
            Some(&[node_b].into_iter().collect())
        );

        // Remove tx1
        tracker.remove(&tx1);
        assert!(!tracker.contains(&tx1));
        assert!(tracker.txs_needing_shard(shard0).is_none());
        assert_eq!(
            tracker.txs_needing_shard(shard1),
            Some(&[tx2].into_iter().collect())
        );
    }

    #[test]
    fn test_provision_tracker_basic() {
        let mut tracker = ProvisionTracker::new();

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);

        // First provision from shard0 for tx1 returns true
        assert!(tracker.add(tx1, shard0));

        // Second provision from shard0 for tx1 returns false (already seen)
        assert!(!tracker.add(tx1, shard0));

        // First provision from shard1 for tx1 returns true (different shard)
        assert!(tracker.add(tx1, shard1));

        // First provision from shard0 for tx2 returns true (different tx)
        assert!(tracker.add(tx2, shard0));

        // Check lookups
        let from_shard0 = tracker.txs_with_provision_from(shard0);
        assert!(from_shard0.contains(&tx1));
        assert!(from_shard0.contains(&tx2));

        // Remove tx1
        tracker.remove_tx(&tx1);
        assert!(!tracker.has_provision(tx1, shard0));
        assert!(tracker.has_provision(tx2, shard0));
    }
}
