//! The active shard partition: a binary trie over the `blake3(node_id)`
//! keyspace whose leaves are the live shards.
//!
//! Every node id routes to exactly one shard by walking the trie from the root
//! along its hash bits (most-significant first) until it reaches a leaf —
//! longest-prefix match. A node id's shard prefix is therefore a prefix of its
//! JMT leaf key, so a shard owns a contiguous subtree of the global state tree.

use std::collections::BTreeSet;

use blake3::hash as blake3_hash;

use crate::{NodeId, ShardGroupId};

/// The set of live shards, forming a complete partition of the keyspace: every
/// infinite bit path from the root passes through exactly one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardTrie {
    leaves: BTreeSet<ShardGroupId>,
}

impl ShardTrie {
    /// The single-shard trie: the root owns the whole keyspace.
    #[must_use]
    pub fn single() -> Self {
        Self {
            leaves: BTreeSet::from([ShardGroupId::ROOT]),
        }
    }

    /// A uniform trie with `2^depth` leaves, all at `depth`.
    #[must_use]
    pub fn uniform(depth: u32) -> Self {
        let count = 1u64 << depth;
        Self {
            leaves: (0..count).map(|p| ShardGroupId::leaf(depth, p)).collect(),
        }
    }

    /// A uniform trie with `count` leaves.
    ///
    /// # Panics
    /// Panics if `count` is not a power of two (a uniform binary trie only has
    /// power-of-two leaf counts).
    #[must_use]
    pub fn uniform_from_count(count: u64) -> Self {
        assert!(count > 0, "shard count must be positive");
        assert!(
            count.is_power_of_two(),
            "uniform shard count must be a power of two, got {count}"
        );
        Self::uniform(count.trailing_zeros())
    }

    /// Build a trie directly from a leaf set. The caller asserts the leaves
    /// form a complete partition.
    #[must_use]
    pub fn from_leaves(leaves: impl IntoIterator<Item = ShardGroupId>) -> Self {
        Self {
            leaves: leaves.into_iter().collect(),
        }
    }

    /// The shard owning `node_id`, by longest-prefix match.
    ///
    /// # Panics
    /// Panics if the trie is not a complete partition (a hash path descends
    /// past `depth 63` without hitting a leaf).
    #[must_use]
    pub fn shard_for(&self, node_id: &NodeId) -> ShardGroupId {
        let hash = blake3_hash(&node_id.0);
        let bits = u64::from_be_bytes(
            hash.as_bytes()[..8]
                .try_into()
                .expect("blake3 output is 32 bytes"),
        );
        let mut id = ShardGroupId::ROOT;
        loop {
            if self.leaves.contains(&id) {
                return id;
            }
            let depth = id.depth();
            assert!(depth < 64, "shard trie is not a complete partition");
            let bit = (bits >> (63 - depth)) & 1;
            let (left, right) = id.children();
            id = if bit == 0 { left } else { right };
        }
    }

    /// The live shards, in heap-index order.
    #[must_use]
    pub fn leaves(&self) -> impl ExactSizeIterator<Item = ShardGroupId> + '_ {
        self.leaves.iter().copied()
    }

    /// Number of live shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the trie has no shards (never true for a valid partition).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Whether `shard` is a live leaf.
    #[must_use]
    pub fn contains(&self, shard: ShardGroupId) -> bool {
        self.leaves.contains(&shard)
    }

    /// Split a leaf into its two children, returning them.
    ///
    /// # Panics
    /// Panics if `shard` is not a live leaf.
    pub fn split(&mut self, shard: ShardGroupId) -> (ShardGroupId, ShardGroupId) {
        assert!(self.leaves.remove(&shard), "split of non-leaf {shard:?}");
        let (left, right) = shard.children();
        self.leaves.insert(left);
        self.leaves.insert(right);
        (left, right)
    }

    /// Merge two sibling leaves back into their parent, returning it.
    ///
    /// # Panics
    /// Panics if the two shards are not live sibling leaves.
    pub fn merge(&mut self, left: ShardGroupId, right: ShardGroupId) -> ShardGroupId {
        assert_eq!(
            left.sibling(),
            Some(right),
            "{left:?} and {right:?} are not siblings"
        );
        assert!(self.leaves.remove(&left), "merge of non-leaf {left:?}");
        assert!(self.leaves.remove(&right), "merge of non-leaf {right:?}");
        let parent = left.parent().expect("non-root leaf has a parent");
        self.leaves.insert(parent);
        parent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_routes_everything_to_root() {
        let trie = ShardTrie::single();
        assert_eq!(trie.len(), 1);
        assert_eq!(trie.shard_for(&NodeId([1; 30])), ShardGroupId::ROOT);
        assert_eq!(trie.shard_for(&NodeId([0xff; 30])), ShardGroupId::ROOT);
    }

    #[test]
    fn uniform_partitions_by_top_bits() {
        let trie = ShardTrie::uniform(1);
        assert_eq!(trie.len(), 2);
        // Every node lands on one of the two depth-1 leaves, by its hash MSB.
        for seed in 0u8..32 {
            let shard = trie.shard_for(&NodeId([seed; 30]));
            assert_eq!(shard.depth(), 1);
            assert!(trie.contains(shard));
        }
    }

    #[test]
    fn uniform_from_count_requires_power_of_two() {
        assert_eq!(ShardTrie::uniform_from_count(4).len(), 4);
        assert_eq!(ShardTrie::uniform_from_count(1), ShardTrie::single());
    }

    #[test]
    fn split_then_merge_round_trips() {
        let mut trie = ShardTrie::single();
        let (l, r) = trie.split(ShardGroupId::ROOT);
        assert_eq!(trie.len(), 2);
        assert!(trie.contains(l) && trie.contains(r));
        let parent = trie.merge(l, r);
        assert_eq!(parent, ShardGroupId::ROOT);
        assert_eq!(trie, ShardTrie::single());
    }

    #[test]
    fn shard_for_matches_a_uniform_leaf_prefix() {
        // The routed shard's path equals the top `depth` bits of the hash.
        let trie = ShardTrie::uniform(3);
        let node = NodeId([0xab; 30]);
        let shard = trie.shard_for(&node);
        let hash = blake3_hash(&node.0);
        let bits = u64::from_be_bytes(hash.as_bytes()[..8].try_into().unwrap());
        assert_eq!(shard.path(), bits >> (64 - 3));
    }

    #[test]
    fn non_uniform_split_to_three_routes_by_longest_prefix() {
        // 1 shard → split the root → 2 → split one child → 3 leaves at mixed
        // depths: a non-power-of-two partition reached by surgical splits.
        let mut trie = ShardTrie::single();
        let (left, right) = trie.split(ShardGroupId::ROOT);
        let (left0, left1) = trie.split(left);
        assert_eq!(trie.len(), 3);
        assert_eq!(right, ShardGroupId::leaf(1, 1));
        assert_eq!(left0, ShardGroupId::leaf(2, 0));
        assert_eq!(left1, ShardGroupId::leaf(2, 1));

        // Every node resolves to exactly one leaf by its hash's longest
        // matching prefix: top bit 1 → the depth-1 leaf; top bit 0 → the
        // depth-2 leaf chosen by the second bit.
        for seed in 0u8..=255 {
            let node = NodeId([seed; 30]);
            let bits = u64::from_be_bytes(blake3_hash(&node.0).as_bytes()[..8].try_into().unwrap());
            let expected = if (bits >> 63) & 1 == 1 {
                ShardGroupId::leaf(1, 1)
            } else {
                ShardGroupId::leaf(2, (bits >> 62) & 1)
            };
            assert_eq!(trie.shard_for(&node), expected, "seed {seed}");
        }

        // Merging the two depth-2 leaves restores the 2-shard partition.
        assert_eq!(trie.merge(left0, left1), ShardGroupId::leaf(1, 0));
        assert_eq!(trie.len(), 2);
    }
}
