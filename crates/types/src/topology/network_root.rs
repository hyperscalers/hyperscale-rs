//! Network state root: the single logical global-JMT root reconstituted from
//! per-shard subtree roots.
//!
//! Node-major JMT keying ([`crate::state_key`]) makes every shard a contiguous
//! prefix subtree of one logical global tree, so a shard's `state_root` is the
//! root of that tree's subtree at the shard's prefix. Combining sibling subtree
//! roots up the [`ShardTrie`] with the JMT's own internal-node hash rule
//! reconstitutes the global root — which is what lets a cross-shard state proof
//! be one continuous Merkle path: key → its shard subtree root → network root.
//!
//! The combine *is* the JMT internal hashing (not an opaque `hash(r0 ‖ r1 ‖ …)`),
//! so the result is provable-into. It is well-defined at an epoch boundary,
//! where each shard's "final block of the epoch" fixes its subtree root.

use std::collections::BTreeMap;

use hyperscale_jmt::{Blake3Hasher, Hasher, NibblePath};

use crate::{Hash, ShardId, ShardTrie, StateRoot};

/// The network state root for `trie`: the global-JMT root obtained by combining
/// each shard leaf's `state_root` up the trie with the JMT internal-node hash.
///
/// `shard_root` supplies each leaf's subtree root. A leaf with no entry
/// contributes [`StateRoot::ZERO`] — the JMT empty-subtree sentinel — so callers
/// consuming the result as a commitment must ensure every active shard has
/// reported a root for the epoch.
#[must_use]
pub fn network_state_root(
    trie: &ShardTrie,
    shard_root: &BTreeMap<ShardId, StateRoot>,
) -> StateRoot {
    combine(trie, shard_root, ShardId::ROOT)
}

/// Combine the subtree at `node`: a trie leaf yields its shard root; an internal
/// node yields the JMT internal hash of its two children's combined roots.
///
/// Terminates because a [`ShardTrie`] is a complete partition — every root-to-leaf
/// bit path reaches a leaf — so the recursion descends at most to the deepest leaf.
fn combine(
    trie: &ShardTrie,
    shard_root: &BTreeMap<ShardId, StateRoot>,
    node: ShardId,
) -> StateRoot {
    if trie.contains(node) {
        return shard_root.get(&node).copied().unwrap_or(StateRoot::ZERO);
    }
    let (left, right) = node.children();
    let l = combine(trie, shard_root, left);
    let r = combine(trie, shard_root, right);
    let hash = Blake3Hasher::hash_internal(&[*l.as_bytes(), *r.as_bytes()]);
    StateRoot::from_raw(Hash::from_hash_bytes(&hash))
}

/// The JMT root path a shard's state tree is rooted at: the shard's `depth`-bit
/// prefix as a [`NibblePath`].
///
/// Rooting a shard's tree here makes its `state_root` the global tree's subtree
/// root at that prefix, so [`network_state_root`] reconstitutes the global root
/// (and a split re-roots a child onto the parent's existing subtree node — no
/// state copy). [`ShardId::ROOT`] yields the empty path (whole keyspace).
#[must_use]
pub fn shard_prefix_path(shard: ShardId) -> NibblePath {
    let depth = shard.depth();
    let path = shard.path(); // top `depth` bits hold the prefix, left-aligned
    let mut prefix = NibblePath::empty();
    let mut taken = 0u32;
    while taken < depth {
        let count = (depth - taken).min(8);
        let shift = 64 - taken - count;
        // `chunk` is masked to `count <= 8` bits and `count <= 8`, so both
        // conversions are exact; `unwrap_or` keeps this panic-free regardless.
        let chunk = u8::try_from((path >> shift) & ((1u64 << count) - 1)).unwrap_or(0);
        prefix.push_bits(chunk, u8::try_from(count).unwrap_or(8));
        taken += count;
    }
    prefix
}

#[cfg(test)]
mod tests {
    use blake3::hash as blake3_hash;
    use hyperscale_jmt::{MemoryStore, Tree};

    use super::*;

    type Jmt = Tree<Blake3Hasher, 1>;

    /// A 32-byte key whose top `shard.depth()` bits equal `shard.path()` (so it
    /// routes to `shard` under longest-prefix match), with the remaining bits
    /// pseudo-randomly varied by `i` so keys branch realistically within a shard.
    fn key_in_shard(shard: ShardId, i: u64) -> [u8; 32] {
        let mut seed = [0u8; 16];
        seed[..8].copy_from_slice(&shard.inner().to_be_bytes());
        seed[8..].copy_from_slice(&i.to_be_bytes());
        let mut key = *blake3_hash(&seed).as_bytes();
        let depth = shard.depth();
        if depth > 0 {
            let mut top = u64::from_be_bytes(key[..8].try_into().unwrap());
            let keep_mask = u64::MAX >> depth; // zeros in the top `depth` bits
            top = (top & keep_mask) | (shard.path() << (64 - depth));
            key[..8].copy_from_slice(&top.to_be_bytes());
        }
        key
    }

    /// Root of a one-shot JMT over `updates`, rooted at `root_path` (single
    /// version; no parent). Empty path = whole-keyspace (monolithic) tree;
    /// a shard prefix = that shard's subtree root.
    fn jmt_root_at(
        root_path: &NibblePath,
        updates: &BTreeMap<[u8; 32], Option<[u8; 32]>>,
    ) -> [u8; 32] {
        let store = MemoryStore::new();
        Jmt::apply_updates_at(&store, None, 1, root_path, updates)
            .expect("apply_updates_at")
            .root_hash
    }

    /// Route a raw 32-byte key to its leaf by walking the trie on the key's own
    /// top bits (mirrors `ShardTrie::shard_for`, sans the node-id hashing step).
    fn shard_for_key_bits(trie: &ShardTrie, key: &[u8; 32]) -> ShardId {
        let bits = u64::from_be_bytes(key[..8].try_into().unwrap());
        let mut id = ShardId::ROOT;
        loop {
            if trie.contains(id) {
                return id;
            }
            let bit = (bits >> (63 - id.depth())) & 1;
            let (l, r) = id.children();
            id = if bit == 0 { l } else { r };
        }
    }

    /// The keystone property: combining each shard's independently-built subtree
    /// root up the trie equals the root of one monolithic JMT over every key.
    fn assert_identity(trie: &ShardTrie, keys_per_shard: u64) {
        let mut all: BTreeMap<[u8; 32], Option<[u8; 32]>> = BTreeMap::new();
        let mut per_shard: BTreeMap<ShardId, BTreeMap<[u8; 32], Option<[u8; 32]>>> =
            BTreeMap::new();

        for leaf in trie.leaves() {
            for i in 0..keys_per_shard {
                let key = key_in_shard(leaf, i);
                let value = *blake3_hash(&key).as_bytes();
                assert_eq!(
                    shard_for_key_bits(trie, &key),
                    leaf,
                    "key routed to wrong shard"
                );
                all.insert(key, Some(value));
                per_shard.entry(leaf).or_default().insert(key, Some(value));
            }
        }

        // Monolithic tree: whole keyspace, rooted at the empty path.
        let global = jmt_root_at(&NibblePath::empty(), &all);
        // Each shard's subtree: rooted at the shard's prefix, so its root is the
        // global tree's subtree node at that prefix.
        let shard_roots: BTreeMap<ShardId, StateRoot> = trie
            .leaves()
            .map(|leaf| {
                let keys = per_shard.get(&leaf).expect("every shard is non-empty");
                let root = jmt_root_at(&shard_prefix_path(leaf), keys);
                (leaf, StateRoot::from_raw(Hash::from_hash_bytes(&root)))
            })
            .collect();

        let combined = network_state_root(trie, &shard_roots);
        assert_eq!(
            combined.as_bytes(),
            &global,
            "combine != monolithic global root"
        );
    }

    #[test]
    fn combine_equals_monolithic_uniform() {
        assert_identity(&ShardTrie::uniform(1), 16);
        assert_identity(&ShardTrie::uniform(2), 12);
        assert_identity(&ShardTrie::uniform(3), 8);
    }

    #[test]
    fn combine_equals_monolithic_non_uniform() {
        // Surgical splits to a {depth-1, depth-2, depth-2} partition — leaves at
        // mixed depths, reached the way resharding reaches a non-power-of-two trie.
        let mut trie = ShardTrie::single();
        let (left, _right) = trie.split(ShardId::ROOT);
        trie.split(left);
        assert_eq!(trie.len(), 3);
        assert_identity(&trie, 10);
    }

    #[test]
    fn single_shard_network_root_is_the_shard_root() {
        let trie = ShardTrie::single();
        let r = StateRoot::from_raw(Hash::from_hash_bytes(&[7u8; 32]));
        let roots = BTreeMap::from([(ShardId::ROOT, r)]);
        assert_eq!(network_state_root(&trie, &roots), r);
    }

    #[test]
    fn determinism_across_anchor_insertion_order() {
        // The combine reads a BTreeMap, so it is order-independent by
        // construction; assert the same shard→root mapping built in opposite
        // insertion orders gives byte-identical roots.
        let trie = ShardTrie::uniform(2);
        let leaves: Vec<ShardId> = trie.leaves().collect();
        let mk = |seed: u8| StateRoot::from_raw(Hash::from_hash_bytes(&[seed; 32]));

        let mut forward = BTreeMap::new();
        for (i, s) in leaves.iter().enumerate() {
            forward.insert(*s, mk(u8::try_from(i).expect("few leaves")));
        }
        let mut reverse = BTreeMap::new();
        for (i, s) in leaves.iter().enumerate().rev() {
            reverse.insert(*s, mk(u8::try_from(i).expect("few leaves")));
        }
        assert_eq!(
            network_state_root(&trie, &forward),
            network_state_root(&trie, &reverse)
        );
    }

    #[test]
    fn missing_shard_contributes_empty_sentinel() {
        // A leaf absent from the anchor map combines as StateRoot::ZERO.
        let trie = ShardTrie::uniform(1);
        let r0 = StateRoot::from_raw(Hash::from_hash_bytes(&[3u8; 32]));
        let roots = BTreeMap::from([(ShardId::leaf(1, 0), r0)]);
        let expected = StateRoot::from_raw(Hash::from_hash_bytes(&Blake3Hasher::hash_internal(&[
            *r0.as_bytes(),
            *StateRoot::ZERO.as_bytes(),
        ])));
        assert_eq!(network_state_root(&trie, &roots), expected);
    }
}
