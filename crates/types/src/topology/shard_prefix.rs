//! Shard prefix paths: the JMT root path a shard's state tree is rooted at.
//!
//! Node-major JMT keying ([`crate::state_key`]) makes every shard a contiguous
//! prefix subtree of one logical global tree, so a shard's `state_root` is the
//! root of that tree's subtree at the shard's prefix. Rooting each shard's JMT
//! at [`shard_prefix_path`] is what makes that identity hold — a shard's
//! `state_root` is exactly the corresponding subtree node of a monolithic global
//! tree (proven by the keystone test below). That is what lets a cross-shard
//! state proof be a Merkle path `key → its shard's subtree root`, verified
//! against that shard's own attested root, and what makes a resharding split
//! re-root a child onto the parent's existing subtree node with no state copy.
//! Roots are tracked per shard and never combined into a single network root.

use hyperscale_jmt::NibblePath;

use crate::ShardId;

/// The JMT root path a shard's state tree is rooted at: the shard's `depth`-bit
/// prefix as a [`NibblePath`].
///
/// Rooting a shard's tree here makes its `state_root` the corresponding subtree
/// node of a monolithic global tree at that prefix (so a split re-roots a child
/// onto the parent's existing subtree node — no state copy). [`ShardId::ROOT`]
/// yields the empty path (whole keyspace).
#[must_use]
pub fn shard_prefix_path(shard: ShardId) -> NibblePath {
    let depth = shard.depth();
    let path = shard.path(); // the `depth`-bit prefix in the low `depth` bits
    let mut prefix = NibblePath::empty();
    let mut taken = 0u32;
    while taken < depth {
        let count = (depth - taken).min(8);
        // Most-significant chunk first: the prefix's leading bits sit at
        // the top of the value's `depth` significant bits.
        let shift = depth - taken - count;
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
    use std::collections::BTreeMap;

    use blake3::hash as blake3_hash;
    use hyperscale_jmt::{Blake3Hasher, Hasher, LeafValue, MemoryStore, NibblePath, Tree};

    use super::shard_prefix_path;
    use crate::{Hash, ShardId, ShardTrie, StateRoot};

    type Jmt = Tree<Blake3Hasher, 1>;

    /// Combine each shard leaf's prefix-rooted `state_root` up the trie with the
    /// JMT internal-node hash. Test-only: production tracks each shard's root
    /// individually and never combines, but the combine is the cleanest way to
    /// *prove* the per-shard subtree-root identity below (combine == monolithic
    /// global root ⇒ each shard root is a genuine subtree node).
    fn network_state_root(
        trie: &ShardTrie,
        shard_root: &BTreeMap<ShardId, StateRoot>,
    ) -> StateRoot {
        combine(trie, shard_root, ShardId::ROOT)
    }

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
        updates: &BTreeMap<[u8; 32], Option<LeafValue>>,
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
    /// root up the trie equals the root of one monolithic JMT over every key —
    /// i.e. each prefix-rooted shard `state_root` is a genuine subtree node of
    /// the global tree. The whole sharding substrate (cross-shard proofs,
    /// snap-sync anchors, zero-copy resharding) rests on this identity.
    fn assert_identity(trie: &ShardTrie, keys_per_shard: u64) {
        let mut all: BTreeMap<[u8; 32], Option<LeafValue>> = BTreeMap::new();
        let mut per_shard: BTreeMap<ShardId, BTreeMap<[u8; 32], Option<LeafValue>>> =
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
                all.insert(key, Some(LeafValue::new(value, 1)));
                per_shard
                    .entry(leaf)
                    .or_default()
                    .insert(key, Some(LeafValue::new(value, 1)));
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
    fn prefix_rooted_shards_equal_monolithic_uniform() {
        assert_identity(&ShardTrie::uniform(1), 16);
        assert_identity(&ShardTrie::uniform(2), 12);
        assert_identity(&ShardTrie::uniform(3), 8);
    }

    #[test]
    fn prefix_rooted_shards_equal_monolithic_non_uniform() {
        // Surgical splits to a {depth-1, depth-2, depth-2} partition — leaves at
        // mixed depths, reached the way resharding reaches a non-power-of-two trie.
        let mut trie = ShardTrie::single();
        let (left, _right) = trie.split(ShardId::ROOT);
        trie.split(left);
        assert_eq!(trie.len(), 3);
        assert_identity(&trie, 10);
    }

    /// Degenerate / one-sided split coverage that `assert_identity` skips (it
    /// populates both children of every split). The split identity
    /// `r_p == hash_internal(r_p0, r_p1)`:
    ///
    /// - **holds** when `p`'s prefix-rooted root is an *internal* node (≥2 keys),
    ///   even if every key is on one side of the split bit — the empty child
    ///   contributes `EMPTY` and the root still materializes at `p`'s depth;
    /// - **fails (fail-closed)** when `p` collapses to a single leaf (≤1 key):
    ///   JMT path compression bubbles the leaf past the prefix depth, so `r_p`
    ///   *is* the leaf (`== r_p0`) and `hash_internal(r_p0, EMPTY) != r_p`.
    ///
    /// This pins the precondition the resharding split-trigger enforces (reject a
    /// <2-key split). If a JMT change ever made a one-sided ≥2-key root collapse,
    /// this catches it.
    #[test]
    fn split_identity_holds_one_sided_internal_but_not_collapsed_leaf() {
        let p = ShardId::leaf(1, 0);
        let (p0, _p1) = p.children();
        let empty = *StateRoot::ZERO.as_bytes();

        // All keys under p0 → one-sided at p's split bit; p1 is empty.
        let root_over = |root_path: &NibblePath, n: u64| -> [u8; 32] {
            let mut updates: BTreeMap<[u8; 32], Option<LeafValue>> = BTreeMap::new();
            for i in 0..n {
                let key = key_in_shard(p0, i);
                updates.insert(key, Some(LeafValue::new(*blake3_hash(&key).as_bytes(), 1)));
            }
            jmt_root_at(root_path, &updates)
        };

        // ≥2 one-sided keys: the root materializes at p as a one-child internal
        // node, so r_p == hash_internal(r_p0, EMPTY) and r_p != r_p0.
        let r_p = root_over(&shard_prefix_path(p), 2);
        let r_p0 = root_over(&shard_prefix_path(p0), 2);
        assert_ne!(
            r_p, r_p0,
            "one-sided ≥2-key root must materialize at the prefix, not collapse"
        );
        assert_eq!(
            Blake3Hasher::hash_internal(&[r_p0, empty]),
            r_p,
            "one-sided identity must hold for an internal root"
        );

        // 1 key: p collapses to the bare leaf (== the child root), so the naive
        // identity fails-closed — exactly what the split-trigger's <2-key guard
        // prevents.
        let collapsed = root_over(&shard_prefix_path(p), 1);
        let solo_child = root_over(&shard_prefix_path(p0), 1);
        assert_eq!(
            collapsed, solo_child,
            "single-key shard collapses the prefix root to the leaf"
        );
        assert_ne!(
            Blake3Hasher::hash_internal(&[solo_child, empty]),
            collapsed,
            "single-key shard must fail the naive identity (precondition: ≥2 keys)"
        );
    }
}
