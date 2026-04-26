//! Property-based tests for hyperscale-jmt.
//!
//! Each proptest exercises a core invariant on randomly-generated trees:
//!
//! - **Roundtrip**: every inserted key is retrievable with its value.
//! - **Order/version independence**: building the same final state via
//!   different commit sequences produces the same root hash.
//! - **Delete semantics**: deleted keys become absent; others preserved.
//! - **Proof roundtrip**: inclusion and non-inclusion proofs verify.
//! - **Tamper rejection**: byte-level mutation of a proof breaks verify.
//! - **Historical reads**: old roots still resolve old values after
//!   subsequent updates.

use std::collections::BTreeMap;

use hyperscale_jmt::{
    Blake3Hasher, EMPTY_HASH, Hash, Key, MemoryStore, NodeKey, Tree, TreeReader, ValueHash,
};
use proptest::prelude::*;

type Jmt = Tree<Blake3Hasher, 1>;

// ============================================================
// Strategies
// ============================================================

fn key_strategy() -> impl Strategy<Value = Key> {
    prop::array::uniform32(any::<u8>())
}

fn value_strategy() -> impl Strategy<Value = ValueHash> {
    prop::array::uniform32(any::<u8>())
}

/// 0..32 entries — allows empty trees to be tested too.
fn entries_strategy() -> impl Strategy<Value = BTreeMap<Key, ValueHash>> {
    prop::collection::btree_map(key_strategy(), value_strategy(), 0..32)
}

/// 1..32 entries — for tests that need a non-empty tree.
fn non_empty_entries() -> impl Strategy<Value = BTreeMap<Key, ValueHash>> {
    prop::collection::btree_map(key_strategy(), value_strategy(), 1..32)
}

// ============================================================
// Helpers
// ============================================================

/// Build a fresh tree at version 1 from `entries` and return the
/// populated store, root key (if any), and root hash.
fn build_tree(entries: &BTreeMap<Key, ValueHash>) -> (MemoryStore, Option<NodeKey>, Hash) {
    let mut store = MemoryStore::new();
    if entries.is_empty() {
        return (store, None, EMPTY_HASH);
    }
    let updates: BTreeMap<Key, Option<ValueHash>> =
        entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
    let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
    let root_hash = res.root_hash;
    store.apply(&res);
    let root = store.get_root_key(1);
    (store, root, root_hash)
}

// ============================================================
// Properties
// ============================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every inserted (k, v) pair must round-trip through get.
    #[test]
    fn insert_roundtrip(entries in entries_strategy()) {
        let (store, root_opt, _) = build_tree(&entries);
        match root_opt {
            Some(root) => {
                for (k, v) in &entries {
                    prop_assert_eq!(Jmt::get(&store, &root, k), Some(*v));
                }
            }
            None => {
                prop_assert!(entries.is_empty());
            }
        }
    }

    /// Splitting a batch of inserts across two versions must produce
    /// the same final root as a single combined commit.
    #[test]
    fn multi_version_equivalence(
        entries in prop::collection::btree_map(key_strategy(), value_strategy(), 4..32),
    ) {
        let n = entries.len();
        let half = n / 2;
        let first_half: BTreeMap<Key, ValueHash> =
            entries.iter().take(half).map(|(k, v)| (*k, *v)).collect();
        let second_half: BTreeMap<Key, ValueHash> =
            entries.iter().skip(half).map(|(k, v)| (*k, *v)).collect();

        // Approach A: single commit with everything.
        let (_, _, root_a) = build_tree(&entries);

        // Approach B: first half at v1, second half at v2.
        let mut store_b = MemoryStore::new();
        let u1: BTreeMap<Key, Option<ValueHash>> =
            first_half.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let r1 = Jmt::apply_updates(&store_b, None, 1, &u1).unwrap();
        store_b.apply(&r1);

        let u2: BTreeMap<Key, Option<ValueHash>> =
            second_half.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let root_b = if u2.is_empty() {
            r1.root_hash
        } else {
            let r2 = Jmt::apply_updates(&store_b, Some(1), 2, &u2).unwrap();
            store_b.apply(&r2);
            r2.root_hash
        };

        prop_assert_eq!(root_a, root_b);
    }

    /// All keys present in the tree must prove-and-verify as a batch.
    #[test]
    fn batch_inclusion_proof(entries in non_empty_entries()) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();
        let keys: Vec<Key> = entries.keys().copied().collect();
        let proof = Jmt::prove(&store, &root, &keys).unwrap();
        let expected: Vec<(Key, Option<ValueHash>)> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        Jmt::verify(&proof, root_hash, &expected).unwrap();
    }

    /// A subset of keys must also prove-and-verify correctly, exercising
    /// the sibling-emission path (non-claimed buckets).
    #[test]
    fn subset_inclusion_proof(
        entries in prop::collection::btree_map(key_strategy(), value_strategy(), 4..32),
        subset_mask in prop::collection::vec(any::<bool>(), 4..32),
    ) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();
        let keys_all: Vec<(Key, ValueHash)> = entries.iter().map(|(k, v)| (*k, *v)).collect();
        let subset: Vec<(Key, ValueHash)> = keys_all
            .iter()
            .zip(subset_mask.iter().cycle())
            .filter_map(|(kv, &take)| if take { Some(*kv) } else { None })
            .collect();
        if subset.is_empty() {
            return Ok(());
        }
        let subset_keys: Vec<Key> = subset.iter().map(|(k, _)| *k).collect();
        let proof = Jmt::prove(&store, &root, &subset_keys).unwrap();
        let expected: Vec<(Key, Option<ValueHash>)> =
            subset.iter().map(|(k, v)| (*k, Some(*v))).collect();
        Jmt::verify(&proof, root_hash, &expected).unwrap();
    }

    /// Non-inclusion proofs: a key not in the tree must prove as absent.
    #[test]
    fn non_inclusion_proof(
        entries in non_empty_entries(),
        absent in key_strategy(),
    ) {
        // Skip if absent happens to collide with an existing key.
        if entries.contains_key(&absent) {
            return Ok(());
        }
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();
        let proof = Jmt::prove(&store, &root, &[absent]).unwrap();
        Jmt::verify(&proof, root_hash, &[(absent, None)]).unwrap();
    }

    /// Mixed batch: some present, some absent.
    #[test]
    fn mixed_inclusion_non_inclusion(
        entries in non_empty_entries(),
        extras in prop::collection::vec(key_strategy(), 1..8),
    ) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();

        // Filter extras to only those not in `entries` to avoid ambiguous assertions.
        let absent: Vec<Key> = extras
            .iter()
            .copied()
            .filter(|k| !entries.contains_key(k))
            .collect();
        if absent.is_empty() {
            return Ok(());
        }

        let mut keys: Vec<Key> = entries.keys().copied().collect();
        keys.extend(&absent);

        let proof = Jmt::prove(&store, &root, &keys).unwrap();

        let mut expected: Vec<(Key, Option<ValueHash>)> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        for a in &absent {
            expected.push((*a, None));
        }
        Jmt::verify(&proof, root_hash, &expected).unwrap();
    }

    /// Tampering any single byte of a proof's siblings must cause verify
    /// to fail (assuming the proof has siblings).
    #[test]
    fn tampered_sibling_rejected(
        entries in prop::collection::btree_map(key_strategy(), value_strategy(), 4..32),
        pick_key in 0usize..32,
        sib_idx in 0usize..64,
        byte_idx in 0usize..32,
    ) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();
        let keys: Vec<Key> = entries.keys().copied().collect();
        let k = keys[pick_key % keys.len()];

        let mut proof = Jmt::prove(&store, &root, &[k]).unwrap();
        if proof.siblings.is_empty() {
            // No siblings (degenerate tree with a single key) — skip.
            return Ok(());
        }
        let i = sib_idx % proof.siblings.len();
        let j = byte_idx % 32;
        proof.siblings[i][j] ^= 0xFF;

        let expected = vec![(k, Some(*entries.get(&k).unwrap()))];
        let result = Jmt::verify(&proof, root_hash, &expected);
        prop_assert!(result.is_err());
    }

    /// Tampering a value_hash in a leaf claim must break verify.
    #[test]
    fn tampered_value_rejected(
        entries in non_empty_entries(),
        pick_key in 0usize..32,
        byte_idx in 0usize..32,
    ) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();
        let keys: Vec<Key> = entries.keys().copied().collect();
        let k = keys[pick_key % keys.len()];

        let mut proof = Jmt::prove(&store, &root, &[k]).unwrap();
        if let Some(claim) = proof.claims.first_mut() {
            if let Some(ref mut vh) = claim.value_hash {
                vh[byte_idx % 32] ^= 0xFF;
            } else {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let expected = vec![(k, Some(*entries.get(&k).unwrap()))];
        let result = Jmt::verify(&proof, root_hash, &expected);
        prop_assert!(result.is_err());
    }

    /// Deleting a key leaves the tree consistent: the deleted key
    /// returns None; remaining keys remain retrievable.
    #[test]
    fn delete_one_leaves_rest_intact(
        entries in non_empty_entries(),
        delete_idx in 0usize..100,
    ) {
        let (mut store, _, _) = build_tree(&entries);
        let keys: Vec<Key> = entries.keys().copied().collect();
        let target = keys[delete_idx % keys.len()];

        let updates: BTreeMap<Key, Option<ValueHash>> =
            std::iter::once((target, None)).collect();
        let res = Jmt::apply_updates(&store, Some(1), 2, &updates).unwrap();
        store.apply(&res);

        if let Some(root2) = store.get_root_key(2) {
            prop_assert_eq!(Jmt::get(&store, &root2, &target), None);
            for (k, v) in &entries {
                if *k != target {
                    prop_assert_eq!(Jmt::get(&store, &root2, k), Some(*v));
                }
            }
        } else {
            // Tree is empty — only possible when target was the only entry.
            prop_assert_eq!(entries.len(), 1);
            prop_assert_eq!(res.root_hash, EMPTY_HASH);
        }
    }

    /// Historical reads must see the state as of the queried version,
    /// unaffected by subsequent updates.
    #[test]
    fn historical_reads_preserved(
        v1_entries in non_empty_entries(),
        v2_updates in entries_strategy(),
    ) {
        let mut store = MemoryStore::new();
        let u1: BTreeMap<Key, Option<ValueHash>> =
            v1_entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &u1).unwrap();
        store.apply(&r1);

        if !v2_updates.is_empty() {
            let u2: BTreeMap<Key, Option<ValueHash>> =
                v2_updates.iter().map(|(k, v)| (*k, Some(*v))).collect();
            let r2 = Jmt::apply_updates(&store, Some(1), 2, &u2).unwrap();
            store.apply(&r2);
        }

        let root1 = store.get_root_key(1).unwrap();
        for (k, v) in &v1_entries {
            prop_assert_eq!(Jmt::get(&store, &root1, k), Some(*v));
        }
    }

    /// Update semantics: setting a key to a new value then reading
    /// returns the new value at the new version but the old value at
    /// the old version.
    #[test]
    fn update_preserves_version_isolation(
        entries in non_empty_entries(),
        pick_key in 0usize..100,
        new_value in value_strategy(),
    ) {
        let (mut store, _, _) = build_tree(&entries);
        let keys: Vec<Key> = entries.keys().copied().collect();
        let target = keys[pick_key % keys.len()];
        let old_value = *entries.get(&target).unwrap();
        prop_assume!(old_value != new_value);

        let u2: BTreeMap<Key, Option<ValueHash>> =
            std::iter::once((target, Some(new_value))).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &u2).unwrap();
        store.apply(&r2);

        let root1 = store.get_root_key(1).unwrap();
        let root2 = store.get_root_key(2).unwrap();
        prop_assert_eq!(Jmt::get(&store, &root1, &target), Some(old_value));
        prop_assert_eq!(Jmt::get(&store, &root2, &target), Some(new_value));
    }

    /// Any proof generated from a random tree must encode+decode to an
    /// equal proof, and the decoded proof must still verify.
    #[test]
    fn encode_decode_roundtrip(
        entries in non_empty_entries(),
        extra_keys in prop::collection::vec(key_strategy(), 0..4),
    ) {
        let (store, root_opt, root_hash) = build_tree(&entries);
        let root = root_opt.unwrap();

        // Mix of present and possibly-absent keys.
        let mut query: Vec<Key> = entries.keys().copied().collect();
        query.extend(&extra_keys);

        let proof = Jmt::prove(&store, &root, &query).unwrap();

        let bytes = proof.encode();
        let decoded = hyperscale_jmt::MultiProof::decode(&bytes).unwrap();
        prop_assert_eq!(&proof, &decoded);

        // Re-verify with the same expected claims the original proof
        // would satisfy.
        let mut expected: Vec<(Key, Option<ValueHash>)> = query
            .iter()
            .copied()
            .map(|k| (k, entries.get(&k).copied()))
            .collect();
        // Dedup because query may contain duplicates after extras overlap.
        expected.sort_by_key(|(k, _)| *k);
        expected.dedup_by_key(|(k, _)| *k);
        Jmt::verify(&decoded, root_hash, &expected).unwrap();
    }
}
