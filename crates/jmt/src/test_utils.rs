//! Shared fixtures for the crate's tree and proof tests.

use std::collections::BTreeMap;

use crate::hasher::{Blake3Hasher, Hash};
use crate::node::{Key, LeafValue, NodeKey, ValueHash};
use crate::storage::{MemoryStore, TreeReader};
use crate::tree::Tree;

type Jmt = Tree<Blake3Hasher, 1>;

/// A 32-byte key with `b` as its leading byte.
pub fn k(b: u8) -> Key {
    let mut key = [0u8; 32];
    key[0] = b;
    key
}

/// A 32-byte value hash filled with `b`.
pub const fn v(b: u8) -> ValueHash {
    [b; 32]
}

/// A leaf update value: the hash `v(b)` with a placeholder byte length.
/// Structural tests (roots, proofs, ranges) are length-independent, so
/// the length is a fixed `1`; byte-accounting tests build [`LeafValue`]
/// explicitly with the lengths under test.
pub const fn vl(b: u8) -> LeafValue {
    LeafValue::new(v(b), 1)
}

/// A store populated with `entries` at version 1, returning its root
/// key and root hash.
pub fn build_store(entries: &[(Key, ValueHash)]) -> (MemoryStore, NodeKey, Hash) {
    let mut store = MemoryStore::new();
    let updates: BTreeMap<Key, Option<LeafValue>> = entries
        .iter()
        .map(|(k, v)| (*k, Some(LeafValue::new(*v, 1))))
        .collect();
    let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
    store.apply(&res);
    let root = store.get_root_key(1).unwrap();
    (store, root, res.root_hash)
}
