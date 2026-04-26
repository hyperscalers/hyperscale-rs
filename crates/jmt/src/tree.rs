//! Tree operations: insertion, reads, root hashing.
//!
//! The [`Tree`] type is a zero-sized namespace bundling the hasher and
//! arity into a single type parameter set. Users typically alias it:
//!
//! ```ignore
//! use hyperscale_jmt::{Blake3Hasher, Tree};
//! type Jmt = Tree<Blake3Hasher>; // binary, Blake3
//! type Jmt4 = Tree<Blake3Hasher, 2>; // radix-4, Blake3 (for benchmarking)
//! ```

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Range;

use crate::hasher::{Hash, Hasher, EMPTY_HASH};
use crate::node::{
    Child, ChildKind, InternalNode, Key, LeafNode, NibblePath, Node, NodeKey, StaleNodeIndex,
    TreeUpdateBatch, ValueHash,
};
use crate::storage::TreeReader;

/// Namespace for tree operations, parameterized by hasher and arity.
///
/// `ARITY_BITS` is the number of bits consumed per level; the arity is
/// `1 << ARITY_BITS`. Supported values are `1` (binary, default), `2`
/// (radix-4), and `4` (radix-16). Larger values are not recommended as
/// they blow up multiproof sibling counts.
pub struct Tree<H: Hasher, const ARITY_BITS: u8 = 1>(PhantomData<H>);

impl<H: Hasher, const ARITY_BITS: u8> Tree<H, ARITY_BITS> {
    /// Number of children per internal node.
    pub const ARITY: usize = 1 << ARITY_BITS as usize;

    /// Apply a batch of key updates to produce a new version of the tree.
    ///
    /// - `parent_version`: the version to base this update on, or `None`
    ///   for the initial commit into an empty store.
    /// - `new_version`: the version label for the resulting root. Must
    ///   be strictly greater than `parent_version`.
    /// - `updates`: `Some(value_hash)` to insert or update, `None` to
    ///   delete. The map's key ordering is used to sort updates by key.
    ///
    /// Returns an [`UpdateResult`] whose `batch` must be persisted to
    /// make the new version visible to reads.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::NonMonotonicVersion`] if `new_version` is
    /// not strictly greater than `parent_version`,
    /// [`UpdateError::ParentVersionMissing`] if the parent root is not
    /// in `store`, [`UpdateError::MissingNode`] if a referenced node
    /// has been pruned, or [`UpdateError::Invariant`] if an internal
    /// post-condition fails.
    pub fn apply_updates<S>(
        store: &S,
        parent_version: Option<u64>,
        new_version: u64,
        updates: &BTreeMap<Key, Option<ValueHash>>,
    ) -> Result<UpdateResult, UpdateError>
    where
        S: TreeReader,
    {
        if let Some(parent) = parent_version {
            if new_version <= parent {
                return Err(UpdateError::NonMonotonicVersion {
                    parent,
                    new: new_version,
                });
            }
        }

        // BTreeMap iteration is sorted by key.
        let kvs: Vec<(&Key, Option<ValueHash>)> = updates.iter().map(|(k, v)| (k, *v)).collect();

        let mut batch = TreeUpdateBatch::default();

        let new_root = match parent_version {
            Some(parent) => {
                let root_key = store
                    .get_root_key(parent)
                    .ok_or(UpdateError::ParentVersionMissing(parent))?;
                update_existing::<S, H, ARITY_BITS>(
                    store,
                    &root_key,
                    new_version,
                    &kvs,
                    &mut batch,
                )?
            }
            None => {
                build_fresh::<H, ARITY_BITS>(&NibblePath::empty(), new_version, &kvs, &mut batch)
            }
        };

        // Write the root. An empty tree produces no root node; callers
        // interpret a missing root_key as EMPTY_HASH.
        let (root_hash, root_key) = match new_root {
            Some(node) => {
                let hash = node.hash::<H>();
                let key = NodeKey::root(new_version);
                batch.new_nodes.push((key.clone(), node));
                batch.root_key = Some((new_version, key.clone()));
                (hash, key)
            }
            None => (EMPTY_HASH, NodeKey::root(new_version)),
        };

        Ok(UpdateResult {
            root_hash,
            root_key,
            batch,
        })
    }

    /// Read the value hash stored under `key` at the given root.
    pub fn get<S>(store: &S, root_key: &NodeKey, key: &Key) -> Option<ValueHash>
    where
        S: TreeReader,
    {
        let mut current = store.get_node(root_key)?;
        let mut current_path = root_key.path.clone();

        loop {
            match &*current {
                Node::Leaf(leaf) => {
                    return if leaf.key == *key {
                        Some(leaf.value_hash)
                    } else {
                        None
                    };
                }
                Node::Internal(internal) => {
                    let bucket = bits_at(key, current_path.len(), ARITY_BITS);
                    let child = internal.children.get(usize::from(bucket))?.as_ref()?;
                    let next_path = child_path(&current_path, bucket, ARITY_BITS);
                    let child_key = NodeKey::new(child.version, next_path.clone());
                    current = store.get_node(&child_key)?;
                    current_path = next_path;
                }
            }
        }
    }

    /// Root hash of a committed version, or `None` if the version has
    /// no committed root (pruned or never-written).
    pub fn root_hash_at<S>(store: &S, version: u64) -> Option<Hash>
    where
        S: TreeReader,
    {
        let root_key = store.get_root_key(version)?;
        let node = store.get_node(&root_key)?;
        Some(node.hash::<H>())
    }
}

/// Result of a successful [`Tree::apply_updates`] call.
#[derive(Clone, Debug)]
pub struct UpdateResult {
    /// Hash of the new root (or [`EMPTY_HASH`] for an empty tree).
    pub root_hash: Hash,
    /// Storage key of the new root node.
    pub root_key: NodeKey,
    /// Batch of node writes/stale entries the caller must persist.
    pub batch: TreeUpdateBatch,
}

/// Errors produced by [`Tree::apply_updates`].
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// `parent_version` was supplied but no root is recorded for it.
    #[error("parent version {0} not found in store")]
    ParentVersionMissing(u64),

    /// `new_version` is not strictly greater than `parent_version`.
    #[error("new version {new} must be greater than parent version {parent}")]
    NonMonotonicVersion {
        /// The parent version supplied by the caller.
        parent: u64,
        /// The (rejected) new version supplied by the caller.
        new: u64,
    },

    /// A child node referenced by an internal node is absent from storage.
    #[error("storage corruption: node at {key:?} referenced but missing")]
    MissingNode {
        /// Key of the missing node.
        key: NodeKey,
    },

    /// An internal post-condition was violated (indicates a bug).
    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),
}

// ============================================================
// Private helpers
// ============================================================

/// Extract `count` bits (right-aligned, `count <= 8`) from `key`
/// starting at bit offset `depth_bits` from the MSB.
fn bits_at(key: &Key, depth_bits: u16, count: u8) -> u8 {
    debug_assert!(count <= 8);
    debug_assert!(depth_bits as usize + count as usize <= 256);

    let byte = (depth_bits / 8) as usize;
    let off = (depth_bits % 8) as usize;
    let hi = u16::from(key[byte]);
    let lo = u16::from(*key.get(byte + 1).unwrap_or(&0));
    let combined = (hi << 8) | lo;
    let shift = 16 - off - count as usize;
    let mask = (1u16 << count) - 1;
    u8::try_from((combined >> shift) & mask).unwrap_or(u8::MAX)
}

/// Build a child path by appending `count` bits of `bucket` to `parent`.
fn child_path(parent: &NibblePath, bucket: u8, count: u8) -> NibblePath {
    let mut p = parent.clone();
    p.push_bits(bucket, count);
    p
}

/// Iterator yielding `(bucket, range)` tuples over contiguous ranges of
/// sorted `kvs` that share the same `count`-bit chunk at `depth_bits`.
struct BitRangeIter<'a> {
    kvs: &'a [(&'a Key, Option<ValueHash>)],
    depth_bits: u16,
    bits_per_level: u8,
    pos: usize,
}

impl<'a> BitRangeIter<'a> {
    fn new(kvs: &'a [(&'a Key, Option<ValueHash>)], depth_bits: u16, bits_per_level: u8) -> Self {
        Self {
            kvs,
            depth_bits,
            bits_per_level,
            pos: 0,
        }
    }
}

impl Iterator for BitRangeIter<'_> {
    type Item = (u8, Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.kvs.len() {
            return None;
        }
        let bucket = bits_at(self.kvs[self.pos].0, self.depth_bits, self.bits_per_level);
        let start = self.pos;
        while self.pos < self.kvs.len()
            && bits_at(self.kvs[self.pos].0, self.depth_bits, self.bits_per_level) == bucket
        {
            self.pos += 1;
        }
        Some((bucket, start..self.pos))
    }
}

/// Classify a node as either a leaf or an internal, for [`ChildKind`].
fn kind_of(node: &Node) -> ChildKind {
    match node {
        Node::Internal(_) => ChildKind::Internal,
        Node::Leaf(_) => ChildKind::Leaf,
    }
}

// ------------------------------------------------------------
// Recursive update entry points
// ------------------------------------------------------------

/// Update a subtree loaded from storage at `node_key`. Marks the loaded
/// node stale. Returns the new subtree's root node, or `None` if the
/// updates emptied the subtree.
fn update_existing<S, H, const ARITY_BITS: u8>(
    store: &S,
    node_key: &NodeKey,
    new_version: u64,
    kvs: &[(&Key, Option<ValueHash>)],
    batch: &mut TreeUpdateBatch,
) -> Result<Option<Node>, UpdateError>
where
    S: TreeReader,
    H: Hasher,
{
    let node = store
        .get_node(node_key)
        .ok_or_else(|| UpdateError::MissingNode {
            key: node_key.clone(),
        })?;
    batch.stale_nodes.push(StaleNodeIndex {
        stale_since_version: new_version,
        node_key: node_key.clone(),
    });

    match &*node {
        Node::Internal(internal) => update_existing_internal::<S, H, ARITY_BITS>(
            store,
            &node_key.path,
            internal,
            new_version,
            kvs,
            batch,
        ),
        Node::Leaf(leaf) => Ok(merge_leaf::<H, ARITY_BITS>(
            leaf,
            &node_key.path,
            new_version,
            kvs,
            batch,
        )),
    }
}

/// Update an existing internal node against a batch of sorted kvs.
fn update_existing_internal<S, H, const ARITY_BITS: u8>(
    store: &S,
    parent_path: &NibblePath,
    existing: &InternalNode,
    new_version: u64,
    kvs: &[(&Key, Option<ValueHash>)],
    batch: &mut TreeUpdateBatch,
) -> Result<Option<Node>, UpdateError>
where
    S: TreeReader,
    H: Hasher,
{
    let arity = 1usize << ARITY_BITS as usize;
    let parent_depth = parent_path.len();

    // Recurse into each bucket that has updates.
    let mut updated: Vec<(u8, Option<Node>)> = Vec::new();
    for (bucket, range) in BitRangeIter::new(kvs, parent_depth, ARITY_BITS) {
        let sub_kvs = &kvs[range];
        let sub_path = child_path(parent_path, bucket, ARITY_BITS);

        let new_subnode = match existing
            .children
            .get(bucket as usize)
            .and_then(|c| c.as_ref())
        {
            Some(existing_child) => {
                let existing_child_key = NodeKey::new(existing_child.version, sub_path);
                update_existing::<S, H, ARITY_BITS>(
                    store,
                    &existing_child_key,
                    new_version,
                    sub_kvs,
                    batch,
                )?
            }
            None => build_fresh::<H, ARITY_BITS>(&sub_path, new_version, sub_kvs, batch),
        };
        updated.push((bucket, new_subnode));
    }

    // Combine: start from the old children, apply updates.
    let mut children: Vec<Option<Child>> = existing.children.clone();
    if children.len() != arity {
        children.resize(arity, None);
    }

    // Buffered new child nodes (bucket → Node) — written to batch only
    // if the parent stays internal.
    let mut buffered: Vec<(u8, Node)> = Vec::with_capacity(updated.len());

    for (bucket, subnode) in updated {
        let idx = bucket as usize;
        match subnode {
            Some(node) => {
                let hash = node.hash::<H>();
                let kind = kind_of(&node);
                children[idx] = Some(Child {
                    version: new_version,
                    hash,
                    kind,
                });
                buffered.push((bucket, node));
            }
            None => {
                children[idx] = None;
            }
        }
    }

    finalize::<S, H, ARITY_BITS>(
        store,
        parent_path,
        children,
        buffered,
        new_version,
        /* load_preserved_on_collapse = */ true,
        batch,
    )
}

/// Build a subtree from scratch at `path`. Called when inserting into
/// a previously-empty slot. `kvs` is sorted by key.
///
/// Writes intermediate child nodes to `batch`. Returns the subtree's
/// root node (to be written by the caller at `path`).
fn build_fresh<H: Hasher, const ARITY_BITS: u8>(
    path: &NibblePath,
    new_version: u64,
    kvs: &[(&Key, Option<ValueHash>)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    // Drop deletions — nothing to delete from an empty subtree.
    let present: Vec<(&Key, ValueHash)> = kvs
        .iter()
        .filter_map(|(k, v)| v.map(|vh| (*k, vh)))
        .collect();

    match present.len() {
        0 => None,
        1 => {
            let (k, vh) = present[0];
            Some(Node::Leaf(LeafNode::new(*k, vh)))
        }
        _ => build_fresh_multi::<H, ARITY_BITS>(path, new_version, &present, batch),
    }
}

fn build_fresh_multi<H: Hasher, const ARITY_BITS: u8>(
    path: &NibblePath,
    new_version: u64,
    present: &[(&Key, ValueHash)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    let arity = 1usize << ARITY_BITS as usize;
    let depth = path.len();

    let mut children: Vec<Option<Child>> = vec![None; arity];
    let mut buffered: Vec<(u8, Node)> = Vec::new();

    // Group `present` by bit-bucket at the current depth.
    let mut pos = 0;
    while pos < present.len() {
        let bucket = bits_at(present[pos].0, depth, ARITY_BITS);
        let start = pos;
        while pos < present.len() && bits_at(present[pos].0, depth, ARITY_BITS) == bucket {
            pos += 1;
        }
        let sub = &present[start..pos];
        let sub_path = child_path(path, bucket, ARITY_BITS);
        let sub_kvs: Vec<(&Key, Option<ValueHash>)> =
            sub.iter().map(|(k, v)| (*k, Some(*v))).collect();

        if let Some(node) = build_fresh::<H, ARITY_BITS>(&sub_path, new_version, &sub_kvs, batch) {
            let hash = node.hash::<H>();
            let kind = kind_of(&node);
            children[bucket as usize] = Some(Child {
                version: new_version,
                hash,
                kind,
            });
            buffered.push((bucket, node));
        }
    }

    // In a fresh build there's nothing to "load from store" on collapse
    // — any single-leaf child is necessarily in `buffered`.
    finalize::<NeverStore, H, ARITY_BITS>(
        NEVER_STORE,
        path,
        children,
        buffered,
        new_version,
        /* load_preserved_on_collapse = */ false,
        batch,
    )
    // finalize returns Result; since load_preserved_on_collapse=false
    // cannot fail, unwrap is safe.
    .expect("build_fresh finalize must not load preserved")
}

/// An existing leaf meets a batch of updates. Either update/delete in
/// place (single matching-key update) or split by forming a combined
/// key-set and rebuilding a fresh subtree at this path.
fn merge_leaf<H: Hasher, const ARITY_BITS: u8>(
    existing: &LeafNode,
    path: &NibblePath,
    new_version: u64,
    kvs: &[(&Key, Option<ValueHash>)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    // Single-kv case matching existing leaf: update or delete in place.
    if kvs.len() == 1 && *kvs[0].0 == existing.key {
        return kvs[0]
            .1
            .map(|vh| Node::Leaf(LeafNode::new(existing.key, vh)));
    }

    // Form a combined "present" set = existing leaf superseded by any
    // matching update, plus non-matching inserts.
    let mut combined: Vec<(Key, ValueHash)> = Vec::with_capacity(kvs.len() + 1);
    let mut existing_covered = false;
    for (k, v) in kvs {
        if **k == existing.key {
            existing_covered = true;
            if let Some(vh) = v {
                combined.push((**k, *vh));
            }
        } else if let Some(vh) = v {
            combined.push((**k, *vh));
        }
    }
    if !existing_covered {
        combined.push((existing.key, existing.value_hash));
    }
    combined.sort_by_key(|(k, _)| *k);

    match combined.len() {
        0 => None,
        1 => {
            let (k, vh) = combined[0];
            Some(Node::Leaf(LeafNode::new(k, vh)))
        }
        _ => {
            let kvs: Vec<(&Key, Option<ValueHash>)> =
                combined.iter().map(|(k, v)| (k, Some(*v))).collect();
            build_fresh::<H, ARITY_BITS>(path, new_version, &kvs, batch)
        }
    }
}

/// Given the post-update children layout and a buffer of regenerated
/// child nodes, decide whether to emit an internal node (writing the
/// buffered children) or collapse to a single leaf.
///
/// `load_preserved_on_collapse` controls whether we're willing to load
/// a preserved (not-in-buffer) leaf from the store to bubble up on
/// collapse. Fresh-build callers pass `false` since every child in a
/// fresh build is in the buffer by construction.
fn finalize<S, H, const ARITY_BITS: u8>(
    store: &S,
    parent_path: &NibblePath,
    children: Vec<Option<Child>>,
    mut buffered: Vec<(u8, Node)>,
    new_version: u64,
    load_preserved_on_collapse: bool,
    batch: &mut TreeUpdateBatch,
) -> Result<Option<Node>, UpdateError>
where
    S: TreeReader,
    H: Hasher,
{
    let non_empty: Vec<usize> = children
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.as_ref().map(|_| i))
        .collect();

    match non_empty.len() {
        0 => Ok(None),
        1 => {
            let only_idx = non_empty[0];
            let only = children[only_idx].as_ref().unwrap().clone();
            if only.kind == ChildKind::Leaf {
                let leaf_node =
                    if let Some(pos) = buffered.iter().position(|(b, _)| *b as usize == only_idx) {
                        buffered.swap_remove(pos).1
                    } else {
                        if !load_preserved_on_collapse {
                            return Err(UpdateError::Invariant(
                                "fresh build produced a preserved leaf — impossible",
                            ));
                        }
                        let preserved_path = child_path(
                            parent_path,
                            u8::try_from(only_idx).unwrap_or(u8::MAX),
                            ARITY_BITS,
                        );
                        let preserved_key = NodeKey::new(only.version, preserved_path);
                        let loaded = store.get_node(&preserved_key).ok_or_else(|| {
                            UpdateError::MissingNode {
                                key: preserved_key.clone(),
                            }
                        })?;
                        batch.stale_nodes.push(StaleNodeIndex {
                            stale_since_version: new_version,
                            node_key: preserved_key,
                        });
                        (*loaded).clone()
                    };
                // Discard remaining buffered children — never written.
                Ok(Some(leaf_node))
            } else {
                for (bucket, node) in buffered {
                    let path = child_path(parent_path, bucket, ARITY_BITS);
                    batch
                        .new_nodes
                        .push((NodeKey::new(new_version, path), node));
                }
                Ok(Some(Node::Internal(InternalNode::new::<H>(children))))
            }
        }
        _ => {
            for (bucket, node) in buffered {
                let path = child_path(parent_path, bucket, ARITY_BITS);
                batch
                    .new_nodes
                    .push((NodeKey::new(new_version, path), node));
            }
            Ok(Some(Node::Internal(InternalNode::new::<H>(children))))
        }
    }
}

// ------------------------------------------------------------
// NeverStore: a TreeReader that panics on use.
//
// Used to satisfy the `S: TreeReader` bound on `finalize` when called
// from `build_fresh_multi`, which sets `load_preserved_on_collapse =
// false` and therefore never touches the store.
// ------------------------------------------------------------

struct NeverStore;
const NEVER_STORE: &NeverStore = &NeverStore;

impl TreeReader for NeverStore {
    fn get_node(&self, _key: &NodeKey) -> Option<std::sync::Arc<Node>> {
        unreachable!("NeverStore accessed — finalize load_preserved_on_collapse invariant broken")
    }
    fn get_root_key(&self, _version: u64) -> Option<NodeKey> {
        unreachable!("NeverStore accessed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Blake3Hasher;
    use crate::storage::MemoryStore;

    type Jmt = Tree<Blake3Hasher, 1>;

    fn k(b: u8) -> Key {
        let mut key = [0u8; 32];
        key[0] = b;
        key
    }

    fn v(b: u8) -> ValueHash {
        [b; 32]
    }

    #[test]
    fn single_insert_produces_leaf_root() {
        let store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10)))].into_iter().collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        let expected = Blake3Hasher::hash_leaf(&k(1), &v(10));
        assert_eq!(res.root_hash, expected);
    }

    #[test]
    fn insert_then_read_roundtrip() {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> = [
            (k(1), Some(v(10))),
            (k(2), Some(v(20))),
            (k(3), Some(v(30))),
        ]
        .into_iter()
        .collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);

        let root = store.get_root_key(1).unwrap();
        assert_eq!(Jmt::get(&store, &root, &k(1)), Some(v(10)));
        assert_eq!(Jmt::get(&store, &root, &k(2)), Some(v(20)));
        assert_eq!(Jmt::get(&store, &root, &k(3)), Some(v(30)));
        assert_eq!(Jmt::get(&store, &root, &k(4)), None);
    }

    #[test]
    fn update_value_changes_root() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10))), (k(2), Some(v(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(99)))].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);

        assert_ne!(r1.root_hash, r2.root_hash);
        let root2 = store.get_root_key(2).unwrap();
        assert_eq!(Jmt::get(&store, &root2, &k(1)), Some(v(99)));
        assert_eq!(Jmt::get(&store, &root2, &k(2)), Some(v(20)));
    }

    #[test]
    fn delete_removes_key_and_collapses() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10))), (k(2), Some(v(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<ValueHash>> = [(k(1), None)].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);

        // Deleting one of two keys should leave the root as a bare leaf
        // for key 2 (path compression bubbles the leaf up).
        let expected = Blake3Hasher::hash_leaf(&k(2), &v(20));
        assert_eq!(r2.root_hash, expected);

        let root2 = store.get_root_key(2).unwrap();
        assert_eq!(Jmt::get(&store, &root2, &k(1)), None);
        assert_eq!(Jmt::get(&store, &root2, &k(2)), Some(v(20)));
    }

    #[test]
    fn historical_reads_see_prior_version() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10)))].into_iter().collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);
        let v2: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(99)))].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);

        let root1 = store.get_root_key(1).unwrap();
        let root2 = store.get_root_key(2).unwrap();
        assert_eq!(Jmt::get(&store, &root1, &k(1)), Some(v(10)));
        assert_eq!(Jmt::get(&store, &root2, &k(1)), Some(v(99)));
    }

    #[test]
    fn many_keys_all_retrievable() {
        let mut store = MemoryStore::new();
        let mut updates = BTreeMap::new();
        for i in 0u8..64 {
            let mut key = [0u8; 32];
            key[0] = i;
            key[31] = i.wrapping_mul(7);
            updates.insert(key, Some([i; 32]));
        }
        let r = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&r);

        let root = store.get_root_key(1).unwrap();
        for (k, v) in &updates {
            assert_eq!(Jmt::get(&store, &root, k), *v);
        }
    }

    #[test]
    fn delete_all_keys_produces_empty_tree() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10))), (k(2), Some(v(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<ValueHash>> =
            [(k(1), None), (k(2), None)].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);

        assert_eq!(r2.root_hash, EMPTY_HASH);
        assert!(store.get_root_key(2).is_none());
    }

    #[test]
    fn delete_nonexistent_is_noop() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10)))].into_iter().collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Delete a key that isn't in the tree.
        let v2: BTreeMap<Key, Option<ValueHash>> = [(k(99), None)].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();

        assert_eq!(r1.root_hash, r2.root_hash);
    }

    #[test]
    fn non_monotonic_version_rejected() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<ValueHash>> = [(k(1), Some(v(10)))].into_iter().collect();
        let r1 = Jmt::apply_updates(&store, None, 5, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<ValueHash>> = [(k(2), Some(v(20)))].into_iter().collect();
        let err = Jmt::apply_updates(&store, Some(5), 5, &v2).unwrap_err();
        assert!(matches!(err, UpdateError::NonMonotonicVersion { .. }));
    }

    #[test]
    fn deep_prefix_divergence() {
        // Two keys whose first 20 bytes are identical — forces a long
        // chain of single-child internals in binary. Verify reads still
        // work through the chain.
        let mut store = MemoryStore::new();
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        for i in 0..20 {
            k1[i] = 0xAB;
            k2[i] = 0xAB;
        }
        k1[20] = 0x00;
        k2[20] = 0xFF;

        let updates: BTreeMap<Key, Option<ValueHash>> =
            [(k1, Some(v(1))), (k2, Some(v(2)))].into_iter().collect();
        let r = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&r);

        let root = store.get_root_key(1).unwrap();
        assert_eq!(Jmt::get(&store, &root, &k1), Some(v(1)));
        assert_eq!(Jmt::get(&store, &root, &k2), Some(v(2)));
    }

    #[test]
    fn radix4_variant_also_works() {
        // Verify the const-generic parameterization works: instantiate
        // radix-4 and run the same basic workflow.
        type Jmt4 = Tree<Blake3Hasher, 2>;
        assert_eq!(Jmt4::ARITY, 4);

        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> = [
            (k(1), Some(v(10))),
            (k(2), Some(v(20))),
            (k(3), Some(v(30))),
            (k(4), Some(v(40))),
        ]
        .into_iter()
        .collect();
        let r = Jmt4::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&r);

        let root = store.get_root_key(1).unwrap();
        for (key, val) in &updates {
            assert_eq!(Jmt4::get(&store, &root, key), *val);
        }
    }
}
