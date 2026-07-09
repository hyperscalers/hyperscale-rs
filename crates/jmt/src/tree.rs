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

use crate::hasher::{EMPTY_HASH, Hash, Hasher};
use crate::node::{
    Child, ChildKind, InternalNode, Key, LeafNode, LeafValue, NibblePath, Node, NodeKey,
    StaleNodeIndex, TreeUpdateBatch, ValueHash, bits_at,
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

    /// Apply `updates` to a whole-keyspace tree (rooted at the empty path).
    /// Equivalent to [`Self::apply_updates_at`] with [`NibblePath::empty`].
    ///
    /// # Errors
    ///
    /// See [`Self::apply_updates_at`].
    pub fn apply_updates<S>(
        store: &S,
        parent_version: Option<u64>,
        new_version: u64,
        updates: &BTreeMap<Key, Option<LeafValue>>,
    ) -> Result<UpdateResult, UpdateError>
    where
        S: TreeReader,
    {
        Self::apply_updates_at(
            store,
            parent_version,
            new_version,
            &NibblePath::empty(),
            updates,
        )
    }

    /// Apply a batch of key updates to the tree rooted at `root_path`,
    /// producing a new version.
    ///
    /// - `parent_version`: the version to base this update on, or `None` for the
    ///   initial commit into an empty store.
    /// - `new_version`: the version label for the resulting root. Must be
    ///   strictly greater than `parent_version`.
    /// - `root_path`: where this tree is rooted — [`NibblePath::empty`] for a
    ///   whole-keyspace tree, or a prefix so the tree covers only keys sharing
    ///   that prefix (its root node sits at the prefix depth, so the root hash is
    ///   the subtree root at that prefix). All keys in `updates` must share
    ///   `root_path`, and incremental updates must reuse it.
    /// - `updates`: `Some(value)` (hash + byte length) to insert or update,
    ///   `None` to delete. The map's key ordering sorts updates by key.
    ///
    /// Returns an [`UpdateResult`] whose `batch` must be persisted to make the
    /// new version visible to reads.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::NonMonotonicVersion`] if `new_version` is not
    /// strictly greater than `parent_version`,
    /// [`UpdateError::ParentVersionMissing`] if the parent root is not in
    /// `store`, [`UpdateError::MissingNode`] if a referenced node has been
    /// pruned, or [`UpdateError::Invariant`] if an internal post-condition fails.
    pub fn apply_updates_at<S>(
        store: &S,
        parent_version: Option<u64>,
        new_version: u64,
        root_path: &NibblePath,
        updates: &BTreeMap<Key, Option<LeafValue>>,
    ) -> Result<UpdateResult, UpdateError>
    where
        S: TreeReader,
    {
        if let Some(parent) = parent_version
            && new_version <= parent
        {
            return Err(UpdateError::NonMonotonicVersion {
                parent,
                new: new_version,
            });
        }

        // BTreeMap iteration is sorted by key.
        let kvs: Vec<(&Key, Option<LeafValue>)> = updates.iter().map(|(k, v)| (k, *v)).collect();

        let mut batch = TreeUpdateBatch::default();

        let new_root = if let Some(parent) = parent_version {
            let root_key = store
                .get_root_key(parent)
                .ok_or(UpdateError::ParentVersionMissing(parent))?;
            debug_assert_eq!(
                &root_key.path, root_path,
                "JMT root path must be stable across versions of a tree",
            );
            update_existing::<S, H, ARITY_BITS>(
                store,
                root_key.version,
                root_path,
                new_version,
                &kvs,
                &mut batch,
            )?
        } else {
            let (leaves, bytes) = insert_deltas(&kvs);
            batch.leaf_delta += leaves;
            batch.bytes_delta += bytes;
            build_fresh::<H, ARITY_BITS>(root_path, new_version, &kvs, &mut batch)
        };

        // Write the root at `root_path`. An empty tree produces no root node;
        // callers interpret a missing root_key as EMPTY_HASH.
        let (root_hash, root_key) = match new_root {
            Some(node) => {
                let hash = node.hash::<H>();
                let key = NodeKey::new(new_version, root_path.clone());
                batch.new_nodes.push((key.clone(), node));
                batch.root_key = Some((new_version, key.clone()));
                (hash, key)
            }
            None => (EMPTY_HASH, NodeKey::new(new_version, root_path.clone())),
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
        // Single key reused down the descent: each level pushes ARITY_BITS
        // onto the path in place rather than cloning.
        let mut current_key = root_key.clone();
        let mut current = store.get_node(&current_key)?;

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
                    let bucket = bits_at(key, current_key.path.len(), ARITY_BITS);
                    let child = internal.children.get(usize::from(bucket))?.as_ref()?;
                    current_key.version = child.version;
                    current_key.path.push_bits(bucket, ARITY_BITS);
                    current = store.get_node(&current_key)?;
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

/// Build a child path by appending `count` bits of `bucket` to `parent`.
fn child_path(parent: &NibblePath, bucket: u8, count: u8) -> NibblePath {
    let mut p = parent.clone();
    p.push_bits(bucket, count);
    p
}

/// Leaf-count and byte deltas for a fresh build at an empty slot. Every
/// `Some`-valued entry in `kvs` is new by construction (the slot held
/// nothing), so each counts +1 toward `leaf_delta` and adds its value
/// length toward `bytes_delta`. Returns `(leaf_delta, bytes_delta)`.
fn insert_deltas(kvs: &[(&Key, Option<LeafValue>)]) -> (i64, i64) {
    let mut leaves: i64 = 0;
    let mut bytes: i64 = 0;
    for (_, v) in kvs {
        if let Some(value) = v {
            leaves += 1;
            bytes += i64::try_from(value.len).expect("value length fits i64");
        }
    }
    (leaves, bytes)
}

/// Iterator yielding `(bucket, range)` tuples over contiguous ranges of
/// sorted `kvs` that share the same `count`-bit chunk at `depth_bits`.
struct BitRangeIter<'a> {
    kvs: &'a [(&'a Key, Option<LeafValue>)],
    depth_bits: u16,
    bits_per_level: u8,
    pos: usize,
}

impl<'a> BitRangeIter<'a> {
    const fn new(
        kvs: &'a [(&'a Key, Option<LeafValue>)],
        depth_bits: u16,
        bits_per_level: u8,
    ) -> Self {
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
const fn kind_of(node: &Node) -> ChildKind {
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
    version: u64,
    path: &NibblePath,
    new_version: u64,
    kvs: &[(&Key, Option<LeafValue>)],
    batch: &mut TreeUpdateBatch,
) -> Result<Option<Node>, UpdateError>
where
    S: TreeReader,
    H: Hasher,
{
    // Build the lookup key once and use it for both `get_node` and the
    // stale-nodes record. The owning `NodeKey` is moved into `stale_nodes`
    // after the recursive descent finishes so callers can share a single
    // `NibblePath` buffer across sibling buckets.
    let node_key = NodeKey::new(version, path.clone());
    let node = store
        .get_node(&node_key)
        .ok_or_else(|| UpdateError::MissingNode {
            key: node_key.clone(),
        })?;

    let result = match &*node {
        Node::Internal(internal) => update_existing_internal::<S, H, ARITY_BITS>(
            store,
            path,
            internal,
            new_version,
            kvs,
            batch,
        ),
        Node::Leaf(leaf) => Ok(merge_leaf::<H, ARITY_BITS>(
            leaf,
            path,
            new_version,
            kvs,
            batch,
        )),
    };

    batch.stale_nodes.push(StaleNodeIndex {
        stale_since_version: new_version,
        node_key,
    });

    result
}

#[cfg(feature = "parallel")]
type BucketResult = Result<(u8, Option<Node>, TreeUpdateBatch), UpdateError>;

/// Update an existing internal node against a batch of sorted kvs.
#[allow(clippy::too_many_lines)] // single dispatch over parallel/sequential bucket recursion
fn update_existing_internal<S, H, const ARITY_BITS: u8>(
    store: &S,
    parent_path: &NibblePath,
    existing: &InternalNode,
    new_version: u64,
    kvs: &[(&Key, Option<LeafValue>)],
    batch: &mut TreeUpdateBatch,
) -> Result<Option<Node>, UpdateError>
where
    S: TreeReader,
    H: Hasher,
{
    // `BitRangeIter` (the bucket grouper used below) assumes `kvs` is
    // sorted by key. The top-level `update` sorts at entry; this guard
    // catches a future caller wiring a recursion that bypasses the sort.
    debug_assert!(
        kvs.windows(2).all(|w| w[0].0 <= w[1].0),
        "update_existing_internal: kvs must be sorted by key",
    );
    let arity = 1usize << ARITY_BITS as usize;
    let parent_depth = parent_path.len();

    let dispatch_bucket = |bucket: u8,
                           range: Range<usize>,
                           sub_path: &NibblePath,
                           sub_batch: &mut TreeUpdateBatch|
     -> Result<Option<Node>, UpdateError> {
        let sub_kvs = &kvs[range];
        if let Some(existing_child) = existing
            .children
            .get(bucket as usize)
            .and_then(|c| c.as_ref())
        {
            update_existing::<S, H, ARITY_BITS>(
                store,
                existing_child.version,
                sub_path,
                new_version,
                sub_kvs,
                sub_batch,
            )
        } else {
            let (leaves, bytes) = insert_deltas(sub_kvs);
            sub_batch.leaf_delta += leaves;
            sub_batch.bytes_delta += bytes;
            Ok(build_fresh::<H, ARITY_BITS>(
                sub_path,
                new_version,
                sub_kvs,
                sub_batch,
            ))
        }
    };

    // Above the threshold, dispatch bucket recursion in parallel. Each
    // task accumulates into its own `TreeUpdateBatch`, which is merged
    // into the parent's batch sequentially after the join. Below it,
    // walk buckets in place against `batch` directly with a single shared
    // path buffer (truncate + push_bits) instead of cloning `parent_path`
    // per bucket.
    #[cfg(feature = "parallel")]
    let updated: Vec<(u8, Option<Node>)> = if kvs.len() >= 4096 {
        use rayon::prelude::*;

        let bucket_jobs: Vec<(u8, Range<usize>)> =
            BitRangeIter::new(kvs, parent_depth, ARITY_BITS).collect();

        let bucket_results: Vec<BucketResult> = bucket_jobs
            .into_par_iter()
            .map(|(bucket, range)| {
                let sub_path = child_path(parent_path, bucket, ARITY_BITS);
                let mut local_batch = TreeUpdateBatch::default();
                let new_subnode = dispatch_bucket(bucket, range, &sub_path, &mut local_batch)?;
                Ok((bucket, new_subnode, local_batch))
            })
            .collect();

        let mut updated = Vec::with_capacity(bucket_results.len());
        for r in bucket_results {
            let (bucket, new_subnode, local_batch) = r?;
            batch.new_nodes.extend(local_batch.new_nodes);
            batch.stale_nodes.extend(local_batch.stale_nodes);
            batch.leaf_delta += local_batch.leaf_delta;
            batch.bytes_delta += local_batch.bytes_delta;
            updated.push((bucket, new_subnode));
        }
        updated
    } else {
        let mut path_buf = parent_path.clone();
        let base_bits = path_buf.len();
        BitRangeIter::new(kvs, parent_depth, ARITY_BITS)
            .map(|(bucket, range)| {
                path_buf.truncate(base_bits);
                path_buf.push_bits(bucket, ARITY_BITS);
                dispatch_bucket(bucket, range, &path_buf, batch).map(|n| (bucket, n))
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    #[cfg(not(feature = "parallel"))]
    let updated: Vec<(u8, Option<Node>)> = {
        let mut path_buf = parent_path.clone();
        let base_bits = path_buf.len();
        BitRangeIter::new(kvs, parent_depth, ARITY_BITS)
            .map(|(bucket, range)| {
                path_buf.truncate(base_bits);
                path_buf.push_bits(bucket, ARITY_BITS);
                dispatch_bucket(bucket, range, &path_buf, batch).map(|n| (bucket, n))
            })
            .collect::<Result<Vec<_>, _>>()?
    };

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
    kvs: &[(&Key, Option<LeafValue>)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    // Drop deletions — nothing to delete from an empty subtree.
    let present: Vec<(&Key, LeafValue)> = kvs
        .iter()
        .filter_map(|(k, v)| v.map(|value| (*k, value)))
        .collect();

    match present.len() {
        0 => None,
        1 => {
            let (k, value) = present[0];
            Some(Node::Leaf(LeafNode::new(*k, value.hash, value.len)))
        }
        _ => build_fresh_multi::<H, ARITY_BITS>(path, new_version, &present, batch),
    }
}

fn build_fresh_multi<H: Hasher, const ARITY_BITS: u8>(
    path: &NibblePath,
    new_version: u64,
    present: &[(&Key, LeafValue)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    let arity = 1usize << ARITY_BITS as usize;
    let depth = path.len();

    let mut children: Vec<Option<Child>> = vec![None; arity];
    let mut buffered: Vec<(u8, Node)> = Vec::new();

    // Above the threshold, group buckets and recurse in parallel: each
    // task produces its own `TreeUpdateBatch` which is merged into the
    // parent's batch after the join. Below it, fall through to the
    // in-place sequential loop that writes directly into `batch`,
    // avoiding the extra allocations.
    #[cfg(feature = "parallel")]
    if present.len() >= 4096 {
        use rayon::prelude::*;

        let mut bucket_slices: Vec<(u8, &[(&Key, LeafValue)])> = Vec::new();
        let mut pos = 0;
        while pos < present.len() {
            let bucket = bits_at(present[pos].0, depth, ARITY_BITS);
            let start = pos;
            while pos < present.len() && bits_at(present[pos].0, depth, ARITY_BITS) == bucket {
                pos += 1;
            }
            bucket_slices.push((bucket, &present[start..pos]));
        }

        let bucket_results: Vec<(u8, Option<Node>, TreeUpdateBatch)> = bucket_slices
            .into_par_iter()
            .map(|(bucket, sub)| {
                let sub_path = child_path(path, bucket, ARITY_BITS);
                let sub_kvs: Vec<(&Key, Option<LeafValue>)> =
                    sub.iter().map(|(k, v)| (*k, Some(*v))).collect();
                let mut local_batch = TreeUpdateBatch::default();
                let node = build_fresh::<H, ARITY_BITS>(
                    &sub_path,
                    new_version,
                    &sub_kvs,
                    &mut local_batch,
                );
                (bucket, node, local_batch)
            })
            .collect();

        for (bucket, node_opt, local_batch) in bucket_results {
            batch.new_nodes.extend(local_batch.new_nodes);
            batch.stale_nodes.extend(local_batch.stale_nodes);
            batch.leaf_delta += local_batch.leaf_delta;
            batch.bytes_delta += local_batch.bytes_delta;
            if let Some(node) = node_opt {
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

        return finalize::<NeverStore, H, ARITY_BITS>(
            NEVER_STORE,
            path,
            children,
            buffered,
            new_version,
            false,
            batch,
        )
        .expect("build_fresh finalize must not load preserved");
    }

    // Sequential: group `present` by bit-bucket and recurse in place.
    // `build_fresh` only borrows the sub-path, so a single working buffer
    // pushed/truncated per bucket replaces N per-bucket path clones.
    let mut sub_path_buf = path.clone();
    let base_bits = sub_path_buf.len();
    let mut pos = 0;
    while pos < present.len() {
        let bucket = bits_at(present[pos].0, depth, ARITY_BITS);
        let start = pos;
        while pos < present.len() && bits_at(present[pos].0, depth, ARITY_BITS) == bucket {
            pos += 1;
        }
        let sub = &present[start..pos];
        sub_path_buf.truncate(base_bits);
        sub_path_buf.push_bits(bucket, ARITY_BITS);
        let sub_kvs: Vec<(&Key, Option<LeafValue>)> =
            sub.iter().map(|(k, v)| (*k, Some(*v))).collect();

        if let Some(node) =
            build_fresh::<H, ARITY_BITS>(&sub_path_buf, new_version, &sub_kvs, batch)
        {
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
    kvs: &[(&Key, Option<LeafValue>)],
    batch: &mut TreeUpdateBatch,
) -> Option<Node> {
    let existing_len = i64::try_from(existing.value_len).expect("value length fits i64");

    // Single-kv case matching existing leaf: update or delete in place.
    // The leaf count is unchanged by an update but its bytes move by the
    // size difference; a delete drops both the leaf and its bytes.
    if kvs.len() == 1 && *kvs[0].0 == existing.key {
        return if let Some(value) = kvs[0].1 {
            batch.bytes_delta +=
                i64::try_from(value.len).expect("value length fits i64") - existing_len;
            Some(Node::Leaf(LeafNode::new(
                existing.key,
                value.hash,
                value.len,
            )))
        } else {
            batch.leaf_delta -= 1;
            batch.bytes_delta -= existing_len;
            None
        };
    }

    // Form a combined "present" set = existing leaf superseded by any
    // matching update, plus non-matching inserts.
    let mut combined: Vec<(Key, LeafValue)> = Vec::with_capacity(kvs.len() + 1);
    let mut existing_covered = false;
    for (k, v) in kvs {
        if **k == existing.key {
            existing_covered = true;
            if let Some(value) = v {
                combined.push((**k, *value));
            }
        } else if let Some(value) = v {
            combined.push((**k, *value));
        }
    }
    if !existing_covered {
        combined.push((
            existing.key,
            LeafValue::new(existing.value_hash, existing.value_len),
        ));
    }
    combined.sort_by_key(|(k, _)| *k);

    // This subtree held exactly one leaf before the merge; it holds
    // `combined.len()` after. Deletes of absent keys never enter
    // `combined`, so they contribute zero. The fresh rebuild below must
    // not count again — its keys are not new inserts from the tree's
    // perspective, they're this subtree's contents. The byte total moves
    // from the single prior leaf to the sum of the combined leaves.
    batch.leaf_delta += i64::try_from(combined.len()).expect("update batch size fits i64") - 1;
    let combined_bytes: i64 = combined
        .iter()
        .map(|(_, value)| i64::try_from(value.len).expect("value length fits i64"))
        .sum();
    batch.bytes_delta += combined_bytes - existing_len;

    match combined.len() {
        0 => None,
        1 => {
            let (k, value) = combined[0];
            Some(Node::Leaf(LeafNode::new(k, value.hash, value.len)))
        }
        _ => {
            let kvs: Vec<(&Key, Option<LeafValue>)> =
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
    fn root_path(&self) -> NibblePath {
        unreachable!("NeverStore accessed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Blake3Hasher;
    use crate::storage::MemoryStore;
    use crate::test_utils::{k, v, vl};

    type Jmt = Tree<Blake3Hasher, 1>;

    #[test]
    fn single_insert_produces_leaf_root() {
        let store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(1), Some(vl(10)))).collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        let expected = Blake3Hasher::hash_leaf(&k(1), &v(10));
        assert_eq!(res.root_hash, expected);
    }

    #[test]
    fn insert_then_read_roundtrip() {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(vl(10))),
            (k(2), Some(vl(20))),
            (k(3), Some(vl(30))),
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
        let v1: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(10))), (k(2), Some(vl(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(99)))).collect();
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
        let v1: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(10))), (k(2), Some(vl(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), None)).collect();
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
    fn leaf_delta_counts_fresh_inserts_and_ignores_absent_deletes() {
        let store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(vl(10))),
            (k(2), Some(vl(20))),
            (k(3), Some(vl(30))),
            (k(4), None), // delete of a key that never existed
        ]
        .into_iter()
        .collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        assert_eq!(res.batch.leaf_delta, 3);
    }

    #[test]
    fn leaf_delta_zero_for_value_updates() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(10))), (k(2), Some(vl(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(11))), (k(2), Some(vl(21)))]
            .into_iter()
            .collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, 0);
    }

    #[test]
    fn leaf_delta_negative_for_deletes() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(vl(10))),
            (k(2), Some(vl(20))),
            (k(3), Some(vl(30))),
        ]
        .into_iter()
        .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), None)).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);
        assert_eq!(r2.batch.leaf_delta, -1);

        let v3: BTreeMap<Key, Option<LeafValue>> =
            [(k(2), None), (k(3), None)].into_iter().collect();
        let r3 = Jmt::apply_updates(&store, Some(2), 3, &v3).unwrap();
        assert_eq!(r3.batch.leaf_delta, -2);
    }

    #[test]
    fn leaf_delta_counts_split_of_a_bare_leaf_root() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(10)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Root is a bare leaf; inserting a second key takes the
        // merge_leaf rebuild path.
        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(2), Some(vl(20)))).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, 1);
    }

    #[test]
    fn leaf_delta_mixed_batch() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(10))), (k(2), Some(vl(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Two new inserts, one value update, one real delete, one
        // delete of an absent key: +2 + 0 − 1 + 0 = +1.
        let v2: BTreeMap<Key, Option<LeafValue>> = [
            (k(3), Some(vl(30))),
            (k(4), Some(vl(40))),
            (k(1), Some(vl(11))),
            (k(2), None),
            (k(5), None),
        ]
        .into_iter()
        .collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, 1);
    }

    #[test]
    fn bytes_delta_sums_insert_lengths() {
        let store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(LeafValue::new(v(10), 100))),
            (k(2), Some(LeafValue::new(v(20), 250))),
            (k(3), None), // delete of an absent key contributes nothing
        ]
        .into_iter()
        .collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        assert_eq!(res.batch.leaf_delta, 2);
        assert_eq!(res.batch.bytes_delta, 350);
    }

    #[test]
    fn bytes_delta_signed_for_in_place_value_size_change() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(1), Some(LeafValue::new(v(10), 100)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Grow the value in place: leaf count unchanged, bytes +150.
        let v2: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(1), Some(LeafValue::new(v(11), 250)))).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);
        assert_eq!(r2.batch.leaf_delta, 0);
        assert_eq!(r2.batch.bytes_delta, 150);

        // Shrink it: -200.
        let v3: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(1), Some(LeafValue::new(v(12), 50)))).collect();
        let r3 = Jmt::apply_updates(&store, Some(2), 3, &v3).unwrap();
        assert_eq!(r3.batch.leaf_delta, 0);
        assert_eq!(r3.batch.bytes_delta, -200);
    }

    #[test]
    fn bytes_delta_subtracts_deleted_length() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(LeafValue::new(v(10), 100))),
            (k(2), Some(LeafValue::new(v(20), 70))),
        ]
        .into_iter()
        .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), None)).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, -1);
        assert_eq!(r2.batch.bytes_delta, -100);
    }

    #[test]
    fn bytes_delta_through_merge_leaf_rebuild() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(1), Some(LeafValue::new(v(10), 100)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Inserting a second key splits the bare-leaf root (the
        // merge_leaf rebuild path): +1 leaf, + the new value's bytes,
        // the prior leaf's bytes carried through unchanged.
        let v2: BTreeMap<Key, Option<LeafValue>> =
            std::iter::once((k(2), Some(LeafValue::new(v(20), 80)))).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, 1);
        assert_eq!(r2.batch.bytes_delta, 80);
    }

    #[test]
    fn bytes_delta_mixed_batch() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(LeafValue::new(v(10), 100))),
            (k(2), Some(LeafValue::new(v(20), 200))),
        ]
        .into_iter()
        .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // insert 30 (+90), insert 40 (+40), grow k1 100→130 (+30),
        // delete k2 (−200), delete absent k5 (0): net −40 bytes, +1 leaf.
        let v2: BTreeMap<Key, Option<LeafValue>> = [
            (k(3), Some(LeafValue::new(v(30), 90))),
            (k(4), Some(LeafValue::new(v(40), 40))),
            (k(1), Some(LeafValue::new(v(11), 130))),
            (k(2), None),
            (k(5), None),
        ]
        .into_iter()
        .collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        assert_eq!(r2.batch.leaf_delta, 1);
        assert_eq!(r2.batch.bytes_delta, -40);
    }

    #[test]
    fn value_length_does_not_affect_root() {
        let mk = |len_a: u64, len_b: u64| {
            let store = MemoryStore::new();
            let updates: BTreeMap<Key, Option<LeafValue>> = [
                (k(1), Some(LeafValue::new(v(10), len_a))),
                (k(2), Some(LeafValue::new(v(20), len_b))),
            ]
            .into_iter()
            .collect();
            Jmt::apply_updates(&store, None, 1, &updates)
                .unwrap()
                .root_hash
        };
        // Same keys and value hashes, wildly different lengths → identical
        // root: value_len sits outside the leaf hash preimage.
        assert_eq!(mk(1, 2), mk(9_999, 12_345));
    }

    #[test]
    fn sum_subtree_value_lens_totals_leaf_lengths() {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(LeafValue::new(v(10), 100))),
            (k(2), Some(LeafValue::new(v(20), 250))),
            (k(3), Some(LeafValue::new(v(30), 7))),
        ]
        .into_iter()
        .collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let root = store.get_root_key(1).unwrap();
        assert_eq!(Jmt::sum_subtree_value_lens(&store, &root).unwrap(), 357);
    }

    #[test]
    fn historical_reads_see_prior_version() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(10)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);
        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(99)))).collect();
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
            updates.insert(key, Some(LeafValue::new([i; 32], 1)));
        }
        let r = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&r);

        let root = store.get_root_key(1).unwrap();
        for (k, v) in &updates {
            assert_eq!(Jmt::get(&store, &root, k), v.map(|lv| lv.hash));
        }
    }

    #[test]
    fn delete_all_keys_produces_empty_tree() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = [(k(1), Some(vl(10))), (k(2), Some(vl(20)))]
            .into_iter()
            .collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> =
            [(k(1), None), (k(2), None)].into_iter().collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();
        store.apply(&r2);

        assert_eq!(r2.root_hash, EMPTY_HASH);
        assert!(store.get_root_key(2).is_none());
    }

    #[test]
    fn delete_nonexistent_is_noop() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(10)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 1, &v1).unwrap();
        store.apply(&r1);

        // Delete a key that isn't in the tree.
        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(99), None)).collect();
        let r2 = Jmt::apply_updates(&store, Some(1), 2, &v2).unwrap();

        assert_eq!(r1.root_hash, r2.root_hash);
    }

    #[test]
    fn non_monotonic_version_rejected() {
        let mut store = MemoryStore::new();
        let v1: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(1), Some(vl(10)))).collect();
        let r1 = Jmt::apply_updates(&store, None, 5, &v1).unwrap();
        store.apply(&r1);

        let v2: BTreeMap<Key, Option<LeafValue>> = std::iter::once((k(2), Some(vl(20)))).collect();
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

        let updates: BTreeMap<Key, Option<LeafValue>> =
            [(k1, Some(vl(1))), (k2, Some(vl(2)))].into_iter().collect();
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
        let updates: BTreeMap<Key, Option<LeafValue>> = [
            (k(1), Some(vl(10))),
            (k(2), Some(vl(20))),
            (k(3), Some(vl(30))),
            (k(4), Some(vl(40))),
        ]
        .into_iter()
        .collect();
        let r = Jmt4::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&r);

        let root = store.get_root_key(1).unwrap();
        for (key, val) in &updates {
            assert_eq!(Jmt4::get(&store, &root, key), val.map(|lv| lv.hash));
        }
    }
}
