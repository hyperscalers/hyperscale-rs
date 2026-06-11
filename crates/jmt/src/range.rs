//! Range enumeration and range proofs for state snap-sync.
//!
//! A joiner bootstraps a shard's committed state by fetching contiguous
//! key ranges from serving peers and verifying each range against the
//! shard's attested subtree root. Three primitives:
//!
//! - [`Tree::collect_range`] — enumerate up to `limit` leaves with
//!   keys in `[start, end]`, in ascending key order, at a pinned
//!   version (server side).
//! - [`Tree::prove_range`] — build a [`MultiProof`] covering a collected
//!   chunk (server side).
//! - [`Tree::verify_range`] — check a chunk against an expected root:
//!   every returned leaf is in the tree, *and* the chunk is complete —
//!   the tree holds no other leaf inside the span the chunk claims to
//!   cover (joiner side).
//!
//! # Completeness
//!
//! A plain multiproof authenticates inclusion only: a malicious server
//! could omit a leaf from the chunk and supply its subtree as an opaque
//! sibling hash, or prove a leaf it never returned. [`Tree::verify_range`]
//! closes both holes:
//!
//! - The proof's claims must be exactly the returned leaves plus at most
//!   two *boundary anchors* (non-inclusion claims at the span's ends) —
//!   a superset would let the server prove a leaf it never returned.
//! - Every non-empty sibling subtree's key interval must lie entirely
//!   outside the claimed-complete span `[start, span_end]`, where
//!   `span_end` is the last returned leaf when the chunk is truncated
//!   (`more = true`) or the requested end bound otherwise. An
//!   `EMPTY_HASH` sibling holds no leaves and is safe anywhere; lying
//!   `EMPTY_HASH` over a populated subtree breaks the root
//!   reconstruction instead.
//!
//! The boundary anchors exist because sibling intervals are aligned
//! blocks: a block holding only out-of-span leaves can still straddle a
//! span boundary, and would be indistinguishable from an omission.
//! Anchoring both ends opens the boundary paths, so every block that
//! survives as a sibling is entirely inside or entirely outside the
//! span — the interval test is exact. Anchors only prevent false
//! rejections; completeness never depends on the server supplying them.
//!
//! Verified import needs no dedicated machinery: a proof-checked chunk
//! feeds [`Tree::apply_updates_at`] to build the fresh tree, and the
//! final root must equal the attested root.

use crate::hasher::{EMPTY_HASH, Hash, Hasher};
use crate::multiproof::{
    ClaimTermination, MultiProof, ProofClaim, ProofError, check_claim_grid, terminal_group,
};
use crate::node::{Key, NibblePath, Node, NodeKey, ValueHash, bits_at};
use crate::storage::TreeReader;
use crate::tree::Tree;

/// One contiguous chunk of leaves enumerated from a tree, in ascending
/// key order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeChunk {
    /// `(key, value_hash)` pairs, strictly ascending by key.
    pub leaves: Vec<(Key, ValueHash)>,
    /// Whether leaves with keys greater than the last returned remain in
    /// the tree. When set, the chunk is complete only through its last
    /// leaf; the next fetch resumes immediately after it.
    pub more: bool,
}

impl<H: Hasher, const ARITY_BITS: u8> Tree<H, ARITY_BITS> {
    /// Enumerate up to `limit` leaves with keys in `[start, end]`
    /// (inclusive), in ascending key order, from the tree rooted at
    /// `root_key`.
    ///
    /// `root_key` pins both the version and the rooting prefix, so the
    /// enumeration is a consistent point-in-time read. Subtrees outside
    /// the span are skipped, so the walk's cost tracks the span's leaf
    /// population, not the tree's.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::RootMissing`] if `root_key` does not resolve
    /// in `store` (never committed or pruned — never conflated with an
    /// empty range), [`ProofError::MissingNode`] if a referenced child has
    /// been pruned underneath the walk, or [`ProofError::Malformed`] for a
    /// zero `limit` or an inverted range.
    pub fn collect_range<S>(
        store: &S,
        root_key: &NodeKey,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<RangeChunk, ProofError>
    where
        S: TreeReader,
    {
        if limit == 0 {
            return Err(ProofError::Malformed("zero range limit"));
        }
        if start > end {
            return Err(ProofError::Malformed("inverted range"));
        }
        if store.get_node(root_key).is_none() {
            return Err(ProofError::RootMissing);
        }
        // Collect one extra leaf: its presence is the `more` signal.
        let mut leaves = Vec::new();
        let mut current = root_key.clone();
        collect_rec::<S, ARITY_BITS>(store, &mut current, (start, end), limit + 1, &mut leaves)?;
        let more = leaves.len() > limit;
        if more {
            leaves.truncate(limit);
        }
        Ok(RangeChunk { leaves, more })
    }

    /// Build a [`MultiProof`] covering a collected chunk over the range
    /// `[start, requested_end]`.
    ///
    /// The proof covers the chunk's keys plus the boundary anchors: a
    /// claim at `start`, and one at `requested_end` when the chunk is
    /// exhaustive (`more = false`). See the module docs for why the
    /// anchors are needed.
    ///
    /// # Errors
    ///
    /// See [`Tree::prove`].
    pub fn prove_range<S>(
        store: &S,
        root_key: &NodeKey,
        start: &Key,
        requested_end: &Key,
        chunk: &RangeChunk,
    ) -> Result<MultiProof, ProofError>
    where
        S: TreeReader,
    {
        let mut keys: Vec<Key> = chunk.leaves.iter().map(|(k, _)| *k).collect();
        keys.push(*start);
        if !chunk.more {
            keys.push(*requested_end);
        }
        Self::prove(store, root_key, &keys)
    }

    /// Verify a range chunk against `expected_root`.
    ///
    /// `root_path` is the prefix the tree is rooted at — the caller knows
    /// it (a shard's prefix), so a proof claiming a different rooting
    /// depth is rejected outright. `start` and `requested_end` are the
    /// requested key range (inclusive); both must sit under `root_path`.
    ///
    /// On success the chunk's leaves are exactly the tree's leaves in
    /// `[start, span_end]`, where `span_end` is the last returned leaf if
    /// `chunk.more`, or `requested_end` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::RangeIncomplete`] when the proof shows the
    /// tree holds a leaf inside the claimed span that the chunk omits;
    /// [`ProofError::ValueMismatch`] when a claim disagrees with a
    /// returned leaf; [`ProofError::RootMismatch`] when the reconstructed
    /// root differs from `expected_root`; and [`ProofError::Malformed`]
    /// for structural violations.
    pub fn verify_range(
        proof: &MultiProof,
        expected_root: Hash,
        root_path: &NibblePath,
        start: &Key,
        requested_end: &Key,
        chunk: &RangeChunk,
    ) -> Result<(), ProofError> {
        let root_depth = root_path.len();
        if proof.root_depth_bits != root_depth {
            return Err(ProofError::Malformed("proof rooted at unexpected depth"));
        }
        check_claim_grid::<ARITY_BITS>(&proof.claims, root_depth)?;
        if start > requested_end {
            return Err(ProofError::Malformed("inverted range"));
        }
        if NibblePath::from_key_prefix(start, root_depth) != *root_path
            || NibblePath::from_key_prefix(requested_end, root_depth) != *root_path
        {
            return Err(ProofError::Malformed("range outside the proven subtree"));
        }

        // Chunk shape: strictly ascending, inside [start, requested_end].
        for pair in chunk.leaves.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(ProofError::Malformed("chunk leaves not strictly ascending"));
            }
        }
        if let Some((first, _)) = chunk.leaves.first()
            && first < start
        {
            return Err(ProofError::Malformed("chunk leaf before range start"));
        }
        if let Some((last, _)) = chunk.leaves.last()
            && last > requested_end
        {
            return Err(ProofError::Malformed("chunk leaf past range end"));
        }
        if chunk.more && chunk.leaves.is_empty() {
            return Err(ProofError::Malformed("truncated chunk with no leaves"));
        }
        let span_end: Key = chunk
            .leaves
            .last()
            .filter(|_| chunk.more)
            .map_or(*requested_end, |(last, _)| *last);

        if proof.claims.is_empty() {
            // Only an entirely empty tree verifies with an empty proof.
            return if chunk.leaves.is_empty() && expected_root == EMPTY_HASH {
                Ok(())
            } else {
                Err(ProofError::Malformed("empty proof for non-empty root"))
            };
        }

        check_claims_match_chunk(&proof.claims, chunk, start, &span_end)?;

        // Reconstruct the root, rejecting any non-empty sibling inside
        // the span.
        let mut prefix = [0u8; 32];
        prefix[..root_path.as_bytes().len()].copy_from_slice(root_path.as_bytes());
        let (computed, consumed) = verify_range_rec::<H, ARITY_BITS>(
            &proof.claims,
            root_depth,
            &mut prefix,
            &proof.siblings,
            (start, &span_end),
        )?;
        if consumed != proof.siblings.len() {
            return Err(ProofError::Malformed("trailing siblings"));
        }
        if computed != expected_root {
            return Err(ProofError::RootMismatch);
        }
        Ok(())
    }
}

/// Check that `claims` are exactly `chunk`'s leaves plus boundary
/// anchors — a superset would let the server prove (and the verifier
/// hash in) a leaf it never returned. An anchor claiming an in-span
/// leaf the chunk omits is the omission itself.
fn check_claims_match_chunk(
    claims: &[ProofClaim],
    chunk: &RangeChunk,
    start: &Key,
    span_end: &Key,
) -> Result<(), ProofError> {
    for pair in claims.windows(2) {
        if pair[0].key >= pair[1].key {
            return Err(ProofError::Malformed("claims not strictly ascending"));
        }
    }
    let leaf_key = |key: &Key| chunk.leaves.binary_search_by_key(key, |(k, _)| *k).is_ok();
    let mut leaf_idx = 0usize;
    for claim in claims {
        if leaf_idx < chunk.leaves.len() && claim.key == chunk.leaves[leaf_idx].0 {
            let (_, value_hash) = &chunk.leaves[leaf_idx];
            if !matches!(claim.termination, ClaimTermination::Leaf)
                || claim.value_hash != Some(*value_hash)
            {
                return Err(ProofError::ValueMismatch);
            }
            leaf_idx += 1;
        } else if claim.key == *start || claim.key == *span_end {
            match &claim.termination {
                // A leaf at an anchor the chunk doesn't carry is an
                // in-span leaf the server withheld.
                ClaimTermination::Leaf => return Err(ProofError::RangeIncomplete),
                ClaimTermination::EmptySubtree => {}
                ClaimTermination::LeafMismatch { stored_key, .. } => {
                    if stored_key >= start && stored_key <= span_end && !leaf_key(stored_key) {
                        return Err(ProofError::RangeIncomplete);
                    }
                }
            }
        } else {
            return Err(ProofError::Malformed("claim is neither leaf nor anchor"));
        }
    }
    if leaf_idx != chunk.leaves.len() {
        return Err(ProofError::Malformed("claims do not cover chunk leaves"));
    }
    Ok(())
}

/// Depth-first in-order leaf collection over `span` (inclusive),
/// capped at `cap` entries.
fn collect_rec<S, const ARITY_BITS: u8>(
    store: &S,
    node_key: &mut NodeKey,
    span: (&Key, &Key),
    cap: usize,
    out: &mut Vec<(Key, ValueHash)>,
) -> Result<(), ProofError>
where
    S: TreeReader,
{
    if out.len() >= cap {
        return Ok(());
    }
    let node = store
        .get_node(node_key)
        .ok_or_else(|| ProofError::MissingNode {
            key: node_key.clone(),
        })?;
    let depth = node_key.path.len();

    match &*node {
        Node::Leaf(leaf) => {
            if leaf.key >= *span.0 && leaf.key <= *span.1 {
                out.push((leaf.key, leaf.value_hash));
            }
        }
        Node::Internal(internal) => {
            for bucket in 0..(1usize << ARITY_BITS) {
                if out.len() >= cap {
                    break;
                }
                let Some(child) = internal.children.get(bucket).and_then(|c| c.as_ref()) else {
                    continue;
                };
                let bucket_u8 = u8::try_from(bucket).unwrap_or(u8::MAX);
                // Skip subtrees entirely outside the span.
                let (low, high) = subspan(&node_key.path, ARITY_BITS, u64::from(bucket_u8));
                if high < *span.0 || low > *span.1 {
                    continue;
                }
                let saved_version = node_key.version;
                node_key.version = child.version;
                node_key.path.push_bits(bucket_u8, ARITY_BITS);
                let result = collect_rec::<S, ARITY_BITS>(store, node_key, span, cap, out);
                node_key.path.truncate(depth);
                node_key.version = saved_version;
                result?;
            }
        }
    }
    Ok(())
}

/// Reconstruct the subtree hash for `claims`, rejecting any non-empty
/// sibling whose key interval overlaps the claimed-complete `span`.
///
/// `prefix` carries the bits of the path walked so far; bits at offsets
/// `>= depth` are zero on entry and restored to zero on return, so a
/// sibling's key interval is `[prefix, prefix-with-ones-below]`.
fn verify_range_rec<H, const ARITY_BITS: u8>(
    claims: &[ProofClaim],
    depth: u16,
    prefix: &mut Key,
    siblings: &[Hash],
    span: (&Key, &Key),
) -> Result<(Hash, usize), ProofError>
where
    H: Hasher,
{
    debug_assert!(!claims.is_empty());

    if let Some(hash) = terminal_group::<H>(claims, depth)? {
        return Ok((hash, 0));
    }

    let arity = 1usize << ARITY_BITS as usize;
    let child_depth = depth + u16::from(ARITY_BITS);
    let mut consumed = 0usize;
    let mut children: Vec<Hash> = vec![EMPTY_HASH; arity];
    let mut pos = 0usize;
    for (bucket, child) in children.iter_mut().enumerate() {
        let bucket_u8 = u8::try_from(bucket).unwrap_or(u8::MAX);
        let start_idx = pos;
        while pos < claims.len() && bits_at(&claims[pos].key, depth, ARITY_BITS) as usize == bucket
        {
            pos += 1;
        }
        if pos == start_idx {
            let sibling = *siblings.get(consumed).ok_or(ProofError::Malformed(
                "not enough siblings to reconstruct internal node",
            ))?;
            consumed += 1;
            // A non-empty sibling subtree must lie entirely outside the
            // span, otherwise the chunk omits leaves it claims to cover.
            // An EMPTY_HASH sibling holds no leaves and is safe anywhere;
            // lying EMPTY_HASH over a populated subtree breaks the root
            // reconstruction instead.
            if sibling != EMPTY_HASH {
                set_bits(prefix, depth, ARITY_BITS, bucket_u8);
                let low = *prefix;
                let mut high = *prefix;
                fill_ones_from(&mut high, child_depth);
                set_bits(prefix, depth, ARITY_BITS, 0);
                if high >= *span.0 && low <= *span.1 {
                    return Err(ProofError::RangeIncomplete);
                }
            }
            *child = sibling;
        } else {
            set_bits(prefix, depth, ARITY_BITS, bucket_u8);
            let result = verify_range_rec::<H, ARITY_BITS>(
                &claims[start_idx..pos],
                child_depth,
                prefix,
                &siblings[consumed..],
                span,
            );
            set_bits(prefix, depth, ARITY_BITS, 0);
            let (hash, used) = result?;
            *child = hash;
            consumed += used;
        }
    }
    if pos != claims.len() {
        return Err(ProofError::Malformed("claims not covered by bucket split"));
    }
    Ok((H::hash_internal(&children), consumed))
}

/// The key immediately after `key`, or `None` at the key-space maximum.
#[must_use]
pub fn next_key(key: &Key) -> Option<Key> {
    let mut out = *key;
    for byte in out.iter_mut().rev() {
        if *byte == u8::MAX {
            *byte = 0;
        } else {
            *byte += 1;
            return Some(out);
        }
    }
    None
}

/// The `index`-th of `2^split_bits` equal key sub-spans of the subtree
/// at `path`, as an inclusive `(low, high)` pair.
///
/// Snap-sync fan-out partitions a shard's span this way so peers serve
/// disjoint ranges in parallel.
///
/// # Panics
///
/// Panics if `index >= 2^split_bits`, `split_bits > 8`, or the split
/// extends past the 256-bit key space.
#[must_use]
pub fn subspan(path: &NibblePath, split_bits: u8, index: u64) -> (Key, Key) {
    assert!(split_bits <= 8, "subspan splits at most 8 bits at a time");
    assert!(
        index < 1 << split_bits,
        "subspan index {index} out of range for {split_bits} split bits",
    );
    assert!(
        usize::from(path.len()) + usize::from(split_bits) <= 256,
        "subspan split extends past the key space",
    );
    let mut low = [0u8; 32];
    low[..path.as_bytes().len()].copy_from_slice(path.as_bytes());
    set_bits(
        &mut low,
        path.len(),
        split_bits,
        u8::try_from(index).expect("index < 2^split_bits <= 256"),
    );
    let mut high = low;
    fill_ones_from(&mut high, path.len() + u16::from(split_bits));
    (low, high)
}

/// Overwrite `count` bits of `key` at bit offset `at` (from the MSB)
/// with the low `count` bits of `val`.
fn set_bits(key: &mut Key, at: u16, count: u8, val: u8) {
    debug_assert!(count <= 8);
    debug_assert!(usize::from(at) + usize::from(count) <= 256);

    let byte = usize::from(at / 8);
    let off = usize::from(at % 8);
    let shift = 16 - off - usize::from(count);
    let mask = ((1u16 << count) - 1) << shift;
    let placed = (u16::from(val) << shift) & mask;

    let hi_mask = u8::try_from(mask >> 8).unwrap_or(u8::MAX);
    let hi_placed = u8::try_from(placed >> 8).unwrap_or(u8::MAX);
    key[byte] = (key[byte] & !hi_mask) | hi_placed;
    if byte + 1 < key.len() {
        let lo_mask = u8::try_from(mask & 0xFF).unwrap_or(u8::MAX);
        let lo_placed = u8::try_from(placed & 0xFF).unwrap_or(u8::MAX);
        key[byte + 1] = (key[byte + 1] & !lo_mask) | lo_placed;
    }
}

/// Set every bit of `key` at offsets `>= from` to one.
fn fill_ones_from(key: &mut Key, from: u16) {
    let from = usize::from(from);
    if from >= 256 {
        return;
    }
    let byte = from / 8;
    let off = from % 8;
    key[byte] |= u8::MAX >> off;
    for b in key.iter_mut().skip(byte + 1) {
        *b = u8::MAX;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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

    fn build_store(entries: &[(Key, ValueHash)]) -> (MemoryStore, NodeKey, Hash) {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let root = store.get_root_key(1).unwrap();
        (store, root, res.root_hash)
    }

    /// Entries under the 4-bit prefix 0xA, in a tree rooted at that prefix.
    fn build_prefix_store(
        count: u8,
    ) -> (
        MemoryStore,
        NodeKey,
        Hash,
        NibblePath,
        Vec<(Key, ValueHash)>,
    ) {
        let mut prefix = NibblePath::empty();
        prefix.push_bits(0b1010, 4);

        let mut sorted: Vec<(Key, ValueHash)> = (0..count)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = 0xA0 | (i % 16);
                key[1] = i;
                (key, v(i.wrapping_mul(7)))
            })
            .collect();
        sorted.sort_unstable_by_key(|(k, _)| *k);

        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> =
            sorted.iter().map(|(k, val)| (*k, Some(*val))).collect();
        let res = Jmt::apply_updates_at(&store, None, 1, &prefix, &updates).unwrap();
        store.apply(&res);
        let root_key = store.get_root_key(1).unwrap();
        (store, root_key, res.root_hash, prefix, sorted)
    }

    /// The span covered by the 4-bit prefix 0xA.
    fn prefix_span() -> (Key, Key) {
        let mut low = [0u8; 32];
        low[0] = 0xA0;
        let mut high = [0xFFu8; 32];
        high[0] = 0xAF;
        (low, high)
    }

    #[test]
    fn round_trip_whole_keyspace_with_import() {
        let entries: Vec<(Key, ValueHash)> = (0u8..50).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        assert_eq!(chunk.leaves.len(), 50);
        assert!(!chunk.more);

        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();

        // Verified import: the chunk rebuilds an identical tree.
        let imported_store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> = chunk
            .leaves
            .iter()
            .map(|(key, val)| (*key, Some(*val)))
            .collect();
        let res = Jmt::apply_updates(&imported_store, None, 1, &updates).unwrap();
        assert_eq!(res.root_hash, root_hash);
    }

    #[test]
    fn chunked_prefix_rooted_round_trip_with_import() {
        let (store, root_key, root_hash, prefix, entries) = build_prefix_store(24);
        let (span_low, span_high) = prefix_span();

        // Paginate in chunks of 5, verifying each chunk independently.
        let mut collected: Vec<(Key, ValueHash)> = Vec::new();
        let mut cursor = span_low;
        loop {
            let chunk = Jmt::collect_range(&store, &root_key, &cursor, &span_high, 5).unwrap();
            let proof = Jmt::prove_range(&store, &root_key, &cursor, &span_high, &chunk).unwrap();
            Jmt::verify_range(&proof, root_hash, &prefix, &cursor, &span_high, &chunk).unwrap();
            collected.extend_from_slice(&chunk.leaves);
            if !chunk.more {
                break;
            }
            cursor = next_key(&chunk.leaves.last().unwrap().0).unwrap();
        }
        assert_eq!(collected, entries);

        // Verified import at the same prefix reproduces the attested root.
        let imported_store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> = collected
            .iter()
            .map(|(key, val)| (*key, Some(*val)))
            .collect();
        let res = Jmt::apply_updates_at(&imported_store, None, 1, &prefix, &updates).unwrap();
        assert_eq!(res.root_hash, root_hash);
    }

    #[test]
    fn mid_span_pagination_resume_verifies() {
        // Resume from an arbitrary cursor: the left-boundary blocks hold
        // only already-fetched leaves; the start anchor keeps them from
        // reading as omissions.
        let entries: Vec<(Key, ValueHash)> = (0u8..32).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let cursor = next_key(&k(13)).unwrap();
        let end = [0xFFu8; 32];
        let chunk = Jmt::collect_range(&store, &root, &cursor, &end, 100).unwrap();
        assert_eq!(chunk.leaves.len(), 18);
        let proof = Jmt::prove_range(&store, &root, &cursor, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &cursor,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn omitted_middle_leaf_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let mut chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        chunk.leaves.remove(5);
        // The server proves exactly what it returned — the omitted leaf's
        // subtree becomes a sibling inside the span.
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::RangeIncomplete));
    }

    #[test]
    fn truncated_tail_claiming_complete_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let mut chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        chunk.leaves.pop();
        assert!(!chunk.more);
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::RangeIncomplete));
    }

    #[test]
    fn truncated_tail_with_more_is_valid_pagination() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let mut chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        chunk.leaves.pop();
        chunk.more = true;
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn tampered_value_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let mut chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        chunk.leaves[3].1 = v(99);
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::ValueMismatch));
    }

    #[test]
    fn fabricated_extra_leaf_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i * 2), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let mut chunk = Jmt::collect_range(&store, &root, &start, &end, 100).unwrap();
        // Insert a leaf the tree does not hold (odd key inside the range).
        chunk.leaves.insert(3, (k(5), v(55)));
        chunk.leaves.sort_unstable_by_key(|(key, _)| *key);
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::ValueMismatch));
    }

    #[test]
    fn empty_gap_range_verifies() {
        // Leaves at 0x00.. and 0xF0..; the range [0x20.., 0x30..] is empty.
        let entries = vec![(k(0x00), v(1)), (k(0xF0), v(2))];
        let (store, root, root_hash) = build_store(&entries);

        let start = k(0x20);
        let end = k(0x30);
        let chunk = RangeChunk {
            leaves: Vec::new(),
            more: false,
        };
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn empty_gap_range_with_straddling_neighbor_verifies() {
        // A leaf just past the requested end whose aligned block straddles
        // the end boundary — the end anchor keeps it from reading as an
        // omission.
        let entries = vec![(k(0x00), v(1)), (k(0x2F), v(2))];
        let (store, root, root_hash) = build_store(&entries);

        let start = next_key(&k(0x00)).unwrap();
        let end = k(0x20);
        let chunk = RangeChunk {
            leaves: Vec::new(),
            more: false,
        };
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn empty_chunk_over_populated_span_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let chunk = RangeChunk {
            leaves: Vec::new(),
            more: false,
        };
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::RangeIncomplete));
    }

    #[test]
    fn more_with_no_leaves_rejected() {
        let entries = vec![(k(1), v(1))];
        let (store, root, root_hash) = build_store(&entries);

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let chunk = RangeChunk {
            leaves: Vec::new(),
            more: true,
        };
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::Malformed(_)));
    }

    #[test]
    fn unexpected_root_depth_rejected() {
        let (store, root_key, root_hash, _prefix, _entries) = build_prefix_store(8);
        let (span_low, span_high) = prefix_span();

        let chunk = Jmt::collect_range(&store, &root_key, &span_low, &span_high, 100).unwrap();
        let proof = Jmt::prove_range(&store, &root_key, &span_low, &span_high, &chunk).unwrap();
        // The proof is rooted at the 4-bit prefix; claiming the empty
        // root path must be rejected before any reconstruction.
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &span_low,
            &span_high,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::Malformed(_)));
    }

    #[test]
    fn range_outside_root_prefix_rejected() {
        let (_store, _root_key, root_hash, prefix, _entries) = build_prefix_store(8);

        // A range under prefix 0xB against a tree rooted at 0xA.
        let mut low = [0u8; 32];
        low[0] = 0xB0;
        let mut high = [0xFFu8; 32];
        high[0] = 0xBF;
        let chunk = RangeChunk {
            leaves: Vec::new(),
            more: false,
        };
        let proof = MultiProof {
            root_depth_bits: 4,
            claims: Vec::new(),
            siblings: Vec::new(),
        };
        let err = Jmt::verify_range(&proof, root_hash, &prefix, &low, &high, &chunk).unwrap_err();
        assert!(matches!(err, ProofError::Malformed(_)));
    }

    #[test]
    fn leaf_outside_requested_range_rejected() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let start = k(2);
        let end = [0xFFu8; 32];
        let chunk = Jmt::collect_range(&store, &root, &[0u8; 32], &[0xFFu8; 32], 100).unwrap();
        // First leaf (key 0) precedes the verified range start.
        let proof = Jmt::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        let err = Jmt::verify_range(
            &proof,
            root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::Malformed(_)));
    }

    #[test]
    fn collect_range_paginates_in_key_order() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i * 3), v(i))).collect();
        let (store, root, _root_hash) = build_store(&entries);

        let chunk = Jmt::collect_range(&store, &root, &[0u8; 32], &[0xFFu8; 32], 4).unwrap();
        assert_eq!(chunk.leaves.len(), 4);
        assert!(chunk.more);
        let keys: Vec<Key> = chunk.leaves.iter().map(|(key, _)| *key).collect();
        assert_eq!(keys, vec![k(0), k(3), k(6), k(9)]);

        let resumed =
            Jmt::collect_range(&store, &root, &next_key(&k(9)).unwrap(), &[0xFFu8; 32], 100)
                .unwrap();
        assert_eq!(resumed.leaves.len(), 6);
        assert!(!resumed.more);
        assert_eq!(resumed.leaves.first().unwrap().0, k(12));
    }

    #[test]
    fn collect_range_honors_the_end_bound() {
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i), v(i))).collect();
        let (store, root, _root_hash) = build_store(&entries);

        // End mid-tree: enumeration stops at the bound, exhaustively.
        let chunk = Jmt::collect_range(&store, &root, &k(2), &k(6), 100).unwrap();
        let keys: Vec<Key> = chunk.leaves.iter().map(|(key, _)| *key).collect();
        assert_eq!(keys, vec![k(2), k(3), k(4), k(5), k(6)]);
        assert!(!chunk.more, "no in-range leaves remain");

        // End exactly on a leaf key: the leaf is included.
        let chunk = Jmt::collect_range(&store, &root, &k(0), &k(0), 100).unwrap();
        assert_eq!(chunk.leaves.len(), 1);
        assert!(!chunk.more);

        // `more` reflects in-range leaves only, even when the next
        // tree leaf past the limit probe lies outside the span.
        let chunk = Jmt::collect_range(&store, &root, &k(2), &k(6), 3).unwrap();
        assert_eq!(chunk.leaves.len(), 3);
        assert!(chunk.more, "in-range leaves remain past the limit");
        let chunk = Jmt::collect_range(&store, &root, &k(2), &k(6), 5).unwrap();
        assert_eq!(chunk.leaves.len(), 5);
        assert!(!chunk.more, "the span is exhausted at exactly the limit");
    }

    #[test]
    fn collect_range_empty_span_collects_nothing() {
        // A span between two adjacent leaves holds nothing; the walk
        // must not spill into leaves past `end`.
        let entries: Vec<(Key, ValueHash)> = (0u8..10).map(|i| (k(i * 10), v(i))).collect();
        let (store, root, _root_hash) = build_store(&entries);

        let chunk = Jmt::collect_range(&store, &root, &k(1), &k(9), 100).unwrap();
        assert!(chunk.leaves.is_empty());
        assert!(!chunk.more);

        let err = Jmt::collect_range(&store, &root, &k(9), &k(1), 100).unwrap_err();
        assert!(matches!(err, ProofError::Malformed(_)));
    }

    #[test]
    fn collect_range_missing_root_errors() {
        let store = MemoryStore::new();
        let root = NodeKey::root(1);
        let err = Jmt::collect_range(&store, &root, &[0u8; 32], &[0xFFu8; 32], 10).unwrap_err();
        assert!(matches!(err, ProofError::RootMissing));
    }

    #[test]
    fn radix4_range_round_trip() {
        type Jmt4 = Tree<Blake3Hasher, 2>;
        let mut store = MemoryStore::new();
        let entries: Vec<(Key, ValueHash)> = (0u8..16).map(|i| (k(i), v(i * 3))).collect();
        let updates: BTreeMap<Key, Option<ValueHash>> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let res = Jmt4::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let root = store.get_root_key(1).unwrap();

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
        let chunk = Jmt4::collect_range(&store, &root, &start, &end, 100).unwrap();
        assert_eq!(chunk.leaves.len(), 16);
        let proof = Jmt4::prove_range(&store, &root, &start, &end, &chunk).unwrap();
        Jmt4::verify_range(
            &proof,
            res.root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();

        let mut tampered = chunk;
        tampered.leaves.remove(7);
        let proof = Jmt4::prove_range(&store, &root, &start, &end, &tampered).unwrap();
        let err = Jmt4::verify_range(
            &proof,
            res.root_hash,
            &NibblePath::empty(),
            &start,
            &end,
            &tampered,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::RangeIncomplete));
    }
}
