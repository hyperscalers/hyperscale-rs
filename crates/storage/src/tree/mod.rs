//! Binary Jellyfish Merkle Tree (Blake3) state tree — flat single-tree design.
//!
//! All substates across all owners live in a single JMT.
//!
//! # Key mapping
//!
//! A substate key's two halves *are* its 48-byte JMT key — the leaf
//! is read off the key with no hashing, so one owner's substates form a
//! contiguous subtree under the prefix its own bits name (see
//! `hyperscale_types::state_key`).
//!
//! # Value encoding
//!
//! The tree stores per-value hashes (`BLAKE3(raw_value_bytes)`) as
//! `ValueHash`. Raw substate bytes are stored separately in the state
//! CF (current values) and state-history CF (per-write prior values),
//! not in the tree.

mod collected_writes;
pub mod proofs;
mod snapshot;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub use collected_writes::CollectedWrites;
use hyperscale_jmt::{
    Blake3Hasher, Key, LeafValue, NibblePath, Node as JmtNode, NodeKey, Tree, TreeReader,
    UpdateResult, ValueHash,
};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{BlockHeight, Hash, SettledWrites, StateRoot, SubstateKey, SubstateLeaf};
use rayon::prelude::*;
pub use snapshot::JmtSnapshot;

use crate::shard::writes::entry_leaf_rows;

/// Layered tree reader that overlays pending JMT snapshots on a base store.
///
/// Used during chained verification: block N+1's `prepare_block_commit` needs
/// tree nodes from block N's verification, which hasn't committed yet. The
/// overlay provides those nodes without mutating the shared tree store —
/// avoiding corruption from abandoned blocks (view changes / forks).
pub struct OverlayTreeReader<'a, S> {
    base: &'a S,
    /// Overlay nodes indexed by `NodeKey` for O(1) lookup.
    nodes: HashMap<NodeKey, Arc<JmtNode>>,
}

impl<'a, S> OverlayTreeReader<'a, S> {
    /// Create a new `OverlayTreeReader`.
    pub fn new(base: &'a S, snapshots: &[Arc<JmtSnapshot>]) -> Self {
        let mut nodes = HashMap::new();
        for snapshot in snapshots {
            for (key, node) in &snapshot.nodes {
                nodes.insert(key.clone(), Arc::clone(node));
            }
        }
        Self { base, nodes }
    }
}

impl<S: TreeReader + Sync> TreeReader for OverlayTreeReader<'_, S> {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<JmtNode>> {
        self.nodes
            .get(key)
            .cloned()
            .or_else(|| self.base.get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        // The root for this version lives at the store's root path (empty for a
        // whole-keyspace store, the shard prefix for a per-shard store).
        let root_key = NodeKey::new(version, self.base.root_path());
        if self.nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            self.base.get_root_key(version)
        }
    }

    fn root_path(&self) -> NibblePath {
        self.base.root_path()
    }
}

/// The JMT configuration this backend uses: binary arity, Blake3 hasher.
/// Centralizing as a type alias so callers don't repeat the parameters.
pub type Jmt = Tree<Blake3Hasher, 1>;

/// A JMT root hash as a [`StateRoot`], mapping the empty-tree sentinel
/// (all zeroes) to `StateRoot::ZERO`.
#[must_use]
pub(crate) fn state_root_from_jmt(root_hash: [u8; 32]) -> StateRoot {
    if root_hash == [0u8; 32] {
        StateRoot::ZERO
    } else {
        StateRoot::from_raw(Hash::from_hash_bytes(&root_hash))
    }
}

/// Apply one batch of snap-synced import leaves to the JMT at
/// `version`, on top of `parent_version` (`None` for the first batch of
/// an import into an empty store).
///
/// The leaves' substate keys are the leaf keys, so the tree is rebuilt
/// from them directly instead of re-deriving through
/// [`put_at_version`]. The caller persists the result's node batch plus
/// whatever raw-value records its backend keeps; a single-batch import
/// stores the returned root as the imported state root, a chunked one
/// chains batches through `parent_version` and keeps only the final
/// root.
///
/// # Errors
///
/// Returns a description when the JMT update fails.
pub fn import_leaf_updates<S: TreeReader>(
    store: &S,
    root_path: &NibblePath,
    parent_version: Option<u64>,
    version: u64,
    leaves: &[SubstateLeaf],
) -> Result<(StateRoot, UpdateResult), String> {
    let updates: BTreeMap<Key, Option<LeafValue>> = leaves
        .iter()
        .map(|leaf| {
            let len = leaf.value.len() as u64;
            (
                leaf.key.to_bytes(),
                Some(LeafValue::new(hash_value(&leaf.value), len)),
            )
        })
        .collect();
    let result = Jmt::apply_updates_at(store, parent_version, version, root_path, &updates)
        .map_err(|e| format!("snap-sync JMT import: {e}"))?;
    Ok((state_root_from_jmt(result.root_hash), result))
}

/// Hash a raw value to a 32-byte value hash stored in leaves.
#[must_use]
pub fn hash_value(value: &[u8]) -> ValueHash {
    jmt_value_hash(value)
}

/// Returns `None` when the JMT is truly empty (zero root) — no parent
/// node exists.
///
/// An empty tree has no root node at any version, including a split
/// child that adopted an empty subtree at a nonzero genesis height.
/// Otherwise returns `Some(block_height)`.
#[must_use]
pub fn jmt_parent_height(block_height: BlockHeight, root: StateRoot) -> Option<BlockHeight> {
    if root == StateRoot::ZERO {
        None
    } else {
        Some(block_height)
    }
}

/// The root node at `version`, in `pending_snapshots` or `store`.
#[must_use]
pub(crate) fn materialized_root<S: TreeReader>(
    store: &S,
    pending_snapshots: &[Arc<JmtSnapshot>],
    version: u64,
) -> Option<Arc<JmtNode>> {
    let root_key = NodeKey::new(version, store.root_path());
    pending_snapshots
        .iter()
        .find_map(|s| {
            s.nodes
                .iter()
                .find(|(k, _)| *k == root_key)
                .map(|(_, n)| Arc::clone(n))
        })
        .or_else(|| store.get_node(&root_key))
}

/// Build a no-op `JmtSnapshot` for a block with no state changes (empty receipts).
///
/// The state root is unchanged (`parent_state_root`). We copy the parent's
/// root node to the new version so the overlay chain stays intact; a
/// parent descending from the zero root has none to copy.
///
/// # Safety assumption
///
/// This function sets `result_root = parent_state_root` unconditionally.
/// Callers must only use this for blocks with genuinely empty receipts
/// (no state changes). For consensus blocks, this is verified by the
/// verification pipeline. For synced blocks, the QC signature attests
/// to correctness — a QC-certified block with empty receipts is
/// guaranteed to have `state_root == parent_state_root`.
pub fn noop_jmt_snapshot<S: TreeReader>(
    store: &S,
    pending_snapshots: &[Arc<JmtSnapshot>],
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    block_height: BlockHeight,
) -> JmtSnapshot {
    let mut nodes = Vec::new();

    if let Some(parent_ver) = jmt_parent_height(parent_block_height, parent_state_root)
        && let Some(node) = materialized_root(store, pending_snapshots, parent_ver.inner())
    {
        nodes.push((NodeKey::new(block_height.inner(), store.root_path()), node));
    }

    JmtSnapshot {
        base_root: parent_state_root,
        base_height: parent_block_height,
        result_root: parent_state_root,
        new_height: block_height,
        nodes,
        stale_node_keys: Vec::new(),
        bytes_delta: 0,
        settled: SettledWrites::default(),
    }
}

/// Flatten writes into `(key, optional_value)` work items; `None`
/// values are deletes.
///
/// The tree stores values, so it takes the settled form and only the
/// settled form — a movement is relative and has no place here. That is
/// a type, not a check, because the failure it prevents is silent: this
/// walk would simply not see a movement, and the root would be attested
/// without the change in it.
///
/// Ordered-collection entries flatten to their leaf form — the derived
/// leaf key, the self-describing [`hyperscale_types::EntryLeaf`]
/// value — so the attested root covers every entry the way it covers
/// every cell.
fn flatten_work_items(writes: &SettledWrites) -> Vec<(SubstateKey, Option<Cow<'_, [u8]>>)> {
    writes
        .cells()
        .iter()
        .map(|(key, change)| (*key, change.as_deref().map(Cow::Borrowed)))
        .chain(
            entry_leaf_rows(writes.entries())
                .into_iter()
                .map(|(key, change)| (key, change.map(Cow::Owned))),
        )
        .collect()
}

/// Computes new state tree nodes for the given database updates, returning
/// the new root hash and all collected writes.
///
/// Takes any `TreeReader` — the caller provides a reader appropriate
/// to its storage backend.
///
/// `parent_version` is the version of the existing root (`None` for initial state).
/// `new_version` is the version to stamp on new nodes (typically block height).
///
/// Accepts multiple [`SettledWrites`] — all are flattened directly into
/// JMT work items without merging. Since transactions hold exclusive
/// state locks, there are no key conflicts between them.
///
/// # Panics
///
/// Panics if `new_version` is not strictly greater than `parent_version`.
pub fn put_at_version<S: TreeReader + Sync>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    writes: &SettledWrites,
) -> (StateRoot, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    let work_items = flatten_work_items(writes);

    if work_items.is_empty() {
        // No updates — carry the existing root forward to the new version.
        let mut collected = CollectedWrites::default();
        let root_hash = parent_version
            .and_then(|v| {
                let root_key = NodeKey::new(v, store.root_path());
                let Some(root_node) = store.get_node(&root_key) else {
                    tracing::warn!(
                        version = new_version,
                        parent = v,
                        "empty update cannot carry its root — parent version unmaterialized",
                    );
                    return None;
                };
                let hash: [u8; 32] = root_node.hash::<Blake3Hasher>();
                if hash == [0u8; 32] {
                    return None;
                }
                let new_root_key = NodeKey::new(new_version, store.root_path());
                collected.nodes.push((new_root_key, root_node));
                Some(StateRoot::from_raw(Hash::from_hash_bytes(&hash)))
            })
            .unwrap_or(StateRoot::ZERO);
        return (root_hash, collected);
    }

    // Parallel phase: BLAKE3 hash each value. Each item is independent —
    // this parallelizes the per-entry hashing work; the leaf key is the
    // substate key's own bytes.
    let mut updates: Vec<(Key, Option<LeafValue>)> = work_items
        .par_iter()
        .map(|(key, value_ref)| {
            let jmt_value = value_ref
                .as_deref()
                .map(|v| LeafValue::new(hash_value(v), v.len() as u64));
            (key.to_bytes(), jmt_value)
        })
        .collect();

    updates.par_sort_by(|a, b| a.0.cmp(&b.0));

    let updates_btree: BTreeMap<Key, Option<LeafValue>> = updates.into_iter().collect();

    let result = Jmt::apply_updates_at(
        store,
        parent_version,
        new_version,
        &store.root_path(),
        &updates_btree,
    )
    .expect("JMT apply_updates failed");

    let root_hash = state_root_from_jmt(result.root_hash);

    let mut collected = CollectedWrites::default();
    for (node_key, node) in &result.batch.new_nodes {
        collected
            .nodes
            .push((node_key.clone(), Arc::new(node.clone())));
    }
    for stale in &result.batch.stale_nodes {
        collected.stale_node_keys.push(stale.node_key.clone());
    }
    collected.bytes_delta = result.batch.bytes_delta;

    (root_hash, collected)
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{KEY_BYTES, MemoryStore, TreeWriter};
    use hyperscale_types::test_utils::test_prefix;
    use hyperscale_types::{Address, LocalKey};

    use super::*;

    fn cell(owner: Address, local: [u8; 16]) -> SubstateKey {
        SubstateKey {
            owner,
            local: LocalKey(local),
        }
    }

    /// A write keys its leaf by identity — `[owner | local]` — so the
    /// leaf enumerated back out of the tree carries the key's own bytes.
    #[test]
    fn put_at_version_keys_writes_by_identity() {
        let mut store = MemoryStore::new();
        let key = cell(test_prefix(0xA5), [0x3Cu8; 16]);

        let writes = SettledWrites::from_absolutes(BTreeMap::from([(key, Some(vec![42]))]));

        let (root, collected) = put_at_version(&store, None, 1, &writes);
        assert_ne!(root, StateRoot::ZERO);
        for (node_key, node) in &collected.nodes {
            store.put_node(node_key.clone(), node.as_ref().clone());
        }

        let root_key = NodeKey::new(1, store.root_path());
        let chunk =
            Jmt::collect_range(&store, &root_key, &[0u8; KEY_BYTES], &[0xFF; KEY_BYTES], 10)
                .expect("range");
        let leaf_keys: Vec<Key> = chunk.leaves.iter().map(|(k, _)| *k).collect();
        assert_eq!(leaf_keys, vec![key.to_bytes()]);
    }
}
