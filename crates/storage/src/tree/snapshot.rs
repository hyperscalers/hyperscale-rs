//! JMT snapshot for deferred application of block commits.

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

use hyperscale_jmt::{Child, EMPTY_HASH, NibblePath, Node, NodeKey};
use hyperscale_types::{AnswerDelta, BlockHeight, SettledWrites, StateRoot, SubstateKey};

use super::{CollectedWrites, state_root_from_jmt};
use crate::shard::writes::entry_leaf_rows;
use crate::{Substates, answer_delta};

/// A block's settled writes, with every leaf they put in the tree
/// findable by its key.
///
/// A cell's leaf is keyed by the cell. An entry's leaf is keyed by a
/// digest of the entry, which no reader can turn back into the entry, so
/// each entry's leaf is held beside the writes, keyed and encoded once
/// for the block. A read of unpersisted state by leaf key then answers
/// for an entry's leaf as the persisted store does, which holds each
/// leaf as a cell.
#[derive(Debug, Clone, Default)]
pub struct SettledLeaves {
    writes: SettledWrites,
    entry_leaves: BTreeMap<SubstateKey, Option<Vec<u8>>>,
}

impl SettledLeaves {
    /// Every leaf key these writes touch, removals included: each cell
    /// written and each entry's leaf.
    pub fn leaf_keys(&self) -> impl Iterator<Item = &SubstateKey> {
        self.writes.cells().keys().chain(self.entry_leaves.keys())
    }

    /// Overwrite `value` with what these writes leave at the leaf `key`,
    /// a cell's or an entry's, where they wrote it. An entry's leaf
    /// overrides a cell at the same key, as the tree lays them.
    pub fn lay_leaf(&self, key: SubstateKey, value: &mut Option<Vec<u8>>) {
        if let Some(change) = self
            .entry_leaves
            .get(&key)
            .or_else(|| self.writes.cells().get(&key))
        {
            value.clone_from(change);
        }
    }
}

impl From<SettledWrites> for SettledLeaves {
    fn from(writes: SettledWrites) -> Self {
        Self {
            entry_leaves: entry_leaf_rows(writes.entries()),
            writes,
        }
    }
}

impl Deref for SettledLeaves {
    type Target = SettledWrites;

    fn deref(&self) -> &SettledWrites {
        &self.writes
    }
}

/// A snapshot of JMT nodes computed during speculative execution.
///
/// Created during speculative state root computation (e.g., block verification).
/// Can be applied to the real JMT during block commit, avoiding redundant computation.
///
/// Nodes are stored as `(NodeKey, Arc<Node>)` — the canonical hydrated form.
/// Storage backends serialize at write time.
#[derive(Debug, Clone)]
#[must_use]
pub struct JmtSnapshot {
    /// The JMT root this snapshot was computed from.
    pub base_root: StateRoot,
    /// The block height this snapshot was computed from.
    pub base_height: BlockHeight,
    /// The resulting state root after applying all updates.
    pub result_root: StateRoot,
    /// The block height after applying this snapshot.
    pub new_height: BlockHeight,
    /// New tree nodes.
    pub nodes: Vec<(NodeKey, Arc<Node>)>,
    /// Keys of nodes that became stale.
    pub stale_node_keys: Vec<NodeKey>,
    /// Net change to the tree's total substate value bytes in this block.
    pub bytes_delta: i64,
    /// The cell values these nodes hash — the block's writes as absolutes,
    /// resolved once against the state its parent left behind.
    ///
    /// A reader of unpersisted state lays these down as they stand rather
    /// than resolving the block's movements a second time. Two resolutions
    /// mean two baselines, and a validator that picks the second from how
    /// far it happens to have persisted computes a state root no one else
    /// does.
    pub(crate) settled: SettledLeaves,
}

impl JmtSnapshot {
    /// Create a snapshot from collected writes.
    pub fn from_collected_writes(
        collected: CollectedWrites,
        settled: SettledWrites,
        base_root: StateRoot,
        base_height: BlockHeight,
        result_root: StateRoot,
        new_height: BlockHeight,
    ) -> Self {
        Self {
            base_root,
            base_height,
            result_root,
            new_height,
            nodes: collected.nodes,
            stale_node_keys: collected.stale_node_keys,
            bytes_delta: collected.bytes_delta,
            settled: settled.into(),
        }
    }

    /// What these writes do to the answers under `under` that
    /// `parent`, the state they land on, holds: see [`answer_delta`].
    #[must_use]
    pub fn answer_delta(
        &self,
        parent: &(impl Substates + ?Sized),
        under: &NibblePath,
    ) -> AnswerDelta {
        answer_delta(self.settled.cells(), parent, under)
    }

    /// The two child hashes of the internal node behind `result_root`
    /// (`StateRoot::ZERO` for an absent side) — the post-split subtree
    /// roots a final-epoch header carries as `split_child_roots`.
    ///
    /// The root node is the shortest-path node written at `new_height`:
    /// any update rewrites it, and the no-update path copies the
    /// parent's root node forward, so it is present either way. Returns
    /// `None` when the root is a leaf (a ≤1-key tree has no internal
    /// root; callers fail closed) or when the snapshot carries no nodes
    /// (empty tree).
    #[must_use]
    pub fn root_child_hashes(&self) -> Option<(StateRoot, StateRoot)> {
        let (_, root_node) = self
            .nodes
            .iter()
            .filter(|(key, _)| key.version == self.new_height.inner())
            .min_by_key(|(key, _)| key.path.len())?;
        match root_node.as_ref() {
            Node::Internal(internal) => {
                debug_assert_eq!(internal.hash, *self.result_root.as_bytes());
                let child = |slot: &Option<Child>| {
                    state_root_from_jmt(slot.as_ref().map_or(EMPTY_HASH, |c| c.hash))
                };
                Some((child(&internal.children[0]), child(&internal.children[1])))
            }
            Node::Leaf(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_jmt::{Blake3Hasher, Hasher, KEY_BYTES, Key, LeafValue, MemoryStore, ValueHash};

    use super::*;
    use crate::tree::{Jmt, noop_jmt_snapshot};

    /// A tree key with `b` as its leading byte.
    fn k(b: u8) -> Key {
        let mut key = [0u8; KEY_BYTES];
        key[0] = b;
        key
    }

    /// A 32-byte value hash filled with `b`.
    const fn v(b: u8) -> ValueHash {
        [b; 32]
    }

    /// Apply `entries` at version 1 against an empty store and wrap the
    /// result as a `JmtSnapshot`, mirroring what `prepare_block_commit`
    /// produces for the block at height 1.
    fn snapshot_of(entries: &[(Key, ValueHash)]) -> (MemoryStore, JmtSnapshot) {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<LeafValue>> = entries
            .iter()
            .map(|(key, val)| (*key, Some(LeafValue::new(*val, 1))))
            .collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let snapshot = JmtSnapshot {
            base_root: StateRoot::ZERO,
            base_height: BlockHeight::GENESIS,
            result_root: state_root_from_jmt(res.root_hash),
            new_height: BlockHeight::new(1),
            nodes: res
                .batch
                .new_nodes
                .iter()
                .map(|(key, node)| (key.clone(), Arc::new(node.clone())))
                .collect(),
            stale_node_keys: Vec::new(),
            bytes_delta: 0,
            settled: SettledWrites::default().into(),
        };
        (store, snapshot)
    }

    #[test]
    fn root_child_hashes_compose_to_the_result_root() {
        // Keys on both sides of the top bit: both children populated.
        let (_, snapshot) = snapshot_of(&[(k(0x00), v(1)), (k(0x80), v(2))]);
        let (left, right) = snapshot.root_child_hashes().expect("internal root");
        assert_ne!(left, StateRoot::ZERO);
        assert_ne!(right, StateRoot::ZERO);
        assert_eq!(
            Blake3Hasher::hash_internal(&[*left.as_bytes(), *right.as_bytes()]),
            *snapshot.result_root.as_bytes(),
        );
    }

    #[test]
    fn one_sided_root_reports_the_empty_side_as_zero() {
        // Two keys under the left bit: the root still materializes as an
        // internal node with an empty right child.
        let (_, snapshot) = snapshot_of(&[(k(0x00), v(1)), (k(0x01), v(2))]);
        let (left, right) = snapshot.root_child_hashes().expect("internal root");
        assert_ne!(left, StateRoot::ZERO);
        assert_eq!(right, StateRoot::ZERO);
        assert_eq!(
            Blake3Hasher::hash_internal(&[*left.as_bytes(), *right.as_bytes()]),
            *snapshot.result_root.as_bytes(),
        );
    }

    #[test]
    fn leaf_root_fails_closed() {
        // A single key collapses the root to a bare leaf — no pair exists.
        let (_, snapshot) = snapshot_of(&[(k(0x42), v(1))]);
        assert_eq!(snapshot.root_child_hashes(), None);
    }

    #[test]
    fn noop_snapshot_carries_the_root_node_forward() {
        // An empty block copies the parent's root node to its own height;
        // the pair must read identically off the copied node.
        let (store, parent) = snapshot_of(&[(k(0x00), v(1)), (k(0x80), v(2))]);
        let pending = [Arc::new(parent.clone())];
        let noop = noop_jmt_snapshot(
            &store,
            &pending,
            parent.result_root,
            parent.new_height,
            BlockHeight::new(2),
        );
        assert_eq!(noop.root_child_hashes(), parent.root_child_hashes());
        assert!(noop.root_child_hashes().is_some());
    }
}
