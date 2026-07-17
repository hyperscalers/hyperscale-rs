//! Binary Jellyfish Merkle Tree (Blake3) state tree — flat single-tree design.
//!
//! All substates across all entities and partitions live in a single JMT.
//! Storage keys are BLAKE3-hashed to 32-byte JMT keys for compact paths.
//!
//! # Key mapping
//!
//! `jmt_key = BLAKE3(entity_key || partition_num || sort_key)` → `[u8; 32]`
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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub use collected_writes::CollectedWrites;
use hyperscale_jmt::{
    Blake3Hasher, Key, LeafValue, NibblePath, Node as JmtNode, NodeKey, Tree, TreeReader,
    UpdateResult, ValueHash,
};
use hyperscale_types::state_key::{db_node_key_to_node_id, jmt_leaf_key, jmt_value_hash};
use hyperscale_types::{BlockHeight, Hash, NodeId, StateRoot};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, DbSortKey, PartitionDatabaseUpdates,
};
use rayon::prelude::*;
pub use snapshot::{JmtSnapshot, LeafSubstateKeyAssociation};

use crate::ImportLeaf;

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

/// Hash a storage key to a 32-byte JMT key, owner-prefixing internal nodes.
///
/// Storage keys are variable-length (`entity_key || partition_num || sort_key`).
/// `owner_map` maps an internal node (vault, KV store) to its owning global
/// ancestor; a key whose node is present is prefixed under that owner so the
/// owner's footprint stays a contiguous prefix subtree. Globals are absent and
/// key under themselves. The map is the merge of every committed receipt's
/// `owned_nodes`, so the key bytes are identical on every node.
#[must_use]
#[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s
pub fn hash_storage_key(storage_key: &[u8], owner_map: &HashMap<NodeId, NodeId>) -> Key {
    let owner = db_node_key_to_node_id(storage_key).and_then(|n| owner_map.get(&n).copied());
    jmt_leaf_key(storage_key, owner)
}

/// A JMT root hash as a [`StateRoot`], mapping the empty-tree sentinel
/// (all zeroes) to `StateRoot::ZERO`.
#[must_use]
pub fn state_root_from_jmt(root_hash: [u8; 32]) -> StateRoot {
    if root_hash == [0u8; 32] {
        StateRoot::ZERO
    } else {
        StateRoot::from_raw(Hash::from_hash_bytes(&root_hash))
    }
}

/// Rebuild a JMT at `height` from snap-synced import leaves.
///
/// The shipped leaf keys are already owner-prefixed, so the tree is
/// rebuilt from them directly instead of re-deriving through
/// [`put_at_version`], which would need the owner map. The caller
/// persists the result's node batch plus whatever raw-pair and
/// leaf-association records its backend keeps, and stores the returned
/// root as the imported state root.
///
/// # Errors
///
/// Returns a description when the JMT update fails.
pub fn import_leaf_updates<S: TreeReader>(
    store: &S,
    root_path: &NibblePath,
    height: BlockHeight,
    leaves: &[ImportLeaf],
) -> Result<(StateRoot, UpdateResult), String> {
    let updates: BTreeMap<Key, Option<LeafValue>> = leaves
        .iter()
        .map(|leaf| {
            let len = leaf.value.len() as u64;
            (
                leaf.leaf_key,
                Some(LeafValue::new(hash_value(&leaf.value), len)),
            )
        })
        .collect();
    let result = Jmt::apply_updates_at(store, None, height.inner(), root_path, &updates)
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

/// Find the nearest version at or below `version` whose root node is
/// actually reachable — in `pending_snapshots` or `store` — walking back
/// through node-less no-op snapshots.
///
/// A block prepared before its parent's tree existed (the recovery bridge
/// builds over a sync-admitted parent whose tree materializes only at
/// commit) leaves a no-op snapshot that carries its parent's root without
/// holding the node. The root is byte-identical along that chain, so a
/// reader or applier can anchor on the nearest version that actually
/// holds it. Returns `None` when the walk dead-ends with no materialized
/// ancestor.
#[must_use]
pub fn resolve_materialized_root<S: TreeReader>(
    store: &S,
    pending_snapshots: &[Arc<JmtSnapshot>],
    version: u64,
) -> Option<(u64, Arc<JmtNode>)> {
    let mut ver = version;
    loop {
        let root_key = NodeKey::new(ver, store.root_path());
        let found = pending_snapshots
            .iter()
            .find_map(|s| {
                s.nodes
                    .iter()
                    .find(|(k, _)| *k == root_key)
                    .map(|(_, n)| Arc::clone(n))
            })
            .or_else(|| store.get_node(&root_key));
        if let Some(node) = found {
            return Some((ver, node));
        }
        // The version's snapshot is a node-less no-op: its tree IS its
        // base's tree, so continue the search there. Terminates — a
        // snapshot's base height is strictly below its own.
        let noop = pending_snapshots.iter().find(|s| {
            s.new_height.inner() == ver && s.nodes.is_empty() && s.result_root == s.base_root
        })?;
        ver = jmt_parent_height(noop.base_height, noop.base_root)?.inner();
    }
}

/// The root-node copy a node-less no-op snapshot still needs at persist
/// time.
///
/// Its prepare ran before the parent's tree existed (the recovery bridge
/// over a sync-admitted parent), so the carry that keeps the version
/// chain unbroken couldn't happen then. Persistence is height-ordered, so
/// the parent's root is durable here; returns the node to write at the
/// snapshot's version. `None` when the snapshot already carries nodes,
/// applies a real delta, or descends from the zero root. A no-op
/// snapshot whose parent root is genuinely absent warns: a silent hole
/// surfaces later as a `ParentVersionMissing` panic on the next
/// content-bearing block.
#[must_use]
pub fn carry_noop_root<S: TreeReader>(
    store: &S,
    snapshot: &JmtSnapshot,
) -> Option<(NodeKey, Arc<JmtNode>)> {
    if !snapshot.nodes.is_empty() || snapshot.result_root != snapshot.base_root {
        return None;
    }
    let parent_ver = jmt_parent_height(snapshot.base_height, snapshot.base_root)?;
    let root_key = NodeKey::new(parent_ver.inner(), store.root_path());
    let Some(node) = store.get_node(&root_key) else {
        tracing::warn!(
            height = snapshot.new_height.inner(),
            parent = parent_ver.inner(),
            "no-op snapshot persisted without a durable parent root — JMT version chain hole",
        );
        return None;
    };
    Some((
        NodeKey::new(snapshot.new_height.inner(), store.root_path()),
        node,
    ))
}

/// Build a no-op `JmtSnapshot` for a block with no state changes (empty receipts).
///
/// The state root is unchanged (`parent_state_root`). We copy the nearest
/// materialized root node — resolving through node-less no-op ancestors —
/// to the new version so the overlay chain stays intact. If no
/// materialized ancestor is reachable (the recovery bridge prepares
/// before its sync-admitted parent's tree exists), the snapshot is
/// created without it and the persist path completes the copy via
/// [`carry_noop_root`] once the parent's tree is durable.
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
        && let Some((_, node)) =
            resolve_materialized_root(store, pending_snapshots, parent_ver.inner())
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
        leaf_associations: Vec::new(),
        bytes_delta: 0,
    }
}

/// Build a storage key from `entity_key` + `partition_num` + `sort_key`.
fn make_storage_key(entity_key: &[u8], partition_num: u8, sort_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(entity_key.len() + 1 + sort_key.len());
    key.extend_from_slice(entity_key);
    key.push(partition_num);
    key.extend_from_slice(sort_key);
    key
}

/// Flatten database updates into `(storage_key_bytes, optional_value)`
/// work items. `None` values are deletes; Reset partitions delete every
/// key listed in `reset_old_keys` before writing their new values.
fn flatten_work_items<'a>(
    database_updates_list: &[&'a DatabaseUpdates],
    reset_old_keys: &HashMap<(Vec<u8>, u8), Vec<DbSortKey>>,
) -> Vec<(Vec<u8>, Option<&'a [u8]>)> {
    let mut work_items: Vec<(Vec<u8>, Option<&[u8]>)> = Vec::new();

    for database_updates in database_updates_list {
        for (entity_key, node_updates) in &database_updates.node_updates {
            for (&partition_num, partition_updates) in &node_updates.partition_updates {
                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (sort_key, update) in substate_updates {
                            let storage_key =
                                make_storage_key(entity_key, partition_num, &sort_key.0);
                            let value_ref = match update {
                                DatabaseUpdate::Set(value) => Some(value.as_slice()),
                                DatabaseUpdate::Delete => None,
                            };
                            work_items.push((storage_key, value_ref));
                        }
                    }
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values,
                    } => {
                        if let Some(old_sort_keys) =
                            reset_old_keys.get(&(entity_key.clone(), partition_num))
                        {
                            for old_sk in old_sort_keys {
                                let storage_key =
                                    make_storage_key(entity_key, partition_num, &old_sk.0);
                                work_items.push((storage_key, None));
                            }
                        }
                        for (sort_key, value) in new_substate_values {
                            let storage_key =
                                make_storage_key(entity_key, partition_num, &sort_key.0);
                            work_items.push((storage_key, Some(value.as_slice())));
                        }
                    }
                }
            }
        }
    }

    work_items
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
/// `reset_old_keys` provides the storage keys that existed in Reset partitions
/// before the reset. These are needed to generate JMT deletes because hashed keys
/// prevent tree-based enumeration.
///
/// Accepts multiple `DatabaseUpdates` slices — all are flattened directly
/// into JMT work items without merging. Since transactions hold exclusive
/// state locks, there are no key conflicts between updates.
///
/// # Panics
///
/// Panics if `new_version` is not strictly greater than `parent_version`.
#[allow(clippy::implicit_hasher)] // call sites pass std `HashMap`s; generic hasher would require turbofishing every site
pub fn put_at_version<S: TreeReader + Sync>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    database_updates_list: &[&DatabaseUpdates],
    reset_old_keys: &HashMap<(Vec<u8>, u8), Vec<DbSortKey>>,
    owner_map: &HashMap<NodeId, NodeId>,
) -> (StateRoot, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    let work_items = flatten_work_items(database_updates_list, reset_old_keys);

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

    // Parallel phase: BLAKE3 hash each storage key and value. Each item is
    // independent — this parallelizes the per-entry hashing work.
    let mut updates: Vec<(Key, Option<LeafValue>)> = work_items
        .par_iter()
        .map(|(storage_key, value_ref)| {
            let jmt_key = hash_storage_key(storage_key, owner_map);
            let jmt_value = value_ref.map(|v| LeafValue::new(hash_value(v), v.len() as u64));
            (jmt_key, jmt_value)
        })
        .collect();

    // Record each write's hashed-key → raw-key association before the
    // raw keys are consumed. `jmt_leaf_key` is one-way, so this mapping
    // is what lets range serving resolve enumerated leaves back to raw
    // substate pairs.
    let leaf_associations: Vec<LeafSubstateKeyAssociation> = updates
        .iter()
        .zip(work_items)
        .map(
            |(&(leaf_key, _), (storage_key, value_ref))| LeafSubstateKeyAssociation {
                leaf_key,
                storage_key: value_ref.is_some().then_some(storage_key),
            },
        )
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
    collected.leaf_associations = leaf_associations;
    collected.bytes_delta = result.batch.bytes_delta;

    (root_hash, collected)
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::MemoryStore;

    use super::*;
    use crate::{DatabaseUpdate, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates};

    /// One association per work item: the hashed leaf key paired with
    /// the raw storage key for sets, `None` for deletes.
    #[test]
    fn put_at_version_records_leaf_associations() {
        let store = MemoryStore::new();

        let set_entity = vec![1u8; 50];
        let del_entity = vec![2u8; 50];
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            set_entity.clone(),
            NodeDatabaseUpdates {
                partition_updates: std::iter::once((
                    0u8,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: std::iter::once((
                            DbSortKey(vec![9]),
                            DatabaseUpdate::Set(vec![42]),
                        ))
                        .collect(),
                    },
                ))
                .collect(),
            },
        );
        updates.node_updates.insert(
            del_entity.clone(),
            NodeDatabaseUpdates {
                partition_updates: std::iter::once((
                    1u8,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: std::iter::once((
                            DbSortKey(vec![5]),
                            DatabaseUpdate::Delete,
                        ))
                        .collect(),
                    },
                ))
                .collect(),
            },
        );

        let (_, collected) = put_at_version(
            &store,
            None,
            1,
            &[&updates],
            &HashMap::new(),
            &HashMap::new(),
        );

        let set_raw = make_storage_key(&set_entity, 0, &[9]);
        let del_raw = make_storage_key(&del_entity, 1, &[5]);
        let by_key = |raw: &[u8]| {
            let hashed = hash_storage_key(raw, &HashMap::new());
            collected
                .leaf_associations
                .iter()
                .find(|a| a.leaf_key == hashed)
                .expect("association recorded for every work item")
                .clone()
        };
        assert_eq!(collected.leaf_associations.len(), 2);
        assert_eq!(by_key(&set_raw).storage_key, Some(set_raw.clone()));
        assert_eq!(by_key(&del_raw).storage_key, None);
    }
}
