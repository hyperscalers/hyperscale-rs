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

pub use collected_writes::CollectedWrites;
pub use snapshot::{JmtSnapshot, LeafSubstateKeyAssociation};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Layered tree reader that overlays pending JMT snapshots on a base store.
///
/// Used during chained verification: block N+1's `prepare_block_commit` needs
/// tree nodes from block N's verification, which hasn't committed yet. The
/// overlay provides those nodes without mutating the shared tree store —
/// avoiding corruption from abandoned blocks (view changes / forks).
pub struct OverlayTreeReader<'a, S> {
    base: &'a S,
    /// Overlay nodes indexed by NodeKey for O(1) lookup.
    nodes: HashMap<jmt::NodeKey, Arc<jmt::Node>>,
}

impl<'a, S> OverlayTreeReader<'a, S> {
    /// Create a new OverlayTreeReader.
    pub fn new(base: &'a S, snapshots: &[Arc<JmtSnapshot>]) -> Self {
        let mut nodes = HashMap::new();
        for snapshot in snapshots.iter() {
            for (key, node) in &snapshot.nodes {
                nodes.insert(key.clone(), Arc::clone(node));
            }
        }
        Self { base, nodes }
    }
}

impl<S: jmt::TreeReader + Sync> jmt::TreeReader for OverlayTreeReader<'_, S> {
    fn get_node(&self, key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
        self.nodes
            .get(key)
            .cloned()
            .or_else(|| self.base.get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<jmt::NodeKey> {
        // Check if any overlay snapshot wrote a root at this version.
        // Root keys follow the convention NodeKey::root(version).
        let root_key = jmt::NodeKey::root(version);
        if self.nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            self.base.get_root_key(version)
        }
    }
}

use hyperscale_jmt as jmt;
use hyperscale_jmt::{Blake3Hasher, Tree};
use hyperscale_types::{BlockHeight, Hash, StateRoot};
use rayon::prelude::*;

// Re-export JMT types used in public APIs (CollectedWrites, etc.)
pub use jmt::Node as JmtNode;
pub use jmt::NodeKey as JmtNodeKey;

/// The JMT configuration this backend uses: binary arity, Blake3 hasher.
/// Centralizing as a type alias so callers don't repeat the parameters.
pub type Jmt = Tree<Blake3Hasher, 1>;

/// Hash a storage key to a 32-byte JMT key.
///
/// Storage keys are variable-length (`entity_key || partition_num || sort_key`).
/// BLAKE3 hashing produces a fixed 32-byte key for uniform path depth.
pub fn hash_storage_key(storage_key: &[u8]) -> jmt::Key {
    blake3::hash(storage_key).into()
}

/// Hash a raw value to a 32-byte value hash stored in leaves.
pub fn hash_value(value: &[u8]) -> jmt::ValueHash {
    blake3::hash(value).into()
}

/// Returns `None` when the JMT is truly empty (height 0 with zero root),
/// indicating no parent node exists. Otherwise returns `Some(block_height)`.
pub fn jmt_parent_height(block_height: BlockHeight, root: StateRoot) -> Option<BlockHeight> {
    if block_height == BlockHeight::GENESIS && root == StateRoot::ZERO {
        None
    } else {
        Some(block_height)
    }
}

/// Build a no-op JmtSnapshot for a block with no state changes (empty receipts).
///
/// The state root is unchanged (`parent_state_root`). We try to copy the
/// parent's root node to the new version so the overlay chain stays intact.
/// If the parent root node isn't available (e.g., after sync when the tree
/// hasn't been persisted yet), the snapshot is created without it — the
/// commit path resolves this when the parent IS in the store.
///
/// # Safety assumption
///
/// This function sets `result_root = parent_state_root` unconditionally.
/// Callers must only use this for blocks with genuinely empty receipts
/// (no state changes). For consensus blocks, this is verified by the
/// verification pipeline. For synced blocks, the QC signature attests
/// to correctness — a QC-certified block with empty receipts is
/// guaranteed to have `state_root == parent_state_root`.
pub fn noop_jmt_snapshot<S: jmt::TreeReader>(
    store: &S,
    pending_snapshots: &[Arc<JmtSnapshot>],
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    block_height: BlockHeight,
) -> JmtSnapshot {
    let mut nodes = Vec::new();

    // Try to find the parent's root node so the version chain is unbroken.
    if let Some(parent_ver) = jmt_parent_height(parent_block_height, parent_state_root) {
        let root_key = jmt::NodeKey::root(parent_ver.0);

        // Check pending snapshots first (overlay), then the base store.
        let root_node = pending_snapshots
            .iter()
            .find_map(|s| {
                s.nodes
                    .iter()
                    .find(|(k, _)| *k == root_key)
                    .map(|(_, n)| Arc::clone(n))
            })
            .or_else(|| store.get_node(&root_key));

        if let Some(node) = root_node {
            nodes.push((jmt::NodeKey::root(block_height.0), node));
        }
    }

    JmtSnapshot {
        base_root: parent_state_root,
        base_height: parent_block_height,
        result_root: parent_state_root,
        new_height: block_height,
        nodes,
        stale_node_keys: Vec::new(),
        leaf_substate_associations: Vec::new(),
    }
}

/// Build a storage key from entity_key + partition_num + sort_key.
fn make_storage_key(entity_key: &[u8], partition_num: u8, sort_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(entity_key.len() + 1 + sort_key.len());
    key.extend_from_slice(entity_key);
    key.push(partition_num);
    key.extend_from_slice(sort_key);
    key
}

/// Computes new state tree nodes for the given database updates, returning
/// the new root hash and all collected writes.
///
/// Takes any `jmt::TreeReader` — the caller provides a reader appropriate
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
pub fn put_at_version<S: jmt::TreeReader + Sync>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    database_updates_list: &[&radix_substate_store_interface::interface::DatabaseUpdates],
    reset_old_keys: &HashMap<
        (Vec<u8>, u8),
        Vec<radix_substate_store_interface::interface::DbSortKey>,
    >,
) -> (StateRoot, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    // Flatten all database updates into (storage_key_bytes, optional_value) work items.
    let mut work_items: Vec<(Vec<u8>, Option<&[u8]>)> = Vec::new();

    for database_updates in database_updates_list {
        for (entity_key, node_updates) in &database_updates.node_updates {
            for (&partition_num, partition_updates) in &node_updates.partition_updates {
                match partition_updates {
                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta {
                        substate_updates,
                    } => {
                        for (sort_key, update) in substate_updates {
                            let storage_key = make_storage_key(entity_key, partition_num, &sort_key.0);
                            let value_ref = match update {
                                radix_common::prelude::DatabaseUpdate::Set(value) => {
                                    Some(value.as_slice())
                                }
                                radix_common::prelude::DatabaseUpdate::Delete => None,
                            };
                            work_items.push((storage_key, value_ref));
                        }
                    }
                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Reset {
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
                            let storage_key = make_storage_key(entity_key, partition_num, &sort_key.0);
                            work_items.push((storage_key, Some(value.as_slice())));
                        }
                    }
                };
            }
        }
    }

    if work_items.is_empty() {
        // No updates — carry the existing root forward to the new version.
        let mut collected = CollectedWrites::default();
        let root_hash = parent_version
            .and_then(|v| {
                let root_key = jmt::NodeKey::root(v);
                let root_node = store.get_node(&root_key)?;
                let hash: [u8; 32] = root_node.hash::<Blake3Hasher>();
                if hash == [0u8; 32] {
                    return None;
                }
                let new_root_key = jmt::NodeKey::root(new_version);
                collected.nodes.push((new_root_key, root_node));
                Some(StateRoot::from_raw(Hash::from_hash_bytes(&hash)))
            })
            .unwrap_or(StateRoot::ZERO);
        return (root_hash, collected);
    }

    // Parallel phase: BLAKE3 hash each storage key and value. Each item is
    // independent — this parallelizes the per-entry hashing work.
    let mut updates: Vec<(jmt::Key, Option<jmt::ValueHash>)> = work_items
        .par_iter()
        .map(|(storage_key, value_ref)| {
            let jmt_key = hash_storage_key(storage_key);
            let jmt_value = value_ref.map(hash_value);
            (jmt_key, jmt_value)
        })
        .collect();

    updates.par_sort_by(|a, b| a.0.cmp(&b.0));

    let updates_btree: BTreeMap<jmt::Key, Option<jmt::ValueHash>> = updates.into_iter().collect();

    let result = Jmt::apply_updates(store, parent_version, new_version, updates_btree)
        .expect("JMT apply_updates failed");

    let root_hash = if result.root_hash == [0u8; 32] {
        StateRoot::ZERO
    } else {
        StateRoot::from_raw(Hash::from_hash_bytes(&result.root_hash))
    };

    let mut collected = CollectedWrites::default();
    for (node_key, node) in &result.batch.new_nodes {
        collected
            .nodes
            .push((node_key.clone(), Arc::new(node.clone())));
    }
    for stale in &result.batch.stale_nodes {
        collected.stale_node_keys.push(stale.node_key.clone());
    }

    (root_hash, collected)
}
