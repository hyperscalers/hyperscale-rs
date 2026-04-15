//! Verkle state tree — flat single-tree design.
//!
//! All substates across all entities and partitions live in a single JVT tree.
//! Storage keys are BLAKE3-hashed to 32-byte JVT keys for optimal tree depth.
//!
//! # Key mapping
//!
//! `jvt_key = BLAKE3(entity_key || partition_num || sort_key)` → `[u8; 32]`
//!
//! # Value encoding
//!
//! JVT values are field elements (`value_to_field(raw_bytes)`). Raw substate
//! bytes are stored separately in the versioned data store (MVCC), not in the tree.

mod collected_writes;
pub mod proofs;
mod snapshot;

pub use collected_writes::CollectedWrites;
pub use snapshot::{JvtSnapshot, LeafSubstateKeyAssociation};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Layered tree reader that overlays pending JVT snapshots on a base store.
///
/// Used during chained verification: block N+1's `prepare_block_commit` needs
/// tree nodes from block N's verification, which hasn't committed yet. The
/// overlay provides those nodes without mutating the shared tree store —
/// avoiding corruption from abandoned blocks (view changes / forks).
pub struct OverlayTreeReader<'a, S> {
    base: &'a S,
    /// Overlay nodes indexed by NodeKey for O(1) lookup.
    nodes: HashMap<jvt::NodeKey, Arc<jvt::Node>>,
}

impl<'a, S> OverlayTreeReader<'a, S> {
    /// Create a new OverlayTreeReader.
    pub fn new(base: &'a S, snapshots: &[Arc<JvtSnapshot>]) -> Self {
        let mut nodes = HashMap::new();
        for snapshot in snapshots.iter() {
            for (key, node) in &snapshot.nodes {
                nodes.insert(key.clone(), Arc::clone(node));
            }
        }
        Self { base, nodes }
    }
}

impl<S: jvt::TreeReader + Sync> jvt::TreeReader for OverlayTreeReader<'_, S> {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        self.nodes
            .get(key)
            .cloned()
            .or_else(|| self.base.get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        // Check if any overlay snapshot wrote a root at this version.
        // Root keys follow the convention NodeKey::root(version).
        let root_key = jvt::NodeKey::root(version);
        if self.nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            self.base.get_root_key(version)
        }
    }
}

use hyperscale_types::Hash;
use jellyfish_verkle_tree as jvt;
use rayon::prelude::*;

// Re-export JVT types used in public APIs (CollectedWrites, NodeCache, etc.)
pub use jvt::Node as JvtNode;
pub use jvt::NodeKey as JvtNodeKey;

/// Hash a storage key to a 32-byte JVT key.
///
/// Storage keys are variable-length (`entity_key || partition_num || sort_key`).
/// BLAKE3 hashing produces a fixed 32-byte key for optimal JVT tree depth (~4 levels).
pub fn hash_storage_key(storage_key: &[u8]) -> jvt::Key {
    blake3::hash(storage_key).into()
}

/// Returns `None` when the JVT is truly empty (height 0 with zero root),
/// indicating no parent node exists. Otherwise returns `Some(block_height)`.
pub fn jvt_parent_height(block_height: u64, root: Hash) -> Option<u64> {
    if block_height == 0 && root == Hash::ZERO {
        None
    } else {
        Some(block_height)
    }
}

/// Build a no-op JvtSnapshot for a block with no state changes (empty receipts).
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
pub fn noop_jvt_snapshot<S: jvt::TreeReader>(
    store: &S,
    pending_snapshots: &[Arc<JvtSnapshot>],
    parent_state_root: Hash,
    parent_block_height: u64,
    block_height: u64,
) -> JvtSnapshot {
    let mut nodes = Vec::new();

    // Try to find the parent's root node so the version chain is unbroken.
    if let Some(parent_ver) = jvt_parent_height(parent_block_height, parent_state_root) {
        let root_key = jvt::NodeKey::root(parent_ver);

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
            nodes.push((jvt::NodeKey::root(block_height), node));
        }
    }

    JvtSnapshot {
        base_root: parent_state_root,
        base_version: parent_block_height,
        result_root: parent_state_root,
        new_version: block_height,
        nodes,
        stale_node_keys: Vec::new(),
        leaf_substate_associations: Vec::new(),
    }
}

/// Convert a JVT commitment to a Hash (for state root, value hashes).
///
/// Uses compressed serialization (32 bytes) for the consensus-visible identity.
pub fn commitment_to_hash(c: jvt::Commitment) -> Hash {
    use ark_serialize::CanonicalSerialize;
    let mut buf = [0u8; 32];
    c.0.serialize_compressed(&mut buf[..])
        .expect("Bandersnatch point serialization should never fail");
    Hash::from_hash_bytes(&buf)
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
/// Takes any `jvt::TreeReader` — the caller is responsible for providing
/// a reader appropriate to its storage backend (e.g. cache-backed for RocksDB,
/// direct HashMap for in-memory). `put_at_version` is agnostic to caching
/// and serialization.
///
/// `parent_version` is the version of the existing root (`None` for initial state).
/// `new_version` is the version to stamp on new nodes (typically block height).
///
/// `reset_old_keys` provides the storage keys that existed in Reset partitions
/// before the reset. These are needed to generate JVT deletes because hashed keys
/// prevent tree-based enumeration.
///
/// Accepts multiple `DatabaseUpdates` slices — all are flattened directly
/// into JVT work items without merging. Since transactions hold exclusive
/// state locks, there are no key conflicts between updates.
pub fn put_at_version<S: jvt::TreeReader + Sync>(
    store: &S,
    parent_version: Option<u64>,
    new_version: u64,
    database_updates_list: &[&radix_substate_store_interface::interface::DatabaseUpdates],
    reset_old_keys: &HashMap<
        (Vec<u8>, u8),
        Vec<radix_substate_store_interface::interface::DbSortKey>,
    >,
) -> (Hash, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    // Flatten all database updates into (storage_key_bytes, jvt_value) work items,
    // then parallel-hash and convert to JVT key-value pairs.
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
        // We must write a root node at new_version so the next block can find it.
        let mut collected = CollectedWrites::default();
        let root_hash = parent_version
            .and_then(|v| {
                let root_key = jvt::NodeKey::root(v);
                let root_node = store.get_node(&root_key)?;
                let commitment = root_node.commitment();
                if commitment == jvt::zero_commitment() {
                    return None;
                }
                let new_root_key = jvt::NodeKey::root(new_version);
                collected.nodes.push((new_root_key, root_node));
                Some(commitment_to_hash(commitment))
            })
            .unwrap_or(Hash::ZERO);
        return (root_hash, collected);
    }

    // Parallel phase: BLAKE3 hash each storage key and convert values to field
    // elements. Each item is independent — this parallelizes the most expensive
    // per-entry work (two BLAKE3 hashes + field conversion for Set operations).
    let mut updates: Vec<(jvt::Key, Option<jvt::Value>)> = work_items
        .par_iter()
        .map(|(storage_key, value_ref)| {
            let jvt_key = hash_storage_key(storage_key);
            let jvt_value = value_ref.map(jvt::commitment::value_to_field);
            (jvt_key, jvt_value)
        })
        .collect();

    // Sort by key for the BTreeMap ordering that apply_updates expects.
    // No dedup needed — state locking guarantees no key conflicts between
    // transactions, so each key appears at most once.
    updates.par_sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let updates_btree: BTreeMap<jvt::Key, Option<jvt::Value>> = updates.into_iter().collect();

    let result = jvt::apply_updates(store, parent_version, new_version, updates_btree);

    let root_hash = if result.root_commitment == jvt::zero_commitment() {
        Hash::ZERO
    } else {
        commitment_to_hash(result.root_commitment)
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
