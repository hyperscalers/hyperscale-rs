//! Verkle-based state tree — flat single-tree design.
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

pub mod proofs;
pub mod tree_store;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use jellyfish_verkle_tree as jvt;

use jvt::TreeReader as _;
use tree_store::*;

/// Hash a storage key to a 32-byte JVT key.
///
/// Storage keys are variable-length (`entity_key || partition_num || sort_key`).
/// BLAKE3 hashing produces a fixed 32-byte key for optimal JVT tree depth (~4 levels).
pub fn hash_storage_key(storage_key: &[u8]) -> jvt::Key {
    blake3::hash(storage_key).into()
}

/// Build a storage key from entity_key + partition_num + sort_key.
fn make_storage_key(entity_key: &[u8], partition_num: u8, sort_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(entity_key.len() + 1 + sort_key.len());
    key.extend_from_slice(entity_key);
    key.push(partition_num);
    key.extend_from_slice(sort_key);
    key
}

/// Adapter that bridges `ReadableTreeStore` → JVT `TreeReader`.
struct StoreAdapter<'a, S> {
    store: &'a S,
}

impl<S: ReadableTreeStore> jvt::TreeReader for StoreAdapter<'_, S> {
    fn get_node(&self, key: &jvt::NodeKey) -> Option<Arc<jvt::Node>> {
        let stored_key = StoredNodeKey::from_jvt(key);
        self.store
            .get_node(&stored_key)
            .map(|sn| Arc::new(sn.to_jvt()))
    }

    fn get_root_key(&self, version: u64) -> Option<jvt::NodeKey> {
        let root = jvt::NodeKey::root(version);
        let stored_key = StoredNodeKey::from_jvt(&root);
        if self.store.get_node(&stored_key).is_some() {
            Some(root)
        } else {
            None
        }
    }
}

/// Computes new state tree nodes for the given database updates, returning
/// the new root hash and all collected writes.
///
/// The store only needs `ReadableTreeStore + Sync` — no writes are performed.
/// The caller applies the returned `CollectedWrites`.
///
/// `parent_version` is the version of the existing root (`None` for initial state).
/// `new_version` is the version to stamp on new nodes (typically block height).
///
/// `reset_old_keys` provides the storage keys that existed in Reset partitions
/// before the reset. These are needed to generate JVT deletes because hashed keys
/// prevent tree-based enumeration. The caller obtains these from the data store
/// (OrdMap prefix scan or RocksDB range scan) before calling this function.
pub fn put_at_version<S: ReadableTreeStore + Sync, D: Dispatch>(
    tree_store: &S,
    parent_version: Option<Version>,
    new_version: Version,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
    _dispatch: &D,
    reset_old_keys: &HashMap<(Vec<u8>, u8), Vec<Vec<u8>>>,
) -> (Hash, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    let adapter = StoreAdapter { store: tree_store };

    // Flatten all database updates into JVT key-value pairs.
    // Key: BLAKE3(storage_key) → [u8; 32]
    // Value: value_to_field(raw_bytes) → FieldElement
    let mut updates: BTreeMap<jvt::Key, Option<jvt::Value>> = BTreeMap::new();

    for (entity_key, node_updates) in &database_updates.node_updates {
        for (&partition_num, partition_updates) in &node_updates.partition_updates {
            match partition_updates {
                radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta {
                    substate_updates,
                } => {
                    for (sort_key, update) in substate_updates {
                        let storage_key = make_storage_key(entity_key, partition_num, &sort_key.0);
                        let jvt_key = hash_storage_key(&storage_key);
                        let jvt_value = match update {
                            radix_common::prelude::DatabaseUpdate::Set(value) => {
                                Some(jvt::commitment::value_to_field(value))
                            }
                            radix_common::prelude::DatabaseUpdate::Delete => None,
                        };
                        updates.insert(jvt_key, jvt_value);
                    }
                }
                radix_substate_store_interface::interface::PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // Delete all existing substates in this partition via caller-provided keys.
                    if let Some(old_keys) = reset_old_keys.get(&(entity_key.clone(), partition_num))
                    {
                        for old_sk in old_keys {
                            let jvt_key = hash_storage_key(old_sk);
                            updates.insert(jvt_key, None);
                        }
                    }
                    // Insert the new values (overwrites any deletes for keys that reappear).
                    for (sort_key, value) in new_substate_values {
                        let storage_key = make_storage_key(entity_key, partition_num, &sort_key.0);
                        let jvt_key = hash_storage_key(&storage_key);
                        updates.insert(jvt_key, Some(jvt::commitment::value_to_field(value)));
                    }
                }
            };
        }
    }

    if updates.is_empty() {
        // No updates — carry the existing root forward to the new version.
        // We must write a root node at new_version so the next block can find it.
        let mut collected = CollectedWrites::default();
        let root_hash = parent_version
            .and_then(|v| {
                let root_key = jvt::NodeKey::root(v);
                let root_node = adapter.get_node(&root_key)?;
                let commitment = root_node.commitment();
                if commitment == jvt::zero_commitment() {
                    return None;
                }
                // Write a copy of the root node at the new version
                let new_root_key = jvt::NodeKey::root(new_version);
                collected.nodes.push((
                    StoredNodeKey::from_jvt(&new_root_key),
                    StoredNode::from_jvt(&root_node),
                ));
                Some(commitment_to_hash(commitment))
            })
            .unwrap_or(Hash::ZERO);
        return (root_hash, collected);
    }

    let result = jvt::apply_updates(&adapter, parent_version, new_version, updates);

    let root_hash = if result.root_commitment == jvt::zero_commitment() {
        Hash::ZERO
    } else {
        commitment_to_hash(result.root_commitment)
    };

    // Collect writes
    let mut collected = CollectedWrites::default();
    for (node_key, node) in &result.batch.new_nodes {
        collected.nodes.push((
            StoredNodeKey::from_jvt(node_key),
            StoredNode::from_jvt(node),
        ));
    }
    for stale in &result.batch.stale_nodes {
        collected
            .stale_tree_parts
            .push(StaleTreePart::Node(StoredNodeKey::from_jvt(
                &stale.node_key,
            )));
    }

    (root_hash, collected)
}

/// Compute and immediately apply state tree updates.
/// Convenience for tests and direct commits.
pub fn put_at_version_and_apply<S: ReadableTreeStore + WriteableTreeStore + Sync, D: Dispatch>(
    tree_store: &S,
    parent_version: Option<Version>,
    new_version: Version,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
    dispatch: &D,
    reset_old_keys: &HashMap<(Vec<u8>, u8), Vec<Vec<u8>>>,
) -> Hash {
    let (root, collected) = put_at_version(
        tree_store,
        parent_version,
        new_version,
        database_updates,
        dispatch,
        reset_old_keys,
    );
    collected.apply_to(tree_store);
    root
}

/// Writes collected during state tree computation, to be applied atomically.
#[derive(Default)]
pub struct CollectedWrites {
    pub nodes: Vec<(StoredNodeKey, StoredNode)>,
    pub stale_tree_parts: Vec<StaleTreePart>,
}

impl CollectedWrites {
    /// Apply collected nodes and stale parts to a store.
    pub fn apply_to(self, store: &(impl WriteableTreeStore + ?Sized)) {
        for (key, node) in self.nodes {
            store.insert_node(key, node);
        }
        for part in self.stale_tree_parts {
            store.record_stale_tree_part(part);
        }
    }
}
