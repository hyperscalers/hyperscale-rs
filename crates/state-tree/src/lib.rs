//! Verkle-based state tree — flat single-tree design.
//!
//! All substates across all entities and partitions live in a single JVT tree.
//! Storage keys are used directly as variable-length JVT keys (no hashing).
//! This preserves entity locality — substates under the same entity share
//! a common tree prefix and cluster together.
//!
//! # Key mapping
//!
//! `jvt_key = entity_key || partition_num || sort_key` (raw concatenation)
//!
//! # Value encoding
//!
//! JVT values store the raw substate bytes directly. This enables historical
//! value retrieval via the versioned tree — walking an old root gives you
//! the old values without needing a separate association table.

pub mod proofs;
pub mod tree_store;

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use jellyfish_verkle_tree as jvt;

use jvt::TreeReader as _;
use tree_store::*;

/// Convert a storage key to a JVT key (direct passthrough — no hashing).
///
/// JVT now supports variable-length keys, so we use the raw storage key
/// directly. This preserves entity locality in the tree.
pub fn to_jvt_key(storage_key: &[u8]) -> jvt::Key {
    storage_key.to_vec()
}

/// Build a prefix for enumerating all substates in a partition.
fn make_partition_prefix(entity_key: &[u8], partition_num: u8) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(entity_key.len() + 1);
    prefix.extend_from_slice(entity_key);
    prefix.push(partition_num);
    prefix
}

/// Build a JVT key from entity_key + partition_num + sort_key.
fn make_jvt_key(entity_key: &[u8], partition_num: u8, sort_key: &[u8]) -> jvt::Key {
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
pub fn put_at_version<S: ReadableTreeStore + Sync, D: Dispatch>(
    tree_store: &S,
    parent_version: Option<Version>,
    new_version: Version,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
    _dispatch: &D,
) -> (Hash, CollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );

    let adapter = StoreAdapter { store: tree_store };

    // Flatten all database updates into JVT key-value pairs.
    // Key: entity_key || partition_num || sort_key (raw concatenation)
    // Value: raw substate bytes (JVT stores them directly; hashes internally for >31 bytes)
    let mut updates: BTreeMap<jvt::Key, Option<jvt::Value>> = BTreeMap::new();

    for (entity_key, node_updates) in &database_updates.node_updates {
        for (&partition_num, partition_updates) in &node_updates.partition_updates {
            match partition_updates {
                radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta {
                    substate_updates,
                } => {
                    for (sort_key, update) in substate_updates {
                        let jvt_key = make_jvt_key(entity_key, partition_num, &sort_key.0);
                        let jvt_value = match update {
                            radix_common::prelude::DatabaseUpdate::Set(value) => {
                                Some(value.clone())
                            }
                            radix_common::prelude::DatabaseUpdate::Delete => None,
                        };
                        updates.insert(jvt_key, jvt_value);
                    }
                }
                radix_substate_store_interface::interface::PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    // Reset = delete all existing substates in this partition,
                    // then insert the new values. We enumerate existing leaves
                    // under the partition prefix and mark them as deletes.
                    if let Some(parent_ver) = parent_version {
                        let prefix = make_partition_prefix(entity_key, partition_num);
                        if let Some(existing) =
                            list_leaves_with_prefix(tree_store, parent_ver, &prefix)
                        {
                            for (existing_key, _) in existing {
                                updates.insert(existing_key, None);
                            }
                        }
                    }
                    // Insert the new values (overwrites any deletes for keys that reappear)
                    for (sort_key, value) in new_substate_values {
                        let jvt_key = make_jvt_key(entity_key, partition_num, &sort_key.0);
                        updates.insert(jvt_key, Some(value.clone()));
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
) -> Hash {
    let (root, collected) = put_at_version(
        tree_store,
        parent_version,
        new_version,
        database_updates,
        dispatch,
    );
    collected.apply_to(tree_store);
    root
}

/// List all leaf (key, value) pairs in the tree at a given version whose keys
/// start with `prefix`.
///
/// Uses JVT's versioned tree walk — reads historical state as long as the
/// nodes haven't been garbage-collected.
///
/// Returns `None` if the version's root doesn't exist (GC'd or not committed).
pub fn list_leaves_with_prefix<S: ReadableTreeStore>(
    tree_store: &S,
    version: Version,
    prefix: &[u8],
) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let adapter = StoreAdapter { store: tree_store };
    let root_key = jvt::NodeKey::root(version);

    // Check the root exists
    adapter.get_node(&root_key)?;

    // iter_leaves is on TreeIterator, which MemoryStore implements but our
    // adapter doesn't. Use the collect_leaves approach via get_value for each
    // matching key. Actually, we need to walk the tree.
    //
    // For now, use a simple approach: walk the tree recursively.
    let mut results = Vec::new();
    collect_prefix_leaves(&adapter, &root_key, &[], prefix, &mut results);
    Some(results)
}

/// Recursively collect leaves whose full key starts with `prefix`.
fn collect_prefix_leaves<S: jvt::TreeReader>(
    store: &S,
    node_key: &jvt::NodeKey,
    path_prefix: &[u8],
    target_prefix: &[u8],
    results: &mut Vec<(Vec<u8>, Vec<u8>)>,
) {
    let node = match store.get_node(node_key) {
        Some(n) => n,
        None => return,
    };

    match &*node {
        jvt::Node::Internal(internal) => {
            let depth = path_prefix.len();
            let mut child_indices: Vec<u8> = internal.children.keys().copied().collect();
            child_indices.sort();

            for &child_idx in &child_indices {
                // If we're still within the prefix, only follow matching children
                if depth < target_prefix.len() && child_idx != target_prefix[depth] {
                    continue;
                }

                let child = &internal.children[&child_idx];
                let mut child_path = path_prefix.to_vec();
                child_path.push(child_idx);
                let child_key = jvt::NodeKey::new(child.version, child_path.clone());
                collect_prefix_leaves(store, &child_key, &child_path, target_prefix, results);
            }
        }
        jvt::Node::EaS(eas) => {
            // Check if this EaS node's keys could match the prefix
            // Full key = path_prefix || stem || suffix_byte
            // We need: path_prefix || stem || suffix starts with target_prefix
            let node_prefix = {
                let mut p = path_prefix.to_vec();
                p.extend_from_slice(&eas.stem);
                p
            };

            // If the node's prefix diverges from target before we've consumed target, skip
            let common = node_prefix.len().min(target_prefix.len());
            if node_prefix[..common] != target_prefix[..common] {
                return;
            }

            let mut suffix_keys: Vec<u8> = eas.values.keys().copied().collect();
            suffix_keys.sort();

            for suffix in suffix_keys {
                let mut full_key = node_prefix.clone();
                full_key.push(suffix);

                if full_key.len() >= target_prefix.len()
                    && full_key[..target_prefix.len()] == *target_prefix
                {
                    results.push((full_key, eas.values[&suffix].clone()));
                }
            }
        }
    }
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
