use crate::jellyfish::{JellyfishMerkleTree, TreeUpdateBatch};
use crate::tier_framework::{ReadableTier, StoredNode};
use crate::tree_store::{StoredTreeNodeKey, TreeNode, TypedInMemoryTreeStore, WriteableTreeStore};
use crate::types::*;
use crate::{put_at_version, put_at_version_and_apply, tree_store::Version};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_types::Hash;
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn sync_dispatch() -> SyncDispatch {
    SyncDispatch::new()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Apply a JMT update batch to the in-memory store.
fn apply_batch(store: &TypedInMemoryTreeStore, batch: &TreeUpdateBatch<Version>) {
    for (k, node) in batch.node_batch.iter().flatten() {
        store.insert_node(
            StoredTreeNodeKey::unprefixed(k.clone()),
            TreeNode::from_jmt_node(node, k),
        );
    }
}

fn make_leaf_key(b: u8) -> LeafKey {
    LeafKey::new(&[b; 32])
}

fn make_value_hash(b: u8) -> Hash {
    Hash::from_bytes(&[b])
}

/// Build a DatabaseUpdates for a single substate write.
fn make_update(node_key: &[u8], partition: u8, sort_key: &[u8], value: &[u8]) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        node_key.to_vec(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(
                        DbSortKey(sort_key.to_vec()),
                        DatabaseUpdate::Set(value.to_vec()),
                    )]
                    .into_iter()
                    .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    updates
}

fn make_delete(node_key: &[u8], partition: u8, sort_key: &[u8]) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        node_key.to_vec(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(DbSortKey(sort_key.to_vec()), DatabaseUpdate::Delete)]
                        .into_iter()
                        .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    updates
}

// ---------------------------------------------------------------------------
// Low-level JMT tests (single-tier)
// ---------------------------------------------------------------------------

#[test]
fn single_insert_and_get_with_proof() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let key = make_leaf_key(0xAA);
    let value_hash = make_value_hash(1);
    let payload: Version = 1;

    let mut value_set = BTreeMap::new();
    value_set.insert(key.clone(), Some((value_hash, payload)));

    let (root_hash, batch) = tree
        .batch_put_value_set(value_set, None, None, 1, &sync_dispatch())
        .expect("insert should succeed");
    apply_batch(&store, &batch);

    // Get with proof
    let (result, proof) = tree.get_with_proof(&key, 1).expect("get should succeed");
    let (got_hash, got_payload, got_version) = result.expect("key should exist");

    assert_eq!(got_hash, value_hash);
    assert_eq!(got_payload, payload);
    assert_eq!(got_version, 1);

    // Root hash should be non-zero
    assert_ne!(root_hash, Hash::ZERO);

    // Root hash from get_root_hash should match
    assert_eq!(tree.get_root_hash(1).unwrap(), root_hash);

    // Leaf count should be 1
    assert_eq!(tree.get_leaf_count(1).unwrap(), 1);

    // Proof leaf should be present
    assert!(proof.leaf().is_some());
}

#[test]
fn get_nonexistent_key_returns_none() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let key_a = make_leaf_key(0xAA);
    let key_b = make_leaf_key(0xBB);
    let value_hash = make_value_hash(1);

    let mut value_set = BTreeMap::new();
    value_set.insert(key_a.clone(), Some((value_hash, 1u64)));

    let (_root_hash, batch) = tree
        .batch_put_value_set(value_set, None, None, 1, &sync_dispatch())
        .expect("insert should succeed");
    apply_batch(&store, &batch);

    // Query for key_b which was never inserted
    let (result, proof) = tree.get_with_proof(&key_b, 1).expect("get should succeed");
    assert!(result.is_none());
    // Non-inclusion proof: either shows a different leaf or empty subtree
    assert!(proof.leaf().is_some() || proof.siblings().is_empty());
}

#[test]
fn batch_insert_multiple_keys() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let keys: Vec<LeafKey> = (0..10).map(|i| make_leaf_key(i * 17)).collect();
    let mut value_set = BTreeMap::new();
    for (i, key) in keys.iter().enumerate() {
        value_set.insert(key.clone(), Some((make_value_hash(i as u8), i as Version)));
    }

    let (root_hash, batch) = tree
        .batch_put_value_set(value_set, None, None, 1, &sync_dispatch())
        .expect("batch insert should succeed");
    apply_batch(&store, &batch);

    assert_ne!(root_hash, Hash::ZERO);
    assert_eq!(tree.get_leaf_count(1).unwrap(), 10);

    // Each key should be retrievable
    for (i, key) in keys.iter().enumerate() {
        let (result, _) = tree.get_with_proof(key, 1).expect("get should succeed");
        let (got_hash, _, _) = result.expect("key should exist");
        assert_eq!(got_hash, make_value_hash(i as u8));
    }
}

#[test]
fn update_existing_key_changes_root() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let key = make_leaf_key(0xAA);

    // Version 1: insert
    let mut v1 = BTreeMap::new();
    v1.insert(key.clone(), Some((make_value_hash(1), 1u64)));
    let (root_v1, batch) = tree
        .batch_put_value_set(v1, None, None, 1, &sync_dispatch())
        .expect("insert v1");
    apply_batch(&store, &batch);

    // Version 2: update same key with different value
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), Some((make_value_hash(2), 2u64)));
    let (root_v2, batch) = tree
        .batch_put_value_set(v2, None, Some(1), 2, &sync_dispatch())
        .expect("insert v2");
    apply_batch(&store, &batch);

    assert_ne!(
        root_v1, root_v2,
        "different values must produce different roots"
    );

    // Version 1 root should still be accessible
    assert_eq!(tree.get_root_hash(1).unwrap(), root_v1);

    // Version 2 should return the new value
    let (result, _) = tree.get_with_proof(&key, 2).unwrap();
    let (got_hash, _, _) = result.unwrap();
    assert_eq!(got_hash, make_value_hash(2));
}

#[test]
fn delete_key_removes_from_tree() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let key = make_leaf_key(0xAA);

    // Insert
    let mut v1 = BTreeMap::new();
    v1.insert(key.clone(), Some((make_value_hash(1), 1u64)));
    let (root_v1, batch) = tree
        .batch_put_value_set(v1, None, None, 1, &sync_dispatch())
        .expect("insert");
    apply_batch(&store, &batch);

    // Delete (set to None)
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), None);
    let (root_v2, batch) = tree
        .batch_put_value_set(v2, None, Some(1), 2, &sync_dispatch())
        .expect("delete");
    apply_batch(&store, &batch);

    // Root should now be the placeholder (empty tree)
    assert_eq!(root_v2, SPARSE_MERKLE_PLACEHOLDER_HASH);
    assert_ne!(root_v1, root_v2);

    // Key should no longer exist at version 2
    let (result, _) = tree.get_with_proof(&key, 2).unwrap();
    assert!(result.is_none());
}

#[test]
fn stale_node_tracking() {
    let store = TypedInMemoryTreeStore::new();
    let tree = JellyfishMerkleTree::new(&store);

    let key = make_leaf_key(0xAA);

    // Insert at v1
    let mut v1 = BTreeMap::new();
    v1.insert(key.clone(), Some((make_value_hash(1), 1u64)));
    let (_, batch_v1) = tree
        .batch_put_value_set(v1, None, None, 1, &sync_dispatch())
        .unwrap();
    apply_batch(&store, &batch_v1);
    assert_eq!(batch_v1.num_new_leaves, 1);
    assert_eq!(batch_v1.num_stale_leaves, 0);

    // Update at v2 — old leaf becomes stale
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), Some((make_value_hash(2), 2u64)));
    let (_, batch_v2) = tree
        .batch_put_value_set(v2, None, Some(1), 2, &sync_dispatch())
        .unwrap();
    assert_eq!(batch_v2.num_new_leaves, 1);
    assert_eq!(batch_v2.num_stale_leaves, 1);
    assert!(
        !batch_v2.stale_node_index_batch[0].is_empty(),
        "should have stale node entries"
    );
}

#[test]
fn deterministic_root_hash() {
    // Same data inserted in the same order should always produce the same root.
    let root1 = {
        let store = TypedInMemoryTreeStore::new();
        let tree = JellyfishMerkleTree::new(&store);
        let mut vs = BTreeMap::new();
        vs.insert(make_leaf_key(1), Some((make_value_hash(10), 1u64)));
        vs.insert(make_leaf_key(2), Some((make_value_hash(20), 1u64)));
        let (root, batch) = tree
            .batch_put_value_set(vs, None, None, 1, &sync_dispatch())
            .unwrap();
        apply_batch(&store, &batch);
        root
    };

    let root2 = {
        let store = TypedInMemoryTreeStore::new();
        let tree = JellyfishMerkleTree::new(&store);
        let mut vs = BTreeMap::new();
        vs.insert(make_leaf_key(1), Some((make_value_hash(10), 1u64)));
        vs.insert(make_leaf_key(2), Some((make_value_hash(20), 1u64)));
        let (root, batch) = tree
            .batch_put_value_set(vs, None, None, 1, &sync_dispatch())
            .unwrap();
        apply_batch(&store, &batch);
        root
    };

    assert_eq!(root1, root2);
}

// ---------------------------------------------------------------------------
// Domain separation tests
// ---------------------------------------------------------------------------

#[test]
fn domain_separation_leaf_vs_internal() {
    // A leaf hash and an internal node hash with the same 64 bytes of data
    // must produce different results due to domain tags.
    let a = Hash::from_bytes(&[1; 32]);
    let b = Hash::from_bytes(&[2; 32]);

    let leaf = SparseMerkleLeafNode::new(LeafKey::new(a.as_bytes()), b);
    let internal = SparseMerkleInternalNode::new(a, b);

    assert_ne!(
        leaf.hash(),
        internal.hash(),
        "leaf and internal hashes must differ even with same input bytes"
    );
}

#[test]
fn leaf_hash_matches_between_types() {
    // SparseMerkleLeafNode::hash() and LeafNode::leaf_hash() must agree
    // for the same key and value_hash.
    let key = make_leaf_key(0xCC);
    let value_hash = make_value_hash(42);

    let sparse_leaf = SparseMerkleLeafNode::new(key.clone(), value_hash);
    let leaf_node = LeafNode::new(key, value_hash, 1u64, 1);

    assert_eq!(sparse_leaf.hash(), leaf_node.leaf_hash());
}

// ---------------------------------------------------------------------------
// 3-tier put_at_version tests
// ---------------------------------------------------------------------------

#[test]
fn put_at_version_empty_tree() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xAA; 32];
    let value = vec![1, 2, 3];

    let updates = make_update(&entity_key, 0, &[1], &value);
    let root = put_at_version_and_apply(&store, None, 1, &updates, &sync_dispatch());

    assert_ne!(
        root,
        Hash::ZERO,
        "non-empty update should produce non-zero root"
    );
}

#[test]
fn put_at_version_returns_zero_for_empty_updates() {
    let store = TypedInMemoryTreeStore::new();
    let updates = DatabaseUpdates::default();
    let root = put_at_version_and_apply(&store, None, 1, &updates, &sync_dispatch());

    assert_eq!(root, Hash::ZERO, "empty updates should produce zero root");
}

#[test]
fn put_at_version_sequential_versions() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xBB; 32];

    // Version 1
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10, 20]);
    let root_v1 = put_at_version_and_apply(&store, None, 1, &updates_v1, &sync_dispatch());

    // Version 2: different value for same substate
    let updates_v2 = make_update(&entity_key, 0, &[1], &[30, 40]);
    let root_v2 = put_at_version_and_apply(&store, Some(1), 2, &updates_v2, &sync_dispatch());

    assert_ne!(
        root_v1, root_v2,
        "different values must produce different roots"
    );
}

#[test]
fn put_at_version_multiple_entities() {
    let store = TypedInMemoryTreeStore::new();

    let mut updates = make_update(&[0xAA; 32], 0, &[1], &[10]);
    let updates_b = make_update(&[0xBB; 32], 0, &[2], &[20]);
    updates.node_updates.extend(updates_b.node_updates);

    let root = put_at_version_and_apply(&store, None, 1, &updates, &sync_dispatch());
    assert_ne!(root, Hash::ZERO);
}

#[test]
fn put_at_version_delete_all_returns_zero() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xCC; 32];

    // Insert
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10]);
    let root_v1 = put_at_version_and_apply(&store, None, 1, &updates_v1, &sync_dispatch());
    assert_ne!(root_v1, Hash::ZERO);

    // Delete
    let updates_v2 = make_delete(&entity_key, 0, &[1]);
    let root_v2 = put_at_version_and_apply(&store, Some(1), 2, &updates_v2, &sync_dispatch());

    // After deleting the only entry, root should return to zero
    assert_eq!(root_v2, Hash::ZERO);
}

#[test]
fn put_at_version_multiple_partitions() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xDD; 32];

    // Insert into partition 0 and partition 5 in one update
    let mut updates = DatabaseUpdates::default();
    let mut partition_updates = indexmap::IndexMap::new();
    partition_updates.insert(
        0u8,
        PartitionDatabaseUpdates::Delta {
            substate_updates: [(DbSortKey(vec![1]), DatabaseUpdate::Set(vec![10]))]
                .into_iter()
                .collect(),
        },
    );
    partition_updates.insert(
        5u8,
        PartitionDatabaseUpdates::Delta {
            substate_updates: [(DbSortKey(vec![2]), DatabaseUpdate::Set(vec![20]))]
                .into_iter()
                .collect(),
        },
    );
    updates.node_updates.insert(
        entity_key.clone(),
        NodeDatabaseUpdates { partition_updates },
    );

    let root = put_at_version_and_apply(&store, None, 1, &updates, &sync_dispatch());
    assert_ne!(root, Hash::ZERO);
}

#[test]
fn put_at_version_partition_reset() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xEE; 32];

    // V1: insert
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10]);
    let root_v1 = put_at_version_and_apply(&store, None, 1, &updates_v1, &sync_dispatch());

    // V2: reset partition with new values
    let mut updates_v2 = DatabaseUpdates::default();
    updates_v2.node_updates.insert(
        entity_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: [(
                0u8,
                PartitionDatabaseUpdates::Reset {
                    new_substate_values: [(DbSortKey(vec![99]), vec![88])].into_iter().collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    let root_v2 = put_at_version_and_apply(&store, Some(1), 2, &updates_v2, &sync_dispatch());

    assert_ne!(root_v1, root_v2, "reset should produce different root");
    assert_ne!(root_v2, Hash::ZERO);
}

// ---------------------------------------------------------------------------
// NibblePath tests
// ---------------------------------------------------------------------------

#[test]
fn nibble_path_push_pop_roundtrip() {
    let mut path = NibblePath::new_even(vec![]);
    path.push(Nibble::from(0xA));
    path.push(Nibble::from(0x3));
    path.push(Nibble::from(0xF));

    assert_eq!(path.num_nibbles(), 3);
    assert_eq!(path.get_nibble(0), Nibble::from(0xA));
    assert_eq!(path.get_nibble(1), Nibble::from(0x3));
    assert_eq!(path.get_nibble(2), Nibble::from(0xF));

    assert_eq!(path.pop(), Some(Nibble::from(0xF)));
    assert_eq!(path.num_nibbles(), 2);
    assert_eq!(path.pop(), Some(Nibble::from(0x3)));
    assert_eq!(path.pop(), Some(Nibble::from(0xA)));
    assert_eq!(path.pop(), None);
    assert!(path.is_empty());
}

#[test]
fn nibble_path_prefix_with() {
    let path = NibblePath::new_even(vec![0xAB]);
    let prefixed = path.prefix_with(&[0x12, 0x34]);

    assert_eq!(prefixed.num_nibbles(), 6); // 2*2 + 1*2
    assert_eq!(prefixed.get_nibble(0), Nibble::from(0x1));
    assert_eq!(prefixed.get_nibble(1), Nibble::from(0x2));
    assert_eq!(prefixed.get_nibble(4), Nibble::from(0xA));
    assert_eq!(prefixed.get_nibble(5), Nibble::from(0xB));
}

// ---------------------------------------------------------------------------
// TreeNodeKey tests
// ---------------------------------------------------------------------------

#[test]
fn tree_node_key_gen_child_and_parent() {
    let root = TreeNodeKey::new_empty_path(1);
    let child = root.gen_child_node_key(1, Nibble::from(5));

    assert_eq!(child.version(), 1);
    assert_eq!(child.nibble_path().num_nibbles(), 1);
    assert_eq!(child.nibble_path().get_nibble(0), Nibble::from(5));

    let parent = child.gen_parent_node_key();
    assert_eq!(parent.nibble_path().num_nibbles(), 0);
}

// ---------------------------------------------------------------------------
// Parallel dispatch tests
// ---------------------------------------------------------------------------

#[test]
fn parallel_dispatch_matches_sequential() {
    use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};

    let pooled = PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap();
    let sequential = sync_dispatch();

    // Insert enough distinct entity keys to create internal nodes with 3+ children,
    // exercising the parallel path in batch_insert_at (threshold: ranges.len() >= 3).
    let store_par = TypedInMemoryTreeStore::new();
    let store_seq = TypedInMemoryTreeStore::new();

    // 16 keys with different first nibbles to ensure 3+ children at the root
    let updates = {
        let mut u = DatabaseUpdates::default();
        for i in 0u8..16 {
            let entity_key = {
                let mut k = vec![i; 32];
                k[1] = 0xAA; // vary second byte to avoid collisions
                k
            };
            let sub = make_update(&entity_key, 0, &[i], &[i, i + 1]);
            u.node_updates.extend(sub.node_updates);
        }
        u
    };

    // Version 1: initial insert
    let root_par = put_at_version_and_apply(&store_par, None, 1, &updates, &pooled);
    let root_seq = put_at_version_and_apply(&store_seq, None, 1, &updates, &sequential);

    assert_eq!(
        root_par, root_seq,
        "parallel and sequential must produce identical roots on insert"
    );
    assert_ne!(root_par, Hash::ZERO);

    // Version 2: update half the keys
    let updates_v2 = {
        let mut u = DatabaseUpdates::default();
        for i in (0u8..16).step_by(2) {
            let entity_key = {
                let mut k = vec![i; 32];
                k[1] = 0xAA;
                k
            };
            let sub = make_update(&entity_key, 0, &[i], &[i + 10, i + 11]);
            u.node_updates.extend(sub.node_updates);
        }
        u
    };

    let root_par_v2 = put_at_version_and_apply(&store_par, Some(1), 2, &updates_v2, &pooled);
    let root_seq_v2 = put_at_version_and_apply(&store_seq, Some(1), 2, &updates_v2, &sequential);

    assert_eq!(
        root_par_v2, root_seq_v2,
        "parallel and sequential must produce identical roots on update"
    );
    assert_ne!(root_par_v2, root_par);
}

// ---------------------------------------------------------------------------
// TierCollectedWrites and CollectedAssociation tests
// ---------------------------------------------------------------------------

#[test]
fn tier_collected_writes_merge() {
    use crate::tier_framework::{
        CollectedAssociation, CollectedSubstateValue, TierCollectedWrites,
    };
    use crate::tree_store::{StaleTreePart, StoredTreeNodeKey, TreeNode};

    let key1 = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(1));
    let key2 = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(2));
    let key3 = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(3));

    let mut a = TierCollectedWrites {
        nodes: vec![(key1.clone(), TreeNode::Null)],
        stale_tree_parts: vec![StaleTreePart::Node(key2.clone())],
        associations: vec![CollectedAssociation {
            tree_node_key: key1.clone(),
            partition_key: Arc::new(DbPartitionKey {
                node_key: vec![1],
                partition_num: 0,
            }),
            sort_key: DbSortKey(vec![1]),
            value: CollectedSubstateValue::Upserted(vec![10]),
        }],
    };

    let b = TierCollectedWrites {
        nodes: vec![(key3.clone(), TreeNode::Null)],
        stale_tree_parts: vec![StaleTreePart::Node(key1.clone())],
        associations: vec![CollectedAssociation {
            tree_node_key: key2.clone(),
            partition_key: Arc::new(DbPartitionKey {
                node_key: vec![2],
                partition_num: 0,
            }),
            sort_key: DbSortKey(vec![2]),
            value: CollectedSubstateValue::Unchanged,
        }],
    };

    a.merge(b);

    assert_eq!(a.nodes.len(), 2, "nodes should be merged");
    assert_eq!(a.stale_tree_parts.len(), 2, "stale parts should be merged");
    assert_eq!(a.associations.len(), 2, "associations should be merged");
}

#[test]
fn collected_association_resolve_upserted() {
    use crate::tier_framework::{CollectedAssociation, CollectedSubstateValue};

    let key = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(1));
    let assoc = CollectedAssociation {
        tree_node_key: key.clone(),
        partition_key: Arc::new(DbPartitionKey {
            node_key: vec![1],
            partition_num: 0,
        }),
        sort_key: DbSortKey(vec![1]),
        value: CollectedSubstateValue::Upserted(vec![42, 43]),
    };

    let result = assoc.resolve(|_pk, _sk| panic!("lookup should not be called for Upserted"));
    let (resolved_key, resolved_value) = result.expect("Upserted should always resolve");
    assert_eq!(resolved_key, key);
    assert_eq!(resolved_value, vec![42, 43]);
}

#[test]
fn collected_association_resolve_unchanged_found() {
    use crate::tier_framework::{CollectedAssociation, CollectedSubstateValue};

    let key = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(1));
    let assoc = CollectedAssociation {
        tree_node_key: key.clone(),
        partition_key: Arc::new(DbPartitionKey {
            node_key: vec![1],
            partition_num: 0,
        }),
        sort_key: DbSortKey(vec![1]),
        value: CollectedSubstateValue::Unchanged,
    };

    let result = assoc.resolve(|_pk, _sk| Some(vec![99]));
    let (resolved_key, resolved_value) =
        result.expect("Unchanged with found lookup should resolve");
    assert_eq!(resolved_key, key);
    assert_eq!(resolved_value, vec![99]);
}

#[test]
fn collected_association_resolve_unchanged_not_found() {
    use crate::tier_framework::{CollectedAssociation, CollectedSubstateValue};

    let key = StoredTreeNodeKey::unprefixed(TreeNodeKey::new_empty_path(1));
    let assoc = CollectedAssociation {
        tree_node_key: key,
        partition_key: Arc::new(DbPartitionKey {
            node_key: vec![1],
            partition_num: 0,
        }),
        sort_key: DbSortKey(vec![1]),
        value: CollectedSubstateValue::Unchanged,
    };

    let result = assoc.resolve(|_pk, _sk| None);
    assert!(
        result.is_none(),
        "Unchanged with missing lookup should return None"
    );
}

// ---------------------------------------------------------------------------
// Version = block height tests (gaps, genesis at version 0, direct put_at_version)
// ---------------------------------------------------------------------------

#[test]
fn put_at_version_genesis_at_version_zero() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xAA; 32];
    let value = vec![1, 2, 3];

    // Genesis: parent=None, new_version=0
    let updates = make_update(&entity_key, 0, &[1], &value);
    let root = put_at_version_and_apply(&store, None, 0, &updates, &sync_dispatch());

    assert_ne!(root, Hash::ZERO, "genesis should produce non-zero root");

    // Can read back at version 0
    let entity_tier = crate::entity_tier::EntityTier::new(&store, Some(0));
    let leaf_key = LeafKey::new(&entity_key);
    let (result, _proof) = entity_tier
        .jmt()
        .get_with_proof(&leaf_key, 0)
        .expect("get at version 0 should succeed");
    assert!(result.is_some(), "entity should exist at genesis version 0");
}

#[test]
fn put_at_version_non_sequential_gaps() {
    // Simulates version = block height with gaps (e.g., empty blocks that
    // were committed separately advance the version).
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xBB; 32];

    // Version 0 (genesis)
    let updates_v0 = make_update(&entity_key, 0, &[1], &[10]);
    let root_v0 = put_at_version_and_apply(&store, None, 0, &updates_v0, &sync_dispatch());
    assert_ne!(root_v0, Hash::ZERO);

    // Jump to version 5 (simulating blocks 1-4 were empty and advanced version)
    let updates_v5 = make_update(&entity_key, 0, &[1], &[20]);
    let root_v5 = put_at_version_and_apply(&store, Some(0), 5, &updates_v5, &sync_dispatch());
    assert_ne!(root_v5, Hash::ZERO);
    assert_ne!(root_v0, root_v5);

    // Jump to version 10
    let updates_v10 = make_update(&entity_key, 0, &[2], &[30]);
    let root_v10 = put_at_version_and_apply(&store, Some(5), 10, &updates_v10, &sync_dispatch());
    assert_ne!(root_v10, Hash::ZERO);
    assert_ne!(root_v5, root_v10);

    // Historical reads still work at each version
    let entity_tier_v0 = crate::entity_tier::EntityTier::new(&store, Some(0));
    let leaf_key = LeafKey::new(&entity_key);
    let (result_v0, _) = entity_tier_v0
        .jmt()
        .get_with_proof(&leaf_key, 0)
        .expect("get at v0");
    assert!(result_v0.is_some(), "entity should exist at version 0");

    let entity_tier_v5 = crate::entity_tier::EntityTier::new(&store, Some(5));
    let (result_v5, _) = entity_tier_v5
        .jmt()
        .get_with_proof(&leaf_key, 5)
        .expect("get at v5");
    assert!(result_v5.is_some(), "entity should exist at version 5");

    let entity_tier_v10 = crate::entity_tier::EntityTier::new(&store, Some(10));
    let (result_v10, _) = entity_tier_v10
        .jmt()
        .get_with_proof(&leaf_key, 10)
        .expect("get at v10");
    assert!(result_v10.is_some(), "entity should exist at version 10");
}

#[test]
fn put_at_version_direct_returns_collected_writes() {
    // Test put_at_version (not _and_apply) returns correct collected writes.
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xCC; 32];

    let updates = make_update(&entity_key, 0, &[1], &[42]);
    let (root, collected) = put_at_version(&store, None, 1, &updates, &sync_dispatch());

    assert_ne!(root, Hash::ZERO);

    // Collected writes should have nodes and associations
    assert!(!collected.nodes.is_empty(), "should have tree nodes");
    assert!(
        !collected.associations.is_empty(),
        "should have associations"
    );

    // The store should still be empty (nothing applied yet)
    let entity_tier = crate::entity_tier::EntityTier::new(&store, Some(1));
    let leaf_key = LeafKey::new(&entity_key);
    let result = entity_tier.jmt().get_with_proof(&leaf_key, 1);
    assert!(result.is_err(), "store should have no nodes before apply");

    // Now apply and verify
    let _associations = collected.apply_to(&store);
    let entity_tier = crate::entity_tier::EntityTier::new(&store, Some(1));
    let (found, _) = entity_tier
        .jmt()
        .get_with_proof(&leaf_key, 1)
        .expect("get after apply");
    assert!(found.is_some(), "entity should exist after applying writes");
}

// ---------------------------------------------------------------------------
// Partition/substate tier parallelism test
// ---------------------------------------------------------------------------

#[test]
fn parallel_dispatch_partition_tier() {
    // Exercise parallelism at the partition tier by creating a single entity
    // with many partitions (>= 3 to trigger batch_insert_at parallel path).
    use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};

    let pooled = PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap();
    let sequential = sync_dispatch();

    let store_par = TypedInMemoryTreeStore::new();
    let store_seq = TypedInMemoryTreeStore::new();

    let entity_key = vec![0xFF; 32];

    // Single entity with 8 partitions, each with one substate.
    // This creates 8 children at the partition tier root, triggering parallelism.
    let updates = {
        let mut partition_updates = indexmap::IndexMap::new();
        for p in 0u8..8 {
            partition_updates.insert(
                p,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(DbSortKey(vec![p]), DatabaseUpdate::Set(vec![p, p + 1]))]
                        .into_iter()
                        .collect(),
                },
            );
        }
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            entity_key.clone(),
            NodeDatabaseUpdates { partition_updates },
        );
        u
    };

    let root_par = put_at_version_and_apply(&store_par, None, 1, &updates, &pooled);
    let root_seq = put_at_version_and_apply(&store_seq, None, 1, &updates, &sequential);

    assert_eq!(
        root_par, root_seq,
        "parallel and sequential must produce identical roots for partition-heavy updates"
    );
    assert_ne!(root_par, Hash::ZERO);

    // Update half the partitions at version 2
    let updates_v2 = {
        let mut partition_updates = indexmap::IndexMap::new();
        for p in (0u8..8).step_by(2) {
            partition_updates.insert(
                p,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(
                        DbSortKey(vec![p]),
                        DatabaseUpdate::Set(vec![p + 10, p + 11]),
                    )]
                    .into_iter()
                    .collect(),
                },
            );
        }
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            entity_key.clone(),
            NodeDatabaseUpdates { partition_updates },
        );
        u
    };

    let root_par_v2 = put_at_version_and_apply(&store_par, Some(1), 2, &updates_v2, &pooled);
    let root_seq_v2 = put_at_version_and_apply(&store_seq, Some(1), 2, &updates_v2, &sequential);

    assert_eq!(
        root_par_v2, root_seq_v2,
        "parallel and sequential must match on partition tier update"
    );
    assert_ne!(root_par_v2, root_par);
}

#[test]
fn parallel_dispatch_substate_tier() {
    // Exercise parallelism at the substate tier by creating a single entity
    // with one partition containing many substates.
    use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};

    let pooled = PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap();
    let sequential = sync_dispatch();

    let store_par = TypedInMemoryTreeStore::new();
    let store_seq = TypedInMemoryTreeStore::new();

    let entity_key = vec![0xAA; 32];

    // Single entity, single partition, 16 substates with different sort keys.
    // This creates 16 children at the substate tier root.
    let updates = {
        let mut substate_updates = indexmap::IndexMap::new();
        for s in 0u8..16 {
            // Use 32-byte sort keys to ensure different nibble paths
            let mut sort_key = vec![s; 32];
            sort_key[1] = 0xBB;
            substate_updates.insert(DbSortKey(sort_key), DatabaseUpdate::Set(vec![s, s + 1]));
        }
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            entity_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(0u8, PartitionDatabaseUpdates::Delta { substate_updates })]
                    .into_iter()
                    .collect(),
            },
        );
        u
    };

    let root_par = put_at_version_and_apply(&store_par, None, 1, &updates, &pooled);
    let root_seq = put_at_version_and_apply(&store_seq, None, 1, &updates, &sequential);

    assert_eq!(
        root_par, root_seq,
        "parallel and sequential must produce identical roots for substate-heavy updates"
    );
    assert_ne!(root_par, Hash::ZERO);
}

// ---------------------------------------------------------------------------
// Version ordering validation tests
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "new_version (5) must be greater than parent_version (Some(5))")]
fn put_at_version_rejects_equal_versions() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xAA; 32];

    // First write at version 5
    let updates = make_update(&entity_key, 0, &[1], &[10]);
    put_at_version_and_apply(&store, None, 5, &updates, &sync_dispatch());

    // Attempt parent_version == new_version: should panic
    let updates_v2 = make_update(&entity_key, 0, &[1], &[20]);
    put_at_version_and_apply(&store, Some(5), 5, &updates_v2, &sync_dispatch());
}

#[test]
#[should_panic(expected = "new_version (3) must be greater than parent_version (Some(10))")]
fn put_at_version_rejects_backwards_version() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xBB; 32];

    let updates = make_update(&entity_key, 0, &[1], &[10]);
    put_at_version_and_apply(&store, None, 10, &updates, &sync_dispatch());

    // Attempt new_version < parent_version: should panic
    let updates_v2 = make_update(&entity_key, 0, &[1], &[20]);
    put_at_version_and_apply(&store, Some(10), 3, &updates_v2, &sync_dispatch());
}

// ---------------------------------------------------------------------------
// Parallel dispatch: fresh subtree (batch_update_subtree) parallelization
// ---------------------------------------------------------------------------

#[test]
fn parallel_dispatch_fresh_tree_matches_sequential() {
    // Exercises the parallelized batch_update_subtree path: a completely fresh
    // tree with many entities (no persisted_version, so batch_update_subtree is
    // used instead of batch_insert_at).
    use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};

    let pooled = PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap();
    let sequential = sync_dispatch();

    let store_par = TypedInMemoryTreeStore::new();
    let store_seq = TypedInMemoryTreeStore::new();

    // 32 entities with varying keys to create a wide tree at the root.
    let updates = {
        let mut u = DatabaseUpdates::default();
        for i in 0u8..32 {
            let entity_key = {
                let mut k = vec![i; 32];
                k[1] = 0xCC;
                k
            };
            let sub = make_update(&entity_key, 0, &[i], &[i, i.wrapping_add(1)]);
            u.node_updates.extend(sub.node_updates);
        }
        u
    };

    let root_par = put_at_version_and_apply(&store_par, None, 1, &updates, &pooled);
    let root_seq = put_at_version_and_apply(&store_seq, None, 1, &updates, &sequential);

    assert_eq!(
        root_par, root_seq,
        "parallel and sequential must match for fresh tree insertion"
    );
    assert_ne!(root_par, Hash::ZERO);
}

// ---------------------------------------------------------------------------
// Parallel dispatch: partition reset under parallelism
// ---------------------------------------------------------------------------

#[test]
fn parallel_dispatch_partition_reset() {
    // Exercises the StaleTreePart::Subtree collection path under parallel dispatch.
    use hyperscale_dispatch_pooled::{PooledDispatch, ThreadPoolConfig};

    let pooled = PooledDispatch::new(ThreadPoolConfig::minimal()).unwrap();
    let sequential = sync_dispatch();

    let store_par = TypedInMemoryTreeStore::new();
    let store_seq = TypedInMemoryTreeStore::new();

    let entity_key = vec![0xEE; 32];

    // V1: insert 4 partitions with data
    let updates_v1 = {
        let mut partition_updates = indexmap::IndexMap::new();
        for p in 0u8..4 {
            partition_updates.insert(
                p,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(DbSortKey(vec![p]), DatabaseUpdate::Set(vec![p, p + 1]))]
                        .into_iter()
                        .collect(),
                },
            );
        }
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            entity_key.clone(),
            NodeDatabaseUpdates { partition_updates },
        );
        u
    };

    let root_par_v1 = put_at_version_and_apply(&store_par, None, 1, &updates_v1, &pooled);
    let root_seq_v1 = put_at_version_and_apply(&store_seq, None, 1, &updates_v1, &sequential);
    assert_eq!(root_par_v1, root_seq_v1);

    // V2: reset partitions 0 and 2 with new values
    let updates_v2 = {
        let mut partition_updates = indexmap::IndexMap::new();
        for &p in &[0u8, 2] {
            partition_updates.insert(
                p,
                PartitionDatabaseUpdates::Reset {
                    new_substate_values: [(DbSortKey(vec![99, p]), vec![88, p])]
                        .into_iter()
                        .collect(),
                },
            );
        }
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            entity_key.clone(),
            NodeDatabaseUpdates { partition_updates },
        );
        u
    };

    let root_par_v2 = put_at_version_and_apply(&store_par, Some(1), 2, &updates_v2, &pooled);
    let root_seq_v2 = put_at_version_and_apply(&store_seq, Some(1), 2, &updates_v2, &sequential);

    assert_eq!(
        root_par_v2, root_seq_v2,
        "parallel and sequential must match for partition reset"
    );
    assert_ne!(root_par_v2, root_par_v1);
}
