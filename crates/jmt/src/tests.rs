use crate::jellyfish::{JellyfishMerkleTree, TreeUpdateBatch};
use crate::tier_framework::StoredNode;
use crate::tree_store::{StoredTreeNodeKey, TreeNode, TypedInMemoryTreeStore, WriteableTreeStore};
use crate::types::*;
use crate::{put_at_next_version, tree_store::Version};
use hyperscale_types::Hash;
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use std::collections::BTreeMap;

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
        .batch_put_value_set(value_set, None, None, 1)
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
        .batch_put_value_set(value_set, None, None, 1)
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
        .batch_put_value_set(value_set, None, None, 1)
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
        .batch_put_value_set(v1, None, None, 1)
        .expect("insert v1");
    apply_batch(&store, &batch);

    // Version 2: update same key with different value
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), Some((make_value_hash(2), 2u64)));
    let (root_v2, batch) = tree
        .batch_put_value_set(v2, None, Some(1), 2)
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
    let (root_v1, batch) = tree.batch_put_value_set(v1, None, None, 1).expect("insert");
    apply_batch(&store, &batch);

    // Delete (set to None)
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), None);
    let (root_v2, batch) = tree
        .batch_put_value_set(v2, None, Some(1), 2)
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
    let (_, batch_v1) = tree.batch_put_value_set(v1, None, None, 1).unwrap();
    apply_batch(&store, &batch_v1);
    assert_eq!(batch_v1.num_new_leaves, 1);
    assert_eq!(batch_v1.num_stale_leaves, 0);

    // Update at v2 — old leaf becomes stale
    let mut v2 = BTreeMap::new();
    v2.insert(key.clone(), Some((make_value_hash(2), 2u64)));
    let (_, batch_v2) = tree.batch_put_value_set(v2, None, Some(1), 2).unwrap();
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
        let (root, batch) = tree.batch_put_value_set(vs, None, None, 1).unwrap();
        apply_batch(&store, &batch);
        root
    };

    let root2 = {
        let store = TypedInMemoryTreeStore::new();
        let tree = JellyfishMerkleTree::new(&store);
        let mut vs = BTreeMap::new();
        vs.insert(make_leaf_key(1), Some((make_value_hash(10), 1u64)));
        vs.insert(make_leaf_key(2), Some((make_value_hash(20), 1u64)));
        let (root, batch) = tree.batch_put_value_set(vs, None, None, 1).unwrap();
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
// 3-tier put_at_next_version tests
// ---------------------------------------------------------------------------

#[test]
fn put_at_next_version_empty_tree() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xAA; 32];
    let value = vec![1, 2, 3];

    let updates = make_update(&entity_key, 0, &[1], &value);
    let root = put_at_next_version(&store, None, &updates);

    assert_ne!(
        root,
        Hash::ZERO,
        "non-empty update should produce non-zero root"
    );
}

#[test]
fn put_at_next_version_returns_zero_for_empty_updates() {
    let store = TypedInMemoryTreeStore::new();
    let updates = DatabaseUpdates::default();
    let root = put_at_next_version(&store, None, &updates);

    assert_eq!(root, Hash::ZERO, "empty updates should produce zero root");
}

#[test]
fn put_at_next_version_sequential_versions() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xBB; 32];

    // Version 1
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10, 20]);
    let root_v1 = put_at_next_version(&store, None, &updates_v1);

    // Version 2: different value for same substate
    let updates_v2 = make_update(&entity_key, 0, &[1], &[30, 40]);
    let root_v2 = put_at_next_version(&store, Some(1), &updates_v2);

    assert_ne!(
        root_v1, root_v2,
        "different values must produce different roots"
    );
}

#[test]
fn put_at_next_version_multiple_entities() {
    let store = TypedInMemoryTreeStore::new();

    let mut updates = make_update(&[0xAA; 32], 0, &[1], &[10]);
    let updates_b = make_update(&[0xBB; 32], 0, &[2], &[20]);
    updates.node_updates.extend(updates_b.node_updates);

    let root = put_at_next_version(&store, None, &updates);
    assert_ne!(root, Hash::ZERO);
}

#[test]
fn put_at_next_version_delete_all_returns_zero() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xCC; 32];

    // Insert
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10]);
    let root_v1 = put_at_next_version(&store, None, &updates_v1);
    assert_ne!(root_v1, Hash::ZERO);

    // Delete
    let updates_v2 = make_delete(&entity_key, 0, &[1]);
    let root_v2 = put_at_next_version(&store, Some(1), &updates_v2);

    // After deleting the only entry, root should return to zero
    assert_eq!(root_v2, Hash::ZERO);
}

#[test]
fn put_at_next_version_multiple_partitions() {
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

    let root = put_at_next_version(&store, None, &updates);
    assert_ne!(root, Hash::ZERO);
}

#[test]
fn put_at_next_version_partition_reset() {
    let store = TypedInMemoryTreeStore::new();
    let entity_key = vec![0xEE; 32];

    // V1: insert
    let updates_v1 = make_update(&entity_key, 0, &[1], &[10]);
    let root_v1 = put_at_next_version(&store, None, &updates_v1);

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
    let root_v2 = put_at_next_version(&store, Some(1), &updates_v2);

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
