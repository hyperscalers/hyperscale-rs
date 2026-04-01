use crate::core::SimStorage;

use hyperscale_storage::test_helpers::{
    make_database_update, make_mapped_database_update, make_test_block, make_test_certificate,
    make_test_qc,
};
use hyperscale_storage::{
    CommitStore, CommittableSubstateDatabase, ConsensusStore, DatabaseUpdate, DatabaseUpdates,
    DbPartitionKey, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates, SubstateDatabase,
    SubstateStore,
};
use hyperscale_types::{
    zero_bls_signature, BlockHeight, Hash, NodeId, ShardGroupId, SignerBitfield,
};
use std::sync::Arc;

#[test]
fn test_basic_substate_operations() {
    let mut storage = SimStorage::new();

    // Create a partition key and sort key
    let partition_key = DbPartitionKey {
        node_key: vec![1, 2, 3],
        partition_num: 0,
    };
    let sort_key = DbSortKey(vec![10, 20]);

    // Initially empty
    assert!(storage
        .get_raw_substate_by_db_key(&partition_key, &sort_key)
        .is_none());

    // Commit a value
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        partition_key.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![99, 88, 77]))]
                        .into_iter()
                        .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    storage.commit(&updates);

    // Now we can read it
    let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
    assert_eq!(value, Some(vec![99, 88, 77]));
}

#[test]
fn test_snapshot_isolation() {
    let mut storage = SimStorage::new();

    let partition_key = DbPartitionKey {
        node_key: vec![1, 2, 3],
        partition_num: 0,
    };
    let sort_key = DbSortKey(vec![10]);

    // Write initial value
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        partition_key.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![1]))]
                        .into_iter()
                        .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    storage.commit(&updates);

    // Take snapshot
    let snapshot = storage.snapshot();

    // Modify storage
    let mut updates2 = DatabaseUpdates::default();
    updates2.node_updates.insert(
        partition_key.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(sort_key.clone(), DatabaseUpdate::Set(vec![2]))]
                        .into_iter()
                        .collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    storage.commit(&updates2);

    // Snapshot has old value
    assert_eq!(
        snapshot.get_raw_substate_by_db_key(&partition_key, &sort_key),
        Some(vec![1])
    );

    // Storage has new value
    assert_eq!(
        storage.get_raw_substate_by_db_key(&partition_key, &sort_key),
        Some(vec![2])
    );
}

#[test]
fn test_snapshot_structural_sharing_performance() {
    let storage = SimStorage::new();

    // Insert 10,000 items via substates-only (no JVT computation).
    // This test measures OrdMap snapshot performance, not tree commit speed.
    for i in 0..10_000u32 {
        let partition_key = DbPartitionKey {
            node_key: i.to_be_bytes().to_vec(),
            partition_num: 0,
        };
        let sort_key = DbSortKey(vec![0]);

        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            partition_key.node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(sort_key, DatabaseUpdate::Set(vec![i as u8]))]
                            .into_iter()
                            .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        storage.commit_substates_only(&updates);
    }

    // Snapshot should be nearly instant (O(1), not O(n))
    let start = std::time::Instant::now();
    let _snap1 = storage.snapshot();
    let _snap2 = storage.snapshot();
    let _snap3 = storage.snapshot();
    let _snap4 = storage.snapshot();
    let _snap5 = storage.snapshot();
    let elapsed = start.elapsed();

    // 5 snapshots of 10k items should be very fast
    // With BTreeMap clone this would take 10+ ms; with OrdMap it's < 1ms
    assert!(
        elapsed.as_millis() < 50,
        "5 snapshots took {:?}, expected < 50ms",
        elapsed
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Consensus operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_block_storage_and_retrieval() {
    let storage = SimStorage::new();
    let block = make_test_block(42);
    let qc = make_test_qc(&block);

    assert!(storage.get_block(BlockHeight(42)).is_none());

    storage.put_block(BlockHeight(42), &block, &qc);

    let (stored_block, stored_qc) = storage.get_block(BlockHeight(42)).unwrap();
    assert_eq!(stored_block.header.height, BlockHeight(42));
    assert_eq!(stored_block.header.timestamp, 42_000);
    assert_eq!(stored_qc.block_hash, block.hash());
}

#[test]
fn test_block_get_nonexistent() {
    let storage = SimStorage::new();
    assert!(storage.get_block(BlockHeight(999)).is_none());
}

#[test]
fn test_committed_state() {
    let storage = SimStorage::new();
    let hash = Hash::from_bytes(&[42; 32]);
    let qc = hyperscale_types::QuorumCertificate {
        block_hash: hash,
        shard_group_id: ShardGroupId(0),
        height: BlockHeight(10),
        parent_block_hash: Hash::ZERO,
        round: 3,
        aggregated_signature: zero_bls_signature(),
        signers: SignerBitfield::new(4),
        weighted_timestamp_ms: 10_000,
    };

    storage.set_committed_state(BlockHeight(10), hash, &qc);

    assert_eq!(storage.committed_height(), BlockHeight(10));
    assert_eq!(storage.committed_hash(), Some(hash));
    let stored_qc = storage.latest_qc().unwrap();
    assert_eq!(stored_qc.height, BlockHeight(10));
    assert_eq!(stored_qc.round, 3);
}

#[test]
fn test_committed_height_default() {
    let storage = SimStorage::new();
    assert_eq!(storage.committed_height(), BlockHeight(0));
    assert!(storage.committed_hash().is_none());
    assert!(storage.latest_qc().is_none());
}

#[test]
fn test_certificate_store_and_retrieve() {
    let storage = SimStorage::new();
    let cert = make_test_certificate(1, ShardGroupId(0));
    let tx_hash = cert.transaction_hash;

    storage.store_certificate(&cert);

    let stored = storage.get_certificate(&tx_hash).unwrap();
    assert_eq!(stored.transaction_hash, tx_hash);
}

#[test]
fn test_certificate_get_missing() {
    let storage = SimStorage::new();
    assert!(storage
        .get_certificate(&Hash::from_bytes(&[99; 32]))
        .is_none());
}

#[test]
fn test_vote_persistence() {
    let storage = SimStorage::new();
    let block_hash = Hash::from_bytes(&[1; 32]);

    storage.put_own_vote(100, 5, block_hash);

    let vote = storage.get_own_vote(100);
    assert_eq!(vote, Some((block_hash, 5)));
}

#[test]
fn test_vote_get_missing() {
    let storage = SimStorage::new();
    assert!(storage.get_own_vote(100).is_none());
}

#[test]
fn test_vote_overwrite() {
    let storage = SimStorage::new();
    let hash_a = Hash::from_bytes(&[1; 32]);
    let hash_b = Hash::from_bytes(&[2; 32]);

    storage.put_own_vote(100, 0, hash_a);
    assert_eq!(storage.get_own_vote(100), Some((hash_a, 0)));

    storage.put_own_vote(100, 1, hash_b);
    assert_eq!(storage.get_own_vote(100), Some((hash_b, 1)));

    let all = storage.get_all_own_votes();
    assert_eq!(all.len(), 1);
}

#[test]
fn test_vote_pruning() {
    let storage = SimStorage::new();
    let hash = Hash::from_bytes(&[1; 32]);

    storage.put_own_vote(10, 0, hash);
    storage.put_own_vote(20, 0, hash);
    storage.put_own_vote(30, 0, hash);

    storage.prune_own_votes(20);

    assert!(storage.get_own_vote(10).is_none());
    assert!(storage.get_own_vote(20).is_none());
    assert!(storage.get_own_vote(30).is_some());
}

#[test]
fn test_get_all_own_votes() {
    let storage = SimStorage::new();
    let hash = Hash::from_bytes(&[1; 32]);

    storage.put_own_vote(10, 0, hash);
    storage.put_own_vote(20, 1, hash);

    let all = storage.get_all_own_votes();
    assert_eq!(all.len(), 2);
    assert_eq!(all.get(&10), Some(&(hash, 0)));
    assert_eq!(all.get(&20), Some(&(hash, 1)));
}

#[test]
fn test_get_block_for_sync() {
    let storage = SimStorage::new();
    let block = make_test_block(5);
    let qc = make_test_qc(&block);
    storage.put_block(BlockHeight(5), &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight(5));
    assert!(result.is_some());
    assert_eq!(result.unwrap().0.header.height, BlockHeight(5));

    assert!(storage.get_block_for_sync(BlockHeight(999)).is_none());
}

#[test]
fn test_transactions_batch_missing() {
    let storage = SimStorage::new();
    let result = storage.get_transactions_batch(&[Hash::from_bytes(&[1; 32])]);
    assert!(result.is_empty());
}

#[test]
fn test_transactions_batch_with_indexed_block() {
    let storage = SimStorage::new();
    let mut block = make_test_block(1);

    let tx = Arc::new(hyperscale_types::test_utils::test_transaction(42));
    let tx_hash = tx.hash();
    block.transactions = vec![tx];

    let qc = make_test_qc(&block);
    storage.put_block(BlockHeight(1), &block, &qc);

    let result = storage.get_transactions_batch(&[tx_hash]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].hash(), tx_hash);

    // Missing hash still excluded
    let missing = Hash::from_bytes(&[99; 32]);
    let partial = storage.get_transactions_batch(&[tx_hash, missing]);
    assert_eq!(partial.len(), 1);
}

#[test]
fn test_certificates_batch() {
    let storage = SimStorage::new();
    let cert1 = make_test_certificate(1, ShardGroupId(0));
    let cert2 = make_test_certificate(2, ShardGroupId(0));
    let hash1 = cert1.transaction_hash;
    let hash2 = cert2.transaction_hash;

    storage.store_certificate(&cert1);
    storage.store_certificate(&cert2);

    let result = storage.get_certificates_batch(&[hash1, hash2]);
    assert_eq!(result.len(), 2);
}

#[test]
fn test_certificates_batch_partial() {
    let storage = SimStorage::new();
    let cert = make_test_certificate(1, ShardGroupId(0));
    let hash = cert.transaction_hash;
    storage.store_certificate(&cert);

    let missing = Hash::from_bytes(&[99; 32]);
    let result = storage.get_certificates_batch(&[hash, missing]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].transaction_hash, hash);
}

// ═══════════════════════════════════════════════════════════════════════
// JVT state tracking
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_initial_jvt_version_is_zero() {
    let storage = SimStorage::new();
    assert_eq!(storage.jvt_version(), 0);
}

#[test]
fn test_initial_state_root_is_zero() {
    let storage = SimStorage::new();
    assert_eq!(storage.state_root_hash(), Hash::ZERO);
}

#[test]
fn test_jvt_version_increments_on_commit() {
    let storage = SimStorage::new();
    assert_eq!(storage.jvt_version(), 0);

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert_eq!(storage.jvt_version(), 1);

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    assert_eq!(storage.jvt_version(), 2);
}

#[test]
fn test_state_root_changes_on_commit() {
    let storage = SimStorage::new();
    let root0 = storage.state_root_hash();

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    let root1 = storage.state_root_hash();
    assert_ne!(root0, root1, "root should change after first commit");

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    let root2 = storage.state_root_hash();
    assert_ne!(root1, root2, "root should change after second commit");
}

#[test]
fn test_state_root_deterministic() {
    // Two storage instances with identical commits should have identical roots
    let s1 = SimStorage::new();
    let s2 = SimStorage::new();

    let updates = make_database_update(vec![1, 2, 3], 0, vec![10], vec![42]);
    s1.commit_shared(&updates);
    s2.commit_shared(&updates);

    assert_eq!(s1.state_root_hash(), s2.state_root_hash());
    assert_eq!(s1.jvt_version(), s2.jvt_version());
}

#[test]
fn test_state_root_differs_for_different_data() {
    let s1 = SimStorage::new();
    let s2 = SimStorage::new();

    s1.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    s2.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![2]));

    assert_ne!(s1.state_root_hash(), s2.state_root_hash());
}

#[test]
fn test_empty_commit_still_advances_version() {
    let storage = SimStorage::new();
    let updates = DatabaseUpdates::default();
    storage.commit_shared(&updates);
    assert_eq!(storage.jvt_version(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// CommitStore
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_commit_block_single_cert() {
    let storage = SimStorage::new();
    let shard = ShardGroupId(0);
    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let cert = Arc::new(make_test_certificate(1, shard));

    let result = storage.commit_block(&updates, &[cert], 1, None);
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_multiple_certs() {
    let storage = SimStorage::new();
    let shard = ShardGroupId(0);
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
    let cert1 = Arc::new(make_test_certificate(1, shard));
    let cert2 = Arc::new(make_test_certificate(2, shard));

    let result = storage.commit_block(&merged, &[cert1, cert2], 1, None);
    // Certificate merging: all certs applied as single JVT version = block_height
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_empty_certs() {
    let storage = SimStorage::new();
    storage.commit_block(&DatabaseUpdates::default(), &[], 1, None);
    // Empty block: JVT version still advances to block_height
    assert_eq!(storage.jvt_version(), 1);
}

#[test]
fn test_prepare_then_commit_fast_path() {
    // Two identical storage instances: one uses prepare+commit, other uses commit_block.
    // Both should produce the same result.
    let s_prepared = SimStorage::new();
    let s_direct = SimStorage::new();
    let shard = ShardGroupId(0);
    let cert = Arc::new(make_test_certificate(1, shard));

    // Prepare path
    let parent_root = s_prepared.state_root_hash();
    let (spec_root, prepared) =
        s_prepared.prepare_block_commit(parent_root, &DatabaseUpdates::default(), 1);
    let certs = std::slice::from_ref(&cert);
    let result_prepared = s_prepared.commit_prepared_block(prepared, certs, None);

    // Direct path
    let result_direct = s_direct.commit_block(
        &DatabaseUpdates::default(),
        std::slice::from_ref(&cert),
        1,
        None,
    );

    assert_eq!(result_prepared, result_direct);
    assert_eq!(spec_root, result_prepared);
}

#[test]
fn test_prepare_commit_state_root_matches() {
    let storage = SimStorage::new();
    let shard = ShardGroupId(0);
    let cert = Arc::new(make_test_certificate(1, shard));

    let parent_root = storage.state_root_hash();
    let (spec_root, prepared) =
        storage.prepare_block_commit(parent_root, &DatabaseUpdates::default(), 1);
    let result = storage.commit_prepared_block(prepared, &[cert], None);

    assert_eq!(spec_root, result);
}

#[test]
fn test_commit_certificate_individual() {
    let storage = SimStorage::new();
    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let cert = make_test_certificate(1, ShardGroupId(0));

    storage.commit_certificate_with_writes(&cert, &updates);

    // Individual cert commits persist substate data + certificate metadata,
    // but JVT is deferred to block commit.
    assert_eq!(storage.jvt_version(), 0);
    assert_eq!(storage.state_root_hash(), Hash::ZERO);
    // Certificate should be stored
    assert!(storage.get_certificate(&cert.transaction_hash).is_some());
}

#[test]
fn test_commit_block_stores_certificates() {
    let storage = SimStorage::new();
    let shard = ShardGroupId(0);
    let cert = Arc::new(make_test_certificate(1, shard));
    let tx_hash = cert.transaction_hash;

    let _ = storage.commit_block(&DatabaseUpdates::default(), &[cert], 1, None);

    assert!(storage.get_certificate(&tx_hash).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// Utility methods
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_clear() {
    let mut storage = SimStorage::new();

    // Add some data
    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    let hash = Hash::from_bytes(&[1; 32]);
    storage.put_own_vote(10, 0, hash);
    assert!(storage.jvt_version() > 0);
    assert!(!storage.is_empty());

    storage.clear();

    assert_eq!(storage.jvt_version(), 0);
    assert_eq!(storage.state_root_hash(), Hash::ZERO);
    assert!(storage.is_empty());
    assert!(storage.get_own_vote(10).is_none());
}

#[test]
fn test_len_and_is_empty() {
    let storage = SimStorage::new();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert!(!storage.is_empty());
    assert_eq!(storage.len(), 1);

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    assert_eq!(storage.len(), 2);
}

#[test]
fn test_list_substates_for_node() {
    let storage = SimStorage::new();
    let node_id = NodeId([1; 30]);

    // Commit two substates for the same node
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
    let updates2 = make_mapped_database_update(1, 0, vec![20], vec![200]);
    let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
    let cert = make_test_certificate(1, ShardGroupId(0));
    storage.commit_certificate_with_writes(&cert, &merged);

    let substates: Vec<_> = storage.list_substates_for_node(&node_id).collect();
    assert_eq!(substates.len(), 2, "should find exactly 2 substates");

    // Verify actual values
    let values: Vec<&Vec<u8>> = substates.iter().map(|(_, _, v)| v).collect();
    assert!(values.contains(&&vec![100u8]), "should contain first value");
    assert!(
        values.contains(&&vec![200u8]),
        "should contain second value"
    );

    // Different node should have no substates
    let other_node = NodeId([99; 30]);
    let other_substates: Vec<_> = storage.list_substates_for_node(&other_node).collect();
    assert!(other_substates.is_empty());
}

#[test]
fn test_list_substates_for_node_at_height_returns_historical_data() {
    let storage = SimStorage::new();
    let node_id = NodeId([1; 30]);
    let shard = ShardGroupId(0);

    // Block height 1: commit value [100] for node 1
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
    let cert1 = Arc::new(make_test_certificate(1, shard));
    let result1 = storage.commit_block(&updates1, &[cert1], 1, None);
    let root_v1 = result1;

    // Block height 2: overwrite with value [200]
    let updates2 = make_mapped_database_update(1, 0, vec![10], vec![200]);
    let cert2 = Arc::new(make_test_certificate(2, shard));
    let result2 = storage.commit_block(&updates2, &[cert2], 2, None);
    let root_v2 = result2;
    assert_ne!(root_v1, root_v2, "roots must differ after overwrite");

    // Read at version 1: should get the original value [100]
    let v1_substates = storage
        .list_substates_for_node_at_height(&node_id, 1)
        .expect("version 1 should be available");
    assert_eq!(v1_substates.len(), 1, "should find 1 substate at v1");
    assert_eq!(v1_substates[0].2, vec![100u8], "v1 value should be [100]");

    // Read at version 2: should get the overwritten value [200]
    let v2_substates = storage
        .list_substates_for_node_at_height(&node_id, 2)
        .expect("version 2 should be available");
    assert_eq!(v2_substates.len(), 1, "should find 1 substate at v2");
    assert_eq!(v2_substates[0].2, vec![200u8], "v2 value should be [200]");

    // Read for a nonexistent node: should be Some(empty)
    let other = storage
        .list_substates_for_node_at_height(&NodeId([99; 30]), 1)
        .expect("version 1 should be available even for unknown node");
    assert!(other.is_empty());

    // Read at a future version: should be None
    assert!(
        storage
            .list_substates_for_node_at_height(&node_id, 99)
            .is_none(),
        "future version should return None"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Receipt storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_storage_roundtrip() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_receipt_storage_roundtrip(&storage);
}

#[test]
fn test_receipt_storage_synced() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_receipt_storage_synced(&storage);
}

#[test]
fn test_receipt_batch_storage() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_receipt_batch_storage(&storage);
}

#[test]
fn test_receipt_idempotent_overwrite() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_receipt_idempotent_overwrite(&storage);
}
