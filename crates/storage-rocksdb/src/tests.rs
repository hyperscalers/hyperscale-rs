use crate::core::RocksDbStorage;

use hyperscale_storage::test_helpers::{
    make_database_update, make_mapped_database_update, make_test_block, make_test_qc,
    make_test_wave_certificate,
};
use hyperscale_storage::{
    CommitStore, ConsensusStore, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    NodeDatabaseUpdates, PartitionDatabaseUpdates, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{BlockHeight, Hash, QuorumCertificate, ShardGroupId};
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn test_basic_substate_operations() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

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
    storage.commit(&updates).unwrap();

    // Now we can read it
    let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
    assert_eq!(value, Some(vec![99, 88, 77]));
}

#[test]
fn test_snapshot() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

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
    storage.commit(&updates).unwrap();

    // Take snapshot
    let snapshot = storage.snapshot();

    // Snapshot can read data
    assert_eq!(
        snapshot.get_raw_substate_by_db_key(&partition_key, &sort_key),
        Some(vec![1])
    );
}

#[test]
fn test_vote_persistence_and_recovery() {
    let temp_dir = TempDir::new().unwrap();

    // Write votes in first session
    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        storage.put_own_vote(100, 0, Hash::from_bytes(&[1; 32]));
        storage.put_own_vote(101, 1, Hash::from_bytes(&[2; 32]));
        storage.put_own_vote(102, 0, Hash::from_bytes(&[3; 32]));
    }

    // Reopen and verify recovery
    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.voted_heights.len(), 3);
        assert_eq!(
            recovered.voted_heights.get(&100),
            Some(&(Hash::from_bytes(&[1; 32]), 0))
        );
        assert_eq!(
            recovered.voted_heights.get(&101),
            Some(&(Hash::from_bytes(&[2; 32]), 1))
        );
        assert_eq!(
            recovered.voted_heights.get(&102),
            Some(&(Hash::from_bytes(&[3; 32]), 0))
        );
    }
}

#[test]
fn test_vote_pruning() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    for h in 100..=105 {
        storage.put_own_vote(h, 0, Hash::from_bytes(&[h as u8; 32]));
    }

    let votes = storage.get_all_own_votes();
    assert_eq!(votes.len(), 6);

    storage.prune_own_votes(102);

    let votes = storage.get_all_own_votes();
    assert_eq!(votes.len(), 3);
    assert!(votes.contains_key(&103));
    assert!(votes.contains_key(&104));
    assert!(votes.contains_key(&105));
    assert!(!votes.contains_key(&100));
    assert!(!votes.contains_key(&101));
    assert!(!votes.contains_key(&102));
}

#[test]
fn test_vote_equivocation_prevention_after_recovery() {
    let temp_dir = TempDir::new().unwrap();

    let block_a = Hash::from_bytes(&[1; 32]);
    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        storage.put_own_vote(100, 0, block_a);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.voted_heights.get(&100), Some(&(block_a, 0)));

        let block_b = Hash::from_bytes(&[2; 32]);
        assert_ne!(recovered.voted_heights.get(&100), Some(&(block_b, 0)));
    }
}

#[test]
fn test_recovery_resumes_at_correct_height() {
    let temp_dir = TempDir::new().unwrap();

    let expected_hash = Hash::from_hash_bytes(&[50; 32]);

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        storage.set_chain_metadata(BlockHeight(50), Some(expected_hash), None);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.committed_height, 50);
        assert_eq!(recovered.committed_hash, Some(expected_hash));
    }
}

#[test]
fn test_commit_certificate_with_writes_persists_both() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10, 20], vec![99, 88, 77]);
    let cert = make_test_wave_certificate(42, ShardGroupId(0));
    let wave_hash = cert.wave_id.hash();

    storage.commit_certificate_with_writes(&cert, &updates);

    let stored_cert = storage.get_certificate(&wave_hash);
    assert!(stored_cert.is_some());
    assert_eq!(stored_cert.unwrap().wave_id.hash(), wave_hash);

    let node_id = hyperscale_types::NodeId([1; 30]);
    let substates: Vec<_> = storage.list_substates_for_node(&node_id).collect();
    assert_eq!(substates.len(), 1, "should find the committed substate");
    assert_eq!(
        substates[0].2,
        vec![99, 88, 77],
        "value should match what was written"
    );
}

#[test]
fn test_get_own_vote() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    assert!(storage.get_own_vote(100).is_none());

    let block_hash = Hash::from_bytes(&[1; 32]);
    storage.put_own_vote(100, 5, block_hash);

    let vote = storage.get_own_vote(100);
    assert_eq!(vote, Some((block_hash, 5)));

    assert!(storage.get_own_vote(101).is_none());
}

#[test]
fn test_block_storage_and_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

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
fn test_block_range_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    for h in 10..15u64 {
        let block = make_test_block(h);
        let qc = make_test_qc(&block);
        storage.put_block(BlockHeight(h), &block, &qc);
    }

    let blocks = storage.get_blocks_range(BlockHeight(11), BlockHeight(14));
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].0.header.height, BlockHeight(11));
    assert_eq!(blocks[1].0.header.height, BlockHeight(12));
    assert_eq!(blocks[2].0.header.height, BlockHeight(13));
}

#[test]
fn test_recovery_with_qc() {
    use hyperscale_types::{zero_bls_signature, SignerBitfield};

    let temp_dir = TempDir::new().unwrap();
    let expected_hash = Hash::from_hash_bytes(&[99; 32]);

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let qc = QuorumCertificate {
            block_hash: expected_hash,
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(100),
            parent_block_hash: Hash::from_bytes(&[98; 32]),
            round: 5,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
            weighted_timestamp_ms: 100_000,
        };
        storage.set_chain_metadata(BlockHeight(100), Some(expected_hash), Some(&qc));
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.committed_height, 100);
        assert_eq!(recovered.committed_hash, Some(expected_hash));
        assert!(recovered.latest_qc.is_some());

        let qc = recovered.latest_qc.unwrap();
        assert_eq!(qc.height, BlockHeight(100));
        assert_eq!(qc.round, 5);
        assert_eq!(qc.block_hash, expected_hash);
    }
}

#[test]
fn test_certificate_idempotency() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10, 20], vec![99, 88, 77]);
    let cert = make_test_wave_certificate(42, ShardGroupId(0));
    let wave_hash = cert.wave_id.hash();

    storage.commit_certificate_with_writes(&cert, &updates);
    storage.commit_certificate_with_writes(&cert, &updates);

    let stored = storage.get_certificate(&wave_hash);
    assert!(stored.is_some());
    assert_eq!(stored.unwrap().wave_id.hash(), wave_hash);
}

#[test]
fn test_vote_overwrite_same_height() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let block_a = Hash::from_bytes(&[1; 32]);
    let block_b = Hash::from_bytes(&[2; 32]);

    storage.put_own_vote(100, 0, block_a);
    assert_eq!(storage.get_own_vote(100), Some((block_a, 0)));

    storage.put_own_vote(100, 1, block_b);
    assert_eq!(storage.get_own_vote(100), Some((block_b, 1)));

    let all_votes = storage.get_all_own_votes();
    assert_eq!(all_votes.len(), 1);
    assert_eq!(all_votes.get(&100), Some(&(block_b, 1)));
}

#[test]
fn test_empty_state_on_fresh_database() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let recovered = storage.load_recovered_state();

    assert_eq!(recovered.committed_height, 0);
    assert!(recovered.committed_hash.is_none());
    assert!(recovered.latest_qc.is_none());
    assert!(recovered.voted_heights.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// JVT state tracking
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_block_height_increments_on_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    assert_eq!(storage.jvt_version(), 0);

    storage
        .commit(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]))
        .unwrap();
    assert_eq!(storage.jvt_version(), 1);

    storage
        .commit(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]))
        .unwrap();
    assert_eq!(storage.jvt_version(), 2);
}

#[test]
fn test_state_root_changes_on_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let root0 = storage.state_root_hash();

    storage
        .commit(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]))
        .unwrap();
    let root1 = storage.state_root_hash();
    assert_ne!(root0, root1, "root should change after first commit");

    storage
        .commit(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]))
        .unwrap();
    let root2 = storage.state_root_hash();
    assert_ne!(root1, root2, "root should change after second commit");
}

// ═══════════════════════════════════════════════════════════════════════
// CommitStore
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_commit_block_applies_writes() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let shard = ShardGroupId(0);
    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let cert = Arc::new(make_test_wave_certificate(1, shard));

    let result = storage.commit_block(&updates, &[cert], 1, None, &[]);
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_multiple_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let shard = ShardGroupId(0);
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
    let cert1 = Arc::new(make_test_wave_certificate(1, shard));
    let cert2 = Arc::new(make_test_wave_certificate(2, shard));

    let result = storage.commit_block(&merged, &[cert1, cert2], 1, None, &[]);
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_empty_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    storage.commit_block(&DatabaseUpdates::default(), &[], 1, None, &[]);
    assert_eq!(storage.jvt_version(), 1);
}

#[test]
fn test_prepare_then_commit_matches_direct() {
    let shard = ShardGroupId(0);
    let cert = Arc::new(make_test_wave_certificate(1, shard));

    let temp_dir1 = TempDir::new().unwrap();
    let s_prepared = RocksDbStorage::open(temp_dir1.path()).unwrap();
    let parent_root = s_prepared.state_root_hash();
    let (spec_root, prepared) =
        s_prepared.prepare_block_commit(parent_root, &DatabaseUpdates::default(), 1);
    let certs = std::slice::from_ref(&cert);
    let result_prepared = s_prepared.commit_prepared_block(prepared, certs, None, &[]);

    let temp_dir2 = TempDir::new().unwrap();
    let s_direct = RocksDbStorage::open(temp_dir2.path()).unwrap();
    let result_direct = s_direct.commit_block(
        &DatabaseUpdates::default(),
        std::slice::from_ref(&cert),
        1,
        None,
        &[],
    );

    assert_eq!(result_prepared, result_direct);
    assert_eq!(spec_root, result_prepared);
}

#[test]
fn test_commit_block_stores_certificates() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let shard = ShardGroupId(0);
    let cert = Arc::new(make_test_wave_certificate(1, shard));
    let wave_hash = cert.wave_id.hash();

    let _ = storage.commit_block(&DatabaseUpdates::default(), &[cert], 1, None, &[]);

    assert!(storage.get_certificate(&wave_hash).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// Batch operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_transactions_batch_missing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let result = storage.get_transactions_batch(&[Hash::from_bytes(&[1; 32])]);
    assert!(result.is_empty());
}

#[test]
fn test_certificates_batch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let cert1 = make_test_wave_certificate(1, ShardGroupId(0));
    let cert2 = make_test_wave_certificate(2, ShardGroupId(0));
    let hash1 = cert1.wave_id.hash();
    let hash2 = cert2.wave_id.hash();

    storage.store_certificate(&cert1);
    storage.store_certificate(&cert2);

    let result = storage.get_certificates_batch(&[hash1, hash2]);
    assert_eq!(result.len(), 2);

    let missing = Hash::from_bytes(&[99; 32]);
    let partial = storage.get_certificates_batch(&[hash1, missing]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].wave_id.hash(), hash1);
}

// ═══════════════════════════════════════════════════════════════════════
// Parity tests with SimStorage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_initial_block_height_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    assert_eq!(storage.jvt_version(), 0);
}

#[test]
fn test_initial_state_root_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    assert_eq!(storage.state_root_hash(), Hash::ZERO);
}

#[test]
fn test_state_root_deterministic() {
    let updates = make_database_update(vec![1, 2, 3], 0, vec![10], vec![42]);

    let td1 = TempDir::new().unwrap();
    let s1 = RocksDbStorage::open(td1.path()).unwrap();
    s1.commit(&updates).unwrap();

    let td2 = TempDir::new().unwrap();
    let s2 = RocksDbStorage::open(td2.path()).unwrap();
    s2.commit(&updates).unwrap();

    assert_eq!(s1.state_root_hash(), s2.state_root_hash());
    assert_eq!(s1.jvt_version(), s2.jvt_version());
}

#[test]
fn test_state_root_differs_for_different_data() {
    let td1 = TempDir::new().unwrap();
    let s1 = RocksDbStorage::open(td1.path()).unwrap();
    s1.commit(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]))
        .unwrap();

    let td2 = TempDir::new().unwrap();
    let s2 = RocksDbStorage::open(td2.path()).unwrap();
    s2.commit(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![2]))
        .unwrap();

    assert_ne!(s1.state_root_hash(), s2.state_root_hash());
}

#[test]
fn test_certificate_store_and_retrieve() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let cert = make_test_wave_certificate(1, ShardGroupId(0));
    let wave_hash = cert.wave_id.hash();

    storage.store_certificate(&cert);

    let stored = storage.get_certificate(&wave_hash).unwrap();
    assert_eq!(stored.wave_id.hash(), wave_hash);
}

#[test]
fn test_certificate_get_missing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    assert!(storage
        .get_certificate(&Hash::from_bytes(&[99; 32]))
        .is_none());
}

#[test]
fn test_get_block_for_sync() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let block = make_test_block(5);
    let qc = make_test_qc(&block);
    storage.put_block(BlockHeight(5), &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight(5));
    assert!(result.is_some());
    assert_eq!(result.unwrap().0.header.height, BlockHeight(5));

    assert!(storage.get_block_for_sync(BlockHeight(999)).is_none());
}

#[test]
fn test_commit_certificate_via_commit_store() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let cert = make_test_wave_certificate(1, ShardGroupId(0));

    storage.commit_certificate_with_writes(&cert, &updates);

    assert_eq!(storage.jvt_version(), 0);
    assert_eq!(storage.state_root_hash(), Hash::ZERO);
    assert!(storage.get_certificate(&cert.wave_id.hash()).is_some());
}

#[test]
fn test_empty_commit_still_advances_version() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates = hyperscale_storage::DatabaseUpdates::default();
    storage.commit(&updates).unwrap();
    assert_eq!(storage.jvt_version(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// Persistence across reopen
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_substates_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let node_id = hyperscale_types::NodeId([1; 30]);

    let root_after_write;
    let version_after_write;
    let cert_hash;
    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
        let cert = make_test_wave_certificate(1, ShardGroupId(0));
        cert_hash = cert.wave_id.hash();
        storage.commit_certificate_with_writes(&cert, &updates);
        root_after_write = storage.state_root_hash();
        version_after_write = storage.jvt_version();
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        assert_eq!(storage.jvt_version(), version_after_write);
        assert_eq!(storage.state_root_hash(), root_after_write);

        let cert = storage.get_certificate(&cert_hash);
        assert!(cert.is_some(), "certificate should survive reopen");
        assert_eq!(cert.unwrap().wave_id.hash(), cert_hash);

        let substates: Vec<_> = storage.list_substates_for_node(&node_id).collect();
        assert_eq!(substates.len(), 1, "substate should survive reopen");
        assert_eq!(substates[0].2, vec![42]);
    }
}

#[test]
fn test_blocks_and_votes_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let vote_hash = Hash::from_bytes(&[7; 32]);

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let block = make_test_block(10);
        let qc = make_test_qc(&block);
        storage.put_block(BlockHeight(10), &block, &qc);
        storage.put_own_vote(10, 3, vote_hash);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let (block, qc) = storage
            .get_block(BlockHeight(10))
            .expect("block should survive reopen");
        assert_eq!(block.header.height, BlockHeight(10));
        assert_eq!(qc.height, BlockHeight(10));

        let vote = storage.get_own_vote(10);
        assert_eq!(vote, Some((vote_hash, 3)), "vote should survive reopen");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Receipt storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_receipt_storage_roundtrip(&storage);
}

#[test]
fn test_receipt_storage_synced() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_receipt_storage_synced(&storage);
}

#[test]
fn test_receipt_batch_storage() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_receipt_batch_storage(&storage);
}

#[test]
fn test_receipt_idempotent_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_receipt_idempotent_overwrite(&storage);
}

#[test]
fn test_receipt_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let bundle = hyperscale_storage::test_helpers::make_test_receipt_bundle(55);
    let tx_hash = bundle.tx_hash;

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        storage.store_receipt_bundle(&bundle);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        assert!(storage.has_receipt(&tx_hash));
        let retrieved = storage.get_ledger_receipt(&tx_hash).unwrap();
        assert_eq!(*retrieved, *bundle.ledger_receipt);
        let local = storage.get_local_execution(&tx_hash).unwrap();
        assert_eq!(local, bundle.local_execution.unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Execution certificate storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_ec_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_ec_storage_roundtrip(&storage);
}

#[test]
fn test_ec_storage_batch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    hyperscale_storage::test_helpers::test_ec_storage_batch(&storage);
}

#[test]
fn test_ec_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let ec = hyperscale_storage::test_helpers::make_test_execution_certificate(1, 10);
    let canonical_hash = ec.canonical_hash();

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        storage.store_execution_certificates(std::slice::from_ref(&ec));
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let retrieved = storage.get_execution_certificate(&canonical_hash).unwrap();
        assert_eq!(retrieved.block_height(), 10);
        assert_eq!(retrieved.canonical_hash(), canonical_hash);

        let by_height = storage.get_execution_certificates_by_height(10);
        assert_eq!(by_height.len(), 1);
    }
}

#[test]
fn test_ec_atomic_with_block_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let ec = hyperscale_storage::test_helpers::make_test_execution_certificate(1, 1);
    let canonical_hash = ec.canonical_hash();
    let cert = Arc::new(make_test_wave_certificate(1, ShardGroupId(0)));

    // Commit block with EC atomically
    storage.commit_block(&DatabaseUpdates::default(), &[cert], 1, None, &[ec]);

    // EC should be retrievable
    let retrieved = storage.get_execution_certificate(&canonical_hash).unwrap();
    assert_eq!(retrieved.block_height(), 1);
}
