use crate::core::RocksDbStorage;

use hyperscale_storage::test_helpers::{
    make_database_update, make_mapped_database_update, make_test_block, make_test_qc,
    make_test_wave_certificate,
};
use hyperscale_storage::{
    ChainReader, ChainWriter, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    NodeDatabaseUpdates, PartitionDatabaseUpdates, SubstateDatabase, SubstateStore,
};
use hyperscale_types::{BlockHeight, Hash, QuorumCertificate, ReceiptBundle, ShardGroupId};
use std::sync::Arc;
use tempfile::TempDir;

/// Helper: wrap DatabaseUpdates into a single ReceiptBundle for test commit calls.
fn updates_to_receipts(updates: &DatabaseUpdates) -> Vec<ReceiptBundle> {
    if updates.node_updates.is_empty() {
        return vec![];
    }
    vec![ReceiptBundle {
        tx_hash: Hash::ZERO,
        local_receipt: Arc::new(hyperscale_types::LocalReceipt {
            outcome: hyperscale_types::TransactionOutcome::Success,
            database_updates: updates.clone(),
            application_events: vec![],
        }),
        execution_output: None,
    }]
}

/// Helper: commit a block with empty updates and no ECs/receipts.
fn commit_empty(storage: &RocksDbStorage, block: &hyperscale_types::Block, qc: &QuorumCertificate) {
    storage.commit_block(&Arc::new(block.clone()), &Arc::new(qc.clone()), &[]);
}

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

    // Verify the substate was written to the state CF via direct key lookup.
    // make_mapped_database_update uses SpreadPrefixKeyMapper, so extract the
    // mapped key from the updates struct.
    let (db_node_key, node_upd) = updates.node_updates.iter().next().unwrap();
    let (db_part_num, _) = node_upd.partition_updates.iter().next().unwrap();
    let partition_key = DbPartitionKey {
        node_key: db_node_key.clone(),
        partition_num: *db_part_num,
    };
    let sort_key = DbSortKey(vec![10, 20]);
    let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
    assert_eq!(
        value,
        Some(vec![99, 88, 77]),
        "value should match what was written"
    );
}

#[test]
fn test_block_storage_and_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let block = make_test_block(1);
    let qc = make_test_qc(&block);

    assert!(storage.get_block(BlockHeight(1)).is_none());

    commit_empty(&storage, &block, &qc);

    let (stored_block, stored_qc) = storage.get_block(BlockHeight(1)).unwrap();
    assert_eq!(stored_block.header.height, BlockHeight(1));
    assert_eq!(stored_block.header.timestamp, 1_000);
    assert_eq!(stored_qc.block_hash, block.hash());
}

#[test]
fn test_block_range_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    for h in 1..=5u64 {
        let block = make_test_block(h);
        let qc = make_test_qc(&block);
        commit_empty(&storage, &block, &qc);
    }

    let blocks = storage.get_blocks_range(BlockHeight(2), BlockHeight(5));
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].0.header.height, BlockHeight(2));
    assert_eq!(blocks[1].0.header.height, BlockHeight(3));
    assert_eq!(blocks[2].0.header.height, BlockHeight(4));
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
fn test_empty_state_on_fresh_database() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let recovered = storage.load_recovered_state();

    assert_eq!(recovered.committed_height, 0);
    assert!(recovered.committed_hash.is_none());
    assert!(recovered.latest_qc.is_none());
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
// ChainWriter
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_commit_block_applies_writes() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let block = make_test_block(1);
    let qc = make_test_qc(&block);

    let receipts = updates_to_receipts(&updates);
    let result = storage.commit_block(&Arc::new(block), &Arc::new(qc), &receipts);
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_multiple_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
    let block = make_test_block(1);
    let qc = make_test_qc(&block);

    let receipts = updates_to_receipts(&merged);
    let result = storage.commit_block(&Arc::new(block), &Arc::new(qc), &receipts);
    assert_ne!(result, Hash::ZERO);
}

#[test]
fn test_commit_block_empty_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let block = make_test_block(1);
    let qc = make_test_qc(&block);

    storage.commit_block(&Arc::new(block), &Arc::new(qc), &[]);
    assert_eq!(storage.jvt_version(), 1);
}

#[test]
fn test_prepare_then_commit_matches_direct() {
    let temp_dir1 = TempDir::new().unwrap();
    let s_prepared = RocksDbStorage::open(temp_dir1.path()).unwrap();
    let parent_root = s_prepared.state_root_hash();
    let (spec_root, prepared) = s_prepared.prepare_block_commit(parent_root, 0, &[], 1, &[]);
    let block = make_test_block(1);
    let qc = make_test_qc(&block);
    let result_prepared = s_prepared
        .commit_prepared_blocks(vec![(prepared, Arc::new(block), Arc::new(qc))])
        .remove(0);

    let temp_dir2 = TempDir::new().unwrap();
    let s_direct = RocksDbStorage::open(temp_dir2.path()).unwrap();
    let block2 = make_test_block(1);
    let qc2 = make_test_qc(&block2);
    let result_direct = s_direct.commit_block(&Arc::new(block2), &Arc::new(qc2), &[]);

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

    // Create a block that includes this certificate
    let mut block = make_test_block(1);
    block.certificates = vec![Arc::new(hyperscale_types::FinalizedWave {
        certificate: cert,
        receipts: vec![],
    })];
    let qc = make_test_qc(&block);

    let _ = storage.commit_block(&Arc::new(block), &Arc::new(qc), &[]);

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

    storage.put_certificate(&hash1, &cert1);
    storage.put_certificate(&hash2, &cert2);

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

    storage.put_certificate(&wave_hash, &cert);

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

    let block = make_test_block(1);
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight(1));
    assert!(result.is_some());
    assert_eq!(result.unwrap().0.header.height, BlockHeight(1));

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

        // Verify the substate was written via direct key lookup.
        // make_mapped_database_update uses SpreadPrefixKeyMapper, so use the
        // same helper to reconstruct the mapped key.
        let mapped_updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
        let (db_node_key, node_upd) = mapped_updates.node_updates.iter().next().unwrap();
        let (db_part_num, _) = node_upd.partition_updates.iter().next().unwrap();
        let partition_key = DbPartitionKey {
            node_key: db_node_key.clone(),
            partition_num: *db_part_num,
        };
        let sort_key = DbSortKey(vec![10]);
        let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
        assert_eq!(value, Some(vec![42]), "substate should survive reopen");
    }
}

#[test]
fn test_blocks_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let block = make_test_block(1);
        let qc = make_test_qc(&block);
        commit_empty(&storage, &block, &qc);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

        let (block, qc) = storage
            .get_block(BlockHeight(1))
            .expect("block should survive reopen");
        assert_eq!(block.header.height, BlockHeight(1));
        assert_eq!(qc.height, BlockHeight(1));
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Receipt storage
// ═══════════════════════════════════════════════════════════════════════

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
        assert!(storage.get_local_receipt(&tx_hash).is_some());
        let retrieved = storage.get_local_receipt(&tx_hash).unwrap();
        assert_eq!(*retrieved, *bundle.local_receipt);
        let local = storage.get_execution_output(&tx_hash).unwrap();
        assert_eq!(local, bundle.execution_output.unwrap());
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
    let ec = hyperscale_storage::test_helpers::make_test_execution_certificate(1, 1);

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let block = hyperscale_storage::test_helpers::make_test_block(0);
        let qc = hyperscale_storage::test_helpers::make_test_qc(&block);
        storage.commit_block(&Arc::new(block), &Arc::new(qc), &[]);
        let mut block = hyperscale_storage::test_helpers::make_test_block(1);
        block
            .certificates
            .push(Arc::new(hyperscale_types::FinalizedWave {
                certificate: Arc::new(hyperscale_types::WaveCertificate {
                    wave_id: hyperscale_types::WaveId::new(
                        ShardGroupId(0),
                        1,
                        std::collections::BTreeSet::new(),
                    ),
                    execution_certificates: vec![Arc::new(ec)],
                }),
                receipts: vec![],
            }));
        let qc = hyperscale_storage::test_helpers::make_test_qc(&block);
        storage.commit_block(&Arc::new(block), &Arc::new(qc), &[]);
    }

    {
        let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
        let by_height = storage.get_execution_certificates_by_height(1);
        assert_eq!(by_height.len(), 1);
        assert_eq!(by_height[0].block_height(), 1);
    }
}

#[test]
fn test_ec_atomic_with_block_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();

    let ec = hyperscale_storage::test_helpers::make_test_execution_certificate(1, 1);
    let mut block = make_test_block(1);
    block
        .certificates
        .push(Arc::new(hyperscale_types::FinalizedWave {
            certificate: Arc::new(hyperscale_types::WaveCertificate {
                wave_id: hyperscale_types::WaveId::new(
                    ShardGroupId(0),
                    1,
                    std::collections::BTreeSet::new(),
                ),
                execution_certificates: vec![Arc::new(ec)],
            }),
            receipts: vec![],
        }));
    let qc = make_test_qc(&block);

    // Commit block with EC atomically
    storage.commit_block(&Arc::new(block), &Arc::new(qc), &[]);

    // EC should be retrievable by height
    let by_height = storage.get_execution_certificates_by_height(1);
    assert_eq!(by_height.len(), 1);
    assert_eq!(by_height[0].block_height(), 1);
}
