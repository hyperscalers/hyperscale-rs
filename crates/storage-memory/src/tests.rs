use crate::core::SimStorage;

use hyperscale_storage::test_helpers::{
    make_database_update, make_mapped_database_update, make_test_block, make_test_qc,
};
use hyperscale_storage::{
    ChainReader, ChainWriter, CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates,
    DbPartitionKey, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates, SubstateDatabase,
    SubstateStore,
};
use hyperscale_types::{BlockHeight, Hash, NodeId, StateRoot, TxHash};
use std::sync::Arc;

/// Helper: commit a block with given updates by injecting them via a single-tx
/// FinalizedWave inside `block.certificates`.
fn commit_with(
    storage: &SimStorage,
    updates: &DatabaseUpdates,
    block: &hyperscale_types::Block,
    qc: &hyperscale_types::QuorumCertificate,
) -> StateRoot {
    let block = block.clone();
    let block = if !updates.node_updates.is_empty() {
        let receipt = hyperscale_types::ReceiptBundle {
            tx_hash: TxHash::ZERO,
            local_receipt: Arc::new(hyperscale_types::LocalReceipt {
                outcome: hyperscale_types::TransactionOutcome::Success,
                database_updates: updates.clone(),
                application_events: vec![],
            }),
            execution_output: None,
        };
        let new_fw = Arc::new(hyperscale_types::FinalizedWave {
            certificate: Arc::new(hyperscale_types::WaveCertificate {
                wave_id: hyperscale_types::WaveId::new(
                    hyperscale_types::ShardGroupId(0),
                    block.height(),
                    std::collections::BTreeSet::new(),
                ),
                execution_certificates: vec![],
            }),
            receipts: vec![receipt],
        });
        match block {
            hyperscale_types::Block::Live {
                header,
                transactions,
                mut certificates,
                provisions,
            } => {
                certificates.push(new_fw);
                hyperscale_types::Block::Live {
                    header,
                    transactions,
                    certificates,
                    provisions,
                }
            }
            hyperscale_types::Block::Sealed {
                header,
                transactions,
                mut certificates,
            } => {
                certificates.push(new_fw);
                hyperscale_types::Block::Sealed {
                    header,
                    transactions,
                    certificates,
                }
            }
        }
    } else {
        block
    };
    storage.commit_block(&Arc::new(block), &Arc::new(qc.clone()))
}

/// Helper: commit a block with empty updates and no ECs/receipts.
fn commit_empty(
    storage: &SimStorage,
    block: &hyperscale_types::Block,
    qc: &hyperscale_types::QuorumCertificate,
) -> StateRoot {
    commit_with(storage, &DatabaseUpdates::default(), block, qc)
}

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

    // Insert 10,000 items via substates-only (no JMT computation).
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
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);

    assert!(storage.get_block(BlockHeight(1)).is_none());

    commit_empty(&storage, &block, &qc);

    let stored = storage.get_block(BlockHeight(1)).unwrap();
    assert_eq!(stored.block.height(), BlockHeight(1));
    assert_eq!(
        stored.block.header().timestamp,
        hyperscale_types::ProposerTimestamp(1_000)
    );
    assert_eq!(stored.qc.block_hash, block.hash());
}

#[test]
fn test_block_get_nonexistent() {
    let storage = SimStorage::new();
    assert!(storage.get_block(BlockHeight(999)).is_none());
}

#[test]
fn test_committed_height_default() {
    let storage = SimStorage::new();
    assert_eq!(storage.committed_height(), BlockHeight(0));
    assert!(storage.committed_hash().is_none());
    assert!(storage.latest_qc().is_none());
}

#[test]
fn test_get_block_for_sync() {
    let storage = SimStorage::new();
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight(1));
    assert!(result.is_some());
    assert_eq!(result.unwrap().block.height(), BlockHeight(1));

    assert!(storage.get_block_for_sync(BlockHeight(999)).is_none());
}

#[test]
fn test_transactions_batch_missing() {
    let storage = SimStorage::new();
    let result = storage.get_transactions_batch(&[TxHash::from_raw(Hash::from_bytes(&[1; 32]))]);
    assert!(result.is_empty());
}

#[test]
fn test_transactions_batch_with_indexed_block() {
    let storage = SimStorage::new();
    let block = make_test_block(BlockHeight(1));

    let tx = Arc::new(hyperscale_types::test_utils::test_transaction(42));
    let tx_hash = tx.hash();
    let block = match block {
        hyperscale_types::Block::Live {
            header,
            certificates,
            provisions,
            ..
        } => hyperscale_types::Block::Live {
            header,
            transactions: vec![tx],
            certificates,
            provisions,
        },
        hyperscale_types::Block::Sealed {
            header,
            certificates,
            ..
        } => hyperscale_types::Block::Sealed {
            header,
            transactions: vec![tx],
            certificates,
        },
    };

    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);

    let result = storage.get_transactions_batch(&[tx_hash]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].hash(), tx_hash);

    // Missing hash still excluded
    let missing = TxHash::from_raw(Hash::from_bytes(&[99; 32]));
    let partial = storage.get_transactions_batch(&[tx_hash, missing]);
    assert_eq!(partial.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// JMT state tracking
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_initial_jmt_height_is_zero() {
    let storage = SimStorage::new();
    assert_eq!(storage.jmt_height(), BlockHeight(0));
}

#[test]
fn test_initial_state_root_is_zero() {
    let storage = SimStorage::new();
    assert_eq!(storage.state_root_hash(), StateRoot::ZERO);
}

#[test]
fn test_jmt_height_increments_on_commit() {
    let storage = SimStorage::new();
    assert_eq!(storage.jmt_height(), BlockHeight(0));

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert_eq!(storage.jmt_height(), BlockHeight(1));

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    assert_eq!(storage.jmt_height(), BlockHeight(2));
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
    assert_eq!(s1.jmt_height(), s2.jmt_height());
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
    assert_eq!(storage.jmt_height(), BlockHeight(1));
}

// ═══════════════════════════════════════════════════════════════════════
// ChainWriter
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_commit_block_single() {
    let storage = SimStorage::new();
    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);

    let result = commit_with(&storage, &updates, &block, &qc);
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_multiple_updates() {
    let storage = SimStorage::new();
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = hyperscale_storage::merge_database_updates(&[updates1, updates2]);
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);

    let result = commit_with(&storage, &merged, &block, &qc);
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_empty() {
    let storage = SimStorage::new();
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);
    // Empty block: JMT version still advances to block_height
    assert_eq!(storage.jmt_height(), BlockHeight(1));
}

#[test]
fn test_prepare_then_commit_fast_path() {
    // Two identical storage instances: one uses prepare+commit, other uses commit_block.
    // Both should produce the same result.
    let s_prepared = SimStorage::new();
    let s_direct = SimStorage::new();
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);

    // Prepare path
    let parent_root = s_prepared.state_root_hash();
    let (spec_root, prepared) = s_prepared.prepare_block_commit(
        parent_root,
        BlockHeight::GENESIS,
        &[],
        BlockHeight(1),
        &[],
        None,
    );
    let result_prepared = s_prepared
        .commit_prepared_blocks(vec![(
            prepared,
            Arc::new(block.clone()),
            Arc::new(qc.clone()),
        )])
        .remove(0);

    // Direct path
    let result_direct = commit_empty(&s_direct, &block, &qc);

    assert_eq!(result_prepared, result_direct);
    assert_eq!(spec_root, result_prepared);
}

#[test]
fn test_prepare_commit_state_root_matches() {
    let storage = SimStorage::new();
    let block = make_test_block(BlockHeight(1));
    let qc = make_test_qc(&block);

    let parent_root = storage.state_root_hash();
    let (spec_root, prepared) = storage.prepare_block_commit(
        parent_root,
        BlockHeight::GENESIS,
        &[],
        BlockHeight(1),
        &[],
        None,
    );
    let result = storage
        .commit_prepared_blocks(vec![(prepared, Arc::new(block), Arc::new(qc))])
        .remove(0);

    assert_eq!(spec_root, result);
}

// ═══════════════════════════════════════════════════════════════════════
// Utility methods
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_clear() {
    let mut storage = SimStorage::new();

    // Add some data
    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert!(storage.jmt_height() > BlockHeight::GENESIS);
    assert!(!storage.is_empty());

    storage.clear();

    assert_eq!(storage.jmt_height(), BlockHeight(0));
    assert_eq!(storage.state_root_hash(), StateRoot::ZERO);
    assert!(storage.is_empty());
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
fn test_list_substates_for_node_at_height_returns_historical_data() {
    let storage = SimStorage::new();
    let node_id = NodeId([1; 30]);

    // Block height 1: commit value [100] for node 1
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
    let block1 = make_test_block(BlockHeight(1));
    let qc1 = make_test_qc(&block1);
    let root_v1 = commit_with(&storage, &updates1, &block1, &qc1);

    // Block height 2: overwrite with value [200]
    let updates2 = make_mapped_database_update(1, 0, vec![10], vec![200]);
    let block2 = make_test_block(BlockHeight(2));
    let qc2 = make_test_qc(&block2);
    let root_v2 = commit_with(&storage, &updates2, &block2, &qc2);
    assert_ne!(root_v1, root_v2, "roots must differ after overwrite");

    // Read at version 1: should get the original value [100]
    let v1_substates = storage
        .list_substates_for_node_at_height(&node_id, BlockHeight(1))
        .expect("version 1 should be available");
    assert_eq!(v1_substates.len(), 1, "should find 1 substate at v1");
    assert_eq!(v1_substates[0].2, vec![100u8], "v1 value should be [100]");

    // Read at version 2: should get the overwritten value [200]
    let v2_substates = storage
        .list_substates_for_node_at_height(&node_id, BlockHeight(2))
        .expect("version 2 should be available");
    assert_eq!(v2_substates.len(), 1, "should find 1 substate at v2");
    assert_eq!(v2_substates[0].2, vec![200u8], "v2 value should be [200]");

    // Read for a nonexistent node: should be Some(empty)
    let other = storage
        .list_substates_for_node_at_height(&NodeId([99; 30]), BlockHeight(1))
        .expect("version 1 should be available even for unknown node");
    assert!(other.is_empty());

    // Read at a future version: should be None
    assert!(
        storage
            .list_substates_for_node_at_height(&node_id, BlockHeight(99))
            .is_none(),
        "future version should return None"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Execution certificate storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_ec_storage_roundtrip() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_ec_storage_roundtrip(&storage);
}

#[test]
fn test_ec_storage_batch() {
    let storage = SimStorage::new();
    hyperscale_storage::test_helpers::test_ec_storage_batch(&storage);
}

// ═══════════════════════════════════════════════════════════════════════
// Persistence-lag determinism
// ═══════════════════════════════════════════════════════════════════════

/// Regression test: two validators with different `persisted_height`
/// but reading at the same historical version must observe identical substate
/// values. This is the scenario that caused the shard-0 state-root
/// divergence — base snapshots used to read "current StateCf" which
/// leaked post-anchor writes on the faster-persisting validator.
#[test]
fn test_snapshot_at_version_is_deterministic_across_persistence_lag() {
    use hyperscale_storage::VersionedStore;

    let nid = NodeId([1u8; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let commit = |storage: &SimStorage, height: BlockHeight, value: Vec<u8>| {
        let block = make_test_block(height);
        let qc = make_test_qc(&block);
        let updates = make_mapped_database_update(1, partition_num, sort_key.clone(), value);
        commit_with(storage, &updates, &block, &qc);
    };

    // Validator A: persists through block 5.
    let a = SimStorage::new();
    for h in 1..=5u64 {
        commit(&a, BlockHeight(h), vec![h as u8]);
    }
    assert_eq!(a.jmt_height(), BlockHeight(5));

    // Validator B: stops at block 3.
    let b = SimStorage::new();
    for h in 1..=3u64 {
        commit(&b, BlockHeight(h), vec![h as u8]);
    }
    assert_eq!(b.jmt_height(), BlockHeight(3));

    // Both read at version 3 via the state-history log. Must see block-3's
    // value on both, not A's current (block-5) value. Before the fix, A
    // would return 5.
    let snap_a = a.snapshot_at(BlockHeight(3));
    let snap_b = b.snapshot_at(BlockHeight(3));
    let pk = DbPartitionKey {
        node_key: hyperscale_storage::keys::node_entity_key(&nid),
        partition_num,
    };
    let sk = DbSortKey(sort_key.clone());

    assert_eq!(
        snap_a.get_raw_substate_by_db_key(&pk, &sk),
        Some(vec![3]),
        "validator A must see block-3 value at v3, not its current (block-5) value"
    );
    assert_eq!(
        snap_a.get_raw_substate_by_db_key(&pk, &sk),
        snap_b.get_raw_substate_by_db_key(&pk, &sk),
        "validators at different persisted heights must agree on version-3 state"
    );
}

/// Exercises the seek-for-prev read path: a key with many historical
/// versions resolves to the correct floor at any target version without
/// scanning all intermediate versions. Correctness check; the perf win
/// is visible as lower CPU on hot keys in production.
#[test]
fn test_snapshot_resolves_floor_among_many_versions() {
    use hyperscale_storage::VersionedStore;

    let node_seed = 5u8;
    let nid = NodeId([node_seed; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let storage = SimStorage::new();
    for h in 1..=50u64 {
        let block = make_test_block(BlockHeight(h));
        let qc = make_test_qc(&block);
        let updates =
            make_mapped_database_update(node_seed, partition_num, sort_key.clone(), vec![h as u8]);
        commit_with(&storage, &updates, &block, &qc);
    }

    let pk = DbPartitionKey {
        node_key: hyperscale_storage::keys::node_entity_key(&nid),
        partition_num,
    };
    let sk = DbSortKey(sort_key);

    // Read at every 10th version — each should return the exact write
    // from that height, not the latest or any adjacent version.
    for target in [1u64, 10, 20, 25, 49, 50] {
        let snap = storage.snapshot_at(BlockHeight(target));
        assert_eq!(
            snap.get_raw_substate_by_db_key(&pk, &sk),
            Some(vec![target as u8]),
            "snapshot_at({target}) should resolve to block-{target} value"
        );
    }
}

/// State-history walkthrough: key K created at V1 with value A, deleted
/// at V2, recreated at V3 with value B. Every historical version must
/// read back the correct value — that's the "smallest history entry
/// after V" invariant end-to-end.
///
/// Uses `commit_shared` (test-only helper) so we don't have to
/// construct full blocks/QCs around every write.
#[test]
fn test_state_history_create_delete_create() {
    use hyperscale_storage::VersionedStore;

    let nid = NodeId([7u8; 30]);
    let partition_num = 0;
    let sort_key = vec![42u8];
    let pk = DbPartitionKey {
        node_key: hyperscale_storage::keys::node_entity_key(&nid),
        partition_num,
    };
    let sk = DbSortKey(sort_key.clone());

    let storage = SimStorage::new();

    // Keep a second key alive throughout so the JMT never empties out
    // — the JMT parent-version chain would otherwise break at V2 if
    // deleting K left the tree empty. The state-history behavior we're
    // actually testing is entirely independent of this.
    let anchor = make_mapped_database_update(99, 0, vec![0xFF], vec![0xFF]);

    // V1: create with value A (=0xAA). Also set the anchor key.
    let mut v1 = make_mapped_database_update(7, partition_num, sort_key.clone(), vec![0xAA]);
    hyperscale_storage::merge_into(&mut v1, &anchor);
    storage.commit_shared(&v1);

    // V2: delete K.
    let mut v2 = DatabaseUpdates::default();
    v2.node_updates.insert(
        pk.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: [(
                partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: [(sk.clone(), DatabaseUpdate::Delete)].into_iter().collect(),
                },
            )]
            .into_iter()
            .collect(),
        },
    );
    storage.commit_shared(&v2);

    // V3: create again with value B (=0xBB).
    let v3 = make_mapped_database_update(7, partition_num, sort_key.clone(), vec![0xBB]);
    storage.commit_shared(&v3);

    // Expected:
    // V0: before any writes → None. History[K,1] = None wins (smallest
    //     v' > 0 for K). prior = None → None.
    // V1: snapshot_at(1) is "current" branch (1 == current_version only
    //     after V1 commit; but we're at V3 now, so V1 is historical).
    //     Smallest history > V1 is (K, 2) with prior=Some(A). → A.
    // V2: smallest history > V2 is (K, 3) with prior=None (K was
    //     deleted at V2, so pre-V3 was absent). → None.
    // V3: trivial branch (current). current_state[K] = B. → B.
    let expected: &[(u64, Option<Vec<u8>>)] = &[
        (0, None),
        (1, Some(vec![0xAA])),
        (2, None),
        (3, Some(vec![0xBB])),
    ];

    for (v, want) in expected {
        let snap = storage.snapshot_at(BlockHeight(*v));
        let got = snap.get_raw_substate_by_db_key(&pk, &sk);
        assert_eq!(
            &got, want,
            "state-history read at V={v}: want={want:?}, got={got:?}"
        );
    }
}

/// `snapshot_at(V)` must panic when V is below the retention floor.
/// This is the DA-assumption guard: internal code should never
/// anchor a view at a version beyond the retention window, and
/// hitting it means a bug elsewhere (not a graceful-degradation
/// case).
#[test]
#[should_panic(expected = "below retention floor")]
fn test_snapshot_at_below_retention_panics() {
    // Tiny retention: floor = current - 2.
    let storage = SimStorage::with_jmt_history_length(2);
    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight(h));
        let qc = make_test_qc(&block);
        commit_with(&storage, &DatabaseUpdates::default(), &block, &qc);
    }
    // current=10, floor=8. Asking for V=1 is well below floor.
    let _snap =
        <SimStorage as hyperscale_storage::VersionedStore>::snapshot_at(&storage, BlockHeight(1));
}

/// `list_substates_for_node_at_height` is an external-facing API —
/// it must return `None` for out-of-retention heights rather than
/// panicking (the panic path is reserved for `snapshot_at` callers).
#[test]
fn test_list_substates_at_height_respects_retention() {
    use hyperscale_storage::keys;

    let nid = NodeId([9u8; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let storage = SimStorage::with_jmt_history_length(2);
    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight(h));
        let qc = make_test_qc(&block);
        let updates =
            make_mapped_database_update(9, partition_num, sort_key.clone(), vec![h as u8]);
        commit_with(&storage, &updates, &block, &qc);
    }
    // current=10, floor=8.
    let _ = keys::node_entity_key(&nid); // use imported for consistency

    // Within retention: returns Some.
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight(9));
    assert!(got.is_some(), "height within retention must succeed");

    // Below retention: returns None (graceful).
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight(1));
    assert!(got.is_none(), "height below retention must return None");

    // Above current: returns None.
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight(99));
    assert!(got.is_none(), "future height returns None");
}

/// A Reset partition must capture a history entry for every key
/// removed so historical reads see the pre-reset contents.
#[test]
fn test_reset_partition_captures_history_for_all_removed_keys() {
    use hyperscale_storage::VersionedStore;

    let node_key = vec![3u8; 50];
    let partition_num = 0;
    let pk = DbPartitionKey {
        node_key: node_key.clone(),
        partition_num,
    };

    let storage = SimStorage::new();

    // V1: populate partition with A/B/C.
    {
        let block = make_test_block(BlockHeight(1));
        let qc = make_test_qc(&block);
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [
                            (DbSortKey(vec![0xA1]), DatabaseUpdate::Set(vec![0xAA])),
                            (DbSortKey(vec![0xB1]), DatabaseUpdate::Set(vec![0xBB])),
                            (DbSortKey(vec![0xC1]), DatabaseUpdate::Set(vec![0xCC])),
                        ]
                        .into_iter()
                        .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        commit_with(&storage, &updates, &block, &qc);
    }

    // V2: reset partition to only D/E.
    {
        let block = make_test_block(BlockHeight(2));
        let qc = make_test_qc(&block);
        let mut updates = DatabaseUpdates::default();
        let mut new_values = indexmap::IndexMap::new();
        new_values.insert(DbSortKey(vec![0xD1]), vec![0xDD]);
        new_values.insert(DbSortKey(vec![0xE1]), vec![0xEE]);
        updates.node_updates.insert(
            node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition_num,
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values: new_values,
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        commit_with(&storage, &updates, &block, &qc);
    }

    // At V1, the original contents A/B/C must still be visible.
    let snap_v1 = storage.snapshot_at(BlockHeight(1));
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xA1])),
        Some(vec![0xAA]),
    );
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xB1])),
        Some(vec![0xBB]),
    );
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xC1])),
        Some(vec![0xCC]),
    );
    // D/E must not be visible at V1 — they don't exist yet.
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xD1])),
        None,
    );

    // At V2, only D/E are visible.
    let snap_v2 = storage.snapshot_at(BlockHeight(2));
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xA1])),
        None,
    );
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xD1])),
        Some(vec![0xDD]),
    );
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xE1])),
        Some(vec![0xEE]),
    );
}

/// Genesis-style writes via `commit_substates_only` must NOT populate
/// the state-history log — there is no pre-state to preserve, and
/// polluting the log with `(K, 0) → None` entries would waste space
/// until GC.
#[test]
fn test_genesis_skips_history_entries() {
    use hyperscale_storage::SubstatesOnlyCommit;

    let storage = SimStorage::new();

    let updates = make_database_update(vec![1u8; 50], 0, vec![1], vec![0xAA]);
    <SimStorage as SubstatesOnlyCommit>::commit_substates_only(&storage, &updates);

    // History map must be empty after a genesis-style commit.
    assert_eq!(
        storage.state.read().unwrap().state_history.len(),
        0,
        "commit_substates_only must not record state-history entries"
    );
    // current_state must have the genesis write though.
    assert_eq!(
        storage.state.read().unwrap().current_state.len(),
        1,
        "commit_substates_only populates current_state"
    );
}
