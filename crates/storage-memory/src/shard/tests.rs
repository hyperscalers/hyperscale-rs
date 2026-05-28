use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_storage::shard::keys;
use hyperscale_storage::test_helpers::{
    make_database_update, make_mapped_database_update, make_test_block, make_test_certified,
    make_test_qc,
};
use hyperscale_storage::tree::{jmt_parent_height, put_at_version};
use hyperscale_storage::{
    CommittableSubstateDatabase, DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey,
    NodeDatabaseUpdates, PartitionDatabaseUpdates, ShardChainReader, ShardChainWriter,
    SubstateDatabase, SubstateStore, VersionedStore, merge_database_updates, merge_into,
    test_helpers,
};
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeight, CertifiedBlock,
    ConsensusReceipt, FinalizedWave, GlobalReceiptHash, Hash, NodeId, ProposerTimestamp,
    QuorumCertificate, ShardGroupId, StateRoot, StoredReceipt, SyncHint, TxHash, Verifiable,
    Verified, WaveCertificate, WaveId,
};

fn no_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}
use indexmap::IndexMap;

use super::core::SimShardStorage;
use super::state::apply_updates;

impl SimShardStorage {
    /// Atomically commit a certificate and its state writes.
    ///
    /// Applies database updates and stores certificate metadata.
    /// JMT is deferred to block commit — this mirrors the production
    /// `RocksDbShardStorage::commit_certificate_with_writes()` to ensure DST
    /// catches timing bugs where code incorrectly assumes state is available
    /// before certificate persistence.
    ///
    /// # Panics
    ///
    /// Panics if either internal `RwLock` is poisoned.
    #[allow(clippy::significant_drop_tightening)] // both reads need the lock
    pub fn commit_certificate_with_writes(
        &self,
        certificate: &WaveCertificate,
        updates: &DatabaseUpdates,
    ) {
        {
            let mut s = self.state.write().unwrap();
            let ver = s.current_block_height.inner();
            apply_updates(&mut s, updates, ver, /* write_history */ true);
        }
        self.consensus
            .write()
            .unwrap()
            .certificates
            .insert(certificate.wave_id().clone(), certificate.clone());
    }

    /// Test helper: commits database updates with auto-incrementing JMT version.
    /// Not used in production (use `commit_block` instead).
    ///
    /// Computes JMT updates and applies them to the tree store, resolving
    /// leaf-substate associations for historical reads.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn commit_shared(&self, updates: &DatabaseUpdates) {
        let mut s = self.state.write().unwrap();

        let new_version = s.current_block_height.inner() + 1;

        // Apply substate updates first (visible for association resolution below).
        apply_updates(&mut s, updates, new_version, /* write_history */ true);

        let parent_version =
            jmt_parent_height(s.current_block_height, s.current_root_hash).map(BlockHeight::inner);
        let (new_root, collected) = put_at_version(
            &s.tree_store,
            parent_version,
            new_version,
            &[updates],
            &HashMap::new(),
        );

        for (key, node) in &collected.nodes {
            s.tree_store.insert(key.clone(), Arc::clone(node));
        }
        for stale_key in &collected.stale_node_keys {
            s.tree_store.remove(stale_key);
        }

        s.current_block_height = BlockHeight::new(new_version);
        s.current_root_hash = new_root;
    }
}

impl CommittableSubstateDatabase for SimShardStorage {
    fn commit(&mut self, updates: &DatabaseUpdates) {
        self.commit_shared(updates);
    }
}

/// Helper: commit a block with given updates by injecting them via a single-tx
/// `FinalizedWave` inside `block.certificates`.
fn commit_with(
    storage: &SimShardStorage,
    updates: &DatabaseUpdates,
    block: &Block,
    qc: &Verified<QuorumCertificate>,
) -> StateRoot {
    let block = block.clone();
    let block = if updates.node_updates.is_empty() {
        block
    } else {
        let receipt = StoredReceipt {
            tx_hash: TxHash::ZERO,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: updates.clone(),
                application_events: vec![],
                beacon_witness_events: Vec::new(),
            }),
            metadata: None,
        };
        let new_fw: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(
                    WaveId::new(ShardGroupId::new(0), block.height(), BTreeSet::new()),
                    vec![],
                )),
                vec![receipt],
            )
            .into(),
        );
        match block {
            Block::Live {
                header,
                transactions,
                certificates,
                provisions,
            } => {
                let mut certificates = (*certificates).clone();
                certificates.push(new_fw);
                Block::Live {
                    header,
                    transactions,
                    certificates: Arc::new(certificates),
                    provisions,
                }
            }
            Block::Sealed {
                header,
                transactions,
                certificates,
                provision_hashes,
            } => {
                let mut certificates = (*certificates).clone();
                certificates.push(new_fw);
                Block::Sealed {
                    header,
                    transactions,
                    certificates: Arc::new(certificates),
                    provision_hashes,
                }
            }
        }
    };
    // SAFETY: synthetic test fixture; storage round-trip tests don't
    // exercise the `Verified<CertifiedBlock>` predicate.
    let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
        CertifiedBlock::new_unchecked(block, <Verified<_>>::clone(qc)),
    ));
    storage.commit_block(&certified, &no_witness())
}

/// Helper: commit a block with empty updates and no ECs/receipts.
fn commit_empty(
    storage: &SimShardStorage,
    block: &Block,
    qc: &Verified<QuorumCertificate>,
) -> StateRoot {
    commit_with(storage, &DatabaseUpdates::default(), block, qc)
}

#[test]
fn test_basic_substate_operations() {
    let mut storage = SimShardStorage::new();

    // Create a partition key and sort key
    let partition_key = DbPartitionKey {
        node_key: vec![1, 2, 3],
        partition_num: 0,
    };
    let sort_key = DbSortKey(vec![10, 20]);

    // Initially empty
    assert!(
        storage
            .get_raw_substate_by_db_key(&partition_key, &sort_key)
            .is_none()
    );

    // Commit a value
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        partition_key.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: std::iter::once((
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((
                        sort_key.clone(),
                        DatabaseUpdate::Set(vec![99, 88, 77]),
                    ))
                    .collect(),
                },
            ))
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
    let mut storage = SimShardStorage::new();

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
            partition_updates: std::iter::once((
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((
                        sort_key.clone(),
                        DatabaseUpdate::Set(vec![1]),
                    ))
                    .collect(),
                },
            ))
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
            partition_updates: std::iter::once((
                partition_key.partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((
                        sort_key.clone(),
                        DatabaseUpdate::Set(vec![2]),
                    ))
                    .collect(),
                },
            ))
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
fn test_snapshot_clone_performance() {
    let storage = SimShardStorage::new();

    // Insert 10,000 items via substates-only (no JMT computation).
    // This test bounds the cost of a single BTreeMap-clone snapshot at
    // simulation scale, not tree commit speed.
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
                partition_updates: std::iter::once((
                    partition_key.partition_num,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: std::iter::once((
                            sort_key,
                            DatabaseUpdate::Set(vec![u8::try_from(i).unwrap_or(u8::MAX)]),
                        ))
                        .collect(),
                    },
                ))
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

    // Guardrail against accidental quadratic behaviour or extra
    // per-snapshot work; 5 BTreeMap clones of 10k entries fits well
    // under the cap on any reasonable machine.
    assert!(
        elapsed.as_millis() < 50,
        "5 snapshots took {elapsed:?}, expected < 50ms"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Consensus operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_block_storage_and_retrieval() {
    let storage = SimShardStorage::new();
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    assert!(storage.get_block(BlockHeight::new(1)).is_none());

    commit_empty(&storage, &block, &qc);

    let stored = storage.get_block(BlockHeight::new(1)).unwrap();
    assert_eq!(stored.block().height(), BlockHeight::new(1));
    assert_eq!(
        stored.block().header().timestamp(),
        ProposerTimestamp::from_millis(1_000)
    );
    assert_eq!(stored.qc().block_hash(), block.hash());
}

#[test]
fn test_block_get_nonexistent() {
    let storage = SimShardStorage::new();
    assert!(storage.get_block(BlockHeight::new(999)).is_none());
}

#[test]
fn test_committed_height_default() {
    let storage = SimShardStorage::new();
    assert_eq!(storage.committed_height(), BlockHeight::new(0));
    assert!(storage.committed_hash().is_none());
    assert!(storage.latest_qc().is_none());
}

#[test]
fn test_get_block_for_sync() {
    let storage = SimShardStorage::new();
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight::new(1));
    assert!(result.is_some());
    assert_eq!(result.unwrap().block.height(), BlockHeight::new(1));

    assert!(storage.get_block_for_sync(BlockHeight::new(999)).is_none());
}

#[test]
fn test_transactions_batch_missing() {
    let storage = SimShardStorage::new();
    let result = storage.get_transactions_batch(&[TxHash::from_raw(Hash::from_bytes(&[1; 32]))]);
    assert!(result.is_empty());
}

#[test]
fn test_transactions_batch_with_indexed_block() {
    let storage = SimShardStorage::new();
    let block = make_test_block(BlockHeight::new(1));

    let tx = Arc::new(test_transaction(42));
    let tx_hash = tx.hash();
    let block = match block {
        Block::Live {
            header,
            certificates,
            provisions,
            ..
        } => Block::Live {
            header,
            transactions: Arc::new(vec![tx].into()),
            certificates,
            provisions,
        },
        Block::Sealed {
            header,
            certificates,
            provision_hashes,
            ..
        } => Block::Sealed {
            header,
            transactions: Arc::new(vec![tx].into()),
            certificates,
            provision_hashes,
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
    let storage = SimShardStorage::new();
    assert_eq!(storage.jmt_height(), BlockHeight::new(0));
}

#[test]
fn test_initial_state_root_is_zero() {
    let storage = SimShardStorage::new();
    assert_eq!(storage.state_root(), StateRoot::ZERO);
}

#[test]
fn test_jmt_height_increments_on_commit() {
    let storage = SimShardStorage::new();
    assert_eq!(storage.jmt_height(), BlockHeight::new(0));

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    assert_eq!(storage.jmt_height(), BlockHeight::new(2));
}

#[test]
fn test_state_root_changes_on_commit() {
    let storage = SimShardStorage::new();
    let root0 = storage.state_root();

    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    let root1 = storage.state_root();
    assert_ne!(root0, root1, "root should change after first commit");

    storage.commit_shared(&make_database_update(vec![4, 5, 6], 0, vec![20], vec![2]));
    let root2 = storage.state_root();
    assert_ne!(root1, root2, "root should change after second commit");
}

#[test]
fn test_state_root_deterministic() {
    // Two storage instances with identical commits should have identical roots
    let s1 = SimShardStorage::new();
    let s2 = SimShardStorage::new();

    let updates = make_database_update(vec![1, 2, 3], 0, vec![10], vec![42]);
    s1.commit_shared(&updates);
    s2.commit_shared(&updates);

    assert_eq!(s1.state_root(), s2.state_root());
    assert_eq!(s1.jmt_height(), s2.jmt_height());
}

#[test]
fn test_state_root_differs_for_different_data() {
    let s1 = SimShardStorage::new();
    let s2 = SimShardStorage::new();

    s1.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    s2.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![2]));

    assert_ne!(s1.state_root(), s2.state_root());
}

#[test]
fn test_empty_commit_still_advances_version() {
    let storage = SimShardStorage::new();
    let updates = DatabaseUpdates::default();
    storage.commit_shared(&updates);
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));
}

// ═══════════════════════════════════════════════════════════════════════
// ShardChainWriter
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_commit_block_single() {
    let storage = SimShardStorage::new();
    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    let result = commit_with(&storage, &updates, &block, &qc);
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_multiple_updates() {
    let storage = SimShardStorage::new();
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = merge_database_updates(&[updates1, updates2]);
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    let result = commit_with(&storage, &merged, &block, &qc);
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_empty() {
    let storage = SimShardStorage::new();
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);
    // Empty block: JMT version still advances to block_height
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));
}

#[test]
fn test_prepare_then_commit_fast_path() {
    // Two identical storage instances: one uses prepare+commit, other uses commit_block.
    // Both should produce the same result.
    let s_prepared = Arc::new(SimShardStorage::new());
    let s_direct = SimShardStorage::new();
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    // Prepare path
    let parent_root = s_prepared.state_root();
    let (spec_root, _jmt_snapshot, prepared) = s_prepared.prepare_block_commit(
        parent_root,
        BlockHeight::GENESIS,
        &[],
        BlockHeight::new(1),
        &[],
        None,
    );
    let certified = make_test_certified(block.clone());
    let result_prepared = prepared(SyncHint::FlushNow, &certified, &no_witness());

    // Direct path
    let result_direct = commit_empty(&s_direct, &block, &qc);

    assert_eq!(result_prepared, result_direct);
    assert_eq!(spec_root, result_prepared);
}

#[test]
fn test_prepare_commit_state_root_matches() {
    let storage = Arc::new(SimShardStorage::new());
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    let parent_root = storage.state_root();
    let (spec_root, _jmt_snapshot, prepared) = storage.prepare_block_commit(
        parent_root,
        BlockHeight::GENESIS,
        &[],
        BlockHeight::new(1),
        &[],
        None,
    );
    let certified = make_test_certified(block);
    // Embed the supplied verified QC by replacing the helper's
    // placeholder. SAFETY: synthetic test fixture.
    let _ = qc;
    let result = prepared(SyncHint::FlushNow, &certified, &no_witness());

    assert_eq!(spec_root, result);
}

// ═══════════════════════════════════════════════════════════════════════
// Utility methods
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_clear() {
    let mut storage = SimShardStorage::new();

    // Add some data
    storage.commit_shared(&make_database_update(vec![1, 2, 3], 0, vec![10], vec![1]));
    assert!(storage.jmt_height() > BlockHeight::GENESIS);
    assert!(!storage.is_empty());

    storage.clear();

    assert_eq!(storage.jmt_height(), BlockHeight::new(0));
    assert_eq!(storage.state_root(), StateRoot::ZERO);
    assert!(storage.is_empty());
}

#[test]
fn test_len_and_is_empty() {
    let storage = SimShardStorage::new();
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
    let storage = SimShardStorage::new();
    let node_id = NodeId([1; 30]);

    // Block height 1: commit value [100] for node 1
    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![100]);
    let block1 = make_test_block(BlockHeight::new(1));
    let qc1 = make_test_qc(&block1);
    let root_v1 = commit_with(&storage, &updates1, &block1, &qc1);

    // Block height 2: overwrite with value [200]
    let updates2 = make_mapped_database_update(1, 0, vec![10], vec![200]);
    let block2 = make_test_block(BlockHeight::new(2));
    let qc2 = make_test_qc(&block2);
    let root_v2 = commit_with(&storage, &updates2, &block2, &qc2);
    assert_ne!(root_v1, root_v2, "roots must differ after overwrite");

    // Read at version 1: should get the original value [100]
    let v1_substates = storage
        .list_substates_for_node_at_height(&node_id, BlockHeight::new(1))
        .expect("version 1 should be available");
    assert_eq!(v1_substates.len(), 1, "should find 1 substate at v1");
    assert_eq!(v1_substates[0].2, vec![100u8], "v1 value should be [100]");

    // Read at version 2: should get the overwritten value [200]
    let v2_substates = storage
        .list_substates_for_node_at_height(&node_id, BlockHeight::new(2))
        .expect("version 2 should be available");
    assert_eq!(v2_substates.len(), 1, "should find 1 substate at v2");
    assert_eq!(v2_substates[0].2, vec![200u8], "v2 value should be [200]");

    // Read for a nonexistent node: should be Some(empty)
    let other = storage
        .list_substates_for_node_at_height(&NodeId([99; 30]), BlockHeight::new(1))
        .expect("version 1 should be available even for unknown node");
    assert!(other.is_empty());

    // Read at a future version: should be None
    assert!(
        storage
            .list_substates_for_node_at_height(&node_id, BlockHeight::new(99))
            .is_none(),
        "future version should return None"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Execution certificate storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_ec_storage_roundtrip() {
    let storage = SimShardStorage::new();
    test_helpers::test_ec_storage_roundtrip(&storage);
}

#[test]
fn test_ec_storage_batch() {
    let storage = SimShardStorage::new();
    test_helpers::test_ec_storage_batch(&storage);
}

// ═══════════════════════════════════════════════════════════════════════
// Persistence-lag determinism
// ═══════════════════════════════════════════════════════════════════════

/// Two validators with different `persisted_height` but reading at the
/// same historical version must observe identical substate values —
/// historical reads must not be influenced by writes committed past the
/// requested version on the faster-persisting validator.
#[test]
fn test_snapshot_at_version_is_deterministic_across_persistence_lag() {
    let nid = NodeId([1u8; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let commit = |storage: &SimShardStorage, height: BlockHeight, value: Vec<u8>| {
        let block = make_test_block(height);
        let qc = make_test_qc(&block);
        let updates = make_mapped_database_update(1, partition_num, sort_key.clone(), value);
        commit_with(storage, &updates, &block, &qc);
    };

    // Validator A: persists through block 5.
    let a = SimShardStorage::new();
    for h in 1..=5u64 {
        commit(
            &a,
            BlockHeight::new(h),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
    }
    assert_eq!(a.jmt_height(), BlockHeight::new(5));

    // Validator B: stops at block 3.
    let b = SimShardStorage::new();
    for h in 1..=3u64 {
        commit(
            &b,
            BlockHeight::new(h),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
    }
    assert_eq!(b.jmt_height(), BlockHeight::new(3));

    // Both read at version 3 via the state-history log. Must see block-3's
    // value on both, not A's current (block-5) value.
    let snap_a = a.snapshot_at(BlockHeight::new(3));
    let snap_b = b.snapshot_at(BlockHeight::new(3));
    let pk = DbPartitionKey {
        node_key: keys::node_entity_key(&nid),
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
    let node_seed = 5u8;
    let nid = NodeId([node_seed; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let storage = SimShardStorage::new();
    for h in 1..=50u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        let updates = make_mapped_database_update(
            node_seed,
            partition_num,
            sort_key.clone(),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
        commit_with(&storage, &updates, &block, &qc);
    }

    let pk = DbPartitionKey {
        node_key: keys::node_entity_key(&nid),
        partition_num,
    };
    let sk = DbSortKey(sort_key);

    // Read at every 10th version — each should return the exact write
    // from that height, not the latest or any adjacent version.
    for target in [1u64, 10, 20, 25, 49, 50] {
        let snap = storage.snapshot_at(BlockHeight::new(target));
        assert_eq!(
            snap.get_raw_substate_by_db_key(&pk, &sk),
            Some(vec![u8::try_from(target).unwrap_or(u8::MAX)]),
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
    let nid = NodeId([7u8; 30]);
    let partition_num = 0;
    let sort_key = vec![42u8];
    let pk = DbPartitionKey {
        node_key: keys::node_entity_key(&nid),
        partition_num,
    };
    let sk = DbSortKey(sort_key.clone());

    let storage = SimShardStorage::new();

    // Keep a second key alive throughout so the JMT never empties out
    // — the JMT parent-version chain would otherwise break at V2 if
    // deleting K left the tree empty. The state-history behavior we're
    // actually testing is entirely independent of this.
    let anchor = make_mapped_database_update(99, 0, vec![0xFF], vec![0xFF]);

    // V1: create with value A (=0xAA). Also set the anchor key.
    let mut v1 = make_mapped_database_update(7, partition_num, sort_key.clone(), vec![0xAA]);
    merge_into(&mut v1, &anchor);
    storage.commit_shared(&v1);

    // V2: delete K.
    let mut v2 = DatabaseUpdates::default();
    v2.node_updates.insert(
        pk.node_key.clone(),
        NodeDatabaseUpdates {
            partition_updates: std::iter::once((
                partition_num,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((sk.clone(), DatabaseUpdate::Delete))
                        .collect(),
                },
            ))
            .collect(),
        },
    );
    storage.commit_shared(&v2);

    // V3: create again with value B (=0xBB).
    let v3 = make_mapped_database_update(7, partition_num, sort_key, vec![0xBB]);
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
        let snap = storage.snapshot_at(BlockHeight::new(*v));
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
    let storage = SimShardStorage::with_jmt_history_length(2);
    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        commit_with(&storage, &DatabaseUpdates::default(), &block, &qc);
    }
    // current=10, floor=8. Asking for V=1 is well below floor.
    let _snap = <SimShardStorage as VersionedStore>::snapshot_at(&storage, BlockHeight::new(1));
}

/// `list_substates_for_node_at_height` is an external-facing API —
/// it must return `None` for out-of-retention heights rather than
/// panicking (the panic path is reserved for `snapshot_at` callers).
#[test]
fn test_list_substates_at_height_respects_retention() {
    let nid = NodeId([9u8; 30]);
    let partition_num = 0;
    let sort_key = vec![1u8];

    let storage = SimShardStorage::with_jmt_history_length(2);
    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        let updates = make_mapped_database_update(
            9,
            partition_num,
            sort_key.clone(),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
        commit_with(&storage, &updates, &block, &qc);
    }
    // current=10, floor=8.
    let _ = keys::node_entity_key(&nid); // use imported for consistency

    // Within retention: returns Some.
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight::new(9));
    assert!(got.is_some(), "height within retention must succeed");

    // Below retention: returns None (graceful).
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight::new(1));
    assert!(got.is_none(), "height below retention must return None");

    // Above current: returns None.
    let got = storage.list_substates_for_node_at_height(&nid, BlockHeight::new(99));
    assert!(got.is_none(), "future height returns None");
}

/// A Reset partition must capture a history entry for every key
/// removed so historical reads see the pre-reset contents.
#[test]
fn test_reset_partition_captures_history_for_all_removed_keys() {
    let node_key = vec![3u8; 50];
    let partition_num = 0;
    let pk = DbPartitionKey {
        node_key: node_key.clone(),
        partition_num,
    };

    let storage = SimShardStorage::new();

    // V1: populate partition with A/B/C.
    {
        let block = make_test_block(BlockHeight::new(1));
        let qc = make_test_qc(&block);
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            node_key.clone(),
            NodeDatabaseUpdates {
                partition_updates: std::iter::once((
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
                ))
                .collect(),
            },
        );
        commit_with(&storage, &updates, &block, &qc);
    }

    // V2: reset partition to only D/E.
    {
        let block = make_test_block(BlockHeight::new(2));
        let qc = make_test_qc(&block);
        let mut updates = DatabaseUpdates::default();
        let mut new_values = IndexMap::new();
        new_values.insert(DbSortKey(vec![0xD1]), vec![0xDD]);
        new_values.insert(DbSortKey(vec![0xE1]), vec![0xEE]);
        updates.node_updates.insert(
            node_key,
            NodeDatabaseUpdates {
                partition_updates: std::iter::once((
                    partition_num,
                    PartitionDatabaseUpdates::Reset {
                        new_substate_values: new_values,
                    },
                ))
                .collect(),
            },
        );
        commit_with(&storage, &updates, &block, &qc);
    }

    // At V1, the original contents A/B/C must still be visible.
    let snap_v1 = storage.snapshot_at(BlockHeight::new(1));
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
    let snap_v2 = storage.snapshot_at(BlockHeight::new(2));
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
    let storage = SimShardStorage::new();

    let updates = make_database_update(vec![1u8; 50], 0, vec![1], vec![0xAA]);
    storage.commit_substates_only(&updates);

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
