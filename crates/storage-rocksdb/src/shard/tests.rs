use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_jmt::NibblePath;
use hyperscale_storage::test_helpers::{
    db_node_key, make_database_update, make_mapped_database_update, make_test_block,
    make_test_certified, make_test_execution_certificate, make_test_qc, make_test_receipt,
    make_test_wave_certificate, test_ec_storage_batch as helpers_test_ec_storage_batch,
    test_ec_storage_roundtrip as helpers_test_ec_storage_roundtrip,
    test_witness_payload_range_reads as helpers_test_witness_payload_range_reads,
};
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, SafeVoteRegisterStore, ShardChainReader, ShardChainWriter,
    SubstateDatabase, SubstateStore, VersionedStore, merge_database_updates, merge_into,
};
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight,
    Bls12381G2Signature, BoundedVec, CertifiedBlock, ChainOrigin, ConsensusReceipt,
    ExecutionCertificate, FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, Hash,
    ProposerTimestamp, QuorumCertificate, Round, SafeVoteRegisters, ShardId, SignerBitfield,
    StateRoot, StoredReceipt, SyncHint, TxHash, ValidatorId, Verifiable, Verified, VrfProof,
    WaveCertificate, WaveId, WeightedTimestamp,
};

fn no_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}

/// Build a placeholder EC whose `wave_id` matches the WC the caller is about
/// to construct, so the WC satisfies the local-EC invariant enforced at
/// SBOR decode time. The EC carries no signers / outcomes — these tests
/// exercise the storage codec, not consensus.
fn placeholder_local_ec(shard: ShardId, height: BlockHeight) -> Arc<ExecutionCertificate> {
    Arc::new(ExecutionCertificate::new(
        WaveId::new(shard, height, std::collections::BTreeSet::new()),
        WeightedTimestamp::from_millis(0),
        GlobalReceiptRoot::ZERO,
        Vec::new(),
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::empty(),
    ))
}
use hyperscale_storage::tree::hash_storage_key;
use rocksdb::WriteBatch;
use sbor::prelude::IndexMap;
use tempfile::TempDir;

use super::column_families::{LeafAssociationsCf, STATE_HISTORY_CF};
use super::core::RocksDbShardStorage;
use super::metadata::write_chain_origin;
use crate::config::RocksDbConfig;

/// Helper: wrap `DatabaseUpdates` into a single `StoredReceipt` for test commit calls.
fn updates_to_receipts(updates: &DatabaseUpdates) -> Vec<StoredReceipt> {
    if updates.node_updates.is_empty() {
        return vec![];
    }
    vec![StoredReceipt {
        tx_hash: TxHash::ZERO,
        consensus: Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            database_updates: updates.clone(),
            owned_nodes: BoundedVec::new(),
            application_events: vec![],
            beacon_witness_events: Vec::new(),
        }),
        metadata: None,
    }]
}

/// Helper: commit a block with empty updates and no ECs/receipts.
fn commit_empty(storage: &RocksDbShardStorage, block: &Block, qc: &Verified<QuorumCertificate>) {
    // SAFETY: synthetic test fixture; round-trip tests don't exercise
    // the `Verified<CertifiedBlock>` predicate.
    let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
        CertifiedBlock::new_unchecked(block.clone(), <Verified<_>>::clone(qc)),
    ));
    storage.commit_block(&certified, &no_witness());
}

/// Build a `DatabaseUpdates` containing a single `Delete` operation.
fn make_database_delete(node_key: Vec<u8>, partition: u8, sort_key: Vec<u8>) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    updates.node_updates.insert(
        node_key,
        NodeDatabaseUpdates {
            partition_updates: std::iter::once((
                partition,
                PartitionDatabaseUpdates::Delta {
                    substate_updates: std::iter::once((
                        DbSortKey(sort_key),
                        DatabaseUpdate::Delete,
                    ))
                    .collect(),
                },
            ))
            .collect(),
        },
    );
    updates
}

/// The leaf-association CF mirrors the live substate key set: a set
/// writes the hashed-key → raw-key mapping, a delete drops it.
#[test]
fn leaf_associations_track_live_substates() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let node_key = vec![3u8; 50];
    let updates = make_database_update(node_key.clone(), 0, vec![7], vec![1, 2, 3]);
    storage.commit(&updates).unwrap();

    let mut raw_key = node_key.clone();
    raw_key.push(0);
    raw_key.push(7);
    let hashed = Hash::from_hash_bytes(&hash_storage_key(&raw_key, &HashMap::new()));
    assert_eq!(
        storage.cf_get::<LeafAssociationsCf>(&hashed),
        Some(raw_key.clone()),
    );

    storage
        .commit(&make_database_delete(node_key, 0, vec![7]))
        .unwrap();
    assert_eq!(storage.cf_get::<LeafAssociationsCf>(&hashed), None);
}

/// The per-version substate byte total tracks inserts, value updates and
/// deletes; historical entries stay readable and survive a reopen.
#[test]
fn substate_bytes_tracks_commits_and_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let key_a = vec![3u8; 50];
    let key_b = vec![4u8; 50];

    // v1: two inserts.
    let v1 = merge_database_updates(&[
        make_database_update(key_a.clone(), 0, vec![7], vec![1]),
        make_database_update(key_b, 0, vec![8], vec![2]),
    ]);
    storage.commit(&v1).unwrap();
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(1)), Some(2));

    // v2: value update only — count unchanged.
    storage
        .commit(&make_database_update(key_a.clone(), 0, vec![7], vec![9]))
        .unwrap();
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(2)), Some(2));

    // v3: delete one — count drops; the historical entry is untouched.
    storage
        .commit(&make_database_delete(key_a, 0, vec![7]))
        .unwrap();
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(3)), Some(1));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(1)), Some(2));

    drop(storage);
    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(reopened.substate_bytes_at(BlockHeight::new(3)), Some(1));
    assert_eq!(reopened.substate_bytes_at(BlockHeight::new(2)), Some(2));
    assert_eq!(reopened.substate_bytes_at(BlockHeight::new(4)), None);
}

/// Recovery seeds the coordinator's count frontier with the substate
/// count behind the committed tip.
#[test]
fn recovered_state_carries_substate_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    for h in 1..=3u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        let updates =
            make_mapped_database_update(u8::try_from(h).unwrap_or(u8::MAX), 0, vec![1], vec![1]);
        rocks_commit_with(&storage, &updates, &block, &qc);
    }

    assert_eq!(storage.load_recovered_state().substate_bytes, 3);
}

#[test]
fn test_basic_substate_operations() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    // 50-byte spread-prefix node_key — snapshot iteration decodes composite
    // keys so raw short keys hit the entity-key length assertion.
    let partition_key = DbPartitionKey {
        node_key: vec![3u8; 50],
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
    storage.commit(&updates).unwrap();

    // Now we can read it
    let value = storage.get_raw_substate_by_db_key(&partition_key, &sort_key);
    assert_eq!(value, Some(vec![99, 88, 77]));
}

#[test]
fn test_snapshot() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    // Use a realistic 50-byte node_key (spread-prefix format). Snapshot
    // snapshots decode composite keys during iteration, so raw short keys
    // would hit the entity-key length assertion.
    let partition_key = DbPartitionKey {
        node_key: vec![7u8; 50],
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
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        storage.set_chain_metadata(BlockHeight::new(50), Some(expected_hash), None);
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.committed_height, BlockHeight::new(50));
        assert_eq!(
            recovered.committed_hash,
            Some(BlockHash::from_raw(expected_hash))
        );
    }
}

#[test]
fn test_commit_certificate_with_writes_persists_both() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10, 20], vec![99, 88, 77]);
    let cert = make_test_wave_certificate(BlockHeight::new(42), ShardId::ROOT);
    let wave_id = cert.wave_id().clone();

    storage.commit_certificate_with_writes(&cert, &updates);

    let stored_cert = storage.get_certificate(&wave_id);
    assert!(stored_cert.is_some());
    assert_eq!(stored_cert.unwrap().wave_id(), &wave_id);

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
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

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
fn test_block_range_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    for h in 1..=5u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        commit_empty(&storage, &block, &qc);
    }

    let blocks = storage.get_blocks_range(BlockHeight::new(2), BlockHeight::new(5));
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].block().height(), BlockHeight::new(2));
    assert_eq!(blocks[1].block().height(), BlockHeight::new(3));
    assert_eq!(blocks[2].block().height(), BlockHeight::new(4));
}

#[test]
fn test_recovery_with_qc() {
    use hyperscale_types::{SignerBitfield, zero_bls_signature};

    let temp_dir = TempDir::new().unwrap();
    let expected_raw = Hash::from_hash_bytes(&[99; 32]);
    let expected_hash = BlockHash::from_raw(expected_raw);

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let qc = QuorumCertificate::new(
            expected_hash,
            ShardId::ROOT,
            BlockHeight::new(100),
            BlockHash::from_raw(Hash::from_bytes(&[98; 32])),
            Round::new(5),
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(100_000),
        );
        storage.set_chain_metadata(BlockHeight::new(100), Some(expected_raw), Some(&qc));
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let recovered = storage.load_recovered_state();

        assert_eq!(recovered.committed_height, BlockHeight::new(100));
        assert_eq!(recovered.committed_hash, Some(expected_hash));
        assert!(recovered.latest_qc.is_some());

        let qc = recovered.latest_qc.unwrap();
        assert_eq!(qc.height(), BlockHeight::new(100));
        assert_eq!(qc.round(), Round::new(5));
        assert_eq!(qc.block_hash(), expected_hash);
    }
}

#[test]
fn test_recovery_seeds_committed_anchor_from_parent_qc() {
    let temp_dir = TempDir::new().unwrap();
    let height = BlockHeight::new(1);
    let block = make_test_block(height); // parent QC is the genesis QC (WT zero)
    let tip_qc = make_test_qc(&block); // tip's own QC: WT = block timestamp (1000)

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        commit_empty(&storage, &block, &tip_qc);
        storage.set_chain_metadata(
            height,
            Some(Hash::from_hash_bytes(&[42; 32])),
            Some(&*tip_qc),
        );
    }

    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let recovered = storage.load_recovered_state();

    // The anchor is the committed tip's *parent* QC weighted timestamp (the
    // genesis QC's zero here), read back from the tip's stored header — not the
    // tip's own QC timestamp (1000) that `latest_qc` carries. Seeding from the
    // tip's own WT would resolve the wrong committee for the first post-restart
    // child of a tip that is an epoch's first block.
    assert_eq!(
        recovered.committed_anchor_ts,
        Some(WeightedTimestamp::ZERO),
        "anchor must come from the tip's parent QC, not its own QC",
    );
    assert_eq!(
        recovered.latest_qc.map(|qc| qc.weighted_timestamp()),
        Some(WeightedTimestamp::from_millis(1000)),
        "sanity: the tip's own QC carries the distinct, non-zero timestamp",
    );
}

#[test]
fn test_certificate_idempotency() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10, 20], vec![99, 88, 77]);
    let cert = make_test_wave_certificate(BlockHeight::new(42), ShardId::ROOT);
    let wave_id = cert.wave_id().clone();

    storage.commit_certificate_with_writes(&cert, &updates);
    storage.commit_certificate_with_writes(&cert, &updates);

    let stored = storage.get_certificate(&wave_id);
    assert!(stored.is_some());
    assert_eq!(stored.unwrap().wave_id(), &wave_id);
}

#[test]
fn test_empty_state_on_fresh_database() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let recovered = storage.load_recovered_state();

    assert_eq!(recovered.committed_height, BlockHeight::new(0));
    assert!(recovered.committed_hash.is_none());
    assert!(recovered.latest_qc.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// JMT state tracking
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_block_height_increments_on_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    assert_eq!(storage.jmt_height(), BlockHeight::new(0));

    storage
        .commit(&make_database_update(db_node_key(1), 0, vec![10], vec![1]))
        .unwrap();
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));

    storage
        .commit(&make_database_update(db_node_key(4), 0, vec![20], vec![2]))
        .unwrap();
    assert_eq!(storage.jmt_height(), BlockHeight::new(2));
}

#[test]
fn test_state_root_changes_on_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let root0 = storage.state_root();

    storage
        .commit(&make_database_update(db_node_key(1), 0, vec![10], vec![1]))
        .unwrap();
    let root1 = storage.state_root();
    assert_ne!(root0, root1, "root should change after first commit");

    storage
        .commit(&make_database_update(db_node_key(4), 0, vec![20], vec![2]))
        .unwrap();
    let root2 = storage.state_root();
    assert_ne!(root1, root2, "root should change after second commit");
}

// ═══════════════════════════════════════════════════════════════════════
// ShardChainWriter
// ═══════════════════════════════════════════════════════════════════════

/// Append a `FinalizedWave` to a block in place. Because `Block` is an enum,
/// this replaces the whole value via `std::mem::replace`.
fn push_wave(block: &mut Block, fw: Arc<Verifiable<FinalizedWave>>) {
    let taken = std::mem::replace(
        block,
        Block::Sealed {
            header: block.header().clone(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provision_hashes: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        },
    );
    *block = match taken {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            ready_signals,
            equivocations,
            reshape_trigger,
            randomness_reveal,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Live {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provisions,
                ready_signals,
                equivocations,
                reshape_trigger,
                randomness_reveal,
            }
        }
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            ready_signals,
            equivocations,
            reshape_trigger,
            randomness_reveal,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provision_hashes,
                ready_signals,
                equivocations,
                reshape_trigger,
                randomness_reveal,
            }
        }
    };
}

/// Wrap receipts into a single `FinalizedWave` attached to `block.certificates`,
/// so the new `commit_block` (which derives receipts from `block.certificates`)
/// can apply them.
fn attach_receipts(block: &mut Block, receipts: Vec<StoredReceipt>) {
    let new_fw: Arc<Verifiable<FinalizedWave>> = Arc::new(
        FinalizedWave::new(
            Arc::new(WaveCertificate::new(
                WaveId::new(
                    ShardId::ROOT,
                    block.height(),
                    std::collections::BTreeSet::new(),
                ),
                vec![placeholder_local_ec(ShardId::ROOT, block.height())],
            )),
            receipts,
        )
        .into(),
    );
    // Take block out, mutate, and put back.
    let taken = std::mem::replace(
        block,
        Block::Sealed {
            header: block.header().clone(),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provision_hashes: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        },
    );
    *block = match taken {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            ready_signals,
            equivocations,
            reshape_trigger,
            randomness_reveal,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(new_fw);
            Block::Live {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provisions,
                ready_signals,
                equivocations,
                reshape_trigger,
                randomness_reveal,
            }
        }
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            ready_signals,
            equivocations,
            reshape_trigger,
            randomness_reveal,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(new_fw);
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provision_hashes,
                ready_signals,
                equivocations,
                reshape_trigger,
                randomness_reveal,
            }
        }
    };
}

#[test]
fn test_commit_block_applies_writes() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let mut block = make_test_block(BlockHeight::new(1));
    let receipts = updates_to_receipts(&updates);
    attach_receipts(&mut block, receipts);
    let result = storage.commit_block(&make_test_certified(block), &no_witness());
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_multiple_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates1 = make_mapped_database_update(1, 0, vec![10], vec![1]);
    let updates2 = make_mapped_database_update(2, 0, vec![20], vec![2]);
    let merged = merge_database_updates(&[updates1, updates2]);
    let mut block = make_test_block(BlockHeight::new(1));
    let receipts = updates_to_receipts(&merged);
    attach_receipts(&mut block, receipts);
    let result = storage.commit_block(&make_test_certified(block), &no_witness());
    assert_ne!(result, StateRoot::ZERO);
}

#[test]
fn test_commit_block_empty_certs() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let block = make_test_block(BlockHeight::new(1));
    storage.commit_block(&make_test_certified(block), &no_witness());
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));
}

#[test]
fn test_prepare_then_commit_matches_direct() {
    let temp_dir1 = TempDir::new().unwrap();
    let s_prepared =
        Arc::new(RocksDbShardStorage::open(temp_dir1.path(), NibblePath::empty()).unwrap());
    let parent_root = s_prepared.state_root();
    let (spec_root, _jmt_snapshot, prepared) = s_prepared.prepare_block_commit(
        parent_root,
        BlockHeight::GENESIS,
        &[],
        BlockHeight::new(1),
        &[],
        None,
    );
    let block = make_test_block(BlockHeight::new(1));
    let result_prepared = prepared(
        SyncHint::FlushNow,
        &make_test_certified(block),
        &no_witness(),
    );

    let temp_dir2 = TempDir::new().unwrap();
    let s_direct = RocksDbShardStorage::open(temp_dir2.path(), NibblePath::empty()).unwrap();
    let block2 = make_test_block(BlockHeight::new(1));
    let result_direct = s_direct.commit_block(&make_test_certified(block2), &no_witness());

    assert_eq!(result_prepared, result_direct);
    assert_eq!(spec_root, result_prepared);
}

#[test]
fn test_commit_block_stores_certificates() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let shard = ShardId::ROOT;
    let cert = Arc::new(make_test_wave_certificate(BlockHeight::new(1), shard));
    let wave_id = cert.wave_id().clone();

    // Create a block that includes this certificate
    let block = make_test_block(BlockHeight::new(1));
    let fw_certificates = Arc::new(vec![Arc::new(FinalizedWave::new(cert, vec![]).into())].into());
    let block = match block {
        Block::Live {
            header,
            transactions,
            provisions,
            ..
        } => Block::Live {
            header,
            transactions,
            certificates: fw_certificates,
            provisions,
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        },
        Block::Sealed {
            header,
            transactions,
            provision_hashes,
            ..
        } => Block::Sealed {
            header,
            transactions,
            certificates: fw_certificates,
            provision_hashes,
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        },
    };
    let _ = storage.commit_block(&make_test_certified(block), &no_witness());

    assert!(storage.get_certificate(&wave_id).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// Batch operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_transactions_batch_missing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let result = storage.get_transactions_batch(&[TxHash::from_raw(Hash::from_bytes(&[1; 32]))]);
    assert!(result.is_empty());
}

#[test]
fn test_certificates_batch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let cert1 = make_test_wave_certificate(BlockHeight::new(1), ShardId::ROOT);
    let cert2 = make_test_wave_certificate(BlockHeight::new(2), ShardId::ROOT);
    let id1 = cert1.wave_id().clone();
    let id2 = cert2.wave_id().clone();

    storage.put_certificate(&id1, &cert1);
    storage.put_certificate(&id2, &cert2);

    let result = storage.get_certificates_batch(&[id1.clone(), id2]);
    assert_eq!(result.len(), 2);

    let missing = WaveId::new(
        ShardId::leaf(8, 99),
        BlockHeight::new(99),
        std::collections::BTreeSet::new(),
    );
    let partial = storage.get_certificates_batch(&[id1.clone(), missing]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].wave_id(), &id1);
}

// ═══════════════════════════════════════════════════════════════════════
// Parity tests with SimShardStorage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_initial_block_height_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(storage.jmt_height(), BlockHeight::new(0));
}

#[test]
fn test_initial_state_root_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(storage.state_root(), StateRoot::ZERO);
}

#[test]
fn test_state_root_deterministic() {
    let updates = make_database_update(db_node_key(1), 0, vec![10], vec![42]);

    let td1 = TempDir::new().unwrap();
    let s1 = RocksDbShardStorage::open(td1.path(), NibblePath::empty()).unwrap();
    s1.commit(&updates).unwrap();

    let td2 = TempDir::new().unwrap();
    let s2 = RocksDbShardStorage::open(td2.path(), NibblePath::empty()).unwrap();
    s2.commit(&updates).unwrap();

    assert_eq!(s1.state_root(), s2.state_root());
    assert_eq!(s1.jmt_height(), s2.jmt_height());
}

#[test]
fn test_state_root_differs_for_different_data() {
    let td1 = TempDir::new().unwrap();
    let s1 = RocksDbShardStorage::open(td1.path(), NibblePath::empty()).unwrap();
    s1.commit(&make_database_update(db_node_key(1), 0, vec![10], vec![1]))
        .unwrap();

    let td2 = TempDir::new().unwrap();
    let s2 = RocksDbShardStorage::open(td2.path(), NibblePath::empty()).unwrap();
    s2.commit(&make_database_update(db_node_key(1), 0, vec![10], vec![2]))
        .unwrap();

    assert_ne!(s1.state_root(), s2.state_root());
}

#[test]
fn test_certificate_store_and_retrieve() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let cert = make_test_wave_certificate(BlockHeight::new(1), ShardId::ROOT);
    let wave_id = cert.wave_id().clone();

    storage.put_certificate(&wave_id, &cert);

    let stored = storage.get_certificate(&wave_id).unwrap();
    assert_eq!(stored.wave_id(), &wave_id);
}

#[test]
fn test_certificate_get_missing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let missing = WaveId::new(
        ShardId::leaf(8, 99),
        BlockHeight::new(99),
        std::collections::BTreeSet::new(),
    );
    assert!(storage.get_certificate(&missing).is_none());
}

#[test]
fn test_get_block_for_sync() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);
    commit_empty(&storage, &block, &qc);

    let result = storage.get_block_for_sync(BlockHeight::new(1));
    assert!(result.is_some());
    assert_eq!(result.unwrap().0.height(), BlockHeight::new(1));

    assert!(storage.get_block_for_sync(BlockHeight::new(999)).is_none());
}

#[test]
fn test_commit_certificate_via_commit_store() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
    let cert = make_test_wave_certificate(BlockHeight::new(1), ShardId::ROOT);

    storage.commit_certificate_with_writes(&cert, &updates);

    assert_eq!(storage.jmt_height(), BlockHeight::new(0));
    assert_eq!(storage.state_root(), StateRoot::ZERO);
    assert!(storage.get_certificate(cert.wave_id()).is_some());
}

#[test]
fn test_empty_commit_still_advances_version() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = DatabaseUpdates::default();
    storage.commit(&updates).unwrap();
    assert_eq!(storage.jmt_height(), BlockHeight::new(1));
}

// ═══════════════════════════════════════════════════════════════════════
// Persistence across reopen
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_substates_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();

    let root_after_write;
    let version_after_write;
    let cert_id;
    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let updates = make_mapped_database_update(1, 0, vec![10], vec![42]);
        let cert = make_test_wave_certificate(BlockHeight::new(1), ShardId::ROOT);
        cert_id = cert.wave_id().clone();
        storage.commit_certificate_with_writes(&cert, &updates);
        root_after_write = storage.state_root();
        version_after_write = storage.jmt_height();
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

        assert_eq!(storage.jmt_height(), version_after_write);
        assert_eq!(storage.state_root(), root_after_write);

        let cert = storage.get_certificate(&cert_id);
        assert!(cert.is_some(), "certificate should survive reopen");
        assert_eq!(cert.unwrap().wave_id(), &cert_id);

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
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let block = make_test_block(BlockHeight::new(1));
        let qc = make_test_qc(&block);
        commit_empty(&storage, &block, &qc);
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

        let stored = storage
            .get_block(BlockHeight::new(1))
            .expect("block should survive reopen");
        assert_eq!(stored.block().height(), BlockHeight::new(1));
        assert_eq!(stored.qc().height(), BlockHeight::new(1));
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Receipt storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_receipt_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let receipt = make_test_receipt(55);
    let tx_hash = receipt.tx_hash;

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        storage.store_receipt(&receipt);
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        assert!(storage.get_consensus_receipt(&tx_hash).is_some());
        let retrieved = storage.get_consensus_receipt(&tx_hash).unwrap();
        assert_eq!(retrieved, receipt.consensus);
        let local = storage.get_execution_metadata(&tx_hash).unwrap();
        assert_eq!(local, receipt.metadata.unwrap());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Execution certificate storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_ec_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    helpers_test_ec_storage_roundtrip(&storage);
}

#[test]
fn test_ec_storage_batch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    helpers_test_ec_storage_batch(&storage);
}

#[test]
fn witness_payload_range_reads() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    helpers_test_witness_payload_range_reads(&storage);
}

#[test]
fn test_ec_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let ec = make_test_execution_certificate(1, BlockHeight::new(1));
    let wave_id = ec.wave_id().clone();

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let block = make_test_block(BlockHeight::new(0));
        storage.commit_block(&make_test_certified(block), &no_witness());
        let mut block = make_test_block(BlockHeight::new(1));
        push_wave(
            &mut block,
            Arc::new(
                FinalizedWave::new(
                    Arc::new(WaveCertificate::new(wave_id.clone(), vec![Arc::new(ec)])),
                    vec![],
                )
                .into(),
            ),
        );
        storage.commit_block(&make_test_certified(block), &no_witness());
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let cert = storage
            .get_execution_certificate(&wave_id)
            .expect("EC must survive reopen");
        assert_eq!(cert.block_height(), BlockHeight::new(1));
    }
}

#[test]
fn test_ec_atomic_with_block_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let ec = make_test_execution_certificate(1, BlockHeight::new(1));
    let wave_id = ec.wave_id().clone();
    let mut block = make_test_block(BlockHeight::new(1));
    push_wave(
        &mut block,
        Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id.clone(), vec![Arc::new(ec)])),
                vec![],
            )
            .into(),
        ),
    );
    // Commit block with EC atomically
    storage.commit_block(&make_test_certified(block), &no_witness());

    let cert = storage
        .get_execution_certificate(&wave_id)
        .expect("EC must be retrievable after commit");
    assert_eq!(cert.block_height(), BlockHeight::new(1));
}

// ─── State-history semantics (parity with storage-memory tests) ─────────────
//
// These mirror `storage-memory/src/tests.rs`:
//   - test_state_history_create_delete_create
//   - test_snapshot_at_below_retention_panics
//   - test_list_substates_at_height_respects_retention
//   - test_reset_partition_captures_history_for_all_removed_keys
//   - test_genesis_skips_history_entries
//
// RocksDB encodes the history log differently (SBOR codec, prefix extractor,
// snapshot isolation, column family) so backend parity is not free.

/// Helper: port of `commit_with` from the memory tests. Injects the updates
/// as a single-tx `FinalizedWave` receipt inside a block and commits it.
fn rocks_commit_with(
    storage: &RocksDbShardStorage,
    updates: &DatabaseUpdates,
    block: &Block,
    qc: &Verified<QuorumCertificate>,
) {
    let mut block = block.clone();
    if !updates.node_updates.is_empty() {
        let receipt = StoredReceipt {
            tx_hash: TxHash::ZERO,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: updates.clone(),
                owned_nodes: BoundedVec::new(),
                application_events: vec![],
                beacon_witness_events: Vec::new(),
            }),
            metadata: None,
        };
        let wave = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(
                    WaveId::new(
                        ShardId::ROOT,
                        block.height(),
                        std::collections::BTreeSet::new(),
                    ),
                    vec![placeholder_local_ec(ShardId::ROOT, block.height())],
                )),
                vec![receipt],
            )
            .into(),
        );
        push_wave(&mut block, wave);
    }
    // SAFETY: synthetic test fixture; round-trip tests don't exercise
    // the `Verified<CertifiedBlock>` predicate.
    let certified = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
        CertifiedBlock::new_unchecked(block, <Verified<_>>::clone(qc)),
    ));
    storage.commit_block(&certified, &no_witness());
}

/// State-history walkthrough: key K created at V1 with value A, deleted
/// at V2, recreated at V3 with value B. Every historical version must
/// read back the correct value — that's the "smallest history entry
/// after V" invariant end-to-end.
#[test]
fn test_state_history_create_delete_create() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let node_key = vec![7u8; 50];
    let partition_num = 0u8;
    let sort_key = vec![42u8];
    let pk = DbPartitionKey {
        node_key: node_key.clone(),
        partition_num,
    };
    let sk = DbSortKey(sort_key.clone());

    // Keep an anchor key alive throughout so the JMT never empties out —
    // deleting K alone at V2 would otherwise break the parent-version
    // chain. The state-history behavior under test is independent of this.
    let anchor_node_key = vec![99u8; 50];
    let mk_delta = |nk: &[u8], p: u8, sk_bytes: Vec<u8>, val: DatabaseUpdate| {
        let mut u = DatabaseUpdates::default();
        u.node_updates.insert(
            nk.to_vec(),
            NodeDatabaseUpdates {
                partition_updates: std::iter::once((
                    p,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: std::iter::once((DbSortKey(sk_bytes), val)).collect(),
                    },
                ))
                .collect(),
            },
        );
        u
    };

    // V1: create K=A, plus anchor.
    let mut v1 = mk_delta(
        &node_key,
        partition_num,
        sort_key.clone(),
        DatabaseUpdate::Set(vec![0xAA]),
    );
    let anchor = mk_delta(
        &anchor_node_key,
        0,
        vec![0xFF],
        DatabaseUpdate::Set(vec![0xFF]),
    );
    merge_into(&mut v1, &anchor);
    storage.commit(&v1).unwrap();

    // V2: delete K.
    let v2 = mk_delta(
        &node_key,
        partition_num,
        sort_key.clone(),
        DatabaseUpdate::Delete,
    );
    storage.commit(&v2).unwrap();

    // V3: recreate K=B.
    let v3 = mk_delta(
        &node_key,
        partition_num,
        sort_key,
        DatabaseUpdate::Set(vec![0xBB]),
    );
    storage.commit(&v3).unwrap();

    // See memory test for derivation:
    let expected: &[(u64, Option<Vec<u8>>)] = &[
        (0, None),
        (1, Some(vec![0xAA])),
        (2, None),
        (3, Some(vec![0xBB])),
    ];
    for (v, want) in expected {
        let snap =
            <RocksDbShardStorage as VersionedStore>::snapshot_at(&storage, BlockHeight::new(*v));
        let got = snap.get_raw_substate_by_db_key(&pk, &sk);
        assert_eq!(
            &got, want,
            "state-history read at V={v}: want={want:?}, got={got:?}"
        );
    }
}

/// JMT GC prunes per-version substate byte totals below the retention
/// cutoff and retains everything at or above it.
#[test]
fn substate_bytes_pruned_by_jmt_gc() {
    let temp_dir = TempDir::new().unwrap();
    let config = RocksDbConfig {
        jmt_history_length: 2,
        ..Default::default()
    };
    let storage =
        RocksDbShardStorage::open_with_config(temp_dir.path(), &config, NibblePath::empty())
            .unwrap();

    for h in 1..=10u64 {
        let updates = make_database_update(
            vec![u8::try_from(h).unwrap_or(u8::MAX); 50],
            0,
            vec![1],
            vec![1],
        );
        storage.commit(&updates).unwrap();
    }
    storage.run_jmt_gc();

    // current=10, cutoff=8: below-cutoff entries pruned, the rest intact.
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(7)), None);
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(8)), Some(8));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(10)), Some(10));
}

/// `snapshot_at(V)` must panic when V is below the retention floor.
#[test]
#[should_panic(expected = "below retention floor")]
fn test_snapshot_at_below_retention_panics() {
    let temp_dir = TempDir::new().unwrap();
    let config = RocksDbConfig {
        jmt_history_length: 2,
        ..Default::default()
    };
    let storage =
        RocksDbShardStorage::open_with_config(temp_dir.path(), &config, NibblePath::empty())
            .unwrap();

    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        commit_empty(&storage, &block, &qc);
    }
    // current=10, floor=8. V=1 is well below floor.
    let _snap = <RocksDbShardStorage as VersionedStore>::snapshot_at(&storage, BlockHeight::new(1));
}

/// `list_substates_for_node_at_height` is an external-facing API — it
/// must return `None` for out-of-retention heights rather than panicking.
#[test]
fn test_list_substates_at_height_respects_retention() {
    use hyperscale_types::NodeId;

    let temp_dir = TempDir::new().unwrap();
    let config = RocksDbConfig {
        jmt_history_length: 2,
        ..Default::default()
    };
    let storage =
        RocksDbShardStorage::open_with_config(temp_dir.path(), &config, NibblePath::empty())
            .unwrap();

    let nid = NodeId([9u8; 30]);
    let partition_num = 0u8;
    let sort_key = vec![1u8];

    for h in 1..=10u64 {
        let block = make_test_block(BlockHeight::new(h));
        let qc = make_test_qc(&block);
        let updates = make_mapped_database_update(
            9,
            partition_num,
            sort_key.clone(),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
        rocks_commit_with(&storage, &updates, &block, &qc);
    }
    // current=10, floor=8.

    // Within retention: returns Some.
    assert!(
        storage
            .list_substates_for_node_at_height(&nid, BlockHeight::new(9))
            .is_some(),
        "height within retention must succeed"
    );
    // Below retention: returns None.
    assert!(
        storage
            .list_substates_for_node_at_height(&nid, BlockHeight::new(1))
            .is_none(),
        "height below retention must return None"
    );
    // Above current: returns None.
    assert!(
        storage
            .list_substates_for_node_at_height(&nid, BlockHeight::new(99))
            .is_none(),
        "future height returns None"
    );
}

/// A Reset partition must capture a history entry for every key removed
/// so historical reads see the pre-reset contents.
#[test]
fn test_reset_partition_captures_history_for_all_removed_keys() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let node_key = vec![3u8; 50];
    let partition_num = 0u8;
    let pk = DbPartitionKey {
        node_key: node_key.clone(),
        partition_num,
    };

    // V1: populate A/B/C.
    {
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
        storage.commit(&updates).unwrap();
    }

    // V2: reset to D/E only.
    {
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
        storage.commit(&updates).unwrap();
    }

    // V1: original A/B/C visible, D/E not yet.
    let snap_v1 =
        <RocksDbShardStorage as VersionedStore>::snapshot_at(&storage, BlockHeight::new(1));
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xA1])),
        Some(vec![0xAA])
    );
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xB1])),
        Some(vec![0xBB])
    );
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xC1])),
        Some(vec![0xCC])
    );
    assert_eq!(
        snap_v1.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xD1])),
        None
    );

    // V2: only D/E visible.
    let snap_v2 =
        <RocksDbShardStorage as VersionedStore>::snapshot_at(&storage, BlockHeight::new(2));
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xA1])),
        None
    );
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xD1])),
        Some(vec![0xDD])
    );
    assert_eq!(
        snap_v2.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![0xE1])),
        Some(vec![0xEE])
    );
}

/// Genesis-style writes via `commit_substates_only` must NOT populate the
/// state-history CF — there is no pre-state to preserve.
#[test]
fn test_genesis_skips_history_entries() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_database_update(vec![1u8; 50], 0, vec![1], vec![0xAA]);
    storage.commit_substates_only(&updates);

    // StateHistoryCf must be empty after a genesis-style commit.
    let history_count = {
        let cf = storage
            .db
            .cf_handle(STATE_HISTORY_CF)
            .expect("state_history CF exists");
        let mut iter = storage.db.raw_iterator_cf(cf);
        iter.seek_to_first();
        let mut n = 0usize;
        while iter.valid() {
            n += 1;
            iter.next();
        }
        n
    };
    assert_eq!(
        history_count, 0,
        "commit_substates_only must not record state-history entries"
    );

    // StateCf must hold the genesis write (readable via current-tip snapshot).
    let pk = DbPartitionKey {
        node_key: vec![1u8; 50],
        partition_num: 0,
    };
    let sk = DbSortKey(vec![1]);
    assert_eq!(
        storage.get_raw_substate_by_db_key(&pk, &sk),
        Some(vec![0xAA])
    );
}

/// Witness retention follows the commit-carried floor (a `WriteBatch`
/// range delete) with one window of hysteresis, and recovery rebuilds
/// the accumulator window from the tip header's base — entries below it
/// are serving stock only.
#[test]
fn witness_window_retention_and_recovery() {
    use hyperscale_storage::test_helpers::{commit_block_with_witness_window, stake_deposit};
    use hyperscale_types::ShardWitnessPayload;

    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let deposits: Vec<_> = (0u64..6).map(stake_deposit).collect();

    // Window [0, 4): all four leaves appended, nothing pruned.
    commit_block_with_witness_window(
        &storage,
        BlockHeight::new(1),
        0,
        &deposits[0..4],
        &deposits[0..4],
        None,
    );
    // Window [2, 6): the tail appends, persisted floor untouched.
    commit_block_with_witness_window(
        &storage,
        BlockHeight::new(2),
        2,
        &deposits[2..6],
        &deposits[4..6],
        None,
    );
    // Window [4, 6): the base advance carries the previous window's
    // base as the persisted floor — leaves below 2 drop, [2, 4) stays
    // as hysteresis stock.
    commit_block_with_witness_window(
        &storage,
        BlockHeight::new(3),
        4,
        &deposits[4..6],
        &[],
        Some(BeaconWitnessLeafCount::new(2)),
    );

    // A read spanning the dropped range comes back short; the retained
    // hysteresis range answers in full.
    assert_eq!(storage.get_beacon_witness_payload_range(0, 6).len(), 4);
    assert_eq!(
        storage.get_beacon_witness_payload_range(2, 6),
        deposits[2..6].to_vec(),
    );

    // Recovery starts the accumulator window at the tip's base.
    let recovered = storage.load_recovered_state();
    assert_eq!(
        recovered.beacon_witness_start,
        BeaconWitnessLeafCount::new(4)
    );
    let expected: Vec<_> = deposits[4..6]
        .iter()
        .map(ShardWitnessPayload::leaf_hash)
        .collect();
    assert_eq!(recovered.beacon_witness_leaf_hashes, expected);
}

// ─── Safe-vote registers ─────────────────────────────────────────────────────

fn registers(locked: u64, last_voted: u64) -> SafeVoteRegisters {
    SafeVoteRegisters {
        locked_round: Round::new(locked),
        last_voted_round: Round::new(last_voted),
    }
}

/// Persisted registers read back, survive a reopen, and land in
/// `load_recovered_state`.
#[test]
fn safe_vote_registers_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let v1 = ValidatorId::new(1);
    let v2 = ValidatorId::new(2);
    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        storage.persist_safe_vote_registers(v1, registers(3, 5));
        storage.persist_safe_vote_registers(v2, registers(2, 2));
        assert_eq!(storage.safe_vote_registers(v1), Some(registers(3, 5)));
    }

    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(reopened.safe_vote_registers(v1), Some(registers(3, 5)));
    let recovered = reopened.load_recovered_state();
    assert_eq!(
        recovered.safe_vote_registers.get(&v1),
        Some(&registers(3, 5))
    );
    assert_eq!(
        recovered.safe_vote_registers.get(&v2),
        Some(&registers(2, 2))
    );
}

/// Writes merge field-wise max, so a lower or mixed write can never
/// regress either register — including on a cold write-path cache after
/// a reopen, where the merge must consult the stored record.
#[test]
fn safe_vote_registers_writes_are_monotone() {
    let temp_dir = TempDir::new().unwrap();
    let v = ValidatorId::new(7);
    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        storage.persist_safe_vote_registers(v, registers(4, 6));
        storage.persist_safe_vote_registers(v, registers(2, 9));
        assert_eq!(storage.safe_vote_registers(v), Some(registers(4, 9)));
    }

    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    reopened.persist_safe_vote_registers(v, registers(3, 3));
    assert_eq!(reopened.safe_vote_registers(v), Some(registers(4, 9)));
}

/// A record written under a different chain origin is invisible to
/// reads and recovery — a checkpoint-seeded child store inherits the
/// parent's records but must not apply them to the child chain's
/// unrelated round numbering. The next write starts a fresh record
/// under the new origin.
#[test]
fn safe_vote_registers_ignore_stale_chain_incarnation() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let v = ValidatorId::new(1);
    storage.persist_safe_vote_registers(v, registers(8, 8));

    let mut batch = WriteBatch::default();
    write_chain_origin(
        &mut batch,
        ChainOrigin {
            genesis_height: BlockHeight::new(11),
            anchor_wt: WeightedTimestamp::from_millis(999),
        },
    );
    storage.db.write(batch).unwrap();

    assert_eq!(storage.safe_vote_registers(v), None);
    assert!(
        storage
            .load_recovered_state()
            .safe_vote_registers
            .is_empty()
    );

    storage.persist_safe_vote_registers(v, registers(1, 2));
    assert_eq!(storage.safe_vote_registers(v), Some(registers(1, 2)));
}
