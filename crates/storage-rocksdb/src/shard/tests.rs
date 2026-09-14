use std::cell::Cell;
use std::sync::Arc;

use hyperscale_jmt::NibblePath;
use hyperscale_storage::test_helpers::{
    PendingBaseline, commit_settled_at, commit_writes, commit_writes_at, entry_key,
    make_settled_writes, make_test_block, make_test_block_with_anchor_wt, make_test_certified,
    make_test_execution_certificate, make_test_finalization, make_test_qc, make_test_receipt,
    paced, placeholder_local_ec, position, registers, state_key, test_a_committed_block_reads_back,
    test_a_committed_cell_reads_back_and_a_snapshot_keeps_its_version,
    test_a_fresh_store_holds_nothing, test_a_leg_entry_holds_the_floor_to_its_horizon,
    test_a_legs_own_finalization_keeps_the_floor, test_a_package_cell_lands_in_the_artifact_index,
    test_commits_advance_the_version_and_writes_move_the_root,
    test_committed_bundle_outlives_sealing, test_committed_receipts_reach_state,
    test_ec_storage_batch as helpers_test_ec_storage_batch,
    test_ec_storage_roundtrip as helpers_test_ec_storage_roundtrip,
    test_entries_commit_serve_and_history, test_historical_reads_resolve_per_version,
    test_historical_reads_respect_retention, test_history_reads_through_create_delete_create,
    test_prepared_commit_for_a_committed_block_applies_nothing,
    test_prepared_commit_refuses_a_different_block_at_one_height,
    test_prepared_commit_writes_committed_cells, test_recovery_carries_the_tip_drain_total,
    test_registers_are_monotone_and_recoverable, test_registers_ignore_a_stale_chain_incarnation,
    test_registers_recover_their_justification, test_retained_bundle_drops_below_the_history_floor,
    test_snapshot_at_below_the_floor_panics, test_substate_bytes_track_commits,
    test_sweep_index_counts_a_pending_ancestors_move, test_sweep_index_tracks_the_leaves,
    test_sweep_stops_at_the_ceiling_or_the_cap, test_the_replay_floor_stops_at_the_chain_origin,
    test_the_root_is_a_function_of_the_writes,
    test_the_tx_index_answers_with_every_certificate_of_this_shards,
    test_tx_index_answers_with_the_local_shards_certificate,
    test_undischarged_record_holds_the_floor, test_unresolved_fold,
    test_widest_tick_copy_holds_the_slot,
    test_witness_payload_range_reads as helpers_test_witness_payload_range_reads,
    test_witness_window_retention_and_recovery, with_provisions,
};
use hyperscale_storage::{
    PackageArtifactStore, ParentAnchor, SafeVoteRegisterStore, ShardChainReader, ShardChainWriter,
    SubstateStore, Substates, VersionedStore,
};
use hyperscale_types::{
    AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash, BlockHeight,
    ConsensusReceipt, Finalization, FinalizationHash, GlobalReceiptHash, Hash, QuorumCertificate,
    Round, ShardId, StateWrites, StoredReceipt, SyncHint, TickHalf, TickId, TxHash, ValidatorId,
    Verifiable, WeightedTimestamp, WitnessSources,
};

fn no_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}

use rocksdb::WriteBatch;
use tempfile::TempDir;

use super::column_families::STATE_HISTORY_CF;
use super::core::RocksDbShardStorage;
use super::metadata::write_chain_origin;

/// Commit `block` with no writes and no witness.
fn commit_empty(storage: &RocksDbShardStorage, block: &Block) {
    commit_settled_at(
        storage,
        &make_test_certified(block.clone()),
        &[],
        &[],
        &no_witness(),
    );
}

/// A fresh store in a temporary directory; the directory rides with it.
fn open_fresh() -> (TempDir, RocksDbShardStorage) {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    (temp_dir, storage)
}

#[test]
fn a_fresh_store_holds_nothing() {
    let (_dir, storage) = open_fresh();
    test_a_fresh_store_holds_nothing(&storage);
}

#[test]
fn a_committed_cell_reads_back_and_a_snapshot_keeps_its_version() {
    let (_dir, storage) = open_fresh();
    test_a_committed_cell_reads_back_and_a_snapshot_keeps_its_version(&storage);
}

#[test]
fn commits_advance_the_version_and_writes_move_the_root() {
    let (_dir, storage) = open_fresh();
    test_commits_advance_the_version_and_writes_move_the_root(&storage);
}

#[test]
fn the_root_is_a_function_of_the_writes() {
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let next = Cell::new(0usize);
    test_the_root_is_a_function_of_the_writes(|| {
        let dir = &dirs[next.get()];
        next.set(next.get() + 1);
        RocksDbShardStorage::open(dir.path(), NibblePath::empty()).unwrap()
    });
}

#[test]
fn a_committed_block_reads_back() {
    let (_dir, storage) = open_fresh();
    test_a_committed_block_reads_back(&storage);
}

#[test]
fn committed_receipts_reach_state() {
    let (_dir, storage) = open_fresh();
    test_committed_receipts_reach_state(&storage);
}

#[test]
fn history_reads_through_create_delete_create() {
    let (_dir, storage) = open_fresh();
    test_history_reads_through_create_delete_create(&storage);
}

#[test]
fn historical_reads_resolve_per_version() {
    let (_dir, storage) = open_fresh();
    test_historical_reads_resolve_per_version(&storage);
}

#[test]
#[should_panic(expected = "below retention floor")]
fn snapshot_at_below_the_floor_panics() {
    let (_dir, storage) = open_fresh();
    test_snapshot_at_below_the_floor_panics(&storage);
}

#[test]
fn historical_reads_respect_retention() {
    let (_dir, storage) = open_fresh();
    test_historical_reads_respect_retention(&storage);
}

#[test]
fn witness_window_retention_and_recovery() {
    let (_dir, storage) = open_fresh();
    test_witness_window_retention_and_recovery(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn a_blocks_sweep_stops_at_the_ceiling_or_the_cap() {
    let (_dir, storage) = open_fresh();
    test_sweep_stops_at_the_ceiling_or_the_cap(&storage);
}

#[test]
fn the_sweep_index_tracks_the_leaves() {
    let (_dir, storage) = open_fresh();
    test_sweep_index_tracks_the_leaves(&storage);
}

#[test]
fn the_sweep_index_counts_a_pending_ancestors_move() {
    let (_dir, storage) = open_fresh();
    test_sweep_index_counts_a_pending_ancestors_move(&storage);
}

/// The shared entry pipeline, then the `RocksDB` tail: carry the tip
/// past the horizon and GC — the superseded history rows go, the
/// current index and a scan at the floor survive.
#[test]
fn entries_commit_serve_ranges_and_gc_history() {
    let (_dir, storage) = open_fresh();
    test_entries_commit_serve_and_history(&storage);

    let key = entry_key(7, 5);
    for seed in 3..=6u8 {
        commit_writes_at(
            &storage,
            &make_settled_writes(9, seed, vec![seed]),
            paced(u64::from(seed), 2),
        );
    }
    assert!(storage.run_state_history_gc() > 0);
    assert_eq!(
        storage.entries_in_range(key.owner, key.collection, 0, u128::MAX, 10),
        vec![(5, vec![5]), (10, vec![99]), (30, vec![30])],
    );
    assert_eq!(
        storage.snapshot_at(BlockHeight::new(6)).entries_in_range(
            key.owner,
            key.collection,
            0,
            u128::MAX,
            10
        ),
        vec![(5, vec![5]), (10, vec![99]), (30, vec![30])],
    );
}

/// The shared byte-total test, then a reopen: every version's total
/// survives it.
#[test]
fn substate_bytes_tracks_commits_and_survives_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_substate_bytes_track_commits(&storage);
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

    for h in 1..=3u8 {
        commit_writes(&storage, &make_settled_writes(h, 1, vec![1]));
    }

    assert_eq!(
        storage.load_recovered_state(ShardId::ROOT).substate_bytes,
        3
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
        let recovered = storage.load_recovered_state(ShardId::ROOT);

        assert_eq!(recovered.committed_height, BlockHeight::new(50));
        assert_eq!(
            recovered.committed_hash,
            Some(BlockHash::from_raw(expected_hash))
        );
    }
}

#[test]
fn test_block_range_retrieval() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    for h in 1..=5u64 {
        let block = make_test_block(BlockHeight::new(h));
        commit_empty(&storage, &block);
    }

    let blocks = storage.get_blocks_range(BlockHeight::new(2), BlockHeight::new(5));
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].block().height(), BlockHeight::new(2));
    assert_eq!(blocks[1].block().height(), BlockHeight::new(3));
    assert_eq!(blocks[2].block().height(), BlockHeight::new(4));
}

#[test]
fn test_recovery_with_qc() {
    use hyperscale_types::SignerBitfield;

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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(100_000),
        );
        storage.set_chain_metadata(BlockHeight::new(100), Some(expected_raw), Some(&qc));
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let recovered = storage.load_recovered_state(ShardId::ROOT);

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
        commit_empty(&storage, &block);
        storage.set_chain_metadata(
            height,
            Some(Hash::from_hash_bytes(&[42; 32])),
            Some(&*tip_qc),
        );
    }

    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let recovered = storage.load_recovered_state(ShardId::ROOT);

    // The anchor is the committed tip's *parent* QC weighted timestamp (the
    // genesis QC's zero here), read back from the tip's stored header — not the
    // tip's own QC timestamp (1000) that `latest_qc` carries. Seeding from the
    // tip's own WT would resolve the wrong committee for the first post-restart
    // child of a tip that is an epoch's first block.
    assert_eq!(
        recovered.committed_block_anchor_wt,
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
fn test_recovery_seeds_committee_anchor_from_the_header_below_the_tip() {
    let temp_dir = TempDir::new().unwrap();
    // Two committed heights whose anchors sit in different windows: the tip's
    // own at 200, the one its parent carried at 100.
    let parent = make_test_block_with_anchor_wt(BlockHeight::new(1), 100);
    let tip = make_test_block_with_anchor_wt(BlockHeight::new(2), 200);
    let tip_qc = make_test_qc(&tip);

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        commit_empty(&storage, &parent);
        commit_empty(&storage, &tip);
        storage.set_chain_metadata(
            BlockHeight::new(2),
            Some(*tip.hash().as_raw()),
            Some(&*tip_qc),
        );
    }

    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let recovered = storage.load_recovered_state(ShardId::ROOT);

    // A block's committee keys on its parent, so the committee that signed the
    // tip anchors one height below it. Recovering only the tip's own anchor
    // would resolve the tip against the window it opens.
    assert_eq!(
        recovered.committed_block_anchor_wt,
        Some(WeightedTimestamp::from_millis(200)),
    );
    assert_eq!(
        recovered.committed_committee_anchor_wt,
        Some(WeightedTimestamp::from_millis(100)),
        "the tip's committee anchor comes from the header below it",
    );
}

#[test]
fn test_empty_state_on_fresh_database() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let recovered = storage.load_recovered_state(ShardId::ROOT);

    assert_eq!(recovered.committed_height, BlockHeight::new(0));
    assert!(recovered.committed_hash.is_none());
    assert!(recovered.latest_qc.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// JMT state tracking
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// ShardChainWriter
// ═══════════════════════════════════════════════════════════════════════

/// Append a `Finalization` to a block in place. Because `Block` is an enum,
/// this replaces the whole value via `std::mem::replace`.
fn push_finalization(block: &mut Block, fw: Arc<Verifiable<Finalization>>) {
    let taken = std::mem::replace(
        block,
        Block::Sealed {
            header: block.header().clone(),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provision_hashes: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        },
    );
    *block = match taken {
        Block::Live {
            header,
            transactions,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Live {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provisions,
                abandonment_records,
                state_claims,
                witness_sources,
            }
        }
        Block::Sealed {
            header,
            transactions,
            certificates,
            provision_hashes,
            abandonment_records,
            state_claims,
            witness_sources,
        } => {
            let mut certificates = (*certificates).clone();
            certificates.push(fw);
            Block::Sealed {
                header,
                transactions,
                certificates: Arc::new(certificates),
                provision_hashes,
                abandonment_records,
                state_claims,
                witness_sources,
            }
        }
    };
}

/// A prepared commit for a block the store already holds — landed by a
/// sync commit between prepare and flush, or by a second vnode on the
/// store — applies nothing: the block is in, and its batch would
/// otherwise be replayed onto a version already written.
#[test]
fn a_prepared_commit_for_a_committed_block_applies_nothing() {
    let temp_dir = TempDir::new().unwrap();
    let storage =
        Arc::new(RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap());
    test_prepared_commit_for_a_committed_block_applies_nothing(&storage);
}

#[test]
#[should_panic(expected = "meets a different block already there")]
fn a_prepared_commit_refuses_a_different_block_at_one_height() {
    let temp_dir = TempDir::new().unwrap();
    let storage =
        Arc::new(RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap());
    test_prepared_commit_refuses_a_different_block_at_one_height(&storage);
}

#[test]
fn a_prepared_commit_writes_its_committed_cells() {
    let temp_dir = TempDir::new().unwrap();
    let storage =
        Arc::new(RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap());
    test_prepared_commit_writes_committed_cells(&storage);
}

/// A finalization whose single receipt carries `writes`. Its placeholder
/// EC refuses nothing, so the whole set settles.
fn finalization_with_writes(
    height: BlockHeight,
    writes: StateWrites,
) -> Arc<Verifiable<Finalization>> {
    let tick_id = TickId::new(ShardId::ROOT, height);
    let receipt = StoredReceipt {
        tx_hash: TxHash::from(Hash::from_bytes(&height.inner().to_le_bytes())),
        consensus: Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Vec::new(),
            events: Vec::new(),
        }),
        metadata: None,
    };
    Arc::new(Verifiable::from(Finalization::new(
        tick_id,
        TickHalf::Determined,
        vec![placeholder_local_ec(ShardId::ROOT, height)],
        vec![receipt],
    )))
}

/// A prepared block's priors come from the pending chain it was prepared
/// over, not the persisted store. A rewrite of a value a pending ancestor
/// tombstoned is a real write — judging it against the persisted state
/// would call it a no-op, skip the substate puts, and fork the state CFs
/// from the attested root once the tombstone lands.
#[test]
fn a_rewrite_over_a_pending_tombstone_is_not_a_noop() {
    let temp_dir = TempDir::new().unwrap();
    let storage =
        Arc::new(RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap());

    let cell = state_key(9, 1);
    let entry = entry_key(9, 7);
    let mut writes = StateWrites::default();
    writes.cells.insert(cell, Some(vec![4, 5]));
    writes.entries.insert(entry, Some(vec![1, 2, 3]));

    // Block 1 writes both values and persists.
    let (root1, _snap1, prepared1) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: storage.state_root(),
            height: BlockHeight::GENESIS,
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[finalization_with_writes(
            BlockHeight::new(1),
            writes.clone(),
        )],
        &[],
        &[],
        BlockHeight::new(1),
    );
    prepared1(
        SyncHint::FlushNow,
        &make_test_certified(make_test_block(BlockHeight::new(1))),
        &no_witness(),
    );

    // Block 2 tombstones both; block 3 rewrites the block-1 values and
    // is prepared while block 2 is certified but unpersisted.
    let mut tombstones = StateWrites::default();
    tombstones.cells.insert(cell, None);
    tombstones.entries.insert(entry, None);
    let (root2, snap2, prepared2) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: root1,
            height: BlockHeight::new(1),
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[finalization_with_writes(BlockHeight::new(2), tombstones)],
        &[],
        &[],
        BlockHeight::new(2),
    );
    let (_root3, _snap3, prepared3) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: root2,
            height: BlockHeight::new(2),
            // Block 2 is certified and unpersisted, so the store's own
            // snapshot answers for block 1. What the parent left is that
            // plus what block 2 settled, which is what a view supplies
            // here in production.
            state: &PendingBaseline::new(
                storage.snapshot(),
                std::slice::from_ref(&snap2),
                BlockHeight::new(2),
            ),
            pending: std::slice::from_ref(&snap2),
            base_reads: None,
        },
        &[finalization_with_writes(BlockHeight::new(3), writes)],
        &[],
        &[],
        BlockHeight::new(3),
    );
    prepared2(
        SyncHint::FlushNow,
        &make_test_certified(make_test_block(BlockHeight::new(2))),
        &no_witness(),
    );
    prepared3(
        SyncHint::FlushNow,
        &make_test_certified(make_test_block(BlockHeight::new(3))),
        &no_witness(),
    );

    // The rewrites reached the substate CFs beside the attested root.
    assert_eq!(storage.cell(cell), Some(vec![4, 5]));
    assert_eq!(
        storage.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 16),
        vec![(7, vec![1, 2, 3])]
    );
    // And history holds the pending-chain priors: at block 2 both are
    // tombstoned, at block 1 both hold their first values.
    let at_2 = storage.snapshot_at(BlockHeight::new(2));
    assert_eq!(at_2.cell(cell), None);
    assert!(
        at_2.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 16)
            .is_empty()
    );
    let at_1 = storage.snapshot_at(BlockHeight::new(1));
    assert_eq!(at_1.cell(cell), Some(vec![4, 5]));
    assert_eq!(
        at_1.entries_in_range(entry.owner, entry.collection, 0, u128::MAX, 16),
        vec![(7, vec![1, 2, 3])]
    );
}

#[test]
fn test_commit_block_stores_certificates() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let shard = ShardId::ROOT;
    let cert = make_test_finalization(BlockHeight::new(1), shard);
    let cert_hash = cert.receipt_hash();

    // Create a block that includes this certificate
    let block = make_test_block(BlockHeight::new(1));
    let fw_certificates = Arc::new(vec![Arc::new(cert.into())]);
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
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        },
    };
    let _ = commit_settled_at(
        &storage,
        &make_test_certified(block),
        &[],
        &[],
        &no_witness(),
    );

    assert!(storage.get_certificate(&cert_hash).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// Batch operations
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_certificates_batch() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let cert1 = make_test_finalization(BlockHeight::new(1), ShardId::ROOT);
    let cert2 = make_test_finalization(BlockHeight::new(2), ShardId::ROOT);
    let id1 = cert1.receipt_hash();
    let id2 = cert2.receipt_hash();

    storage.put_certificate(&cert1.receipt_hash(), &cert1);
    storage.put_certificate(&cert2.receipt_hash(), &cert2);

    let result = storage.get_certificates_batch(&[id1, id2]);
    assert_eq!(result.len(), 2);

    let missing = FinalizationHash::from_raw(Hash::from_bytes(b"absent"));
    let partial = storage.get_certificates_batch(&[id1, missing]);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].receipt_hash(), id1);
}

// ═══════════════════════════════════════════════════════════════════════
// Parity tests with SimShardStorage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_certificate_store_and_retrieve() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let cert = make_test_finalization(BlockHeight::new(1), ShardId::ROOT);
    let tick_id = *cert.tick_id();

    storage.put_certificate(&cert.receipt_hash(), &cert);

    let stored = storage.get_certificate(&cert.receipt_hash()).unwrap();
    assert_eq!(stored.tick_id(), &tick_id);
}

#[test]
fn test_certificate_get_missing() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let missing = FinalizationHash::from_raw(Hash::from_bytes(b"absent"));
    assert!(storage.get_certificate(&missing).is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Persistence across reopen
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_substates_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();

    let root_after_write;
    let version_after_write;
    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        commit_writes(&storage, &make_settled_writes(1, 10, vec![42]));
        root_after_write = storage.state_root();
        version_after_write = storage.jmt_height();
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        assert_eq!(storage.jmt_height(), version_after_write);
        assert_eq!(storage.state_root(), root_after_write);
        assert_eq!(
            storage.cell(state_key(1, 10)),
            Some(vec![42]),
            "substate should survive reopen"
        );
    }
}

#[test]
fn test_blocks_survive_reopen() {
    let temp_dir = TempDir::new().unwrap();

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let block = make_test_block(BlockHeight::new(1));
        commit_empty(&storage, &block);
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
fn a_replay_names_what_committed_and_never_resolved() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_unresolved_fold(&storage);
}

#[test]
fn a_replay_reaches_a_record_no_verdict_has_discharged() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_undischarged_record_holds_the_floor(&storage);
}

#[test]
fn a_replay_stops_at_the_chain_origin() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_the_replay_floor_stops_at_the_chain_origin(&storage);
}

#[test]
fn a_replay_keeps_a_leg_its_own_finalization_settled() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_a_legs_own_finalization_keeps_the_floor(&storage);
}

#[test]
fn a_leg_entry_holds_the_floor_to_its_horizon() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_a_leg_entry_holds_the_floor_to_its_horizon(&storage);
}

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
    let tick_id = *ec.tick_id();

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let mut block = make_test_block(BlockHeight::new(1));
        push_finalization(
            &mut block,
            Arc::new(
                Finalization::new(tick_id, TickHalf::Determined, vec![Arc::new(ec)], vec![]).into(),
            ),
        );
        commit_settled_at(
            &storage,
            &make_test_certified(block),
            &[],
            &[],
            &no_witness(),
        );
    }

    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let cert = storage
            .get_execution_certificate(&tick_id)
            .expect("EC must survive reopen");
        assert_eq!(cert.block_height(), BlockHeight::new(1));
    }
}

#[test]
fn test_ec_atomic_with_block_commit() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let ec = make_test_execution_certificate(1, BlockHeight::new(1));
    let tick_id = *ec.tick_id();
    let mut block = make_test_block(BlockHeight::new(1));
    push_finalization(
        &mut block,
        Arc::new(
            Finalization::new(tick_id, TickHalf::Determined, vec![Arc::new(ec)], vec![]).into(),
        ),
    );
    // Commit block with EC atomically
    commit_settled_at(
        &storage,
        &make_test_certified(block),
        &[],
        &[],
        &no_witness(),
    );

    let cert = storage
        .get_execution_certificate(&tick_id)
        .expect("EC must be retrievable after commit");
    assert_eq!(cert.block_height(), BlockHeight::new(1));
}

// ─── State-history semantics (parity with storage-memory tests) ─────────────
//
// These mirror `storage-memory/src/tests.rs`:
//   - test_state_history_create_delete_create
//   - test_snapshot_at_below_retention_panics
//   - test_historical_substate_read_respects_retention
//   - test_reset_partition_captures_history_for_all_removed_keys
//   - test_genesis_skips_history_entries
//
// RocksDB encodes the history log differently (wire codec, prefix extractor,
// snapshot isolation, column family) so backend parity is not free.

/// JMT GC prunes per-version substate byte totals below the retention
/// cutoff and retains everything at or above it.
#[test]
fn substate_bytes_pruned_by_jmt_gc() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    for h in 1..=10u64 {
        let writes = make_settled_writes(u8::try_from(h).unwrap_or(u8::MAX), 1, vec![1]);
        commit_writes_at(&storage, &writes, paced(h, 2));
    }
    storage.run_jmt_gc();

    // Two blocks fit the horizon, so a tip at 10 floors at 8: below it
    // the entries are pruned, the rest intact.
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(7)), None);
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(8)), Some(8));
    assert_eq!(storage.substate_bytes_at(BlockHeight::new(10)), Some(10));
}

/// Genesis-style writes via `commit_substates_only` must NOT populate the
/// state-history CF — there is no pre-state to preserve.
#[test]
fn test_genesis_skips_history_entries() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();

    let updates = make_settled_writes(1, 1, vec![0xAA]);
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
    assert_eq!(storage.cell(state_key(1, 1)), Some(vec![0xAA]));
}

// ─── Safe-vote registers ─────────────────────────────────────────────────────

#[test]
fn safe_vote_registers_recover_their_justification() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_registers_recover_their_justification(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn safe_vote_registers_are_monotone_and_recoverable() {
    let (_dir, storage) = open_fresh();
    test_registers_are_monotone_and_recoverable(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn safe_vote_registers_ignore_a_stale_chain_incarnation() {
    let (_dir, storage) = open_fresh();
    test_registers_ignore_a_stale_chain_incarnation(
        &storage,
        |origin| {
            let mut batch = WriteBatch::default();
            write_chain_origin(&mut batch, origin);
            storage.db.write(batch).unwrap();
        },
        || storage.load_recovered_state(ShardId::ROOT),
    );
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
        storage.persist_vote_position(v1, &position(registers(3, 5)));
        storage.persist_vote_position(v2, &position(registers(2, 2)));
        assert_eq!(storage.safe_vote_registers(v1), Some(registers(3, 5)));
    }

    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(reopened.safe_vote_registers(v1), Some(registers(3, 5)));
    let recovered = reopened.load_recovered_state(ShardId::ROOT);
    assert_eq!(
        recovered.safe_vote_registers.get(&v1),
        Some(&registers(3, 5))
    );
    assert_eq!(
        recovered.safe_vote_registers.get(&v2),
        Some(&registers(2, 2))
    );
}

/// The register merge holds on a cold write-path cache after a reopen,
/// where it must consult the stored record.
#[test]
fn safe_vote_registers_writes_are_monotone_across_a_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let v = ValidatorId::new(7);
    {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        storage.persist_vote_position(v, &position(registers(4, 6)));
        storage.persist_vote_position(v, &position(registers(2, 9)));
        assert_eq!(storage.safe_vote_registers(v), Some(registers(4, 9)));
    }

    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    reopened.persist_vote_position(v, &position(registers(3, 3)));
    assert_eq!(reopened.safe_vote_registers(v), Some(registers(4, 9)));
}

#[test]
fn recovery_carries_the_tip_drain_total() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_recovery_carries_the_tip_drain_total(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn a_committed_bundle_outlives_the_sealing_of_its_block() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_committed_bundle_outlives_sealing(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

/// Storing the bodies is only worth anything if they outlive the process
/// that committed them, which no in-memory backend can show.
#[test]
fn a_committed_bundle_survives_a_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let hash = {
        let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
        let block = with_provisions(
            make_test_block(BlockHeight::new(1)),
            ShardId::leaf(1, 1),
            TxHash::ZERO,
        );
        let hash = block.provisions()[0].hash();
        commit_settled_at(
            &storage,
            &make_test_certified(block),
            &[],
            &[],
            &no_witness(),
        );
        hash
    };

    let reopened = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(
        reopened
            .load_recovered_state(ShardId::ROOT)
            .retained_provisions
            .iter()
            .map(|bundle| bundle.hash())
            .collect::<Vec<_>>(),
        vec![hash],
    );
}

#[test]
fn a_retained_bundle_drops_below_the_history_floor() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_retained_bundle_drops_below_the_history_floor(&storage, 3, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn the_widest_copy_of_a_tick_holds_the_slot() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_widest_tick_copy_holds_the_slot(&storage);
}

#[test]
fn the_tx_index_answers_with_the_local_shards_certificate() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_tx_index_answers_with_the_local_shards_certificate(&storage);
}

#[test]
fn the_tx_index_answers_with_every_certificate_of_this_shards() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    test_the_tx_index_answers_with_every_certificate_of_this_shards(&storage);
}

/// The shared package-index test, then a reopen: the index is what a
/// restarting host reseeds its caches from.
#[test]
fn a_package_cell_lands_in_the_artifact_index_and_survives_a_reopen() {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    let artifact = test_a_package_cell_lands_in_the_artifact_index(&storage);
    drop(storage);
    let storage = RocksDbShardStorage::open(temp_dir.path(), NibblePath::empty()).unwrap();
    assert_eq!(storage.package_artifacts(), vec![artifact]);
}
