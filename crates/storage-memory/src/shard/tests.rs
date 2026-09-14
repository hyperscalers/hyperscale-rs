use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_storage::test_helpers::{
    commit_settled_at, commit_writes, make_settled_writes, make_test_block,
    make_test_block_with_anchor_wt, make_test_certified, make_test_qc, push_certificate, state_key,
    test_a_committed_block_reads_back,
    test_a_committed_cell_reads_back_and_a_snapshot_keeps_its_version,
    test_a_fresh_store_holds_nothing, test_a_package_cell_lands_in_the_artifact_index,
    test_commits_advance_the_version_and_writes_move_the_root, test_committed_receipts_reach_state,
    test_entries_commit_serve_and_history, test_historical_reads_resolve_per_version,
    test_historical_reads_respect_retention, test_history_reads_through_create_delete_create,
    test_registers_are_monotone_and_recoverable, test_registers_ignore_a_stale_chain_incarnation,
    test_snapshot_at_below_the_floor_panics, test_substate_bytes_track_commits,
    test_sweep_index_counts_a_pending_ancestors_move, test_sweep_index_tracks_the_leaves,
    test_sweep_stops_at_the_ceiling_or_the_cap, test_the_root_is_a_function_of_the_writes,
    test_witness_window_retention_and_recovery,
};
use hyperscale_storage::{
    DedupWindow, ParentAnchor, ShardChainReader, ShardChainWriter, SubstateStore, Substates,
    VersionedStore, test_helpers,
};
use hyperscale_types::test_utils::{
    install_stub_protocol_statics, make_leg_finalization, stub_transaction, test_prefix,
    test_principal, test_transaction,
};
use hyperscale_types::{
    Address, AddressClass, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeight,
    ChainOrigin, Deadline, Hash, LocalKey, RETENTION_HORIZON, SettledWrites, ShardId, StateRoot,
    SubstateKey, SyncHint, TimestampRange, Transaction, TxHash, Verifiable, WeightedTimestamp,
    Window, WitnessSources,
};

fn no_witness() -> BeaconWitnessCommit {
    BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO)
}

use super::core::SimShardStorage;

/// Commit `block` with no writes and no witness.
fn commit_empty(storage: &SimShardStorage, block: &Block) -> StateRoot {
    commit_settled_at(
        storage,
        &make_test_certified(block.clone()),
        &[],
        &[],
        &no_witness(),
    )
}

#[test]
fn a_blocks_sweep_stops_at_the_ceiling_or_the_cap() {
    test_sweep_stops_at_the_ceiling_or_the_cap(&SimShardStorage::default());
}

#[test]
fn the_sweep_index_tracks_the_leaves() {
    test_sweep_index_tracks_the_leaves(&SimShardStorage::default());
}

#[test]
fn the_sweep_index_counts_a_pending_ancestors_move() {
    test_sweep_index_counts_a_pending_ancestors_move(&SimShardStorage::default());
}

#[test]
fn entries_commit_serve_ranges_and_keep_history() {
    test_entries_commit_serve_and_history(&SimShardStorage::default());
}

#[test]
fn a_fresh_store_holds_nothing() {
    test_a_fresh_store_holds_nothing(&SimShardStorage::default());
}

#[test]
fn a_committed_cell_reads_back_and_a_snapshot_keeps_its_version() {
    test_a_committed_cell_reads_back_and_a_snapshot_keeps_its_version(&SimShardStorage::default());
}

#[test]
fn commits_advance_the_version_and_writes_move_the_root() {
    test_commits_advance_the_version_and_writes_move_the_root(&SimShardStorage::default());
}

#[test]
fn the_root_is_a_function_of_the_writes() {
    test_the_root_is_a_function_of_the_writes(SimShardStorage::default);
}

#[test]
fn a_committed_block_reads_back() {
    test_a_committed_block_reads_back(&SimShardStorage::default());
}

#[test]
fn committed_receipts_reach_state() {
    test_committed_receipts_reach_state(&SimShardStorage::default());
}

#[test]
fn substate_bytes_track_commits() {
    test_substate_bytes_track_commits(&SimShardStorage::default());
}

#[test]
fn history_reads_through_create_delete_create() {
    test_history_reads_through_create_delete_create(&SimShardStorage::default());
}

#[test]
fn historical_reads_resolve_per_version() {
    test_historical_reads_resolve_per_version(&SimShardStorage::default());
}

#[test]
#[should_panic(expected = "below retention floor")]
fn snapshot_at_below_the_floor_panics() {
    test_snapshot_at_below_the_floor_panics(&SimShardStorage::default());
}

#[test]
fn historical_reads_respect_retention() {
    test_historical_reads_respect_retention(&SimShardStorage::default());
}

#[test]
fn witness_window_retention_and_recovery() {
    let storage = SimShardStorage::default();
    test_witness_window_retention_and_recovery(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn safe_vote_registers_are_monotone_and_recoverable() {
    let storage = SimShardStorage::default();
    test_registers_are_monotone_and_recoverable(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn safe_vote_registers_ignore_a_stale_chain_incarnation() {
    let storage = SimShardStorage::default();
    test_registers_ignore_a_stale_chain_incarnation(
        &storage,
        |origin| storage.consensus.write().unwrap().chain_origin = origin,
        || storage.load_recovered_state(ShardId::ROOT),
    );
}

#[test]
fn a_package_cell_lands_in_the_artifact_index() {
    test_a_package_cell_lands_in_the_artifact_index(&SimShardStorage::default());
}

#[test]
fn test_snapshot_clone_performance() {
    let storage = SimShardStorage::default();

    // Insert 10,000 items via substates-only (no JMT computation).
    // This test bounds the cost of a single BTreeMap-clone snapshot at
    // simulation scale, not tree commit speed.
    for i in 0..10_000u32 {
        let mut body = [0u8; 31];
        body[..4].copy_from_slice(&i.to_be_bytes());
        let owner = Address::new(body, AddressClass::Component);
        let writes = SettledWrites::from_absolutes(BTreeMap::from([(
            SubstateKey {
                owner,
                local: LocalKey([0; 16]),
            },
            Some(vec![u8::try_from(i).unwrap_or(u8::MAX)]),
        )]));
        storage.commit_substates_only(&writes);
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
fn test_transactions_batch_with_indexed_block() {
    let storage = SimShardStorage::default();
    let block = make_test_block(BlockHeight::new(1));

    let tx = Arc::new(Verifiable::from(test_transaction(42)));
    let tx_hash = tx.hash();
    let block = match block {
        Block::Live {
            header,
            certificates,
            provisions,
            ..
        } => Block::Live {
            header,
            transactions: Arc::new(vec![tx]),
            certificates,
            provisions,
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        },
        Block::Sealed {
            header,
            certificates,
            provision_hashes,
            ..
        } => Block::Sealed {
            header,
            transactions: Arc::new(vec![tx]),
            certificates,
            provision_hashes,
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        },
    };
    commit_empty(&storage, &block);

    let result = storage.get_transactions_batch(&[tx_hash]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].hash(), tx_hash);

    // Missing hash still excluded
    let missing = TxHash::from(Hash::from_bytes(&[99; 32]));
    let partial = storage.get_transactions_batch(&[tx_hash, missing]);
    assert_eq!(partial.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════
// JMT state tracking
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// ShardChainWriter
// ═══════════════════════════════════════════════════════════════════════

/// A prepared commit for a block the store already holds — landed by a
/// sync commit between prepare and flush, or by a second vnode on the
/// store — applies nothing: the block is in, and its history would
/// otherwise be written twice at one version.
#[test]
fn a_prepared_commit_for_a_committed_block_applies_nothing() {
    let storage = Arc::new(SimShardStorage::default());
    test_helpers::test_prepared_commit_for_a_committed_block_applies_nothing(&storage);
}

#[test]
#[should_panic(expected = "meets a different block already there")]
fn a_prepared_commit_refuses_a_different_block_at_one_height() {
    let storage = Arc::new(SimShardStorage::default());
    test_helpers::test_prepared_commit_refuses_a_different_block_at_one_height(&storage);
}

#[test]
fn a_prepared_commit_writes_its_committed_cells() {
    let storage = Arc::new(SimShardStorage::default());
    test_helpers::test_prepared_commit_writes_committed_cells(&storage);
}

#[test]
fn test_prepare_commit_state_root_matches() {
    let storage = Arc::new(SimShardStorage::default());
    let block = make_test_block(BlockHeight::new(1));
    let qc = make_test_qc(&block);

    let parent_root = storage.state_root();
    let (spec_root, _jmt_snapshot, prepared) = storage.prepare_block_commit(
        ParentAnchor {
            state_root: parent_root,
            height: BlockHeight::GENESIS,
            state: &storage.snapshot(),
            pending: &[],
            base_reads: None,
        },
        &[],
        &[],
        &[],
        BlockHeight::new(1),
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
    let mut storage = SimShardStorage::default();

    // Add some data
    commit_writes(&storage, &make_settled_writes(1, 10, vec![1]));
    assert!(storage.jmt_height() > BlockHeight::GENESIS);
    assert!(!storage.is_empty());

    storage.clear();

    assert_eq!(storage.jmt_height(), BlockHeight::new(0));
    assert_eq!(storage.state_root(), StateRoot::ZERO);
    assert!(storage.is_empty());
}

#[test]
fn test_len_and_is_empty() {
    let storage = SimShardStorage::default();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);

    commit_writes(&storage, &make_settled_writes(1, 10, vec![1]));
    assert!(!storage.is_empty());
    assert_eq!(storage.len(), 1);

    commit_writes(&storage, &make_settled_writes(4, 20, vec![2]));
    assert_eq!(storage.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Execution certificate storage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn a_replay_names_what_committed_and_never_resolved() {
    let storage = SimShardStorage::default();
    test_helpers::test_unresolved_fold(&storage);
}

#[test]
fn a_replay_reaches_a_record_no_verdict_has_discharged() {
    let storage = SimShardStorage::default();
    test_helpers::test_undischarged_record_holds_the_floor(&storage);
}

#[test]
fn a_replay_stops_at_the_chain_origin() {
    let storage = SimShardStorage::default();
    test_helpers::test_the_replay_floor_stops_at_the_chain_origin(&storage);
}

#[test]
fn a_replay_keeps_a_leg_its_own_finalization_settled() {
    let storage = SimShardStorage::default();
    test_helpers::test_a_legs_own_finalization_keeps_the_floor(&storage);
}

#[test]
fn a_leg_entry_holds_the_floor_to_its_horizon() {
    let storage = SimShardStorage::default();
    test_helpers::test_a_leg_entry_holds_the_floor_to_its_horizon(&storage);
}

#[test]
fn recovery_carries_the_tip_drain_total() {
    let storage = SimShardStorage::default();
    test_helpers::test_recovery_carries_the_tip_drain_total(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn a_committed_bundle_outlives_the_sealing_of_its_block() {
    let storage = SimShardStorage::default();
    test_helpers::test_committed_bundle_outlives_sealing(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn a_retained_bundle_drops_below_the_history_floor() {
    let storage = SimShardStorage::default();
    test_helpers::test_retained_bundle_drops_below_the_history_floor(&storage, 3, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

#[test]
fn the_widest_copy_of_a_tick_holds_the_slot() {
    let storage = SimShardStorage::default();
    test_helpers::test_widest_tick_copy_holds_the_slot(&storage);
}

#[test]
fn the_tx_index_answers_with_the_local_shards_certificate() {
    let storage = SimShardStorage::default();
    test_helpers::test_tx_index_answers_with_the_local_shards_certificate(&storage);
}

#[test]
fn the_tx_index_answers_with_every_certificate_of_this_shards() {
    let storage = SimShardStorage::default();
    test_helpers::test_the_tx_index_answers_with_every_certificate_of_this_shards(&storage);
}

#[test]
fn test_ec_storage_roundtrip() {
    let storage = SimShardStorage::default();
    test_helpers::test_ec_storage_roundtrip(&storage);
}

#[test]
fn test_ec_storage_batch() {
    let storage = SimShardStorage::default();
    test_helpers::test_ec_storage_batch(&storage);
}

#[test]
fn witness_payload_range_reads() {
    let storage = SimShardStorage::default();
    test_helpers::test_witness_payload_range_reads(&storage);
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
    let node_seed = 1u8;

    let commit = |storage: &SimShardStorage, height: BlockHeight, value: Vec<u8>| {
        commit_writes(storage, &make_settled_writes(node_seed, 1, value));
        assert_eq!(storage.jmt_height(), height);
    };

    // Validator A: persists through block 5.
    let a = SimShardStorage::default();
    for h in 1..=5u64 {
        commit(
            &a,
            BlockHeight::new(h),
            vec![u8::try_from(h).unwrap_or(u8::MAX)],
        );
    }
    assert_eq!(a.jmt_height(), BlockHeight::new(5));

    // Validator B: stops at block 3.
    let b = SimShardStorage::default();
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
    let key = state_key(node_seed, 1);

    assert_eq!(
        snap_a.cell(key),
        Some(vec![3]),
        "validator A must see block-3 value at v3, not its current (block-5) value"
    );
    assert_eq!(
        snap_a.cell(key),
        snap_b.cell(key),
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

    let storage = SimShardStorage::default();
    for h in 1..=50u64 {
        let writes = make_settled_writes(node_seed, 1, vec![u8::try_from(h).unwrap_or(u8::MAX)]);
        commit_writes(&storage, &writes);
    }

    let key = state_key(node_seed, 1);

    // Read at every 10th version — each should return the exact write
    // from that height, not the latest or any adjacent version.
    for target in [1u64, 10, 20, 25, 49, 50] {
        let snap = storage.snapshot_at(BlockHeight::new(target));
        assert_eq!(
            snap.cell(key),
            Some(vec![u8::try_from(target).unwrap_or(u8::MAX)]),
            "snapshot_at({target}) should resolve to block-{target} value"
        );
    }
}

/// Genesis-style writes via `commit_substates_only` must NOT populate
/// the state-history log — there is no pre-state to preserve, and
/// polluting the log with `(K, 0) → None` entries would waste space
/// until GC.
#[test]
fn test_genesis_skips_history_entries() {
    let storage = SimShardStorage::default();

    let updates = make_settled_writes(1, 1, vec![0xAA]);
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

// ─── Safe-vote registers ─────────────────────────────────────────────────────

#[test]
fn safe_vote_registers_recover_their_justification() {
    let storage = SimShardStorage::default();
    test_helpers::test_registers_recover_their_justification(&storage, || {
        storage.load_recovered_state(ShardId::ROOT)
    });
}

// ─── Dedup window ───────────────────────────────────────────────────
//
// The window a coordinator rebuilds when it resumes a chain it did not
// commit itself. An empty index refuses no duplicate, so what these pin
// is that the fold reaches back far enough and reports honestly when it
// cannot.

/// A block at `height` anchored at `anchor_wt_ms`, carrying `txs`.
fn block_with_txs(
    height: BlockHeight,
    anchor_wt_ms: u64,
    txs: Vec<Arc<Verifiable<Transaction>>>,
) -> Block {
    match make_test_block_with_anchor_wt(height, anchor_wt_ms) {
        Block::Live {
            header,
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
            ..
        } => Block::Live {
            header,
            transactions: Arc::new(txs),
            certificates,
            provisions,
            abandonment_records,
            state_claims,
            witness_sources,
        },
        sealed @ Block::Sealed { .. } => sealed,
    }
}

/// A transaction whose signed window ends at `end_ms` — the deadline the
/// fold has to recover for it.
fn dedup_tx(seed: u8, end_ms: u64) -> Arc<Verifiable<Transaction>> {
    install_stub_protocol_statics();
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO,
        WeightedTimestamp::from_millis(end_ms),
    );
    Arc::new(Verifiable::from(stub_transaction(
        test_principal(seed),
        &[test_prefix(seed)],
        1_000,
        validity,
    )))
}

/// The fold recovers each committed transaction against the close of the
/// delivery window its own signed end opens, not against when the block
/// carrying it committed.
#[test]
fn dedup_window_recovers_committed_txs_with_their_own_deadlines() {
    let storage = SimShardStorage::default();
    let tx = dedup_tx(1, 90_000);
    let tx_hash = tx.hash();
    let block = block_with_txs(BlockHeight::new(1), 1_000, vec![tx]);
    commit_empty(&storage, &block);

    let window = DedupWindow::from_reader(
        &storage,
        BlockHeight::new(1),
        WeightedTimestamp::from_millis(1_000),
        ChainOrigin {
            genesis_height: BlockHeight::new(1),
            anchor_wt: WeightedTimestamp::ZERO,
        },
    );

    assert_eq!(
        window.committed,
        vec![(
            tx_hash,
            Window::Delivery
                .of(Deadline::of(WeightedTimestamp::from_millis(90_000)))
                .end
        )],
    );
}

/// The fold records the names a finalization *decided*, as the live
/// index does.
///
/// A leg's finalization names its transaction without resolving it, and
/// the reclaim's finalization naming it later is the one neither may
/// refuse. A window that took the bare name would hold it for the
/// retention span, so a restarted replica would refuse the reclaim — and
/// every abandoning record naming it — while its peers admitted both.
///
/// The rebuild twin of `a_leg_finalization_does_not_resolve_its_transaction`.
#[test]
fn dedup_window_records_only_what_a_finalization_decided() {
    let storage = SimShardStorage::default();
    let tx = dedup_tx(1, 60_000);
    let tx_hash = tx.hash();
    let leg = Arc::new(Verifiable::from(make_leg_finalization(
        BlockHeight::new(1),
        tx_hash,
    )));
    let block = push_certificate(block_with_txs(BlockHeight::new(1), 1_000, vec![tx]), leg);
    commit_empty(&storage, &block);

    let window = DedupWindow::from_reader(
        &storage,
        BlockHeight::new(1),
        WeightedTimestamp::from_millis(1_000),
        ChainOrigin {
            genesis_height: BlockHeight::new(1),
            anchor_wt: WeightedTimestamp::ZERO,
        },
    );

    assert!(
        window.resolved.is_empty(),
        "the leg's finalization decided nothing: {:?}",
        window.resolved,
    );
    assert_eq!(
        window.finalizations.len(),
        1,
        "while the certificate's own identity is recorded whatever it decided",
    );
}

/// A walk that reaches the height its chain starts at is whole, whatever
/// its span.
///
/// For the network's first chain nothing was ever committed beneath it.
/// For a reshape successor its predecessor's blocks do sit below, but what
/// they carried is refused on validity — a transaction whose window opened
/// before the chain did cannot be admitted here — so this window has
/// nothing left to hold.
#[test]
fn dedup_window_reaching_the_height_its_chain_starts_at_is_whole() {
    let storage = SimShardStorage::default();
    let block = block_with_txs(BlockHeight::new(1), 1_000, vec![dedup_tx(2, 90_000)]);
    commit_empty(&storage, &block);

    let window = DedupWindow::from_reader(
        &storage,
        BlockHeight::new(1),
        WeightedTimestamp::from_millis(1_000),
        ChainOrigin {
            genesis_height: BlockHeight::new(1),
            anchor_wt: WeightedTimestamp::from_millis(900),
        },
    );

    assert!(
        window.reached_origin,
        "the walk bottomed out at the height its chain begins",
    );
}

/// A chain holding nothing below the height it starts at leaves the window
/// short rather than empty — the shape a snap-synced store has, whose
/// origin sits far below the anchor it imported at.
///
/// Empty is the safe answer for a replay window and the unsafe one here:
/// an index covering nothing refuses nothing, so the shortfall has to be
/// reported instead of erasing the window.
#[test]
fn dedup_window_stops_short_without_claiming_the_origin() {
    let storage = SimShardStorage::default();
    // Three blocks, all inside the window, none of them the chain's
    // claimed origin — so the walk runs out beneath them.
    let tx = dedup_tx(3, 900_000);
    let tx_hash = tx.hash();
    for height in 1..=3u64 {
        let txs = if height == 3 {
            vec![tx.clone()]
        } else {
            vec![]
        };
        let block = block_with_txs(BlockHeight::new(height), 400_000 + height, txs);
        commit_empty(&storage, &block);
    }

    let window = DedupWindow::from_reader(
        &storage,
        BlockHeight::new(3),
        WeightedTimestamp::from_millis(400_003),
        ChainOrigin::ROOT,
    );

    assert_eq!(
        window.committed,
        vec![(
            tx_hash,
            Window::Delivery
                .of(Deadline::of(WeightedTimestamp::from_millis(900_000)))
                .end
        )],
    );
    assert!(
        !window.reached_origin,
        "a walk that ran out of blocks above its origin has not reached it",
    );
    assert_eq!(
        window.covered_from,
        Some(WeightedTimestamp::from_millis(400_001)),
        "coverage reaches as deep as the oldest block it read",
    );
}

/// Each batch is stamped against the anchor of the block that carried it,
/// not against the tip the walk started from.
///
/// The live path keys the provision tier on the committing clock. A walk
/// starting inside the window cannot see below it to reproduce that
/// clock's monotonic clamp, so it takes each block's own anchor — landing
/// at or before where the live path put the entry. Early expiry costs a
/// re-request; the tip's clock would hold every entry in the window for an
/// extra window's width.
#[test]
fn dedup_window_stamps_each_batch_against_its_own_block() {
    let storage = SimShardStorage::default();
    let (older_ms, newer_ms) = (10_000u64, 40_000u64);
    let (older_tx, newer_tx) = (test_transaction(4).hash(), test_transaction(5).hash());

    for (height, anchor_ms, tx_hash) in [(1u64, older_ms, older_tx), (2, newer_ms, newer_tx)] {
        let block = test_helpers::with_provisions(
            block_with_txs(BlockHeight::new(height), anchor_ms, vec![]),
            ShardId::ROOT,
            tx_hash,
        );
        commit_empty(&storage, &block);
    }

    let window = DedupWindow::from_reader(
        &storage,
        BlockHeight::new(2),
        WeightedTimestamp::from_millis(newer_ms),
        ChainOrigin {
            genesis_height: BlockHeight::new(1),
            anchor_wt: WeightedTimestamp::ZERO,
        },
    );

    let deadlines: Vec<WeightedTimestamp> = {
        let mut stamped: Vec<WeightedTimestamp> =
            window.provisions.iter().map(|(_, at)| *at).collect();
        stamped.sort_unstable();
        stamped
    };
    assert_eq!(
        deadlines,
        vec![
            WeightedTimestamp::from_millis(older_ms).plus(RETENTION_HORIZON),
            WeightedTimestamp::from_millis(newer_ms).plus(RETENTION_HORIZON),
        ],
        "two blocks at different anchors must not share one deadline",
    );
}
