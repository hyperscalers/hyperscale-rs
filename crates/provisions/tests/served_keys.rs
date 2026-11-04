//! A block's served keys read alike wherever they are read: off the
//! prepared block before it is held, off the chain's view of it while it
//! is pending, once it is persisted, and after later blocks have changed
//! the same intervals and persisted in turn. On the memory store and on
//! `RocksDB`.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_hbor::Capped;
use hyperscale_jmt::NibblePath;
use hyperscale_provisions::served_keys;
use hyperscale_storage::test_helpers::{
    TestStore, commit_writes, entry_key, make_test_block, make_test_certified,
    placeholder_local_ec, push_certificate, state_key,
};
use hyperscale_storage::{
    ChainEntry, ChainWrites, MemberInputs, ParentAnchor, PendingChain, PreparedBlockView,
    ShardStorage, SubstateStore,
};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHeight, CertifiedBlock, ConsensusReceipt,
    DeclaredRange, Finalization, FrontierInputs, GlobalReceiptHash, Hash, ProtocolHasher,
    SettledWrites, ShardId, StoredReceipt, SubstateKey, SyncHint, TickHalf, TickId, TxHash,
    Verified, WeightedTimestamp, entry_leaf_key,
};
use tempfile::tempdir;

/// A collection the block inserts into.
const INSERTED: u8 = 0x11;
/// A collection the block deletes from, past the range's cap.
const THINNED: u8 = 0x22;
/// A collection the block deletes from and writes again.
const REWRITTEN: u8 = 0x33;
/// A collection the block leaves alone.
const UNTOUCHED: u8 = 0x44;

/// Entry changes across collections: `(collection, order, value)`, a
/// `None` value deleting.
fn entries(changes: &[(u8, u128, Option<u8>)]) -> SettledWrites {
    SettledWrites::from_parts(
        BTreeMap::new(),
        changes
            .iter()
            .map(|(seed, order, value)| (entry_key(*seed, *order), value.map(|byte| vec![byte])))
            .collect(),
    )
}

/// The interval `[0, 100]` of a collection, capped at `cap`.
const fn interval(seed: u8, cap: u32) -> DeclaredRange {
    let probe = entry_key(seed, 0);
    DeclaredRange {
        owner: probe.owner,
        collection: probe.collection,
        lo: 0,
        hi: 100,
        cap,
    }
}

fn leaf(seed: u8, order: u128) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, entry_key(seed, order))
}

/// A transaction reading one cell and every collection's interval.
fn request() -> ProvisionsRequest {
    ProvisionsRequest {
        tx_hash: TxHash::from(Hash::from_bytes(b"reader")),
        clock: WeightedTimestamp::ZERO,
        targets: vec![ShardId::leaf(1, 1)],
        local_keys: vec![state_key(0x55, 1)],
        local_ranges: vec![
            interval(INSERTED, 3),
            interval(THINNED, 2),
            interval(REWRITTEN, 3),
            interval(UNTOUCHED, 2),
        ],
    }
}

/// The keys [`request`] is served after the block, as the reading at
/// every stage must find them.
fn expected() -> Vec<SubstateKey> {
    let mut expected = vec![
        state_key(0x55, 1),
        leaf(INSERTED, 10),
        leaf(INSERTED, 15),
        leaf(INSERTED, 20),
        leaf(THINNED, 30),
        leaf(THINNED, 40),
        leaf(REWRITTEN, 10),
        leaf(REWRITTEN, 25),
        leaf(REWRITTEN, 30),
        leaf(UNTOUCHED, 1),
        leaf(UNTOUCHED, 2),
    ];
    expected.sort_unstable();
    expected
}

/// The parent's collections, committed at the store's next height.
fn commit_parent(store: &impl TestStore) {
    commit_writes(
        store,
        &entries(&[
            (INSERTED, 10, Some(1)),
            (INSERTED, 20, Some(1)),
            (INSERTED, 30, Some(1)),
            (THINNED, 10, Some(1)),
            (THINNED, 20, Some(1)),
            (THINNED, 30, Some(1)),
            (THINNED, 40, Some(1)),
            (THINNED, 50, Some(1)),
            (REWRITTEN, 10, Some(1)),
            (REWRITTEN, 20, Some(1)),
            (REWRITTEN, 30, Some(1)),
            (UNTOUCHED, 1, Some(1)),
            (UNTOUCHED, 2, Some(1)),
            (UNTOUCHED, 3, Some(1)),
        ]),
    );
}

/// The block at `height`: an insertion, two deletions past a cap of
/// two, and a deletion beside a rewrite and an insertion.
fn the_block(height: BlockHeight) -> Arc<Verified<CertifiedBlock>> {
    let changes = entries(&[
        (INSERTED, 15, Some(2)),
        (THINNED, 10, None),
        (THINNED, 20, None),
        (REWRITTEN, 20, None),
        (REWRITTEN, 10, Some(2)),
        (REWRITTEN, 25, Some(2)),
    ]);
    let receipt = StoredReceipt {
        tx_hash: TxHash::ZERO,
        consensus: Arc::new(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: changes.into(),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        }),
    };
    let finalization = Finalization::new(
        TickId::new(ShardId::ROOT, height),
        TickHalf::Determined,
        Some(placeholder_local_ec(ShardId::ROOT, height)),
        Capped::from_array([receipt]),
    );
    make_test_certified(push_certificate(
        make_test_block(height),
        finalization.into(),
    ))
}

/// Two later blocks that move every interval, each change one the
/// block's own reading must not see.
fn commit_later_blocks(store: &impl TestStore) {
    commit_writes(
        store,
        &entries(&[
            (INSERTED, 12, Some(3)),
            (THINNED, 10, Some(3)),
            (REWRITTEN, 20, Some(3)),
            (UNTOUCHED, 0, Some(3)),
        ]),
    );
    commit_writes(
        store,
        &entries(&[
            (INSERTED, 10, None),
            (THINNED, 30, None),
            (REWRITTEN, 25, None),
            (UNTOUCHED, 1, None),
        ]),
    );
}

/// The served keys of [`request`] at the block, read at every stage of
/// its life over `store`, are one list, and the one the block leaves.
fn the_served_keys_read_alike(store: impl ShardStorage + Clone) {
    let store = Arc::new(store);
    commit_parent(&*store);
    let parent_height = store.jmt_height();
    let height = parent_height.next();
    let chain = Arc::new(PendingChain::new(Arc::clone(&store), BlockHeight::GENESIS));
    let certified = the_block(height);
    let block = certified.block();

    let parent_view = chain.view_at(block.header().parent_block_hash(), parent_height);
    let anchored = parent_view.snapshot();
    let (_, jmt_snapshot, commit) = store.prepare_block_commit(
        ParentAnchor {
            state_root: store.state_root(),
            height: parent_height,
            state: &anchored,
            pending: parent_view.pending_snapshots(),
            base_reads: None,
        },
        &block.certificates()[..],
        ChainWrites {
            creations: &[],
            removals: &[],
            sweep_frontier: block.header().sweep_frontier(),
            frontier: &FrontierInputs::still(ShardId::ROOT),
            state_claims: block.state_claims(),
            members: &MemberInputs::still(ShardId::ROOT),
        },
        height,
    );

    let expected = expected();
    let prepared = served_keys(
        &PreparedBlockView {
            parent: &anchored,
            block: &jmt_snapshot,
        },
        &request(),
    );
    assert_eq!(prepared, expected, "the prepared block");

    let at_block = || {
        let view = chain.view_at(block.hash(), height);
        let state = view
            .served_snapshot()
            .expect("the view holds the block's state");
        served_keys(&state, &request())
    };
    chain.insert(
        block.hash(),
        ChainEntry {
            parent_block_hash: block.header().parent_block_hash(),
            height,
            settled_txs: Vec::new(),
            jmt_snapshot: Arc::clone(&jmt_snapshot),
            certified_block: Some(Arc::clone(&certified)),
        },
    );
    assert_eq!(at_block(), expected, "the block pending");

    commit(
        SyncHint::FlushNow,
        &certified,
        &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
    );
    chain.prune(height);
    assert_eq!(store.jmt_height(), height);
    assert_eq!(at_block(), expected, "the block persisted");

    commit_later_blocks(&*store);
    assert_eq!(store.jmt_height(), height.next().next());
    assert_eq!(at_block(), expected, "the block read after later ones");
}

#[test]
fn the_served_keys_read_alike_in_memory() {
    the_served_keys_read_alike(SimShardStorage::default());
}

#[test]
fn the_served_keys_read_alike_on_rocksdb() {
    let dir = tempdir().expect("a temporary directory");
    the_served_keys_read_alike(
        RocksDbShardStorage::open(dir.path(), NibblePath::empty()).expect("the store opens"),
    );
}
