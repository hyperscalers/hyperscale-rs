use hyperscale_storage::test_helpers::{
    make_test_beacon_block, make_test_beacon_state, make_test_block_and_state,
};
use hyperscale_storage::{BeaconChainReader, BeaconChainWriter};
use hyperscale_types::{BeaconBlockHash, Epoch};
use tempfile::TempDir;

use super::core::RocksDbBeaconStorage;

fn fresh_store() -> (RocksDbBeaconStorage, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let store = RocksDbBeaconStorage::open(tmp.path()).expect("open beacon store");
    (store, tmp)
}

#[test]
fn empty_store_has_no_latest_and_misses_all_reads() {
    let (store, _tmp) = fresh_store();
    assert!(store.latest_committed_epoch().is_none());
    assert!(store.latest_committed().is_none());
    assert!(store.get_beacon_block_by_epoch(Epoch::new(0)).is_none());
    assert!(
        store
            .get_beacon_block_by_hash(BeaconBlockHash::ZERO)
            .is_none()
    );
    assert!(store.get_state_by_epoch(Epoch::new(0)).is_none());
}

#[test]
fn commit_then_read_round_trips_by_epoch_and_hash() {
    let (store, _tmp) = fresh_store();
    let block = make_test_beacon_block(7, b"seven-prev");
    let state = make_test_beacon_state(7, b"seven-state");
    let hash = block.block_hash();
    store.commit_beacon_block(&block, &state);

    let by_epoch = store
        .get_beacon_block_by_epoch(Epoch::new(7))
        .expect("epoch lookup");
    assert_eq!(by_epoch.block_hash(), hash);

    let by_hash = store.get_beacon_block_by_hash(hash).expect("hash lookup");
    assert_eq!(by_hash.epoch(), Epoch::new(7));

    let stored_state = store
        .get_state_by_epoch(Epoch::new(7))
        .expect("state lookup");
    assert_eq!(*stored_state, *state);
}

#[test]
fn latest_committed_returns_paired_block_and_state() {
    let (store, _tmp) = fresh_store();
    store.commit_beacon_block(
        &make_test_beacon_block(3, b"three"),
        &make_test_beacon_state(3, b"three-state"),
    );
    store.commit_beacon_block(
        &make_test_beacon_block(11, b"eleven"),
        &make_test_beacon_state(11, b"eleven-state"),
    );
    store.commit_beacon_block(
        &make_test_beacon_block(5, b"five"),
        &make_test_beacon_state(5, b"five-state"),
    );

    assert_eq!(store.latest_committed_epoch(), Some(Epoch::new(11)));
    let (block, state) = store.latest_committed().expect("latest");
    assert_eq!(block.epoch(), Epoch::new(11));
    assert_eq!(state.current_epoch, Epoch::new(11));
}

#[test]
fn commit_is_idempotent_on_same_epoch_block_and_state() {
    let (store, _tmp) = fresh_store();
    let block = make_test_beacon_block(3, b"same");
    let state = make_test_beacon_state(3, b"same-state");
    let hash = block.block_hash();
    store.commit_beacon_block(&block, &state);
    store.commit_beacon_block(&block, &state);

    assert_eq!(store.latest_committed_epoch(), Some(Epoch::new(3)));
    assert_eq!(
        store.get_beacon_block_by_hash(hash).map(|b| b.epoch()),
        Some(Epoch::new(3))
    );
    let stored_state = store.get_state_by_epoch(Epoch::new(3)).expect("state");
    assert_eq!(*stored_state, *state);
}

/// Persistence round-trip: reopening the directory recovers the
/// committed (block, state) pairs byte-identical to what was
/// committed. `BeaconCoordinator::new` reads `latest_committed()` on
/// restart, so per-epoch fidelity here is what makes warm-restart
/// indistinguishable from cold-start at the FSM layer.
#[test]
fn reopen_recovers_committed_block_and_state_pairs() {
    use std::collections::BTreeMap;
    let tmp = TempDir::new().expect("tempdir");
    let mut expected: BTreeMap<u64, (BeaconBlockHash, _)> = BTreeMap::new();
    {
        let store = RocksDbBeaconStorage::open(tmp.path()).expect("open");
        for epoch in 1u64..=5 {
            let (block, state) = make_test_block_and_state(epoch, format!("e{epoch}").as_bytes());
            expected.insert(epoch, (block.block_hash(), (*state).clone()));
            store.commit_beacon_block(&block, &state);
        }
    }
    let store = RocksDbBeaconStorage::open(tmp.path()).expect("reopen");
    assert_eq!(store.latest_committed_epoch(), Some(Epoch::new(5)));
    let (block, state) = store.latest_committed().expect("latest after reopen");
    assert_eq!(block.epoch(), Epoch::new(5));
    assert_eq!(state.current_epoch, Epoch::new(5));
    assert_eq!(block.block_hash(), expected[&5].0);
    assert_eq!(*state, expected[&5].1);

    for epoch in 1u64..=5 {
        let b = store
            .get_beacon_block_by_epoch(Epoch::new(epoch))
            .expect("block");
        let s = store.get_state_by_epoch(Epoch::new(epoch)).expect("state");
        assert_eq!(b.epoch(), Epoch::new(epoch));
        assert_eq!(s.current_epoch, Epoch::new(epoch));
        assert_eq!(b.block_hash(), expected[&epoch].0);
        assert_eq!(*s, expected[&epoch].1);
    }
}
