use std::sync::Arc;

use hyperscale_storage::test_helpers::{make_test_beacon_block, make_test_beacon_state};
use hyperscale_storage::{BeaconChainReader, BeaconChainWriter};
use hyperscale_types::{BeaconBlockHash, BeaconState, Epoch};

use super::core::SimBeaconStorage;

#[test]
fn empty_store_has_no_latest_and_misses_all_reads() {
    let store = SimBeaconStorage::new();
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
    let store = SimBeaconStorage::new();
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
    let store = SimBeaconStorage::new();
    store.commit_beacon_block(
        &make_test_beacon_block(3, b"three"),
        &make_test_beacon_state(3, b"three-state"),
    );
    store.commit_beacon_block(
        &make_test_beacon_block(11, b"eleven"),
        &make_test_beacon_state(11, b"eleven-state"),
    );
    // Earlier-epoch insert doesn't move the latest pointer.
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
fn states_since_walks_down_to_the_floor_oldest_first() {
    let store = SimBeaconStorage::new();
    for e in 1..=5u64 {
        store.commit_beacon_block(
            &make_test_beacon_block(e, b"block"),
            &make_test_beacon_state(e, b"state"),
        );
    }

    let epochs = |states: Vec<Arc<BeaconState>>| {
        states
            .iter()
            .map(|s| s.current_epoch.inner())
            .collect::<Vec<_>>()
    };
    // A floor below the chain's start stops at the first absent epoch
    // (epoch 0 was never committed) rather than walking past it.
    assert_eq!(
        epochs(store.states_since(Epoch::new(0))),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(epochs(store.states_since(Epoch::new(4))), vec![4, 5]);
    // A floor above the latest still yields the latest state.
    assert_eq!(epochs(store.states_since(Epoch::new(9))), vec![5]);
}

#[test]
fn states_since_empty_chain_is_empty() {
    let store = SimBeaconStorage::new();
    assert!(store.states_since(Epoch::new(0)).is_empty());
}

#[test]
fn commit_is_idempotent_on_same_epoch_block_and_state() {
    let store = SimBeaconStorage::new();
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
