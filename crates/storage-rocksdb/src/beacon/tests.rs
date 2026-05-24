use hyperscale_storage::test_helpers::make_test_beacon_block as block_at;
use hyperscale_storage::{BeaconChainReader, BeaconChainWriter};
use hyperscale_types::{BeaconBlockHash, Slot};
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
    assert!(store.latest_committed_slot().is_none());
    assert!(store.get_beacon_block_by_slot(Slot::new(0)).is_none());
    assert!(
        store
            .get_beacon_block_by_hash(BeaconBlockHash::ZERO)
            .is_none()
    );
    assert_eq!(store.iter_beacon_blocks_from(Slot::new(0)).count(), 0);
}

#[test]
fn commit_then_read_round_trips_by_slot_and_hash() {
    let (store, _tmp) = fresh_store();
    let block = block_at(7, b"seven-prev");
    let hash = block.block_hash();
    store.commit_beacon_block(&block);

    let by_slot = store
        .get_beacon_block_by_slot(Slot::new(7))
        .expect("slot lookup");
    assert_eq!(by_slot.block_hash(), hash);

    let by_hash = store.get_beacon_block_by_hash(hash).expect("hash lookup");
    assert_eq!(by_hash.slot(), Slot::new(7));
}

#[test]
fn latest_committed_slot_tracks_the_max_committed() {
    let (store, _tmp) = fresh_store();
    assert!(store.latest_committed_slot().is_none());
    store.commit_beacon_block(&block_at(3, b"a"));
    assert_eq!(store.latest_committed_slot(), Some(Slot::new(3)));
    store.commit_beacon_block(&block_at(11, b"b"));
    assert_eq!(store.latest_committed_slot(), Some(Slot::new(11)));
    store.commit_beacon_block(&block_at(5, b"c"));
    assert_eq!(store.latest_committed_slot(), Some(Slot::new(11)));
}

#[test]
fn iter_returns_blocks_in_ascending_slot_order_from_the_floor() {
    let (store, _tmp) = fresh_store();
    for slot in [4u64, 1, 9, 2, 7] {
        store.commit_beacon_block(&block_at(slot, format!("b{slot}").as_bytes()));
    }
    let slots: Vec<u64> = store
        .iter_beacon_blocks_from(Slot::new(2))
        .map(|b| b.slot().inner())
        .collect();
    assert_eq!(slots, vec![2, 4, 7, 9]);
}

#[test]
fn commit_is_idempotent_on_same_slot_and_hash() {
    let (store, _tmp) = fresh_store();
    let block = block_at(3, b"same");
    let hash = block.block_hash();
    store.commit_beacon_block(&block);
    store.commit_beacon_block(&block);
    assert_eq!(store.iter_beacon_blocks_from(Slot::new(0)).count(), 1);
    assert_eq!(
        store.get_beacon_block_by_hash(hash).map(|b| b.slot()),
        Some(Slot::new(3))
    );
}

/// Persistence round-trip: reopening the directory recovers the
/// committed chain. Phase B's `BeaconCoordinator` relies on this for
/// startup replay of `BeaconState` from genesis.
#[test]
fn reopen_recovers_committed_blocks() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let store = RocksDbBeaconStorage::open(tmp.path()).expect("open");
        for slot in 1u64..=5 {
            store.commit_beacon_block(&block_at(slot, format!("b{slot}").as_bytes()));
        }
    }
    let store = RocksDbBeaconStorage::open(tmp.path()).expect("reopen");
    assert_eq!(store.latest_committed_slot(), Some(Slot::new(5)));
    let slots: Vec<u64> = store
        .iter_beacon_blocks_from(Slot::new(0))
        .map(|b| b.slot().inner())
        .collect();
    assert_eq!(slots, vec![1, 2, 3, 4, 5]);
}
