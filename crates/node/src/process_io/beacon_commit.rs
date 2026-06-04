//! Process-scoped dedup for beacon-block commits.
//!
//! Every co-hosted vnode runs its own `BeaconCoordinator`, and they all
//! converge on the same committed beacon block — so each independently
//! emits `Action::CommitBeaconBlock` for it. `BeaconCommitCoordinator`
//! is the first leg of the three-layer dedup (this in-flight set +
//! `RocksDbBeaconStorage::commit_lock` + idempotent `commit_beacon_block`):
//! it lets only the first vnode to reach a given `(epoch, hash)` perform
//! the storage write, so the rest skip before the round-trip rather than
//! bottoming out as idempotent no-ops.
//!
//! Per-vnode `BeaconBlockPersisted` feedback is emitted by the shard loop
//! independently of this dedup, so every vnode still learns the beacon
//! advanced even when its own commit was deduped.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use hyperscale_storage::BeaconStorage;
use hyperscale_types::{BeaconBlockHash, BeaconState, CertifiedBeaconBlock, Epoch, Verified};

/// Serializes the redundant per-vnode beacon commits down to one storage
/// write per `(epoch, hash)`. Process-scoped; one per host, shared across
/// every co-hosted vnode's commit handler.
pub struct BeaconCommitCoordinator {
    inner: Mutex<CommitDedup>,
}

struct CommitDedup {
    /// Highest epoch already written to storage. Anything at or below it
    /// is on disk, so a late or lagging re-submission skips without a
    /// round-trip.
    committed_through: Option<Epoch>,
    /// `(epoch, hash)` a vnode is writing right now — holds off a second
    /// concurrent writer until `committed_through` advances past it.
    in_flight: HashSet<(Epoch, BeaconBlockHash)>,
}

impl BeaconCommitCoordinator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CommitDedup {
                committed_through: None,
                in_flight: HashSet::new(),
            }),
        }
    }

    /// Commit `block` + `state` to `storage` unless a co-hosted vnode has
    /// already written (or is mid-write on) this `(epoch, hash)`. Returns
    /// `true` iff this call performed the storage write.
    ///
    /// The storage round-trip runs with no coordinator lock held —
    /// `BeaconStorage` serializes the actual write under its own
    /// `commit_lock`, and holding this lock across the write would
    /// needlessly serialize every co-hosted vnode here too.
    pub fn commit(
        &self,
        storage: &Arc<dyn BeaconStorage>,
        block: &Arc<Verified<CertifiedBeaconBlock>>,
        state: &BeaconState,
    ) -> bool {
        let epoch = block.epoch();
        let key = (epoch, block.block_hash());
        {
            let mut dedup = self.inner.lock().expect("beacon commit dedup poisoned");
            if dedup
                .committed_through
                .is_some_and(|through| epoch <= through)
            {
                return false;
            }
            if !dedup.in_flight.insert(key) {
                return false;
            }
        }
        storage.commit_beacon_block(block, state);
        let mut dedup = self.inner.lock().expect("beacon commit dedup poisoned");
        dedup.in_flight.remove(&key);
        dedup.committed_through = Some(dedup.committed_through.map_or(epoch, |c| c.max(epoch)));
        true
    }
}

impl Default for BeaconCommitCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::test_helpers::{make_test_beacon_block, make_test_beacon_state};
    use hyperscale_storage_memory::SimBeaconStorage;

    use super::*;

    fn storage() -> Arc<dyn BeaconStorage> {
        Arc::new(SimBeaconStorage::new())
    }

    #[test]
    fn first_commit_writes_and_a_repeat_of_the_same_block_is_deduped() {
        let coord = BeaconCommitCoordinator::new();
        let storage = storage();
        let block = make_test_beacon_block(4, b"four");
        let state = make_test_beacon_state(4, b"four");

        assert!(
            coord.commit(&storage, &block, &state),
            "first submission writes"
        );
        assert!(
            !coord.commit(&storage, &block, &state),
            "the same (epoch, hash) from another vnode is deduped"
        );
    }

    #[test]
    fn epoch_at_or_below_the_watermark_is_deduped() {
        let coord = BeaconCommitCoordinator::new();
        let storage = storage();
        coord.commit(
            &storage,
            &make_test_beacon_block(7, b"seven"),
            &make_test_beacon_state(7, b"seven"),
        );

        // A lagging vnode re-submitting an already-committed epoch skips.
        assert!(!coord.commit(
            &storage,
            &make_test_beacon_block(7, b"seven"),
            &make_test_beacon_state(7, b"seven"),
        ));
        assert!(!coord.commit(
            &storage,
            &make_test_beacon_block(3, b"three"),
            &make_test_beacon_state(3, b"three"),
        ));
    }

    #[test]
    fn a_higher_epoch_writes() {
        let coord = BeaconCommitCoordinator::new();
        let storage = storage();
        assert!(coord.commit(
            &storage,
            &make_test_beacon_block(1, b"one"),
            &make_test_beacon_state(1, b"one"),
        ));
        assert!(
            coord.commit(
                &storage,
                &make_test_beacon_block(2, b"two"),
                &make_test_beacon_state(2, b"two"),
            ),
            "the next epoch advances past the watermark and writes"
        );
    }
}
