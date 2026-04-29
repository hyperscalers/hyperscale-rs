//! Mutable topology state wrapping an immutable [`TopologySnapshot`].
//!
//! `TopologyCoordinator` is owned by `NodeStateMachine`. It produces
//! `Arc<TopologySnapshot>` snapshots that are passed by reference to
//! subsystems and shared with the `io_loop`.

use hyperscale_types::{ShardGroupId, TopologySnapshot, ValidatorId, ValidatorSet};
use std::collections::HashMap;
use std::sync::Arc;

/// Mutable topology state machine.
///
/// Wraps an `Arc<TopologySnapshot>` (immutable query view). Mutations build
/// new snapshots (immutable-replace pattern).
///
/// Only `NodeStateMachine` owns this; subsystems receive `&TopologySnapshot`
/// via `snapshot()`.
#[derive(Debug, Clone)]
pub struct TopologyCoordinator {
    snapshot: Arc<TopologySnapshot>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Constructors
// ═══════════════════════════════════════════════════════════════════════════

impl TopologyCoordinator {
    /// Create a topology with modulo-based shard assignment.
    ///
    /// Validators are assigned to shards by `id % num_shards`.
    #[must_use]
    pub fn new(
        local_validator_id: ValidatorId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            snapshot: Arc::new(TopologySnapshot::new(
                local_validator_id,
                num_shards,
                validator_set,
            )),
        }
    }

    /// Create a topology with an explicit local shard override.
    ///
    /// All validators are placed in `local_shard` regardless of their ID.
    /// Useful for tests where `validator_id % num_shards != desired_shard`.
    #[must_use]
    pub fn with_local_shard(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            snapshot: Arc::new(TopologySnapshot::with_local_shard(
                local_validator_id,
                local_shard,
                num_shards,
                validator_set,
            )),
        }
    }

    /// Create a topology with explicit shard committees.
    ///
    /// Shard membership is taken directly from the provided map.
    #[must_use]
    pub fn with_shard_committees(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>>,
    ) -> Self {
        Self {
            snapshot: Arc::new(TopologySnapshot::with_shard_committees(
                local_validator_id,
                local_shard,
                num_shards,
                global_validator_set,
                shard_committees,
            )),
        }
    }

    /// Get the current immutable snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &Arc<TopologySnapshot> {
        &self.snapshot
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{ValidatorInfo, ValidatorSet, generate_bls_keypair};

    fn make_test_validator(id: u64, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: power,
        }
    }

    fn make_topology(num_validators: u64, local_id: u64) -> TopologyCoordinator {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        TopologyCoordinator::new(ValidatorId(local_id), 1, ValidatorSet::new(validators))
    }

    #[test]
    fn test_snapshot_access() {
        let topology = make_topology(4, 0);
        let snap = topology.snapshot();

        assert_eq!(snap.local_committee_size(), 4);
        assert_eq!(snap.local_validator_id(), ValidatorId(0));
        assert_eq!(snap.local_shard(), ShardGroupId(0));
    }

    #[test]
    fn test_constructors() {
        // with_local_shard
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let topology = TopologyCoordinator::with_local_shard(
            ValidatorId(0),
            ShardGroupId(1),
            2,
            ValidatorSet::new(validators),
        );
        assert_eq!(topology.snapshot().local_shard(), ShardGroupId(1));
        assert_eq!(topology.snapshot().local_committee_size(), 4);

        // with_shard_committees
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(ShardGroupId(0), vec![ValidatorId(0), ValidatorId(2)]);
        committees.insert(ShardGroupId(1), vec![ValidatorId(1), ValidatorId(3)]);

        let topology = TopologyCoordinator::with_shard_committees(
            ValidatorId(0),
            ShardGroupId(0),
            2,
            &vs,
            committees,
        );
        assert_eq!(
            topology
                .snapshot()
                .committee_for_shard(ShardGroupId(0))
                .len(),
            2
        );
    }
}
