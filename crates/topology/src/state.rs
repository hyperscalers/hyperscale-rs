//! Mutable topology state wrapping an immutable [`TopologySnapshot`].
//!
//! `TopologyState` is owned by `NodeStateMachine`. It holds epoch lifecycle
//! state (`next_epoch`) and produces `Arc<TopologySnapshot>` snapshots that
//! are passed by reference to subsystems and shared with the `io_loop`.

use hyperscale_types::{
    EpochConfig, ShardGroupId, TopologySnapshot, TopologySnapshotError, ValidatorId, ValidatorSet,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Errors from topology operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologyError {
    /// No next epoch configuration available for transition.
    #[error("no next epoch configuration available")]
    NoNextEpoch,

    /// Validator not found in epoch configuration.
    #[error("validator {0:?} not found in epoch configuration")]
    ValidatorNotInEpoch(ValidatorId),
}

impl From<TopologySnapshotError> for TopologyError {
    fn from(err: TopologySnapshotError) -> Self {
        match err {
            TopologySnapshotError::ValidatorNotInEpoch(v) => TopologyError::ValidatorNotInEpoch(v),
        }
    }
}

/// Mutable topology state machine.
///
/// Wraps an `Arc<TopologySnapshot>` (immutable query view) plus epoch lifecycle
/// state. Mutations build new snapshots (immutable-replace pattern).
///
/// Only `NodeStateMachine` owns this; subsystems receive `&TopologySnapshot`
/// via `snapshot()`.
#[derive(Debug, Clone)]
pub struct TopologyState {
    snapshot: Arc<TopologySnapshot>,
    next_epoch: Option<EpochConfig>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Constructors
// ═══════════════════════════════════════════════════════════════════════════

impl TopologyState {
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
            next_epoch: None,
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
            next_epoch: None,
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
            next_epoch: None,
        }
    }

    /// Create from an epoch configuration (production path).
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError`] if the epoch configuration is invalid
    /// (e.g. a shard committee references unknown validators).
    pub fn from_epoch_config(
        local_validator_id: ValidatorId,
        epoch: &EpochConfig,
    ) -> Result<Self, TopologyError> {
        Ok(Self {
            snapshot: Arc::new(TopologySnapshot::from_epoch_config(
                local_validator_id,
                epoch,
            )?),
            next_epoch: None,
        })
    }

    /// Get the current immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &Arc<TopologySnapshot> {
        &self.snapshot
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Mutation methods (&mut self)
// ═══════════════════════════════════════════════════════════════════════════

impl TopologyState {
    /// Set the next epoch configuration (called when global consensus finalizes it).
    pub fn set_next_epoch(&mut self, next: EpochConfig) {
        self.next_epoch = Some(next);
    }

    /// Transition to the next epoch, building a fresh snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`TopologyError::NoNextEpoch`] if no next epoch has been
    /// set, or any [`TopologyError`] from rebuilding the snapshot.
    pub fn transition_to_next_epoch(&mut self) -> Result<(), TopologyError> {
        let next = self.next_epoch.take().ok_or(TopologyError::NoNextEpoch)?;
        self.snapshot = Arc::new(TopologySnapshot::from_epoch_config(
            self.snapshot.local_validator_id(),
            &next,
        )?);
        Ok(())
    }

    /// Mark a shard as splitting (entering grace period).
    ///
    /// Builds a new snapshot with the shard marked.
    pub fn mark_shard_splitting(&mut self, shard: ShardGroupId) {
        self.snapshot = Arc::new(self.snapshot.with_shard_splitting(shard));
    }

    /// Clear the splitting state for a shard.
    ///
    /// Builds a new snapshot with the shard unmarked.
    pub fn clear_shard_splitting(&mut self, shard: ShardGroupId) {
        self.snapshot = Arc::new(self.snapshot.without_shard_splitting(shard));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeight, EpochId, ValidatorInfo, ValidatorSet, generate_bls_keypair,
    };

    fn make_test_validator(id: u64, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: power,
        }
    }

    fn make_topology(num_validators: u64, local_id: u64) -> TopologyState {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        TopologyState::new(ValidatorId(local_id), 1, ValidatorSet::new(validators))
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
    fn test_epoch_transition() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let epoch0 = EpochConfig::genesis(2, vs.clone());

        let mut topology = TopologyState::from_epoch_config(ValidatorId(0), &epoch0).unwrap();
        assert_eq!(topology.snapshot().current_epoch(), EpochId::GENESIS);

        // Transition without setting next epoch should fail.
        assert!(topology.transition_to_next_epoch().is_err());

        // Set next epoch and transition.
        let mut epoch1 = EpochConfig::genesis(2, vs);
        epoch1.epoch_id = EpochId(1);

        topology.set_next_epoch(epoch1);
        assert!(topology.transition_to_next_epoch().is_ok());
        assert_eq!(topology.snapshot().current_epoch(), EpochId(1));
    }

    #[test]
    fn test_shard_splitting() {
        let mut topology = make_topology(4, 0);

        assert!(!topology.snapshot().is_shard_splitting(ShardGroupId(0)));

        topology.mark_shard_splitting(ShardGroupId(0));
        assert!(topology.snapshot().is_shard_splitting(ShardGroupId(0)));

        topology.clear_shard_splitting(ShardGroupId(0));
        assert!(!topology.snapshot().is_shard_splitting(ShardGroupId(0)));
    }

    #[test]
    fn test_constructors() {
        // with_local_shard
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let topology = TopologyState::with_local_shard(
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

        let topology = TopologyState::with_shard_committees(
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

    #[test]
    fn test_from_epoch_config() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let epoch = EpochConfig::genesis(2, vs);

        let topology = TopologyState::from_epoch_config(ValidatorId(0), &epoch).unwrap();
        assert_eq!(topology.snapshot().local_shard(), ShardGroupId(0));
        assert_eq!(topology.snapshot().num_shards(), 2);
        assert_eq!(topology.snapshot().current_epoch(), EpochId::GENESIS);
        assert!(topology.snapshot().can_participate_in_consensus());
    }

    #[test]
    fn test_from_epoch_config_unknown_validator() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let epoch = EpochConfig::genesis(2, vs);

        let result = TopologyState::from_epoch_config(ValidatorId(100), &epoch);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TopologyError::ValidatorNotInEpoch(ValidatorId(100))
        );
    }

    #[test]
    fn test_epoch_defaults_for_static_constructor() {
        let topology = make_topology(4, 0);
        let snap = topology.snapshot();

        assert_eq!(snap.current_epoch(), EpochId::GENESIS);
        assert_eq!(snap.epoch_end_height(), BlockHeight(u64::MAX));
        assert!(snap.can_participate_in_consensus());
        assert!(!snap.is_shard_splitting(ShardGroupId(0)));
    }
}
