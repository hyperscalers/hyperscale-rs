//! Epoch identifier and per-epoch configuration.
//!
//! An epoch is a time period during which shard membership is stable.
//! At epoch boundaries, validators may be shuffled between shards.

use crate::{BlockHeight, Hash, ShardGroupId, ValidatorId, ValidatorSet};
use sbor::prelude::*;
use std::collections::HashMap;
use std::fmt;

use crate::topology::consensus_config::ShardCommitteeConfig;

/// Epoch identifier (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Genesis epoch.
    pub const GENESIS: Self = EpochId(0);

    /// Get the next epoch.
    #[must_use]
    pub fn next(self) -> Self {
        EpochId(self.0 + 1)
    }

    /// Get the previous epoch (returns None if at genesis).
    #[must_use]
    pub fn prev(self) -> Option<Self> {
        if self.0 > 0 {
            Some(EpochId(self.0 - 1))
        } else {
            None
        }
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Epoch({})", self.0)
    }
}

/// Default epoch length in shard-level blocks.
/// Configurable per-deployment. Example: 14400 blocks ≈ 24 hours at 6s blocks.
pub const DEFAULT_EPOCH_LENGTH: u64 = 14400;

/// Validator lifecycle states for shuffling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor, Default)]
pub enum ValidatorShardState {
    /// Actively participating in consensus for this shard.
    #[default]
    Active,

    /// Syncing to this shard, will become Active next epoch.
    /// Cannot vote, but receives all messages for sync.
    Waiting,

    /// Being shuffled out, still active this epoch but leaving next.
    ShufflingOut,

    /// Leaving the network (unbonding).
    Leaving,
}

impl fmt::Display for ValidatorShardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidatorShardState::Active => write!(f, "Active"),
            ValidatorShardState::Waiting => write!(f, "Waiting"),
            ValidatorShardState::ShufflingOut => write!(f, "ShufflingOut"),
            ValidatorShardState::Leaving => write!(f, "Leaving"),
        }
    }
}

/// Configuration for a single epoch.
#[derive(Debug, Clone, BasicSbor)]
pub struct EpochConfig {
    /// Epoch identifier.
    pub epoch_id: EpochId,

    /// Number of shards in this epoch.
    pub num_shards: u64,

    /// Shard committee assignments.
    /// Maps `ShardGroupId` -> ordered list of validators in that shard.
    pub shard_committees: HashMap<ShardGroupId, ShardCommitteeConfig>,

    /// Validators in the "waiting" state (syncing to new shard).
    /// These can observe but not vote until next epoch.
    pub waiting_validators: HashMap<ShardGroupId, Vec<ValidatorId>>,

    /// Global validator set for this epoch.
    pub validator_set: ValidatorSet,

    /// Randomness seed used for this epoch's configuration.
    /// Derived from previous epoch's final block signatures.
    pub randomness_seed: Hash,

    /// First shard-level block height of this epoch (per shard).
    pub start_heights: HashMap<ShardGroupId, BlockHeight>,

    /// Expected end heights (start + `EPOCH_LENGTH`).
    pub expected_end_heights: HashMap<ShardGroupId, BlockHeight>,
}

impl EpochConfig {
    /// Create a genesis epoch configuration.
    #[must_use]
    pub fn genesis(num_shards: u64, validator_set: ValidatorSet) -> Self {
        let mut shard_committees = HashMap::new();
        let mut start_heights = HashMap::new();
        let mut expected_end_heights = HashMap::new();

        // Distribute validators across shards using modulo
        let mut shard_validators: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
        for v in &validator_set.validators {
            let shard = ShardGroupId(v.validator_id.0 % num_shards);
            shard_validators
                .entry(shard)
                .or_default()
                .push(v.validator_id);
        }

        // Build voting power map
        let voting_powers: HashMap<ValidatorId, u64> = validator_set
            .validators
            .iter()
            .map(|v| (v.validator_id, v.voting_power))
            .collect();

        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id);

            // Committee config
            let validators = shard_validators.remove(&shard).unwrap_or_default();
            shard_committees.insert(shard, ShardCommitteeConfig::new(validators, &voting_powers));

            // Heights
            start_heights.insert(shard, BlockHeight(0));
            expected_end_heights.insert(shard, BlockHeight(DEFAULT_EPOCH_LENGTH));
        }

        Self {
            epoch_id: EpochId::GENESIS,
            num_shards,
            shard_committees,
            waiting_validators: HashMap::new(),
            validator_set,
            randomness_seed: Hash::ZERO,
            start_heights,
            expected_end_heights,
        }
    }

    /// Find which shard a validator belongs to (returns None if not found).
    #[must_use]
    pub fn find_validator_shard(&self, validator_id: ValidatorId) -> Option<ShardGroupId> {
        for (shard, committee) in &self.shard_committees {
            if committee.active_validators.contains(&validator_id) {
                return Some(*shard);
            }
        }
        // Also check waiting validators
        for (shard, waiting) in &self.waiting_validators {
            if waiting.contains(&validator_id) {
                return Some(*shard);
            }
        }
        None
    }

    /// Check if a validator is in waiting state for a shard.
    #[must_use]
    pub fn is_validator_waiting(&self, validator_id: ValidatorId, shard: ShardGroupId) -> bool {
        self.waiting_validators
            .get(&shard)
            .is_some_and(|waiting| waiting.contains(&validator_id))
    }

    /// Get the committee for a shard.
    #[must_use]
    pub fn committee_for_shard(&self, shard: ShardGroupId) -> Option<&ShardCommitteeConfig> {
        self.shard_committees.get(&shard)
    }

    /// Determine which shard a `NodeId` belongs to (hash-modulo).
    #[must_use]
    pub fn shard_for_node_id(&self, node_id: &crate::NodeId) -> ShardGroupId {
        crate::shard_for_node(node_id, self.num_shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ValidatorInfo, generate_bls_keypair};

    fn make_test_validator(id: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: 1,
        }
    }

    #[test]
    fn test_epoch_id_operations() {
        let epoch = EpochId(5);
        assert_eq!(epoch.next(), EpochId(6));
        assert_eq!(epoch.prev(), Some(EpochId(4)));
        assert_eq!(EpochId::GENESIS.prev(), None);
    }

    #[test]
    fn test_genesis_epoch_config() {
        let validators: Vec<_> = (0..8).map(make_test_validator).collect();
        let validator_set = ValidatorSet::new(validators);

        let config = EpochConfig::genesis(2, validator_set);

        assert_eq!(config.epoch_id, EpochId::GENESIS);
        assert_eq!(config.num_shards, 2);
        assert_eq!(config.shard_committees.len(), 2);

        // Check that validators are distributed (0,2,4,6 to shard 0; 1,3,5,7 to shard 1)
        let shard0 = config.committee_for_shard(ShardGroupId(0)).unwrap();
        let shard1 = config.committee_for_shard(ShardGroupId(1)).unwrap();
        assert_eq!(shard0.active_validators.len(), 4);
        assert_eq!(shard1.active_validators.len(), 4);
    }

    #[test]
    fn test_find_validator_shard() {
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
        let validator_set = ValidatorSet::new(validators);

        let config = EpochConfig::genesis(2, validator_set);

        // Validator 0 should be in shard 0 (0 % 2 = 0)
        assert_eq!(
            config.find_validator_shard(ValidatorId(0)),
            Some(ShardGroupId(0))
        );
        // Validator 1 should be in shard 1 (1 % 2 = 1)
        assert_eq!(
            config.find_validator_shard(ValidatorId(1)),
            Some(ShardGroupId(1))
        );
        // Unknown validator
        assert_eq!(config.find_validator_shard(ValidatorId(100)), None);
    }
}
