//! Epoch-related types for global consensus.
//!
//! An epoch is a time period during which shard membership is stable.
//! At epoch boundaries, validators may be shuffled between shards.

use crate::{BlockHeight, Hash, PublicKey, ShardGroupId, ValidatorId, ValidatorSet};
use sbor::prelude::*;
use std::collections::HashMap;
use std::fmt;

/// Epoch identifier (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct EpochId(pub u64);

impl EpochId {
    /// Genesis epoch.
    pub const GENESIS: Self = EpochId(0);

    /// Get the next epoch.
    pub fn next(self) -> Self {
        EpochId(self.0 + 1)
    }

    /// Get the previous epoch (returns None if at genesis).
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

/// Validator rating for SPOS-style shuffling probability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ValidatorRating {
    /// Current rating (0-100, starting at 50).
    pub score: u64,
    /// Blocks proposed successfully.
    pub blocks_proposed: u64,
    /// Blocks missed when should have proposed.
    pub blocks_missed: u64,
}

impl Default for ValidatorRating {
    fn default() -> Self {
        Self {
            score: 50,
            blocks_proposed: 0,
            blocks_missed: 0,
        }
    }
}

impl ValidatorRating {
    /// Create a new rating with default score.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update rating based on epoch performance using EMA with 0.9 decay.
    /// new_rating = (current * 0.9) + (epoch_performance * 0.1)
    pub fn update_with_epoch_performance(&mut self, epoch_performance: u64) {
        // EMA: new = old * 0.9 + new * 0.1
        // Using integer math: new = (old * 9 + new) / 10
        self.score = (self.score * 9 + epoch_performance) / 10;
        // Clamp to valid range
        self.score = self.score.clamp(0, 100);
    }

    /// Apply penalty for equivocation.
    pub fn apply_equivocation_penalty(&mut self) {
        self.score = self.score.saturating_sub(50);
    }

    /// Apply penalty for missed proposals (>50%).
    pub fn apply_missed_proposal_penalty(&mut self) {
        self.score = self.score.saturating_sub(10);
    }

    /// Apply penalty for sync failure.
    pub fn apply_sync_failure_penalty(&mut self) {
        self.score = self.score.saturating_sub(10);
    }
}

/// Extended validator info for global consensus.
#[derive(Debug, Clone, BasicSbor)]
pub struct GlobalValidatorInfo {
    pub validator_id: ValidatorId,
    pub public_key: PublicKey,
    pub voting_power: u64,
    pub rating: ValidatorRating,
    pub current_shard: ShardGroupId,
    pub state: ValidatorShardState,
    /// How many epochs this validator has been active in current shard.
    pub epochs_in_shard: u64,
}

impl GlobalValidatorInfo {
    /// Create new global validator info.
    pub fn new(
        validator_id: ValidatorId,
        public_key: PublicKey,
        voting_power: u64,
        shard: ShardGroupId,
    ) -> Self {
        Self {
            validator_id,
            public_key,
            voting_power,
            rating: ValidatorRating::default(),
            current_shard: shard,
            state: ValidatorShardState::Active,
            epochs_in_shard: 0,
        }
    }

    /// Check if this validator can participate in consensus.
    pub fn can_participate(&self) -> bool {
        matches!(self.state, ValidatorShardState::Active)
    }

    /// Check if this validator is eligible for shuffling.
    pub fn is_shuffle_eligible(&self, min_epochs: u64) -> bool {
        self.state == ValidatorShardState::Active && self.epochs_in_shard >= min_epochs
    }
}

/// Per-shard committee configuration.
#[derive(Debug, Clone, BasicSbor)]
pub struct ShardCommitteeConfig {
    /// Ordered list of active (eligible) validators.
    pub active_validators: Vec<ValidatorId>,

    /// Total voting power of active validators.
    pub total_voting_power: u64,

    /// Target size for this shard (may differ during splitting).
    pub target_size: usize,
}

impl ShardCommitteeConfig {
    /// Create a new shard committee config.
    pub fn new(validators: Vec<ValidatorId>, voting_powers: &HashMap<ValidatorId, u64>) -> Self {
        let total_voting_power = validators.iter().filter_map(|v| voting_powers.get(v)).sum();
        Self {
            active_validators: validators,
            total_voting_power,
            target_size: 100, // Default target
        }
    }

    /// Check if this committee has enough validators for BFT.
    pub fn has_minimum_validators(&self, min: usize) -> bool {
        self.active_validators.len() >= min
    }
}

/// Shard configuration with hash range for dynamic topology.
#[derive(Debug, Clone, BasicSbor)]
pub struct ShardHashRange {
    pub shard_id: ShardGroupId,
    /// Inclusive start of hash range.
    pub hash_range_start: u64,
    /// Exclusive end of hash range.
    pub hash_range_end: u64,
}

impl ShardHashRange {
    /// Check if a hash value falls within this range.
    pub fn contains(&self, hash_value: u64) -> bool {
        hash_value >= self.hash_range_start && hash_value < self.hash_range_end
    }

    /// Split this range into two equal halves.
    pub fn split(&self, new_shard_id: ShardGroupId) -> (ShardHashRange, ShardHashRange) {
        let midpoint = self.hash_range_start + (self.hash_range_end - self.hash_range_start) / 2;
        (
            ShardHashRange {
                shard_id: self.shard_id,
                hash_range_start: self.hash_range_start,
                hash_range_end: midpoint,
            },
            ShardHashRange {
                shard_id: new_shard_id,
                hash_range_start: midpoint,
                hash_range_end: self.hash_range_end,
            },
        )
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
    /// Maps ShardGroupId -> ordered list of validators in that shard.
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

    /// Expected end heights (start + EPOCH_LENGTH).
    pub expected_end_heights: HashMap<ShardGroupId, BlockHeight>,

    /// Hash ranges for each shard (for NodeId -> Shard mapping).
    pub shard_ranges: Vec<ShardHashRange>,
}

impl EpochConfig {
    /// Create a genesis epoch configuration.
    pub fn genesis(num_shards: u64, validator_set: ValidatorSet) -> Self {
        let mut shard_committees = HashMap::new();
        let mut start_heights = HashMap::new();
        let mut expected_end_heights = HashMap::new();
        let mut shard_ranges = Vec::new();

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

        // Create hash ranges (divide u64 space evenly)
        let range_size = u64::MAX / num_shards;
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id);

            // Committee config
            let validators = shard_validators.remove(&shard).unwrap_or_default();
            shard_committees.insert(shard, ShardCommitteeConfig::new(validators, &voting_powers));

            // Heights
            start_heights.insert(shard, BlockHeight(0));
            expected_end_heights.insert(shard, BlockHeight(DEFAULT_EPOCH_LENGTH));

            // Hash range
            let start = shard_id * range_size;
            let end = if shard_id == num_shards - 1 {
                u64::MAX
            } else {
                (shard_id + 1) * range_size
            };
            shard_ranges.push(ShardHashRange {
                shard_id: shard,
                hash_range_start: start,
                hash_range_end: end,
            });
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
            shard_ranges,
        }
    }

    /// Find which shard a validator belongs to (returns None if not found).
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
    pub fn is_validator_waiting(&self, validator_id: ValidatorId, shard: ShardGroupId) -> bool {
        self.waiting_validators
            .get(&shard)
            .map(|waiting| waiting.contains(&validator_id))
            .unwrap_or(false)
    }

    /// Get the committee for a shard.
    pub fn committee_for_shard(&self, shard: ShardGroupId) -> Option<&ShardCommitteeConfig> {
        self.shard_committees.get(&shard)
    }

    /// Get the hash range for a shard.
    pub fn hash_range_for_shard(&self, shard: ShardGroupId) -> Option<&ShardHashRange> {
        self.shard_ranges.iter().find(|r| r.shard_id == shard)
    }

    /// Determine which shard a NodeId belongs to based on hash ranges.
    pub fn shard_for_node_id(&self, node_id: &crate::NodeId) -> ShardGroupId {
        let hash = blake3::hash(&node_id.0);
        let bytes = hash.as_bytes();
        let hash_value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);

        for range in &self.shard_ranges {
            if range.contains(hash_value) {
                return range.shard_id;
            }
        }

        // Fallback to modulo (should never happen if ranges are set up correctly)
        ShardGroupId(hash_value % self.num_shards)
    }
}

/// Global consensus configuration.
#[derive(Debug, Clone, BasicSbor)]
pub struct GlobalConsensusConfig {
    /// Epoch length in shard blocks.
    pub epoch_length: u64,

    /// Fraction of validators to shuffle per epoch (e.g., 0.2 = 20%).
    /// Stored as percentage (0-100) to avoid floating point.
    pub shuffle_percentage: u64,

    /// Minimum validators per shard.
    pub min_validators_per_shard: usize,

    /// Maximum validators per shard.
    pub max_validators_per_shard: usize,

    /// Minimum epochs before a validator can be shuffled.
    pub min_epochs_before_shuffle: u64,
}

impl Default for GlobalConsensusConfig {
    fn default() -> Self {
        Self {
            epoch_length: DEFAULT_EPOCH_LENGTH,
            shuffle_percentage: 20, // 20% = 1/5
            min_validators_per_shard: 4,
            max_validators_per_shard: 400,
            min_epochs_before_shuffle: 1,
        }
    }
}

impl GlobalConsensusConfig {
    /// Calculate how many validators to shuffle given a committee size.
    pub fn shuffle_count(&self, committee_size: usize) -> usize {
        (committee_size * self.shuffle_percentage as usize / 100).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, ValidatorInfo};

    fn make_test_validator(id: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: KeyPair::generate_ed25519().public_key(),
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
    fn test_validator_rating_ema() {
        let mut rating = ValidatorRating::new();
        assert_eq!(rating.score, 50);

        // Good performance (100) should increase rating
        rating.update_with_epoch_performance(100);
        assert_eq!(rating.score, 55); // (50 * 9 + 100) / 10 = 55

        // Poor performance (0) should decrease rating
        rating.update_with_epoch_performance(0);
        assert_eq!(rating.score, 49); // (55 * 9 + 0) / 10 = 49
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
    fn test_shard_hash_range_split() {
        let range = ShardHashRange {
            shard_id: ShardGroupId(0),
            hash_range_start: 0,
            hash_range_end: 1000,
        };

        let (left, right) = range.split(ShardGroupId(1));

        assert_eq!(left.hash_range_start, 0);
        assert_eq!(left.hash_range_end, 500);
        assert_eq!(right.hash_range_start, 500);
        assert_eq!(right.hash_range_end, 1000);
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
