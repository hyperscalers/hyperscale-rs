//! Per-shard committee config and global consensus tuning, plus per-validator
//! state used by the epoch shuffler.

use crate::{Bls12381G1PublicKey, ShardGroupId, ValidatorId};
use sbor::prelude::*;
use std::collections::HashMap;

use crate::topology::epoch::{DEFAULT_EPOCH_LENGTH, ValidatorShardState};

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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Update rating based on epoch performance using EMA with 0.9 decay.
    /// `new_rating` = (current * 0.9) + (`epoch_performance` * 0.1)
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
    /// Globally unique validator identifier.
    pub validator_id: ValidatorId,
    /// BLS public key for vote verification.
    pub public_key: Bls12381G1PublicKey,
    /// Voting weight for this validator.
    pub voting_power: u64,
    /// Performance score driving shard reassignment.
    pub rating: ValidatorRating,
    /// Shard the validator is currently committee-member of.
    pub current_shard: ShardGroupId,
    /// Lifecycle state within `current_shard` (Active / Waiting / etc.).
    pub state: ValidatorShardState,
    /// How many epochs this validator has been active in current shard.
    pub epochs_in_shard: u64,
}

impl GlobalValidatorInfo {
    /// Create new global validator info.
    #[must_use]
    pub fn new(
        validator_id: ValidatorId,
        public_key: Bls12381G1PublicKey,
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
    #[must_use]
    pub fn can_participate(&self) -> bool {
        matches!(self.state, ValidatorShardState::Active)
    }

    /// Check if this validator is eligible for shuffling.
    #[must_use]
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
    #[must_use]
    pub fn new(validators: Vec<ValidatorId>, voting_powers: &HashMap<ValidatorId, u64>) -> Self {
        let total_voting_power = validators.iter().filter_map(|v| voting_powers.get(v)).sum();
        Self {
            active_validators: validators,
            total_voting_power,
            target_size: 100, // Default target
        }
    }

    /// Check if this committee has enough validators for BFT.
    #[must_use]
    pub fn has_minimum_validators(&self, min: usize) -> bool {
        self.active_validators.len() >= min
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
    #[must_use]
    pub fn shuffle_count(&self, committee_size: usize) -> usize {
        let pct = usize::try_from(self.shuffle_percentage).unwrap_or(usize::MAX);
        (committee_size * pct / 100).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
