//! Validator set types.

use crate::{Bls12381G1PublicKey, ValidatorId};
use sbor::prelude::*;

/// Information about a validator.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ValidatorInfo {
    /// Unique identifier for this validator.
    pub validator_id: ValidatorId,

    /// Public key for signature verification (BLS for aggregatable consensus).
    pub public_key: Bls12381G1PublicKey,

    /// Voting power (stake weight).
    pub voting_power: u64,
}

/// A set of validators.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor, Default)]
pub struct ValidatorSet {
    /// The validators, ordered by validator ID.
    pub validators: Vec<ValidatorInfo>,
}

impl ValidatorSet {
    /// Create a new validator set.
    pub fn new(mut validators: Vec<ValidatorInfo>) -> Self {
        validators.sort_by_key(|v| v.validator_id);
        Self { validators }
    }

    /// Get the number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get total voting power.
    pub fn total_voting_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    /// Find a validator by ID.
    pub fn get(&self, validator_id: ValidatorId) -> Option<&ValidatorInfo> {
        self.validators
            .iter()
            .find(|v| v.validator_id == validator_id)
    }

    /// Get validator at a specific index.
    pub fn get_by_index(&self, index: usize) -> Option<&ValidatorInfo> {
        self.validators.get(index)
    }

    /// Get the index of a validator.
    pub fn index_of(&self, validator_id: ValidatorId) -> Option<usize> {
        self.validators
            .iter()
            .position(|v| v.validator_id == validator_id)
    }

    /// Get all public keys.
    pub fn public_keys(&self) -> Vec<Bls12381G1PublicKey> {
        self.validators.iter().map(|v| v.public_key).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_bls_keypair;

    fn make_validator(id: u64, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: power,
        }
    }

    #[test]
    fn test_validator_set_sorted() {
        let validators = vec![
            make_validator(3, 1),
            make_validator(1, 1),
            make_validator(2, 1),
        ];

        let set = ValidatorSet::new(validators);

        assert_eq!(set.validators[0].validator_id, ValidatorId(1));
        assert_eq!(set.validators[1].validator_id, ValidatorId(2));
        assert_eq!(set.validators[2].validator_id, ValidatorId(3));
    }

    #[test]
    fn test_validator_set_lookup() {
        let validators = vec![
            make_validator(0, 10),
            make_validator(1, 20),
            make_validator(2, 30),
        ];

        let set = ValidatorSet::new(validators);

        assert_eq!(set.len(), 3);
        assert_eq!(set.total_voting_power(), 60);

        let v1 = set.get(ValidatorId(1)).unwrap();
        assert_eq!(v1.voting_power, 20);

        assert_eq!(set.index_of(ValidatorId(2)), Some(2));
        assert_eq!(set.index_of(ValidatorId(99)), None);
    }
}
