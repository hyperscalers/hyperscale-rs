//! Immutable topology snapshot for shard committee queries.
//!
//! `TopologySnapshot` is the read-only view of topology state, passed by
//! reference to subsystem methods and shared via `ArcSwap` with the `io_loop`.
//! All query methods are `&self`; mutations happen in `TopologyState`
//! (in the `hyperscale-topology` crate) which builds new snapshots.

use crate::{
    BlockHeight, Bls12381G1PublicKey, EpochConfig, EpochId, NodeId, Round, RoutableTransaction,
    ShardCommitteeConfig, ShardGroupId, ValidatorId, ValidatorSet, ValidatorShardState, VotePower,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Hash a `NodeId` to a u64 using blake3 (first 8 bytes, little-endian).
#[must_use]
pub fn node_id_hash_u64(node_id: &NodeId) -> u64 {
    let hash = blake3::hash(&node_id.0);
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Compute which shard owns a `NodeId` (hash-modulo).
#[must_use]
pub fn shard_for_node(node_id: &NodeId, num_shards: u64) -> ShardGroupId {
    ShardGroupId(node_id_hash_u64(node_id) % num_shards)
}

/// Per-validator info (voting power + public key).
#[derive(Debug, Clone)]
struct ValidatorInfoEntry {
    voting_power: u64,
    public_key: Bls12381G1PublicKey,
}

/// Immutable topology snapshot — all query methods, no mutation.
///
/// Subsystem crates depend on this (via `hyperscale-types`) instead of the
/// full `hyperscale-topology` crate.
#[derive(Clone)]
pub struct TopologySnapshot {
    local_validator_id: ValidatorId,
    local_shard: ShardGroupId,
    local_state: ValidatorShardState,
    num_shards: u64,
    shard_committees: HashMap<ShardGroupId, ShardCommitteeConfig>,
    validator_info: HashMap<ValidatorId, ValidatorInfoEntry>,
    global_validator_set: Arc<ValidatorSet>,
    current_epoch: EpochId,
    epoch_end_height: BlockHeight,
    splitting_shards: HashSet<ShardGroupId>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Constructors
// ═══════════════════════════════════════════════════════════════════════════

impl TopologySnapshot {
    /// Create a snapshot with modulo-based shard assignment.
    ///
    /// Validators are assigned to shards by `id % num_shards`.
    #[must_use]
    pub fn new(
        local_validator_id: ValidatorId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let local_shard = ShardGroupId(local_validator_id.0 % num_shards);
        Self::build_modulo(local_validator_id, local_shard, num_shards, validator_set)
    }

    /// Create a snapshot with an explicit local shard override.
    ///
    /// All validators are placed in `local_shard` regardless of their ID.
    /// Useful for tests where `validator_id % num_shards != desired_shard`.
    ///
    /// # Panics
    ///
    /// Panics if `local_shard` is not in range `[0, num_shards)`.
    #[must_use]
    pub fn with_local_shard(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let validator_info = build_validator_info(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        // Put all validators into the specified local shard.
        let committee = shard_committees
            .get_mut(&local_shard)
            .expect("local_shard should be within num_shards");
        for v in &validator_set.validators {
            committee.active_validators.push(v.validator_id);
            committee.total_voting_power += v.voting_power;
        }

        Self {
            local_validator_id,
            local_shard,
            local_state: ValidatorShardState::Active,
            num_shards,
            shard_committees,
            validator_info,
            global_validator_set: Arc::new(validator_set),
            current_epoch: EpochId::GENESIS,
            epoch_end_height: BlockHeight(u64::MAX),
            splitting_shards: HashSet::new(),
        }
    }

    /// Create a snapshot with explicit shard committees.
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
        let validator_info = build_validator_info(global_validator_set);

        let mut committees = empty_committees(num_shards);

        for (shard, validators) in shard_committees {
            if let Some(committee) = committees.get_mut(&shard) {
                for validator_id in validators {
                    let voting_power = validator_info
                        .get(&validator_id)
                        .map_or(1, |v| v.voting_power);
                    committee.active_validators.push(validator_id);
                    committee.total_voting_power += voting_power;
                }
            }
        }

        Self {
            local_validator_id,
            local_shard,
            local_state: ValidatorShardState::Active,
            num_shards,
            shard_committees: committees,
            validator_info,
            global_validator_set: Arc::new(global_validator_set.clone()),
            current_epoch: EpochId::GENESIS,
            epoch_end_height: BlockHeight(u64::MAX),
            splitting_shards: HashSet::new(),
        }
    }

    /// Create from an epoch configuration (production path).
    ///
    /// # Errors
    ///
    /// Returns [`TopologySnapshotError::ValidatorNotInEpoch`] if
    /// `local_validator_id` is not present in any shard committee
    /// of `epoch`.
    pub fn from_epoch_config(
        local_validator_id: ValidatorId,
        epoch: &EpochConfig,
    ) -> Result<Self, TopologySnapshotError> {
        let local_shard = epoch.find_validator_shard(local_validator_id).ok_or(
            TopologySnapshotError::ValidatorNotInEpoch(local_validator_id),
        )?;

        let local_state = if epoch.is_validator_waiting(local_validator_id, local_shard) {
            ValidatorShardState::Waiting
        } else {
            ValidatorShardState::Active
        };

        let validator_info = build_validator_info(&epoch.validator_set);

        let epoch_end_height = epoch
            .expected_end_heights
            .values()
            .min()
            .copied()
            .unwrap_or(BlockHeight(u64::MAX));

        Ok(Self {
            local_validator_id,
            local_shard,
            local_state,
            num_shards: epoch.num_shards,
            shard_committees: epoch.shard_committees.clone(),
            validator_info,
            global_validator_set: Arc::new(epoch.validator_set.clone()),
            current_epoch: epoch.epoch_id,
            epoch_end_height,
            splitting_shards: HashSet::new(),
        })
    }

    /// Internal constructor for modulo-based assignment.
    fn build_modulo(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let validator_info = build_validator_info(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        for v in &validator_set.validators {
            let shard = ShardGroupId(v.validator_id.0 % num_shards);
            if let Some(committee) = shard_committees.get_mut(&shard) {
                committee.active_validators.push(v.validator_id);
                committee.total_voting_power += v.voting_power;
            }
        }

        Self {
            local_validator_id,
            local_shard,
            local_state: ValidatorShardState::Active,
            num_shards,
            shard_committees,
            validator_info,
            global_validator_set: Arc::new(validator_set),
            current_epoch: EpochId::GENESIS,
            epoch_end_height: BlockHeight(u64::MAX),
            splitting_shards: HashSet::new(),
        }
    }

    /// Create a new snapshot with the given shard marked as splitting.
    #[must_use]
    pub fn with_shard_splitting(&self, shard: ShardGroupId) -> Self {
        let mut snapshot = self.clone();
        snapshot.splitting_shards.insert(shard);
        snapshot
    }

    /// Create a new snapshot with the given shard's splitting state cleared.
    #[must_use]
    pub fn without_shard_splitting(&self, shard: ShardGroupId) -> Self {
        let mut snapshot = self.clone();
        snapshot.splitting_shards.remove(&shard);
        snapshot
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Query methods (&self)
// ═══════════════════════════════════════════════════════════════════════════

impl TopologySnapshot {
    /// Get the local validator's ID.
    #[must_use]
    pub fn local_validator_id(&self) -> ValidatorId {
        self.local_validator_id
    }

    /// Get the local shard group.
    #[must_use]
    pub fn local_shard(&self) -> ShardGroupId {
        self.local_shard
    }

    /// Get the total number of shards.
    #[must_use]
    pub fn num_shards(&self) -> u64 {
        self.num_shards
    }

    /// Get the ordered committee members for a shard.
    #[must_use]
    pub fn committee_for_shard(&self, shard: ShardGroupId) -> &[ValidatorId] {
        self.shard_committees
            .get(&shard)
            .map_or(&[][..], |c| c.active_validators.as_slice())
    }

    /// Get total voting power for a shard's committee.
    #[must_use]
    pub fn voting_power_for_shard(&self, shard: ShardGroupId) -> u64 {
        self.shard_committees
            .get(&shard)
            .map_or(0, |c| c.total_voting_power)
    }

    /// Get voting power for a specific validator.
    #[must_use]
    pub fn voting_power(&self, validator_id: ValidatorId) -> Option<u64> {
        self.validator_info
            .get(&validator_id)
            .map(|v| v.voting_power)
    }

    /// Get the public key for a validator.
    #[must_use]
    pub fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey> {
        self.validator_info.get(&validator_id).map(|v| v.public_key)
    }

    /// Get the global validator set.
    #[must_use]
    pub fn global_validator_set(&self) -> &Arc<ValidatorSet> {
        &self.global_validator_set
    }

    /// Get the validator ID at a specific index in the local committee.
    #[must_use]
    pub fn local_validator_at_index(&self, index: usize) -> Option<ValidatorId> {
        self.local_committee().get(index).copied()
    }

    // ── Derived committee queries ────────────────────────────────────────

    /// Get the number of committee members for a shard.
    #[must_use]
    pub fn committee_size_for_shard(&self, shard: ShardGroupId) -> usize {
        self.committee_for_shard(shard).len()
    }

    /// Get the index of a validator in a shard's committee.
    #[must_use]
    pub fn committee_index_for_shard(
        &self,
        shard: ShardGroupId,
        validator_id: ValidatorId,
    ) -> Option<usize> {
        self.committee_for_shard(shard)
            .iter()
            .position(|v| *v == validator_id)
    }

    /// Check if the given voting power meets quorum for a shard (> 2/3).
    #[must_use]
    pub fn has_quorum_for_shard(&self, shard: ShardGroupId, voting_power: u64) -> bool {
        VotePower::has_quorum(voting_power, self.voting_power_for_shard(shard))
    }

    /// Get the minimum voting power required for quorum in a shard.
    #[must_use]
    pub fn quorum_threshold_for_shard(&self, shard: ShardGroupId) -> u64 {
        (self.voting_power_for_shard(shard) * 2 / 3) + 1
    }

    // ── Local shard shortcuts ────────────────────────────────────────────

    /// Get the ordered committee members for the local shard.
    #[must_use]
    pub fn local_committee(&self) -> &[ValidatorId] {
        self.committee_for_shard(self.local_shard)
    }

    /// Get total voting power for the local shard.
    #[must_use]
    pub fn local_voting_power(&self) -> u64 {
        self.voting_power_for_shard(self.local_shard)
    }

    /// Get the number of committee members for the local shard.
    #[must_use]
    pub fn local_committee_size(&self) -> usize {
        self.committee_size_for_shard(self.local_shard)
    }

    /// Get the index of a validator in the local shard's committee.
    #[must_use]
    pub fn local_committee_index(&self, validator_id: ValidatorId) -> Option<usize> {
        self.committee_index_for_shard(self.local_shard, validator_id)
    }

    /// Check if the given voting power meets quorum for the local shard.
    #[must_use]
    pub fn local_has_quorum(&self, voting_power: u64) -> bool {
        self.has_quorum_for_shard(self.local_shard, voting_power)
    }

    /// Get the minimum voting power required for quorum in the local shard.
    #[must_use]
    pub fn local_quorum_threshold(&self) -> u64 {
        self.quorum_threshold_for_shard(self.local_shard)
    }

    /// Check if a validator is a member of the local shard's committee.
    #[must_use]
    pub fn is_committee_member(&self, validator_id: ValidatorId) -> bool {
        self.local_committee_index(validator_id).is_some()
    }

    // ── Proposer selection ───────────────────────────────────────────────

    /// Get the proposer for a given height and round.
    ///
    /// # Panics
    /// Panics if the local committee is empty (invariant violation).
    #[must_use]
    pub fn proposer_for(&self, height: BlockHeight, round: Round) -> ValidatorId {
        let committee = self.local_committee();
        debug_assert!(
            !committee.is_empty(),
            "proposer_for called with empty committee for shard {:?}",
            self.local_shard
        );
        let index = usize::try_from((height.0 + round.0) % committee.len() as u64)
            .expect("modulo of usize len fits in usize");
        committee[index]
    }

    /// Check if the local validator should propose at this height and round.
    #[must_use]
    pub fn should_propose(&self, height: BlockHeight, round: Round) -> bool {
        self.proposer_for(height, round) == self.local_validator_id
    }

    // ── Node / transaction routing ───────────────────────────────────────

    /// Determine which shard a `NodeId` belongs to (hash-modulo).
    #[must_use]
    pub fn shard_for_node_id(&self, node_id: &NodeId) -> ShardGroupId {
        crate::shard_for_node(node_id, self.num_shards)
    }

    /// Compute write shards for a transaction.
    pub fn consensus_shards(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        tx.declared_writes
            .iter()
            .map(|node_id| self.shard_for_node_id(node_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Compute read-only shards for a transaction.
    pub fn provisioning_shards(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        let write_shards: BTreeSet<_> = tx
            .declared_writes
            .iter()
            .map(|node_id| self.shard_for_node_id(node_id))
            .collect();

        tx.declared_reads
            .iter()
            .map(|node_id| self.shard_for_node_id(node_id))
            .filter(|shard| !write_shards.contains(shard))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Check if a transaction is cross-shard.
    pub fn is_cross_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.consensus_shards(tx).len() > 1
    }

    /// Check if a transaction is single-shard.
    pub fn is_single_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.consensus_shards(tx).len() <= 1
    }

    /// Get all shards involved in a transaction (both consensus and provisioning).
    pub fn all_shards_for_transaction(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        let consensus = self.consensus_shards(tx);
        let provisioning = self.provisioning_shards(tx);
        let all: BTreeSet<_> = consensus.into_iter().chain(provisioning).collect();
        all.into_iter().collect()
    }

    /// Check if a transaction involves the local shard for consensus.
    pub fn involves_local_shard_for_consensus(&self, tx: &RoutableTransaction) -> bool {
        tx.declared_writes
            .iter()
            .any(|node_id| self.shard_for_node_id(node_id) == self.local_shard)
    }

    /// Check if this shard is involved in a transaction at all.
    pub fn involves_local_shard(&self, tx: &RoutableTransaction) -> bool {
        let local = self.local_shard;
        tx.declared_writes
            .iter()
            .chain(tx.declared_reads.iter())
            .any(|node_id| self.shard_for_node_id(node_id) == local)
    }

    // ── Epoch awareness ──────────────────────────────────────────────────

    /// Get the current epoch identifier.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.current_epoch
    }

    /// Get the block height at which the current epoch ends.
    #[must_use]
    pub fn epoch_end_height(&self) -> BlockHeight {
        self.epoch_end_height
    }

    /// Check if this validator can participate in consensus.
    ///
    /// Returns `false` if the validator is in a "Waiting" state.
    #[must_use]
    pub fn can_participate_in_consensus(&self) -> bool {
        matches!(self.local_state, ValidatorShardState::Active)
    }

    /// Check if a shard is currently in a splitting state.
    #[must_use]
    pub fn is_shard_splitting(&self, shard: ShardGroupId) -> bool {
        self.splitting_shards.contains(&shard)
    }

    /// Check if a `NodeId` belongs to a shard that is currently splitting.
    #[must_use]
    pub fn is_node_in_splitting_shard(&self, node_id: &NodeId) -> bool {
        let shard = self.shard_for_node_id(node_id);
        self.is_shard_splitting(shard)
    }
}

impl std::fmt::Debug for TopologySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologySnapshot")
            .field("validator", &self.local_validator_id)
            .field("shard", &self.local_shard)
            .field("num_shards", &self.num_shards)
            .field("epoch", &self.current_epoch)
            .field(
                "committee_size",
                &self.committee_for_shard(self.local_shard).len(),
            )
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Error type
// ═══════════════════════════════════════════════════════════════════════════

/// Errors from topology snapshot operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologySnapshotError {
    /// Validator not found in epoch configuration.
    #[error("validator {0:?} not found in epoch configuration")]
    ValidatorNotInEpoch(ValidatorId),
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn build_validator_info(validator_set: &ValidatorSet) -> HashMap<ValidatorId, ValidatorInfoEntry> {
    validator_set
        .validators
        .iter()
        .map(|v| {
            (
                v.validator_id,
                ValidatorInfoEntry {
                    voting_power: v.voting_power,
                    public_key: v.public_key,
                },
            )
        })
        .collect()
}

fn empty_committees(num_shards: u64) -> HashMap<ShardGroupId, ShardCommitteeConfig> {
    (0..num_shards)
        .map(|id| {
            (
                ShardGroupId(id),
                ShardCommitteeConfig {
                    active_validators: Vec::new(),
                    total_voting_power: 0,
                    target_size: 100,
                },
            )
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_bls_keypair, ValidatorInfo};

    fn make_test_validator(id: u64, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: power,
        }
    }

    fn make_snapshot(num_validators: u64, local_id: u64) -> TopologySnapshot {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        TopologySnapshot::new(ValidatorId(local_id), 1, ValidatorSet::new(validators))
    }

    #[test]
    fn test_committee_basics() {
        let snapshot = make_snapshot(4, 0);

        assert_eq!(snapshot.local_committee_size(), 4);
        assert_eq!(snapshot.local_validator_id(), ValidatorId(0));
        assert_eq!(snapshot.local_shard(), ShardGroupId(0));
    }

    #[test]
    fn test_quorum() {
        let snapshot = make_snapshot(4, 0);

        assert_eq!(snapshot.local_voting_power(), 4);
        assert_eq!(snapshot.local_quorum_threshold(), 3);

        assert!(!snapshot.local_has_quorum(2));
        assert!(snapshot.local_has_quorum(3));
        assert!(snapshot.local_has_quorum(4));
    }

    #[test]
    fn test_proposer_rotation() {
        let snapshot = make_snapshot(4, 0);

        assert_eq!(
            snapshot.proposer_for(BlockHeight(0), Round(0)),
            ValidatorId(0)
        );
        assert_eq!(
            snapshot.proposer_for(BlockHeight(1), Round(0)),
            ValidatorId(1)
        );
        assert_eq!(
            snapshot.proposer_for(BlockHeight(4), Round(0)),
            ValidatorId(0)
        );
        assert_eq!(
            snapshot.proposer_for(BlockHeight(0), Round(1)),
            ValidatorId(1)
        );
    }

    #[test]
    fn test_with_local_shard() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let snapshot = TopologySnapshot::with_local_shard(
            ValidatorId(0),
            ShardGroupId(1),
            2,
            ValidatorSet::new(validators),
        );

        assert_eq!(snapshot.local_shard(), ShardGroupId(1));
        assert_eq!(snapshot.local_committee_size(), 4);
        // Other shard should be empty.
        assert_eq!(snapshot.committee_for_shard(ShardGroupId(0)).len(), 0);
    }

    #[test]
    fn test_with_shard_committees() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(ShardGroupId(0), vec![ValidatorId(0), ValidatorId(2)]);
        committees.insert(ShardGroupId(1), vec![ValidatorId(1), ValidatorId(3)]);

        let snapshot = TopologySnapshot::with_shard_committees(
            ValidatorId(0),
            ShardGroupId(0),
            2,
            &vs,
            committees,
        );

        assert_eq!(snapshot.committee_for_shard(ShardGroupId(0)).len(), 2);
        assert_eq!(snapshot.committee_for_shard(ShardGroupId(1)).len(), 2);
    }

    #[test]
    fn test_from_epoch_config() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let epoch = EpochConfig::genesis(2, vs);

        let snapshot = TopologySnapshot::from_epoch_config(ValidatorId(0), &epoch).unwrap();

        assert_eq!(snapshot.local_shard(), ShardGroupId(0));
        assert_eq!(snapshot.num_shards(), 2);
        assert_eq!(snapshot.current_epoch(), EpochId::GENESIS);
        assert!(snapshot.can_participate_in_consensus());
    }

    #[test]
    fn test_from_epoch_config_unknown_validator() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let epoch = EpochConfig::genesis(2, vs);

        let result = TopologySnapshot::from_epoch_config(ValidatorId(100), &epoch);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            TopologySnapshotError::ValidatorNotInEpoch(ValidatorId(100))
        );
    }

    #[test]
    fn test_shard_splitting() {
        let snapshot = make_snapshot(4, 0);

        assert!(!snapshot.is_shard_splitting(ShardGroupId(0)));

        let with_split = snapshot.with_shard_splitting(ShardGroupId(0));
        assert!(with_split.is_shard_splitting(ShardGroupId(0)));

        let cleared = with_split.without_shard_splitting(ShardGroupId(0));
        assert!(!cleared.is_shard_splitting(ShardGroupId(0)));
    }

    #[test]
    fn test_epoch_defaults() {
        let snapshot = make_snapshot(4, 0);

        assert_eq!(snapshot.current_epoch(), EpochId::GENESIS);
        assert_eq!(snapshot.epoch_end_height(), BlockHeight(u64::MAX));
        assert!(snapshot.can_participate_in_consensus());
        assert!(!snapshot.is_shard_splitting(ShardGroupId(0)));
    }

    #[test]
    fn test_multi_shard_modulo_assignment() {
        let validators: Vec<_> = (0..8).map(|i| make_test_validator(i, 1)).collect();
        let snapshot = TopologySnapshot::new(ValidatorId(0), 2, ValidatorSet::new(validators));

        // Shard 0: validators 0, 2, 4, 6
        let shard0 = snapshot.committee_for_shard(ShardGroupId(0));
        assert_eq!(shard0.len(), 4);
        assert!(shard0.contains(&ValidatorId(0)));
        assert!(shard0.contains(&ValidatorId(2)));
        assert!(shard0.contains(&ValidatorId(4)));
        assert!(shard0.contains(&ValidatorId(6)));

        // Shard 1: validators 1, 3, 5, 7
        let shard1 = snapshot.committee_for_shard(ShardGroupId(1));
        assert_eq!(shard1.len(), 4);
        assert!(shard1.contains(&ValidatorId(1)));
        assert!(shard1.contains(&ValidatorId(3)));
    }
}
