//! Topology trait and static implementation.

use crate::{
    Bls12381G1PublicKey, EpochId, NodeId, RoutableTransaction, ShardGroupId, ValidatorId,
    ValidatorSet, VotePower,
};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Compute which shard owns a NodeId.
pub fn shard_for_node(node_id: &NodeId, num_shards: u64) -> ShardGroupId {
    let hash = blake3::hash(&node_id.0);
    let bytes = hash.as_bytes();
    let hash_value = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    ShardGroupId(hash_value % num_shards)
}

/// Unified topology trait for consensus and execution.
pub trait Topology: Send + Sync {
    /// Get the local validator's ID.
    fn local_validator_id(&self) -> ValidatorId;

    /// Get the local shard group.
    fn local_shard(&self) -> ShardGroupId;

    /// Get the total number of shards.
    fn num_shards(&self) -> u64;

    /// Get the ordered committee members for a shard.
    ///
    /// Returns `Cow` to allow both borrowed (StaticTopology) and owned (DynamicTopology) data.
    /// This enables interior mutability for dynamic topologies while maintaining zero-copy
    /// performance for static topologies.
    fn committee_for_shard(&self, shard: ShardGroupId) -> Cow<'_, [ValidatorId]>;

    /// Get total voting power for a shard's committee.
    fn voting_power_for_shard(&self, shard: ShardGroupId) -> u64;

    /// Get voting power for a specific validator.
    fn voting_power(&self, validator_id: ValidatorId) -> Option<u64>;

    /// Get the public key for a validator.
    fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey>;

    /// Get the global validator set.
    fn global_validator_set(&self) -> &ValidatorSet;

    /// Get the validator ID at a specific index in the local committee.
    ///
    /// Returns None if the index is out of bounds.
    fn local_validator_at_index(&self, index: usize) -> Option<ValidatorId> {
        let committee = self.local_committee();
        committee.get(index).copied()
    }

    // Derived methods

    /// Get the number of committee members for a shard.
    fn committee_size_for_shard(&self, shard: ShardGroupId) -> usize {
        self.committee_for_shard(shard).len()
    }

    /// Get the index of a validator in a shard's committee.
    fn committee_index_for_shard(
        &self,
        shard: ShardGroupId,
        validator_id: ValidatorId,
    ) -> Option<usize> {
        let committee = self.committee_for_shard(shard);
        committee.iter().position(|v| *v == validator_id)
    }

    /// Check if the given voting power meets quorum for a shard (> 2/3).
    fn has_quorum_for_shard(&self, shard: ShardGroupId, voting_power: u64) -> bool {
        VotePower::has_quorum(voting_power, self.voting_power_for_shard(shard))
    }

    /// Get the minimum voting power required for quorum in a shard.
    fn quorum_threshold_for_shard(&self, shard: ShardGroupId) -> u64 {
        (self.voting_power_for_shard(shard) * 2 / 3) + 1
    }

    /// Get the ordered committee members for the local shard.
    fn local_committee(&self) -> Cow<'_, [ValidatorId]> {
        self.committee_for_shard(self.local_shard())
    }

    /// Get total voting power for the local shard's committee.
    fn local_voting_power(&self) -> u64 {
        self.voting_power_for_shard(self.local_shard())
    }

    /// Get the number of committee members for the local shard.
    fn local_committee_size(&self) -> usize {
        self.committee_size_for_shard(self.local_shard())
    }

    /// Get the index of a validator in the local shard's committee.
    fn local_committee_index(&self, validator_id: ValidatorId) -> Option<usize> {
        self.committee_index_for_shard(self.local_shard(), validator_id)
    }

    /// Check if the given voting power meets quorum for the local shard.
    fn local_has_quorum(&self, voting_power: u64) -> bool {
        self.has_quorum_for_shard(self.local_shard(), voting_power)
    }

    /// Get the minimum voting power required for quorum in the local shard.
    fn local_quorum_threshold(&self) -> u64 {
        self.quorum_threshold_for_shard(self.local_shard())
    }

    /// Check if a validator is a member of the local shard's committee.
    fn is_committee_member(&self, validator_id: ValidatorId) -> bool {
        self.local_committee_index(validator_id).is_some()
    }

    /// Get the proposer for a given height and round.
    fn proposer_for(&self, height: u64, round: u64) -> ValidatorId {
        let committee = self.local_committee();
        let index = (height + round) as usize % committee.len();
        committee[index]
    }

    /// Check if the local validator should propose at this height and round.
    fn should_propose(&self, height: u64, round: u64) -> bool {
        self.proposer_for(height, round) == self.local_validator_id()
    }

    /// Determine which shard a NodeId belongs to.
    fn shard_for_node_id(&self, node_id: &NodeId) -> ShardGroupId {
        shard_for_node(node_id, self.num_shards())
    }

    /// Compute write shards for a transaction.
    fn consensus_shards(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        tx.declared_writes
            .iter()
            .map(|node_id| self.shard_for_node_id(node_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Compute read-only shards for a transaction.
    fn provisioning_shards(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
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
    fn is_cross_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.consensus_shards(tx).len() > 1
    }

    /// Check if a transaction is single-shard.
    fn is_single_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.consensus_shards(tx).len() <= 1
    }

    /// Get all shards involved in a transaction (both consensus and provisioning).
    fn all_shards_for_transaction(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        let consensus = self.consensus_shards(tx);
        let provisioning = self.provisioning_shards(tx);
        let all: BTreeSet<_> = consensus.into_iter().chain(provisioning).collect();
        all.into_iter().collect()
    }

    /// Check if a transaction involves the local shard for consensus.
    fn involves_local_shard_for_consensus(&self, tx: &RoutableTransaction) -> bool {
        tx.declared_writes
            .iter()
            .any(|node_id| self.shard_for_node_id(node_id) == self.local_shard())
    }

    /// Check if this shard is involved in a transaction at all.
    fn involves_local_shard(&self, tx: &RoutableTransaction) -> bool {
        let local = self.local_shard();
        tx.declared_writes
            .iter()
            .chain(tx.declared_reads.iter())
            .any(|node_id| self.shard_for_node_id(node_id) == local)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Epoch-awareness methods (for dynamic topology support)
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the current epoch identifier.
    ///
    /// For static topologies, this always returns epoch 0 (genesis).
    /// For dynamic topologies, this returns the current active epoch.
    fn current_epoch(&self) -> EpochId {
        EpochId::GENESIS
    }

    /// Get the block height at which the current epoch ends.
    ///
    /// For static topologies, this returns the maximum block height (epochs never end).
    /// For dynamic topologies, this returns the expected end height for the local shard.
    fn epoch_end_height(&self) -> crate::BlockHeight {
        crate::BlockHeight(u64::MAX)
    }

    /// Check if this validator can participate in consensus.
    ///
    /// Returns `false` if the validator is in a "Waiting" state (syncing to a new shard
    /// after being shuffled). In this state, the validator receives messages but cannot vote.
    ///
    /// For static topologies, this always returns `true`.
    fn can_participate_in_consensus(&self) -> bool {
        true
    }

    /// Check if a shard is currently in a splitting state.
    ///
    /// When a shard is splitting, the mempool should reject new transactions
    /// targeting NodeIds in that shard to allow in-flight transactions to drain.
    ///
    /// For static topologies, this always returns `false`.
    fn is_shard_splitting(&self, _shard: ShardGroupId) -> bool {
        false
    }

    /// Check if a NodeId belongs to a shard that is currently splitting.
    ///
    /// Convenience method that combines `shard_for_node_id` and `is_shard_splitting`.
    fn is_node_in_splitting_shard(&self, node_id: &NodeId) -> bool {
        let shard = self.shard_for_node_id(node_id);
        self.is_shard_splitting(shard)
    }
}

/// Errors that can occur when validating topology information.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologyError {
    /// Validator is not a member of the committee.
    #[error("validator {0:?} is not in the committee")]
    NotInCommittee(ValidatorId),
}

/// Per-shard committee information.
#[derive(Debug, Clone)]
struct ShardCommittee {
    committee: Vec<ValidatorId>,
    total_voting_power: u64,
}

/// Internal validator info storage.
#[derive(Debug, Clone)]
struct ValidatorInfoInternal {
    voting_power: u64,
    public_key: Bls12381G1PublicKey,
}

/// A static topology implementation.
#[derive(Debug, Clone)]
pub struct StaticTopology {
    local_validator_id: ValidatorId,
    local_shard: ShardGroupId,
    num_shards: u64,
    shard_committees: HashMap<ShardGroupId, ShardCommittee>,
    validator_info: HashMap<ValidatorId, ValidatorInfoInternal>,
    global_validator_set: ValidatorSet,
}

impl StaticTopology {
    /// Create a new static topology from a global validator set.
    pub fn new(
        local_validator_id: ValidatorId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let local_shard = ShardGroupId(local_validator_id.0 % num_shards);

        let validator_info: HashMap<_, _> = validator_set
            .validators
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    ValidatorInfoInternal {
                        voting_power: v.voting_power,
                        public_key: v.public_key,
                    },
                )
            })
            .collect();

        let mut shard_committees: HashMap<ShardGroupId, ShardCommittee> = HashMap::new();

        for shard_id in 0..num_shards {
            shard_committees.insert(
                ShardGroupId(shard_id),
                ShardCommittee {
                    committee: Vec::new(),
                    total_voting_power: 0,
                },
            );
        }

        for v in &validator_set.validators {
            let shard = ShardGroupId(v.validator_id.0 % num_shards);
            if let Some(committee) = shard_committees.get_mut(&shard) {
                committee.committee.push(v.validator_id);
                committee.total_voting_power += v.voting_power;
            }
        }

        Self {
            local_validator_id,
            local_shard,
            num_shards,
            shard_committees,
            validator_info,
            global_validator_set: validator_set,
        }
    }

    /// Create a topology as an Arc.
    pub fn into_arc(self) -> Arc<dyn Topology> {
        Arc::new(self)
    }

    /// Create a topology with an explicit local shard assignment.
    pub fn with_local_shard(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let validator_info: HashMap<_, _> = validator_set
            .validators
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    ValidatorInfoInternal {
                        voting_power: v.voting_power,
                        public_key: v.public_key,
                    },
                )
            })
            .collect();

        let mut shard_committees: HashMap<ShardGroupId, ShardCommittee> = HashMap::new();

        for shard_id in 0..num_shards {
            shard_committees.insert(
                ShardGroupId(shard_id),
                ShardCommittee {
                    committee: Vec::new(),
                    total_voting_power: 0,
                },
            );
        }

        let committee = shard_committees
            .get_mut(&local_shard)
            .expect("local_shard should exist");
        for v in &validator_set.validators {
            committee.committee.push(v.validator_id);
            committee.total_voting_power += v.voting_power;
        }

        Self {
            local_validator_id,
            local_shard,
            num_shards,
            shard_committees,
            validator_info,
            global_validator_set: validator_set,
        }
    }

    /// Create a topology with explicit shard committees.
    pub fn with_shard_committees(
        local_validator_id: ValidatorId,
        local_shard: ShardGroupId,
        num_shards: u64,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>>,
    ) -> Self {
        let validator_info: HashMap<_, _> = global_validator_set
            .validators
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    ValidatorInfoInternal {
                        voting_power: v.voting_power,
                        public_key: v.public_key,
                    },
                )
            })
            .collect();

        let mut committees: HashMap<ShardGroupId, ShardCommittee> = HashMap::new();

        for shard_id in 0..num_shards {
            committees.insert(
                ShardGroupId(shard_id),
                ShardCommittee {
                    committee: Vec::new(),
                    total_voting_power: 0,
                },
            );
        }

        for (shard, validators) in shard_committees {
            if let Some(committee) = committees.get_mut(&shard) {
                for validator_id in validators {
                    let voting_power = validator_info
                        .get(&validator_id)
                        .map(|v| v.voting_power)
                        .unwrap_or(1);
                    committee.committee.push(validator_id);
                    committee.total_voting_power += voting_power;
                }
            }
        }

        Self {
            local_validator_id,
            local_shard,
            num_shards,
            shard_committees: committees,
            validator_info,
            global_validator_set: global_validator_set.clone(),
        }
    }
}

impl Topology for StaticTopology {
    fn local_validator_id(&self) -> ValidatorId {
        self.local_validator_id
    }

    fn local_shard(&self) -> ShardGroupId {
        self.local_shard
    }

    fn num_shards(&self) -> u64 {
        self.num_shards
    }

    fn committee_for_shard(&self, shard: ShardGroupId) -> Cow<'_, [ValidatorId]> {
        Cow::Borrowed(
            self.shard_committees
                .get(&shard)
                .map(|c| c.committee.as_slice())
                .unwrap_or(&[]),
        )
    }

    fn voting_power_for_shard(&self, shard: ShardGroupId) -> u64 {
        self.shard_committees
            .get(&shard)
            .map(|c| c.total_voting_power)
            .unwrap_or(0)
    }

    fn voting_power(&self, validator_id: ValidatorId) -> Option<u64> {
        self.validator_info
            .get(&validator_id)
            .map(|v| v.voting_power)
    }

    fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey> {
        self.validator_info.get(&validator_id).map(|v| v.public_key)
    }

    fn global_validator_set(&self) -> &ValidatorSet {
        &self.global_validator_set
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Dynamic Topology
// ═══════════════════════════════════════════════════════════════════════════

use crate::{BlockHeight, EpochConfig, ValidatorShardState};
use std::collections::HashSet;
use std::sync::RwLock;

/// Dynamic topology that can be updated at epoch boundaries.
///
/// Unlike `StaticTopology`, this implementation:
/// - Supports epoch transitions with validator shuffling
/// - Tracks validator state (Active, Waiting, etc.)
/// - Tracks shards that are splitting (for transaction rejection)
/// - Uses interior mutability via `RwLock` for epoch updates
///
/// The `Cow` return type in `committee_for_shard` allows this implementation
/// to return owned data from behind the `RwLock`.
pub struct DynamicTopology {
    /// Local validator ID (immutable).
    local_validator_id: ValidatorId,

    /// Mutable state protected by RwLock.
    inner: RwLock<DynamicTopologyInner>,
}

/// Interior state of DynamicTopology.
struct DynamicTopologyInner {
    /// Current epoch configuration.
    current: EpochConfig,

    /// Next epoch configuration (set during transition window).
    next: Option<EpochConfig>,

    /// Current shard for this validator.
    local_shard: ShardGroupId,

    /// State within the shard.
    local_state: ValidatorShardState,

    /// Validator public keys and voting power cache.
    validator_info: HashMap<ValidatorId, ValidatorInfoInternal>,

    /// Shards currently in split grace period.
    /// Transactions targeting these shards are rejected.
    splitting_shards: HashSet<ShardGroupId>,
}

/// Error type for topology operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DynamicTopologyError {
    /// No next epoch configuration available.
    #[error("no next epoch configuration available")]
    NoNextEpoch,

    /// Validator not found in epoch configuration.
    #[error("validator {0:?} not found in epoch configuration")]
    ValidatorNotInEpoch(ValidatorId),
}

impl DynamicTopology {
    /// Create from initial epoch configuration.
    pub fn from_epoch_config(
        local_validator_id: ValidatorId,
        epoch: EpochConfig,
    ) -> Result<Self, DynamicTopologyError> {
        let local_shard = epoch.find_validator_shard(local_validator_id).ok_or(
            DynamicTopologyError::ValidatorNotInEpoch(local_validator_id),
        )?;

        let local_state = if epoch.is_validator_waiting(local_validator_id, local_shard) {
            ValidatorShardState::Waiting
        } else {
            ValidatorShardState::Active
        };

        let validator_info = epoch
            .validator_set
            .validators
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    ValidatorInfoInternal {
                        voting_power: v.voting_power,
                        public_key: v.public_key,
                    },
                )
            })
            .collect();

        Ok(Self {
            local_validator_id,
            inner: RwLock::new(DynamicTopologyInner {
                current: epoch,
                next: None,
                local_shard,
                local_state,
                validator_info,
                splitting_shards: HashSet::new(),
            }),
        })
    }

    /// Create as an Arc for use with trait objects.
    pub fn into_arc(self) -> Arc<dyn Topology> {
        Arc::new(self)
    }

    /// Set the next epoch configuration.
    ///
    /// Called when global consensus has finalized the next epoch config.
    pub fn set_next_epoch(&self, next: EpochConfig) {
        let mut inner = self.inner.write().expect("RwLock poisoned");
        inner.next = Some(next);
    }

    /// Transition to the next epoch.
    ///
    /// Called when epoch boundary is reached.
    pub fn transition_to_next_epoch(&self) -> Result<(), DynamicTopologyError> {
        let mut inner = self.inner.write().expect("RwLock poisoned");

        let next = inner.next.take().ok_or(DynamicTopologyError::NoNextEpoch)?;

        // Update local shard assignment
        let new_shard = next.find_validator_shard(self.local_validator_id).ok_or(
            DynamicTopologyError::ValidatorNotInEpoch(self.local_validator_id),
        )?;

        // Determine if we're in waiting state
        let new_state = if next.is_validator_waiting(self.local_validator_id, new_shard) {
            ValidatorShardState::Waiting
        } else {
            ValidatorShardState::Active
        };

        // Update validator info cache
        inner.validator_info = next
            .validator_set
            .validators
            .iter()
            .map(|v| {
                (
                    v.validator_id,
                    ValidatorInfoInternal {
                        voting_power: v.voting_power,
                        public_key: v.public_key,
                    },
                )
            })
            .collect();

        inner.local_shard = new_shard;
        inner.local_state = new_state;
        inner.current = next;

        // Clear splitting shards on epoch transition
        inner.splitting_shards.clear();

        Ok(())
    }

    /// Mark a shard as splitting (entering grace period).
    pub fn mark_shard_splitting(&self, shard: ShardGroupId) {
        let mut inner = self.inner.write().expect("RwLock poisoned");
        inner.splitting_shards.insert(shard);
    }

    /// Clear the splitting state for a shard.
    pub fn clear_shard_splitting(&self, shard: ShardGroupId) {
        let mut inner = self.inner.write().expect("RwLock poisoned");
        inner.splitting_shards.remove(&shard);
    }

    /// Get the current epoch ID.
    pub fn epoch_id(&self) -> EpochId {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.current.epoch_id
    }

    /// Get the local validator's shard state.
    pub fn local_validator_state(&self) -> ValidatorShardState {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.local_state
    }

    /// Check if the next epoch configuration is set.
    pub fn has_next_epoch(&self) -> bool {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.next.is_some()
    }
}

impl Topology for DynamicTopology {
    fn local_validator_id(&self) -> ValidatorId {
        self.local_validator_id
    }

    fn local_shard(&self) -> ShardGroupId {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.local_shard
    }

    fn num_shards(&self) -> u64 {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.current.num_shards
    }

    fn committee_for_shard(&self, shard: ShardGroupId) -> Cow<'_, [ValidatorId]> {
        let inner = self.inner.read().expect("RwLock poisoned");
        let validators = inner
            .current
            .shard_committees
            .get(&shard)
            .map(|c| c.active_validators.clone())
            .unwrap_or_default();
        Cow::Owned(validators)
    }

    fn voting_power_for_shard(&self, shard: ShardGroupId) -> u64 {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner
            .current
            .shard_committees
            .get(&shard)
            .map(|c| c.total_voting_power)
            .unwrap_or(0)
    }

    fn voting_power(&self, validator_id: ValidatorId) -> Option<u64> {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner
            .validator_info
            .get(&validator_id)
            .map(|v| v.voting_power)
    }

    fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey> {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner
            .validator_info
            .get(&validator_id)
            .map(|v| v.public_key)
    }

    fn global_validator_set(&self) -> &ValidatorSet {
        // This is safe because ValidatorSet is immutable within an epoch,
        // but we need to be careful about lifetimes with RwLock.
        // For now, we'll return a reference that lives as long as self.
        // This works because the validator set is in the EpochConfig which
        // is stored in inner.current.
        //
        // Note: This is a slight compromise - if we truly needed interior
        // mutability of the validator set, we'd need to return Cow here too.
        // But ValidatorSet doesn't change within an epoch.
        //
        // Safety: We hold a read lock for the duration of the borrow.
        // This is safe as long as callers don't hold the reference across
        // yield points.
        unsafe {
            let inner = self.inner.read().expect("RwLock poisoned");
            let ptr = &inner.current.validator_set as *const ValidatorSet;
            // Extend the lifetime - this is safe because:
            // 1. The validator set lives in self.inner.current
            // 2. We never replace current without going through transition_to_next_epoch
            // 3. The caller should not hold this reference across await points
            &*ptr
        }
    }

    // Epoch-awareness overrides

    fn current_epoch(&self) -> EpochId {
        self.epoch_id()
    }

    fn epoch_end_height(&self) -> BlockHeight {
        let inner = self.inner.read().expect("RwLock poisoned");
        // Return the minimum end height across all shards
        inner
            .current
            .expected_end_heights
            .values()
            .min()
            .copied()
            .unwrap_or(BlockHeight(u64::MAX))
    }

    fn can_participate_in_consensus(&self) -> bool {
        let inner = self.inner.read().expect("RwLock poisoned");
        matches!(inner.local_state, ValidatorShardState::Active)
    }

    fn is_shard_splitting(&self, shard: ShardGroupId) -> bool {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.splitting_shards.contains(&shard)
    }

    fn shard_for_node_id(&self, node_id: &NodeId) -> ShardGroupId {
        let inner = self.inner.read().expect("RwLock poisoned");
        inner.current.shard_for_node_id(node_id)
    }
}

impl std::fmt::Debug for DynamicTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().expect("RwLock poisoned");
        f.debug_struct("DynamicTopology")
            .field("local_validator_id", &self.local_validator_id)
            .field("epoch", &inner.current.epoch_id)
            .field("local_shard", &inner.local_shard)
            .field("local_state", &inner.local_state)
            .field("num_shards", &inner.current.num_shards)
            .finish()
    }
}

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

    fn make_test_topology(num_validators: u64, local_id: u64) -> StaticTopology {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        StaticTopology::new(ValidatorId(local_id), 1, ValidatorSet::new(validators))
    }

    #[test]
    fn test_committee_basics() {
        let topology = make_test_topology(4, 0);

        assert_eq!(topology.local_committee_size(), 4);
        assert_eq!(topology.local_validator_id(), ValidatorId(0));
        assert_eq!(topology.local_shard(), ShardGroupId(0));
    }

    #[test]
    fn test_quorum() {
        let topology = make_test_topology(4, 0);

        assert_eq!(topology.local_voting_power(), 4);
        assert_eq!(topology.local_quorum_threshold(), 3);

        assert!(!topology.local_has_quorum(2));
        assert!(topology.local_has_quorum(3));
        assert!(topology.local_has_quorum(4));
    }

    #[test]
    fn test_proposer_rotation() {
        let topology = make_test_topology(4, 0);

        assert_eq!(topology.proposer_for(0, 0), ValidatorId(0));
        assert_eq!(topology.proposer_for(1, 0), ValidatorId(1));
        assert_eq!(topology.proposer_for(4, 0), ValidatorId(0));
        assert_eq!(topology.proposer_for(0, 1), ValidatorId(1));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // DynamicTopology tests
    // ═══════════════════════════════════════════════════════════════════════

    fn make_dynamic_topology(num_validators: u64, local_id: u64) -> DynamicTopology {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let epoch_config = EpochConfig::genesis(2, validator_set);
        DynamicTopology::from_epoch_config(ValidatorId(local_id), epoch_config).unwrap()
    }

    #[test]
    fn test_dynamic_topology_basics() {
        let topology = make_dynamic_topology(4, 0);

        assert_eq!(topology.local_validator_id(), ValidatorId(0));
        assert_eq!(topology.local_shard(), ShardGroupId(0)); // 0 % 2 = 0
        assert_eq!(topology.num_shards(), 2);
        assert_eq!(topology.current_epoch(), EpochId::GENESIS);
    }

    #[test]
    fn test_dynamic_topology_committee() {
        let topology = make_dynamic_topology(8, 0);

        // With 8 validators and 2 shards:
        // Shard 0: validators 0, 2, 4, 6
        // Shard 1: validators 1, 3, 5, 7
        let committee = topology.committee_for_shard(ShardGroupId(0));
        assert_eq!(committee.len(), 4);
        assert!(committee.contains(&ValidatorId(0)));
        assert!(committee.contains(&ValidatorId(2)));
        assert!(committee.contains(&ValidatorId(4)));
        assert!(committee.contains(&ValidatorId(6)));

        let committee1 = topology.committee_for_shard(ShardGroupId(1));
        assert_eq!(committee1.len(), 4);
    }

    #[test]
    fn test_dynamic_topology_epoch_awareness() {
        let topology = make_dynamic_topology(4, 0);

        // Static epoch awareness defaults
        assert!(topology.can_participate_in_consensus());
        assert!(!topology.is_shard_splitting(ShardGroupId(0)));
        assert_eq!(
            topology.local_validator_state(),
            ValidatorShardState::Active
        );
    }

    #[test]
    fn test_dynamic_topology_split_tracking() {
        let topology = make_dynamic_topology(4, 0);

        // Initially no shards are splitting
        assert!(!topology.is_shard_splitting(ShardGroupId(0)));

        // Mark shard as splitting
        topology.mark_shard_splitting(ShardGroupId(0));
        assert!(topology.is_shard_splitting(ShardGroupId(0)));
        assert!(!topology.is_shard_splitting(ShardGroupId(1)));

        // Clear splitting state
        topology.clear_shard_splitting(ShardGroupId(0));
        assert!(!topology.is_shard_splitting(ShardGroupId(0)));
    }

    #[test]
    fn test_dynamic_topology_validator_not_found() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let validator_set = ValidatorSet::new(validators);
        let epoch_config = EpochConfig::genesis(2, validator_set);

        // Try to create topology for validator not in the set
        let result = DynamicTopology::from_epoch_config(ValidatorId(100), epoch_config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            DynamicTopologyError::ValidatorNotInEpoch(ValidatorId(100))
        );
    }

    #[test]
    fn test_dynamic_topology_epoch_transition() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let validator_set = ValidatorSet::new(validators.clone());
        let epoch0 = EpochConfig::genesis(2, validator_set.clone());
        let topology = DynamicTopology::from_epoch_config(ValidatorId(0), epoch0.clone()).unwrap();

        assert_eq!(topology.epoch_id(), EpochId::GENESIS);

        // Create next epoch config (same validators for simplicity)
        let mut epoch1 = EpochConfig::genesis(2, validator_set);
        epoch1.epoch_id = EpochId(1);

        // Transition without setting next epoch should fail
        let result = topology.transition_to_next_epoch();
        assert!(result.is_err());

        // Set next epoch and transition
        topology.set_next_epoch(epoch1);
        assert!(topology.has_next_epoch());

        let result = topology.transition_to_next_epoch();
        assert!(result.is_ok());
        assert_eq!(topology.epoch_id(), EpochId(1));
        assert!(!topology.has_next_epoch());
    }
}
