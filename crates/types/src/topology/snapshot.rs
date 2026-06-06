//! Immutable topology snapshot for shard committee queries.
//!
//! `TopologySnapshot` is the read-only view of topology state, passed by
//! reference to subsystem methods and shared via `ArcSwap` with the `io_loop`.
//! All query methods are `&self`; mutations happen in `TopologyCoordinator`
//! (in the `hyperscale-topology` crate) which builds new snapshots.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use blake3::hash as blake3_hash;

use crate::{
    Bls12381G1PublicKey, NetworkDefinition, NodeId, Round, RoutableTransaction, ShardId, ShardTrie,
    ValidatorId, ValidatorSet, VotePower,
};

/// Per-shard committee membership.
#[derive(Debug, Clone)]
struct ShardCommittee {
    active_validators: Vec<ValidatorId>,
    total_voting_power: VotePower,
}

/// Hash a `NodeId` to a u64 using blake3 (first 8 bytes, little-endian).
#[must_use]
pub fn node_id_hash_u64(node_id: &NodeId) -> u64 {
    let hash = blake3_hash(&node_id.0);
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Compute which shard owns a `NodeId` in a uniform `num_shards`-way trie.
///
/// The shard is the leaf at depth `log2(num_shards)` whose path is the top
/// `depth` bits of `blake3(node_id)` (most-significant first) — a prefix of the
/// node's JMT leaf key, so the shard owns a contiguous state subtree. For a
/// non-uniform partition, route through [`ShardTrie::shard_for`] instead.
///
/// # Panics
/// Panics if `num_shards` is not a power of two.
#[must_use]
pub fn shard_for_node(node_id: &NodeId, num_shards: u64) -> ShardId {
    assert!(
        num_shards.is_power_of_two(),
        "num_shards must be a power of two, got {num_shards}"
    );
    let depth = num_shards.trailing_zeros();
    if depth == 0 {
        return ShardId::ROOT;
    }
    let hash = blake3_hash(&node_id.0);
    let bits = u64::from_be_bytes(
        hash.as_bytes()[..8]
            .try_into()
            .expect("blake3 output is 32 bytes"),
    );
    ShardId::leaf(depth, bits >> (64 - depth))
}

/// Per-validator info (voting power + public key).
#[derive(Debug, Clone)]
struct ValidatorInfoEntry {
    voting_power: VotePower,
    public_key: Bls12381G1PublicKey,
}

/// Immutable topology snapshot — all query methods, no mutation.
///
/// Identity-agnostic: callers carry their own `(validator_id, shard)` and
/// pass them in at call sites that need self. One snapshot can be shared
/// across every vnode on a host.
///
/// Subsystem crates depend on this (via `hyperscale-types`) instead of the
/// full `hyperscale-topology` crate.
///
/// # Invariants
///
/// Every validator listed in any committee's `active_validators` is present
/// in `validator_info` (with the same voting power that contributed to
/// `total_voting_power`). Constructors enforce this — `with_shard_committees`
/// panics on a missing entry, `build_modulo` and `single_shard` derive
/// committees from the same `ValidatorSet` that seeds `validator_info`.
/// Downstream code relies on this to call `voting_power(committee_member)`
/// and `public_key(committee_member)` with `expect` rather than fallback.
#[derive(Clone)]
pub struct TopologySnapshot {
    network: NetworkDefinition,
    shard_trie: ShardTrie,
    shard_committees: HashMap<ShardId, ShardCommittee>,
    validator_info: HashMap<ValidatorId, ValidatorInfoEntry>,
    global_validator_set: Arc<ValidatorSet>,
}

/// The uniform-trie leaf for flat shard index `index` of `num_shards`.
const fn uniform_leaf(num_shards: u64, index: u64) -> ShardId {
    ShardId::leaf(num_shards.trailing_zeros(), index)
}

// ═══════════════════════════════════════════════════════════════════════════
// Constructors
// ═══════════════════════════════════════════════════════════════════════════

impl TopologySnapshot {
    /// Create a snapshot with modulo-based shard assignment.
    ///
    /// Validators are assigned to shards by `id % num_shards`.
    #[must_use]
    pub fn new(network: NetworkDefinition, num_shards: u64, validator_set: ValidatorSet) -> Self {
        let validator_info = build_validator_info(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        for v in &validator_set.validators {
            let shard = uniform_leaf(num_shards, v.validator_id.inner() % num_shards);
            if let Some(committee) = shard_committees.get_mut(&shard) {
                committee.active_validators.push(v.validator_id);
                committee.total_voting_power += v.voting_power;
            }
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees,
            validator_info,
            global_validator_set: Arc::new(validator_set),
        }
    }

    /// Create a single-shard snapshot — all validators in `shard`.
    ///
    /// Useful for tests where `validator_id % num_shards != desired_shard`.
    ///
    /// # Panics
    ///
    /// Panics if `shard` is not in range `[0, num_shards)`.
    #[must_use]
    pub fn single_shard(
        network: NetworkDefinition,
        shard: ShardId,
        num_shards: u64,
        validator_set: ValidatorSet,
    ) -> Self {
        let validator_info = build_validator_info(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        let committee = shard_committees
            .get_mut(&shard)
            .expect("shard should be within num_shards");
        for v in &validator_set.validators {
            committee.active_validators.push(v.validator_id);
            committee.total_voting_power += v.voting_power;
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees,
            validator_info,
            global_validator_set: Arc::new(validator_set),
        }
    }

    /// Create a snapshot with explicit shard committees.
    ///
    /// Shard membership is taken directly from the provided map.
    ///
    /// # Panics
    ///
    /// Panics if a committee references a validator that is not present in
    /// `global_validator_set`. Snapshots must be internally consistent so
    /// downstream code can look up `public_key`/`voting_power` for any
    /// committee member without a fallback.
    #[must_use]
    pub fn with_shard_committees(
        network: NetworkDefinition,
        num_shards: u64,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardId, Vec<ValidatorId>>,
    ) -> Self {
        let validator_info = build_validator_info(global_validator_set);

        let mut committees = empty_committees(num_shards);

        for (shard, validators) in shard_committees {
            if let Some(committee) = committees.get_mut(&shard) {
                for validator_id in validators {
                    let info = validator_info.get(&validator_id).unwrap_or_else(|| {
                        panic!(
                            "committee for shard {shard:?} references validator {validator_id:?} \
                             that is not in the global validator set",
                        )
                    });
                    committee.active_validators.push(validator_id);
                    committee.total_voting_power += info.voting_power;
                }
            }
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees: committees,
            validator_info,
            global_validator_set: Arc::new(global_validator_set.clone()),
        }
    }

    /// Create a snapshot whose shard partition is exactly the keys of
    /// `shard_committees`.
    ///
    /// Unlike [`Self::with_shard_committees`] (which assumes a uniform
    /// `num_shards`-way partition), the live shards are precisely those keys.
    /// Used to mirror a `BeaconState`'s committees, whose keys define the
    /// active partition — uniform today, non-uniform under resharding.
    ///
    /// # Panics
    ///
    /// Panics if a committee references a validator absent from
    /// `global_validator_set`.
    #[must_use]
    pub fn from_explicit_committees(
        network: NetworkDefinition,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardId, Vec<ValidatorId>>,
    ) -> Self {
        let validator_info = build_validator_info(global_validator_set);
        let shard_trie = ShardTrie::from_leaves(shard_committees.keys().copied());
        let committees: HashMap<ShardId, ShardCommittee> = shard_committees
            .into_iter()
            .map(|(shard, validators)| {
                let mut committee = ShardCommittee {
                    active_validators: Vec::new(),
                    total_voting_power: VotePower::ZERO,
                };
                for validator_id in validators {
                    let info = validator_info.get(&validator_id).unwrap_or_else(|| {
                        panic!(
                            "committee for shard {shard:?} references validator {validator_id:?} \
                             that is not in the global validator set",
                        )
                    });
                    committee.active_validators.push(validator_id);
                    committee.total_voting_power += info.voting_power;
                }
                (shard, committee)
            })
            .collect();

        Self {
            network,
            shard_trie,
            shard_committees: committees,
            validator_info,
            global_validator_set: Arc::new(global_validator_set.clone()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Query methods (&self)
// ═══════════════════════════════════════════════════════════════════════════

impl TopologySnapshot {
    /// Get the Radix network this topology is operating on.
    ///
    /// Used by signing-message construction sites to bind `network.id`
    /// into BLS-signed consensus messages, so signatures don't replay
    /// across networks.
    #[must_use]
    pub const fn network(&self) -> &NetworkDefinition {
        &self.network
    }

    /// Get the total number of shards (live leaves of the partition).
    #[must_use]
    pub fn num_shards(&self) -> u64 {
        self.shard_trie.len() as u64
    }

    /// The active shard partition. Routing and shard enumeration go through
    /// this; [`Self::num_shards`] is its leaf count.
    #[must_use]
    pub const fn shard_trie(&self) -> &ShardTrie {
        &self.shard_trie
    }

    /// Get the ordered committee members for a shard.
    #[must_use]
    pub fn committee_for_shard(&self, shard: ShardId) -> &[ValidatorId] {
        self.shard_committees
            .get(&shard)
            .map_or(&[][..], |c| c.active_validators.as_slice())
    }

    /// Get total voting power for a shard's committee.
    #[must_use]
    pub fn voting_power_for_shard(&self, shard: ShardId) -> VotePower {
        self.shard_committees
            .get(&shard)
            .map_or(VotePower::ZERO, |c| c.total_voting_power)
    }

    /// Get voting power for a specific validator.
    #[must_use]
    pub fn voting_power(&self, validator_id: ValidatorId) -> Option<VotePower> {
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
    pub const fn global_validator_set(&self) -> &Arc<ValidatorSet> {
        &self.global_validator_set
    }

    // ── Derived committee queries ────────────────────────────────────────

    /// Get the number of committee members for a shard.
    #[must_use]
    pub fn committee_size_for_shard(&self, shard: ShardId) -> usize {
        self.committee_for_shard(shard).len()
    }

    /// Get the index of a validator in a shard's committee.
    #[must_use]
    pub fn committee_index_for_shard(
        &self,
        shard: ShardId,
        validator_id: ValidatorId,
    ) -> Option<usize> {
        self.committee_for_shard(shard)
            .iter()
            .position(|v| *v == validator_id)
    }

    /// Check if the given voting power meets quorum for a shard (> 2/3).
    #[must_use]
    pub fn has_quorum_for_shard(&self, shard: ShardId, voting_power: VotePower) -> bool {
        VotePower::has_quorum(voting_power, self.voting_power_for_shard(shard))
    }

    /// Get the minimum voting power required for quorum in a shard.
    #[must_use]
    pub fn quorum_threshold_for_shard(&self, shard: ShardId) -> VotePower {
        VotePower::quorum_threshold(self.voting_power_for_shard(shard))
    }

    // ── Proposer selection ───────────────────────────────────────────────

    /// Get the proposer for `shard` at a given round.
    ///
    /// Rounds increase per block, so the round alone determines the leader:
    /// `committee[round % n]`. The round is QC- and header-attested, so every
    /// validator selects the same proposer. A large `round` is harmless here —
    /// the modulo can never panic — and is rejected separately at header
    /// admission.
    ///
    /// # Panics
    /// Panics if the committee for `shard` is empty (invariant violation).
    #[must_use]
    pub fn proposer_for(&self, shard: ShardId, round: Round) -> ValidatorId {
        let committee = self.committee_for_shard(shard);
        assert!(
            !committee.is_empty(),
            "proposer_for called with empty committee for shard {shard:?}",
        );
        let index = usize::try_from(round.inner() % committee.len() as u64)
            .expect("modulo of usize len fits in usize");
        committee[index]
    }

    // ── Node / transaction routing ───────────────────────────────────────

    /// Determine which shard a `NodeId` belongs to (hash-modulo).
    #[must_use]
    pub fn shard_for_node_id(&self, node_id: &NodeId) -> ShardId {
        self.shard_trie.shard_for(node_id)
    }

    /// Every shard a transaction touches via either `declared_reads` or
    /// `declared_writes`. Each shard executes the whole transaction, so
    /// every touched shard needs every input substate it doesn't own
    /// locally — reads and writes participate symmetrically here.
    pub fn all_shards_for_transaction(&self, tx: &RoutableTransaction) -> Vec<ShardId> {
        tx.declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|node_id| self.shard_for_node_id(node_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Check if a transaction is cross-shard.
    pub fn is_cross_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.all_shards_for_transaction(tx).len() > 1
    }

    /// Check if a transaction is single-shard.
    pub fn is_single_shard_transaction(&self, tx: &RoutableTransaction) -> bool {
        self.all_shards_for_transaction(tx).len() <= 1
    }

    /// Check if `shard` is involved in `tx`'s consensus path — i.e. owns at
    /// least one of `tx`'s declared writes.
    pub fn involves_shard_for_consensus(&self, shard: ShardId, tx: &RoutableTransaction) -> bool {
        tx.declared_writes()
            .iter()
            .any(|node_id| self.shard_for_node_id(node_id) == shard)
    }

    /// Check if `shard` is involved in `tx` at all (reads or writes).
    pub fn involves_shard(&self, shard: ShardId, tx: &RoutableTransaction) -> bool {
        tx.declared_writes()
            .iter()
            .chain(tx.declared_reads().iter())
            .any(|node_id| self.shard_for_node_id(node_id) == shard)
    }
}

impl std::fmt::Debug for TopologySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologySnapshot")
            .field("num_shards", &self.shard_trie.len())
            .field("shard_count_populated", &self.shard_committees.len())
            .finish_non_exhaustive()
    }
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

fn empty_committees(num_shards: u64) -> HashMap<ShardId, ShardCommittee> {
    ShardTrie::uniform_from_count(num_shards)
        .leaves()
        .map(|shard| {
            (
                shard,
                ShardCommittee {
                    active_validators: Vec::new(),
                    total_voting_power: VotePower::ZERO,
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
    use crate::{ValidatorInfo, generate_bls_keypair};

    fn make_test_validator(id: u64, power: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId::new(id),
            public_key: generate_bls_keypair().public_key(),
            voting_power: VotePower::new(power),
        }
    }

    fn make_snapshot(num_validators: u64) -> TopologySnapshot {
        let validators: Vec<_> = (0..num_validators)
            .map(|i| make_test_validator(i, 1))
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    #[test]
    fn test_committee_basics() {
        let snapshot = make_snapshot(4);

        assert_eq!(snapshot.committee_size_for_shard(ShardId::ROOT), 4);
        assert_eq!(snapshot.num_shards(), 1);
    }

    #[test]
    fn test_quorum() {
        let snapshot = make_snapshot(4);
        let shard = ShardId::ROOT;

        assert_eq!(snapshot.voting_power_for_shard(shard), VotePower::new(4));
        assert_eq!(
            snapshot.quorum_threshold_for_shard(shard),
            VotePower::new(3)
        );

        assert!(!snapshot.has_quorum_for_shard(shard, VotePower::new(2)));
        assert!(snapshot.has_quorum_for_shard(shard, VotePower::new(3)));
        assert!(snapshot.has_quorum_for_shard(shard, VotePower::new(4)));
    }

    #[test]
    fn test_proposer_rotation() {
        let snapshot = make_snapshot(4);
        let shard = ShardId::ROOT;

        // Round-only rotation: committee[round % n].
        assert_eq!(
            snapshot.proposer_for(shard, Round::new(0)),
            ValidatorId::new(0)
        );
        assert_eq!(
            snapshot.proposer_for(shard, Round::new(1)),
            ValidatorId::new(1)
        );
        assert_eq!(
            snapshot.proposer_for(shard, Round::new(3)),
            ValidatorId::new(3)
        );
        assert_eq!(
            snapshot.proposer_for(shard, Round::new(4)),
            ValidatorId::new(0)
        );
    }

    #[test]
    fn test_single_shard() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let shard = ShardId::leaf(1, 1);
        let snapshot = TopologySnapshot::single_shard(
            NetworkDefinition::simulator(),
            shard,
            2,
            ValidatorSet::new(validators),
        );

        assert_eq!(snapshot.committee_size_for_shard(shard), 4);
        // Other shard should be empty.
        assert_eq!(snapshot.committee_for_shard(ShardId::leaf(1, 0)).len(), 0);
    }

    #[test]
    fn test_with_shard_committees() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(
            ShardId::leaf(1, 0),
            vec![ValidatorId::new(0), ValidatorId::new(2)],
        );
        committees.insert(
            ShardId::leaf(1, 1),
            vec![ValidatorId::new(1), ValidatorId::new(3)],
        );

        let snapshot = TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            2,
            &vs,
            committees,
        );

        assert_eq!(snapshot.committee_for_shard(ShardId::leaf(1, 0)).len(), 2);
        assert_eq!(snapshot.committee_for_shard(ShardId::leaf(1, 1)).len(), 2);
    }

    /// `with_shard_committees` panics on a committee referencing a
    /// validator absent from the global validator set. Pinned here so any
    /// future refactor that quietly relaxes the invariant fails.
    #[test]
    #[should_panic(expected = "committee for shard")]
    fn test_with_shard_committees_panics_on_unknown_validator() {
        let validators: Vec<_> = (0..2).map(|i| make_test_validator(i, 1)).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        // ValidatorId::new(99) isn't in `vs`; constructor must reject.
        committees.insert(
            ShardId::ROOT,
            vec![ValidatorId::new(0), ValidatorId::new(99)],
        );
        let _ = TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            1,
            &vs,
            committees,
        );
    }

    /// Sum-of-voting-power invariant — committee `total_voting_power`
    /// matches the sum of constituent members' `voting_power`. Locked at
    /// constructor exit by `debug_assert_invariants` so any drift
    /// (e.g. a future constructor populating one but not the other)
    /// fires in development.
    #[test]
    fn test_total_voting_power_matches_sum_of_members() {
        let validators: Vec<_> = (0..4).map(|i| make_test_validator(i, 7)).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(
            ShardId::ROOT,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(2),
            ],
        );
        let snapshot = TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            1,
            &vs,
            committees,
        );
        assert_eq!(
            snapshot.voting_power_for_shard(ShardId::ROOT),
            VotePower::new(21)
        );
    }

    #[test]
    fn test_multi_shard_modulo_assignment() {
        let validators: Vec<_> = (0..8).map(|i| make_test_validator(i, 1)).collect();
        let snapshot = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        );

        // Shard 0: validators 0, 2, 4, 6
        let shard0 = snapshot.committee_for_shard(ShardId::leaf(1, 0));
        assert_eq!(shard0.len(), 4);
        assert!(shard0.contains(&ValidatorId::new(0)));
        assert!(shard0.contains(&ValidatorId::new(2)));
        assert!(shard0.contains(&ValidatorId::new(4)));
        assert!(shard0.contains(&ValidatorId::new(6)));

        // Shard 1: validators 1, 3, 5, 7
        let shard1 = snapshot.committee_for_shard(ShardId::leaf(1, 1));
        assert_eq!(shard1.len(), 4);
        assert!(shard1.contains(&ValidatorId::new(1)));
        assert!(shard1.contains(&ValidatorId::new(3)));
    }
}
