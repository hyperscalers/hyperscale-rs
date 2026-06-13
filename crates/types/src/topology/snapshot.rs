//! Immutable topology snapshot for shard committee queries.
//!
//! `TopologySnapshot` is the read-only view of topology state, passed by
//! reference to subsystem methods and shared via `ArcSwap` with the `io_loop`.
//! All query methods are `&self`; mutations happen in `TopologyCoordinator`
//! (in the `hyperscale-topology` crate) which builds new snapshots.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use blake3::hash as blake3_hash;

use crate::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, Bls12381G1PublicKey, NetworkDefinition, NodeId,
    Round, RoutableTransaction, ShardId, ShardTrie, StateRoot, ValidatorId, ValidatorSet,
    VoteCount,
};

/// Per-shard committee membership, split into its two consumer views.
#[derive(Debug, Clone)]
struct ShardCommittee {
    /// Full membership — the networking view. Gossip fan-out, fetch peer
    /// pools, and sender-identity checks read this, so a member that is
    /// still bootstrapping (or has just been rotated out) keeps receiving
    /// traffic and can serve sync.
    active_validators: Vec<ValidatorId>,
    /// Ready-filtered subset of `active_validators`, in the same order —
    /// the consensus view. Proposer rotation, quorum thresholds, and
    /// vote-bitfield indexing read this, so a not-ready member never
    /// counts toward 2f+1 and imposes no liveness drag.
    consensus_validators: Vec<ValidatorId>,
}

/// A shard's beacon-attested committed boundary — the snap-sync anchor.
///
/// Projected from the beacon fold's per-shard boundary record. A joiner
/// bootstraps the shard's committed state against `state_root` and
/// block-syncs the tail from `height`; `block_hash` identifies the
/// boundary block a serving peer checkpoints at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAnchor {
    /// Subtree root at the shard's most recent committed boundary block.
    pub state_root: StateRoot,
    /// Hash of that boundary block.
    pub block_hash: BlockHash,
    /// Height of that boundary block — where tail block-sync starts.
    pub height: BlockHeight,
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
/// node's JMT leaf key, so the shard owns a contiguous state subtree.
///
/// This assumes a uniform power-of-two partition and exists only for genesis
/// and offline tooling that constructs such a partition by count. Live routing
/// must resolve against the active partition via [`TopologySnapshot::shard_for_node_id`]
/// or [`ShardTrie::shard_for`], which handle non-uniform tries.
///
/// # Panics
/// Panics if `num_shards` is not a power of two.
#[must_use]
pub fn uniform_shard_for_node(node_id: &NodeId, num_shards: u64) -> ShardId {
    ShardTrie::uniform_from_count(num_shards).shard_for(node_id)
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
/// in `validator_pubkeys`. Constructors enforce this — `with_shard_committees`
/// panics on a missing entry, `new` and `single_shard` derive committees from
/// the same `ValidatorSet` that seeds `validator_pubkeys`. Downstream code
/// relies on this to call `public_key(committee_member)` with `expect` rather
/// than fallback.
#[derive(Clone)]
pub struct TopologySnapshot {
    network: NetworkDefinition,
    shard_trie: ShardTrie,
    shard_committees: HashMap<ShardId, ShardCommittee>,
    boundaries: HashMap<ShardId, ShardAnchor>,
    /// Per-shard beacon-witness window base for the window this snapshot
    /// governs, projected from `BeaconState.witness_window_bases`.
    /// Absent shards read as `ZERO` (nothing consumed).
    witness_bases: HashMap<ShardId, BeaconWitnessLeafCount>,
    /// Per-shard observer cohorts of pending splits — each splitting
    /// shard's drawn observers and the pending child each one syncs,
    /// projected from `BeaconState.pending_reshapes`. Observers ride
    /// the splitting shard's committee in the networking view but never
    /// its consensus subset; their ready signals classify as
    /// `ReshapeReady` witness leaves.
    reshape_observers: HashMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// Per-child keeper sets of pending merges — each merging child's
    /// drawn keepers and the parent each one reforms, projected from
    /// `BeaconState.pending_reshapes`. Keepers stay ordinary `OnShard`
    /// members of their child (the networking and consensus view both
    /// see them), but their ready signals classify as `ReshapeReady`
    /// witness leaves: they signal that the sibling half has synced.
    reshape_keepers: HashMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
    /// Shards with an admitted, not-yet-executed split as of this
    /// window's committee freeze. Frozen with the same discipline as
    /// `witness_bases`, so both writes of a window's schedule entry
    /// carry the same set — [`TopologySchedule::split_at_next_boundary`]
    /// reads it to tell "no split lands at this window's end" apart from
    /// "the next window's entry isn't committed locally yet".
    ///
    /// [`TopologySchedule::split_at_next_boundary`]: crate::TopologySchedule::split_at_next_boundary
    split_pending: BTreeSet<ShardId>,
    validator_pubkeys: HashMap<ValidatorId, Bls12381G1PublicKey>,
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
        let validator_pubkeys = build_validator_pubkeys(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        for v in &validator_set.validators {
            let shard = uniform_leaf(num_shards, v.validator_id.inner() % num_shards);
            if let Some(committee) = shard_committees.get_mut(&shard) {
                committee.active_validators.push(v.validator_id);
                committee.consensus_validators.push(v.validator_id);
            }
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees,
            boundaries: HashMap::new(),
            witness_bases: HashMap::new(),
            reshape_observers: HashMap::new(),
            reshape_keepers: HashMap::new(),
            split_pending: BTreeSet::new(),
            validator_pubkeys,
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
        let validator_pubkeys = build_validator_pubkeys(&validator_set);

        let mut shard_committees = empty_committees(num_shards);

        let committee = shard_committees
            .get_mut(&shard)
            .expect("shard should be within num_shards");
        for v in &validator_set.validators {
            committee.active_validators.push(v.validator_id);
            committee.consensus_validators.push(v.validator_id);
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees,
            boundaries: HashMap::new(),
            witness_bases: HashMap::new(),
            reshape_observers: HashMap::new(),
            reshape_keepers: HashMap::new(),
            split_pending: BTreeSet::new(),
            validator_pubkeys,
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
    /// downstream code can look up `public_key` for any committee member
    /// without a fallback.
    #[must_use]
    pub fn with_shard_committees(
        network: NetworkDefinition,
        num_shards: u64,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardId, Vec<ValidatorId>>,
    ) -> Self {
        let validator_pubkeys = build_validator_pubkeys(global_validator_set);

        let mut committees = empty_committees(num_shards);

        for (shard, validators) in shard_committees {
            if let Some(committee) = committees.get_mut(&shard) {
                for validator_id in validators {
                    assert!(
                        validator_pubkeys.contains_key(&validator_id),
                        "committee for shard {shard:?} references validator {validator_id:?} \
                         that is not in the global validator set",
                    );
                    committee.active_validators.push(validator_id);
                    committee.consensus_validators.push(validator_id);
                }
            }
        }

        Self {
            network,
            shard_trie: ShardTrie::uniform_from_count(num_shards),
            shard_committees: committees,
            boundaries: HashMap::new(),
            witness_bases: HashMap::new(),
            reshape_observers: HashMap::new(),
            reshape_keepers: HashMap::new(),
            split_pending: BTreeSet::new(),
            validator_pubkeys,
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
    /// `consensus_members` carries each shard's ready-filtered consensus
    /// subset (the validators that count for proposer rotation, quorum, and
    /// vote-bitfield indexing); a shard absent from it has an empty consensus
    /// committee. `boundaries` carries each shard's attested boundary anchor;
    /// shards with no attested boundary yet are simply absent.
    /// `witness_bases` carries each shard's beacon-witness window base;
    /// shards absent from it read as `ZERO`. `reshape_observers` carries
    /// the observer cohorts of pending splits — each splitting shard
    /// mapped to its drawn observers and the pending child each one
    /// syncs; empty cohorts are pruned so an absent shard and a shard
    /// with no cohort answer queries identically. `split_pending` carries
    /// the shards whose admitted split has not executed as of this
    /// window's committee freeze.
    ///
    /// # Panics
    ///
    /// Panics if a committee references a validator absent from
    /// `global_validator_set`, or if a consensus member is not also a
    /// member of the same shard's full committee.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirror of the BeaconState projection, one argument per field
    pub fn from_explicit_committees(
        network: NetworkDefinition,
        global_validator_set: &ValidatorSet,
        shard_committees: HashMap<ShardId, Vec<ValidatorId>>,
        mut consensus_members: HashMap<ShardId, Vec<ValidatorId>>,
        boundaries: HashMap<ShardId, ShardAnchor>,
        witness_bases: HashMap<ShardId, BeaconWitnessLeafCount>,
        mut reshape_observers: HashMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
        mut reshape_keepers: HashMap<ShardId, BTreeMap<ValidatorId, ShardId>>,
        split_pending: BTreeSet<ShardId>,
    ) -> Self {
        let validator_pubkeys = build_validator_pubkeys(global_validator_set);
        let shard_trie = ShardTrie::from_leaves(shard_committees.keys().copied());
        let committees: HashMap<ShardId, ShardCommittee> = shard_committees
            .into_iter()
            .map(|(shard, validators)| {
                let mut committee = ShardCommittee {
                    active_validators: Vec::new(),
                    consensus_validators: consensus_members.remove(&shard).unwrap_or_default(),
                };
                for validator_id in validators {
                    assert!(
                        validator_pubkeys.contains_key(&validator_id),
                        "committee for shard {shard:?} references validator {validator_id:?} \
                         that is not in the global validator set",
                    );
                    committee.active_validators.push(validator_id);
                }
                for validator_id in &committee.consensus_validators {
                    assert!(
                        committee.active_validators.contains(validator_id),
                        "consensus subset for shard {shard:?} references validator \
                         {validator_id:?} outside the shard's committee",
                    );
                }
                (shard, committee)
            })
            .collect();

        reshape_observers.retain(|_, cohort| !cohort.is_empty());
        reshape_keepers.retain(|_, keepers| !keepers.is_empty());
        Self {
            network,
            shard_trie,
            shard_committees: committees,
            boundaries,
            witness_bases,
            reshape_observers,
            reshape_keepers,
            split_pending,
            validator_pubkeys,
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

    /// The pending child assigned to `validator` as an observer of the
    /// pending split of `shard`, or `None` when the validator holds no
    /// observer seat there.
    ///
    /// A `Some` answer marks the validator's ready signals on `shard`
    /// as `ReshapeReady` witness leaves and names the sub-prefix the
    /// observer syncs.
    #[must_use]
    pub fn reshape_observer_child(
        &self,
        shard: ShardId,
        validator: ValidatorId,
    ) -> Option<ShardId> {
        self.reshape_observers
            .get(&shard)
            .and_then(|cohort| cohort.get(&validator))
            .copied()
    }

    /// The parent `validator` reforms as a keeper of `child` in a pending
    /// merge, or `None` when the validator holds no keeper seat there.
    ///
    /// A `Some` answer marks the validator's ready signals on `child` as
    /// `ReshapeReady` witness leaves — the keeper has synced the sibling
    /// half into the merged store.
    #[must_use]
    pub fn reshape_keeper_parent(&self, child: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.reshape_keepers
            .get(&child)
            .and_then(|keepers| keepers.get(&validator))
            .copied()
    }

    /// Whether `shard` had an admitted, not-yet-executed split as of this
    /// window's committee freeze — i.e. whether the trie *might* replace
    /// it with its children at the end of this window. `false` is
    /// definitive: no split can land at this window's boundary.
    #[must_use]
    pub fn split_pending(&self, shard: ShardId) -> bool {
        self.split_pending.contains(&shard)
    }

    /// Get the ordered committee members for a shard — full membership,
    /// the networking view.
    ///
    /// Includes members that are not yet ready (bootstrapping joiners),
    /// so gossip fan-out and fetch peer pools still reach them. Consensus
    /// queries (proposer rotation, quorum, vote-bitfield indexing) read
    /// [`Self::consensus_committee_for_shard`] instead.
    #[must_use]
    pub fn committee_for_shard(&self, shard: ShardId) -> &[ValidatorId] {
        self.shard_committees
            .get(&shard)
            .map_or(&[][..], |c| c.active_validators.as_slice())
    }

    /// Ready-filtered consensus members for a shard, in canonical order.
    ///
    /// This is the set vote/QC signer bitfields index into, the proposer
    /// rotation cycles over, and the 2f+1 denominator counts. A committee
    /// member that has not signalled Ready is absent here while remaining
    /// in [`Self::committee_for_shard`].
    #[must_use]
    pub fn consensus_committee_for_shard(&self, shard: ShardId) -> &[ValidatorId] {
        self.shard_committees
            .get(&shard)
            .map_or(&[][..], |c| c.consensus_validators.as_slice())
    }

    /// Total votes a shard's consensus committee can cast — one per ready
    /// member.
    #[must_use]
    pub fn committee_votes(&self, shard: ShardId) -> VoteCount {
        self.shard_committees
            .get(&shard)
            .map_or(VoteCount::ZERO, |c| {
                VoteCount::of(c.consensus_validators.len())
            })
    }

    /// The votes a validator contributes — one if it is known to this
    /// snapshot, `None` otherwise.
    #[must_use]
    pub fn vote_of(&self, validator_id: ValidatorId) -> Option<VoteCount> {
        self.validator_pubkeys
            .contains_key(&validator_id)
            .then_some(VoteCount::MIN)
    }

    /// Get the public key for a validator.
    #[must_use]
    pub fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey> {
        self.validator_pubkeys.get(&validator_id).copied()
    }

    /// Get the global validator set.
    #[must_use]
    pub const fn global_validator_set(&self) -> &Arc<ValidatorSet> {
        &self.global_validator_set
    }

    /// The shard's beacon-attested boundary anchor.
    ///
    /// `None` means the shard has no attested anchor — either the shard is
    /// unknown or it has not yet had a committed boundary crossing — so a
    /// bootstrapping joiner falls back to genesis replay instead of
    /// snap-sync.
    #[must_use]
    pub fn boundary(&self, shard: ShardId) -> Option<ShardAnchor> {
        self.boundaries.get(&shard).copied()
    }

    /// The shard's beacon-witness window base for the window this
    /// snapshot governs — the folded watermark frozen at promotion.
    /// `ZERO` for shards the projection doesn't know (nothing consumed).
    #[must_use]
    pub fn witness_base(&self, shard: ShardId) -> BeaconWitnessLeafCount {
        self.witness_bases
            .get(&shard)
            .copied()
            .unwrap_or(BeaconWitnessLeafCount::ZERO)
    }

    // ── Derived committee queries ────────────────────────────────────────

    /// Get the index of a validator in a shard's consensus committee —
    /// the position vote/QC signer bitfields encode. `None` for
    /// non-members and for members that have not signalled Ready.
    #[must_use]
    pub fn committee_index_for_shard(
        &self,
        shard: ShardId,
        validator_id: ValidatorId,
    ) -> Option<usize> {
        self.consensus_committee_for_shard(shard)
            .iter()
            .position(|v| *v == validator_id)
    }

    /// Check if the given vote count meets quorum for a shard (> 2/3).
    #[must_use]
    pub fn has_quorum_for_shard(&self, shard: ShardId, votes: VoteCount) -> bool {
        VoteCount::has_quorum(votes, self.committee_votes(shard))
    }

    /// Get the minimum vote count required for quorum in a shard.
    #[must_use]
    pub fn quorum_threshold_for_shard(&self, shard: ShardId) -> VoteCount {
        VoteCount::quorum_threshold(self.committee_votes(shard))
    }

    // ── Proposer selection ───────────────────────────────────────────────

    /// Get the proposer for `shard` at a given round.
    ///
    /// Rounds increase per block, so the round alone determines the leader:
    /// `committee[round % n]` over the ready-filtered consensus committee.
    /// The round is QC- and header-attested, so every validator selects the
    /// same proposer. A large `round` is harmless here — the modulo can
    /// never panic — and is rejected separately at header admission.
    ///
    /// # Panics
    /// Panics if the consensus committee for `shard` is empty (invariant
    /// violation).
    #[must_use]
    pub fn proposer_for(&self, shard: ShardId, round: Round) -> ValidatorId {
        let committee = self.consensus_committee_for_shard(shard);
        assert!(
            !committee.is_empty(),
            "proposer_for called with empty consensus committee for shard {shard:?}",
        );
        let index = usize::try_from(round.inner() % committee.len() as u64)
            .expect("modulo of usize len fits in usize");
        committee[index]
    }

    // ── Node / transaction routing ───────────────────────────────────────

    /// Determine which shard a `NodeId` belongs to, by longest-prefix match
    /// against the active [`ShardTrie`].
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

fn build_validator_pubkeys(
    validator_set: &ValidatorSet,
) -> HashMap<ValidatorId, Bls12381G1PublicKey> {
    validator_set
        .validators
        .iter()
        .map(|v| (v.validator_id, v.public_key))
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
                    consensus_validators: Vec::new(),
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
    use crate::{Hash, ValidatorInfo, generate_bls_keypair};

    fn make_test_validator(id: u64) -> ValidatorInfo {
        ValidatorInfo {
            validator_id: ValidatorId::new(id),
            public_key: generate_bls_keypair().public_key(),
        }
    }

    #[test]
    fn reshape_observer_child_resolves_only_held_seats() {
        let shard = ShardId::ROOT;
        let (left, _) = shard.children();
        let observer = ValidatorId::new(1);
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
        let vs = ValidatorSet::new(validators);
        let members: Vec<ValidatorId> = vs.validators.iter().map(|v| v.validator_id).collect();
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            HashMap::from([(shard, members.clone())]),
            HashMap::from([(shard, members)]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (shard, BTreeMap::from([(observer, left)])),
                // Empty cohorts prune away — an absent shard and a shard
                // with no cohort answer identically.
                (ShardId::leaf(1, 1), BTreeMap::new()),
            ]),
            HashMap::new(),
            BTreeSet::from([shard]),
        );

        assert_eq!(snapshot.reshape_observer_child(shard, observer), Some(left));
        assert_eq!(
            snapshot.reshape_observer_child(shard, ValidatorId::new(0)),
            None,
        );
        assert_eq!(
            snapshot.reshape_observer_child(ShardId::leaf(1, 1), observer),
            None,
        );
        // Default construction carries no seats at all.
        assert_eq!(
            make_snapshot(4).reshape_observer_child(shard, observer),
            None
        );
    }

    fn make_snapshot(num_validators: u64) -> TopologySnapshot {
        let validators: Vec<_> = (0..num_validators).map(make_test_validator).collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    #[test]
    fn test_committee_basics() {
        let snapshot = make_snapshot(4);

        assert_eq!(snapshot.committee_for_shard(ShardId::ROOT).len(), 4);
        assert_eq!(snapshot.num_shards(), 1);
    }

    #[test]
    fn test_quorum() {
        let snapshot = make_snapshot(4);
        let shard = ShardId::ROOT;

        assert_eq!(snapshot.committee_votes(shard), VoteCount::new(4));
        assert_eq!(
            snapshot.quorum_threshold_for_shard(shard),
            VoteCount::new(3)
        );

        assert!(!snapshot.has_quorum_for_shard(shard, VoteCount::new(2)));
        assert!(snapshot.has_quorum_for_shard(shard, VoteCount::new(3)));
        assert!(snapshot.has_quorum_for_shard(shard, VoteCount::new(4)));
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
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
        let shard = ShardId::leaf(1, 1);
        let snapshot = TopologySnapshot::single_shard(
            NetworkDefinition::simulator(),
            shard,
            2,
            ValidatorSet::new(validators),
        );

        assert_eq!(snapshot.committee_for_shard(shard).len(), 4);
        // Other shard should be empty.
        assert_eq!(snapshot.committee_for_shard(ShardId::leaf(1, 0)).len(), 0);
    }

    #[test]
    fn test_with_shard_committees() {
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
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
        let validators: Vec<_> = (0..2).map(make_test_validator).collect();
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

    /// `boundary()` exposes a projected anchor; shards without one read
    /// `None`.
    #[test]
    fn test_boundary_anchor_exposed() {
        let validators: Vec<_> = (0..2).map(make_test_validator).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(ShardId::leaf(1, 0), vec![ValidatorId::new(0)]);
        committees.insert(ShardId::leaf(1, 1), vec![ValidatorId::new(1)]);

        let anchor = ShardAnchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
            height: BlockHeight::new(42),
        };
        let mut boundaries = HashMap::new();
        boundaries.insert(ShardId::leaf(1, 0), anchor);

        let mut witness_bases = HashMap::new();
        witness_bases.insert(ShardId::leaf(1, 0), BeaconWitnessLeafCount::new(7));

        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            committees.clone(),
            committees,
            boundaries,
            witness_bases,
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        );

        assert_eq!(snapshot.boundary(ShardId::leaf(1, 0)), Some(anchor));
        assert_eq!(snapshot.boundary(ShardId::leaf(1, 1)), None);
        assert_eq!(
            snapshot.witness_base(ShardId::leaf(1, 0)),
            BeaconWitnessLeafCount::new(7)
        );
        // Absent shards read as ZERO — nothing consumed.
        assert_eq!(
            snapshot.witness_base(ShardId::leaf(1, 1)),
            BeaconWitnessLeafCount::ZERO
        );
    }

    /// The committee view splits: full membership answers networking
    /// queries while the consensus subset drives proposer rotation,
    /// quorum arithmetic, and bitfield indexing.
    #[test]
    fn test_consensus_subset_excluded_from_consensus_queries() {
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
        let vs = ValidatorSet::new(validators);
        let shard = ShardId::ROOT;
        let members: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        // Validator 2 is a member but not ready — absent from the subset.
        let ready: Vec<ValidatorId> = [0u64, 1, 3].map(ValidatorId::new).to_vec();

        let mut committees = HashMap::new();
        committees.insert(shard, members.clone());
        let mut consensus = HashMap::new();
        consensus.insert(shard, ready.clone());

        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            committees,
            consensus,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        );

        // Networking view keeps everyone.
        assert_eq!(snapshot.committee_for_shard(shard), members.as_slice());
        // Consensus view drops the not-ready member everywhere.
        assert_eq!(
            snapshot.consensus_committee_for_shard(shard),
            ready.as_slice()
        );
        assert_eq!(snapshot.committee_votes(shard), VoteCount::of(3));
        assert_eq!(snapshot.quorum_threshold_for_shard(shard), VoteCount::of(3));
        assert_eq!(
            snapshot.committee_index_for_shard(shard, ValidatorId::new(2)),
            None
        );
        assert_eq!(
            snapshot.committee_index_for_shard(shard, ValidatorId::new(3)),
            Some(2)
        );
        // Proposer rotation cycles over the subset only.
        for round in 0..8u64 {
            assert_ne!(
                snapshot.proposer_for(shard, Round::new(round)),
                ValidatorId::new(2)
            );
        }
    }

    /// A consensus member outside the shard's full committee is a
    /// constructor invariant violation.
    #[test]
    #[should_panic(expected = "outside the shard's committee")]
    fn test_consensus_subset_must_be_within_committee() {
        let validators: Vec<_> = (0..2).map(make_test_validator).collect();
        let vs = ValidatorSet::new(validators);
        let mut committees = HashMap::new();
        committees.insert(ShardId::ROOT, vec![ValidatorId::new(0)]);
        let mut consensus = HashMap::new();
        consensus.insert(ShardId::ROOT, vec![ValidatorId::new(1)]);
        let _ = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            committees,
            consensus,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            BTreeSet::new(),
        );
    }

    /// A committee's vote count is its member count — one vote each.
    #[test]
    fn test_committee_votes_is_member_count() {
        let validators: Vec<_> = (0..4).map(make_test_validator).collect();
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
        assert_eq!(snapshot.committee_votes(ShardId::ROOT), VoteCount::of(3));
    }

    #[test]
    fn test_multi_shard_modulo_assignment() {
        let validators: Vec<_> = (0..8).map(make_test_validator).collect();
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
