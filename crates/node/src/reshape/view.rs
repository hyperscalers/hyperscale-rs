//! Shared reshape decision predicates over a [`TopologySnapshot`].
//!
//! Both harnesses gate reshape on the same committed-state projection: a shard's
//! boundary anchor projects (`Some`) exactly once it seeds — the projection
//! drops zeroed genesis placeholders ([`BeaconState::derive_topology_snapshot`]
//! filters `block_hash == ZERO`), so `boundary(shard).is_some()` is equivalent to
//! the raw `BeaconState.boundaries[shard].block_hash != ZERO` the simulation used
//! to read directly. Routing both the production supervisor and the simulation
//! driver through these predicates gives one definition of the gate, so neither
//! hand-rolls it and they cannot silently diverge.
//!
//! [`BeaconState::derive_topology_snapshot`]: hyperscale_types::BeaconState::derive_topology_snapshot

use std::collections::BTreeMap;

use hyperscale_types::{ShardAnchor, ShardId, TopologySnapshot, ValidatorId};

/// Reshape gate predicates over one host's [`TopologySnapshot`] — the
/// identity-agnostic projection of the committed `BeaconState`.
pub struct ReshapeView<'a> {
    topology_snapshot: &'a TopologySnapshot,
}

impl<'a> ReshapeView<'a> {
    /// View the reshape gate through `topology`.
    #[must_use]
    pub const fn new(topology_snapshot: &'a TopologySnapshot) -> Self {
        Self { topology_snapshot }
    }

    /// The shard's beacon-attested boundary anchor, or `None` until it seeds.
    #[must_use]
    pub fn boundary(&self, shard: ShardId) -> Option<ShardAnchor> {
        self.topology_snapshot.boundary(shard)
    }

    /// The shard's full committee — the ready-signal broadcast recipients.
    #[must_use]
    pub fn committee(&self, shard: ShardId) -> &[ValidatorId] {
        self.topology_snapshot.committee_for_shard(shard)
    }

    /// The split child `validator` syncs as an observer of `parent`'s pending
    /// split, or `None` when it holds no observer seat there.
    #[must_use]
    pub fn observer_child(&self, parent: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology_snapshot
            .reshape_observer_child(parent, validator)
    }

    /// The parent `validator` reforms as a keeper of `child` in a pending
    /// merge, or `None` when it holds no keeper seat there.
    #[must_use]
    pub fn keeper_parent(&self, child: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology_snapshot
            .reshape_keeper_parent(child, validator)
    }

    /// The pending-split observer cohorts, keyed by splitting parent — the
    /// orchestrator scans these for its host's observer seats.
    #[must_use]
    pub const fn observer_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.topology_snapshot.reshape_observer_cohorts()
    }

    /// The pending-merge keeper cohorts, keyed by the child each keeper runs —
    /// each maps a keeper to the parent it reforms. The orchestrator scans these
    /// for its host's keeper seats.
    #[must_use]
    pub const fn keeper_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.topology_snapshot.reshape_keeper_cohorts()
    }

    /// The executed-split parent-half cohorts, keyed by the child each member
    /// seats on — each maps a member to the parent it re-roots its local store
    /// from. The orchestrator scans these for its host's parent-half seats.
    #[must_use]
    pub const fn parent_half_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.topology_snapshot.reshape_parent_half_cohorts()
    }

    /// Whether `shard` has seeded a beacon-attested boundary anchor. The
    /// projection drops zeroed genesis placeholders, so a projected anchor
    /// means the shard's boundary crossing committed.
    #[must_use]
    pub fn seeded(&self, shard: ShardId) -> bool {
        self.topology_snapshot.boundary(shard).is_some()
    }

    /// Whether both of `parent`'s split children have seeded — the gate a
    /// splitting parent's observers flip on.
    #[must_use]
    pub fn children_seeded(&self, parent: ShardId) -> bool {
        let (left, right) = parent.children();
        self.seeded(left) && self.seeded(right)
    }

    /// Whether `parent`'s merge has executed — the beacon seated a live
    /// committee on the reformed parent and composed its anchor. The gate a
    /// merge's keepers build and flip on.
    ///
    /// A bare seeded check is ambiguous for a grow-then-merge: the parent's own
    /// pre-merge terminal boundary record can still project while the merge
    /// pends, so the keeper must wait for a *live* committee — present only once
    /// the merge actually reforms the parent.
    #[must_use]
    pub fn merge_composed(&self, parent: ShardId) -> bool {
        self.seeded(parent) && !self.committee(parent).is_empty()
    }

    /// Whether both of `parent`'s split children are live — each has produced
    /// past its genesis, not merely seeded. The make-before-break cutover: a
    /// splitting parent's committee may dissolve only once this holds.
    #[must_use]
    pub fn children_live(&self, parent: ShardId) -> bool {
        self.topology_snapshot.children_live(parent)
    }

    /// Whether `shard`'s reshape successor(s) are live — both split children, or
    /// a merge's reformed parent producing under a live committee. The signal a
    /// terminating committee waits on before it stops finalizing and serving.
    #[must_use]
    pub fn successors_live(&self, shard: ShardId) -> bool {
        self.topology_snapshot.successors_live(shard)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, Hash, NetworkDefinition, ShardAnchor,
        ShardId, StateRoot, TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet,
        WeightedTimestamp, generate_bls_keypair,
    };

    use super::ReshapeView;

    /// A non-zero anchor — the projection only carries seeded boundaries.
    fn seeded_anchor() -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
            height: BlockHeight::new(1),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            settled_waves_root: None,
        }
    }

    /// A snapshot whose projection carries exactly `seeded`'s boundaries — the
    /// shape `derive_topology_snapshot` produces after its zero-placeholder filter.
    fn snapshot_with_seeded(seeded: &[ShardId]) -> TopologySnapshot {
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            HashMap::new(),
            HashMap::new(),
            seeded.iter().map(|&s| (s, seeded_anchor())).collect(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )
    }

    #[test]
    fn children_seeded_requires_both_children() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();

        assert!(!ReshapeView::new(&snapshot_with_seeded(&[])).children_seeded(parent));
        assert!(!ReshapeView::new(&snapshot_with_seeded(&[left])).children_seeded(parent));
        assert!(ReshapeView::new(&snapshot_with_seeded(&[left, right])).children_seeded(parent));
    }

    #[test]
    fn merge_composed_requires_a_live_committee() {
        let parent = ShardId::ROOT;
        // Seeded but no live committee — the parent's pre-merge terminal record,
        // not a reformed parent.
        assert!(!ReshapeView::new(&snapshot_with_seeded(&[])).merge_composed(parent));
        assert!(!ReshapeView::new(&snapshot_with_seeded(&[parent])).merge_composed(parent));
        // Seeded with a live committee — the merge reformed it.
        let validator = ValidatorId::new(1);
        let validators = ValidatorSet::new(vec![ValidatorInfo {
            validator_id: validator,
            public_key: generate_bls_keypair().public_key(),
        }]);
        let composed = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &validators,
            std::iter::once((parent, vec![validator])).collect(),
            std::iter::once((parent, vec![validator])).collect(),
            std::iter::once((parent, seeded_anchor())).collect(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        assert!(ReshapeView::new(&composed).merge_composed(parent));
    }
}
