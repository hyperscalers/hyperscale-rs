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

use hyperscale_types::{
    NetworkDefinition, ReshapeSeat, ResolvedCommittee, ShardAnchor, ShardId, TopologySchedule,
    TopologySnapshot, ValidatorId, WeightedTimestamp,
};

/// Reshape gate predicates over one host's [`TopologySchedule`].
///
/// Its head, the identity-agnostic projection of the committed
/// `BeaconState`, is what the gates read, and its retained windows are
/// what a followed block is classified under.
pub struct ReshapeView<'a> {
    schedule: &'a TopologySchedule,
}

impl<'a> ReshapeView<'a> {
    /// View the reshape gate through `schedule`.
    #[must_use]
    pub const fn new(schedule: &'a TopologySchedule) -> Self {
        Self { schedule }
    }

    /// The schedule the view reads.
    #[must_use]
    pub const fn schedule(&self) -> &'a TopologySchedule {
        self.schedule
    }

    fn topology_snapshot(&self) -> &'a TopologySnapshot {
        self.schedule.head()
    }

    /// The weighted timestamp `shard`'s chain terminates at — the end of
    /// the window its cut is scheduled for — or `None` while no cut is
    /// scheduled.
    ///
    /// Definitive in both directions once the shard's own window entry is
    /// in hand, since no fold schedules a terminal for the window it
    /// opens. A follower of a splitting parent reads this to recognise
    /// the terminal crossing as it passes, rather than learning which
    /// crossing was terminal an epoch later from the beacon's anchor.
    #[must_use]
    pub(crate) fn terminal_cut(&self, shard: ShardId) -> Option<WeightedTimestamp> {
        let windows = self.schedule.windows();
        if windows.epoch_duration_ms() == 0 {
            return None;
        }
        let terminal = self.topology_snapshot().scheduled_terminal(shard)?;
        Some(windows.window_of(terminal).end)
    }

    /// The chain's network definition — the domain every signature and QC
    /// verification binds to.
    #[must_use]
    pub(crate) fn network(&self) -> &NetworkDefinition {
        self.topology_snapshot().network()
    }

    /// Whether the beacon has folded a boundary crossing of `shard`'s own —
    /// it is producing on its own chain, not merely seeded.
    ///
    /// Separates the two records a reshape successor's boundary can hold. A
    /// seed written by the parent's terminal fold is the deterministic
    /// genesis, comparable to what a successor derived for itself; a
    /// crossing the successor produced is not, and replaces the seed if it
    /// folds first. A derivation cross-check is only meaningful while this
    /// is `false`.
    #[must_use]
    pub(crate) fn advanced_past_genesis(&self, shard: ShardId) -> bool {
        self.topology_snapshot().advanced_past_genesis(shard)
    }

    /// The shard's beacon-attested boundary anchor, or `None` until it seeds.
    #[must_use]
    pub(crate) fn boundary(&self, shard: ShardId) -> Option<ShardAnchor> {
        self.topology_snapshot().boundary(shard)
    }

    /// `shard`'s consensus committee resolved for QC verification — its
    /// members' public keys and the shard's quorum threshold. `None` once
    /// the shard has left the head's committee set.
    ///
    /// Callers that must verify a *terminating* shard's QCs capture this
    /// while the shard is still live, rather than resolving it after the
    /// fact: the applying fold drops a split parent from the lookahead, so
    /// the moment the head advances past its cut there is no committee
    /// left to resolve — precisely when a follower reaches its terminal.
    /// Committees are frozen per window, so a copy taken during the final
    /// window is exactly the set that signed that window's QCs.
    #[must_use]
    pub(crate) fn resolved_committee(&self, shard: ShardId) -> Option<ResolvedCommittee> {
        let members = self
            .topology_snapshot()
            .consensus_committee_for_shard(shard);
        if members.is_empty() {
            return None;
        }
        Some(ResolvedCommittee {
            public_keys: members
                .iter()
                .map(|v| self.topology_snapshot().public_key(*v))
                .collect::<Option<Vec<_>>>()?,
            quorum_threshold: self.topology_snapshot().quorum_threshold_for_shard(shard),
        })
    }

    /// The shard's full committee — the ready-signal broadcast recipients.
    #[must_use]
    pub fn committee(&self, shard: ShardId) -> &[ValidatorId] {
        self.topology_snapshot().committee_for_shard(shard)
    }

    /// The split child `validator` syncs as an observer of `parent`'s pending
    /// split, or `None` when it holds no observer seat there.
    #[must_use]
    pub fn observer_child(&self, parent: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology_snapshot()
            .reshape_observer_child(parent, validator)
    }

    /// The parent `validator` reforms as a keeper of `child` in a pending
    /// merge, or `None` when it holds no keeper seat there.
    #[must_use]
    pub fn keeper_parent(&self, child: ShardId, validator: ValidatorId) -> Option<ShardId> {
        self.topology_snapshot()
            .reshape_keeper_parent(child, validator)
    }

    /// The pending-split observer cohorts, keyed by splitting parent — the
    /// orchestrator scans these for its host's observer seats.
    #[must_use]
    pub fn observer_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> {
        self.topology_snapshot().reshape_observer_cohorts()
    }

    /// The pending-merge keeper cohorts, keyed by the child each keeper runs —
    /// each maps a keeper to its seat on the parent it reforms. The
    /// orchestrator scans these for its host's keeper seats.
    #[must_use]
    pub fn keeper_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> {
        self.topology_snapshot().reshape_keeper_cohorts()
    }

    /// Whether the beacon has credited `validator`'s observer seat in
    /// `parent`'s pending split. `false` for a seat that does not exist —
    /// a cohort that has lapsed has nothing left to assert either.
    #[must_use]
    pub(crate) fn observer_ready(&self, parent: ShardId, validator: ValidatorId) -> bool {
        self.topology_snapshot()
            .reshape_observer_seat(parent, validator)
            .is_some_and(|seat| seat.ready)
    }

    /// Whether the beacon has credited `validator`'s keeper seat on `child`.
    #[must_use]
    pub(crate) fn keeper_ready(&self, child: ShardId, validator: ValidatorId) -> bool {
        self.topology_snapshot()
            .reshape_keeper_seat(child, validator)
            .is_some_and(|seat| seat.ready)
    }

    /// The executed-split parent-half cohorts, keyed by the child each member
    /// seats on — each maps a member to the parent it re-roots its local store
    /// from. The orchestrator scans these for its host's parent-half seats.
    #[must_use]
    pub fn parent_half_cohorts(&self) -> &BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> {
        self.topology_snapshot().reshape_parent_half_cohorts()
    }

    /// Whether `shard` has seeded a beacon-attested boundary anchor. The
    /// projection drops zeroed genesis placeholders, so a projected anchor
    /// means the shard's boundary crossing committed.
    #[must_use]
    pub(crate) fn seeded(&self, shard: ShardId) -> bool {
        self.topology_snapshot().boundary(shard).is_some()
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
    pub(crate) fn merge_composed(&self, parent: ShardId) -> bool {
        self.seeded(parent) && !self.committee(parent).is_empty()
    }

    /// Whether both of `parent`'s split children are live — each has produced
    /// past its genesis, not merely seeded. The make-before-break cutover: a
    /// splitting parent's committee may dissolve only once this holds.
    #[must_use]
    pub fn children_live(&self, parent: ShardId) -> bool {
        self.topology_snapshot().children_live(parent)
    }

    /// Whether `shard`'s reshape successor(s) are live — both split children, or
    /// a merge's reformed parent producing under a live committee. The signal a
    /// terminating committee waits on before it stops finalizing and serving.
    #[must_use]
    pub fn successors_live(&self, shard: ShardId) -> bool {
        self.topology_snapshot().successors_live(shard)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch, Hash, NetworkDefinition,
        ShardAnchor, ShardId, Signer, StateRoot, TopologySchedule, TopologySnapshot, ValidatorId,
        ValidatorInfo, ValidatorSet, WeightedTimestamp,
    };

    use super::ReshapeView;

    /// A schedule headed by `snapshot`, cut into windows `epoch_duration_ms`
    /// long.
    fn windowed(snapshot: TopologySnapshot, epoch_duration_ms: u64) -> TopologySchedule {
        TopologySchedule::new(
            epoch_duration_ms,
            Epoch::GENESIS,
            std::sync::Arc::new(snapshot),
        )
    }

    /// A non-zero anchor — the projection only carries seeded boundaries.
    fn seeded_anchor() -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
            height: BlockHeight::new(1),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_roots: None,
            handoff_complete: None,
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

    /// A scheduled cut resolves to the *end* of the window it names —
    /// the instant the parent's chain terminates and its children take
    /// over — and is absent both when nothing is scheduled and on a
    /// single-committee schedule that has no boundaries at all.
    #[test]
    fn terminal_cut_resolves_the_scheduled_window_end() {
        let parent = ShardId::ROOT;
        let unscheduled = windowed(snapshot_with_seeded(&[]), 1_000);
        assert_eq!(ReshapeView::new(&unscheduled).terminal_cut(parent), None);

        let terminals = BTreeMap::from([(parent, Epoch::new(6))]);
        let scheduled = windowed(
            snapshot_with_seeded(&[]).with_scheduled_terminals(terminals.clone()),
            1_000,
        );
        assert_eq!(
            ReshapeView::new(&scheduled).terminal_cut(parent),
            Some(WeightedTimestamp::from_millis(7_000)),
        );
        // A shard with no cut of its own is unaffected by another's.
        assert_eq!(
            ReshapeView::new(&scheduled).terminal_cut(ShardId::leaf(1, 0)),
            None,
        );
        // No epoch boundaries exist to cut on.
        let unwindowed = windowed(
            snapshot_with_seeded(&[]).with_scheduled_terminals(terminals),
            0,
        );
        assert_eq!(ReshapeView::new(&unwindowed).terminal_cut(parent), None);
    }

    #[test]
    fn children_seeded_requires_both_children() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();

        let seeded = |shards: &[ShardId]| windowed(snapshot_with_seeded(shards), 1_000);
        assert!(!ReshapeView::new(&seeded(&[])).children_seeded(parent));
        assert!(!ReshapeView::new(&seeded(&[left])).children_seeded(parent));
        assert!(ReshapeView::new(&seeded(&[left, right])).children_seeded(parent));
    }

    #[test]
    fn merge_composed_requires_a_live_committee() {
        let parent = ShardId::ROOT;
        // Seeded but no live committee — the parent's pre-merge terminal record,
        // not a reformed parent.
        let seeded = |shards: &[ShardId]| windowed(snapshot_with_seeded(shards), 1_000);
        assert!(!ReshapeView::new(&seeded(&[])).merge_composed(parent));
        assert!(!ReshapeView::new(&seeded(&[parent])).merge_composed(parent));
        // Seeded with a live committee — the merge reformed it.
        let validator = ValidatorId::new(1);
        let validators = ValidatorSet::new(vec![ValidatorInfo {
            validator_id: validator,
            public_key: BlsSigner::generate().public_key(),
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
        assert!(ReshapeView::new(&windowed(composed, 1_000)).merge_composed(parent));
    }
}
