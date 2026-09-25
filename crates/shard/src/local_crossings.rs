//! Crossings whose two ends share this shard, read at the block's own
//! parent.
//!
//! A crossing record and its answers sit under the producing and the
//! consuming node's targets. Where both route here, no counterpart holds
//! the cells to be asked about them, so the block reads them itself, at
//! the one anchor every voter holds through its own anchored view: the
//! parent. The readings carry the empty proof, and the verifier re-reads
//! each one from its own parent view instead of walking a proof.

use hyperscale_hbor::Bytes;
use hyperscale_storage::Substates;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    AbandonmentRecord, Anchor, Inclusion, MAX_PROOFS_PER_QUERY, MerkleInclusionProof, ShardId,
    StateClaim, Stated, SubstateKey, UnclaimedCrossing,
};
use hyperscale_vm_effects::{Answered, CrossingId, CrossingLeaf, ProtocolHasher, Terms};

/// What `state` says of `key`: the presence hashing to its value, or
/// its absence.
fn read(state: &(impl Substates + ?Sized), key: SubstateKey) -> Inclusion {
    state.cell(key).map_or(Inclusion::Absent, |bytes| {
        Inclusion::Present(jmt_value_hash(&bytes))
    })
}

/// What a parent-anchored claim states of `key`: an owed record's value,
/// which the commit fold credits its consumer off, and every other cell
/// as its presence or absence alone.
fn stated(state: &(impl Substates + ?Sized), key: SubstateKey) -> Stated {
    match state.cell(key) {
        Some(bytes)
            if matches!(
                CrossingLeaf::read(&ProtocolHasher, key, &bytes),
                Some(CrossingLeaf::Record { cell, .. }) if cell.terms == Terms::Owed
            ) =>
        {
            Bytes::new(bytes).map_or_else(|_| Stated::Inclusion(read(state, key)), Stated::Held)
        }
        Some(bytes) => Stated::Inclusion(Inclusion::Present(jmt_value_hash(&bytes))),
        None => Stated::Inclusion(Inclusion::Absent),
    }
}

/// The claims a block carries for `local_crossings`, read off `state`,
/// the parent's, at `parent`.
///
/// Every crossing's three keys, cut into claims by the section's order
/// rule and each key named for its crossing. An owed record rides with
/// its value, which is what the fold credits a crossing a merge brought
/// to both its ends off.
#[must_use]
pub fn parent_claims(
    local_crossings: &[CrossingId],
    parent: Anchor,
    state: &(impl Substates + ?Sized),
) -> Vec<StateClaim> {
    let mut readings: Vec<(SubstateKey, CrossingId)> = local_crossings
        .iter()
        .flat_map(|id| {
            [
                id.record_key(&ProtocolHasher),
                id.answer_key(&ProtocolHasher, Answered::Taken),
                id.answer_key(&ProtocolHasher, Answered::Never),
            ]
            .map(|key| (key, *id))
        })
        .collect();
    readings.sort_unstable_by_key(|(key, _)| *key);
    readings.dedup_by_key(|(key, _)| *key);
    readings
        .chunks(MAX_PROOFS_PER_QUERY)
        .map(|chunk| {
            StateClaim::new(
                parent,
                chunk.iter().map(|(key, _)| (*key, stated(state, *key))),
                MerkleInclusionProof::new(Vec::new()),
            )
            .naming(chunk.iter().copied())
        })
        .collect()
}

/// The first parent-anchored reading among `claims` that `state`
/// contradicts, if any.
///
/// `state` is the verifier's own parent view. A claim anchored on
/// `local` is a parent-anchored one: admission refuses any other anchor
/// of this shard's.
#[must_use]
pub fn disagreeing_parent_reading(
    claims: &[StateClaim],
    local: ShardId,
    state: &(impl Substates + ?Sized),
) -> Option<SubstateKey> {
    claims
        .iter()
        .filter(|claim| claim.anchor.shard == local)
        .flat_map(|claim| claim.cells.iter())
        .find(|(key, stated)| stated.inclusion() != read(state, *key))
        .map(|(key, _)| *key)
}

/// Whether `state`, the parent's, holds the record `crossing` names, as
/// the name restates it.
///
/// A departure names a crossing off this shard's own leaf, so the
/// record is read here, at the parent every voter holds, and the name
/// carries no proof.
#[must_use]
pub fn unclaimed_stands(crossing: &UnclaimedCrossing, state: &(impl Substates + ?Sized)) -> bool {
    state
        .cell(crossing.record)
        .and_then(
            |bytes| match CrossingLeaf::read(&ProtocolHasher, crossing.record, &bytes)? {
                CrossingLeaf::Record { cell, .. } => Some(cell),
                CrossingLeaf::Answer { .. } => None,
            },
        )
        .is_some_and(|cell| crossing.restates(&cell))
}

/// The first crossing among `records` whose record `state`, the
/// parent's, does not hold as named.
#[must_use]
pub fn misstated_unclaimed(
    records: &[AbandonmentRecord],
    state: &(impl Substates + ?Sized),
) -> Option<SubstateKey> {
    records
        .iter()
        .flat_map(AbandonmentRecord::unclaimed)
        .find(|crossing| !unclaimed_stands(crossing, state))
        .map(|crossing| crossing.record)
}

/// `records` keeping only the crossings `state`, the parent's, holds as
/// named, and dropping a record left naming nothing.
#[must_use]
pub fn keep_standing_unclaimed(
    records: Vec<AbandonmentRecord>,
    state: &(impl Substates + ?Sized),
) -> Vec<AbandonmentRecord> {
    records
        .into_iter()
        .filter_map(|record| {
            let standing: Vec<UnclaimedCrossing> = record
                .unclaimed()
                .iter()
                .filter(|crossing| unclaimed_stands(crossing, state))
                .copied()
                .collect();
            let kept = AbandonmentRecord::new(
                record.shard(),
                record.terminal_wt(),
                record.unsettled().iter().cloned(),
            )
            .with_unclaimed(standing);
            (kept.names() > 0).then_some(kept)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        Address, AddressClass, BlockHeight, CollectionId, StateRoot, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingCell, Hash32, IntentHash, Terms, TxHash};
    use hyperscale_vm_types::ResourceAddr;

    use super::*;

    struct Cells(BTreeMap<SubstateKey, Vec<u8>>);

    impl Substates for Cells {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    fn crossing(seed: u8) -> CrossingId {
        CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed + 1; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    fn parent() -> Anchor {
        Anchor {
            shard: ShardId::ROOT,
            height: BlockHeight::new(4),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(4_000),
        }
    }

    /// A local crossing is read at the parent as three keyed, named
    /// readings with the empty proof, a present cell as the hash of its
    /// value; the verifier's re-read agrees with the parent state it was
    /// read from and disagrees once a cell differs.
    #[test]
    fn a_local_crossing_is_read_at_the_parent_and_re_read_by_the_verifier() {
        let id = crossing(0x41);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let state = Cells(BTreeMap::from([(record, vec![1, 2, 3])]));
        let claims = parent_claims(&[id], parent(), &state);
        assert_eq!(claims.len(), 1);
        let claim = &claims[0];
        assert!(claim.is_well_formed());
        assert!(claim.proof.as_bytes().is_empty());
        assert_eq!(claim.anchor, parent());
        assert_eq!(
            claim.reading(record),
            Some(Inclusion::Present(jmt_value_hash(&[1, 2, 3])))
        );
        assert_eq!(claim.reading(taken), Some(Inclusion::Absent));
        assert_eq!(claim.crossing_of(taken), Some(id));
        assert_eq!(claim.keys().len(), 3);
        assert!(claim.held(record).is_none(), "never valued");

        assert_eq!(
            disagreeing_parent_reading(&claims, ShardId::ROOT, &state),
            None
        );
        let changed = Cells(BTreeMap::from([(record, vec![9]), (taken, vec![7])]));
        assert_eq!(
            disagreeing_parent_reading(&claims, ShardId::ROOT, &changed),
            Some(record.min(taken)),
        );
        assert_eq!(
            disagreeing_parent_reading(&claims, ShardId::leaf(1, 1), &changed),
            None,
            "a claim on another shard is not a parent reading",
        );
    }

    /// A crossing named off a leaf stands where the parent holds its
    /// record as named: escrowed, issued by the named transaction, with
    /// the named consumer and validity end. An absent, misstated or
    /// owed record is the one the voter refuses and the proposer drops.
    #[test]
    fn a_crossing_named_off_a_leaf_is_read_at_the_parent() {
        let id = crossing(0x41);
        let record = id.record_key(&ProtocolHasher);
        let cell = id.cell(
            TxHash(Hash32([9; 32])),
            ResourceAddr::new([0xE1; 31]),
            100,
            5_000,
            Terms::Escrowed { credit: record },
        );
        let state = Cells(BTreeMap::from([(record, cell.to_bytes())]));
        let named = UnclaimedCrossing::of(record, &cell);
        let departed = ShardId::leaf(1, 0);
        let naming = |crossing: UnclaimedCrossing| {
            AbandonmentRecord::new(departed, WeightedTimestamp::from_millis(9_000), [])
                .with_unclaimed([crossing])
        };

        assert!(unclaimed_stands(&named, &state));
        assert_eq!(misstated_unclaimed(&[naming(named)], &state), None);
        assert_eq!(
            keep_standing_unclaimed(vec![naming(named)], &state),
            vec![naming(named)]
        );

        let misstated = UnclaimedCrossing {
            validity_end: WeightedTimestamp::from_millis(5_001),
            ..named
        };
        assert_eq!(
            misstated_unclaimed(&[naming(misstated)], &state),
            Some(record)
        );
        assert!(keep_standing_unclaimed(vec![naming(misstated)], &state).is_empty());

        let empty = Cells(BTreeMap::new());
        assert!(!unclaimed_stands(&named, &empty), "an absent record");
        let owed = Cells(BTreeMap::from([(
            record,
            CrossingCell {
                terms: Terms::Owed,
                ..cell
            }
            .to_bytes(),
        )]));
        assert!(!unclaimed_stands(&named, &owed), "an owed record");
    }
}
