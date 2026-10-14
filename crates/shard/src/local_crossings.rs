//! What a block reads at its own parent.
//!
//! A crossing record and its answers sit under the producing and the
//! consuming node's targets. Where both route here, no counterpart holds
//! the cells to be asked about them, so the block reads them itself, at
//! the one anchor every voter holds through its own anchored view: the
//! parent. A record taken back on its consumer's `Never` is read here
//! too, whatever holds the answer: the fold returns the record the
//! parent holds. A decline reads this chain's own member row the same
//! way: the row leaf of a transaction whose escrowed record the block
//! holds, absent. The readings carry the empty proof, and the verifier
//! re-reads each one from its own parent view instead of walking a
//! proof.

use std::collections::BTreeMap;
use std::iter::once;

use hyperscale_hbor::Bytes;
use hyperscale_storage::{Substates, member_row_leaf};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    AbandonmentRecord, Anchor, Inclusion, Issuer, MAX_PROOFS_PER_QUERY, MerkleInclusionProof,
    ShardId, ShardTrie, StateClaim, Stated, SubstateKey, TxHash, UnclaimedCrossing,
};
use hyperscale_vm_effects::{Answered, CrossingId, CrossingLeaf, ProtocolHasher, Terms};

/// What `state` says of `key`: the presence hashing to its value, or
/// its absence.
fn read(state: &(impl Substates + ?Sized), key: SubstateKey) -> Inclusion {
    state.cell(key).map_or(Inclusion::Absent, |bytes| {
        Inclusion::Present(jmt_value_hash(&bytes))
    })
}

/// What a parent-anchored claim states of `key`: a record's value, which
/// the commit fold credits an owed record's consumer off and declines an
/// escrowed record on, and every other cell as its presence or absence
/// alone.
fn stated(state: &(impl Substates + ?Sized), key: SubstateKey) -> Stated {
    match state.cell(key) {
        Some(bytes)
            if matches!(
                CrossingLeaf::read(&ProtocolHasher, key, &bytes),
                Some(CrossingLeaf::Record { .. })
            ) =>
        {
            Bytes::new(bytes).map_or_else(|_| Stated::Inclusion(read(state, key)), Stated::Held)
        }
        Some(bytes) => Stated::Inclusion(Inclusion::Present(jmt_value_hash(&bytes))),
        None => Stated::Inclusion(Inclusion::Absent),
    }
}

/// The transaction whose member row a decline of `id`'s record reads at
/// the parent, where `state`, the parent's, holds the record escrowed
/// with no answer of its transaction: the one a block reading the
/// crossing there may decline.
fn declinable(state: &(impl Substates + ?Sized), id: &CrossingId) -> Option<TxHash> {
    let record = id.record_key(&ProtocolHasher);
    let CrossingLeaf::Record { cell, .. } =
        CrossingLeaf::read(&ProtocolHasher, record, &state.cell(record)?)?
    else {
        return None;
    };
    let answered = [Answered::Taken, Answered::Never]
        .into_iter()
        .any(|answered| {
            state
                .cell(id.answer_key(&ProtocolHasher, answered))
                .is_some_and(|value| Issuer::from(&cell).answered_by(id, answered, &value))
        });
    (matches!(cell.terms, Terms::Escrowed { .. }) && !answered).then_some(cell.tx)
}

/// The claims a block carries of its own parent, read off `state`, the
/// parent's, at `parent`.
///
/// Of each of `local_crossings`, the keys of its record and its answers
/// that `parent`'s shard holds, named for its crossing, and the member
/// row leaf of each of `rowless` that `state` does not hold, read absent
/// and named for nothing: one sorted key list, cut into claims by the
/// section's order rule. A record rides with its value, which is what
/// the fold credits, declines or takes back a crossing off: one whose
/// consumer is elsewhere is read beside its consumer's `Never` read at a
/// boundary of the consumer's shard, and one a merge brought to both its
/// ends beside its answers read here. An escrowed record of both ends no
/// answer of its transaction stands for ([`declinable`]) is read for a
/// decline alone, which reads no answer in the block: its record, and
/// its transaction's row as each of `rowless` is read. A row that stands
/// is left unread: only its absence licenses anything.
#[must_use]
pub fn parent_claims(
    local_crossings: &[CrossingId],
    rowless: &[TxHash],
    parent: Anchor,
    state: &(impl Substates + ?Sized),
) -> Vec<StateClaim> {
    let held = |key: &SubstateKey| ShardTrie::shard_owns_prefix(parent.shard, key.owner);
    let mut issuers: Vec<TxHash> = Vec::new();
    let mut readings: BTreeMap<SubstateKey, (Stated, Option<CrossingId>)> = BTreeMap::new();
    for id in local_crossings {
        let answer_keys = [Answered::Taken, Answered::Never]
            .map(|answered| id.answer_key(&ProtocolHasher, answered));
        let declines = answer_keys
            .iter()
            .all(held)
            .then(|| declinable(state, id))
            .flatten();
        issuers.extend(declines);
        let answers = answer_keys.into_iter().filter(|_| declines.is_none());
        readings.extend(
            once(id.record_key(&ProtocolHasher))
                .chain(answers)
                .filter(held)
                .map(|key| (key, (stated(state, key), Some(*id)))),
        );
    }
    readings.extend(
        rowless
            .iter()
            .chain(&issuers)
            .map(|tx| member_row_leaf(parent.shard, *tx))
            .filter(|row| read(state, *row) == Inclusion::Absent)
            .map(|row| (row, (Stated::Inclusion(Inclusion::Absent), None))),
    );
    let readings: Vec<(SubstateKey, (Stated, Option<CrossingId>))> = readings.into_iter().collect();
    readings
        .chunks(MAX_PROOFS_PER_QUERY)
        .map(|chunk| {
            StateClaim::new(
                parent,
                chunk
                    .iter()
                    .map(|(key, (stated, _))| (*key, stated.clone())),
                MerkleInclusionProof::new(Vec::new()),
            )
            .naming(
                chunk
                    .iter()
                    .filter_map(|(key, (_, id))| Some((*key, (*id)?))),
            )
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

    use hyperscale_storage::test_helpers::StatedRowChain;
    use hyperscale_storage::{SubstateStore, member_row_leaf, unclaimed_declines};
    use hyperscale_storage_memory::SimShardStorage;
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
        let claims = parent_claims(&[id], &[], parent(), &state);
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

    /// A crossing whose record the parent holds escrowed, with no answer
    /// of its transaction, is read for a decline: the record with its
    /// value and its transaction's row absent, and neither answer key.
    /// The fold declines on exactly that block. A row standing is left
    /// unread and nothing is declined. With an answer of the
    /// transaction standing the crossing is read as its three keys, and
    /// no row is read for it.
    #[test]
    fn an_unanswered_escrowed_crossing_is_read_at_the_parent_for_its_decline() {
        let id = crossing(0x41);
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let tx = TxHash(Hash32([9; 32]));
        let cell = id.cell(
            tx,
            ResourceAddr::new([0xE1; 31]),
            100,
            4_000,
            Terms::Escrowed { credit: record },
        );
        let row = member_row_leaf(ShardId::ROOT, tx);
        let at = parent().ts;
        let declined = |state: &Cells, claims: &[StateClaim]| {
            unclaimed_declines(claims, ShardId::ROOT, at, state)
                .cells
                .into_keys()
                .collect::<Vec<_>>()
        };

        let state = Cells(BTreeMap::from([(record, cell.to_bytes())]));
        let claims = parent_claims(&[id], &[], parent(), &state);
        assert_eq!(claims.len(), 1);
        let mut read = vec![record, row];
        read.sort_unstable();
        assert_eq!(claims[0].keys(), read, "the record and the row, no answer");
        assert_eq!(claims[0].held(record), Some(cell.to_bytes().as_slice()));
        assert_eq!(claims[0].crossing_of(record), Some(id));
        assert_eq!(claims[0].reading(row), Some(Inclusion::Absent));
        assert_eq!(
            disagreeing_parent_reading(&claims, ShardId::ROOT, &state),
            None
        );
        assert_eq!(declined(&state, &claims), vec![never]);

        let mut seated = Cells(state.0.clone());
        seated.0.insert(row, vec![1]);
        let claims = parent_claims(&[id], &[], parent(), &seated);
        assert_eq!(
            claims.iter().flat_map(StateClaim::keys).collect::<Vec<_>>(),
            vec![record],
            "a row that stands is left unread",
        );
        assert!(declined(&seated, &claims).is_empty());

        for answered in [Answered::Never, Answered::Taken] {
            let mut answered_state = Cells(state.0.clone());
            answered_state.0.insert(
                id.answer_key(&ProtocolHasher, answered),
                id.answer(tx, answered, 4_000).to_bytes(),
            );
            let claims = parent_claims(&[id], &[], parent(), &answered_state);
            let mut read = vec![record, never, taken];
            read.sort_unstable();
            assert_eq!(
                claims.iter().flat_map(StateClaim::keys).collect::<Vec<_>>(),
                read,
                "an answered crossing is read whole, and no row with it",
            );
            assert!(declined(&answered_state, &claims).is_empty());
        }
    }

    /// Voters holding one chain to different persistence depths judge a
    /// parent reading of an entry's leaf alike: absent over a row that
    /// stands at the parent is refused by each, and absent over a row an
    /// ancestor deleted passes each, wherever the write sits in the
    /// voter's store or its pending chain.
    #[test]
    fn voters_at_every_persistence_depth_judge_an_entry_leaf_reading_alike() {
        let row = member_row_leaf(ShardId::ROOT, StatedRowChain::<SimShardStorage>::member());
        let absent_at = |height: u64| {
            [StateClaim::new(
                Anchor {
                    height: BlockHeight::new(height),
                    ..parent()
                },
                [(row, Inclusion::Absent)],
                MerkleInclusionProof::new(Vec::new()),
            )]
        };
        for (height, refused) in [(1, Some(row)), (3, Some(row)), (4, None)] {
            for persisted in 0..=height {
                let voter = StatedRowChain::at_depth(SimShardStorage::default(), persisted);
                let state = voter.view(height).snapshot();
                assert_eq!(
                    disagreeing_parent_reading(&absent_at(height), ShardId::ROOT, &state),
                    refused,
                    "a voter with {persisted} persisted, at height {height}",
                );
                let held = [StateClaim::new(
                    absent_at(height)[0].anchor,
                    [(row, read(&state, row))],
                    MerkleInclusionProof::new(Vec::new()),
                )];
                let deepest = StatedRowChain::at_depth(SimShardStorage::default(), height);
                assert_eq!(
                    disagreeing_parent_reading(
                        &held,
                        ShardId::ROOT,
                        &deepest.view(height).snapshot(),
                    ),
                    None,
                    "what a proposer with {persisted} persisted reads at height {height}",
                );
            }
        }
    }

    /// Proposers holding one chain to different persistence depths read
    /// the row a decline stands on alike, and every voter passes what
    /// each built: no reading of a row that stands at the parent, and
    /// the row leaf absent once an ancestor has deleted it, wherever
    /// that ancestor sits in the proposer's store or its pending chain.
    #[test]
    fn proposers_at_every_persistence_depth_read_a_declines_row_alike() {
        let tx = StatedRowChain::<SimShardStorage>::member();
        let row = member_row_leaf(ShardId::ROOT, tx);
        for (height, read) in [(1, None), (3, None), (4, Some(Inclusion::Absent))] {
            let at = Anchor {
                height: BlockHeight::new(height),
                ..parent()
            };
            for persisted in 0..=height {
                let proposer = StatedRowChain::at_depth(SimShardStorage::default(), persisted);
                let built = parent_claims(&[], &[tx], at, &proposer.view(height).snapshot());
                assert_eq!(
                    built
                        .iter()
                        .filter_map(|claim| claim.reading(row))
                        .collect::<Vec<_>>(),
                    read.into_iter().collect::<Vec<_>>(),
                    "a proposer with {persisted} persisted, at height {height}",
                );
                for voting in 0..=height {
                    let voter = StatedRowChain::at_depth(SimShardStorage::default(), voting);
                    assert_eq!(
                        disagreeing_parent_reading(
                            &built,
                            ShardId::ROOT,
                            &voter.view(height).snapshot(),
                        ),
                        None,
                        "a voter with {voting} persisted, at height {height}",
                    );
                }
            }
        }
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
