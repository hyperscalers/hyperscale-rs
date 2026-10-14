//! The crossing settlements and credits a block's claims license,
//! applied in its commit fold.
//!
//! A producer's record is removed once its consumer's `Taken` of the
//! record's own transaction is read present, and a consumer's answer is
//! removed once the record it answers for is read absent, with its
//! producing member's exit, at a boundary the beacon recorded for the
//! record's shard. Each is a value-free write the evidence for is a
//! reading the block carries, so every voter recomputes it inside
//! `state_root` and no member runs for it. What retires a record is the
//! claim's own rule, [`StateClaim::retires`]; what removes an answer
//! reads the answer, so it is decided here, where the readings meet the
//! state the block lands on.
//!
//! An answer is the one trace that its record was taken or refused. A
//! recovery of the record's shard discards that shard's chain above its
//! last recorded boundary, and a retirement discarded with it leaves the
//! record standing again: with the answer still here the record meets
//! it, is credited or taken no second time and is retired again. So an
//! answer goes only on a reading no recovery discards.
//!
//! An owed crossing's consumer runs no member either: a valued reading
//! of the record, with no `Taken` of its transaction standing in the
//! parent, credits the consumer's vault and writes the `Taken` in the
//! same fold.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    Anchor, Inclusion, Issuer, Movement, ProtocolHasher, SettledWrites, ShardId, StateClaim,
    StateWrites, SubstateKey, TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::{
    Answered, Crossing, CrossingAnswer, CrossingCell, CrossingId, CrossingLeaf, Terms,
};

use crate::Substates;
use crate::shard::members::member_row_leaf;
use crate::shard::sweep::committed_tx_cell_key;
use crate::shard::writes::fold_state_writes;

/// Among the held readings of the key the block carries, the one at
/// the newest anchor by weighted time, decoded as a crossing leaf.
///
/// `Some` only for a record, and a bare presence of the key licenses
/// nothing — a reading that carries no value says nothing an arrival
/// can be composed from.
///
/// The arrival a consuming core runs against. The answer does not
/// depend on how many readings of the key a block carries or in what
/// order.
#[must_use]
pub fn live_record(
    state_claims: &[StateClaim],
    key: SubstateKey,
) -> Option<(Crossing, CrossingCell)> {
    state_claims
        .iter()
        .filter_map(|claim| claim.held(key).map(|bytes| (claim.anchor.ts, bytes)))
        .max_by_key(|(ts, _)| *ts)
        .and_then(
            |(_, bytes)| match CrossingLeaf::read(&ProtocolHasher, key, bytes)? {
                CrossingLeaf::Record { crossing, cell } => Some((crossing, cell)),
                CrossingLeaf::Answer { .. } => None,
            },
        )
}

/// Every record `state_claims` read live, with the transaction that
/// issued it.
///
/// The crossings a consumer here waiting on them counts as arrived. Off
/// [`live_record`], so the reading a member runs against is the one that
/// counts.
#[must_use]
pub fn record_arrivals(state_claims: &[StateClaim]) -> BTreeSet<(SubstateKey, TxHash)> {
    let keys: BTreeSet<SubstateKey> = state_claims.iter().flat_map(StateClaim::keys).collect();
    keys.into_iter()
        .filter_map(|key| live_record(state_claims, key).map(|(_, cell)| (key, cell.tx)))
        .collect()
}

/// The credits the owed records `state_claims` read license, with the
/// `Taken` answer each writes: what the consumer's commit fold lands in
/// place of a member taking the crossing.
///
/// A reading credits where it names its crossing at the crossing's own
/// record key, carries the record's value, the value reads as an owed
/// record of that crossing, and `state` holds no `Taken` of the
/// record's transaction for it. The guard is read in the parent, and a
/// record credits at most once in a block, and not at all beside an
/// absence of the same key the block carries. So one owed record is
/// credited once: within a block by the last rule, and across blocks by
/// the `Taken` it writes, which stands until a boundary of the record's
/// shard shows the record gone for good.
///
/// A `Taken` of another transaction answered a record that stood at
/// this key before and guards nothing of this one: the credit lands and
/// its own `Taken` is written over the other.
///
/// Reads block content and one parent point per reading, and never
/// fails: a reading that does not decode licenses nothing.
#[must_use]
pub fn owed_credits(state_claims: &[StateClaim], state: &(impl Substates + ?Sized)) -> StateWrites {
    let absent: BTreeSet<SubstateKey> = state_claims
        .iter()
        .flat_map(|claim| claim.cells.iter())
        .filter(|(_, stated)| stated.inclusion() == Inclusion::Absent)
        .map(|(key, _)| *key)
        .collect();
    let mut credited: BTreeSet<SubstateKey> = BTreeSet::new();
    let mut writes = StateWrites::default();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher) || absent.contains(key) {
                continue;
            }
            let Some(bytes) = claim.held(*key) else {
                continue;
            };
            let Some(CrossingLeaf::Record { crossing, cell }) =
                CrossingLeaf::read(&ProtocolHasher, *key, bytes)
            else {
                continue;
            };
            if cell.terms != Terms::Owed || crossing.id != *id {
                continue;
            }
            let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
            let answered = state
                .cell(taken)
                .is_some_and(|value| Issuer::from(&cell).answered_by(id, Answered::Taken, &value));
            if answered || !credited.insert(*key) {
                continue;
            }
            let mut credit = StateWrites::default();
            credit.cells.insert(
                taken,
                Some(
                    id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                        .to_bytes(),
                ),
            );
            credit.movements.insert(
                id.owed_credit(&ProtocolHasher, cell.resource),
                Movement {
                    resource: cell.resource,
                    credit: cell.amount,
                    debit: 0,
                    unjudged_debit: 0,
                },
            );
            fold_state_writes(&mut writes, &credit);
        }
    }
    writes
}

/// What a block's claims do to the crossing families, read against the
/// state it lands on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CrossingSettlements {
    /// The cells removed, ascending and each once.
    pub removed: Vec<SubstateKey>,
    /// The unseen `Never`s a presence of their record marks seen, with
    /// their bytes.
    pub seen: Vec<(SubstateKey, Vec<u8>)>,
}

/// What `state_claims` do to the crossing families of `state`, the
/// block `local`'s chain commits at `anchor` landing on it.
///
/// Every key `written` writes is left alone: a receipt is its member's
/// own decision and always lands.
///
/// - A record whose `Taken` is read present as the answer to it is
///   removed ([`StateClaim::retires`], over the record `state` holds).
/// - An answer whose record is read absent, under the crossing's name,
///   is removed where the claim is anchored on this chain itself (a
///   crossing a merge brought together, read at the parent), or where
///   the claim is at a boundary of the block
///   ([`StateClaim::at_boundary`]) and its producer member's exit is
///   proven at that anchor ([`exit_proven`]). A fresh absence removes
///   nothing, whatever the answer says of itself.
/// - An unseen `Never` whose record is read present is marked seen.
///
/// The fold tells a boundary reading by its age against the block, and
/// reads no schedule: that the anchor is a boundary the beacon recorded
/// is what every voter held the block to before it committed.
///
/// A key absent from `state` has nothing to remove: a record already
/// reclaimed, an answer already deleted, or a cell under a prefix a
/// follower does not hold.
#[must_use]
pub fn crossing_settlements(
    state_claims: &[StateClaim],
    local: ShardId,
    anchor: WeightedTimestamp,
    written: &SettledWrites,
    state: &(impl Substates + ?Sized),
) -> CrossingSettlements {
    let untouched = |key: &SubstateKey| !written.cells().contains_key(key);
    let standing = |id: &CrossingId| {
        state
            .cell(id.record_key(&ProtocolHasher))
            .and_then(|value| Issuer::of_record(id, &value))
    };
    let mut removed: BTreeSet<SubstateKey> = state_claims
        .iter()
        .flat_map(|claim| claim.retires(standing))
        .map(|(key, _)| key)
        .filter(untouched)
        .collect();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher)
                || claim.reading(*key) != Some(Inclusion::Absent)
            {
                continue;
            }
            for answered in [Answered::Taken, Answered::Never] {
                let answer_key = id.answer_key(&ProtocolHasher, answered);
                if !untouched(&answer_key) {
                    continue;
                }
                let Some(bytes) = state.cell(answer_key) else {
                    continue;
                };
                let deletes = claim.anchor.shard == local
                    || (claim.at_boundary(anchor)
                        && CrossingAnswer::from_bytes(&bytes).is_none_or(|answer| {
                            exit_proven(state_claims, &claim.anchor, &answer)
                        }));
                if deletes {
                    removed.insert(answer_key);
                }
            }
        }
    }
    let mut seen: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
    for claim in state_claims {
        for (key, id) in claim.crossings.iter() {
            if *key != id.record_key(&ProtocolHasher)
                || !matches!(claim.reading(*key), Some(Inclusion::Present(_)))
            {
                continue;
            }
            let never = id.answer_key(&ProtocolHasher, Answered::Never);
            if !untouched(&never) || removed.contains(&never) {
                continue;
            }
            let Some(answer) = state
                .cell(never)
                .as_deref()
                .and_then(CrossingAnswer::from_bytes)
            else {
                continue;
            };
            if !answer.seen {
                seen.insert(never, answer.seen_now().to_bytes());
            }
        }
    }
    CrossingSettlements {
        removed: removed.into_iter().collect(),
        seen: seen.into_iter().collect(),
    }
}

/// Whether the claims prove, at exactly `anchor`, that the producing
/// member of `answer`'s transaction on the anchor's shard has exited or
/// never existed and can never commit: its member row read absent, and
/// either the transaction's committed marker read present or the anchor
/// at or past the transaction's validity end.
///
/// With either, the shard cannot commit the transaction after the
/// anchor: it commits a transaction once, and admits none past its
/// validity end. A row is written by the block committing the
/// transaction and goes with its member's finalization, which lands the
/// member's own writes in the same block, or with a fate. Neither a fate
/// nor a reclaim writes the record, and no line runs a member whose row
/// is gone, so with the row gone nothing writes the record again on any
/// chain extending the anchor, and its absence there stands for good. A
/// reclaim deletes no row: a leg its reclaim took back without its ever
/// running keeps its row, released, until its fate at the close of its
/// leg entry window, and proves no exit before it. A boundary taken
/// before the record was written shows the row standing, or the clock
/// short of the validity end with no marker, and proves nothing.
/// Readings at different anchors never combine.
fn exit_proven(state_claims: &[StateClaim], anchor: &Anchor, answer: &CrossingAnswer) -> bool {
    let validity_end = WeightedTimestamp::from_millis(answer.validity_end_ms);
    let row = member_row_leaf(anchor.shard, answer.tx);
    let marker = committed_tx_cell_key(anchor.shard, answer.tx, validity_end);
    let at_anchor = || state_claims.iter().filter(|claim| claim.anchor == *anchor);
    let row_gone = at_anchor().any(|claim| claim.reading(row) == Some(Inclusion::Absent));
    let committed =
        at_anchor().any(|claim| matches!(claim.reading(marker), Some(Inclusion::Present(_))));
    row_gone && (committed || anchor.ts >= validity_end)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::slice::from_ref;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::{stub_abort_charge, stub_stated_terms, test_key};
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CollectionId, Deadline, EpochWindows,
        FrontierInputs, Hash, MemberTerms, MerkleInclusionProof, RETENTION_HORIZON, ReadFence,
        ReadFrontier, ReadMark, Reading, ResourceAddr, Settlement, ShardId, StateRoot, Stated,
        StatedTerms, TickHalf, TickId, TickLine, TxHash, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash};
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::shard::members::{MemberIndex, MemberInputs, RowState, SettledHalf};

    /// A store of cells alone.
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
            consumer: Address::new([seed | 0x80; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    fn claim(readings: Vec<(SubstateKey, Inclusion, CrossingId)>) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 1),
                height: BlockHeight::new(4),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(4_000),
            },
            readings
                .iter()
                .map(|(key, inclusion, _)| (*key, *inclusion)),
            MerkleInclusionProof::dummy(),
        )
        .naming(readings.into_iter().map(|(key, _, id)| (key, id)))
    }

    /// The fold removes what the claims license and the state holds,
    /// leaves a key a receipt writes to the receipt, writes nothing for
    /// a key absent from the state, and names a key licensed twice once.
    #[test]
    fn the_fold_removes_what_is_licensed_and_present() {
        let retired = crossing(0x11);
        let answered = crossing(0x12);
        let gone = crossing(0x13);
        let written = crossing(0x14);
        let key = |id: &CrossingId, answered: Option<Answered>| {
            answered.map_or_else(
                || id.record_key(&ProtocolHasher),
                |answered| id.answer_key(&ProtocolHasher, answered),
            )
        };
        let state = Cells(BTreeMap::from([
            (key(&retired, None), escrowed(&retired, issuer())),
            (
                key(&answered, Some(Answered::Taken)),
                answered
                    .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                    .to_bytes(),
            ),
            (key(&written, None), escrowed(&written, issuer())),
            (test_key(0x50), vec![5]),
        ]));
        let receipts =
            SettledWrites::from_absolutes(BTreeMap::from([(key(&written, None), Some(vec![9]))]));
        let (row, _) = exit_keys();
        let claims = vec![
            claim_at(
                4,
                VALIDITY_END_MS,
                vec![
                    taken_by(&retired, issuer()),
                    (key(&answered, None), Inclusion::Absent, answered),
                    taken_by(&gone, issuer()),
                    taken_by(&written, issuer()),
                ],
                vec![(row, Inclusion::Absent)],
            ),
            claim_at(
                5,
                VALIDITY_END_MS,
                vec![taken_by(&retired, issuer())],
                vec![],
            ),
        ];
        let mut expected = vec![key(&retired, None), key(&answered, Some(Answered::Taken))];
        expected.sort_unstable();
        assert_eq!(
            crossing_settlements(&claims, ELSEWHERE, past(&claims), &receipts, &state).removed,
            expected,
            "the retired record and the answered crossing's Taken go; the Never absent from \
             the state, the record already gone and the key a receipt writes do not",
        );
        assert!(
            crossing_settlements(&[], ELSEWHERE, WeightedTimestamp::ZERO, &receipts, &state)
                == CrossingSettlements::default(),
            "no claim licenses nothing",
        );
    }

    /// The escrowed record of `id` that `tx` issued, as its cell holds
    /// it.
    fn escrowed(id: &CrossingId, tx: TxHash) -> Vec<u8> {
        id.cell(
            tx,
            RESOURCE,
            AMOUNT,
            VALIDITY_END_MS,
            Terms::Escrowed {
                credit: test_key(0x60),
            },
        )
        .to_bytes()
    }

    /// `id`'s `Taken` read present, stating the answer `tx`'s take
    /// writes.
    fn taken_by(id: &CrossingId, tx: TxHash) -> (SubstateKey, Inclusion, CrossingId) {
        let taken = id.answer(tx, Answered::Taken, VALIDITY_END_MS).to_bytes();
        (
            id.answer_key(&ProtocolHasher, Answered::Taken),
            Inclusion::Present(jmt_value_hash(&taken)),
            *id,
        )
    }

    /// A transaction carrying the same intent after `issuer()`'s record
    /// at the key has gone.
    fn later() -> TxHash {
        TxHash::from(Hash::from_bytes(b"a later transaction"))
    }

    /// A record key names its edge and no transaction. A `Taken` one
    /// transaction's consumer wrote is no answer to the record a later
    /// transaction issued on the same edge, and retires nothing of it;
    /// the later transaction's own `Taken` does.
    #[test]
    fn an_old_take_retires_nothing_of_a_later_transactions_record() {
        let id = crossing(0x15);
        let record = id.record_key(&ProtocolHasher);
        let state = Cells(BTreeMap::from([(record, escrowed(&id, later()))]));
        assert_eq!(
            fold(&[claim(vec![taken_by(&id, issuer())])], &state),
            CrossingSettlements::default(),
            "the earlier transaction's Taken leaves the later record standing",
        );
        assert_eq!(
            fold(&[claim(vec![taken_by(&id, later())])], &state).removed,
            vec![record],
            "and the later transaction's own Taken retires it",
        );
        let restated = id
            .answer(later(), Answered::Taken, VALIDITY_END_MS + 1)
            .to_bytes();
        let unbound = (
            id.answer_key(&ProtocolHasher, Answered::Taken),
            Inclusion::Present(jmt_value_hash(&restated)),
            id,
        );
        assert_eq!(
            fold(&[claim(vec![unbound])], &state),
            CrossingSettlements::default(),
            "an answer stating another validity end is not the record's",
        );
    }

    /// The chain committing the block, other than the producer's.
    const ELSEWHERE: ShardId = ShardId::leaf(1, 0);
    /// The producer's shard, where every reading below is taken.
    const PRODUCER: ShardId = ShardId::leaf(1, 1);

    /// A claim of `PRODUCER`'s state at `height` and `ts_ms`, naming the
    /// crossing readings and leaving the rest unnamed.
    fn claim_at(
        height: u64,
        ts_ms: u64,
        named: Vec<(SubstateKey, Inclusion, CrossingId)>,
        unnamed: Vec<(SubstateKey, Inclusion)>,
    ) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            named
                .iter()
                .map(|(key, inclusion, _)| (*key, *inclusion))
                .chain(unnamed),
            MerkleInclusionProof::dummy(),
        )
        .naming(named.into_iter().map(|(key, _, id)| (key, id)))
    }

    /// A consumer's state holding `id`'s `Never`, seen or not.
    fn declined(id: &CrossingId, seen: bool) -> Cells {
        let never = if seen {
            id.answer(issuer(), Answered::Never, VALIDITY_END_MS)
        } else {
            id.unseen_never(issuer(), VALIDITY_END_MS)
        };
        Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Never),
            never.to_bytes(),
        )]))
    }

    fn never_of(id: &CrossingId) -> SubstateKey {
        id.answer_key(&ProtocolHasher, Answered::Never)
    }

    fn absent(id: &CrossingId) -> (SubstateKey, Inclusion, CrossingId) {
        (id.record_key(&ProtocolHasher), Inclusion::Absent, *id)
    }

    fn present(id: &CrossingId) -> (SubstateKey, Inclusion, CrossingId) {
        (
            id.record_key(&ProtocolHasher),
            Inclusion::Present([7; 32]),
            *id,
        )
    }

    /// The anchor of a block every one of `claims` is at a boundary of:
    /// a millisecond more than a retention horizon past the newest.
    fn past(claims: &[StateClaim]) -> WeightedTimestamp {
        claims
            .iter()
            .map(|claim| claim.anchor.ts)
            .max()
            .unwrap_or(WeightedTimestamp::ZERO)
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_millis(1))
    }

    /// The anchor of a block every one of `claims` is fresh to: exactly
    /// a retention horizon past the oldest, the last instant admission
    /// carries it as a fresh claim.
    fn fresh_to(claims: &[StateClaim]) -> WeightedTimestamp {
        claims
            .iter()
            .map(|claim| claim.anchor.ts)
            .min()
            .unwrap_or(WeightedTimestamp::ZERO)
            .plus(RETENTION_HORIZON)
    }

    /// What a block carrying `claims`, each at a boundary of it, does on
    /// a chain other than the producer's.
    fn fold(claims: &[StateClaim], state: &Cells) -> CrossingSettlements {
        crossing_settlements(
            claims,
            ELSEWHERE,
            past(claims),
            &SettledWrites::default(),
            state,
        )
    }

    /// What a block carrying `claims`, each fresh to it, does on a chain
    /// other than the producer's.
    fn fold_fresh(claims: &[StateClaim], state: &Cells) -> CrossingSettlements {
        crossing_settlements(
            claims,
            ELSEWHERE,
            fresh_to(claims),
            &SettledWrites::default(),
            state,
        )
    }

    /// A consumer's state holding `id`'s `Taken`.
    fn took(id: &CrossingId) -> Cells {
        Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        )]))
    }

    /// A fresh absence of the record deletes no answer, whatever the
    /// answer says of itself and whatever the block reads beside it: a
    /// `Taken`, a `Never` its consumer read the record for and one it
    /// did not each stand, with the producing member's exit proven at
    /// the same anchor or with the record read present below it. The
    /// absence is on a chain a recovery of the producer can still
    /// discard, up to the last instant it is fresh.
    #[test]
    fn a_fresh_absence_deletes_no_answer() {
        let id = crossing(0x21);
        let (row, marker) = exit_keys();
        let exited = claim_at(
            90,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let read_before = claim_at(80, VALIDITY_END_MS - 1_000, vec![present(&id)], vec![]);
        for state in [took(&id), declined(&id, true), declined(&id, false)] {
            assert_eq!(
                fold_fresh(from_ref(&exited), &state).removed,
                Vec::new(),
                "a fresh absence with its producer's exit deletes nothing",
            );
            assert_eq!(
                fold_fresh(&[read_before.clone(), exited.clone()], &state).removed,
                Vec::new(),
                "nor does one the block read the record present below",
            );
            assert_eq!(
                fold(from_ref(&exited), &state).removed.len(),
                1,
                "the same reading a millisecond past the horizon is a boundary's",
            );
        }
    }

    /// A record read absent at a boundary deletes its answers once the
    /// producing member's exit is proven at that boundary: the row gone
    /// with the anchor at or past the transaction's validity end, or
    /// with its committed marker present. A `Taken` and a `Never` go
    /// alike, seen or not.
    #[test]
    fn a_boundary_absence_deletes_an_answer_once_its_producers_member_has_exited() {
        let id = crossing(0x22);
        let (row, marker) = exit_keys();
        let by_clock = claim_at(
            90,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        );
        let by_marker = claim_at(
            8,
            8_000,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        for proof in [by_clock, by_marker] {
            let proof = from_ref(&proof);
            assert_eq!(fold(proof, &took(&id)).removed, vec![taken]);
            assert_eq!(
                fold(proof, &declined(&id, true)).removed,
                vec![never_of(&id)]
            );
            assert_eq!(
                fold(proof, &declined(&id, false)).removed,
                vec![never_of(&id)]
            );
        }

        // The exit's readings ride in another claim at the same anchor.
        let split = [
            claim_at(90, VALIDITY_END_MS, vec![absent(&id)], vec![]),
            claim_at(90, VALIDITY_END_MS, vec![], vec![(row, Inclusion::Absent)]),
        ];
        assert_eq!(fold(&split, &took(&id)).removed, vec![taken]);

        // Both answers of one crossing, each of its own transaction.
        let mut both = took(&id);
        both.0.insert(
            never_of(&id),
            id.answer(later(), Answered::Never, VALIDITY_END_MS)
                .to_bytes(),
        );
        assert_eq!(
            fold(&split, &both).removed,
            vec![taken],
            "an answer whose own transaction's row is not read stands",
        );
    }

    /// An answer whose producer's shard has departed goes at a boundary
    /// of the shard holding the record's prefix since, on that shard's
    /// own row leaf: the predecessor's terminal fated every row, so the
    /// successor's leaf is what says no member of the transaction writes
    /// on the chain extending the anchor. The departed shard's leaf read
    /// at the successor's anchor proves nothing of that chain.
    #[test]
    fn an_answer_of_a_departed_producer_goes_at_its_successors_boundary() {
        let id = crossing(0x23);
        let (successor, _) = PRODUCER.children();
        let at_successor = |row: SubstateKey| {
            StateClaim::new(
                Anchor {
                    shard: successor,
                    height: BlockHeight::new(91),
                    state_root: StateRoot::ZERO,
                    ts: WeightedTimestamp::from_millis(VALIDITY_END_MS),
                },
                [
                    (id.record_key(&ProtocolHasher), Inclusion::Absent),
                    (row, Inclusion::Absent),
                ],
                MerkleInclusionProof::dummy(),
            )
            .naming([(id.record_key(&ProtocolHasher), id)])
        };
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        assert_eq!(
            fold(
                &[at_successor(member_row_leaf(successor, issuer()))],
                &took(&id)
            )
            .removed,
            vec![taken],
        );
        assert!(
            fold(&[at_successor(exit_keys().0)], &took(&id))
                .removed
                .is_empty()
        );
    }

    /// A boundary at which the record reads absent because it is not
    /// yet written deletes nothing: the producing member's row stands
    /// there, or the transaction is uncommitted with its validity still
    /// open, or nothing is read of the member at all.
    #[test]
    fn a_boundary_before_the_record_was_written_deletes_nothing() {
        let id = crossing(0x24);
        let (row, marker) = exit_keys();
        let standing = claim_at(
            8,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Present([2; 32])),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        let uncommitted = claim_at(
            8,
            VALIDITY_END_MS - 1,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent), (marker, Inclusion::Absent)],
        );
        let unread = claim_at(8, VALIDITY_END_MS, vec![absent(&id)], vec![]);
        for state in [took(&id), declined(&id, true), declined(&id, false)] {
            for boundary in [&standing, &uncommitted, &unread] {
                assert_eq!(
                    fold(from_ref(boundary), &state),
                    CrossingSettlements::default(),
                );
            }
        }
    }

    /// A presence of the record marks an unseen `Never` seen, and leaves
    /// a seen one alone.
    #[test]
    fn a_presence_marks_an_unseen_never_seen() {
        let id = crossing(0x23);
        let settled = fold(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            &declined(&id, false),
        );
        assert_eq!(
            settled.seen,
            vec![(
                never_of(&id),
                id.answer(issuer(), Answered::Never, VALIDITY_END_MS)
                    .to_bytes()
            )],
        );
        let settled = fold(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            &declined(&id, true),
        );
        assert!(settled.seen.is_empty());
    }

    /// A `Never` a receipt writes is the receipt's, and no presence
    /// marks it.
    #[test]
    fn a_receipt_written_never_is_not_marked() {
        let id = crossing(0x24);
        let receipts =
            SettledWrites::from_absolutes(BTreeMap::from([(never_of(&id), Some(vec![1]))]));
        let settled = crossing_settlements(
            &[claim_at(4, 4_000, vec![present(&id)], vec![])],
            ELSEWHERE,
            WeightedTimestamp::from_millis(4_000),
            &receipts,
            &declined(&id, false),
        );
        assert!(settled.seen.is_empty());
    }

    /// The member row and committed marker of the issuing transaction on
    /// the producer's shard.
    fn exit_keys() -> (SubstateKey, SubstateKey) {
        (
            member_row_leaf(PRODUCER, issuer()),
            committed_tx_cell_key(
                PRODUCER,
                issuer(),
                WeightedTimestamp::from_millis(VALIDITY_END_MS),
            ),
        )
    }

    /// A `Never` goes once its producer's leg is fated, and not at the
    /// leg's reclaim. The producer's chain commits the issuing
    /// transaction as a leg that waits; a reclaim's finalization names it
    /// and releases the row, which stands, so a reading of the row beside
    /// the record's absence proves no exit; the fate deletes the row, and
    /// the reading taken past it does.
    #[test]
    fn an_unseen_never_goes_once_its_producers_leg_is_fated() {
        let id = crossing(0x2B);
        let state = declined(&id, false);
        let (row, _) = exit_keys();
        let mut producer = MemberIndex::empty(PRODUCER);
        let removed = |producer: &MemberIndex, height: u64| {
            let reading = if producer.members.contains_key(&issuer()) {
                Inclusion::Present([2; 32])
            } else {
                Inclusion::Absent
            };
            let read = claim_at(
                height,
                VALIDITY_END_MS,
                vec![absent(&id)],
                vec![(row, reading)],
            );
            fold(&[read], &state).removed
        };
        let state_of =
            |producer: &MemberIndex| producer.members.get(&issuer()).map(|row| row.state);

        let stub = stub_stated_terms(issuer(), 1);
        producer.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(
                issuer(),
                Deadline::of(WeightedTimestamp::from_millis(VALIDITY_END_MS)),
            )],
            terms: vec![StatedTerms {
                terms: MemberTerms {
                    leg: true,
                    settlement: Settlement::Alone,
                    ..stub.terms
                },
                ..stub
            }],
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(state_of(&producer), Some(RowState::Pending));
        assert!(removed(&producer, 91).is_empty());

        producer.advance(&MemberInputs {
            height: BlockHeight::new(2),
            settled: vec![SettledHalf {
                tick: TickId::new(PRODUCER, BlockHeight::new(2)),
                half: TickHalf::Determined,
                stated: Vec::new(),
                deleted: Vec::new(),
                accepted: Vec::new(),
                reclaimed: vec![issuer()],
            }],
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(
            state_of(&producer),
            Some(RowState::Released {
                settlement: Settlement::Alone
            }),
        );
        assert!(
            removed(&producer, 92).is_empty(),
            "the reclaim deletes no row, so the leg has not exited",
        );

        producer.advance(&MemberInputs {
            height: BlockHeight::new(3),
            manifest: Arc::new(Capped::from_array([TickLine::Fate {
                tx: issuer(),
                charge: stub_abort_charge(1),
            }])),
            ..MemberInputs::still(PRODUCER)
        });
        assert_eq!(state_of(&producer), None);
        assert_eq!(removed(&producer, 93), vec![never_of(&id)]);
    }

    /// A standing member row proves no exit.
    #[test]
    fn a_standing_member_row_proves_no_exit() {
        let id = crossing(0x27);
        let (row, marker) = exit_keys();
        let standing = claim_at(
            8,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Present([2; 32])),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        assert!(fold(&[standing], &declined(&id, false)).removed.is_empty());
    }

    /// A transaction not yet committed and not yet past its validity end
    /// may still commit, so its missing row proves no exit.
    #[test]
    fn an_uncommitted_transaction_before_its_end_proves_no_exit() {
        let id = crossing(0x28);
        let (row, marker) = exit_keys();
        let early = claim_at(
            8,
            VALIDITY_END_MS - 1,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent), (marker, Inclusion::Absent)],
        );
        assert!(fold(&[early], &declined(&id, false)).removed.is_empty());
    }

    /// The row and the marker read at two anchors prove nothing together.
    #[test]
    fn exit_readings_at_two_anchors_do_not_combine() {
        let id = crossing(0x29);
        let (row, marker) = exit_keys();
        let claims = [
            claim_at(8, 8_000, vec![absent(&id)], vec![(row, Inclusion::Absent)]),
            claim_at(
                9,
                9_000,
                vec![],
                vec![(marker, Inclusion::Present([3; 32]))],
            ),
        ];
        assert!(fold(&claims, &declined(&id, false)).removed.is_empty());
    }

    /// Where both ends are this chain's, a record read absent at the
    /// parent deletes an answer on its own, fresh as the reading is.
    #[test]
    fn a_parent_anchored_absence_deletes_a_local_unseen_never() {
        let id = crossing(0x2A);
        let settled = crossing_settlements(
            &[claim_at(4, 4_000, vec![absent(&id)], vec![])],
            PRODUCER,
            WeightedTimestamp::from_millis(4_000),
            &SettledWrites::default(),
            &declined(&id, false),
        );
        assert_eq!(settled.removed, vec![never_of(&id)]);
    }

    fn read(readings: Vec<(SubstateKey, Stated, CrossingId)>) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::leaf(1, 1),
                height: BlockHeight::new(4),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(4_000),
            },
            readings
                .iter()
                .map(|(key, stated, _)| (*key, stated.clone())),
            MerkleInclusionProof::dummy(),
        )
        .naming(readings.into_iter().map(|(key, _, id)| (key, id)))
    }

    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    const AMOUNT: u128 = 250;
    const VALIDITY_END_MS: u64 = 60_000;

    fn issuer() -> TxHash {
        TxHash::from(Hash::from_bytes(b"issuer"))
    }

    /// The record `id` names on `terms`, read held at its key.
    fn held(id: &CrossingId, terms: Terms) -> (SubstateKey, Stated, CrossingId) {
        let cell = id.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, terms);
        (
            id.record_key(&ProtocolHasher),
            Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            *id,
        )
    }

    /// What `owed_credits` credits at `id`'s vault, and the `Taken` it
    /// writes, out of `writes`.
    fn credit_of(writes: &StateWrites, id: &CrossingId) -> (Option<u128>, Option<Vec<u8>>) {
        (
            writes
                .movements
                .get(&id.owed_credit(&ProtocolHasher, RESOURCE))
                .map(|movement| movement.credit),
            writes
                .cells
                .get(&id.answer_key(&ProtocolHasher, Answered::Taken))
                .cloned()
                .flatten(),
        )
    }

    /// A held owed reading with no `Taken` in the parent credits the
    /// consumer's vault and writes the `Taken` a take would have written.
    #[test]
    fn an_owed_reading_credits_its_consumer_once() {
        let id = crossing(0x21);
        let empty = Cells(BTreeMap::new());
        let taken = id
            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();

        let writes = owed_credits(&[read(vec![held(&id, Terms::Owed)])], &empty);
        assert_eq!(credit_of(&writes, &id), (Some(AMOUNT), Some(taken)));
        assert_eq!(
            writes.movements.len() + writes.cells.len(),
            2,
            "and nothing else"
        );

        let twice = owed_credits(
            &[
                read(vec![held(&id, Terms::Owed)]),
                read(vec![held(&id, Terms::Owed)]),
            ],
            &empty,
        );
        assert_eq!(
            credit_of(&twice, &id).0,
            Some(AMOUNT),
            "two readings of one record in one block credit it once",
        );
    }

    /// A claim of `PRODUCER`'s state at `height` and `ts_ms` holding
    /// `id`'s owed record.
    fn owed_at(height: u64, ts_ms: u64, id: &CrossingId) -> StateClaim {
        let (key, stated, id) = held(id, Terms::Owed);
        StateClaim::new(
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            [(key, stated)],
            MerkleInclusionProof::dummy(),
        )
        .naming([(key, id)])
    }

    const EPOCH_MS: u64 = 300_000;

    /// An owed record written at or below its producer's last boundary,
    /// credited, and retired above the boundary stands again once the
    /// producer is recovered to the boundary, and is credited once. The
    /// retirement's absence is fresh, so the consumer's `Taken` outlives
    /// it; the recovered chain's reading of the record passes the read
    /// frontier, whose mark orders the later epoch above the discarded
    /// suffix and is long pruned, and meets the `Taken`, which credits
    /// nothing and retires the standing record again.
    #[test]
    fn a_recovered_producers_owed_record_is_credited_once() {
        let windows = EpochWindows::new(EPOCH_MS);
        let id = crossing(0x31);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let mut frontier = ReadFrontier::default();
        let mut state = Cells(BTreeMap::new());
        let mut credited = 0u128;

        // The producer's boundary is height 95. Its suffix writes nothing
        // of the record, written at or below 95, and retires it at 103.
        let credit = [owed_at(100, EPOCH_MS + 9_000, &id)];
        let writes = owed_credits(&credit, &state);
        credited += credit_of(&writes, &id)
            .0
            .expect("the first reading credits");
        state
            .0
            .insert(taken, credit_of(&writes, &id).1.expect("and writes Taken"));
        frontier.advance(&FrontierInputs::for_block(
            &credit,
            windows,
            WeightedTimestamp::from_millis(EPOCH_MS + 10_000),
            ELSEWHERE,
        ));

        let (row, _) = exit_keys();
        let retired = [claim_at(
            103,
            EPOCH_MS + 15_000,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        let block = WeightedTimestamp::from_millis(EPOCH_MS + 16_000);
        assert_eq!(
            crossing_settlements(
                &retired,
                ELSEWHERE,
                block,
                &SettledWrites::default(),
                &state
            ),
            CrossingSettlements::default(),
            "the retirement's absence is fresh and deletes nothing",
        );
        frontier.advance(&FrontierInputs::for_block(
            &retired, windows, block, ELSEWHERE,
        ));
        assert_eq!(
            frontier.entry(PRODUCER),
            Some(ReadMark {
                epoch: windows.epoch_for(WeightedTimestamp::from_millis(EPOCH_MS + 15_000)),
                height: BlockHeight::new(103),
            }),
        );

        // The producer is recovered to height 95 sixteen epochs on; its
        // fresh chain reaches 97 with the record standing as 95 held it.
        let bridge_ms = 18 * EPOCH_MS;
        let again = [owed_at(97, bridge_ms + 5_000, &id)];
        let reading = Reading {
            key: record,
            shard: PRODUCER,
            mark: ReadMark::of(&again[0].anchor, windows),
        };
        let fence = ReadFence {
            presences: vec![reading],
            ..ReadFence::default()
        };
        assert!(
            fence.check(&frontier).is_ok(),
            "a mark at a lower height in a later epoch sits above the frontier's entry",
        );
        frontier.advance(&FrontierInputs::for_block(
            &[],
            windows,
            WeightedTimestamp::from_millis(bridge_ms + 6_000),
            ELSEWHERE,
        ));
        assert_eq!(
            frontier.entry(PRODUCER),
            None,
            "and the entry is long pruned"
        );

        let writes = owed_credits(&again, &state);
        credited += credit_of(&writes, &id).0.unwrap_or(0);
        assert_eq!(credited, AMOUNT, "the record is credited once");
        assert!(writes.cells.is_empty() && writes.movements.is_empty());

        // The recovered producer reads the standing Taken and retires
        // the record again.
        let standing = Cells(BTreeMap::from([(
            record,
            id.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed)
                .to_bytes(),
        )]));
        let answer = [claim(vec![taken_by(&id, issuer())])];
        assert_eq!(
            crossing_settlements(
                &answer,
                PRODUCER,
                fresh_to(&answer),
                &SettledWrites::default(),
                &standing,
            )
            .removed,
            vec![record],
        );
    }

    /// A record a recovered producer writes again for the same
    /// transaction, its first retirement discarded, is retired on the
    /// `Taken` that still stands on its consumer: the answer binds to
    /// the record by its transaction, so the record written a second
    /// time is the one it answers. The answer then goes at the first
    /// boundary of the recovered chain that shows the record gone and
    /// its member exited, and at none before.
    #[test]
    fn a_record_a_recovered_producer_writes_again_is_retired_on_the_standing_taken() {
        let id = crossing(0x32);
        let record = id.record_key(&ProtocolHasher);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let (row, _) = exit_keys();
        let consumer = took(&id);

        // The discarded suffix retired the record, and the consumer read
        // the absence fresh.
        let retired = [claim_at(
            103,
            EPOCH_MS + 15_000,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        assert_eq!(
            fold_fresh(&retired, &consumer),
            CrossingSettlements::default()
        );

        // The recovered chain runs the standing leg again and writes the
        // record of the same transaction.
        let producer = Cells(BTreeMap::from([(record, escrowed(&id, issuer()))]));
        let answer = [claim(vec![taken_by(&id, issuer())])];
        assert_eq!(
            crossing_settlements(
                &answer,
                PRODUCER,
                fresh_to(&answer),
                &SettledWrites::default(),
                &producer,
            )
            .removed,
            vec![record],
            "the standing Taken retires the record written again",
        );

        // A boundary of the recovered chain taken while the leg's row
        // stands deletes nothing; the one after its exit deletes.
        let running = [claim_at(
            96,
            18 * EPOCH_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Present([2; 32]))],
        )];
        assert_eq!(fold(&running, &consumer), CrossingSettlements::default());
        let exited = [claim_at(
            140,
            19 * EPOCH_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        )];
        assert_eq!(fold(&exited, &consumer).removed, vec![taken]);
    }

    /// An owed record a later transaction issued where an earlier one's
    /// was taken is credited once: the earlier `Taken` standing at the
    /// key guards nothing of it, the credit's own `Taken` is written
    /// over it, and with that standing a second reading credits nothing.
    #[test]
    fn an_owed_credit_lands_beside_another_transactions_taken() {
        let id = crossing(0x23);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let record = id.cell(later(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed);
        let reading = || {
            read(vec![(
                id.record_key(&ProtocolHasher),
                Stated::Held(Bytes::new(record.to_bytes()).expect("a record fits")),
                id,
            )])
        };
        let old = id
            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();
        let own = id
            .answer(later(), Answered::Taken, VALIDITY_END_MS)
            .to_bytes();
        let mut state = Cells(BTreeMap::from([(taken, old)]));

        let writes = owed_credits(&[reading()], &state);
        assert_eq!(
            credit_of(&writes, &id),
            (Some(AMOUNT), Some(own.clone())),
            "the later record is credited and its own Taken written over the earlier one",
        );
        state.0.insert(taken, own);
        let again = owed_credits(&[reading()], &state);
        assert!(
            again.cells.is_empty() && again.movements.is_empty(),
            "with its own Taken standing it is not credited twice: {again:?}",
        );
    }

    /// Nothing but a held owed record of the named crossing, with no
    /// `Taken` standing and no absence beside it, credits anything.
    #[test]
    fn an_owed_credit_needs_the_whole_licence() {
        let id = crossing(0x22);
        let empty = Cells(BTreeMap::new());
        let nothing = |claims: &[StateClaim], state: &Cells| {
            let writes = owed_credits(claims, state);
            assert!(
                writes.cells.is_empty() && writes.movements.is_empty(),
                "{writes:?}"
            );
        };
        let record = id.record_key(&ProtocolHasher);

        let answered = Cells(BTreeMap::from([(
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                .to_bytes(),
        )]));
        nothing(&[read(vec![held(&id, Terms::Owed)])], &answered);
        nothing(
            &[read(vec![(
                record,
                Stated::from(Inclusion::Present([7; 32])),
                id,
            )])],
            &empty,
        );
        nothing(
            &[read(vec![held(
                &id,
                Terms::Escrowed {
                    credit: test_key(0x60),
                },
            )])],
            &empty,
        );
        nothing(
            &[read(vec![(record, Stated::from(Inclusion::Absent), id)])],
            &empty,
        );
        nothing(
            &[
                read(vec![held(&id, Terms::Owed)]),
                read(vec![(record, Stated::from(Inclusion::Absent), id)]),
            ],
            &empty,
        );

        // A record whose consumer is not the one its reading names.
        let stranger = CrossingId {
            consumer: Address::new([0x7F; 31], AddressClass::Component),
            ..id
        };
        let (key, _, _) = held(&id, Terms::Owed);
        let misnamed = stranger.cell(issuer(), RESOURCE, AMOUNT, VALIDITY_END_MS, Terms::Owed);
        nothing(
            &[read(vec![(
                key,
                Stated::Held(Bytes::new(misnamed.to_bytes()).expect("a record fits")),
                id,
            )])],
            &empty,
        );
    }

    proptest! {
        /// A block whose claims all name no crossing and hold no value
        /// moves nothing in the crossings fold, whatever cells they read
        /// and whatever the state holds: no record retired, no answer
        /// deleted or marked seen, no credit and no arrival, on a
        /// consumer's chain and on the producer's own, fresh to the
        /// block or at a boundary of it. Such a claim acts
        /// only beside a named or valued reading of its own block, and
        /// here there is none. Nor does one offer the fence anything to
        /// judge: none retires a record or reads a deleting absence.
        #[test]
        fn bare_claims_move_nothing_in_the_crossings_fold(
            readings in vec((0usize..10, any::<bool>(), 1u64..12), 1..16),
        ) {
            let (unseen, seen, owed) = (crossing(0x31), crossing(0x32), crossing(0x33));
            let (row, marker) = exit_keys();
            let record = |id: &CrossingId| id.record_key(&ProtocolHasher);
            let taken = |id: &CrossingId| id.answer_key(&ProtocolHasher, Answered::Taken);
            let keys = [
                record(&unseen),
                never_of(&unseen),
                record(&seen),
                never_of(&seen),
                taken(&seen),
                record(&owed),
                taken(&owed),
                row,
                marker,
                test_key(0x50),
            ];
            let (owed_record, owed_value, _) = held(&owed, Terms::Owed);
            let state = Cells(BTreeMap::from([
                (
                    never_of(&unseen),
                    unseen.unseen_never(issuer(), VALIDITY_END_MS).to_bytes(),
                ),
                (
                    never_of(&seen),
                    seen.answer(issuer(), Answered::Never, VALIDITY_END_MS).to_bytes(),
                ),
                (
                    taken(&seen),
                    seen.answer(issuer(), Answered::Taken, VALIDITY_END_MS).to_bytes(),
                ),
                (record(&seen), escrowed(&seen, issuer())),
                (
                    owed_record,
                    owed_value.held().expect("a held record").to_vec(),
                ),
            ]));
            let claims: Vec<StateClaim> = readings
                .into_iter()
                .map(|(key, present, height)| {
                    // A presence states what the state holds at the
                    // key, so an answer read bare is the very answer a
                    // named reading would bind on.
                    let inclusion = if present {
                        Inclusion::Present(
                            state
                                .cell(keys[key])
                                .map_or([7; 32], |value| jmt_value_hash(&value)),
                        )
                    } else {
                        Inclusion::Absent
                    };
                    claim_at(
                        height,
                        VALIDITY_END_MS + height,
                        vec![],
                        vec![(keys[key], inclusion)],
                    )
                })
                .collect();
            let holder = Issuer {
                tx: issuer(),
                validity_end_ms: VALIDITY_END_MS,
            };
            for claim in &claims {
                prop_assert!(claim.crossings.is_empty() && !claim.holds_a_value());
                prop_assert!(claim.retires(|_| Some(holder)).is_empty());
                prop_assert_eq!(claim.deleting().count(), 0);
            }
            for local in [ELSEWHERE, PRODUCER] {
                for anchor in [fresh_to(&claims), past(&claims)] {
                    prop_assert_eq!(
                        crossing_settlements(
                            &claims,
                            local,
                            anchor,
                            &SettledWrites::default(),
                            &state,
                        ),
                        CrossingSettlements::default(),
                    );
                }
            }
            prop_assert_eq!(owed_credits(&claims, &state), StateWrites::default());
            prop_assert!(record_arrivals(&claims).is_empty());
        }

        /// Whatever a block's claims read of three crossings and their
        /// producing member, named or not, fresh to the block or at a
        /// boundary of it, the crossings fold is a function of the block
        /// and the state it lands on, and folding the block again over
        /// what its first fold left writes nothing. An answer goes only
        /// where a named absence of its record is at a boundary of the
        /// block with the member's exit read at the same anchor, or is
        /// read on the chain itself.
        #[test]
        fn a_block_folded_twice_writes_what_one_fold_does(
            readings in vec((0usize..8, any::<bool>(), any::<bool>(), 0u64..3), 1..12),
            boundary in any::<bool>(),
            seen in any::<bool>(),
        ) {
            let ids = [crossing(0x41), crossing(0x42), crossing(0x43)];
            let (row, marker) = exit_keys();
            let record = |id: &CrossingId| id.record_key(&ProtocolHasher);
            let taken = |id: &CrossingId| id.answer_key(&ProtocolHasher, Answered::Taken);
            let never = if seen {
                ids[1].answer(issuer(), Answered::Never, VALIDITY_END_MS)
            } else {
                ids[1].unseen_never(issuer(), VALIDITY_END_MS)
            };
            let state = Cells(BTreeMap::from([
                (
                    taken(&ids[0]),
                    ids[0].answer(issuer(), Answered::Taken, VALIDITY_END_MS).to_bytes(),
                ),
                (never_of(&ids[1]), never.to_bytes()),
                (record(&ids[2]), escrowed(&ids[2], issuer())),
            ]));
            // One reading a key at each anchor, as a block carries them.
            let mut at: BTreeMap<(u64, SubstateKey), (Inclusion, Option<CrossingId>)> =
                BTreeMap::new();
            for (pick, present, named, height) in readings {
                let (key, id) = match pick {
                    0..=2 => (record(&ids[pick]), Some(ids[pick])),
                    3 => (taken(&ids[2]), Some(ids[2])),
                    4 => (row, None),
                    5 => (marker, None),
                    6 => (never_of(&ids[1]), Some(ids[1])),
                    _ => (test_key(0x50), None),
                };
                let inclusion = if present {
                    Inclusion::Present(jmt_value_hash(
                        &ids[2]
                            .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                            .to_bytes(),
                    ))
                } else {
                    Inclusion::Absent
                };
                at.insert((height, key), (inclusion, id.filter(|_| named)));
            }
            let mut claims: Vec<StateClaim> = Vec::new();
            for height in 0..3u64 {
                let (named, unnamed): (Vec<_>, Vec<_>) = at
                    .iter()
                    .filter(|((read_at, _), _)| *read_at == height)
                    .map(|((_, key), (inclusion, id))| (*key, *inclusion, *id))
                    .partition(|(_, _, id)| id.is_some());
                if named.is_empty() && unnamed.is_empty() {
                    continue;
                }
                claims.push(claim_at(
                    height + 1,
                    VALIDITY_END_MS + height,
                    named
                        .into_iter()
                        .map(|(key, inclusion, id)| (key, inclusion, id.expect("named")))
                        .collect(),
                    unnamed
                        .into_iter()
                        .map(|(key, inclusion, _)| (key, inclusion))
                        .collect(),
                ));
            }
            let anchor = if boundary { past(&claims) } else { fresh_to(&claims) };
            for local in [ELSEWHERE, PRODUCER] {
                let fold = |state: &Cells| {
                    crossing_settlements(&claims, local, anchor, &SettledWrites::default(), state)
                };
                let first = fold(&state);
                prop_assert_eq!(&first, &fold(&state), "the fold reads nothing but its inputs");
                if local == ELSEWHERE {
                    for key in [taken(&ids[0]), never_of(&ids[1])] {
                        let licensed = boundary
                            && claims.iter().any(|claim| {
                                claim.deleting().any(|read| {
                                    read == record(&ids[0]) && key == taken(&ids[0])
                                        || read == record(&ids[1]) && key == never_of(&ids[1])
                                }) && claims.iter().any(|beside| {
                                    beside.anchor == claim.anchor
                                        && beside.reading(row) == Some(Inclusion::Absent)
                                })
                            });
                        prop_assert_eq!(first.removed.contains(&key), licensed);
                    }
                }
                let mut left = Cells(state.0.clone());
                for key in &first.removed {
                    left.0.remove(key);
                }
                for (key, bytes) in &first.seen {
                    left.0.insert(*key, bytes.clone());
                }
                prop_assert_eq!(
                    fold(&left),
                    CrossingSettlements::default(),
                    "a second fold of the block writes nothing",
                );
            }
        }
    }
}
