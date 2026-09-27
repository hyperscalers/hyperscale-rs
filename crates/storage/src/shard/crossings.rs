//! The crossing settlements and credits a block's claims license,
//! applied in its commit fold.
//!
//! A producer's record is removed once its consumer's `Taken` is read
//! present, and a consumer's answer is removed once the record it
//! answers for is read absent after the consumer read it present. Each
//! is a value-free write the evidence for is a reading the block
//! carries, so every voter recomputes it inside `state_root` and no
//! member runs for it. What retires a record is the claim's own rule,
//! [`StateClaim::retires`]; what removes an answer reads the answer, so
//! it is decided here, where the readings meet the state the block
//! lands on.
//!
//! An owed crossing's consumer runs no member either: a valued reading
//! of the record, with no `Taken` standing in the parent, credits the
//! consumer's vault and writes the `Taken` in the same fold.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    Anchor, Inclusion, Movement, ProtocolHasher, SettledWrites, ShardId, StateClaim, StateWrites,
    SubstateKey, TxHash, WeightedTimestamp,
};
use hyperscale_vm_effects::{
    Answered, Crossing, CrossingAnswer, CrossingCell, CrossingLeaf, Terms,
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
/// record of that crossing, and `state` holds no `Taken` for it. The
/// guard is read in the parent, and a record credits at most once in a
/// block, and not at all beside an absence of the same key the block
/// carries. So one owed record is credited once: within a block by the
/// last rule, across blocks by the `Taken` it writes, and once that
/// `Taken` is deleted on an absence at or above the read frontier, by
/// the frontier refusing every presence below it.
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
            if state.cell(taken).is_some() || !credited.insert(*key) {
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
/// block `local`'s chain commits landing on it, leaving alone every key
/// `written` writes: a receipt is its member's own decision and always
/// lands.
///
/// - A record whose `Taken` is read present is removed
///   ([`StateClaim::retires`]).
/// - An answer whose record is read absent is removed when its consumer
///   read the record present before it: a seen answer, or one the block
///   carries the record present for at or below the absence. An unseen
///   `Never` is removed otherwise only on its producer member's exit
///   ([`exit_proven`]), or where both ends of the crossing are this
///   chain's (a crossing a merge brought together, whose producer never
///   runs a pre-cut leg).
/// - An unseen `Never` whose record is read present is marked seen: the
///   record was written at or before that anchor, and this block raises
///   the read frontier to it, so every later absence postdates the
///   write.
///
/// A key absent from `state` has nothing to remove: a record already
/// reclaimed, an answer already deleted, or a cell under a prefix a
/// follower does not hold.
#[must_use]
pub fn crossing_settlements(
    state_claims: &[StateClaim],
    local: ShardId,
    written: &SettledWrites,
    state: &(impl Substates + ?Sized),
) -> CrossingSettlements {
    let untouched = |key: &SubstateKey| !written.cells().contains_key(key);
    let mut removed: BTreeSet<SubstateKey> = state_claims
        .iter()
        .flat_map(StateClaim::retires)
        .filter(|key| untouched(key) && state.cell(*key).is_some())
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
                let deletes = CrossingAnswer::from_bytes(&bytes).is_none_or(|answer| {
                    answer.seen
                        || claim.anchor.shard == local
                        || present_at_or_below(state_claims, *key, &claim.anchor)
                        || exit_proven(state_claims, &claim.anchor, &answer)
                });
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

/// Whether the claims carry `record` present at an anchor of `absent`'s
/// lineage at or below it: the block itself read the record before the
/// absence it deletes an answer on.
fn present_at_or_below(state_claims: &[StateClaim], record: SubstateKey, absent: &Anchor) -> bool {
    state_claims.iter().any(|claim| {
        matches!(claim.reading(record), Some(Inclusion::Present(_)))
            && claim.anchor.height <= absent.height
            && (claim.anchor.shard.is_ancestor_of(absent.shard)
                || absent.shard.is_ancestor_of(claim.anchor.shard))
    })
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
/// transaction and goes only with the member's own writes, so with the
/// row gone nothing writes the record again, and its absence at the
/// anchor stands. Readings at different anchors never combine.
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

    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CollectionId, Hash, MerkleInclusionProof,
        ResourceAddr, ShardId, StateRoot, Stated, TxHash, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash};

    use super::*;

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
        let present = Inclusion::Present([7; 32]);
        let state = Cells(BTreeMap::from([
            (key(&retired, None), vec![1]),
            (
                key(&answered, Some(Answered::Taken)),
                answered
                    .answer(issuer(), Answered::Taken, VALIDITY_END_MS)
                    .to_bytes(),
            ),
            (key(&written, None), vec![4]),
            (test_key(0x50), vec![5]),
        ]));
        let receipts =
            SettledWrites::from_absolutes(BTreeMap::from([(key(&written, None), Some(vec![9]))]));
        let claims = vec![
            claim(vec![
                (key(&retired, Some(Answered::Taken)), present, retired),
                (key(&answered, None), Inclusion::Absent, answered),
                (key(&gone, Some(Answered::Taken)), present, gone),
                (key(&written, Some(Answered::Taken)), present, written),
            ]),
            claim(vec![(
                key(&retired, Some(Answered::Taken)),
                present,
                retired,
            )]),
        ];
        let mut expected = vec![key(&retired, None), key(&answered, Some(Answered::Taken))];
        expected.sort_unstable();
        assert_eq!(
            crossing_settlements(&claims, ELSEWHERE, &receipts, &state).removed,
            expected,
            "the retired record and the answered crossing's Taken go; the Never absent from \
             the state, the record already gone and the key a receipt writes do not",
        );
        assert!(
            crossing_settlements(&[], ELSEWHERE, &receipts, &state)
                == CrossingSettlements::default(),
            "no claim licenses nothing",
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

    fn fold(claims: &[StateClaim], state: &Cells) -> CrossingSettlements {
        crossing_settlements(claims, ELSEWHERE, &SettledWrites::default(), state)
    }

    /// An absence deletes an answer its consumer read the record for.
    #[test]
    fn an_absence_deletes_a_seen_answer() {
        let id = crossing(0x21);
        let state = declined(&id, true);
        let settled = fold(&[claim_at(4, 4_000, vec![absent(&id)], vec![])], &state);
        assert_eq!(settled.removed, vec![never_of(&id)]);
    }

    /// The D03 residual: an absence read where the record may not yet
    /// have been written leaves an abandonment's `Never` standing.
    #[test]
    fn an_absence_alone_leaves_an_unseen_never() {
        let id = crossing(0x22);
        let state = declined(&id, false);
        let settled = fold(&[claim_at(4, 4_000, vec![absent(&id)], vec![])], &state);
        assert_eq!(settled, CrossingSettlements::default());
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
            &receipts,
            &declined(&id, false),
        );
        assert!(settled.seen.is_empty());
    }

    /// A block carrying the record present at or below its absence
    /// deletes an unseen `Never`; one carrying the presence above the
    /// absence, which the record was written between, does not.
    #[test]
    fn a_same_block_presence_and_absence_delete() {
        let id = crossing(0x25);
        let state = declined(&id, false);
        let settled = fold(
            &[
                claim_at(4, 4_000, vec![present(&id)], vec![]),
                claim_at(6, 6_000, vec![absent(&id)], vec![]),
            ],
            &state,
        );
        assert_eq!(settled.removed, vec![never_of(&id)]);
        assert!(settled.seen.is_empty(), "a deleted Never is not marked");
        let settled = fold(
            &[
                claim_at(4, 4_000, vec![absent(&id)], vec![]),
                claim_at(6, 6_000, vec![present(&id)], vec![]),
            ],
            &state,
        );
        assert!(settled.removed.is_empty());
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

    /// An exit proof deletes an unseen `Never`: the row gone at one
    /// anchor with the marker present, or with the anchor past the
    /// transaction's validity end.
    #[test]
    fn an_exit_proof_deletes_an_unseen_never() {
        let id = crossing(0x26);
        let state = declined(&id, false);
        let (row, marker) = exit_keys();
        let by_marker = claim_at(
            8,
            8_000,
            vec![absent(&id)],
            vec![
                (row, Inclusion::Absent),
                (marker, Inclusion::Present([3; 32])),
            ],
        );
        assert_eq!(fold(&[by_marker], &state).removed, vec![never_of(&id)]);
        let by_clock = claim_at(
            90,
            VALIDITY_END_MS,
            vec![absent(&id)],
            vec![(row, Inclusion::Absent)],
        );
        assert_eq!(fold(&[by_clock], &state).removed, vec![never_of(&id)]);
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
    /// parent deletes an unseen `Never` on its own.
    #[test]
    fn a_parent_anchored_absence_deletes_a_local_unseen_never() {
        let id = crossing(0x2A);
        let settled = crossing_settlements(
            &[claim_at(4, 4_000, vec![absent(&id)], vec![])],
            PRODUCER,
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
            vec![1],
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
}
