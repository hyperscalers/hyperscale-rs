//! The crossing settlements and credits a block's claims license,
//! applied in its commit fold.
//!
//! A producer's record is removed once its consumer's `Taken` is read
//! present, and a consumer's answers are removed once the record they
//! answer for is read absent. Each is a value-free write the evidence
//! for is a reading the block carries, so every voter recomputes it
//! inside `state_root` and no member runs for it. What a reading
//! licenses is the claim's own rule, [`StateClaim::settles`]; this is
//! where it meets the state the block lands on.
//!
//! An owed crossing's consumer runs no member either: a valued reading
//! of the record, with no `Taken` standing in the parent, credits the
//! consumer's vault and writes the `Taken` in the same fold.

use std::collections::BTreeSet;

use hyperscale_types::{
    Inclusion, Movement, ProtocolHasher, SettledWrites, StateClaim, StateWrites, SubstateKey,
};
use hyperscale_vm_effects::{Answered, CrossingLeaf, Terms};

use crate::Substates;
use crate::shard::writes::fold_state_writes;

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

/// The cells `state_claims` license removing, ascending and each once:
/// what [`StateClaim::settles`] yields over every claim, less the keys
/// `written` writes and the keys absent from `state`.
///
/// A receipt is its member's own decision and always lands, so the
/// fold never writes a key a receipt writes. A key absent from the
/// state the block lands on has nothing to remove: a record already
/// reclaimed, an answer already deleted, or a cell under a prefix a
/// follower does not hold.
#[must_use]
pub fn crossing_settlements(
    state_claims: &[StateClaim],
    written: &SettledWrites,
    state: &(impl Substates + ?Sized),
) -> Vec<SubstateKey> {
    let licensed: BTreeSet<SubstateKey> =
        state_claims.iter().flat_map(StateClaim::settles).collect();
    licensed
        .into_iter()
        .filter(|key| !written.cells().contains_key(key) && state.cell(*key).is_some())
        .collect()
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
            (key(&answered, Some(Answered::Taken)), vec![2]),
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
            crossing_settlements(&claims, &receipts, &state),
            expected,
            "the retired record and the answered crossing's Taken go; the Never absent from \
             the state, the record already gone and the key a receipt writes do not",
        );
        assert!(
            crossing_settlements(&[], &receipts, &state).is_empty(),
            "no claim licenses nothing",
        );
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
