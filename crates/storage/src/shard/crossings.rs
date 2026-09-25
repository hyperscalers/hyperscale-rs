//! The crossing settlements a block's claims license, applied in its
//! commit fold.
//!
//! A producer's record is removed once its consumer's `Taken` is read
//! present, and a consumer's answers are removed once the record they
//! answer for is read absent. Each is a value-free write the evidence
//! for is a reading the block carries, so every voter recomputes it
//! inside `state_root` and no member runs for it. What a reading
//! licenses is the claim's own rule, [`StateClaim::settles`]; this is
//! where it meets the state the block lands on.

use std::collections::BTreeSet;

use hyperscale_types::{SettledWrites, StateClaim, SubstateKey};

use crate::Substates;

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

    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CollectionId, Inclusion, MerkleInclusionProof,
        ShardId, StateRoot, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{Answered, CrossingId, Hash32, IntentHash, ProtocolHasher};

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
}
