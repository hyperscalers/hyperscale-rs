//! Crossings whose two ends share this shard, read at the block's own
//! parent.
//!
//! A crossing record and its answers sit under the producing and the
//! consuming node's targets. Where both route here, no counterpart holds
//! the cells to be asked about them, so the block reads them itself, at
//! the one anchor every voter holds through its own anchored view: the
//! parent. The readings carry the empty proof, and the verifier re-reads
//! each one from its own parent view instead of walking a proof.

use hyperscale_storage::Substates;
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, Inclusion, MAX_PROOFS_PER_QUERY, MerkleInclusionProof, ShardId, StateClaim, SubstateKey,
};
use hyperscale_vm_effects::{Answered, CrossingId, ProtocolHasher};

/// What `state` says of `key`: the presence hashing to its value, or
/// its absence. Never the value itself, so a parent-anchored reading has
/// one weight.
fn read(state: &(impl Substates + ?Sized), key: SubstateKey) -> Inclusion {
    state.cell(key).map_or(Inclusion::Absent, |bytes| {
        Inclusion::Present(jmt_value_hash(&bytes))
    })
}

/// The claims a block carries for `local_crossings`, read off `state`,
/// the parent's, at `parent`: every crossing's three keys, cut into
/// claims by the section's order rule and each key named for its
/// crossing.
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
                chunk.iter().map(|(key, _)| (*key, read(state, *key))),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        Address, AddressClass, BlockHeight, CollectionId, StateRoot, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{Hash32, IntentHash};

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
}
