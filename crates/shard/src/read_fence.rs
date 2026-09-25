//! The read frontier's fence over a block: what it judges, from the
//! block's content, and what a proposer drops to pass it.
//!
//! The voter judges a block where it reads the parent state, in the
//! state-root verification: a record presence below the floor the
//! parent left for its producer's lineage, a presence below a
//! same-block absence of its key, and a record absence that would
//! delete an answer below the floor or off the record's owner. The
//! proposer runs the same judgement in dropping form before it builds,
//! so a proposal never refuses itself.

use std::collections::BTreeSet;

use hyperscale_types::{
    EpochWindows, Inclusion, ReadFence, ReadFrontier, ReadMark, Reading, StateClaim, SubstateKey,
};
use hyperscale_vm_effects::{CrossingLeaf, ProtocolHasher};

/// What the frontier fences in a block carrying `claims`: every held
/// reading whose bytes decode as a crossing record, and every absent
/// reading.
#[must_use]
pub fn read_fence(claims: &[StateClaim], windows: EpochWindows) -> ReadFence {
    let mut presences = Vec::new();
    let mut absences = Vec::new();
    let mut deletions = Vec::new();
    for claim in claims {
        let mark = ReadMark::of(&claim.anchor, windows);
        deletions.extend(claim.deleting().map(|key| Reading {
            key,
            shard: claim.anchor.shard,
            mark,
        }));
        for (key, stated) in claim.cells.iter() {
            let reading = Reading {
                key: *key,
                shard: claim.anchor.shard,
                mark,
            };
            match stated.held() {
                Some(bytes) => {
                    if matches!(
                        CrossingLeaf::read(&ProtocolHasher, *key, bytes),
                        Some(CrossingLeaf::Record { .. })
                    ) {
                        presences.push(reading);
                    }
                }
                None => {
                    if stated.inclusion() == Inclusion::Absent {
                        absences.push(reading);
                    }
                }
            }
        }
    }
    ReadFence {
        presences,
        absences,
        deletions,
    }
}

/// A proposal's claims with what the fence refuses dropped, and how many
/// readings went.
pub struct Dropped {
    /// The claims kept, each cut to the readings the fence admits.
    pub claims: Vec<StateClaim>,
    /// How many readings were dropped.
    pub refused: usize,
}

/// Drop from a proposal's claims every reading the fence would refuse:
/// each refused presence or deleting absence is cut from its claim.
#[must_use]
pub fn drop_refused(
    state_claims: Vec<StateClaim>,
    fence: &ReadFence,
    windows: EpochWindows,
    parent: &ReadFrontier,
) -> Dropped {
    let refused = fence.refused(parent);
    let claims: Vec<StateClaim> = state_claims
        .into_iter()
        .filter_map(|claim| {
            let mark = ReadMark::of(&claim.anchor, windows);
            let cut: BTreeSet<SubstateKey> = refused
                .readings
                .iter()
                .filter(|reading| reading.shard == claim.anchor.shard && reading.mark == mark)
                .map(|reading| reading.key)
                .collect();
            if cut.is_empty() {
                Some(claim)
            } else {
                claim.restrict(|key| !cut.contains(&key))
            }
        })
        .collect();
    Dropped {
        claims,
        refused: refused.readings.len(),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::{state_and_proof, test_key};
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, Epoch, Hash, ReadFrontier, ReadMark, ShardId,
        Stated, TxHash, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};
    use hyperscale_vm_types::ResourceAddr;

    use super::*;

    /// A claim of `producer` carrying a live owed record and one other
    /// reading, with the fence it is judged by.
    struct Offered {
        producer: ShardId,
        claim: StateClaim,
        fence: ReadFence,
        other: SubstateKey,
    }

    fn offered() -> Offered {
        let windows = EpochWindows::new(1_000_000);
        let producer = ShardId::leaf(1, 1);
        let id = CrossingId {
            producer: Address::new([0xAA; 31], AddressClass::Component),
            consumer: Address::new([0x11; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0xAC; 32])),
            local: 0,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let cell = id.cell(
            TxHash::from(Hash::from_bytes(b"issuer")),
            ResourceAddr::new([0xE0; 31]),
            5,
            9_000,
            Terms::Owed,
        );
        let other = test_key(0x90);
        let (state_root, proof) = state_and_proof(producer, &[record, other], &[record, other]);
        let claim = StateClaim::new(
            Anchor {
                shard: producer,
                height: BlockHeight::new(5),
                state_root,
                ts: WeightedTimestamp::from_millis(5_000),
            },
            [
                (record, Stated::Held(Bytes::new(cell.to_bytes()).unwrap())),
                (other, Inclusion::Present([1; 32]).into()),
            ],
            proof,
        );
        let fence = read_fence(std::slice::from_ref(&claim), windows);
        assert_eq!(fence.presences.len(), 1, "the record reads as a presence");
        Offered {
            producer,
            claim,
            fence,
            other,
        }
    }

    /// Where the fence refuses nothing the proposer drops nothing.
    #[test]
    fn the_proposer_keeps_what_the_fence_admits() {
        let offered = offered();
        let kept = drop_refused(
            vec![offered.claim.clone()],
            &offered.fence,
            EpochWindows::new(1_000_000),
            &ReadFrontier::default(),
        );
        assert_eq!(kept.refused, 0);
        assert_eq!(kept.claims, vec![offered.claim]);
    }

    /// The proposer cuts a refused presence out of its claim and keeps
    /// the claim's other reading.
    #[test]
    fn the_proposer_drops_what_the_fence_refuses() {
        let offered = offered();
        let raised = ReadFrontier::from_entries([(
            offered.producer,
            ReadMark {
                epoch: Epoch::GENESIS,
                height: BlockHeight::new(9),
            },
        )]);
        let dropped = drop_refused(
            vec![offered.claim],
            &offered.fence,
            EpochWindows::new(1_000_000),
            &raised,
        );
        assert_eq!(dropped.refused, 1, "the presence");
        assert_eq!(
            dropped
                .claims
                .iter()
                .map(StateClaim::keys)
                .collect::<Vec<_>>(),
            vec![vec![offered.other]],
            "the refused presence is cut and the other reading kept",
        );
    }
}
