//! The read frontier's fence over a block: what it judges, from the
//! block's content, and what a proposer drops to pass it.
//!
//! The voter judges a block where it reads the parent state, in the
//! state-root verification: a record presence below the floor the
//! parent left for its producer's lineage, a presence below a
//! same-block absence of its key, and a late delivery either of whose
//! answers stands. The proposer runs the same judgement in dropping
//! form before it builds, so a proposal never refuses itself, and a
//! transaction admitted on a dropped presence goes with it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_engine::legs::live_record;
use hyperscale_types::{
    EpochWindows, Finalization, Inclusion, ReadFence, ReadFrontier, ReadMark, Reading, StateClaim,
    SubstateKey, Transaction, TxHash, Verifiable, Verified,
};
use hyperscale_vm_effects::{CrossingLeaf, ProtocolHasher};

/// What the frontier fences in a block carrying `claims`: every held
/// reading whose bytes decode as a crossing record, every absent
/// reading, and `late_answers`, the answer cells its late deliveries
/// consume here.
#[must_use]
pub fn read_fence(
    claims: &[StateClaim],
    windows: EpochWindows,
    late_answers: BTreeMap<TxHash, Vec<SubstateKey>>,
) -> ReadFence {
    let mut presences = Vec::new();
    let mut absences = Vec::new();
    for claim in claims {
        let mark = ReadMark::of(&claim.anchor, windows);
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
        late_answers,
    }
}

/// Every cell the block's own finalizations write, deleted or not: what
/// the fence reads beside the parent state for an answer that stands.
#[must_use]
pub fn written_by(finalizations: &[Arc<Verifiable<Finalization>>]) -> BTreeSet<SubstateKey> {
    finalizations
        .iter()
        .flat_map(|finalization| finalization.settling_receipts())
        .filter_map(|receipt| {
            receipt
                .consensus
                .writes()
                .map(|writes| writes.cells.clone())
        })
        .flat_map(BTreeMap::into_keys)
        .collect()
}

/// A proposal's claims and transactions with what the fence refuses
/// dropped, and how many items went.
pub struct Dropped {
    /// The claims kept, each cut to the readings the fence admits.
    pub claims: Vec<StateClaim>,
    /// The transactions kept.
    pub transactions: Vec<Arc<Verified<Transaction>>>,
    /// How many readings, late deliveries and licensed transactions
    /// were dropped.
    pub refused: usize,
}

/// Drop from a proposal everything the fence would refuse: every
/// refused presence is cut from its claim, every refused late delivery
/// goes, and so does every transaction `record_licences` names whose
/// record keys lose their live reading among the claims kept.
///
/// `record_licences` names, for each transaction admitted on a record
/// presence rather than a payer bundle, the record keys it leaned on.
/// `standing` says whether an answer cell is present in the parent
/// state or written by the block's own finalizations.
#[must_use]
pub fn drop_refused(
    state_claims: Vec<StateClaim>,
    transactions: Vec<Arc<Verified<Transaction>>>,
    fence: &ReadFence,
    record_licences: &BTreeMap<TxHash, Vec<SubstateKey>>,
    windows: EpochWindows,
    parent: &ReadFrontier,
    standing: impl Fn(SubstateKey) -> bool,
) -> Dropped {
    let refused = fence.refused(parent, standing);
    let mut dropped = refused.readings.len();
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
    let transactions = transactions
        .into_iter()
        .filter(|tx| {
            let hash = tx.hash();
            let licensed = record_licences.get(&hash).is_none_or(|keys| {
                keys.iter()
                    .all(|key| live_record(&claims, *key).is_some_and(|(_, cell)| cell.tx == hash))
            });
            let kept = licensed && !refused.deliveries.contains(&hash);
            if !kept {
                dropped += 1;
            }
            kept
        })
        .collect();
    Dropped {
        claims,
        transactions,
        refused: dropped,
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::{state_and_proof, test_key, test_transaction};
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, Epoch, ReadFrontier, ReadMark, ShardId, Stated,
        WeightedTimestamp,
    };
    use hyperscale_vm_effects::{Answered, CrossingId, Hash32, IntentHash, Terms};
    use hyperscale_vm_types::ResourceAddr;

    use super::*;

    /// A claim of `producer` carrying a live owed record of `delivery`
    /// and one other reading, with the licences and answers a fence
    /// judges it by.
    struct Offered {
        producer: ShardId,
        claim: StateClaim,
        fence: ReadFence,
        licences: BTreeMap<TxHash, Vec<SubstateKey>>,
        answer: SubstateKey,
        other: SubstateKey,
        txs: Vec<Arc<Verified<Transaction>>>,
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
        let answer = id.answer_key(&ProtocolHasher, Answered::Taken);
        let wrap = |seed: u8| {
            Arc::new(Verified::<Transaction>::from_persisted(test_transaction(
                seed,
            )))
        };
        let (delivery, late, plain) = (wrap(1), wrap(2), wrap(3));
        let cell = id.cell(
            delivery.hash(),
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
        let fence = read_fence(
            std::slice::from_ref(&claim),
            windows,
            BTreeMap::from([(late.hash(), vec![answer])]),
        );
        assert_eq!(fence.presences.len(), 1, "the record reads as a presence");
        Offered {
            producer,
            claim,
            fence,
            licences: BTreeMap::from([(delivery.hash(), vec![record])]),
            answer,
            other,
            txs: vec![delivery, late, plain],
        }
    }

    /// Where the fence refuses nothing the proposer drops nothing.
    #[test]
    fn the_proposer_keeps_what_the_fence_admits() {
        let offered = offered();
        let kept = drop_refused(
            vec![offered.claim.clone()],
            offered.txs.clone(),
            &offered.fence,
            &offered.licences,
            EpochWindows::new(1_000_000),
            &ReadFrontier::default(),
            |_| false,
        );
        assert_eq!(kept.refused, 0);
        assert_eq!(kept.claims, vec![offered.claim]);
        assert_eq!(kept.transactions.len(), 3);
    }

    /// The proposer cuts a refused presence out of its claim, keeps the
    /// claim's other reading, and drops the transaction that leaned on
    /// the presence and the late delivery whose answer stands.
    #[test]
    fn the_proposer_drops_what_the_fence_refuses_and_what_leaned_on_it() {
        let offered = offered();
        let raised = ReadFrontier::from_entries([(
            offered.producer,
            ReadMark {
                epoch: Epoch::GENESIS,
                height: BlockHeight::new(9),
            },
        )]);
        let plain = offered.txs[2].hash();
        let dropped = drop_refused(
            vec![offered.claim],
            offered.txs,
            &offered.fence,
            &offered.licences,
            EpochWindows::new(1_000_000),
            &raised,
            |key| key == offered.answer,
        );
        assert_eq!(
            dropped.refused, 3,
            "the presence, the late delivery and the leaning transaction"
        );
        assert_eq!(
            dropped
                .claims
                .iter()
                .map(StateClaim::keys)
                .collect::<Vec<_>>(),
            vec![vec![offered.other]],
            "the refused presence is cut and the other reading kept",
        );
        assert_eq!(
            dropped
                .transactions
                .iter()
                .map(|tx| tx.hash())
                .collect::<Vec<_>>(),
            vec![plain],
        );
    }
}
