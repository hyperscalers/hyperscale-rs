//! What a block is judged by against its parent state, and how a
//! proposer builds the claims that pass it.
//!
//! A voter reads its own anchored parent view and refuses a block whose
//! committed markers or member rows collide with it, whose claims the
//! read frontier fences, whose parent-anchored readings disagree with
//! it, or whose departures name a crossing it does not hold as named.
//! These are validity rules at vote time: a replica following a
//! certified block never evaluates them.

use std::fmt;

use hyperscale_storage::{
    CommittedHere, MemberInputs, Substates, colliding_committed_cell, colliding_member_row,
    load_read_frontier,
};
use hyperscale_types::{
    AbandonmentRecord, Anchor, FrontierInputs, FrontierRefusal, ReadFence, ShardId, StateClaim,
    SubstateKey, TxHash,
};
use hyperscale_vm_effects::CrossingId;

use crate::local_crossings::{disagreeing_parent_reading, misstated_unclaimed, parent_claims};
use crate::read_fence::{Dropped, drop_refused};

/// The parts of a block its parent state judges.
pub struct AtParent<'a> {
    /// The chain the block extends.
    pub local: ShardId,
    /// The committed markers the block writes.
    pub creations: &'a [CommittedHere],
    /// What the block writes to tick membership.
    pub members: &'a MemberInputs,
    /// What the read frontier judges of the block's claims.
    pub fence: &'a ReadFence,
    /// The block's claims.
    pub state_claims: &'a [StateClaim],
    /// The block's abandonment records.
    pub abandonment_records: &'a [AbandonmentRecord],
}

/// Why the parent state refuses a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentRefusal {
    /// A committed marker the parent already holds, or one two of the
    /// block's transactions name: the transaction was committed here.
    CommittedCell(SubstateKey),
    /// A member row key a standing row or another of the block's
    /// transactions takes: one row would stand for two.
    MemberRow(TxHash),
    /// A reading the read frontier fences.
    Frontier(Box<FrontierRefusal>),
    /// A parent-anchored reading the parent state does not bear out.
    ParentReading(SubstateKey),
    /// A crossing a departure names off this shard's leaf whose record
    /// the parent does not hold as named.
    MisstatedUnclaimed(SubstateKey),
}

impl fmt::Display for ParentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommittedCell(key) => {
                write!(f, "committed cell {key:?} already present or named twice")
            }
            Self::MemberRow(tx) => write!(f, "member row of {tx:?} already taken"),
            Self::Frontier(refusal) => write!(f, "read frontier refuses: {refusal}"),
            Self::ParentReading(key) => {
                write!(
                    f,
                    "parent-anchored reading of {key:?} disagrees with the parent"
                )
            }
            Self::MisstatedUnclaimed(key) => {
                write!(f, "named crossing {key:?} not held by the parent as named")
            }
        }
    }
}

/// Judge `block` against `parent`, the voter's own anchored view of the
/// block's parent.
///
/// # Errors
///
/// The first [`ParentRefusal`] the parent state gives.
pub fn refused_at_parent(
    block: &AtParent<'_>,
    parent: &(impl Substates + ?Sized),
) -> Result<(), ParentRefusal> {
    if let Some(key) = colliding_committed_cell(block.creations, parent) {
        return Err(ParentRefusal::CommittedCell(key));
    }
    if let Some(tx) = colliding_member_row(
        block.members.shard,
        block.members.transactions.iter().map(|(tx, _)| *tx),
        parent,
    ) {
        return Err(ParentRefusal::MemberRow(tx));
    }
    block
        .fence
        .check(&load_read_frontier(parent, block.local))
        .map_err(ParentRefusal::Frontier)?;
    if let Some(key) = disagreeing_parent_reading(block.state_claims, block.local, parent) {
        return Err(ParentRefusal::ParentReading(key));
    }
    if let Some(key) = misstated_unclaimed(block.abandonment_records, parent) {
        return Err(ParentRefusal::MisstatedUnclaimed(key));
    }
    Ok(())
}

/// A proposal's claims, built to pass [`refused_at_parent`].
pub struct ProposalClaims {
    /// The claims the block carries, in the section's order.
    pub claims: Vec<StateClaim>,
    /// What those claims do to the read frontier.
    pub frontier: FrontierInputs,
    /// How many readings the fence refused and the proposer dropped.
    pub refused: usize,
}

/// The claims a proposer carries: `selected` with every reading `fence`
/// refuses against `parent` cut, and the crossings whose ends share this
/// shard read at `parent_anchor` beside them.
///
/// The parent-anchored readings join after the cut. They pass the fence
/// without one: each is read at the parent itself, so no floor the
/// parent's own table holds sits above it.
#[must_use]
pub fn proposal_claims(
    selected: Vec<StateClaim>,
    fence: &ReadFence,
    frontier: &FrontierInputs,
    local_crossings: &[CrossingId],
    parent_anchor: Anchor,
    parent: &(impl Substates + ?Sized),
) -> ProposalClaims {
    let Dropped {
        mut claims,
        refused,
    } = drop_refused(
        selected,
        fence,
        frontier.windows,
        &load_read_frontier(parent, frontier.local),
    );
    claims.extend(parent_claims(local_crossings, parent_anchor, parent));
    claims.sort_unstable();
    let frontier =
        FrontierInputs::for_block(&claims, frontier.windows, frontier.anchor, frontier.local);
    ProposalClaims {
        claims,
        frontier,
        refused,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::Bytes;
    use hyperscale_storage::read_frontier_writes;
    use hyperscale_types::test_utils::{state_and_proof, test_key};
    use hyperscale_types::{
        Address, AddressClass, BlockHeight, CollectionId, Deadline, EntryKey, Epoch, EpochWindows,
        Hash, ReadFrontier, ReadMark, Reading, SettledEntries, StateRoot, Stated,
        UnclaimedCrossing, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingCell, Hash32, IntentHash, ProtocolHasher, Terms};
    use hyperscale_vm_types::ResourceAddr;

    use super::*;
    use crate::read_fence::read_fence;

    const WINDOW_MS: u64 = 1_000_000;

    fn windows() -> EpochWindows {
        EpochWindows::new(WINDOW_MS)
    }

    /// A parent state of cells and collection entries.
    #[derive(Default, Clone)]
    struct Parent {
        cells: BTreeMap<SubstateKey, Vec<u8>>,
        entries: BTreeMap<EntryKey, Vec<u8>>,
    }

    impl Parent {
        fn apply(&mut self, writes: &SettledEntries) {
            for (key, change) in writes {
                match change {
                    Some(bytes) => {
                        self.entries.insert(*key, bytes.clone());
                    }
                    None => {
                        self.entries.remove(key);
                    }
                }
            }
        }

        /// Raise the read frontier `local`'s table holds for each of
        /// `marks`.
        fn raise(&mut self, local: ShardId, marks: &[(ShardId, ReadMark)]) {
            let writes = read_frontier_writes(
                self,
                &FrontierInputs {
                    local,
                    anchor: WeightedTimestamp::from_millis(100),
                    windows: windows(),
                    marks: marks.iter().copied().collect(),
                },
            );
            self.apply(&writes);
        }
    }

    impl Substates for Parent {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.cells.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.entries
                .iter()
                .filter(|(key, _)| {
                    key.owner == owner
                        && key.collection == collection
                        && (lo..=hi).contains(&key.order)
                })
                .map(|(key, bytes)| (key.order, bytes.clone()))
                .take(limit)
                .collect()
        }
    }

    fn mark(height: u64) -> ReadMark {
        ReadMark {
            epoch: Epoch::GENESIS,
            height: BlockHeight::new(height),
        }
    }

    fn anchor(shard: ShardId, height: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::from_millis(height * 1_000),
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

    fn record_cell(id: CrossingId, terms: Terms) -> CrossingCell {
        id.cell(
            TxHash(Hash32([9; 32])),
            ResourceAddr::new([0xE0; 31]),
            5,
            9_000,
            terms,
        )
    }

    /// A parent holding an owed record of a crossing both of whose ends
    /// share the shard.
    fn holding_an_owed_record(id: CrossingId) -> Parent {
        let mut parent = Parent::default();
        parent.cells.insert(
            id.record_key(&ProtocolHasher),
            record_cell(id, Terms::Owed).to_bytes(),
        );
        parent
    }

    /// A counterpart's claim at `height` carrying a live owed record.
    fn remote_record_claim(producer: ShardId, height: u64) -> StateClaim {
        let id = crossing(0xAA);
        let record = id.record_key(&ProtocolHasher);
        let (state_root, proof) = state_and_proof(producer, &[record], &[record]);
        StateClaim::new(
            Anchor {
                state_root,
                ..anchor(producer, height)
            },
            [(
                record,
                Stated::Held(Bytes::new(record_cell(id, Terms::Owed).to_bytes()).unwrap()),
            )],
            proof,
        )
    }

    struct Block {
        local: ShardId,
        creations: Vec<CommittedHere>,
        members: MemberInputs,
        fence: ReadFence,
        state_claims: Vec<StateClaim>,
        abandonment_records: Vec<AbandonmentRecord>,
    }

    impl Block {
        fn empty(local: ShardId) -> Self {
            Self {
                local,
                creations: Vec::new(),
                members: MemberInputs::still(local),
                fence: ReadFence::default(),
                state_claims: Vec::new(),
                abandonment_records: Vec::new(),
            }
        }

        fn judged(&self, parent: &Parent) -> Result<(), ParentRefusal> {
            refused_at_parent(
                &AtParent {
                    local: self.local,
                    creations: &self.creations,
                    members: &self.members,
                    fence: &self.fence,
                    state_claims: &self.state_claims,
                    abandonment_records: &self.abandonment_records,
                },
                parent,
            )
        }
    }

    /// Each rule the parent state judges a block by refuses under its
    /// own name, and a block none of them touches passes.
    #[test]
    fn each_parent_rule_refuses_by_its_own_name() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let parent = Parent::default();
        assert_eq!(Block::empty(local).judged(&parent), Ok(()));

        let marker = test_key(0x30);
        let twice = CommittedHere {
            key: marker,
            value: vec![1],
            inherited: None,
        };
        let block = Block {
            creations: vec![twice.clone(), twice],
            ..Block::empty(local)
        };
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::CommittedCell(marker))
        );

        let tx = TxHash::from(Hash::from_bytes(b"twice"));
        let deadline = Deadline::of(WeightedTimestamp::from_millis(90_000));
        let block = Block {
            members: MemberInputs {
                transactions: vec![(tx, deadline), (tx, deadline)],
                ..MemberInputs::still(local)
            },
            ..Block::empty(local)
        };
        assert_eq!(block.judged(&parent), Err(ParentRefusal::MemberRow(tx)));

        let mut raised = Parent::default();
        raised.raise(local, &[(producer, mark(9))]);
        let block = Block {
            fence: ReadFence {
                presences: vec![Reading {
                    key: test_key(0x40),
                    shard: producer,
                    mark: mark(5),
                }],
                ..ReadFence::default()
            },
            ..Block::empty(local)
        };
        assert!(
            matches!(
                block.judged(&raised),
                Err(ParentRefusal::Frontier(refusal))
                    if matches!(*refusal, FrontierRefusal::BelowFloor { .. })
            ),
            "a presence below its producer's floor",
        );
        assert_eq!(block.judged(&parent), Ok(()), "and passes with no floor");

        let id = crossing(0x41);
        let held = holding_an_owed_record(id);
        let block = Block {
            state_claims: parent_claims(&[id], anchor(local, 4), &held),
            ..Block::empty(local)
        };
        assert_eq!(block.judged(&held), Ok(()));
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::ParentReading(id.record_key(&ProtocolHasher))),
            "read at a parent holding the record, judged at one without it",
        );

        let escrowed = crossing(0x51);
        let record = escrowed.record_key(&ProtocolHasher);
        let named = UnclaimedCrossing::of(
            record,
            &record_cell(escrowed, Terms::Escrowed { credit: record }),
        );
        let block = Block {
            abandonment_records: vec![
                AbandonmentRecord::new(producer, WeightedTimestamp::from_millis(9_000), [])
                    .with_unclaimed([named]),
            ],
            ..Block::empty(local)
        };
        assert_eq!(
            block.judged(&parent),
            Err(ParentRefusal::MisstatedUnclaimed(record)),
        );
    }

    /// A proposal cuts the counterpart reading its parent's floor
    /// refuses, carries its parent-anchored readings uncut, and the block
    /// it builds passes every rule its voters judge it by: the fence
    /// defers nothing read at the parent, even with this shard's own
    /// entry raised by the parent's own parent reading.
    #[test]
    fn a_proposal_passes_its_own_parent_checks() {
        let local = ShardId::leaf(1, 0);
        let producer = ShardId::leaf(1, 1);
        let id = crossing(0x41);
        let mut parent = holding_an_owed_record(id);
        parent.raise(local, &[(producer, mark(9)), (local, mark(3))]);

        let stale = remote_record_claim(producer, 5);
        let fence = read_fence(std::slice::from_ref(&stale), windows());
        let built = proposal_claims(
            vec![stale],
            &fence,
            &FrontierInputs::for_block(
                &[],
                windows(),
                WeightedTimestamp::from_millis(4_500),
                local,
            ),
            &[id],
            anchor(local, 4),
            &parent,
        );
        assert_eq!(built.refused, 1, "the counterpart's stale presence");
        assert_eq!(built.claims.len(), 1, "the parent reading alone");
        assert_eq!(built.claims[0].anchor.shard, local);
        assert_eq!(built.frontier.marks.get(&local), Some(&mark(4)));

        let block = Block {
            fence: read_fence(&built.claims, windows()),
            state_claims: built.claims,
            ..Block::empty(local)
        };
        assert_eq!(block.fence.presences.len(), 1, "the owed record is fenced");
        assert_eq!(block.judged(&parent), Ok(()));
    }

    /// A reading taken at the parent raises this shard's own entry, and
    /// a split child inherits it: a reading of the parent's older than
    /// that entry is refused on the right child as on the left.
    #[test]
    fn a_parent_reading_raises_the_local_entry_and_a_child_refuses_an_older_one() {
        let local = ShardId::leaf(1, 0);
        let id = crossing(0x41);
        let mut parent = holding_an_owed_record(id);
        let read = parent_claims(&[id], anchor(local, 4), &parent);
        let inputs = FrontierInputs::for_block(
            &read,
            windows(),
            WeightedTimestamp::from_millis(4_500),
            local,
        );
        assert_eq!(inputs.marks.get(&local), Some(&mark(4)));
        let writes = read_frontier_writes(&parent, &inputs);
        parent.apply(&writes);

        let older = read_fence(&parent_claims(&[id], anchor(local, 3), &parent), windows());
        let same = read_fence(&read, windows());
        for child in <[ShardId; 2]>::from(local.children()) {
            let table = load_read_frontier(&parent, child);
            assert_eq!(
                table.floor(local),
                Some(mark(4)),
                "{child:?} inherits the entry"
            );
            assert!(
                matches!(
                    older.check(&table).map_err(|refusal| *refusal),
                    Err(FrontierRefusal::BelowFloor { .. })
                ),
                "{child:?} refuses the older reading",
            );
            assert_eq!(
                same.check(&table),
                Ok(()),
                "{child:?} admits the entry's own mark"
            );
        }
        assert_eq!(
            load_read_frontier(&parent, local),
            ReadFrontier::from_entries([(local, mark(4))]),
        );
    }
}
