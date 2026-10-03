//! What a block is judged by against its parent state, and how a
//! proposer builds the claims that pass it.
//!
//! A voter reads its own anchored parent view and refuses a block whose
//! committed markers or member rows collide with it, whose claims the
//! read frontier fences, whose parent-anchored readings disagree with
//! it, whose departures name a crossing it does not hold as named, or
//! whose fees a payer this shard holds cannot cover.
//! These are validity rules at vote time: a replica following a
//! certified block never evaluates them.

use std::collections::BTreeMap;
use std::fmt;

use hyperscale_jmt::NibblePath;
use hyperscale_storage::{
    CommittedHere, FeeTerms, MemberInputs, Substates, colliding_committed_cell,
    colliding_member_row, held_total, key_under_prefix, load_read_frontier,
};
use hyperscale_types::{
    AbandonmentRecord, Anchor, FrontierInputs, FrontierRefusal, ReadFence, ShardId,
    SharedTransactions, StateClaim, SubstateKey, Transaction, TxHash, shard_prefix_path,
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
    /// The block's transactions, whose fees its payers must cover.
    pub transactions: &'a SharedTransactions,
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
    /// A fee the payer's stored rule does not let this transaction's
    /// attesting set engage.
    UnadmittedPayer(SubstateKey),
    /// A fee vault whose balance does not cover what it already holds
    /// plus what the block charges it.
    UncoveredPayer(SubstateKey),
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
            Self::UnadmittedPayer(vault) => {
                write!(f, "payer of {vault:?} does not admit the attesting set")
            }
            Self::UncoveredPayer(vault) => {
                write!(
                    f,
                    "fee vault {vault:?} does not cover its holds and charges"
                )
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
    let mut charges = PayerCharges::new(block.local, parent);
    for tx in block.transactions.iter() {
        charges.charge(tx.as_unverified())?;
    }
    Ok(())
}

/// What each fee vault this shard holds is charged, judged against one
/// state: the parent's for a voter, and the same parent for the proposer
/// building on it, so a proposal never refuses itself.
///
/// A hold is state, written by the block that includes its transaction
/// and deleted in the write set that burns its price, so the parent's
/// held total is every reservation the chain still carries against the
/// vault, and nothing but the block's own charges is added to it.
pub struct PayerCharges<'s, S: ?Sized> {
    prefix: NibblePath,
    state: &'s S,
    charged: BTreeMap<SubstateKey, u128>,
}

impl<'s, S: Substates + ?Sized> PayerCharges<'s, S> {
    /// No charges yet against `state`, for the vaults under `local`'s
    /// prefix: the ones this shard writes holds for.
    pub fn new(local: ShardId, state: &'s S) -> Self {
        Self {
            prefix: shard_prefix_path(local),
            state,
            charged: BTreeMap::new(),
        }
    }

    /// Charge `tx`'s ceiling to its payer's vault, or say why the payer
    /// refuses it. A payer this shard does not hold is another shard's
    /// to judge, and a refused charge leaves the vault's figure as it
    /// was.
    ///
    /// # Errors
    ///
    /// [`ParentRefusal::UnadmittedPayer`] where the payer's stored rule
    /// does not admit the attesting set, and
    /// [`ParentRefusal::UncoveredPayer`] where the vault's balance falls
    /// short of its held total plus every charge so far and this one.
    pub fn charge(&mut self, tx: &Transaction) -> Result<(), ParentRefusal> {
        let terms = FeeTerms::of(tx);
        if !key_under_prefix(&terms.vault.to_bytes(), &self.prefix) {
            return Ok(());
        }
        if !tx.payer_admits_attesters(self.state.cell(tx.auth_cell()).as_deref()) {
            return Err(ParentRefusal::UnadmittedPayer(terms.vault));
        }
        let charged = self
            .charged
            .entry(terms.vault)
            .or_insert_with(|| held_total(self.state, terms.vault));
        let wanted = charged.saturating_add(terms.max_fee);
        if wanted > vault_balance(self.state, terms.vault) {
            return Err(ParentRefusal::UncoveredPayer(terms.vault));
        }
        *charged = wanted;
        Ok(())
    }
}

/// A vault's balance of the protocol resource as `state` holds it: zero
/// where the vault is absent.
fn vault_balance(state: &(impl Substates + ?Sized), vault: SubstateKey) -> u128 {
    state
        .cell(vault)
        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
        .map_or(0, u128::from_le_bytes)
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
    use std::sync::Arc;

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_storage::read_frontier_writes;
    use hyperscale_types::test_utils::{state_and_proof, stub_transaction, test_key};
    use hyperscale_types::{
        Address, AddressClass, BlockHeight, CollectionId, Deadline, EntryKey, Epoch, EpochWindows,
        Hash, PrincipalAddr, ReadFrontier, ReadMark, Reading, SettledEntries, StateRoot, Stated,
        TimestampRange, UnclaimedCrossing, Verifiable, WeightedTimestamp,
    };
    use hyperscale_vm_effects::{
        CrossingCell, Hash32, IntentHash, ProtocolHasher, Terms, fee_hold_total_key,
    };
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
        transactions: SharedTransactions,
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
                transactions: Arc::new(Capped::empty()),
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
                    transactions: &self.transactions,
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

    /// A fixture payer and a transaction of `max_fee` it signs alone.
    fn paid(max_fee: u128) -> (Transaction, SubstateKey) {
        let payer = PrincipalAddr::new([0x42; 31]);
        let tx = stub_transaction(
            payer,
            &[payer.address()],
            max_fee,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        );
        let vault = FeeTerms::of(&tx).vault;
        (tx, vault)
    }

    /// `parent` holding `balance` in `vault` and `held` reserved against it.
    fn funded(vault: SubstateKey, balance: u128, held: u128) -> Parent {
        let mut parent = Parent::default();
        parent.cells.insert(vault, balance.to_le_bytes().to_vec());
        if held != 0 {
            parent.cells.insert(
                fee_hold_total_key(&ProtocolHasher, vault),
                held.to_le_bytes().to_vec(),
            );
        }
        parent
    }

    /// A vault this shard holds covers what it already holds plus every
    /// charge so far: charges accumulate, and a refused one moves nothing.
    #[test]
    fn a_held_payer_covers_its_holds_and_charges() {
        let (tx, vault) = paid(300);
        let parent = funded(vault, 1_000, 700);
        let mut charges = PayerCharges::new(ShardId::ROOT, &parent);
        assert_eq!(charges.charge(&tx), Ok(()), "700 held + 300 fits 1_000");
        assert_eq!(
            charges.charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "a second 300 does not"
        );
        let (one, _) = paid(0);
        assert_eq!(
            charges.charge(&one),
            Ok(()),
            "the refused charge left the figure at 1_000"
        );

        let empty = Parent::default();
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &empty).charge(&tx),
            Err(ParentRefusal::UncoveredPayer(vault)),
            "an absent vault holds nothing"
        );
    }

    /// A stored rule that does not admit the attesting set refuses the
    /// fee before any balance is read.
    #[test]
    fn a_payer_whose_rule_refuses_the_signer_refuses_the_fee() {
        let (tx, vault) = paid(1);
        let mut parent = funded(vault, 1_000, 0);
        parent.cells.insert(tx.auth_cell(), vec![0xAB]);
        assert_eq!(
            PayerCharges::new(ShardId::ROOT, &parent).charge(&tx),
            Err(ParentRefusal::UnadmittedPayer(vault))
        );
    }

    /// A payer whose vault another shard holds is that shard's to judge.
    #[test]
    fn a_payer_another_shard_holds_is_not_judged_here() {
        let (tx, vault) = paid(1_000);
        let (left, right) = ShardId::ROOT.children();
        let elsewhere = if key_under_prefix(&vault.to_bytes(), &shard_prefix_path(left)) {
            right
        } else {
            left
        };
        let empty = Parent::default();
        assert_eq!(PayerCharges::new(elsewhere, &empty).charge(&tx), Ok(()));
    }

    /// The parent state refuses a block whose payer cannot cover it, by
    /// that rule's name.
    #[test]
    fn a_block_its_payer_cannot_cover_is_refused() {
        let (tx, vault) = paid(301);
        let mut block = Block::empty(ShardId::ROOT);
        block.transactions = Arc::new(Capped::from_array([Arc::new(Verifiable::from(tx))]));
        assert_eq!(
            block.judged(&funded(vault, 1_000, 700)),
            Err(ParentRefusal::UncoveredPayer(vault))
        );
        assert_eq!(block.judged(&funded(vault, 1_001, 700)), Ok(()));
    }
}
