//! Tick membership as committed state: which transactions this chain has
//! committed and not resolved, and which tick holds each.
//!
//! Three ordered collections under the shard's own owner at
//! [`TICK_MEMBER_SLOT`], told apart by their material, which also names
//! the shard. Member rows are keyed by the first 128 bits of the
//! transaction hash and tick rows by height. Seats are keyed as member
//! rows are, and stand exactly while a member a counterpart settles
//! against is in flight: what a counterpart reads, by presence alone, to
//! tell a seated member from one still waiting. Naming the shard puts a
//! predecessor's rows in a collection its successor never reads as its
//! own, even where the two share an owner address, as a split's left
//! child shares its parent's.
//!
//! One fold writes the family, [`member_writes`], off the block and the
//! parent's rows alone, so a replica that cannot route a transaction
//! folds the same writes as one that can, and every reader of the root
//! derives one set. What only a routing replica can derive of a member,
//! the block states: in its terms section for a transaction it commits
//! and does not run, and on the member line for one it runs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor, HborDecode, from_slice, to_vec};
use hyperscale_types::{
    AbandonmentRecord, AbortCharge, Address, Block, BlockHeight, CollectionId, Deadline,
    DiscardCause, EntryKey, Finalization, Holds, Joins, MAX_TICK_LINES_PER_BLOCK,
    MAX_VALIDITY_RANGE, MemberTerms, Movement, Reach, Reserves, SettledEntries, Settlement,
    ShardId, ShardTrie, StateWrites, StatedTerms, SubstateKey, TickHalf, TickId, TickLine,
    TickManifest, Transaction, TxHash, TxOutcome, Verifiable, Verified, WeightedTimestamp,
    entry_leaf_key,
};
use hyperscale_vm_effects::{
    CrossingId, ProtocolHasher, TICK_MEMBER_SLOT, collection_id, fee_hold_key, protocol_resource,
};
use hyperscale_vm_types::MAX_CROSSINGS_PER_TX;

use crate::Substates;
use crate::shard::fee_holds::FeeTerms;
use crate::shard::writes::fold_state_writes;

/// Where a member stands in its tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum RowState {
    /// Committed, and named by no tick yet.
    Pending,
    /// Named by the tick at `tick`, on the terms the line gave.
    InFlight {
        /// The height of the tick holding it.
        tick: BlockHeight,
        /// The terms it joined on.
        joins: Joins,
        /// Which half settles it, and whether a discard keeps it.
        settlement: Settlement,
    },
    /// Let go by a discard of the tick that held it, and not yet
    /// aborted.
    Released {
        /// Which half its line said settles it.
        settlement: Settlement,
    },
}

impl RowState {
    /// Whether a row standing so holds a seat: in flight, and settled
    /// against by a counterpart.
    #[must_use]
    pub const fn seated(self) -> bool {
        matches!(
            self,
            Self::InFlight {
                settlement: Settlement::Shared,
                ..
            }
        )
    }
}

/// What a member is judged on while no line has named it: the terms its
/// committing block stated that a naming line restates or ends.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct Waiting {
    /// Whether this shard runs a leg of the transaction and not its
    /// core.
    pub leg: bool,
    /// Which half settles it, and whether a discard keeps it.
    pub settlement: Settlement,
    /// Its declared accesses, each under the mode it takes.
    pub declared: Holds,
    /// The remote shards whose committed bundle it requires before it
    /// runs.
    pub engages: Reach,
    /// Whether it is the payer's leg, which waits for every shard it
    /// reaches to engage.
    pub waits: bool,
}

/// One committed, unresolved member.
///
/// Its terms stand from the block that committed it: stated by that
/// block's terms section, or by the member line of a transaction the
/// block itself names to run.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct MemberRow {
    /// The transaction, whole, so a key two hashes share is visible.
    pub tx: TxHash,
    /// Its deadline, off its signed validity range.
    pub deadline: Deadline,
    /// The parent-QC clock of the block that committed it: the clock it
    /// is priced at.
    pub committed: WeightedTimestamp,
    /// The height of the block that committed it, from which a crossing
    /// read for it counts as arrived.
    pub height: BlockHeight,
    /// Where it stands.
    pub state: RowState,
    /// What it holds while in flight, as its line named them; empty in
    /// every other state.
    pub holds: Holds,
    /// The remote shards it reaches.
    pub reach: Reach,
    /// The remote shards whose certificates its settlement awaits.
    pub awaits: Reach,
    /// What an abort of it burns, out of whose vault.
    pub charge: AbortCharge,
    /// The price this shard attests for it, in quanta.
    pub share: u128,
    /// What its declared reservations promise of this shard's fee
    /// vaults, for as long as the row stands.
    pub reserves: Reserves,
    /// The escrowed crossings it consumes; empty once a line names it
    /// to run.
    pub crossings: Capped<Vec<CrossingId>, MAX_CROSSINGS_PER_TX>,
    /// What it is judged on until a line names it: `Some` exactly while
    /// it stands `Pending`.
    pub waiting: Option<Waiting>,
    /// Whether a committed abandonment record names it.
    pub covered: bool,
}

impl MemberRow {
    /// The row a block writes for a transaction it commits and does not
    /// run, on the terms it states.
    fn pending(
        tx: TxHash,
        deadline: Deadline,
        committed: WeightedTimestamp,
        height: BlockHeight,
        terms: &MemberTerms,
    ) -> Self {
        Self {
            tx,
            deadline,
            committed,
            height,
            state: RowState::Pending,
            holds: Capped::empty(),
            reach: terms.reach.clone(),
            awaits: terms.awaits.clone(),
            charge: terms.charge,
            share: terms.share,
            reserves: terms.reserves.clone(),
            crossings: terms.crossings.clone(),
            waiting: Some(Waiting {
                leg: terms.leg,
                settlement: terms.settlement,
                declared: terms.declared.clone(),
                engages: terms.engages.clone(),
                waits: terms.waits,
            }),
            covered: false,
        }
    }

    /// The end of the transaction's abandon window.
    #[must_use]
    pub fn until(&self) -> WeightedTimestamp {
        self.deadline.at().plus(MAX_VALIDITY_RANGE)
    }
}

/// One tick with members in flight.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hbor)]
pub struct TickRow {
    /// The transactions it holds, in manifest order.
    pub members: Capped<Vec<TxHash>, MAX_TICK_LINES_PER_BLOCK>,
    /// Whether its determined half is still owed.
    pub determined_unsettled: bool,
    /// Whether its legs half is still owed.
    pub legs_unsettled: bool,
}

impl TickRow {
    const fn owes(&self) -> bool {
        self.determined_unsettled || self.legs_unsettled
    }

    const fn clear(&mut self, half: TickHalf) {
        match half {
            TickHalf::Determined => self.determined_unsettled = false,
            TickHalf::Legs => self.legs_unsettled = false,
        }
    }
}

/// What one finalization settles: its tick, its half and the members it
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledHalf {
    /// The tick the half belongs to.
    pub tick: TickId,
    /// Which half.
    pub half: TickHalf,
    /// The members it names.
    pub members: Vec<TxHash>,
}

/// Everything [`member_writes`] reads of a block: owned, so it rides
/// beside the block's other chain writes to every site that prepares a
/// commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInputs {
    /// The committing chain.
    pub shard: ShardId,
    /// The block's height, which is its tick's.
    pub height: BlockHeight,
    /// The block's parent-QC clock.
    pub committed: WeightedTimestamp,
    /// Each transaction the block carries, with its deadline.
    pub transactions: Vec<(TxHash, Deadline)>,
    /// What each transaction the block carries reserves against its
    /// payer's vault, in the same order.
    pub fees: Vec<FeeTerms>,
    /// What each of its finalizations settles.
    pub settled: Vec<SettledHalf>,
    /// The transactions its abandonment records name.
    pub covered: Vec<TxHash>,
    /// Its tick manifest.
    pub manifest: Arc<TickManifest>,
    /// The terms it states of the transactions it commits and does not
    /// run.
    pub terms: Vec<StatedTerms>,
}

impl MemberInputs {
    /// What `block` writes to the family, read off the sections it
    /// carries and nothing this replica derives.
    #[must_use]
    pub fn of(block: &Block) -> Self {
        let header = block.header();
        Self {
            manifest: Arc::new(block.tick_manifest().clone()),
            ..Self::deriving(
                header.shard_id(),
                header.height(),
                header.parent_qc().weighted_timestamp(),
                block.transactions().iter().map(|tx| tx.as_unverified()),
                block.certificates(),
                block.abandonment_records(),
                block.terms().to_vec(),
            )
        }
    }

    /// A block that writes nothing to the family: no transactions, no
    /// finalizations, no records and no lines.
    #[must_use]
    pub fn still(shard: ShardId) -> Self {
        Self {
            shard,
            height: BlockHeight::GENESIS,
            committed: WeightedTimestamp::ZERO,
            transactions: Vec::new(),
            fees: Vec::new(),
            settled: Vec::new(),
            covered: Vec::new(),
            manifest: Arc::new(Capped::empty()),
            terms: Vec::new(),
        }
    }

    /// What a block of these sections writes before any line of it is
    /// named, each transaction standing on the entry of `terms` that
    /// names it: the rows a proposer names its lines over and a voter
    /// judges them over, where `terms` is what each derives for every
    /// transaction of the block.
    #[must_use]
    pub fn deriving<'a>(
        shard: ShardId,
        height: BlockHeight,
        committed: WeightedTimestamp,
        transactions: impl IntoIterator<Item = &'a Transaction>,
        certificates: &[Arc<Verifiable<Finalization>>],
        records: &[AbandonmentRecord],
        terms: Vec<StatedTerms>,
    ) -> Self {
        let transactions: Vec<&Transaction> = transactions.into_iter().collect();
        Self {
            shard,
            height,
            committed,
            fees: transactions.iter().map(|tx| FeeTerms::of(tx)).collect(),
            transactions: transactions
                .into_iter()
                .map(|tx| (tx.hash(), Deadline::of_transaction(tx)))
                .collect(),
            settled: certificates
                .iter()
                .map(|fw| {
                    let fw = fw.as_unverified();
                    // Off the local certificate, which admission requires
                    // of every committed finalization. Read without
                    // relying on it, since a root is checked before a
                    // block's sections are.
                    let members = fw
                        .execution_certificates()
                        .iter()
                        .find(|ec| ec.tick_id() == fw.tick_id())
                        .map_or_default(|ec| {
                            ec.tx_outcomes().iter().map(TxOutcome::tx_hash).collect()
                        });
                    SettledHalf {
                        tick: *fw.tick_id(),
                        half: fw.half(),
                        members,
                    }
                })
                .collect(),
            covered: records
                .iter()
                .flat_map(|record| record.unsettled().iter().map(|name| name.tx_hash))
                .collect(),
            manifest: Arc::new(Capped::empty()),
            terms,
        }
    }
}

/// Material telling the family's collections apart.
const MEMBERS: u8 = 0;
const TICKS: u8 = 1;
const SEATS: u8 = 2;

fn collection_of(shard: ShardId, kind: u8) -> (Address, CollectionId) {
    let owner = ShardTrie::shard_owner(shard);
    let material = [vec![kind], shard.inner().to_be_bytes().to_vec()];
    (
        owner,
        collection_id(&ProtocolHasher, owner, TICK_MEMBER_SLOT, &material),
    )
}

/// A member's order key: the first 128 bits of its hash.
#[must_use]
pub fn member_order(tx: TxHash) -> u128 {
    let mut high = [0u8; 16];
    high.copy_from_slice(&tx.as_bytes()[..16]);
    u128::from_be_bytes(high)
}

/// The tree leaf of `tx`'s member row in `shard`'s collection: the key a
/// state claim reads to prove the row standing or gone.
#[must_use]
pub fn member_row_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, member_entry(shard, tx))
}

fn member_entry(shard: ShardId, tx: TxHash) -> EntryKey {
    let (owner, collection) = collection_of(shard, MEMBERS);
    EntryKey {
        owner,
        collection,
        order: member_order(tx),
    }
}

/// The tree leaf of `tx`'s seat in `shard`'s family: present exactly
/// while `tx` is in flight there and a counterpart settles it against
/// `shard`'s certificate.
#[must_use]
pub fn seat_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    let (owner, collection) = collection_of(shard, SEATS);
    entry_leaf_key(
        &ProtocolHasher,
        EntryKey {
            owner,
            collection,
            order: member_order(tx),
        },
    )
}

fn tick_entry(shard: ShardId, height: BlockHeight) -> EntryKey {
    let (owner, collection) = collection_of(shard, TICKS);
    EntryKey {
        owner,
        collection,
        order: u128::from(height.inner()),
    }
}

fn read_at<T: HborDecode>(state: &(impl Substates + ?Sized), key: EntryKey) -> Option<T> {
    state
        .entries_in_range(key.owner, key.collection, key.order, key.order, 1)
        .into_iter()
        .next()
        .and_then(|(_, bytes)| from_slice(&bytes).ok())
}

fn read_all(state: &(impl Substates + ?Sized), shard: ShardId, kind: u8) -> Vec<(u128, Vec<u8>)> {
    let (owner, collection) = collection_of(shard, kind);
    state.entries_in_range(owner, collection, 0, u128::MAX, usize::MAX)
}

/// The family as the fold changes it: each row read at most once, and
/// written back only where it changed.
struct Working<'s, S: ?Sized> {
    state: &'s S,
    shard: ShardId,
    members: BTreeMap<u128, Option<MemberRow>>,
    /// Each row read, as the state held it: what a changed row's seat is
    /// written against.
    read: BTreeMap<u128, Option<MemberRow>>,
    ticks: BTreeMap<BlockHeight, Option<TickRow>>,
    changed_members: BTreeSet<u128>,
    changed_ticks: BTreeSet<BlockHeight>,
}

impl<'s, S: Substates + ?Sized> Working<'s, S> {
    const fn new(state: &'s S, shard: ShardId) -> Self {
        Self {
            state,
            shard,
            members: BTreeMap::new(),
            read: BTreeMap::new(),
            ticks: BTreeMap::new(),
            changed_members: BTreeSet::new(),
            changed_ticks: BTreeSet::new(),
        }
    }

    /// The row standing for `tx`: the transaction's own, never one whose
    /// hash merely shares its key.
    fn member(&mut self, tx: TxHash) -> Option<MemberRow> {
        let order = member_order(tx);
        if !self.members.contains_key(&order) {
            let stored = self.stored(tx);
            self.members.insert(order, stored);
        }
        self.members[&order].clone().filter(|row| row.tx == tx)
    }

    /// The row the state holds under `tx`'s key, whoever's it is.
    fn stored(&mut self, tx: TxHash) -> Option<MemberRow> {
        let (state, shard) = (self.state, self.shard);
        self.read
            .entry(member_order(tx))
            .or_insert_with(|| read_at(state, member_entry(shard, tx)))
            .clone()
    }

    fn set_member(&mut self, tx: TxHash, row: Option<MemberRow>) {
        let order = member_order(tx);
        self.members.insert(order, row);
        self.changed_members.insert(order);
    }

    fn tick(&mut self, height: BlockHeight) -> Option<TickRow> {
        let (state, shard) = (self.state, self.shard);
        self.ticks
            .entry(height)
            .or_insert_with(|| read_at(state, tick_entry(shard, height)))
            .clone()
    }

    fn set_tick(&mut self, height: BlockHeight, row: Option<TickRow>) {
        self.ticks.insert(height, row);
        self.changed_ticks.insert(height);
    }

    /// Release `tx` from its tick: `Released`, holding nothing.
    fn release(&mut self, tx: TxHash) {
        if let Some(mut row) = self.member(tx) {
            let RowState::InFlight { settlement, .. } = row.state else {
                return;
            };
            row.state = RowState::Released { settlement };
            row.holds = Capped::empty();
            self.set_member(tx, Some(row));
        }
    }

    /// A finalization deletes the rows it names and clears its half; a
    /// tick owing neither half goes.
    fn settle(&mut self, settled: &SettledHalf) {
        if settled.tick.shard_id() != self.shard {
            return;
        }
        for &tx in &settled.members {
            if self.member(tx).is_some() {
                self.set_member(tx, None);
            }
        }
        let height = settled.tick.block_height();
        if let Some(mut tick) = self.tick(height) {
            tick.clear(settled.half);
            let owes = tick.owes();
            self.set_tick(height, owes.then_some(tick));
        }
    }

    /// A discard releases every member of the tick that shares no
    /// verdict with a counterpart, and the one it abandons whatever that
    /// shares; a recovery discard releases the whole tick. What stays is
    /// owed only its legs half. The member an `Unanswerable` discard
    /// names is deleted rather than released: no counterpart is left to
    /// answer for it, nothing will ever abort it, and a released row an
    /// abort named would stand in flight for good.
    fn discard(&mut self, tick: TickId, cause: DiscardCause) {
        if tick.shard_id() != self.shard {
            return;
        }
        let height = tick.block_height();
        let Some(held) = self.tick(height) else {
            return;
        };
        let abandoned = match cause {
            DiscardCause::Abandoned(tx) | DiscardCause::Unanswerable(tx) => Some(tx),
            DiscardCause::Recovery => None,
        };
        let dropped = match cause {
            DiscardCause::Unanswerable(tx) => Some(tx),
            _ => None,
        };
        let whole = matches!(cause, DiscardCause::Recovery);
        let mut kept = Vec::new();
        for &tx in held.members.iter() {
            let keeps = self.member(tx).is_some_and(|row| row.state.seated());
            if keeps && !whole && Some(tx) != abandoned {
                kept.push(tx);
            } else if Some(tx) == dropped {
                self.set_member(tx, None);
            } else {
                self.release(tx);
            }
        }
        let remains = (!kept.is_empty()).then(|| TickRow {
            members: Capped::new(kept).expect("a subset of a capped list"),
            determined_unsettled: false,
            legs_unsettled: true,
        });
        self.set_tick(height, remains);
    }

    /// The terminal's fates delete the rows they name, and every tick
    /// row they leave listing no standing member.
    fn fate(&mut self, fated: &[TxHash]) {
        let mut ticks = BTreeSet::new();
        for &tx in fated {
            let Some(row) = self.member(tx) else {
                continue;
            };
            if let RowState::InFlight { tick, .. } = row.state {
                ticks.insert(tick);
            }
            self.set_member(tx, None);
        }
        for height in ticks {
            let Some(tick) = self.tick(height) else {
                continue;
            };
            if tick.members.iter().all(|&tx| self.member(tx).is_none()) {
                self.set_tick(height, None);
            }
        }
    }

    /// A record naming a standing row covers it.
    fn cover(&mut self, tx: TxHash) {
        if let Some(mut row) = self.member(tx)
            && !row.covered
        {
            row.covered = true;
            self.set_member(tx, Some(row));
        }
    }

    /// The manifest's member lines put their rows in flight in the
    /// block's own tick.
    ///
    /// A line naming one of the block's own transactions to run writes
    /// the row itself, whatever stands under its key: the block states
    /// no entry for it, and the row a proposer or voter folded from the
    /// terms it derived must come to the same bytes. So a named row keeps
    /// nothing its line does not state. A row standing from an earlier
    /// block keeps where it was committed and whether a record covers it,
    /// and an abort keeps the crossings it never consumed.
    fn name(&mut self, inputs: &MemberInputs) {
        let height = inputs.height;
        let own: BTreeMap<TxHash, Deadline> = inputs.transactions.iter().copied().collect();
        let mut composed = TickRow::default();
        let mut members = Vec::new();
        for line in inputs.manifest.iter() {
            match line {
                TickLine::Member {
                    tx,
                    joins,
                    settlement,
                    holds,
                    reach,
                    awaits,
                    charge,
                    share,
                    reserves,
                } => {
                    let runs = joins.dispatched();
                    let (deadline, committed, committed_at, covered, crossings) =
                        if let Some(&deadline) = own.get(tx).filter(|_| runs) {
                            (deadline, inputs.committed, height, false, Capped::empty())
                        } else if let Some(row) = self.member(*tx) {
                            let crossings = if runs { Capped::empty() } else { row.crossings };
                            (
                                row.deadline,
                                row.committed,
                                row.height,
                                row.covered,
                                crossings,
                            )
                        } else {
                            continue;
                        };
                    let row = MemberRow {
                        tx: *tx,
                        deadline,
                        committed,
                        height: committed_at,
                        state: RowState::InFlight {
                            tick: height,
                            joins: *joins,
                            settlement: *settlement,
                        },
                        holds: holds.clone(),
                        reach: reach.clone(),
                        awaits: awaits.clone(),
                        charge: *charge,
                        share: *share,
                        reserves: reserves.clone(),
                        crossings,
                        waiting: None,
                        covered,
                    };
                    self.set_member(*tx, Some(row));
                    members.push(*tx);
                    match settlement.half() {
                        TickHalf::Determined => composed.determined_unsettled = true,
                        TickHalf::Legs => composed.legs_unsettled = true,
                    }
                }
                TickLine::Fate { .. } | TickLine::Discard { .. } => {}
            }
        }
        if !members.is_empty() {
            composed.members = Capped::new(members).expect("a manifest caps its lines");
            self.set_tick(height, Some(composed));
        }
    }

    fn into_writes(self, writes: &mut SettledEntries) {
        let (owner, members) = collection_of(self.shard, MEMBERS);
        let (_, seats) = collection_of(self.shard, SEATS);
        for order in self.changed_members {
            let row = self.members[&order].as_ref();
            writes.insert(
                EntryKey {
                    owner,
                    collection: members,
                    order,
                },
                row.map(|row| to_vec(row).expect("a member row encodes")),
            );
            // A row the fold never read is one the block commits fresh,
            // under a key no standing row holds, so it held no seat.
            let was = self
                .read
                .get(&order)
                .and_then(Option::as_ref)
                .is_some_and(|row| row.state.seated());
            let seat = row.filter(|row| row.state.seated());
            if was != seat.is_some() {
                writes.insert(
                    EntryKey {
                        owner,
                        collection: seats,
                        order,
                    },
                    seat.map(|row| to_vec(&row.tx).expect("a hash encodes")),
                );
            }
        }
        for height in self.changed_ticks {
            let value = self.ticks[&height]
                .as_ref()
                .map(|row| to_vec(row).expect("a tick row encodes"));
            writes.insert(tick_entry(self.shard, height), value);
        }
    }
}

/// The entry writes one block makes to the tick membership family.
///
/// In a fixed order: the finalizations delete the rows they name and
/// clear their halves; the discards release their ticks' members; the
/// records cover the rows they name; each of the block's transactions
/// its terms section names gets a `Pending` row on those terms; and the
/// manifest's member lines put rows in flight in the block's own tick,
/// writing the row of a transaction the block both commits and runs. No
/// row leaves by age: every exit is a committed line or certificate. A
/// row's seat is written beside it wherever the row comes to hold one or
/// stops holding one.
///
/// Total over any terms section. A transaction's terms are the first
/// entry naming it; an entry naming no transaction of the block, or a
/// transaction an earlier entry named, is never read; and a transaction
/// with neither an entry nor a line running it gets no row.
///
/// `state` is the state the block's writes land on, read through the
/// same view the block's movements resolve against.
///
/// # Panics
///
/// If a row fails to encode, which rows within their caps cannot.
#[must_use]
pub fn member_writes(state: &(impl Substates + ?Sized), inputs: &MemberInputs) -> SettledEntries {
    let mut family = Working::new(state, inputs.shard);
    for settled in &inputs.settled {
        family.settle(settled);
    }
    for line in inputs.manifest.iter() {
        if let TickLine::Discard { tick, cause } = line {
            family.discard(*tick, *cause);
        }
    }
    for &tx in &inputs.covered {
        family.cover(tx);
    }
    let mut stated: BTreeMap<TxHash, &MemberTerms> = BTreeMap::new();
    for entry in &inputs.terms {
        stated.entry(entry.tx).or_insert(&entry.terms);
    }
    for &(tx, deadline) in &inputs.transactions {
        if let Some(terms) = stated.get(&tx) {
            family.set_member(
                tx,
                Some(MemberRow::pending(
                    tx,
                    deadline,
                    inputs.committed,
                    inputs.height,
                    terms,
                )),
            );
        }
    }
    family.name(inputs);

    let fated: Vec<TxHash> = inputs
        .manifest
        .iter()
        .filter_map(|line| match line {
            TickLine::Fate { tx, .. } => Some(*tx),
            _ => None,
        })
        .collect();
    family.fate(&fated);

    let mut writes = SettledEntries::new();
    family.into_writes(&mut writes);
    writes
}

/// What the terminal's fates burn: one unjudged debit of each fated
/// member's charge on its vault, wherever the vault lies, beside the
/// deletion of the fee hold the charge ends.
///
/// A store folds only the writes under its own prefix, since an abort's
/// floor is settled by the shard holding the vault and by no other; the
/// fold reads nothing but the carried lines, so a replica that cannot
/// route the transaction burns what one that can does.
#[must_use]
pub fn fate_writes(manifest: &TickManifest) -> StateWrites {
    let resource = protocol_resource(&ProtocolHasher);
    let mut writes = StateWrites::default();
    for line in manifest.iter() {
        let TickLine::Fate { tx, charge } = line else {
            continue;
        };
        let mut fate = StateWrites::default();
        fate.movements
            .insert(charge.vault, Movement::unjudged(resource, charge.amount));
        fate.cells
            .insert(fee_hold_key(&ProtocolHasher, charge.vault, *tx), None);
        fold_state_writes(&mut writes, &fate);
    }
    writes
}

/// The first transaction of `transactions` whose member key is taken:
/// by a row standing in `state`, or by an earlier transaction of the
/// same block.
///
/// Two hashes sharing their first 128 bits would share one row, and the
/// second would overwrite the first's standing. A verifier refuses the
/// block and a proposer keeps the first of each colliding set, beside
/// the committed cell's own rule.
#[must_use]
pub fn colliding_member_row(
    shard: ShardId,
    transactions: impl IntoIterator<Item = TxHash>,
    state: &(impl Substates + ?Sized),
) -> Option<TxHash> {
    let mut named = BTreeSet::new();
    transactions
        .into_iter()
        .find(|&tx| member_taken(shard, tx, &mut named, state))
}

/// Drop from `transactions` every one [`colliding_member_row`] would
/// refuse, keeping the first of each set sharing a key. What a proposer
/// builds from; a dropped transaction stays pooled.
pub fn without_colliding_member_rows<const N: usize>(
    shard: ShardId,
    transactions: &mut Capped<Vec<Arc<Verified<Transaction>>>, N>,
    state: &(impl Substates + ?Sized),
) {
    let mut named = BTreeSet::new();
    transactions.retain(|tx| !member_taken(shard, tx.hash(), &mut named, state));
}

/// Whether `tx`'s member key is taken in `state` or already in `named`.
fn member_taken(
    shard: ShardId,
    tx: TxHash,
    named: &mut BTreeSet<u128>,
    state: &(impl Substates + ?Sized),
) -> bool {
    !named.insert(member_order(tx))
        || read_at::<MemberRow>(state, member_entry(shard, tx)).is_some()
}

/// The family as `state` holds it for `shard`: what a seat loads, and
/// what a coordinator then advances by the same fold every commit runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIndex {
    shard: ShardId,
    /// Every member row, by transaction.
    pub members: BTreeMap<TxHash, MemberRow>,
    /// Every tick row, by height.
    pub ticks: BTreeMap<BlockHeight, TickRow>,
}

impl MemberIndex {
    /// No rows at all, for `shard`.
    #[must_use]
    pub const fn empty(shard: ShardId) -> Self {
        Self {
            shard,
            members: BTreeMap::new(),
            ticks: BTreeMap::new(),
        }
    }

    /// The height of the oldest block that committed a member still held:
    /// where a replay of what this shard owes begins.
    #[must_use]
    pub fn lowest_committed(&self) -> Option<BlockHeight> {
        self.members.values().map(|row| row.height).min()
    }

    /// Both collections, one range read each.
    #[must_use]
    pub fn load(state: &(impl Substates + ?Sized), shard: ShardId) -> Self {
        let members = read_all(state, shard, MEMBERS)
            .into_iter()
            .filter_map(|(_, bytes)| from_slice::<MemberRow>(&bytes).ok())
            .map(|row| (row.tx, row))
            .collect();
        let ticks = read_all(state, shard, TICKS)
            .into_iter()
            .filter_map(|(order, bytes)| {
                let height = BlockHeight::new(u64::try_from(order).ok()?);
                Some((height, from_slice::<TickRow>(&bytes).ok()?))
            })
            .collect();
        Self {
            shard,
            members,
            ticks,
        }
    }

    /// The shard whose family this is.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.shard
    }

    /// Fold one block's content in, as [`member_writes`] folds it into
    /// state.
    ///
    /// # Panics
    ///
    /// If a written row fails to decode, which a row this fold encoded
    /// cannot.
    pub fn advance(&mut self, inputs: &MemberInputs) {
        let writes = member_writes(&*self, inputs);
        let (_, members) = collection_of(self.shard, MEMBERS);
        let (_, ticks) = collection_of(self.shard, TICKS);
        for (key, change) in writes {
            if key.collection == members {
                let Some(bytes) = change else {
                    self.members.retain(|tx, _| member_order(*tx) != key.order);
                    continue;
                };
                let row: MemberRow = from_slice(&bytes).expect("the fold encodes rows it decodes");
                self.members.insert(row.tx, row);
            } else if key.collection == ticks {
                let height = BlockHeight::new(
                    u64::try_from(key.order).expect("tick rows are keyed by height"),
                );
                match change {
                    Some(bytes) => {
                        let row: TickRow =
                            from_slice(&bytes).expect("the fold encodes rows it decodes");
                        self.ticks.insert(height, row);
                    }
                    None => {
                        self.ticks.remove(&height);
                    }
                }
            }
        }
    }

    /// The heights whose determined half the chain still owes.
    #[must_use]
    pub fn owed_determined(&self) -> BTreeSet<BlockHeight> {
        self.ticks
            .iter()
            .filter(|(_, tick)| tick.determined_unsettled)
            .map(|(height, _)| *height)
            .collect()
    }
}

/// The index read as the state its own collections sit in; every other
/// collection, a predecessor's included, reads empty.
impl Substates for MemberIndex {
    fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
        None
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        let (own, members) = collection_of(self.shard, MEMBERS);
        let (_, ticks) = collection_of(self.shard, TICKS);
        if owner != own {
            return Vec::new();
        }
        let mut entries: Vec<(u128, Vec<u8>)> = if collection == members {
            self.members
                .iter()
                .map(|(tx, row)| (member_order(*tx), row))
                .filter(|(order, _)| (lo..=hi).contains(order))
                .map(|(order, row)| (order, to_vec(row).expect("a member row encodes")))
                .collect()
        } else if collection == ticks {
            self.ticks
                .iter()
                .map(|(height, row)| (u128::from(height.inner()), row))
                .filter(|(order, _)| (lo..=hi).contains(order))
                .map(|(order, row)| (order, to_vec(row).expect("a tick row encodes")))
                .collect()
        } else {
            Vec::new()
        };
        entries.sort_unstable_by_key(|(order, _)| *order);
        entries.truncate(limit);
        entries
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{
        StubTree, stub_abort_charge, stub_stated_terms, test_transaction,
    };
    use hyperscale_types::{
        Declared, Derivation, DerivationError, Derived, Hash, TransactionEnvelope,
    };

    use super::*;

    /// A store of entries alone, for the fold to read and write.
    #[derive(Default)]
    struct Entries(BTreeMap<EntryKey, Vec<u8>>);

    impl Entries {
        fn apply(&mut self, writes: &SettledEntries) {
            for (key, change) in writes {
                match change {
                    Some(bytes) => {
                        self.0.insert(*key, bytes.clone());
                    }
                    None => {
                        self.0.remove(key);
                    }
                }
            }
        }

        fn fold(&mut self, inputs: &MemberInputs) {
            let writes = member_writes(&*self, inputs);
            self.apply(&writes);
        }
    }

    impl Substates for Entries {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.0
                .iter()
                .filter(|(key, _)| {
                    key.owner == owner
                        && key.collection == collection
                        && (lo..=hi).contains(&key.order)
                })
                .take(limit)
                .map(|(key, bytes)| (key.order, bytes.clone()))
                .collect()
        }
    }

    const LOCAL: ShardId = ShardId::leaf(1, 0);

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    /// A block committing `txs`, stating stub terms for each.
    fn committing(height: u64, txs: &[u8]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            committed: WeightedTimestamp::from_millis(height * 1_000),
            transactions: txs
                .iter()
                .map(|&seed| {
                    (
                        tx(seed),
                        Deadline::of(WeightedTimestamp::from_millis(90_000)),
                    )
                })
                .collect(),
            terms: txs
                .iter()
                .map(|&seed| stub_stated_terms(tx(seed), seed))
                .collect(),
            ..MemberInputs::still(LOCAL)
        }
    }

    /// `block` as it is carried: stating no terms for a transaction a
    /// line of it runs.
    fn carried(block: &MemberInputs) -> MemberInputs {
        let run: BTreeSet<TxHash> = block
            .manifest
            .iter()
            .filter_map(|line| match line {
                TickLine::Member { tx, joins, .. } if joins.dispatched() => Some(*tx),
                _ => None,
            })
            .collect();
        MemberInputs {
            terms: block
                .terms
                .iter()
                .filter(|entry| !run.contains(&entry.tx))
                .cloned()
                .collect(),
            ..block.clone()
        }
    }

    /// `seed`'s member line on `joins`, restating what its stub terms
    /// state.
    fn joining(seed: u8, joins: Joins) -> TickLine {
        let terms = stub_stated_terms(tx(seed), seed).terms;
        TickLine::Member {
            tx: tx(seed),
            joins,
            settlement: terms.settlement,
            holds: if joins.dispatched() {
                terms.declared
            } else {
                Capped::empty()
            },
            reach: terms.reach,
            awaits: terms.awaits,
            charge: terms.charge,
            share: terms.share,
            reserves: terms.reserves,
        }
    }

    fn naming(height: u64, lines: Vec<TickLine>) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            manifest: Arc::new(Capped::new(lines).expect("a list written out in a test")),
            ..MemberInputs::still(LOCAL)
        }
    }

    fn member(seed: u8, settlement: Settlement) -> TickLine {
        TickLine::Member {
            tx: tx(seed),
            joins: Joins::Executes,
            settlement,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: stub_abort_charge(seed),
            share: 0,
            reserves: Capped::empty(),
        }
    }

    fn settling(height: u64, tick: u64, half: TickHalf, txs: &[u8]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            settled: vec![SettledHalf {
                tick: TickId::new(LOCAL, BlockHeight::new(tick)),
                half,
                members: txs.iter().map(|&seed| tx(seed)).collect(),
            }],
            ..MemberInputs::still(LOCAL)
        }
    }

    fn state_of(store: &Entries, seed: u8) -> Option<RowState> {
        MemberIndex::load(store, LOCAL)
            .members
            .get(&tx(seed))
            .map(|row| row.state)
    }

    /// A committed transaction stands `Pending` until a line names it,
    /// and in flight in the naming block's tick until its half settles;
    /// a settled member has no row, and a tick owing neither half has
    /// none either.
    #[test]
    fn a_member_is_pending_then_in_flight_then_gone() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2]));
        assert_eq!(state_of(&store, 1), Some(RowState::Pending));
        let pending = &MemberIndex::load(&store, LOCAL).members[&tx(1)];
        assert_eq!(
            pending.committed,
            WeightedTimestamp::from_millis(1_000),
            "the row carries its committing block's clock",
        );
        let stated = stub_stated_terms(tx(1), 1).terms;
        assert_eq!(
            (&pending.reach, &pending.awaits, pending.charge),
            (&stated.reach, &stated.awaits, stated.charge),
            "the row carries the terms its committing block stated",
        );
        assert_eq!(
            (pending.share, &pending.reserves, &pending.crossings),
            (stated.share, &stated.reserves, &stated.crossings),
        );
        assert_eq!(
            pending.waiting,
            Some(Waiting {
                leg: stated.leg,
                settlement: stated.settlement,
                declared: stated.declared,
                engages: stated.engages,
                waits: stated.waits,
            }),
        );

        store.fold(&naming(
            2,
            vec![member(1, Settlement::Alone), member(2, Settlement::Shared)],
        ));
        assert!(matches!(
            state_of(&store, 1),
            Some(RowState::InFlight { tick, settlement: Settlement::Alone, .. })
                if tick == BlockHeight::new(2)
        ));
        let index = MemberIndex::load(&store, LOCAL);
        assert_eq!(
            index.members[&tx(1)].charge,
            stub_abort_charge(1),
            "the row keeps the charge its line named",
        );
        let tick = &index.ticks[&BlockHeight::new(2)];
        assert!(tick.determined_unsettled && tick.legs_unsettled);
        assert_eq!(
            index.owed_determined(),
            BTreeSet::from([BlockHeight::new(2)])
        );

        store.fold(&settling(3, 2, TickHalf::Determined, &[1]));
        assert_eq!(state_of(&store, 1), None, "a settled member has no row");
        let index = MemberIndex::load(&store, LOCAL);
        assert!(index.owed_determined().is_empty());
        assert!(index.ticks[&BlockHeight::new(2)].legs_unsettled);

        store.fold(&settling(4, 2, TickHalf::Legs, &[2]));
        let index = MemberIndex::load(&store, LOCAL);
        assert!(
            index.members.is_empty() && index.ticks.is_empty(),
            "{index:?}"
        );
    }

    fn seated_in(store: &Entries, seed: u8) -> bool {
        let (owner, collection) = collection_of(LOCAL, SEATS);
        store.0.contains_key(&EntryKey {
            owner,
            collection,
            order: member_order(tx(seed)),
        })
    }

    /// A seat stands exactly while a member a counterpart settles against
    /// is in flight: named `Shared`, kept by a discard that does not
    /// abandon it, and gone once it is released, settled or fated.
    #[test]
    fn a_seat_stands_while_a_shared_member_is_in_flight() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3, 4, 5]));
        assert!((1..=5).all(|seed| !seated_in(&store, seed)), "pending");

        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Alone),
                member(2, Settlement::Shared),
                member(3, Settlement::Awaited),
                member(4, Settlement::Shared),
            ],
        ));
        assert_eq!(
            (1..=4)
                .map(|seed| seated_in(&store, seed))
                .collect::<Vec<_>>(),
            vec![false, true, false, true],
            "only a shared member holds a seat",
        );

        store.fold(&naming(
            3,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(2)),
                cause: DiscardCause::Abandoned(tx(4)),
            }],
        ));
        assert!(seated_in(&store, 2), "a discard keeps a shared member");
        assert!(!seated_in(&store, 4), "the member it abandons is released");

        store.fold(&settling(4, 2, TickHalf::Legs, &[2]));
        assert!(!seated_in(&store, 2), "a settled member has no seat");

        store.fold(&naming(5, vec![member(5, Settlement::Shared)]));
        assert!(seated_in(&store, 5));
        store.fold(&naming(
            6,
            vec![TickLine::Fate {
                tx: tx(5),
                charge: stub_abort_charge(5),
            }],
        ));
        assert!(!seated_in(&store, 5), "a fated member has no seat");

        store.fold(&committing(7, &[6, 7]));
        store.fold(&naming(
            8,
            vec![member(6, Settlement::Shared), member(7, Settlement::Shared)],
        ));
        store.fold(&naming(
            9,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(8)),
                cause: DiscardCause::Unanswerable(tx(6)),
            }],
        ));
        assert!(
            !seated_in(&store, 6),
            "a member nobody can answer for is dropped, seat and all",
        );
        assert!(seated_in(&store, 7), "and its shared sibling is kept");
        store.fold(&naming(
            10,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(8)),
                cause: DiscardCause::Recovery,
            }],
        ));
        assert!(
            !seated_in(&store, 7),
            "a recovery releases the whole tick, seats included",
        );
    }

    /// A discard releases what shares no verdict with a counterpart and
    /// keeps what does, unless it abandons that member; a recovery
    /// discard releases the whole tick.
    #[test]
    fn a_discard_releases_what_shares_no_verdict() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3, 4]));
        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Alone),
                member(2, Settlement::Shared),
                member(3, Settlement::Awaited),
                member(4, Settlement::Shared),
            ],
        ));
        store.fold(&naming(
            3,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(2)),
                cause: DiscardCause::Abandoned(tx(4)),
            }],
        ));
        let released = |settlement| Some(RowState::Released { settlement });
        assert_eq!(state_of(&store, 1), released(Settlement::Alone));
        assert!(matches!(
            state_of(&store, 2),
            Some(RowState::InFlight { .. })
        ));
        assert_eq!(state_of(&store, 3), released(Settlement::Awaited));
        assert_eq!(
            state_of(&store, 4),
            released(Settlement::Shared),
            "the abandoned member goes whatever it shares",
        );
        let tick = &MemberIndex::load(&store, LOCAL).ticks[&BlockHeight::new(2)];
        assert_eq!(tick.members[..], [tx(2)]);
        assert!(!tick.determined_unsettled && tick.legs_unsettled);

        store.fold(&naming(
            4,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(2)),
                cause: DiscardCause::Recovery,
            }],
        ));
        assert_eq!(state_of(&store, 2), released(Settlement::Shared));
        assert!(MemberIndex::load(&store, LOCAL).ticks.is_empty());
    }

    /// An `Unanswerable` discard deletes the member it names, which
    /// nothing will ever abort, and releases the rest as any discard does.
    #[test]
    fn an_unanswerable_discard_deletes_its_member() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3]));
        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Shared),
                member(2, Settlement::Shared),
                member(3, Settlement::Awaited),
            ],
        ));
        store.fold(&naming(
            3,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(2)),
                cause: DiscardCause::Unanswerable(tx(1)),
            }],
        ));
        assert_eq!(state_of(&store, 1), None, "deleted, never released");
        assert!(matches!(
            state_of(&store, 2),
            Some(RowState::InFlight { .. })
        ));
        assert_eq!(
            state_of(&store, 3),
            Some(RowState::Released {
                settlement: Settlement::Awaited
            }),
        );
        let tick = &MemberIndex::load(&store, LOCAL).ticks[&BlockHeight::new(2)];
        assert_eq!(tick.members[..], [tx(2)]);
    }

    /// A record covers the row it names, and nothing else.
    #[test]
    fn a_record_covers_the_row_it_names() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2]));
        store.fold(&MemberInputs {
            covered: vec![tx(1), tx(9)],
            ..MemberInputs::still(LOCAL)
        });
        let index = MemberIndex::load(&store, LOCAL);
        assert!(index.members[&tx(1)].covered);
        assert!(!index.members[&tx(2)].covered);
        assert!(!index.members.contains_key(&tx(9)));
    }

    /// A successor never reads its predecessors' rows as its own, even
    /// where it shares their owner address, and its fold writes nothing
    /// under theirs: the terminal already removed them.
    #[test]
    fn a_successor_never_reads_its_predecessors_rows() {
        let parent = ShardId::ROOT;
        let (left, _) = parent.children();
        let mut store = Entries::default();
        store.fold(&MemberInputs {
            transactions: vec![(tx(1), Deadline::of(WeightedTimestamp::ZERO))],
            terms: vec![stub_stated_terms(tx(1), 1)],
            ..MemberInputs::still(parent)
        });
        assert_eq!(MemberIndex::load(&store, parent).members.len(), 1);
        assert!(
            MemberIndex::load(&store, left).members.is_empty(),
            "the left child shares its parent's owner and still reads none of its rows",
        );
        assert!(member_writes(&store, &MemberInputs::still(left)).is_empty());
    }

    /// The terminal's fates delete every row they name and every tick row
    /// they empty, and burn each member's charge once, composing two
    /// charges on one vault, each deleting its own fee hold.
    #[test]
    fn terminal_fates_remove_every_row_and_debit_once() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3]));
        store.fold(&naming(2, vec![member(1, Settlement::Alone)]));
        let fated = |seed: u8, charge| TickLine::Fate {
            tx: tx(seed),
            charge,
        };
        let shared = stub_abort_charge(7);
        let manifest: TickManifest = Capped::new(vec![
            fated(1, stub_abort_charge(1)),
            fated(2, shared),
            fated(3, shared),
        ])
        .expect("a list written out in a test");
        store.fold(&naming(3, manifest.to_vec()));
        let index = MemberIndex::load(&store, LOCAL);
        assert!(
            index.members.is_empty() && index.ticks.is_empty(),
            "{index:?}"
        );

        let debits = fate_writes(&manifest);
        assert!(debits.entries.is_empty());
        assert_eq!(debits.movements.len(), 2);
        let released = |seed: u8, charge: AbortCharge| {
            (fee_hold_key(&ProtocolHasher, charge.vault, tx(seed)), None)
        };
        assert_eq!(
            debits.cells,
            [
                released(1, stub_abort_charge(1)),
                released(2, shared),
                released(3, shared),
            ]
            .into_iter()
            .collect(),
            "each fate deletes its own hold beside its debit",
        );
        let debit = |charge: AbortCharge| debits.movements[&charge.vault];
        assert_eq!(
            debit(stub_abort_charge(1)),
            Movement::unjudged(protocol_resource(&ProtocolHasher), 13),
        );
        assert_eq!(
            debit(shared),
            Movement::unjudged(protocol_resource(&ProtocolHasher), 26),
            "two fates on one vault burn both charges",
        );
    }

    /// A member key is taken by a standing row, or by an earlier
    /// transaction of the same block.
    #[test]
    fn a_member_key_is_taken_by_a_standing_row_or_the_block() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1]));
        let mut twin = *tx(2).as_bytes();
        twin[31] ^= 1;
        let twin = TxHash::from(Hash::from_hash_bytes(&twin));
        assert_eq!(member_order(twin), member_order(tx(2)));

        assert_eq!(colliding_member_row(LOCAL, [tx(1)], &store), Some(tx(1)));
        assert_eq!(
            colliding_member_row(LOCAL, [tx(2), twin], &store),
            Some(twin)
        );
        assert_eq!(colliding_member_row(LOCAL, [tx(2), tx(3)], &store), None);
    }

    /// A cache loaded from state and advanced by the same fold stays
    /// equal to state through every kind of step the fold takes.
    #[test]
    fn a_cache_advances_as_state_does() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3, 4]));
        let mut cache = MemberIndex::load(&store, LOCAL);
        let steps = [
            naming(
                2,
                vec![
                    member(1, Settlement::Alone),
                    member(2, Settlement::Shared),
                    member(3, Settlement::Awaited),
                ],
            ),
            MemberInputs {
                covered: vec![tx(4)],
                ..committing(3, &[5])
            },
            settling(4, 2, TickHalf::Determined, &[1]),
            naming(
                5,
                vec![TickLine::Discard {
                    tick: TickId::new(LOCAL, BlockHeight::new(2)),
                    cause: DiscardCause::Unanswerable(tx(3)),
                }],
            ),
            settling(6, 2, TickHalf::Legs, &[2]),
        ];
        for step in &steps {
            store.fold(step);
            cache.advance(step);
            assert_eq!(cache, MemberIndex::load(&store, LOCAL), "after {step:?}");
        }
        assert_eq!(cache.members[&tx(5)].height, BlockHeight::new(3));
    }

    /// Lines are named over the rows a block's content leaves, every
    /// transaction of it on the terms derived for it, and the block is
    /// then folded as carried over those same rows. That second fold
    /// leaves what one fold of the carried block over its parent's rows
    /// leaves, whatever the block carries: a count read after it is the
    /// count the commit leaves.
    #[test]
    fn a_block_folded_again_with_its_lines_leaves_what_one_fold_does() {
        let discard = |tick: u64, cause| TickLine::Discard {
            tick: TickId::new(LOCAL, BlockHeight::new(tick)),
            cause,
        };
        let lines = |lines: Vec<TickLine>| {
            Arc::new(Capped::new(lines).expect("a list written out in a test"))
        };
        let steps = [
            committing(1, &[1, 2, 3, 4, 5]),
            naming(
                2,
                vec![
                    member(1, Settlement::Alone),
                    member(2, Settlement::Shared),
                    member(3, Settlement::Awaited),
                    member(4, Settlement::Shared),
                ],
            ),
            // Settles a member, covers one in flight and one it commits,
            // commits two, names one of them and a standing one, and
            // drops a member nobody can answer for.
            MemberInputs {
                settled: settling(3, 2, TickHalf::Determined, &[1]).settled,
                covered: vec![tx(2), tx(6)],
                manifest: lines(vec![
                    member(5, Settlement::Alone),
                    member(6, Settlement::Shared),
                    discard(2, DiscardCause::Unanswerable(tx(4))),
                ]),
                ..committing(3, &[6, 7])
            },
            // Settles a row the same block commits again, and lets a
            // tick go whole.
            MemberInputs {
                settled: settling(4, 3, TickHalf::Determined, &[5]).settled,
                manifest: lines(vec![discard(2, DiscardCause::Recovery)]),
                ..committing(4, &[5])
            },
            naming(
                5,
                vec![
                    TickLine::Fate {
                        tx: tx(2),
                        charge: stub_abort_charge(2),
                    },
                    TickLine::Fate {
                        tx: tx(6),
                        charge: stub_abort_charge(6),
                    },
                ],
            ),
        ];
        let mut once = MemberIndex::empty(LOCAL);
        for step in &steps {
            let mut twice = once.clone();
            twice.advance(&MemberInputs {
                manifest: Arc::new(Capped::empty()),
                ..step.clone()
            });
            twice.advance(&carried(step));
            once.advance(&carried(step));
            assert_eq!(twice, once, "after {step:?}");
        }

        assert_eq!(
            once.members.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([tx(3), tx(5), tx(7)]),
        );
    }

    fn row_of(store: &Entries, seed: u8) -> Option<MemberRow> {
        MemberIndex::load(store, LOCAL).members.remove(&tx(seed))
    }

    /// A transaction a block names to run as it commits it has one row
    /// whichever way the fold reaches it. A proposer and a voter fold
    /// every transaction on the terms they derive and then the block as
    /// carried, so there the line names a `Pending` row an entry wrote; a
    /// replica committing the block folds what it carries, which states
    /// no entry for the transaction, so there the line writes the row
    /// alone. Every entry of the family is the same bytes on both roads,
    /// and so the root over them is one.
    #[test]
    fn a_member_named_in_its_own_block_folds_to_one_root_either_way() {
        let mut parent = Entries::default();
        parent.fold(&committing(1, &[1, 2]));
        parent.fold(&naming(2, vec![joining(1, Joins::Executes)]));
        // Runs two of its own on either dispatched terms, one of them
        // under a record naming it; aborts a third; leaves a fourth
        // waiting; and names a standing row beside them.
        let block = MemberInputs {
            covered: vec![tx(3), tx(6)],
            manifest: Arc::new(Capped::from_array([
                joining(3, Joins::Executes),
                joining(4, Joins::ExecutesAborted),
                joining(5, Joins::Aborted),
                joining(2, Joins::Executes),
            ])),
            ..committing(3, &[3, 4, 5, 6])
        };
        let stated = carried(&block);
        assert_eq!(
            stated.terms.iter().map(|e| e.tx).collect::<Vec<_>>(),
            [tx(5), tx(6)]
        );

        let mut derived = Entries(parent.0.clone());
        derived.fold(&MemberInputs {
            manifest: Arc::new(Capped::empty()),
            ..block
        });
        derived.fold(&stated);
        let mut committed = Entries(parent.0.clone());
        committed.fold(&stated);

        assert_eq!(derived.0, committed.0);
        assert_eq!(MemberIndex::load(&committed, LOCAL).members.len(), 6);
        for seed in [3, 4] {
            let row = row_of(&committed, seed).expect("the line wrote its row");
            assert!(matches!(row.state, RowState::InFlight { tick, .. } if tick.inner() == 3));
            assert_eq!((row.waiting, row.crossings.len()), (None, 0));
            assert!(!row.covered, "a record covers standing rows only");
        }
    }

    /// The fold is total over any section: an entry naming no
    /// transaction of the block and a second entry for one hash are
    /// never read, so a block carrying them writes what the block without
    /// them writes, and a transaction with neither an entry nor a line
    /// running it gets no row.
    #[test]
    fn a_fold_passes_over_an_entry_no_transaction_matches() {
        let block = committing(1, &[1, 2]);
        let mut plain = Entries::default();
        plain.fold(&block);

        let mut padded = block.clone();
        padded.terms.insert(0, stub_stated_terms(tx(9), 9));
        padded.terms.push(stub_stated_terms(tx(1), 7));
        let mut store = Entries::default();
        store.fold(&padded);
        assert_eq!(store.0, plain.0);
        assert_eq!(
            row_of(&store, 1).expect("stated").charge,
            stub_abort_charge(1),
            "the first entry naming it is the one read",
        );
        assert_eq!(row_of(&store, 9), None);

        let unstated = MemberInputs {
            terms: vec![stub_stated_terms(tx(1), 1)],
            manifest: Arc::new(Capped::from_array([joining(2, Joins::Aborted)])),
            ..block
        };
        let mut store = Entries::default();
        store.fold(&unstated);
        assert_eq!(
            MemberIndex::load(&store, LOCAL)
                .members
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [tx(1)],
            "neither stated nor run, so no row, whatever names it",
        );
    }

    /// A block that runs a transaction as it commits it states no entry
    /// for it, and the row its line writes carries what the line states:
    /// the share, the charge, the reach and the reservations, under the
    /// block's own clock and the transaction's own deadline.
    #[test]
    fn a_row_named_in_its_committing_block_carries_its_share() {
        let block = carried(&MemberInputs {
            manifest: Arc::new(Capped::from_array([joining(1, Joins::Executes)])),
            ..committing(4, &[1])
        });
        assert!(block.terms.is_empty());
        let mut store = Entries::default();
        store.fold(&block);

        let terms = stub_stated_terms(tx(1), 1).terms;
        let row = row_of(&store, 1).expect("the line wrote its row");
        assert_eq!(row.share, 7);
        assert_eq!(
            (row.share, row.charge, &row.reserves),
            (terms.share, terms.charge, &terms.reserves),
        );
        assert_eq!(
            (&row.reach, &row.awaits, &row.holds),
            (&terms.reach, &terms.awaits, &terms.declared)
        );
        assert_eq!(
            (row.deadline, row.committed, row.height),
            (block.transactions[0].1, block.committed, block.height),
        );
        assert_eq!((row.waiting, row.crossings.len()), (None, 0));
    }

    /// A line naming a `Pending` row to run ends what the row waited on:
    /// the terms it was judged by go, its crossings are consumed, and
    /// what it declared stands on as the holds the line names. Its
    /// reservations stand.
    #[test]
    fn a_pending_row_drops_what_it_waited_on_when_named() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1]));
        let pending = row_of(&store, 1).expect("committed");
        assert!(pending.waiting.is_some() && !pending.crossings.is_empty());

        store.fold(&naming(2, vec![joining(1, Joins::Executes)]));
        let named = row_of(&store, 1).expect("in flight");
        let terms = stub_stated_terms(tx(1), 1).terms;
        assert_eq!((named.waiting, named.crossings.len()), (None, 0));
        assert_eq!(named.holds, terms.declared);
        assert_eq!(named.reserves, pending.reserves);
        assert_eq!(
            (named.deadline, named.committed, named.height),
            (pending.deadline, pending.committed, pending.height),
            "a row keeps where it was committed",
        );
    }

    /// A transaction a block both commits and aborts has its entry and
    /// its line: the row is written on the stated terms and the abort
    /// applies to it as to any standing row, so the crossings it never
    /// consumed stay on it.
    #[test]
    fn a_transaction_aborted_in_its_committing_block_keeps_its_crossings() {
        let block = carried(&MemberInputs {
            manifest: Arc::new(Capped::from_array([joining(1, Joins::Aborted)])),
            ..committing(1, &[1])
        });
        assert_eq!(block.terms.len(), 1, "an abort runs nothing");
        let mut store = Entries::default();
        store.fold(&block);

        let terms = stub_stated_terms(tx(1), 1).terms;
        let row = row_of(&store, 1).expect("stated, then named");
        assert!(matches!(
            row.state,
            RowState::InFlight {
                joins: Joins::Aborted,
                ..
            }
        ));
        assert_eq!(row.crossings, terms.crossings);
        assert_eq!(row.waiting, None);
        assert_eq!(row.reserves, terms.reserves);

        // And one aborted by a later block keeps them alike.
        let mut later = Entries::default();
        later.fold(&committing(1, &[1]));
        later.fold(&naming(2, vec![joining(1, Joins::Aborted)]));
        assert_eq!(row_of(&later, 1).expect("named").crossings, terms.crossings);
    }

    /// A manifest and a tick row's members share one cap, so a manifest
    /// of member lines at its cap names a tick row holding every one.
    #[test]
    fn a_manifest_of_member_lines_at_its_cap_names_a_tick_row() {
        let hash = |at: usize| TxHash::from(Hash::from_bytes(&at.to_le_bytes()));
        let deadline = Deadline::of(WeightedTimestamp::from_millis(90_000));
        let lines: Vec<TickLine> = (0..MAX_TICK_LINES_PER_BLOCK)
            .map(|at| TickLine::Member {
                tx: hash(at),
                joins: Joins::Executes,
                settlement: Settlement::Alone,
                holds: Capped::empty(),
                reach: Capped::empty(),
                awaits: Capped::empty(),
                charge: stub_abort_charge(0),
                share: 0,
                reserves: Capped::empty(),
            })
            .collect();
        let block = MemberInputs {
            height: BlockHeight::new(1),
            transactions: (0..MAX_TICK_LINES_PER_BLOCK)
                .map(|at| (hash(at), deadline))
                .collect(),
            manifest: Arc::new(Capped::new(lines).expect("a manifest at its cap")),
            ..MemberInputs::still(LOCAL)
        };
        let mut rows = MemberIndex::empty(LOCAL);
        rows.advance(&block);
        assert_eq!(rows.members.len(), MAX_TICK_LINES_PER_BLOCK);
        assert_eq!(
            rows.ticks[&BlockHeight::new(1)].members.len(),
            MAX_TICK_LINES_PER_BLOCK,
        );
    }

    /// A derivation that refuses every envelope while still reading
    /// what the envelope declares of itself.
    struct Refusing;

    impl Derivation for Refusing {
        fn derive(&self, _: &TransactionEnvelope) -> Result<Derived, DerivationError> {
            Err(DerivationError::Refused("stub refusal".into()))
        }

        fn declared(&self, vm: &TransactionEnvelope) -> Result<Declared, DerivationError> {
            let stub = StubTree::decode(vm)?;
            Ok(Declared {
                effective_window: stub.window(),
                network: stub.network,
                terms: stub.terms,
            })
        }
    }

    /// A replica that cannot route a transaction reads the same inputs
    /// off its block as one that can, the stated terms included, and so
    /// folds the same row.
    #[test]
    fn a_replica_that_cannot_route_folds_the_row_its_peers_do() {
        let routed = test_transaction(7);
        let unrouted = Transaction::new(routed.body().clone());
        unrouted
            .try_derived(&Refusing)
            .expect_err("the derivation refuses it");
        assert!(!unrouted.is_routed());

        let inputs = |tx: &Transaction| {
            MemberInputs::deriving(
                LOCAL,
                BlockHeight::new(1),
                WeightedTimestamp::from_millis(1_000),
                [tx],
                &[],
                &[],
                vec![stub_stated_terms(tx.hash(), 3)],
            )
        };
        assert_eq!(inputs(&unrouted), inputs(&routed));
        let (mut here, mut there) = (Entries::default(), Entries::default());
        here.fold(&inputs(&unrouted));
        there.fold(&inputs(&routed));
        assert_eq!(here.0, there.0);
        assert_eq!(
            MemberIndex::load(&here, LOCAL).members[&routed.hash()].state,
            RowState::Pending,
        );
    }
}
