//! Tick membership as committed state: which transactions this chain has
//! committed and not resolved, and which tick holds each.
//!
//! Four ordered collections under the shard's own owner at
//! [`TICK_MEMBER_SLOT`], told apart by their material, which also names
//! the shard. Member rows are keyed by the first 128 bits of the
//! transaction hash and tick rows by height. Seats are keyed as member
//! rows are, and stand exactly while a member a counterpart settles
//! against is in flight: what a counterpart reads, by presence alone, to
//! tell a seated member from one still waiting. Reserved totals are
//! keyed by the first 128 bits of a vault's hashed key, each the sum of
//! what the rows standing reserve of that vault: what admission weighs a
//! new fee hold against, beside the holds already standing. They sit
//! with the rows and not with the vault, since only a store that folds
//! the rows can keep their sum. Naming the shard puts a
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
    AbandonmentRecord, AbortCharge, Address, Block, BlockHeight, CollectionId, Crossings, Deadline,
    DiscardCause, EntryKey, Finalization, Hash, Holds, Joins, MAX_TICK_LINES_PER_BLOCK,
    MAX_VALIDITY_RANGE, MemberTerms, Movement, Reach, Reserves, SettledEntries, Settlement,
    ShardId, ShardTrie, StateWrites, StatedTerms, SubstateKey, TickHalf, TickId, TickLine,
    TickManifest, Transaction, TxHash, TxOutcome, Verifiable, Verified, WeightedTimestamp,
    entry_leaf_key,
};
use hyperscale_vm_effects::{
    ProtocolHasher, TICK_MEMBER_SLOT, collection_id, fee_hold_key, protocol_resource,
};

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
    /// Let go and not yet ended: by a discard of the tick that held it,
    /// or by the reclaim of what it issued while no tick had named it.
    /// No line names it to run.
    Released {
        /// Which half its terms said settles it: its line's, or its
        /// committing block's where no line ever named it.
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
    pub crossings: Crossings,
    /// What it is judged on until a line names it: `Some` exactly while
    /// it stands `Pending`.
    pub waiting: Option<Waiting>,
    /// Whether a committed abandonment record names it.
    pub covered: bool,
    /// Whether a line ever named it to run, so a certificate of this
    /// shard's for it may be out. Stands through every release and
    /// abort that follows.
    pub executed: bool,
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
            executed: false,
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
    /// The members standing in it outside the determined half: the rows
    /// in flight in this tick that a legs half settles. Its legs half is
    /// owed while there is one.
    pub awaiting: u32,
}

impl TickRow {
    const fn owes(&self) -> bool {
        self.determined_unsettled || self.awaiting > 0
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
    /// The members it names whose rows it deletes: the ones a committing
    /// block reserved a place for.
    pub deleted: Vec<TxHash>,
    /// The members it names that hold no place of their own, which are
    /// reclaims: each takes back the records of a transaction whose row,
    /// where one still waits, the finalization releases and does not
    /// delete.
    pub reclaimed: Vec<TxHash>,
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
                    // Off the outcomes the finalization settles in its
                    // local certificate, which admission requires of
                    // every committed finalization. Read without relying
                    // on it, since a root is checked before a block's
                    // sections are.
                    let (deleted, reclaimed): (Vec<&TxOutcome>, Vec<&TxOutcome>) = fw
                        .settled_outcomes()
                        .partition(|outcome| outcome.reserved());
                    let names = |outcomes: Vec<&TxOutcome>| {
                        outcomes.into_iter().map(TxOutcome::tx_hash).collect()
                    };
                    SettledHalf {
                        tick: *fw.tick_id(),
                        half: fw.half(),
                        deleted: names(deleted),
                        reclaimed: names(reclaimed),
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

/// The tick `row` stands in awaiting its legs half, if it does: in
/// flight there, on terms a legs half settles.
fn awaited_in(row: Option<&MemberRow>) -> Option<BlockHeight> {
    match row?.state {
        RowState::InFlight {
            tick, settlement, ..
        } if settlement.half() == TickHalf::Legs => Some(tick),
        RowState::InFlight { .. } | RowState::Pending | RowState::Released { .. } => None,
    }
}

/// Whether `row` stands in flight in the tick at `height`.
fn in_tick(row: &MemberRow, height: BlockHeight) -> bool {
    matches!(row.state, RowState::InFlight { tick, .. } if tick == height)
}

/// Material telling the family's collections apart.
const MEMBERS: u8 = 0;
const TICKS: u8 = 1;
const SEATS: u8 = 2;
const RESERVED: u8 = 3;

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

/// A vault's order key among the reserved totals: the first 128 bits of
/// its hashed key.
fn reserved_order(vault: SubstateKey) -> u128 {
    let mut high = [0u8; 16];
    high.copy_from_slice(&Hash::from_bytes(&vault.to_bytes()).as_bytes()[..16]);
    u128::from_be_bytes(high)
}

fn reserved_entry(shard: ShardId, order: u128) -> EntryKey {
    let (owner, collection) = collection_of(shard, RESERVED);
    EntryKey {
        owner,
        collection,
        order,
    }
}

/// What the rows standing in `shard`'s family reserve of `vault`: the
/// sum of their declared reservations on it, zero where none stands.
///
/// Two vaults sharing an order key share one total, so each reads the
/// sum of both: more than its own, which refuses a hold and never
/// admits one.
#[must_use]
pub fn reserved_total(
    state: &(impl Substates + ?Sized),
    shard: ShardId,
    vault: SubstateKey,
) -> u128 {
    read_at(state, reserved_entry(shard, reserved_order(vault))).unwrap_or(0)
}

/// What `row` reserves: nothing where no row stands.
fn reserves_of(row: Option<&MemberRow>) -> &[(SubstateKey, u128)] {
    row.map_or(&[], |row| &row.reserves[..])
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
    /// Each row read, as the state held it: what a changed row's seat
    /// and reservations are written against.
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

    /// Write the row under `tx`'s key. A row that stood there awaiting
    /// its tick's legs half, and no longer does, leaves that tick: its
    /// count falls, and a tick left owing neither half goes.
    fn set_member(&mut self, tx: TxHash, row: Option<MemberRow>) {
        let order = member_order(tx);
        if !self.members.contains_key(&order) {
            let stored = self.stored(tx);
            self.members.insert(order, stored);
        }
        let left = awaited_in(self.members[&order].as_ref());
        if left != awaited_in(row.as_ref())
            && let Some(height) = left
            && let Some(mut tick) = self.tick(height)
        {
            tick.awaiting = tick.awaiting.saturating_sub(1);
            let owes = tick.owes();
            self.set_tick(height, owes.then_some(tick));
        }
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

    /// A finalization deletes the rows of the members it settles. A
    /// determined half clears its tick's determined half; a legs half
    /// settles by member, so its tick owes it for as long as a row
    /// stands awaiting it. A tick owing neither half goes.
    ///
    /// A reclaim it names deletes nothing. Where the transaction's row
    /// still waits `Pending`, the records its member here would have
    /// answered for are taken back, so it is released on the settlement
    /// its terms state: no line names a released row to run, and its
    /// exit is the one a released row has. A row in any other state is
    /// left as it stands: its own tick or an earlier discard already
    /// decided what ends it.
    fn settle(&mut self, settled: &SettledHalf) {
        if settled.tick.shard_id() != self.shard {
            return;
        }
        for &tx in &settled.deleted {
            if self.member(tx).is_some() {
                self.set_member(tx, None);
            }
        }
        for &tx in &settled.reclaimed {
            let Some(mut row) = self.member(tx) else {
                continue;
            };
            if row.state != RowState::Pending {
                continue;
            }
            let Some(waiting) = row.waiting.take() else {
                continue;
            };
            row.state = RowState::Released {
                settlement: waiting.settlement,
            };
            self.set_member(tx, Some(row));
        }
        let height = settled.tick.block_height();
        if settled.half == TickHalf::Determined
            && let Some(mut tick) = self.tick(height)
        {
            tick.determined_unsettled = false;
            let owes = tick.owes();
            self.set_tick(height, owes.then_some(tick));
        }
    }

    /// A discard releases every member standing in the tick that shares
    /// no verdict with a counterpart, and the one it abandons whatever
    /// that shares; a recovery discard releases the whole tick. What
    /// stays is owed only its legs half, for each member kept. The
    /// member an `Unanswerable` discard names is released as an
    /// abandoned one is, and the fate its block names for it is what
    /// deletes its row.
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
        let whole = matches!(cause, DiscardCause::Recovery);
        let mut kept = Vec::new();
        for &tx in held.members.iter() {
            let Some(row) = self.member(tx).filter(|row| in_tick(row, height)) else {
                continue;
            };
            if row.state.seated() && !whole && Some(tx) != abandoned {
                if !kept.contains(&tx) {
                    kept.push(tx);
                }
            } else {
                self.release(tx);
            }
        }
        let awaiting = u32::try_from(kept.len()).expect("a tick's members are within their cap");
        let remains = (!kept.is_empty()).then(|| TickRow {
            members: Capped::new(kept).expect("a subset of a capped list"),
            determined_unsettled: false,
            awaiting,
        });
        self.set_tick(height, remains);
    }

    /// Fates delete the rows they name, and every tick row they leave
    /// listing no standing member.
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
    /// block keeps where it was committed, whether a record covers it and
    /// whether a line ever ran it, and an abort keeps the crossings it
    /// never consumed. The row's deadline is the transaction's own, read
    /// off the block that committed it and never off a line; the
    /// deadline and the answers an abort line carries are for the replica
    /// seating it.
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
                    deadline: _,
                    nevers: _,
                } => {
                    let runs = joins.dispatched();
                    let (deadline, committed, committed_at, covered, executed, crossings) =
                        if let Some(&deadline) = own.get(tx).filter(|_| runs) {
                            (
                                deadline,
                                inputs.committed,
                                height,
                                false,
                                true,
                                Capped::empty(),
                            )
                        } else if let Some(row) = self.member(*tx) {
                            let crossings = if runs { Capped::empty() } else { row.crossings };
                            (
                                row.deadline,
                                row.committed,
                                row.height,
                                row.covered,
                                runs || row.executed,
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
                        executed,
                    };
                    self.set_member(*tx, Some(row));
                    members.push(*tx);
                    if settlement.half() == TickHalf::Determined {
                        composed.determined_unsettled = true;
                    }
                }
                TickLine::Fate { .. } | TickLine::Discard { .. } => {}
            }
        }
        if !members.is_empty() {
            let awaiting = members
                .iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|&&tx| awaited_in(self.member(tx).as_ref()) == Some(height))
                .count();
            composed.awaiting =
                u32::try_from(awaiting).expect("a manifest's lines are within their cap");
            composed.members = Capped::new(members).expect("a manifest caps its lines");
            self.set_tick(height, Some(composed));
        }
    }

    /// Every changed row is written against the row the state holds
    /// under its key, read here where the fold did not: a block folded
    /// again over the rows its first fold left commits its transactions
    /// over rows already standing.
    ///
    /// A vault's reserved total moves by exactly what the rows written
    /// differ from the rows held in what they reserve of it, whichever
    /// line or certificate changed them, and is deleted at zero. What
    /// leaves is subtracted first, so no step passes the total the block
    /// leaves. A chain a quorum certifies holds at most
    /// [`MAX_UNSETTLED_TXS`] rows, each stating the sums of at most
    /// [`MAX_HOLDS_PER_MEMBER`] declared amounts of at most
    /// [`MAX_DECLARED_RESERVE`], so its totals are exact. The adds
    /// saturate only over amounts a block states past what any
    /// derivation yields, and no voter accepts that block.
    ///
    /// [`MAX_UNSETTLED_TXS`]: hyperscale_types::MAX_UNSETTLED_TXS
    /// [`MAX_HOLDS_PER_MEMBER`]: hyperscale_types::MAX_HOLDS_PER_MEMBER
    /// [`MAX_DECLARED_RESERVE`]: hyperscale_types::MAX_DECLARED_RESERVE
    fn into_writes(self, writes: &mut SettledEntries) {
        let (owner, members) = collection_of(self.shard, MEMBERS);
        let (_, seats) = collection_of(self.shard, SEATS);
        let mut moved: BTreeMap<u128, (u128, u128)> = BTreeMap::new();
        for order in self.changed_members {
            let key = EntryKey {
                owner,
                collection: members,
                order,
            };
            let row = self.members[&order].as_ref();
            writes.insert(
                key,
                row.map(|row| to_vec(row).expect("a member row encodes")),
            );
            let held: Option<MemberRow> = match self.read.get(&order) {
                Some(held) => held.clone(),
                None => read_at(self.state, key),
            };
            let (left, entered) = (reserves_of(held.as_ref()), reserves_of(row));
            if left != entered {
                for &(vault, amount) in left {
                    let sum = &mut moved.entry(reserved_order(vault)).or_default().0;
                    *sum = sum.saturating_add(amount);
                }
                for &(vault, amount) in entered {
                    let sum = &mut moved.entry(reserved_order(vault)).or_default().1;
                    *sum = sum.saturating_add(amount);
                }
            }
            let was = held.is_some_and(|row| row.state.seated());
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
        for (order, (left, entered)) in moved {
            let key = reserved_entry(self.shard, order);
            let standing: u128 = read_at(self.state, key).unwrap_or(0);
            let total = standing
                .checked_sub(left)
                .expect("a vault's reserved total covers what every standing row reserves of it")
                .saturating_add(entered);
            if total != standing {
                writes.insert(
                    key,
                    (total != 0).then(|| to_vec(&total).expect("an amount encodes")),
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
/// In a fixed order: the finalizations delete the rows of the members
/// they settle and release the waiting row of each transaction a reclaim
/// names, a determined half clearing its tick's determined half and a
/// legs half leaving its tick owed for the members still standing in
/// it; the discards release their ticks' members; the records cover the
/// rows they name; each of the block's transactions its terms section
/// names gets a `Pending` row on those terms; and the manifest's member
/// lines put rows in flight in the block's own tick, writing the row of
/// a transaction the block both commits and runs; and its fates delete
/// the rows they name, last, so a member the block's own discard or
/// reclaim released ends deleted.
/// The fold reads no clock, and deletes no row but by a finalization
/// settling it or a fate. A row's seat is written beside it wherever
/// the row comes to hold one or stops holding one, and a vault's
/// reserved total wherever the rows written change what they reserve of
/// it: a released row reserves what it did, until it goes.
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
/// If a row fails to encode, which rows within their caps cannot. If a
/// vault's reserved total falls short of what the rows `state` holds
/// reserve of it, which no state this fold wrote does.
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

/// What a manifest's fates burn: one unjudged debit of each fated
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
    /// Every reserved total, by its vault's order key: what the fold
    /// differences the rows it changes against.
    reserved: BTreeMap<u128, u128>,
}

impl MemberIndex {
    /// No rows at all, for `shard`.
    #[must_use]
    pub const fn empty(shard: ShardId) -> Self {
        Self {
            shard,
            members: BTreeMap::new(),
            ticks: BTreeMap::new(),
            reserved: BTreeMap::new(),
        }
    }

    /// The height of the oldest block that committed a member still held:
    /// where a replay of what this shard owes begins.
    #[must_use]
    pub fn lowest_committed(&self) -> Option<BlockHeight> {
        self.members.values().map(|row| row.height).min()
    }

    /// The rows and the totals kept over them, one range read each.
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
        let reserved = read_all(state, shard, RESERVED)
            .into_iter()
            .filter_map(|(order, bytes)| Some((order, from_slice::<u128>(&bytes).ok()?)))
            .collect();
        Self {
            shard,
            members,
            ticks,
            reserved,
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
        let (_, reserved) = collection_of(self.shard, RESERVED);
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
            } else if key.collection == reserved {
                match change {
                    Some(bytes) => {
                        let total = from_slice(&bytes).expect("the fold encodes totals it decodes");
                        self.reserved.insert(key.order, total);
                    }
                    None => {
                        self.reserved.remove(&key.order);
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
        let (_, reserved) = collection_of(self.shard, RESERVED);
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
        } else if collection == reserved {
            self.reserved
                .range(lo..=hi)
                .map(|(order, total)| (*order, to_vec(total).expect("an amount encodes")))
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
        Declared, Derivation, DerivationError, Derived, MAX_DECLARED_RESERVE, TransactionEnvelope,
    };
    use proptest::collection::vec;
    use proptest::option;
    use proptest::prelude::*;

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
            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
            nevers: Capped::empty(),
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
            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
            nevers: Capped::empty(),
        }
    }

    fn settling(height: u64, tick: u64, half: TickHalf, txs: &[u8]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            settled: vec![SettledHalf {
                tick: TickId::new(LOCAL, BlockHeight::new(tick)),
                half,
                deleted: txs.iter().map(|&seed| tx(seed)).collect(),
                reclaimed: Vec::new(),
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
        assert!(tick.determined_unsettled && tick.awaiting == 1);
        assert_eq!(
            index.owed_determined(),
            BTreeSet::from([BlockHeight::new(2)])
        );

        store.fold(&settling(3, 2, TickHalf::Determined, &[1]));
        assert_eq!(state_of(&store, 1), None, "a settled member has no row");
        let index = MemberIndex::load(&store, LOCAL);
        assert!(index.owed_determined().is_empty());
        assert_eq!(index.ticks[&BlockHeight::new(2)].awaiting, 1);

        store.fold(&settling(4, 2, TickHalf::Legs, &[2]));
        let index = MemberIndex::load(&store, LOCAL);
        assert!(
            index.members.is_empty() && index.ticks.is_empty(),
            "{index:?}"
        );
    }

    /// A tick owes its legs half while one of its legs members still
    /// stands in it: a legs finalization deletes the rows it names and
    /// leaves the tick standing for the rest, whichever half settles in
    /// between.
    #[test]
    fn a_tick_owes_its_legs_while_a_member_stands_in_them() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3]));
        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Alone),
                member(2, Settlement::Shared),
                member(3, Settlement::Awaited),
            ],
        ));
        let standing = |store: &Entries| {
            let index = MemberIndex::load(store, LOCAL);
            (
                index
                    .ticks
                    .get(&BlockHeight::new(2))
                    .map(|tick| tick.awaiting),
                index.members.keys().copied().collect::<BTreeSet<_>>(),
            )
        };
        assert_eq!(standing(&store).0, Some(2));

        store.fold(&settling(3, 2, TickHalf::Legs, &[2]));
        assert_eq!(standing(&store), (Some(1), BTreeSet::from([tx(1), tx(3)])));
        store.fold(&settling(4, 2, TickHalf::Determined, &[1]));
        assert_eq!(
            standing(&store),
            (Some(1), BTreeSet::from([tx(3)])),
            "the tick stands for the leg no finalization has named",
        );
        store.fold(&settling(5, 2, TickHalf::Legs, &[3]));
        assert_eq!(standing(&store), (None, BTreeSet::new()));
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
            vec![
                TickLine::Discard {
                    tick: TickId::new(LOCAL, BlockHeight::new(8)),
                    cause: DiscardCause::Unanswerable(tx(6)),
                },
                TickLine::Fate {
                    tx: tx(6),
                    charge: stub_abort_charge(6),
                },
            ],
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
        assert!(!tick.determined_unsettled && tick.awaiting == 1);

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

    /// An `Unanswerable` discard releases the member it names and the
    /// rest as any discard does, and the fate beside it deletes the row:
    /// a discard alone deletes nothing, so every row that goes without a
    /// finalization goes by a fate.
    #[test]
    fn an_unanswerable_discard_releases_its_member_and_its_fate_deletes_it() {
        let named = || {
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
            store
        };
        let discard = TickLine::Discard {
            tick: TickId::new(LOCAL, BlockHeight::new(2)),
            cause: DiscardCause::Unanswerable(tx(1)),
        };
        let fate = TickLine::Fate {
            tx: tx(1),
            charge: stub_abort_charge(1),
        };

        let mut alone = named();
        alone.fold(&naming(3, vec![discard.clone()]));
        assert_eq!(
            state_of(&alone, 1),
            Some(RowState::Released {
                settlement: Settlement::Shared
            }),
            "released, as an abandoned member is",
        );
        assert!(!seated_in(&alone, 1));

        let mut store = named();
        store.fold(&naming(3, vec![discard, fate]));
        assert_eq!(state_of(&store, 1), None, "released, then fated");
        assert!(!seated_in(&store, 1));
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

    /// A block at `height` whose finalization of the tick at `tick` names
    /// the reclaims of `txs`: outcomes holding no reserved place.
    fn reclaiming(height: u64, tick: u64, txs: &[u8]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            settled: vec![SettledHalf {
                tick: TickId::new(LOCAL, BlockHeight::new(tick)),
                half: TickHalf::Determined,
                deleted: Vec::new(),
                reclaimed: txs.iter().map(|&seed| tx(seed)).collect(),
            }],
            ..MemberInputs::still(LOCAL)
        }
    }

    /// A reclaim's finalization deletes no row. The waiting row of the
    /// transaction it names is released on the settlement its terms
    /// state, keeping its reach, its charge and what it reserves, and
    /// dropping what it waited on; a later line cannot put it in flight
    /// from `Pending`, since it stands there no more. Its fate is what
    /// deletes it.
    #[test]
    fn a_reclaim_releases_the_waiting_row_it_names_and_deletes_nothing() {
        let mut store = Entries::default();
        store.fold(&reserving(1, &[(1, 9, 40)]));
        let waiting = row_of(&store, 1).expect("a committed row");
        let stated = waiting.waiting.clone().expect("a pending row waits");
        assert_eq!(waiting.state, RowState::Pending);
        assert_eq!(reserved(&store, 9), 40);

        store.fold(&reclaiming(2, 2, &[1]));
        let released = row_of(&store, 1).expect("the reclaim deletes no row");
        assert_eq!(
            released,
            MemberRow {
                state: RowState::Released {
                    settlement: stated.settlement,
                },
                waiting: None,
                ..waiting
            },
        );
        assert_eq!(
            reserved(&store, 9),
            40,
            "a released row reserves what it did"
        );
        assert!(!seated_in(&store, 1));

        store.fold(&reclaiming(3, 3, &[1]));
        assert_eq!(
            row_of(&store, 1),
            Some(released),
            "a second reclaim naming it changes nothing",
        );

        store.fold(&naming(
            4,
            vec![TickLine::Fate {
                tx: tx(1),
                charge: stub_abort_charge(1),
            }],
        ));
        assert_eq!(row_of(&store, 1), None);
        assert_eq!(reserved(&store, 9), 0);
    }

    /// A leg a line named to run after its reclaim was admitted is left
    /// running: the reclaim's finalization over a row in flight changes
    /// nothing, and neither does one over a row a discard released, an
    /// aborted one, or a transaction no row stands for.
    #[test]
    fn a_leg_named_after_its_reclaim_is_left_running() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3]));
        store.fold(&naming(
            2,
            vec![member(1, Settlement::Alone), joining(3, Joins::Aborted)],
        ));
        store.fold(&naming(3, vec![member(2, Settlement::Shared)]));
        store.fold(&discarding(4, 3, DiscardCause::Recovery));
        let before: Vec<Option<MemberRow>> = (1..=3).map(|seed| row_of(&store, seed)).collect();
        assert!(matches!(
            before[0].as_ref().map(|row| row.state),
            Some(RowState::InFlight {
                joins: Joins::Executes,
                ..
            })
        ));
        assert!(matches!(
            before[1].as_ref().map(|row| row.state),
            Some(RowState::Released { .. })
        ));
        let ticks = MemberIndex::load(&store, LOCAL).ticks;

        store.fold(&reclaiming(5, 5, &[1, 2, 3, 4]));
        let after: Vec<Option<MemberRow>> = (1..=3).map(|seed| row_of(&store, seed)).collect();
        assert_eq!(after, before);
        assert_eq!(row_of(&store, 4), None);
        assert_eq!(MemberIndex::load(&store, LOCAL).ticks, ticks);
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
            // releases and fates a member nobody can answer for.
            MemberInputs {
                settled: settling(3, 2, TickHalf::Determined, &[1]).settled,
                covered: vec![tx(2), tx(6)],
                manifest: lines(vec![
                    discard(2, DiscardCause::Unanswerable(tx(4))),
                    TickLine::Fate {
                        tx: tx(4),
                        charge: stub_abort_charge(4),
                    },
                    member(5, Settlement::Alone),
                    member(6, Settlement::Shared),
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

    /// A row a line names to run is marked executed for as long as it
    /// stands: through the release a discard gives it and the abort a
    /// later line names it on, and whether an entry or its own block's
    /// line wrote it. A row no line ever ran is never marked, by an
    /// abort or by the release of one.
    #[test]
    fn executed_survives_a_release_and_an_abort() {
        let executed = |store: &Entries, seed: u8| row_of(store, seed).expect("standing").executed;
        let released = |store: &Entries, seed: u8| {
            matches!(
                row_of(store, seed).expect("standing").state,
                RowState::Released { .. }
            )
        };
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2]));
        assert!(!executed(&store, 1) && !executed(&store, 2), "pending");

        store.fold(&naming(
            2,
            vec![joining(1, Joins::Executes), joining(2, Joins::Aborted)],
        ));
        assert!(executed(&store, 1), "named to run");
        assert!(!executed(&store, 2), "an abort alone runs nothing");

        store.fold(&discarding(3, 2, DiscardCause::Recovery));
        assert!(released(&store, 1) && released(&store, 2));
        assert!(executed(&store, 1), "released");
        assert!(!executed(&store, 2));

        store.fold(&naming(
            4,
            vec![joining(1, Joins::Aborted), joining(2, Joins::Aborted)],
        ));
        assert!(executed(&store, 1), "aborted after it ran");
        assert!(!executed(&store, 2), "aborted twice, and never run");

        let own = carried(&MemberInputs {
            manifest: Arc::new(Capped::from_array([
                joining(3, Joins::ExecutesAborted),
                joining(4, Joins::Aborted),
            ])),
            ..committing(5, &[3, 4])
        });
        assert_eq!(
            own.terms.len(),
            1,
            "the block states the one it does not run"
        );
        store.fold(&own);
        assert!(executed(&store, 3), "run by its committing block's line");
        assert!(
            !executed(&store, 4),
            "aborted by its committing block's line"
        );
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
                deadline,
                nevers: Capped::empty(),
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

    fn vault(seed: u8) -> SubstateKey {
        stub_abort_charge(seed).vault
    }

    /// What the rows standing reserve of `vault(seed)`.
    fn reserved(store: &Entries, seed: u8) -> u128 {
        reserved_total(store, LOCAL, vault(seed))
    }

    /// A block committing a member for each `(seed, vault, amount)`,
    /// reserving `amount` of that vault.
    fn reserving(height: u64, members: &[(u8, u8, u128)]) -> MemberInputs {
        let seeds: Vec<u8> = members.iter().map(|&(seed, ..)| seed).collect();
        let mut block = committing(height, &seeds);
        for (entry, &(_, on, amount)) in block.terms.iter_mut().zip(members) {
            entry.terms.reserves = Capped::from_array([(vault(on), amount)]);
        }
        block
    }

    /// A line naming `seed`'s standing row to run on `settlement`,
    /// restating what the row states.
    fn restating(store: &Entries, seed: u8, settlement: Settlement) -> TickLine {
        let row = row_of(store, seed).expect("a standing row");
        TickLine::Member {
            tx: row.tx,
            joins: Joins::Executes,
            settlement,
            holds: Capped::empty(),
            reach: row.reach,
            awaits: row.awaits,
            charge: row.charge,
            share: row.share,
            reserves: row.reserves,
            deadline: row.deadline,
            nevers: Capped::empty(),
        }
    }

    fn discarding(height: u64, tick: u64, cause: DiscardCause) -> MemberInputs {
        naming(
            height,
            vec![TickLine::Discard {
                tick: TickId::new(LOCAL, BlockHeight::new(tick)),
                cause,
            }],
        )
    }

    /// Two members reserving 40 and 2 of one vault, the first named
    /// `first` and the second `second` in tick 2.
    fn two_in_flight_on_one_vault(first: Settlement, second: Settlement) -> Entries {
        let mut store = Entries::default();
        store.fold(&reserving(1, &[(1, 9, 40), (2, 9, 2)]));
        let lines = vec![restating(&store, 1, first), restating(&store, 2, second)];
        store.fold(&naming(2, lines));
        assert_eq!(reserved(&store, 9), 42);
        store
    }

    /// A vault's reserved total rises by what each member a block
    /// commits reserves of it, whether the block's terms section or a
    /// line of its own wrote the row, and no other vault's moves. A
    /// successor's family reads none of it.
    #[test]
    fn a_committed_member_raises_a_vaults_reserved_total() {
        let mut store = Entries::default();
        store.fold(&reserving(1, &[(1, 9, 40), (2, 9, 2), (3, 8, 5)]));
        assert_eq!(reserved(&store, 9), 42, "two members of one vault");
        assert_eq!(reserved(&store, 8), 5);
        assert_eq!(reserved(&store, 7), 0, "a vault nobody reserves");

        let block = carried(&MemberInputs {
            manifest: Arc::new(Capped::from_array([joining(4, Joins::Executes)])),
            ..committing(2, &[4])
        });
        assert!(block.terms.is_empty(), "its line alone writes its row");
        store.fold(&block);
        assert_eq!(reserved(&store, 4), 4);
        assert_eq!(reserved(&store, 9), 42);

        let (left, _) = LOCAL.children();
        assert_eq!(reserved_total(&store, left, vault(9)), 0);
    }

    /// A finalization deletes the rows it names, and the total falls by
    /// what each reserved.
    #[test]
    fn a_settled_member_lowers_it() {
        let mut store = two_in_flight_on_one_vault(Settlement::Alone, Settlement::Shared);
        store.fold(&settling(3, 2, TickHalf::Determined, &[1]));
        assert_eq!(reserved(&store, 9), 2);
        store.fold(&settling(4, 2, TickHalf::Legs, &[2]));
        assert_eq!(reserved(&store, 9), 0);
    }

    /// An `Unanswerable` discard releases the member it names, which
    /// still reserves what it did; the fate beside it deletes the row,
    /// and the total falls by what that member reserved alone.
    #[test]
    fn an_unanswerable_member_lowers_it_with_its_fate() {
        let discard = TickLine::Discard {
            tick: TickId::new(LOCAL, BlockHeight::new(2)),
            cause: DiscardCause::Unanswerable(tx(1)),
        };
        let fate = TickLine::Fate {
            tx: tx(1),
            charge: stub_abort_charge(1),
        };
        let mut alone = two_in_flight_on_one_vault(Settlement::Shared, Settlement::Shared);
        alone.fold(&naming(3, vec![discard.clone()]));
        assert_eq!(reserved(&alone, 9), 42, "a released row still reserves");

        let mut store = two_in_flight_on_one_vault(Settlement::Shared, Settlement::Shared);
        store.fold(&naming(3, vec![discard, fate]));
        assert_eq!(row_of(&store, 1), None);
        assert_eq!(reserved(&store, 9), 2);
    }

    /// A fate deletes its row and the total falls with it. A terminal
    /// fates every row, in flight or not, so it leaves no total at all;
    /// and a member a block both commits and fates never moves one.
    #[test]
    fn a_fated_member_lowers_it() {
        let fated = |seed: u8| TickLine::Fate {
            tx: tx(seed),
            charge: stub_abort_charge(seed),
        };
        let mut store = two_in_flight_on_one_vault(Settlement::Alone, Settlement::Shared);
        store.fold(&reserving(3, &[(3, 9, 100), (4, 8, 5)]));
        store.fold(&naming(4, vec![fated(2)]));
        assert_eq!(reserved(&store, 9), 140);

        store.fold(&naming(5, vec![fated(1), fated(3), fated(4)]));
        assert!(MemberIndex::load(&store, LOCAL).members.is_empty());
        assert!(
            read_all(&store, LOCAL, RESERVED).is_empty(),
            "a terminal leaves no row and so no total",
        );

        let both = MemberInputs {
            manifest: Arc::new(Capped::from_array([fated(5)])),
            ..reserving(6, &[(5, 9, 7)])
        };
        assert!(member_writes(&store, &both).values().all(Option::is_none));
        store.fold(&both);
        assert!(store.0.is_empty(), "committed and fated in one block");
    }

    /// A released row still stands, and may be named again and run, so
    /// what it reserves stays counted until it is deleted.
    #[test]
    fn a_released_member_keeps_it() {
        let mut store = two_in_flight_on_one_vault(Settlement::Alone, Settlement::Awaited);
        store.fold(&discarding(3, 2, DiscardCause::Recovery));
        assert!(matches!(
            state_of(&store, 1),
            Some(RowState::Released { .. })
        ));
        assert!(matches!(
            state_of(&store, 2),
            Some(RowState::Released { .. })
        ));
        assert_eq!(reserved(&store, 9), 42);

        let again = vec![restating(&store, 1, Settlement::Alone)];
        store.fold(&naming(4, again));
        assert_eq!(reserved(&store, 9), 42, "named again");
        store.fold(&settling(5, 4, TickHalf::Determined, &[1]));
        assert_eq!(reserved(&store, 9), 2, "and settled");
    }

    /// A line naming a standing row restates what the row reserves, to
    /// run or to abort, and the total does not move: the fold writes no
    /// total for the block at all.
    #[test]
    fn a_named_member_keeps_it() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2]));
        let (_, totals) = collection_of(LOCAL, RESERVED);
        let block = naming(
            2,
            vec![joining(1, Joins::Executes), joining(2, Joins::Aborted)],
        );
        let writes = member_writes(&store, &block);
        assert!(writes.keys().all(|key| key.collection != totals));
        store.fold(&block);
        assert!(matches!(
            state_of(&store, 1),
            Some(RowState::InFlight { .. })
        ));
        assert_eq!((reserved(&store, 1), reserved(&store, 2)), (1, 2));
    }

    /// A discard that keeps a member in flight and releases its sibling
    /// leaves both rows standing, and the total where it was.
    #[test]
    fn a_kept_member_keeps_it() {
        let mut store = two_in_flight_on_one_vault(Settlement::Shared, Settlement::Shared);
        store.fold(&discarding(3, 2, DiscardCause::Abandoned(tx(1))));
        assert!(matches!(
            state_of(&store, 1),
            Some(RowState::Released { .. })
        ));
        assert!(matches!(
            state_of(&store, 2),
            Some(RowState::InFlight { .. })
        ));
        assert_eq!(reserved(&store, 9), 42);
    }

    /// A total is an entry only while a row reserves of its vault: the
    /// block that deletes the last such row deletes the entry, a member
    /// reserving nothing writes none, and a block whose rows leave a
    /// vault's sum where it stood writes none either.
    #[test]
    fn the_total_is_deleted_at_zero() {
        let (_, totals) = collection_of(LOCAL, RESERVED);
        let total_writes = |store: &Entries, block: &MemberInputs| -> Vec<Option<Vec<u8>>> {
            member_writes(store, block)
                .into_iter()
                .filter(|(key, _)| key.collection == totals)
                .map(|(_, change)| change)
                .collect()
        };
        let mut store = two_in_flight_on_one_vault(Settlement::Alone, Settlement::Alone);
        assert_eq!(read_all(&store, LOCAL, RESERVED).len(), 1);

        // Settles 40 and commits 40 on the same vault.
        let swap = MemberInputs {
            settled: settling(3, 2, TickHalf::Determined, &[1]).settled,
            ..reserving(3, &[(3, 9, 40), (4, 8, 0)])
        };
        assert!(total_writes(&store, &swap).is_empty());
        store.fold(&swap);
        assert_eq!((reserved(&store, 9), reserved(&store, 8)), (42, 0));

        store.fold(&naming(
            4,
            vec![
                restating(&store, 3, Settlement::Alone),
                restating(&store, 4, Settlement::Alone),
            ],
        ));
        let last = MemberInputs {
            settled: vec![
                settling(5, 2, TickHalf::Determined, &[2]).settled[0].clone(),
                settling(5, 4, TickHalf::Determined, &[3, 4]).settled[0].clone(),
            ],
            ..MemberInputs::still(LOCAL)
        };
        assert_eq!(total_writes(&store, &last), [None], "deleted, never zero");
        store.fold(&last);
        assert!(store.0.is_empty());
    }

    /// What a naming line states its member reserves where it does not
    /// restate the row: an amount of a vault.
    type Restated = Option<(u8, u128)>;

    /// One step of a chain's life, as raw choices a run resolves against
    /// the rows then standing.
    #[derive(Debug, Clone)]
    enum Step {
        /// Commit a member for each `(seed, vault, amount, runs)`, the
        /// flagged ones named to run by the block's own lines.
        Commit(Vec<(u8, u8, u128, bool)>),
        /// Name each `(seed, shape, reserves)`: on the terms `shape`
        /// picks, restating what its row reserves or stating `reserves`.
        Name(Vec<(u8, u8, Restated)>),
        /// Settle a half of the tick `pick` chooses, naming these.
        Settle(u8, bool, Vec<u8>),
        /// Discard the tick `pick` chooses for the cause `cause` picks.
        Discard(u8, u8, u8),
        /// Fate these.
        Fate(Vec<u8>),
    }

    fn step() -> impl Strategy<Value = Step> {
        let seed = || 1u8..=8;
        let amount = || {
            prop_oneof![
                0u128..4,
                any::<u64>().prop_map(u128::from),
                Just(MAX_DECLARED_RESERVE),
            ]
        };
        prop_oneof![
            3 => vec((seed(), 1u8..=3, amount(), any::<bool>()), 1..4)
                .prop_map(Step::Commit),
            3 => vec(
                (seed(), 0u8..6, option::of((1u8..=3, amount()))),
                1..4,
            )
            .prop_map(Step::Name),
            2 => (any::<u8>(), any::<bool>(), vec(seed(), 0..4))
                .prop_map(|(pick, half, members)| Step::Settle(pick, half, members)),
            2 => (any::<u8>(), 0u8..3, seed())
                .prop_map(|(pick, cause, member)| Step::Discard(pick, cause, member)),
            1 => vec(seed(), 1..6).prop_map(Step::Fate),
        ]
    }

    /// The line running `entry`'s transaction in the block that commits
    /// it, on the terms the entry states.
    fn running(entry: &StatedTerms) -> TickLine {
        TickLine::Member {
            tx: entry.tx,
            joins: Joins::Executes,
            settlement: entry.terms.settlement,
            holds: entry.terms.declared.clone(),
            reach: entry.terms.reach.clone(),
            awaits: entry.terms.awaits.clone(),
            charge: entry.terms.charge,
            share: entry.terms.share,
            reserves: entry.terms.reserves.clone(),
            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
            nevers: Capped::empty(),
        }
    }

    /// The block `step` is at `height` over `rows`: a commit of the
    /// seeds no row stands for, since a block never commits over a
    /// standing row, and everything else as chosen.
    fn block_of(step: &Step, height: u64, rows: &MemberIndex) -> MemberInputs {
        let tick_at = |pick: u8| {
            rows.ticks
                .keys()
                .nth(usize::from(pick) % rows.ticks.len().max(1))
                .map_or_else(|| u64::from(pick), |tick| tick.inner())
        };
        match step {
            Step::Commit(members) => {
                let mut fresh = BTreeSet::new();
                let members: Vec<(u8, u8, u128, bool)> = members
                    .iter()
                    .copied()
                    .filter(|&(seed, ..)| {
                        !rows.members.contains_key(&tx(seed)) && fresh.insert(seed)
                    })
                    .collect();
                let terms: Vec<(u8, u8, u128)> = members
                    .iter()
                    .map(|&(seed, on, amount, _)| (seed, on, amount))
                    .collect();
                let block = reserving(height, &terms);
                let lines: Vec<TickLine> = block
                    .terms
                    .iter()
                    .zip(&members)
                    .filter(|(_, member)| member.3)
                    .map(|(entry, _)| running(entry))
                    .collect();
                MemberInputs {
                    manifest: Arc::new(Capped::new(lines).expect("a few lines")),
                    ..block
                }
            }
            Step::Name(named) => naming(
                height,
                named
                    .iter()
                    .map(|&(seed, shape, stated)| {
                        let row = rows.members.get(&tx(seed));
                        TickLine::Member {
                            tx: tx(seed),
                            joins: [Joins::Executes, Joins::Aborted][usize::from(shape / 3)],
                            settlement: [
                                Settlement::Alone,
                                Settlement::Shared,
                                Settlement::Awaited,
                            ][usize::from(shape % 3)],
                            holds: Capped::empty(),
                            reach: Capped::empty(),
                            awaits: Capped::empty(),
                            charge: stub_abort_charge(seed),
                            share: 0,
                            reserves: stated.map_or_else(
                                || row.map_or_else(Capped::empty, |row| row.reserves.clone()),
                                |(on, amount)| Capped::from_array([(vault(on), amount)]),
                            ),
                            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
                            nevers: Capped::empty(),
                        }
                    })
                    .collect(),
            ),
            Step::Settle(pick, legs, members) => settling(
                height,
                tick_at(*pick),
                if *legs {
                    TickHalf::Legs
                } else {
                    TickHalf::Determined
                },
                members,
            ),
            Step::Discard(pick, cause, member) => discarding(
                height,
                tick_at(*pick),
                match cause {
                    0 => DiscardCause::Abandoned(tx(*member)),
                    1 => DiscardCause::Unanswerable(tx(*member)),
                    _ => DiscardCause::Recovery,
                },
            ),
            Step::Fate(fated) => naming(
                height,
                fated
                    .iter()
                    .map(|&seed| TickLine::Fate {
                        tx: tx(seed),
                        charge: stub_abort_charge(seed),
                    })
                    .collect(),
            ),
        }
    }

    proptest! {
        /// Through any sequence of blocks, a vault's reserved total is
        /// the sum of what the rows standing reserve of it, with no
        /// entry where that is nothing; an index advanced by the fold
        /// holds what state holds; and a block folded again over the
        /// rows its content left leaves what one fold of it leaves.
        #[test]
        fn the_total_is_the_sum_of_the_rows_standing(
            steps in vec(step(), 1..24),
        ) {
            let mut store = Entries::default();
            let mut cache = MemberIndex::empty(LOCAL);
            for (at, step) in steps.iter().enumerate() {
                let block = block_of(step, at as u64 + 1, &cache);
                let carrying = carried(&block);

                let mut twice = Entries(store.0.clone());
                twice.fold(&MemberInputs {
                    manifest: Arc::new(Capped::empty()),
                    ..block
                });
                twice.fold(&carrying);
                store.fold(&carrying);
                cache.advance(&carrying);
                prop_assert_eq!(&twice.0, &store.0, "folded twice, after {:?}", step);

                let loaded = MemberIndex::load(&store, LOCAL);
                prop_assert_eq!(&cache, &loaded, "after {:?}", step);
                let mut standing: BTreeMap<u128, u128> = BTreeMap::new();
                for &(vault, amount) in loaded.members.values().flat_map(|row| row.reserves.iter()) {
                    *standing.entry(reserved_order(vault)).or_default() += amount;
                }
                standing.retain(|_, total| *total != 0);
                prop_assert_eq!(&loaded.reserved, &standing, "after {:?}", step);
                for on in 1..=3 {
                    prop_assert_eq!(
                        reserved(&store, on),
                        standing.get(&reserved_order(vault(on))).copied().unwrap_or(0),
                    );
                }
            }
        }
    }

    proptest! {
        /// Through any sequence of blocks, a tick's count is the rows
        /// standing in it that a legs half settles, and no tick stands
        /// owing neither half.
        #[test]
        fn awaiting_counts_the_rows_standing_in_a_tick(
            steps in vec(step(), 1..24),
        ) {
            let mut rows = MemberIndex::empty(LOCAL);
            for (at, step) in steps.iter().enumerate() {
                let block = block_of(step, at as u64 + 1, &rows);
                rows.advance(&carried(&block));

                let mut standing: BTreeMap<BlockHeight, u32> = BTreeMap::new();
                for tick in rows.members.values().filter_map(|row| awaited_in(Some(row))) {
                    *standing.entry(tick).or_default() += 1;
                }
                let counted: BTreeMap<BlockHeight, u32> = rows
                    .ticks
                    .iter()
                    .filter(|(_, tick)| tick.awaiting > 0)
                    .map(|(height, tick)| (*height, tick.awaiting))
                    .collect();
                prop_assert_eq!(&counted, &standing, "after {:?}", step);
                prop_assert!(rows.ticks.values().all(TickRow::owes), "after {:?}", step);
            }
        }

        /// A proposer and a voter fold a block's content before its
        /// lines are named and then the block as carried. Whatever the
        /// block carries, the second fold leaves every entry of the
        /// family, each tick's count among them, as one fold of the
        /// carried block leaves it.
        #[test]
        fn a_block_folded_twice_writes_what_one_fold_does(
            steps in vec(step(), 1..24),
        ) {
            let mut once = Entries::default();
            let mut rows = MemberIndex::empty(LOCAL);
            for (at, step) in steps.iter().enumerate() {
                let block = block_of(step, at as u64 + 1, &rows);
                let carrying = carried(&block);

                let mut twice = Entries(once.0.clone());
                twice.fold(&MemberInputs {
                    manifest: Arc::new(Capped::empty()),
                    ..block
                });
                twice.fold(&carrying);
                once.fold(&carrying);
                rows.advance(&carrying);
                prop_assert_eq!(&twice.0, &once.0, "after {:?}", step);
                prop_assert_eq!(
                    &MemberIndex::load(&twice, LOCAL).ticks,
                    &rows.ticks,
                    "after {:?}",
                    step
                );
            }
        }
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
