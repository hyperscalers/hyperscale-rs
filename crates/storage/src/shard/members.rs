//! Tick membership as committed state: which transactions this chain has
//! committed and not resolved, and which tick holds each.
//!
//! Two ordered collections under the shard's own owner at
//! [`TICK_MEMBER_SLOT`], told apart by their material, which also names
//! the shard. Member rows are keyed by the first 128 bits of the
//! transaction hash and tick rows by height. Naming the shard puts a
//! predecessor's rows in a collection its successor never reads as its
//! own, even where the two share an owner address, as a split's left
//! child shares its parent's.
//!
//! One fold writes the family, [`member_writes`], off the block and the
//! parent's rows alone, so a replica that cannot route a transaction
//! folds the same writes as one that can, and every reader of the root
//! derives one set.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor, HborDecode, from_slice, to_vec};
use hyperscale_types::{
    AbandonmentRecord, Address, Block, BlockHeight, CollectionId, Deadline, DiscardCause, EntryKey,
    Finalization, Holds, Joins, MAX_TICK_LINES_PER_BLOCK, MAX_VALIDITY_RANGE, Reach,
    SettledEntries, Settlement, ShardId, ShardTrie, SubstateKey, TickHalf, TickId, TickLine,
    TickManifest, Transaction, TxHash, TxOutcome, Verifiable, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::{ProtocolHasher, TICK_MEMBER_SLOT, collection_id};

use crate::Substates;

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

/// One committed, unresolved member.
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
    /// The remote shards it reaches, as its line named them; empty until
    /// a line names it.
    pub reach: Reach,
    /// Whether a committed abandonment record names it.
    pub covered: bool,
}

impl MemberRow {
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
    /// What each of its finalizations settles.
    pub settled: Vec<SettledHalf>,
    /// The transactions its abandonment records name.
    pub covered: Vec<TxHash>,
    /// Its tick manifest.
    pub manifest: Arc<TickManifest>,
}

impl MemberInputs {
    /// What `block` writes to the family.
    #[must_use]
    pub fn of(block: &Block) -> Self {
        let header = block.header();
        Self::from_parts(
            header.shard_id(),
            header.height(),
            header.parent_qc().weighted_timestamp(),
            block.transactions().iter().map(|tx| tx.as_unverified()),
            block.certificates(),
            block.abandonment_records(),
            Arc::new(block.tick_manifest().clone()),
        )
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
            settled: Vec::new(),
            covered: Vec::new(),
            manifest: Arc::new(Capped::empty()),
        }
    }

    /// What a block of these sections writes, for a proposer building one.
    #[must_use]
    pub fn from_parts<'a>(
        shard: ShardId,
        height: BlockHeight,
        committed: WeightedTimestamp,
        transactions: impl IntoIterator<Item = &'a Transaction>,
        certificates: &[Arc<Verifiable<Finalization>>],
        records: &[AbandonmentRecord],
        manifest: Arc<TickManifest>,
    ) -> Self {
        Self {
            shard,
            height,
            committed,
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
            manifest,
        }
    }
}

/// Material telling the member collection from the tick collection.
const MEMBERS: u8 = 0;
const TICKS: u8 = 1;

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

fn member_entry(shard: ShardId, tx: TxHash) -> EntryKey {
    let (owner, collection) = collection_of(shard, MEMBERS);
    EntryKey {
        owner,
        collection,
        order: member_order(tx),
    }
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
            ticks: BTreeMap::new(),
            changed_members: BTreeSet::new(),
            changed_ticks: BTreeSet::new(),
        }
    }

    /// The row standing for `tx`: the transaction's own, never one whose
    /// hash merely shares its key.
    fn member(&mut self, tx: TxHash) -> Option<MemberRow> {
        let order = member_order(tx);
        let (state, shard) = (self.state, self.shard);
        self.members
            .entry(order)
            .or_insert_with(|| read_at(state, member_entry(shard, tx)))
            .clone()
            .filter(|row| row.tx == tx)
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
    /// owed only its legs half.
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
            DiscardCause::Rejected | DiscardCause::Recovery => None,
        };
        let whole = matches!(cause, DiscardCause::Recovery);
        let mut kept = Vec::new();
        for &tx in held.members.iter() {
            let keeps = self.member(tx).is_some_and(|row| {
                matches!(
                    row.state,
                    RowState::InFlight {
                        settlement: Settlement::Shared,
                        ..
                    }
                )
            });
            if keeps && !whole && Some(tx) != abandoned {
                kept.push(tx);
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
    fn name(&mut self, height: BlockHeight, manifest: &TickManifest) {
        let mut composed = TickRow::default();
        let mut members = Vec::new();
        for line in manifest.iter() {
            match line {
                TickLine::Member {
                    tx,
                    joins,
                    settlement,
                    holds,
                    reach,
                } => {
                    let Some(mut row) = self.member(*tx) else {
                        continue;
                    };
                    row.state = RowState::InFlight {
                        tick: height,
                        joins: *joins,
                        settlement: *settlement,
                    };
                    row.holds = holds.clone();
                    row.reach = reach.clone();
                    self.set_member(*tx, Some(row));
                    members.push(*tx);
                    match settlement.half() {
                        TickHalf::Determined => composed.determined_unsettled = true,
                        TickHalf::Legs => composed.legs_unsettled = true,
                    }
                }
                TickLine::Discard { .. } => {}
            }
        }
        if !members.is_empty() {
            composed.members = Capped::new(members).expect("a manifest caps its lines");
            self.set_tick(height, Some(composed));
        }
    }

    fn into_writes(self, writes: &mut SettledEntries) {
        for order in self.changed_members {
            let (owner, collection) = collection_of(self.shard, MEMBERS);
            let key = EntryKey {
                owner,
                collection,
                order,
            };
            let value = self.members[&order]
                .as_ref()
                .map(|row| to_vec(row).expect("a member row encodes"));
            writes.insert(key, value);
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
/// gets a `Pending` row; and the manifest's member lines put rows in
/// flight in the block's own tick. No row leaves by age: every exit is a
/// committed line or certificate.
///
/// Whatever stands in the parent's or either child's collections is
/// removed: a reshape successor's first fold empties what its
/// predecessors left, and every later one finds nothing there.
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
    for &(tx, deadline) in &inputs.transactions {
        family.set_member(
            tx,
            Some(MemberRow {
                tx,
                deadline,
                committed: inputs.committed,
                height: inputs.height,
                state: RowState::Pending,
                holds: Capped::empty(),
                reach: Capped::empty(),
                covered: false,
            }),
        );
    }
    family.name(inputs.height, &inputs.manifest);

    let mut writes = SettledEntries::new();
    family.into_writes(&mut writes);
    clear_predecessors(state, inputs.shard, &mut writes);
    writes
}

/// Remove whatever stands in `shard`'s parent's or children's
/// collections: a reshape successor's first fold empties what its
/// predecessors left, and every later one finds nothing there.
fn clear_predecessors(
    state: &(impl Substates + ?Sized),
    shard: ShardId,
    writes: &mut SettledEntries,
) {
    let children: [ShardId; 2] = shard.children().into();
    for predecessor in shard.parent().into_iter().chain(children) {
        for kind in [MEMBERS, TICKS] {
            let (owner, collection) = collection_of(predecessor, kind);
            for (order, _) in read_all(state, predecessor, kind) {
                writes.insert(
                    EntryKey {
                        owner,
                        collection,
                        order,
                    },
                    None,
                );
            }
        }
    }
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
    use hyperscale_types::Hash;

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
            ..MemberInputs::still(LOCAL)
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
        assert_eq!(
            MemberIndex::load(&store, LOCAL).members[&tx(1)].committed,
            WeightedTimestamp::from_millis(1_000),
            "the row carries its committing block's clock",
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

    /// A successor's fold clears what its predecessors left, even where
    /// it shares their owner address, and never reads their rows as its
    /// own.
    #[test]
    fn a_successor_clears_its_predecessors_rows() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        let mut store = Entries::default();
        store.fold(&MemberInputs {
            transactions: vec![(tx(1), Deadline::of(WeightedTimestamp::ZERO))],
            ..MemberInputs::still(parent)
        });
        assert_eq!(MemberIndex::load(&store, parent).members.len(), 1);
        assert!(
            MemberIndex::load(&store, left).members.is_empty(),
            "the left child shares its parent's owner and still reads none of its rows",
        );

        store.fold(&MemberInputs::still(left));
        assert!(MemberIndex::load(&store, parent).members.is_empty());
        assert!(store.0.is_empty());

        store.fold(&MemberInputs {
            transactions: vec![(tx(2), Deadline::of(WeightedTimestamp::ZERO))],
            ..MemberInputs::still(right)
        });
        store.fold(&MemberInputs::still(parent));
        assert!(
            store.0.is_empty(),
            "a merged parent clears its right child's rows"
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
                    cause: DiscardCause::Rejected,
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
}
