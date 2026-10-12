//! Tick membership as committed state: which transactions this chain has
//! committed and not resolved, and which tick holds each.
//!
//! Five ordered collections under the shard's own owner at the tick
//! member slot, told apart by their material, which also names the
//! shard, as [`MemberCollection`] derives them. Member rows are keyed by
//! the first 128 bits of the transaction hash and tick rows by height.
//! Seats are keyed as member rows are, and stand exactly while a tick
//! holds a member a counterpart settles against, in flight or stated:
//! what a counterpart reads, by presence alone, to tell a seated member
//! from one still waiting.
//! Verdict leaves are keyed as member rows are too, and stand exactly
//! while this shard's own certificate has said yes to a member whose
//! counterparts have not yet answered: one cell a sibling can hash from
//! what it holds of the transaction. Reserved totals are keyed by the
//! first 128 bits of a vault's hashed key, each the sum of what the rows
//! standing reserve of that vault: what admission weighs a new fee hold
//! against, beside the holds already standing. They sit with the rows
//! and not with the vault, since only a store that folds the rows can
//! keep their sum. Naming the shard puts a predecessor's rows in a
//! collection its successor never reads as its own, even where the two
//! share an owner address, as a split's left child shares its parent's.
//!
//! One fold writes the family, [`member_writes`], off the block, the
//! parent's rows and the epoch grid alone, so a replica that cannot
//! route a transaction folds the same writes as one that can, and every
//! reader of the root derives one set. What only a routing replica can
//! derive of a member, the block states: in its terms section for a
//! transaction it commits and does not run, and on the member line for
//! one it runs.
//!
//! A stated row hears its siblings through the block's state claims: a
//! claim names the members whose verdict cells it holds, and the fold
//! classifies what the sibling's state says of each at the claim's
//! anchor, keeping the newest reading per sibling on the row.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;
use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor, HborDecode, from_slice, to_vec};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    AbandonmentRecord, AbortCharge, Address, Anchor, Block, BlockHeight, CollectionId, Crossings,
    Deadline, DiscardCause, EntryKey, EntryLeaf, EpochWindows, ExecutionOutcome, Finalization,
    GlobalReceiptHash, Hash, Heard, Hearing, Holds, Inclusion, Joins, MAX_PREFIXES_PER_TX,
    MAX_TICK_LINES_PER_BLOCK, MAX_VALIDITY_RANGE, MemberCollection, MemberTerms, Movement, Reach,
    ReadMark, Reserves, Said, SettledEntries, Settlement, ShardId, StateClaim, StateWrites,
    StatedTerms, SubstateKey, TickHalf, TickId, TickLine, TickManifest, Transaction, TxHash,
    TxOutcome, VerdictQuestion, Verifiable, Verified, WeightedTimestamp, entry_leaf_key,
    member_order, said_at, verdict_leaf,
};
use hyperscale_vm_effects::{ProtocolHasher, fee_hold_key, protocol_resource};

use crate::Substates;
use crate::shard::fee_holds::FeeTerms;
use crate::shard::sweep::committed_tx_cell_key;
use crate::shard::writes::{entry_leaf_value, fold_state_writes};

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
    /// Run by the tick at `tick`, whose stating half committed this
    /// shard's success for it: a member a counterpart shares the verdict
    /// on, waiting for a legs half to settle it. It holds what it held
    /// in flight.
    Stated {
        /// The height of the tick holding it.
        tick: BlockHeight,
        /// The receipt hash the tick's certificate attests for it.
        receipt: GlobalReceiptHash,
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
    /// Whether a row standing so holds a seat: held by a tick, and
    /// settled against by a counterpart.
    #[must_use]
    pub const fn seated(self) -> bool {
        matches!(
            self,
            Self::InFlight {
                settlement: Settlement::Shared,
                ..
            } | Self::Stated { .. }
        )
    }

    /// The tick holding a row standing so, with the terms it is held
    /// on: its line's while in flight, and a run a counterpart shares
    /// the verdict on once stated, which is the only row that states.
    #[must_use]
    pub const fn held(self) -> Option<(BlockHeight, Joins, Settlement)> {
        match self {
            Self::InFlight {
                tick,
                joins,
                settlement,
            } => Some((tick, joins, settlement)),
            Self::Stated { tick, .. } => Some((tick, Joins::Executes, Settlement::Shared)),
            Self::Pending | Self::Released { .. } => None,
        }
    }

    /// Whether a row standing so hears its siblings: it has said yes,
    /// and what they say decides what ends it.
    #[must_use]
    pub const fn hears(self) -> bool {
        matches!(self, Self::Stated { .. })
    }

    /// Whether a [`TickLine::End`] deletes a row standing so. None does:
    /// a row waiting, held, stated or let go leaves by a finalization or
    /// a fate, whatever line names it.
    const fn ended_by_a_line(self) -> bool {
        match self {
            Self::Pending | Self::InFlight { .. } | Self::Stated { .. } | Self::Released { .. } => {
                false
            }
        }
    }
}

/// The shards a verdict leaf is said among: the ones a member's
/// settlement awaits and the one writing the leaf, each once, ascending.
type Awaited = Capped<Vec<ShardId>, { MAX_PREFIXES_PER_TX + 1 }>;

/// The shards a verdict is shared among where `shard`'s row awaits
/// `awaits`: the same list on every one of them that awaits the rest.
///
/// # Panics
///
/// Never: one shard beside a list at its cap is within the leaf's.
fn shared_among(awaits: &Reach, shard: ShardId) -> Awaited {
    let awaited: BTreeSet<ShardId> = awaits.iter().copied().chain([shard]).collect();
    Capped::new(awaited.into_iter().collect()).expect("one shard more than a capped reach")
}

/// What a shard's committed state says of a member whose counterparts
/// share the verdict.
///
/// It names the transaction and every shard the verdict is shared among,
/// the writer included, so two siblings that await each other encode one
/// value for one transaction and a reader hashes it from its own row.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub(crate) enum VerdictLeaf {
    /// This shard's certificate succeeded for the member, and its
    /// counterparts have yet to answer.
    Yes {
        /// The transaction, whole, so a key two hashes share is visible.
        tx: TxHash,
        /// The shards the verdict is shared among.
        awaited: Awaited,
    },
    /// This shard applied the member's effects. No row gives this leaf,
    /// so no fold writes it: it is the value a reader hashes to tell an
    /// accept from any other shape a cell can hold.
    Accepted {
        /// The transaction, whole, so a key two hashes share is visible.
        tx: TxHash,
        /// The shards the verdict is shared among.
        awaited: Awaited,
    },
}

impl VerdictLeaf {
    /// The yes of `shard` for `tx`, shared among `shard` and `awaits`.
    pub(crate) fn yes(tx: TxHash, awaits: &Reach, shard: ShardId) -> Self {
        Self::Yes {
            tx,
            awaited: shared_among(awaits, shard),
        }
    }
}

/// The value hash `sibling`'s tree holds at `tx`'s verdict cell while
/// the cell holds `leaf`: the hash of the entry's leaf encoding, which
/// is what a state claim proves present there.
///
/// # Panics
///
/// Never: a verdict leaf within its caps encodes.
#[must_use]
pub(crate) fn verdict_hash(sibling: ShardId, tx: TxHash, leaf: &VerdictLeaf) -> [u8; 32] {
    jmt_value_hash(&entry_leaf_value(
        &MemberCollection::Verdicts.entry(sibling, tx),
        &to_vec(leaf).expect("a verdict leaf encodes"),
    ))
}

/// What a block's claims carry at one anchor where a claim names a
/// member's verdict: the members named there, and every cell the block
/// reads at that anchor.
///
/// One anchor's keys are cut into claims by size, so a member's verdict
/// cell and the row and marker cells read beside it may sit in different
/// claims of the block; the cells here are all of them. Readings at two
/// anchors are two of these and never combine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReadings {
    /// The anchor the cells were read at.
    anchor: Anchor,
    /// The anchor's mark on the epoch grid.
    mark: ReadMark,
    /// The members a claim at the anchor names whose verdict cell the
    /// block carries there, ascending and each once.
    names: Vec<TxHash>,
    /// Every cell the block's claims read at the anchor.
    cells: BTreeMap<SubstateKey, Inclusion>,
}

impl AnchorReadings {
    /// What `claims` carry at each anchor where one of them names a
    /// verdict, ascending by anchor, each marked on the `windows` grid.
    ///
    /// A name whose verdict cell no claim at its anchor carries is
    /// dropped here, so what the fold does for a name is bounded by the
    /// proven cells the block pays for. A key two claims at one anchor
    /// both read keeps the first reading, which no admitted block
    /// carries a second of.
    #[must_use]
    pub(crate) fn among(claims: &[StateClaim], windows: EpochWindows) -> Vec<Self> {
        let mut named: BTreeMap<Anchor, BTreeSet<TxHash>> = BTreeMap::new();
        for claim in claims {
            if !claim.verdicts.is_empty() {
                named
                    .entry(claim.anchor)
                    .or_default()
                    .extend(claim.verdicts.iter().copied());
            }
        }
        if named.is_empty() {
            return Vec::new();
        }
        let mut cells: BTreeMap<Anchor, BTreeMap<SubstateKey, Inclusion>> = BTreeMap::new();
        for claim in claims {
            if !named.contains_key(&claim.anchor) {
                continue;
            }
            let at = cells.entry(claim.anchor).or_default();
            for (key, stated) in claim.cells.iter() {
                at.entry(*key).or_insert_with(|| stated.inclusion());
            }
        }
        named
            .into_iter()
            .filter_map(|(anchor, members)| {
                let cells = cells.remove(&anchor)?;
                let bound: Vec<TxHash> = members
                    .into_iter()
                    .filter(|tx| cells.contains_key(&verdict_leaf(anchor.shard, *tx)))
                    .collect();
                (!bound.is_empty()).then(|| Self {
                    anchor,
                    mark: ReadMark::of(&anchor, windows),
                    names: bound,
                    cells,
                })
            })
            .collect()
    }
}

/// The cells of a block's claims its hear step read, by the anchor each
/// was read at: observability of what hearing costs a block, and nothing
/// a write turns on.
///
/// A reading is the verdict leaf, with the member row and committed
/// marker where the leaf reads absent. Every reading the step classified
/// for a hearing row is `carried`; the ones that replaced the row's
/// entry are `changed` too. The rest were carried for nothing: a copy of
/// a reading an earlier block already committed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeardCells {
    /// The cells of every reading classified for a hearing row.
    pub carried: BTreeMap<Anchor, BTreeSet<SubstateKey>>,
    /// The cells of the readings that replaced a row's entry.
    pub changed: BTreeMap<Anchor, BTreeSet<SubstateKey>>,
}

impl HeardCells {
    /// How many cells were carried, and how many of them in a reading
    /// that changed an entry.
    fn counts(&self) -> (usize, usize) {
        let count = |cells: &BTreeMap<Anchor, BTreeSet<SubstateKey>>| {
            cells.values().map(BTreeSet::len).sum()
        };
        (count(&self.carried), count(&self.changed))
    }

    /// What a block whose claims are `claims` spent on verdict readings,
    /// or `None` where no claim of it names a member.
    ///
    /// Counting and nothing else: no proof is walked or cut. A claim
    /// naming a member is weighed whole, and what of a claim was carried
    /// to a hearing row, or changed an entry, is the claim's weight in
    /// proportion to those of its cells. A proof's bytes are shared
    /// among its cells, so the share is an attribution and not what the
    /// cells would weigh in a claim of their own.
    #[must_use]
    pub fn measures(&self, claims: &[StateClaim]) -> Option<VerdictMeasures> {
        let naming = || claims.iter().filter(|claim| !claim.verdicts.is_empty());
        naming().next()?;
        let (carried, changed) = self.counts();
        let share = |cells: &BTreeMap<Anchor, BTreeSet<SubstateKey>>| -> usize {
            claims
                .iter()
                .filter_map(|claim| {
                    let read = cells.get(&claim.anchor)?;
                    let held = claim
                        .cells
                        .iter()
                        .filter(|(key, _)| read.contains(key))
                        .count();
                    Some(claim.wire_weight() * held / claim.cells.len().max(1))
                })
                .sum()
        };
        Some(VerdictMeasures {
            cells: [
                naming().map(|claim| claim.cells.len()).sum(),
                carried,
                changed,
            ],
            bytes: [
                naming().map(StateClaim::wire_weight).sum(),
                share(&self.carried),
                share(&self.changed),
            ],
        })
    }
}

/// What one block spent on verdict readings, each figure three ways:
/// over the claims naming a member, over the cells of those a hearing
/// row read, and over the cells of those that changed a row's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictMeasures {
    /// Cells: named, carried to a hearing row, changing an entry.
    pub cells: [usize; 3],
    /// Bytes on the wire in the same order: the naming claims whole,
    /// proofs included, then each claim's weight in proportion to its
    /// cells carried, and to its cells that changed an entry.
    pub bytes: [usize; 3],
}

/// What `at`'s shard says of `tx` at `at`'s anchor, to a reader whose
/// row shares the verdict among `awaited` and whose transaction's signed
/// validity ends at `validity_end`: the anchor's mark and the reading.
///
/// A verdict cell read present says yes where it holds the yes the
/// reader's own row would give for that sibling, accepted where it holds
/// the accept, and left for any other value, a verdict shared among
/// other shards included. Read absent, it is judged with the sibling's
/// member row and committed marker at the same anchor: left where the
/// row is absent and the marker present or the anchor at or past the
/// validity end, since the sibling then holds no row and can commit
/// none; and not stated, `None`, in every other case, where it may still
/// commit or state.
///
/// `None` overall where the anchor proves nothing of `tx`: the verdict
/// cell is not among its cells, or it is absent without both the row
/// and the marker read beside it.
fn sibling_said(
    at: &AnchorReadings,
    tx: TxHash,
    validity_end: WeightedTimestamp,
    awaited: &Awaited,
) -> Option<(ReadMark, Option<Said>)> {
    let sibling = at.anchor.shard;
    let leaf = *at.cells.get(&verdict_leaf(sibling, tx))?;
    let beside = at
        .cells
        .get(&member_row_leaf(sibling, tx))
        .zip(
            at.cells
                .get(&committed_tx_cell_key(sibling, tx, validity_end)),
        )
        .map(|(row, marker)| (*row, *marker));
    let (yes, accepted) = sibling_hashes(sibling, tx, awaited);
    let said = said_at(leaf, beside, at.anchor.ts, validity_end, yes, accepted)?;
    Some((at.mark, said))
}

/// The value hashes `sibling`'s verdict cell for `tx` holds where it
/// says yes and where it says accepted, among the shards `awaited`.
fn sibling_hashes(sibling: ShardId, tx: TxHash, awaited: &Awaited) -> (Hash, Hash) {
    let hash = |leaf: VerdictLeaf| Hash::from_hash_bytes(&verdict_hash(sibling, tx, &leaf));
    (
        hash(VerdictLeaf::Yes {
            tx,
            awaited: awaited.clone(),
        }),
        hash(VerdictLeaf::Accepted {
            tx,
            awaited: awaited.clone(),
        }),
    )
}

/// The questions a shard's hearing rows put to their siblings, with the
/// two hashes each is read by kept from one derivation to the next.
///
/// A question's hashes turn only on the transaction, the sibling and the
/// shards the row shares its verdict with, so they are derived when the
/// question first stands and reused while the row awaits the same
/// shards. The kept hashes are replaced whole at every derivation, so
/// they number the questions the last one found: at most one per sibling
/// a hearing row awaits.
///
/// The same walk measures how long a row waits to hear: the tip each
/// hearing row was first seen at is kept beside whether its wait has
/// been reported, replaced whole as the hashes are, so it numbers the
/// hearing rows. Observability only.
#[derive(Debug, Default)]
pub struct VerdictAsks {
    kept: BTreeMap<(TxHash, ShardId), (Reach, Hash, Hash)>,
    seen: BTreeMap<TxHash, (BlockHeight, bool)>,
}

/// What one derivation of the verdict questions found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The questions standing, ascending by transaction and then
    /// sibling.
    pub questions: Vec<VerdictQuestion>,
    /// For each row that at this tip first holds a reading of every
    /// sibling it awaits, the blocks since the tip it was first seen
    /// hearing at.
    pub waited: Vec<u64>,
}

impl VerdictAsks {
    /// One question per sibling a hearing row of `rows`, the rows at
    /// the tip committed at `tip`, awaits, where `asks` says the sibling
    /// is asked given the row's entry for it, and whether that entry
    /// counts. One walk of the rows, ascending by transaction and then
    /// sibling.
    pub fn questions(
        &mut self,
        rows: &MemberIndex,
        tip: BlockHeight,
        mut asks: impl FnMut(ShardId, Option<&Heard>) -> Option<bool>,
    ) -> Asked {
        let shard = rows.shard();
        let mut kept = BTreeMap::new();
        let mut seen = BTreeMap::new();
        let mut questions = Vec::new();
        let mut waited = Vec::new();
        for row in rows.members.values().filter(|row| row.state.hears()) {
            let (since, mut reported) = self.seen.get(&row.tx).copied().unwrap_or((tip, false));
            let heard_all = row
                .awaits
                .iter()
                .all(|sibling| row.hearing.iter().any(|heard| heard.shard == *sibling));
            if heard_all && !reported {
                waited.push(tip.inner().saturating_sub(since.inner()));
                reported = true;
            }
            seen.insert(row.tx, (since, reported));
            for &sibling in row.awaits.iter() {
                let entry = row
                    .hearing
                    .iter()
                    .find(|heard| heard.shard == sibling)
                    .copied();
                let Some(counted) = asks(sibling, entry.as_ref()) else {
                    continue;
                };
                let key = (row.tx, sibling);
                let (yes, accepted) = match self.kept.get(&key) {
                    Some((awaits, yes, accepted)) if *awaits == row.awaits => (*yes, *accepted),
                    _ => sibling_hashes(sibling, row.tx, &shared_among(&row.awaits, shard)),
                };
                kept.insert(key, (row.awaits.clone(), yes, accepted));
                questions.push(VerdictQuestion {
                    sibling,
                    tx: row.tx,
                    validity_end: row.deadline.validity_end(),
                    yes,
                    accepted,
                    entry,
                    counted,
                });
            }
        }
        self.kept = kept;
        self.seen = seen;
        Asked { questions, waited }
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
    /// What each sibling its settlement awaits last said of it, read
    /// while it stands stated; empty in every other state.
    pub hearing: Hearing,
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
            hearing: Capped::empty(),
        }
    }

    /// The end of the transaction's abandon window.
    #[must_use]
    pub fn until(&self) -> WeightedTimestamp {
        self.deadline.at().plus(MAX_VALIDITY_RANGE)
    }

    /// The verdict leaf standing beside this row in `shard`'s family: a
    /// yes while it stands stated, and none in any other state.
    fn verdict(&self, shard: ShardId) -> Option<VerdictLeaf> {
        matches!(self.state, RowState::Stated { .. })
            .then(|| VerdictLeaf::yes(self.tx, &self.awaits, shard))
    }

    /// Take `heard` as its sibling's reading where it is newer than the
    /// one held: at a strictly higher mark, whatever either says. Says
    /// whether the row changed.
    ///
    /// # Panics
    ///
    /// Never: the row keeps one entry per shard it awaits, and both
    /// lists share a cap.
    fn hear(&mut self, heard: Heard) -> bool {
        match self
            .hearing
            .binary_search_by_key(&heard.shard, |held| held.shard)
        {
            Ok(at) if self.hearing[at].mark >= heard.mark => false,
            Ok(at) => {
                self.hearing[at] = heard;
                true
            }
            Err(at) => {
                self.hearing
                    .insert(at, heard)
                    .expect("one entry per awaited shard is within the reach cap");
                true
            }
        }
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
    /// in flight in this tick that its stating half moves, and the rows
    /// stated in it that a legs half settles. One of those halves is
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
    /// The members a stating half states a yes for, each beside the
    /// receipt hash its certificate attests: rows it moves and does not
    /// delete. Empty for any other half.
    pub stated: Vec<(TxHash, GlobalReceiptHash)>,
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
    /// What its claims carry at each anchor where one names a verdict,
    /// ascending by anchor.
    pub heard: Vec<AnchorReadings>,
}

/// The sections of a block the fold reads beside its transactions, its
/// terms and its lines.
#[derive(Debug, Clone, Copy)]
pub struct MemberSections<'a> {
    /// Its finalizations, each settling, stating or reclaiming members.
    pub certificates: &'a [Arc<Verifiable<Finalization>>],
    /// Its abandonment records, whose names cover the rows standing for
    /// them.
    pub records: &'a [AbandonmentRecord],
    /// Its state claims, which the rows they name a verdict for hear.
    pub claims: &'a [StateClaim],
}

impl MemberInputs {
    /// What `block` writes to the family, read off the sections it
    /// carries, the `windows` grid its claims' anchors are marked on,
    /// and nothing this replica derives.
    #[must_use]
    pub fn of(block: &Block, windows: EpochWindows) -> Self {
        let header = block.header();
        Self {
            manifest: Arc::new(block.tick_manifest().clone()),
            ..Self::deriving(
                header.shard_id(),
                header.height(),
                header.parent_qc().weighted_timestamp(),
                block.transactions().iter().map(|tx| tx.as_unverified()),
                MemberSections {
                    certificates: block.certificates(),
                    records: block.abandonment_records(),
                    claims: block.state_claims(),
                },
                windows,
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
            heard: Vec::new(),
        }
    }

    /// What a block of these sections writes before any line of it is
    /// named, each transaction standing on the entry of `terms` that
    /// names it: the rows a proposer names its lines over and a voter
    /// judges them over, where `terms` is what each derives for every
    /// transaction of the block. Its claims' anchors are marked on the
    /// `windows` grid.
    #[must_use]
    pub fn deriving<'a>(
        shard: ShardId,
        height: BlockHeight,
        committed: WeightedTimestamp,
        transactions: impl IntoIterator<Item = &'a Transaction>,
        sections: MemberSections<'_>,
        windows: EpochWindows,
        terms: Vec<StatedTerms>,
    ) -> Self {
        let MemberSections {
            certificates,
            records,
            claims,
        } = sections;
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
                    let stated = fw
                        .stated_outcomes()
                        .filter_map(|outcome| match outcome.outcome() {
                            ExecutionOutcome::Succeeded { receipt_hash } => {
                                Some((outcome.tx_hash(), *receipt_hash))
                            }
                            ExecutionOutcome::Failed | ExecutionOutcome::Aborted => None,
                        })
                        .collect();
                    SettledHalf {
                        tick: *fw.tick_id(),
                        half: fw.half(),
                        deleted: names(deleted),
                        stated,
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
            heard: AnchorReadings::among(claims, windows),
        }
    }
}

/// The tick `row` stands in outside its determined half, if it does: in
/// flight there on terms the determined half does not settle, or stated
/// there.
fn awaited_in(row: Option<&MemberRow>) -> Option<BlockHeight> {
    row?.state
        .held()
        .filter(|(_, _, settlement)| !settlement.alone())
        .map(|(tick, ..)| tick)
}

/// Whether `row` stands in the tick at `height`, in flight or stated.
fn in_tick(row: &MemberRow, height: BlockHeight) -> bool {
    row.state.held().is_some_and(|(tick, ..)| tick == height)
}

/// The hashes whose order keys lie in `lo..=hi`. Hashes order as their
/// bytes do, so a span of keys is a span of the hashes carrying them.
fn member_span(lo: u128, hi: u128) -> RangeInclusive<TxHash> {
    let bound = |order: u128, rest: u8| {
        let mut bytes = [rest; 32];
        bytes[..16].copy_from_slice(&order.to_be_bytes());
        TxHash::from(Hash::from_hash_bytes(&bytes))
    };
    bound(lo, 0x00)..=bound(hi, 0xFF)
}

/// The tree leaf of `tx`'s member row in `shard`'s collection: the key a
/// state claim reads to prove the row standing or gone.
#[must_use]
pub fn member_row_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, member_entry(shard, tx))
}

fn member_entry(shard: ShardId, tx: TxHash) -> EntryKey {
    MemberCollection::Members.entry(shard, tx)
}

/// The tree leaf of `tx`'s seat in `shard`'s family: present exactly
/// while a tick of `shard`'s holds `tx`, in flight or stated, and a
/// counterpart settles it against `shard`'s certificate.
#[must_use]
pub fn seat_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, MemberCollection::Seats.entry(shard, tx))
}

/// A vault's order key among the reserved totals: the first 128 bits of
/// its hashed key.
fn reserved_order(vault: SubstateKey) -> u128 {
    let mut high = [0u8; 16];
    high.copy_from_slice(&Hash::from_bytes(&vault.to_bytes()).as_bytes()[..16]);
    u128::from_be_bytes(high)
}

fn reserved_entry(shard: ShardId, order: u128) -> EntryKey {
    let (owner, collection) = MemberCollection::Reserved.of(shard);
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
    let (owner, collection) = MemberCollection::Ticks.of(shard);
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

fn read_all(
    state: &(impl Substates + ?Sized),
    shard: ShardId,
    kind: MemberCollection,
) -> Vec<(u128, Vec<u8>)> {
    let (owner, collection) = kind.of(shard);
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
    /// The cells the hear step read.
    heard: HeardCells,
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
            heard: HeardCells {
                carried: BTreeMap::new(),
                changed: BTreeMap::new(),
            },
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

    /// Write the row under `tx`'s key. A row that stood in a tick
    /// outside its determined half, and no longer does, leaves that
    /// tick: its count falls, and a tick left owing nothing goes.
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

    /// Release `tx` from its tick, in flight or stated: `Released`,
    /// holding nothing and keeping nothing it heard.
    fn release(&mut self, tx: TxHash) {
        if let Some(mut row) = self.member(tx) {
            let Some((_, _, settlement)) = row.state.held() else {
                return;
            };
            row.state = RowState::Released { settlement };
            row.holds = Capped::empty();
            row.hearing = Capped::empty();
            self.set_member(tx, Some(row));
        }
    }

    /// Each stated row a claim of the block names hears what the
    /// claim's shard says of it at the claim's anchor, where the row
    /// awaits that shard and the anchor's cells prove a reading. A claim
    /// of this shard's own is never heard: a row hears its siblings.
    ///
    /// The row is taken under the name and the cells are derived from
    /// the row, so a name with no row here, a row that does not hear or
    /// does not await the shard, and cells the block does not carry at
    /// that anchor all move nothing. A reading replaces the one held
    /// only at a strictly higher mark, so the anchors of one block may
    /// be taken in any order, and a second fold of the block finds
    /// every reading already held.
    fn hear(&mut self, heard: &[AnchorReadings]) {
        for at in heard {
            let sibling = at.anchor.shard;
            if sibling == self.shard {
                continue;
            }
            for &tx in &at.names {
                let Some(mut row) = self.member(tx) else {
                    continue;
                };
                if !row.state.hears() || !row.awaits.contains(&sibling) {
                    continue;
                }
                let validity_end = row.deadline.validity_end();
                let Some((mark, said)) =
                    sibling_said(at, tx, validity_end, &shared_among(&row.awaits, self.shard))
                else {
                    continue;
                };
                let leaf = verdict_leaf(sibling, tx);
                let read: Vec<SubstateKey> = if at.cells.get(&leaf) == Some(&Inclusion::Absent) {
                    vec![
                        leaf,
                        member_row_leaf(sibling, tx),
                        committed_tx_cell_key(sibling, tx, validity_end),
                    ]
                } else {
                    vec![leaf]
                };
                let changed = row.hear(Heard {
                    shard: sibling,
                    mark,
                    said,
                });
                if changed {
                    self.set_member(tx, Some(row));
                    self.heard
                        .changed
                        .entry(at.anchor)
                        .or_default()
                        .extend(read.iter().copied());
                }
                self.heard
                    .carried
                    .entry(at.anchor)
                    .or_default()
                    .extend(read);
            }
        }
    }

    /// A finalization deletes the rows of the members it settles. A
    /// determined half clears its tick's determined half; a legs half
    /// settles by member, so its tick owes it for as long as a row
    /// stands awaiting it. A tick owing neither half goes.
    ///
    /// A stating half moves each member it states a yes for to `Stated`,
    /// under the receipt hash its certificate attests, where the row
    /// stands in flight in that tick on terms a counterpart shares, and
    /// nowhere else: a row already stated, released or named again is
    /// left as it stands. The row's share goes to zero, since the
    /// stating half is where it was counted, and an abort line later
    /// named for it attests nothing more. It stays awaited in its tick.
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
        let height = settled.tick.block_height();
        for &tx in &settled.deleted {
            if self.member(tx).is_some() {
                self.set_member(tx, None);
            }
        }
        for &(tx, receipt) in &settled.stated {
            let Some(mut row) = self.member(tx) else {
                continue;
            };
            let shared_here = matches!(
                row.state,
                RowState::InFlight {
                    tick,
                    settlement: Settlement::Shared,
                    ..
                } if tick == height
            );
            if !shared_here {
                continue;
            }
            row.state = RowState::Stated {
                tick: height,
                receipt,
            };
            row.share = 0;
            self.set_member(tx, Some(row));
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
    /// that shares; a recovery discard releases the whole tick, stated
    /// members included. What stays is owed its stating half or a legs
    /// half, for each member kept. The member an `Unanswerable` discard
    /// names is released as an abandoned one is, and the fate its block
    /// names for it is what deletes its row.
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
            if let Some((tick, ..)) = row.state.held() {
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

    /// Ends delete the rows they name wherever
    /// [`RowState::ended_by_a_line`] holds, and move no other row: a line
    /// naming a row that stands any other way, or no row, writes nothing.
    fn end(&mut self, ended: &[TxHash]) {
        for &tx in ended {
            if self
                .member(tx)
                .is_some_and(|row| row.state.ended_by_a_line())
            {
                self.set_member(tx, None);
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
    /// nothing its line does not state, and nothing it heard. A row
    /// standing from an earlier block keeps where it was committed,
    /// whether a record covers it and whether a line ever ran it, and an
    /// abort keeps the crossings it never consumed. The row's deadline is
    /// the transaction's own, read off the block that committed it and
    /// never off a line; the deadline and the answers an abort line
    /// carries are for the replica seating it.
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
                        hearing: Capped::empty(),
                    };
                    self.set_member(*tx, Some(row));
                    members.push(*tx);
                    if settlement.alone() {
                        composed.determined_unsettled = true;
                    }
                }
                TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => {}
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
    /// A row's verdict leaf is written wherever the leaf the row written
    /// gives differs from the one the row held gives, so the leaf goes
    /// with its row whatever moves or deletes it.
    ///
    /// [`MAX_UNSETTLED_TXS`]: hyperscale_types::MAX_UNSETTLED_TXS
    /// [`MAX_HOLDS_PER_MEMBER`]: hyperscale_types::MAX_HOLDS_PER_MEMBER
    /// [`MAX_DECLARED_RESERVE`]: hyperscale_types::MAX_DECLARED_RESERVE
    fn into_writes(self, writes: &mut SettledEntries) {
        let (owner, members) = MemberCollection::Members.of(self.shard);
        let (_, seats) = MemberCollection::Seats.of(self.shard);
        let (_, verdicts) = MemberCollection::Verdicts.of(self.shard);
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
            let said = held.as_ref().and_then(|row| row.verdict(self.shard));
            let says = row.and_then(|row| row.verdict(self.shard));
            if said != says {
                writes.insert(
                    EntryKey {
                        owner,
                        collection: verdicts,
                        order,
                    },
                    says.map(|leaf| to_vec(&leaf).expect("a verdict leaf encodes")),
                );
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
/// names, a determined half clearing its tick's determined half, a
/// stating half moving the rows it states a yes for to `Stated`, and a
/// legs half leaving its tick owed for the members still standing in
/// it; the discards release their ticks' members; the records cover the
/// rows they name; each of the block's transactions its terms section
/// names gets a `Pending` row on those terms; and the manifest's member
/// lines put rows in flight in the block's own tick, writing the row of
/// a transaction the block both commits and runs; each stated row a
/// claim names then hears what the claim's shard says of it; and its
/// fates delete the rows they name, so a member the block's own discard
/// or reclaim released ends deleted; and its ends, last, delete the rows
/// they name wherever `RowState::ended_by_a_line` holds.
/// The fold reads the block, the state it lands on and the epoch grid
/// the block's anchors are marked on: no clock of this replica's and
/// nothing of the schedule. It deletes no row but by a finalization
/// settling it, a fate or an end. A row's seat is written beside it wherever
/// the row comes to hold one or stops holding one, its verdict leaf
/// wherever the row comes to say yes or stops saying it, and a vault's
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
    fold_members(state, inputs).0
}

/// [`member_writes`], beside the cells its hear step read.
fn fold_members(
    state: &(impl Substates + ?Sized),
    inputs: &MemberInputs,
) -> (SettledEntries, HeardCells) {
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
    family.hear(&inputs.heard);

    let (mut fated, mut ended) = (Vec::new(), Vec::new());
    for line in inputs.manifest.iter() {
        match line {
            TickLine::Fate { tx, .. } => fated.push(*tx),
            TickLine::End { tx } => ended.push(*tx),
            TickLine::Member { .. } | TickLine::Discard { .. } => {}
        }
    }
    family.fate(&fated);
    family.end(&ended);

    let heard = std::mem::take(&mut family.heard);
    let mut writes = SettledEntries::new();
    family.into_writes(&mut writes);
    (writes, heard)
}

/// One verdict leaf a block wrote or deleted, for one sibling that reads
/// it: a shard the leaf's verdict is shared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictChange {
    /// The sibling that reads the change.
    pub target: ShardId,
    /// The member whose leaf changed.
    pub tx: TxHash,
    /// The leaf's key.
    pub leaf: SubstateKey,
    /// For a leaf the block deleted, the member's row and committed
    /// marker keys, which a reader judges the absence beside; `None`
    /// for a leaf it wrote.
    pub beside: Option<(SubstateKey, SubstateKey)>,
}

/// The value an entry's leaf cell holds, decoded.
fn leaf_entry<T: HborDecode>(cell: Option<Vec<u8>>) -> Option<T> {
    from_slice(&from_slice::<EntryLeaf>(&cell?).ok()?.value).ok()
}

/// The verdict leaves `block` changed, each once per sibling its verdict
/// is shared with, ascending by member and then sibling: judged from
/// each leaf's cell before (`prior`) and after (`after`) the block.
///
/// A leaf moves only with its row, and a block moves a stated row or
/// makes one only by what it carries: a finalization stating or settling
/// the member, a line naming, fating or ending it, or a discard of its
/// tick, whose members the tick row `prior` holds lists. Those members
/// are the only leaves read, so the work is bounded by the block and
/// the ticks it discards, and no collection is walked. A leaf written
/// names its siblings itself; a leaf deleted names them in the value it
/// held, beside the row whose signed validity end keys the committed
/// marker.
#[must_use]
pub fn verdict_changes(
    block: &Block,
    prior: impl Fn(SubstateKey) -> Option<Vec<u8>>,
    after: impl Fn(SubstateKey) -> Option<Vec<u8>>,
) -> Vec<VerdictChange> {
    let shard = block.header().shard_id();
    let mut moved: BTreeSet<TxHash> = BTreeSet::new();
    for finalization in block.certificates().iter() {
        let finalization = finalization.as_unverified();
        moved.extend(
            finalization
                .stated_outcomes()
                .chain(finalization.settled_outcomes())
                .map(TxOutcome::tx_hash),
        );
    }
    for line in block.tick_manifest().iter() {
        match line {
            TickLine::Member { tx, .. } | TickLine::Fate { tx, .. } | TickLine::End { tx } => {
                moved.insert(*tx);
            }
            TickLine::Discard { tick, cause } => {
                if let DiscardCause::Abandoned(tx) | DiscardCause::Unanswerable(tx) = cause {
                    moved.insert(*tx);
                }
                let row = entry_leaf_key(&ProtocolHasher, tick_entry(shard, tick.block_height()));
                if tick.shard_id() == shard
                    && let Some(held) = leaf_entry::<TickRow>(prior(row))
                {
                    moved.extend(held.members.iter().copied());
                }
            }
        }
    }
    leaf_changes(shard, moved, prior, after)
}

/// [`verdict_changes`] over the members whose rows a block may have
/// moved.
fn leaf_changes(
    shard: ShardId,
    moved: impl IntoIterator<Item = TxHash>,
    prior: impl Fn(SubstateKey) -> Option<Vec<u8>>,
    after: impl Fn(SubstateKey) -> Option<Vec<u8>>,
) -> Vec<VerdictChange> {
    let mut changes = Vec::new();
    for member in moved {
        let leaf = verdict_leaf(shard, member);
        let (was, now) = (prior(leaf), after(leaf));
        if was == now {
            continue;
        }
        let deleted = now.is_none();
        let Some(VerdictLeaf::Yes { tx, awaited } | VerdictLeaf::Accepted { tx, awaited }) =
            leaf_entry(now.or(was))
        else {
            continue;
        };
        let beside = if deleted {
            let Some(row) = leaf_entry::<MemberRow>(prior(member_row_leaf(shard, tx))) else {
                continue;
            };
            Some((
                member_row_leaf(shard, tx),
                committed_tx_cell_key(shard, tx, row.deadline.validity_end()),
            ))
        } else {
            None
        };
        changes.extend(
            awaited
                .iter()
                .filter(|sibling| **sibling != shard)
                .map(|&target| VerdictChange {
                    target,
                    tx,
                    leaf,
                    beside,
                }),
        );
    }
    changes
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
        let members = read_all(state, shard, MemberCollection::Members)
            .into_iter()
            .filter_map(|(_, bytes)| from_slice::<MemberRow>(&bytes).ok())
            .map(|row| (row.tx, row))
            .collect();
        let ticks = read_all(state, shard, MemberCollection::Ticks)
            .into_iter()
            .filter_map(|(order, bytes)| {
                let height = BlockHeight::new(u64::try_from(order).ok()?);
                Some((height, from_slice::<TickRow>(&bytes).ok()?))
            })
            .collect();
        let reserved = read_all(state, shard, MemberCollection::Reserved)
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
    /// state, and say which cells of the block's claims its rows heard.
    ///
    /// # Panics
    ///
    /// If a written row fails to decode, which a row this fold encoded
    /// cannot.
    pub fn advance(&mut self, inputs: &MemberInputs) -> HeardCells {
        let (writes, heard) = fold_members(&*self, inputs);
        let (_, members) = MemberCollection::Members.of(self.shard);
        let (_, ticks) = MemberCollection::Ticks.of(self.shard);
        let (_, reserved) = MemberCollection::Reserved.of(self.shard);
        for (key, change) in writes {
            if key.collection == members {
                // One row stands under a key, whichever hash carries it.
                let held: Vec<TxHash> = self
                    .members
                    .range(member_span(key.order, key.order))
                    .map(|(tx, _)| *tx)
                    .collect();
                for tx in held {
                    self.members.remove(&tx);
                }
                if let Some(bytes) = change {
                    let row: MemberRow =
                        from_slice(&bytes).expect("the fold encodes rows it decodes");
                    self.members.insert(row.tx, row);
                }
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
        heard
    }

    /// How many of the members `inputs` settles hold a seat here: the
    /// members whose verdict a counterpart shares, counted while each
    /// row still says so, which is before the block is folded in.
    #[must_use]
    pub fn seated_among(&self, inputs: &MemberInputs) -> usize {
        inputs
            .settled
            .iter()
            .flat_map(|half| &half.deleted)
            .filter(|tx| self.members.get(tx).is_some_and(|row| row.state.seated()))
            .count()
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
        let (own, members) = MemberCollection::Members.of(self.shard);
        let (_, ticks) = MemberCollection::Ticks.of(self.shard);
        let (_, reserved) = MemberCollection::Reserved.of(self.shard);
        if owner != own || lo > hi {
            return Vec::new();
        }
        if collection == members {
            self.members
                .range(member_span(lo, hi))
                .take(limit)
                .map(|(tx, row)| {
                    (
                        member_order(*tx),
                        to_vec(row).expect("a member row encodes"),
                    )
                })
                .collect()
        } else if collection == ticks {
            let Ok(lo) = u64::try_from(lo) else {
                return Vec::new();
            };
            let hi = u64::try_from(hi).unwrap_or(u64::MAX);
            self.ticks
                .range(BlockHeight::new(lo)..=BlockHeight::new(hi))
                .take(limit)
                .map(|(height, row)| {
                    (
                        u128::from(height.inner()),
                        to_vec(row).expect("a tick row encodes"),
                    )
                })
                .collect()
        } else if collection == reserved {
            self.reserved
                .range(lo..=hi)
                .take(limit)
                .map(|(order, total)| (*order, to_vec(total).expect("an amount encodes")))
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::slice::from_ref;

    use hyperscale_jmt::{Blake3Hasher, Key as JmtKey, LeafValue, MemoryStore, NodeKey, Tree};
    use hyperscale_types::test_utils::{
        StubTree, make_live_block, stub_abort_charge, stub_stated_terms, test_key, test_transaction,
    };
    use hyperscale_types::{
        AddressClass, Declared, Derivation, DerivationError, Derived, Epoch, LocalKey,
        MAX_DECLARED_RESERVE, MAX_PROOFS_PER_QUERY, MAX_STATE_CLAIMS_BYTES,
        MAX_STATE_CLAIMS_PER_BLOCK, MerkleInclusionProof, StateRoot, TransactionEnvelope,
        ValidatorId, shard_prefix_path, state_claims_admit_block,
    };
    use proptest::collection::vec;
    use proptest::option;
    use proptest::prelude::*;

    use super::*;
    use crate::test_helpers::with_state_claims;

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
                stated: Vec::new(),
                reclaimed: Vec::new(),
            }],
            ..MemberInputs::still(LOCAL)
        }
    }

    /// The receipt hash a stating half attests for `seed`'s success.
    fn effects(seed: u8) -> GlobalReceiptHash {
        GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed, 0xEF]))
    }

    /// A block at `height` carrying the stating half of the tick at
    /// `tick`: settling the refusals of `refused` and stating a yes for
    /// each of `yes`.
    fn stating(height: u64, tick: u64, refused: &[u8], yes: &[u8]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            settled: vec![SettledHalf {
                tick: TickId::new(LOCAL, BlockHeight::new(tick)),
                half: TickHalf::Stated,
                deleted: refused.iter().map(|&seed| tx(seed)).collect(),
                stated: yes.iter().map(|&seed| (tx(seed), effects(seed))).collect(),
                reclaimed: Vec::new(),
            }],
            ..MemberInputs::still(LOCAL)
        }
    }

    const PEER: ShardId = ShardId::leaf(1, 1);

    /// `seed`'s line as a core member running beside [`PEER`], priced at
    /// `share`.
    fn sharing(seed: u8, share: u128) -> TickLine {
        TickLine::Member {
            tx: tx(seed),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::empty(),
            reach: Capped::from_array([PEER]),
            awaits: Capped::from_array([PEER]),
            charge: stub_abort_charge(seed),
            share,
            reserves: Capped::empty(),
            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
            nevers: Capped::empty(),
        }
    }

    /// The verdict leaf `store` holds for `seed`, as bytes.
    fn leaf_of(store: &Entries, seed: u8) -> Option<Vec<u8>> {
        let (owner, collection) = MemberCollection::Verdicts.of(LOCAL);
        store
            .0
            .get(&EntryKey {
                owner,
                collection,
                order: member_order(tx(seed)),
            })
            .cloned()
    }

    /// A stating half moves the member it states a yes for to `Stated`
    /// under the receipt hash it attests, zeroes its share, keeps its
    /// seat and writes its leaf; the member it refuses is deleted. The
    /// leaf names the transaction and both shards, so the sibling
    /// encodes the same value from its own row. Whatever ends or moves
    /// the row takes the leaf with it: a legs half, a recovery, a fate.
    #[test]
    fn a_stating_half_writes_a_leaf_a_sibling_can_hash() {
        let stated = || {
            let mut store = Entries::default();
            store.fold(&committing(1, &[1, 2, 3]));
            store.fold(&naming(
                2,
                vec![sharing(1, 7), sharing(2, 9), member(3, Settlement::Alone)],
            ));
            assert_eq!(leaf_of(&store, 1), None, "a row in flight says nothing");
            store.fold(&stating(3, 2, &[2], &[1]));
            store
        };
        let mut store = stated();
        let row = row_of(&store, 1).expect("a stated row stands");
        assert_eq!(
            row.state,
            RowState::Stated {
                tick: BlockHeight::new(2),
                receipt: effects(1),
            },
        );
        assert_eq!(row.share, 0, "the stating half counted it");
        assert!(row.executed && seated_in(&store, 1));
        assert_eq!(
            row_of(&store, 2),
            None,
            "a refusal settles in the stating half"
        );
        assert!(leaf_of(&store, 2).is_none() && !seated_in(&store, 2));
        assert!(matches!(
            state_of(&store, 3),
            Some(RowState::InFlight { .. })
        ));

        let ours = VerdictLeaf::yes(tx(1), &row.awaits, LOCAL);
        assert_eq!(
            ours,
            VerdictLeaf::Yes {
                tx: tx(1),
                awaited: Capped::from_array([LOCAL, PEER]),
            },
        );
        assert_eq!(leaf_of(&store, 1), Some(to_vec(&ours).unwrap()));
        assert_eq!(
            VerdictLeaf::yes(tx(1), &Capped::from_array([LOCAL]), PEER),
            ours,
            "the sibling derives the value from what its own row awaits",
        );
        let tick = &MemberIndex::load(&store, LOCAL).ticks[&BlockHeight::new(2)];
        assert!(
            tick.determined_unsettled && tick.awaiting == 1,
            "a stated row is awaited in its tick: {tick:?}",
        );

        store.fold(&settling(4, 2, TickHalf::Legs, &[1]));
        assert_eq!(row_of(&store, 1), None);
        assert!(leaf_of(&store, 1).is_none() && !seated_in(&store, 1));

        let mut recovered = stated();
        recovered.fold(&discarding(4, 2, DiscardCause::Recovery));
        assert_eq!(
            state_of(&recovered, 1),
            Some(RowState::Released {
                settlement: Settlement::Shared,
            }),
            "a recovery releases a stated member with the rest of its tick",
        );
        assert!(leaf_of(&recovered, 1).is_none() && !seated_in(&recovered, 1));
        assert!(MemberIndex::load(&recovered, LOCAL).ticks.is_empty());

        let mut kept = stated();
        kept.fold(&settling(4, 2, TickHalf::Determined, &[3]));
        kept.fold(&discarding(5, 2, DiscardCause::Abandoned(tx(9))));
        assert!(
            matches!(state_of(&kept, 1), Some(RowState::Stated { .. })),
            "a discard that does not abandon it keeps a stated member",
        );
        assert!(leaf_of(&kept, 1).is_some());
        kept.fold(&naming(
            6,
            vec![
                TickLine::Discard {
                    tick: TickId::new(LOCAL, BlockHeight::new(2)),
                    cause: DiscardCause::Unanswerable(tx(1)),
                },
                TickLine::Fate {
                    tx: tx(1),
                    charge: stub_abort_charge(1),
                },
            ],
        ));
        assert_eq!(row_of(&kept, 1), None);
        assert!(leaf_of(&kept, 1).is_none() && !seated_in(&kept, 1));
        assert!(MemberIndex::load(&kept, LOCAL).ticks.is_empty());
    }

    /// A stating half moves only a row in flight in its own tick on
    /// terms a counterpart shares: one settled alone, one reaching
    /// counterparts that settle nothing against it, one in another tick
    /// and one released are left as they stand.
    #[test]
    fn a_stating_half_moves_only_a_shared_row_of_its_tick() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3, 4]));
        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Alone),
                member(2, Settlement::Awaited),
                member(4, Settlement::Shared),
            ],
        ));
        store.fold(&naming(3, vec![member(3, Settlement::Shared)]));
        store.fold(&discarding(4, 2, DiscardCause::Abandoned(tx(4))));
        let before: Vec<Option<MemberRow>> = (1..=4).map(|seed| row_of(&store, seed)).collect();

        let block = stating(5, 2, &[], &[1, 2, 3, 4, 5]);
        assert!(member_writes(&store, &block).is_empty());
        store.fold(&block);
        let after: Vec<Option<MemberRow>> = (1..=4).map(|seed| row_of(&store, seed)).collect();
        assert_eq!(after, before);
        assert!((1..=5).all(|seed| leaf_of(&store, seed).is_none()));
    }

    /// A block carrying a stating half folds to the same entries whether
    /// its content is folded once, or once before its lines are named and
    /// again as carried; and its stating half folded over the rows it
    /// left writes nothing.
    #[test]
    fn a_fold_over_stating_halves_twice_writes_what_one_does() {
        let named = || {
            let mut store = Entries::default();
            store.fold(&committing(1, &[1, 2, 3]));
            store.fold(&naming(2, vec![sharing(1, 7), sharing(2, 9)]));
            store
        };
        let block = MemberInputs {
            settled: stating(3, 2, &[2], &[1]).settled,
            ..naming(3, vec![sharing(3, 4)])
        };
        let mut once = named();
        once.fold(&block);
        let mut twice = named();
        twice.fold(&MemberInputs {
            manifest: Arc::new(Capped::empty()),
            ..block.clone()
        });
        twice.fold(&block);
        assert_eq!(once.0, twice.0);
        assert!(leaf_of(&once, 1).is_some() && leaf_of(&once, 3).is_none());

        let again = MemberInputs {
            settled: block.settled,
            ..MemberInputs::still(LOCAL)
        };
        assert!(
            member_writes(&once, &again).is_empty(),
            "a stating half over rows it already moved writes nothing",
        );
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
        let (owner, collection) = MemberCollection::Seats.of(LOCAL);
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

    /// A discard of any cause lets go of every member its tick's
    /// determined half settles: none is left in flight, and the tick
    /// owes that half no longer. A determined half is whole over the
    /// rows standing for it, and a discard leaves it none.
    #[test]
    fn a_discard_leaves_no_row_in_flight_for_a_determined_half() {
        for cause in [
            DiscardCause::Abandoned(tx(2)),
            DiscardCause::Unanswerable(tx(2)),
            DiscardCause::Recovery,
        ] {
            let mut store = Entries::default();
            store.fold(&committing(1, &[1, 2, 3, 4]));
            store.fold(&naming(
                2,
                vec![
                    member(1, Settlement::Alone),
                    member(2, Settlement::Shared),
                    member(3, Settlement::Alone),
                    member(4, Settlement::Shared),
                ],
            ));
            let index = MemberIndex::load(&store, LOCAL);
            assert!(index.ticks[&BlockHeight::new(2)].determined_unsettled);

            store.fold(&discarding(3, 2, cause));
            let released = Some(RowState::Released {
                settlement: Settlement::Alone,
            });
            assert_eq!(state_of(&store, 1), released, "{cause:?}");
            assert_eq!(state_of(&store, 3), released, "{cause:?}");
            let index = MemberIndex::load(&store, LOCAL);
            assert!(
                index
                    .ticks
                    .get(&BlockHeight::new(2))
                    .is_none_or(|tick| !tick.determined_unsettled),
                "{cause:?}",
            );
            assert!(index.owed_determined().is_empty(), "{cause:?}");
        }
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
                stated: Vec::new(),
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

    /// An end line moves no row a line does not end: one naming a row
    /// that waits, runs alone, runs beside a counterpart, stands stated
    /// or was let go, or naming no row at all, writes nothing, to the
    /// family or to the verdict leaf beside a stated row, and burns
    /// nothing. A second fold of the block writes nothing either, and a
    /// fate beside the ends still deletes the row it names.
    #[test]
    fn an_end_line_moves_no_row_a_line_does_not_end() {
        let mut store = Entries::default();
        store.fold(&committing(1, &[1, 2, 3, 4, 5]));
        store.fold(&naming(
            2,
            vec![member(2, Settlement::Alone), sharing(3, 7), sharing(4, 9)],
        ));
        store.fold(&stating(3, 2, &[], &[4]));
        store.fold(&naming(4, vec![member(5, Settlement::Alone)]));
        store.fold(&discarding(5, 4, DiscardCause::Recovery));
        assert_eq!(state_of(&store, 1), Some(RowState::Pending));
        assert!(matches!(
            (state_of(&store, 2), state_of(&store, 3)),
            (
                Some(RowState::InFlight {
                    settlement: Settlement::Alone,
                    ..
                }),
                Some(RowState::InFlight {
                    settlement: Settlement::Shared,
                    ..
                }),
            )
        ));
        assert!(matches!(state_of(&store, 4), Some(RowState::Stated { .. })));
        assert!(matches!(
            state_of(&store, 5),
            Some(RowState::Released { .. })
        ));
        assert!(leaf_of(&store, 4).is_some() && seated_in(&store, 4));

        let ends: Vec<TickLine> = (1..=6).map(|seed| TickLine::End { tx: tx(seed) }).collect();
        let block = naming(6, ends.clone());
        assert!(
            member_writes(&store, &block).is_empty(),
            "no row stands in a state a line ends",
        );
        let before = store.0.clone();
        store.fold(&block);
        store.fold(&block);
        assert_eq!(store.0, before);
        assert_eq!(
            fate_writes(&block.manifest),
            StateWrites::default(),
            "an end burns no charge and deletes no fee hold",
        );

        let mut beside = ends;
        beside.push(TickLine::Fate {
            tx: tx(1),
            charge: stub_abort_charge(1),
        });
        store.fold(&naming(7, beside));
        assert_eq!(row_of(&store, 1), None, "the fate deletes its row");
        assert_eq!(MemberIndex::load(&store, LOCAL).members.len(), 4);
        assert!(leaf_of(&store, 4).is_some() && seated_in(&store, 4));
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

    /// A read of the cache answers as the state it was loaded from does:
    /// one key, a span of keys and every key, under any limit.
    #[test]
    fn a_cache_reads_as_state_does() {
        let mut store = Entries::default();
        store.fold(&reserving(1, &[(1, 1, 5), (2, 2, 7), (3, 1, 9), (4, 3, 2)]));
        store.fold(&naming(
            2,
            vec![
                member(1, Settlement::Shared),
                member(3, Settlement::Awaited),
            ],
        ));
        store.fold(&naming(3, vec![member(2, Settlement::Awaited)]));
        store.fold(&stating(4, 2, &[], &[1]));
        assert!(leaf_of(&store, 1).is_some(), "a stated row among them");
        let cache = MemberIndex::load(&store, LOCAL);
        assert_eq!(cache.members.len(), 4);
        assert_eq!(cache.ticks.len(), 2);

        let mut spans = vec![(0, u128::MAX), (1, 0), (2, 2), (2, 3), (4, u128::MAX)];
        for seed in 0..=5 {
            let order = member_order(tx(seed));
            let total = reserved_order(vault(seed));
            spans.extend([(order, order), (0, order), (order, u128::MAX)]);
            spans.extend([(total, total), (0, total)]);
        }
        for kind in [
            MemberCollection::Members,
            MemberCollection::Ticks,
            MemberCollection::Seats,
            MemberCollection::Verdicts,
            MemberCollection::Reserved,
        ] {
            let (owner, collection) = kind.of(LOCAL);
            for &(lo, hi) in &spans {
                for limit in [0, 1, 2, usize::MAX] {
                    let held =
                        if matches!(kind, MemberCollection::Seats | MemberCollection::Verdicts) {
                            Vec::new()
                        } else {
                            store.entries_in_range(owner, collection, lo, hi, limit)
                        };
                    assert_eq!(
                        cache.entries_in_range(owner, collection, lo, hi, limit),
                        held,
                        "collection {kind:?} over {lo}..={hi} limited to {limit}"
                    );
                }
            }
        }
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
            read_all(&store, LOCAL, MemberCollection::Reserved).is_empty(),
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
        let (_, totals) = MemberCollection::Reserved.of(LOCAL);
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
        let (_, totals) = MemberCollection::Reserved.of(LOCAL);
        let total_writes = |store: &Entries, block: &MemberInputs| -> Vec<Option<Vec<u8>>> {
            member_writes(store, block)
                .into_iter()
                .filter(|(key, _)| key.collection == totals)
                .map(|(_, change)| change)
                .collect()
        };
        let mut store = two_in_flight_on_one_vault(Settlement::Alone, Settlement::Alone);
        assert_eq!(read_all(&store, LOCAL, MemberCollection::Reserved).len(), 1);

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

    /// The epoch grid the readings below are marked on.
    const GRID_MS: u64 = 1_000_000;
    const GRID: EpochWindows = EpochWindows::new(GRID_MS);

    /// A third shard, which no row below awaits.
    const THIRD: ShardId = ShardId::leaf(2, 2);

    /// The deadline of the members that hear below, far enough out that
    /// an anchor can sit on either side of the validity end.
    fn far() -> Deadline {
        Deadline::of(WeightedTimestamp::from_millis(50 * GRID_MS))
    }

    fn validity_end() -> WeightedTimestamp {
        let end = far().validity_end();
        assert!(end > WeightedTimestamp::from_millis(GRID_MS));
        end
    }

    /// A block committing `seeds` under [`far`].
    fn committing_far(height: u64, seeds: &[u8]) -> MemberInputs {
        let mut block = committing(height, seeds);
        for (_, deadline) in &mut block.transactions {
            *deadline = far();
        }
        block
    }

    /// A store where `1` stands stated beside [`PEER`], `2` in flight
    /// beside it, `3` pending and `4` released.
    fn listening() -> Entries {
        let mut store = Entries::default();
        store.fold(&committing_far(1, &[1, 2, 3, 4]));
        store.fold(&naming(2, vec![sharing(1, 7)]));
        store.fold(&naming(
            3,
            vec![sharing(2, 7), member(4, Settlement::Alone)],
        ));
        store.fold(&stating(4, 2, &[], &[1]));
        store.fold(&discarding(5, 3, DiscardCause::Abandoned(tx(4))));
        assert!(matches!(state_of(&store, 1), Some(RowState::Stated { .. })));
        assert!(matches!(
            state_of(&store, 2),
            Some(RowState::InFlight { .. })
        ));
        assert_eq!(state_of(&store, 3), Some(RowState::Pending));
        assert!(matches!(
            state_of(&store, 4),
            Some(RowState::Released { .. })
        ));
        store
    }

    /// `shard`'s header at `height`, clocked at `ts_ms`.
    fn anchor_on(shard: ShardId, height: u64, ts_ms: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::from_bytes(&height.to_be_bytes())),
            ts: WeightedTimestamp::from_millis(ts_ms),
        }
    }

    /// [`PEER`]'s header at `height`, clocked one millisecond a height:
    /// in the grid's first epoch and before every validity end.
    fn at(height: u64) -> Anchor {
        anchor_on(PEER, height, height)
    }

    fn mark(epoch: u64, height: u64) -> ReadMark {
        ReadMark {
            epoch: Epoch::new(epoch),
            height: BlockHeight::new(height),
        }
    }

    /// The three cells `shard` keeps for `seed`: its verdict cell, its
    /// member row and its committed marker.
    fn cells_of(shard: ShardId, seed: u8) -> [SubstateKey; 3] {
        [
            verdict_leaf(shard, tx(seed)),
            member_row_leaf(shard, tx(seed)),
            committed_tx_cell_key(shard, tx(seed), validity_end()),
        ]
    }

    const PRESENT: Inclusion = Inclusion::Present([0x5A; 32]);

    /// The hash [`PEER`]'s own fold leaves at `seed`'s verdict cell for
    /// a yes shared with [`LOCAL`], derived as the writer derives it.
    fn peers_yes(seed: u8) -> Inclusion {
        let leaf = VerdictLeaf::yes(tx(seed), &Capped::from_array([LOCAL]), PEER);
        Inclusion::Present(verdict_hash(PEER, tx(seed), &leaf))
    }

    /// A claim at `anchor` over `cells`, naming `seeds`.
    fn reading(anchor: Anchor, cells: &[(SubstateKey, Inclusion)], seeds: &[u8]) -> StateClaim {
        StateClaim::new(anchor, cells.iter().copied(), MerkleInclusionProof::dummy())
            .hearing(seeds.iter().map(|&seed| tx(seed)))
    }

    /// A block at `height` carrying `claims` and nothing else.
    fn carrying(height: u64, claims: &[StateClaim]) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            heard: AnchorReadings::among(claims, GRID),
            ..MemberInputs::still(LOCAL)
        }
    }

    fn heard_by(store: &Entries, seed: u8) -> Vec<Heard> {
        row_of(store, seed)
            .expect("a standing row")
            .hearing
            .iter()
            .copied()
            .collect()
    }

    fn from_peer(mark: ReadMark, said: Option<Said>) -> Vec<Heard> {
        vec![Heard {
            shard: PEER,
            mark,
            said,
        }]
    }

    /// What `1` holds after a block carrying one claim at [`PEER`]'s
    /// height 7 over `cells`, naming it.
    fn hearing_of(cells: &[(SubstateKey, Inclusion)]) -> Vec<Heard> {
        let mut store = listening();
        store.fold(&carrying(6, &[reading(at(7), cells, &[1])]));
        heard_by(&store, 1)
    }

    /// The sibling's verdict cell holding the yes its own fold writes
    /// for the shards this row shares the verdict among reads yes.
    #[test]
    fn the_yes_hash_of_the_readers_awaited_set_reads_yes() {
        let [leaf, ..] = cells_of(PEER, 1);
        assert_eq!(
            hearing_of(&[(leaf, peers_yes(1))]),
            from_peer(mark(0, 7), Some(Said::Yes)),
        );
    }

    /// The cell holding the accept for those shards reads accepted.
    #[test]
    fn the_accepted_hash_of_the_readers_awaited_set_reads_accepted() {
        let [leaf, ..] = cells_of(PEER, 1);
        let accepted = VerdictLeaf::Accepted {
            tx: tx(1),
            awaited: Capped::from_array([LOCAL, PEER]),
        };
        assert_eq!(
            hearing_of(&[(
                leaf,
                Inclusion::Present(verdict_hash(PEER, tx(1), &accepted))
            )]),
            from_peer(mark(0, 7), Some(Said::Accepted)),
        );
    }

    /// The cell holding any other value reads left: a yes or an accept
    /// shared among other shards, the yes of another transaction, the
    /// yes hashed as another shard's cell holds it, and bytes that are
    /// no leaf at all.
    #[test]
    fn any_other_value_reads_left() {
        let [leaf, ..] = cells_of(PEER, 1);
        let wider: Awaited = Capped::from_array([LOCAL, PEER, THIRD]);
        let others = [
            verdict_hash(
                PEER,
                tx(1),
                &VerdictLeaf::Yes {
                    tx: tx(1),
                    awaited: wider.clone(),
                },
            ),
            verdict_hash(
                PEER,
                tx(1),
                &VerdictLeaf::Accepted {
                    tx: tx(1),
                    awaited: wider,
                },
            ),
            verdict_hash(
                PEER,
                tx(1),
                &VerdictLeaf::yes(tx(9), &Capped::from_array([LOCAL]), PEER),
            ),
            verdict_hash(
                LOCAL,
                tx(1),
                &VerdictLeaf::yes(tx(1), &Capped::from_array([LOCAL]), PEER),
            ),
            [0x5A; 32],
        ];
        for other in others {
            assert_eq!(
                hearing_of(&[(leaf, Inclusion::Present(other))]),
                from_peer(mark(0, 7), Some(Said::Left)),
            );
        }
    }

    /// The cell absent, with the sibling's row absent and its committed
    /// marker present at the same anchor, reads left: it committed the
    /// member and holds no row for it.
    #[test]
    fn an_absent_leaf_with_its_row_gone_and_its_marker_present_reads_left() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        assert_eq!(
            hearing_of(&[
                (leaf, Inclusion::Absent),
                (row, Inclusion::Absent),
                (marker, PRESENT),
            ]),
            from_peer(mark(0, 7), Some(Said::Left)),
        );
    }

    /// The cell absent, with the sibling's row absent and the anchor at
    /// or past the validity end, reads left though no marker stands: it
    /// can no longer commit the member. One millisecond short of the
    /// end, the same cells say nothing yet.
    #[test]
    fn an_absent_leaf_with_its_row_gone_past_the_validity_end_reads_left() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let end = validity_end().as_millis();
        let cells = [
            (leaf, Inclusion::Absent),
            (row, Inclusion::Absent),
            (marker, Inclusion::Absent),
        ];
        let read_at = |ts_ms: u64| {
            let mut store = listening();
            let anchor = anchor_on(PEER, 7, ts_ms);
            store.fold(&carrying(6, &[reading(anchor, &cells, &[1])]));
            (heard_by(&store, 1), ReadMark::of(&anchor, GRID))
        };
        let (heard, mark) = read_at(end);
        assert_eq!(heard, from_peer(mark, Some(Said::Left)));
        let (heard, mark) = read_at(end - 1);
        assert_eq!(heard, from_peer(mark, None));
    }

    /// The cell absent in every other case is not stated: the sibling
    /// still holds a row for the member, or holds none and has neither
    /// committed it nor run out of time to.
    #[test]
    fn an_absent_leaf_otherwise_is_not_stated() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        for (row_reads, marker_reads) in [
            (PRESENT, PRESENT),
            (PRESENT, Inclusion::Absent),
            (Inclusion::Absent, Inclusion::Absent),
        ] {
            assert_eq!(
                hearing_of(&[
                    (leaf, Inclusion::Absent),
                    (row, row_reads),
                    (marker, marker_reads),
                ]),
                from_peer(mark(0, 7), None),
            );
        }
    }

    /// Readings at two anchors never combine: an absent verdict cell at
    /// one anchor and the row and marker that would prove the exit at
    /// another prove nothing, whichever anchor names the member.
    #[test]
    fn readings_at_two_anchors_never_combine() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let exit = [(row, Inclusion::Absent), (marker, PRESENT)];
        let split = [
            reading(at(7), &[(leaf, Inclusion::Absent)], &[1]),
            reading(at(8), &exit, &[]),
        ];
        let store = listening();
        assert!(member_writes(&store, &carrying(6, &split)).is_empty());

        let halves = [
            reading(
                at(7),
                &[(leaf, Inclusion::Absent), (row, Inclusion::Absent)],
                &[1],
            ),
            reading(at(8), &[(leaf, Inclusion::Absent), (marker, PRESENT)], &[1]),
        ];
        assert!(member_writes(&store, &carrying(6, &halves)).is_empty());

        let same_height_another_root = Anchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"another")),
            ..at(7)
        };
        let forked = [
            reading(at(7), &[(leaf, Inclusion::Absent)], &[1]),
            reading(same_height_another_root, &exit, &[]),
        ];
        assert!(member_writes(&store, &carrying(6, &forked)).is_empty());
    }

    /// A not-stated reading is kept with its mark: an older yes arriving
    /// after it does not replace it, and a newer one does.
    #[test]
    fn a_not_stated_reading_keeps_its_mark() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let mut store = listening();
        let silent = reading(
            at(9),
            &[(leaf, Inclusion::Absent), (row, PRESENT), (marker, PRESENT)],
            &[1],
        );
        store.fold(&carrying(6, &[silent]));
        assert_eq!(heard_by(&store, 1), from_peer(mark(0, 9), None));

        let older = carrying(7, &[reading(at(5), &[(leaf, peers_yes(1))], &[1])]);
        assert!(member_writes(&store, &older).is_empty());
        let level = carrying(7, &[reading(at(9), &[(leaf, peers_yes(1))], &[1])]);
        assert!(
            member_writes(&store, &level).is_empty(),
            "a reading at the mark held is not newer",
        );

        store.fold(&carrying(
            8,
            &[reading(at(10), &[(leaf, peers_yes(1))], &[1])],
        ));
        assert_eq!(heard_by(&store, 1), from_peer(mark(0, 10), Some(Said::Yes)));
    }

    /// An absent verdict cell carried without both the sibling's row and
    /// its marker at that anchor proves nothing, so the reading held
    /// stands: not replaced by a not-stated one, and not raised.
    #[test]
    fn an_absent_leaf_without_its_row_and_marker_leaves_the_hearing_untouched() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let mut store = listening();
        store.fold(&carrying(
            6,
            &[reading(at(5), &[(leaf, peers_yes(1))], &[1])],
        ));
        let held = from_peer(mark(0, 5), Some(Said::Yes));
        assert_eq!(heard_by(&store, 1), held);

        for beside in [
            vec![],
            vec![(row, Inclusion::Absent)],
            vec![(marker, PRESENT)],
        ] {
            let mut cells = vec![(leaf, Inclusion::Absent)];
            cells.extend(beside);
            let block = carrying(7, &[reading(at(9), &cells, &[1])]);
            assert!(member_writes(&store, &block).is_empty(), "{cells:?}");
        }
        assert_eq!(heard_by(&store, 1), held);
    }

    /// One anchor's keys are cut into claims by size. A member whose
    /// verdict cell rides one claim and whose row and marker ride
    /// another at the same anchor is heard as if one claim held all
    /// three.
    #[test]
    fn a_member_cut_across_two_claims_at_one_anchor_is_heard() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let cut = [
            reading(at(7), &[(leaf, Inclusion::Absent)], &[1]),
            reading(at(7), &[(row, Inclusion::Absent)], &[]),
            reading(at(7), &[(marker, PRESENT)], &[]),
        ];
        let mut store = listening();
        store.fold(&carrying(6, &cut));
        assert_eq!(heard_by(&store, 1), from_peer(mark(0, 7), Some(Said::Left)));
    }

    /// The same cut carried by two blocks moves nothing: each block is
    /// read alone, and neither holds the three cells.
    #[test]
    fn a_member_cut_across_two_blocks_moves_nothing() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let mut store = listening();
        let first = carrying(6, &[reading(at(7), &[(leaf, Inclusion::Absent)], &[1])]);
        let second = carrying(
            7,
            &[reading(
                at(7),
                &[(row, Inclusion::Absent), (marker, PRESENT)],
                &[1],
            )],
        );
        assert!(member_writes(&store, &first).is_empty());
        store.fold(&first);
        assert!(member_writes(&store, &second).is_empty());
        store.fold(&second);
        assert!(heard_by(&store, 1).is_empty());
    }

    /// A name moves nothing where no row here hears the claim's shard:
    /// no row under it, a row pending, in flight or released, a stated
    /// row that does not await the shard, or another transaction keyed
    /// where the row is. Nor do a member's cells carried with no name,
    /// or a name whose verdict cell the block carries at another anchor
    /// only.
    #[test]
    fn a_name_with_no_hearing_row_moves_nothing() {
        let store = listening();
        let yes = |shard: ShardId, seed: u8| {
            let leaf = VerdictLeaf::yes(tx(seed), &Capped::from_array([LOCAL]), shard);
            (
                verdict_leaf(shard, tx(seed)),
                Inclusion::Present(verdict_hash(shard, tx(seed), &leaf)),
            )
        };
        let moves_nothing = |claims: &[StateClaim], why: &str| {
            let block = carrying(6, claims);
            assert!(member_writes(&store, &block).is_empty(), "{why}");
        };

        for (seed, why) in [
            (9, "no row"),
            (3, "a pending row"),
            (2, "a row in flight"),
            (4, "a released row"),
        ] {
            moves_nothing(&[reading(at(7), &[yes(PEER, seed)], &[seed])], why);
        }
        moves_nothing(
            &[reading(anchor_on(THIRD, 7, 7), &[yes(THIRD, 1)], &[1])],
            "a shard the row does not await",
        );
        moves_nothing(&[reading(at(7), &[yes(PEER, 1)], &[])], "no name");
        moves_nothing(
            &[
                reading(at(7), &[(test_key(1), PRESENT)], &[1]),
                reading(at(8), &[yes(PEER, 1)], &[]),
            ],
            "a name at an anchor that holds no verdict cell of it",
        );
        let twin = {
            let mut bytes = *tx(1).as_bytes();
            bytes[31] ^= 0x01;
            TxHash::from(Hash::from_hash_bytes(&bytes))
        };
        assert_eq!(verdict_leaf(PEER, twin), verdict_leaf(PEER, tx(1)));
        moves_nothing(
            &[
                StateClaim::new(at(7), [yes(PEER, 1)], MerkleInclusionProof::dummy())
                    .hearing([twin]),
            ],
            "another transaction sharing the row's key",
        );

        let heard = carrying(6, &[reading(at(7), &[yes(PEER, 1)], &[1])]);
        assert!(
            !member_writes(&store, &heard).is_empty(),
            "the same cell named for the stated row is heard",
        );
    }

    /// A claim of this shard's own is never heard, even by a stated row
    /// whose line names this shard among the ones it awaits: a row
    /// hears its siblings, and a shard's own claims are read at its
    /// parent, where no proof rides.
    #[test]
    fn a_claim_of_this_shards_own_is_never_heard() {
        let mut store = Entries::default();
        store.fold(&committing_far(1, &[1]));
        store.fold(&naming(
            2,
            vec![TickLine::Member {
                tx: tx(1),
                joins: Joins::Executes,
                settlement: Settlement::Shared,
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                awaits: Capped::from_array([LOCAL, PEER]),
                charge: stub_abort_charge(1),
                share: 7,
                reserves: Capped::empty(),
                deadline: far(),
                nevers: Capped::empty(),
            }],
        ));
        store.fold(&stating(3, 2, &[], &[1]));
        let leaf = VerdictLeaf::yes(tx(1), &Capped::from_array([LOCAL, PEER]), LOCAL);
        let own = carrying(
            6,
            &[reading(
                anchor_on(LOCAL, 7, 7),
                &[(
                    verdict_leaf(LOCAL, tx(1)),
                    Inclusion::Present(verdict_hash(LOCAL, tx(1), &leaf)),
                )],
                &[1],
            )],
        );
        assert!(!own.heard.is_empty());
        assert!(member_writes(&store, &own).is_empty());
    }

    /// A release empties what the row heard, whether the reading landed
    /// in an earlier block or rides the block that releases it.
    #[test]
    fn a_release_empties_the_hearing() {
        let [leaf, ..] = cells_of(PEER, 1);
        let yes = reading(at(7), &[(leaf, peers_yes(1))], &[1]);
        let recovery = discarding(7, 2, DiscardCause::Recovery);

        let mut store = listening();
        store.fold(&carrying(6, from_ref(&yes)));
        assert!(!heard_by(&store, 1).is_empty());
        store.fold(&recovery);
        assert!(matches!(
            state_of(&store, 1),
            Some(RowState::Released { .. })
        ));
        assert!(heard_by(&store, 1).is_empty());

        let mut together = listening();
        together.fold(&MemberInputs {
            heard: carrying(6, from_ref(&yes)).heard,
            ..recovery
        });
        assert!(matches!(
            state_of(&together, 1),
            Some(RowState::Released { .. })
        ));
        assert!(heard_by(&together, 1).is_empty());
    }

    /// A row stated by a block hears the claims that block carries, and
    /// a second fold of the block writes nothing more.
    #[test]
    fn a_row_hears_in_the_block_that_states_it() {
        let [leaf, ..] = cells_of(PEER, 1);
        let mut store = Entries::default();
        store.fold(&committing_far(1, &[1]));
        store.fold(&naming(2, vec![sharing(1, 7)]));
        let block = MemberInputs {
            heard: carrying(3, &[reading(at(7), &[(leaf, peers_yes(1))], &[1])]).heard,
            ..stating(3, 2, &[], &[1])
        };
        store.fold(&block);
        assert_eq!(heard_by(&store, 1), from_peer(mark(0, 7), Some(Said::Yes)));
        assert!(member_writes(&store, &block).is_empty());
    }

    /// Only a hearing row puts a question, one per sibling it awaits
    /// that the caller admits, carrying the hash the sibling's own fold
    /// would write for a yes, the row's entry and the signed end its
    /// marker is keyed by. The hashes are kept only for the questions
    /// the last derivation found.
    #[test]
    fn a_hearing_row_asks_each_sibling_it_awaits_by_the_hash_that_sibling_writes() {
        let [leaf, ..] = cells_of(PEER, 1);
        let mut store = listening();
        let mut asks = VerdictAsks::default();
        let rows = MemberIndex::load(&store, LOCAL);
        let Inclusion::Present(yes) = peers_yes(1) else {
            unreachable!("a yes is a presence");
        };
        let Asked {
            questions: asked,
            waited,
        } = asks.questions(&rows, BlockHeight::new(5), |_, _| Some(true));
        assert!(waited.is_empty(), "nothing heard yet");
        assert_eq!(
            asked,
            vec![VerdictQuestion {
                sibling: PEER,
                tx: tx(1),
                validity_end: validity_end(),
                yes: Hash::from_hash_bytes(&yes),
                accepted: asked[0].accepted,
                entry: None,
                counted: true,
            }],
            "the stated row asks, and no row in flight, pending or released",
        );
        assert_ne!(asked[0].accepted, asked[0].yes);
        assert_eq!(asks.kept.len(), 1);

        store.fold(&carrying(
            6,
            &[reading(at(7), &[(leaf, peers_yes(1))], &[1])],
        ));
        let rows = MemberIndex::load(&store, LOCAL);
        let mut seen = Vec::new();
        let Asked {
            questions: again,
            waited,
        } = asks.questions(&rows, BlockHeight::new(9), |sibling, entry| {
            seen.push((sibling, entry.copied()));
            Some(false)
        });
        assert_eq!(waited, vec![4], "heard four blocks after it was first seen");
        assert!(
            asks.questions(&rows, BlockHeight::new(12), |_, _| Some(true))
                .waited
                .is_empty(),
            "a row's wait is reported once",
        );
        let entry = from_peer(mark(0, 7), Some(Said::Yes)).pop();
        assert_eq!(seen, vec![(PEER, entry)]);
        assert_eq!(again[0].entry, entry);
        assert!(!again[0].counted, "as the caller says of the entry");
        assert_eq!(
            (again[0].yes, again[0].accepted),
            (asked[0].yes, asked[0].accepted)
        );

        assert!(
            asks.questions(&rows, BlockHeight::new(13), |_, _| None)
                .questions
                .is_empty()
        );
        assert!(
            asks.kept.is_empty(),
            "nothing is kept for a question not standing"
        );
        assert_eq!(asks.seen.len(), 1, "one tip kept a hearing row");

        // A row that stops hearing is forgotten with its wait.
        store.fold(&settling(7, 2, TickHalf::Legs, &[1]));
        let rows = MemberIndex::load(&store, LOCAL);
        let _ = asks.questions(&rows, BlockHeight::new(14), |_, _| Some(true));
        assert!(asks.seen.is_empty());
    }

    /// The fold says which cells its rows heard and which of them moved
    /// an entry. A reading a second block carries again is heard and
    /// changes nothing, which is what every proposer building on a block
    /// not yet committed spends; an absent leaf is read with its row and
    /// marker, three cells; and a name no hearing row answers to is not
    /// counted at all.
    #[test]
    fn the_fold_tells_the_cells_it_heard_from_the_ones_that_changed_an_entry() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let [unheard, ..] = cells_of(PEER, 2);
        let mut rows = MemberIndex::load(&listening(), LOCAL);
        let cells = |keys: &[SubstateKey], anchor: Anchor| {
            BTreeMap::from([(anchor, keys.iter().copied().collect::<BTreeSet<_>>())])
        };

        let yes = [reading(
            at(7),
            &[(leaf, peers_yes(1)), (unheard, peers_yes(2))],
            &[1, 2],
        )];
        let first = rows.advance(&carrying(6, &yes));
        assert_eq!(first.carried, cells(&[leaf], at(7)));
        assert_eq!(first.changed, first.carried);
        assert_eq!(first.counts(), (1, 1));

        let again = rows.advance(&carrying(7, &yes));
        assert_eq!(again.carried, cells(&[leaf], at(7)));
        assert!(again.changed.is_empty(), "the copy moves no entry");
        assert_eq!(again.counts(), (1, 0));

        let left = [reading(
            at(8),
            &[
                (leaf, Inclusion::Absent),
                (row, Inclusion::Absent),
                (marker, PRESENT),
            ],
            &[1],
        )];
        let exit = rows.advance(&carrying(8, &left));
        assert_eq!(exit.carried, cells(&[leaf, row, marker], at(8)));
        assert_eq!(exit.counts(), (3, 3));
        assert_eq!(
            rows.members[&tx(1)].hearing.to_vec(),
            from_peer(mark(0, 8), Some(Said::Left))
        );
    }

    /// One reading of a sibling's verdict as a block carries it: `keys`
    /// proved against `store`'s tree at `root`, naming `named`.
    fn proven_reading(
        store: &MemoryStore,
        anchor: Anchor,
        keys: &[SubstateKey],
        named: &[TxHash],
    ) -> StateClaim {
        let jmt_keys: Vec<JmtKey> = keys.iter().map(SubstateKey::to_bytes).collect();
        let proof = Tree::<Blake3Hasher, 1>::prove(
            store,
            &NodeKey::new(1, shard_prefix_path(anchor.shard)),
            &jmt_keys,
        )
        .expect("every key proves against the held version");
        let proof = MerkleInclusionProof::new(proof.encode());
        let cells = proof
            .inclusions(anchor.state_root, anchor.shard, keys)
            .expect("the proof answers for its keys");
        let claim = StateClaim::new(anchor, cells, proof).hearing(named.iter().copied());
        assert!(claim.is_well_formed());
        claim.verify().expect("the reading proves itself");
        claim
    }

    /// `count` keys under `shard`'s prefix, each under an owner of its
    /// own, from a fixed seed: the cells of every other owner a shard's
    /// tree holds.
    fn other_owners(shard: ShardId, count: usize, seed: u64) -> Vec<SubstateKey> {
        let root_path = shard_prefix_path(shard);
        let shard_first = root_path.as_bytes().first().copied().unwrap_or(0);
        let keep = u8::try_from(root_path.len().min(8)).unwrap_or(8);
        let mut state = seed;
        let mut next = move || {
            // splitmix64: a fixed sequence, so the measurement is one figure.
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        (0..count)
            .map(|_| {
                let mut body = [0u8; 31];
                for chunk in body.chunks_mut(8) {
                    let word = next().to_le_bytes();
                    chunk.copy_from_slice(&word[..chunk.len()]);
                }
                if keep > 0 {
                    let mask = 0xFFu8 << (8 - keep);
                    body[0] = (body[0] & !mask) | (shard_first & mask);
                }
                let mut local = [0u8; 16];
                for chunk in local.chunks_mut(8) {
                    chunk.copy_from_slice(&next().to_le_bytes());
                }
                SubstateKey {
                    owner: Address::new(body, AddressClass::Component),
                    local: LocalKey(local),
                }
            })
            .collect()
    }

    /// What one population costs a verdict reading, in the order the
    /// figures are pinned: a one-cell reading alone, mean and largest; a
    /// three-cell reading alone, mean and largest; then one claim's
    /// bytes for each batch of [`BATCHES`], in that order.
    type ReadingCosts = [usize; 9];

    /// One way readings are proved together in a claim.
    struct Batch {
        /// How many readings the claim holds.
        readings: usize,
        /// How many cells each reading is: one for a leaf present,
        /// three for a leaf absent.
        cells: usize,
        /// What brings a claim of this shape.
        from: &'static str,
    }

    /// The batches priced, the three an answer brings first. The last
    /// two fill a claim to its cell cap: only one push of a block that
    /// changed that many leaves brings such a claim, and the readings of
    /// separate answers reach it only by a proof merge, which nothing
    /// provides.
    const BATCHES: [Batch; 5] = [
        Batch {
            readings: VERDICT_FETCH_READINGS,
            cells: 1,
            from: "a fetch return of present leaves",
        },
        Batch {
            readings: 64,
            cells: 1,
            from: "a push of 64 present leaves",
        },
        Batch {
            readings: VERDICT_FETCH_READINGS,
            cells: 3,
            from: "a fetch return of absent leaves",
        },
        Batch {
            readings: ONE_CELL_BATCH,
            cells: 1,
            from: "upper bound: one push at the cell cap, or a proof merge nothing provides",
        },
        Batch {
            readings: THREE_CELL_BATCH,
            cells: 3,
            from: "upper bound: one push at the cell cap, or a proof merge nothing provides",
        },
    ];

    /// How many questions one verdict fetch asks, and so how many
    /// readings one fetch return proves together.
    const VERDICT_FETCH_READINGS: usize = 21;

    /// The owners a sibling's tree holds beside its own.
    const OTHER_OWNERS: usize = 20_000;
    /// The committed markers under the shard's owner for transactions
    /// that are no core member's: one for every transaction a block
    /// carried, each standing until its validity end and the committed
    /// grace past it.
    const OTHER_MARKERS: usize = 100_000;
    /// One-cell readings to a claim at its cell cap.
    const ONE_CELL_BATCH: usize = MAX_PROOFS_PER_QUERY;
    /// Three-cell readings to a claim at its cell cap.
    const THREE_CELL_BATCH: usize = MAX_PROOFS_PER_QUERY / 3;

    /// What verdict readings cost at `stated` members standing stated
    /// and as many gone, on a tree shaped as a sibling's is.
    fn reading_costs(stated: usize) -> ReadingCosts {
        const SAMPLE: usize = 256;
        let member = |seed: usize| TxHash::from(Hash::from_bytes(&seed.to_le_bytes()));
        let standing: Vec<TxHash> = (0..stated).map(member).collect();
        let gone: Vec<TxHash> = (stated..2 * stated).map(member).collect();
        let mut leaves = other_owners(PEER, OTHER_OWNERS, 20_000);
        for &tx in &standing {
            leaves.extend(cells_of_member(PEER, tx));
            leaves.push(seat_leaf(PEER, tx));
        }
        for &tx in &gone {
            leaves.push(cells_of_member(PEER, tx)[2]);
        }
        leaves.extend(
            (0..OTHER_MARKERS).map(|seed| cells_of_member(PEER, member(usize::MAX / 2 + seed))[2]),
        );
        let root_path = shard_prefix_path(PEER);
        let updates: BTreeMap<JmtKey, Option<LeafValue>> = leaves
            .iter()
            .map(|key| {
                let value = key.to_bytes();
                (
                    key.to_bytes(),
                    Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
                )
            })
            .collect();
        let mut store = MemoryStore::new();
        let applied =
            Tree::<Blake3Hasher, 1>::apply_updates_at(&store, None, 1, &root_path, &updates)
                .expect("a fresh tree takes its first version");
        store.apply(&applied);
        let anchor = Anchor {
            shard: PEER,
            height: BlockHeight::new(1),
            state_root: StateRoot::from_raw(Hash::from_hash_bytes(&applied.root_hash)),
            ts: WeightedTimestamp::ZERO,
        };

        let one_cell = |tx: TxHash| vec![cells_of_member(PEER, tx)[0]];
        let three_cells = |tx: TxHash| cells_of_member(PEER, tx).to_vec();
        let alone = |members: &[TxHash], cells: &dyn Fn(TxHash) -> Vec<SubstateKey>| {
            let weights: Vec<usize> = members
                .iter()
                .take(SAMPLE)
                .map(|&tx| proven_reading(&store, anchor, &cells(tx), &[tx]).wire_weight())
                .collect();
            (
                weights.iter().sum::<usize>() / weights.len(),
                *weights.iter().max().expect("a sample"),
            )
        };
        let batched = |batch: &Batch| {
            let (members, cells): (&[TxHash], &dyn Fn(TxHash) -> Vec<SubstateKey>) =
                if batch.cells == 1 {
                    (&standing, &one_cell)
                } else {
                    (&gone, &three_cells)
                };
            let named = &members[..batch.readings];
            let keys: Vec<SubstateKey> = named.iter().flat_map(|&tx| cells(tx)).collect();
            proven_reading(&store, anchor, &keys, named).wire_weight()
        };
        let (yes_mean, yes_max) = alone(&standing, &one_cell);
        let (left_mean, left_max) = alone(&gone, &three_cells);
        let [fetched_yes, pushed_yes, fetched_left, full_yes, full_left] =
            BATCHES.map(|batch| batched(&batch));
        [
            yes_mean,
            yes_max,
            left_mean,
            left_max,
            fetched_yes,
            pushed_yes,
            fetched_left,
            full_yes,
            full_left,
        ]
    }

    /// What verdict readings cost the claims section, measured on a tree
    /// shaped as a sibling's is: twenty thousand other owners under the
    /// shard's prefix, and under the shard's one owner a row, a seat, a
    /// verdict leaf and a committed marker for each stated member, a
    /// marker alone for each member that has left, and a hundred
    /// thousand markers of the transactions that are no core member's.
    /// A reading of a stated member is its leaf, one cell; a reading of
    /// a member that left is its absent leaf beside its absent row and
    /// its marker, three. Each is weighed carried alone and in each
    /// batch of [`BATCHES`], one claim at one anchor, and against what
    /// one block's section holds by its bytes and by its count of
    /// claims.
    ///
    /// The figures are pinned, so a change to the encoding, the tree or
    /// the method moves them in the open.
    #[test]
    fn a_block_of_verdict_readings_fits_the_claims_budget() {
        const PINNED: [(usize, ReadingCosts); 3] = [
            (
                256,
                [1071, 1139, 2387, 2630, 7994, 19_212, 24_683, 61_585, 84_960],
            ),
            (
                3_072,
                [
                    1188, 1300, 2749, 2983, 10_531, 26_890, 29_502, 90_212, 101_104,
                ],
            ),
            (
                12_288,
                [
                    1252, 1364, 2875, 3111, 11_977, 31_098, 32_727, 106_437, 112_232,
                ],
            ),
        ];
        for (stated, pinned) in PINNED {
            let costs = reading_costs(stated);
            let [yes_mean, yes_max, left_mean, left_max, batches @ ..] = costs;
            // What one block's section holds: by bytes, and by claims.
            let claims_fit =
                |weight: usize| (MAX_STATE_CLAIMS_BYTES / weight).min(MAX_STATE_CLAIMS_PER_BLOCK);
            println!(
                "verdict readings at {stated} stated members and {stated} gone, among \
                 {OTHER_OWNERS} other owners and {OTHER_MARKERS} other markers: {costs:?}",
            );
            println!(
                "  one-cell alone: mean {yes_mean}, max {yes_max} bytes; {} fit a block of \
                 {MAX_STATE_CLAIMS_BYTES} bytes and {MAX_STATE_CLAIMS_PER_BLOCK} claims",
                claims_fit(yes_mean),
            );
            println!(
                "  three-cell alone: mean {left_mean}, max {left_max} bytes; {} fit",
                claims_fit(left_mean),
            );
            assert!(state_claims_admit_block(yes_max) && state_claims_admit_block(left_max));
            for (batch, weight) in BATCHES.iter().zip(batches) {
                let Batch {
                    readings,
                    cells,
                    from,
                } = *batch;
                println!(
                    "  {cells}-cell batched {readings} to a claim ({from}): {weight} bytes, {} \
                     a reading; {} claims and {} readings fit",
                    weight / readings,
                    claims_fit(weight),
                    claims_fit(weight) * readings,
                );
                assert!(state_claims_admit_block(weight));
                let alone = if cells == 1 { yes_mean } else { left_mean };
                assert!(
                    weight / readings < alone,
                    "a batched reading shares its proof and weighs less than one alone",
                );
            }
            assert_eq!(
                costs, pinned,
                "the measured costs at {stated} stated members are the ones pinned",
            );
        }
    }

    /// What a block spent on verdict readings is told three ways: the
    /// claims naming a member, the cells of those a hearing row read,
    /// and the ones that changed its entry, each claim's bytes shared
    /// among its cells. A block naming no member spent nothing.
    #[test]
    fn a_blocks_verdict_spend_is_measured_over_what_its_rows_heard() {
        let [heard, unheard] = [tx(1), tx(2)];
        let keys = [verdict_leaf(PEER, heard), verdict_leaf(PEER, unheard)];
        let root_path = shard_prefix_path(PEER);
        let updates: BTreeMap<JmtKey, Option<LeafValue>> = keys
            .iter()
            .chain(&other_owners(PEER, 64, 7))
            .map(|key| {
                let value = key.to_bytes();
                (
                    key.to_bytes(),
                    Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
                )
            })
            .collect();
        let mut store = MemoryStore::new();
        let applied =
            Tree::<Blake3Hasher, 1>::apply_updates_at(&store, None, 1, &root_path, &updates)
                .expect("a fresh tree takes its first version");
        store.apply(&applied);
        let anchor = Anchor {
            state_root: StateRoot::from_raw(Hash::from_hash_bytes(&applied.root_hash)),
            ..at(7)
        };
        let both = proven_reading(&store, anchor, &keys, &[heard, unheard]);
        let bare = proven_reading(&store, anchor, &other_owners(PEER, 64, 7)[..1], &[]);
        let claims = [both.clone(), bare.clone()];

        let mut rows = MemberIndex::load(&listening(), LOCAL);
        let cells = rows.advance(&carrying(6, &claims));
        let only_heard = both.wire_weight() / 2;
        assert_eq!(
            cells.measures(&claims),
            Some(VerdictMeasures {
                cells: [2, 1, 1],
                bytes: [both.wire_weight(), only_heard, only_heard],
            }),
            "the bare claim is no verdict reading, and the cell no row read is named only",
        );

        let again = rows.advance(&carrying(7, &claims));
        assert_eq!(
            again.measures(&claims),
            Some(VerdictMeasures {
                cells: [2, 1, 0],
                bytes: [both.wire_weight(), only_heard, 0],
            }),
            "a copy is carried and changes nothing",
        );
        assert_eq!(again.measures(&[bare]), None);
    }

    /// The members a block settles are counted as core where their row
    /// holds a seat when the block lands: stated, or in flight beside a
    /// counterpart, and no other.
    #[test]
    fn the_core_members_a_block_settles_are_the_seated_ones() {
        let rows = MemberIndex::load(&listening(), LOCAL);
        let settles = |seeds: &[u8]| rows.seated_among(&settling(6, 2, TickHalf::Legs, seeds));
        assert_eq!(settles(&[1]), 1, "a stated row");
        assert_eq!(settles(&[2]), 1, "a row in flight beside a counterpart");
        assert_eq!(settles(&[3, 4]), 0, "a pending row and a released one");
        assert_eq!(settles(&[1, 2, 3, 4, 9]), 2);
    }

    /// `tx`'s verdict leaf, member row and committed marker on `shard`.
    fn cells_of_member(shard: ShardId, tx: TxHash) -> [SubstateKey; 3] {
        [
            verdict_leaf(shard, tx),
            member_row_leaf(shard, tx),
            committed_tx_cell_key(shard, tx, validity_end()),
        ]
    }

    /// The cell a tree holds at `key` where its entries are `store`'s.
    fn cell_of(store: &Entries, key: SubstateKey) -> Option<Vec<u8>> {
        store
            .0
            .iter()
            .find(|(entry, _)| entry_leaf_key(&ProtocolHasher, **entry) == key)
            .map(|(entry, value)| entry_leaf_value(entry, value))
    }

    /// A block that states a member writes its leaf, which the sibling
    /// reads as that one cell; a block that takes the stated row away
    /// deletes the leaf, which the sibling reads beside the row and the
    /// marker keyed by the row's own validity end. A member whose leaf a
    /// block leaves as it was changes nothing a sibling reads.
    #[test]
    fn a_block_names_each_leaf_it_writes_or_deletes_for_the_siblings_that_read_it() {
        let [leaf, row, marker] = cells_of(LOCAL, 1);
        let changed = |before: &Entries, after: &Entries| {
            leaf_changes(
                LOCAL,
                [tx(1), tx(2)],
                |key| cell_of(before, key),
                |key| cell_of(after, key),
            )
        };
        let mut store = Entries::default();
        store.fold(&committing_far(1, &[1, 2]));
        let committed = store.0.clone();
        store.fold(&naming(2, vec![sharing(1, 7), sharing(2, 7)]));
        assert!(changed(&Entries(committed), &store).is_empty());

        let named = store.0.clone();
        store.fold(&stating(3, 2, &[], &[1]));
        assert_eq!(
            changed(&Entries(named), &store),
            vec![VerdictChange {
                target: PEER,
                tx: tx(1),
                leaf,
                beside: None,
            }],
        );

        let stated = store.0.clone();
        store.fold(&settling(4, 2, TickHalf::Legs, &[1]));
        assert_eq!(
            changed(&Entries(stated), &store),
            vec![VerdictChange {
                target: PEER,
                tx: tx(1),
                leaf,
                beside: Some((row, marker)),
            }],
        );
        let settled = Entries(store.0.clone());
        assert!(changed(&settled, &store).is_empty());
    }

    /// What a block writes is read off the claims it carries: the
    /// readings its inputs hold are the ones gathered from its own claims
    /// section, and folding them records what the claim says.
    #[test]
    fn a_blocks_inputs_gather_the_claims_it_carries() {
        let [leaf, ..] = cells_of(PEER, 1);
        let block = with_state_claims(
            make_live_block(
                LOCAL,
                BlockHeight::new(6),
                0,
                ValidatorId::new(0),
                Vec::new(),
                Vec::new(),
            ),
            vec![reading(at(7), &[(leaf, peers_yes(1))], &[1])],
        );
        let inputs = MemberInputs::of(&block, GRID);
        assert!(!inputs.heard.is_empty());
        assert_eq!(
            inputs.heard,
            AnchorReadings::among(block.state_claims(), GRID)
        );

        let mut store = listening();
        store.fold(&inputs);
        assert_eq!(heard_by(&store, 1), from_peer(mark(0, 7), Some(Said::Yes)));
    }

    /// What a claim carries is gathered once per anchor: only anchors a
    /// claim names a member at, only the names whose verdict cell rides
    /// there, each once, and every cell of every claim at the anchor.
    #[test]
    fn readings_are_gathered_by_the_anchors_that_name_a_member() {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let [other, ..] = cells_of(PEER, 2);
        let claims = [
            reading(at(7), &[(leaf, Inclusion::Absent)], &[1, 2, 9]),
            reading(at(7), &[(row, Inclusion::Absent), (marker, PRESENT)], &[1]),
            reading(at(8), &[(other, PRESENT)], &[]),
        ];
        let gathered = AnchorReadings::among(&claims, GRID);
        assert_eq!(
            gathered,
            vec![AnchorReadings {
                anchor: at(7),
                mark: mark(0, 7),
                names: vec![tx(1)],
                cells: BTreeMap::from([
                    (leaf, Inclusion::Absent),
                    (row, Inclusion::Absent),
                    (marker, PRESENT),
                ]),
            }],
        );
        assert!(AnchorReadings::among(&claims[2..3], GRID).is_empty());
    }

    /// One reading of [`PEER`] about member `1`: the height and epoch of
    /// its anchor, and what the anchor's cells say.
    type Drawn = (u64, u64, u8);

    /// The claim a drawn reading is carried as. What an anchor says is a
    /// function of the anchor, as one committed state says one thing.
    fn drawn_claim((height, epoch, _): Drawn) -> (StateClaim, Heard) {
        let [leaf, row, marker] = cells_of(PEER, 1);
        let anchor = anchor_on(PEER, height, epoch * GRID_MS + height);
        let (cells, said) = match (height + 3 * epoch) % 5 {
            0 => (vec![(leaf, peers_yes(1))], Some(Said::Yes)),
            1 => (vec![(leaf, PRESENT)], Some(Said::Left)),
            2 => (
                vec![
                    (leaf, Inclusion::Absent),
                    (row, Inclusion::Absent),
                    (marker, PRESENT),
                ],
                Some(Said::Left),
            ),
            3 => (
                vec![
                    (leaf, Inclusion::Absent),
                    (row, PRESENT),
                    (marker, Inclusion::Absent),
                ],
                None,
            ),
            _ => {
                let accepted = VerdictLeaf::Accepted {
                    tx: tx(1),
                    awaited: Capped::from_array([LOCAL, PEER]),
                };
                (
                    vec![(
                        leaf,
                        Inclusion::Present(verdict_hash(PEER, tx(1), &accepted)),
                    )],
                    Some(Said::Accepted),
                )
            }
        };
        (
            reading(anchor, &cells, &[1]),
            Heard {
                shard: PEER,
                mark: ReadMark::of(&anchor, GRID),
                said,
            },
        )
    }

    proptest! {
        /// Readings arriving in any order, one block each or cut into
        /// blocks anywhere, leave the row holding the one taken at the
        /// highest mark, whatever it and the ones before it say.
        #[test]
        fn the_newest_reading_wins_in_any_arrival_order(
            drawn in vec((1u64..12, 0u64..3, any::<u8>()), 1..10),
        ) {
            let newest = drawn
                .iter()
                .map(|&reading| drawn_claim(reading).1)
                .max_by_key(|heard| heard.mark)
                .expect("at least one reading");

            let mut store = listening();
            let mut height = 6;
            let mut block: Vec<StateClaim> = Vec::new();
            for &(at_height, epoch, cut) in &drawn {
                let (claim, _) = drawn_claim((at_height, epoch, cut));
                if !block.iter().any(|held| held.anchor == claim.anchor) {
                    block.push(claim);
                }
                if cut % 2 == 0 {
                    store.fold(&carrying(height, &block));
                    block.clear();
                    height += 1;
                }
            }
            store.fold(&carrying(height, &block));
            prop_assert_eq!(heard_by(&store, 1), vec![newest]);

            let mut reversed = listening();
            for (offset, &reading) in drawn.iter().rev().enumerate() {
                reversed.fold(&carrying(6 + offset as u64, &[drawn_claim(reading).0]));
            }
            prop_assert_eq!(heard_by(&reversed, 1), vec![newest]);
        }
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
        /// Carry the stating half of the tick `pick` chooses, settling
        /// the refusals of the first seeds and stating a yes for each of
        /// the second.
        State(u8, Vec<u8>, Vec<u8>),
        /// Discard the tick `pick` chooses for the cause `cause` picks.
        Discard(u8, u8, u8),
        /// Fate these.
        Fate(Vec<u8>),
        /// End these.
        End(Vec<u8>),
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
            2 => (any::<u8>(), vec(seed(), 0..3), vec(seed(), 0..4))
                .prop_map(|(pick, refused, yes)| Step::State(pick, refused, yes)),
            2 => (any::<u8>(), 0u8..3, seed())
                .prop_map(|(pick, cause, member)| Step::Discard(pick, cause, member)),
            1 => vec(seed(), 1..6).prop_map(Step::Fate),
            1 => vec(seed(), 1..6).prop_map(Step::End),
        ]
    }

    /// What a block's claims say of [`PEER`]'s members, as raw choices:
    /// for each `(seed, height, epoch, shape)`, a reading of `seed` at
    /// the anchor `height` and `epoch` pick, of the shape `shape` picks.
    type Hears = Vec<(u8, u64, u64, u8)>;

    /// What a block carries beside its step: the readings its claims
    /// come to, and whether it states every member it can.
    fn listens() -> impl Strategy<Value = (Hears, bool)> {
        (
            vec((1u8..=8, 1u64..6, 0u64..3, 0u8..7), 0..5),
            any::<bool>(),
        )
    }

    /// The readings `hears` come to: every chosen member named at its
    /// anchor, its cells there as the last choice for it gives them, and
    /// each anchor's cells cut into two claims.
    fn heard_of(hears: &Hears) -> Vec<AnchorReadings> {
        let end = Deadline::of(WeightedTimestamp::from_millis(90_000)).validity_end();
        let mut anchors: BTreeMap<Anchor, BTreeMap<u8, u8>> = BTreeMap::new();
        for &(seed, height, epoch, shape) in hears {
            anchors
                .entry(anchor_on(PEER, height, epoch * GRID_MS + height))
                .or_default()
                .insert(seed, shape);
        }
        let mut claims = Vec::new();
        for (anchor, members) in anchors {
            let mut cells: Vec<(SubstateKey, Inclusion)> = Vec::new();
            for (&seed, &shape) in &members {
                let leaf = verdict_leaf(PEER, tx(seed));
                let row = member_row_leaf(PEER, tx(seed));
                let marker = committed_tx_cell_key(PEER, tx(seed), end);
                match shape {
                    0 => cells.push((leaf, peers_yes(seed))),
                    1 => cells.push((leaf, PRESENT)),
                    2 => cells.extend([
                        (leaf, Inclusion::Absent),
                        (row, Inclusion::Absent),
                        (marker, PRESENT),
                    ]),
                    3 => cells.extend([
                        (leaf, Inclusion::Absent),
                        (row, PRESENT),
                        (marker, Inclusion::Absent),
                    ]),
                    4 => cells.push((leaf, Inclusion::Absent)),
                    5 => cells.push((row, Inclusion::Absent)),
                    _ => {
                        let accepted = VerdictLeaf::Accepted {
                            tx: tx(seed),
                            awaited: Capped::from_array([LOCAL, PEER]),
                        };
                        cells.push((
                            leaf,
                            Inclusion::Present(verdict_hash(PEER, tx(seed), &accepted)),
                        ));
                    }
                }
            }
            cells.sort_unstable();
            let names: Vec<u8> = members.keys().copied().collect();
            for piece in cells.chunks(cells.len().div_ceil(2).max(1)) {
                claims.push(reading(anchor, piece, &names));
            }
        }
        AnchorReadings::among(&claims, GRID)
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

    /// `seed`'s member line on the terms `shape` picks, reserving
    /// `reserves`. A member a counterpart shares the verdict on awaits
    /// [`PEER`], so its row hears once it states.
    fn shaped(seed: u8, shape: u8, reserves: Reserves) -> TickLine {
        let settlement =
            [Settlement::Alone, Settlement::Shared, Settlement::Awaited][usize::from(shape % 3)];
        TickLine::Member {
            tx: tx(seed),
            joins: [Joins::Executes, Joins::Aborted][usize::from(shape / 3)],
            settlement,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: if settlement == Settlement::Shared {
                Capped::from_array([PEER])
            } else {
                Capped::empty()
            },
            charge: stub_abort_charge(seed),
            share: 0,
            reserves,
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
                        let reserves = stated.map_or_else(
                            || {
                                rows.members
                                    .get(&tx(seed))
                                    .map_or_else(Capped::empty, |row| row.reserves.clone())
                            },
                            |(on, amount)| Capped::from_array([(vault(on), amount)]),
                        );
                        shaped(seed, shape, reserves)
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
            Step::State(pick, refused, yes) => stating(height, tick_at(*pick), refused, yes),
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
            Step::End(ended) => naming(
                height,
                ended
                    .iter()
                    .map(|&seed| TickLine::End { tx: tx(seed) })
                    .collect(),
            ),
        }
    }

    /// The block `step` is at `height` over `rows`, carrying the claims
    /// `hears` come to and, where `states`, the stating half of every
    /// tick holding a row in flight on shared terms, a yes for each such
    /// row: so rows that hear are common among the rows a run reaches.
    fn listening_block(
        step: &Step,
        (hears, states): &(Hears, bool),
        height: u64,
        rows: &MemberIndex,
    ) -> MemberInputs {
        let mut block = block_of(step, height, rows);
        block.heard = heard_of(hears);
        if *states {
            let mut yes: BTreeMap<BlockHeight, Vec<(TxHash, GlobalReceiptHash)>> = BTreeMap::new();
            for row in rows.members.values() {
                if let RowState::InFlight {
                    tick,
                    settlement: Settlement::Shared,
                    ..
                } = row.state
                {
                    yes.entry(tick)
                        .or_default()
                        .push((row.tx, GlobalReceiptHash::ZERO));
                }
            }
            block
                .settled
                .extend(yes.into_iter().map(|(tick, stated)| SettledHalf {
                    tick: TickId::new(LOCAL, tick),
                    half: TickHalf::Stated,
                    deleted: Vec::new(),
                    stated,
                    reclaimed: Vec::new(),
                }));
        }
        block
    }

    proptest! {
        /// Through any sequence of blocks, a manifest of end lines naming
        /// every member writes nothing over the rows left standing.
        #[test]
        fn an_end_line_writes_nothing_over_any_rows(
            steps in vec(step(), 1..24),
        ) {
            let mut store = Entries::default();
            let mut rows = MemberIndex::empty(LOCAL);
            for (at, step) in steps.iter().enumerate() {
                let block = carried(&block_of(step, at as u64 + 1, &rows));
                store.fold(&block);
                rows.advance(&block);
                let ends = naming(
                    at as u64 + 2,
                    (1..=8).map(|seed| TickLine::End { tx: tx(seed) }).collect(),
                );
                prop_assert!(member_writes(&store, &ends).is_empty(), "after {:?}", step);
            }
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
            steps in vec((step(), listens()), 1..24),
        ) {
            let mut store = Entries::default();
            let mut cache = MemberIndex::empty(LOCAL);
            for (at, (step, listens)) in steps.iter().enumerate() {
                let block = listening_block(step, listens, at as u64 + 1, &cache);
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
        /// standing in it outside its determined half, in flight or
        /// stated, and no tick stands owing nothing.
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

        /// Through any sequence of blocks, a verdict leaf stands exactly
        /// beside each stated row, holding what the row gives, and
        /// beside no other.
        #[test]
        fn a_verdict_leaf_stands_exactly_beside_a_stated_row(
            steps in vec(step(), 1..24),
        ) {
            let mut store = Entries::default();
            let mut rows = MemberIndex::empty(LOCAL);
            let (owner, collection) = MemberCollection::Verdicts.of(LOCAL);
            for (at, step) in steps.iter().enumerate() {
                let block = carried(&block_of(step, at as u64 + 1, &rows));
                store.fold(&block);
                rows.advance(&block);

                let leaves: BTreeMap<u128, Vec<u8>> = store
                    .0
                    .iter()
                    .filter(|(key, _)| key.owner == owner && key.collection == collection)
                    .map(|(key, bytes)| (key.order, bytes.clone()))
                    .collect();
                let given: BTreeMap<u128, Vec<u8>> = rows
                    .members
                    .values()
                    .filter_map(|row| Some((member_order(row.tx), to_vec(&row.verdict(LOCAL)?).unwrap())))
                    .collect();
                prop_assert_eq!(&leaves, &given, "after {:?}", step);
            }
        }

        /// A proposer and a voter fold a block's content before its
        /// lines are named and then the block as carried. Whatever the
        /// block carries, the claims naming its members' verdicts among
        /// it, the second fold leaves every entry of the family, each
        /// tick's count and each row's hearing among them, as one fold
        /// of the carried block leaves it; its claims folded again over
        /// the rows it left write nothing; and only a stated row holds a
        /// reading.
        #[test]
        fn a_block_folded_twice_writes_what_one_fold_does(
            steps in vec((step(), listens()), 1..24),
        ) {
            let mut once = Entries::default();
            let mut rows = MemberIndex::empty(LOCAL);
            for (at, (step, listens)) in steps.iter().enumerate() {
                let block = listening_block(step, listens, at as u64 + 1, &rows);
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
                prop_assert!(
                    rows.members
                        .values()
                        .all(|row| row.hearing.is_empty() || row.state.hears()),
                    "after {:?}",
                    step
                );
                let listening_only = MemberInputs {
                    heard: carrying.heard.clone(),
                    ..MemberInputs::still(LOCAL)
                };
                prop_assert!(
                    member_writes(&once, &listening_only).is_empty(),
                    "heard again after {:?}",
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
                MemberSections {
                    certificates: &[],
                    records: &[],
                    claims: &[],
                },
                EpochWindows::new(0),
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
