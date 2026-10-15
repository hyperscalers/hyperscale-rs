//! Which committed transactions join a block's tick: the one rule a
//! proposer names member lines by and a voter checks them against.
//!
//! A member joins when everything it needs has committed — its
//! counterparts' bundles and the crossings its legs consume, and its
//! payer's engagement wait over one way or the other — and no cell an
//! in-flight leg holds provisionally refuses it. Every input is read off
//! committed content at the block's parent, so two replicas at different
//! committed tips name one list.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_effects_bridge::is_protocol_vault;
use hyperscale_hbor::Capped;
use hyperscale_storage::{MemberIndex, MemberRow, RowState, member_row_leaf, seat_leaf};
use hyperscale_types::{
    AbortCharge, Address, Anchor, BlockHeight, CollectionId, Crossings, Deadline, Decision,
    DeclaredKey, DiscardCause, Evidence, Hears, Holds, Inclusion, Joins, MAX_TICK_LINES_PER_BLOCK,
    MemberTerms, Mode, ModeKind, PriceTable, Reach, Reserves, Role, Settlement, ShardId, ShardTrie,
    SiblingView, Source, StateClaim, SubstateKey, TickId, TickLine, TopologySnapshot, Transaction,
    TxHash, Value, WeightedTimestamp, Window, compatible, decide, tick_manifest_admits_block,
    tick_manifest_admits_members, value_of, verdict_leaf,
};
use hyperscale_vm_effects::{CrossingId, Kind};
use hyperscale_vm_types::{AddressClass, LegShape, ProtocolHasher};

use crate::legs::{Classified, Member};

/// One thing a cross-shard member waits for before it can run.
///
/// The kind is part of the key, because a shard can owe both and an
/// arrival of one must not read as an answer to the other. What a member
/// files is its execution scope minus itself: a member running only its
/// own legs files no [`CommittedState`](Self::CommittedState) at all, a
/// core member files one per other core shard, and any member consuming
/// a value edge its own shard does not produce files the
/// [`Crossing`](Self::Crossing) for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Requirement {
    /// A counterpart's committed state for the transaction, carried by a
    /// bundle from that shard.
    CommittedState(ShardId),
    /// A crossing's record cell, read live by a committed state claim
    /// naming the transaction as its issuer.
    ///
    /// The key alone: the record sits under the producer's prefix, and
    /// admission holds the claim's anchor to the shard that owned that
    /// prefix at the anchor's own clock, so whoever wrote it, a claim
    /// that admits speaks for the one root the record means anything
    /// under. The same claim is what the arrival is read from.
    Crossing {
        /// The record cell.
        key: SubstateKey,
    },
}

/// What `member`, a divided member of a transaction with these `legs`,
/// files before it can run: its execution scope minus itself, and the
/// crossings the legs it runs consume.
#[must_use]
pub fn requirements_of(member: &Member, legs: &[LegShape]) -> BTreeSet<Requirement> {
    divided_requirements(legs, member.classified(), member.local())
}

/// What a divided member of a transaction files: its execution scope
/// minus itself, and the crossings the legs it runs consume.
///
/// A member running only its own legs is in no core set and files no
/// committed state at all; a core member files one per other core shard;
/// and either files a crossing for every escrowed value edge landing on
/// it from a node it does not run. Nothing else — the engagement exchange a whole
/// shape files is not here, since a divided member's inbound escrow is
/// its engagement and the crossing bundle it consumes is its
/// counterpart's commitment.
#[must_use]
pub fn divided_requirements(
    legs: &[LegShape],
    classified: &Classified,
    local: ShardId,
) -> BTreeSet<Requirement> {
    let mut requirements: BTreeSet<Requirement> = BTreeSet::new();
    let core = classified.core();

    if core.contains(&local) {
        requirements.extend(
            core.iter()
                .filter(|&&shard| shard != local)
                .map(|&shard| Requirement::CommittedState(shard)),
        );
    }
    // Every member admits the whole manifest, and admission resolves a
    // component call against the target's own record — a declared read
    // of its leaf, provisioned by the shard holding it. So a member waits
    // for the commit-time bundle of every remote shard holding a
    // component the transaction calls, which is where the records it
    // cannot read itself arrive. A principal has no record to read, so a
    // transaction reaching only accounts waits on nobody here, and a
    // shard that only takes delivery commits nothing and sends no bundle.
    if let Some(trie) = classified.placement() {
        requirements.extend(
            legs.iter()
                .filter(|leg| leg.target.class() == AddressClass::Component)
                .map(|leg| trie.shard_for_prefix(leg.target))
                .filter(|&shard| shard != local && classified.commits_at(shard))
                .map(Requirement::CommittedState),
        );
    }
    // A member waits only on the escrowed arrivals feeding its core
    // share: an owed crossing is credited by the consumer's commit fold,
    // and an inbound leg consumes nothing that crosses, so a member on
    // the far side of a core waits on nothing at all — which is what
    // lets the core's arrival exist in the first place.
    requirements.extend(
        classified
            .edges()
            .iter()
            .filter(|edge| edge.to.contains(&local) && edge.crossing.kind == Kind::Escrowed)
            .map(|edge| Requirement::Crossing {
                key: edge.crossing.id.record_key(&ProtocolHasher),
            }),
    );
    requirements
}

/// How unresolved legs are reaching the cells they claimed.
///
/// A cross-shard leg's local writes are provisional until its tick
/// resolves. Whether that stops a later transaction depends entirely on
/// *how* each of them reaches the cell, and the kernel already decides
/// that: [`compatible`] is the same relation it uses to schedule a batch,
/// asked here across a boundary the batch cannot see.
///
/// The two commutative modes are what make this worth asking. A delta
/// and a reservation each say what they moved rather than what the cell
/// ends at, so neither depends on seeing the other and settlement
/// composes them in any order — two payments on one vault need not take
/// turns. A fresh read does depend on seeing it, and an exclusive write
/// carries an absolute that cannot be composed with anything, so both
/// still wait.
///
/// One commutative pair waits as well: a debit beside an in-flight delta
/// that debits. A reservation states its amount, which is held against
/// the cell while its leg is unresolved, so a later debit is judged with
/// it counted. A debiting delta states none, and an unresolved leg's
/// writes are in no later tick's view, so nothing stands for what it
/// took: a second debit of the cell, a reservation or another delta,
/// would be judged against a balance that hides the first, and the two
/// could settle past the cell. A credit can overrun nothing and is
/// admitted beside either. A principal's vault of the protocol resource
/// is exempt, since the one debiting delta that reaches it is a fee,
/// which its fee hold bounds.
///
/// Claims and candidates are both [`DeclaredKey`]s, which name one cell
/// or one collection interval. A collection interval covers other
/// intervals of the same collection and nothing else — an interval is
/// over entries, and no point cell is an entry. Overlap alone decides
/// nothing; what decides is whether the modes on the two sides can be in
/// flight together.
#[derive(Debug, Default)]
pub struct ProvisionalCells {
    cells: BTreeMap<SubstateKey, BTreeSet<ModeKind>>,
    /// Modes held per collection, interval-insensitive: two intervals of
    /// one collection contend by mode alone, the conservative half of
    /// the kernel's overlap arithmetic.
    collections: BTreeMap<(Address, CollectionId), BTreeSet<ModeKind>>,
    /// The cells an unresolved leg debits by a delta, a principal's vault
    /// of the protocol resource apart.
    debited: BTreeSet<SubstateKey>,
}

impl ProvisionalCells {
    /// Record how one unresolved leg declared it would reach each cell.
    pub fn claim(&mut self, declared: &[(DeclaredKey, Mode)]) {
        for (key, mode) in declared {
            let kind = mode.kind();
            match key {
                DeclaredKey::Cell(cell) => {
                    self.cells.entry(*cell).or_default().insert(kind);
                    if matches!(mode, Mode::Delta { moves } if moves.debits())
                        && !is_protocol_vault(cell)
                    {
                        self.debited.insert(*cell);
                    }
                }
                DeclaredKey::Range(range) => {
                    self.collections
                        .entry((range.owner, range.collection))
                        .or_default()
                        .insert(kind);
                }
            }
        }
    }

    /// Whether nothing is claimed — the common case, and worth
    /// short-circuiting on since it spares every candidate the walk.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.collections.is_empty()
    }

    /// Whether a candidate's declared access cannot be in flight beside
    /// what is already held.
    ///
    /// Incompatible on any one cell is enough: the candidate is one
    /// transaction and it executes whole or not at all.
    #[must_use]
    pub fn blocks(&self, declared: &[(DeclaredKey, Mode)]) -> bool {
        declared.iter().any(|(key, mode)| {
            let candidate = mode.kind();
            let held = match key {
                DeclaredKey::Cell(cell) => {
                    let debits = match mode {
                        Mode::Reserve { .. } => true,
                        Mode::Delta { moves } => moves.debits(),
                        Mode::Read | Mode::Write { .. } => false,
                    };
                    if debits && self.debited.contains(cell) {
                        return true;
                    }
                    self.cells.get(cell)
                }
                // A candidate interval contends with claims on its own
                // collection — never with point cells, which no interval
                // contains.
                DeclaredKey::Range(range) => self.collections.get(&(range.owner, range.collection)),
            };
            held.into_iter()
                .flat_map(BTreeSet::iter)
                .any(|held| !compatible(*held, candidate))
        })
    }
}

/// What a member no tick has named is judged on: the terms its
/// committing block stated, borrowed from where they stand.
#[derive(Debug, Clone, Copy)]
pub struct Judged<'a> {
    /// Whether this shard runs a leg of it, which its fate ends if it
    /// never runs, and never an abort.
    leg: bool,
    /// Which half settles it, and whether a discard keeps it.
    settlement: Settlement,
    /// Its declared accesses, each under the mode it takes.
    declared: &'a Holds,
    /// The remote shards the transaction reaches.
    reach: &'a Reach,
    /// The remote shards whose certificates its settlement awaits.
    awaits: &'a Reach,
    /// The remote shards whose committed bundle it requires before it
    /// runs.
    engages: &'a Reach,
    /// The escrowed crossings it consumes.
    crossings: &'a [CrossingId],
    /// Whether it is the payer's leg, which waits for every shard it
    /// reaches to engage until its deadline.
    waits: bool,
}

impl<'a> Judged<'a> {
    /// What `terms` state.
    #[must_use]
    pub fn of(terms: &'a MemberTerms) -> Self {
        Self {
            leg: terms.leg,
            settlement: terms.settlement,
            declared: &terms.declared,
            reach: &terms.reach,
            awaits: &terms.awaits,
            engages: &terms.engages,
            crossings: &terms.crossings,
            waits: terms.waits,
        }
    }

    /// What `row`, standing `Pending`, carries from its committing
    /// block.
    ///
    /// # Panics
    ///
    /// If `row` does not carry what it waits on, which every `Pending`
    /// row does.
    #[must_use]
    pub fn of_row(row: &'a MemberRow) -> Self {
        let waiting = row
            .waiting
            .as_ref()
            .expect("a pending row carries what it waits on");
        Self {
            leg: waiting.leg,
            settlement: waiting.settlement,
            declared: &waiting.declared,
            reach: &row.reach,
            awaits: &row.awaits,
            engages: &waiting.engages,
            crossings: &row.crossings,
            waits: waiting.waits,
        }
    }

    /// The shards whose committed bundle naming it decides whether it is
    /// ready: the ones it requires, and where it is the payer's leg
    /// every shard it reaches.
    pub fn sources(&self) -> impl Iterator<Item = ShardId> + 'a {
        let counterparts = if self.waits { &self.reach[..] } else { &[] };
        self.engages.iter().chain(counterparts).copied()
    }

    /// The record cells of the crossings it consumes, each of which a
    /// committed claim reads live before it runs.
    pub fn records(&self) -> impl Iterator<Item = SubstateKey> + 'a {
        self.crossings
            .iter()
            .map(|id| id.record_key(&ProtocolHasher))
    }

    /// Whether a counterpart's verdict can still discard the member's
    /// effects, so what it declared is held while it is in flight.
    fn abortable(&self) -> bool {
        self.settlement != Settlement::Alone
    }
}

/// The terms of `tx`'s member on `local`: what its including block
/// states of it.
///
/// Classified and priced under `committee`, the committee at that
/// block's parent anchor. `tx` must be routed, and declare no more
/// accesses than a member holds.
#[must_use]
pub fn terms_of(tx: &Transaction, committee: &TopologySnapshot, local: ShardId) -> MemberTerms {
    let trie = committee.shard_trie();
    terms_of_member(&member_of(tx, trie, local), tx, trie, &committee.prices())
}

/// `tx`'s member on `local`, classified under `trie`: the one freeze
/// every per-member question of a routed transaction is asked of. The
/// shards it touches are its routing's prefixes placed by the same trie.
#[must_use]
pub fn member_of(tx: &Transaction, trie: &ShardTrie, local: ShardId) -> Member {
    let participating = tx
        .routing()
        .all_prefixes()
        .into_iter()
        .map(|prefix| trie.shard_for_prefix(prefix))
        .collect();
    let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
    Member::of(classified, local, participating)
}

/// The remote shards whose certificates `member`'s settlement awaits.
///
/// Its siblings where it is a core or whole member reaching beyond its
/// shard, and nobody otherwise. What its row records as `awaits`, and so
/// the shards it stands toward.
#[must_use]
pub fn awaited_core(member: &Member) -> Reach {
    remote(member.awaited(), member.local())
}

/// The terms of `member`, `tx`'s member classified under `trie`, priced
/// at `prices`.
///
/// # Panics
///
/// If `tx` declares more accesses than a member holds, which admission
/// refuses of every transaction a block carries. Otherwise never: a
/// transaction reaches no more shards than its routing names prefixes,
/// and a star's edges are capped.
#[must_use]
pub fn terms_of_member(
    member: &Member,
    tx: &Transaction,
    trie: &ShardTrie,
    prices: &PriceTable,
) -> MemberTerms {
    let local = member.local();
    let classified = member.classified();
    let reach = remote(member.reach().iter().copied(), local);
    let settlement = if !member.abortable() {
        Settlement::Alone
    } else if matches!(member.role(), Role::Whole | Role::Core) {
        Settlement::Shared
    } else {
        Settlement::Awaited
    };
    let (engages, crossings, waits) = if !member.reaches_beyond() {
        (Capped::empty(), Capped::empty(), false)
    } else if classified.decomposed() {
        let engages = requirements_of(member, tx.legs())
            .into_iter()
            .filter_map(|requirement| match requirement {
                Requirement::CommittedState(shard) => Some(shard),
                Requirement::Crossing { .. } => None,
            });
        let crossings = classified
            .refusable_consumed(local)
            .map(|edge| edge.crossing.id)
            .collect();
        (
            remote(engages, local),
            Capped::new(crossings).expect("a star's edges are capped"),
            false,
        )
    } else {
        let payer = trie.shard_for_prefix(tx.fee_payer());
        let provisioning = tx
            .routing()
            .provision_prefixes
            .iter()
            .map(|prefix| trie.shard_for_prefix(*prefix));
        if payer == local {
            (
                remote(provisioning, local),
                Capped::empty(),
                !reach.is_empty(),
            )
        } else {
            (
                remote(provisioning.chain([payer]), local),
                Capped::empty(),
                false,
            )
        }
    };
    MemberTerms {
        leg: member.role() == Role::Leg,
        settlement,
        declared: Capped::new(tx.routing().declared_modes.clone())
            .expect("a committed transaction declares no more than a member holds"),
        awaits: awaited_core(member),
        reach,
        engages,
        crossings,
        waits,
        charge: AbortCharge::of(tx, prices),
        share: classified.local_price(tx, local, prices),
        reserves: local_reserves(tx, trie, local),
    }
}

/// `shards` without `local`, each once, ascending.
fn remote(shards: impl IntoIterator<Item = ShardId>, local: ShardId) -> Reach {
    let shards: BTreeSet<ShardId> = shards.into_iter().filter(|&shard| shard != local).collect();
    Capped::new(shards.into_iter().collect())
        .expect("a transaction reaches no more shards than it names prefixes")
}

/// What `tx`'s declared reservations promise of the vaults `local`
/// charges fees to: each principal's protocol vault under its prefix
/// once, in key order, at the sum reserved on it. A vault on another
/// shard, a component's cell and every other mode state nothing.
fn local_reserves(tx: &Transaction, trie: &ShardTrie, local: ShardId) -> Reserves {
    let mut reserved: BTreeMap<SubstateKey, u128> = BTreeMap::new();
    for (key, mode) in &tx.routing().declared_modes {
        if let (DeclaredKey::Cell(cell), Mode::Reserve { amount }) = (key, mode)
            && is_protocol_vault(cell)
            && trie.shard_for_prefix(cell.owner) == local
        {
            let sum = reserved.entry(*cell).or_default();
            *sum = sum.saturating_add(*amount);
        }
    }
    Capped::new(reserved.into_iter().collect()).expect("one entry at most for each declared access")
}

/// What committed content says a member has in hand, read as the chain
/// up to the block being named.
pub trait CommittedInputs {
    /// Whether a committed bundle from `source` names `tx`.
    fn engaged(&self, source: ShardId, tx: TxHash) -> bool;
    /// Whether a committed claim has read `key` live naming `tx`, at or
    /// after the block that committed `tx` here.
    fn arrived(&self, key: SubstateKey, tx: TxHash) -> bool;
}

/// Whether a member can join a tick at `anchor`, and on what terms.
///
/// `None` while it waits: on a bundle or a crossing it requires, or on
/// its payer's engagement short of `deadline`, the transaction's own.
/// Past that deadline with a counterpart silent it joins, attested
/// aborted.
#[must_use]
pub fn readiness(
    tx: TxHash,
    judged: &Judged<'_>,
    deadline: Deadline,
    anchor: WeightedTimestamp,
    inputs: &dyn CommittedInputs,
) -> Option<Joins> {
    let provisioned = judged
        .engages
        .iter()
        .all(|&shard| inputs.engaged(shard, tx))
        && judged.records().all(|key| inputs.arrived(key, tx));
    if !provisioned {
        return None;
    }
    if !judged.waits {
        return Some(Joins::Executes);
    }
    let silent = judged.reach.iter().any(|&shard| !inputs.engaged(shard, tx));
    if !silent {
        Some(Joins::Executes)
    } else if deadline.passed(anchor) {
        Some(Joins::ExecutesAborted)
    } else {
        None
    }
}

/// Committed inputs as the sets a coordinator gathers for the members
/// it asks about: what it hands a builder, and what a voter reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommittedSets {
    /// `(source, tx)` for every committed bundle naming `tx`.
    pub engaged: BTreeSet<(ShardId, TxHash)>,
    /// `(record, tx)` for every record read live naming `tx`, at or after
    /// the block that committed `tx`.
    pub arrived: BTreeSet<(SubstateKey, TxHash)>,
    /// What each shard says of its evidence at the block's anchor that a
    /// member in flight reaches, or a released one a counterpart settles
    /// against.
    pub evidence: BTreeMap<ShardId, Evidence>,
    /// What the schedule and the mirror say, at the block's anchor, of
    /// each shard a row accepted at the parent awaits.
    pub siblings: SiblingViews,
}

/// What each sibling of the rows accepted at a block's parent counts by,
/// at the block's anchor.
///
/// Where its verdict is read from and what the schedule says of it, and
/// for a departed one whose terminal's ended names this replica holds,
/// whether they name each such row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiblingViews {
    /// The source and the schedule's view of each sibling.
    pub shards: BTreeMap<ShardId, (Option<Source>, SiblingView)>,
    /// For each departed sibling whose ended names are held and each
    /// accepted row awaiting it, whether the names hold the row's
    /// transaction.
    pub ended: BTreeMap<(ShardId, TxHash), bool>,
}

impl SiblingViews {
    /// What each sibling `row` awaits counts as, in the order the row
    /// lists them. A sibling nothing was gathered for is this replica's
    /// lack.
    #[must_use]
    pub fn values(&self, row: &MemberRow) -> Vec<Value> {
        row.awaits
            .iter()
            .map(|sibling| {
                let Some(&(source, view)) = self.shards.get(sibling) else {
                    return Value::N;
                };
                let view = SiblingView {
                    ended: self.ended.get(&(*sibling, row.tx)).copied(),
                    ..view
                };
                let entry = row.hearing.iter().find(|heard| heard.shard == *sibling);
                value_of(entry, source, &view)
            })
            .collect()
    }
}

impl CommittedSets {
    /// What `shard`'s evidence says at the block's anchor: unknown where
    /// the coordinator did not read it.
    #[must_use]
    pub fn evidence(&self, shard: ShardId) -> Evidence {
        self.evidence
            .get(&shard)
            .copied()
            .unwrap_or(Evidence::Unknown)
    }
}

impl CommittedInputs for CommittedSets {
    fn engaged(&self, source: ShardId, tx: TxHash) -> bool {
        self.engaged.contains(&(source, tx))
    }

    fn arrived(&self, key: SubstateKey, tx: TxHash) -> bool {
        self.arrived.contains(&(key, tx))
    }
}

/// What a block's tick manifest names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ManifestKind {
    /// Member lines, discards, the fates of members no shard can answer
    /// for and the ends of accepted rows: a block the chain carries
    /// content in.
    #[default]
    Members,
    /// A line for every member row, an end for an accepted one and a
    /// fate for any other: the chain's terminal.
    Fates,
    /// Nothing: a coast block past the terminal, or a recovery's bridge.
    Empty,
}

/// The lines a chain's terminal names: one per member row, in
/// transaction order.
///
/// An accepted row is ended, which burns nothing and leaves its name
/// for a sibling still deciding to read; every other row is fated,
/// priced by what its row carries.
#[must_use]
pub fn terminal_fates(rows: &MemberIndex) -> Vec<TickLine> {
    rows.members
        .values()
        .map(|row| match row.state {
            RowState::Accepted => TickLine::End { tx: row.tx },
            RowState::Pending
            | RowState::InFlight { .. }
            | RowState::Stated { .. }
            | RowState::Released { .. } => TickLine::Fate {
                tx: row.tx,
                charge: row.charge,
            },
        })
        .collect()
}

/// The accepted rows of `rows` that stood accepted at `parent`, each
/// with what [`decide`] says of it under `views`: the rows a block's
/// `End` lines may name, judged over `rows`, the parent's advanced by
/// the block's claims, so a reading the block carries counts.
fn accepted_decisions<'r>(
    rows: &'r MemberIndex,
    parent: &'r MemberIndex,
    views: &'r SiblingViews,
) -> impl Iterator<Item = (TxHash, Decision)> + 'r {
    rows.members
        .values()
        .filter(|row| row.state == RowState::Accepted)
        .filter(|row| {
            parent
                .members
                .get(&row.tx)
                .is_some_and(|stood| stood.state == RowState::Accepted)
        })
        .map(|row| (row.tx, decide(Hears::Accepted, &views.values(row))))
}

/// The `End` lines a block names after its other lines: one for every
/// row accepted at `parent` that [`decide`] ends over `rows`, in
/// transaction order, for as long as `budget`, what the other lines
/// left, takes them.
#[must_use]
pub fn end_lines(
    rows: &MemberIndex,
    parent: &MemberIndex,
    views: &SiblingViews,
    mut budget: ManifestBudget,
) -> Vec<TickLine> {
    accepted_decisions(rows, parent, views)
        .filter(|(_, decision)| *decision == Decision::End)
        .map(|(tx, _)| TickLine::End { tx })
        .take_while(|line| budget.take(line))
        .collect()
}

/// Why a block's `End` lines are not ones a voter admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unlicensed {
    /// No replica licenses the lines.
    Refused(String),
    /// This replica cannot say whether the row is ended: it lacks the
    /// published window or a departed sibling's ended names.
    Lacking(TxHash),
}

/// Whether `ended`, the transactions the `End` lines closing a block's
/// manifest name, in the block's order, are lines the chain licenses.
///
/// Each names a row accepted at `parent`, in strictly ascending
/// transaction order, that [`decide`] ends over `rows`, and fits
/// `budget`, what the block's other lines left. A block may carry any
/// subset of the lines it could: none is owed.
///
/// # Errors
///
/// [`Unlicensed::Refused`] for a line out of order, naming a row that
/// was not accepted at the parent or that waits, or past the budget; and
/// [`Unlicensed::Lacking`], where no line is refused, for the first one
/// this replica cannot judge.
pub fn ends_stand(
    ended: &[TxHash],
    rows: &MemberIndex,
    parent: &MemberIndex,
    views: &SiblingViews,
    mut budget: ManifestBudget,
) -> Result<(), Unlicensed> {
    if ended.is_empty() {
        return Ok(());
    }
    if !ended.is_sorted_by(|earlier, later| earlier < later) {
        return Err(Unlicensed::Refused(
            "the block's end lines are not in ascending transaction order".into(),
        ));
    }
    let decisions: BTreeMap<TxHash, Decision> = accepted_decisions(rows, parent, views).collect();
    let mut lacking = None;
    for &tx in ended {
        match decisions.get(&tx) {
            Some(Decision::End) => {}
            Some(Decision::Lacking) => lacking = lacking.or(Some(tx)),
            Some(Decision::Wait | Decision::Accept | Decision::Refuse | Decision::LetGo) => {
                return Err(Unlicensed::Refused(format!(
                    "an end line names {tx:?}, whose row still waits on a sibling"
                )));
            }
            None => {
                return Err(Unlicensed::Refused(format!(
                    "an end line names {tx:?}, which no row accepted at the parent stands for"
                )));
            }
        }
        if !budget.take(&TickLine::End { tx }) {
            return Err(Unlicensed::Refused(format!(
                "the end line of {tx:?} is past the manifest's budget"
            )));
        }
    }
    lacking.map_or(Ok(()), |tx| Err(Unlicensed::Lacking(tx)))
}

/// What a proposer's coordinator hands the block builder.
///
/// What committed content up to the parent says of every member it may
/// name. The builder adds the block's own bundles and claims, once it
/// has dropped what the block will not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestInputs {
    /// What committed content up to the parent says of the members.
    pub committed: CommittedSets,
    /// Whether the block is its shard's crossing block past a halt
    /// recovery's bridge, which discards every tick its parent's rows
    /// hold.
    pub recovery: bool,
    /// What the block's manifest names.
    pub kind: ManifestKind,
}

/// Where a candidate stands, as its row says, with what judging it
/// reads.
#[derive(Debug, Clone, Copy)]
pub enum Standing<'a> {
    /// Committed, and named by no tick yet: judged on the terms its
    /// committing block stated.
    Pending(Judged<'a>),
    /// Committed and named by no tick yet, and the victim of a hold cycle
    /// the block's own claims prove: aborted on those terms, whatever
    /// its deadline. See [`wounded`].
    Wounded(Judged<'a>),
    /// Held by a tick that lets go of it on its abort: a member a
    /// counterpart's verdict can discard, which a departure covers and
    /// which the tick does not hold as its own abandonment. Judged on
    /// its row alone.
    Held {
        /// The tick holding it.
        tick: TickId,
        /// The remote shards its line named.
        reach: &'a Reach,
    },
    /// Let go, by a discard of the tick that held it, and due an abort.
    /// Judged on its row alone.
    Released {
        /// The remote shards its terms named.
        reach: &'a Reach,
    },
}

impl<'a> Standing<'a> {
    /// How `row`, committed and named by no tick, stands: wounded where
    /// the block's claims prove it the victim of a hold cycle.
    fn waiting(row: &'a MemberRow, wounded: &BTreeSet<TxHash>) -> Self {
        let judged = Judged::of_row(row);
        if wounded.contains(&row.tx) {
            Self::Wounded(judged)
        } else {
            Self::Pending(judged)
        }
    }

    /// The remote shards the transaction reaches.
    const fn reach(&self) -> &'a Reach {
        match self {
            Self::Pending(judged) | Self::Wounded(judged) => judged.reach,
            Self::Held { reach, .. } | Self::Released { reach, .. } => reach,
        }
    }

    /// Whether this shard runs a leg of it and no tick has named it: a
    /// member its fate ends at the close of its leg entry window. A held
    /// row is never one, and a released one is a candidate only where an
    /// abort is its exit.
    const fn leg(&self) -> bool {
        match self {
            Self::Pending(judged) | Self::Wounded(judged) => judged.leg,
            Self::Held { .. } | Self::Released { .. } => false,
        }
    }
}

/// The member lines a block names over `rows`: the family after the
/// block's own finalizations, discards, records and transactions.
///
/// Every in-flight row's holds are held, a stated row's as it held them
/// in flight, and each row takes the exit its standing gives it at
/// `anchor`, which [`Exit::of`] decides on the row alone, so a replica
/// that cannot route a member names and expects the lines its peers do.
/// A pending member of `wounded`, the victims
/// the block's own state claims prove (see [`wounded`]), is aborted
/// short of its deadline.
///
/// A fate ends a row no certificate of this shard's is owed for: a
/// member a counterpart settles against, in flight or released, at any
/// age once `evidence` reads every shard it reaches unreadable, and a
/// member settled on this shard's word alone that never ran or was let
/// go of, once the window its leg entry stands in has closed. Each
/// burns the charge its row carries. A member whose counterparts'
/// evidence is not yet folded is left where it stands and returned
/// beside the lines, so a voter, which cannot judge a manifest without
/// it, defers.
///
/// On a recovery's crossing block (`recovery`) every tick the rows hold
/// is discarded whole: each was anchored below the bridge, so no
/// committee the shard keeps can certify it, and no other line names
/// its members in that block.
///
/// The lines are listed as the budget is charged: a recovery's
/// discards; the fates in transaction order, each after the
/// `Unanswerable` discard of the tick holding its member, the two taken
/// together so both fit or neither is named; the member lines; the
/// `Abandoned` discards. Nothing is named past the first refusal. The
/// budget is returned as the lines left it, for the `End` lines a block
/// names after them.
#[must_use]
pub fn member_lines(
    rows: &MemberIndex,
    anchor: WeightedTimestamp,
    inputs: &dyn CommittedInputs,
    evidence: &dyn Fn(ShardId) -> Evidence,
    recovery: bool,
    wounded: &BTreeSet<TxHash>,
) -> (Vec<TickLine>, Vec<TxHash>, ManifestBudget) {
    let mut holds = ProvisionalCells::default();
    let mut candidates = Vec::new();
    let mut missing = Vec::new();
    let mut fated: Vec<(Option<TickLine>, TickLine)> = Vec::new();
    let recovered: Vec<BlockHeight> = if recovery {
        rows.ticks.keys().copied().collect()
    } else {
        Vec::new()
    };
    for row in rows.members.values() {
        if row.state.held().is_some() {
            holds.claim(&row.holds);
        }
        match Exit::of(row, rows, anchor, evidence, &recovered, wounded) {
            Exit::None => {}
            Exit::Unread => missing.push(row.tx),
            Exit::Fated(held_by) => {
                let discard = held_by.map(|tick| TickLine::Discard {
                    tick,
                    cause: DiscardCause::Unanswerable(row.tx),
                });
                let fate = TickLine::Fate {
                    tx: row.tx,
                    charge: row.charge,
                };
                fated.push((discard, fate));
            }
            Exit::Candidate(standing) => candidates.push(Nameable {
                tx: row.tx,
                deadline: row.deadline,
                standing,
                charge: row.charge,
                share: row.share,
                reserves: &row.reserves,
                nevers: (!row.executed && !row.covered).then_some(&row.crossings),
            }),
        }
    }
    let mut budget = ManifestBudget::default();
    let mut lines = Vec::new();
    let recoveries = recovered.into_iter().map(|height| {
        let discard = TickLine::Discard {
            tick: TickId::new(rows.shard(), height),
            cause: DiscardCause::Recovery,
        };
        (None, discard)
    });
    for (discard, line) in recoveries.chain(fated) {
        if !budget.take_all(discard.iter().chain([&line])) {
            return (lines, missing, budget);
        }
        lines.extend(discard);
        lines.push(line);
    }
    lines.extend(select_members(
        anchor,
        candidates,
        inputs,
        &mut holds,
        &mut budget,
    ));
    (lines, missing, budget)
}

/// What a block's lines may do with one row.
enum Exit<'a> {
    /// Nothing: it stands as it is.
    None,
    /// Nothing yet: the evidence of a shard it reaches is not folded.
    Unread,
    /// A fate ends it, after the `Unanswerable` discard of the tick
    /// holding it where one does.
    Fated(Option<TickId>),
    /// A member line may name it.
    Candidate(Standing<'a>),
}

impl<'a> Exit<'a> {
    /// How `row` of `rows` stands toward the lines of a block anchored
    /// at `anchor`, where `recovered` are the ticks the block discards
    /// whole.
    ///
    /// A row a tick holds leaves by a clock only where no counterpart can
    /// still settle against a certificate of this shard's for it; a row
    /// let go of always has a clock, since no half settles it:
    ///
    /// - one no tick has named is aborted at its deadline, or wounded
    ///   short of it, having certified nothing; a leg is never aborted,
    ///   and is fated once its leg entry window has closed, what it
    ///   issued going back in its producer's fold on its consumer's
    ///   `Never`;
    /// - one a tick holds leaves by its tick, and otherwise only where a
    ///   counterpart's verdict can discard it: fated once nobody can
    ///   answer for it, or aborted past its deadline under a covering
    ///   record; a stated row is the shared member in flight it was;
    /// - one let go of that reaches no other shard is aborted at its
    ///   deadline;
    /// - one let go of that is settled on this shard's word alone and
    ///   reaches others is a leg, or a core member no sibling shares a
    ///   verdict with: its certificate is owed nowhere, and it is fated
    ///   where a waiting leg is;
    /// - one let go of that a counterpart settles against is aborted at
    ///   its deadline, a record covering it or not, while a shard it
    ///   reaches can answer, and is fated once nobody can answer for it.
    ///   Only a recovery's discard leaves such a row standing past the
    ///   block that released it, and the abort ends it on this shard
    ///   alone, where nothing else can. Its certificate is the fresh
    ///   committee's, anchored past the bridge: a counterpart that has
    ///   not settled reads it and ends its own row by it, and one that
    ///   settled against the certificate the replaced committee left
    ///   keeps what it settled;
    /// - one let go of out of an abort is aborted again at its deadline,
    ///   whether or not it ran;
    /// - one that has accepted stands whatever the clock or the evidence
    ///   says: it has settled, and only an `End` line ends it.
    ///
    /// The reading that nobody can answer is taken first, so it wins
    /// over the abort a covering record or a deadline would license.
    fn of(
        row: &'a MemberRow,
        rows: &MemberIndex,
        anchor: WeightedTimestamp,
        evidence: &dyn Fn(ShardId) -> Evidence,
        recovered: &[BlockHeight],
        wounded: &BTreeSet<TxHash>,
    ) -> Self {
        let passed = row.deadline.passed(anchor);
        let lapsed = anchor >= Window::LegEntry.of(row.deadline).end;
        let held = |tick: BlockHeight, joins: Joins, settlement: Settlement| {
            // A tick still owing its determined half is let go of by
            // nothing but a recovery: a determined contribution that
            // ran is readable, and a discard dropping it would lose
            // it. An abort is its tick's own to settle, and so is a
            // member no counterpart's verdict can discard.
            if recovered.contains(&tick)
                || rows
                    .ticks
                    .get(&tick)
                    .is_some_and(|held| held.determined_unsettled)
                || joins == Joins::Aborted
                || settlement == Settlement::Alone
            {
                return Self::None;
            }
            let tick = TickId::new(rows.shard(), tick);
            match answerable(&row.reach, evidence) {
                Some(false) => Self::Fated(Some(tick)),
                None => Self::Unread,
                Some(true) if passed && row.covered => Self::Candidate(Standing::Held {
                    tick,
                    reach: &row.reach,
                }),
                Some(true) => Self::None,
            }
        };
        match row.state {
            RowState::InFlight {
                tick,
                joins,
                settlement,
            } => held(tick, joins, settlement),
            RowState::Stated { tick, .. } => held(tick, Joins::Executes, Settlement::Shared),
            RowState::Released { settlement } => {
                let aborted = |due: bool| {
                    if due {
                        Self::Candidate(Standing::Released { reach: &row.reach })
                    } else {
                        Self::None
                    }
                };
                if row.reach.is_empty() {
                    return aborted(passed);
                }
                match settlement {
                    Settlement::Alone if lapsed => Self::Fated(None),
                    Settlement::Alone => Self::None,
                    Settlement::Shared => match answerable(&row.reach, evidence) {
                        Some(false) => Self::Fated(None),
                        None => Self::Unread,
                        Some(true) => aborted(passed),
                    },
                    Settlement::Awaited => aborted(passed),
                }
            }
            RowState::Accepted => Self::None,
            RowState::Pending => {
                let standing = Standing::waiting(row, wounded);
                if standing.leg() && lapsed {
                    Self::Fated(None)
                } else {
                    Self::Candidate(standing)
                }
            }
        }
    }
}

/// Whether a counterpart of a member reaching `reach` can still answer
/// for it: `Some(false)` once every shard of its `reach` has departed
/// with its settled set unreadable, `None` while a window that could say
/// is not yet folded. A member reaching nobody has no counterpart to
/// fall silent.
fn answerable(reach: &Reach, evidence: &dyn Fn(ShardId) -> Evidence) -> Option<bool> {
    if reach.is_empty() {
        return Some(true);
    }
    let mut unknown = false;
    for &shard in reach.iter() {
        match evidence(shard) {
            Evidence::Live { .. } | Evidence::Readable => return Some(true),
            Evidence::Unknown => unknown = true,
            Evidence::Unreadable => {}
        }
    }
    (!unknown).then_some(false)
}

/// What a manifest has spent of its byte budget, its line cap and its
/// member cap.
#[derive(Debug, Default, Clone, Copy)]
pub struct ManifestBudget {
    spent: usize,
    lines: usize,
    members: usize,
}

impl ManifestBudget {
    /// Take `line` if it fits what is left, and say whether it did.
    pub fn take(&mut self, line: &TickLine) -> bool {
        self.take_all([line])
    }

    /// Take every one of `lines` if all of them fit what is left, and
    /// none of them otherwise.
    fn take_all<'l>(&mut self, lines: impl IntoIterator<Item = &'l TickLine>) -> bool {
        let (mut spent, mut count, mut members) = (self.spent, self.lines, self.members);
        for line in lines {
            spent = spent.saturating_add(line.wire_weight());
            count += 1;
            members += usize::from(matches!(line, TickLine::Member { .. }));
        }
        if !tick_manifest_admits_block(spent)
            || count > MAX_TICK_LINES_PER_BLOCK
            || !tick_manifest_admits_members(members)
        {
            return false;
        }
        self.spent = spent;
        self.lines = count;
        self.members = members;
        true
    }
}

/// One transaction a block's lines may name.
#[derive(Debug, Clone, Copy)]
pub struct Nameable<'a> {
    /// The transaction.
    pub tx: TxHash,
    /// Its deadline, off its signed validity range.
    pub deadline: Deadline,
    /// Where its row stands, with what judging it reads.
    pub standing: Standing<'a>,
    /// What an abort of it burns.
    pub charge: AbortCharge,
    /// The price this shard attests for it.
    pub share: u128,
    /// What its declared reservations promise of this shard's fee
    /// vaults.
    pub reserves: &'a Reserves,
    /// The crossings an abort of it answers `Never` for: every escrowed
    /// crossing it consumes where it never ran and no abandonment record
    /// covers it, and none otherwise, since a member that ran wrote its
    /// own answers and a covered one's records are declined by its own
    /// shard's fold once its row is gone.
    /// A member that ran and that a recovery released answers none
    /// either: its row lists no crossing, its run's answers settle with
    /// no half, and nothing returns an escrow held for it.
    pub nevers: Option<&'a Crossings>,
}

/// The lines a block names: every ready candidate, in canonical order,
/// that no provisional hold refuses, up to the budget, then the discards
/// its aborts imply.
///
/// A candidate past its deadline at `anchor` is named `Aborted` and
/// nothing else, whether or not it is ready: a member that awaits nobody
/// and succeeds decides its transaction, so it is named to run only
/// while the deadline has not passed, and its success is admissible
/// whenever it then commits. A leg past its deadline is not named at all:
/// its fate ends it at the close of its leg entry window. A candidate a
/// tick holds or let go of is one [`Exit::of`] found due an abort. A
/// [`Standing::Wounded`] candidate is named
/// `Aborted` as one past its deadline is. An abort line carries the
/// candidate's deadline and the crossings it answers `Never` for, so a
/// replica holding nothing of the transaction seats and settles it. An
/// abort of a member a tick holds is charged together with that tick's
/// `Abandoned` discard, so the pair fits or neither does.
///
/// Canonical order puts the transactions reaching beyond this shard
/// first, then hash order: theirs are the provisional writes everything
/// else has to be compatible with, and a determined member is the
/// cheaper of the two to defer. `holds` carries in what in-flight legs
/// claim and leaves with what the named lines add, so a member of this
/// very tick can be what keeps the next one out. The walk stops at the
/// first line the budget refuses, and the rest wait a block.
#[must_use]
pub fn select_members<'a>(
    anchor: WeightedTimestamp,
    candidates: impl IntoIterator<Item = Nameable<'a>>,
    inputs: &dyn CommittedInputs,
    holds: &mut ProvisionalCells,
    budget: &mut ManifestBudget,
) -> Vec<TickLine> {
    let mut ordered: Vec<Nameable<'a>> = candidates.into_iter().collect();
    ordered.sort_by_key(|candidate| (candidate.standing.reach().is_empty(), candidate.tx));
    let mut lines = Vec::new();
    let mut discards = Vec::new();
    for candidate in ordered {
        let Nameable {
            tx,
            deadline,
            standing,
            charge,
            share,
            reserves,
            nevers,
        } = candidate;
        if deadline.passed(anchor) || matches!(standing, Standing::Wounded(_)) {
            if standing.leg() {
                continue;
            }
            let line = TickLine::Member {
                tx,
                joins: Joins::Aborted,
                settlement: if standing.reach().is_empty() {
                    Settlement::Alone
                } else {
                    Settlement::Awaited
                },
                holds: Capped::empty(),
                reach: standing.reach().clone(),
                awaits: Capped::empty(),
                charge,
                share,
                reserves: reserves.clone(),
                deadline,
                nevers: nevers.cloned().unwrap_or_else(Capped::empty),
            };
            let discard = match standing {
                Standing::Held { tick, .. } => Some(TickLine::Discard {
                    tick,
                    cause: DiscardCause::Abandoned(tx),
                }),
                Standing::Pending(_) | Standing::Wounded(_) | Standing::Released { .. } => None,
            };
            if !budget.take_all(std::iter::once(&line).chain(&discard)) {
                break;
            }
            lines.push(line);
            discards.extend(discard);
            continue;
        }
        let Standing::Pending(judged) = standing else {
            continue;
        };
        let Some(joins) = readiness(tx, &judged, deadline, anchor, inputs) else {
            continue;
        };
        let abortable = judged.abortable();
        if !holds.is_empty() && holds.blocks(judged.declared) {
            continue;
        }
        let line = TickLine::Member {
            tx,
            joins,
            settlement: judged.settlement,
            holds: if abortable {
                judged.declared.clone()
            } else {
                Capped::empty()
            },
            reach: judged.reach.clone(),
            awaits: judged.awaits.clone(),
            charge,
            share,
            reserves: reserves.clone(),
            deadline,
            nevers: Capped::empty(),
        };

        if !budget.take(&line) {
            break;
        }
        // After the test, never before: a transaction is not what keeps
        // itself out.
        if abortable {
            holds.claim(judged.declared);
        }
        lines.push(line);
    }
    lines.extend(discards);
    lines
}

/// A pending core member a held core member keeps out of a block, where
/// the two await a shard in common: one shard's half of a cycle in which
/// each of two shards holds what the other waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contention {
    /// The member kept out.
    pub waiting: TxHash,
    /// A member whose holds refuse it.
    pub holder: TxHash,
}

/// A core member's holds, as a refusal reads them.
struct CoreHolder<'r> {
    tx: TxHash,
    holds: &'r Holds,
    cells: ProvisionalCells,
    awaits: &'r Reach,
}

impl<'r> CoreHolder<'r> {
    /// A holder over `holds`, or `None` where it holds nothing.
    fn of(tx: TxHash, holds: &'r Holds, awaits: &'r Reach) -> Option<Self> {
        if holds.is_empty() {
            return None;
        }
        let mut cells = ProvisionalCells::default();
        cells.claim(holds);
        Some(Self {
            tx,
            holds,
            cells,
            awaits,
        })
    }

    /// Whether these holds refuse `waiting`, which awaits a shard this
    /// holder awaits too.
    fn refuses(&self, waiting: &Judged<'_>) -> bool {
        self.shared(waiting).next().is_some() && self.cells.blocks(waiting.declared)
    }

    /// The shards both this holder and `waiting` await: where each has a
    /// sibling that holds a seat while its tick is in flight.
    fn shared<'w>(&'w self, waiting: &'w Judged<'_>) -> impl Iterator<Item = ShardId> + 'w {
        self.awaits
            .iter()
            .copied()
            .filter(|shard| waiting.awaits.contains(shard))
    }
}

/// Every core member of `rows` in flight, with what it holds.
fn in_flight_holders<'r>(
    rows: impl Iterator<Item = &'r MemberRow>,
) -> impl Iterator<Item = CoreHolder<'r>> {
    rows.filter(|row| row.state.seated())
        .filter_map(|row| CoreHolder::of(row.tx, &row.holds, &row.awaits))
}

/// The contentions a block naming `lines` over `rows` leaves standing.
///
/// Every core member short of its deadline that is ready at `anchor` and
/// that no line names, paired with each core member whose holds refuse
/// it and which awaits a shard it awaits too: one in flight on its
/// row, or named by `lines` themselves. `rows` is the family before the
/// lines, so a member they name is still `Pending` there and counts
/// once, as a holder.
#[must_use]
pub fn contentions(
    rows: &MemberIndex,
    lines: &[TickLine],
    anchor: WeightedTimestamp,
    inputs: &dyn CommittedInputs,
) -> Vec<Contention> {
    let named: BTreeSet<TxHash> = lines
        .iter()
        .filter_map(|line| match line {
            TickLine::Member { tx, .. } => Some(*tx),
            TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
        })
        .collect();
    let in_lines = lines.iter().filter_map(|line| match line {
        TickLine::Member {
            tx,
            settlement: Settlement::Shared,
            holds,
            awaits,
            ..
        } => CoreHolder::of(*tx, holds, awaits),
        TickLine::Member {
            settlement: Settlement::Alone | Settlement::Awaited,
            ..
        }
        | TickLine::Fate { .. }
        | TickLine::Discard { .. }
        | TickLine::End { .. } => None,
    });
    let holders: Vec<CoreHolder<'_>> = in_flight_holders(rows.members.values())
        .chain(in_lines)
        .collect();
    if holders.is_empty() {
        return Vec::new();
    }
    let mut contended = Vec::new();
    for row in rows.members.values() {
        if row.state != RowState::Pending || named.contains(&row.tx) || row.deadline.passed(anchor)
        {
            continue;
        }
        let waiting = Judged::of_row(row);
        if waiting.settlement != Settlement::Shared {
            continue;
        }
        let refusing: Vec<&CoreHolder<'_>> = holders
            .iter()
            .filter(|holder| holder.refuses(&waiting))
            .collect();
        if refusing.is_empty()
            || readiness(row.tx, &waiting, row.deadline, anchor, inputs).is_none()
        {
            continue;
        }
        contended.extend(refusing.into_iter().map(|holder| Contention {
            waiting: row.tx,
            holder: holder.tx,
        }));
    }
    contended
}

/// The pending core members of `rows` that `claims`, a block's own state
/// claims, prove the victims of a hold cycle at `anchor`.
///
/// A cycle is two core members each shard holds in the other's order:
/// here, `holder` is in flight and its holds refuse `waiting`, which is
/// pending; on a counterpart both await, the claims at one anchor there
/// read `waiting` seated and `holder` committed, unseated and with no
/// verdict leaf. Holds are the whole transaction's declared set, and
/// `waiting`'s refuses `holder`'s in turn, so the counterpart's seat of
/// `waiting` refuses `holder` there just as `holder` refuses `waiting`
/// here, and neither certificate the other awaits can come. Nor can the
/// reading go stale: the counterpart releases `waiting` only on this
/// shard's verdict, which a pending member has not given, so `holder`
/// stays refused there for as long as this shard's own rows stand.
///
/// A reading anchored at or past `holder`'s deadline proves nothing: by
/// then the counterpart may have aborted `holder` where it waits, which
/// leaves its row standing with no seat while the cycle is already
/// breaking. The anchor's clock is the one that abort is judged by.
///
/// The victim is the later of the two in hash order. Both shards order
/// them alike, and only the shard where the victim is pending names it,
/// so a cycle the deadline is not already breaking loses one member.
#[must_use]
pub fn wounded(
    rows: &MemberIndex,
    anchor: WeightedTimestamp,
    claims: &[StateClaim],
) -> BTreeSet<TxHash> {
    if claims.is_empty() {
        return BTreeSet::new();
    }
    seat_questions(rows, anchor)
        .into_iter()
        .filter(|question| {
            let Some(lapse) = rows
                .members
                .get(&question.holder)
                .map(|row| row.deadline.at())
            else {
                return false;
            };
            question.proven_by(claims.iter().filter(|claim| claim.anchor.ts < lapse))
        })
        .map(|question| question.waiting)
        .collect()
}

/// What a shard asks a counterpart before it aborts a pending core member
/// as the victim of a hold cycle.
///
/// Whether, at one anchor there, `waiting` is seated and `holder`, which
/// refuses it here, is committed and unseated with no verdict leaf. See
/// [`wounded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeatQuestion {
    /// The counterpart both members await, where each has a sibling.
    pub shard: ShardId,
    /// The pending member, the later of the two in hash order.
    pub waiting: TxHash,
    /// The member in flight here whose holds refuse it.
    pub holder: TxHash,
}

impl SeatQuestion {
    /// The cells it reads on its counterpart: the waiting member's seat,
    /// the holder's row, the holder's seat and the holder's verdict leaf.
    #[must_use]
    pub fn keys(&self) -> [SubstateKey; 4] {
        [
            seat_leaf(self.shard, self.waiting),
            member_row_leaf(self.shard, self.holder),
            seat_leaf(self.shard, self.holder),
            verdict_leaf(self.shard, self.holder),
        ]
    }

    /// Whether `read`, one anchor's readings, answers with the cycle: the
    /// waiting member seated, and the holder committed, unseated and
    /// with no verdict leaf. A holder whose verdict leaf stands proves no
    /// cycle, whatever its seat reads.
    fn answered_by(&self, read: impl Fn(SubstateKey) -> Option<Inclusion>) -> bool {
        let [seat, row, unseated, unsaid] = self.keys();
        matches!(read(seat), Some(Inclusion::Present(_)))
            && matches!(read(row), Some(Inclusion::Present(_)))
            && read(unseated) == Some(Inclusion::Absent)
            && read(unsaid) == Some(Inclusion::Absent)
    }

    /// Whether `claims` answer it at one anchor. The readings may sit in
    /// several claims at that anchor: one anchor is one root, however its
    /// cells were cut.
    #[must_use]
    pub fn proven_by<'c>(&self, claims: impl IntoIterator<Item = &'c StateClaim>) -> bool {
        let claims: Vec<&StateClaim> = claims
            .into_iter()
            .filter(|claim| claim.anchor.shard == self.shard)
            .collect();
        let anchors: BTreeSet<Anchor> = claims.iter().map(|claim| claim.anchor).collect();
        anchors.into_iter().any(|anchor| {
            self.answered_by(|key| {
                claims
                    .iter()
                    .filter(|claim| claim.anchor == anchor)
                    .find_map(|claim| claim.reading(key))
            })
        })
    }
}

/// The seat questions the pending core members of `rows` put.
///
/// One for each pending core member short of its deadline at `anchor`
/// and each core member in flight that refuses it, is earlier in hash
/// order, and awaits a counterpart it awaits, per counterpart. The
/// refusal is asked both ways: the waiting member's seat on the
/// counterpart must refuse the holder there too, or an unseated holder
/// would read as a cycle when it was only not yet ready. A holder past
/// its own deadline asks nothing: the counterpart where it waits aborts
/// it, which breaks the cycle with no victim here.
#[must_use]
pub fn seat_questions(rows: &MemberIndex, anchor: WeightedTimestamp) -> Vec<SeatQuestion> {
    let holders: Vec<CoreHolder<'_>> = in_flight_holders(
        rows.members
            .values()
            .filter(|row| !row.deadline.passed(anchor)),
    )
    .collect();
    if holders.is_empty() {
        return Vec::new();
    }
    let mut questions = Vec::new();
    for row in rows.members.values() {
        if row.state != RowState::Pending || row.deadline.passed(anchor) {
            continue;
        }
        let waiting = Judged::of_row(row);
        if waiting.settlement != Settlement::Shared {
            continue;
        }
        let mut seat: Option<ProvisionalCells> = None;
        for holder in holders
            .iter()
            .filter(|holder| holder.tx < row.tx && holder.refuses(&waiting))
        {
            let seat = seat.get_or_insert_with(|| {
                let mut cells = ProvisionalCells::default();
                cells.claim(waiting.declared);
                cells
            });
            if !seat.blocks(holder.holds) {
                continue;
            }
            questions.extend(holder.shared(&waiting).map(|shard| SeatQuestion {
                shard,
                waiting: row.tx,
                holder: holder.tx,
            }));
        }
    }
    questions
}

#[cfg(test)]
mod tests {
    use std::slice::from_ref;
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_effects_bridge::vault_key;
    use hyperscale_hbor::{Bytes, to_vec};
    use hyperscale_storage::{
        MemberInputs, SettledHalf, TickRow, Waiting, fate_writes, member_writes,
    };
    use hyperscale_types::test_utils::{
        StubTree, proven_claim, stub_abort_charge, stub_stated_terms,
    };
    use hyperscale_types::{
        AddressClass, BlockHeight, DeclaredRange, DeclaredWork, Derivation, DerivationError,
        Derived, EPOCH_DURATION, EntryKey, Epoch, GlobalReceiptHash, HALT_THRESHOLD_EPOCHS, Hash,
        Heard, LocalKey, MAX_HOLDS_PER_MEMBER, MAX_NAMED_MEMBERS_PER_TICK, MAX_TICK_MANIFEST_BYTES,
        MAX_TXS_PER_BLOCK, MAX_VALIDITY_RANGE, NetworkId, PrincipalAddr, ReadMark, Routing, Said,
        StatedTerms, TICK_LINE_BYTES, TRANSACTION_EVIDENCE_HORIZON, Terms, TickHalf,
        TimestampRange, TransactionEnvelope, Unpublished, entry_leaf_key,
        tick_manifest_admits_members,
    };
    use hyperscale_vm_effects::{Hash32, IntentHash};
    use hyperscale_vm_types::Moves;

    use super::*;
    use crate::genesis::PROTOCOL_RESOURCE;

    /// [`member_lines`] without the budget they leave.
    fn lines_and_missing(
        rows: &MemberIndex,
        anchor: WeightedTimestamp,
        inputs: &dyn CommittedInputs,
        evidence: &dyn Fn(ShardId) -> Evidence,
        recovery: bool,
        wounded: &BTreeSet<TxHash>,
    ) -> (Vec<TickLine>, Vec<TxHash>) {
        let (lines, missing, _) = member_lines(rows, anchor, inputs, evidence, recovery, wounded);
        (lines, missing)
    }

    fn cell(owner: u8, local: u8) -> DeclaredKey {
        DeclaredKey::Cell(SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Component),
            local: LocalKey([local; 16]),
        })
    }

    fn interval(owner: u8, lo: u128, hi: u128) -> DeclaredKey {
        DeclaredKey::Range(DeclaredRange {
            owner: Address::new([owner; 31], AddressClass::Component),
            collection: CollectionId([7; 16]),
            lo,
            hi,
            cap: 8,
        })
    }

    const RESERVE: Mode = Mode::Reserve { amount: 5 };
    const WRITE: Mode = Mode::Write { moves: Moves::Both };
    const DEBIT: Mode = Mode::Delta { moves: Moves::Out };
    const CREDIT: Mode = Mode::Delta { moves: Moves::In };

    #[test]
    fn nothing_is_blocked_by_an_empty_claim_set() {
        let claims = ProvisionalCells::default();
        assert!(claims.is_empty());
        assert!(!claims.blocks(&[(cell(1, 1), WRITE)]));
    }

    /// The reason the whole relation is here: payment traffic is a
    /// reservation out and a credit in, and those compose. A vault an
    /// unresolved leg is moving does not stop the next payment from
    /// moving it too.
    #[test]
    fn commutative_access_does_not_wait_on_commutative_access() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), CREDIT)]);
        assert!(!claims.blocks(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]));
        assert!(!claims.blocks(&[(cell(1, 1), RESERVE)]));

        let mut reserved = ProvisionalCells::default();
        reserved.claim(&[(cell(1, 1), RESERVE)]);
        assert!(!reserved.blocks(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]));
        assert!(!reserved.blocks(&[(cell(1, 1), RESERVE)]));
    }

    /// A read depends on the value, and an exclusive write replaces it.
    /// Neither survives a change it cannot see.
    #[test]
    fn a_read_or_an_exclusive_write_still_waits() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]);
        assert!(claims.blocks(&[(cell(1, 1), Mode::Read)]));
        assert!(claims.blocks(&[(cell(1, 1), WRITE)]));
    }

    /// An exclusive claim excludes everything, commutative included: it
    /// carries an absolute, and an absolute composes with nothing.
    #[test]
    fn an_exclusive_claim_excludes_every_mode() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), WRITE)]);
        for mode in [
            Mode::Delta { moves: Moves::Both },
            RESERVE,
            Mode::Read,
            WRITE,
        ] {
            assert!(
                claims.blocks(&[(cell(1, 1), mode)]),
                "{mode:?} slipped past"
            );
        }
    }

    #[test]
    fn a_claim_leaves_siblings_and_other_owners_alone() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), WRITE)]);
        assert!(!claims.blocks(&[(cell(1, 2), WRITE)]), "sibling cell");
        assert!(!claims.blocks(&[(cell(2, 1), WRITE)]), "other owner");
    }

    /// Two intervals of one collection contend by mode alone — the
    /// interval-insensitive half of the kernel's overlap arithmetic —
    /// and an interval never contends with a point cell, which no
    /// interval contains.
    #[test]
    fn intervals_contend_by_collection_and_leave_points_alone() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(interval(1, 0, 10), WRITE)]);
        assert!(claims.blocks(&[(interval(1, 20, 30), Mode::Read)]));
        assert!(!claims.blocks(&[(cell(1, 1), WRITE)]));

        let mut over_cell = ProvisionalCells::default();
        over_cell.claim(&[(cell(1, 1), WRITE)]);
        assert!(!over_cell.blocks(&[(interval(1, 0, 10), WRITE)]));
    }

    /// A debiting delta states no amount, so nothing holds what an
    /// in-flight one took: a second debit of the cell, stated or not,
    /// would be judged against a balance that hides the first.
    #[test]
    fn a_held_delta_debit_blocks_a_second_debit() {
        for held in [DEBIT, Mode::Delta { moves: Moves::Both }] {
            let mut claims = ProvisionalCells::default();
            claims.claim(&[(cell(1, 1), held)]);
            for mode in [DEBIT, Mode::Delta { moves: Moves::Both }, RESERVE] {
                assert!(
                    claims.blocks(&[(cell(1, 1), mode)]),
                    "{mode:?} slipped past a held {held:?}"
                );
            }
            assert!(!claims.blocks(&[(cell(1, 2), DEBIT)]), "sibling cell");
        }
    }

    /// A credit cannot run past the cell whatever it does not see, and a
    /// held credit hides nothing a debit could overdraw.
    #[test]
    fn it_admits_a_credit() {
        let mut debited = ProvisionalCells::default();
        debited.claim(&[(cell(1, 1), DEBIT)]);
        assert!(!debited.blocks(&[(cell(1, 1), CREDIT)]));

        let mut credited = ProvisionalCells::default();
        credited.claim(&[(cell(1, 1), CREDIT)]);
        for mode in [DEBIT, Mode::Delta { moves: Moves::Both }, RESERVE] {
            assert!(!credited.blocks(&[(cell(1, 1), mode)]), "{mode:?}");
        }
    }

    /// The fee is the one debiting delta on a protocol vault, and its fee
    /// hold bounds it: a payer's in-flight member keeps none of its
    /// other transactions out.
    #[test]
    fn a_fee_entry_blocks_nothing() {
        let vault = vault_key(PrincipalAddr::new([0x52; 31]), *PROTOCOL_RESOURCE);
        assert!(is_protocol_vault(&vault));
        let vault = DeclaredKey::Cell(vault);
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(vault, DEBIT)]);
        for mode in [DEBIT, RESERVE, CREDIT] {
            assert!(!claims.blocks(&[(vault, mode)]), "{mode:?}");
        }
    }

    /// Committed inputs as a test states them.
    #[derive(Default)]
    struct Held {
        engaged: BTreeSet<(ShardId, TxHash)>,
        arrived: BTreeSet<(SubstateKey, TxHash)>,
    }

    impl CommittedInputs for Held {
        fn engaged(&self, source: ShardId, tx: TxHash) -> bool {
            self.engaged.contains(&(source, tx))
        }

        fn arrived(&self, key: SubstateKey, tx: TxHash) -> bool {
            self.arrived.contains(&(key, tx))
        }
    }

    const PEER: ShardId = ShardId::leaf(1, 1);

    const CHARGE: AbortCharge = stub_abort_charge(0);

    const UNRESERVED: &Reserves = &Capped::empty();

    fn pending(tx: TxHash, terms: &MemberTerms, deadline: Deadline) -> Nameable<'_> {
        Nameable {
            tx,
            deadline,
            standing: Standing::Pending(Judged::of(terms)),
            charge: CHARGE,
            share: 0,
            reserves: UNRESERVED,
            nevers: None,
        }
    }

    /// The `Pending` row a block stating `terms` writes for `seed`.
    fn stating(seed: u8, deadline: Deadline, terms: &MemberTerms) -> MemberRow {
        MemberRow {
            tx: tx(seed),
            deadline,
            committed: ms(0),
            height: BlockHeight::new(1),
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

    /// A deadline no fixture reaches.
    fn far() -> Deadline {
        Deadline::of(WeightedTimestamp::from_millis(u64::MAX / 2))
    }

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    fn ms(v: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(v)
    }

    /// The terms of a member reaching no other shard.
    fn alone(declared: Vec<(DeclaredKey, Mode)>) -> MemberTerms {
        MemberTerms {
            leg: false,
            settlement: Settlement::Alone,
            declared: Capped::new(declared).expect("within the cap"),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            engages: Capped::empty(),
            crossings: Capped::empty(),
            waits: false,
            charge: CHARGE,
            share: 0,
            reserves: Capped::empty(),
        }
    }

    /// The terms of a core member with a sibling on `PEER`, requiring
    /// the committed bundle of each of `engages`.
    fn leg(declared: Vec<(DeclaredKey, Mode)>, engages: &[ShardId]) -> MemberTerms {
        MemberTerms {
            settlement: Settlement::Shared,
            reach: Capped::from_array([PEER]),
            awaits: Capped::from_array([PEER]),
            engages: Capped::new(engages.to_vec()).expect("within the cap"),
            ..alone(declared)
        }
    }

    /// A derivation under which a transaction declares exactly the
    /// accesses a test states, and nothing of a tree.
    struct Declaring(Vec<(DeclaredKey, Mode)>);

    impl Derivation for Declaring {
        fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
            let stub = StubTree::decode(vm)?;
            let mut declared_modes = self.0.clone();
            declared_modes.sort_unstable();
            let work = DeclaredWork {
                compute: stub.terms.gas_limit_total(),
                footprint: declared_modes.len() as u64,
                ..DeclaredWork::ZERO
            };
            let payer = stub.terms.fee_payer;
            Ok(Derived {
                accounts: vec![payer.address()],
                effective_window: stub.window(),
                network: stub.network,
                routing: Routing {
                    read_keys: Vec::new(),
                    write_keys: declared_modes.iter().map(|(key, _)| *key).collect(),
                    read_prefixes: Vec::new(),
                    write_prefixes: declared_modes.iter().map(|(key, _)| key.owner()).collect(),
                    provision_keys: Vec::new(),
                    provision_prefixes: Vec::new(),
                    declared_modes,
                },
                attested_by: vec![payer],
                attestations: Vec::new(),
                fee_vault_local: vault_key(payer, *PROTOCOL_RESOURCE).local.0,
                auth_cell_local: [0xAE; 16],
                work,
                shares: Vec::new(),
                node_terms: Vec::new(),
                artifacts: Vec::new(),
                everywhere: work,
                legs: Vec::new(),
                nullifiers: Vec::new(),
                packages: Vec::new(),
                terms: stub.terms,
            })
        }
    }

    /// A transaction `payer` pays for that declares `declared`.
    fn declaring(payer: PrincipalAddr, declared: Vec<(DeclaredKey, Mode)>) -> Transaction {
        let vm = StubTree {
            terms: Terms {
                fee_payer: payer,
                max_fee: 1_000,
                gas_limits: Capped::from_array([1_000_000]),
                priority_bp: 0,
                message: Bytes::empty(),
            },
            network: NetworkId(242),
            members: 0,
            validity: TimestampRange::new(ms(0), ms(60_000)),
            body: Vec::new(),
        }
        .envelope();
        let tx = Transaction::new(vm);
        tx.try_derived(&Declaring(declared))
            .expect("the fixture derivation routes it");
        tx
    }

    /// A member reserving twice on its own payer's protocol vault, once
    /// on a remote principal's and once on a local component's, beside a
    /// debit of the first: its shard, its transaction, the payer's vault
    /// and the terms it derives.
    fn reserving_member() -> (ShardId, Transaction, SubstateKey, MemberTerms) {
        let trie = ShardTrie::uniform_from_count(2);
        let principal_on = |shard: ShardId, wanted: bool| {
            (0u8..=255)
                .map(|seed| PrincipalAddr::new([seed; 31]))
                .find(|principal| (trie.shard_for_prefix(*principal) == shard) == wanted)
                .expect("a principal routes to each shard")
        };
        let payer = PrincipalAddr::new([0x52; 31]);
        let local = trie.shard_for_prefix(payer);
        let remote = principal_on(local, false);
        let till = (0u8..=255)
            .map(|seed| Address::new([seed; 31], AddressClass::Component))
            .find(|component| trie.shard_for_prefix(*component) == local)
            .expect("a component routes to each shard");
        let vault = vault_key(payer, *PROTOCOL_RESOURCE);
        let tx = declaring(
            payer,
            vec![
                (DeclaredKey::Cell(vault), Mode::Reserve { amount: 60 }),
                (DeclaredKey::Cell(vault), Mode::Reserve { amount: 25 }),
                (DeclaredKey::Cell(vault), DEBIT),
                (
                    DeclaredKey::Cell(vault_key(remote, *PROTOCOL_RESOURCE)),
                    Mode::Reserve { amount: 7 },
                ),
                (
                    DeclaredKey::Cell(vault_key(till, *PROTOCOL_RESOURCE)),
                    Mode::Reserve { amount: 9 },
                ),
            ],
        );
        let participating: BTreeSet<ShardId> = tx
            .routing()
            .write_prefixes
            .iter()
            .map(|owner| trie.shard_for_prefix(*owner))
            .collect();
        assert_eq!(participating.len(), 2);
        let member = Member::of(
            Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &trie),
            local,
            participating,
        );
        let terms = terms_of_member(&member, &tx, &trie, &PriceTable::GENESIS);
        (local, tx, vault, terms)
    }

    /// An entry and a member line carrying `terms` with reservations at
    /// the cap encode under their weights.
    fn reserves_at_the_cap_encode_under_their_weights(tx: TxHash, terms: MemberTerms) {
        let widest: Reserves = Capped::new(
            (0..MAX_HOLDS_PER_MEMBER)
                .map(|at| {
                    let mut owner = [0xFF; 31];
                    owner[..8].copy_from_slice(&(at as u64).to_le_bytes());
                    (
                        vault_key(PrincipalAddr::new(owner), *PROTOCOL_RESOURCE),
                        u128::MAX,
                    )
                })
                .collect(),
        )
        .expect("a list at the cap");
        let entry = StatedTerms {
            tx,
            terms: MemberTerms {
                reserves: widest,
                ..terms
            },
        };
        assert!(to_vec(&entry).expect("an entry encodes").len() <= entry.terms.wire_weight());
        let line = TickLine::Member {
            tx,
            joins: Joins::Aborted,
            settlement: Settlement::Awaited,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: entry.terms.charge,
            share: u128::MAX,
            reserves: entry.terms.reserves,
            deadline: far(),
            nevers: Capped::empty(),
        };
        assert!(to_vec(&line).expect("a line encodes").len() <= line.wire_weight());
    }

    /// A member's row states what its declared reservations promise of
    /// the fee vaults its shard holds: a principal's protocol vault under
    /// the local prefix, once, at the sum reserved on it. A vault on
    /// another shard, a component's cell and every other mode state
    /// nothing. The row carries them whether an entry or a line of its
    /// own block wrote it, through a naming and a release, and an entry
    /// and a line at the cap encode under their weights.
    #[test]
    fn a_row_states_its_local_reservations_for_as_long_as_it_stands() {
        let (local, tx, vault, terms) = reserving_member();
        let reserved: Reserves = Capped::from_array([(vault, 85)]);
        assert_eq!(terms.reserves, reserved);
        assert_eq!(terms.declared.len(), 5, "what it declared stands beside");

        let at = |height: u64| BlockHeight::new(height);
        let deadline = Deadline::of_transaction(&tx);
        let line = |joins| TickLine::Member {
            tx: tx.hash(),
            joins,
            settlement: terms.settlement,
            holds: terms.declared.clone(),
            reach: terms.reach.clone(),
            awaits: terms.awaits.clone(),
            charge: terms.charge,
            share: terms.share,
            reserves: terms.reserves.clone(),
            deadline,
            nevers: Capped::empty(),
        };
        let committing = |stated: Vec<StatedTerms>, lines: Vec<TickLine>| MemberInputs {
            height: at(1),
            transactions: vec![(tx.hash(), deadline)],
            terms: stated,
            manifest: Arc::new(Capped::new(lines).expect("a list written out in a test")),
            ..MemberInputs::still(local)
        };
        let entry = StatedTerms {
            tx: tx.hash(),
            terms: terms.clone(),
        };

        let mut by_entry = MemberIndex::empty(local);
        by_entry.advance(&committing(vec![entry], Vec::new()));

        let mut by_line = MemberIndex::empty(local);
        by_line.advance(&committing(Vec::new(), vec![line(Joins::Executes)]));
        assert_eq!(by_entry.members[&tx.hash()].reserves, reserved);
        assert_eq!(by_line.members[&tx.hash()].reserves, reserved);

        by_entry.advance(&MemberInputs {
            height: at(2),
            manifest: Arc::new(Capped::from_array([line(Joins::Executes)])),
            ..MemberInputs::still(local)
        });
        assert!(matches!(
            by_entry.members[&tx.hash()].state,
            RowState::InFlight { .. }
        ));
        assert_eq!(by_entry.members[&tx.hash()].reserves, reserved, "named");
        by_entry.advance(&MemberInputs {
            height: at(3),
            manifest: Arc::new(Capped::from_array([TickLine::Discard {
                tick: TickId::new(local, at(2)),
                cause: DiscardCause::Recovery,
            }])),
            ..MemberInputs::still(local)
        });
        assert!(matches!(
            by_entry.members[&tx.hash()].state,
            RowState::Released { .. }
        ));
        assert_eq!(by_entry.members[&tx.hash()].reserves, reserved, "released");

        reserves_at_the_cap_encode_under_their_weights(tx.hash(), terms);
    }

    /// A multi-core member in flight at the terminal is one no
    /// finalization settled here: settling a member deletes its row, so
    /// the terminal fates exactly the members still outside the settled
    /// set, each at the charge its line kept.
    #[test]
    fn in_flight_multi_core_at_the_terminal_is_unsettled() {
        let shard = ShardId::ROOT;
        let at = |height: u64| BlockHeight::new(height);
        let mut rows = MemberIndex::empty(shard);
        rows.advance(&MemberInputs {
            height: at(1),
            transactions: vec![(tx(1), far()), (tx(2), far())],
            terms: vec![stub_stated_terms(tx(1), 1), stub_stated_terms(tx(2), 2)],
            ..MemberInputs::still(shard)
        });
        let in_flight = |seed: u8| TickLine::Member {
            tx: tx(seed),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::empty(),
            reach: Capped::from_array([PEER]),
            awaits: Capped::empty(),
            charge: stub_abort_charge(seed),
            share: 0,
            reserves: Capped::empty(),
            deadline: far(),
            nevers: Capped::empty(),
        };
        rows.advance(&MemberInputs {
            height: at(2),
            manifest: Arc::new(Capped::from_array([in_flight(1), in_flight(2)])),
            ..MemberInputs::still(shard)
        });
        rows.advance(&MemberInputs {
            height: at(3),
            settled: vec![SettledHalf {
                tick: TickId::new(shard, at(2)),
                half: TickHalf::Legs,
                deleted: vec![tx(1)],
                stated: Vec::new(),
                accepted: Vec::new(),
            }],
            ..MemberInputs::still(shard)
        });

        assert_eq!(
            terminal_fates(&rows),
            vec![TickLine::Fate {
                tx: tx(2),
                charge: stub_abort_charge(2),
            }],
        );
    }

    /// A member no line has named is fated at the charge its committing
    /// block stated, read off its row: the terminal asks nothing of the
    /// node naming it.
    #[test]
    fn a_terminal_fates_a_pending_row_off_its_row() {
        let shard = ShardId::ROOT;
        let mut rows = MemberIndex::empty(shard);
        rows.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(tx(1), far()), (tx(2), far())],
            terms: vec![stub_stated_terms(tx(1), 1), stub_stated_terms(tx(2), 2)],
            ..MemberInputs::still(shard)
        });
        assert!(
            rows.members
                .values()
                .all(|row| row.state == RowState::Pending)
        );
        assert_eq!(
            terminal_fates(&rows),
            vec![
                TickLine::Fate {
                    tx: tx(1),
                    charge: stub_abort_charge(1),
                },
                TickLine::Fate {
                    tx: tx(2),
                    charge: stub_abort_charge(2),
                },
            ],
        );
    }

    /// A member waits on every bundle and crossing it requires, and a
    /// payer on its counterparts' engagement until the wait's deadline,
    /// past which it runs attested aborted.
    #[test]
    fn a_member_is_ready_once_its_committed_inputs_are() {
        let crossing = CrossingId {
            producer: Address::new([3; 31], AddressClass::Component),
            consumer: Address::new([4; 31], AddressClass::Component),
            intent: IntentHash(Hash32([3; 32])),
            local: 0,
            output: 0,
        };
        let record = crossing.record_key(&ProtocolHasher);
        let terms = MemberTerms {
            crossings: Capped::from_array([crossing]),
            ..leg(vec![], &[PEER])
        };
        let deadline = Deadline::of(ms(5_000));
        let ready = |terms: &MemberTerms, at: WeightedTimestamp, held: &Held| {
            readiness(tx(1), &Judged::of(terms), deadline, at, held)
        };
        let mut held = Held::default();
        assert_eq!(ready(&terms, ms(0), &held), None);
        held.engaged.insert((PEER, tx(1)));
        assert_eq!(ready(&terms, ms(0), &held), None, "the crossing");
        held.arrived.insert((record, tx(2)));
        assert_eq!(
            ready(&terms, ms(0), &held),
            None,
            "an arrival naming another transaction answers nothing"
        );
        held.arrived.insert((record, tx(1)));
        assert_eq!(ready(&terms, ms(0), &held), Some(Joins::Executes));

        let payer = MemberTerms {
            waits: true,
            ..leg(vec![], &[])
        };
        let silent = Held::default();
        assert_eq!(
            ready(
                &payer,
                deadline.at().minus(Duration::from_millis(1)),
                &silent
            ),
            None
        );
        assert_eq!(
            ready(&payer, deadline.at(), &silent),
            Some(Joins::ExecutesAborted)
        );
        assert_eq!(
            ready(&payer, ms(0), &held),
            Some(Joins::Executes),
            "an engaged counterpart ends the wait"
        );
        assert_eq!(ready(&alone(vec![]), ms(0), &silent), Some(Joins::Executes));
    }

    /// Members reaching beyond the shard are named first, a member an
    /// earlier abortable one's hold refuses is skipped, one awaiting
    /// nobody claims nothing, and no terms state a declaration a line
    /// cannot carry.
    #[test]
    fn members_are_named_in_canonical_order_under_the_hold_rule() {
        let shared = cell(1, 1);
        let reaching = leg(vec![(shared, WRITE)], &[]);
        let local = alone(vec![(shared, WRITE)]);
        let held = Held::default();
        let mut holds = ProvisionalCells::default();
        let lines = select_members(
            ms(0),
            [
                pending(tx(1), &local, far()),
                pending(tx(9), &reaching, far()),
            ],
            &held,
            &mut holds,
            &mut ManifestBudget::default(),
        );
        let named: Vec<TxHash> = lines
            .iter()
            .map(|line| match line {
                TickLine::Member { tx, .. } => *tx,
                other @ (TickLine::Discard { .. }
                | TickLine::Fate { .. }
                | TickLine::End { .. }) => {
                    panic!("{other:?}")
                }
            })
            .collect();
        assert_eq!(
            named,
            vec![tx(9)],
            "the reaching member goes first and its write holds the local one out",
        );
        assert!(holds.blocks(&[(shared, WRITE)]));

        let mut holds = ProvisionalCells::default();
        let lines = select_members(
            ms(0),
            [
                pending(tx(1), &local, far()),
                pending(tx(2), &alone(vec![(shared, WRITE)]), far()),
            ],
            &held,
            &mut holds,
            &mut ManifestBudget::default(),
        );
        assert_eq!(lines.len(), 2, "determined members hold nothing back");
        assert!(holds.is_empty());
        assert!(lines.iter().all(|line| matches!(
            line,
            TickLine::Member { holds, settlement: Settlement::Alone, .. } if holds.is_empty()
        )));

        assert!(
            Holds::new(vec![(shared, RESERVE); MAX_HOLDS_PER_MEMBER + 1]).is_err(),
            "a declaration no line can carry is stated by no terms",
        );
    }

    /// The walk stops at the first line the budget refuses.
    #[test]
    fn the_walk_stops_at_the_budget() {
        let declared: Vec<(DeclaredKey, Mode)> = (0..MAX_HOLDS_PER_MEMBER)
            .map(|at| (interval(9, at as u128, at as u128), RESERVE))
            .collect();
        let wide = leg(declared, &[]);
        let candidates: Vec<Nameable<'_>> = (0..8u8)
            .map(|seed| pending(tx(seed), &wide, far()))
            .collect();
        let lines = select_members(
            ms(0),
            candidates,
            &Held::default(),
            &mut ProvisionalCells::default(),
            &mut ManifestBudget::default(),
        );
        let fits = MAX_TICK_MANIFEST_BYTES / lines[0].wire_weight();
        assert_eq!(lines.len(), fits.min(8));
        assert!(lines.len() < 8, "the fixture must reach the budget");
    }

    /// A manifest names no more members than a tick's manifest may,
    /// whether it names them to run or aborted: a member line holding
    /// nothing is the lightest there is, so neither the bytes nor the
    /// line cap stops the walk first, and the rest wait a block.
    #[test]
    fn the_walk_stops_at_the_member_cap() {
        let determined = alone(Vec::new());
        let waiting: Vec<TxHash> = (0..=MAX_NAMED_MEMBERS_PER_TICK as u64)
            .map(|at| TxHash::from(Hash::from_bytes(&at.to_be_bytes())))
            .collect();
        for (anchor, joins) in [(ms(0), Joins::Executes), (far().at(), Joins::Aborted)] {
            let lines = select_members(
                anchor,
                waiting.iter().map(|&tx| pending(tx, &determined, far())),
                &Held::default(),
                &mut ProvisionalCells::default(),
                &mut ManifestBudget::default(),
            );
            assert_eq!(lines.len(), MAX_NAMED_MEMBERS_PER_TICK, "{joins:?}");
            assert!(
                lines.iter().all(|line| matches!(
                    line,
                    TickLine::Member { joins: named, .. } if *named == joins
                )),
                "{joins:?}",
            );
        }
    }

    /// A tick seats as many members as a block carries: every
    /// transaction one block commits is named to run in one tick, and
    /// the manifest naming them all is admitted, with no seat held back
    /// for a member no line names.
    #[test]
    fn a_tick_seats_as_many_members_as_a_block_carries() {
        assert_eq!(MAX_NAMED_MEMBERS_PER_TICK, MAX_TXS_PER_BLOCK);
        let determined = alone(Vec::new());
        let carried: Vec<TxHash> = (0..MAX_TXS_PER_BLOCK as u64)
            .map(|at| TxHash::from(Hash::from_bytes(&at.to_be_bytes())))
            .collect();
        let lines = select_members(
            ms(0),
            carried.iter().map(|&tx| pending(tx, &determined, far())),
            &Held::default(),
            &mut ProvisionalCells::default(),
            &mut ManifestBudget::default(),
        );
        assert_eq!(lines.len(), MAX_TXS_PER_BLOCK);
        assert!(tick_manifest_admits_members(lines.len()));
    }

    /// Past its deadline a candidate is named `Aborted`, whether or not
    /// it is ready and whatever holds stand, and a leg is not named at
    /// all: its fate ends it.
    #[test]
    fn a_candidate_past_its_deadline_is_named_aborted() {
        let shared = cell(1, 1);
        let passed = Deadline::of(ms(0));
        let waiting = leg(vec![(shared, WRITE)], &[PEER]);
        let a_leg = MemberTerms {
            leg: true,
            ..alone(vec![])
        };
        let mut holds = ProvisionalCells::default();
        holds.claim(&[(shared, WRITE)]);
        let anchor = ms(60_000);
        assert!(passed.passed(anchor));
        let lines = select_members(
            anchor,
            [
                pending(tx(1), &waiting, passed),
                pending(tx(2), &a_leg, passed),
            ],
            &Held::default(),
            &mut holds,
            &mut ManifestBudget::default(),
        );
        assert_eq!(
            lines,
            vec![TickLine::Member {
                tx: tx(1),
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                awaits: Capped::empty(),
                charge: CHARGE,
                share: 0,
                reserves: Capped::empty(),
                deadline: passed,
                nevers: Capped::empty(),
            }],
        );
    }

    /// A core member waits on every sibling's committed bundle, so one
    /// whose sibling never engages is never named to run, and its row,
    /// still `Pending`, is named `Aborted` at the deadline.
    #[test]
    fn a_core_member_whose_sibling_never_engages_is_aborted_at_its_deadline() {
        let core = leg(vec![], &[PEER]);
        let deadline = Deadline::of(ms(10_000));
        let named = |at: WeightedTimestamp| {
            select_members(
                at,
                [pending(tx(1), &core, deadline)],
                &Held::default(),
                &mut ProvisionalCells::default(),
                &mut ManifestBudget::default(),
            )
        };
        assert!(
            named(deadline.at().minus(Duration::from_millis(1))).is_empty(),
            "no sibling bundle, no run"
        );
        assert_eq!(
            named(deadline.at()),
            vec![TickLine::Member {
                tx: tx(1),
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                awaits: Capped::empty(),
                charge: CHARGE,
                share: 0,
                reserves: Capped::empty(),
                deadline,
                nevers: Capped::empty(),
            }],
        );
    }

    /// A held row is a candidate only past its deadline, covered by a
    /// departure, held by a tick that is not its abandonment, and one a
    /// counterpart's verdict can discard, and it is judged on its row
    /// alone.
    #[test]
    fn member_lines_name_a_held_row_on_the_row_alone() {
        let deadline = Deadline::of(ms(10_000));
        let row = |seed: u8, joins, settlement, covered| MemberRow {
            tx: tx(seed),
            deadline,
            committed: ms(0),
            height: BlockHeight::new(1),
            state: RowState::InFlight {
                tick: BlockHeight::new(2),
                joins,
                settlement,
            },
            holds: Capped::empty(),
            reach: Capped::from_array([PEER]),
            awaits: Capped::empty(),
            covered,
            charge: CHARGE,
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            waiting: None,
            executed: joins.dispatched(),
            hearing: Capped::empty(),
        };
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        for held in [
            row(1, Joins::Executes, Settlement::Shared, true),
            row(2, Joins::Executes, Settlement::Shared, false),
            row(3, Joins::Aborted, Settlement::Awaited, true),
            row(4, Joins::Executes, Settlement::Alone, true),
        ] {
            rows.members.insert(held.tx, held);
        }
        let live = |_| Evidence::Live { terminating: false };
        let lines = |at: WeightedTimestamp| {
            lines_and_missing(&rows, at, &Held::default(), &live, false, &BTreeSet::new())
        };
        let (before, missing) = lines(deadline.at().minus(Duration::from_millis(1)));
        assert!(before.is_empty() && missing.is_empty());
        let (after, missing) = lines(deadline.at());
        assert!(
            missing.is_empty(),
            "a held row a shard answers for defers nobody"
        );
        assert_eq!(
            after,
            vec![
                TickLine::Member {
                    tx: tx(1),
                    joins: Joins::Aborted,
                    settlement: Settlement::Awaited,
                    holds: Capped::empty(),
                    reach: Capped::from_array([PEER]),
                    awaits: Capped::empty(),
                    charge: CHARGE,
                    share: 0,
                    reserves: Capped::empty(),
                    deadline,
                    nevers: Capped::empty(),
                },
                TickLine::Discard {
                    tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                    cause: DiscardCause::Abandoned(tx(1)),
                },
            ],
        );
    }

    /// A row standing as `state`, reaching `PEER`, past `deadline` at
    /// the anchors a test reads it at.
    fn standing(seed: u8, deadline: Deadline, state: RowState, covered: bool) -> MemberRow {
        MemberRow {
            tx: tx(seed),
            deadline,
            committed: ms(0),
            height: BlockHeight::new(1),
            state,
            holds: Capped::empty(),
            reach: Capped::from_array([PEER]),
            awaits: Capped::empty(),
            covered,
            charge: stub_abort_charge(seed),
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            waiting: None,
            executed: true,
            hearing: Capped::empty(),
        }
    }

    /// The lines named over `row` alone at `anchor`, every shard reading
    /// `evidence`.
    fn lines_over(
        row: &MemberRow,
        anchor: WeightedTimestamp,
        evidence: Evidence,
    ) -> (Vec<TickLine>, Vec<TxHash>) {
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        rows.members.insert(row.tx, row.clone());
        lines_and_missing(
            &rows,
            anchor,
            &Held::default(),
            &|_| evidence,
            false,
            &BTreeSet::new(),
        )
    }

    fn fate_of(seed: u8) -> TickLine {
        TickLine::Fate {
            tx: tx(seed),
            charge: stub_abort_charge(seed),
        }
    }

    fn unanswerable(tick: u64, seed: u8) -> TickLine {
        TickLine::Discard {
            tick: TickId::new(ShardId::ROOT, BlockHeight::new(tick)),
            cause: DiscardCause::Unanswerable(tx(seed)),
        }
    }

    /// A member in flight that a counterpart settles against is let go
    /// of once every shard it reaches is unreadable, at any age: the
    /// `Unanswerable` discard of its tick, then its fate at the charge
    /// its row carries. That reading wins over the abort a covering
    /// record licenses past the deadline. One whose evidence is not yet
    /// folded holds the voter back, and one a shard can still answer for
    /// stands until a record covers it past its deadline.
    #[test]
    fn a_member_in_flight_nobody_can_answer_for_is_discarded_and_fated() {
        let deadline = Deadline::of(ms(10_000));
        let before = deadline.at().minus(Duration::from_millis(1));
        let in_flight = |joins, covered| {
            standing(
                1,
                deadline,
                RowState::InFlight {
                    tick: BlockHeight::new(2),
                    joins,
                    settlement: Settlement::Shared,
                },
                covered,
            )
        };
        let pair = (vec![unanswerable(2, 1), fate_of(1)], vec![]);
        for joins in [Joins::Executes, Joins::ExecutesAborted] {
            for covered in [false, true] {
                let row = in_flight(joins, covered);
                for anchor in [before, deadline.at()] {
                    assert_eq!(
                        lines_over(&row, anchor, Evidence::Unreadable),
                        pair,
                        "{joins:?}, covered {covered}, at {anchor:?}",
                    );
                    assert_eq!(
                        lines_over(&row, anchor, Evidence::Unknown),
                        (vec![], vec![tx(1)]),
                    );
                }
                for answered in [Evidence::Readable, Evidence::Live { terminating: true }] {
                    assert_eq!(
                        lines_over(&row, before, answered),
                        (vec![], vec![]),
                        "a shard that can answer keeps it short of its deadline",
                    );
                    let (lines, missing) = lines_over(&row, deadline.at(), answered);
                    assert!(missing.is_empty());
                    if covered {
                        assert!(
                            matches!(
                                lines[..],
                                [
                                    TickLine::Member {
                                        joins: Joins::Aborted,
                                        ..
                                    },
                                    TickLine::Discard {
                                        cause: DiscardCause::Abandoned(_),
                                        ..
                                    },
                                ]
                            ),
                            "a covered member a shard can still answer for is aborted at its \
                             deadline: {lines:?}",
                        );
                    } else {
                        assert!(lines.is_empty(), "{lines:?}");
                    }
                }
            }
        }
    }

    /// A member no counterpart settles against is never fated on its
    /// counterparts' evidence: an abort in flight is its own tick's to
    /// settle, and so is a member settled on this shard's certificate
    /// alone.
    #[test]
    fn a_member_in_flight_no_counterpart_settles_against_is_not_fated() {
        let deadline = Deadline::of(ms(10_000));
        for (joins, settlement) in [
            (Joins::Aborted, Settlement::Awaited),
            (Joins::Aborted, Settlement::Alone),
            (Joins::Executes, Settlement::Alone),
        ] {
            let row = standing(
                1,
                deadline,
                RowState::InFlight {
                    tick: BlockHeight::new(2),
                    joins,
                    settlement,
                },
                true,
            );
            for evidence in [Evidence::Unreadable, Evidence::Unknown] {
                assert_eq!(
                    lines_over(&row, deadline.at(), evidence),
                    (vec![], vec![]),
                    "{joins:?}, {settlement:?}, {evidence:?}",
                );
            }
        }
    }

    /// A released member a counterpart settles against is fated once
    /// every shard it reaches is unreadable, at any age and ahead of the
    /// abort its deadline licenses: no discard, since no tick holds it.
    /// One whose evidence is not yet folded holds the voter back. Beside
    /// a counterpart that can still answer it stands short of its
    /// deadline and is aborted from it, a record covering it or not.
    #[test]
    fn a_released_shared_row_nobody_can_answer_for_is_fated() {
        let deadline = Deadline::of(ms(10_000));
        let before = deadline.at().minus(Duration::from_millis(1));
        let released = |covered| {
            standing(
                1,
                deadline,
                RowState::Released {
                    settlement: Settlement::Shared,
                },
                covered,
            )
        };
        for covered in [false, true] {
            let row = released(covered);
            for anchor in [before, deadline.at()] {
                assert_eq!(
                    lines_over(&row, anchor, Evidence::Unreadable),
                    (vec![fate_of(1)], vec![]),
                    "covered {covered}, at {anchor:?}",
                );
                assert_eq!(
                    lines_over(&row, anchor, Evidence::Unknown),
                    (vec![], vec![tx(1)]),
                );
            }
            for answered in [Evidence::Readable, Evidence::Live { terminating: false }] {
                assert_eq!(lines_over(&row, before, answered), (vec![], vec![]));
                assert_eq!(
                    lines_over(&row, deadline.at(), answered),
                    (vec![aborting(&row, Capped::empty())], vec![]),
                    "covered {covered}, {answered:?}",
                );
            }
        }
    }

    /// A released member no counterpart settles against is not fated on
    /// its counterparts' evidence, whatever it reads.
    #[test]
    fn a_released_row_no_counterpart_settles_against_is_not_fated() {
        let deadline = Deadline::of(ms(10_000));
        for settlement in [Settlement::Alone, Settlement::Awaited] {
            let row = standing(1, deadline, RowState::Released { settlement }, false);
            for evidence in [Evidence::Unreadable, Evidence::Unknown] {
                let (lines, missing) = lines_over(&row, deadline.at(), evidence);
                assert!(missing.is_empty(), "{settlement:?}, {evidence:?}");
                assert!(
                    !lines
                        .iter()
                        .any(|line| matches!(line, TickLine::Fate { .. })),
                    "{settlement:?}, {evidence:?}: {lines:?}",
                );
            }
        }
    }

    const MS: Duration = Duration::from_millis(1);

    /// Every reading a shard's evidence gives.
    const READINGS: [Evidence; 5] = [
        Evidence::Live { terminating: false },
        Evidence::Live { terminating: true },
        Evidence::Readable,
        Evidence::Unreadable,
        Evidence::Unknown,
    ];

    /// The first anchor past the window `deadline`'s leg entry stands
    /// in.
    fn lapse(deadline: Deadline) -> WeightedTimestamp {
        Window::LegEntry.of(deadline).end
    }

    /// The line aborting `row`, answering `Never` for `nevers`.
    fn aborting(row: &MemberRow, nevers: Crossings) -> TickLine {
        TickLine::Member {
            tx: row.tx,
            joins: Joins::Aborted,
            settlement: if row.reach.is_empty() {
                Settlement::Alone
            } else {
                Settlement::Awaited
            },
            holds: Capped::empty(),
            reach: row.reach.clone(),
            awaits: Capped::empty(),
            charge: row.charge,
            share: row.share,
            reserves: row.reserves.clone(),
            deadline: row.deadline,
            nevers,
        }
    }

    /// The terms of `seed`'s leg, its core on `PEER`: settled on this
    /// shard's word alone, and run once `PEER`'s bundle names it.
    fn waiting_leg(seed: u8) -> MemberTerms {
        MemberTerms {
            leg: true,
            reach: Capped::from_array([PEER]),
            engages: Capped::from_array([PEER]),
            charge: stub_abort_charge(seed),
            ..alone(vec![])
        }
    }

    /// A leg still pending at its deadline is named by no line while its
    /// leg entry stands, and is fated at the charge its row carries from
    /// the anchor that window closes at, whatever its counterparts'
    /// evidence reads and whether or not its core's bundle ever came.
    #[test]
    fn a_leg_pending_past_its_deadline_is_named_for_an_exit() {
        let deadline = Deadline::of(ms(10_000));
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        for seed in [1, 2] {
            rows.members
                .insert(tx(seed), stating(seed, deadline, &waiting_leg(seed)));
        }
        let silent = Held::default();
        let engaged = Held {
            engaged: BTreeSet::from([(PEER, tx(1)), (PEER, tx(2))]),
            arrived: BTreeSet::new(),
        };
        let lines = |anchor, inputs: &Held, said: Evidence| {
            lines_and_missing(&rows, anchor, inputs, &|_| said, false, &BTreeSet::new())
        };

        let short = deadline.at().minus(MS);
        let live = Evidence::Live { terminating: false };
        assert_eq!(
            lines(short, &silent, live),
            (vec![], vec![]),
            "no bundle from the core's shard, no run",
        );
        assert!(
            matches!(
                lines(short, &engaged, live).0[..],
                [
                    TickLine::Member {
                        joins: Joins::Executes,
                        ..
                    },
                    TickLine::Member {
                        joins: Joins::Executes,
                        ..
                    },
                ]
            ),
            "short of the deadline the bundle is what names each to run",
        );

        let lapse = lapse(deadline);
        let mut fates = vec![(tx(1), fate_of(1)), (tx(2), fate_of(2))];
        fates.sort_by_key(|(tx, _)| *tx);
        let fates: Vec<TickLine> = fates.into_iter().map(|(_, fate)| fate).collect();
        for said in READINGS {
            for inputs in [&silent, &engaged] {
                for standing in [
                    deadline.at(),
                    deadline.at().plus(MAX_VALIDITY_RANGE),
                    lapse.minus(MS),
                ] {
                    assert_eq!(
                        lines(standing, inputs, said),
                        (vec![], vec![]),
                        "its fate is its road at {standing:?}, {said:?}",
                    );
                }
                for closed in [lapse, lapse.plus(TRANSACTION_EVIDENCE_HORIZON)] {
                    assert_eq!(
                        lines(closed, inputs, said),
                        (fates.clone(), vec![]),
                        "fated at {closed:?}, {said:?}",
                    );
                }
            }
        }
    }

    /// A pending member that is no leg keeps its abort line at any
    /// anchor past its deadline: the close of the leg entry window fates
    /// only a leg, and a core member's abort is what answers its
    /// producers.
    #[test]
    fn a_pending_member_that_is_no_leg_is_aborted_at_any_anchor_past_its_deadline() {
        let deadline = Deadline::of(ms(10_000));
        let core = MemberTerms {
            leg: false,
            ..waiting_leg(1)
        };
        let row = stating(1, deadline, &core);
        for said in READINGS {
            assert_eq!(
                lines_over(&row, deadline.at().minus(MS), said),
                (vec![], vec![]),
                "short of its deadline it waits on its bundle",
            );
            for anchor in [
                deadline.at(),
                lapse(deadline).minus(MS),
                lapse(deadline),
                lapse(deadline).plus(TRANSACTION_EVIDENCE_HORIZON),
            ] {
                assert_eq!(
                    lines_over(&row, anchor, said),
                    (vec![aborting(&row, Capped::empty())], vec![]),
                    "{anchor:?}, {said:?}",
                );
            }
        }
    }

    /// A member let go of that reaches no other shard is aborted from
    /// its deadline, whichever half its line said settles it, and never
    /// fated: nobody but this shard holds anything of it.
    #[test]
    fn a_released_row_reaching_nobody_is_aborted_from_its_deadline() {
        let deadline = Deadline::of(ms(10_000));
        for settlement in [Settlement::Alone, Settlement::Shared, Settlement::Awaited] {
            for covered in [false, true] {
                let row = MemberRow {
                    reach: Capped::empty(),
                    ..standing(1, deadline, RowState::Released { settlement }, covered)
                };
                for said in READINGS {
                    assert_eq!(
                        lines_over(&row, deadline.at().minus(MS), said),
                        (vec![], vec![]),
                        "{settlement:?}, covered {covered}, {said:?}",
                    );
                    for anchor in [deadline.at(), lapse(deadline)] {
                        assert_eq!(
                            lines_over(&row, anchor, said),
                            (vec![aborting(&row, Capped::empty())], vec![]),
                            "{settlement:?}, covered {covered}, {said:?} at {anchor:?}",
                        );
                    }
                }
            }
        }
    }

    /// A member let go of that is settled on this shard's word alone and
    /// reaches others, a leg or a core member no sibling shares a verdict
    /// with, is named by no line while its leg entry window stands, a
    /// covering record or not, and is fated from the anchor the window
    /// closes at: its certificate is owed nowhere, and no reading of its
    /// counterparts' evidence is asked for.
    #[test]
    fn a_released_member_settled_alone_is_fated_once_its_leg_entry_window_closes() {
        let deadline = Deadline::of(ms(10_000));
        for covered in [false, true] {
            for executed in [false, true] {
                let row = MemberRow {
                    executed,
                    ..standing(
                        1,
                        deadline,
                        RowState::Released {
                            settlement: Settlement::Alone,
                        },
                        covered,
                    )
                };
                for said in READINGS {
                    for standing in [
                        deadline.at().minus(MS),
                        deadline.at(),
                        lapse(deadline).minus(MS),
                    ] {
                        assert_eq!(
                            lines_over(&row, standing, said),
                            (vec![], vec![]),
                            "covered {covered}, executed {executed}, {said:?} at {standing:?}",
                        );
                    }
                    for closed in [
                        lapse(deadline),
                        lapse(deadline).plus(TRANSACTION_EVIDENCE_HORIZON),
                    ] {
                        assert_eq!(
                            lines_over(&row, closed, said),
                            (vec![fate_of(1)], vec![]),
                            "covered {covered}, executed {executed}, {said:?} at {closed:?}",
                        );
                    }
                }
            }
        }
    }

    /// A member let go of out of an abort is aborted again from its
    /// deadline, whether or not it ran and a record covering it or not.
    /// It answers the crossings it consumes only where it never ran and
    /// no record covers it.
    #[test]
    fn a_released_abort_is_named_again_from_its_deadline_whether_or_not_it_ran() {
        let deadline = Deadline::of(ms(10_000));
        let consumed: Crossings = consuming().crossings;
        assert!(!consumed.is_empty());
        let released = |executed, covered| MemberRow {
            executed,
            crossings: consumed.clone(),
            ..standing(
                1,
                deadline,
                RowState::Released {
                    settlement: Settlement::Awaited,
                },
                covered,
            )
        };
        for said in READINGS {
            for (executed, covered, nevers) in [
                (false, false, consumed.clone()),
                (false, true, Capped::empty()),
                (true, true, Capped::empty()),
                (true, false, Capped::empty()),
            ] {
                let row = released(executed, covered);
                assert_eq!(
                    lines_over(&row, deadline.at().minus(MS), said),
                    (vec![], vec![]),
                    "an abort a wound named and a recovery released waits for its deadline",
                );
                for anchor in [deadline.at(), lapse(deadline)] {
                    assert_eq!(
                        lines_over(&row, anchor, said),
                        (vec![aborting(&row, nevers.clone())], vec![]),
                        "executed {executed}, covered {covered}, {said:?} at {anchor:?}",
                    );
                }
            }
        }
    }

    /// The lines named over `rows` at `anchor`, every shard reading
    /// `said`, on a recovery's crossing block where `recovery`.
    fn lines_at(
        rows: &MemberIndex,
        anchor: WeightedTimestamp,
        said: Evidence,
        recovery: bool,
    ) -> (Vec<TickLine>, Vec<TxHash>) {
        lines_and_missing(
            rows,
            anchor,
            &Held::default(),
            &|_| said,
            recovery,
            &BTreeSet::new(),
        )
    }

    /// A row the tick at `tick` holds, reaching `PEER`, with a line
    /// having run it.
    fn held_in(
        seed: u8,
        deadline: Deadline,
        tick: u64,
        joins: Joins,
        settlement: Settlement,
    ) -> MemberRow {
        standing(
            seed,
            deadline,
            RowState::InFlight {
                tick: BlockHeight::new(tick),
                joins,
                settlement,
            },
            false,
        )
    }

    /// `rows` holding `members`, each under its own transaction.
    fn rows_of(members: impl IntoIterator<Item = MemberRow>) -> MemberIndex {
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        rows.members
            .extend(members.into_iter().map(|row| (row.tx, row)));
        rows
    }

    /// The tick row holding `seeds`, owing its legs half, and its
    /// determined half where `determined`.
    fn tick_holding(seeds: &[u8], determined: bool) -> TickRow {
        TickRow {
            members: Capped::new(seeds.iter().map(|&seed| tx(seed)).collect())
                .expect("a list written out in a test"),
            determined_unsettled: determined,
            awaiting: 1,
        }
    }

    /// `rows` after a block at `height` naming `lines`.
    fn naming(rows: &mut MemberIndex, height: u64, lines: Vec<TickLine>) {
        rows.advance(&MemberInputs {
            height: BlockHeight::new(height),
            manifest: Arc::new(Capped::new(lines).expect("a list written out in a test")),
            ..MemberInputs::still(ShardId::ROOT)
        });
    }

    /// A stated row's holds stand as they stood in flight: a pending
    /// member writing a cell it holds would run over provisional writes
    /// no verdict has resolved, so no line names it to run while the
    /// stated row stands, and one does once the row is gone.
    #[test]
    fn a_stated_rows_holds_keep_a_conflicting_member_out_of_a_block() {
        let held_cell = cell(1, 1);
        let stated = MemberRow {
            state: RowState::Stated {
                tick: BlockHeight::new(2),
                receipt: GlobalReceiptHash::ZERO,
            },
            holds: Capped::from_array([(held_cell, WRITE)]),
            ..held_in(1, far(), 2, Joins::Executes, Settlement::Shared)
        };
        let waiting = stating(2, far(), &alone(vec![(held_cell, WRITE)]));
        let runs = |rows: &MemberIndex| {
            let live = Evidence::Live { terminating: false };
            lines_at(rows, ms(1), live, false).0.iter().any(|line| {
                matches!(
                    line,
                    TickLine::Member { tx, joins: Joins::Executes, .. } if *tx == waiting.tx
                )
            })
        };
        let mut beside = rows_of([stated, waiting.clone()]);
        beside
            .ticks
            .insert(BlockHeight::new(2), tick_holding(&[1], false));
        assert!(
            !runs(&beside),
            "a stated row's hold keeps a conflicting member out of the block",
        );
        assert!(
            runs(&rows_of([waiting.clone()])),
            "and the member is named to run once the stated row is gone",
        );
    }

    /// A stated row takes every exit the shared member in flight it was
    /// takes, and no other: it stands beside a live counterpart, its
    /// holds still claimed; a covering record past its deadline aborts
    /// it beside the `Abandoned` discard of its tick, on a share already
    /// counted; a recovery discards its tick whole; and it is fated,
    /// after its tick's discard, once nobody can answer for it. A tick
    /// still owing its determined half lets go of it for nothing but a
    /// recovery.
    #[test]
    fn a_stated_row_takes_the_exits_of_the_shared_member_it_was() {
        let shard = ShardId::ROOT;
        let at = BlockHeight::new;
        let deadline = Deadline::of(ms(10_000));
        let live = Evidence::Live { terminating: false };
        let held_cell = cell(1, 1);
        let stated = |covered: bool| MemberRow {
            state: RowState::Stated {
                tick: at(2),
                receipt: GlobalReceiptHash::ZERO,
            },
            share: 0,
            holds: Capped::from_array([(held_cell, WRITE)]),
            covered,
            ..held_in(1, deadline, 2, Joins::Executes, Settlement::Shared)
        };
        let holding = |row: MemberRow, determined: bool| {
            let mut rows = rows_of([row]);
            rows.ticks.insert(at(2), tick_holding(&[1], determined));
            rows
        };
        let tick = TickId::new(shard, at(2));

        let standing = holding(stated(false), false);
        assert_eq!(
            lines_at(&standing, deadline.at(), live, false),
            (vec![], vec![]),
            "past its deadline and uncovered, it stands",
        );
        assert_eq!(
            in_flight_holders(standing.members.values())
                .map(|holder| holder.tx)
                .collect::<Vec<_>>(),
            vec![tx(1)],
            "a stated row holds what it held in flight",
        );

        let covered = holding(stated(true), false);
        assert_eq!(
            lines_at(&covered, ms(9_999), live, false).0,
            vec![],
            "a covering record aborts nothing short of the deadline",
        );
        assert_eq!(
            lines_at(&covered, deadline.at(), live, false).0,
            vec![
                aborting(&covered.members[&tx(1)], Capped::empty()),
                TickLine::Discard {
                    tick,
                    cause: DiscardCause::Abandoned(tx(1)),
                },
            ],
        );
        assert!(
            matches!(
                aborting(&covered.members[&tx(1)], Capped::empty()),
                TickLine::Member { share: 0, .. }
            ),
            "the abort attests nothing more: its stating half counted the member",
        );
        assert_eq!(
            lines_at(&holding(stated(true), true), deadline.at(), live, false).0,
            vec![],
            "a tick owing its determined half lets go of nothing",
        );

        assert_eq!(
            lines_at(&standing, ms(1), Evidence::Unreadable, false).0,
            vec![
                TickLine::Discard {
                    tick,
                    cause: DiscardCause::Unanswerable(tx(1)),
                },
                TickLine::Fate {
                    tx: tx(1),
                    charge: standing.members[&tx(1)].charge,
                },
            ],
        );
        assert_eq!(
            lines_at(&standing, ms(1), Evidence::Unknown, false),
            (vec![], vec![tx(1)]),
            "an unread counterpart defers, as for a row in flight",
        );
        assert_eq!(
            lines_at(&standing, ms(1), Evidence::Unreadable, true).0,
            vec![TickLine::Discard {
                tick,
                cause: DiscardCause::Recovery,
            }],
            "a recovery discards its tick whole and names nothing else of it",
        );
    }

    /// An abort its tick's discard let go of is named again. A tick
    /// holds an abort beside a member a counterpart settles against; a
    /// departure covers that member, and past its deadline the block
    /// abandons it beside the discard of the tick, which releases the
    /// abort uncovered. No finalization names the released abort and no
    /// record covers it, so the next block aborts it once more, on its
    /// row alone.
    #[test]
    fn an_abort_released_beside_an_abandoned_sibling_is_named_again() {
        let shard = ShardId::ROOT;
        let at = BlockHeight::new;
        let deadline = Deadline::of(ms(10_000));
        let live = Evidence::Live { terminating: false };
        let mut rows = rows_of([
            MemberRow {
                executed: false,
                ..held_in(1, deadline, 2, Joins::Aborted, Settlement::Awaited)
            },
            held_in(2, deadline, 2, Joins::Executes, Settlement::Shared),
        ]);
        rows.ticks.insert(at(2), tick_holding(&[1, 2], false));

        let content = MemberInputs {
            height: at(3),
            covered: vec![tx(2)],
            ..MemberInputs::still(shard)
        };
        let mut carried = rows.clone();
        carried.advance(&content);
        let (lines, missing) = lines_at(&carried, deadline.at(), live, false);
        assert!(missing.is_empty());
        assert_eq!(
            lines,
            vec![
                aborting(&carried.members[&tx(2)], Capped::empty()),
                TickLine::Discard {
                    tick: TickId::new(shard, at(2)),
                    cause: DiscardCause::Abandoned(tx(2)),
                },
            ],
            "the abort in flight is its own tick's, and only its sibling is named",
        );
        rows.advance(&MemberInputs {
            manifest: Arc::new(Capped::new(lines).expect("two lines")),
            ..content
        });
        rows.advance(&MemberInputs {
            height: at(4),
            settled: vec![SettledHalf {
                tick: TickId::new(shard, at(3)),
                half: TickHalf::Legs,
                deleted: vec![tx(2)],
                stated: Vec::new(),
                accepted: Vec::new(),
            }],
            ..MemberInputs::still(shard)
        });

        assert!(rows.ticks.is_empty(), "no tick holds anything");
        let left = rows.members[&tx(1)].clone();
        assert_eq!(rows.members.len(), 1);
        assert_eq!(
            (left.state, left.covered, left.executed),
            (
                RowState::Released {
                    settlement: Settlement::Awaited,
                },
                false,
                false,
            ),
        );
        for said in READINGS {
            for anchor in [deadline.at(), lapse(deadline)] {
                assert_eq!(
                    lines_at(&rows, anchor, said, false),
                    (vec![aborting(&left, Capped::empty())], vec![]),
                    "{said:?} at {anchor:?}",
                );
            }
        }
    }

    /// Every member a halt recovery's discard lets go of has an exit by
    /// a clock. One whose verdict a counterpart shares is aborted from
    /// its deadline beside a shard that can still answer, no record
    /// covering it, and is fated at any age once every shard it reaches
    /// is unreadable. One its own tick decided is fated from the close of
    /// its leg entry window, a record covering it or not.
    #[test]
    fn a_member_a_recovery_released_is_named_for_an_exit() {
        let shard = ShardId::ROOT;
        let at = BlockHeight::new;
        let deadline = Deadline::of(ms(10_000));
        let mut rows = rows_of([
            held_in(1, deadline, 2, Joins::Executes, Settlement::Shared),
            held_in(2, deadline, 2, Joins::Executes, Settlement::Alone),
        ]);
        rows.ticks.insert(at(2), tick_holding(&[1, 2], true));
        let live = Evidence::Live { terminating: false };
        let (lines, _) = lines_at(&rows, ms(5_000), live, true);
        assert_eq!(
            lines,
            vec![TickLine::Discard {
                tick: TickId::new(shard, at(2)),
                cause: DiscardCause::Recovery,
            }],
        );
        naming(&mut rows, 3, lines);
        rows.advance(&MemberInputs {
            height: at(4),
            covered: vec![tx(2)],
            ..MemberInputs::still(shard)
        });
        assert!(
            rows.ticks.is_empty(),
            "the recovery discards the tick whole"
        );
        let state_of = |seed: u8| {
            let row = &rows.members[&tx(seed)];
            (row.state, row.covered)
        };
        assert_eq!(
            state_of(1),
            (
                RowState::Released {
                    settlement: Settlement::Shared,
                },
                false,
            ),
        );
        assert_eq!(
            state_of(2),
            (
                RowState::Released {
                    settlement: Settlement::Alone,
                },
                true,
            ),
        );

        let lapse = lapse(deadline);
        for anchor in [
            deadline.at().minus(MS),
            deadline.at(),
            lapse.minus(MS),
            lapse,
            lapse.plus(TRANSACTION_EVIDENCE_HORIZON),
        ] {
            for said in READINGS {
                let mut fated = Vec::new();
                if said == Evidence::Unreadable {
                    fated.push((tx(1), fate_of(1)));
                }
                if anchor >= lapse {
                    fated.push((tx(2), fate_of(2)));
                }
                fated.sort_by_key(|(tx, _)| *tx);
                let answered = !matches!(said, Evidence::Unreadable | Evidence::Unknown);
                let aborted = (answered && anchor >= deadline.at())
                    .then(|| aborting(&rows.members[&tx(1)], Capped::empty()));
                let named: Vec<TickLine> = fated
                    .into_iter()
                    .map(|(_, fate)| fate)
                    .chain(aborted)
                    .collect();
                let unread = if said == Evidence::Unknown {
                    vec![tx(1)]
                } else {
                    vec![]
                };
                assert_eq!(
                    lines_at(&rows, anchor, said, false),
                    (named, unread),
                    "{said:?} at {anchor:?}",
                );
            }
        }
    }

    /// Whether `lines` name `seed`'s member: a member line, a fate, an
    /// end, or a discard naming it.
    fn names(lines: &[TickLine], seed: u8) -> bool {
        lines.iter().any(|line| match line {
            TickLine::Member { tx: named, .. }
            | TickLine::Fate { tx: named, .. }
            | TickLine::End { tx: named }
            | TickLine::Discard {
                cause: DiscardCause::Unanswerable(named) | DiscardCause::Abandoned(named),
                ..
            } => *named == tx(seed),
            TickLine::Discard {
                cause: DiscardCause::Recovery,
                ..
            } => false,
        })
    }

    /// The seeds of the rows [`before_a_halt`] stands.
    const WAITING_LEG: u8 = 1;
    const WAITING_CORE: u8 = 2;
    const BELOW_SHARED: u8 = 3;
    const BELOW_ALONE: u8 = 4;
    const BELOW_LOCAL: u8 = 5;
    const BELOW_ABORT: u8 = 6;
    const ABOVE_SHARED: u8 = 7;
    const RELEASED_SHARED: u8 = 8;

    /// Rows of every standing a chain holds as it halts: a leg and a
    /// core member still waiting; in the tick at height 2, a member a
    /// counterpart settles against, one settled alone that reaches
    /// `PEER`, one that reaches nobody, and an abort; in the tick at
    /// height 5, a member a counterpart settles against; and one such
    /// member a discard released already.
    fn before_a_halt(deadline: Deadline) -> MemberIndex {
        let mut rows = rows_of([
            stating(WAITING_LEG, deadline, &waiting_leg(WAITING_LEG)),
            stating(
                WAITING_CORE,
                deadline,
                &MemberTerms {
                    leg: false,
                    settlement: Settlement::Shared,
                    ..waiting_leg(WAITING_CORE)
                },
            ),
            held_in(
                BELOW_SHARED,
                deadline,
                2,
                Joins::Executes,
                Settlement::Shared,
            ),
            held_in(BELOW_ALONE, deadline, 2, Joins::Executes, Settlement::Alone),
            MemberRow {
                reach: Capped::empty(),
                ..held_in(BELOW_LOCAL, deadline, 2, Joins::Executes, Settlement::Alone)
            },
            MemberRow {
                executed: false,
                ..held_in(
                    BELOW_ABORT,
                    deadline,
                    2,
                    Joins::Aborted,
                    Settlement::Awaited,
                )
            },
            held_in(
                ABOVE_SHARED,
                deadline,
                5,
                Joins::Executes,
                Settlement::Shared,
            ),
            standing(
                RELEASED_SHARED,
                deadline,
                RowState::Released {
                    settlement: Settlement::Shared,
                },
                false,
            ),
        ]);
        rows.ticks.insert(
            BlockHeight::new(2),
            tick_holding(&[BELOW_SHARED, BELOW_ALONE, BELOW_LOCAL, BELOW_ABORT], true),
        );
        rows.ticks
            .insert(BlockHeight::new(5), tick_holding(&[ABOVE_SHARED], false));
        rows
    }

    /// A recovery's crossing block stands a whole halt past every
    /// deadline and every leg entry window the rows before it carry. It
    /// discards every tick its parent's rows hold, at or below the
    /// frontier and above it alike, and names no other line for their
    /// members; it fates the pending leg, which issued nothing, and
    /// aborts the pending core member and the member a discard released
    /// before the halt. The block after it fates the released member
    /// settled on this shard's word alone and aborts every other member
    /// the recovery released, those a counterpart settles against among
    /// them: no half settles a released row, so the abort ends on this
    /// shard a row nothing else can. Each abort is then its own tick's to
    /// settle, and no later line names it, whatever its counterparts'
    /// evidence says.
    #[test]
    fn a_row_a_recovery_released_is_aborted_from_its_deadline_beside_a_live_counterpart() {
        let deadline = Deadline::of(ms(10_000));
        let halted = Duration::from_secs(HALT_THRESHOLD_EPOCHS * EPOCH_DURATION.as_secs());
        let resumed = deadline.at().plus(halted);
        assert!(resumed >= lapse(deadline));
        let live = Evidence::Live { terminating: false };
        let mut rows = before_a_halt(deadline);
        let named_at = |rows: &MemberIndex, anchor, said, recovery| {
            let (lines, missing) = lines_at(rows, anchor, said, recovery);
            assert!(missing.is_empty());
            lines
        };
        let in_order = |mut aborted: Vec<TickLine>| {
            aborted.sort_by_key(|line| match line {
                TickLine::Member { tx, reach, .. } => (reach.is_empty(), *tx),
                _ => unreachable!("an abort is a member line"),
            });
            aborted
        };

        let first = named_at(&rows, resumed, live, true);
        assert_eq!(
            first,
            [
                TickLine::Discard {
                    tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                    cause: DiscardCause::Recovery,
                },
                TickLine::Discard {
                    tick: TickId::new(ShardId::ROOT, BlockHeight::new(5)),
                    cause: DiscardCause::Recovery,
                },
                fate_of(WAITING_LEG),
            ]
            .into_iter()
            .chain(in_order(vec![
                aborting(&rows.members[&tx(WAITING_CORE)], Capped::empty()),
                aborting(&rows.members[&tx(RELEASED_SHARED)], Capped::empty()),
            ]))
            .collect::<Vec<_>>(),
        );
        naming(&mut rows, 6, first);
        for seed in [BELOW_SHARED, ABOVE_SHARED] {
            assert_eq!(
                rows.members[&tx(seed)].state,
                RowState::Released {
                    settlement: Settlement::Shared,
                },
            );
        }

        let second = named_at(&rows, resumed.plus(MS), live, false);
        assert_eq!(
            second,
            std::iter::once(fate_of(BELOW_ALONE))
                .chain(in_order(vec![
                    aborting(&rows.members[&tx(BELOW_ABORT)], Capped::empty()),
                    aborting(&rows.members[&tx(BELOW_LOCAL)], Capped::empty()),
                    aborting(&rows.members[&tx(BELOW_SHARED)], Capped::empty()),
                    aborting(&rows.members[&tx(ABOVE_SHARED)], Capped::empty()),
                ]))
                .collect::<Vec<_>>(),
        );
        naming(&mut rows, 7, second);

        let aborted = [BELOW_SHARED, RELEASED_SHARED, ABOVE_SHARED];
        for seed in aborted {
            assert!(
                matches!(
                    rows.members[&tx(seed)].state,
                    RowState::InFlight {
                        joins: Joins::Aborted,
                        settlement: Settlement::Awaited,
                        ..
                    }
                ),
                "{seed} stands in the tick that aborts it",
            );
        }
        for anchor in [
            resumed.plus(MS * 2),
            resumed.plus(TRANSACTION_EVIDENCE_HORIZON),
            resumed.plus(halted),
        ] {
            for said in [
                live,
                Evidence::Live { terminating: true },
                Evidence::Readable,
            ] {
                let lines = named_at(&rows, anchor, said, false);
                for seed in aborted {
                    assert!(!names(&lines, seed), "{seed} is its tick's: {lines:?}");
                }
            }
        }
        let silent = named_at(&rows, resumed.plus(MS * 2), Evidence::Unreadable, false);
        for seed in aborted {
            assert!(
                !names(&silent, seed),
                "an abort in flight is its own tick's to settle: {silent:?}",
            );
        }
    }

    /// Short of its deadline a member a recovery released, which a
    /// counterpart settles against, is named by no line beside a shard
    /// that can still answer, whether a tick at or below the frontier
    /// held it or a discard released it before the halt.
    #[test]
    fn a_row_a_recovery_released_stands_short_of_its_deadline() {
        let resumed = ms(60_000);
        let deadline = Deadline::of(resumed.plus(Duration::from_secs(60)));
        let mut rows = before_a_halt(deadline);
        let first = lines_at(&rows, resumed, Evidence::Live { terminating: false }, true).0;
        naming(&mut rows, 6, first);
        for seed in [BELOW_SHARED, RELEASED_SHARED] {
            assert_eq!(
                rows.members[&tx(seed)].state,
                RowState::Released {
                    settlement: Settlement::Shared,
                },
            );
        }
        for said in [
            Evidence::Live { terminating: false },
            Evidence::Live { terminating: true },
            Evidence::Readable,
        ] {
            let short = lines_at(&rows, deadline.at().minus(MS), said, false).0;
            let due = lines_at(&rows, deadline.at(), said, false).0;
            for seed in [BELOW_SHARED, RELEASED_SHARED] {
                assert!(!names(&short, seed), "{seed}, {said:?}: {short:?}");
                assert!(
                    due.contains(&aborting(&rows.members[&tx(seed)], Capped::empty())),
                    "{seed}, {said:?}: {due:?}",
                );
            }
        }
    }

    /// A member that ran and that a recovery released, a counterpart
    /// settling against it, is aborted from its deadline answering no
    /// crossing, a record covering it or not: the line that ran it left
    /// its row listing none, so the abort has none to name. Stated before
    /// its release, it attests no share, which its stating half counted,
    /// and burns the charge its row carries; released in flight, it
    /// attests the share no half of its tick settled.
    #[test]
    fn a_released_shared_row_that_ran_names_no_crossing() {
        let deadline = Deadline::of(ms(10_000));
        let core = MemberTerms {
            share: 9,
            ..consuming()
        };
        assert!(!core.crossings.is_empty());
        let shard = ShardId::ROOT;
        let at = BlockHeight::new;
        let live = Evidence::Live { terminating: false };
        for covered in [false, true] {
            for stated in [false, true] {
                let mut rows = rows_of([stating(1, deadline, &core)]);
                assert_eq!(rows.members[&tx(1)].crossings, core.crossings);
                naming(
                    &mut rows,
                    2,
                    vec![TickLine::Member {
                        tx: tx(1),
                        joins: Joins::Executes,
                        settlement: Settlement::Shared,
                        holds: Capped::empty(),
                        reach: core.reach.clone(),
                        awaits: core.awaits.clone(),
                        charge: core.charge,
                        share: core.share,
                        reserves: core.reserves.clone(),
                        deadline,
                        nevers: Capped::empty(),
                    }],
                );
                assert!(
                    rows.members[&tx(1)].crossings.is_empty(),
                    "the line that runs a member consumes its crossings",
                );
                if stated {
                    rows.advance(&MemberInputs {
                        height: at(3),
                        settled: vec![SettledHalf {
                            tick: TickId::new(shard, at(2)),
                            half: TickHalf::Stated,
                            deleted: Vec::new(),
                            stated: vec![(tx(1), GlobalReceiptHash::ZERO)],
                            accepted: Vec::new(),
                        }],
                        ..MemberInputs::still(shard)
                    });
                    assert!(matches!(
                        rows.members[&tx(1)].state,
                        RowState::Stated { .. }
                    ));
                }
                let discard = lines_at(&rows, ms(5_000), live, true).0;
                naming(&mut rows, 4, discard);
                rows.advance(&MemberInputs {
                    height: at(5),
                    covered: if covered { vec![tx(1)] } else { Vec::new() },
                    ..MemberInputs::still(shard)
                });
                let released = rows.members[&tx(1)].clone();
                assert_eq!(
                    (released.state, released.executed, released.covered),
                    (
                        RowState::Released {
                            settlement: Settlement::Shared,
                        },
                        true,
                        covered,
                    ),
                );
                assert!(released.crossings.is_empty());
                assert_eq!(released.share, if stated { 0 } else { 9 });

                assert_eq!(
                    lines_at(&rows, deadline.at().minus(MS), live, false),
                    (vec![], vec![]),
                    "covered {covered}, stated {stated}",
                );
                let (lines, missing) = lines_at(&rows, deadline.at(), live, false);
                assert!(missing.is_empty());
                assert_eq!(
                    lines,
                    vec![aborting(&released, Capped::empty())],
                    "covered {covered}, stated {stated}",
                );
                assert_eq!(abort_of(&lines, 1), (deadline, Capped::empty()));
                assert!(
                    matches!(
                        lines[..],
                        [TickLine::Member { share, charge, .. }]
                            if share == released.share && charge == released.charge
                    ),
                    "{lines:?}",
                );
            }
        }
    }

    /// An end line spends a bare line's bytes and one of the manifest's
    /// lines, and none of its member seats: a manifest takes them up to
    /// its line cap, past the cap on the members it names.
    #[test]
    fn an_end_line_spends_a_line_and_no_member_seat() {
        const { assert!(MAX_TICK_LINES_PER_BLOCK > MAX_NAMED_MEMBERS_PER_TICK) };
        let end = TickLine::End { tx: tx(1) };
        let mut budget = ManifestBudget::default();
        for _ in 0..MAX_TICK_LINES_PER_BLOCK {
            assert!(budget.take(&end));
        }
        assert_eq!(budget.members, 0);
        assert_eq!(budget.lines, MAX_TICK_LINES_PER_BLOCK);
        assert_eq!(budget.spent, MAX_TICK_LINES_PER_BLOCK * TICK_LINE_BYTES);
        assert!(!budget.take(&end), "the line cap refuses one more");
    }

    /// The `Unanswerable` discard of a member and its fate are charged
    /// to the manifest together, so a block names both or neither: a
    /// discard alone would leave a released row the next block has to
    /// fate, and a fate alone a tick still holding a member with no row.
    /// Nothing is named past the pair the budget refuses.
    #[test]
    fn an_unanswerable_discard_and_its_fate_fit_together_or_neither_is_named() {
        let hash = |at: usize| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(at as u64).to_be_bytes());
            TxHash::from(Hash::from_hash_bytes(&bytes))
        };
        let pairs = MAX_TICK_LINES_PER_BLOCK / 2;
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        for at in 0..=pairs {
            let row = MemberRow {
                tx: hash(at),
                ..standing(
                    1,
                    far(),
                    RowState::InFlight {
                        tick: BlockHeight::new(5),
                        joins: Joins::Executes,
                        settlement: Settlement::Shared,
                    },
                    false,
                )
            };
            rows.members.insert(row.tx, row);
        }
        // A member ready to run, ordered after every pair.
        let ready = MemberRow {
            tx: hash(usize::MAX),
            ..stating(0, far(), &alone(vec![]))
        };
        rows.members.insert(ready.tx, ready);
        // A tick a recovery's crossing block discards.
        rows.ticks.insert(
            BlockHeight::new(1),
            TickRow {
                members: Capped::empty(),
                determined_unsettled: false,
                awaiting: 1,
            },
        );
        let named = |recovery: bool| {
            let (lines, missing) = lines_and_missing(
                &rows,
                ms(0),
                &Held::default(),
                &|_| Evidence::Unreadable,
                recovery,
                &BTreeSet::new(),
            );
            assert!(missing.is_empty());
            lines
        };
        let paired = |lines: &[TickLine]| {
            lines.chunks(2).enumerate().all(|(at, pair)| {
                matches!(
                    pair,
                    [
                        TickLine::Discard {
                            cause: DiscardCause::Unanswerable(discarded),
                            ..
                        },
                        TickLine::Fate { tx: fated, .. },
                    ] if *discarded == hash(at) && *fated == hash(at)
                )
            })
        };

        let lines = named(false);
        assert_eq!(lines.len(), MAX_TICK_LINES_PER_BLOCK);
        assert!(paired(&lines), "every discard is followed by its fate");

        // A recovery's discard spent first leaves room for one line more
        // than the pairs that fit: the last pair is named by neither of
        // its lines, and the member behind it waits a block.
        let lines = named(true);
        assert_eq!(lines.len(), MAX_TICK_LINES_PER_BLOCK - 1);
        assert_eq!(
            lines[0],
            TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(1)),
                cause: DiscardCause::Recovery,
            },
        );
        assert!(
            paired(&lines[1..]),
            "the pair that does not fit is left whole"
        );
    }

    /// Rows standing as a manifest lists its lines: members a counterpart
    /// settles against in flight in ticks 1, 5 and 6 and one released,
    /// the counterpart of one of them live, and a pending member; beside
    /// them the lines a block anchored at their deadline names, on a
    /// recovery's crossing block where `recovery`.
    fn listed(recovery: bool) -> (MemberIndex, Vec<TickLine>) {
        const LIVE: ShardId = ShardId::leaf(1, 0);
        let deadline = Deadline::of(ms(10_000));
        let in_flight = |tick: u64| RowState::InFlight {
            tick: BlockHeight::new(tick),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
        };
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        let mut put = |row: MemberRow| {
            rows.members.insert(row.tx, row);
        };
        put(standing(1, deadline, in_flight(1), false));
        put(standing(2, deadline, in_flight(5), false));
        put(standing(
            3,
            deadline,
            RowState::Released {
                settlement: Settlement::Shared,
            },
            false,
        ));
        put(standing(4, deadline, in_flight(6), false));
        put(MemberRow {
            reach: Capped::from_array([LIVE]),
            ..standing(5, deadline, in_flight(5), true)
        });
        put(stating(6, far(), &alone(vec![])));
        for (tick, mut members) in [(1, vec![tx(1)]), (5, vec![tx(2), tx(5)]), (6, vec![tx(4)])] {
            members.sort();
            rows.ticks.insert(
                BlockHeight::new(tick),
                TickRow {
                    members: Capped::new(members).expect("a tick's members"),
                    determined_unsettled: false,
                    awaiting: 1,
                },
            );
        }
        let (lines, missing) = lines_and_missing(
            &rows,
            deadline.at(),
            &Held::default(),
            &|shard| {
                if shard == LIVE {
                    Evidence::Readable
                } else {
                    Evidence::Unreadable
                }
            },
            recovery,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty());
        (rows, lines)
    }

    /// A manifest lists its lines as its budget is charged: the fates in
    /// transaction order with each discard before its fate, the member
    /// lines, then the discards the aborts imply.
    #[test]
    fn a_manifest_lists_fates_then_member_lines_then_their_discards() {
        let (rows, lines) = listed(false);
        let fate = |hash: TxHash| TickLine::Fate {
            tx: hash,
            charge: rows.members[&hash].charge,
        };

        let mut fated = vec![
            (tx(1), Some(1)),
            (tx(2), Some(5)),
            (tx(3), None),
            (tx(4), Some(6)),
        ];
        fated.sort();
        let mut expected = Vec::new();
        for (hash, held_by) in fated {
            expected.extend(held_by.map(|tick| TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(tick)),
                cause: DiscardCause::Unanswerable(hash),
            }));
            expected.push(fate(hash));
        }
        assert_eq!(lines[..expected.len()], expected[..]);
        let rest = &lines[expected.len()..];
        assert!(
            matches!(
                rest,
                [
                    TickLine::Member { tx: aborted, joins: Joins::Aborted, .. },
                    TickLine::Member { tx: ran, joins: Joins::Executes, .. },
                    TickLine::Discard { cause: DiscardCause::Abandoned(abandoned), .. },
                ] if *aborted == tx(5) && *ran == tx(6) && *abandoned == tx(5)
            ),
            "the member lines, then the discards their aborts imply: {rest:?}",
        );
    }

    /// On a recovery's crossing block the manifest lists the recovery's
    /// discards first, and the discard is whole: every tick the rows
    /// hold, whatever its members, and no other line names a member of
    /// one; a member no tick holds is fated or named as on any block.
    #[test]
    fn a_manifest_lists_recovery_discards_then_fates_then_member_lines() {
        let (rows, lines) = listed(true);
        let fate = |hash: TxHash| TickLine::Fate {
            tx: hash,
            charge: rows.members[&hash].charge,
        };

        let mut expected: Vec<TickLine> = [1, 5, 6]
            .into_iter()
            .map(|tick| TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(tick)),
                cause: DiscardCause::Recovery,
            })
            .collect();
        expected.push(fate(tx(3)));
        assert_eq!(lines[..expected.len()], expected[..]);
        let rest = &lines[expected.len()..];
        assert!(
            matches!(
                rest,
                [TickLine::Member { tx: ran, joins: Joins::Executes, .. }] if *ran == tx(6)
            ),
            "no line names a member of a discarded tick: {rest:?}",
        );
    }

    /// The crossing block discards every tick row its parent holds, ahead
    /// of every other line: a tick owing its determined half, a tick
    /// holding a stated row and a row in flight, and a tick holding no
    /// row at all, whatever their heights, and names no other line for a
    /// member of any. A block that does not cross discards none of them.
    #[test]
    fn the_crossing_block_discards_every_tick_row() {
        let deadline = Deadline::of(ms(10_000));
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        for row in [
            standing(
                1,
                deadline,
                RowState::InFlight {
                    tick: BlockHeight::new(2),
                    joins: Joins::Executes,
                    settlement: Settlement::Alone,
                },
                false,
            ),
            standing(
                2,
                deadline,
                RowState::Stated {
                    tick: BlockHeight::new(5),
                    receipt: GlobalReceiptHash::ZERO,
                },
                false,
            ),
            standing(
                3,
                deadline,
                RowState::InFlight {
                    tick: BlockHeight::new(5),
                    joins: Joins::Executes,
                    settlement: Settlement::Shared,
                },
                true,
            ),
        ] {
            rows.members.insert(row.tx, row);
        }
        rows.ticks
            .insert(BlockHeight::new(2), tick_holding(&[1], true));
        rows.ticks
            .insert(BlockHeight::new(5), tick_holding(&[2, 3], false));
        rows.ticks
            .insert(BlockHeight::new(7), tick_holding(&[], true));

        for (anchor, said) in [
            (ms(1), Evidence::Readable),
            (deadline.at(), Evidence::Readable),
            (deadline.at(), Evidence::Unreadable),
        ] {
            let (lines, missing) = lines_at(&rows, anchor, said, true);
            assert!(missing.is_empty());
            assert_eq!(
                lines,
                [2, 5, 7]
                    .into_iter()
                    .map(|height| TickLine::Discard {
                        tick: TickId::new(ShardId::ROOT, BlockHeight::new(height)),
                        cause: DiscardCause::Recovery,
                    })
                    .collect::<Vec<_>>(),
                "at {anchor:?} under {said:?}",
            );
            let (lines, _) = lines_at(&rows, anchor, said, false);
            assert!(
                !lines.iter().any(|line| matches!(
                    line,
                    TickLine::Discard {
                        cause: DiscardCause::Recovery,
                        ..
                    }
                )),
                "a block that does not cross discards nothing for a recovery: {lines:?}",
            );
        }
    }

    /// A row its tick's determined half settles leaves that tick by the
    /// half or by a recovery, and by no other line: run or aborted,
    /// reaching a counterpart or nobody, covered or not, at any age and
    /// under any evidence, no line aborts it, names it again or fates it,
    /// and none discards its tick. So the rows a tick holds for its
    /// determined half stand together until that half settles them
    /// together.
    #[test]
    fn a_row_its_determined_half_settles_leaves_by_no_line_but_a_recovery() {
        let deadline = Deadline::of(ms(10_000));
        let tick = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        for joins in [Joins::Executes, Joins::Aborted] {
            for covered in [false, true] {
                let reaching = MemberRow {
                    covered,
                    ..held_in(1, deadline, 2, joins, Settlement::Alone)
                };
                let local = MemberRow {
                    covered,
                    reach: Capped::empty(),
                    ..held_in(2, deadline, 2, joins, Settlement::Alone)
                };
                let mut rows = rows_of([reaching, local]);
                rows.ticks.insert(
                    BlockHeight::new(2),
                    TickRow {
                        members: Capped::from_array([tx(1), tx(2)]),
                        determined_unsettled: true,
                        awaiting: 0,
                    },
                );
                for anchor in [ms(1), deadline.at(), Window::LegEntry.of(deadline).end] {
                    for evidence in [
                        Evidence::Live { terminating: false },
                        Evidence::Readable,
                        Evidence::Unreadable,
                        Evidence::Unknown,
                    ] {
                        assert_eq!(
                            lines_at(&rows, anchor, evidence, false),
                            (vec![], vec![]),
                            "{joins:?}, covered: {covered}, at {anchor:?} under {evidence:?}",
                        );
                    }
                }
                assert_eq!(
                    lines_at(&rows, ms(1), Evidence::Readable, true).0,
                    vec![TickLine::Discard {
                        tick,
                        cause: DiscardCause::Recovery,
                    }],
                );
            }
        }
    }

    /// A tick still owing its determined half is let go of by nothing
    /// but a recovery: a covered held row past its deadline, and one no
    /// counterpart can answer for, both wait for that half to settle, so
    /// a fate and its discard wait behind it too.
    #[test]
    fn a_tick_owing_its_determined_half_is_not_discarded() {
        let deadline = Deadline::of(ms(10_000));
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        rows.members.insert(
            tx(1),
            MemberRow {
                tx: tx(1),
                deadline,
                committed: ms(0),
                height: BlockHeight::new(1),
                state: RowState::InFlight {
                    tick: BlockHeight::new(2),
                    joins: Joins::Executes,
                    settlement: Settlement::Shared,
                },
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                awaits: Capped::empty(),
                covered: true,
                charge: CHARGE,
                share: 0,
                reserves: Capped::empty(),
                crossings: Capped::empty(),
                waiting: None,
                executed: true,
                hearing: Capped::empty(),
            },
        );
        rows.ticks.insert(
            BlockHeight::new(2),
            TickRow {
                members: Capped::from_array([tx(1)]),
                determined_unsettled: true,
                awaiting: 1,
            },
        );
        for evidence in [Evidence::Readable, Evidence::Unreadable] {
            assert_eq!(
                lines_and_missing(
                    &rows,
                    deadline.at(),
                    &Held::default(),
                    &|_| evidence,
                    false,
                    &BTreeSet::new(),
                ),
                (vec![], vec![]),
                "{evidence:?}",
            );
        }
        // Once the half has settled, the member nobody can answer for is
        // discarded and fated.
        let mut settled = rows.clone();
        settled
            .ticks
            .get_mut(&BlockHeight::new(2))
            .expect("the tick stands")
            .determined_unsettled = false;
        assert_eq!(
            lines_and_missing(
                &settled,
                deadline.at(),
                &Held::default(),
                &|_| Evidence::Unreadable,
                false,
                &BTreeSet::new(),
            ),
            (
                vec![
                    TickLine::Discard {
                        tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                        cause: DiscardCause::Unanswerable(tx(1)),
                    },
                    TickLine::Fate {
                        tx: tx(1),
                        charge: CHARGE,
                    },
                ],
                vec![],
            ),
        );
        // A halt recovery's crossing block discards it whole, owed half
        // and all, and names nothing else of its rows.
        assert_eq!(
            lines_and_missing(
                &rows,
                deadline.at(),
                &Held::default(),
                &|_| Evidence::Unreadable,
                true,
                &BTreeSet::new(),
            )
            .0,
            vec![TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                cause: DiscardCause::Recovery,
            }],
        );
    }

    /// A ready core member left out pairs with every core holder that
    /// refuses it and awaits a shard it awaits, in flight or named
    /// beside it; one that is not ready, that awaits no shard in common,
    /// or that a line names stands in no contention.
    #[test]
    fn a_ready_core_member_left_out_contends_with_its_core_holders() {
        const OTHER: ShardId = ShardId::leaf(1, 0);
        let shared = cell(1, 1);
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        let row = |seed: u8, state, holds: Vec<(DeclaredKey, Mode)>| MemberRow {
            tx: tx(seed),
            deadline: far(),
            committed: ms(0),
            height: BlockHeight::new(1),
            state,
            holds: Capped::new(holds).expect("within the cap"),
            reach: Capped::from_array([PEER]),
            awaits: Capped::from_array([PEER]),
            covered: false,
            charge: CHARGE,
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            waiting: None,
            executed: true,
            hearing: Capped::empty(),
        };
        let in_flight = RowState::InFlight {
            tick: BlockHeight::new(2),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
        };
        let ready = leg(vec![(shared, WRITE)], &[PEER]);
        let elsewhere = MemberTerms {
            reach: Capped::from_array([OTHER]),
            awaits: Capped::from_array([OTHER]),
            ..ready.clone()
        };
        for member in [
            row(1, in_flight, vec![(shared, WRITE)]),
            stating(2, far(), &ready),
            stating(3, far(), &ready),
            stating(4, far(), &elsewhere),
            stating(5, far(), &ready),
        ] {
            rows.members.insert(member.tx, member);
        }
        let mut held = Held::default();
        for seed in [2, 4, 5] {
            held.engaged.insert((PEER, tx(seed)));
        }
        let named = TickLine::Member {
            tx: tx(5),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::from_array([(shared, WRITE)]),
            reach: Capped::from_array([PEER]),
            awaits: Capped::from_array([PEER]),
            charge: CHARGE,
            share: 0,
            reserves: Capped::empty(),
            deadline: far(),
            nevers: Capped::empty(),
        };
        assert_eq!(
            contentions(&rows, &[named], ms(0), &held),
            vec![
                Contention {
                    waiting: tx(2),
                    holder: tx(1),
                },
                Contention {
                    waiting: tx(2),
                    holder: tx(5),
                },
            ],
            "tx 3 is not ready, tx 4 awaits no shard in common, tx 5 is named",
        );
    }

    /// A family of one core member in flight holding `declared`, and one
    /// pending beside it that declares the same and waits on `PEER`'s
    /// bundle.
    fn held_beside_pending(held: u8, waiting: u8, declared: &[(DeclaredKey, Mode)]) -> MemberIndex {
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        let in_flight = MemberRow {
            tx: tx(held),
            deadline: far(),
            committed: ms(0),
            height: BlockHeight::new(1),
            state: RowState::InFlight {
                tick: BlockHeight::new(2),
                joins: Joins::Executes,
                settlement: Settlement::Shared,
            },
            holds: Capped::new(declared.to_vec()).expect("within the cap"),
            reach: Capped::from_array([PEER]),
            awaits: Capped::from_array([PEER]),
            charge: CHARGE,
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            waiting: None,
            covered: false,
            executed: true,
            hearing: Capped::empty(),
        };
        let pending = stating(waiting, far(), &leg(declared.to_vec(), &[PEER]));
        for member in [in_flight, pending] {
            rows.members.insert(member.tx, member);
        }
        rows
    }

    /// A claim on `PEER` over the three cells a seat question about
    /// `holder` refusing `waiting` reads, proven against a tree holding
    /// `leaves`.
    fn seat_reading(holder: u8, waiting: u8, leaves: &[SubstateKey]) -> StateClaim {
        proven_claim(
            PEER,
            5,
            leaves,
            &[
                seat_leaf(PEER, tx(waiting)),
                member_row_leaf(PEER, tx(holder)),
                seat_leaf(PEER, tx(holder)),
                verdict_leaf(PEER, tx(holder)),
            ],
        )
    }

    /// The reading that proves the cycle: `waiting` seated on `PEER`, and
    /// `holder` committed there with no seat and no verdict leaf.
    fn crossed_reading(holder: u8, waiting: u8) -> StateClaim {
        crossed_reading_at(holder, waiting, 5)
    }

    /// [`crossed_reading`] at `PEER`'s `height`, whose clock is a second a
    /// height.
    fn crossed_reading_at(holder: u8, waiting: u8, height: u64) -> StateClaim {
        let leaves = [
            seat_leaf(PEER, tx(waiting)),
            member_row_leaf(PEER, tx(holder)),
        ];
        proven_claim(
            PEER,
            height,
            &leaves,
            &[
                leaves[0],
                leaves[1],
                seat_leaf(PEER, tx(holder)),
                verdict_leaf(PEER, tx(holder)),
            ],
        )
    }

    /// A pending core member that a held one refuses, and that one claim
    /// reads seated on their shared counterpart with the holder unseated
    /// there, is aborted short of its deadline when it is the later of
    /// the two; the earlier one waits, and so does either one without
    /// the whole reading.
    #[test]
    fn the_later_member_of_a_proven_hold_cycle_is_aborted() {
        let declared = vec![(cell(1, 1), WRITE)];
        let family = |held: u8, waiting: u8| held_beside_pending(held, waiting, &declared);
        let crossed = crossed_reading;
        let reading = seat_reading;
        let live = |_| Evidence::Live { terminating: false };
        let lines = |rows: &MemberIndex, claims: &[StateClaim]| {
            let victims = wounded(rows, ms(0), claims);
            lines_and_missing(rows, ms(0), &Held::default(), &live, false, &victims).0
        };

        assert_eq!(
            lines(&family(1, 2), &[crossed(1, 2)]),
            vec![TickLine::Member {
                tx: tx(2),
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                awaits: Capped::empty(),
                charge: CHARGE,
                share: 0,
                reserves: Capped::empty(),
                deadline: far(),
                nevers: Capped::empty(),
            }],
            "the later member is the victim",
        );
        assert!(
            lines(&family(2, 1), &[crossed(2, 1)]).is_empty(),
            "the earlier member waits for the counterpart to abort the later",
        );
        assert!(lines(&family(1, 2), &[]).is_empty(), "no reading, no abort");
        let whole = crossed(1, 2);
        let split: Vec<StateClaim> = [
            |key: SubstateKey| key == seat_leaf(PEER, tx(2)),
            |key: SubstateKey| key != seat_leaf(PEER, tx(2)),
        ]
        .into_iter()
        .filter_map(|keep| whole.restrict(keep))
        .collect();
        assert_eq!(split.len(), 2);
        assert_eq!(
            lines(&family(1, 2), &split).len(),
            1,
            "a reading cut across claims at one anchor proves as one",
        );
        assert!(
            lines(
                &family(1, 2),
                &[reading(
                    1,
                    2,
                    &[
                        seat_leaf(PEER, tx(2)),
                        member_row_leaf(PEER, tx(1)),
                        seat_leaf(PEER, tx(1)),
                    ],
                )],
            )
            .is_empty(),
            "a holder seated on the counterpart too is no cycle",
        );
    }

    /// The reading that proves a cycle wounds nobody where the holder
    /// cannot be part of one: past its own deadline, the counterpart
    /// where it waits aborts it; and reaching the counterpart only by a
    /// leg, it holds no seat there to read.
    #[test]
    fn a_reading_wounds_nobody_through_a_lapsed_or_leg_holder() {
        let declared = vec![(cell(1, 1), WRITE)];
        let claims = [crossed_reading(1, 2)];
        let lapse = Deadline::of(ms(0));

        let standing = held_beside_pending(1, 2, &declared);
        assert_eq!(
            wounded(&standing, lapse.at(), &claims),
            BTreeSet::from([tx(2)]),
            "the reading wounds while the holder's deadline stands",
        );

        let mut lapsing = held_beside_pending(1, 2, &declared);
        if let Some(holder) = lapsing.members.get_mut(&tx(1)) {
            holder.deadline = lapse;
        }
        assert!(
            wounded(&lapsing, lapse.at(), &claims).is_empty(),
            "a holder past its deadline is aborted where it waits",
        );

        let mut leg_there = held_beside_pending(1, 2, &declared);
        if let Some(holder) = leg_there.members.get_mut(&tx(1)) {
            holder.awaits = Capped::from_array([ShardId::leaf(1, 0)]);
        }
        assert!(
            wounded(&leg_there, ms(0), &claims).is_empty(),
            "a holder reaching the counterpart only by a leg holds no seat there",
        );

        // The counterpart's deadline abort of the holder leaves its row
        // with no seat, so a reading anchored at or past the deadline
        // reads a cycle that is already breaking.
        let mut lapsing_there = held_beside_pending(1, 2, &declared);
        let lapse = Deadline::of(ms(1_000));
        if let Some(holder) = lapsing_there.members.get_mut(&tx(1)) {
            holder.deadline = lapse;
        }
        let at_lapse = lapse.at().as_millis().div_ceil(1_000);
        let read_at = |height| [crossed_reading_at(1, 2, height)];
        assert!(
            wounded(&lapsing_there, ms(0), &read_at(at_lapse)).is_empty(),
            "a reading past the holder's deadline proves nothing",
        );
        assert_eq!(
            wounded(&lapsing_there, ms(0), &read_at(5)),
            BTreeSet::from([tx(2)]),
            "one taken before it still does",
        );

        // A counterpart that never committed the holder reads no cycle.
        let unseen = seat_reading(1, 2, &[seat_leaf(PEER, tx(2))]);
        assert!(
            wounded(&standing, ms(0), &[unseen]).is_empty(),
            "a holder with no row on the counterpart is no cycle",
        );
    }

    /// A holder whose verdict leaf stands on the counterpart proves no
    /// cycle, so the pending member is not wounded. The same reading with
    /// the leaf absent is the cycle, and one that does not read the leaf
    /// proves nothing either way.
    #[test]
    fn a_holder_standing_beside_a_verdict_leaf_proves_no_cycle() {
        let declared = vec![(cell(1, 1), WRITE)];
        let rows = held_beside_pending(1, 2, &declared);
        let (seat, row, unseated, leaf) = (
            seat_leaf(PEER, tx(2)),
            member_row_leaf(PEER, tx(1)),
            seat_leaf(PEER, tx(1)),
            verdict_leaf(PEER, tx(1)),
        );
        let asked = [seat, row, unseated, leaf];

        let stated = proven_claim(PEER, 5, &[seat, row, leaf], &asked);
        assert_eq!(stated.reading(unseated), Some(Inclusion::Absent));
        assert!(matches!(stated.reading(leaf), Some(Inclusion::Present(_))));
        assert!(
            wounded(&rows, ms(0), &[stated]).is_empty(),
            "a holder whose verdict leaf stands proves no cycle",
        );

        let cycle = proven_claim(PEER, 5, &[seat, row], &asked);
        assert_eq!(
            wounded(&rows, ms(0), from_ref(&cycle)),
            BTreeSet::from([tx(2)]),
            "with the leaf absent the reading is the cycle",
        );

        let unread = cycle
            .restrict(|key| key != leaf)
            .expect("three cells are left");
        assert!(
            wounded(&rows, ms(0), from_ref(&unread)).is_empty(),
            "a reading that does not say whether the leaf stands proves nothing",
        );
        let leaf_alone = cycle.restrict(|key| key == leaf).expect("one cell is left");
        assert_eq!(
            wounded(&rows, ms(0), &[unread, leaf_alone]),
            BTreeSet::from([tx(2)]),
            "and the leaf read in another claim at the same anchor completes it",
        );
    }

    /// Past its deadline, a held member a record covers is aborted
    /// beside its tick's discard, and a member let go of is aborted on
    /// its row unless it is settled alone and reaches another shard,
    /// whether or not it ran and a record covering it or not. A member
    /// settled alone with a reach is a leg, or a core member its own tick
    /// decided, and no abort names it.
    #[test]
    fn a_held_or_released_member_is_aborted_by_its_standing() {
        let held = BlockHeight::new(5);
        let passed = Deadline::of(ms(0));
        let released = |seed, deadline, covered, settlement| {
            standing(seed, deadline, RowState::Released { settlement }, covered)
        };
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        let mut stand = |row: MemberRow| {
            rows.members.insert(row.tx, row);
        };
        stand(standing(
            1,
            passed,
            RowState::InFlight {
                tick: held,
                joins: Joins::Executes,
                settlement: Settlement::Shared,
            },
            true,
        ));
        stand(released(5, passed, false, Settlement::Awaited));
        stand(MemberRow {
            reach: Capped::empty(),
            ..released(6, passed, false, Settlement::Alone)
        });
        stand(released(7, passed, true, Settlement::Awaited));
        stand(released(8, far(), true, Settlement::Awaited));
        stand(released(9, passed, true, Settlement::Alone));
        stand(MemberRow {
            executed: false,
            ..released(10, passed, false, Settlement::Awaited)
        });
        rows.ticks.insert(
            held,
            TickRow {
                members: Capped::from_array([tx(1)]),
                determined_unsettled: false,
                awaiting: 1,
            },
        );

        let anchor = ms(60_000);
        assert!(anchor < lapse(passed));
        let (lines, missing) = lines_and_missing(
            &rows,
            anchor,
            &Held::default(),
            &|_| Evidence::Live { terminating: false },
            false,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty());
        let mut reaching = vec![
            aborting(&rows.members[&tx(1)], Capped::empty()),
            aborting(&rows.members[&tx(5)], Capped::empty()),
            aborting(&rows.members[&tx(7)], Capped::empty()),
            aborting(&rows.members[&tx(10)], Capped::empty()),
        ];
        reaching.sort_by_key(|line| match line {
            TickLine::Member { tx, .. } => *tx,
            _ => unreachable!("an abort is a member line"),
        });
        assert_eq!(
            lines,
            reaching
                .into_iter()
                .chain([
                    aborting(&rows.members[&tx(6)], Capped::empty()),
                    TickLine::Discard {
                        tick: TickId::new(ShardId::ROOT, held),
                        cause: DiscardCause::Abandoned(tx(1)),
                    },
                ])
                .collect::<Vec<_>>(),
        );
    }

    /// The deadline and the answered crossings of the line aborting
    /// `seed` among `lines`.
    fn abort_of(lines: &[TickLine], seed: u8) -> (Deadline, Crossings) {
        lines
            .iter()
            .find_map(|line| match line {
                TickLine::Member {
                    tx: named,
                    joins: Joins::Aborted,
                    deadline,
                    nevers,
                    ..
                } if *named == tx(seed) => Some((*deadline, nevers.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no line aborts {seed}: {lines:?}"))
    }

    /// The terms of a core member consuming one escrowed crossing from a
    /// leg on `PEER`.
    fn consuming() -> MemberTerms {
        MemberTerms {
            crossings: stub_stated_terms(tx(0), 9).terms.crossings,
            ..leg(vec![], &[PEER])
        }
    }

    /// An abort of a core member no line ever ran names every escrowed
    /// crossing the member consumes, off its row, beside the row's
    /// deadline: what a replica holding nothing of the transaction
    /// writes its `Never`s from. One an abandonment record covers names
    /// none, since its own shard's fold declines its records once its row
    /// is gone, and so does one
    /// a line ran, which wrote its own answers.
    #[test]
    fn an_abort_of_a_pending_core_member_carries_its_nevers() {
        let passed = Deadline::of(ms(0));
        let core = consuming();
        assert_eq!(core.crossings.len(), 1);
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        for seed in [1, 2, 3] {
            rows.members.insert(tx(seed), stating(seed, passed, &core));
        }
        rows.members.get_mut(&tx(2)).expect("standing").covered = true;
        // A row a tick ran and a recovery then released keeps what it
        // was named on, and a record covers it.
        let ran = rows.members.get_mut(&tx(3)).expect("standing");
        ran.state = RowState::Released {
            settlement: Settlement::Shared,
        };
        ran.waiting = None;
        ran.executed = true;
        ran.covered = true;
        // Left on the row so the line's silence is the rule's and not an
        // empty list's.
        assert_eq!(ran.crossings, core.crossings);

        let live = |_| Evidence::Live { terminating: false };
        let (lines, missing) = lines_and_missing(
            &rows,
            ms(60_000),
            &Held::default(),
            &live,
            false,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty());
        assert_eq!(abort_of(&lines, 1), (passed, core.crossings.clone()));
        assert_eq!(abort_of(&lines, 2), (passed, Capped::empty()), "covered");
        assert_eq!(abort_of(&lines, 3), (passed, Capped::empty()), "executed");

        // A wound aborts short of the deadline on the same terms.
        let far_off = far();
        let mut waiting = MemberIndex::empty(ShardId::ROOT);
        waiting.members.insert(tx(1), stating(1, far_off, &core));
        let (lines, _) = lines_and_missing(
            &waiting,
            ms(0),
            &Held::default(),
            &live,
            false,
            &BTreeSet::from([tx(1)]),
        );
        assert_eq!(abort_of(&lines, 1), (far_off, core.crossings));

        // A line that runs a member answers nothing.
        let ready = MemberTerms {
            crossings: Capped::empty(),
            ..leg(vec![], &[])
        };
        let mut running = MemberIndex::empty(ShardId::ROOT);
        running.members.insert(tx(1), stating(1, far_off, &ready));
        let (lines, _) = lines_and_missing(
            &running,
            ms(0),
            &Held::default(),
            &live,
            false,
            &BTreeSet::new(),
        );
        assert!(
            matches!(
                &lines[..],
                [TickLine::Member { joins: Joins::Executes, deadline, nevers, .. }]
                    if *deadline == far_off && nevers.is_empty()
            ),
            "{lines:?}",
        );
    }

    /// A record covers only a row standing when its block commits. A
    /// transaction a record named before this chain committed it gets an
    /// uncovered row, so its abort names its crossings; one the record
    /// reaches after the commit names none.
    #[test]
    fn a_row_committed_after_its_record_stands_uncovered() {
        let shard = ShardId::ROOT;
        let passed = Deadline::of(ms(0));
        let core = consuming();
        let stated = |seed: u8| StatedTerms {
            tx: tx(seed),
            terms: core.clone(),
        };
        let mut rows = MemberIndex::empty(shard);
        rows.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(tx(2), passed)],
            terms: vec![stated(2)],
            covered: vec![tx(1)],
            ..MemberInputs::still(shard)
        });
        rows.advance(&MemberInputs {
            height: BlockHeight::new(2),
            transactions: vec![(tx(1), passed)],
            terms: vec![stated(1)],
            covered: vec![tx(2)],
            ..MemberInputs::still(shard)
        });
        assert!(!rows.members[&tx(1)].covered);
        assert!(rows.members[&tx(2)].covered);

        let live = |_| Evidence::Live { terminating: false };
        let (lines, _) = lines_and_missing(
            &rows,
            ms(60_000),
            &Held::default(),
            &live,
            false,
            &BTreeSet::new(),
        );
        assert_eq!(abort_of(&lines, 1), (passed, core.crossings));
        assert_eq!(abort_of(&lines, 2), (passed, Capped::empty()));
    }

    /// An abort a line named stands in flight until its own tick's
    /// finalization settles it, and no later block names it again: every
    /// replica seats it from the line, so nothing waits on a second
    /// naming. Not past its deadline, not under a covering record, and
    /// not whatever its counterparts' evidence reads.
    #[test]
    fn an_abort_in_flight_is_named_by_no_later_block() {
        let shard = ShardId::ROOT;
        let passed = Deadline::of(ms(0));
        let core = consuming();
        let live = |_| Evidence::Live { terminating: false };
        let mut rows = MemberIndex::empty(shard);
        rows.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(tx(1), passed)],
            terms: vec![StatedTerms {
                tx: tx(1),
                terms: core.clone(),
            }],
            ..MemberInputs::still(shard)
        });
        let (aborting, _) = lines_and_missing(
            &rows,
            ms(60_000),
            &Held::default(),
            &live,
            false,
            &BTreeSet::new(),
        );
        assert_eq!(abort_of(&aborting, 1), (passed, core.crossings));
        rows.advance(&MemberInputs {
            height: BlockHeight::new(2),
            manifest: Arc::new(Capped::new(aborting).expect("one line")),
            ..MemberInputs::still(shard)
        });
        let row = &rows.members[&tx(1)];
        assert!(matches!(
            row.state,
            RowState::InFlight {
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                ..
            }
        ));
        assert!(!row.executed, "an abort runs nothing");

        for covered in [false, true] {
            rows.members.get_mut(&tx(1)).expect("in flight").covered = covered;
            for evidence in [
                Evidence::Live { terminating: false },
                Evidence::Live { terminating: true },
                Evidence::Readable,
                Evidence::Unreadable,
                Evidence::Unknown,
            ] {
                for at in [ms(60_000), passed.at().plus(Duration::from_hours(48))] {
                    assert_eq!(
                        lines_and_missing(
                            &rows,
                            at,
                            &Held::default(),
                            &|_| evidence,
                            false,
                            &BTreeSet::new(),
                        ),
                        (vec![], vec![]),
                        "covered {covered}, {evidence:?}, at {at:?}",
                    );
                }
            }
        }
    }

    /// A row standing accepted beside [`PEER`], holding `heard` of it.
    fn accepted(seed: u8, heard: Option<(u64, Said)>) -> MemberRow {
        MemberRow {
            awaits: Capped::from_array([PEER]),
            hearing: Capped::new(
                heard
                    .into_iter()
                    .map(|(epoch, said)| Heard {
                        shard: PEER,
                        mark: ReadMark {
                            epoch: Epoch::new(epoch),
                            height: BlockHeight::new(7),
                        },
                        said: Some(said),
                    })
                    .collect(),
            )
            .expect("one entry"),
            ..standing(seed, far(), RowState::Accepted, false)
        }
    }

    /// What a block anchored in epoch 5 reads of [`PEER`], read from
    /// `source` in a published window that is held and records no
    /// recovery, under `evidence`.
    fn peer_read_from(source: Source, evidence: Evidence) -> SiblingViews {
        SiblingViews {
            shards: BTreeMap::from([(
                PEER,
                (
                    Some(source),
                    SiblingView {
                        epoch: Epoch::new(5),
                        terminating: Some(false),
                        recovery: Ok(None),
                        evidence: Ok(evidence),
                        ended: None,
                    },
                ),
            )]),
            ended: BTreeMap::new(),
        }
    }

    fn peer_running() -> SiblingViews {
        peer_read_from(Source::Live, Evidence::Live { terminating: false })
    }

    fn end_of(seed: u8) -> TickLine {
        TickLine::End { tx: tx(seed) }
    }

    /// The end lines of `seeds`, in transaction order.
    fn ends_of(seeds: &[u8]) -> Vec<TickLine> {
        let mut ended: Vec<TxHash> = seeds.iter().map(|&seed| tx(seed)).collect();
        ended.sort_unstable();
        ended.into_iter().map(|tx| TickLine::End { tx }).collect()
    }

    /// A terminal names a line for every row in one manifest, in
    /// transaction order: an end for each accepted row, which burns
    /// nothing, and a fate for every other. Folded, it leaves no row and
    /// no tick.
    #[test]
    fn a_terminal_ends_its_accepted_rows_in_one_manifest() {
        let stated = RowState::Stated {
            tick: BlockHeight::new(2),
            receipt: GlobalReceiptHash::ZERO,
        };
        let mut rows = rows_of([
            accepted(1, None),
            standing(2, far(), stated, false),
            accepted(3, Some((5, Said::Yes))),
            standing(4, far(), RowState::Pending, false),
        ]);
        rows.ticks
            .insert(BlockHeight::new(2), tick_holding(&[2], false));
        let lines = terminal_fates(&rows);
        let mut expected = vec![end_of(1), fate_of(2), end_of(3), fate_of(4)];
        expected.sort_by_key(|line| match line {
            TickLine::End { tx } | TickLine::Fate { tx, .. } => *tx,
            _ => unreachable!("a terminal names ends and fates"),
        });
        assert_eq!(lines, expected);
        assert!(lines.len() <= MAX_TICK_LINES_PER_BLOCK);

        let manifest = Capped::new(lines.clone()).expect("one manifest holds every row's line");
        let burned = fate_writes(&manifest);
        assert_eq!(
            burned.movements.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([stub_abort_charge(2).vault, stub_abort_charge(4).vault]),
            "only the fates burn a charge",
        );
        naming(&mut rows, 9, lines);
        assert!(rows.members.is_empty() && rows.ticks.is_empty());
    }

    /// No member line, fate or discard names an accepted row, whatever
    /// the clock and the evidence say, and none is ever unread: it holds
    /// nothing, and only an end line ends it.
    #[test]
    fn an_accepted_row_is_named_by_no_member_line() {
        let rows = rows_of([accepted(1, None)]);
        for anchor in [ms(0), far().at(), lapse(far()), lapse(far()).plus(MS)] {
            for said in READINGS {
                for recovery in [false, true] {
                    assert_eq!(
                        lines_at(&rows, anchor, said, recovery),
                        (vec![], vec![]),
                        "at {anchor:?} under {said:?}",
                    );
                }
            }
        }
    }

    /// A fate is licensed by what `evidence` says of the shards a row
    /// reaches and by nothing gathered for the rows that hear: a held
    /// member is fated exactly where its reach reads unreadable, whatever
    /// the sibling views say of the same shard.
    #[test]
    fn a_fate_is_licensed_at_the_anchor_it_is_today() {
        let held = held_in(1, far(), 2, Joins::Executes, Settlement::Shared);
        let mut rows = rows_of([held]);
        rows.ticks
            .insert(BlockHeight::new(2), tick_holding(&[1], false));
        let lines = |evidence: Evidence, siblings: SiblingViews| {
            let sets = CommittedSets {
                evidence: BTreeMap::from([(PEER, evidence)]),
                siblings,
                ..CommittedSets::default()
            };
            member_lines(
                &rows,
                ms(0),
                &sets,
                &|shard| sets.evidence(shard),
                false,
                &BTreeSet::new(),
            )
            .0
        };
        let gone = || peer_read_from(Source::Gone, Evidence::Unreadable);
        assert_eq!(
            lines(Evidence::Unreadable, peer_running()),
            vec![unanswerable(2, 1), fate_of(1)],
        );
        assert_eq!(
            lines(Evidence::Unreadable, SiblingViews::default()),
            vec![unanswerable(2, 1), fate_of(1)],
        );
        for readable in [Evidence::Live { terminating: false }, Evidence::Readable] {
            assert!(lines(readable, gone()).is_empty(), "{readable:?}");
        }
    }

    /// A proposer ends every row accepted at the parent that no sibling
    /// can still ask about, in transaction order, and no other: a row
    /// whose sibling still says yes or has not answered waits, one this
    /// replica cannot judge is left out, and a row the block itself
    /// accepts is not ended in it.
    #[test]
    fn end_lines_name_the_rows_no_sibling_can_still_ask_about() {
        let parent = rows_of([
            accepted(1, Some((5, Said::Accepted))),
            accepted(2, Some((5, Said::Yes))),
            accepted(3, None),
            accepted(4, Some((5, Said::Left))),
            accepted(6, Some((6, Said::Accepted))),
            standing(
                5,
                far(),
                RowState::Stated {
                    tick: BlockHeight::new(2),
                    receipt: GlobalReceiptHash::ZERO,
                },
                false,
            ),
        ]);
        let mut rows = parent.clone();
        rows.members
            .insert(tx(5), accepted(5, Some((5, Said::Accepted))));
        let named =
            |views: &SiblingViews| end_lines(&rows, &parent, views, ManifestBudget::default());
        assert_eq!(named(&peer_running()), ends_of(&[1, 4]));
        assert!(
            named(&SiblingViews::default()).is_empty(),
            "nothing gathered of a sibling is this replica's lack",
        );

        // A departed sibling: an accepted entry counts, and past it the
        // names its terminal ended, held or not.
        let departed = peer_read_from(Source::Gone, Evidence::Readable);
        assert_eq!(named(&departed), ends_of(&[1]));
        let unreadable = peer_read_from(Source::Gone, Evidence::Unreadable);
        assert_eq!(named(&unreadable), ends_of(&[1, 2, 3, 4, 6]));
        let named_by_terminal = SiblingViews {
            ended: BTreeMap::from([((PEER, tx(2)), true), ((PEER, tx(3)), false)]),
            ..departed
        };
        assert_eq!(named(&named_by_terminal), ends_of(&[1, 2, 3]));
    }

    /// The end lines take what the other lines left of the manifest's
    /// budget and stop at its first refusal.
    #[test]
    fn end_lines_stop_at_the_budget() {
        let rows = rows_of((1..=4).map(|seed| accepted(seed, Some((5, Said::Left)))));
        let mut budget = ManifestBudget::default();
        for _ in 0..MAX_TICK_LINES_PER_BLOCK - 2 {
            assert!(budget.take(&end_of(9)));
        }
        assert_eq!(
            end_lines(&rows, &rows, &peer_running(), budget),
            ends_of(&[1, 2, 3, 4])[..2],
        );
    }

    /// A voter admits any subset of the end lines the chain licenses, in
    /// ascending order, and refuses every other: one out of order or
    /// named twice, one for a row that was not accepted at the parent,
    /// one for a row that still waits on a sibling, and one past the
    /// budget the other lines left.
    #[test]
    fn an_end_line_is_admitted_only_where_decide_ends_its_row() {
        let parent = rows_of([
            accepted(1, Some((5, Said::Accepted))),
            accepted(2, Some((5, Said::Yes))),
            accepted(3, None),
            accepted(4, Some((5, Said::Left))),
            standing(
                5,
                far(),
                RowState::Stated {
                    tick: BlockHeight::new(2),
                    receipt: GlobalReceiptHash::ZERO,
                },
                false,
            ),
        ]);
        let mut rows = parent.clone();
        rows.members
            .insert(tx(5), accepted(5, Some((5, Said::Accepted))));
        let judged = |ended: &[u8], views: &SiblingViews, budget: ManifestBudget| {
            let ended: Vec<TxHash> = ended.iter().map(|&seed| tx(seed)).collect();
            ends_stand(&ended, &rows, &parent, views, budget)
        };
        assert!(tx(1) < tx(4) && tx(4) < tx(2));
        let fresh = ManifestBudget::default;
        let live = peer_running();
        for admitted in [&[][..], &[1], &[4], &[1, 4]] {
            assert_eq!(judged(admitted, &live, fresh()), Ok(()), "{admitted:?}");
        }
        for (refused, why) in [
            (&[4, 1][..], "out of order"),
            (&[1, 1], "named twice"),
            (&[2], "its sibling still says yes"),
            (&[3], "its sibling has not answered"),
            (&[5], "accepted by the block itself"),
            (&[9], "no row stands for it"),
            (&[1, 4, 2], "one of them waits"),
        ] {
            assert!(
                matches!(judged(refused, &live, fresh()), Err(Unlicensed::Refused(_))),
                "{why}",
            );
        }
    }

    /// A voter holds a block's end lines to the budget its other lines
    /// left: a line that fits is admitted, and a block naming one more
    /// than fits is refused, however well licensed each line is.
    #[test]
    fn an_ended_line_past_the_manifest_budget_is_refused() {
        let rows = rows_of([
            accepted(1, Some((5, Said::Accepted))),
            accepted(4, Some((5, Said::Left))),
        ]);
        assert!(tx(1) < tx(4));
        let live = peer_running();
        let mut left = ManifestBudget::default();
        for _ in 0..MAX_TICK_LINES_PER_BLOCK - 1 {
            assert!(left.take(&end_of(9)));
        }
        let judged = |ended: &[TxHash]| ends_stand(ended, &rows, &rows, &live, left);
        assert_eq!(judged(&[tx(1)]), Ok(()));
        assert_eq!(judged(&[tx(4)]), Ok(()));
        assert!(matches!(
            judged(&[tx(1), tx(4)]),
            Err(Unlicensed::Refused(_))
        ));
        assert_eq!(
            ends_stand(
                &[tx(1), tx(4)],
                &rows,
                &rows,
                &live,
                ManifestBudget::default()
            ),
            Ok(()),
        );
    }

    /// A voter that cannot judge a line, for want of the published
    /// window or of a departed sibling's names, answers that it lacks
    /// them, so the vote is deferred; a line no replica licenses is
    /// refused whatever else this one lacks.
    #[test]
    fn an_end_line_a_voter_cannot_judge_is_lacking_and_not_refused() {
        let rows = rows_of([accepted(1, None), accepted(2, Some((5, Said::Yes)))]);
        assert!(tx(1) < tx(2));
        let judged = |ended: &[u8], views: &SiblingViews| {
            let ended: Vec<TxHash> = ended.iter().map(|&seed| tx(seed)).collect();
            ends_stand(&ended, &rows, &rows, views, ManifestBudget::default())
        };
        let departed = peer_read_from(Source::Gone, Evidence::Readable);
        assert_eq!(judged(&[1], &departed), Err(Unlicensed::Lacking(tx(1))));
        let (source, view) = departed.shards[&PEER];
        let unpublished = SiblingViews {
            shards: BTreeMap::from([(
                PEER,
                (
                    source,
                    SiblingView {
                        recovery: Err(Unpublished),
                        ..view
                    },
                ),
            )]),
            ended: BTreeMap::new(),
        };
        assert_eq!(judged(&[1], &unpublished), Err(Unlicensed::Lacking(tx(1))));
        for held in [true, false] {
            let named = SiblingViews {
                ended: BTreeMap::from([((PEER, tx(1)), held)]),
                ..departed.clone()
            };
            assert_eq!(judged(&[1], &named), Ok(()), "named {held}");
        }

        // A sibling that runs and still says yes is a wait every replica
        // computes alike, beside a row this one cannot judge.
        let mixed = SiblingViews {
            shards: BTreeMap::from([(PEER, peer_running().shards[&PEER])]),
            ended: BTreeMap::new(),
        };
        assert!(matches!(
            judged(&[1, 2], &mixed),
            Err(Unlicensed::Refused(_))
        ));
    }

    /// A reading the block itself carries counts: an end line is judged
    /// over the rows advanced by the block's claims, so a row whose
    /// sibling's accept rides the block is ended in it, and is not where
    /// the rows are read without the block's claims.
    #[test]
    fn an_end_line_is_judged_over_the_rows_the_blocks_claims_advanced() {
        let parent = rows_of([accepted(1, Some((4, Said::Yes)))]);
        let heard = rows_of([accepted(1, Some((5, Said::Accepted)))]);
        let live = peer_running();
        let budget = ManifestBudget::default;
        assert_eq!(end_lines(&heard, &parent, &live, budget()), vec![end_of(1)]);
        assert_eq!(
            ends_stand(&[tx(1)], &heard, &parent, &live, budget()),
            Ok(())
        );
        assert!(end_lines(&parent, &parent, &live, budget()).is_empty());
        assert!(matches!(
            ends_stand(&[tx(1)], &parent, &parent, &live, budget()),
            Err(Unlicensed::Refused(_))
        ));
    }

    /// A holder that has accepted on the counterpart stands there with a
    /// row, no seat and an accepted leaf, as the fold writes them, and
    /// that reading proves no hold cycle: the pending member beside it
    /// is not wounded.
    #[test]
    fn an_unseated_accepted_holder_proves_no_cycle() {
        let mut peers = MemberIndex::empty(PEER);
        let mut entries: BTreeMap<EntryKey, Vec<u8>> = BTreeMap::new();
        let tick = TickId::new(PEER, BlockHeight::new(2));
        let half = |half: TickHalf, stated: bool| SettledHalf {
            tick,
            half,
            deleted: Vec::new(),
            stated: if stated {
                vec![(tx(1), GlobalReceiptHash::ZERO)]
            } else {
                Vec::new()
            },
            accepted: if stated { Vec::new() } else { vec![tx(1)] },
        };
        let blocks = [
            MemberInputs {
                height: BlockHeight::new(2),
                transactions: vec![(tx(1), far())],
                manifest: Arc::new(Capped::from_array([TickLine::Member {
                    tx: tx(1),
                    joins: Joins::Executes,
                    settlement: Settlement::Shared,
                    holds: Capped::empty(),
                    reach: Capped::from_array([ShardId::ROOT]),
                    awaits: Capped::from_array([ShardId::ROOT]),
                    charge: CHARGE,
                    share: 0,
                    reserves: Capped::empty(),
                    deadline: far(),
                    nevers: Capped::empty(),
                }])),
                ..MemberInputs::still(PEER)
            },
            MemberInputs {
                height: BlockHeight::new(3),
                settled: vec![half(TickHalf::Stated, true)],
                ..MemberInputs::still(PEER)
            },
            MemberInputs {
                height: BlockHeight::new(4),
                settled: vec![half(TickHalf::Legs, false)],
                ..MemberInputs::still(PEER)
            },
        ];
        for block in &blocks {
            for (key, change) in member_writes(&peers, block) {
                match change {
                    Some(bytes) => entries.insert(key, bytes),
                    None => entries.remove(&key),
                };
            }
            peers.advance(block);
        }
        assert_eq!(peers.members[&tx(1)].state, RowState::Accepted);
        let (row, unseated, leaf) = (
            member_row_leaf(PEER, tx(1)),
            seat_leaf(PEER, tx(1)),
            verdict_leaf(PEER, tx(1)),
        );
        let written: BTreeSet<SubstateKey> = entries
            .keys()
            .map(|key| entry_leaf_key(&ProtocolHasher, *key))
            .collect();
        assert!(written.contains(&row) && written.contains(&leaf) && !written.contains(&unseated));

        let declared = vec![(cell(1, 1), WRITE)];
        let rows = held_beside_pending(1, 2, &declared);
        let leaves: Vec<SubstateKey> = written
            .into_iter()
            .chain([seat_leaf(PEER, tx(2))])
            .collect();
        let reading = seat_reading(1, 2, &leaves);
        assert_eq!(reading.reading(unseated), Some(Inclusion::Absent));
        assert!(wounded(&rows, ms(0), from_ref(&reading)).is_empty());
        let cycle = seat_reading(1, 2, &[seat_leaf(PEER, tx(2)), row]);
        assert_eq!(
            wounded(&rows, ms(0), from_ref(&cycle)),
            BTreeSet::from([tx(2)]),
            "without the leaf the same reading is the cycle",
        );
    }

    /// A crossing block over the most tick rows a chain can hold names
    /// the recovery discard of every one in a single manifest, ahead of
    /// every other line; one tick row more than the cap would be left
    /// standing past the crossing.
    #[test]
    fn a_crossing_discards_a_full_chain_of_ticks_in_one_manifest() {
        let fill = |count: usize| {
            let mut rows = MemberIndex::empty(ShardId::ROOT);
            for height in 1..=count {
                rows.ticks.insert(
                    BlockHeight::new(u64::try_from(height).unwrap()),
                    TickRow {
                        members: Capped::empty(),
                        determined_unsettled: true,
                        awaiting: 0,
                    },
                );
            }
            rows
        };
        let live = |_| Evidence::Live { terminating: false };
        let at_cap = fill(MAX_TICK_LINES_PER_BLOCK);
        let (lines, missing, _) = member_lines(
            &at_cap,
            ms(5_000),
            &Held::default(),
            &live,
            true,
            &BTreeSet::new(),
        );
        assert!(missing.is_empty());
        assert_eq!(lines.len(), MAX_TICK_LINES_PER_BLOCK);
        assert!(lines.iter().all(|line| matches!(
            line,
            TickLine::Discard {
                cause: DiscardCause::Recovery,
                ..
            }
        )));
        let over = fill(MAX_TICK_LINES_PER_BLOCK + 1);
        let (lines, _, _) = member_lines(
            &over,
            ms(5_000),
            &Held::default(),
            &live,
            true,
            &BTreeSet::new(),
        );
        assert_eq!(
            lines.len(),
            MAX_TICK_LINES_PER_BLOCK,
            "one past the cap is left out"
        );
    }
}
