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

use hyperscale_hbor::Capped;
use hyperscale_storage::{MemberIndex, RowState, member_row_leaf, seat_leaf};
use hyperscale_types::{
    AbortCharge, Address, Anchor, BlockHeight, CollectionId, Deadline, DeclaredKey, DiscardCause,
    Evidence, Holds, Inclusion, Joins, MAX_HOLDS_PER_MEMBER, MAX_TICK_LINES_PER_BLOCK, Mode,
    ModeKind, Reach, Role, Settlement, ShardId, ShardTrie, StateClaim, SubstateKey, TickId,
    TickLine, TopologySnapshot, Transaction, TxHash, WeightedTimestamp, compatible,
    tick_manifest_admits_block,
};
use hyperscale_vm_effects::Kind;
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
}

impl ProvisionalCells {
    /// Record how one unresolved leg declared it would reach each cell.
    pub fn claim(&mut self, declared: &[(DeclaredKey, Mode)]) {
        for (key, mode) in declared {
            let kind = mode.kind();
            match key {
                DeclaredKey::Cell(cell) => {
                    self.cells.entry(*cell).or_default().insert(kind);
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
                DeclaredKey::Cell(cell) => self.cells.get(cell),
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

/// A payer's wait for its counterparts' engagement: the shards whose
/// bundles it waits on, and when it stops waiting and runs aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngagementWait {
    /// The counterparts it waits on.
    pub counterparts: BTreeSet<ShardId>,
    /// The deadline past which it runs without them.
    pub deadline: WeightedTimestamp,
}

/// What a member's classification says about how it joins a tick,
/// derived once from its transaction and the committee its including
/// block was classified under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFacts {
    /// The remote shards the transaction reaches.
    pub reach: Reach,
    /// Whether this shard runs a leg of it, which its reclaim resolves
    /// if it never runs, and never an abort.
    pub leg: bool,
    /// Which half settles it, and whether a discard keeps it.
    pub settlement: Settlement,
    /// Its declared accesses, each under the mode it takes.
    pub declared: Vec<(DeclaredKey, Mode)>,
    /// What it waits on before it can run.
    pub requires: BTreeSet<Requirement>,
    /// The payer's engagement wait, where this shard pays and waits.
    pub engagement: Option<EngagementWait>,
    /// What an abort of it burns, priced under the committee it is
    /// classified under.
    pub charge: AbortCharge,
}

impl MemberFacts {
    /// The facts of `tx`'s member on `local`, classified under
    /// `committee`, the committee at its including block's parent
    /// anchor. `tx` must be routed.
    #[must_use]
    pub fn of(tx: &Transaction, committee: &TopologySnapshot, local: ShardId) -> Self {
        let trie = committee.shard_trie();
        let participating: BTreeSet<ShardId> = committee
            .all_shards_for_transaction(tx)
            .into_iter()
            .collect();
        let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
        let charge = AbortCharge {
            vault: tx.fee_vault(),
            amount: tx.price(&committee.prices()),
        };
        Self::of_member(
            &Member::of(classified, local, participating),
            tx,
            trie,
            charge,
        )
    }

    /// The facts of `member`, `tx`'s member classified under `trie`.
    ///
    /// # Panics
    ///
    /// Never: a transaction reaches no more shards than its routing
    /// names prefixes, which caps the reach.
    #[must_use]
    pub fn of_member(
        member: &Member,
        tx: &Transaction,
        trie: &ShardTrie,
        charge: AbortCharge,
    ) -> Self {
        let local = member.local();
        let reaches_beyond = member.reaches_beyond();
        let settlement = if !member.abortable() {
            Settlement::Alone
        } else if matches!(member.role(), Role::Whole | Role::Core) {
            Settlement::Shared
        } else {
            Settlement::Awaited
        };
        let (requires, engagement) = if !reaches_beyond {
            (BTreeSet::new(), None)
        } else if member.classified().decomposed() {
            (requirements_of(member, tx.legs()), None)
        } else {
            let remote: BTreeSet<ShardId> = member
                .reach()
                .iter()
                .copied()
                .filter(|&shard| shard != local)
                .collect();
            let payer = trie.shard_for_prefix(tx.fee_payer());
            let mut requires: BTreeSet<Requirement> = tx
                .routing()
                .provision_prefixes
                .iter()
                .map(|prefix| trie.shard_for_prefix(*prefix))
                .filter(|&shard| shard != local)
                .map(Requirement::CommittedState)
                .collect();
            let engagement = if payer == local {
                (!remote.is_empty()).then(|| EngagementWait {
                    counterparts: remote,
                    deadline: Deadline::of_transaction(tx).at(),
                })
            } else {
                requires.insert(Requirement::CommittedState(payer));
                None
            };
            (requires, engagement)
        };
        Self {
            reach: Capped::new(
                member
                    .reach()
                    .iter()
                    .copied()
                    .filter(|&shard| shard != local)
                    .collect(),
            )
            .expect("a transaction reaches no more shards than it names prefixes"),
            leg: member.role() == Role::Leg,
            settlement,
            declared: tx.routing().declared_modes.clone(),
            requires,
            engagement,
            charge,
        }
    }

    /// Whether the transaction reaches beyond this shard.
    #[must_use]
    pub fn reaches_beyond(&self) -> bool {
        !self.reach.is_empty()
    }

    /// Whether a counterpart's verdict can still discard the member's
    /// effects, so what it declared is held while it is in flight.
    #[must_use]
    pub fn abortable(&self) -> bool {
        self.settlement != Settlement::Alone
    }
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
/// its payer's engagement short of the wait's deadline. Past that
/// deadline with a counterpart silent it joins, attested aborted.
#[must_use]
pub fn readiness(
    tx: TxHash,
    facts: &MemberFacts,
    anchor: WeightedTimestamp,
    inputs: &dyn CommittedInputs,
) -> Option<Joins> {
    let provisioned = facts.requires.iter().all(|requirement| match requirement {
        Requirement::CommittedState(shard) => inputs.engaged(*shard, tx),
        Requirement::Crossing { key } => inputs.arrived(*key, tx),
    });
    if !provisioned {
        return None;
    }
    let Some(wait) = &facts.engagement else {
        return Some(Joins::Executes);
    };
    let silent = wait
        .counterparts
        .iter()
        .any(|&shard| !inputs.engaged(shard, tx));
    if !silent {
        Some(Joins::Executes)
    } else if anchor >= wait.deadline {
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
    /// What each shard a held member reaches says of its evidence at the
    /// block's anchor.
    pub evidence: BTreeMap<ShardId, Evidence>,
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
    /// Member lines and discards: a block the chain carries content in.
    #[default]
    Members,
    /// A fate for every member row: the chain's terminal.
    Fates,
    /// Nothing: a coast block past the terminal, or a recovery's bridge.
    Empty,
}

/// The fates a chain's terminal names: one per member row, in
/// transaction order.
///
/// Each is priced by what its line kept on its row, or by its facts where
/// no line named it. A row whose price `facts` does not
/// have is returned beside the lines, so a voter defers and a proposer
/// waits, as they do for a pending row's member line.
#[must_use]
pub fn terminal_fates<'f>(
    rows: &MemberIndex,
    facts: &dyn Fn(TxHash) -> Option<&'f MemberFacts>,
) -> (Vec<TickLine>, Vec<TxHash>) {
    let mut lines = Vec::new();
    let mut missing = Vec::new();
    for row in rows.members.values() {
        match row
            .charge
            .or_else(|| facts(row.tx).map(|known| known.charge))
        {
            Some(charge) => lines.push(TickLine::Fate { tx: row.tx, charge }),
            None => missing.push(row.tx),
        }
    }
    (lines, missing)
}

/// What a proposer's coordinator hands the block builder.
///
/// The facts of every member it may name, and what committed content up
/// to the parent says of them. The builder adds the block's own bundles
/// and claims, once it has dropped what the block will not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestInputs {
    /// Each member's facts, by transaction.
    pub facts: BTreeMap<TxHash, MemberFacts>,
    /// What committed content up to the parent says of them.
    pub committed: CommittedSets,
    /// The frontier of a halt recovery whose ticks the block discards,
    /// where its parent is the fresh committee's.
    pub recovery: Option<BlockHeight>,
    /// What the block's manifest names.
    pub kind: ManifestKind,
}

/// Where a candidate stands, as its row says, with what judging it
/// reads.
#[derive(Debug, Clone, Copy)]
pub enum Standing<'a> {
    /// Committed, and named by no tick yet: judged on its facts.
    Pending(&'a MemberFacts),
    /// Committed and named by no tick yet, and the victim of a hold cycle
    /// the block's own claims prove: aborted on its facts, whatever its
    /// deadline. See [`wounded`].
    Wounded(&'a MemberFacts),
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
    /// Let go by a discard of the tick that held it. Judged on its row
    /// alone.
    Released {
        /// Whether a committed departure names it.
        covered: bool,
        /// Which half its line said settles it.
        settlement: Settlement,
        /// The remote shards its line named.
        reach: &'a Reach,
    },
}

impl Standing<'_> {
    /// The remote shards the transaction reaches.
    const fn reach(&self) -> &Reach {
        match self {
            Self::Pending(facts) | Self::Wounded(facts) => &facts.reach,
            Self::Held { reach, .. } | Self::Released { reach, .. } => reach,
        }
    }

    /// What an abort of it burns: its facts' price while it is pending,
    /// and `named`, the price its row kept from the line that named it,
    /// once a line has.
    const fn charge(&self, named: Option<AbortCharge>) -> Option<AbortCharge> {
        match self {
            Self::Pending(facts) | Self::Wounded(facts) => Some(facts.charge),
            Self::Held { .. } | Self::Released { .. } => named,
        }
    }

    /// Whether this shard runs a leg of it, which its reclaim resolves.
    /// A held row is never one; a released one is judged by
    /// [`Nameable::abortable`] on its row.
    const fn leg(&self) -> bool {
        match self {
            Self::Pending(facts) | Self::Wounded(facts) => facts.leg,
            Self::Held { .. } | Self::Released { .. } => false,
        }
    }
}

/// The member lines a block names over `rows`: the family after the
/// block's own finalizations, discards, records and transactions.
///
/// Every `Pending` row is a candidate, and past its deadline so is one a
/// tick let go of, and one a tick holds that an abort may name on its
/// row alone; every in-flight row's holds are held. A candidate whose
/// facts `facts` does not have is left waiting and returned beside the
/// lines, so a voter, which cannot judge a manifest without them,
/// defers, and a proposer names what it can. A held row never needs
/// them, so no member in flight keeps a voter that cannot route it from
/// judging a manifest. A pending member of `wounded`, the victims the
/// block's own state claims prove (see [`wounded`]), is aborted short of
/// its deadline.
#[must_use]
pub fn member_lines<'f>(
    rows: &MemberIndex,
    anchor: WeightedTimestamp,
    facts: &dyn Fn(TxHash) -> Option<&'f MemberFacts>,
    inputs: &dyn CommittedInputs,
    evidence: &dyn Fn(ShardId) -> Evidence,
    recovery: Option<BlockHeight>,
    wounded: &BTreeSet<TxHash>,
) -> (Vec<TickLine>, Vec<TxHash>) {
    let mut holds = ProvisionalCells::default();
    let mut candidates = Vec::new();
    let mut missing = Vec::new();
    let mut unanswerable = Vec::new();
    // Every tick at or below a halt recovery's frontier is discarded
    // whole by the first block the fresh committee's certificate
    // follows: no fresh quorum can hold it, and no other line names its
    // members in that block.
    let recovered: Vec<BlockHeight> = recovery.map_or_else(Vec::new, |frontier| {
        rows.ticks
            .range(..=frontier)
            .map(|(height, _)| *height)
            .collect()
    });
    for row in rows.members.values() {
        let passed = row.deadline.passed(anchor);
        let standing = match row.state {
            RowState::InFlight {
                tick,
                joins,
                settlement,
            } => {
                holds.claim(&row.holds);
                if recovered.contains(&tick) {
                    continue;
                }
                // A tick still owing its determined half is let go of by
                // nothing but a recovery: a determined contribution that
                // ran is readable, and a discard dropping it would lose
                // it.
                if rows
                    .ticks
                    .get(&tick)
                    .is_some_and(|held| held.determined_unsettled)
                {
                    continue;
                }
                let tick = TickId::new(rows.shard(), tick);
                if joins != Joins::Aborted && settlement != Settlement::Alone {
                    match answerable(&row.reach, evidence) {
                        Some(true) => {}
                        Some(false) => {
                            unanswerable.push(TickLine::Discard {
                                tick,
                                cause: DiscardCause::Unanswerable(row.tx),
                            });
                            continue;
                        }
                        None => {
                            missing.push(row.tx);
                            continue;
                        }
                    }
                }
                if !(passed
                    && row.covered
                    && joins != Joins::Aborted
                    && settlement != Settlement::Alone)
                {
                    continue;
                }
                Standing::Held {
                    tick,
                    reach: &row.reach,
                }
            }
            RowState::Released { settlement } => {
                if !passed {
                    continue;
                }
                Standing::Released {
                    covered: row.covered,
                    settlement,
                    reach: &row.reach,
                }
            }
            RowState::Pending => match facts(row.tx) {
                None => {
                    missing.push(row.tx);
                    continue;
                }
                Some(known) if wounded.contains(&row.tx) => Standing::Wounded(known),
                Some(known) => Standing::Pending(known),
            },
        };
        let Some(charge) = standing.charge(row.charge) else {
            continue;
        };
        candidates.push(Nameable {
            tx: row.tx,
            deadline: row.deadline,
            standing,
            charge,
        });
    }
    let mut budget = ManifestBudget::default();
    let mut lines = select_members(anchor, candidates, inputs, &mut holds, &mut budget);
    let recoveries = recovered.into_iter().map(|height| TickLine::Discard {
        tick: TickId::new(rows.shard(), height),
        cause: DiscardCause::Recovery,
    });
    for discard in unanswerable.into_iter().chain(recoveries) {
        if !budget.take(&discard) {
            break;
        }
        lines.push(discard);
    }
    (lines, missing)
}

/// Whether a counterpart of a held member can still answer for it: `Some(false)`
/// once every shard of its `reach` has departed with its settled set
/// unreadable, `None` while a window that could say is not yet folded.
/// A member reaching nobody has no counterpart to fall silent.
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

/// What a manifest has spent of its byte budget and its line cap.
#[derive(Debug, Default, Clone, Copy)]
pub struct ManifestBudget {
    spent: usize,
    lines: usize,
}

impl ManifestBudget {
    /// Take `line` if it fits what is left, and say whether it did.
    pub fn take(&mut self, line: &TickLine) -> bool {
        self.take_all([line])
    }

    /// Take every one of `lines` if all of them fit what is left, and
    /// none of them otherwise.
    fn take_all<'l>(&mut self, lines: impl IntoIterator<Item = &'l TickLine>) -> bool {
        let (mut spent, mut count) = (self.spent, self.lines);
        for line in lines {
            spent = spent.saturating_add(line.wire_weight());
            count += 1;
        }
        if !tick_manifest_admits_block(spent) || count > MAX_TICK_LINES_PER_BLOCK {
            return false;
        }
        self.spent = spent;
        self.lines = count;
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
    /// What an abort of it burns: priced by its facts while it is
    /// pending, and read off its row once a line has named it.
    pub charge: AbortCharge,
}

/// What an abort of a candidate lets go of.
#[derive(Debug, Clone, Copy)]
enum Abort {
    /// Nothing: no tick holds it.
    Unheld,
    /// The tick that holds it, which a discard beside the abort releases.
    Held(TickId),
}

impl Nameable<'_> {
    /// Whether an abort may name this candidate past its deadline, and
    /// what the abort lets go of.
    ///
    /// A `Pending` row was never certified, so nothing can settle it.
    /// A row a tick holds is abandoned only once a departure covers it,
    /// never by the tick that is itself its abandonment, and never where
    /// no counterpart's verdict can discard it, since its own tick
    /// decides it: a leg's readings license its reclaim, and a core
    /// member is named to run only once every sibling's committed bundle
    /// names it, so a sibling's cell read absent reaches only a `Pending`
    /// row. A row let go of is aborted once it reaches no other shard, or
    /// once a departure covers it and a counterpart's verdict could have
    /// discarded it: one that is `Alone` with a reach is a leg, which its
    /// reclaim resolves, or a core member its own tick decides.
    fn abortable(&self) -> Option<Abort> {
        match self.standing {
            Standing::Pending(_) | Standing::Wounded(_) => Some(Abort::Unheld),
            Standing::Held { tick, .. } => Some(Abort::Held(tick)),
            Standing::Released {
                covered,
                settlement,
                reach,
            } if reach.is_empty() || (covered && !matches!(settlement, Settlement::Alone)) => {
                Some(Abort::Unheld)
            }
            Standing::Released { .. } => None,
        }
    }
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
/// its reclaim resolves it. A [`Standing::Wounded`] candidate is named
/// `Aborted` as one past its deadline is. An abort of a member a tick
/// holds is charged together with that tick's `Abandoned` discard, so the
/// pair fits or neither does.
///
/// Canonical order puts the transactions reaching beyond this shard
/// first, then hash order: theirs are the provisional writes everything
/// else has to be compatible with, and a determined member is the
/// cheaper of the two to defer. `holds` carries in what in-flight legs
/// claim and leaves with what the named lines add, so a member of this
/// very tick can be what keeps the next one out. A member whose
/// declaration no line can carry is never named. The walk stops at the
/// first line the budget refuses, and the rest wait a block.
///
/// # Panics
///
/// Never: a declaration is carried only once it is checked against the
/// cap on a line's holds.
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
        } = candidate;
        if deadline.passed(anchor) || matches!(standing, Standing::Wounded(_)) {
            if standing.leg() {
                continue;
            }
            let Some(abort) = candidate.abortable() else {
                continue;
            };
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
                charge,
            };
            let discard = match abort {
                Abort::Unheld => None,
                Abort::Held(tick) => Some(TickLine::Discard {
                    tick,
                    cause: DiscardCause::Abandoned(tx),
                }),
            };
            if !budget.take_all(std::iter::once(&line).chain(&discard)) {
                break;
            }
            lines.push(line);
            discards.extend(discard);
            continue;
        }
        let Standing::Pending(facts) = standing else {
            continue;
        };
        let Some(joins) = readiness(tx, facts, anchor, inputs) else {
            continue;
        };
        let abortable = facts.abortable();
        if abortable && facts.declared.len() > MAX_HOLDS_PER_MEMBER {
            continue;
        }
        if !holds.is_empty() && holds.blocks(&facts.declared) {
            continue;
        }
        let line = TickLine::Member {
            tx,
            joins,
            settlement: facts.settlement,
            holds: if abortable {
                Capped::new(facts.declared.clone()).expect("checked against the cap above")
            } else {
                Capped::empty()
            },
            reach: facts.reach.clone(),
            charge,
        };
        if !budget.take(&line) {
            break;
        }
        // After the test, never before: a transaction is not what keeps
        // itself out.
        if abortable {
            holds.claim(&facts.declared);
        }
        lines.push(line);
    }
    lines.extend(discards);
    lines
}

/// A pending core member a held core member keeps out of a block, where
/// the two reach a shard in common: one shard's half of a cycle in which
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
    reach: &'r Reach,
}

impl<'r> CoreHolder<'r> {
    /// A holder over `holds`, or `None` where it holds nothing.
    fn of(tx: TxHash, holds: &'r Holds, reach: &'r Reach) -> Option<Self> {
        if holds.is_empty() {
            return None;
        }
        let mut cells = ProvisionalCells::default();
        cells.claim(holds);
        Some(Self {
            tx,
            holds,
            cells,
            reach,
        })
    }

    /// Whether these holds refuse `waiting`, which reaches a shard this
    /// holder reaches too.
    fn refuses(&self, waiting: &MemberFacts) -> bool {
        self.shared(waiting).next().is_some() && self.cells.blocks(&waiting.declared)
    }

    /// The shards both this holder and `waiting` reach.
    fn shared<'w>(&'w self, waiting: &'w MemberFacts) -> impl Iterator<Item = ShardId> + 'w {
        self.reach
            .iter()
            .copied()
            .filter(|shard| waiting.reach.contains(shard))
    }
}

/// Every core member `rows` hold in flight, with what it holds.
fn in_flight_holders(rows: &MemberIndex) -> impl Iterator<Item = CoreHolder<'_>> {
    rows.members
        .values()
        .filter(|row| {
            matches!(
                row.state,
                RowState::InFlight {
                    settlement: Settlement::Shared,
                    ..
                }
            )
        })
        .filter_map(|row| CoreHolder::of(row.tx, &row.holds, &row.reach))
}

/// The contentions a block naming `lines` over `rows` leaves standing.
///
/// Every core member short of its deadline that is ready at `anchor` and
/// that no line names, paired with each core member whose holds refuse
/// it and which reaches a shard it reaches too: one in flight on its
/// row, or named by `lines` themselves. `rows` is the family before the
/// lines, so a member they name is still `Pending` there and counts
/// once, as a holder.
#[must_use]
pub fn contentions<'f>(
    rows: &MemberIndex,
    lines: &[TickLine],
    anchor: WeightedTimestamp,
    facts: &dyn Fn(TxHash) -> Option<&'f MemberFacts>,
    inputs: &dyn CommittedInputs,
) -> Vec<Contention> {
    let named: BTreeSet<TxHash> = lines
        .iter()
        .filter_map(|line| match line {
            TickLine::Member { tx, .. } => Some(*tx),
            TickLine::Fate { .. } | TickLine::Discard { .. } => None,
        })
        .collect();
    let in_lines = lines.iter().filter_map(|line| match line {
        TickLine::Member {
            tx,
            settlement: Settlement::Shared,
            holds,
            reach,
            ..
        } => CoreHolder::of(*tx, holds, reach),
        _ => None,
    });
    let holders: Vec<CoreHolder<'_>> = in_flight_holders(rows).chain(in_lines).collect();
    if holders.is_empty() {
        return Vec::new();
    }
    let mut contended = Vec::new();
    for row in rows.members.values() {
        if row.state != RowState::Pending || named.contains(&row.tx) || row.deadline.passed(anchor)
        {
            continue;
        }
        let Some(waiting) = facts(row.tx) else {
            continue;
        };
        if waiting.settlement != Settlement::Shared
            || readiness(row.tx, waiting, anchor, inputs).is_none()
        {
            continue;
        }
        contended.extend(
            holders
                .iter()
                .filter(|holder| holder.refuses(waiting))
                .map(|holder| Contention {
                    waiting: row.tx,
                    holder: holder.tx,
                }),
        );
    }
    contended
}

/// The pending core members of `rows` that `claims`, a block's own state
/// claims, prove the victims of a hold cycle at `anchor`.
///
/// A cycle is two core members each shard holds in the other's order:
/// here, `holder` is in flight and its holds refuse `waiting`, which is
/// pending; on a counterpart both reach, one claim reads `waiting` seated
/// and `holder` committed and unseated, at one anchor. Holds are the
/// whole transaction's declared set, and `waiting`'s refuses `holder`'s
/// in turn, so the counterpart's seat of `waiting` refuses `holder` there
/// just as `holder` refuses `waiting` here, and neither certificate the
/// other awaits can come. Nor can the
/// reading go stale: the counterpart releases `waiting` only on this
/// shard's verdict, which a pending member has not given, so `holder`
/// stays refused there for as long as this shard's own rows stand.
///
/// The victim is the later of the two in hash order. Both shards order
/// them alike, and only the shard where the victim is pending names it,
/// so a cycle loses exactly one member.
#[must_use]
pub fn wounded<'f>(
    rows: &MemberIndex,
    anchor: WeightedTimestamp,
    facts: &dyn Fn(TxHash) -> Option<&'f MemberFacts>,
    claims: &[StateClaim],
) -> BTreeSet<TxHash> {
    if claims.is_empty() {
        return BTreeSet::new();
    }
    seat_questions(rows, anchor, facts)
        .into_iter()
        .filter(|question| question.proven_by(claims))
        .map(|question| question.waiting)
        .collect()
}

/// What a shard asks a counterpart before it aborts a pending core member
/// as the victim of a hold cycle.
///
/// Whether, at one anchor there, `waiting` is seated and `holder`, which
/// refuses it here, is committed and unseated. See [`wounded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeatQuestion {
    /// The counterpart both members reach.
    pub shard: ShardId,
    /// The pending member, the later of the two in hash order.
    pub waiting: TxHash,
    /// The member in flight here whose holds refuse it.
    pub holder: TxHash,
}

impl SeatQuestion {
    /// The cells it reads on its counterpart: the waiting member's seat,
    /// the holder's row and the holder's seat.
    #[must_use]
    pub fn keys(&self) -> [SubstateKey; 3] {
        [
            seat_leaf(self.shard, self.waiting),
            member_row_leaf(self.shard, self.holder),
            seat_leaf(self.shard, self.holder),
        ]
    }

    /// Whether `read`, one anchor's readings, answers with the cycle: the
    /// waiting member seated, and the holder committed and unseated.
    #[must_use]
    pub fn answered_by(&self, read: impl Fn(SubstateKey) -> Option<Inclusion>) -> bool {
        let [seat, row, none] = self.keys();
        matches!(read(seat), Some(Inclusion::Present(_)))
            && matches!(read(row), Some(Inclusion::Present(_)))
            && read(none) == Some(Inclusion::Absent)
    }

    /// Whether `claims` answer it at one anchor. The readings may sit in
    /// several claims at that anchor: one anchor is one root, however its
    /// cells were cut.
    fn proven_by(&self, claims: &[StateClaim]) -> bool {
        let anchors: BTreeSet<Anchor> = claims
            .iter()
            .filter(|claim| claim.anchor.shard == self.shard)
            .map(|claim| claim.anchor)
            .collect();
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
/// order, and reaches a counterpart it reaches, per counterpart. The
/// refusal is asked both ways: the waiting member's seat on the
/// counterpart must refuse the holder there too, or an unseated holder
/// would read as a cycle when it was only not yet ready.
#[must_use]
pub fn seat_questions<'f>(
    rows: &MemberIndex,
    anchor: WeightedTimestamp,
    facts: &dyn Fn(TxHash) -> Option<&'f MemberFacts>,
) -> Vec<SeatQuestion> {
    let holders: Vec<CoreHolder<'_>> = in_flight_holders(rows).collect();
    if holders.is_empty() {
        return Vec::new();
    }
    let mut questions = Vec::new();
    for row in rows.members.values() {
        if row.state != RowState::Pending || row.deadline.passed(anchor) {
            continue;
        }
        let Some(waiting) = facts(row.tx) else {
            continue;
        };
        if waiting.settlement != Settlement::Shared {
            continue;
        }
        let mut seat: Option<ProvisionalCells> = None;
        for holder in holders
            .iter()
            .filter(|holder| holder.tx < row.tx && holder.refuses(waiting))
        {
            let seat = seat.get_or_insert_with(|| {
                let mut cells = ProvisionalCells::default();
                cells.claim(&waiting.declared);
                cells
            });
            if !seat.blocks(holder.holds) {
                continue;
            }
            questions.extend(holder.shared(waiting).map(|shard| SeatQuestion {
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
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_storage::{MemberInputs, MemberRow, SettledHalf, TickRow};
    use hyperscale_types::test_utils::{proven_claim, stub_abort_charge};
    use hyperscale_types::{
        AddressClass, BlockHeight, DeclaredRange, Hash, LocalKey, MAX_TICK_MANIFEST_BYTES, TickHalf,
    };
    use hyperscale_vm_types::Moves;

    use super::*;

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

    #[test]
    fn nothing_is_blocked_by_an_empty_claim_set() {
        let claims = ProvisionalCells::default();
        assert!(claims.is_empty());
        assert!(!claims.blocks(&[(cell(1, 1), WRITE)]));
    }

    /// The reason the whole relation is here: payment traffic is delta
    /// and reserve, and those compose. A vault an unresolved leg is
    /// moving does not stop the next payment from moving it too.
    #[test]
    fn commutative_access_does_not_wait_on_commutative_access() {
        let mut claims = ProvisionalCells::default();
        claims.claim(&[(cell(1, 1), Mode::Delta { moves: Moves::Both })]);
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

    fn pending(tx: TxHash, facts: &MemberFacts, deadline: Deadline) -> Nameable<'_> {
        Nameable {
            tx,
            deadline,
            standing: Standing::Pending(facts),
            charge: CHARGE,
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

    fn alone(declared: Vec<(DeclaredKey, Mode)>) -> MemberFacts {
        MemberFacts {
            reach: Capped::empty(),
            leg: false,
            settlement: Settlement::Alone,
            declared,
            requires: BTreeSet::new(),
            engagement: None,
            charge: CHARGE,
        }
    }

    fn leg(declared: Vec<(DeclaredKey, Mode)>, requires: &[Requirement]) -> MemberFacts {
        MemberFacts {
            reach: Capped::from_array([PEER]),
            leg: false,
            settlement: Settlement::Shared,
            declared,
            requires: requires.iter().copied().collect(),
            engagement: None,
            charge: CHARGE,
        }
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
            ..MemberInputs::still(shard)
        });
        let in_flight = |seed: u8| TickLine::Member {
            tx: tx(seed),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::empty(),
            reach: Capped::from_array([PEER]),
            charge: stub_abort_charge(seed),
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
                members: vec![tx(1)],
            }],
            ..MemberInputs::still(shard)
        });

        let (fates, missing) = terminal_fates(&rows, &|_| None);
        assert!(missing.is_empty(), "a named row prices its own fate");
        assert_eq!(
            fates,
            vec![TickLine::Fate {
                tx: tx(2),
                charge: stub_abort_charge(2),
            }],
        );
    }

    /// A member waits on every bundle and crossing it requires, and a
    /// payer on its counterparts' engagement until the wait's deadline,
    /// past which it runs attested aborted.
    #[test]
    fn a_member_is_ready_once_its_committed_inputs_are() {
        let record = SubstateKey {
            owner: Address::new([3; 31], AddressClass::Component),
            local: LocalKey([3; 16]),
        };
        let facts = leg(
            vec![],
            &[
                Requirement::CommittedState(PEER),
                Requirement::Crossing { key: record },
            ],
        );
        let mut held = Held::default();
        assert_eq!(readiness(tx(1), &facts, ms(0), &held), None);
        held.engaged.insert((PEER, tx(1)));
        assert_eq!(readiness(tx(1), &facts, ms(0), &held), None, "the crossing");
        held.arrived.insert((record, tx(2)));
        assert_eq!(
            readiness(tx(1), &facts, ms(0), &held),
            None,
            "an arrival naming another transaction answers nothing"
        );
        held.arrived.insert((record, tx(1)));
        assert_eq!(
            readiness(tx(1), &facts, ms(0), &held),
            Some(Joins::Executes)
        );

        let payer = MemberFacts {
            engagement: Some(EngagementWait {
                counterparts: BTreeSet::from([PEER]),
                deadline: ms(5_000),
            }),
            ..leg(vec![], &[])
        };
        let silent = Held::default();
        assert_eq!(readiness(tx(1), &payer, ms(4_999), &silent), None);
        assert_eq!(
            readiness(tx(1), &payer, ms(5_000), &silent),
            Some(Joins::ExecutesAborted)
        );
        assert_eq!(
            readiness(tx(1), &payer, ms(0), &held),
            Some(Joins::Executes),
            "an engaged counterpart ends the wait"
        );
        assert_eq!(
            readiness(tx(1), &alone(vec![]), ms(0), &silent),
            Some(Joins::Executes)
        );
    }

    /// Members reaching beyond the shard are named first, a member an
    /// earlier abortable one's hold refuses is skipped, one awaiting
    /// nobody claims nothing, and a member no line can carry is never
    /// named.
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
                other @ (TickLine::Discard { .. } | TickLine::Fate { .. }) => panic!("{other:?}"),
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

        let wide = leg(vec![(shared, RESERVE); MAX_HOLDS_PER_MEMBER + 1], &[]);
        assert!(
            select_members(
                ms(0),
                [pending(tx(3), &wide, far())],
                &held,
                &mut ProvisionalCells::default(),
                &mut ManifestBudget::default(),
            )
            .is_empty(),
            "a declaration no line can carry is never named",
        );
    }

    /// The walk stops at the first line the budget refuses.
    #[test]
    fn the_walk_stops_at_the_budget() {
        let declared: Vec<(DeclaredKey, Mode)> = (0..MAX_HOLDS_PER_MEMBER)
            .map(|at| (interval(9, at as u128, at as u128), RESERVE))
            .collect();
        let wide = leg(declared, &[]);
        let facts: Vec<Nameable<'_>> = (0..8u8)
            .map(|seed| pending(tx(seed), &wide, far()))
            .collect();
        let lines = select_members(
            ms(0),
            facts,
            &Held::default(),
            &mut ProvisionalCells::default(),
            &mut ManifestBudget::default(),
        );
        let fits = MAX_TICK_MANIFEST_BYTES / lines[0].wire_weight();
        assert_eq!(lines.len(), fits.min(8));
        assert!(lines.len() < 8, "the fixture must reach the budget");
    }

    /// Past its deadline a candidate is named `Aborted`, whether or not
    /// it is ready and whatever holds stand, and a leg is not named at
    /// all: its reclaim resolves it.
    #[test]
    fn a_candidate_past_its_deadline_is_named_aborted() {
        let shared = cell(1, 1);
        let passed = Deadline::of(ms(0));
        let waiting = leg(vec![(shared, WRITE)], &[Requirement::CommittedState(PEER)]);
        let a_leg = MemberFacts {
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
                charge: CHARGE,
            }],
        );
    }

    /// A core member waits on every sibling's committed bundle, so one
    /// whose sibling never engages is never named to run, and its row,
    /// still `Pending`, is named `Aborted` at the deadline.
    #[test]
    fn a_core_member_whose_sibling_never_engages_is_aborted_at_its_deadline() {
        let core = leg(vec![], &[Requirement::CommittedState(PEER)]);
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
                charge: CHARGE,
            }],
        );
    }

    /// A held row is a candidate only past its deadline, covered by a
    /// departure, held by a tick that is not its abandonment, and one a
    /// counterpart's verdict can discard, and it is judged on its row
    /// alone: no facts are asked for it.
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
            covered,
            charge: Some(CHARGE),
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
            member_lines(
                &rows,
                at,
                &|_| None,
                &Held::default(),
                &live,
                None,
                &BTreeSet::new(),
            )
        };
        let (before, missing) = lines(deadline.at().minus(Duration::from_millis(1)));
        assert!(before.is_empty() && missing.is_empty());
        let (after, missing) = lines(deadline.at());
        assert!(missing.is_empty(), "a held row asks for no facts");
        assert_eq!(
            after,
            vec![
                TickLine::Member {
                    tx: tx(1),
                    joins: Joins::Aborted,
                    settlement: Settlement::Awaited,
                    holds: Capped::empty(),
                    reach: Capped::from_array([PEER]),
                    charge: CHARGE,
                },
                TickLine::Discard {
                    tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                    cause: DiscardCause::Abandoned(tx(1)),
                },
            ],
        );
    }

    /// A held member a counterpart's verdict can discard is dropped by an
    /// `Unanswerable` discard once every shard it reaches has departed
    /// with its settled set unreadable, ahead of any abort, at any age;
    /// one whose evidence is not yet readable at the anchor holds the
    /// voter back, and one a shard can still answer for stays.
    #[test]
    fn a_held_member_nobody_can_answer_for_is_dropped() {
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
                covered: true,
                charge: Some(CHARGE),
            },
        );
        let lines = |evidence: Evidence| {
            member_lines(
                &rows,
                deadline.at(),
                &|_| None,
                &Held::default(),
                &|_| evidence,
                None,
                &BTreeSet::new(),
            )
        };
        assert_eq!(
            lines(Evidence::Unreadable),
            (
                vec![TickLine::Discard {
                    tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                    cause: DiscardCause::Unanswerable(tx(1)),
                }],
                vec![],
            ),
        );
        assert_eq!(lines(Evidence::Unknown), (vec![], vec![tx(1)]));
        let (answered, missing) = lines(Evidence::Readable);
        assert!(missing.is_empty());
        assert!(
            matches!(
                answered[..],
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
            "a covered member a shard can still answer for is aborted at its deadline: \
             {answered:?}",
        );
    }

    /// A tick still owing its determined half is let go of by nothing
    /// but a recovery: a covered held row past its deadline, and one no
    /// counterpart can answer for, both wait for that half to settle.
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
                covered: true,
                charge: Some(CHARGE),
            },
        );
        rows.ticks.insert(
            BlockHeight::new(2),
            TickRow {
                members: Capped::from_array([tx(1)]),
                determined_unsettled: true,
                legs_unsettled: true,
            },
        );
        for evidence in [Evidence::Readable, Evidence::Unreadable] {
            assert_eq!(
                member_lines(
                    &rows,
                    deadline.at(),
                    &|_| None,
                    &Held::default(),
                    &|_| evidence,
                    None,
                    &BTreeSet::new(),
                ),
                (vec![], vec![]),
                "{evidence:?}",
            );
        }
        // A halt recovery discards it whole, owed half and all, once its
        // frontier reaches the tick, and names nothing else of its rows.
        let recovered = |frontier: u64| {
            member_lines(
                &rows,
                deadline.at(),
                &|_| None,
                &Held::default(),
                &|_| Evidence::Unreadable,
                Some(BlockHeight::new(frontier)),
                &BTreeSet::new(),
            )
            .0
        };
        assert_eq!(
            recovered(2),
            vec![TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                cause: DiscardCause::Recovery,
            }],
        );
        assert!(recovered(1).is_empty(), "a tick above the frontier stands");
    }

    /// A ready core member left out pairs with every core holder that
    /// refuses it and reaches a shard it reaches, in flight or named
    /// beside it; one that is not ready, that reaches no shard in common,
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
            covered: false,
            charge: Some(CHARGE),
        };
        let in_flight = RowState::InFlight {
            tick: BlockHeight::new(2),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
        };
        for member in [
            row(1, in_flight, vec![(shared, WRITE)]),
            row(2, RowState::Pending, vec![]),
            row(3, RowState::Pending, vec![]),
            row(4, RowState::Pending, vec![]),
            row(5, RowState::Pending, vec![]),
        ] {
            rows.members.insert(member.tx, member);
        }
        let ready = leg(vec![(shared, WRITE)], &[Requirement::CommittedState(PEER)]);
        let elsewhere = MemberFacts {
            reach: Capped::from_array([OTHER]),
            ..ready.clone()
        };
        let mut held = Held::default();
        for seed in [2, 4, 5] {
            held.engaged.insert((PEER, tx(seed)));
        }
        let facts = |tx_hash: TxHash| match tx_hash {
            hash if hash == tx(4) => Some(&elsewhere),
            _ => Some(&ready),
        };
        let named = TickLine::Member {
            tx: tx(5),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
            holds: Capped::from_array([(shared, WRITE)]),
            reach: Capped::from_array([PEER]),
            charge: CHARGE,
        };
        assert_eq!(
            contentions(&rows, &[named], ms(0), &facts, &held),
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
            "tx 3 is not ready, tx 4 reaches no shard in common, tx 5 is named",
        );
    }

    /// A family of one core member in flight holding `declared`, and one
    /// pending beside it.
    fn held_beside_pending(held: u8, waiting: u8, declared: &[(DeclaredKey, Mode)]) -> MemberIndex {
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        let row = |seed: u8, state, holds: &[(DeclaredKey, Mode)], reach: Reach| MemberRow {
            tx: tx(seed),
            deadline: far(),
            committed: ms(0),
            height: BlockHeight::new(1),
            state,
            holds: Capped::new(holds.to_vec()).expect("within the cap"),
            reach,
            covered: false,
            charge: Some(CHARGE),
        };
        let in_flight = RowState::InFlight {
            tick: BlockHeight::new(2),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
        };
        for member in [
            row(held, in_flight, declared, Capped::from_array([PEER])),
            row(waiting, RowState::Pending, &[], Capped::empty()),
        ] {
            rows.members.insert(member.tx, member);
        }
        rows
    }

    /// A pending core member that a held one refuses, and that one claim
    /// reads seated on their shared counterpart with the holder unseated
    /// there, is aborted short of its deadline when it is the later of
    /// the two; the earlier one waits, and so does either one without
    /// the whole reading.
    #[test]
    fn the_later_member_of_a_proven_hold_cycle_is_aborted() {
        let declared = vec![(cell(1, 1), WRITE)];
        let facts = leg(declared.clone(), &[Requirement::CommittedState(PEER)]);
        let family = |held: u8, waiting: u8| held_beside_pending(held, waiting, &declared);
        let reading = |held: u8, waiting: u8, leaves: &[SubstateKey]| {
            proven_claim(
                PEER,
                5,
                leaves,
                &[
                    seat_leaf(PEER, tx(waiting)),
                    member_row_leaf(PEER, tx(held)),
                    seat_leaf(PEER, tx(held)),
                ],
            )
        };
        let crossed = |held: u8, waiting: u8| {
            reading(
                held,
                waiting,
                &[
                    seat_leaf(PEER, tx(waiting)),
                    member_row_leaf(PEER, tx(held)),
                ],
            )
        };
        let live = |_| Evidence::Live { terminating: false };
        let lines = |rows: &MemberIndex, claims: &[StateClaim]| {
            let facts = |_| Some(&facts);
            let victims = wounded(rows, ms(0), &facts, claims);
            member_lines(rows, ms(0), &facts, &Held::default(), &live, None, &victims).0
        };

        assert_eq!(
            lines(&family(1, 2), &[crossed(1, 2)]),
            vec![TickLine::Member {
                tx: tx(2),
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::from_array([PEER]),
                charge: CHARGE,
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

    /// Past its deadline, a held member is aborted beside its tick's
    /// discard, and a member let go of is aborted on its row once it
    /// reaches no other shard, or once a departure covers it and it is
    /// not `Alone`: an `Alone` member with a reach is a leg.
    #[test]
    fn a_held_or_released_member_is_aborted_by_its_standing() {
        let peer: Reach = Capped::from_array([PEER]);
        let none: Reach = Capped::empty();
        let held = TickId::new(ShardId::ROOT, BlockHeight::new(5));
        let passed = Deadline::of(ms(0));
        let candidate = |seed, deadline, standing| Nameable {
            tx: tx(seed),
            deadline,
            standing,
            charge: CHARGE,
        };
        let released = |covered, settlement, reach| Standing::Released {
            covered,
            settlement,
            reach,
        };
        let lines = select_members(
            ms(60_000),
            [
                candidate(
                    1,
                    passed,
                    Standing::Held {
                        tick: held,
                        reach: &peer,
                    },
                ),
                candidate(5, passed, released(false, Settlement::Awaited, &peer)),
                candidate(6, passed, released(false, Settlement::Alone, &none)),
                candidate(7, passed, released(true, Settlement::Awaited, &peer)),
                candidate(8, far(), released(true, Settlement::Awaited, &peer)),
                candidate(9, passed, released(true, Settlement::Alone, &peer)),
            ],
            &Held::default(),
            &mut ProvisionalCells::default(),
            &mut ManifestBudget::default(),
        );
        let aborted = |seed, settlement, reach: &Reach| TickLine::Member {
            tx: tx(seed),
            joins: Joins::Aborted,
            settlement,
            holds: Capped::empty(),
            reach: reach.clone(),
            charge: CHARGE,
        };
        assert_eq!(
            lines,
            vec![
                aborted(1, Settlement::Awaited, &peer),
                aborted(7, Settlement::Awaited, &peer),
                aborted(6, Settlement::Alone, &none),
                TickLine::Discard {
                    tick: held,
                    cause: DiscardCause::Abandoned(tx(1)),
                },
            ],
        );
    }
}
