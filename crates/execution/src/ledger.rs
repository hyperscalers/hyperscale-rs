//! What this shard has committed and not yet resolved.
//!
//! A committed transaction is owed exactly one outcome, and until a
//! certificate carries that outcome the transaction is in flight: its fee
//! reservation is engaged, its work counts against the drain, and the
//! shards party to it are still expected to certify it. This is the list
//! of those, and it is a fold over committed blocks rather than a
//! projection of live execution state — entries insert when a block
//! commits a transaction and release when a committed block carries the
//! outcome resolving it, so every replica's ledger is identical at equal
//! committed frontiers.
//!
//! That is the whole reason it exists apart from [`TickRegistry`]. Tick
//! state is what a node is *working on*, and it does not survive a
//! restart: a shard whose replicas all came back cannot name what it
//! committed and never finished, so it can neither finish it nor abort
//! it. A ledger folded from the chain can be rebuilt from the chain.
//!
//! [`TickRegistry`]: crate::ticks::TickRegistry

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use hyperscale_engine::legs::Classified;
use hyperscale_storage::committed_tx_cell_key;
use hyperscale_types::{
    AbandonmentRecord, CommittedAt, Deadline, Finalization, Inclusion, MAX_VALIDITY_RANGE,
    PriceTable, Probed, RoutePrefix, ShardId, ShardTrie, SubstateKey, Transaction,
    TransactionDecision, TxHash, TxResolution, UnsettledTx, Verifiable, Verified,
    WeightedTimestamp, Window,
};
use hyperscale_vm_effects::{Answered, Kind};
use hyperscale_vm_types::ProtocolHasher;

/// What the chain read of one cell a counterpart was asked about:
/// which question the cell answers, and what it said.
///
/// A reading is the chain's, folded off the block that carries the
/// claim by every replica alike, and it is never asked again: it is
/// what licenses the settlement of the crossing the cell was asked
/// about. What this validator has fetched and holds to offer is not
/// here — it is the validator's own, and lives beside the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reading {
    probed: Probed,
    inclusion: Inclusion,
}

/// How far a tick of this shard's has spoken for a transaction, in the
/// order the ranks outrank each other: a tick discarded, wedged or
/// refused never lowers it, and a second abandonment composes the same
/// answer a first did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Certified {
    /// No tick of this shard's has taken the transaction.
    No,
    /// A tick took it as an abandonment: no execution of ours ran, so
    /// no counterpart holds a certificate of ours to combine an accept
    /// with, and the abandonment's own answer is the only one this
    /// shard gives.
    ByAbandonment,
    /// A tick took it as an executing member. Its certificate may be
    /// out and a sibling may have combined an accept with it, so no
    /// later exit of this shard's may answer for it.
    ByExecution,
}

/// One committed transaction's outstanding account.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Owed {
    /// What abandoning the transaction states: its deadline, which every
    /// window the entry is held to is read off; the reservation its
    /// committing block took against the drain; and the charge an abort
    /// burns. Held here because an abandonment has no execution to read
    /// them from and must release exactly what was taken, and because a
    /// record naming the transaction restates exactly these.
    figures: UnsettledTx,
    /// How far a tick of this shard's has spoken for the transaction.
    ///
    /// What it answers is whether a certificate of ours is out where a
    /// counterpart could settle against it, which is what decides whether
    /// this shard may speak for the transaction alone, and whether that
    /// certificate came from an execution, which is what decides whether
    /// an abandonment may still answer for it. The account is where it
    /// belongs rather than the tick that produced it: the certificate
    /// outlives the tick, and a shard that could not say whether it had
    /// issued one would have to assume it had.
    certified: Certified,
    /// What this shard's part in the transaction is, which decides what
    /// the entry waits on and what ends it, with whatever it keeps for
    /// the settlement of what it issued.
    part: Part,
    /// The departed counterpart a committed record says left this
    /// transaction unsettled.
    ///
    /// The evidence that nothing can settle it, in the one form that
    /// outlives the settled set it was read from. Where the deadline
    /// window says how long this shard may speak for a transaction on its
    /// own clock, this says it may speak whatever the clock reads: no
    /// counterpart is left to contradict it, and the chain says so.
    ///
    /// It also decides how long the entry lives. A covered entry is
    /// abandonable from the moment the record commits, so what it waits on
    /// is a block carrying the abort — and the departure that covered it
    /// is the one clock both the entry and the record are stated in.
    departed_by: Option<ShardId>,
    /// The core shards whose certificates accepted it. A core shard's
    /// tick closes on every other core shard's certificate, so one
    /// saying it succeeded is not the transaction accepted — that is
    /// every core shard saying so, and this is the count.
    accepted: BTreeSet<ShardId>,
    /// What the chain has read of the cells counterparts were asked
    /// about, by the shard each was read on and the cell.
    ///
    /// Held on the entry rather than beside the ledger because that is
    /// the lifetime: a reading speaks only for a transaction still owed
    /// an outcome here, and the entry going is what makes it moot. A
    /// second home would have to be reclaimed on its own rule, and two
    /// rules for one fact are two answers to when it stops being true.
    readings: BTreeMap<(ShardId, SubstateKey), Reading>,
}

impl Owed {
    /// The questions the chain read absent, each an answer that the
    /// counterpart asked can never settle the transaction.
    fn absences(&self) -> impl Iterator<Item = Probed> + '_ {
        self.readings.values().filter_map(|reading| {
            matches!(reading.inclusion, Inclusion::Absent).then_some(reading.probed)
        })
    }

    /// Whether the chain read a consumer's `Never` present: the
    /// consumer's own word that it will never take the crossing.
    fn declined(&self) -> bool {
        self.readings.values().any(|reading| {
            reading.probed == Probed::Decline && matches!(reading.inclusion, Inclusion::Present(_))
        })
    }

    /// Whether the chain has established that no counterpart can settle
    /// the transaction: a departed shard's record names it, a cell a
    /// counterpart would have written was read absent inside its
    /// window, or a consumer's `Never` was read present. Any of the
    /// three licenses the abandonment or the reclaim, and puts every
    /// question the entry asks to rest.
    fn covered(&self) -> bool {
        self.departed_by.is_some() || self.absences().next().is_some() || self.declined()
    }

    /// What the evidence covering the entry established of the
    /// transaction, where it established a verdict at all: a departure
    /// or a core's committed cell absent says the core never took it,
    /// and a consumer's `Never` says it refused it, which aborts the
    /// transaction either way.
    ///
    /// Every way of being covered is one of those three, so this is
    /// [`Self::covered`] with the verdict said out loud rather than a
    /// second reading of the same rows: a reading that answers nothing
    /// never reaches `readings` at all.
    fn abandoned_verdict(&self) -> Option<TransactionDecision> {
        self.covered().then_some(TransactionDecision::Aborted)
    }

    /// The moment the entry stops being settleable and becomes the
    /// shard's to abandon: the transaction's deadline. A delivery never
    /// reaches this — the crossing it claims is owed to this shard and
    /// nothing takes it back, so there is no instant at which giving up
    /// on it would be right.
    const fn opens(&self) -> WeightedTimestamp {
        self.figures.deadline.at()
    }

    /// Where a tick may abandon the entry: from its opening, for the one
    /// validity range every abandonment gets to commit.
    fn abandon_window(&self) -> Range<WeightedTimestamp> {
        let opens = self.opens();
        opens..opens.plus(MAX_VALIDITY_RANGE)
    }

    /// Whether an executing tick of this shard's took the transaction.
    const fn executed(&self) -> bool {
        matches!(self.certified, Certified::ByExecution)
    }
}

/// Where a departed participant's chain ended, and how long what it left
/// behind can still be read.
#[derive(Debug, Clone, Copy)]
struct Departure {
    /// The terminal cut — what dates the departure against a
    /// transaction's own commit frontier.
    cut: WeightedTimestamp,
    /// The handoff-anchored terminal-evidence expiry, `None` while the
    /// beacon has not stamped the handoff complete. The entries this
    /// shard holds against the departed shard live to exactly here,
    /// because this is when its settled set stops answering: a shorter
    /// life would strand them before the evidence that decides them is
    /// even attested, and a longer one would hold them past any answer.
    /// An open window holds them — the coordinator re-stamps on every
    /// commit, so the expiry lands within a commit of the beacon's stamp.
    readable_until: Option<WeightedTimestamp>,
}

/// A transaction the ledger let go of without an outcome, because no
/// counterpart is left to reach one with.
///
/// The reservation it took against the drain is not returned — only a
/// committed certificate does that, and none is coming — so this is the
/// leak, and `covered_by_record` is what says which kind. Covered means a
/// record had established the abort was safe and the chain did not get one
/// committed before the entry ran out of counterparts. Uncovered means no
/// record ever named it: either the departed counterpart settled it before
/// it left, in which case its certificate was the only resolution there
/// was, or the evidence never arrived to write a record from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unanswerable {
    /// The transaction dropped.
    pub(crate) tx_hash: TxHash,
    /// Whether a committed record had named it unsettled by a departed
    /// counterpart.
    pub(crate) covered_by_record: bool,
}

/// What this shard's part in a transaction is, which decides what the
/// entry waits on and what ends it.
///
/// A whole shape holds nothing beyond its account: it is decided by its
/// own finalization or abandoned at its deadline. The rest keep the
/// body and the classification the work they run is composed from, and
/// a leg entry — a leg's, or a resolved issuer's — keeps beside them
/// where its settlement stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// This shard's verdict is the transaction's, or a share of it: the
    /// entry is abandonable at its deadline and released by that
    /// verdict.
    Whole,
    /// A leg outside the core, held for the settlement of what it
    /// issued: never abandoned, probed past the deadline, released by
    /// the reclaim or the retirement.
    Leg(LegEntry),
    /// A member of the core, whose verdict is its own and which issues
    /// crossings deliveries elsewhere consume.
    Core(Kept),
    /// A core issuer whose own verdict resolved the transaction with
    /// crossings still owed a claim, kept on as a leg entry for the
    /// reclaim of what its deliveries never claimed — and named by no
    /// abandonment record: a departed deliverer's successor still
    /// delivers, and only the lapse says a delivery never will.
    Remainder(LegEntry),
}

/// What a leg entry holds for the settlement of what it issued: what
/// the settlement is composed from, and where it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegEntry {
    /// The body and the classification the settlement derives from.
    kept: Kept,
    /// Whether a tick of this shard's has taken the entry's records for
    /// the reclaim, so the finalization naming the hash next is that
    /// member's.
    reclaiming: bool,
    /// The records this entry issued here that the commit fold has
    /// removed on their consumers' `Taken`: what the entry closes on,
    /// once every one of them is here.
    gone: BTreeSet<SubstateKey>,
    /// Whether a committed finalization of this shard's settled the
    /// transaction's price: a leg's own, which burned it inside its
    /// writes, or the verdict that made an issuer a remainder.
    ///
    /// A committed fact rather than the tick's admission, which is what
    /// [`Owed::certified`] records: a tick discarded before its
    /// finalization commits burned nothing, and a reclaim reading the
    /// admission would charge nothing either.
    charged: bool,
}

impl LegEntry {
    const fn unsettled(kept: Kept, charged: bool) -> Self {
        Self {
            kept,
            reclaiming: false,
            gone: BTreeSet::new(),
            charged,
        }
    }

    /// Whether the commit fold has closed what this entry waited on:
    /// every record it issued here removed on its consumer's `Taken`,
    /// nothing covering it and no reclaim taking its records. Every
    /// input is committed content. A shard's owed crossings arrive by
    /// its commit fold and owe it nothing, so a shard with legs on both
    /// sides of the core closes on its records alone.
    fn settled(&self, local: ShardId) -> bool {
        let issued = self.kept.issued(local);
        !issued.is_empty()
            && issued.iter().all(|record| self.gone.contains(record))
            && !self.reclaiming
    }
}

impl Part {
    /// A whole entry.
    pub(crate) const fn whole() -> Self {
        Self::Whole
    }

    /// A leg outside the core, with the body and classification its
    /// settlement is composed from and its price still owed.
    pub(crate) const fn leg(kept: Kept) -> Self {
        Self::Leg(LegEntry::unsettled(kept, false))
    }

    /// A member of the core, with the body and classification the
    /// reclaim of what it issued is composed from.
    pub(crate) const fn core(kept: Kept) -> Self {
        Self::Core(kept)
    }

    /// Whether the entry bears no verdict of its own and is held for a
    /// settlement: a leg's, or a resolved issuer's.
    const fn is_leg(&self) -> bool {
        self.held().is_some()
    }

    /// Whether this shard's own verdict already resolved the transaction
    /// and the entry stays for the reclaim alone.
    const fn is_remainder(&self) -> bool {
        matches!(self, Self::Remainder(_))
    }

    /// Whether a core issuer still holds crossings its deliveries owe a
    /// claim for, so its verdict resolves the transaction and leaves the
    /// entry standing for the reclaim.
    fn issued(&self, local: ShardId) -> bool {
        match self {
            Self::Core(kept) => !kept.deliveries(local).is_empty(),
            Self::Whole | Self::Leg(_) | Self::Remainder(_) => false,
        }
    }

    /// Keep a core issuer on for the reclaim of what its deliveries
    /// never claimed, its own verdict having resolved the transaction
    /// and settled the price.
    fn resolve(&mut self) {
        *self = match std::mem::replace(self, Self::Whole) {
            Self::Core(kept) => Self::Remainder(LegEntry::unsettled(kept, true)),
            part => part,
        };
    }

    /// Record that a committed finalization of this shard's settled the
    /// price of a leg entry.
    const fn charge(&mut self) {
        if let Some(held) = self.held_mut() {
            held.charged = true;
        }
    }

    /// Record that a tick of this shard's has taken a leg entry's
    /// records for the reclaim.
    const fn take_reclaim(&mut self) {
        if let Some(held) = self.held_mut() {
            held.reclaiming = true;
        }
    }

    /// Record that the commit fold removed `record`, one this entry
    /// issued, on its consumer's `Taken`.
    fn mark_gone(&mut self, record: SubstateKey) {
        if let Some(held) = self.held_mut() {
            held.gone.insert(record);
        }
    }

    /// What a leg entry holds, where the entry is one.
    const fn held(&self) -> Option<&LegEntry> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(held),
            Self::Whole | Self::Core(_) => None,
        }
    }

    const fn held_mut(&mut self) -> Option<&mut LegEntry> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(held),
            Self::Whole | Self::Core(_) => None,
        }
    }

    /// What the entry keeps beside its account, where it keeps
    /// anything: every part but a whole shape, which is decided by its
    /// own finalization and composes nothing.
    const fn kept(&self) -> Option<&Kept> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(&held.kept),
            Self::Core(kept) => Some(kept),
            Self::Whole => None,
        }
    }

    /// What an entry that issues crossings of its own composes their
    /// settlement from, and whose core a mirrored verdict and a probe
    /// are read off.
    const fn settling(&self) -> Option<&Kept> {
        self.kept()
    }

    /// The part `local` plays in a transaction frozen as `classified`,
    /// with the body it keeps where it keeps one.
    ///
    /// Read off the classification the committing block froze, at the
    /// same commit, so a rebuilt ledger marks the same entries: the
    /// freeze is a function of the block and the placement it committed
    /// under, and the replay re-freezes both. A shard only ever holds an
    /// entry for a transaction it commits, so a divided one here is a
    /// core member or a leg.
    fn of(local: ShardId, tx: &Arc<Verifiable<Transaction>>, classified: &Classified) -> Self {
        if !classified.decomposed() {
            return Self::whole();
        }
        let kept = Kept::of(tx, classified);
        if classified.core().contains(&local) {
            Self::core(kept)
        } else {
            Self::leg(kept)
        }
    }
}

/// What an entry that may be reclaimed keeps beside its account: a leg
/// entry's, for the reclaim and the refusal mirror, or an issuer's, for
/// the reclaim of what its deliveries never claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub(crate) body: Arc<Verified<Transaction>>,
    /// The classification the committing block froze, which every cell
    /// the entry asks about and every scope a settlement runs under is
    /// read off.
    pub(crate) classified: Classified,
}

impl Kept {
    /// The body and the classification an entry keeps, read off the
    /// classification the committing block froze.
    ///
    /// Block-container entries decoded from the wire land as
    /// `Unverified`; lift via `from_persisted` under the same
    /// BFT-transitive trust that gates the containing block. Honest
    /// live-consensus blocks already carry `Verified` entries.
    pub(crate) fn of(tx: &Verifiable<Transaction>, classified: &Classified) -> Self {
        let body: Arc<Verified<Transaction>> = match tx.clone().into_verified() {
            Ok(verified) => Arc::new(verified),
            Err(raw) => Arc::new(Verified::<Transaction>::from_persisted(raw)),
        };
        Self {
            body,
            classified: classified.clone(),
        }
    }

    /// Whose refusal is the transaction's, and whose committed cells a
    /// probe asks about. An issuer in the core holds the core it is
    /// part of, itself included; the prober skips this shard, since
    /// what it has committed is not something it fetches a proof of.
    /// Empty for a shape with no core.
    const fn core(&self) -> &BTreeSet<ShardId> {
        self.classified.core()
    }

    /// The record cells `local` writes for the crossings it issued, of
    /// either kind: what the commit fold removes one by one as their
    /// consumers' `Taken` is read, and what the entry closes on.
    fn issued(&self, local: ShardId) -> Vec<SubstateKey> {
        self.classified
            .crossings()
            .filter(|(edge, _)| edge.from == local)
            .map(|(edge, _)| edge.crossing.id.record_key(&ProtocolHasher))
            .collect()
    }

    /// The claim cells the consumers' folds write for the owed crossings
    /// `local` issued, each under the shard that held the consumer when
    /// the transaction committed. The cell follows its prefix to a
    /// departed consumer's successor, which [`Ledger::questions`]
    /// resolves off the trie it is given.
    fn deliveries(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.answers(local, Kind::Owed, Answered::Taken)
    }

    /// The answer cells in `answered`'s role that consumers of the
    /// `kind` crossings `local` issued write, each under the consumer's
    /// frozen home.
    fn answers(
        &self,
        local: ShardId,
        kind: Kind,
        answered: Answered,
    ) -> Vec<(ShardId, SubstateKey)> {
        self.classified
            .crossings()
            .filter(|(edge, _)| edge.from == local && edge.crossing.kind == kind)
            .map(|(edge, home)| (home, edge.crossing.id.answer_key(&ProtocolHasher, answered)))
            .collect()
    }

    /// The claim cells core consumers write for the crossings a leg on
    /// `local` issued, each under the shard holding the consumer's
    /// target — what a probe asks the core about, and whose presence
    /// licenses the retirement. Empty for a core shard: a leg beside the
    /// core is the core's, so nothing a core shard produces is claimed
    /// by a core it is not in.
    fn claims(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.answers(local, Kind::Escrowed, Answered::Taken)
    }

    /// The decline cells core consumers write for the escrowed crossings
    /// `local` issued: the `Never` beside each of [`Self::claims`].
    fn declines(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.answers(local, Kind::Escrowed, Answered::Never)
    }
}

/// A leg entry a committed record has licensed a settlement of, with
/// what the settlement is composed from.
///
/// Which records, off which body, under which classification, and
/// whether the price is still owed: what [`Ledger::reclaimable`] hands
/// the composer.
#[derive(Debug, Clone)]
pub struct Settleable {
    /// The transaction.
    pub(crate) tx_hash: TxHash,
    /// Its body, which the settlement's edges derive from.
    pub(crate) body: Arc<Verified<Transaction>>,
    /// The classification its committing block froze.
    pub(crate) classified: Classified,
    /// Whether a committed finalization of this shard's settled the
    /// price, so the reclaim charges nothing: a resolved issuer is
    /// charged where it resolves, and a leg when its own finalization
    /// commits. A leg that never ran, or whose tick was discarded before
    /// its finalization committed, owes it on the reclaim's.
    pub(crate) charged: bool,
}

/// One cell a counterpart is asked about for one transaction: which
/// question it answers, and the terms the answer is read against.
///
/// The one enumeration the prober and the commit-time fold both read,
/// so what is asked and what is answered are the same cells. Carried
/// whole rather than looked up again, because the terms a reading needs
/// — the entry's deadline, and the cue that opened the question ahead
/// of it — are the entry's own and the caller holds no entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question {
    /// The transaction the question is asked for.
    pub(crate) tx_hash: TxHash,
    /// The counterpart the question is put to.
    pub shard: ShardId,
    /// The cell it asks about.
    pub(crate) key: SubstateKey,
    /// Which question it is.
    pub(crate) probed: Probed,
    /// The entry's deadline, which every window an answer is held to
    /// is read off.
    pub(crate) deadline: Deadline,
}

impl Question {
    /// Whether the question is worth putting at `now`, the chain's
    /// committed clock: past the deadline. Before it the core may still
    /// legitimately commit, so an absence says nothing, and a presence
    /// arrives by push.
    #[must_use]
    pub(crate) fn open_at(self, now: WeightedTimestamp) -> bool {
        self.deadline.passed(now)
    }
}

/// What one name on a committed finalization means for the entry it
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meaning {
    /// A leg finalizing here without deciding: it ran, and the core
    /// decides the transaction.
    LegRan,
    /// The reclaim of what a leg issued, reporting what the evidence
    /// covering it established of the transaction — a departure, or a
    /// core that never took it, aborts it; a delivery that lapsed says
    /// nothing of the transaction, which the core decided.
    Reclaimed(Option<TransactionDecision>),
    /// This shard's verdict, or a share of it.
    Verdict(TransactionDecision),
}

/// What `decision` on a name means for `owed`, where the finalization
/// carrying it is `deciding` the name or not.
fn meaning(owed: Option<&Owed>, deciding: bool, decision: TransactionDecision) -> Meaning {
    let accepted = decision == TransactionDecision::Accept;
    match owed {
        _ if !deciding => Meaning::LegRan,
        Some(owed) if accepted && owed.part.is_leg() => {
            Meaning::Reclaimed(owed.abandoned_verdict())
        }
        _ => Meaning::Verdict(decision),
    }
}

/// Committed-but-unresolved transactions, each against its deadline and
/// the reservation it holds.
#[derive(Debug)]
pub struct Ledger {
    /// The shard whose account this is, which every reading of a
    /// transaction's reach divides into this shard's share and the
    /// rest.
    local: ShardId,
    owed: BTreeMap<TxHash, Owed>,
    /// Where each departed participant's chain ended, for the entries
    /// whose fate only that shard's settled set can decide. Held against
    /// the schedule window that proves the terminal, which is retained on
    /// a frontier of its own.
    departed: BTreeMap<ShardId, Departure>,
}

impl Ledger {
    /// An empty account for `local`.
    #[must_use]
    pub(crate) const fn new(local: ShardId) -> Self {
        Self {
            local,
            owed: BTreeMap::new(),
            departed: BTreeMap::new(),
        }
    }

    /// The shard whose account this is.
    #[must_use]
    pub(crate) const fn local(&self) -> ShardId {
        self.local
    }

    /// The share of `owed`'s reach that is somebody else's — the routes
    /// this shard does not own.
    ///
    /// Who was party to the transaction is a question about these and
    /// the trie at the commit, and that trie is not something a rebuild
    /// can recover — windows evict, and a shard that has since split
    /// answers for a keyspace it no longer owns. The routes are the
    /// transaction's own and the commit is the block's, and
    /// [`UnsettledTx`] states both, so this reaches the same set from
    /// the committing block and from a record naming the transaction
    /// alike — which is what a replica rotated in after that block has.
    fn remote_routes<'a>(&self, owed: &'a Owed) -> impl Iterator<Item = RoutePrefix> + 'a {
        let local = self.local;
        owed.figures
            .reach
            .iter()
            .copied()
            .filter(move |route| !ShardTrie::shard_owns_route(local, *route))
    }

    /// Record what a committed block puts in flight: each transaction it
    /// carries, with the classification its block froze it under, from
    /// which this shard's part is read.
    ///
    /// One entry point for a live commit and for a replay of the chain
    /// alike, so every term is written once and a rebuilt ledger cannot
    /// disagree with the one it rebuilds. Each is a function of the
    /// transaction body and this shard's own identity, both of which
    /// outlive any window, so the two agree at any distance.
    ///
    /// `committed` is the block itself: what dates every departure
    /// against the entries it registers; `trie` is the placement it
    /// froze the classification under, which prices this shard's share.
    ///
    /// Idempotent per transaction: a hash cannot commit twice within its
    /// own validity window, and re-registering one must not move the
    /// deadline it was admitted under.
    ///
    /// `prices` is the table the committing block's committee anchor
    /// names — the one admission judged its ceiling at — so what a
    /// record restates is what the block that committed the transaction
    /// charged, and a later fold moving the table never moves a figure
    /// already owed. `committed.committee_anchor` states which that was,
    /// so a verifier holding no entry resolves the same window.
    pub(crate) fn register_committed<'a>(
        &mut self,
        committed: CommittedAt,
        prices: &PriceTable,
        members: impl IntoIterator<Item = (&'a Arc<Verifiable<Transaction>>, &'a Classified)>,
    ) {
        for (tx, classified) in members {
            let owed = Owed {
                figures: UnsettledTx::for_transaction(
                    tx,
                    committed,
                    classified.local_price(tx, self.local, prices),
                    classified.escrowed_records(self.local),
                    prices,
                ),
                certified: Certified::No,
                part: Part::of(self.local, tx, classified),
                departed_by: None,
                accepted: BTreeSet::new(),
                readings: BTreeMap::new(),
            };
            self.owed.entry(tx.hash()).or_insert(owed);
        }
    }

    /// What the chain read of `key` on `shard` for `tx_hash`, once it
    /// has read it.
    #[cfg(test)]
    pub(crate) fn reading(
        &self,
        tx_hash: TxHash,
        shard: ShardId,
        key: SubstateKey,
    ) -> Option<Inclusion> {
        let reading = self.owed.get(&tx_hash)?.readings.get(&(shard, key))?;
        Some(reading.inclusion)
    }

    /// Give a registered entry the part a fixture wants it to play,
    /// where the block that committed it froze another.
    #[cfg(test)]
    pub(crate) fn seed(&mut self, tx_hash: TxHash, part: Part) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.part = part;
        }
    }

    /// The core set of a leg entry — whose refusal is the transaction's.
    /// `None` for anything but a leg entry this ledger holds.
    #[must_use]
    pub(crate) fn leg_core(&self, tx_hash: TxHash) -> Option<&BTreeSet<ShardId>> {
        self.owed
            .get(&tx_hash)
            .and_then(|owed| owed.part.settling())
            .map(Kept::core)
    }

    /// Whether `shard` is one of the transaction's core — whose refusal
    /// is the transaction's, and whose word is worth mirroring at all.
    #[must_use]
    pub(crate) fn core_holds(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.leg_core(tx_hash)
            .is_some_and(|core| core.contains(&shard))
    }

    /// Mirror a core shard's acceptance, and say whether it was the last
    /// the transaction was waiting on.
    ///
    /// A core shard's tick closes on every other core shard's
    /// certificate, so one saying it succeeded is not the transaction
    /// accepted: that is every core shard saying so.
    pub(crate) fn record_acceptance(&mut self, tx_hash: TxHash, shard: ShardId) -> bool {
        let Some(core_len) = self
            .leg_core(tx_hash)
            .filter(|core| core.contains(&shard))
            .map(BTreeSet::len)
        else {
            return false;
        };
        self.owed
            .get_mut(&tx_hash)
            .is_some_and(|owed| owed.accepted.insert(shard) && owed.accepted.len() == core_len)
    }

    /// Record what the chain read of `key` on `shard` for `tx_hash`,
    /// the question `probed` asks. First reading wins: `false` says the
    /// cell was already read, the transaction is not held here, or the
    /// reading answers nothing — and a later claim adds nothing.
    ///
    /// A reading [`Probed::read`] does not admit is refused here rather
    /// than only at the fold that fetches one, because what it would
    /// leave behind is not a spare row: [`Self::covered`] counts any
    /// absence, so an absence that answers nothing would license a
    /// reclaim. Capped at the store, the set of absences an entry can
    /// hold is exactly the one `Probed::read` admits — the committed
    /// cell's — which is what lets
    /// [`Self::abandoned_verdict`] read it off `covered` rather than
    /// filtering for it a second time.
    pub(crate) fn record_reading(
        &mut self,
        tx_hash: TxHash,
        shard: ShardId,
        key: SubstateKey,
        probed: Probed,
        inclusion: Inclusion,
    ) -> bool {
        if probed.read(inclusion).is_none() {
            return false;
        }
        let Some(owed) = self.owed.get_mut(&tx_hash) else {
            return false;
        };
        match owed.readings.entry((shard, key)) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(vacant) => {
                vacant.insert(Reading { probed, inclusion });
                true
            }
        }
    }

    /// Every question this ledger has open, under `trie`, whatever the
    /// clock: for each entry nothing has answered for, each other core
    /// shard's committed cell, each core consumer's claim and decline on
    /// the shard holding the consumer's target and on whatever holds the
    /// prefix now, and each delivery's claim on the shard that was to
    /// deliver it and on whatever shard holds the cell's prefix now —
    /// each less the cells the chain has already read.
    ///
    /// Whatever the clock, because a claim the chain committed is read
    /// against these too, and the claim's own anchor says whether the
    /// window was open. `trie` is the block's committee's, which says
    /// who holds a cell's prefix now: a claim cell follows its prefix
    /// across a cut to a departed shard's successor, and both are asked
    /// because the vote fence checks a record against the voter's own
    /// proof of the shard it names, so two validators straddling the
    /// cut would otherwise prove different shards and never both vote
    /// one record. This shard is never asked about: a core member holds
    /// the core it is part of, itself included, but what it has
    /// committed is not something it fetches a proof of.
    #[must_use]
    pub(crate) fn questions(&self, trie: &ShardTrie) -> Vec<Question> {
        let local = self.local;
        let mut questions = Vec::new();
        for (&tx_hash, owed) in &self.owed {
            if owed.covered() {
                continue;
            }
            let Some(kept) = owed.part.settling() else {
                continue;
            };
            let deadline = owed.figures.deadline;
            let question = |shard, key, probed| {
                (!owed.readings.contains_key(&(shard, key))).then_some(Question {
                    tx_hash,
                    shard,
                    key,
                    probed,
                    deadline,
                })
            };
            // What an entry asks about is what it waits on. A leg waits
            // for the core's verdict and for the crossings it issued to
            // be claimed; a core member waits only for its siblings,
            // whose certificates its own settlement needs. Its
            // deliveries are what it waits on once it has a verdict, as
            // the remainder its acceptance leaves.
            //
            // A sibling that refused keeps its committed cell, so the
            // cell reads present and answers nothing here: what covers
            // the waiting core is the sibling's certificate, pushed by
            // its outbound tracker and servable by transaction inside
            // its retention. Losing that road costs liveness only — a
            // presence licenses no credit, so nothing is taken back on
            // it.
            questions.extend(
                kept.core()
                    .iter()
                    .filter(|&&shard| shard != local)
                    .filter_map(|&shard| {
                        let cell = committed_tx_cell_key(shard, tx_hash, deadline.validity_end());
                        question(shard, cell, Probed::Core)
                    }),
            );
            if !owed.part.is_leg() {
                continue;
            }
            // One question per answer cell, whichever kind of consumer
            // writes it: a claim or a decline answers by being present
            // and by nothing else, so the side it was issued to changes
            // nothing about what is asked. A core consumer is asked for
            // both of its answers — it took the crossing, or it never
            // will — and a delivery for its claim alone, since nothing
            // takes an owed crossing back. Asked of the shard the
            // classification homed the consumer on and of whoever holds
            // its prefix now, which are the same shard until a cut moves
            // it.
            let asked = |consumer: ShardId, key: SubstateKey, probed: Probed| {
                BTreeSet::from([consumer, trie.shard_for_prefix(key.owner)])
                    .into_iter()
                    .filter_map(move |shard| question(shard, key, probed))
            };
            for (consumer, claim) in kept.claims(local) {
                questions.extend(asked(consumer, claim, Probed::Claim));
            }
            for (consumer, decline) in kept.declines(local) {
                questions.extend(asked(consumer, decline, Probed::Decline));
            }
            for (consumer, claim) in kept.deliveries(local) {
                questions.extend(asked(consumer, claim, Probed::Claim));
            }
        }
        questions
    }

    /// Whether this ledger still holds `tx_hash`.
    #[must_use]
    pub(crate) fn contains(&self, tx_hash: TxHash) -> bool {
        self.owed.contains_key(&tx_hash)
    }

    /// Whether an entry here will compose the disposal of the record at
    /// `key`, so the leaf road leaves it to that entry.
    ///
    /// The entries that issue are exactly those: a leg and a remainder
    /// settle what they issued, and a core member becomes a remainder
    /// at its own verdict. A delivery and a whole entry issue none —
    /// the whole one including a record reconstructed it, which carries
    /// the figures an abandonment restates and nothing a settlement is
    /// composed from. Scans the entries, as [`Self::untaken_legs`] does.
    #[must_use]
    pub(crate) fn settles_record(&self, key: SubstateKey) -> bool {
        self.owed.values().any(|owed| {
            owed.part
                .settling()
                .is_some_and(|kept| kept.issued(self.local).contains(&key))
        })
    }

    /// Every leg entry no tick has taken the records of yet, with what
    /// it holds.
    ///
    /// The precondition the two settlements below share, so what each of
    /// them adds is its own licence and nothing else: a reclaim needs the
    /// entry covered, a retirement needs every claim read present and
    /// nothing covering it.
    fn untaken_legs(&self) -> impl Iterator<Item = (TxHash, &Owed, &LegEntry)> {
        self.owed.iter().filter_map(|(tx_hash, owed)| {
            let held = owed.part.held()?;
            (!held.reclaiming).then_some((*tx_hash, owed, held))
        })
    }

    /// The leg entries committed content has licensed a reclaim of and
    /// no tick has taken yet, each with the body the reclaim derives
    /// from: a departed counterpart's record names the transaction, or a
    /// claim read a cell a counterpart would have written absent inside
    /// its window.
    ///
    /// Read off committed content alone, like [`Self::past_deadline`],
    /// so every replica at the same frontier composes the same reclaims.
    /// Never a clock reading: a record or a claim is the only thing that
    /// puts an entry here, and both carry evidence.
    ///
    /// Each carries whether a committed finalization of this shard's
    /// settled the price — a leg that ran settled it inside its own
    /// certificate, and one that never ran, or whose tick was discarded
    /// before its finalization committed, owes it on the reclaim's.
    #[must_use]
    pub(crate) fn reclaimable(&self) -> Vec<Settleable> {
        self.untaken_legs()
            .filter(|(_, owed, _)| owed.covered())
            .map(|(tx_hash, _, held)| Settleable {
                tx_hash,
                body: Arc::clone(&held.kept.body),
                classified: held.kept.classified.clone(),
                charged: held.charged,
            })
            .collect()
    }

    /// Record that a tick of this shard's has admitted the reclaim of
    /// `tx_hash`, so the finalization naming the hash next is the
    /// reclaim's and releases the entry.
    pub(crate) fn admit_reclaim(&mut self, tx_hash: TxHash) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.part.take_reclaim();
        }
    }

    /// Record that the commit fold removed `record` on its consumer's
    /// `Taken`, on the entry `tx_hash` names.
    pub(crate) fn settled(&mut self, record: SubstateKey) {
        let local = self.local;
        for owed in self.owed.values_mut() {
            if owed
                .part
                .held()
                .is_some_and(|held| held.kept.issued(local).contains(&record))
            {
                owed.part.mark_gone(record);
            }
        }
    }

    /// Close every leg entry the commit fold has settled, and say what
    /// each closes as: the transaction was accepted, since every record
    /// it issued here was taken.
    ///
    /// No finalization drives this close, so `resolutions_of` never
    /// reports it: this is the one reading of it, taken once per commit
    /// after the fold's removals and the block's own finalizations have
    /// been applied. A remainder closes the same way, restating a verdict
    /// the mempool already holds.
    pub(crate) fn closes(&mut self) -> Vec<(TxHash, TxResolution)> {
        let local = self.local;
        let closed: Vec<TxHash> = self
            .owed
            .iter()
            .filter(|(_, owed)| {
                !owed.covered() && owed.part.held().is_some_and(|held| held.settled(local))
            })
            .map(|(tx_hash, _)| *tx_hash)
            .collect();
        for tx_hash in &closed {
            self.owed.remove(tx_hash);
        }
        closed
            .into_iter()
            .map(|tx_hash| (tx_hash, TxResolution::Decided(TransactionDecision::Accept)))
            .collect()
    }

    /// Record that a tick of this shard's has taken `tx_hash` as a member,
    /// and so will speak for it in a certificate a counterpart can settle
    /// against. The rank only ever rises: a tick lost after an execution
    /// took the transaction leaves its certificate out there, and an
    /// abandonment composed after one never lowers what it answers.
    pub(crate) fn certify(&mut self, tx_hash: TxHash, how: Certified) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.certified = owed.certified.max(how);
        }
    }

    /// Whether a certificate of this shard's covers `tx_hash` — the
    /// question that decides whether a verdict on it is this shard's alone
    /// to reach. False for a transaction this ledger does not hold, which
    /// is the same answer it gives for one no tick ever took.
    #[cfg(test)]
    fn is_certified(&self, tx_hash: TxHash) -> bool {
        self.owed
            .get(&tx_hash)
            .is_some_and(|owed| owed.certified != Certified::No)
    }

    /// Whether an executing tick of this shard's took `tx_hash`, so a
    /// certificate of ours a counterpart may have settled against is
    /// out. False for a transaction this ledger does not hold.
    #[must_use]
    pub(crate) fn executed(&self, tx_hash: TxHash) -> bool {
        self.owed.get(&tx_hash).is_some_and(Owed::executed)
    }

    /// The classification an abandonment of `tx_hash` answers from,
    /// where it answers at all: a held core entry no execution of ours
    /// took and no record covers.
    ///
    /// Every term is committed content or a fold of it. The part and
    /// the classification are the committing block's, the rank is set
    /// by a composition every replica makes at the same commit, and the
    /// record is committed. The last term is what keeps a replica that
    /// held the block and one that reconstructed the entry from a
    /// record composing the same receipt: an entry a record covers is
    /// charge-only on both, and its producer reclaims off the record.
    ///
    /// Such an entry never reached an executing tick, so its member
    /// never ran and wrote no answer, and nothing else writes its claim
    /// or decline key: the abandonment writes `Never` to a key that
    /// holds nothing, and a second abandonment writes the same bytes.
    #[must_use]
    pub(crate) fn abandonment_answers(&self, tx_hash: TxHash) -> Option<&Classified> {
        let owed = self.owed.get(&tx_hash)?;
        match &owed.part {
            Part::Core(kept) if !owed.executed() && owed.departed_by.is_none() => {
                Some(&kept.classified)
            }
            _ => None,
        }
    }

    /// Take what a committed block says departed shards left unsettled.
    ///
    /// A record names transactions its shard did not settle before it
    /// went, which is what puts a settlement of them out of reach for
    /// good. A name this ledger holds is marked; one it does not is
    /// inserted from the record itself, which carries every term
    /// abandoning it takes.
    ///
    /// That insertion is what keeps a rebuild from falling short. The
    /// entry's life is its counterpart's clock while the replay window is
    /// measured in the transaction's, so a restart between the commit and
    /// the record's landing comes back holding the record and not the
    /// entry — and a replica that only marked would name a smaller
    /// abandonable set than its peers at the same frontier, and could not
    /// sign the tick they compose.
    ///
    /// A reconstructed entry is certified by execution, because a record
    /// names nothing else, and runs whole: it holds no body to reclaim
    /// with, and what a record licenses on a name it never held is the
    /// abort.
    ///
    /// Returns how many it reconstructed, which is how far short this
    /// replica's replay window fell — or how long after the block it was
    /// seated, for a validator rotated into the committee. A
    /// reconstructed entry is the entry: the record restates every figure
    /// the transaction fixes and the reach it touches, so what this
    /// derives from it is what a replica that held the block derives.
    pub(crate) fn record_abandonment_records(&mut self, records: &[AbandonmentRecord]) -> usize {
        let mut reconstructed = 0usize;
        for record in records {
            for entry in record.unsettled() {
                if let Some(owed) = self.owed.get_mut(&entry.tx_hash) {
                    owed.departed_by = Some(record.shard());
                    continue;
                }
                reconstructed = reconstructed.saturating_add(1);
                self.owed.insert(
                    entry.tx_hash,
                    Owed {
                        figures: entry.clone(),
                        certified: Certified::ByExecution,
                        part: Part::whole(),
                        departed_by: Some(record.shard()),
                        accepted: BTreeSet::new(),
                        readings: BTreeMap::new(),
                    },
                );
            }
        }
        reconstructed
    }

    /// The transactions this ledger still owes an outcome for that
    /// `shard` was party to, for a shard that left at `cut`, each with the
    /// terms a record naming it must state.
    ///
    /// Only certified ones: a transaction no certificate of ours covers
    /// is decided by its own deadline and needs no record to speak for
    /// it. Only ones this chain committed before the cut, since a shard
    /// that had already gone was issued nothing of what came after —
    /// its successor was, and still holds it. Only ones no
    /// record covers yet, so a departure is answered once. And never a
    /// remainder: its verdict is in, and a departed deliverer's
    /// successor still delivers what it was owed — only the lapse says a
    /// delivery never will.
    #[must_use]
    pub(crate) fn outstanding_with(
        &self,
        shard: ShardId,
        cut: WeightedTimestamp,
    ) -> Vec<UnsettledTx> {
        self.owed
            .iter()
            .filter(|(_, owed)| {
                owed.certified != Certified::No
                    && !owed.part.is_remainder()
                    && !owed.covered()
                    && self.party_to_entry(owed, shard, cut)
            })
            .map(|(_, owed)| owed.figures.clone())
            .collect()
    }

    /// Whether committed content has established that `tx_hash` can
    /// never settle — the question the split-boundary fence otherwise
    /// puts to a settled set that expires.
    #[must_use]
    pub(crate) fn is_covered(&self, tx_hash: TxHash) -> bool {
        self.owed.get(&tx_hash).is_some_and(Owed::covered)
    }

    /// Whether a counterpart's certificate for `tx_hash` is still worth
    /// having here — the entry is held and nothing committed has settled
    /// what it waits on.
    ///
    /// The ledger asks for those certificates itself, when a claim reads
    /// the counterpart's cell present, under the same fetch ids the
    /// expectation tracker asks under — and that ask is one-shot. So a
    /// caller retiring an id one of the two owners has finished with has
    /// to put this question to the other first.
    #[must_use]
    pub(crate) fn awaits_certificate(&self, tx_hash: TxHash) -> bool {
        self.owed.get(&tx_hash).is_some_and(|owed| !owed.covered())
    }

    /// Record where a departed participant's chain ended, and when what it
    /// left stops being readable.
    ///
    /// Idempotent on the cut, which is a property of the schedule rather
    /// than of when this shard got around to reading it. The expiry fills
    /// in when the caller learns it — the beacon stamps the handoff
    /// complete some epochs after the cut — and never moves once set.
    pub(crate) fn record_terminal(
        &mut self,
        shard: ShardId,
        cut: WeightedTimestamp,
        readable_until: Option<WeightedTimestamp>,
    ) {
        self.departed.entry(shard).or_insert(Departure {
            cut,
            readable_until: None,
        });
        if let Some(until) = readable_until {
            self.stamp_terminal(shard, until);
        }
    }

    /// Give a departure this ledger holds open its expiry, once. A
    /// departure not held is not invented here: the cut is the schedule's
    /// to state, and [`Self::record_terminal`] is where it is read.
    pub(crate) fn stamp_terminal(&mut self, shard: ShardId, readable_until: WeightedTimestamp) {
        if let Some(departure) = self.departed.get_mut(&shard)
            && departure.readable_until.is_none()
        {
            departure.readable_until = Some(readable_until);
        }
    }

    /// The departures this ledger holds with no expiry yet.
    ///
    /// An open window is the transient case — the beacon stamps the
    /// handoff some epochs after the cut — but the schedule only lists a
    /// departure while a retained window carries the shard, and the
    /// stamp lands on the head's boundary record, which outlives that
    /// window. An abandonment recorded before its window went and stamped
    /// after has to be asked about by name, or it and every entry a
    /// record covers against it hold each other open for good.
    #[must_use]
    pub(crate) fn unstamped_departures(&self) -> Vec<ShardId> {
        self.departed
            .iter()
            .filter(|(_, departure)| departure.readable_until.is_none())
            .map(|(shard, _)| *shard)
            .collect()
    }

    /// When the shard that held `prefix` when the transaction committed
    /// left, if it has.
    ///
    /// The earliest recorded terminal after this chain committed the
    /// transaction: earlier ones belong to shards that were already gone
    /// and so never held it, and later ones to successors that never did
    /// either. `None` while the prefix is still owned by the shard that
    /// owned it then.
    fn departure_over(&self, owed: &Owed, route: RoutePrefix) -> Option<(ShardId, Departure)> {
        self.departed
            .iter()
            .filter(|(shard, _)| ShardTrie::shard_owns_route(**shard, route))
            .filter(|(_, departure)| departure.cut > owed.figures.committed.anchor)
            .min_by_key(|(_, departure)| departure.cut)
            .map(|(shard, departure)| (*shard, *departure))
    }

    /// Whether `shard`, leaving at `cut`, was party to `owed`, by
    /// [`UnsettledTx::party`] — the rule admission holds a record to —
    /// read against the departures this ledger holds.
    fn party_to_entry(&self, owed: &Owed, shard: ShardId, cut: WeightedTimestamp) -> bool {
        let departures: Vec<(ShardId, WeightedTimestamp)> = self
            .departed
            .iter()
            .map(|(departed, departure)| (*departed, departure.cut))
            .collect();
        owed.figures.party(self.local, shard, cut, &departures)
    }

    /// The shards that could hold a certificate of ours for `tx_hash` —
    /// the ones a settlement of it would need, and so the ones the fence
    /// puts its question to.
    ///
    /// Each remote prefix contributes the shard that owns it under `trie`
    /// and, where the prefix changed hands after the transaction
    /// committed, the departed shard that owned it then. Empty for a
    /// transaction this ledger does not hold, and for one that never left
    /// this shard.
    #[must_use]
    pub(crate) fn counterparts(&self, tx_hash: TxHash, trie: &ShardTrie) -> BTreeSet<ShardId> {
        let Some(owed) = self.owed.get(&tx_hash) else {
            return BTreeSet::new();
        };
        let mut shards = BTreeSet::new();
        for route in self.remote_routes(owed) {
            shards.insert(trie.shard_for_route(route));
            shards.extend(
                self.departed
                    .iter()
                    .filter(|(shard, departure)| {
                        ShardTrie::shard_owns_route(**shard, route)
                            && departure.cut > owed.figures.committed.anchor
                    })
                    .map(|(shard, _)| *shard),
            );
        }
        shards
    }

    /// Whether `tx_hash` reaches beyond this shard at all. A transaction
    /// that does not has no counterpart to hold a certificate of ours,
    /// whatever this shard has said about it.
    #[must_use]
    pub(crate) fn reaches_beyond(&self, tx_hash: TxHash) -> bool {
        self.owed
            .get(&tx_hash)
            .is_some_and(|owed| self.remote_routes(owed).next().is_some())
    }

    /// What a committed block's finalizations settle about the
    /// transactions they name, for the status each is reported under.
    ///
    /// Read before the same finalizations release the entries they
    /// name, since what a name means is a property of the entry.
    #[must_use]
    pub(crate) fn resolutions_of(
        &self,
        finalizations: &[Arc<Verifiable<Finalization>>],
    ) -> Vec<(TxHash, TxResolution)> {
        let mut resolutions = Vec::new();
        for finalization in finalizations {
            let deciding: BTreeSet<TxHash> = finalization.deciding_tx_hashes().collect();
            for (tx_hash, decision) in finalization.tx_decisions() {
                let resolution = match meaning(
                    self.owed.get(&tx_hash),
                    deciding.contains(&tx_hash),
                    decision,
                ) {
                    Meaning::LegRan => TxResolution::LegFinalized,
                    Meaning::Reclaimed(Some(decided)) | Meaning::Verdict(decided) => {
                        TxResolution::Decided(decided)
                    }
                    Meaning::Reclaimed(None) => continue,
                };
                resolutions.push((tx_hash, resolution));
            }
        }
        resolutions
    }

    /// Drop what a committed block's finalizations resolve. Every verdict
    /// arrives this way — accepted, refused, or aborted — so one release
    /// path covers them all.
    ///
    /// A leg entry is released by a finalization that decides the
    /// transaction: a leg that succeeded bears no verdict, so the entry
    /// stays for the reclaim, whose finalization decides it, or for the
    /// commit fold, which closes it once every record it issued was
    /// taken. A leg that failed is the transaction's end on this shard
    /// — it issued nothing, so there is nothing to reclaim — and its own
    /// finalization releases it.
    pub(crate) fn release_resolved(&mut self, finalizations: &[Arc<Verifiable<Finalization>>]) {
        let local = self.local;
        for finalization in finalizations {
            let deciding: BTreeSet<TxHash> = finalization.deciding_tx_hashes().collect();
            for (tx_hash, decision) in finalization.tx_decisions() {
                let Some(owed) = self.owed.get_mut(&tx_hash) else {
                    continue;
                };
                if meaning(Some(owed), deciding.contains(&tx_hash), decision) == Meaning::LegRan
                    && owed.part.is_leg()
                {
                    // The leg ran and its certificate burned the price
                    // inside its writes: what a reclaim of it charges
                    // nothing for.
                    owed.part.charge();
                    continue;
                }
                // An issuer that accepted has crossings out that its
                // deliveries owe a claim for: its verdict resolves the
                // transaction, and the entry stays on as a leg entry for
                // the reclaim alone. One that refused issued nothing.
                let issued = decision == TransactionDecision::Accept && owed.part.issued(local);
                if issued {
                    owed.part.resolve();
                } else {
                    self.owed.remove(&tx_hash);
                }
            }
        }
    }

    /// The transactions a verdict of this shard's can still speak for,
    /// each with the reservation it holds.
    ///
    /// Bounded at both ends. It opens at the transaction's deadline, past
    /// which no shard can finalize it. It closes a `MAX_VALIDITY_RANGE`
    /// later, which is the room the shard has to get an abandonment
    /// committed — and, more than that, is what keeps a verdict from being
    /// composed on an event far from the transaction's own life.
    ///
    /// The upper bound is an atomicity property rather than bookkeeping.
    /// Composing an abandonment discards the tick holding the member, and
    /// the tick discarded is the one that would have settled it; a window
    /// reaching a counterpart's departure would spend settlements that had
    /// already closed. The entry outlives this window so its reservation
    /// stays accountable, and offering it again here is exactly what that
    /// must not cost.
    ///
    /// It binds only an entry an executing tick took. One no execution
    /// of ours ever ran has no executing tick to discard and no
    /// certificate a counterpart could have settled against, so aborting
    /// it at any age spends nothing, and it is offered until an
    /// abandonment's committed finalization releases it: never composed,
    /// or composed and discarded, its abort is the one exit that could
    /// otherwise fall silent. A chain that halts past the window and
    /// recovers composes it on its first commit.
    ///
    /// Read off committed content alone — the ledger is a fold over
    /// committed blocks and `now` is the committed weighted timestamp —
    /// so every replica at the same frontier names the same set, which is
    /// what lets a committee sign the abort it composes.
    ///
    /// A leg entry is never here: its tick attested it and its
    /// certificate settled alone, so there is nothing to abandon. What a
    /// record licenses on one is a reclaim.
    #[must_use]
    pub(crate) fn past_deadline(&self, now: WeightedTimestamp) -> Vec<UnsettledTx> {
        self.owed
            .iter()
            .filter(|(_, owed)| !owed.part.is_leg())
            .filter(|(_, owed)| {
                let window = owed.abandon_window();
                now >= window.start && (owed.covered() || !owed.executed() || now < window.end)
            })
            .map(|(_, owed)| owed.figures.clone())
            .collect()
    }

    /// Drop the entries nothing can still decide.
    ///
    /// An entry lives as long as the question that decides it is still
    /// open, and there are two such questions. A transaction no
    /// certificate of ours covers is decided by its own deadline: nothing
    /// anywhere can settle it, so this shard abandons it, and the window
    /// from the deadline to `MAX_VALIDITY_RANGE` past it is the room to
    /// get that abandonment committed.
    ///
    /// One a certificate of ours does cover is decided by a participant's
    /// settled set, which reads to that shard's terminal-evidence expiry
    /// and never again. So it lives while some participant can
    /// still answer — one still running, whose certificate can yet arrive
    /// or whose own terminal can yet let the set speak, or one departed
    /// within that window. A clock of this transaction's own has nothing
    /// to say about when its counterpart leaves, which is why one cannot
    /// be what ends the entry.
    ///
    /// One a committed record already decided waits on nothing but a block
    /// carrying its abort, so what it lives against is the departure the
    /// record names rather than any counterpart's answerability. That is
    /// the same window the record was composed in, it is the one an entry
    /// reconstructed from a record has, and it is finite where a live
    /// counterpart's is not — which is what lets a replay floor reach
    /// every record still owed a verdict. One a committed claim decided —
    /// a core member whose sibling's cell was read absent — waits on the
    /// same block, and lives to the horizon a leg has, past which nothing
    /// can be composed for the transaction at all.
    ///
    /// A leg entry has a clock of its own, and it is the transaction's:
    /// the close of [`Window::LegEntry`]. Not a sweep — no crossing cell
    /// sweeps — but the end of the room this entry has to turn evidence
    /// into a committed reclaim, floored at the span a core's committed
    /// cell has to be provable absent in so a reading taken at the
    /// latest still has room to become one.
    ///
    /// Past it the **entry** composes nothing, whatever evidence
    /// arrives, and it goes on that reading alone. What it does not end
    /// is the crossing: the record stands in `held`, which no clock
    /// prunes, and a consumer's answer reaching the producer later
    /// settles it from the leaf. Dropping gives this road up; it never
    /// licenses a reclaim. A record's evidence does not extend it, and
    /// no counterpart's silence shortens it.
    ///
    /// Returns the transactions dropped because every counterpart has
    /// fallen silent. Each carries whether a committed record had covered
    /// it, which separates a chain that ran out of room to commit the abort
    /// from one that never had the evidence to compose it. A leg entry
    /// dropped at its horizon is not among them: its reservation came
    /// back with its own finalization, so nothing leaks with it.
    pub(crate) fn prune(&mut self, now: WeightedTimestamp) -> Vec<Unanswerable> {
        let mut unanswerable = Vec::new();
        let mut entries = std::mem::take(&mut self.owed);
        entries.retain(|tx_hash, owed| {
            // A core entry no execution of ours took leaves only by an
            // abandonment's committed finalization: no clock bounds an
            // abort that spends nothing, and dropping the entry would be
            // the silent exit its producer could never read.
            if !owed.executed() && matches!(owed.part, Part::Core(_)) {
                return true;
            }
            // A leg entry goes at its horizon: past it neither the
            // reclaim nor the retirement can be composed *here*,
            // whatever evidence lands, because this is the road that
            // reads an entry. The leaf's road stays open. Short of it
            // only the finalization that decides it ends it.
            if owed.part.is_leg() || owed.absences().next().is_some() {
                return Window::LegEntry.of(owed.figures.deadline).end > now;
            }
            if let Some(shard) = owed.departed_by {
                if self.departed.get(&shard).is_some_and(|departure| {
                    departure.readable_until.is_none_or(|until| now <= until)
                }) {
                    return true;
                }
                unanswerable.push(Unanswerable {
                    tx_hash: *tx_hash,
                    covered_by_record: true,
                });
                return false;
            }
            let answerable = self.remote_routes(owed).any(|route| {
                self.departure_over(owed, route)
                    .is_none_or(|(_, departure)| {
                        departure.readable_until.is_none_or(|until| now <= until)
                    })
            });
            // Having counterparts at all is what makes silence mean
            // something: a transaction that never left this shard has
            // nobody to fall silent, and its own deadline decides it
            // as it decides any other.
            if owed.certified != Certified::No && self.remote_routes(owed).next().is_some() {
                if answerable {
                    return true;
                }
                // Our certificate is out there and no shard is left to
                // combine it with.
                unanswerable.push(Unanswerable {
                    tx_hash: *tx_hash,
                    covered_by_record: false,
                });
                return false;
            }
            owed.abandon_window().end > now
        });
        self.owed = entries;

        // A terminal is what tells a prefix's owner apart from its
        // successor, so one still covering a live entry stays: dropping
        // it would read the departed counterpart as the shard that holds
        // the keyspace now, and hold the entry open against a shard that
        // was never party to it. One a record names stays for a second
        // reason — it is the clock the covered entry lives against, so
        // dropping it would retire the entry on the next pass.
        let owed = &self.owed;
        let local = self.local;
        self.departed.retain(|shard, departure| {
            owed.values().any(|entry| {
                entry.departed_by == Some(*shard)
                    || (departure.cut > entry.figures.committed.anchor
                        && entry.figures.reach.iter().any(|route| {
                            !ShardTrie::shard_owns_route(local, *route)
                                && ShardTrie::shard_owns_route(*shard, *route)
                        }))
            })
        });

        unanswerable
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.owed.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_hbor::Capped;
    use hyperscale_storage::committed_tx_cell_key;
    use hyperscale_types::test_utils::{
        make_finalization, make_leg_finalization, stub_transaction, test_prefix, test_principal,
    };
    use hyperscale_types::{
        AbortCharge, BlockHeight, EPOCH_DURATION, EpochWindows, MAX_FINALIZATION_DELAY,
        MAX_VALIDITY_RANGE, TimestampRange, UnsettledTx, Verified, WeightedTimestamp,
    };

    use super::*;

    /// This shard owns the prefixes whose leading bit is zero, so an
    /// address is remote or local by its top byte and nothing else.
    const LOCAL: ShardId = ShardId::leaf(1, 0);
    const HERE: u8 = 0x11;
    const AWAY: u8 = 0xAA;

    /// The depth-1 shard owning every `AWAY`-topped prefix.
    const PARTNER: ShardId = ShardId::leaf(1, 1);

    /// The depth-2 shard that takes the right half of `PARTNER`'s
    /// keyspace when it splits, and so owns the prefixes `tx(30)`
    /// reaches after `PARTNER` is gone.
    const SUCCESSOR: ShardId = ShardId::leaf(2, 3);

    /// A shape frozen divided with an inbound leg on `LOCAL` feeding a
    /// core on `PARTNER`: the leg issues one crossing the core claims.
    fn classified() -> Classified {
        use hyperscale_types::ShardTrie;
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([PARTNER]));
        classified
    }

    /// The decline cell the core writes beside [`core_claim`] where it
    /// refuses what `classified` says `LOCAL` issued.
    fn core_decline(classified: &Classified) -> (ShardId, SubstateKey) {
        one_answer(classified, Kind::Escrowed, Answered::Never, "to the core")
    }

    /// The one answer cell in `answered`'s role that the consumer of the
    /// `kind` crossing `LOCAL` issued writes, under that consumer's
    /// frozen home.
    fn one_answer(
        classified: &Classified,
        kind: Kind,
        answered: Answered,
        to: &str,
    ) -> (ShardId, SubstateKey) {
        let answers: Vec<(ShardId, SubstateKey)> = classified
            .crossings()
            .filter(|(edge, _)| edge.from == LOCAL && edge.crossing.kind == kind)
            .map(|(edge, home)| (home, edge.crossing.id.answer_key(&ProtocolHasher, answered)))
            .collect();
        assert_eq!(answers.len(), 1, "the fixture issues one crossing {to}");
        answers[0]
    }

    /// The claim cell the core writes for what `classified` says `LOCAL`
    /// issued, under the shard holding the consumer's target.
    fn core_claim(classified: &Classified) -> (ShardId, SubstateKey) {
        one_answer(classified, Kind::Escrowed, Answered::Taken, "to the core")
    }

    /// The committed cell `shard` writes for `tx`.
    fn core_cell(shard: ShardId, tx: &Arc<Verifiable<Transaction>>) -> SubstateKey {
        committed_tx_cell_key(
            shard,
            tx.hash(),
            tx.validity_range().end_timestamp_exclusive,
        )
    }

    /// The claim cell a delivery writes for what `classified` says
    /// `LOCAL` issued, under the shard that delivers it.
    fn delivered_claim(classified: &Classified) -> (ShardId, SubstateKey) {
        one_answer(classified, Kind::Owed, Answered::Taken, "to a delivery")
    }

    /// The two depth-2 shards a delivery fixture places off `LOCAL`,
    /// each holding half of `PARTNER`'s keyspace: the core of one shard
    /// bearing the verdict, and the shard the leg's crossing is
    /// delivered on.
    const BEARER: ShardId = ShardId::leaf(2, 3);
    const DELIVERER: ShardId = ShardId::leaf(2, 2);

    /// The trie [`delivering`] is frozen under.
    fn delivery_trie() -> ShardTrie {
        ShardTrie::from_leaves([LOCAL, DELIVERER, BEARER])
    }

    /// A shape frozen divided with an inbound leg on `LOCAL` feeding an
    /// outbound leg on `DELIVERER` directly, the core of one shard on
    /// `BEARER`: the leg issues one crossing a delivery claims.
    fn delivering() -> Classified {
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(3, LegRole::Core, &[]),
            leg(2, LegRole::Outbound, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &delivery_trie());
        assert_eq!(classified.core(), &BTreeSet::from([BEARER]));
        assert!(classified.decomposed());
        classified
    }

    /// The depth-2 shard beside `LOCAL` in a core of two, holding the
    /// left half of `PARTNER`'s keyspace.
    const SIBLING: ShardId = ShardId::leaf(2, 2);

    /// A shape frozen divided with `LOCAL` in a core of two shards, fed
    /// by an inbound leg on the other half of `PARTNER`'s keyspace.
    fn two_shard_core() -> Classified {
        use hyperscale_types::ShardTrie;
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(3, LegRole::Inbound, &[]),
            leg(0, LegRole::Core, &[(0, 0)]),
            leg(2, LegRole::Core, &[(1, 0)]),
        ];
        let trie = ShardTrie::from_leaves([LOCAL, SIBLING, ShardId::leaf(2, 3)]);
        let classified = Classified::freeze(&legs, legs[0].target, &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([LOCAL, SIBLING]));
        assert!(classified.decomposed());
        classified
    }

    /// A shape frozen divided with `LOCAL` in the core — its sign-in
    /// bears the verdict — and its withdraw delivered on `PARTNER`: an
    /// issuer with one delivery owed a claim.
    fn issuing() -> Classified {
        use hyperscale_types::ShardTrie;
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Attesting, &[]),
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Outbound, &[(1, 0)]),
        ];
        let classified = Classified::freeze(&legs, legs[0].target, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([LOCAL]));
        assert!(classified.decomposed());
        classified
    }

    /// A transaction paying from `payer` and touching `also`, both given
    /// as the byte an address repeats.
    fn tx_over(payer: u8, also: u8, end_ms: u64) -> Arc<Verifiable<Transaction>> {
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(end_ms),
        );
        Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
            stub_transaction(test_principal(payer), &[test_prefix(also)], 1_000, validity),
        )))
    }

    /// A straddler: payer here, the rest of it away.
    fn tx(seed: u8, end_ms: u64) -> Arc<Verifiable<Transaction>> {
        tx_over(HERE, AWAY.wrapping_add(seed) | 0x80, end_ms)
    }

    fn ms(v: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(v)
    }

    /// When a departure at `cut` stops answering, on the production epoch
    /// grid — the same derivation the commit path stamps departures with.
    fn expiry(cut: WeightedTimestamp) -> WeightedTimestamp {
        EpochWindows::new(EPOCH_DURATION.as_secs() * 1000).terminal_evidence_expiry(cut)
    }

    fn commit(ledger: &mut Ledger, tx: &Arc<Verifiable<Transaction>>) {
        commit_as(ledger, tx, &Classified::whole());
    }

    /// Commit `tx` frozen as `classified`, which is what fixes the part
    /// this shard plays and every cell its entry asks about.
    fn commit_as(ledger: &mut Ledger, tx: &Arc<Verifiable<Transaction>>, classified: &Classified) {
        ledger.register_committed(committed_at(tx), &PriceTable::GENESIS, [(tx, classified)]);
    }

    /// Where the fixtures commit `tx`: well inside its window, at a
    /// height of no consequence.
    fn committed_at(tx: &Arc<Verifiable<Transaction>>) -> CommittedAt {
        let anchor = tx
            .validity_range()
            .end_timestamp_exclusive
            .minus(Duration::from_secs(100));
        CommittedAt {
            height: BlockHeight::new(1),
            anchor,
            committee_anchor: anchor,
        }
    }

    /// A record's name for `tx`, stating the terms a committing block
    /// would have registered for it.
    fn names(tx: &Arc<Verifiable<Transaction>>) -> UnsettledTx {
        UnsettledTx {
            tx_hash: tx.hash(),
            deadline: Deadline::of_transaction(tx),
            charged: Classified::freeze(
                tx.legs(),
                tx.fee_payer(),
                tx.accounts(),
                &ShardTrie::uniform(1),
            )
            .local_price(tx, LOCAL, &PriceTable::GENESIS),
            charge: charge(tx),
            committed: committed_at(tx),
            reach: tx.routing().all_routes(),
            escrowed: Capped::empty(),
        }
    }

    /// What abandoning `tx` states, as the ledger hands it to a tick.
    fn abandons(tx: &Arc<Verifiable<Transaction>>) -> UnsettledTx {
        names(tx)
    }

    /// The burn an abort of `tx` settles.
    fn charge(tx: &Arc<Verifiable<Transaction>>) -> AbortCharge {
        UnsettledTx::for_transaction(
            tx,
            committed_at(tx),
            tx.price(&PriceTable::GENESIS),
            Capped::empty(),
            &PriceTable::GENESIS,
        )
        .charge
    }

    /// A committed transaction is owed an outcome from the moment its
    /// block commits until a committed block carries one.
    #[test]
    fn a_committed_transaction_is_owed_an_outcome_until_one_commits() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(1, 60_000);
        commit(&mut ledger, &tx);
        assert_eq!(ledger.len(), 1);

        let resolved =
            make_finalization(BlockHeight::new(1), tx.hash(), TransactionDecision::Accept);
        ledger.release_resolved(&[Arc::new(Verifiable::from(resolved))]);
        assert_eq!(ledger.len(), 0);
    }

    /// Every verdict releases, not only acceptance — an abort resolves a
    /// transaction exactly as a settlement does, which is what lets one
    /// certificate answer for both.
    #[test]
    fn an_abort_releases_as_a_settlement_does() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(2, 60_000);
        commit(&mut ledger, &tx);

        let aborted =
            make_finalization(BlockHeight::new(1), tx.hash(), TransactionDecision::Aborted);
        ledger.release_resolved(&[Arc::new(Verifiable::from(aborted))]);
        assert_eq!(ledger.len(), 0);
    }

    /// Re-registering a transaction leaves the deadline it was admitted
    /// under alone: the fold has to be identical on a replica that sees
    /// the block once and one that replays it.
    #[test]
    fn re_registering_does_not_move_the_deadline() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(3, 60_000);
        commit(&mut ledger, &tx);
        commit(&mut ledger, &tx);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        assert_eq!(ledger.len(), 1, "one entry, not two");
        assert!(
            ledger
                .past_deadline(deadline.minus(Duration::from_millis(1)))
                .is_empty(),
            "and the deadline is still the one it was admitted under",
        );
        assert_eq!(ledger.past_deadline(deadline), vec![abandons(&tx)]);
    }

    /// A transaction becomes abandonable at its own deadline and not
    /// before, carrying the reservation its committing block took.
    #[test]
    fn a_transaction_is_abandonable_at_its_deadline_and_not_before() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(4, 60_000);
        commit(&mut ledger, &tx);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        assert!(
            ledger
                .past_deadline(deadline.minus(Duration::from_millis(1)))
                .is_empty(),
            "merely slow is not abandonable",
        );
        assert_eq!(
            ledger.past_deadline(deadline),
            vec![abandons(&tx)],
            "at the deadline, named with what it reserved",
        );
    }

    /// An entry survives its deadline: the window past it is the room the
    /// shard has to get the abort committed. It goes once no block could
    /// still reference the transaction at all.
    #[test]
    fn an_entry_outlives_its_deadline_and_not_the_retention_window() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(7, 60_000);
        commit(&mut ledger, &tx);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        ledger.prune(deadline);
        assert_eq!(ledger.len(), 1, "still the shard's to resolve");

        ledger.prune(deadline.plus(MAX_VALIDITY_RANGE));
        assert_eq!(ledger.len(), 0, "past every window that could carry it");
    }

    /// A transaction this shard has spoken for is not this shard's to end
    /// on a clock. Its counterpart holds a certificate it can settle
    /// against for as long as it runs, so the entry outlives the window a
    /// deadline would have closed.
    #[test]
    fn a_certified_straddler_outlives_the_deadline_window() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        ledger.prune(deadline.plus(MAX_VALIDITY_RANGE));
        assert_eq!(ledger.len(), 1, "the counterpart can still settle it");

        ledger.prune(ms(600_000));
        assert_eq!(
            ledger.len(),
            1,
            "and no clock of this shard's says otherwise"
        );
    }

    /// Outliving the deadline window is not the same as being abandonable
    /// through it. The entry stays so its reservation stays accountable;
    /// offering it to a verdict again would spend the tick that is still
    /// the transaction's best chance of settling.
    #[test]
    fn an_entry_outliving_the_deadline_window_is_no_longer_a_candidate() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(15, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        assert_eq!(
            ledger.past_deadline(deadline),
            vec![abandons(&tx)],
            "at its deadline it is the shard's to speak for",
        );
        assert_eq!(
            ledger.past_deadline(
                deadline
                    .plus(MAX_VALIDITY_RANGE)
                    .minus(Duration::from_millis(1))
            ),
            vec![abandons(&tx)],
            "and stays so for the room to get that committed",
        );

        let past = deadline.plus(MAX_VALIDITY_RANGE);
        assert!(
            ledger.past_deadline(past).is_empty(),
            "past the window no verdict of this shard's speaks for it",
        );
        ledger.prune(past);
        assert_eq!(ledger.len(), 1, "though the account still owes it");
    }

    /// It goes when the last counterpart that could have answered stops
    /// being able to: a departed shard's settled set reads to its
    /// evidence expiry, and nothing decides the transaction after that.
    #[test]
    fn a_certified_straddler_goes_when_its_last_counterpart_falls_silent() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(9, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let cut = ms(500_000);
        ledger.record_terminal(PARTNER, cut, Some(expiry(cut)));

        ledger.prune(expiry(cut));
        assert_eq!(ledger.len(), 1, "the set still reads at the expiry");

        ledger.prune(expiry(cut).plus(Duration::from_millis(1)));
        assert_eq!(ledger.len(), 0, "and never again past it");
    }

    /// Two cuts over one prefix inside one entry's life name the entry
    /// to the shard that held the prefix when it committed, and to
    /// nothing else. A successor inherits the keyspace, not the
    /// business: a record naming it would abandon what the first
    /// departure had already settled.
    #[test]
    fn only_the_shard_holding_the_prefix_at_the_commit_is_party_to_the_entry() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(30, 60_000);
        assert!(
            tx.routing()
                .all_prefixes()
                .iter()
                .any(|prefix| ShardTrie::shard_owns_prefix(SUCCESSOR, *prefix)),
            "the fixture reaches a prefix both departures own",
        );
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let first = ms(200_000);
        let second = ms(800_000);
        ledger.record_terminal(PARTNER, first, None);
        ledger.record_terminal(SUCCESSOR, second, None);

        assert_eq!(
            ledger
                .outstanding_with(PARTNER, first)
                .iter()
                .map(|entry| entry.tx_hash)
                .collect::<Vec<_>>(),
            vec![tx.hash()],
            "the shard that held the prefix then answers for the entry",
        );
        assert!(
            ledger.outstanding_with(SUCCESSOR, second).is_empty(),
            "and its successor is a stranger to it, so the second cut is offered nothing to name",
        );
    }

    /// The entry names itself on the way out, so its holder can let go of
    /// what it was keeping for a settlement that cannot arrive — and says
    /// whether a record had covered it, which separates a chain that ran
    /// out of room to commit the abort from one that never had the
    /// evidence to compose it.
    #[test]
    fn a_strand_whose_counterparts_all_fell_silent_names_itself() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(16, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let cut = ms(500_000);
        ledger.record_terminal(PARTNER, cut, Some(expiry(cut)));
        assert!(
            ledger.prune(expiry(cut)).is_empty(),
            "while the set still reads, the strand is nobody's to release",
        );
        assert_eq!(
            ledger.prune(expiry(cut).plus(Duration::from_millis(1))),
            vec![Unanswerable {
                tx_hash: tx.hash(),
                covered_by_record: false,
            }],
            "past it, nothing can settle it and the strand is named",
        );
    }

    /// A strand a record had covered is dropped for the same reason but is
    /// a different failure: the abort was licensed and the chain never got
    /// one committed. Only one of the two says the evidence path is
    /// working, so the holder has to be able to tell them apart.
    #[test]
    fn a_covered_strand_names_the_record_that_licensed_its_abort() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(18, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let cut = ms(500_000);
        ledger.record_terminal(PARTNER, cut, Some(expiry(cut)));
        assert_eq!(
            ledger.record_abandonment_records(&[AbandonmentRecord::new(
                PARTNER,
                cut,
                [names(&tx)]
            )]),
            0,
            "the ledger holds the transaction the record names",
        );

        assert_eq!(
            ledger.prune(expiry(cut).plus(Duration::from_millis(1))),
            vec![Unanswerable {
                tx_hash: tx.hash(),
                covered_by_record: true,
            }],
        );
    }

    /// A record naming what the ledger does not hold rebuilds it. That is
    /// a rebuild that came back holding the record and not the entry, and
    /// what the record carries is exactly what the entry would have said,
    /// so the replica reaches the same abandonable set as its peers rather
    /// than a smaller one.
    #[test]
    fn a_record_naming_an_unheld_transaction_rebuilds_it() {
        let mut ledger = Ledger::new(LOCAL);
        let (one, two) = (tx(19, 60_000), tx(20, 60_000));
        let cut = ms(500_000);
        ledger.record_terminal(PARTNER, cut, Some(expiry(cut)));

        assert_eq!(
            ledger.record_abandonment_records(&[AbandonmentRecord::new(
                PARTNER,
                cut,
                [names(&one), names(&two)],
            )]),
            2,
            "neither was held, so both are rebuilt",
        );
        assert_eq!(ledger.len(), 2);
        assert!(ledger.is_covered(one.hash()));

        // And each is abandonable on the record's own terms, which is the
        // whole point of it carrying them.
        let past = ms(60_000)
            .plus(MAX_FINALIZATION_DELAY)
            .plus(MAX_VALIDITY_RANGE);
        let mut offered = ledger.past_deadline(past);
        offered.sort_unstable_by_key(|entry| entry.tx_hash);
        let mut expected = vec![abandons(&one), abandons(&two)];
        expected.sort_unstable_by_key(|entry| entry.tx_hash);
        assert_eq!(offered, expected);
    }

    /// A rebuilt entry lives against the departure that named it, not
    /// against a transaction clock it has nothing to say about. It waits
    /// on a block carrying its abort, and stops when the departure it was
    /// written against stops answering.
    #[test]
    fn a_rebuilt_entry_lives_against_the_departure_that_named_it() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(21, 60_000);
        let cut = ms(500_000);
        ledger.record_terminal(PARTNER, cut, Some(expiry(cut)));
        ledger.record_abandonment_records(&[AbandonmentRecord::new(PARTNER, cut, [names(&tx)])]);

        assert!(
            ledger.prune(cut).is_empty(),
            "the transaction's own deadline is long past, and decides nothing here",
        );
        assert_eq!(ledger.len(), 1);

        assert_eq!(
            ledger.prune(expiry(cut).plus(Duration::from_millis(1))),
            vec![Unanswerable {
                tx_hash: tx.hash(),
                covered_by_record: true,
            }],
        );
    }

    /// A committed record is what lets a verdict outlive the deadline
    /// window. Past that window the shard stops speaking for a
    /// transaction on its own clock; a record says no counterpart is left
    /// to contradict it, and the chain is where that is written.
    #[test]
    fn a_record_reopens_the_window_a_deadline_closed() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(17, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let past = deadline.plus(MAX_VALIDITY_RANGE);
        assert!(
            ledger.past_deadline(past).is_empty(),
            "on its own clock the shard has stopped speaking for it",
        );

        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(500_000),
            [names(&tx)],
        )]);
        assert_eq!(
            ledger.past_deadline(past),
            vec![abandons(&tx)],
            "the record says nothing can settle it, so the shard may",
        );
        assert!(ledger.is_covered(tx.hash()));
    }

    /// A record still opens nothing before the transaction's own
    /// deadline: until then it may yet finalize somewhere, and the record
    /// speaks only to what a departed shard did.
    #[test]
    fn a_record_does_not_reach_back_before_the_deadline() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(18, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);
        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(500_000),
            [names(&tx)],
        )]);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        assert!(
            ledger
                .past_deadline(deadline.minus(Duration::from_millis(1)))
                .is_empty(),
            "merely covered is not yet abandonable",
        );
    }

    /// A transaction that never left this shard has no counterpart to
    /// fall silent, so it is never named as a strand however long this
    /// shard has spoken for it — its own deadline ends it, as ever.
    #[test]
    fn a_local_transaction_is_never_a_silenced_strand() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx_over(HERE, HERE.wrapping_add(1), 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        assert!(
            ledger.prune(deadline).is_empty(),
            "not yet past its own window",
        );
        assert!(
            ledger.prune(deadline.plus(MAX_VALIDITY_RANGE)).is_empty(),
            "and gone at that window's end without ever being a strand",
        );
        assert_eq!(ledger.len(), 0);
    }

    /// One counterpart falling silent is not enough while another can
    /// still answer.
    #[test]
    fn a_straddler_waits_on_whichever_counterpart_can_still_answer() {
        let mut ledger = Ledger::new(LOCAL);
        // Two remote prefixes under different depth-2 shards: `0b10…`
        // and `0b11…`.
        let tx = tx_over(HERE, 0xC0, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);

        let cut = ms(500_000);
        ledger.record_terminal(ShardId::leaf(2, 2), cut, Some(expiry(cut)));
        ledger.prune(expiry(cut).plus(MAX_VALIDITY_RANGE));
        assert_eq!(ledger.len(), 1, "the other shard is still running");
    }

    /// A transaction that never left this shard is decided by its own
    /// deadline whatever this shard said about it: there is no counterpart
    /// holding a certificate of ours, so there is nobody to wait for.
    #[test]
    fn a_certificate_over_a_local_transaction_holds_nothing_open() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx_over(HERE, HERE.wrapping_add(1), 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);
        assert!(!ledger.reaches_beyond(tx.hash()), "nothing of it is remote");

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        ledger.prune(deadline.plus(MAX_VALIDITY_RANGE));
        assert_eq!(ledger.len(), 0, "nobody to wait for");
    }

    /// The certification is the account's, not the tick's: a transaction
    /// the ledger does not hold reads as uncertified, which is the answer
    /// that lets its holder abandon it.
    #[test]
    fn an_unheld_transaction_is_uncertified() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(12, 60_000);
        assert!(!ledger.is_certified(tx.hash()));

        commit(&mut ledger, &tx);
        assert!(!ledger.is_certified(tx.hash()), "committed says nothing");
        ledger.certify(tx.hash(), Certified::ByExecution);
        assert!(ledger.is_certified(tx.hash()));
    }

    /// The rank only rises: an abandonment composed after an execution
    /// took the transaction never lowers what this shard has said, and
    /// an execution outranks an abandonment whichever came first. Either
    /// certifies.
    #[test]
    fn an_execution_certificate_outranks_an_abandonment() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(13, 60_000);
        commit(&mut ledger, &tx);
        assert!(!ledger.is_certified(tx.hash()));
        assert!(!ledger.executed(tx.hash()));

        ledger.certify(tx.hash(), Certified::ByAbandonment);
        assert!(ledger.is_certified(tx.hash()));
        assert!(!ledger.executed(tx.hash()));

        ledger.certify(tx.hash(), Certified::ByExecution);
        assert!(ledger.executed(tx.hash()));

        ledger.certify(tx.hash(), Certified::ByAbandonment);
        assert!(
            ledger.executed(tx.hash()),
            "an abandonment after an execution leaves the certificate out there",
        );
        assert!(ledger.is_certified(tx.hash()));
    }

    /// Past its abandon window a core entry no execution of ours took is
    /// still offered and still held, an abandonment already composed
    /// included: it spends nothing to abort at any age, and dropping it
    /// would be the silent exit its producer could never read. One an
    /// executing tick took is bounded by the window as before.
    #[test]
    fn an_uncertified_entry_outlives_its_abandon_window() {
        let tx = tx(14, 60_000);
        for how in [Certified::No, Certified::ByAbandonment] {
            let mut ledger = Ledger::new(LOCAL);
            commit_as(&mut ledger, &tx, &two_shard_core());
            ledger.certify(tx.hash(), how);
            let past = ledger.owed[&tx.hash()]
                .abandon_window()
                .end
                .plus(Duration::from_secs(1));
            assert!(
                ledger
                    .past_deadline(past)
                    .iter()
                    .any(|entry| entry.tx_hash == tx.hash()),
                "{how:?}: still offered past its window",
            );
            ledger.prune(past);
            assert_eq!(ledger.len(), 1, "{how:?}: and still held");
        }

        let mut ledger = Ledger::new(LOCAL);
        commit_as(&mut ledger, &tx, &two_shard_core());
        ledger.certify(tx.hash(), Certified::ByExecution);
        let past = ledger.owed[&tx.hash()]
            .abandon_window()
            .end
            .plus(Duration::from_secs(1));
        assert!(
            ledger.past_deadline(past).is_empty(),
            "an executed entry is offered inside its window alone",
        );
    }

    /// An abandonment answers exactly where no execution of ours spoke
    /// and no record does, and answers the same on a replica that held
    /// the block and one that met the transaction in a record.
    ///
    /// Beside
    /// [`a_reconstructed_entry_names_the_same_parties_as_a_registered_one`]:
    /// the receipt an abandonment composes reaches the receipt root, so
    /// the two replicas have to compose the same one. A reconstructed
    /// entry runs whole and holds no classification, so it answers with
    /// the charge alone; a record covering the transaction flips the
    /// seated replica to the same answer.
    #[test]
    fn an_abandonment_writes_never_identically_on_a_seated_replica() {
        let tx = tx(8, 60_000);
        let record = AbandonmentRecord::new(PARTNER, ms(70_000), [names(&tx)]);

        let mut seated = Ledger::new(LOCAL);
        commit_as(&mut seated, &tx, &two_shard_core());
        assert_eq!(
            seated.abandonment_answers(tx.hash()),
            Some(&two_shard_core()),
            "a held core entry no execution took answers off its classification",
        );
        seated.certify(tx.hash(), Certified::ByAbandonment);
        assert!(
            seated.abandonment_answers(tx.hash()).is_some(),
            "an abandonment composed and lost does not silence the next",
        );

        let mut entrant = Ledger::new(LOCAL);
        entrant.record_abandonment_records(std::slice::from_ref(&record));
        assert!(
            entrant.abandonment_answers(tx.hash()).is_none(),
            "a reconstructed entry answers with the charge alone",
        );

        seated.record_abandonment_records(&[record]);
        assert!(
            seated.abandonment_answers(tx.hash()).is_none(),
            "a record covering the transaction gives the seated replica the entrant's answer",
        );

        let mut executed = Ledger::new(LOCAL);
        commit_as(&mut executed, &tx, &two_shard_core());
        executed.certify(tx.hash(), Certified::ByExecution);
        assert!(
            executed.abandonment_answers(tx.hash()).is_none(),
            "an executed entry never answers: its certificate may be out",
        );
    }

    /// A counterpart is whoever owns the keyspace the transaction reaches
    /// into: the shard holding it now, and any that held it and left
    /// since the transaction committed.
    #[test]
    fn counterparts_name_the_shard_holding_the_keyspace_and_the_one_that_left_it() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(13, 60_000);
        commit(&mut ledger, &tx);

        let live = ShardTrie::uniform(1);
        assert_eq!(
            ledger.counterparts(tx.hash(), &live),
            BTreeSet::from([PARTNER]),
            "one shard owns the whole remote side",
        );

        // The partner splits. Its keyspace passes to a child, and both
        // answer for the transaction — the child owns it now, the parent
        // held it when our certificate went out.
        ledger.record_terminal(PARTNER, ms(500_000), Some(expiry(ms(500_000))));
        let split = ShardTrie::from_leaves([LOCAL, ShardId::leaf(2, 2), ShardId::leaf(2, 3)]);
        let after = ledger.counterparts(tx.hash(), &split);
        assert!(after.contains(&PARTNER), "the shard that held it then");
        assert_eq!(after.len(), 2, "and the one that holds it now");
    }

    /// A shard that left before this chain committed the transaction
    /// never held it, whatever its keyspace covers now — so its terminal
    /// says nothing about this transaction's fate, and cannot be the
    /// silence that strands it.
    ///
    /// Dated by the block that committed it here, which the entry
    /// carries: a replica meeting the transaction in a record reads the
    /// same block off the name.
    #[test]
    fn a_terminal_older_than_the_transaction_is_not_its_counterpart_leaving() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(14, 600_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);
        // Before the block that committed the transaction here.
        let stale = ms(400_000);
        assert!(
            stale < names(&tx).committed.anchor,
            "the terminal has to predate the commit of the transaction",
        );
        ledger.record_terminal(PARTNER, stale, Some(expiry(stale)));

        assert!(
            ledger
                .prune(expiry(stale).plus(MAX_VALIDITY_RANGE))
                .is_empty(),
            "the shard owning the prefix at commit is the successor, still running",
        );
        assert_eq!(ledger.len(), 1, "so nothing has fallen silent on it");
    }

    /// A departure held with no expiry holds the entry a record covers
    /// against it, however far the clock runs; a stamp landing later
    /// gives both their end, and the entry retires as covered once it is
    /// past.
    #[test]
    fn a_departure_stamped_late_still_retires_what_it_covers() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(4, 60_000);
        commit(&mut ledger, &tx);
        ledger.certify(tx.hash(), Certified::ByExecution);
        let cut = ms(100_000);
        ledger.record_terminal(PARTNER, cut, None);
        ledger.record_abandonment_records(&[AbandonmentRecord::new(PARTNER, cut, [names(&tx)])]);
        assert_eq!(ledger.unstamped_departures(), vec![PARTNER]);

        let far = expiry(cut).plus(EPOCH_DURATION * 100);
        assert!(
            ledger.prune(far).is_empty(),
            "an open window holds the covered entry"
        );
        assert_eq!(ledger.len(), 1);

        ledger.stamp_terminal(PARTNER, expiry(cut));
        assert!(ledger.unstamped_departures().is_empty());
        let dropped = ledger.prune(far);
        assert_eq!(
            dropped,
            vec![Unanswerable {
                tx_hash: tx.hash(),
                covered_by_record: true,
            }],
            "past the stamp the covered entry retires"
        );
        assert_eq!(ledger.len(), 0);
        assert!(
            ledger.unstamped_departures().is_empty(),
            "and the departure goes with the last entry naming it"
        );

        ledger.stamp_terminal(PARTNER, cut);
        assert!(
            ledger.unstamped_departures().is_empty(),
            "a stamp for a departure not held invents nothing"
        );
    }

    /// A leg entry is probeable from its deadline and not a moment
    /// before, and only while no record covers it; an entry this shard
    /// ran whole is never probed, since nothing it awaits is a core.
    #[test]
    fn a_leg_entry_is_probeable_past_its_deadline_until_a_record_covers_it() {
        let mut ledger = Ledger::new(LOCAL);
        let leg = tx(4, 60_000);
        let whole = tx(5, 60_000);
        commit_as(&mut ledger, &leg, &classified());
        commit(&mut ledger, &whole);
        ledger.certify(leg.hash(), Certified::ByExecution);
        ledger.certify(whole.hash(), Certified::ByExecution);

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let questions = ledger.questions(&ShardTrie::uniform(1));
        let (consumer, claim) = core_claim(&classified());
        let (_, decline) = core_decline(&classified());
        let question = |key, probed| Question {
            tx_hash: leg.hash(),
            shard: PARTNER,
            key,
            probed,
            deadline: Deadline::of(ms(60_000)),
        };
        assert_eq!(
            questions,
            vec![
                question(core_cell(PARTNER, &leg), Probed::Core),
                question(claim, Probed::Claim),
                question(decline, Probed::Decline),
            ],
            "the leg asks the core for its committed cell and both its answers, and the whole \
             entry asks nothing"
        );
        assert_eq!(consumer, PARTNER);
        assert!(
            questions
                .iter()
                .all(|question| !question.open_at(deadline.minus(Duration::from_millis(1)))),
            "before the deadline the core may still commit"
        );
        assert!(
            questions.iter().all(|question| question.open_at(deadline)),
            "at the deadline the leg is asked about"
        );

        ledger.record_reading(
            leg.hash(),
            PARTNER,
            core_cell(PARTNER, &leg),
            Probed::Core,
            Inclusion::Absent,
        );
        assert!(
            ledger.questions(&ShardTrie::uniform(1)).is_empty(),
            "a covered entry is asked about once"
        );
        assert_eq!(
            ledger.reclaimable().len(),
            1,
            "and the record licenses the reclaim"
        );
    }

    /// A leg whose counterpart is a delivery is probeable past the
    /// deadline like any other and carries the claim cells the probe
    /// asks about; what covers it is the core's committed cell read
    /// absent, and a claim read absent covers nothing.
    ///
    /// The two readings are not interchangeable and only one of them is
    /// evidence: a committed cell is written at inclusion and by nothing
    /// else, so its absence says the core never took the transaction; a
    /// claim is written by the execution that takes the
    /// crossing, so its absence says only that nobody has taken it yet.
    /// [`Probed::read`] admits the first and refuses the second, and
    /// [`Ledger::record_reading`] is held to the same rule so an entry
    /// cannot hold an absence that answers nothing.
    #[test]
    fn a_leg_delivered_elsewhere_is_probeable_with_its_claims() {
        let mut ledger = Ledger::new(LOCAL);
        let leg = tx(6, 60_000);
        commit_as(&mut ledger, &leg, &delivering());
        ledger.certify(leg.hash(), Certified::ByExecution);

        let (delivered_by, claim) = delivered_claim(&delivering());
        let question = |shard, key, probed| Question {
            tx_hash: leg.hash(),
            shard,
            key,
            probed,
            deadline: Deadline::of(ms(60_000)),
        };
        assert_eq!(delivered_by, DELIVERER);
        assert_eq!(
            ledger.questions(&delivery_trie()),
            vec![
                question(BEARER, core_cell(BEARER, &leg), Probed::Core),
                question(DELIVERER, claim, Probed::Claim),
            ],
        );
        assert!(
            !ledger.record_reading(
                leg.hash(),
                DELIVERER,
                claim,
                Probed::Claim,
                Inclusion::Absent,
            ),
            "a claim read absent answers nothing, so the entry does not hold it",
        );
        assert_eq!(
            ledger.questions(&delivery_trie()).len(),
            2,
            "and the questions both stand, because neither was answered",
        );
        assert!(
            ledger.reclaimable().is_empty(),
            "nothing licenses the reclaim on a silence",
        );

        assert!(
            ledger.record_reading(
                leg.hash(),
                BEARER,
                core_cell(BEARER, &leg),
                Probed::Core,
                Inclusion::Absent,
            ),
            "the core's committed cell absent is the reading that answers",
        );
        assert!(
            ledger.questions(&delivery_trie()).is_empty(),
            "covered once"
        );
        assert_eq!(ledger.reclaimable().len(), 1, "and it licenses the reclaim");
    }

    /// An issuer in the core is released by its own verdict like any
    /// entry — unless it accepted with deliveries owed, when it stays on
    /// as a remainder: never abandoned, named by no departure, probed
    /// past the deadline for its claims, and released by the reclaim's
    /// finalization.
    ///
    /// **A remainder asks one question and a silence never answers it.**
    /// Its only question is its delivery's claim, whose absence says
    /// nothing at any anchor — so nothing a clock reaches covers it, and
    /// the one thing that does is a departure naming the transaction:
    /// the chain that was to deliver is gone, so no claim is coming from
    /// anywhere. The crossing behind it is owed, and an owed crossing is
    /// never credited back — the reclaim this licenses releases the
    /// entry and leaves the record standing.
    #[test]
    fn an_issuer_that_accepted_stays_on_as_a_remainder_for_its_deliveries() {
        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let resolved = |decision| {
            let tx = tx(8, 60_000);
            let mut ledger = Ledger::new(LOCAL);
            commit_as(&mut ledger, &tx, &issuing());
            ledger.certify(tx.hash(), Certified::ByExecution);
            let finalization = make_finalization(BlockHeight::new(1), tx.hash(), decision);
            ledger.release_resolved(&[Arc::new(Verifiable::from(finalization))]);
            (ledger, tx)
        };

        let (ledger, _) = resolved(TransactionDecision::Reject);
        assert_eq!(ledger.len(), 0, "a refusal issued nothing to reclaim");

        let (mut ledger, tx) = resolved(TransactionDecision::Accept);
        assert_eq!(ledger.len(), 1, "an acceptance stays for the reclaim");
        assert!(ledger.past_deadline(deadline).is_empty(), "never abandoned");
        assert!(
            ledger.outstanding_with(PARTNER, ms(70_000)).is_empty(),
            "named by no departure: the successor still delivers"
        );
        let (delivered_by, claim) = delivered_claim(&issuing());
        assert_eq!(
            ledger.questions(&ShardTrie::uniform(1)),
            vec![Question {
                tx_hash: tx.hash(),
                shard: delivered_by,
                key: claim,
                probed: Probed::Claim,
                deadline: Deadline::of(ms(60_000)),
            }],
            "a remainder asks about its deliveries, and never about itself"
        );
        assert!(
            !ledger.record_reading(
                tx.hash(),
                delivered_by,
                claim,
                Probed::Claim,
                Inclusion::Absent
            ),
            "the delivery's silence answers nothing, so the entry does not hold it",
        );
        assert!(
            ledger.reclaimable().is_empty(),
            "and a remainder is never reclaimed on a delivery that has not spoken",
        );

        let cut = ms(500_000);
        ledger.record_terminal(delivered_by, cut, Some(expiry(cut)));
        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            delivered_by,
            cut,
            [names(&tx)],
        )]);
        let reclaims = ledger.reclaimable();
        assert_eq!(
            reclaims.len(),
            1,
            "the departure of the chain that was to deliver is what covers it",
        );
        assert!(
            reclaims[0].charged,
            "the issuer ran, so its reclaim is charged nothing"
        );
        ledger.admit_reclaim(tx.hash());
        let finalization =
            make_finalization(BlockHeight::new(2), tx.hash(), TransactionDecision::Accept);
        ledger.release_resolved(&[Arc::new(Verifiable::from(finalization))]);
        assert_eq!(ledger.len(), 0, "the reclaim's finalization releases it");
    }

    /// A leg's own finalization bears no verdict on the transaction, so
    /// it releases nothing, and the entry is never abandoned — not at its
    /// deadline, and not when a committed record names it.
    #[test]
    fn a_leg_entry_outlives_its_own_finalization_and_is_never_abandoned() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(4, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);

        let own = make_leg_finalization(BlockHeight::new(1), tx.hash());
        ledger.release_resolved(&[Arc::new(Verifiable::from(own))]);
        assert_eq!(ledger.len(), 1, "the leg's finalization decides nothing");

        let past = ms(60_000)
            .plus(MAX_FINALIZATION_DELAY)
            .plus(Duration::from_secs(1));
        assert!(
            ledger.past_deadline(past).is_empty(),
            "a leg is never abandoned"
        );

        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(1_000),
            [names(&tx)],
        )]);
        assert!(
            ledger.past_deadline(past).is_empty(),
            "a record licenses a reclaim of it, never an abort"
        );
        assert_eq!(ledger.len(), 1);
    }

    /// A reclaim charges the price only where no committed finalization
    /// of this shard's did: a leg admitted to a tick that was discarded
    /// before its finalization committed burned nothing, so its reclaim
    /// carries the price; once the leg's own finalization commits, the
    /// price is settled and the reclaim charges nothing.
    #[test]
    fn a_reclaim_charges_what_no_committed_finalization_settled() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(7, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);
        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(1_000),
            [names(&tx)],
        )]);
        assert!(
            !ledger.reclaimable()[0].charged,
            "admission to a tick settles nothing"
        );

        let own = make_leg_finalization(BlockHeight::new(1), tx.hash());
        ledger.release_resolved(&[Arc::new(Verifiable::from(own))]);
        assert!(
            ledger.reclaimable()[0].charged,
            "the leg's committed finalization settled the price"
        );
    }

    /// What a finalization's name means is a property of the entry it
    /// names: a leg's own success is the leg finalizing, its failure the
    /// verdict, and a deciding success on a leg entry the reclaim —
    /// whose meaning is the record's: refused, or never taken.
    #[test]
    fn a_finalizations_name_resolves_by_the_entry_it_names() {
        let fw = |ledger: &Ledger, finalization: Finalization| {
            ledger.resolutions_of(&[Arc::new(Verifiable::from(finalization))])
        };
        let h = BlockHeight::new(1);
        let decided = |tx: &Arc<Verifiable<Transaction>>, decision| {
            vec![(tx.hash(), TxResolution::Decided(decision))]
        };

        let mut ledger = Ledger::new(LOCAL);
        let whole = tx(1, 60_000);
        commit(&mut ledger, &whole);
        assert_eq!(
            fw(
                &ledger,
                make_finalization(h, whole.hash(), TransactionDecision::Reject)
            ),
            decided(&whole, TransactionDecision::Reject),
            "a whole member's verdict is the transaction's"
        );

        let leg = tx(2, 60_000);
        commit_as(&mut ledger, &leg, &classified());
        assert_eq!(
            fw(&ledger, make_leg_finalization(h, leg.hash())),
            vec![(leg.hash(), TxResolution::LegFinalized)],
            "a leg's success is its own state"
        );
        assert_eq!(
            fw(
                &ledger,
                make_finalization(h, leg.hash(), TransactionDecision::Reject)
            ),
            decided(&leg, TransactionDecision::Reject),
            "a leg's failure is the verdict"
        );
        let reclaim =
            make_finalization(BlockHeight::new(9), leg.hash(), TransactionDecision::Accept);
        assert!(
            fw(&ledger, reclaim.clone()).is_empty(),
            "a deciding success on a leg entry nothing covers says nothing"
        );
        ledger.record_reading(
            leg.hash(),
            PARTNER,
            core_cell(PARTNER, &leg),
            Probed::Core,
            Inclusion::Absent,
        );
        assert_eq!(
            fw(&ledger, reclaim),
            decided(&leg, TransactionDecision::Aborted),
            "the reclaim of a leg its core never took reports an abort"
        );
    }

    /// A reconstructed entry answers "who was party" the same as the
    /// entry it stands in for.
    ///
    /// A validator rotated into a committee never saw the block that
    /// committed the transaction, so it holds no entry until a record
    /// naming it commits and it reconstructs one. That entry is read by
    /// the same derivations the registered one is, and the abandonment's
    /// participant set is one of them — it reaches a `TxOutcome` and so
    /// the receipt root, which two replicas of one shard cannot answer
    /// differently and stay a shard.
    #[test]
    fn a_reconstructed_entry_names_the_same_parties_as_a_registered_one() {
        let tx = tx(8, 60_000);
        // The keyspace has since divided, so `PARTNER` is a departed
        // owner and not the shard the prefix routes to now — which is
        // what makes the dating decide something.
        let trie = ShardTrie::uniform(2);
        let record = AbandonmentRecord::new(PARTNER, ms(70_000), [names(&tx)]);

        // The replica that was seated when the block committed.
        let mut seated = Ledger::new(LOCAL);
        commit(&mut seated, &tx);
        seated.certify(tx.hash(), Certified::ByExecution);
        seated.record_abandonment_records(std::slice::from_ref(&record));

        // The replica rotated in afterwards, which meets the transaction
        // for the first time in the record.
        let mut entrant = Ledger::new(LOCAL);
        entrant.record_abandonment_records(&[record]);

        // A departure between the two instants the entry could be dated
        // by: past the block that committed the transaction, and short
        // of the record that names it. Which of the two the ledger reads
        // is what decides whether the departed shard was party, so both
        // replicas have to read the same one.
        for ledger in [&mut seated, &mut entrant] {
            ledger.record_terminal(PARTNER, ms(65_000), None);
        }

        let parties = seated.counterparts(tx.hash(), &trie);
        assert!(
            !parties.is_empty(),
            "the fixture has to reach beyond this shard, or the two agree on nothing",
        );
        assert_eq!(
            entrant.counterparts(tx.hash(), &trie),
            parties,
            "a rotated-in replica must name the same parties the seated one does, \
             or the abandonment it composes carries a different receipt root",
        );
    }

    /// A claim follows its prefix, so the shard that answers for it
    /// after a cut is the frozen consumer's successor — and its word
    /// licenses the retirement exactly as the consumer's would have.
    ///
    /// [`Ledger::questions`] already asks whoever holds the
    /// prefix now, so a ledger matching the frozen shard by identity
    /// drops the answer to a question it asked itself, and the record
    /// cell outlives the entry.
    #[test]
    fn a_successors_claim_retires_the_record_the_consumer_was_holding() {
        // `PARTNER` splits, and the half that takes the `AWAY` prefixes
        // is the depth-2 leaf on the same path.
        const SUCCESSOR: ShardId = ShardId::leaf(2, 2);

        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);

        let (_, claim) = core_claim(&classified());
        assert!(
            ledger.record_reading(
                tx.hash(),
                SUCCESSOR,
                claim,
                Probed::Claim,
                Inclusion::Present([7; 32]),
            ),
            "the successor's claim answers the question the entry asked",
        );
    }

    /// A committed claim reading the consumer's cell present is what
    /// licenses retiring a leg's records — never a clock, never a
    /// certificate — once every consumer has claimed; the retirement's
    /// own finalization releases the entry, and a claimed entry is
    /// neither reclaimable nor abandonable meanwhile.
    /// A consumer's `Never` read present covers the entry: the reclaim
    /// is licensed, the retirement is not, the entry asks nothing more,
    /// and an absence of the `Never` answers nothing.
    #[test]
    fn a_never_read_present_licenses_the_reclaim() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);
        assert!(
            ledger.reclaimable().is_empty(),
            "nothing reclaims on a clock"
        );

        let (consumer, decline) = core_decline(&classified());
        assert!(
            !ledger.record_reading(
                tx.hash(),
                consumer,
                decline,
                Probed::Decline,
                Inclusion::Absent
            ),
            "the Never absent says only that the consumer has not refused",
        );
        assert!(ledger.record_reading(
            tx.hash(),
            consumer,
            decline,
            Probed::Decline,
            Inclusion::Present([7; 32]),
        ));
        let reclaimable = ledger.reclaimable();
        assert_eq!(
            reclaimable.len(),
            1,
            "the consumer's own word licenses the reclaim"
        );
        assert_eq!(reclaimable[0].tx_hash, tx.hash());
        assert!(
            ledger.questions(&ShardTrie::uniform(1)).is_empty(),
            "and the entry asks nothing more"
        );
    }

    /// The commit fold closes a leg entry once every record it issued
    /// here has been removed on its consumer's `Taken`: the close is the
    /// transaction accepted, reported once, with no member composed and
    /// no finalization driving it. A record still standing, a reclaim
    /// in flight, or evidence covering the entry keeps it open.
    #[test]
    fn a_settled_record_closes_the_entry_with_an_accept() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);
        let record = classified()
            .crossings()
            .find(|(edge, _)| edge.from == LOCAL)
            .map(|(edge, _)| edge.crossing.id.record_key(&ProtocolHasher))
            .expect("the leg issues one crossing");
        assert!(ledger.closes().is_empty(), "nothing closes on a clock");

        ledger.settled(record);
        assert_eq!(
            ledger.closes(),
            vec![(
                tx.hash(),
                TxResolution::Decided(TransactionDecision::Accept)
            )],
            "every record issued here was taken: the transaction was accepted",
        );
        assert_eq!(ledger.len(), 0, "and the fold's close releases the entry");
        assert!(ledger.closes().is_empty(), "reported once");

        // A reclaim in flight keeps the entry for the reclaim's own
        // finalization.
        let mut reclaiming = Ledger::new(LOCAL);
        commit_as(&mut reclaiming, &tx, &classified());
        reclaiming.admit_reclaim(tx.hash());
        reclaiming.settled(record);
        assert!(reclaiming.closes().is_empty());
        assert_eq!(reclaiming.len(), 1);
    }

    /// A mixed shard's entry, issuing on one side of the core and taking
    /// delivery on the other, closes on its records alone: what the core
    /// returns to it is its commit fold's credit and owes the entry
    /// nothing.
    #[test]
    fn a_mixed_shards_entry_closes_on_its_records_alone() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.seed(tx.hash(), Part::leg(Kept::of(&tx, &classified())));
        let record = classified()
            .crossings()
            .find(|(edge, _)| edge.from == LOCAL)
            .map(|(edge, _)| edge.crossing.id.record_key(&ProtocolHasher))
            .expect("the leg issues one crossing");
        ledger.settled(record);
        assert_eq!(
            ledger.closes(),
            vec![(
                tx.hash(),
                TxResolution::Decided(TransactionDecision::Accept)
            )],
        );
    }

    /// A leg that failed is the transaction's end on this shard: its
    /// finalization decides, and with nothing issued there is nothing
    /// to reclaim, so the entry goes with it — body and all — and no
    /// record can license a reclaim of it afterwards.
    #[test]
    fn a_failed_legs_own_finalization_releases_its_entry() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(5, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);

        let own = make_finalization(BlockHeight::new(1), tx.hash(), TransactionDecision::Reject);
        ledger.release_resolved(&[Arc::new(Verifiable::from(own))]);
        assert_eq!(ledger.len(), 0, "a failed leg's finalization decides it");
        assert!(
            ledger.owed.values().all(|owed| owed.part.kept().is_none()),
            "and the body goes with it"
        );

        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(1_000),
            [names(&tx)],
        )]);
        assert!(
            ledger.reclaimable().is_empty(),
            "a record naming it afterwards rebuilds an entry with no body to reclaim from"
        );
    }

    /// A committed record is what makes a leg entry reclaimable — never a
    /// clock — and the reclaim's own finalization is what releases it,
    /// body and all.
    #[test]
    fn a_record_licenses_the_reclaim_and_its_finalization_releases_the_entry() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(6, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash(), Certified::ByExecution);
        assert!(
            ledger.reclaimable().is_empty(),
            "nothing is reclaimed on a clock"
        );

        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(1_000),
            [names(&tx)],
        )]);
        let reclaimable = ledger.reclaimable();
        assert_eq!(
            reclaimable.len(),
            1,
            "a committed record licenses the reclaim"
        );
        assert_eq!(reclaimable[0].tx_hash, tx.hash());
        assert_eq!(
            reclaimable[0].body.hash(),
            tx.hash(),
            "with the body the reclaim derives from"
        );

        ledger.admit_reclaim(tx.hash());
        assert!(ledger.reclaimable().is_empty(), "a tick has taken it");
        let reclaim =
            make_finalization(BlockHeight::new(9), tx.hash(), TransactionDecision::Accept);
        ledger.release_resolved(&[Arc::new(Verifiable::from(reclaim))]);
        assert_eq!(ledger.len(), 0, "the reclaim's finalization releases it");
        assert!(
            ledger.owed.values().all(|owed| owed.part.kept().is_none()),
            "and the body goes with it"
        );
    }

    /// A reclaim reports what covered the leg: a departed core aborts
    /// the transaction, and a lapsed delivery says nothing of it, since
    /// the core accepted and its certificates say so.
    #[test]
    fn a_reclaim_reports_what_covered_the_leg() {
        let mut ledger = Ledger::new(LOCAL);
        let reclaim_of = |ledger: &Ledger, tx: &Arc<Verifiable<Transaction>>| {
            ledger.resolutions_of(&[Arc::new(Verifiable::from(make_finalization(
                BlockHeight::new(9),
                tx.hash(),
                TransactionDecision::Accept,
            )))])
        };

        let departed = tx(4, 60_000);
        commit_as(&mut ledger, &departed, &classified());
        ledger.record_abandonment_records(&[AbandonmentRecord::new(
            PARTNER,
            ms(1_000),
            [names(&departed)],
        )]);
        assert_eq!(
            reclaim_of(&ledger, &departed),
            vec![(
                departed.hash(),
                TxResolution::Decided(TransactionDecision::Aborted)
            )],
            "the reclaim of a leg whose core left reports an abort"
        );

        let lapsed = tx(5, 60_000);
        commit_as(&mut ledger, &lapsed, &delivering());
        let (_, claim) = delivered_claim(&delivering());
        ledger.record_reading(
            lapsed.hash(),
            DELIVERER,
            claim,
            Probed::Claim,
            Inclusion::Absent,
        );
        assert!(
            reclaim_of(&ledger, &lapsed).is_empty(),
            "a lapse reclaim says nothing: the core accepted, and its certificates say so"
        );
    }

    /// A core member whose sibling's committed cell was read absent is
    /// covered by the claim alone: abandonable at once, and held until
    /// the horizon past which nothing can be composed — not dropped as a
    /// strand at the next commit, since the sibling never departed.
    #[test]
    fn a_core_member_covered_by_a_siblings_absence_lives_to_its_horizon() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &two_shard_core());
        ledger.certify(tx.hash(), Certified::ByExecution);
        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let past = deadline.plus(MAX_VALIDITY_RANGE);
        assert!(!ledger.is_covered(tx.hash()));
        assert!(
            ledger.past_deadline(past).is_empty(),
            "past the abandon window the shard no longer speaks for it on its own clock"
        );

        let sibling = core_cell(SIBLING, &tx);
        ledger.record_reading(tx.hash(), SIBLING, sibling, Probed::Core, Inclusion::Absent);
        assert!(ledger.is_covered(tx.hash()));
        assert_eq!(
            ledger.past_deadline(past),
            vec![abandons(&tx)],
            "the sibling's silence says nothing can settle it, so the shard may"
        );
        assert!(
            ledger.prune(past).is_empty(),
            "a live sibling's silence is no strand"
        );
        assert_eq!(ledger.len(), 1, "and the entry stands for the abort");
        let horizon = Window::LegEntry.of(Deadline::of(ms(60_000))).end;
        ledger.prune(horizon);
        assert_eq!(ledger.len(), 0, "gone where nothing can be composed for it");
    }

    /// A leg entry dies where its evidence does: at its horizon the claim
    /// cell both its members are proved against is swept, so neither the
    /// reclaim nor the retirement can be composed past it, whatever a
    /// record says. Short of it only the finalization that decides it
    /// ends it, and a record covering it neither extends nor shortens it.
    #[test]
    fn a_leg_entry_dies_where_its_evidence_does() {
        let horizon = Window::LegEntry.of(Deadline::of(ms(60_000))).end;
        for covered in [false, true] {
            let mut ledger = Ledger::new(LOCAL);
            let tx = tx(5, 60_000);
            commit_as(&mut ledger, &tx, &classified());
            ledger.certify(tx.hash(), Certified::ByExecution);
            if covered {
                ledger.record_abandonment_records(&[AbandonmentRecord::new(
                    PARTNER,
                    ms(1_000),
                    [names(&tx)],
                )]);
            }
            assert!(
                ledger
                    .prune(horizon.minus(Duration::from_millis(1)))
                    .is_empty()
            );
            assert_eq!(
                ledger.len(),
                1,
                "covered={covered}: it stands short of its horizon"
            );
            assert!(
                ledger.prune(horizon).is_empty(),
                "covered={covered}: and leaks no reservation going"
            );
            assert_eq!(ledger.len(), 0, "covered={covered}: gone at its horizon");
            assert!(
                ledger.owed.values().all(|owed| owed.part.kept().is_none()),
                "covered={covered}: and the body goes with it"
            );
        }
    }
}
