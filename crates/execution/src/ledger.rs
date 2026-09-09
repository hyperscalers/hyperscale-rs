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

use hyperscale_engine::legs::{Classified, Licence};
use hyperscale_storage::committed_tx_cell_key;
use hyperscale_types::{
    AbandonmentRecord, Deadline, Finalization, Inclusion, MAX_VALIDITY_RANGE, Probed, RoutePrefix,
    ShardId, ShardTrie, SubstateKey, Transaction, TransactionDecision, TxHash, TxResolution,
    UnsettledTx, Verifiable, Verified, WeightedTimestamp, Window,
};

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
    /// Whether a tick of this shard's took the transaction as a member.
    ///
    /// What it answers is whether a certificate of ours is out where a
    /// counterpart could settle against it, which is what decides whether
    /// this shard may speak for the transaction alone. The account is
    /// where it belongs rather than the tick that produced it: the
    /// certificate outlives the tick, and a shard that could not say
    /// whether it had issued one would have to assume it had.
    certified: bool,
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
    /// Where a consumer's certificate spoke a claiming success for this
    /// transaction, if one has.
    ///
    /// The cue to ask, never the answer. A certificate says a
    /// counterpart's execution succeeded; whether it wrote the claim its
    /// success promises is a question about that shard's committed
    /// state, and only its state answers. Opening the probe here rather
    /// than at the deadline is what keeps a retirement as prompt as that
    /// state can show it, which is one [`CLAIM_VISIBILITY_LAG`](hyperscale_types::CLAIM_VISIBILITY_LAG) past the
    /// anchor kept here.
    cued: Option<WeightedTimestamp>,
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
    /// Whether the chain read `claim` present on some shard: the
    /// consumer holds the crossing the cell was asked about.
    fn claimed(&self, claim: SubstateKey) -> bool {
        self.readings.iter().any(|(&(_, key), reading)| {
            key == claim && matches!(reading.inclusion, Inclusion::Present(_))
        })
    }

    /// The questions the chain read absent, each an answer that the
    /// counterpart asked can never settle the transaction.
    fn absences(&self) -> impl Iterator<Item = Probed> + '_ {
        self.readings.values().filter_map(|reading| {
            matches!(reading.inclusion, Inclusion::Absent).then_some(reading.probed)
        })
    }

    /// Whether the chain has established that no counterpart can settle
    /// the transaction: a departed shard's record names it, or a cell a
    /// counterpart would have written was read absent inside its
    /// window. Either licenses the abandonment or the reclaim, and puts
    /// every question the entry asks to rest.
    fn covered(&self) -> bool {
        self.departed_by.is_some() || self.absences().next().is_some()
    }

    /// What the evidence covering the entry established of the
    /// transaction, where it established a verdict at all: a departure
    /// or a core's committed cell absent says the core never took it,
    /// which aborts the transaction; a delivery's claim absent says only
    /// that the delivery lapsed, and the core decided.
    fn abandoned_verdict(&self) -> Option<TransactionDecision> {
        (self.departed_by.is_some() || self.absences().any(|probed| matches!(probed, Probed::Core)))
            .then_some(TransactionDecision::Aborted)
    }

    /// The moment the entry stops being settleable and becomes the
    /// shard's to abandon: the transaction's deadline, or for a delivery
    /// the close of its window, past which the crossing it would claim
    /// lapses and its issuer may reclaim it.
    fn opens(&self) -> WeightedTimestamp {
        if self.part.is_delivery() {
            Window::Delivery.of(self.figures.deadline).end
        } else {
            self.figures.deadline.at()
        }
    }

    /// Where a tick may abandon the entry: from its opening, for the one
    /// validity range every abandonment gets to commit.
    fn abandon_window(&self) -> Range<WeightedTimestamp> {
        let opens = self.opens();
        opens..opens.plus(MAX_VALIDITY_RANGE)
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
    pub tx_hash: TxHash,
    /// Whether a committed record had named it unsettled by a departed
    /// counterpart.
    pub covered_by_record: bool,
}

/// What this shard's part in a transaction is, which decides what the
/// entry waits on and what ends it.
///
/// Two of the parts hold nothing beyond their account: a whole shape
/// and a delivery are decided by their own finalization or abandoned at
/// their window. The rest keep the body and the classification a
/// settlement is composed from, and a leg entry — a leg's, or a
/// resolved issuer's — keeps beside them where that settlement stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// This shard's verdict is the transaction's, or a share of it: the
    /// entry is abandonable at its deadline and released by that
    /// verdict.
    Whole,
    /// This shard only delivers: a leg outside the core that bears no
    /// verdict and issues nothing, admissible to the delivery window's
    /// close, which is its deadline. Abandoned there like a whole entry
    /// — and, unlike one, out of any tick still holding it, since past
    /// the close the crossing it would claim lapses and its issuer may
    /// reclaim it.
    Delivery,
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
    /// Which tick of this shard's has taken the entry's records — a
    /// reclaim or a retirement — so the finalization naming the hash
    /// next is that member's.
    taken: Option<Licence>,
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
            taken: None,
            charged,
        }
    }
}

impl Part {
    /// A whole entry.
    pub(crate) const fn whole() -> Self {
        Self::Whole
    }

    /// A delivery.
    pub(crate) const fn delivery() -> Self {
        Self::Delivery
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

    /// Whether the entry only delivers.
    const fn is_delivery(&self) -> bool {
        matches!(self, Self::Delivery)
    }

    /// Whether a core issuer still holds crossings its deliveries owe a
    /// claim for, so its verdict resolves the transaction and leaves the
    /// entry standing for the reclaim.
    fn issued(&self, local: ShardId) -> bool {
        match self {
            Self::Core(kept) => !kept.deliveries(local).is_empty(),
            Self::Whole | Self::Delivery | Self::Leg(_) | Self::Remainder(_) => false,
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
    /// records on `licence`.
    const fn take(&mut self, licence: Licence) {
        if let Some(held) = self.held_mut() {
            held.taken = Some(licence);
        }
    }

    /// The licence a tick has taken a leg entry's records on, if one
    /// has.
    const fn taken(&self) -> Option<Licence> {
        match self.held() {
            Some(held) => held.taken,
            None => None,
        }
    }

    /// What a leg entry holds, where the entry is one.
    const fn held(&self) -> Option<&LegEntry> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(held),
            Self::Whole | Self::Delivery | Self::Core(_) => None,
        }
    }

    const fn held_mut(&mut self) -> Option<&mut LegEntry> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(held),
            Self::Whole | Self::Delivery | Self::Core(_) => None,
        }
    }

    /// What the entry keeps beside its account, where it keeps anything.
    const fn kept(&self) -> Option<&Kept> {
        match self {
            Self::Leg(held) | Self::Remainder(held) => Some(&held.kept),
            Self::Core(kept) => Some(kept),
            Self::Whole | Self::Delivery => None,
        }
    }

    /// The part `local` plays in a transaction frozen as `classified`,
    /// with the body it keeps where it keeps one.
    ///
    /// Read off the classification the committing block froze, at the
    /// same commit, so a rebuilt ledger marks the same entries: the
    /// freeze is a function of the block and the placement it committed
    /// under, and the replay re-freezes both.
    ///
    /// Classifies **a shard's one entry**, which covers both members a
    /// shard may run, and so asks `only_delivers_at` — every leg here is
    /// a delivery — rather than any member's side. Not the same question
    /// as [`Membership::of`](crate::tick_state::Membership::of), whose
    /// branch looks alike and answers `Delivery` for the delivering
    /// member of a shard this calls a leg. A shard with legs on both
    /// sides of the core holds one entry, and it is the leg's: the
    /// delivering member bears no verdict and owes no reclaim, so an
    /// entry marked `Delivery` for it would abandon at the delivery
    /// window's close what the leg is still owed a reclaim of.
    fn of(local: ShardId, tx: &Arc<Verifiable<Transaction>>, classified: &Classified) -> Self {
        if !classified.decomposed() {
            return Self::whole();
        }
        let in_core = classified.core().contains(&local);
        if !in_core && classified.only_delivers_at(local) {
            return Self::delivery();
        }
        // Block-container entries decoded from the wire land as
        // `Unverified`; lift via `from_persisted` under the same
        // BFT-transitive trust that gates the containing block. Honest
        // live-consensus blocks already carry `Verified` entries.
        let body: Arc<Verified<Transaction>> = match (**tx).clone().into_verified() {
            Ok(verified) => Arc::new(verified),
            Err(raw) => Arc::new(Verified::<Transaction>::from_persisted(raw)),
        };
        let kept = Kept {
            body,
            classified: classified.clone(),
        };
        if in_core {
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
    pub body: Arc<Verified<Transaction>>,
    /// The classification the committing block froze, which every cell
    /// the entry asks about and every scope a settlement runs under is
    /// read off.
    pub classified: Classified,
}

impl Kept {
    /// Whose refusal is the transaction's, and whose committed cells a
    /// probe asks about. An issuer in the core holds the core it is
    /// part of, itself included; the prober skips this shard, since
    /// what it has committed is not something it fetches a proof of.
    /// Empty for a shape with no core.
    const fn core(&self) -> &BTreeSet<ShardId> {
        self.classified.core()
    }

    /// The claim cells deliveries elsewhere write for the crossings
    /// `local` issued, each under the shard that was to deliver it when
    /// the transaction committed — what a lapse probe asks about once
    /// the delivery window has closed. The cell follows its prefix to a
    /// departed deliverer's successor, which [`Ledger::questions`]
    /// resolves off the trie it is given.
    fn deliveries(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.classified.delivered_claims(local)
    }

    /// The claim cells core consumers write for the crossings a leg on
    /// `local` issued, each under the shard holding the consumer's
    /// target — what a probe asks the core about, and whose presence
    /// licenses the retirement. Empty for a core shard: a leg beside the
    /// core is the core's, so nothing a core shard produces is claimed
    /// by a core it is not in.
    fn claims(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        self.classified.core_claims(local)
    }

    /// Every claim cell a consumer elsewhere writes for what `local`
    /// issued, whichever side consumes it.
    fn every_claim(&self, local: ShardId) -> Vec<(ShardId, SubstateKey)> {
        let mut claims = self.claims(local);
        claims.extend(self.deliveries(local));
        claims
    }
}

/// A leg entry a committed record has licensed a settlement of, with
/// what the settlement is composed from.
///
/// One shape for both, because the terms are the same ones: which
/// records, off which body, under which classification, and whether the
/// price is still owed. What differs is the licence, which is the
/// selector's — [`Ledger::reclaimable`] or
/// [`Ledger::retirable`] — and not a field here.
#[derive(Debug, Clone)]
pub struct Settleable {
    /// The transaction.
    pub tx_hash: TxHash,
    /// Its body, which the settlement's edges derive from.
    pub body: Arc<Verified<Transaction>>,
    /// The classification its committing block froze.
    pub classified: Classified,
    /// Whether a committed finalization of this shard's settled the
    /// price, so the settlement charges nothing.
    ///
    /// Always true for a retirable entry — a resolved issuer is charged
    /// where it resolves, and a leg is charged when its own finalization
    /// commits, which is before a retirement can be composed for it — so
    /// only a reclaim ever reads a `false` here.
    pub charged: bool,
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
    pub tx_hash: TxHash,
    /// The counterpart the question is put to.
    pub shard: ShardId,
    /// The cell it asks about.
    pub key: SubstateKey,
    /// Which question it is.
    pub probed: Probed,
    /// The entry's deadline, which every window an answer is held to
    /// is read off.
    pub deadline: Deadline,
    /// Where a consumer's claiming success was spoken, if one has been
    /// heard: the anchor that opens a presence question ahead of the
    /// deadline, and that the cell it asks about becomes readable one
    /// [`CLAIM_VISIBILITY_LAG`](hyperscale_types::CLAIM_VISIBILITY_LAG) past.
    pub cued: Option<WeightedTimestamp>,
}

impl Question {
    /// Whether the question is worth putting at `now`, the chain's
    /// committed clock: past the deadline, or cued by a consumer's
    /// claiming success. The deadline opens the absence — before it the
    /// core may still legitimately commit, so absence says nothing —
    /// and the cue opens the presence, which needs no window at all.
    #[must_use]
    pub fn open_at(self, now: WeightedTimestamp) -> bool {
        self.deadline.passed(now) || self.cued.is_some()
    }
}

/// What one name on a committed finalization means for the entry it
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meaning {
    /// The retirement's: every consumer claimed, so the transaction was
    /// accepted, whatever this member's own outcome says of the records.
    Retired,
    /// A leg finalizing here without deciding: it ran, and the core
    /// decides the transaction.
    LegRan,
    /// A delivery that succeeded claimed what an accepted core issued,
    /// which is the verdict.
    Delivered,
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
        Some(owed) if owed.part.taken() == Some(Licence::Claimed) => Meaning::Retired,
        _ if !deciding => {
            if accepted && owed.is_some_and(|owed| owed.part.is_delivery()) {
                Meaning::Delivered
            } else {
                Meaning::LegRan
            }
        }
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
    pub const fn new(local: ShardId) -> Self {
        Self {
            local,
            owed: BTreeMap::new(),
            departed: BTreeMap::new(),
        }
    }

    /// The shard whose account this is.
    #[must_use]
    pub const fn local(&self) -> ShardId {
        self.local
    }

    /// The share of `owed`'s reach that is somebody else's — the routes
    /// this shard does not own.
    ///
    /// Who was party to the transaction is a question about these and
    /// the trie of the moment, and the trie of the moment is not
    /// something a rebuild can recover — windows evict, and a shard that
    /// has since split answers for a keyspace it no longer owns. The
    /// routes are the transaction's own, and [`UnsettledTx::reach`]
    /// states them, so this reaches the same set from the committing
    /// block and from a record naming the transaction alike — which is
    /// what a replica rotated in after that block has.
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
    /// Idempotent per transaction: a hash cannot commit twice within its
    /// own validity window, and re-registering one must not move the
    /// deadline it was admitted under.
    pub fn register_committed<'a>(
        &mut self,
        members: impl IntoIterator<Item = (&'a Arc<Verifiable<Transaction>>, &'a Classified)>,
    ) {
        for (tx, classified) in members {
            let owed = Owed {
                figures: UnsettledTx::for_transaction(tx),
                certified: false,
                part: Part::of(self.local, tx, classified),
                departed_by: None,
                cued: None,
                accepted: BTreeSet::new(),
                readings: BTreeMap::new(),
            };
            self.owed.entry(tx.hash()).or_insert(owed);
        }
    }

    /// What the chain read of `key` on `shard` for `tx_hash`, once it
    /// has read it.
    #[cfg(test)]
    pub fn reading(&self, tx_hash: TxHash, shard: ShardId, key: SubstateKey) -> Option<Inclusion> {
        let reading = self.owed.get(&tx_hash)?.readings.get(&(shard, key))?;
        Some(reading.inclusion)
    }

    /// Give a registered entry the part a fixture wants it to play,
    /// where the block that committed it froze another.
    #[cfg(test)]
    pub fn seed(&mut self, tx_hash: TxHash, part: Part) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.part = part;
        }
    }

    /// The core set of a leg entry — whose refusal is the transaction's.
    /// `None` for anything but a leg entry this ledger holds.
    #[must_use]
    pub fn leg_core(&self, tx_hash: TxHash) -> Option<&BTreeSet<ShardId>> {
        self.owed
            .get(&tx_hash)
            .and_then(|owed| owed.part.kept())
            .map(Kept::core)
    }

    /// Whether `shard` is one of the transaction's core — whose refusal
    /// is the transaction's, and whose word is worth mirroring at all.
    #[must_use]
    pub fn core_holds(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.leg_core(tx_hash)
            .is_some_and(|core| core.contains(&shard))
    }

    /// Whether `shard` consumes a crossing this shard issued for the
    /// transaction — a core consumer's or a delivery's — so that its
    /// acceptance is the claim the record here was held for.
    ///
    /// Matched on the claim's prefix rather than on the shard the
    /// commit froze, because a claim cell follows its prefix across a
    /// cut and the prober already asks whoever holds it now. Reading the
    /// frozen shard alone would drop the successor's answer to the
    /// question this ledger asked it.
    #[must_use]
    pub fn consumer_holds(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        let kept = self.owed.get(&tx_hash).and_then(|owed| owed.part.kept());
        kept.is_some_and(|kept| {
            kept.every_claim(self.local)
                .iter()
                .any(|(_, claim)| ShardTrie::shard_owns_prefix(shard, claim.owner))
        })
    }

    /// Mirror a core shard's acceptance, and say whether it was the last
    /// the transaction was waiting on.
    ///
    /// A core shard's tick closes on every other core shard's
    /// certificate, so one saying it succeeded is not the transaction
    /// accepted: that is every core shard saying so.
    pub fn record_acceptance(&mut self, tx_hash: TxHash, shard: ShardId) -> bool {
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
    /// cell was already read, or the transaction is not held here, and
    /// a later claim adds nothing.
    pub fn record_reading(
        &mut self,
        tx_hash: TxHash,
        shard: ShardId,
        key: SubstateKey,
        probed: Probed,
        inclusion: Inclusion,
    ) -> bool {
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

    /// Note that a consumer's certificate spoke a claiming success for
    /// `tx_hash` at `at`, which opens its probe.
    ///
    /// The anchor is kept rather than a flag: it is where the writing
    /// execution ran, so it is what the probe holds its own anchor to,
    /// and every member reads it off the same certificate. Where more
    /// than one consumer speaks, the earliest stands — the entry is
    /// asked about as soon as any cell it waits on could be there.
    pub fn cue_probe(&mut self, tx_hash: TxHash, at: WeightedTimestamp) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.cued = Some(owed.cued.map_or(at, |cued| cued.min(at)));
        }
    }

    /// Every question this ledger has open, under `trie`, whatever the
    /// clock: for each entry nothing has answered for, each other core
    /// shard's committed cell, each delivery's claim on the shard that
    /// was to deliver it and on whatever shard holds the cell's prefix
    /// now, and each core consumer's claim on the shard holding the
    /// consumer's target and on whatever holds the prefix now — each
    /// less the cells the chain has already read.
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
    pub fn questions(&self, trie: &ShardTrie) -> Vec<Question> {
        let local = self.local;
        let mut questions = Vec::new();
        for (&tx_hash, owed) in &self.owed {
            if owed.covered() {
                continue;
            }
            let Some(kept) = owed.part.kept() else {
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
                    cued: owed.cued,
                })
            };
            // What an entry asks about is what it waits on. A leg waits
            // for the core's verdict and for the crossings it issued to
            // be claimed; a core member waits only for its siblings,
            // whose certificates its own settlement needs. Its
            // deliveries are what it waits on once it has a verdict, as
            // the remainder its acceptance leaves.
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
            for (delivered_by, claim) in kept.deliveries(local) {
                questions.extend(
                    BTreeSet::from([delivered_by, trie.shard_for_prefix(claim.owner)])
                        .into_iter()
                        .filter_map(|shard| question(shard, claim, Probed::Delivery)),
                );
            }
            for (consumer, claim) in kept.claims(local) {
                questions.extend(
                    BTreeSet::from([consumer, trie.shard_for_prefix(claim.owner)])
                        .into_iter()
                        .filter_map(|shard| question(shard, claim, Probed::Claim)),
                );
            }
        }
        questions
    }

    /// Whether this ledger still holds `tx_hash`.
    #[must_use]
    pub fn contains(&self, tx_hash: TxHash) -> bool {
        self.owed.contains_key(&tx_hash)
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
            held.taken.is_none().then_some((*tx_hash, owed, held))
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
    pub fn reclaimable(&self) -> Vec<Settleable> {
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
    pub fn admit_reclaim(&mut self, tx_hash: TxHash) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.part.take(Licence::Unclaimed);
        }
    }

    /// The leg entries committed claims have licensed the retirement of
    /// and no tick has taken yet: every crossing this shard issued has
    /// its claim cell read present on some shard, no record covers the
    /// entry as unsettled, and nothing is taking it back. Read off
    /// committed content alone, like [`Self::reclaimable`], so every
    /// replica composes the same.
    ///
    /// A claim is answered by whoever holds its prefix, which after a
    /// cut is the frozen consumer's successor — the same widening
    /// [`Self::consumer_holds`] makes, and for the same reason — so the
    /// cell is what is held to, not the shard it was read on.
    #[must_use]
    pub fn retirable(&self) -> Vec<Settleable> {
        self.untaken_legs()
            .filter(|(_, owed, _)| !owed.covered())
            .filter_map(|(tx_hash, owed, held)| {
                let claims: Vec<SubstateKey> = held
                    .kept
                    .every_claim(self.local)
                    .into_iter()
                    .map(|(_, claim)| claim)
                    .collect();
                (!claims.is_empty() && claims.iter().all(|claim| owed.claimed(*claim))).then(|| {
                    Settleable {
                        tx_hash,
                        body: Arc::clone(&held.kept.body),
                        classified: held.kept.classified.clone(),
                        charged: held.charged,
                    }
                })
            })
            .collect()
    }

    /// Record that a tick of this shard's has admitted the retirement
    /// of `tx_hash`'s records, so the finalization naming the hash next
    /// is the retirement's and releases the entry.
    pub fn admit_retire(&mut self, tx_hash: TxHash) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.part.take(Licence::Claimed);
        }
    }

    /// Record that a tick of this shard's has taken `tx_hash` as a member,
    /// and so will speak for it in a certificate a counterpart can settle
    /// against.
    pub fn certify(&mut self, tx_hash: TxHash) {
        if let Some(owed) = self.owed.get_mut(&tx_hash) {
            owed.certified = true;
        }
    }

    /// Whether a certificate of this shard's covers `tx_hash` — the
    /// question that decides whether a verdict on it is this shard's alone
    /// to reach. False for a transaction this ledger does not hold, which
    /// is the same answer it gives for one no tick ever took.
    #[must_use]
    pub fn is_certified(&self, tx_hash: TxHash) -> bool {
        self.owed.get(&tx_hash).is_some_and(|owed| owed.certified)
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
    /// A reconstructed entry is `certified`, because a record names
    /// nothing else, and runs whole: it holds no body to reclaim with,
    /// and what a record licenses on a name it never held is the abort.
    ///
    /// Returns how many it reconstructed, which is how far short this
    /// replica's replay window fell — or how long after the block it was
    /// seated, for a validator rotated into the committee. A
    /// reconstructed entry is the entry: the record restates every figure
    /// the transaction fixes and the reach it touches, so what this
    /// derives from it is what a replica that held the block derives.
    pub fn record_abandonment_records(&mut self, records: &[AbandonmentRecord]) -> usize {
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
                        certified: true,
                        part: Part::whole(),
                        departed_by: Some(record.shard()),
                        cued: None,
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
    /// it. Only ones committed before the cut, since a shard that had
    /// already gone was never party to what came after. Only ones no
    /// record covers yet, so a departure is answered once. And never a
    /// remainder: its verdict is in, and a departed deliverer's
    /// successor still delivers what it was owed — only the lapse says a
    /// delivery never will.
    #[must_use]
    pub fn outstanding_with(&self, shard: ShardId, cut: WeightedTimestamp) -> Vec<UnsettledTx> {
        self.owed
            .iter()
            .filter(|(_, owed)| {
                owed.certified
                    && !owed.part.is_remainder()
                    && !owed.covered()
                    && self.party_to_entry(owed, shard, cut)
            })
            .map(|(_, owed)| owed.figures.clone())
            .collect()
    }

    /// The transactions this ledger holds that `shard`, leaving at `cut`,
    /// was party to: what an abandonment record naming this shard's
    /// business with it may name, and nothing else. Wider than
    /// [`Self::outstanding_with`] — an entry no certificate covers, or one
    /// a record already answered, is still one the shard was party to —
    /// so a voter reading it refuses only a stranger.
    #[must_use]
    pub fn party_to(&self, shard: ShardId, cut: WeightedTimestamp) -> BTreeSet<TxHash> {
        self.owed
            .iter()
            .filter(|(_, owed)| self.party_to_entry(owed, shard, cut))
            .map(|(tx_hash, _)| *tx_hash)
            .collect()
    }

    /// Whether this shard only delivers for `tx_hash`, so no outcome of
    /// its own bears the verdict and the lapse is what bounds it.
    #[must_use]
    pub fn is_delivery(&self, tx_hash: TxHash) -> bool {
        self.owed
            .get(&tx_hash)
            .is_some_and(|owed| owed.part.is_delivery())
    }

    /// Whether committed content has established that `tx_hash` can
    /// never settle — the question the split-boundary fence otherwise
    /// puts to a settled set that expires.
    #[must_use]
    pub fn is_covered(&self, tx_hash: TxHash) -> bool {
        self.owed.get(&tx_hash).is_some_and(Owed::covered)
    }

    /// Record where a departed participant's chain ended, and when what it
    /// left stops being readable.
    ///
    /// Idempotent on the cut, which is a property of the schedule rather
    /// than of when this shard got around to reading it. The expiry fills
    /// in when the caller learns it — the beacon stamps the handoff
    /// complete some epochs after the cut — and never moves once set.
    pub fn record_terminal(
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
    pub fn stamp_terminal(&mut self, shard: ShardId, readable_until: WeightedTimestamp) {
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
    pub fn unstamped_departures(&self) -> Vec<ShardId> {
        self.departed
            .iter()
            .filter(|(_, departure)| departure.readable_until.is_none())
            .map(|(shard, _)| *shard)
            .collect()
    }

    /// When the shard that held `prefix` when the transaction committed
    /// left, if it has.
    ///
    /// The earliest recorded terminal after the transaction's own commit:
    /// earlier ones belong to shards that were already gone and so never
    /// held it, and later ones to successors that never did either. `None`
    /// while the prefix is still owned by the shard that owned it then.
    fn departure_over(&self, owed: &Owed, route: RoutePrefix) -> Option<(ShardId, Departure)> {
        self.departed
            .iter()
            .filter(|(shard, _)| ShardTrie::shard_owns_route(**shard, route))
            .filter(|(_, departure)| departure.cut > owed.figures.first_commit())
            .min_by_key(|(_, departure)| departure.cut)
            .map(|(shard, departure)| (*shard, *departure))
    }

    /// Whether `shard`, leaving at `cut`, was party to `owed`: it held
    /// one of the entry's remote prefixes when the transaction
    /// committed, and left afterwards.
    ///
    /// Owning the prefix and leaving after the commit is not enough. A
    /// successor owns its predecessor's keyspace, so two cuts over one
    /// prefix inside one entry's life would name the entry to both,
    /// where [`Self::departure_over`] reads only the first — and the
    /// second departure would abandon what the first already settled.
    /// The shard a record may name is the one that held the prefix
    /// then, which is the earliest departure over it after the commit.
    fn party_to_entry(&self, owed: &Owed, shard: ShardId, cut: WeightedTimestamp) -> bool {
        cut > owed.figures.first_commit()
            && self.remote_routes(owed).any(|route| {
                ShardTrie::shard_owns_route(shard, route)
                    && self
                        .departure_over(owed, route)
                        .is_none_or(|(_, first)| first.cut >= cut)
            })
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
    pub fn counterparts(&self, tx_hash: TxHash, trie: &ShardTrie) -> BTreeSet<ShardId> {
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
                            && departure.cut > owed.figures.first_commit()
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
    pub fn reaches_beyond(&self, tx_hash: TxHash) -> bool {
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
    pub fn resolutions_of(
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
                    Meaning::Retired | Meaning::Delivered => {
                        TxResolution::Decided(TransactionDecision::Accept)
                    }
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
    /// transaction, or by the retirement's, which decides nothing and
    /// is the last word here all the same: a leg that succeeded bears
    /// no verdict, so the entry stays for the member a tick takes its
    /// records with — the reclaim, whose finalization decides it, or
    /// the retirement. A leg that failed is the transaction's end on
    /// this shard — it issued nothing, so there is nothing to reclaim —
    /// and its own finalization releases it.
    pub fn release_resolved(&mut self, finalizations: &[Arc<Verifiable<Finalization>>]) {
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
    /// Read off committed content alone — the ledger is a fold over
    /// committed blocks and `now` is the committed weighted timestamp —
    /// so every replica at the same frontier names the same set, which is
    /// what lets a committee sign the abort it composes.
    ///
    /// A leg entry is never here: its tick attested it and its
    /// certificate settled alone, so there is nothing to abandon. What a
    /// record licenses on one is a reclaim.
    #[must_use]
    pub fn past_deadline(&self, now: WeightedTimestamp) -> Vec<UnsettledTx> {
        self.owed
            .iter()
            .filter(|(_, owed)| !owed.part.is_leg())
            .filter(|(_, owed)| {
                let window = owed.abandon_window();
                now >= window.start && (owed.covered() || now < window.end)
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
    /// `deadline + 2 * MAX_VALIDITY_RANGE`, which is the validity end plus
    /// the escrow grace — the moment the claim cell both its members are
    /// proved against sweeps, one validity range past the lapse a
    /// delivery's absence is proved at, so a lapse proved at the earliest
    /// has a validity range to become a committed reclaim. Past it there is nothing to take
    /// back, whatever evidence arrives, so the entry goes on that reading
    /// alone. Dropping gives a reclaim up; it never licenses one. A
    /// record's evidence does not extend it, and no counterpart's silence
    /// shortens it: a reclaim waits on a record, and the record's arms
    /// are the evidence, not the counterpart's answerability.
    ///
    /// Returns the transactions dropped because every counterpart has
    /// fallen silent. Each carries whether a committed record had covered
    /// it, which separates a chain that ran out of room to commit the abort
    /// from one that never had the evidence to compose it. A leg entry
    /// dropped at its horizon is not among them: its reservation came
    /// back with its own finalization, so nothing leaks with it.
    pub fn prune(&mut self, now: WeightedTimestamp) -> Vec<Unanswerable> {
        let mut unanswerable = Vec::new();
        let mut entries = std::mem::take(&mut self.owed);
        entries.retain(|tx_hash, owed| {
            // A leg entry goes at its horizon, where the claim
            // cell both its members are proved against is swept:
            // past it neither the reclaim nor the retirement can
            // be composed, whatever evidence lands. Short of it
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
            if owed.certified && self.remote_routes(owed).next().is_some() {
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
                    || (departure.cut > entry.figures.first_commit()
                        && entry.figures.reach.iter().any(|route| {
                            !ShardTrie::shard_owns_route(local, *route)
                                && ShardTrie::shard_owns_route(*shard, *route)
                        }))
            })
        });

        unanswerable
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.owed.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_storage::committed_tx_cell_key;
    use hyperscale_types::test_utils::{
        make_finalization, make_leg_finalization, make_undecided_finalization, stub_transaction,
        test_prefix, test_principal,
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
        let classified = Classified::freeze(&legs, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([PARTNER]));
        classified
    }

    /// The claim cell the core writes for what `classified` says `LOCAL`
    /// issued, under the shard holding the consumer's target.
    fn core_claim(classified: &Classified) -> (ShardId, SubstateKey) {
        let claims = classified.core_claims(LOCAL);
        assert_eq!(
            claims.len(),
            1,
            "the fixture issues one crossing to the core"
        );
        claims[0]
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
        let claims = classified.delivered_claims(LOCAL);
        assert_eq!(
            claims.len(),
            1,
            "the fixture issues one crossing to a delivery"
        );
        claims[0]
    }

    /// A shape frozen divided with an inbound leg on `LOCAL` feeding an
    /// outbound leg on `PARTNER` directly, the core sitting on `PARTNER`
    /// beside it: the leg issues one crossing a delivery claims.
    fn delivering() -> Classified {
        use hyperscale_types::ShardTrie;
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::leg;
        let legs = [
            leg(0, LegRole::Inbound, &[]),
            leg(2, LegRole::Core, &[]),
            leg(2, LegRole::Outbound, &[(0, 0)]),
        ];
        let classified = Classified::freeze(&legs, &[], &ShardTrie::uniform(1));
        assert_eq!(classified.core(), &BTreeSet::from([PARTNER]));
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
        let classified = Classified::freeze(&legs, &[], &trie);
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
        let classified = Classified::freeze(&legs, &[], &ShardTrie::uniform(1));
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
        ledger.register_committed([(tx, classified)]);
    }

    /// A record's name for `tx`, stating the terms a committing block
    /// would have registered for it.
    fn names(tx: &Arc<Verifiable<Transaction>>) -> UnsettledTx {
        UnsettledTx {
            tx_hash: tx.hash(),
            deadline: Deadline::of_transaction(tx),
            declared_work: tx.work(),
            charge: charge(tx),
            reach: tx.routing().all_routes(),
        }
    }

    /// What abandoning `tx` states, as the ledger hands it to a tick.
    fn abandons(tx: &Arc<Verifiable<Transaction>>) -> UnsettledTx {
        names(tx)
    }

    /// The burn an abort of `tx` settles.
    fn charge(tx: &Arc<Verifiable<Transaction>>) -> AbortCharge {
        UnsettledTx::for_transaction(tx).charge
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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

        let first = ms(200_000);
        let second = ms(800_000);
        ledger.record_terminal(PARTNER, first, None);
        ledger.record_terminal(SUCCESSOR, second, None);

        assert_eq!(
            ledger.party_to(PARTNER, first),
            BTreeSet::from([tx.hash()]),
            "the shard that held the prefix then answers for the entry",
        );
        assert!(
            ledger.party_to(SUCCESSOR, second).is_empty(),
            "and its successor is a stranger to it",
        );
        assert!(
            ledger.outstanding_with(SUCCESSOR, second).is_empty(),
            "so the second cut is offered nothing to name",
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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());
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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());
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
        ledger.certify(tx.hash());
        assert!(ledger.is_certified(tx.hash()));
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

    /// A shard that left before the transaction could have been committed
    /// anywhere never held it, whatever its keyspace covers now — so its
    /// terminal says nothing about this transaction's fate, and cannot be
    /// the silence that strands it.
    ///
    /// Dated by the transaction rather than by the block that committed
    /// it here: two shards commit one transaction at two frontiers and a
    /// replica meeting it in a record has neither, so the only instant
    /// every reader agrees on is the transaction's own earliest possible
    /// commit — one validity range before it expires.
    #[test]
    fn a_terminal_older_than_the_transaction_is_not_its_counterpart_leaving() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(14, 600_000);
        ledger.register_committed([(&tx, &Classified::whole())]);
        ledger.certify(tx.hash());
        // Before the earliest instant the transaction could have been
        // committed on any shard, which its validity end fixes.
        let stale = ms(400_000);
        assert!(
            stale < names(&tx).first_commit(),
            "the terminal has to predate every commit of the transaction",
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
        ledger.certify(tx.hash());
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

    /// A delivery-only entry runs on the delivery window's clock: not
    /// abandoned at the transaction's deadline, abandoned at the window's
    /// close if it never ran, released by its own finalization if it did,
    /// and never a leg — nothing to reclaim, nothing to probe.
    #[test]
    fn a_delivery_entry_lives_to_the_windows_close() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(4, 60_000);
        commit(&mut ledger, &tx);
        ledger.seed(tx.hash(), Part::delivery());
        assert!(ledger.is_delivery(tx.hash()));
        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let close = Window::Delivery.of(Deadline::of(ms(60_000))).end;

        assert!(
            ledger.past_deadline(deadline).is_empty(),
            "the transaction's deadline abandons no delivery"
        );
        assert!(
            ledger.questions(&ShardTrie::uniform(1)).is_empty(),
            "and nothing probes for it"
        );
        let abandonable = ledger.past_deadline(close);
        assert_eq!(
            abandonable.len(),
            1,
            "the window's close abandons one never run"
        );
        assert_eq!(abandonable[0].tx_hash, tx.hash());

        let mut delivered = Ledger::new(LOCAL);
        commit(&mut delivered, &tx);
        delivered.seed(tx.hash(), Part::delivery());
        delivered.certify(tx.hash());
        let own = make_finalization(BlockHeight::new(1), tx.hash(), TransactionDecision::Accept);
        delivered.release_resolved(&[Arc::new(Verifiable::from(own))]);
        assert_eq!(
            delivered.len(),
            0,
            "a delivery's own finalization releases it"
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
        ledger.certify(leg.hash());
        ledger.certify(whole.hash());

        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let questions = ledger.questions(&ShardTrie::uniform(1));
        let (consumer, claim) = core_claim(&classified());
        let question = |key, probed| Question {
            tx_hash: leg.hash(),
            shard: PARTNER,
            key,
            probed,
            deadline: Deadline::of(ms(60_000)),
            cued: None,
        };
        assert_eq!(
            questions,
            vec![
                question(core_cell(PARTNER, &leg), Probed::Core),
                question(claim, Probed::Claim),
            ],
            "the leg asks the core for its committed cell and its claim, and the whole entry asks nothing"
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
    /// deadline like any other, and carries the claim cells the probe
    /// asks about; a record over the lapse covers it and licenses the
    /// reclaim.
    #[test]
    fn a_leg_delivered_elsewhere_is_probeable_with_its_claims() {
        let mut ledger = Ledger::new(LOCAL);
        let leg = tx(6, 60_000);
        commit_as(&mut ledger, &leg, &delivering());
        ledger.certify(leg.hash());

        let (delivered_by, claim) = delivered_claim(&delivering());
        let question = |key, probed| Question {
            tx_hash: leg.hash(),
            shard: PARTNER,
            key,
            probed,
            deadline: Deadline::of(ms(60_000)),
            cued: None,
        };
        assert_eq!(delivered_by, PARTNER);
        assert_eq!(
            ledger.questions(&ShardTrie::uniform(1)),
            vec![
                question(core_cell(PARTNER, &leg), Probed::Core),
                question(claim, Probed::Delivery),
            ],
        );
        ledger.record_reading(
            leg.hash(),
            PARTNER,
            claim,
            Probed::Delivery,
            Inclusion::Absent,
        );
        assert!(
            ledger.questions(&ShardTrie::uniform(1)).is_empty(),
            "covered once"
        );
        assert_eq!(
            ledger.reclaimable().len(),
            1,
            "and the lapse licenses the reclaim"
        );
    }

    /// An issuer in the core is released by its own verdict like any
    /// entry — unless it accepted with deliveries owed, when it stays on
    /// as a remainder: never abandoned, named by no departure, probed
    /// past the deadline for its claims, reclaimed on a claim read
    /// absent past the lapse, and released by the reclaim's finalization.
    #[test]
    fn an_issuer_that_accepted_stays_on_as_a_remainder_for_its_deliveries() {
        let deadline = ms(60_000).plus(MAX_FINALIZATION_DELAY);
        let resolved = |decision| {
            let tx = tx(8, 60_000);
            let mut ledger = Ledger::new(LOCAL);
            commit_as(&mut ledger, &tx, &issuing());
            ledger.certify(tx.hash());
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
                probed: Probed::Delivery,
                deadline: Deadline::of(ms(60_000)),
                cued: None,
            }],
            "a remainder asks about its deliveries, and never about itself"
        );
        ledger.record_reading(
            tx.hash(),
            PARTNER,
            claim,
            Probed::Delivery,
            Inclusion::Absent,
        );
        let reclaims = ledger.reclaimable();
        assert_eq!(reclaims.len(), 1);
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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());
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

        let delivery = tx(3, 60_000);
        commit(&mut ledger, &delivery);
        ledger.seed(delivery.hash(), Part::delivery());
        assert_eq!(
            fw(
                &ledger,
                make_undecided_finalization(h, delivery.hash(), TransactionDecision::Accept)
            ),
            decided(&delivery, TransactionDecision::Accept),
            "a delivery that succeeded claimed what an accepted core issued"
        );
        assert_eq!(
            fw(
                &ledger,
                make_undecided_finalization(h, delivery.hash(), TransactionDecision::Reject)
            ),
            vec![(delivery.hash(), TxResolution::LegFinalized)],
            "a delivery that failed decides nothing, and the value waits for a later claim"
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
        seated.certify(tx.hash());
        seated.record_abandonment_records(std::slice::from_ref(&record));

        // The replica rotated in afterwards, which meets the transaction
        // for the first time in the record.
        let mut entrant = Ledger::new(LOCAL);
        entrant.record_abandonment_records(&[record]);

        // A departure between the two instants the entry could be dated
        // by: past anything that could have committed the transaction,
        // and short of the record that names it. Which of the two the
        // ledger reads is what decides whether the departed shard was
        // party, so both replicas have to read the same one.
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
        ledger.certify(tx.hash());
        assert!(
            ledger.consumer_holds(tx.hash(), SUCCESSOR),
            "the shard holding the claim's prefix consumes what the leg issued",
        );

        let (_, claim) = core_claim(&classified());
        ledger.record_reading(
            tx.hash(),
            SUCCESSOR,
            claim,
            Probed::Claim,
            Inclusion::Present([7; 32]),
        );
        let retirable = ledger.retirable();
        assert_eq!(
            retirable.len(),
            1,
            "the successor claimed, so the record has nothing left to hold",
        );
        assert_eq!(retirable[0].tx_hash, tx.hash());
    }

    /// A committed claim reading the consumer's cell present is what
    /// licenses retiring a leg's records — never a clock, never a
    /// certificate — once every consumer has claimed; the retirement's
    /// own finalization releases the entry, and a claimed entry is
    /// neither reclaimable nor abandonable meanwhile.
    #[test]
    fn a_committed_claim_licenses_the_retirement_and_its_finalization_releases_the_entry() {
        let mut ledger = Ledger::new(LOCAL);
        let tx = tx(8, 60_000);
        commit_as(&mut ledger, &tx, &classified());
        ledger.certify(tx.hash());
        assert!(ledger.retirable().is_empty(), "nothing retires on a clock");

        let (_, claim) = core_claim(&classified());
        ledger.record_reading(
            tx.hash(),
            PARTNER,
            claim,
            Probed::Claim,
            Inclusion::Present([7; 32]),
        );
        let retirable = ledger.retirable();
        assert_eq!(retirable.len(), 1, "every consumer claimed");
        assert_eq!(retirable[0].tx_hash, tx.hash());
        assert!(
            ledger.reclaimable().is_empty(),
            "a claim is a settlement, not evidence for a reclaim"
        );
        assert!(
            ledger.past_deadline(ms(200_000)).is_empty(),
            "and abandons nothing"
        );

        ledger.admit_retire(tx.hash());
        assert!(ledger.retirable().is_empty(), "a tick has taken it");
        let retirement = make_leg_finalization(BlockHeight::new(9), tx.hash());
        assert_eq!(
            ledger.resolutions_of(&[Arc::new(Verifiable::from(retirement.clone()))]),
            vec![(
                tx.hash(),
                TxResolution::Decided(TransactionDecision::Accept)
            )],
            "the retirement says every consumer claimed: the transaction was accepted"
        );
        ledger.release_resolved(&[Arc::new(Verifiable::from(retirement))]);
        assert_eq!(ledger.len(), 0, "the retirement's finalization releases it");
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
        ledger.certify(tx.hash());

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
        ledger.certify(tx.hash());
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
            PARTNER,
            claim,
            Probed::Delivery,
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
        ledger.certify(tx.hash());
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
            ledger.certify(tx.hash());
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
