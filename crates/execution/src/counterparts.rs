//! What counterparts' chains have shown about the transactions in
//! flight here, and what this shard still asks them.
//!
//! One account of the exchange: the ledger of what this shard owes an
//! outcome for and what each counterpart's committed state was read to
//! say of it, the mirror of the departed shards' settled sets — shared
//! with the vote fence, which checks a record against exactly what was
//! offered from — the questions put to silent counterparts, and the
//! readings fetched back to offer in a block. Everything here is folded
//! from committed content, so replicas at one frontier hold one
//! account. The tick machine reads the ledger through it and decides
//! what to do with a strand nobody can answer for.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

use hyperscale_core::{Action, CrossingPulls, FetchIds, FetchRequest, ProtocolEvent};
use hyperscale_metrics::{
    record_rebuilt_record_entry, record_reclaim_probe_answered, record_reclaim_probe_pending,
};
use hyperscale_storage::{
    CrossingLeaves, is_crossing_answer_cell, is_crossing_obligation_cell, is_record_cell,
};
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Anchor, Block, BlockHeight, CounterpartMirror,
    CrossingReoffer, Deadline, ExecutionCertificate, Inclusion, MAX_FINALIZATION_DELAY,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_PROVISION_TARGET_SHARDS, MAX_REOFFERS_PER_BLOCK,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof, Probed,
    ProvenAnchors, ProvenCells, RETENTION_HORIZON, SettledTxSet, ShardId, ShardTrie, Spoken,
    StateClaim, SubstateKey, TerminalEvidence, TopologySchedule, TransactionDecision, TxHash,
    TxResolution, UnsettledTx, Verifiable, Verified, WeightedTimestamp, Window,
};
use hyperscale_vm_effects::{
    CrossingAnswer, CrossingCell, CrossingObligation, ProtocolHasher, crossing_decline_key,
};

use crate::ledger::{Ledger, Question, Unanswerable};
use crate::provisioning::Arrival;

/// Whether an absence of a held record's claim, taken at `probed_wt`,
/// says nobody took the crossing.
///
/// From the close of [`Window::Core`], where no core shard of any arity
/// can still commit, to the close of [`Window::LegEntry`], which is as
/// far as any evidence deciding the transaction can be taken. A leaf
/// does not name its consumer's role, so nothing narrower is honest for
/// every record this reads. A record a delivery consumes never reaches
/// the disposal an absence licenses: it names nobody to take it back,
/// and nobody does.
fn held_absence_answers(probed_wt: WeightedTimestamp, deadline: Deadline) -> bool {
    (Window::Core.of(deadline).end..Window::LegEntry.of(deadline).end).contains(&probed_wt)
}

/// What one block's abandonment records may still spend.
///
/// Two figures, because the section answers to two questions. The names
/// are the drain's: how many transactions can be owed an outcome at once
/// is what [`MAX_UNSETTLED_PER_BLOCK`] bounds. The bytes are the wire's:
/// a name costs its reach as well as itself, so the same count of names
/// spans a four-fold range and only
/// [`MAX_PROPOSAL_EVIDENCE_BYTES`] keeps the section inside the frame
/// that carries it.
struct Budget {
    names: usize,
    bytes: usize,
}

impl Budget {
    /// A block's whole allowance, before any record is composed. The
    /// record's own terms are charged with the first name it takes,
    /// which is what leaves room for them.
    const fn empty() -> Self {
        Self {
            names: MAX_UNSETTLED_PER_BLOCK,
            bytes: MAX_PROPOSAL_EVIDENCE_BYTES,
        }
    }

    /// Whether either figure is exhausted.
    const fn spent(&self) -> bool {
        self.names == 0 || self.bytes == 0
    }

    /// Take as many of `unsettled` as the budget still affords, in the
    /// order offered, and charge for them. What is left is dropped: a
    /// name a record does not carry stays uncovered and is offered
    /// again next block.
    fn take(&mut self, unsettled: &mut Vec<UnsettledTx>) {
        let mut taken = 0;
        let mut spend = ABANDONMENT_RECORD_BYTES;
        for entry in unsettled.iter().take(self.names) {
            let next = spend + entry.wire_weight();
            if next > self.bytes {
                break;
            }
            spend = next;
            taken += 1;
        }
        unsettled.truncate(taken);
        if taken == 0 {
            return;
        }
        self.names -= taken;
        self.bytes -= spend;
    }
}

/// An escrow record this shard holds, and where its one question
/// stands.
///
/// One question, to one shard: is the claim cell this record names
/// present? So the bookkeeping is one height rather than a probe —
/// there is no set of counterparts to track, no fetch release to
/// sequence, and no record to compose, because the answer is a reading
/// and a reading is block content already.
#[derive(Debug, Clone)]
pub struct HeldRecord {
    /// The record leaf, which carries the claim key, the issuing
    /// transaction and the expiry every window is read off.
    pub(crate) cell: CrossingCell,
    /// The newest counterpart header the claim has been asked at, so
    /// the question is not re-sent at the same one every block.
    asked_at: Option<BlockHeight>,
    /// What the last committed offer of this crossing was made against:
    /// the consumer header it was paced on, and the chain's clock at the
    /// block that carried it.
    ///
    /// Two figures because an offer is bounded by two different
    /// failures, and neither bound covers the other's. The clock is how
    /// long an answer takes to come back — a round, by
    /// [`MAX_FINALIZATION_DELAY`]'s own definition — and it is what
    /// paces a consumer that is running, whose headers land here far
    /// faster than that. The height is what stops a consumer that is
    /// not: a target whose chain has not advanced could not have
    /// answered however long is waited, and off a leaf, which does not
    /// die, a clock alone would promise into it forever.
    ///
    /// Stamped where the offer commits rather than where it is composed:
    /// a proposer that composed one and lost its round promised nothing,
    /// and the next proposal must not skip the crossing for it.
    offered_at: Option<(BlockHeight, WeightedTimestamp)>,
    /// The decline cell's key, under the same target the claim's key
    /// sits at and off the same edge.
    ///
    /// Held rather than re-derived because three sites compare against
    /// it in every block — the probe that asks, the retention rule that
    /// keeps what lands, and the fold that reads it — and the record
    /// carries the claim's key for the same reason.
    pub(crate) consumer_decline: SubstateKey,
    /// What a committed claim read of the cell, once one has read it:
    /// present at any anchor, absent only past the lapse.
    pub(crate) answer: Option<Inclusion>,
    /// Whether a committed claim read the consumer's decline cell
    /// present: its own word that it will never take the crossing, so
    /// the value is the producer's to credit back.
    ///
    /// A presence and nothing else. The cell is written once by the one
    /// thing that writes it and swept by nothing, so a reading of it at
    /// any anchor is a fact — and its absence says only that the
    /// consumer has not refused, which is what the claim beside it is
    /// asked about.
    pub(crate) declined: bool,
    /// Whether a committed abandonment record says the chain that was
    /// to consume this crossing can never settle the transaction that
    /// issued it.
    ///
    /// The one licence a record takes from something other than its own
    /// claim, and the one that reaches a record no entry names: a
    /// departure is written into the chain, so it answers whenever it
    /// lands rather than only while the transaction is still owed an
    /// outcome here. A transaction nothing settled was never accepted,
    /// so nothing claimed any crossing it issued.
    pub(crate) departed: bool,
}

impl HeldRecord {
    /// The record as the leaves give it: undisposed, unasked.
    #[must_use]
    pub(crate) fn of(cell: CrossingCell) -> Self {
        Self {
            consumer_decline: crossing_decline_key(
                &ProtocolHasher,
                cell.consumer_claim.owner,
                cell.intent,
                cell.local,
                cell.output,
            ),
            cell,
            asked_at: None,
            offered_at: None,
            answer: None,
            declined: false,
            departed: false,
        }
    }

    /// Whether the consumer has answered this crossing, either way.
    ///
    /// Stated once because four sites ask it — the probe that puts the
    /// question, the fold that records what comes back, the offer that
    /// applies the pressure, and the retention rule that keeps a
    /// reading to carry. A record is answered by a claim read present,
    /// by a decline read present, or, until the absence path goes, by a
    /// claim read absent inside the window one answers in; and a
    /// conjunction copied four times is one three of them forget to
    /// grow.
    #[must_use]
    pub(crate) const fn answered(&self) -> bool {
        self.answer.is_some() || self.declined
    }

    /// Whether the crossing this record holds can never be claimed, so
    /// the value is the producer's to take back: the consumer's own
    /// decline says so, a departure says so outright, and so does the
    /// claim read absent inside the window an absence means something
    /// in.
    #[must_use]
    pub(crate) const fn unclaimable(&self) -> bool {
        self.declined || self.departed || matches!(self.answer, Some(Inclusion::Absent))
    }

    /// The deadline every window this record is read against derives
    /// from — the producing intent's, recovered from the expiry the leaf
    /// states.
    #[must_use]
    pub(crate) const fn deadline(&self) -> Deadline {
        Deadline::from_expiry(self.cell.expiry_ms)
    }
}

/// A crossing this shard has answered, and where its one question
/// stands.
///
/// [`HeldRecord`] read from the other end. A producer holds a record and
/// asks whether its consumer claimed; a consumer holds an answer and asks
/// whether the producer still holds the record — the same channel, the
/// same pacing, and the opposite direction.
///
/// One question, to one shard, so the bookkeeping is one height. There is
/// no deadline here because no window is read: only a presence answers,
/// and a presence answers wherever it was taken.
#[derive(Debug, Clone)]
pub struct AnsweredCrossing {
    /// The record cell this claim answers for, under the producing
    /// node's target. Read off the leaf, which is the only thing that
    /// names it.
    pub(crate) record: SubstateKey,
    /// What the last question about this record was put against: the
    /// producer header it was asked at, and this chain's clock when it
    /// was.
    ///
    /// Two figures, because they bound two different failures and
    /// neither covers the other's — [`HeldRecord::offered_at`]'s
    /// argument, on the question side. The height stops a producer that
    /// has **stopped**: a chain that has not advanced could not have
    /// disposed of anything, so it is asked once. The clock stops one
    /// that is **running**: a live producer commit-proves a header here
    /// every block, and a record stands until that producer learns the
    /// answer — so paced on the height alone the question is put once a
    /// block, for every crossing this shard has ever answered, and each
    /// answer rides a block as a claim every voter must prove for
    /// itself.
    ///
    /// **The clock is [`RETENTION_HORIZON`], and asking faster buys
    /// nothing.** Two absences license a deletion only a span apart, so
    /// the shortest path from a standing record to a cleanable answer
    /// is one span whatever the polling rate — and a deletion is
    /// housekeeping with no deadline behind it. Paced here the whole
    /// loop costs one question per answer cell per span; paced at a
    /// round it costs six times that and buys back at most one span on
    /// a path nothing waits on.
    asked_at: Option<(BlockHeight, WeightedTimestamp)>,
    /// How far the record has been read gone.
    pub cleanup: Cleanup,
}

impl AnsweredCrossing {
    /// The answer as the leaves give it: unasked, with nothing yet read
    /// of the record it names.
    #[must_use]
    const fn of(claim: &CrossingAnswer) -> Self {
        Self {
            record: claim.record,
            asked_at: None,
            cleanup: Cleanup::Standing(None),
        }
    }
}

/// How far a crossing this shard answered has been read gone on its
/// producer's chain.
///
/// An answer cell is needed only while the record it answers for
/// stands. Once the producer has disposed of that record — retired it
/// on a claim, credited it back on a decline — no replay is possible,
/// so the consumer deletes its own cell. What licenses the deletion is
/// the record read **absent**, and it is a true absence for this
/// consumer alone: the consumer answered against that record, so it
/// existed, and the only thing that removes one is the producer's
/// disposal.
///
/// **A presence is not a state here.** It says the producer still holds
/// the record, which is the question being put again rather than an
/// answer to it — and the happy path is the absence, since a producer
/// disposes the moment it reads the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleanup {
    /// The record still stands, as far as anything read of it goes —
    /// carrying the newest producer anchor a reading was folded at, or
    /// `None` where none has been.
    ///
    /// The anchor is what makes a folded reading **spent**. A reading
    /// is offered from `fetched` in every block until nothing wants it,
    /// so one that answered and is still wanted is one every block
    /// carries again, for every voter to verify against its own proven
    /// cells.
    Standing(Option<Anchor>),
    /// Read absent once, at this anchor of the producer.
    Once(Anchor),
    /// Read absent at two anchors of the producer far enough apart that
    /// nothing it once promised is servable any more.
    Twice(Anchor, Anchor),
}

impl Cleanup {
    /// The same record read absent at `anchor`.
    ///
    /// **The span is between two anchors of the producer, and that is
    /// the whole of the rule.** A retention floor moves inside the
    /// producer's own commit — `retire_dated` takes
    /// `cutoff = tip_ts.minus(RETENTION_HORIZON)` — so a halted
    /// producer's floor freezes with its tip and it goes on serving
    /// every block at or below the absence anchor indefinitely, while
    /// this chain's clock runs on. Measured here it is `retire_dated`'s
    /// own inequality read from the other side; measured on the
    /// consumer's clock it would delete on schedule into a producer
    /// still serving the bundle a replay needs.
    ///
    /// And measured from the **absence**, never from a reading that
    /// found the record present. The producer goes on re-offering until
    /// it learns the answer, so every block between the claim and its
    /// disposal promises a bundle built from the record — a gap that is
    /// the producer's observe latency and unbounded in principle. At
    /// the absence anchor the record is gone, so every block that ever
    /// promised a bundle is at or below it, which is exactly the set
    /// the serving span bounds.
    #[must_use]
    fn read(self, anchor: Anchor, inclusion: Inclusion) -> Self {
        match (self, inclusion) {
            (Self::Standing(_), Inclusion::Absent) => Self::Once(anchor),
            (Self::Once(first), Inclusion::Absent) if Self::spans(first, anchor) => {
                Self::Twice(first, anchor)
            }
            // The record is still there, so what this reading gives is
            // the anchor it was read at: the question is worth putting
            // again, and not at any header this one already answered
            // for.
            (Self::Standing(seen), Inclusion::Present(_))
                if seen.is_none_or(|seen| anchor.height > seen.height) =>
            {
                Self::Standing(Some(anchor))
            }
            (other, _) => other,
        }
    }

    /// Whether `second` stands far enough past `first` on the
    /// producer's clock that nothing the producer promised below
    /// `first` is servable at `second`.
    #[must_use]
    fn spans(first: Anchor, second: Anchor) -> bool {
        second.ts > first.ts.plus(RETENTION_HORIZON)
    }

    /// Whether a reading taken at `anchor` could still advance this.
    ///
    /// The pacing, and it is the one place a question that cannot be
    /// answered is not asked. After a first absence every anchor short
    /// of the span is a fetch that tells this shard what it already
    /// knows — some seventy of them per crossing at an ordinary block
    /// rate, which is the flood shape a rate defect takes every time it
    /// appears in this family.
    #[must_use]
    fn wants(self, anchor: Anchor) -> bool {
        match self {
            Self::Standing(seen) => seen.is_none_or(|seen| anchor.height > seen.height),
            Self::Once(first) => Self::spans(first, anchor),
            Self::Twice(..) => false,
        }
    }
}

/// Whether any undisposed record is still waiting on `key`.
///
/// Read off the keys rather than off a name, because a record's issuing
/// transaction need not be one this chain committed.
fn awaited_by(held: &BTreeMap<SubstateKey, HeldRecord>, key: SubstateKey) -> bool {
    held.values().any(|record| {
        !record.answered() && (record.cell.consumer_claim == key || record.consumer_decline == key)
    })
}

/// Whether any answer of this shard's still wants a reading of `key`
/// taken at `anchor`.
///
/// [`awaited_by`] on the answering side, and needed for the same reason:
/// a question driven by leaves rather than by entries is one the probe
/// account knows nothing about, so a reading that answers it has to be
/// recognised off the key or it is fetched and then dropped — and a
/// question whose answer is never offered is a question asked again at
/// every header of the counterpart, for as long as the leaf stands.
///
/// **The anchor is the difference from that side, and it is what a
/// second reading needs.** What this asks for is not one reading but
/// two, at producer anchors a retention span apart, so a reading is
/// wanted where it would advance the pair and spent where it would not
/// — and the same reading is both, first and second. Keyed on the cell
/// alone, a reading already folded would be held for the whole span
/// while the question that wants its successor stood down for it.
fn awaits_record(
    answered: &BTreeMap<SubstateKey, AnsweredCrossing>,
    anchor: Anchor,
    key: SubstateKey,
) -> bool {
    answered
        .values()
        .any(|answer| answer.record == key && answer.cleanup.wants(anchor))
}

/// Whether any leaf-driven question of this shard's wants a reading of
/// `key` taken at `anchor`.
///
/// The three sources [`Counterparts::probe`] asks from, read back as one
/// predicate, because two sites need exactly this set and needed it to
/// be the same set. A fetch that lands is offered in a block only if
/// something here wants it, and a reading held to offer is kept only
/// while something here wants it — so a source named in one and missed
/// in the other is a reading fetched, dropped at the next commit and
/// fetched again at the counterpart's next header, for as long as the
/// leaf stands. None of these questions names a transaction of this
/// chain's, which is why the keys are read rather than the names.
fn wants_reading(
    held: &BTreeMap<SubstateKey, HeldRecord>,
    answered: &BTreeMap<SubstateKey, AnsweredCrossing>,
    arrivals: &BTreeMap<SubstateKey, BlockHeight>,
    anchor: Anchor,
    key: SubstateKey,
) -> bool {
    awaited_by(held, key) || awaits_record(answered, anchor, key) || arrivals.contains_key(&key)
}

/// Whether this shard has answered the crossing `cell` records, either
/// way.
///
/// What ends the arrival question and starts the answer one: a shard
/// that has delivered holds a claim naming the record, and that claim is
/// what asks about it from then on. Read whatever the answer says, since
/// a crossing this shard has answered is one it will not deliver again.
///
/// **Two lookups rather than a walk, and the cell is what makes that
/// possible.** An answer sits at one of two keys under the consuming
/// node's own target: the claim, which the record carries outright, and
/// the decline, which derives from the same edge. Asked from the
/// record's side there is no owner to derive either from — the record's
/// owner is the *producing* node's target — so the question could only
/// be answered by scanning every answer this shard has ever written.
/// Every caller holds the cell, so none of them has to.
fn answered_for(answered: &BTreeMap<SubstateKey, AnsweredCrossing>, cell: &CrossingCell) -> bool {
    answered.contains_key(&cell.consumer_claim)
        || answered.contains_key(&crossing_decline_key(
            &ProtocolHasher,
            cell.consumer_claim.owner,
            cell.intent,
            cell.local,
            cell.output,
        ))
}

/// A question this validator put to a counterpart: the question, the
/// header it was asked at, and whether the fetch has returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    question: Question,
    anchor: Anchor,
    returned: bool,
}

/// What a commit folded, and what it could not answer for.
pub struct Committed {
    /// The fetches it releases and the probes it opens.
    pub(crate) actions: Vec<Action>,
    /// The transactions let go of because every counterpart has fallen
    /// silent — the tick machine's to discard.
    pub(crate) unanswerable: Vec<Unanswerable>,
}

/// What this validator holds to offer in a block it proposes.
pub struct Offers {
    /// Readings its own fetches took that no block has carried yet, in
    /// the one order a block carries them.
    pub state_claims: Vec<StateClaim>,
    /// The records it has evidence for and has not yet written down.
    pub abandonment_records: Vec<AbandonmentRecord>,
    /// The crossings its ledger says are still owed a claim, each
    /// promised to the shard holding that claim's prefix now.
    pub reoffers: Vec<CrossingReoffer>,
}

pub struct Counterparts {
    /// Committed transactions still owed an outcome, folded from the
    /// chain rather than read off live tick state — the only account of
    /// what this shard has in flight that can be rebuilt after losing
    /// that state.
    pub(crate) ledger: Ledger,

    /// The departed shards' settled sets and what committed records
    /// cover, shared with the shard coordinator's vote fence. This
    /// account is the only writer, and the only one that says what to
    /// drop — the ledger above is what a covered entry there speaks
    /// for.
    ///
    /// One mirror, because the fence checks a record against exactly
    /// what was offered from, and two copies could answer differently.
    pub(crate) mirror: Arc<CounterpartMirror>,

    /// Commit-proven remote source blocks, shared with the shard
    /// coordinator, which owns the mirror and feeds it off
    /// `RemoteHeaderCommitted`.
    ///
    /// A cross-shard EC is consumable only against a proven source block
    /// — a bare QC certifies availability, and an f+1..2f corrupt
    /// committee can certify a sibling that never commits and export ECs
    /// computed from it. The same anchors are what a probe of a
    /// counterpart's committed set is taken against, and what this
    /// validator's vote fence holds a block's state claims to: one
    /// mirror, so a claim cannot pass the fence at an anchor no prober
    /// here would have chosen.
    pub(crate) proven_anchors: Arc<ProvenAnchors>,

    /// What this validator's own fetches have proven of counterparts'
    /// cells, shared with the shard coordinator's vote fence and with
    /// the state-proof server that relays a peer the bytes.
    ///
    /// Written here because a fetch lands here, and read there because
    /// a block states a reading rather than proving it. Kept apart from
    /// the mirror above for the reason stated on
    /// [`ProvenCells`]: a reading licenses this validator's vote and
    /// composes nothing.
    pub(crate) proven_cells: Arc<ProvenCells>,

    /// The readings this validator's own fetches took that answered,
    /// each with the transactions whose probes it spoke to, held to
    /// offer in a block this validator proposes: a claim is committed
    /// content, folded by every replica at the same height, and the
    /// fetch is only how the proposer came by the answer. A claim leaves
    /// when a block carries it, or when every transaction it answered
    /// for is gone. While it is here the question it answers is not put
    /// again: what licenses that is narrower than the mirror, which
    /// stays fed by committed content alone so two validators at one
    /// committed height compose the same records.
    fetched: BTreeMap<StateClaim, BTreeSet<TxHash>>,

    /// The escrow records this shard holds under its prefix, each still
    /// undisposed, by cell key.
    ///
    /// Read from the leaves whatever brought the store here. A seat's
    /// ledger begins empty and a restart replays only a window, so for
    /// records older than either there is no entry to name them — and
    /// the leaf carries every term needed to ask about one: the claim
    /// cell, the issuing transaction, and the expiry every window is
    /// read off. Held here rather than beside the tick machine because
    /// the question is a counterpart's to answer, like every other
    /// question in this file.
    pub(crate) held: BTreeMap<SubstateKey, HeldRecord>,

    /// The owed claims this shard has written under its prefix, each
    /// still undeleted, by cell key.
    ///
    /// The mirror of [`held`](Self::held) on the answering side, read
    /// from the leaves for the same reason: a seat's ledger begins empty
    /// and a restart replays only a window, so for an answer older than
    /// either there is no entry to name it — and the leaf carries the one
    /// term the question needs, the record it answers for.
    pub(crate) answered: BTreeMap<SubstateKey, AnsweredCrossing>,

    /// The crossings this shard was handed and has not answered, by the
    /// obligation cell it wrote down for each.
    ///
    /// Read from the leaves like [`held`](Self::held) and
    /// [`answered`](Self::answered) beside it, and for a reason those
    /// two do not have: what a bundle handed this shard is otherwise
    /// known only to the provisioning account, which no replica
    /// reproduces and no restart recovers. The leaf is the arrival made
    /// durable, so a refusal is composable from state at any age.
    pub(crate) owed: BTreeMap<SubstateKey, CrossingObligation>,

    /// The producer header each crossing handed to this shard has been
    /// asked about at, by the record cell a bundle carried.
    ///
    /// Pacing alone, and reconciled against the absorptions on every
    /// probe rather than folded: what a bundle handed this shard is the
    /// provisioning account's to say, and an entry here outliving it
    /// would ask about a crossing nothing could still deliver.
    arrivals: BTreeMap<SubstateKey, BlockHeight>,

    /// Where this validator's last composed offer reached, so the next
    /// one starts past it rather than at the lowest keys every time.
    ///
    /// A rotation hint and nothing more. What decides whether a crossing
    /// is promised is [`HeldRecord::offered_at`]; this only spreads one
    /// block's cap over a backlog wider than it, so no record at the
    /// tail waits on the head being answered. Which records a proposer
    /// reaches is not consensus content — only what a block carries is —
    /// so it is node-local and empty after a restart, and a restart
    /// re-offers each record at most once before the walk laps.
    offer_cursor: Option<(ShardId, TxHash)>,

    /// The questions this validator has put to counterparts, by the
    /// shard asked and the cell: the header each was asked at, and
    /// whether the fetch returned. A probe lives while its question is
    /// open — one the chain has answered, or whose entry is gone, is
    /// dropped at the commit and any fetch still out for it released,
    /// so a counterpart that never serves the height does not pin the
    /// slot.
    probes: BTreeMap<(ShardId, SubstateKey), Probe>,

    /// The record pulls this validator has put, with their pacing.
    pulled: CrossingPulls,
}

impl Counterparts {
    /// Holding the escrow records the store gives for this shard's
    /// prefix, which is every start's first term and the only one a
    /// store can answer before a block commits. A leaf that does not
    /// decode is one no disposal could be composed from, so it is
    /// dropped rather than held.
    #[must_use]
    pub(crate) fn holding(
        local_shard: ShardId,
        proven_anchors: Arc<ProvenAnchors>,
        proven_cells: Arc<ProvenCells>,
        mirror: Arc<CounterpartMirror>,
        leaves: &CrossingLeaves,
    ) -> Self {
        Self {
            ledger: Ledger::new(local_shard),
            mirror,
            proven_anchors,
            proven_cells,
            fetched: BTreeMap::new(),
            held: leaves
                .records
                .iter()
                .filter_map(|(key, value)| {
                    Some((*key, HeldRecord::of(CrossingCell::from_bytes(value)?)))
                })
                .collect(),
            answered: leaves
                .claims
                .iter()
                .filter_map(|(key, value)| {
                    Some((
                        *key,
                        AnsweredCrossing::of(&CrossingAnswer::from_bytes(value)?),
                    ))
                })
                .collect(),
            owed: leaves
                .obligations
                .iter()
                .filter_map(|(key, value)| Some((*key, CrossingObligation::from_bytes(value)?)))
                .collect(),
            arrivals: BTreeMap::new(),
            offer_cursor: None,
            probes: BTreeMap::new(),
            pulled: CrossingPulls::new(),
        }
    }

    /// Fold what a committed block says about counterparts — the claims
    /// and records it carries, the entries its certificates resolve, the
    /// departures the schedule now proves — let go of what no window can
    /// still answer, and ask what the block's clock opens.
    ///
    /// `trie` is the block's committee's, which says who was party to
    /// each transaction, and `now` the committed clock every deadline is
    /// read against.
    pub(crate) fn on_commit(
        &mut self,
        trie: &ShardTrie,
        topology_schedule: &TopologySchedule,
        block: &Block,
        now: WeightedTimestamp,
        arrived: &BTreeMap<SubstateKey, Arrival>,
    ) -> Committed {
        self.gc_settled_sets(topology_schedule, now);
        // A reading the chain now carries is everybody's: its answers
        // are folded here, and nothing offers it again.
        for claim in block.state_claims() {
            self.fetched.remove(claim);
        }
        let mut actions = self.fold_state_claims(trie, block);
        // Every verdict this block carries resolves its transactions,
        // whichever way it went; what is left past every window that
        // could still carry one is nobody's to resolve.
        self.ledger.release_resolved(block.certificates());
        // What the block writes down about departed shards, before the
        // prune below reads what is still answerable.
        let rebuilt = self
            .ledger
            .record_abandonment_records(block.abandonment_records());
        for _ in 0..rebuilt {
            record_rebuilt_record_entry();
        }
        self.cover_recorded(block);
        self.fold_crossing_writes(block);
        self.fold_reoffers(block.reoffers(), now);
        self.cover_held(block);
        self.stamp_departures(topology_schedule, now);
        let unanswerable = self.ledger.prune(now);
        actions.extend(self.release_answered_fetches(trie));
        // The committed clock is what opens a leg's deadline, so the
        // cores gone silent past it are asked here.
        actions.extend(self.probe(trie, now, arrived));
        Committed {
            actions,
            unanswerable,
        }
    }

    /// Ask each producer for the records a delivery admitted here still
    /// waits on, which [`ProvisioningTracker::unpushed_crossings`] has
    /// already held to its floor.
    ///
    /// **Asked of whoever holds the record's prefix now.** The
    /// requirement names the shard the producer sat on when the
    /// transaction was classified, and a cut moves a prefix — so asking
    /// that shard is asking somebody who cannot answer, for as long as
    /// the crossing stands.
    ///
    /// The pacing is [`CrossingPulls`]', shared with the parked bodies
    /// the pool asks for before admission.
    pub(crate) fn pull_unpushed_crossings(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        unpushed: &BTreeSet<SubstateKey>,
    ) -> Vec<Action> {
        let local = self.ledger.local();
        let wanted = unpushed.iter().filter_map(|&key| {
            let shard = trie.shard_for_prefix(key.owner);
            (shard != local).then_some((shard, key))
        });
        self.pulled.ask(&self.proven_anchors, now, wanted)
    }

    /// Record a departed shard's settled set where the fence reads it.
    pub(crate) fn on_settled(&self, shard: ShardId, settled: SettledTxSet) {
        self.mirror.record_settled(shard, settled);
    }

    /// The departed shards whose settled sets the fence will need and
    /// this validator does not hold: every shard the schedule still
    /// routes to whose boundary record attests a settled root, until the
    /// handoff-anchored evidence window has closed at `now` (an
    /// unstamped window is open). Re-derived whole on every beacon fold,
    /// so a set acquired, a window closed or a shard evicted simply
    /// drops out.
    #[must_use]
    pub(crate) fn wanted_settled_sets(
        &self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) -> Vec<TerminalEvidence> {
        let head = topology_schedule.head();
        topology_schedule
            .routable_shards()
            .into_iter()
            .filter(|&shard| shard != self.ledger.local())
            .filter(|&shard| !self.mirror.with_settled(|sets| sets.contains_key(&shard)))
            .filter(|&shard| {
                topology_schedule
                    .handoff_evidence_expiry(shard)
                    .is_none_or(|expiry| now <= expiry)
            })
            .filter_map(|shard| {
                let anchor = head.boundary(shard)?;
                let attested_root = anchor.terminal_roots?.settled_txs;
                let terminal_wt = topology_schedule.terminal_cut_wt(shard)?;
                Some(TerminalEvidence {
                    shard,
                    height: anchor.height,
                    block_hash: anchor.block_hash,
                    terminal_wt,
                    attested_root,
                })
            })
            .collect()
    }

    /// What this validator holds to offer in a block it proposes.
    #[must_use]
    pub(crate) fn offers(&mut self, trie: &ShardTrie, now: WeightedTimestamp) -> Offers {
        Offers {
            state_claims: self.state_claims(),
            abandonment_records: self.abandonment_records(),
            reoffers: self.reoffers(trie, now),
        }
    }

    /// The crossings this shard still holds a record for, each promised
    /// again to whoever holds its claim's prefix now.
    ///
    /// Composed off the leaves, which is what lets an offer outlive the
    /// entry that once made it: a record stands until its consumer
    /// answers, and nothing else says a crossing is still owed. The
    /// deadline is the floor, read off the record's own expiry, because
    /// short of it the crossing's first bundle may still be in flight
    /// and nothing has failed to deliver it yet.
    ///
    /// Paced on the consumer's chain **and** on a clock, because the two
    /// bound different failures. An entry dies, so one offer a round is
    /// a bounded promise against it; a leaf does not, so the clock alone
    /// would promise into an unreachable target forever, every round,
    /// into a section capped at [`MAX_REOFFERS_PER_BLOCK`] and shared
    /// with every live one. The target's newest proven header closes
    /// that — a chain that has not advanced is offered once — but it
    /// does not replace the clock: a target that *is* running lands
    /// headers here every block, and paced on those alone a crossing is
    /// promised many times over inside the one round its answer takes,
    /// which is a bundle rebuilt and rebroadcast for each.
    ///
    /// One offer per transaction per target, because an offer promises a
    /// bundle built from exactly the cells it names and a bundle per
    /// record would promise several partial ones. The records of one
    /// transaction into one shard are a subset of the crossings it
    /// carries, so [`MAX_CROSSINGS_PER_TX`](hyperscale_vm_types::MAX_CROSSINGS_PER_TX)
    /// is met by construction.
    fn reoffers(&mut self, trie: &ShardTrie, now: WeightedTimestamp) -> Vec<CrossingReoffer> {
        let local = self.ledger.local();
        let mut outstanding: BTreeMap<(ShardId, TxHash), Vec<SubstateKey>> = BTreeMap::new();
        for (&key, record) in &self.held {
            if record.answered() || now < record.deadline().at() {
                continue;
            }
            let target = trie.shard_for_prefix(record.cell.consumer_claim.owner);
            if target == local {
                continue;
            }
            let Some(anchor) = self.proven_anchors.newest_licensed(target, now, |_| true) else {
                continue;
            };
            if record.offered_at.is_some_and(|(at, when)| {
                at >= anchor.height || now.elapsed_since(when) < MAX_FINALIZATION_DELAY
            }) {
                continue;
            }
            outstanding
                .entry((target, record.cell.tx))
                .or_default()
                .push(key);
        }
        // From past the last offer this validator composed, wrapping
        // once, so a backlog wider than a block's cap is walked rather
        // than the same head of it offered every time.
        let cursor = self.offer_cursor;
        let offers: Vec<CrossingReoffer> = outstanding
            .range((
                cursor.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            ))
            .chain(
                outstanding
                    .iter()
                    .take_while(|(key, _)| cursor.is_some_and(|at| **key <= at)),
            )
            .take(MAX_REOFFERS_PER_BLOCK)
            .filter_map(|(&(target, tx_hash), records)| {
                CrossingReoffer::new(target, tx_hash, records.iter().copied())
            })
            .collect();
        if let Some(last) = offers.last() {
            self.offer_cursor = Some((last.target, last.tx_hash));
        }
        offers
    }

    /// Ask each silent counterpart whether it took the transaction a
    /// leg here issued for, once the transaction's deadline has passed.
    ///
    /// The deadline gates the probe and never the reclaim: absence at a
    /// block past the floor is the evidence, and before it the
    /// counterpart may still legitimately act. Every core shard is asked
    /// about the transaction's committed cell past the deadline: any one
    /// of them absent is the whole answer, while a shard that still
    /// holds its cell says only that a member is pending — its refusal
    /// may yet retract it — and is asked again at each newer header. The
    /// shard holding the core consumer's target is asked about the
    /// consumer's claim, whose presence is what licenses the retirement.
    /// A delivering shard is asked about the crossing's claim cell past
    /// the lapse, the delivery window's close plus the finalization
    /// delay, since a delivery admitted under the close has claimed by
    /// then or never will. Each is asked against that shard's newest
    /// commit-proven header the question stands at — inside the window
    /// an absence answers in, at or past its floor and short of the
    /// probed cell's own sweep, or past the point a presence is asked
    /// from — of those standing at `now`, the chain's committed clock.
    ///
    /// That ceiling is what makes a committee ask one question rather
    /// than four. The answer is held to each voter's own reading, so a
    /// proposer anchoring where its peers did not sends every one of
    /// them to fetch bytes before it can vote; anchoring at a clock they
    /// share, on a header old enough that all of them hold it, they have
    /// already read the cell the block claims. A shard whose header has
    /// not reached here yet is asked when it does, and one whose every
    /// standing header is past the window is not asked at all: the entry
    /// then waits out its horizon.
    ///
    /// A delivering shard that departs at a reshape may leave no header
    /// past the lapse at all, so the claim cell is asked about wherever
    /// its prefix sits: on the shard that was to deliver it and on the
    /// shard the trie names for its owner now, which is the successor
    /// holding the departed chain's cells. Both are asked rather than
    /// the trie's answer alone, because the vote fence checks a record
    /// against the voter's own proof of the shard it names, and two
    /// validators straddling the cut would otherwise prove different
    /// shards and never both vote one record.
    ///
    /// The cell is named from signed content and the counterpart shard
    /// alone, so nothing but the header and the proof is fetched.
    pub(crate) fn probe(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        arrived: &BTreeMap<SubstateKey, Arrival>,
    ) -> Vec<Action> {
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        self.ask_entries(trie, now, &mut wanted);
        self.ask_held_records(trie, now, &mut wanted);
        self.ask_arrived_crossings(trie, now, arrived, &mut wanted);
        self.ask_written_answers(trie, now, &mut wanted);
        wanted
            .into_iter()
            .map(|(anchor, keys)| {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(keys.into_iter().map(|key| (anchor, key)).collect()),
                    shard: anchor.shard,
                    preferred: None,
                    class: None,
                })
            })
            .collect()
    }

    /// The questions this shard's entries open, each at the newest
    /// header it stands at.
    fn ask_entries(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        for question in self.ledger.questions(trie) {
            if !question.open_at(now) {
                continue;
            }
            let Question {
                shard,
                key,
                probed,
                deadline,
                cued,
                ..
            } = question;
            // The newest header the question stands at, of those
            // standing at the chain's clock: the one the shard is
            // likeliest to still serve, and the one every member of
            // this committee is asking of.
            let Some(anchor) = self
                .proven_anchors
                .newest_licensed(shard, now, |ts| probed.asks_at(ts, deadline, cued))
            else {
                continue;
            };
            // A question in flight, one whose answer this validator
            // holds to offer and one the chain answered are left alone:
            // a core's header lands every block, and moving a probe to
            // each new one abandons the fetch before its answer
            // returns. A probe whose fetch returned a reading that
            // answered nothing is moved on, which is how a cell read
            // outside its window is asked again — at a newer header,
            // not of the same one every block.
            if self.holds_answer(shard, key)
                || self
                    .probes
                    .get(&(shard, key))
                    .is_some_and(|probe| !probe.returned || probe.anchor.height >= anchor.height)
            {
                continue;
            }
            self.probes.insert(
                (shard, key),
                Probe {
                    question,
                    anchor,
                    returned: false,
                },
            );
            wanted.entry(anchor).or_default().push(key);
        }
    }

    /// The records this shard holds ask one question each, of whoever
    /// holds the claim's prefix now: has the consumer claimed?
    ///
    /// Nothing is asked of a claim this shard holds itself — the tick
    /// reads that cell directly — and nothing is asked twice at one
    /// header.
    ///
    /// Nothing is asked for a record an entry here settles, either: the
    /// entry asks its own questions under the transaction's name, and a
    /// second question about the same cell buys a proof the chain
    /// already carries and a certificate it has already fetched. The two
    /// ask where they each dispose.
    fn ask_held_records(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        let local = self.ledger.local();
        let ledger = &self.ledger;
        for record in self.held.values_mut() {
            if record.answered() || ledger.settles_records(record.cell.tx) {
                continue;
            }
            let claim = record.cell.consumer_claim;
            let shard = trie.shard_for_prefix(claim.owner);
            if shard == local {
                continue;
            }
            let Some(anchor) = self.proven_anchors.newest_licensed(shard, now, |_| true) else {
                continue;
            };
            if record.asked_at.is_some_and(|asked| asked >= anchor.height) {
                continue;
            }
            record.asked_at = Some(anchor.height);
            // Both cells, at one anchor. They are two keys under one
            // owner, so this is the one fetch it always was and one
            // claim carries both readings — and the question is not
            // "did the consumer claim" but "what did it answer", which
            // has two shapes and one of them is the refusal.
            let entry = wanted.entry(anchor).or_default();
            entry.push(claim);
            entry.push(record.consumer_decline);
        }
    }

    /// The crossings a bundle has handed this shard ask one question
    /// each, of the shard holding the record's prefix now: does the
    /// producer still hold it?
    ///
    /// A delivery past its transaction's validity end is admissible only
    /// against that reading, and the arrival is the only thing on this
    /// side that names the record. No entry here does until a delivery
    /// commits, and the crossing the whole owed strand is about is one
    /// whose delivery never ran — so an entry-driven question is empty
    /// for exactly the case the licence exists for.
    ///
    /// Asked from the **validity end** rather than from the deadline,
    /// because that is the instant past which the licence is needed:
    /// inside its own window the transaction is admissible on its own
    /// terms and the reading would license nothing.
    ///
    /// Asked until this shard holds an answer cell naming the record,
    /// which is where the delivery has run and
    /// [`ask_written_answers`](Self::ask_written_answers) takes the same
    /// question over. The pacing is reconciled against the absorptions
    /// rather than folded: what a bundle handed this shard is the
    /// provisioning account's to say.
    fn ask_arrived_crossings(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        arrived: &BTreeMap<SubstateKey, Arrival>,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        self.arrivals.retain(|key, _| arrived.contains_key(key));
        for (&record, arrival) in arrived {
            if now < arrival.deadline().validity_end()
                || answered_for(&self.answered, &arrival.cell)
            {
                continue;
            }
            let shard = trie.shard_for_prefix(record.owner);
            if shard == self.ledger.local() {
                continue;
            }
            let Some(anchor) = self.proven_anchors.newest_licensed(shard, now, |_| true) else {
                continue;
            };
            if self
                .arrivals
                .get(&record)
                .is_some_and(|&at| at >= anchor.height)
                || self.holds_answer(shard, record)
            {
                continue;
            }
            self.arrivals.insert(record, anchor.height);
            wanted.entry(anchor).or_default().push(record);
        }
    }

    /// The answers this shard has written ask one question each, of the
    /// shard holding the record's prefix now: does the producer still
    /// hold it?
    ///
    /// [`ask_held_records`](Self::ask_held_records) read from the other
    /// end, and paced by the same rule — nothing asked of a record this
    /// shard holds itself, and nothing asked twice at one header.
    fn ask_written_answers(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        for answer in self.answered.values_mut() {
            let record = answer.record;
            let shard = trie.shard_for_prefix(record.owner);
            if shard == self.ledger.local() {
                continue;
            }
            let Some(anchor) = self.proven_anchors.newest_licensed(shard, now, |_| true) else {
                continue;
            };
            if !answer.cleanup.wants(anchor)
                || answer.asked_at.is_some_and(|(asked, when)| {
                    asked >= anchor.height || now.elapsed_since(when) < RETENTION_HORIZON
                })
                || self.fetched.keys().any(|claim| {
                    claim.anchor.shard == shard
                        && claim.reading(record).is_some()
                        && answer.cleanup.wants(claim.anchor)
                })
            {
                continue;
            }
            answer.asked_at = Some((anchor.height, now));
            wanted.entry(anchor).or_default().push(record);
        }
    }

    /// Note an answer cell this shard holds, as the scan at start and
    /// the fold over its own finalizations do.
    #[cfg(test)]
    pub(crate) fn note_answer(&mut self, key: SubstateKey, answer: &CrossingAnswer) {
        self.answered.insert(key, AnsweredCrossing::of(answer));
    }

    /// Whether this shard has already answered the crossing `record`
    /// names, either way.
    ///
    /// Read off the answer cells this shard holds, which
    /// [`holding`](Self::holding) seeds from state rather than from a
    /// replay — so a seat that came up after the answer was written
    /// reads it whole.
    #[must_use]
    pub fn holds_answer_for(&self, cell: &CrossingCell) -> bool {
        answered_for(&self.answered, cell)
    }

    /// Whether this shard has already written down that it owes an
    /// answer for the crossing `record` names.
    ///
    /// [`holds_answer_for`](Self::holds_answer_for)'s neighbour, on the
    /// same terms: read off the cells this shard holds, which
    /// [`holding`](Self::holding) seeds from state, so a seat that came
    /// up after the note was written reads it whole.
    #[must_use]
    pub fn holds_obligation_for(&self, record: SubstateKey) -> bool {
        self.owed.values().any(|note| note.record == record)
    }

    /// Every obligation this shard holds, by the cell it sits at.
    #[must_use]
    pub const fn obligations(&self) -> &BTreeMap<SubstateKey, CrossingObligation> {
        &self.owed
    }

    /// Whether this validator holds an answering reading of `key` on
    /// `shard` to offer, so the question is not put to a counterpart
    /// again for an answer already in hand.
    fn holds_answer(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.fetched
            .keys()
            .any(|claim| claim.anchor.shard == shard && claim.reading(key).is_some())
    }

    /// Take what a fetched proof attests: hold it as proven, close the
    /// questions it answers, and keep the reading to offer in a block
    /// this validator proposes.
    ///
    /// The proof is walked once, on the way into [`ProvenCells`], and
    /// what comes back is the reading. That is what a block carries and
    /// what this validator's vote fence holds another proposer's block
    /// to, so it is recorded whatever the ledger wanted — a proof a peer
    /// relayed answers for a claim rather than for a probe, and the
    /// ledger has no entry waiting on it.
    ///
    /// What the ledger did ask about is what is offered. The probes the
    /// proof spoke to are marked answered, so the question is not put to
    /// the same header again, and a reading that answered is kept
    /// beside the transactions it answered for, which is what keeps the
    /// question from being put to any header until a block carries it.
    pub(crate) fn on_proof_fetched(
        &mut self,
        anchor: Anchor,
        keys: Vec<SubstateKey>,
        proof: MerkleInclusionProof,
    ) {
        let answered: Vec<Question> = self
            .probes
            .values_mut()
            .filter(|probe| {
                !probe.returned && probe.anchor == anchor && keys.contains(&probe.question.key)
            })
            .map(|probe| {
                probe.returned = true;
                probe.question
            })
            .collect();
        let Some(inclusions) = self.proven_cells.record(anchor, keys, proof) else {
            tracing::warn!(
                shard = ?anchor.shard,
                height = anchor.height.inner(),
                "A fetched state proof does not answer for its keys"
            );
            return;
        };
        // A question the proof answered is not put again, and the
        // reading that answered it is the one held to offer: what the
        // answer means is still the chain's to say, and until a block
        // carries the claim nothing here has composed anything from it.
        //
        // One rule for both, because a reading that answers nothing is
        // worth neither. A probe fires from the deadline, and a lapse
        // opens a validity range past it, so the readings taken in
        // between are absences outside their window — true of the tree
        // and mute about the question. Offering one spends a block's
        // cap on a cell no record can be composed from, and holds every
        // voter to a non-answer taken at one height.
        let mut answering: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut speaks_for: BTreeSet<TxHash> = BTreeSet::new();
        for question in &answered {
            let Some(&(_, inclusion)) = inclusions.iter().find(|(key, _)| *key == question.key)
            else {
                continue;
            };
            if question
                .probed
                .answer(anchor.ts, question.deadline, inclusion)
                .is_some()
            {
                answering.insert(question.key);
                speaks_for.insert(question.tx_hash);
            } else {
                record_reclaim_probe_pending();
            }
        }
        answering.extend(
            inclusions.iter().map(|(key, _)| *key).filter(|key| {
                wants_reading(&self.held, &self.answered, &self.arrivals, anchor, *key)
            }),
        );
        if answering.is_empty() {
            return;
        }
        let cells = inclusions
            .iter()
            .copied()
            .filter(|(key, _)| answering.contains(key));
        self.fetched
            .entry(StateClaim::new(anchor, cells))
            .or_default()
            .extend(speaks_for);
    }

    /// Fold the claims a committed block carries into the answers every
    /// replica holds, and hand each to the vote fence.
    ///
    /// A claim answers every cell of the ledger's on the anchor's shard
    /// whose window the anchor's clock sits inside — whether or not this
    /// replica had a probe out, and wherever its own probe sat — so a
    /// replica that never fetched reads the same answer as the one that
    /// did. A claim cell present is the consumer holding the crossing,
    /// which is written straight to the ledger and licenses the
    /// retirement, and the counterpart's own certificate speaks for the
    /// verdict next. A core consumer's claim absent says only that a
    /// sibling is pending, and a committed cell present that a member
    /// is; either is asked again at the next header.
    /// The first proof to answer a cell is the answer; a later one adds
    /// nothing. The hand-off is a continuation emitted here rather than
    /// a map the fence reads later, so an answer is never collected
    /// before it is drained.
    fn fold_state_claims(&mut self, trie: &ShardTrie, block: &Block) -> Vec<Action> {
        if block.state_claims().is_empty() {
            return Vec::new();
        }
        let questions = self.ledger.questions(trie);
        let mut actions = Vec::new();
        for claim in block.state_claims() {
            actions.extend(self.fold_cells(claim, &questions));
            self.fold_held(claim, trie);
            self.fold_answered(claim, trie);
        }
        actions
    }

    /// Read a committed proof against the two cells the held records
    /// are waiting on.
    ///
    /// Both answers are presences, and each is written by the one thing
    /// that writes it: the claim by the consuming execution, the
    /// decline by the consumer's chain. So a presence of either answers
    /// wherever it was taken, and [`Probed`]'s own rule is what says
    /// so rather than a second statement of it here.
    ///
    /// **The claim is read first, and that ordering is the rule.** A
    /// record carrying both cells present is a refusal rather than a
    /// preference — the consumer's own licence is what makes it
    /// impossible — but a producer reading one is not the place to
    /// discover it, and taking back value a consumer demonstrably holds
    /// is the one mistake this cannot make. So a presence of the claim
    /// decides, and nothing below it is reached.
    ///
    /// The claim's *absence* is read last, and only inside
    /// [`held_absence_answers`], which is where a leaf that does not
    /// name its consumer's role can read one honestly. It is the road
    /// the decline replaces, kept until every reader of it goes
    /// together.
    fn fold_held(&mut self, stated: &StateClaim, trie: &ShardTrie) {
        for record in self.held.values_mut() {
            if record.answered() {
                continue;
            }
            let claim = record.cell.consumer_claim;
            if trie.shard_for_prefix(claim.owner) != stated.anchor.shard {
                continue;
            }
            let read = |key, probed: Probed| {
                stated
                    .reading(key)
                    .and_then(|inclusion| probed.read(inclusion))
            };
            if let Some(inclusion) = read(claim, Probed::Claim) {
                record.answer = Some(inclusion);
            } else if read(record.consumer_decline, Probed::Decline).is_some() {
                record.declined = true;
            } else if matches!(stated.reading(claim), Some(Inclusion::Absent))
                && held_absence_answers(stated.anchor.ts, record.deadline())
            {
                record.answer = Some(Inclusion::Absent);
            }
        }
    }

    /// Read a committed proof against the records this shard's own
    /// answers are waiting on.
    ///
    /// [`fold_held`](Self::fold_held) mirrored, with one difference that
    /// is the whole of what a record is: there is no window here, so
    /// **every** reading is recorded, whichever way it went.
    ///
    /// A claim's absence is read inside a window because a leaf holding
    /// one cannot tell a consumer that refused from one that has not run
    /// yet. A record's cannot be mistaken that way: it is written by the
    /// one execution that issues the crossing and removed by the one
    /// that disposes of it. So a reading of one is a fact at whatever
    /// anchor it was taken — present says the producer still holds the
    /// value, absent says it has disposed of it — and both are worth
    /// holding, if only so the question stops being asked.
    ///
    /// What a fact *licenses* is a separate question, and
    /// [`Probed::read`] is where it is answered. Nothing licenses
    /// anything off an absence here yet.
    fn fold_answered(&mut self, stated: &StateClaim, trie: &ShardTrie) {
        for answer in self.answered.values_mut() {
            if trie.shard_for_prefix(answer.record.owner) != stated.anchor.shard {
                continue;
            }
            if let Some(inclusion) = stated.reading(answer.record) {
                answer.cleanup = answer.cleanup.read(stated.anchor, inclusion);
            }
        }
    }

    /// Fold one claim's answers into the questions the ledger is
    /// waiting on.
    fn fold_cells(&mut self, claim: &StateClaim, questions: &[Question]) -> Vec<Action> {
        let mut actions = Vec::new();
        for &Question {
            tx_hash,
            shard,
            key,
            probed,
            deadline,
            ..
        } in questions
        {
            if shard != claim.anchor.shard {
                continue;
            }
            let Some(inclusion) = claim.reading(key) else {
                continue;
            };
            // Judged per cell by the one rule, whoever fetched the
            // proof: an absence is read only inside its window and only
            // for the cell a refusal leaves absent, a presence wherever
            // it was taken and only for the cell a claim writes — and a
            // probe never sent may still be answered by a claim a block
            // carries.
            let Some(inclusion) = probed.answer(claim.anchor.ts, deadline, inclusion) else {
                continue;
            };
            // The question is answered with what the chain read. A
            // claim cell present is the consumer holding the crossing,
            // which is what licenses the retirement.
            if !self
                .ledger
                .record_reading(tx_hash, shard, key, probed, inclusion)
            {
                continue;
            }
            record_reclaim_probe_answered(inclusion.is_present());
            // The counterpart took it, and its certificate says how.
            // Its broadcast may have missed this shard, so it is fetched
            // rather than waited for.
            if inclusion.is_present() {
                actions.push(Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::ExecutionCerts(vec![(shard, tx_hash)]),
                    shard,
                    preferred: None,
                    class: None,
                }));
            }
        }
        actions
    }

    /// Write what the block's records cover into the mirror the gate and
    /// the fence read: neither asks a settled set about a transaction a
    /// departed counterpart's record has established it never settled.
    fn cover_recorded(&self, block: &Block) {
        for record in block.abandonment_records() {
            for tx_hash in record.tx_hashes() {
                self.mirror.cover(tx_hash);
            }
        }
    }

    /// Follow the crossing cells this block's finalizations put into
    /// state, so what is held is what the leaves hold and what is
    /// answered is what they answer.
    ///
    /// One walk for both families, because it is one question — what did
    /// this block write — with two readers, and two walks that had to
    /// name the same receipts is a shape this plan keeps paying for.
    ///
    /// The set the leaf paths compose from has to be the leaf set, and
    /// a scan at startup is only its first term. A crossing issued after
    /// it would otherwise never be held at all, and a record the ledger
    /// disposed of would be held after its leaf was gone — and a
    /// disposal composed over a cell nothing can read is refused, which
    /// strands the rest of its member with it. The answering side is the
    /// same need from the other end: a crossing answered after the scan
    /// would never be held, and an answer already deleted would be held
    /// after its leaf was gone.
    ///
    /// **[`Finalization::settling_receipts`] and not `receipts`**, which
    /// is not the same set and was the defect here. A finalization
    /// carries every receipt its tick produced; what reaches state is
    /// what its certificates *decide*, which drops every member
    /// `uncovered_transactions` names and every refused one bar its
    /// charge — the distinction that function's own doc draws, between
    /// what execution produced and what the tick decided. A member that
    /// succeeded here and was then left uncovered by a counterpart
    /// carries `Succeeded` writes with its cell in them, and those
    /// writes never land. Folded from the wider set, this shard holds a
    /// record no disposal can read, and an answer for a crossing nobody
    /// answered — which stands `admit_refusals` down for good, so the
    /// producer waits on a verdict that is never coming.
    ///
    /// Read off this shard's own finalizations, which is where its
    /// writes are stated, so every replica at one frontier folds the
    /// same set from the same blocks. A leaf that does not decode is one
    /// no member could be composed from, as at the scan.
    fn fold_crossing_writes(&mut self, block: &Block) {
        for finalization in block.certificates().iter() {
            for receipt in finalization.as_unverified().settling_receipts() {
                let Some(writes) = receipt.consensus.writes() else {
                    continue;
                };
                for (key, value) in &writes.cells {
                    match value {
                        Some(bytes) if is_record_cell(*key, bytes) => {
                            if let Some(cell) = CrossingCell::from_bytes(bytes) {
                                self.held
                                    .entry(*key)
                                    .or_insert_with(|| HeldRecord::of(cell));
                            }
                        }
                        Some(bytes) if is_crossing_answer_cell(*key, bytes) => {
                            if let Some(claim) = CrossingAnswer::from_bytes(bytes) {
                                self.answered
                                    .entry(*key)
                                    .or_insert_with(|| AnsweredCrossing::of(&claim));
                            }
                        }
                        Some(bytes) if is_crossing_obligation_cell(*key, bytes) => {
                            if let Some(note) = CrossingObligation::from_bytes(bytes) {
                                self.owed.entry(*key).or_insert(note);
                            }
                        }
                        None => {
                            self.held.remove(key);
                            self.answered.remove(key);
                            self.owed.remove(key);
                        }
                        Some(_) => {}
                    }
                }
            }
        }
    }

    /// Mark the records this block's departures have licensed a reclaim
    /// of: those whose issuing transaction a record names unsettled.
    ///
    /// Every record the transaction issued here, not only one crossing
    /// into the departed shard. A record establishes the transaction was
    /// never settled anywhere, and a crossing is claimed only where the
    /// transaction was accepted — so none of them was.
    ///
    /// The same evidence the ledger takes as `departed_by`, read where
    /// the record is rather than where the entry was. An entry is gone
    /// one [`CLAIM_WINDOW`](hyperscale_types::CLAIM_WINDOW) past the
    /// deadline and a departure can land later than that; the leaf is
    /// still here, and it is what the disposal is composed from.
    fn cover_held(&mut self, block: &Block) {
        if self.held.is_empty() {
            return;
        }
        let named: BTreeSet<TxHash> = block
            .abandonment_records()
            .iter()
            .flat_map(AbandonmentRecord::tx_hashes)
            .collect();
        if named.is_empty() {
            return;
        }
        for record in self.held.values_mut() {
            record.departed = record.departed || named.contains(&record.cell.tx);
        }
    }

    /// Stamp the records this block promised again with the consumer
    /// header each promise was made against, so the next proposal does
    /// not promise the same crossing before that consumer could have
    /// answered.
    ///
    /// Read off the block rather than off what a proposer composed: an
    /// offer counts once it is committed, so one composed and lost with
    /// its round is not one the next proposal skips. The header is this
    /// validator's own newest proven one of the target, which is pacing
    /// and licenses nothing — what a block carries is what every replica
    /// agrees on.
    fn fold_reoffers(&mut self, reoffers: &[CrossingReoffer], now: WeightedTimestamp) {
        for offer in reoffers {
            let Some(anchor) = self
                .proven_anchors
                .newest_licensed(offer.target, now, |_| true)
            else {
                continue;
            };
            for key in offer.records.iter() {
                if let Some(record) = self.held.get_mut(key) {
                    record.offered_at = Some((anchor.height, now));
                }
            }
        }
    }

    /// Tell the mempool a core's refusal of a transaction a leg here
    /// issued for: the verdict, as the counterpart's certificate carries
    /// it. Nothing is written down — what licenses taking the crossing
    /// back is the committed cell the refusal retracts, read absent past
    /// the deadline — and the mempool reads a verdict it already holds
    /// as nothing new.
    pub(crate) fn relay_refusal(
        &self,
        shard: ShardId,
        tx_hash: TxHash,
        decision: TransactionDecision,
    ) -> Vec<Action> {
        if shard == self.ledger.local() || !self.ledger.core_holds(tx_hash, shard) {
            return Vec::new();
        }
        vec![Action::Continuation(ProtocolEvent::TransactionsResolved {
            resolutions: vec![(tx_hash, TxResolution::CoreDecided(decision))],
        })]
    }

    /// Fold a counterpart's claiming success: the cue to ask whether it
    /// wrote the claim, and — where the shard is in the core — one more
    /// core shard saying the transaction went through.
    ///
    /// Nothing is written down. A success is not evidence: its own
    /// finalization can still be refused afterwards, so what a record
    /// stands on is the claim cell proved present, and this only opens
    /// the question.
    pub(crate) fn fold_claimed(
        &mut self,
        shard: ShardId,
        tx_hash: TxHash,
        at: WeightedTimestamp,
    ) -> Vec<Action> {
        if shard == self.ledger.local() {
            return Vec::new();
        }
        if self.ledger.consumer_holds(tx_hash, shard) {
            self.ledger.cue_probe(tx_hash, at);
        }
        if self.ledger.core_holds(tx_hash, shard) && self.ledger.record_acceptance(tx_hash, shard) {
            return vec![Action::Continuation(ProtocolEvent::TransactionsResolved {
                resolutions: vec![(
                    tx_hash,
                    TxResolution::CoreDecided(TransactionDecision::Accept),
                )],
            })];
        }
        Vec::new()
    }

    /// The readings this validator's own fetches took that no block has
    /// carried yet, in the one order a block carries them, under the
    /// block's cap.
    fn state_claims(&self) -> Vec<StateClaim> {
        self.fetched
            .keys()
            .take(MAX_STATE_CLAIMS_PER_BLOCK)
            .cloned()
            .collect()
    }

    /// Drop the claims no transaction they answered for still needs,
    /// and the probes whose question is no longer open — one the chain
    /// answered first, or one whose entry is gone — releasing every
    /// fetch still out for one, so a counterpart that never serves the
    /// height does not pin the slot.
    fn release_answered_fetches(&mut self, trie: &ShardTrie) -> Vec<Action> {
        let unresolved = &self.ledger;
        // A claim is worth carrying while something still wants what it
        // answers: a transaction the ledger owes an outcome for, or a
        // leaf-driven question of this shard's, by [`wants_reading`] —
        // the same predicate that decided the reading was worth keeping
        // when the fetch landed.
        let held = &self.held;
        let answered = &self.answered;
        let arrivals = &self.arrivals;
        self.fetched.retain(|claim, speaks_for| {
            speaks_for
                .iter()
                .any(|tx_hash| unresolved.contains(*tx_hash))
                || claim
                    .cells
                    .iter()
                    .any(|(key, _)| wants_reading(held, answered, arrivals, claim.anchor, *key))
        });
        // The one retention rule for what counterparts said: an entry
        // there speaks for a transaction this ledger still owes an
        // outcome for, and the ledger is here.
        self.mirror.retain(&|tx_hash| unresolved.contains(tx_hash));
        // A probe lives while its question is open, and the ledger says
        // which those are.
        let open: BTreeSet<(ShardId, SubstateKey)> = unresolved
            .questions(trie)
            .into_iter()
            .map(|question| (question.shard, question.key))
            .collect();
        let mut released = Vec::new();
        self.probes.retain(|cell, probe| {
            if open.contains(cell) {
                return true;
            }
            if !probe.returned {
                released.push((probe.anchor, probe.question.key));
            }
            false
        });
        if released.is_empty() {
            Vec::new()
        } else {
            vec![Action::AbandonFetch(FetchIds::StateProofs(released))]
        }
    }

    /// The records this shard has evidence for and has not yet written
    /// down: what each departed counterpart left of its business here.
    ///
    /// Composed from the settled sets, which is what bounds when this can
    /// speak at all: a set is acquired once the departed shard's terminal
    /// roots are attested and dropped at its evidence expiry, so a record
    /// is only ever offered while the evidence for it is readable, which
    /// is the same window every voter can check it in. Absence from a set
    /// is proof rather than ignorance — the set is complete and
    /// beacon-attested — so a transaction of ours it does not name is one
    /// that shard never settled and now never will.
    ///
    /// Bounded by [`MAX_PROPOSAL_EVIDENCE_BYTES`] and by
    /// [`MAX_UNSETTLED_PER_BLOCK`], one of each across every record,
    /// with the remainder left for the next block. The bytes are what
    /// stops first: a name's cost varies with its reach, so the count
    /// alone would admit a section several frames wide.
    ///
    /// Which of them the budgets reach is the same on every proposer: a
    /// departure is composed from the settled sets, which every replica
    /// at a committed height holds alike. Truncating loses nothing — a
    /// name no record carries stays uncovered and is offered again next
    /// block.
    ///
    /// Ascending by shard, which is the one order a block may carry them
    /// in.
    fn abandonment_records(&self) -> Vec<AbandonmentRecord> {
        let mut budget = Budget::empty();
        let mut records: BTreeMap<ShardId, AbandonmentRecord> = BTreeMap::new();
        // The sets are a hash map, so the shards are walked in sorted
        // order rather than its own: which departures the budget reaches
        // must not turn on a per-process iteration order.
        self.mirror.with_settled(|sets| {
            let mut shards: Vec<ShardId> = sets.keys().copied().collect();
            shards.sort_unstable();
            for shard in shards {
                if budget.spent() || records.len() == MAX_PROVISION_TARGET_SHARDS {
                    break;
                }
                let settled = &sets[&shard];
                let mut unsettled = self.ledger.outstanding_with(shard, settled.terminal_wt);
                unsettled.retain(|entry| !settled.txs.contains(&entry.tx_hash));
                budget.take(&mut unsettled);
                if unsettled.is_empty() {
                    continue;
                }
                let record = AbandonmentRecord::new(shard, settled.terminal_wt, unsettled);
                records.insert(shard, record);
            }
        });
        records.into_values().collect()
    }

    /// Record where each departed shard's chain ended, for the entries
    /// whose fate only that shard's settled set can decide.
    ///
    /// Read on every commit, while the schedule still carries the window
    /// that proves the terminal — the account outlives that window, and a
    /// departure it never recorded reads afterwards as a counterpart that
    /// never left. Re-run rather than gated on first sight, because the
    /// expiry is not knowable at the cut: the beacon stamps the handoff
    /// complete some epochs later, and the ledger's entry fills in on the
    /// first commit after the stamp lands.
    pub(crate) fn stamp_departures(
        &mut self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) {
        for (shard, cut) in topology_schedule.departures_at(now) {
            if shard != self.ledger.local() {
                self.ledger.record_terminal(
                    shard,
                    cut,
                    topology_schedule.handoff_evidence_expiry(shard),
                );
            }
        }
        // A departure held open is asked about by name on every commit,
        // since the schedule lists it only while a retained window
        // carries the shard and the stamp lands on the head's boundary
        // record, which outlives that window. One whose evidence the
        // schedule no longer reads at all closes now — the same reading
        // the settled sets are dropped on — so an entry a record covers
        // against it retires with the set that could have answered.
        for shard in self.ledger.unstamped_departures() {
            if let Some(expiry) = topology_schedule.handoff_evidence_expiry(shard) {
                self.ledger.stamp_terminal(shard, expiry);
            } else if !topology_schedule.terminal_evidence_readable(shard, now) {
                self.ledger.stamp_terminal(shard, now);
            }
        }
    }

    /// Fold every verdict a certificate carries, before it is routed:
    /// the leg's tick settled long ago, so the certificate routes
    /// nowhere, and what it says is the one thing in it this shard still
    /// has a use for.
    pub(crate) fn on_certificate(
        &mut self,
        ec: &Arc<Verified<ExecutionCertificate>>,
    ) -> Vec<Action> {
        let shard = ec.shard_id();
        let mut actions = Vec::new();
        for (tx_hash, spoken) in ec.verdicts() {
            actions.extend(match spoken {
                Spoken::Refused(decision) => self.relay_refusal(shard, tx_hash, decision),
                Spoken::Claimed { at } => self.fold_claimed(shard, tx_hash, at),
            });
        }
        actions
    }

    /// Whether `shard`'s settled set stands in for a commit proof of this
    /// certificate's source block.
    ///
    /// Membership means the transaction's certificate committed in the
    /// departed chain at or before its terminal, and the set itself was
    /// verified against the beacon-attested terminal root — a stronger
    /// statement than a commit proof of one source block, which is
    /// exactly what a departed chain can no longer supply. Every outcome
    /// must be named: one outside the set is a verdict the departed
    /// shard never settled, and a certificate naming nothing gives the
    /// set nothing to vouch for.
    pub(crate) fn settled_set_admits(
        &self,
        shard: ShardId,
        cert: &Verifiable<ExecutionCertificate>,
    ) -> bool {
        self.mirror.with_settled(|sets| {
            sets.get(&shard).is_some_and(|settled| {
                let outcomes = cert.tx_outcomes();
                !outcomes.is_empty()
                    && outcomes
                        .iter()
                        .all(|outcome| settled.txs.contains(&outcome.tx_hash()))
            })
        })
    }

    /// Drop settled sets past their evidence window. Past it the gate
    /// rejects any outcome naming the shard regardless of the set, so
    /// retaining it only leaks memory.
    fn gc_settled_sets(&self, topology_schedule: &TopologySchedule, now: WeightedTimestamp) {
        self.mirror
            .retain_departures(&|shard| topology_schedule.terminal_evidence_readable(shard, now));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::state_and_proof;
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, BlockHeight, CLAIM_WINDOW, CommittedAt, Hash, LocalKey,
        ResourceAddr, RoutePrefix, StateRoot, evidence_admits_block,
    };
    use hyperscale_vm_effects::{Hash32, IntentHash, Terms};

    use super::*;

    /// One name reaching `routes` prefixes, seeded by `seed`.
    fn name(seed: usize, routes: usize) -> UnsettledTx {
        let byte = u8::try_from(seed % 256).expect("masked");
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(&seed.to_le_bytes())),
            deadline: Deadline::of(WeightedTimestamp::from_millis(60_000)),
            charged: 5,
            charge: AbortCharge {
                vault: SubstateKey {
                    owner: Address::new([byte; 31], AddressClass::Component),
                    local: LocalKey([byte; 16]),
                },
                amount: 1,
            },
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::ZERO,
                committee_anchor: WeightedTimestamp::ZERO,
            },
            reach: Capped::new(
                (0..routes)
                    .map(|at| {
                        RoutePrefix::from(Address::new(
                            [u8::try_from(at % 256).expect("masked"); 31],
                            AddressClass::Component,
                        ))
                    })
                    .collect(),
            )
            .expect("a reach written out in a test"),
        }
    }

    /// The shard a record's owner prefix routes to, and the one this
    /// fixture's consumer is not.
    const PRODUCER: ShardId = ShardId::leaf(1, 1);
    const CONSUMER: ShardId = ShardId::leaf(1, 0);

    /// A record cell under a prefix `PRODUCER` holds.
    fn producer_record(seed: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([0xAA; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        }
    }

    /// A consumer holding one owed claim, over a two-shard trie.
    fn answering(record: SubstateKey) -> (Counterparts, ShardTrie, Arc<ProvenAnchors>) {
        let anchors = Arc::new(ProvenAnchors::default());
        let mut counterparts = Counterparts::holding(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(ProvenCells::default()),
            Arc::new(CounterpartMirror::default()),
            &CrossingLeaves::default(),
        );
        counterparts.answered.insert(
            SubstateKey {
                owner: Address::new([0x11; 31], AddressClass::Component),
                local: LocalKey([0x01; 16]),
            },
            AnsweredCrossing {
                record,
                asked_at: None,
                cleanup: Cleanup::Standing(None),
            },
        );
        (
            counterparts,
            ShardTrie::from_leaves([CONSUMER, PRODUCER]),
            anchors,
        )
    }

    /// A consumer asks its producer about the record its own answer
    /// names, and stops once the chain has read it.
    ///
    /// The one question that runs from consumer to producer, and the
    /// whole of what the leaf has to carry for it to be askable: the
    /// claim's own key derives under the consuming node's target and the
    /// record's under the producing node's, so without the record on the
    /// leaf there is nothing here to name.
    ///
    /// Paced like the producer's own probe — one question per header, and
    /// none at a header already asked at — because it is the same loop
    /// read from the other end.
    #[test]
    fn a_consumer_asks_its_producer_about_the_record_its_answer_names() {
        let record = producer_record(0x42);
        let (mut counterparts, trie, anchors) = answering(record);
        let now = WeightedTimestamp::from_millis(60_000);

        assert!(
            counterparts.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "a producer this node has proven no anchor of is unaskable",
        );

        // The producer's tree with the record gone — the ordinary case,
        // since a producer retires a record the moment it reads the
        // claim answering it.
        let (state_root, proof) = state_and_proof(PRODUCER, &[], &[record]);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        let asked = counterparts.probe(&trie, now, &BTreeMap::new());
        assert_eq!(
            asked.len(),
            1,
            "the record is asked for, at the newest anchor of the shard holding it",
        );
        assert!(
            matches!(
                &asked[0],
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(keys),
                    shard,
                    ..
                }) if *shard == PRODUCER && keys.as_slice() == [(anchor, record)],
            ),
            "and what is asked for is the record itself: {:?}",
            asked[0],
        );
        assert!(
            counterparts.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "and not again at the same header",
        );

        // Nor at a newer one while the fetch is still out. A question
        // driven by a leaf is not in the probe account, so nothing else
        // would stop it being put again at every header the producer
        // commits — one fetch a block, per crossing this shard ever
        // answered, until the reading lands.
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        counterparts.on_proof_fetched(anchor, vec![record], proof);
        assert!(
            counterparts.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "and not at a newer header while the reading is held to offer",
        );
        assert!(
            counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "the reading a leaf-driven question wanted is offered, not dropped: a \
             question whose answer never reaches a block is asked forever",
        );

        // The record reads absent, which is the producer having
        // disposed of it — a fact, because a record is swept by
        // nothing. One of those is not enough to clean up against,
        // so what it closes is this anchor and not the question.
        let read_absent = |counterparts: &mut Counterparts, at: Anchor| {
            counterparts.fold_answered(
                &StateClaim {
                    anchor: at,
                    cells: Capped::new(vec![(record, Inclusion::Absent)]).expect("one cell"),
                },
                &trie,
            );
        };
        read_absent(&mut counterparts, anchor);
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            counterparts.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "no anchor short of the span could tell this shard anything it does not know",
        );
        assert_eq!(
            counterparts
                .answered
                .values()
                .next()
                .map(|answer| answer.cleanup),
            Some(Cleanup::Once(anchor)),
            "and the one absence is held, with the anchor it was read at",
        );
    }

    /// A record that still stands is asked about again, but only once
    /// a span has passed.
    ///
    /// Both halves cost something and each is asserted where the other
    /// would hide it. A reading that is never repeated never learns the
    /// producer disposed, so the answer cell stands for good and the
    /// state this plan ships never drains. A reading repeated at every
    /// header of a live producer is a fetch a block and a claim in
    /// every block — each one a cell every voter proves for itself,
    /// which is enough under cross-shard load to burn a round.
    ///
    /// The span is the pace because asking faster cannot help: two
    /// absences license a deletion only a [`RETENTION_HORIZON`] apart,
    /// so the shortest path to a cleanable answer is one span whatever
    /// the rate.
    #[test]
    fn a_standing_record_is_asked_about_again_only_once_a_span_has_passed() {
        let record = producer_record(0x42);
        let (mut counterparts, trie, anchors) = answering(record);
        let now = WeightedTimestamp::from_millis(60_000);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: now,
        };
        let (state_root, proof) = state_and_proof(PRODUCER, &[record], &[record]);
        let anchor = Anchor {
            state_root,
            ..anchor
        };
        anchors.record(anchor);
        assert_eq!(counterparts.probe(&trie, now, &BTreeMap::new()).len(), 1);
        counterparts.on_proof_fetched(anchor, vec![record], proof);

        // The record is there: the producer has not disposed of it, so
        // the question is worth putting again — and this reading is
        // spent, or every block carries it again.
        let landed = counterparts
            .fetched
            .keys()
            .find(|claim| claim.reading(record).is_some())
            .cloned()
            .expect("the proof landed as a reading");
        assert!(
            matches!(landed.reading(record), Some(Inclusion::Present(_))),
            "the fixture's proof says the record stands",
        );
        counterparts.fold_answered(&landed, &trie);
        counterparts.release_answered_fetches(&trie);
        assert!(
            !counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "a folded reading is spent whichever way it went",
        );

        let next = Anchor {
            height: BlockHeight::new(8),
            ts: now.plus(Duration::from_secs(1)),
            ..anchor
        };
        anchors.record(next);
        assert!(
            counterparts
                .probe(&trie, next.ts, &BTreeMap::new())
                .is_empty(),
            "and a header a block later is not worth a second question",
        );

        let later = Anchor {
            height: BlockHeight::new(9),
            ts: now.plus(RETENTION_HORIZON).plus(Duration::from_secs(1)),
            ..anchor
        };
        anchors.record(later);
        assert_eq!(
            counterparts.probe(&trie, later.ts, &BTreeMap::new()).len(),
            1,
            "a span later it is: nothing else would ever learn the record had gone",
        );
    }

    /// A second absence, past the span, closes the question — and what
    /// the answer then holds is the pair a deletion is composed
    /// against.
    #[test]
    fn a_second_absence_past_the_span_closes_the_question() {
        let record = producer_record(0x42);
        let (mut counterparts, trie, anchors) = answering(record);
        let now = WeightedTimestamp::from_millis(60_000);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: now,
        };
        let read_absent = |counterparts: &mut Counterparts, at: Anchor| {
            counterparts.fold_answered(
                &StateClaim {
                    anchor: at,
                    cells: Capped::new(vec![(record, Inclusion::Absent)]).expect("one cell"),
                },
                &trie,
            );
        };
        read_absent(&mut counterparts, anchor);

        let far = Anchor {
            height: BlockHeight::new(9),
            ts: now.plus(RETENTION_HORIZON).plus(Duration::from_secs(1)),
            ..anchor
        };
        anchors.record(far);
        assert_eq!(
            counterparts.probe(&trie, far.ts, &BTreeMap::new()).len(),
            1,
            "an anchor far enough past the first is one a second reading can come from",
        );
        read_absent(&mut counterparts, far);
        assert_eq!(
            counterparts
                .answered
                .values()
                .next()
                .map(|answer| answer.cleanup),
            Some(Cleanup::Twice(anchor, far)),
            "two absences far enough apart are the licence, and they are what it carries",
        );
        anchors.record(Anchor {
            height: BlockHeight::new(10),
            ..far
        });
        assert!(
            counterparts
                .probe(&trie, far.ts, &BTreeMap::new())
                .is_empty(),
            "and the question is closed: nothing more is worth asking of this record",
        );
    }

    /// Two absences license a deletion only at two anchors of the
    /// producer a retention span apart.
    ///
    /// The span is the whole of the rule, and it is measured on the
    /// **producer's** clock. A retention floor moves inside the
    /// producer's own commit, so a halted producer's floor freezes with
    /// its tip and it serves every block at or below the absence anchor
    /// indefinitely — while this chain's clock runs on. A pair read too
    /// close together names a producer that may still be serving the
    /// bundle a replay needs, and a replay needs no stale evidence: the
    /// bundle is fresh and the record-present proof sits below the
    /// disposal.
    #[test]
    fn two_absences_license_nothing_until_a_retention_span_separates_them() {
        let at = |secs: u64| Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(secs),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(secs * 1_000),
        };
        let first = at(1_000);
        let one = Cleanup::Standing(None).read(first, Inclusion::Absent);
        assert_eq!(one, Cleanup::Once(first));
        assert!(
            !matches!(one, Cleanup::Twice(..)),
            "one absence licenses nothing",
        );

        let close = at(1_000 + RETENTION_HORIZON.as_secs());
        assert!(
            !one.wants(close),
            "an anchor at exactly the span is not past it, so it is not worth asking at",
        );
        assert_eq!(
            one.read(close, Inclusion::Absent),
            one,
            "and a reading taken there advances nothing",
        );

        let far = at(1_001 + RETENTION_HORIZON.as_secs());
        assert!(one.wants(far), "past the span it is worth asking at");
        let two = one.read(far, Inclusion::Absent);
        assert_eq!(two, Cleanup::Twice(first, far));
        assert!(
            !two.wants(at(9_999)),
            "and nothing further is worth asking: the answer is cleanable",
        );
        assert_eq!(
            two.read(at(9_999), Inclusion::Absent),
            two,
            "the pair a deletion is composed against does not drift to newer anchors",
        );
    }

    /// A reading a leaf-driven question wanted survives the commit that
    /// follows it, and is still there to be offered.
    ///
    /// The retention rule and the rule that decides a landed fetch is
    /// worth keeping are the same rule, and a source named in one and
    /// missed in the other is not a dropped answer but an unbounded
    /// stream: the reading goes at the next commit, no block ever carries
    /// it, the fold never fires, and the question is put again at the
    /// producer's next header — once per block, per crossing this shard
    /// ever answered.
    ///
    /// Asserted across the commit's own release rather than at the
    /// fetch, because that is where the two rules can come apart: the
    /// fetch site keeps the reading and the release throws it away, so a
    /// test that stops at the fetch passes either way.
    #[test]
    fn a_reading_a_leaf_wanted_outlives_the_commit_that_follows_it() {
        let record = producer_record(0x42);
        let (mut counterparts, trie, anchors) = answering(record);
        let now = WeightedTimestamp::from_millis(60_000);
        let (state_root, proof) = state_and_proof(PRODUCER, &[], &[record]);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        assert_eq!(counterparts.probe(&trie, now, &BTreeMap::new()).len(), 1);
        counterparts.on_proof_fetched(anchor, vec![record], proof);

        // The commit's own pass over what is still wanted. Nothing here
        // names a transaction this ledger owes an outcome for, which is
        // the other half of the retention rule.
        counterparts.release_answered_fetches(&trie);
        assert!(
            counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "the reading is still there to offer",
        );
        assert_eq!(
            counterparts.state_claims().len(),
            1,
            "and a block this validator proposes carries it",
        );
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            counterparts.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "so the question is not put again at the producer's next header",
        );
    }

    /// A reading that has been folded is released, and the question
    /// that wants its successor is not held down by it.
    ///
    /// The retention rule and the asking rule are one rule, and this is
    /// the case where keying it on the cell alone comes apart: a first
    /// absence is folded, the reading that carried it is spent, and the
    /// question now wants a *second* at an anchor a span later. Held on
    /// the key, the spent reading is kept for the whole span and the
    /// asking stands down for it — a question and its answer each
    /// waiting on the other, for one retention horizon per crossing.
    #[test]
    fn a_folded_reading_is_released_and_does_not_hold_down_its_successor() {
        let record = producer_record(0x42);
        let (mut counterparts, trie, anchors) = answering(record);
        let now = WeightedTimestamp::from_millis(60_000);
        let (state_root, proof) = state_and_proof(PRODUCER, &[], &[record]);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        assert_eq!(counterparts.probe(&trie, now, &BTreeMap::new()).len(), 1);
        counterparts.on_proof_fetched(anchor, vec![record], proof);
        counterparts.release_answered_fetches(&trie);
        assert!(
            counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "before it is folded the reading is still what the question wants",
        );

        counterparts.fold_answered(
            &StateClaim {
                anchor,
                cells: Capped::new(vec![(record, Inclusion::Absent)]).expect("one cell"),
            },
            &trie,
        );
        counterparts.release_answered_fetches(&trie);
        assert!(
            !counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "and once folded it is spent: no later reading of this record comes from here",
        );

        let far = Anchor {
            height: BlockHeight::new(8),
            ts: now.plus(RETENTION_HORIZON).plus(Duration::from_secs(1)),
            ..anchor
        };
        anchors.record(far);
        assert_eq!(
            counterparts.probe(&trie, far.ts, &BTreeMap::new()).len(),
            1,
            "so the question for the second absence is put",
        );
    }

    /// A record this shard holds, naming a claim cell `CONSUMER` holds
    /// the prefix of, and a deadline read back off the expiry.
    fn producer_cell(seed: u8, deadline: Deadline) -> CrossingCell {
        CrossingCell {
            resource: ResourceAddr::new([0xE1; 31]),
            amount: 1_000,
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
            expiry_ms: deadline.at().as_millis() + CLAIM_WINDOW.as_secs() * 1_000,
            tx: TxHash::from(Hash::from_bytes(&[seed; 32])),
            consumer_claim: SubstateKey {
                owner: Address::new([0x11; 31], AddressClass::Component),
                local: LocalKey([seed; 16]),
            },
            terms: Terms::Owed,
        }
    }

    /// A producer holding `count` records, each its own transaction,
    /// over a two-shard trie — and no ledger entry for any of them.
    fn producing(count: u8, deadline: Deadline) -> (Counterparts, ShardTrie, Arc<ProvenAnchors>) {
        let anchors = Arc::new(ProvenAnchors::default());
        let mut counterparts = Counterparts::holding(
            PRODUCER,
            Arc::clone(&anchors),
            Arc::new(ProvenCells::default()),
            Arc::new(CounterpartMirror::default()),
            &CrossingLeaves::default(),
        );
        for seed in 0..count {
            counterparts.held.insert(
                producer_record(seed),
                HeldRecord::of(producer_cell(seed, deadline)),
            );
        }
        (
            counterparts,
            ShardTrie::from_leaves([CONSUMER, PRODUCER]),
            anchors,
        )
    }

    /// An anchor of `CONSUMER` at `height`, which is all an offer reads
    /// of a target: what it holds is never fetched, only whether its
    /// chain has advanced.
    fn consumer_anchor(height: u64, ts: WeightedTimestamp) -> Anchor {
        Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts,
        }
    }

    /// A crossing is offered again off the leaf that holds it, from its
    /// deadline until its consumer answers, with no entry anywhere.
    ///
    /// The whole of what makes an offer leaf-driven: the ledger here is
    /// empty, so nothing the chain still owes an outcome for names this
    /// transaction, and the record is offered all the same. An entry
    /// prunes; a record stands until it is answered, which is the side
    /// the obligation has to be read from.
    #[test]
    fn a_crossing_is_offered_off_its_leaf_until_its_consumer_answers() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, anchors) = producing(1, deadline);
        let record = producer_record(0);
        let now = deadline.at();

        assert!(
            producer
                .reoffers(&trie, now.minus(Duration::from_millis(1)))
                .is_empty(),
            "short of the deadline the crossing's own bundle may still be in flight",
        );
        assert!(
            producer.reoffers(&trie, now).is_empty(),
            "and a consumer this node has proven no anchor of could not have answered",
        );

        anchors.record(consumer_anchor(7, now));
        let offered = producer.reoffers(&trie, now);
        assert_eq!(offered.len(), 1, "the one crossing it holds is owed");
        assert_eq!(
            offered[0].target, CONSUMER,
            "offered to whoever holds the claim's prefix now",
        );
        assert_eq!(offered[0].tx_hash, producer_cell(0, deadline).tx);
        assert_eq!(
            offered[0].records.as_slice(),
            [record],
            "and carries the record cell a bundle is built from",
        );
        assert_eq!(
            producer.reoffers(&trie, now),
            offered,
            "a proposer that composed an offer and lost its round promised nothing",
        );

        producer.fold_reoffers(&offered, now);
        assert!(
            producer.reoffers(&trie, now).is_empty(),
            "a crossing a committed block promised is not promised again at that header",
        );
        anchors.record(consumer_anchor(8, now));
        let answerable = now.plus(MAX_FINALIZATION_DELAY);
        assert_eq!(
            producer.reoffers(&trie, answerable).len(),
            1,
            "and is, once the consumer's chain has moved and could have answered",
        );

        producer
            .held
            .get_mut(&record)
            .expect("the record this shard holds")
            .answer = Some(Inclusion::Present([0xAB; 32]));
        assert!(
            producer.reoffers(&trie, answerable).is_empty(),
            "a claim read present is the end of the obligation",
        );
    }

    /// The decline cell of the crossing `producer_cell(seed, ..)`
    /// records, which sits under the same target its claim does.
    fn consumer_decline(seed: u8, deadline: Deadline) -> SubstateKey {
        let cell = producer_cell(seed, deadline);
        crossing_decline_key(
            &ProtocolHasher,
            cell.consumer_claim.owner,
            cell.intent,
            cell.local,
            cell.output,
        )
    }

    /// A producer asks after both answers at one anchor, and a decline
    /// read present ends the crossing.
    ///
    /// The channel end to end, because each step of it is a rule of its
    /// own and a source added to one and missed in another is a reading
    /// fetched and dropped forever: the probe names both cells in one
    /// fetch, the landed reading is kept across the commit that follows
    /// it, a block carries it, and the fold reads it as the answer.
    #[test]
    fn a_producer_asks_both_answers_and_a_decline_ends_the_crossing() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, anchors) = producing(1, deadline);
        let record = producer_record(0);
        let claim = producer_cell(0, deadline).consumer_claim;
        let decline = consumer_decline(0, deadline);
        let now = deadline.at();
        assert_eq!(
            decline.owner, claim.owner,
            "both cells sit under the consuming node's own target, which is what              makes this one fetch",
        );

        let (state_root, proof) = state_and_proof(CONSUMER, &[decline], &[claim, decline]);
        let anchor = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        let asked = producer.probe(&trie, now, &BTreeMap::new());
        assert_eq!(asked.len(), 1, "two keys under one owner are one fetch");
        let [
            Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::StateProofs(ids),
                ..
            }),
        ] = asked.as_slice()
        else {
            panic!("a probe asks for state proofs: {asked:?}");
        };
        assert_eq!(
            ids.as_slice(),
            [(anchor, claim), (anchor, decline)],
            "and it asks after both answers at the one anchor",
        );

        producer.on_proof_fetched(anchor, vec![claim, decline], proof);
        producer.release_answered_fetches(&trie);
        let carried = producer.state_claims();
        assert_eq!(
            carried.len(),
            1,
            "the reading survives the commit and a block carries it",
        );
        assert!(
            carried[0].reading(decline).is_some(),
            "including the refusal's own cell, which nothing else here would keep",
        );

        producer.fold_held(&carried[0], &trie);
        let held = producer.held.get(&record).expect("the record still stands");
        assert!(
            held.declined,
            "a decline read present is the crossing's answer"
        );
        assert!(
            held.unclaimable(),
            "and it licenses the credit back, with no window anywhere in the path",
        );
        assert!(
            producer
                .reoffers(&trie, now.plus(MAX_FINALIZATION_DELAY))
                .is_empty(),
            "the pressure stops where the answer arrives",
        );
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            producer.probe(&trie, now, &BTreeMap::new()).is_empty(),
            "and the question is not put again at the consumer's next header",
        );
    }

    /// A claim read present answers over a decline read beside it.
    ///
    /// Both cells present is a refusal rather than a preference, and the
    /// consumer's own licence is what makes it impossible. A producer
    /// reading one is not where that is discovered, and of the two
    /// mistakes available here only one is unrecoverable: taking back
    /// value a consumer demonstrably holds.
    #[test]
    fn a_claim_read_present_answers_over_a_decline_beside_it() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, _anchors) = producing(1, deadline);
        let record = producer_record(0);
        let claim = producer_cell(0, deadline).consumer_claim;
        let decline = consumer_decline(0, deadline);

        let both = StateClaim::new(
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(7),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: deadline.at(),
            },
            [
                (claim, Inclusion::Present([0xAB; 32])),
                (decline, Inclusion::Present([0xCD; 32])),
            ],
        );
        producer.fold_held(&both, &trie);

        let held = producer.held.get(&record).expect("the record still stands");
        assert!(
            matches!(held.answer, Some(Inclusion::Present(_))),
            "the claim is what the record is answered by",
        );
        assert!(
            !held.declined && !held.unclaimable(),
            "so nothing licenses crediting back value the consumer holds",
        );
    }

    /// An offer waits on the consumer's chain and on the clock, and
    /// each bound is asserted where the other would let the offer
    /// through.
    ///
    /// A halted target lands no header, so the clock alone would promise
    /// into it every round for as long as it stays down — off a leaf,
    /// which does not die, that is forever, into a section shared with
    /// every live target. A running target lands a header every block,
    /// so the height alone would promise many times over inside the one
    /// round an answer takes, each promise a bundle rebuilt and
    /// rebroadcast.
    #[test]
    fn an_offer_waits_on_its_target_and_on_the_round_an_answer_takes() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, anchors) = producing(1, deadline);
        let now = deadline.at();
        anchors.record(consumer_anchor(7, now));

        let offered = producer.reoffers(&trie, now);
        assert_eq!(offered.len(), 1);
        producer.fold_reoffers(&offered, now);

        // The height, where the clock has long since run out.
        for hours in 1..6 {
            assert!(
                producer
                    .reoffers(&trie, now.plus(Duration::from_secs(hours * 3_600)))
                    .is_empty(),
                "a halted target is offered once, however long it stays down",
            );
        }

        // The clock, where the target's chain has moved on.
        for height in 8..12 {
            anchors.record(consumer_anchor(height, now));
            assert!(
                producer.reoffers(&trie, now).is_empty(),
                "a running target lands headers faster than it can answer",
            );
        }
        assert_eq!(
            producer
                .reoffers(&trie, now.plus(MAX_FINALIZATION_DELAY))
                .len(),
            1,
            "and is promised again once an answer could have come back",
        );
    }

    /// A backlog wider than one block's cap is walked rather than
    /// re-offering its head, so the record at the tail does not wait on
    /// the one at the head being answered.
    #[test]
    fn a_backlog_wider_than_the_offer_cap_laps_before_it_repeats() {
        let count = u8::try_from(2 * MAX_REOFFERS_PER_BLOCK).expect("two blocks' worth");
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, anchors) = producing(count, deadline);
        let now = deadline.at();
        anchors.record(consumer_anchor(7, now));

        let mut carried: BTreeSet<SubstateKey> = BTreeSet::new();
        for _ in 0..2 {
            let offered = producer.reoffers(&trie, now);
            assert_eq!(
                offered.len(),
                MAX_REOFFERS_PER_BLOCK,
                "each proposal fills the cap",
            );
            for offer in &offered {
                for &key in offer.records.iter() {
                    assert!(carried.insert(key), "and offers nothing a lap has carried");
                }
            }
        }
        assert_eq!(
            carried,
            (0..count).map(producer_record).collect(),
            "two laps of the cap reach every record",
        );
    }

    /// A backlog wider than one block's bytes is carried across blocks
    /// with nothing lost: each block takes a prefix of what is offered,
    /// the next takes up where it stopped, and every name is carried by
    /// exactly one.
    #[test]
    fn a_backlog_over_the_byte_budget_drains_across_blocks() {
        let wide = name(0, 6).wire_weight();
        let backlog: Vec<UnsettledTx> = (0..3 * MAX_PROPOSAL_EVIDENCE_BYTES / wide)
            .map(|seed| name(seed, 6))
            .collect();

        let mut left = backlog.clone();
        let mut carried: Vec<UnsettledTx> = Vec::new();
        for _ in 0..8 {
            if left.is_empty() {
                break;
            }
            let mut offered = left.clone();
            Budget::empty().take(&mut offered);
            assert!(!offered.is_empty(), "each block carries something");
            let record =
                AbandonmentRecord::new(ShardId::ROOT, WeightedTimestamp::ZERO, offered.clone());
            assert!(
                evidence_admits_block(record.wire_weight()),
                "and what it carries is a section a voter admits",
            );
            left.drain(..offered.len());
            carried.extend(offered);
        }
        assert!(left.is_empty(), "the backlog drains");
        assert_eq!(
            carried, backlog,
            "each name carried once, in the order offered"
        );
    }

    /// The bytes stop the composer before the names do, which is the
    /// whole point of the second figure: a name's reach is not something
    /// a count can see.
    #[test]
    fn the_bytes_are_what_stops_a_wide_backlog() {
        let mut wide: Vec<UnsettledTx> = (0..MAX_UNSETTLED_PER_BLOCK)
            .map(|seed| name(seed, 6))
            .collect();
        Budget::empty().take(&mut wide);
        assert!(
            wide.len() < MAX_UNSETTLED_PER_BLOCK,
            "the byte budget bites first",
        );
        assert!(evidence_admits_block(
            ABANDONMENT_RECORD_BYTES + wide.iter().map(UnsettledTx::wire_weight).sum::<usize>()
        ));
    }

    /// A budget with bytes to spare still stops at the drain's count:
    /// the two figures answer different questions and neither subsumes
    /// the other.
    #[test]
    fn the_names_are_what_stops_a_narrow_backlog() {
        let narrow = name(0, 0).wire_weight();
        assert!(
            MAX_UNSETTLED_PER_BLOCK * narrow > MAX_PROPOSAL_EVIDENCE_BYTES,
            "a reachless name is still wide enough that the bytes bind at the drain's count",
        );
        let mut budget = Budget::empty();
        budget.bytes = usize::MAX;
        let mut offered: Vec<UnsettledTx> = (0..MAX_UNSETTLED_PER_BLOCK + 10)
            .map(|seed| name(seed, 0))
            .collect();
        budget.take(&mut offered);
        assert_eq!(offered.len(), MAX_UNSETTLED_PER_BLOCK);
    }

    /// A record's own terms are charged once, with the first name it
    /// takes, so a budget spent across several records still leaves room
    /// for each one's header.
    #[test]
    fn a_records_own_terms_are_charged_with_its_first_name() {
        let mut budget = Budget::empty();
        let mut one = vec![name(0, 2)];
        budget.take(&mut one);
        assert_eq!(
            MAX_PROPOSAL_EVIDENCE_BYTES - budget.bytes,
            ABANDONMENT_RECORD_BYTES + name(0, 2).wire_weight(),
        );
        let mut none: Vec<UnsettledTx> = Vec::new();
        let before = budget.bytes;
        budget.take(&mut none);
        assert_eq!(budget.bytes, before, "an empty take charges nothing");
    }
}
