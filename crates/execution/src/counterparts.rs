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
use std::sync::Arc;

use hyperscale_core::{Action, FetchIds, FetchRequest, ProtocolEvent};
use hyperscale_metrics::{
    record_fenced_claim, record_rebuilt_record_entry, record_reclaim_probe_answered,
    record_reclaim_probe_pending,
};
use hyperscale_storage::CrossingLeaves;
use hyperscale_types::network::response::ServedValue;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Anchor, Block, BlockHeight, CounterpartMirror,
    EpochWindows, ExecutionCertificate, FrontierInputs, Inclusion, MAX_PROPOSAL_EVIDENCE_BYTES,
    MAX_PROVISION_TARGET_SHARDS, MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof, Probed,
    ProvenAnchors, RETENTION_HORIZON, ReadFrontier, ReadMark, SettledTxSet, ShardId, ShardTrie,
    Spoken, StateClaim, Stated, SubstateKey, TerminalEvidence, TopologySchedule,
    TransactionDecision, TxHash, TxOutcome, TxResolution, UnsettledTx, Verifiable, Verified,
    WeightedTimestamp,
};
use hyperscale_vm_effects::{
    Answered, CrossingAnswer, CrossingCell, CrossingId, CrossingLeaf, ProtocolHasher,
};

use crate::ledger::{Ledger, Question, Unanswerable};
use crate::provisioning::WantedRecord;
use crate::record_reads::RecordReads;

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
    /// The record leaf, which carries the consumer's target, the
    /// issuing transaction and the expiry every window is read off.
    pub(crate) cell: CrossingCell,
    /// The newest counterpart header the claim has been asked at, so
    /// the question is not re-sent at the same one every block.
    asked_at: Option<BlockHeight>,
    /// The claim cell's key, under the consuming node's target.
    ///
    /// Held rather than re-derived because three sites compare against
    /// it in every block — the probe that asks, the retention rule that
    /// keeps what lands, and the fold that reads it. Derived through the
    /// crossing's one identity, off the record's own key and value.
    pub(crate) claim: SubstateKey,
    /// The decline cell's key, under the same target the claim's key
    /// sits at and off the same edge, held for the same reason.
    pub(crate) decline: SubstateKey,
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
    /// The record at `key` as the leaves give it: undisposed, unasked,
    /// with both answer keys derived through the crossing the leaf
    /// names.
    #[must_use]
    pub(crate) fn of(key: SubstateKey, cell: CrossingCell) -> Self {
        let id = CrossingId::of_record(key.owner, &cell);
        Self {
            claim: id.answer_key(&ProtocolHasher, Answered::Taken),
            decline: id.answer_key(&ProtocolHasher, Answered::Never),
            cell,
            asked_at: None,
            declined: false,
            departed: false,
        }
    }

    /// Whether the consumer has answered this crossing while the record
    /// stands: its decline read present. A claim read present is not a
    /// state here — the commit fold removes the record on it, and the
    /// record leaves the mirror with it.
    #[must_use]
    pub(crate) const fn answered(&self) -> bool {
        self.declined
    }

    /// Whether the crossing this record holds can never be claimed, so
    /// the value is the producer's to take back.
    ///
    /// Two presences and no absence. The consumer's own decline says
    /// the crossing will never be taken; a departure says the chain
    /// that was to consume it can never settle what issued it. Each is
    /// committed content read present, and neither is bounded by a
    /// window.
    #[must_use]
    pub(crate) const fn unclaimable(&self) -> bool {
        self.declined || self.departed
    }
}

/// A crossing this shard has answered, and where its one question
/// stands.
///
/// [`HeldRecord`] read from the other end. A producer holds a record and
/// asks whether its consumer claimed; a consumer holds an answer and asks
/// whether the producer still holds the record — the same channel and
/// the opposite direction. The question is paced by [`RecordReads`]
/// like a consumer's read of a record it waits on, backing off in the
/// producer's heights: a record goes only when its producer disposes of
/// it, and a deletion is housekeeping with no deadline behind it.
///
/// One question, to one shard. There is no deadline here because no
/// window is read: a presence answers wherever it was taken, and an
/// absence answers at or above the read frontier's floor.
#[derive(Debug, Clone)]
pub struct AnsweredCrossing {
    /// The crossing this answer answers for, read off the leaf, which
    /// names it; what a reading of the record is named for.
    pub(crate) id: CrossingId,
    /// The record cell this claim answers for, under the producing
    /// node's target, derived through the crossing.
    pub(crate) record: SubstateKey,
    /// How far the record has been read gone.
    pub cleanup: Cleanup,
}

impl AnsweredCrossing {
    /// The answer as the leaves give it, for the crossing `id`: unasked,
    /// with nothing yet read of its record.
    #[must_use]
    pub(crate) fn of(id: CrossingId) -> Self {
        Self {
            id,
            record: id.record_key(&ProtocolHasher),
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
    /// Read absent, at this anchor of the producer, at or above the read
    /// frontier's floor for it — and that is the whole of the licence.
    ///
    /// **One reading, because the frontier orders it after every
    /// presence.** A block admits a record presence only at or above
    /// the floor its chain has read the producer to, and every claim
    /// raises that floor, so an absence read at or above it comes after
    /// every presence this chain ever carried and no presence can
    /// license a replay again — which is what the answer cell was
    /// defending against and the only thing it was.
    Gone(Anchor),
}

impl Cleanup {
    /// The same record read absent or present at `anchor`, where
    /// `licensed` says the anchor sits at or above the read frontier's
    /// floor for its producer as the block's parent left it.
    ///
    /// An absence below the floor licenses nothing: a presence above
    /// it may already have been carried, and a deletion on it would
    /// reopen the crossing to a replay. It is not even remembered,
    /// since the question is put again at an anchor the floor admits.
    #[must_use]
    fn read(self, anchor: Anchor, inclusion: Inclusion, licensed: bool) -> Self {
        match (self, inclusion) {
            (Self::Standing(_), Inclusion::Absent) if licensed => Self::Gone(anchor),
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
            Self::Gone(_) => false,
        }
    }
}

/// Whether any undisposed record is still waiting on `key`.
///
/// Read off the keys rather than off a name, because a record's issuing
/// transaction need not be one this chain committed.
fn awaited_by(held: &BTreeMap<SubstateKey, HeldRecord>, key: SubstateKey) -> bool {
    held.values()
        .any(|record| !record.answered() && (record.claim == key || record.decline == key))
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
/// **The anchor is the difference from that side.** A presence folded
/// at one header is spent, and the question wants its successor at a
/// newer one; keyed on the cell alone, the spent reading would be held
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
    wanted: &BTreeSet<SubstateKey>,
    anchor: Anchor,
    key: SubstateKey,
) -> bool {
    awaited_by(held, key) || awaits_record(answered, anchor, key) || wanted.contains(&key)
}

/// What a claim reads that the read frontier fences: whether it carries
/// a record presence, and whether it carries an absence of the record
/// behind an answer this shard holds.
fn fenced_readings(
    answered: &BTreeMap<SubstateKey, AnsweredCrossing>,
    claim: &StateClaim,
) -> (bool, bool) {
    let mut record = false;
    let mut removed = false;
    for (key, stated) in claim.cells.iter() {
        match stated.held() {
            Some(bytes) => {
                if matches!(
                    CrossingLeaf::read(&ProtocolHasher, *key, bytes),
                    Some(CrossingLeaf::Record { .. })
                ) {
                    record = true;
                }
            }
            None => {
                if stated.inclusion() == Inclusion::Absent
                    && answered.values().any(|answer| answer.record == *key)
                {
                    removed = true;
                }
            }
        }
    }
    (record, removed)
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
    /// The leg entries the commit fold closed: every record each
    /// issued here removed on its consumer's `Taken`, which is the
    /// transaction accepted. No finalization drives these, so the
    /// mempool hears them from here.
    pub(crate) settled: Vec<(TxHash, TxResolution)>,
}

/// What this validator holds to offer in a block it proposes.
pub struct Offers {
    /// Claims its own fetches proved that no block has carried yet, in
    /// the one order a block carries them.
    pub state_claims: Vec<StateClaim>,
    /// The records it has evidence for and has not yet written down.
    pub abandonment_records: Vec<AbandonmentRecord>,
    /// The crossings whose two ends share this shard and whose
    /// settlement the mirrors say is due, for the block to read at its
    /// parent: a held record whose answer this shard itself holds, and
    /// an answer whose record routes here and is held no more.
    pub local_crossings: Vec<CrossingId>,
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

    /// The claims this validator's own fetches proved that answered,
    /// each with the transactions whose probes it spoke to, held to
    /// offer in a block this validator proposes: a claim is committed
    /// content, checked and folded by every replica at the same height,
    /// and the fetch is only how the proposer came by the proof. The
    /// claims at one anchor are disjoint, in the form the section
    /// carries them. A claim leaves by key as blocks carry its cells,
    /// or whole when every transaction it answered for is gone. While
    /// it is here the question it answers is not put again: what
    /// licenses that is narrower than the mirror, which stays fed by
    /// committed content alone so two validators at one committed
    /// height compose the same records.
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

    /// The read frontier as the committed chain leaves it: how far
    /// along each producer this shard has read, the copy the fold's own
    /// rule advances here at every commit. Read to license a deletion,
    /// which needs an absence at or above the floor, and to drop what
    /// is held to offer below it.
    frontier: ReadFrontier,

    /// The owed claims this shard has written under its prefix, each
    /// still undeleted, by cell key.
    ///
    /// The mirror of [`held`](Self::held) on the answering side, read
    /// from the leaves for the same reason: a seat's ledger begins empty
    /// and a restart replays only a window, so for an answer older than
    /// either there is no entry to name it — and the leaf carries the one
    /// term the question needs, the record it answers for.
    pub(crate) answered: BTreeMap<SubstateKey, AnsweredCrossing>,

    /// The records a consumer here waits on with no arrival for, as of
    /// the last commit: the candidates' filed requirements and the
    /// pool's delivering bodies. What a fetched or pushed reading of a
    /// record is kept to offer against.
    wanted: BTreeSet<SubstateKey>,

    /// The reads of those records this validator has put, with their
    /// pacing.
    records: RecordReads,

    /// The crossings whose two ends route here that the last probe
    /// found a settlement due for, offered to the next proposal to read
    /// at its parent. A proposal choice: the voter re-reads every
    /// reading it leads to, and a wrong offer costs a claim that
    /// settles nothing.
    local_crossings: BTreeSet<CrossingId>,

    /// The questions this validator has put to counterparts, by the
    /// shard asked and the cell: the header each was asked at, and
    /// whether the fetch returned. A probe lives while its question is
    /// open — one the chain has answered, or whose entry is gone, is
    /// dropped at the commit and any fetch still out for it released,
    /// so a counterpart that never serves the height does not pin the
    /// slot.
    probes: BTreeMap<(ShardId, SubstateKey), Probe>,
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
        mirror: Arc<CounterpartMirror>,
        leaves: &CrossingLeaves,
        frontier: ReadFrontier,
    ) -> Self {
        Self {
            ledger: Ledger::new(local_shard),
            mirror,
            proven_anchors,
            fetched: BTreeMap::new(),
            held: leaves
                .records
                .iter()
                .filter_map(|(key, value)| {
                    let cell = CrossingCell::from_bytes(value)?;
                    Some((*key, HeldRecord::of(*key, cell)))
                })
                .collect(),
            frontier,
            answered: leaves
                .claims
                .iter()
                .filter_map(|(key, value)| {
                    let answer = CrossingAnswer::from_bytes(value)?;
                    let id = CrossingId::of_answer(key.owner, &answer);
                    Some((*key, AnsweredCrossing::of(id)))
                })
                .collect(),
            wanted: BTreeSet::new(),
            records: RecordReads::new(),
            local_crossings: BTreeSet::new(),
            probes: BTreeMap::new(),
        }
    }

    /// Fold what a committed block says about counterparts — the claims
    /// and records it carries, the entries its certificates resolve, the
    /// departures the schedule now proves — let go of what no window can
    /// still answer, and ask what the block's clock opens.
    ///
    /// `trie` is the block's committee's, which says who was party to
    /// each transaction, `now` the committed clock every deadline is
    /// read against, and `wanted` the crossing records consumers here
    /// wait on with no arrival for.
    pub(crate) fn on_commit(
        &mut self,
        trie: &ShardTrie,
        topology_schedule: &TopologySchedule,
        block: &Block,
        now: WeightedTimestamp,
        wanted: &[WantedRecord],
    ) -> Committed {
        let windows = topology_schedule.windows();
        self.gc_settled_sets(topology_schedule, now);
        self.wanted = wanted.iter().map(|wanted| wanted.key).collect();
        // What the block's claims settle, applied to the mirrors first,
        // as the fold applies it to state first: a record removed on
        // its consumer's `Taken` leaves `held` and is marked gone on the
        // entry that issued it, and an answer removed on its record's
        // absence leaves `answered`. A key the mirror never held is
        // nothing to remove, so no presence is read here.
        for key in block.state_claims().iter().flat_map(StateClaim::settles) {
            if let Some(record) = self.held.remove(&key) {
                self.ledger.settled(key, record.cell.tx);
            }
            self.answered.remove(&key);
        }
        // The reads still worth pacing: the records something here
        // waits on, and the records behind the answers this shard holds.
        let live: BTreeSet<SubstateKey> = self
            .wanted
            .iter()
            .copied()
            .chain(self.answered.values().map(|answer| answer.record))
            .collect();
        self.records.sweep(now, &live);
        self.count_carried(block);
        // A reading the chain now carries is everybody's: its answers
        // are folded here, and nothing offers it again. Retired by key
        // from every held claim at the anchor, so a claim another
        // proposer cut differently leaves only what the block carried,
        // and the remainder of a cut claim is offered whole.
        let mut carried: BTreeMap<Anchor, BTreeSet<SubstateKey>> = BTreeMap::new();
        for claim in block.state_claims() {
            carried
                .entry(claim.anchor)
                .or_default()
                .extend(claim.keys());
        }
        if !carried.is_empty() {
            self.fetched = std::mem::take(&mut self.fetched)
                .into_iter()
                .filter_map(|(claim, speaks_for)| {
                    let Some(keys) = carried.get(&claim.anchor) else {
                        return Some((claim, speaks_for));
                    };
                    claim
                        .restrict(|key| !keys.contains(&key))
                        .map(|rest| (rest, speaks_for))
                })
                .collect();
        }
        let mut actions = self.fold_state_claims(trie, windows, block);
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
        self.cover_held(block);
        self.stamp_departures(topology_schedule, now);
        // The entries the fold has closed, read once the block's own
        // finalizations and removals are both in: a settled record and
        // a delivery finalized in one block close together.
        let settled = self.ledger.closes();
        let unanswerable = self.ledger.prune(now);
        // The frontier as this block leaves it, after the licence above
        // read the floor its parent left; then what the raise refuses
        // of the claims held to offer.
        self.frontier
            .advance(&FrontierInputs::of_block(block, windows));
        self.drop_below_floor(windows);
        actions.extend(self.release_answered_fetches(trie));
        // The committed clock is what opens a leg's deadline, so the
        // cores gone silent past it are asked here.
        actions.extend(self.probe(trie, now, wanted, windows));
        Committed {
            actions,
            unanswerable,
            settled,
        }
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
    pub(crate) fn offers(&self) -> Offers {
        Offers {
            state_claims: self.state_claims(),
            abandonment_records: self.abandonment_records(),
            local_crossings: self.local_crossings.iter().copied().collect(),
        }
    }

    /// Ask each silent counterpart whether it took the transaction a
    /// leg here issued for, once the transaction's deadline has passed.
    ///
    /// The deadline gates the probe and never the reclaim: absence at a
    /// block past the floor is the evidence, and before it the
    /// counterpart may still legitimately act. Every core shard is asked
    /// about the transaction's committed cell past the deadline: any one
    /// of them absent is the whole answer, while a shard that still
    /// holds its cell included the transaction and answers with a claim
    /// or a `Never` beside it, and is asked again at each newer header. The
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
    /// the trie's answer alone, because a departed shard may leave no
    /// header past the lapse, and the successor's is the one a proof can
    /// still be taken at.
    ///
    /// The cell is named from signed content and the counterpart shard
    /// alone, so nothing but the header and the proof is fetched.
    pub(crate) fn probe(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        records: &[WantedRecord],
        windows: EpochWindows,
    ) -> Vec<Action> {
        self.wanted = records.iter().map(|record| record.key).collect();
        self.local_crossings.clear();
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        self.ask_entries(trie, now, &mut wanted);
        self.ask_held_records(trie, now, &mut wanted);
        self.ask_wanted_records(trie, now, records, windows, &mut wanted);
        self.ask_written_answers(trie, now, windows, &mut wanted);
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
        for (key, record) in &mut self.held {
            if record.answered() || ledger.settles_records(record.cell.tx) {
                continue;
            }
            let claim = record.claim;
            let shard = trie.shard_for_prefix(claim.owner);
            if shard == local {
                // A consumer on this shard is not asked: its answer, if
                // it has given one, is in this shard's own state, and
                // the block reads it at its parent.
                if self.answered.contains_key(&claim) || self.answered.contains_key(&record.decline)
                {
                    self.local_crossings
                        .insert(CrossingId::of_record(key.owner, &record.cell));
                }
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
            entry.push(record.decline);
        }
    }

    /// The crossing records consumers here wait on ask one question
    /// each, of the shard holding the record's prefix now: has the
    /// producer written it?
    ///
    /// The fallback read, for a record no push has brought. Every
    /// validator derives the wanted set and asks for itself, so f
    /// validators withholding their fetch cannot suppress the read; the
    /// pacing is [`RecordReads`]', armed on the evidence that the
    /// producer's leg has finalized or never will. Asked at the newest
    /// anchor of the holder this validator has commit-proven where that
    /// anchor is at or above the read frontier's floor, since a reading
    /// below it is one every voter refuses, and never of a shard this
    /// chain holds itself, nor while a reading fetched or pushed is
    /// already held to offer.
    fn ask_wanted_records(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        records: &[WantedRecord],
        windows: EpochWindows,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        for record in records {
            let holder = trie.shard_for_prefix(record.key.owner);
            if holder == self.ledger.local() {
                continue;
            }
            self.records.arm(record, holder, now);
            let Some(anchor) = self.newest_above_floor(holder, now, windows) else {
                continue;
            };
            if self.holds_answer(holder, record.key) {
                continue;
            }
            if self.records.due(record.key, anchor) {
                wanted.entry(anchor).or_default().push(record.key);
            }
        }
    }

    /// The newest anchor of `shard` this validator has commit-proven
    /// that sits at or above the read frontier's floor for it. Where the
    /// newest sits below the floor no older one is above it, and the
    /// question waits for the next proven header.
    fn newest_above_floor(
        &self,
        shard: ShardId,
        now: WeightedTimestamp,
        windows: EpochWindows,
    ) -> Option<Anchor> {
        self.proven_anchors
            .newest_licensed(shard, now, |_| true)
            .filter(|anchor| !self.frontier.refuses(shard, ReadMark::of(anchor, windows)))
    }

    /// The answers this shard has written ask one question each, of the
    /// shard holding the record's prefix now: does the producer still
    /// hold it?
    ///
    /// [`ask_wanted_records`](Self::ask_wanted_records) read from the
    /// other end, and paced by the same [`RecordReads`], armed on the
    /// clock the moment the answer stands: nothing asked of a record
    /// this shard holds itself, nothing asked below the floor, and
    /// nothing asked while a reading the answer still wants is held to
    /// offer.
    fn ask_written_answers(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        windows: EpochWindows,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        let local = self.ledger.local();
        for answer in self.answered.values() {
            let record = answer.record;
            let shard = trie.shard_for_prefix(record.owner);
            if shard == local {
                // A producer on this shard is not asked: whether it still
                // holds the record is this shard's own state, and the
                // block reads it at its parent once the record is gone.
                if !self.held.contains_key(&record) {
                    self.local_crossings.insert(answer.id);
                }
                continue;
            }
            self.records.arm_now(record);
            let Some(anchor) = self.newest_above_floor(shard, now, windows) else {
                continue;
            };
            if !answer.cleanup.wants(anchor)
                || self.fetched.keys().any(|claim| {
                    claim.anchor.shard == shard
                        && claim.reading(record).is_some()
                        && answer.cleanup.wants(claim.anchor)
                })
            {
                continue;
            }
            if self.records.due(record, anchor) {
                wanted.entry(anchor).or_default().push(record);
            }
        }
    }

    /// Note an answer cell this shard holds, as the scan at start and
    /// the fold over its own finalizations do.
    #[cfg(test)]
    pub(crate) fn note_answer(&mut self, key: SubstateKey, answer: &CrossingAnswer) {
        self.answered.insert(
            key,
            AnsweredCrossing::of(CrossingId::of_answer(key.owner, answer)),
        );
    }

    /// Whether this validator holds an answering reading of `key` on
    /// `shard` to offer, so the question is not put to a counterpart
    /// again for an answer already in hand.
    fn holds_answer(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.fetched
            .keys()
            .any(|claim| claim.anchor.shard == shard && claim.reading(key).is_some())
    }

    /// Whether this validator holds, to offer, a live reading of the
    /// record at `key` naming `tx` as its issuer: what a delivering body
    /// that consumes it can be admitted beside.
    pub(crate) fn holds_live_record(&self, key: SubstateKey, tx: TxHash) -> bool {
        self.fetched.keys().any(|claim| {
            claim.held(key).is_some_and(|bytes| {
                matches!(
                    CrossingLeaf::read(&ProtocolHasher, key, bytes),
                    Some(CrossingLeaf::Record { cell, .. }) if cell.tx == tx
                )
            })
        })
    }

    /// Take what a fetched proof attests: close the questions it
    /// answers, and hold the claim it proves to offer in a block this
    /// validator proposes.
    ///
    /// The proof is walked once, under the anchor's root, and what
    /// comes back is the reading. What the ledger asked about is what
    /// is offered: the probes the proof spoke to are marked answered,
    /// so the question is not put to the same header again, and the
    /// claim is kept beside the transactions it answered for, which is
    /// what keeps the question from being put to any header until a
    /// block carries it. The claim's proof is the fetched one cut down
    /// to the keys the claim reads, and to the keys no held claim at
    /// the anchor already covers, so what is offered is in the form
    /// the section carries: one proof per claim, disjoint per anchor.
    /// A record value the server proved present rides in the claim as
    /// a held reading, which is how a consumer comes to read the
    /// record's terms.
    pub(crate) fn on_proof_fetched(
        &mut self,
        anchor: Anchor,
        keys: &[SubstateKey],
        proof: &MerkleInclusionProof,
        values: &[ServedValue],
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
        let Ok(inclusions) = proof.inclusions(anchor.state_root, anchor.shard, keys) else {
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
        // and mute about the question. Offering one spends the section
        // on a cell no record can be composed from.
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
                wants_reading(&self.held, &self.answered, &self.wanted, anchor, *key)
            }),
        );
        if answering.is_empty() {
            return;
        }
        // A cell a held claim at this anchor already reads is not held
        // twice; the transactions this proof spoke for lean on that
        // claim instead.
        let mut fresh = answering.clone();
        for (held, held_for) in &mut self.fetched {
            if held.anchor != anchor {
                continue;
            }
            let covered: Vec<SubstateKey> = held
                .keys()
                .into_iter()
                .filter(|key| answering.contains(key))
                .collect();
            if !covered.is_empty() {
                held_for.extend(speaks_for.iter().copied());
                for key in covered {
                    fresh.remove(&key);
                }
            }
        }
        if fresh.is_empty() {
            return;
        }
        let kept: Vec<SubstateKey> = fresh.iter().copied().collect();
        let Ok(proof) = proof.restrict(&kept) else {
            tracing::warn!(
                shard = ?anchor.shard,
                height = anchor.height.inner(),
                "A fetched state proof cannot be cut to the cells it answers"
            );
            return;
        };
        let cells = inclusions
            .iter()
            .filter(|(key, _)| fresh.contains(key))
            .map(|&(key, inclusion)| {
                let held = values
                    .iter()
                    .find(|(served, _)| *served == key)
                    .map(|(_, bytes)| Stated::Held(bytes.clone()));
                (key, held.unwrap_or(Stated::Inclusion(inclusion)))
            });
        // Each reading of a crossing's cell names the crossing, off what
        // the asker holds: a held record's answers, and a held answer's
        // record. What the reading licenses the fold to remove is read
        // off the name, by every replica alike.
        let named: Vec<(SubstateKey, CrossingId)> = kept
            .iter()
            .filter_map(|key| self.crossing_of(*key).map(|id| (*key, id)))
            .collect();
        self.fetched
            .entry(StateClaim::new(anchor, cells, proof).naming(named))
            .or_default()
            .extend(speaks_for);
    }

    /// The crossing a reading of `key` speaks for, where something here
    /// asked about it: a held record's `Taken` or `Never`, or the record
    /// behind an answer this shard holds.
    fn crossing_of(&self, key: SubstateKey) -> Option<CrossingId> {
        self.held
            .iter()
            .find(|(_, record)| record.claim == key || record.decline == key)
            .map(|(record_key, record)| CrossingId::of_record(record_key.owner, &record.cell))
            .or_else(|| {
                self.answered
                    .values()
                    .find(|answer| answer.record == key)
                    .map(|answer| answer.id)
            })
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
    fn fold_state_claims(
        &mut self,
        trie: &ShardTrie,
        windows: EpochWindows,
        block: &Block,
    ) -> Vec<Action> {
        if block.state_claims().is_empty() {
            return Vec::new();
        }
        let questions = self.ledger.questions(trie);
        let mut actions = Vec::new();
        for claim in block.state_claims() {
            actions.extend(self.fold_cells(claim, &questions));
            self.fold_held(claim, trie);
            self.fold_answered(claim, windows);
        }
        actions
    }

    /// Count the fenced claims the block carries, by what each reads: a
    /// record presence, and an absence of a record behind an answer
    /// this shard holds.
    fn count_carried(&self, block: &Block) {
        for claim in block.state_claims() {
            let (record, removed) = fenced_readings(&self.answered, claim);
            if record {
                record_fenced_claim("record", true);
            }
            if removed {
                record_fenced_claim("removed", true);
            }
        }
    }

    /// Drop every held claim with a fenced reading below the floor the
    /// frontier now sets for its producer, whether a fetch or a push
    /// brought it, and start its keys' reads over so the next probe asks
    /// again at a proven anchor at or above the floor. A claim carrying
    /// no fenced reading is left to the age bound and the ledger: a
    /// bare reading below the floor is admissible.
    fn drop_below_floor(&mut self, windows: EpochWindows) {
        let frontier = &self.frontier;
        let answered = &self.answered;
        let mut reset: Vec<SubstateKey> = Vec::new();
        self.fetched.retain(|claim, _| {
            if !frontier.refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows)) {
                return true;
            }
            let (record, removed) = fenced_readings(answered, claim);
            if !record && !removed {
                return true;
            }
            if record {
                record_fenced_claim("record", false);
            }
            if removed {
                record_fenced_claim("removed", false);
            }
            reset.extend(claim.keys());
            false
        });
        for key in reset {
            self.records.reset(key);
        }
    }

    /// Whether a pushed claim sits below the read frontier's floor for
    /// its producer: one every voter refuses, so not worth holding.
    pub(crate) fn refuses_pushed(&self, claim: &StateClaim, windows: EpochWindows) -> bool {
        self.frontier
            .refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows))
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
    /// The claim's *absence* is read for nothing. A leaf does not name
    /// its consumer's role, so an absence says only that the consumer
    /// has not run yet — and the decline is the road that replaced it.
    fn fold_held(&mut self, stated: &StateClaim, trie: &ShardTrie) {
        for record in self.held.values_mut() {
            if record.answered() {
                continue;
            }
            let claim = record.claim;
            if trie.shard_for_prefix(claim.owner) != stated.anchor.shard {
                continue;
            }
            let read = |key, probed: Probed| {
                stated
                    .reading(key)
                    .and_then(|inclusion| probed.read(inclusion))
            };
            // A claim read present beside the decline is the consumer
            // holding the crossing: the fold takes the record on it, and
            // nothing here licenses crediting back what the consumer
            // demonstrably holds.
            if read(claim, Probed::Claim).is_some() {
                continue;
            }
            if read(record.decline, Probed::Decline).is_some() {
                record.declined = true;
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
    /// What a fact *licenses* is the read frontier's question: an
    /// absence licenses a deletion only at or above the floor the
    /// block's parent left for the anchor's shard, read from a shard
    /// that owns the record's prefix at the anchor's clock. A leaf owns
    /// exactly its path's prefixes while it is live and a commit-proven
    /// anchor is a header from its live span, so a sibling child's
    /// absence licenses nothing.
    fn fold_answered(&mut self, stated: &StateClaim, windows: EpochWindows) {
        let shard = stated.anchor.shard;
        let licensed = !self
            .frontier
            .refuses(shard, ReadMark::of(&stated.anchor, windows));
        for answer in self.answered.values_mut() {
            if !ShardTrie::shard_owns_prefix(shard, answer.record.owner) {
                continue;
            }
            if let Some(inclusion) = stated.reading(answer.record) {
                answer.cleanup = answer.cleanup.read(stated.anchor, inclusion, licensed);
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
                    let leaf = value
                        .as_ref()
                        .map(|bytes| CrossingLeaf::read(&ProtocolHasher, *key, bytes));
                    match leaf {
                        Some(Some(CrossingLeaf::Record { cell, .. })) => {
                            self.held
                                .entry(*key)
                                .or_insert_with(|| HeldRecord::of(*key, cell));
                        }
                        Some(Some(CrossingLeaf::Answer { id, .. })) => {
                            self.answered
                                .entry(*key)
                                .or_insert_with(|| AnsweredCrossing::of(id));
                        }
                        None => {
                            self.held.remove(key);
                            // An answer removed is a crossing over at both
                            // ends: its record is gone, which is what
                            // licensed the removal. The arrival the bundle
                            // left behind is stale evidence from here on,
                            // and the question it would otherwise re-open
                            // is the one this cell was answering.
                            self.answered.remove(key);
                        }
                        Some(None) => {}
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

    /// Tell the mempool a core's refusal of a transaction a leg here
    /// issued for: the verdict, as the counterpart's certificate carries
    /// it. Nothing is written down — what licenses taking the crossing
    /// back is the `Never` the refusal's own receipt writes, read
    /// present — and the mempool reads a verdict it already holds as
    /// nothing new.
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

    /// The claims this validator holds that no block has carried yet,
    /// one producer's together in anchor order and the producers by
    /// their oldest anchor: the section's budget is spent in this order
    /// and cuts what does not fit, so no claim of a producer rides while
    /// an older one of it is held back, and the producer closest to
    /// aging out goes first rather than a busy one starving another.
    /// Every claim of a producer raises the same frontier entry, so a
    /// younger one carried ahead of an older would have the older
    /// refused at its next block.
    fn state_claims(&self) -> Vec<StateClaim> {
        let mut oldest: BTreeMap<ShardId, WeightedTimestamp> = BTreeMap::new();
        for claim in self.fetched.keys() {
            oldest
                .entry(claim.anchor.shard)
                .and_modify(|ts| *ts = (*ts).min(claim.anchor.ts))
                .or_insert(claim.anchor.ts);
        }
        let mut claims: Vec<StateClaim> = self.fetched.keys().cloned().collect();
        claims.sort_by_key(|claim| {
            (
                oldest[&claim.anchor.shard],
                claim.anchor.shard,
                claim.anchor.height,
                claim.anchor.ts,
            )
        });
        claims
    }

    /// Keep a pushed claim's cells while something here wants them, and
    /// say whether any was kept. `records` is the wanted set as the
    /// coordinator derives it now, since a push lands between the
    /// commits and probes that otherwise refresh it. A claim carrying
    /// nothing wanted costs no memory: a push that lands before its
    /// consumer's transaction commits here, or before any body reports
    /// its record, is dropped and the key is read once it is wanted.
    /// What is kept is cut to the wanted keys not already held at the
    /// anchor, so the section stays one proof per claim, disjoint per
    /// anchor, and each kept key's read counts the push as an ask
    /// answered at its anchor.
    pub(crate) fn offer_pushed(
        &mut self,
        claim: &StateClaim,
        records: &[WantedRecord],
        now: WeightedTimestamp,
    ) -> bool {
        if now.elapsed_since(claim.anchor.ts) > RETENTION_HORIZON {
            return false;
        }
        self.wanted = records.iter().map(|record| record.key).collect();
        let anchor = claim.anchor;
        let mut wanted: BTreeSet<SubstateKey> = claim
            .keys()
            .into_iter()
            .filter(|key| wants_reading(&self.held, &self.answered, &self.wanted, anchor, *key))
            .collect();
        if wanted.is_empty() {
            return false;
        }
        for held in self.fetched.keys() {
            if held.anchor == anchor {
                for key in held.keys() {
                    wanted.remove(&key);
                }
            }
        }
        if wanted.is_empty() {
            return true;
        }
        let Some(kept) = claim.restrict(|key| wanted.contains(&key)) else {
            return false;
        };
        for key in &wanted {
            self.records.pushed(*key, anchor);
        }
        self.fetched.entry(kept).or_default();
        true
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
        // A claim stands only at an anchor this validator still holds
        // commit-proven, since a retired or fenced anchor is one no
        // voter could stand it at, so one whose anchor is gone is let go
        // of here.
        let held = &self.held;
        let answered = &self.answered;
        let wanted = &self.wanted;
        let proven = &self.proven_anchors;
        self.fetched.retain(|claim, speaks_for| {
            if proven.at(claim.anchor.shard, claim.anchor.height) != Some(claim.anchor) {
                return false;
            }
            speaks_for
                .iter()
                .any(|tx_hash| unresolved.contains(*tx_hash))
                || claim
                    .cells
                    .iter()
                    .any(|(key, _)| wants_reading(held, answered, wanted, claim.anchor, *key))
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
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        let shard = ec.shard_id();
        // A certificate from a record's holder naming the transaction
        // is what arms the consumer's read of the record.
        self.records
            .certified(shard, ec.tx_outcomes().iter().map(TxOutcome::tx_hash), now);
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

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::test_utils::state_and_proof;
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, BlockHeight, CLAIM_WINDOW, CommittedAt, Deadline, Hash,
        LocalKey, MAX_FINALIZATION_DELAY, ResourceAddr, RoutePrefix, StateRoot,
        evidence_admits_block,
    };
    use hyperscale_vm_effects::{Answered, Hash32, IntentHash, Terms};

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
            Arc::new(CounterpartMirror::default()),
            &CrossingLeaves::default(),
            ReadFrontier::default(),
        );
        counterparts.answered.insert(
            SubstateKey {
                owner: Address::new([0x11; 31], AddressClass::Component),
                local: LocalKey([0x01; 16]),
            },
            AnsweredCrossing {
                id: CrossingId::of_record(
                    record.owner,
                    &producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(60_000))),
                ),
                record,
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
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
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
        let asked = counterparts.probe(&trie, now, &[], EpochWindows::new(0));
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
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
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
        counterparts.on_proof_fetched(anchor, &[record], &proof, &[]);
        assert!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
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
                    cells: Capped::new(vec![(record, Inclusion::Absent.into())]).expect("one cell"),
                    crossings: Capped::empty(),
                    proof: MerkleInclusionProof::dummy(),
                },
                EpochWindows::new(0),
            );
        };
        read_absent(&mut counterparts, anchor);
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
            "nothing more is worth asking: the absence is the licence, whole",
        );
        assert_eq!(
            counterparts
                .answered
                .values()
                .next()
                .map(|answer| answer.cleanup),
            Some(Cleanup::Gone(anchor)),
            "and the one absence is the licence, held with the anchor it was read at",
        );
    }

    /// A record that still stands is asked about again, but only once
    /// the read's backoff lets it: a holder header two above the last
    /// ask, or one finalization delay of the holder's clock past it.
    ///
    /// Both halves cost something and each is asserted where the other
    /// would hide it. A reading that is never repeated never learns the
    /// producer disposed, so the answer cell stands for good and the
    /// state never drains. A reading repeated at every header of a live
    /// producer is a fetch a block and a claim in every block — each
    /// one a cell every voter proves for itself, which is enough under
    /// cross-shard load to burn a round.
    #[test]
    fn a_standing_record_is_asked_about_again_once_the_backoff_lets_it() {
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
        assert_eq!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .len(),
            1
        );
        counterparts.on_proof_fetched(anchor, &[record], &proof, &[]);

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
        counterparts.fold_answered(&landed, EpochWindows::new(0));
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
                .probe(&trie, next.ts, &[], EpochWindows::new(0))
                .is_empty(),
            "and a header a block later is not worth a second question",
        );

        let later = Anchor {
            height: BlockHeight::new(9),
            ts: now.plus(MAX_FINALIZATION_DELAY),
            ..anchor
        };
        anchors.record(later);
        assert_eq!(
            counterparts
                .probe(&trie, later.ts, &[], EpochWindows::new(0))
                .len(),
            1,
            "two headers later it is: the record still stands, and nothing else would \
             ever learn it had gone",
        );
    }

    /// One absence of the record at or above the read frontier's floor
    /// is the whole licence, and one below it licenses nothing.
    ///
    /// A block admits a presence only at or above the floor its chain
    /// has read the producer to, so an absence at or above it comes
    /// after every presence the chain ever carried, and no presence can
    /// license a replay again — which is the only thing the answer cell
    /// was defending against. An absence below the floor may sit below
    /// a presence already carried, so it is not even remembered: the
    /// question is put again at an anchor the floor admits. A consumer
    /// needs no second reading and no span of its own.
    #[test]
    fn one_absence_at_or_above_the_floor_is_the_licence() {
        let at = |secs: u64| Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(secs),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(secs * 1_000),
        };
        let standing = Cleanup::Standing(None);
        let first = at(1_000);

        // A presence is the question put again, never an answer to it.
        let seen = standing.read(first, Inclusion::Present([7; 32]), true);
        assert_eq!(seen, Cleanup::Standing(Some(first)));
        assert!(
            !seen.wants(first),
            "and not asked again at the header it was already read at",
        );
        assert!(seen.wants(at(1_001)), "but at the next one it is");

        // An absence below the floor leaves the answer standing.
        assert_eq!(
            seen.read(at(999), Inclusion::Absent, false),
            seen,
            "an absence below the floor licenses nothing and is not remembered",
        );

        // One at or above it licenses outright.
        let gone = seen.read(at(1_001), Inclusion::Absent, true);
        assert_eq!(gone, Cleanup::Gone(at(1_001)));
        assert!(
            !gone.wants(at(9_999)),
            "and nothing further is worth asking: the answer is cleanable",
        );
        assert_eq!(
            gone.read(at(9_999), Inclusion::Absent, true),
            gone,
            "the reading a deletion is composed against does not drift to newer anchors",
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
        assert_eq!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .len(),
            1
        );
        counterparts.on_proof_fetched(anchor, &[record], &proof, &[]);

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
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
            "so the question is not put again at the producer's next header",
        );
    }

    /// An absence read from a shard that does not own the record's
    /// prefix licenses nothing, whatever its anchor: a leaf owns exactly
    /// its path's prefixes while it is live, so a sibling's absence of a
    /// key it never held says nothing about the record.
    #[test]
    fn an_absence_from_a_shard_not_owning_the_prefix_licenses_nothing() {
        let record = producer_record(0x42);
        let (mut counterparts, _, _) = answering(record);
        let absent_at = |shard: ShardId| StateClaim {
            anchor: Anchor {
                shard,
                height: BlockHeight::new(7),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: WeightedTimestamp::from_millis(7_000),
            },
            cells: Capped::new(vec![(record, Inclusion::Absent.into())]).expect("one cell"),
            crossings: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        };
        let cleanup = |counterparts: &Counterparts| {
            counterparts
                .answered
                .values()
                .next()
                .map(|answer| answer.cleanup)
        };
        counterparts.fold_answered(&absent_at(CONSUMER), EpochWindows::new(0));
        assert_eq!(
            cleanup(&counterparts),
            Some(Cleanup::Standing(None)),
            "the consumer's own anchor does not own the producer's prefix, and nothing of \
             it is remembered",
        );
        let owner = absent_at(PRODUCER);
        counterparts.fold_answered(&owner, EpochWindows::new(0));
        assert_eq!(
            cleanup(&counterparts),
            Some(Cleanup::Gone(owner.anchor)),
            "the owner's absence is the reading the question ends on",
        );
    }

    /// One producer's held claims are offered together in anchor order,
    /// and the producers by their oldest anchor: no claim of a producer
    /// rides while an older one of it is held back, and the producer
    /// closest to aging out goes first.
    #[test]
    fn held_claims_travel_by_producer_in_anchor_order() {
        let record = producer_record(0x42);
        let (mut counterparts, _, _) = answering(record);
        let other = ShardId::leaf(2, 0);
        let claim = |shard: ShardId, height: u64| StateClaim {
            anchor: Anchor {
                shard,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: WeightedTimestamp::from_millis(height * 1_000),
            },
            cells: Capped::new(vec![(record, Inclusion::Present([1; 32]).into())])
                .expect("one cell"),
            crossings: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        };
        for held in [claim(PRODUCER, 30), claim(other, 20), claim(PRODUCER, 10)] {
            counterparts.fetched.insert(held, BTreeSet::new());
        }
        let offered: Vec<(ShardId, u64)> = counterparts
            .state_claims()
            .iter()
            .map(|claim| (claim.anchor.shard, claim.anchor.height.inner()))
            .collect();
        assert_eq!(
            offered,
            vec![(PRODUCER, 10), (PRODUCER, 30), (other, 20)],
            "the producer with the oldest anchor goes first, whole, then the next",
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
        assert_eq!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .len(),
            1
        );
        counterparts.on_proof_fetched(anchor, &[record], &proof, &[]);
        counterparts.release_answered_fetches(&trie);
        assert!(
            counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "before it is folded the reading is still what the question wants",
        );

        // Folded as a **presence**, which is the reading that still has
        // a successor: the record stands, so the question is put again
        // at the producer's next header. An absence has no successor —
        // it is the licence itself — so it could not tell a spent
        // reading from a held-down one.
        counterparts.fold_answered(
            &StateClaim {
                anchor,
                cells: Capped::new(vec![(record, Inclusion::Present([9; 32]).into())])
                    .expect("one cell"),
                crossings: Capped::empty(),
                proof: MerkleInclusionProof::dummy(),
            },
            EpochWindows::new(0),
        );
        counterparts.release_answered_fetches(&trie);
        assert!(
            !counterparts
                .fetched
                .keys()
                .any(|claim| claim.reading(record).is_some()),
            "and once folded it is spent: no later reading of this record comes from here",
        );

        let next = Anchor {
            height: BlockHeight::new(8),
            ts: now
                .plus(MAX_FINALIZATION_DELAY)
                .plus(Duration::from_secs(1)),
            ..anchor
        };
        anchors.record(next);
        assert_eq!(
            counterparts
                .probe(&trie, next.ts, &[], EpochWindows::new(0))
                .len(),
            1,
            "so the question is put again once the pacing lets it, and the spent \
             reading is not what stands it down",
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
            consumer: Address::new([0x11; 31], AddressClass::Component),
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
            Arc::new(CounterpartMirror::default()),
            &CrossingLeaves::default(),
            ReadFrontier::default(),
        );
        for seed in 0..count {
            counterparts.held.insert(
                producer_record(seed),
                HeldRecord::of(producer_record(seed), producer_cell(seed, deadline)),
            );
        }
        (
            counterparts,
            ShardTrie::from_leaves([CONSUMER, PRODUCER]),
            anchors,
        )
    }

    /// The crossing `producer_cell(seed, ..)` records, as the record at
    /// `producer_record(seed)` names it.
    fn producer_crossing(seed: u8, deadline: Deadline) -> CrossingId {
        CrossingId::of_record(producer_record(seed).owner, &producer_cell(seed, deadline))
    }

    /// The claim cell of that crossing, under the consuming node's
    /// target.
    fn claim_of(seed: u8, deadline: Deadline) -> SubstateKey {
        producer_crossing(seed, deadline).answer_key(&ProtocolHasher, Answered::Taken)
    }

    /// The decline cell of that crossing, which sits under the same
    /// target its claim does.
    fn consumer_decline(seed: u8, deadline: Deadline) -> SubstateKey {
        producer_crossing(seed, deadline).answer_key(&ProtocolHasher, Answered::Never)
    }

    /// A producer whose consumer sits on its own shard offers the
    /// crossing to the block to read at its parent, once the consumer's
    /// answer is in this shard's own state, and a parent-anchored
    /// reading of the decline present is the crossing's answer.
    #[test]
    fn a_local_consumers_answer_is_read_at_the_parent() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let now = deadline.at();
        let seated = |answer_at: Option<SubstateKey>, answered: Answered| {
            // Seated at the shard the consumer's target routes to, which
            // is what a successor inheriting the producer's prefix
            // becomes.
            let mut counterparts = Counterparts::holding(
                CONSUMER,
                Arc::new(ProvenAnchors::default()),
                Arc::new(CounterpartMirror::default()),
                &CrossingLeaves::default(),
                ReadFrontier::default(),
            );
            let cell = producer_cell(0, deadline);
            counterparts
                .held
                .insert(producer_record(0), HeldRecord::of(producer_record(0), cell));
            if let Some(key) = answer_at {
                counterparts.note_answer(
                    key,
                    &CrossingAnswer {
                        tx: cell.tx,
                        intent: cell.intent,
                        local: cell.local,
                        output: cell.output,
                        producer: producer_record(0).owner,
                        answered,
                    },
                );
            }
            let asked = counterparts.probe(&trie, now, &[], EpochWindows::new(0));
            assert!(
                asked.is_empty(),
                "nothing is fetched of this shard's own state"
            );
            counterparts.offers().local_crossings
        };

        assert!(
            seated(None, Answered::Never).is_empty(),
            "a consumer that has not answered leaves the record waiting, and nothing is read",
        );
        let id = producer_crossing(0, deadline);
        assert_eq!(
            seated(Some(consumer_decline(0, deadline)), Answered::Never),
            vec![id],
            "its own decline has the crossing read at the parent",
        );
        assert_eq!(
            seated(Some(claim_of(0, deadline)), Answered::Taken),
            vec![id],
            "and so does its own claim, whose reading the fold retires the record on",
        );

        // The parent-anchored reading, folded where both ends route: the
        // decline present is the answer, and licenses the credit back.
        let mut counterparts = Counterparts::holding(
            CONSUMER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            &CrossingLeaves::default(),
            ReadFrontier::default(),
        );
        counterparts.held.insert(
            producer_record(0),
            HeldRecord::of(producer_record(0), producer_cell(0, deadline)),
        );
        let decline = consumer_decline(0, deadline);
        let claim = StateClaim::new(
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(7),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: now,
            },
            [(decline, Inclusion::Present([7; 32]))],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(decline, id)]);
        counterparts.fold_held(&claim, &trie);
        let held = counterparts
            .held
            .get(&producer_record(0))
            .expect("the record still stands");
        assert!(held.declined && held.unclaimable());
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
        let claim = claim_of(0, deadline);
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
        let asked = producer.probe(&trie, now, &[], EpochWindows::new(0));
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

        producer.on_proof_fetched(anchor, &[claim, decline], &proof, &[]);
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
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            producer
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
            "and the question is not put again at the consumer's next header",
        );
    }

    /// A fetched proof is held as a claim over exactly the keys it
    /// answered, with its proof cut to them, and the claim passes the
    /// check a block's admission runs. A second fetch at the same anchor
    /// overlapping it is held cut to the keys not yet held, so what is
    /// offered at one anchor is disjoint.
    #[test]
    fn a_fetched_proof_is_held_as_a_claim_over_its_answering_keys() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, anchors) = producing(2, deadline);
        let (claim0, decline0) = (claim_of(0, deadline), consumer_decline(0, deadline));
        let (claim1, decline1) = (claim_of(1, deadline), consumer_decline(1, deadline));
        let now = deadline.at();
        // One tree for both fetches, so both proofs reconstruct the
        // one root the anchor names.
        let (state_root, first) =
            state_and_proof(CONSUMER, &[decline0], &[claim0, decline0, claim1]);
        let (same_root, second) = state_and_proof(CONSUMER, &[decline0], &[claim1, decline1]);
        assert_eq!(state_root, same_root);
        let anchor = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        let _ = producer.probe(&trie, now, &[], EpochWindows::new(0));

        // The fixture tree's leaf value is the key's own bytes; served
        // beside the proof, it rides in the claim as a held reading.
        let served = (decline0, Bytes::new(decline0.to_bytes().to_vec()).unwrap());
        producer.on_proof_fetched(anchor, &[claim0, decline0, claim1], &first, &[served]);
        let held = producer.state_claims();
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].held(decline0),
            Some(decline0.to_bytes().as_slice()),
            "the served value is held in the claim",
        );
        assert_eq!(held[0].held(claim0), None);
        assert_eq!(held[0].keys(), {
            let mut keys = vec![claim0, decline0, claim1];
            keys.sort_unstable();
            keys
        });
        assert_eq!(
            held[0].verify(),
            Ok(()),
            "the proof covers exactly the claim's keys"
        );

        producer.on_proof_fetched(anchor, &[claim1, decline1], &second, &[]);
        let held = producer.state_claims();
        assert_eq!(held.len(), 2, "the overlap is held once");
        let fresh = held
            .iter()
            .find(|claim| claim.keys() == vec![decline1])
            .expect("the second fetch is held cut to the key the first did not cover");
        assert_eq!(fresh.verify(), Ok(()));
        let mut all: Vec<SubstateKey> = held.iter().flat_map(StateClaim::keys).collect();
        let before = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), before, "no key is held twice at one anchor");
    }

    /// A claim read present answers over a decline read beside it.
    ///
    /// Both cells present is a refusal rather than a preference, and the
    /// consumer's own licence is what makes it impossible. A producer
    /// reading one is not where that is discovered, and of the two
    /// mistakes available here only one is unrecoverable: taking back
    /// value a consumer demonstrably holds. So the fold takes the record
    /// on the claim, and the decline beside it licenses nothing.
    #[test]
    fn a_claim_read_present_answers_over_a_decline_beside_it() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, _anchors) = producing(1, deadline);
        let record = producer_record(0);
        let id = producer_crossing(0, deadline);
        let claim = claim_of(0, deadline);
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
            MerkleInclusionProof::dummy(),
        )
        .naming([(claim, id), (decline, id)]);
        assert_eq!(
            both.settles(),
            vec![id.record_key(&ProtocolHasher)],
            "the claim is what the record is answered by: the fold removes it",
        );
        producer.fold_held(&both, &trie);

        let held = producer.held.get(&record).expect("the record still stands");
        assert!(
            !held.declined && !held.unclaimable(),
            "so nothing licenses crediting back value the consumer holds",
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
