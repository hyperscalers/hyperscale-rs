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
use std::sync::{Arc, PoisonError, RwLock};

use hyperscale_core::{Action, FetchIds, FetchRequest, ProtocolEvent};
use hyperscale_metrics::{
    record_crossing_fallback_ask, record_fenced_claim, record_rebuilt_record_entry,
    record_reclaim_probe_answered, record_reclaim_probe_pending,
};
use hyperscale_types::network::response::ServedValue;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Anchor, Block, BlockHeight, CounterpartMirror,
    Deadline, EpochWindows, ExecutionCertificate, FrontierInputs, Inclusion,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_PROVISION_TARGET_SHARDS, MAX_UNSETTLED_PER_BLOCK,
    MAX_VALIDITY_RANGE, MerkleInclusionProof, Probed, ProvenAnchors, RETENTION_HORIZON,
    ReadFrontier, ReadMark, SettledTxSet, ShardId, ShardTrie, Spoken, StateClaim, Stated,
    SubstateKey, TerminalEvidence, TopologySchedule, TransactionDecision, TxHash, TxOutcome,
    TxResolution, UNCLAIMED_CROSSING_BYTES, UnclaimedCrossing, UnsettledTx, Verifiable, Verified,
    WeightedTimestamp,
};
use hyperscale_vm_effects::{Answered, CrossingId, CrossingLeaf, ProtocolHasher, Terms};

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

    /// Take as many of `unsettled` and then of `unclaimed` as the budget
    /// still affords, in the order offered, and charge for them. What is
    /// left is dropped: a name a record does not carry stays uncovered
    /// and is offered again next block.
    fn take(&mut self, unsettled: &mut Vec<UnsettledTx>, unclaimed: &mut Vec<UnclaimedCrossing>) {
        let mut spend = ABANDONMENT_RECORD_BYTES;
        let mut names = 0;
        let weights = unsettled
            .iter()
            .map(UnsettledTx::wire_weight)
            .chain(unclaimed.iter().map(|_| UNCLAIMED_CROSSING_BYTES));
        for weight in weights {
            if names == self.names || spend + weight > self.bytes {
                break;
            }
            spend += weight;
            names += 1;
        }
        let from_unsettled = names.min(unsettled.len());
        unsettled.truncate(from_unsettled);
        unclaimed.truncate(names - from_unsettled);
        if names == 0 {
            return;
        }
        self.names -= names;
        self.bytes -= spend;
    }
}

/// The crossing leaves this shard's committed state holds, read through
/// the committed tip: what the askers ask about.
///
/// Derived storage, and a pacing input only. Nothing composed from a
/// block reads it: a question it raises is answered by a reading every
/// voter re-proves, and a question it misses costs latency.
pub trait CrossingIndex: Send + Sync {
    /// The crossing records and answers under `shard`'s prefix, each
    /// with its bytes as the committed tip holds them, ascending by key.
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)>;

    /// Whether `key` reads present at the committed tip.
    fn present(&self, key: SubstateKey) -> bool;
}

/// The index a shard's store answers with, bound once the store's
/// chain is open: a vnode group is seated before its shard's chain
/// exists, and every coordinator of the group asks the same one.
///
/// Answers as an empty index until bound.
#[derive(Default)]
pub struct CrossingIndexSlot(RwLock<Option<Arc<dyn CrossingIndex>>>);

impl CrossingIndexSlot {
    /// Answer with `index` from here on.
    pub fn bind(&self, index: Arc<dyn CrossingIndex>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Some(index);
    }

    fn bound(&self) -> Option<Arc<dyn CrossingIndex>> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl CrossingIndex for CrossingIndexSlot {
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        self.bound()
            .map_or_else(Vec::new, |index| index.crossing_rows(shard))
    }

    fn present(&self, key: SubstateKey) -> bool {
        self.bound().is_some_and(|index| index.present(key))
    }
}

/// Crossing rows written out by hand: what a test holds where a store
/// would.
#[cfg(test)]
#[derive(Default)]
pub struct TestRows(std::sync::Mutex<BTreeMap<SubstateKey, Vec<u8>>>);

#[cfg(test)]
impl TestRows {
    /// A cell at `key`, crossing leaf or not.
    pub fn put(&self, key: SubstateKey, value: Vec<u8>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, value);
    }

    /// The cell at `key` gone.
    pub fn remove(&self, key: SubstateKey) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
    }
}

#[cfg(test)]
impl CrossingIndex for TestRows {
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(key, value)| {
                ShardTrie::shard_owns_prefix(shard, key.owner)
                    && CrossingLeaf::read(&ProtocolHasher, **key, value).is_some()
            })
            .map(|(key, value)| (*key, value.clone()))
            .collect()
    }

    fn present(&self, key: SubstateKey) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(&key)
    }
}

/// The widest gap, in the counterpart's heights, between two asks of a
/// question nothing has answered.
const MAX_ANSWER_ASK_GAP: u64 = 64;

/// The gap, in the counterpart's heights, before the next ask of an
/// answer asked `asked` times without one: `2^(asked-1)`, capped at
/// [`MAX_ANSWER_ASK_GAP`], so the asks fall at `h, h+1, h+3, h+7, ...`.
fn answer_ask_gap(asked: u32) -> u64 {
    (1u64 << asked.saturating_sub(1).min(6)).min(MAX_ANSWER_ASK_GAP)
}

/// One question a crossing row of this shard's puts to a counterpart,
/// with its pacing and nothing that records an answer.
///
/// A question stands exactly while the row it derives from stands, so
/// a discarded or aborted settlement is asked about again. It is asked
/// only past its transaction's deadline: before it the answer arrives
/// by push, and asking is the fallback for a push that did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asked {
    /// A record here asks its consumer's answer: the claim or the
    /// decline key, which are asked together at one header.
    Answer {
        /// The crossing the record holds.
        id: CrossingId,
        /// The record's deadline, `Deadline::of(V)`, from which it is
        /// asked.
        due_from: WeightedTimestamp,
        /// Past this an escrowed record's consumer can commit nothing
        /// and no abandonment can land, so nothing will answer; `None`
        /// for an owed record, whose answer no window bounds.
        disarm_at: Option<WeightedTimestamp>,
        /// The counterpart header the pair was last asked at.
        asked_at: Option<BlockHeight>,
        /// How many asks have gone unanswered: after the k-th the next
        /// waits `2^(k-1)` heights, capped at [`MAX_ANSWER_ASK_GAP`], so
        /// the asks fall at `h, h+1, h+3, h+7, ...`.
        step: u32,
    },
    /// An answer here asks whether its producer still holds the record.
    Record {
        /// The crossing the answer answers for.
        id: CrossingId,
        /// The answer's deadline, `Deadline::of(V)`, from which it is
        /// asked.
        due_from: WeightedTimestamp,
        /// The newest producer anchor a reading of the record present was
        /// folded at: a question worth putting only at a newer header.
        seen: Option<Anchor>,
        /// A pushed absence of the record was refused below the read
        /// frontier's floor, so the record is read again at once,
        /// whatever the deadline.
        reread: bool,
    },
}

impl Asked {
    /// Whether a reading taken at `anchor` could still move the question.
    fn wants(self, anchor: Anchor) -> bool {
        match self {
            Self::Answer { .. } => true,
            Self::Record { seen, .. } => seen.is_none_or(|seen| anchor.height > seen.height),
        }
    }
}

/// Whether any leaf-driven question of this shard's wants a reading of
/// `key` taken at `anchor`: a crossing row's question, or a record a
/// consumer here waits on.
///
/// Two sites need exactly this set: a fetch that lands is offered in a
/// block only if something here wants it, and a reading held to offer is
/// kept only while something here wants it. None of these questions
/// names a transaction of this chain's, which is why the keys are read
/// rather than the names.
fn wants_reading(
    asks: &BTreeMap<SubstateKey, Asked>,
    awaited: &BTreeSet<SubstateKey>,
    wanted: &BTreeSet<SubstateKey>,
    anchor: Anchor,
    key: SubstateKey,
) -> bool {
    asks.get(&key).is_some_and(|asked| asked.wants(anchor))
        || awaited.contains(&key)
        || wanted.contains(&key)
}

/// Whether `claim` holds at `key` an owed record this shard's commit
/// fold would credit: one whose consumer sits under `local`'s prefix and
/// for which no `Taken` stands at the committed tip.
///
/// Nothing here asks about such a record — the shard runs no member of
/// its transaction — so a push of it is kept on this rule alone, until
/// the fold's `Taken` lands.
fn owed_here(
    claim: &StateClaim,
    key: SubstateKey,
    local: ShardId,
    index: &dyn CrossingIndex,
) -> Option<CrossingId> {
    match CrossingLeaf::read(&ProtocolHasher, key, claim.held(key)?)? {
        CrossingLeaf::Record { crossing, cell }
            if cell.terms == Terms::Owed
                && ShardTrie::shard_owns_prefix(local, cell.consumer)
                && !index.present(crossing.id.answer_key(&ProtocolHasher, Answered::Taken)) =>
        {
            Some(crossing.id)
        }
        _ => None,
    }
}

/// What a claim reads that the read frontier fences: whether it carries
/// a record presence, and whether it carries an absence of the record
/// behind an answer this shard holds.
fn fenced_readings(asks: &BTreeMap<SubstateKey, Asked>, claim: &StateClaim) -> (bool, bool) {
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
                    && matches!(asks.get(key), Some(Asked::Record { .. }))
                {
                    removed = true;
                }
            }
        }
    }
    (record, removed)
}

/// A question this validator put to a counterpart: the question, the
/// header it was asked at, whether the fetch has returned, and how many
/// times it has been asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    question: Question,
    anchor: Anchor,
    returned: bool,
    asked: u32,
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
    /// settlement the rows say is due, for the block to read at its
    /// parent: a record whose answer reads present here, and an answer
    /// whose record routes here and reads absent.
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

    /// The crossing leaves this shard's committed state holds, read
    /// once per commit to derive the questions below and the local
    /// offers. Composition never reads it.
    index: Arc<dyn CrossingIndex>,

    /// The questions this shard's crossing rows put, by the key asked:
    /// a record's consumer answers, and an answer's record. Rebuilt from
    /// the rows at every commit, keeping only the pacing of a question
    /// that still stands; no field records an answer.
    asks: BTreeMap<SubstateKey, Asked>,

    /// The crossing a reading of each key speaks for, over every row:
    /// a record's answers and an answer's record, whoever asks about
    /// them. A record an entry here settles is asked about by the entry
    /// under its transaction's name, and its readings still have to name
    /// the crossing for the fold to settle on them.
    names: BTreeMap<SubstateKey, CrossingId>,

    /// The claim and decline keys of every record row, whoever asks
    /// about them: a pushed answer to one is kept to offer, including
    /// one for a record an entry here owns, which the leaf does not ask
    /// about.
    awaited: BTreeSet<SubstateKey>,

    /// Every owed record this shard holds for a consumer elsewhere, with
    /// its crossing and the instant its re-push opens: what the consumer
    /// credits only once a reading reaches it, and so what this shard
    /// sends it again until its `Taken` comes back.
    owed: BTreeMap<SubstateKey, (CrossingId, WeightedTimestamp)>,

    /// When each owed record was last re-pushed, at this shard's height,
    /// and how many times: node-local pacing, so a restarted replica
    /// re-pushes at once.
    repushed: BTreeMap<SubstateKey, (BlockHeight, u32)>,

    /// The read frontier as the committed chain leaves it: how far
    /// along each producer this shard has read, the copy the fold's own
    /// rule advances here at every commit. Read to license a deletion,
    /// which needs an absence at or above the floor, and to drop what
    /// is held to offer below it.
    frontier: ReadFrontier,

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
    /// Asking nothing yet: the questions derive from `index`'s rows at
    /// the first commit, whatever brought the store here.
    #[must_use]
    pub(crate) fn new(
        local_shard: ShardId,
        proven_anchors: Arc<ProvenAnchors>,
        mirror: Arc<CounterpartMirror>,
        index: Arc<dyn CrossingIndex>,
        frontier: ReadFrontier,
    ) -> Self {
        Self {
            ledger: Ledger::new(local_shard),
            mirror,
            proven_anchors,
            fetched: BTreeMap::new(),
            index,
            asks: BTreeMap::new(),
            names: BTreeMap::new(),
            awaited: BTreeSet::new(),
            owed: BTreeMap::new(),
            repushed: BTreeMap::new(),
            frontier,
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
        // What the block's claims settle is marked gone on the entry that
        // issued it, as the fold removes it from state: a record removed
        // on its consumer's `Taken` closes its entry's share.
        for key in block.state_claims().iter().flat_map(StateClaim::settles) {
            self.ledger.settled(key);
        }
        // The reads still worth pacing: the records something here
        // waits on, and the records behind the answers this shard holds.
        let live: BTreeSet<SubstateKey> = self
            .wanted
            .iter()
            .copied()
            .chain(
                self.asks
                    .iter()
                    .filter(|(_, asked)| matches!(asked, Asked::Record { .. }))
                    .map(|(key, _)| *key),
            )
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
        self.fold_state_claims(trie, block);
        let mut actions = Vec::new();
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
        self.derive_asks(trie);
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
    /// The shard holding an owed crossing's consumer is asked about the
    /// crossing's claim cell past the deadline, where no push answered
    /// it. Each is asked against that shard's newest
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
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        self.ask_entries(trie, now, &mut wanted);
        self.ask_consumer_answers(trie, now, &mut wanted);
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
                ..
            } = question;
            // The newest header the question stands at, of those
            // standing at the chain's clock: the one the shard is
            // likeliest to still serve, and the one every member of
            // this committee is asking of.
            let Some(anchor) = self
                .proven_anchors
                .newest_licensed(shard, now, |ts| probed.asks_at(ts, deadline))
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
            //
            // An answer is the fallback for a push that did not land, so
            // it backs off as the leaf's questions do; a core's cell has
            // no push to stand in for and is asked at every newer header.
            let answer = matches!(probed, Probed::Claim | Probed::Decline);
            let prior = self.probes.get(&(shard, key)).copied();
            let gap = |asked| if answer { answer_ask_gap(asked) } else { 1 };
            if self.holds_answer(shard, key)
                || prior.is_some_and(|probe| {
                    !probe.returned
                        || anchor.height.inner() < probe.anchor.height.inner() + gap(probe.asked)
                })
            {
                continue;
            }
            self.probes.insert(
                (shard, key),
                Probe {
                    question,
                    anchor,
                    returned: false,
                    asked: prior.map_or(1, |probe| probe.asked.saturating_add(1)),
                },
            );
            if answer {
                record_crossing_fallback_ask("producer");
            }
            wanted.entry(anchor).or_default().push(key);
        }
    }

    /// The questions this shard's crossing rows put, rebuilt from the
    /// rows the index holds under this shard's prefix, keeping the pacing
    /// of every question that still stands; and the local crossings a
    /// settlement is due for.
    ///
    /// A record row asks for its consumer's claim and decline keys, and
    /// an answer row for its record key, of whichever shard holds the
    /// key's prefix. A key that routes here is never asked: a record
    /// whose claim or decline reads present, and an answer whose record
    /// reads absent, is offered for the block to read at its parent.
    /// A record an entry here settles is named and not asked about: the
    /// entry asks its own questions under the transaction's name.
    pub(crate) fn derive_asks(&mut self, trie: &ShardTrie) {
        let local = self.ledger.local();
        let mut asks = BTreeMap::new();
        let mut names = BTreeMap::new();
        let mut awaited = BTreeSet::new();
        let mut owed = BTreeMap::new();
        self.local_crossings.clear();
        for (key, value) in self.index.crossing_rows(local) {
            match CrossingLeaf::read(&ProtocolHasher, key, &value) {
                Some(CrossingLeaf::Record { cell, .. }) => {
                    let id = CrossingId::of_record(key.owner, &cell);
                    let claim = id.answer_key(&ProtocolHasher, Answered::Taken);
                    let decline = id.answer_key(&ProtocolHasher, Answered::Never);
                    names.insert(claim, id);
                    names.insert(decline, id);
                    awaited.insert(claim);
                    awaited.insert(decline);
                    let due_from =
                        Deadline::of(WeightedTimestamp::from_millis(cell.validity_end_ms)).at();
                    let consumer_here = trie.shard_for_prefix(claim.owner) == local;
                    if cell.terms == Terms::Owed && !consumer_here {
                        owed.insert(key, (id, due_from));
                    }
                    if self.ledger.settles_record(key) {
                        continue;
                    }
                    if consumer_here {
                        // An owed record whose consumer a merge brought
                        // here is credited by this shard's own fold, off
                        // its reading at the parent.
                        if self.index.present(claim)
                            || self.index.present(decline)
                            || cell.terms == Terms::Owed
                        {
                            self.local_crossings.insert(id);
                        }
                        continue;
                    }
                    let (asked_at, step) = match self.asks.get(&claim) {
                        Some(Asked::Answer { asked_at, step, .. }) => (*asked_at, *step),
                        _ => (None, 0),
                    };
                    let disarm_at = matches!(cell.terms, Terms::Escrowed { .. })
                        .then(|| due_from.plus(MAX_VALIDITY_RANGE));
                    for asked in [claim, decline] {
                        asks.insert(
                            asked,
                            Asked::Answer {
                                id,
                                due_from,
                                disarm_at,
                                asked_at,
                                step,
                            },
                        );
                    }
                }
                Some(CrossingLeaf::Answer { id, answer }) => {
                    let record = id.record_key(&ProtocolHasher);
                    names.insert(record, id);
                    if trie.shard_for_prefix(record.owner) == local {
                        if !self.index.present(record) {
                            self.local_crossings.insert(id);
                        }
                        continue;
                    }
                    let (seen, reread) = match self.asks.get(&record) {
                        Some(Asked::Record { seen, reread, .. }) => (*seen, *reread),
                        _ => (None, false),
                    };
                    let due_from =
                        Deadline::of(WeightedTimestamp::from_millis(answer.validity_end_ms)).at();
                    asks.insert(
                        record,
                        Asked::Record {
                            id,
                            due_from,
                            seen,
                            reread,
                        },
                    );
                }
                None => {}
            }
        }
        self.asks = asks;
        self.names = names;
        self.repushed.retain(|record, _| owed.contains_key(record));
        self.owed = owed;
        self.awaited = awaited;
    }

    /// The owed records to push to their consumers again at `height`,
    /// by the shard holding each consumer's prefix under `trie`.
    ///
    /// An owed record's consumer credits it only once a reading reaches
    /// it, and nothing there asks: the shard runs no member of the
    /// transaction. So the record is pushed again from its deadline, at
    /// this shard's heights `h, h+1, h+3, h+7, ...` with the gap capped
    /// at [`MAX_ANSWER_ASK_GAP`], for as long as it stands, which is
    /// until the fold here reads the `Taken` the consumer's fold wrote.
    /// The pacing is taken as the push is, so a call only a proposer
    /// makes paces only its own pushes.
    pub(crate) fn owed_repushes(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        height: BlockHeight,
    ) -> BTreeMap<ShardId, Vec<SubstateKey>> {
        let mut targets: BTreeMap<ShardId, Vec<SubstateKey>> = BTreeMap::new();
        for (record, (id, due_from)) in &self.owed {
            if now < *due_from {
                continue;
            }
            let pushed = self.repushed.get(record).copied();
            if pushed.is_some_and(|(at, times)| height.inner() < at.inner() + answer_ask_gap(times))
            {
                continue;
            }
            self.repushed.insert(
                *record,
                (
                    height,
                    pushed.map_or(1, |(_, times)| times.saturating_add(1)),
                ),
            );
            targets
                .entry(trie.shard_for_prefix(id.consumer))
                .or_default()
                .push(*record);
        }
        targets
    }

    /// The records this shard holds ask one question each, of whoever
    /// holds the claim's prefix now: what did the consumer answer? Both
    /// cells, at one anchor.
    ///
    /// Asked only past the record's deadline, where no push answered it,
    /// and then at gaps that double per unanswered ask, capped at
    /// [`MAX_ANSWER_ASK_GAP`] heights; an escrowed record is asked no
    /// more once its consumer can commit nothing and no abandonment can
    /// land, and stands as a strand.
    fn ask_consumer_answers(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        let claims: Vec<(SubstateKey, Asked)> = self
            .asks
            .iter()
            .filter(|(key, asked)| match asked {
                Asked::Answer { id, .. } => {
                    **key == id.answer_key(&ProtocolHasher, Answered::Taken)
                }
                Asked::Record { .. } => false,
            })
            .map(|(key, asked)| (*key, *asked))
            .collect();
        for (claim, asked) in claims {
            let Asked::Answer {
                id,
                due_from,
                disarm_at,
                asked_at,
                step,
            } = asked
            else {
                continue;
            };
            if now < due_from || disarm_at.is_some_and(|disarm| now > disarm) {
                continue;
            }
            let shard = trie.shard_for_prefix(claim.owner);
            let Some(anchor) = self.proven_anchors.newest_licensed(shard, now, |_| true) else {
                continue;
            };
            if asked_at
                .is_some_and(|asked| anchor.height.inner() < asked.inner() + answer_ask_gap(step))
            {
                continue;
            }
            // They are two keys under one owner, so this is one fetch and
            // one claim carries both readings — and the question is not
            // "did the consumer claim" but "what did it answer", which
            // has two shapes and one of them is the refusal.
            let decline = id.answer_key(&ProtocolHasher, Answered::Never);
            for key in [claim, decline] {
                self.asks.insert(
                    key,
                    Asked::Answer {
                        id,
                        due_from,
                        disarm_at,
                        asked_at: Some(anchor.height),
                        step: step.saturating_add(1),
                    },
                );
            }
            record_crossing_fallback_ask("producer");
            let entry = wanted.entry(anchor).or_default();
            entry.push(claim);
            entry.push(decline);
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
        let records: Vec<(SubstateKey, Asked)> = self
            .asks
            .iter()
            .filter(|(_, asked)| matches!(asked, Asked::Record { .. }))
            .map(|(key, asked)| (*key, *asked))
            .collect();
        for (record, asked) in records {
            let Asked::Record {
                id,
                due_from,
                seen,
                reread,
            } = asked
            else {
                continue;
            };
            if now < due_from && !reread {
                continue;
            }
            let shard = trie.shard_for_prefix(record.owner);
            self.records.arm_now(record);
            let Some(anchor) = self.newest_above_floor(shard, now, windows) else {
                continue;
            };
            if !asked.wants(anchor)
                || self.fetched.keys().any(|claim| {
                    claim.anchor.shard == shard
                        && claim.reading(record).is_some()
                        && asked.wants(claim.anchor)
                })
            {
                continue;
            }
            if self.records.due(record, anchor) {
                if reread {
                    self.asks.insert(
                        record,
                        Asked::Record {
                            id,
                            due_from,
                            seen,
                            reread: false,
                        },
                    );
                } else {
                    record_crossing_fallback_ask("consumer");
                }
                wanted.entry(anchor).or_default().push(record);
            }
        }
    }

    /// Whether this validator holds an answering reading of `key` on
    /// `shard` to offer, so the question is not put to a counterpart
    /// again for an answer already in hand.
    fn holds_answer(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.fetched
            .keys()
            .any(|claim| claim.anchor.shard == shard && claim.reading(key).is_some())
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
            inclusions
                .iter()
                .map(|(key, _)| *key)
                .filter(|key| wants_reading(&self.asks, &self.awaited, &self.wanted, anchor, *key)),
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
        self.names.get(&key).copied()
    }

    /// Fold the claims a committed block carries into the answers every
    /// replica holds.
    ///
    /// A claim answers every cell of the ledger's on the anchor's shard
    /// whose window the anchor's clock sits inside — whether or not this
    /// replica had a probe out, and wherever its own probe sat — so a
    /// replica that never fetched reads the same answer as the one that
    /// did. A claim cell present is the consumer holding the crossing,
    /// which is written straight to the ledger and licenses the
    /// retirement. A core consumer's claim absent says only that a
    /// sibling is pending, and a committed cell present that a member
    /// is; either is asked again at the next header. The first proof to
    /// answer a cell is the answer; a later one adds nothing.
    fn fold_state_claims(&mut self, trie: &ShardTrie, block: &Block) {
        if block.state_claims().is_empty() {
            return;
        }
        let questions = self.ledger.questions(trie);
        for claim in block.state_claims() {
            self.fold_cells(claim, &questions);
            self.fold_seen(claim);
        }
    }

    /// Count the fenced claims the block carries, by what each reads: a
    /// record presence, and an absence of a record behind an answer
    /// this shard holds.
    fn count_carried(&self, block: &Block) {
        for claim in block.state_claims() {
            let (record, removed) = fenced_readings(&self.asks, claim);
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
    /// brought it. A claim carrying no fenced reading is left to the age
    /// bound and the ledger: a bare reading below the floor is
    /// admissible.
    fn drop_below_floor(&mut self, windows: EpochWindows) {
        let refused: Vec<StateClaim> = self
            .fetched
            .keys()
            .filter(|claim| {
                self.frontier
                    .refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows))
            })
            .filter(|claim| {
                let (record, removed) = fenced_readings(&self.asks, claim);
                record || removed
            })
            .cloned()
            .collect();
        for claim in refused {
            self.fetched.remove(&claim);
            self.refuse_fenced(&claim);
        }
    }

    /// Whether a pushed claim sits below the read frontier's floor for
    /// its producer: one every voter refuses, so not worth holding. A
    /// refused one carrying a fenced reading starts its keys' reads over,
    /// as a held one the floor rises past does.
    pub(crate) fn refuse_pushed(&mut self, claim: &StateClaim, windows: EpochWindows) -> bool {
        if !self
            .frontier
            .refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows))
        {
            return false;
        }
        self.refuse_fenced(claim);
        true
    }

    /// Count a claim the frontier refused and start its fenced keys'
    /// reads over, so the next probe asks again at a proven anchor at or
    /// above the floor.
    ///
    /// A record a consumer here waits on is read again at once, and so
    /// is one whose removal was refused: the push that would have
    /// settled the answer is gone. A refused presence behind an answer
    /// keeps its backoff, or every carried reading that raises the floor
    /// past another validator's held one restarts that validator's asks.
    fn refuse_fenced(&mut self, claim: &StateClaim) {
        let (record, removed) = fenced_readings(&self.asks, claim);
        if record {
            record_fenced_claim("record", false);
        }
        if removed {
            record_fenced_claim("removed", false);
        }
        if !record && !removed {
            return;
        }
        let reread: Vec<SubstateKey> = claim
            .cells
            .iter()
            .filter_map(|(key, stated)| {
                (stated.inclusion() == Inclusion::Absent
                    && matches!(self.asks.get(key), Some(Asked::Record { .. })))
                .then_some(*key)
            })
            .collect();
        for key in reread {
            if let Some(Asked::Record { reread, .. }) = self.asks.get_mut(&key) {
                *reread = true;
            }
            self.records.reset(key);
        }
        for key in claim.keys() {
            if self.wanted.contains(&key) {
                self.records.reset(key);
            }
        }
    }

    /// Note the producer anchors a committed claim read a record present
    /// at, for the answers here that ask about it: the question is worth
    /// putting again only at a newer header.
    ///
    /// Only a presence moves the question. An absence at or above the
    /// read frontier's floor is the fold's licence to delete the answer,
    /// which takes its row and so its question with it; one below the
    /// floor licenses nothing, and the question is put again.
    fn fold_seen(&mut self, stated: &StateClaim) {
        let shard = stated.anchor.shard;
        for (key, asked) in &mut self.asks {
            let Asked::Record { seen, .. } = asked else {
                continue;
            };
            if !ShardTrie::shard_owns_prefix(shard, key.owner) {
                continue;
            }
            if matches!(stated.reading(*key), Some(Inclusion::Present(_)))
                && seen.is_none_or(|seen| stated.anchor.height > seen.height)
            {
                *seen = Some(stated.anchor);
            }
        }
    }

    /// Fold one claim's answers into the questions the ledger is
    /// waiting on.
    fn fold_cells(&mut self, claim: &StateClaim, questions: &[Question]) {
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
        }
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

    /// Fold a core shard's acceptance: one more core shard saying the
    /// transaction went through, and the mempool told once every core
    /// shard has.
    ///
    /// Nothing is written down. What a record stands on is its
    /// consumer's answer, pushed or read present.
    pub(crate) fn fold_accepted(&mut self, shard: ShardId, tx_hash: TxHash) -> Vec<Action> {
        if shard == self.ledger.local() {
            return Vec::new();
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
        let local = self.ledger.local();
        let mut wanted: BTreeSet<SubstateKey> = claim
            .keys()
            .into_iter()
            .filter(|key| {
                wants_reading(&self.asks, &self.awaited, &self.wanted, anchor, *key)
                    || owed_here(claim, *key, local, self.index.as_ref()).is_some()
            })
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
        // An owed record addressed here names its own crossing, which
        // is what the fold credits it under.
        let owed: Vec<(SubstateKey, CrossingId)> = wanted
            .iter()
            .filter_map(|key| {
                owed_here(&kept, *key, local, self.index.as_ref()).map(|id| (*key, id))
            })
            .collect();
        let kept = if owed.is_empty() {
            kept
        } else {
            let named: Vec<(SubstateKey, CrossingId)> =
                kept.crossings.iter().copied().chain(owed).collect();
            kept.naming(named)
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
        let asks = &self.asks;
        let awaited = &self.awaited;
        let wanted = &self.wanted;
        let proven = &self.proven_anchors;
        let local = unresolved.local();
        let index = self.index.as_ref();
        self.fetched.retain(|claim, speaks_for| {
            if proven.at(claim.anchor.shard, claim.anchor.height) != Some(claim.anchor) {
                return false;
            }
            speaks_for
                .iter()
                .any(|tx_hash| unresolved.contains(*tx_hash))
                || claim.cells.iter().any(|(key, _)| {
                    wants_reading(asks, awaited, wanted, claim.anchor, *key)
                        || owed_here(claim, *key, local, index).is_some()
                })
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
                let mut unclaimed = self.unclaimed_with(shard, settled.terminal_wt);
                unclaimed.retain(|crossing| !settled.txs.contains(&crossing.tx));
                budget.take(&mut unsettled, &mut unclaimed);
                if unsettled.is_empty() && unclaimed.is_empty() {
                    continue;
                }
                let record = AbandonmentRecord::new(shard, settled.terminal_wt, unsettled)
                    .with_unclaimed(unclaimed);
                records.insert(shard, record);
            }
        });
        records.into_values().collect()
    }

    /// The crossings this shard's record leaves hold that `shard`,
    /// leaving at `cut`, could have taken and no ledger entry names:
    /// what a departure names off the leaves, because a leg entry is
    /// gone one claim window past its deadline and a departure can be
    /// cut later than that.
    ///
    /// Escrowed records only, whose consumer's route `shard` holds and
    /// whose transaction's deadline had passed by the cut; the rest of
    /// [`UnclaimedCrossing::party`] is the proposer's to apply against
    /// the schedule. Read off the index's rows: a record a departure
    /// already named is offered again while it stands, and a second
    /// naming composes a reclaim that reads it gone.
    fn unclaimed_with(&self, shard: ShardId, cut: WeightedTimestamp) -> Vec<UnclaimedCrossing> {
        self.index
            .crossing_rows(self.ledger.local())
            .into_iter()
            .filter_map(
                |(key, value)| match CrossingLeaf::read(&ProtocolHasher, key, &value)? {
                    CrossingLeaf::Record { cell, .. } => Some((key, cell)),
                    CrossingLeaf::Answer { .. } => None,
                },
            )
            .filter(|(_, cell)| {
                matches!(cell.terms, Terms::Escrowed { .. }) && !self.ledger.contains(cell.tx)
            })
            .map(|(key, cell)| UnclaimedCrossing::of(key, &cell))
            .filter(|crossing| {
                ShardTrie::shard_owns_route(shard, crossing.consumer)
                    && Deadline::of(crossing.validity_end).at() <= cut
            })
            .collect()
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
                Spoken::Accepted => self.fold_accepted(shard, tx_hash),
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
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::state_and_proof;
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, BlockHeight, CommittedAt, Deadline, Hash, LocalKey,
        MAX_FINALIZATION_DELAY, ResourceAddr, RoutePrefix, StateRoot, evidence_admits_block,
    };
    use hyperscale_vm_effects::{Answered, CrossingCell, Hash32, IntentHash, Terms};

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
            escrowed: Capped::empty(),
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

    /// A consumer holding one claim over a two-shard trie, with the
    /// questions its row puts, and the record the claim answers for.
    struct Answering {
        counterparts: Counterparts,
        trie: ShardTrie,
        anchors: Arc<ProvenAnchors>,
        rows: Arc<TestRows>,
        record: SubstateKey,
        answer: SubstateKey,
    }

    fn answering() -> Answering {
        let anchors = Arc::new(ProvenAnchors::default());
        let rows = Arc::new(TestRows::default());
        // A deadline at the clock the tests ask at: nothing is asked
        // before it.
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let id = CrossingId::of_record(producer_record(0x42).owner, &cell);
        let answer = id.answer_key(&ProtocolHasher, Answered::Taken);
        rows.put(
            answer,
            id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                .to_bytes(),
        );
        let mut counterparts = Counterparts::new(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        counterparts.derive_asks(&trie);
        Answering {
            counterparts,
            trie,
            anchors,
            rows,
            record: id.record_key(&ProtocolHasher),
            answer,
        }
    }

    /// A claim at `anchor` reading `record` as `inclusion`, with no proof.
    fn reading(anchor: Anchor, record: SubstateKey, inclusion: Inclusion) -> StateClaim {
        StateClaim {
            anchor,
            cells: Capped::new(vec![(record, inclusion.into())]).expect("one cell"),
            crossings: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        }
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
        let Answering {
            mut counterparts,
            trie,
            anchors,
            rows,
            record,
            answer,
        } = answering();
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

        // The block carrying the absence deletes the answer in its fold,
        // and the row goes with it: nothing is left to ask about.
        rows.remove(answer);
        counterparts.derive_asks(&trie);
        counterparts.release_answered_fetches(&trie);
        anchors.record(Anchor {
            height: BlockHeight::new(9),
            ..anchor
        });
        assert!(
            counterparts
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
            "a question stands exactly while its row stands",
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
        let Answering {
            mut counterparts,
            trie,
            anchors,
            record,
            ..
        } = answering();
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
        counterparts.fold_seen(&landed);
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

    /// A record read present is the question put again, at a newer
    /// header only; an absence moves no question, since the fold deletes
    /// the answer on one the read frontier licenses and the row goes with
    /// it, and one below the floor licenses nothing.
    #[test]
    fn a_presence_paces_the_question_and_an_absence_moves_nothing() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let at = |height: u64| Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(height * 1_000),
        };
        let asked = |counterparts: &Counterparts| counterparts.asks[&record];
        assert!(asked(&counterparts).wants(at(1_000)));

        counterparts.fold_seen(&reading(at(1_000), record, Inclusion::Present([7; 32])));
        assert!(
            !asked(&counterparts).wants(at(1_000)),
            "not asked again at the header it was already read at",
        );
        assert!(
            asked(&counterparts).wants(at(1_001)),
            "but at the next one it is"
        );

        counterparts.fold_seen(&reading(at(1_001), record, Inclusion::Absent));
        assert!(
            asked(&counterparts).wants(at(1_001)),
            "an absence records nothing here",
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
        let Answering {
            mut counterparts,
            trie,
            anchors,
            record,
            ..
        } = answering();
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

    /// A reading from a shard that does not own the record's prefix
    /// moves nothing, whatever its anchor: a leaf owns exactly its
    /// path's prefixes while it is live, so a sibling's reading of a key
    /// it never held says nothing about the record.
    #[test]
    fn a_reading_from_a_shard_not_owning_the_prefix_moves_nothing() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let present_at = |shard: ShardId| {
            reading(
                Anchor {
                    shard,
                    height: BlockHeight::new(7),
                    state_root: StateRoot::from_raw(Hash::ZERO),
                    ts: WeightedTimestamp::from_millis(7_000),
                },
                record,
                Inclusion::Present([7; 32]),
            )
        };
        let seen = |counterparts: &Counterparts| match counterparts.asks[&record] {
            Asked::Record { seen, .. } => seen,
            Asked::Answer { .. } => panic!("an answer asks about its record"),
        };
        counterparts.fold_seen(&present_at(CONSUMER));
        assert_eq!(
            seen(&counterparts),
            None,
            "the consumer's own anchor does not own the producer's prefix",
        );
        let owner = present_at(PRODUCER);
        counterparts.fold_seen(&owner);
        assert_eq!(seen(&counterparts), Some(owner.anchor));
    }

    /// One producer's held claims are offered together in anchor order,
    /// and the producers by their oldest anchor: no claim of a producer
    /// rides while an older one of it is held back, and the producer
    /// closest to aging out goes first.
    #[test]
    fn held_claims_travel_by_producer_in_anchor_order() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
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
        let Answering {
            mut counterparts,
            trie,
            anchors,
            record,
            ..
        } = answering();
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
        counterparts.fold_seen(&reading(anchor, record, Inclusion::Present([9; 32])));
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
    /// the prefix of, whose transaction's deadline is `deadline`.
    fn producer_cell(seed: u8, deadline: Deadline) -> CrossingCell {
        CrossingCell {
            resource: ResourceAddr::new([0xE1; 31]),
            amount: 1_000,
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
            validity_end_ms: deadline.at().as_millis() - MAX_FINALIZATION_DELAY.as_secs() * 1_000,
            tx: TxHash::from(Hash::from_bytes(&[seed; 32])),
            consumer: Address::new([0x11; 31], AddressClass::Component),
            terms: Terms::Owed,
        }
    }

    /// A producer holding `count` records at their derived keys, each its
    /// own transaction, over a two-shard trie — and no ledger entry for
    /// any of them.
    fn producing(
        count: u8,
        deadline: Deadline,
    ) -> (Counterparts, ShardTrie, Arc<ProvenAnchors>, Arc<TestRows>) {
        let anchors = Arc::new(ProvenAnchors::default());
        let rows = Arc::new(TestRows::default());
        for seed in 0..count {
            rows.put(
                record_of(seed, deadline),
                producer_cell(seed, deadline).to_bytes(),
            );
        }
        let mut counterparts = Counterparts::new(
            PRODUCER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        counterparts.derive_asks(&trie);
        (counterparts, trie, anchors, rows)
    }

    /// The record `producer_cell(seed, ..)` sits at, under its producer.
    fn record_of(seed: u8, deadline: Deadline) -> SubstateKey {
        producer_crossing(seed, deadline).record_key(&ProtocolHasher)
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
    /// answer is in this shard's own state, and asks nothing of it. An
    /// owed record is offered unanswered: its credit is this shard's own
    /// fold's.
    #[test]
    fn a_local_consumers_answer_is_read_at_the_parent() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let trie = ShardTrie::from_leaves([ShardId::ROOT]);
        let now = deadline.at();
        let id = producer_crossing(0, deadline);
        let escrowed = Terms::Escrowed {
            credit: producer_record(0),
        };
        let seated = |terms: Terms, answered: Option<Answered>| {
            // Seated where both ends route, which is what a successor
            // inheriting both prefixes becomes.
            let rows = Arc::new(TestRows::default());
            let cell = CrossingCell {
                terms,
                ..producer_cell(0, deadline)
            };
            rows.put(record_of(0, deadline), cell.to_bytes());
            if let Some(answered) = answered {
                rows.put(
                    id.answer_key(&ProtocolHasher, answered),
                    id.answer(cell.tx, answered, cell.validity_end_ms)
                        .to_bytes(),
                );
            }
            let mut counterparts = Counterparts::new(
                ShardId::ROOT,
                Arc::new(ProvenAnchors::default()),
                Arc::new(CounterpartMirror::default()),
                rows,
                ReadFrontier::default(),
            );
            counterparts.derive_asks(&trie);
            let asked = counterparts.probe(&trie, now, &[], EpochWindows::new(0));
            assert!(
                asked.is_empty(),
                "nothing is fetched of this shard's own state"
            );
            counterparts.offers().local_crossings
        };

        assert!(
            seated(escrowed, None).is_empty(),
            "a consumer that has not answered leaves the record waiting, and nothing is read",
        );
        assert_eq!(
            seated(escrowed, Some(Answered::Never)),
            vec![id],
            "its own decline has the crossing read at the parent",
        );
        assert_eq!(
            seated(escrowed, Some(Answered::Taken)),
            vec![id],
            "and so does its own claim, whose reading the fold retires the record on",
        );
        assert_eq!(
            seated(Terms::Owed, None),
            vec![id],
            "an owed record is read unanswered, for this shard's fold to credit",
        );
    }

    /// An answer whose record routes here is offered for the block to
    /// read at its parent once the record reads absent here, and neither
    /// end is ever asked about.
    #[test]
    fn a_local_producers_record_is_read_at_the_parent_once_gone() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let trie = ShardTrie::from_leaves([ShardId::ROOT]);
        let id = producer_crossing(0, deadline);
        let cell = producer_cell(0, deadline);
        let offered = |record_stands: bool| {
            let rows = Arc::new(TestRows::default());
            rows.put(
                id.answer_key(&ProtocolHasher, Answered::Taken),
                id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                    .to_bytes(),
            );
            if record_stands {
                rows.put(record_of(0, deadline), cell.to_bytes());
            }
            let mut counterparts = Counterparts::new(
                ShardId::ROOT,
                Arc::new(ProvenAnchors::default()),
                Arc::new(CounterpartMirror::default()),
                rows,
                ReadFrontier::default(),
            );
            counterparts.derive_asks(&trie);
            assert!(
                counterparts
                    .probe(&trie, deadline.at(), &[], EpochWindows::new(0))
                    .is_empty(),
                "nothing is fetched of this shard's own state",
            );
            counterparts.offers().local_crossings
        };
        assert_eq!(
            offered(true),
            vec![id],
            "while the record stands it is offered from the record's side, its claim present",
        );
        assert_eq!(
            offered(false),
            vec![id],
            "and once it is gone the answer alone offers it, for the fold to delete",
        );
    }

    /// A question stands exactly while its row stands, and records no
    /// answer: a decline read present leaves both of the record's
    /// questions asked, and they go only with the record.
    #[test]
    fn the_asks_hold_no_verdict() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, _anchors, rows) = producing(1, deadline);
        let (claim, decline) = (claim_of(0, deadline), consumer_decline(0, deadline));
        let id = producer_crossing(0, deadline);
        let read = StateClaim::new(
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(7),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: deadline.at(),
            },
            [(decline, Inclusion::Present([7; 32]))],
            MerkleInclusionProof::dummy(),
        )
        .naming([(decline, id)]);
        producer.fold_seen(&read);
        producer.derive_asks(&trie);
        assert!(
            producer.asks.contains_key(&claim) && producer.asks.contains_key(&decline),
            "the refusal is block content, not a flag here",
        );
        rows.remove(record_of(0, deadline));
        producer.derive_asks(&trie);
        assert!(
            producer.asks.is_empty(),
            "and the questions go with the row"
        );
    }

    /// A replica seated on the same rows asks what a replica that
    /// committed through asks: the questions derive from the rows alone.
    #[test]
    fn a_seated_replica_asks_what_one_that_committed_through_asks() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut through, trie, _, rows) = producing(2, deadline);
        through.derive_asks(&trie);
        through.derive_asks(&trie);
        let mut seated = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            rows,
            ReadFrontier::default(),
        );
        seated.derive_asks(&trie);
        assert_eq!(
            seated.asks.keys().collect::<Vec<_>>(),
            through.asks.keys().collect::<Vec<_>>(),
        );
        assert_eq!(seated.names, through.names);
    }

    /// The heights a producer asks its consumer's answer at, over a run
    /// of consumer headers `1..=last`, at the committed clock `now`, for
    /// a record of `terms`.
    fn asked_heights(terms: Terms, now: WeightedTimestamp, last: u64) -> Vec<u64> {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000));
        let anchors = Arc::new(ProvenAnchors::default());
        let rows = Arc::new(TestRows::default());
        let cell = CrossingCell {
            terms,
            ..producer_cell(0, deadline)
        };
        rows.put(record_of(0, deadline), cell.to_bytes());
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            rows,
            ReadFrontier::default(),
        );
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        producer.derive_asks(&trie);
        let mut asked = Vec::new();
        for height in 1..=last {
            anchors.record(Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: WeightedTimestamp::ZERO,
            });
            if !producer
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty()
            {
                asked.push(height);
            }
        }
        asked
    }

    /// A question nobody answers is asked past the deadline at gaps that
    /// double per ask, capped at 64 heights, and never before it.
    #[test]
    fn the_fallback_backs_off_and_opens_at_the_deadline() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000)).at();
        assert!(
            asked_heights(Terms::Owed, deadline.minus(Duration::from_millis(1)), 20).is_empty(),
            "nothing is asked before the deadline: the answer comes by push",
        );
        let asked = asked_heights(Terms::Owed, deadline, 400);
        assert_eq!(&asked[..8], &[1, 2, 4, 8, 16, 32, 64, 128]);
        assert!(
            asked
                .windows(2)
                .all(|pair| pair[1] - pair[0] <= MAX_ANSWER_ASK_GAP),
            "and the gap never passes the cap: {asked:?}",
        );
    }

    /// An escrowed record's question is asked no more once its consumer
    /// can commit nothing and no abandonment can land; an owed record's
    /// keeps the capped pace, since no window bounds its answer.
    #[test]
    fn an_escrowed_record_past_its_abandon_window_is_asked_no_more() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000)).at();
        let past = deadline
            .plus(MAX_VALIDITY_RANGE)
            .plus(Duration::from_millis(1));
        let escrowed = Terms::Escrowed {
            credit: producer_record(0),
        };
        assert!(!asked_heights(escrowed, deadline, 4).is_empty());
        assert!(
            asked_heights(escrowed, past, 20).is_empty(),
            "the row stands as a strand, asked about by nobody",
        );
        assert!(!asked_heights(Terms::Owed, past, 4).is_empty());
    }

    /// A pushed answer that lands before the deadline is kept to offer,
    /// including one for a record an entry here owns and the leaf does
    /// not ask about: a question stands whatever the deadline.
    #[test]
    fn an_early_push_is_held() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000));
        let (mut producer, _, anchors, _) = producing(1, deadline);
        let claim = claim_of(0, deadline);
        let (state_root, proof) = state_and_proof(CONSUMER, &[claim], &[claim]);
        let anchor = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(3),
            state_root,
            ts: WeightedTimestamp::from_millis(1_000),
        };
        anchors.record(anchor);
        let pushed = StateClaim::new(
            anchor,
            [(claim, Inclusion::Present(jmt_value_hash(&claim.to_bytes())))],
            proof,
        );
        assert!(producer.offer_pushed(&pushed, &[], WeightedTimestamp::from_millis(2_000)));
        assert_eq!(producer.state_claims().len(), 1, "and offered in a block");
    }

    /// A standing owed record is pushed to its consumer again from its
    /// deadline, at this shard's heights `1, 2, 4, 8, 16, ...`, and no
    /// more once the row goes.
    #[test]
    fn a_standing_owed_record_is_pushed_again_on_the_backoff() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000));
        let (mut producer, trie, _, rows) = producing(1, deadline);
        let record = record_of(0, deadline);
        assert!(
            producer
                .owed_repushes(
                    &trie,
                    deadline.at().minus(Duration::from_millis(1)),
                    BlockHeight::new(1)
                )
                .is_empty(),
            "before the deadline the first push is the only one",
        );
        let pushed: Vec<u64> = (1..=20)
            .filter(|height| {
                let targets =
                    producer.owed_repushes(&trie, deadline.at(), BlockHeight::new(*height));
                if targets.is_empty() {
                    return false;
                }
                assert_eq!(targets, BTreeMap::from([(CONSUMER, vec![record])]));
                true
            })
            .collect();
        assert_eq!(pushed, vec![1, 2, 4, 8, 16]);

        rows.remove(record);
        producer.derive_asks(&trie);
        assert!(
            producer
                .owed_repushes(&trie, deadline.at(), BlockHeight::new(64))
                .is_empty(),
            "a retired record is pushed no more",
        );
    }

    /// A pushed owed record is kept to offer, named for its crossing,
    /// where its consumer's prefix is held and no `Taken` stands; it is
    /// dropped anywhere else, and once the `Taken` is written.
    #[test]
    fn a_pushed_owed_record_is_kept_where_its_consumer_is() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000));
        let record = record_of(0, deadline);
        let id = producer_crossing(0, deadline);
        let value = producer_cell(0, deadline).to_bytes();
        let (state_root, proof) = state_and_proof(PRODUCER, &[record], &[record]);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(3),
            state_root,
            ts: WeightedTimestamp::from_millis(1_000),
        };
        let pushed = StateClaim::new(
            anchor,
            [(
                record,
                Stated::Held(Bytes::new(value).expect("a record fits")),
            )],
            proof,
        );
        let offered = |local: ShardId, rows: Arc<TestRows>| {
            let anchors = Arc::new(ProvenAnchors::default());
            anchors.record(anchor);
            let mut counterparts = Counterparts::new(
                local,
                anchors,
                Arc::new(CounterpartMirror::default()),
                rows,
                ReadFrontier::default(),
            );
            let kept =
                counterparts.offer_pushed(&pushed, &[], WeightedTimestamp::from_millis(2_000));
            (kept, counterparts.state_claims())
        };

        let (kept, claims) = offered(CONSUMER, Arc::new(TestRows::default()));
        assert!(kept, "the consumer's shard keeps it");
        assert_eq!(
            claims
                .iter()
                .flat_map(|claim| claim.crossings.iter().copied())
                .collect::<Vec<_>>(),
            vec![(record, id)],
            "named for its crossing, which is what the fold credits it under",
        );
        assert!(
            !offered(ShardId::leaf(2, 3), Arc::new(TestRows::default())).0,
            "a shard not holding the consumer drops it",
        );
        let answered = Arc::new(TestRows::default());
        answered.put(
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer(producer_cell(0, deadline).tx, Answered::Taken, 0)
                .to_bytes(),
        );
        assert!(
            !offered(CONSUMER, answered).0,
            "and once its Taken stands there is nothing to credit",
        );
    }

    /// A removal pushed below the read frontier's floor is refused on
    /// arrival, and the answer behind it reads the record again at once,
    /// at the newest proven anchor above the floor, well before the
    /// deadline that would otherwise open the question.
    #[test]
    fn a_refused_removal_push_is_reread_at_once() {
        let Answering {
            mut counterparts,
            trie,
            anchors,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let at = |height: u64| Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(height * 1_000),
        };
        let (stale, newest) = (at(3), at(9));
        anchors.record(stale);
        anchors.record(newest);
        counterparts.frontier =
            ReadFrontier::from_entries([(PRODUCER, ReadMark::of(&at(6), windows))]);
        let early = WeightedTimestamp::from_millis(10_000);
        assert!(
            counterparts.probe(&trie, early, &[], windows).is_empty(),
            "before the deadline the push is the only carrier",
        );

        let removal = reading(stale, record, Inclusion::Absent);
        assert!(
            counterparts.refuse_pushed(&removal, windows),
            "every voter refuses a removal below the floor",
        );
        let asked = counterparts.probe(&trie, early, &[], windows);
        assert!(
            matches!(
                asked.as_slice(),
                [Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(keys),
                    shard,
                    ..
                })] if *shard == PRODUCER && keys.as_slice() == [(newest, record)],
            ),
            "so the record is read again at once, at the newest anchor: {asked:?}",
        );
        assert!(
            counterparts.probe(&trie, early, &[], windows).is_empty(),
            "once, and not again before the deadline",
        );
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
        let (mut producer, trie, anchors, rows) = producing(1, deadline);
        let record = record_of(0, deadline);
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

        assert_eq!(
            carried[0].crossing_of(decline),
            Some(producer_crossing(0, deadline)),
            "and the reading names the crossing, which is what a block composes the reclaim from",
        );

        // The reclaim takes the record, and the question goes with its row.
        rows.remove(record);
        producer.derive_asks(&trie);
        anchors.record(Anchor {
            height: BlockHeight::new(8),
            ..anchor
        });
        assert!(
            producer
                .probe(&trie, now, &[], EpochWindows::new(0))
                .is_empty(),
            "a question stands exactly while its row stands",
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
        let (mut producer, trie, anchors, _rows) = producing(2, deadline);
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
    /// on the claim, in the block that carries both, and the reclaim the
    /// decline composes reads the record gone.
    #[test]
    fn a_claim_read_present_answers_over_a_decline_beside_it() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
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
            Budget::empty().take(&mut offered, &mut Vec::new());
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
        Budget::empty().take(&mut wide, &mut Vec::new());
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
        budget.take(&mut offered, &mut Vec::new());
        assert_eq!(offered.len(), MAX_UNSETTLED_PER_BLOCK);
    }

    /// A record's own terms are charged once, with the first name it
    /// takes, so a budget spent across several records still leaves room
    /// for each one's header.
    #[test]
    fn a_records_own_terms_are_charged_with_its_first_name() {
        let mut budget = Budget::empty();
        let mut one = vec![name(0, 2)];
        budget.take(&mut one, &mut Vec::new());
        assert_eq!(
            MAX_PROPOSAL_EVIDENCE_BYTES - budget.bytes,
            ABANDONMENT_RECORD_BYTES + name(0, 2).wire_weight(),
        );
        let mut none: Vec<UnsettledTx> = Vec::new();
        let before = budget.bytes;
        budget.take(&mut none, &mut Vec::new());
        assert_eq!(budget.bytes, before, "an empty take charges nothing");
    }
}
