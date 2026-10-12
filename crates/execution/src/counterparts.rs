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

use hyperscale_core::{Action, FetchIds, FetchRequest};
use hyperscale_engine::tick_select::SeatQuestion;
use hyperscale_metrics::{
    record_crossing_fallback_ask, record_fenced_claim, record_rebuilt_record_entry,
    record_reclaim_probe_answered, record_reclaim_probe_pending,
};
use hyperscale_storage::{committed_tx_cell_key, member_row_leaf};
use hyperscale_types::network::response::ServedValue;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Anchor, Block, BlockHeight, CounterpartMirror,
    Deadline, EpochWindows, ExecutionCertificate, FrontierInputs, Inclusion,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_PROVISION_TARGET_SHARDS, MAX_STATE_CLAIMS_PER_BLOCK,
    MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof, Probed, ProvenAnchors, RETENTION_HORIZON,
    ReadFrontier, ReadMark, SettledTxSet, ShardId, ShardTrie, StateClaim, Stated, SubstateKey,
    TerminalEvidence, TopologySchedule, TxHash, TxOutcome, TxResolution, UNCLAIMED_CROSSING_BYTES,
    UnclaimedCrossing, UnsettledTx, VerdictCells, VerdictQuestion, Verifiable, Verified,
    WeightedTimestamp, said_at, state_claims_admit_block, verdict_leaf,
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

/// The crossing leaves this shard's persisted state holds: what the
/// askers ask about.
///
/// Derived storage, and a pacing input only. It lags the committed
/// chain by what is not yet persisted. Nothing composed from a block
/// reads it: a question it raises is answered by a reading every voter
/// re-proves, and a question it misses or asks late costs latency.
pub trait CrossingIndex: Send + Sync {
    /// The crossing records and answers under `shard`'s prefix, each
    /// with its bytes as the persisted tip holds them, ascending by key.
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)>;

    /// Whether `key` reads present at the persisted tip.
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

/// The claims a validator holds to offer, each with the transactions
/// it speaks for, and where every cell they read was read.
///
/// The second map is the first one turned over: for each shard and
/// cell a held claim reads, the anchor of every claim reading it, once
/// per claim. It is written by every method that adds or removes a
/// claim and by nothing else, so it holds exactly what a walk of the
/// claims would find, and a question asked of every held claim is one
/// lookup.
#[derive(Debug, Default)]
struct HeldClaims {
    claims: BTreeMap<StateClaim, BTreeSet<TxHash>>,
    readings: BTreeMap<(ShardId, SubstateKey), Vec<Anchor>>,
}

impl HeldClaims {
    /// The held claims, in their own order.
    fn claims(&self) -> impl Iterator<Item = &StateClaim> + Clone {
        self.claims.keys()
    }

    /// Each held claim with the transactions it speaks for, which a
    /// caller may add to.
    fn speaking(&mut self) -> impl Iterator<Item = (&StateClaim, &mut BTreeSet<TxHash>)> {
        self.claims.iter_mut()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Whether a held claim reads `key` on `shard`.
    fn reads(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.readings.contains_key(&(shard, key))
    }

    /// The anchors the held claims read `key` on `shard` at.
    fn read_at(&self, shard: ShardId, key: SubstateKey) -> &[Anchor] {
        self.readings.get(&(shard, key)).map_or(&[], Vec::as_slice)
    }

    /// Hold `claim`, where it is not held already, and hand back the
    /// transactions it speaks for.
    fn hold(&mut self, claim: StateClaim) -> &mut BTreeSet<TxHash> {
        if !self.claims.contains_key(&claim) {
            Self::note(&mut self.readings, &claim);
        }
        self.claims.entry(claim).or_default()
    }

    /// Keep the claims `keep` answers for, which may add to the
    /// transactions each speaks for.
    fn retain(&mut self, mut keep: impl FnMut(&StateClaim, &mut BTreeSet<TxHash>) -> bool) {
        let released: Vec<StateClaim> = self
            .claims
            .extract_if(.., |claim, speaks_for| !keep(claim, speaks_for))
            .map(|(claim, _)| claim)
            .collect();
        for claim in &released {
            self.forget(claim);
        }
    }

    /// Cut out of every held claim the cells a block carried at its
    /// anchor: a claim the block carried whole goes, and one it carried
    /// part of stays as the rest.
    fn cut(&mut self, carried: &BTreeMap<Anchor, BTreeSet<SubstateKey>>) {
        self.claims = std::mem::take(&mut self.claims)
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
        self.readings.clear();
        for claim in self.claims.keys() {
            Self::note(&mut self.readings, claim);
        }
    }

    /// Name `claim`'s anchor under every cell it reads.
    fn note(readings: &mut BTreeMap<(ShardId, SubstateKey), Vec<Anchor>>, claim: &StateClaim) {
        for (key, _) in claim.cells.iter() {
            readings
                .entry((claim.anchor.shard, *key))
                .or_default()
                .push(claim.anchor);
        }
    }

    /// Stop naming `claim`'s anchor under the cells it read, once.
    fn forget(&mut self, claim: &StateClaim) {
        for (key, _) in claim.cells.iter() {
            let cell = (claim.anchor.shard, *key);
            let Some(read_at) = self.readings.get_mut(&cell) else {
                continue;
            };
            if let Some(held) = read_at.iter().position(|at| *at == claim.anchor) {
                read_at.swap_remove(held);
            }
            if read_at.is_empty() {
                self.readings.remove(&cell);
            }
        }
    }
}

/// The three cells one crossing derives: its record, and its consumer's
/// `Taken` and `Never`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrossingCells {
    record: SubstateKey,
    taken: SubstateKey,
    never: SubstateKey,
}

impl CrossingCells {
    fn of(id: &CrossingId) -> Self {
        Self {
            record: id.record_key(&ProtocolHasher),
            taken: id.answer_key(&ProtocolHasher, Answered::Taken),
            never: id.answer_key(&ProtocolHasher, Answered::Never),
        }
    }
}

/// The cells `question` reads on its sibling.
fn verdict_cells(question: &VerdictQuestion) -> VerdictCells {
    let VerdictQuestion {
        sibling,
        tx,
        validity_end,
        ..
    } = *question;
    VerdictCells {
        leaf: verdict_leaf(sibling, tx),
        row: member_row_leaf(sibling, tx),
        marker: committed_tx_cell_key(sibling, tx, validity_end),
    }
}

/// How many verdict questions one request puts to a sibling.
///
/// So also how many are out toward one sibling at once. Each is fetched
/// as its three cells, and a request names no more cells than a
/// state-proof request.
pub const MAX_VERDICT_ASKS_PER_SIBLING: usize = 21;

/// One verdict question as this validator holds it: the question as the
/// committed tip last stood it, its cells, derived once when it first
/// stood, and the pacing of its asks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerdictAsk {
    question: VerdictQuestion,
    cells: VerdictCells,
    /// The sibling's newest commit-proven height when the question first
    /// stood: it is first asked at a header past this one, so a push of
    /// the block that wrote the leaf lands before any ask goes out.
    since: Option<BlockHeight>,
    /// The header it was last asked at.
    asked_at: Option<Anchor>,
    /// Whether that ask has come back.
    returned: bool,
    /// How many times it has been asked.
    asked: u32,
}

/// What one pass over the standing questions gathers toward one
/// sibling.
struct Toward {
    /// The sibling's newest commit-proven header standing at the clock.
    newest: Option<Anchor>,
    /// Whether a request to it is still out.
    out: bool,
    /// The questions due, each with the height it was last asked at.
    due: Vec<(Option<BlockHeight>, TxHash)>,
}

/// One claim held for verdict questions.
///
/// It reads whole readings and nothing else: a leaf present as its one
/// cell, a leaf absent with its row and marker, and it names the member
/// of each. No proof joins two claims, so the readings one answer
/// brought stay one claim, cut down as each is let go.
#[derive(Debug)]
struct HeardClaim {
    claim: StateClaim,
    /// The mark of the claim's anchor.
    mark: ReadMark,
    /// Whether a claim held for another question at the anchor reads a
    /// key inside this claim's span, as of the last tip: it then rides
    /// no block until that claim has.
    waits: bool,
}

/// Where a claim held for verdict questions sits among them: by its
/// anchor's clock, its anchor, and the order it was held in.
type HeardAt = (WeightedTimestamp, Anchor, u64);

/// The readings a validator holds to offer for its verdict questions:
/// for each question at most one, the newest it was given.
///
/// Apart from [`HeldClaims`] in every respect, so no crossing, seat or
/// ledger question is answered, stood down, deduplicated or cut by a
/// cell held here, and nothing held here is let go of by a block
/// carrying its cells: a reading goes when its question does, when the
/// question's row has heard it, when a newer one replaces it, or when no
/// block could carry its anchor.
///
/// Every claim names at least one member and `readings` holds one entry
/// per member a claim names, so both maps hold no more entries than
/// there are questions standing.
#[derive(Debug, Default)]
struct HeardClaims {
    claims: BTreeMap<HeardAt, HeardClaim>,
    readings: BTreeMap<(ShardId, TxHash), HeardAt>,
    /// How many claims have been held, ever: the last term of the next
    /// claim's place.
    held: u64,
}

impl HeardClaims {
    /// The claim holding the reading for `question`, if one is held.
    fn reading(&self, question: (ShardId, TxHash)) -> Option<&HeardClaim> {
        self.claims.get(self.readings.get(&question)?)
    }

    /// Hold `claim`, read at `mark`, as the reading of each member it
    /// names, whose cells `cells` lists, in place of whatever was held
    /// for each.
    fn hold(&mut self, claim: StateClaim, mark: ReadMark, cells: &[(TxHash, VerdictCells)]) {
        if claim.verdicts.is_empty() {
            return;
        }
        let sibling = claim.anchor.shard;
        let replaced: Vec<((ShardId, TxHash), VerdictCells)> = cells
            .iter()
            .map(|(tx, cells)| ((sibling, *tx), *cells))
            .collect();
        self.retire(&replaced);
        let at = (claim.anchor.ts, claim.anchor, self.held);
        self.held += 1;
        for tx in claim.verdicts.iter() {
            self.readings.insert((sibling, *tx), at);
        }
        self.claims.insert(
            at,
            HeardClaim {
                claim,
                mark,
                waits: false,
            },
        );
    }

    /// Let go of the reading held for each question of `gone`, listed
    /// with its cells: each is cut from its claim, one cut a claim, and a
    /// claim left reading nothing goes with it. A claim whose proof
    /// cannot be cut goes whole, and its other questions are asked
    /// again.
    fn retire(&mut self, gone: &[((ShardId, TxHash), VerdictCells)]) {
        let mut cut: BTreeMap<HeardAt, BTreeSet<SubstateKey>> = BTreeMap::new();
        for (question, cells) in gone {
            if let Some(at) = self.readings.remove(question) {
                cut.entry(at).or_default().extend(cells.keys());
            }
        }
        for (at, keys) in cut {
            let Some(held) = self.claims.remove(&at) else {
                continue;
            };
            if let Some(rest) = held.claim.restrict(|key| !keys.contains(&key)) {
                self.claims.insert(
                    at,
                    HeardClaim {
                        claim: rest,
                        ..held
                    },
                );
            } else {
                self.forget(&held.claim, at);
            }
        }
    }

    /// Let go of every claim `keep` does not answer for, with the
    /// readings it held.
    fn retain(&mut self, mut keep: impl FnMut(&StateClaim) -> bool) {
        let dropped: Vec<(HeardAt, HeardClaim)> = self
            .claims
            .extract_if(.., |_, held| !keep(&held.claim))
            .collect();
        for (at, held) in dropped {
            self.forget(&held.claim, at);
        }
    }

    /// Stop naming the claim held at `at` as the reading of the members
    /// `claim` names.
    fn forget(&mut self, claim: &StateClaim, at: HeardAt) {
        for tx in claim.verdicts.iter() {
            let question = (claim.anchor.shard, *tx);
            if self.readings.get(&question) == Some(&at) {
                self.readings.remove(&question);
            }
        }
    }

    /// Mark each claim as waiting or not: it waits where `spans`, the
    /// key spans of the other claims held at its anchor, reach into its
    /// own.
    fn wait_behind(&mut self, spans: &BTreeMap<Anchor, Vec<(SubstateKey, SubstateKey)>>) {
        for held in self.claims.values_mut() {
            let own = held
                .claim
                .cells
                .first()
                .zip(held.claim.cells.last())
                .map(|((lo, _), (hi, _))| (*lo, *hi));
            held.waits = own.is_some_and(|(lo, hi)| {
                spans
                    .get(&held.claim.anchor)
                    .is_some_and(|others| others.iter().any(|(from, to)| *from <= hi && lo <= *to))
            });
        }
    }

    /// The anchor of every claim held.
    fn anchors(&self) -> impl Iterator<Item = Anchor> + '_ {
        self.claims.keys().map(|(_, anchor, _)| *anchor)
    }

    /// The claims no other waits behind, oldest anchor first.
    fn riding(&self) -> impl Iterator<Item = &StateClaim> {
        self.claims
            .values()
            .filter(|held| !held.waits)
            .map(|held| &held.claim)
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.readings.is_empty()
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
        present_at: Option<Anchor>,
        /// A pushed absence of the record was refused below the read
        /// frontier's floor, so the record is read again at once,
        /// whatever the deadline.
        reread: bool,
        /// For a decline whose consumer never read the record: the
        /// declining transaction and its validity end, whose member row
        /// and committed marker on the record's shard are read beside
        /// the record, so an absence can carry the proof that the
        /// producer's member exited.
        exit: Option<(TxHash, WeightedTimestamp)>,
    },
    /// A key read beside an unseen decline's record to prove its
    /// producer's member exited: the member row or the committed marker.
    /// Stands exactly while the decline does, which is until the
    /// producer's row is read absent: at its member's finalization, or,
    /// for a leg that never ran, at the fate that ends its row when its
    /// leg entry window closes, its reclaim having deleted nothing.
    Exit,
}

impl Asked {
    /// Whether a reading taken at `anchor` could still move the question.
    fn wants(self, anchor: Anchor) -> bool {
        match self {
            Self::Answer { .. } | Self::Exit => true,
            Self::Record { present_at, .. } => {
                present_at.is_none_or(|present| anchor.height > present.height)
            }
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
/// for which no `Taken` stands at the persisted tip.
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

/// What the read frontier fences of one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fenced {
    /// A record presence.
    Record,
    /// An absence of the record behind an answer this shard holds.
    Removed,
}

impl Fenced {
    /// How the frontier fences the reading of `key`, if it does.
    fn of(asks: &BTreeMap<SubstateKey, Asked>, key: SubstateKey, stated: &Stated) -> Option<Self> {
        stated.held().map_or_else(
            || {
                (stated.inclusion() == Inclusion::Absent
                    && matches!(asks.get(&key), Some(Asked::Record { .. })))
                .then_some(Self::Removed)
            },
            |bytes| {
                matches!(
                    CrossingLeaf::read(&ProtocolHasher, key, bytes),
                    Some(CrossingLeaf::Record { .. })
                )
                .then_some(Self::Record)
            },
        )
    }
}

/// The cells of `claim` the read frontier fences.
fn fenced_cells<'c>(
    asks: &'c BTreeMap<SubstateKey, Asked>,
    claim: &'c StateClaim,
) -> impl Iterator<Item = (SubstateKey, Fenced)> + 'c {
    claim
        .cells
        .iter()
        .filter_map(|(key, stated)| Fenced::of(asks, *key, stated).map(|fenced| (*key, fenced)))
}

/// What a claim reads that the read frontier fences: whether it carries
/// a record presence, and whether it carries an absence of the record
/// behind an answer this shard holds.
fn fenced_readings(asks: &BTreeMap<SubstateKey, Asked>, claim: &StateClaim) -> (bool, bool) {
    let carries = |kind| fenced_cells(asks, claim).any(|(_, fenced)| fenced == kind);
    (carries(Fenced::Record), carries(Fenced::Removed))
}

/// One fetch per anchor, asking every key `wanted` names at it.
fn fetches(wanted: BTreeMap<Anchor, Vec<SubstateKey>>) -> Vec<Action> {
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

/// A seat question this validator put to a counterpart: the header it
/// was asked at, whether every reading it asked for has come back, how
/// many times it has been asked, and the readings come back so far.
///
/// The fetch layer tracks each key on its own, so one question's four
/// keys can return in different answers — split across chunks, or folded
/// into another asker's fetch of the same key. The question closes on
/// the last of them, and the readings are offered only then, and only
/// where together they read the cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeatProbe {
    anchor: Anchor,
    returned: bool,
    asked: u32,
    parts: Vec<StateClaim>,
}

impl SeatProbe {
    /// What the readings come back so far say of `key`.
    fn read(&self, key: SubstateKey) -> Option<Inclusion> {
        self.parts.iter().find_map(|part| part.reading(key))
    }

    /// Whether this probe still waits on a fetch of `key` at `anchor`.
    fn awaits(&self, question: &SeatQuestion, anchor: Anchor, key: SubstateKey) -> bool {
        !self.returned
            && self.anchor == anchor
            && question.keys().contains(&key)
            && self.read(key).is_none()
    }
}

/// What a commit folded, and what it could not answer for.
pub struct CommitFolded {
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
    /// The claims it holds for its rows' verdict questions, no more than
    /// one block could carry, which a block carries only in what the
    /// others and the local crossings leave of its claims section.
    pub verdict_claims: Vec<StateClaim>,
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
    fetched: HeldClaims,

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

    /// The cells of every crossing a row of this shard's names, derived
    /// where its row is first read and carried from one derivation of
    /// the questions to the next for as long as the row stands.
    cells: BTreeMap<CrossingId, CrossingCells>,

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

    /// The seat questions this validator has put, as the committed tip
    /// last stood them, with their pacing. A question lives while the
    /// tip stands it.
    seats: BTreeMap<SeatQuestion, SeatProbe>,

    /// The verdict questions the committed tip's hearing rows put, by
    /// sibling and member, as the tip last stood them, each with its
    /// cells and pacing. Replaced to the standing questions at every
    /// tip, so it holds at most one entry per sibling a hearing row
    /// awaits: no more than the rows the chain may hold unsettled, times
    /// the shards one awaits.
    verdicts: BTreeMap<(ShardId, TxHash), VerdictAsk>,

    /// The question each verdict leaf is read for: one key per entry of
    /// `verdicts`, written and removed with it, so a fetched or pushed
    /// reading finds its question by lookup.
    verdict_leaves: BTreeMap<SubstateKey, (ShardId, TxHash)>,

    /// The height of the last header a request of verdict questions went
    /// to, per sibling a question stands toward: one entry a sibling.
    verdict_asked: BTreeMap<ShardId, BlockHeight>,

    /// The readings held to offer for those questions, apart from every
    /// other held claim: at most one reading per entry of `verdicts`.
    heard: HeardClaims,
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
            fetched: HeldClaims::default(),
            index,
            asks: BTreeMap::new(),
            names: BTreeMap::new(),
            cells: BTreeMap::new(),
            awaited: BTreeSet::new(),
            owed: BTreeMap::new(),
            repushed: BTreeMap::new(),
            frontier,
            wanted: BTreeSet::new(),
            records: RecordReads::new(),
            local_crossings: BTreeSet::new(),
            probes: BTreeMap::new(),
            seats: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            verdict_leaves: BTreeMap::new(),
            verdict_asked: BTreeMap::new(),
            heard: HeardClaims::default(),
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
    ) -> CommitFolded {
        let windows = topology_schedule.windows();
        self.gc_settled_sets(topology_schedule, now);
        self.wanted = wanted.iter().map(|wanted| wanted.key).collect();
        // What the block's claims settle is marked gone on the entry that
        // issued it, as the fold removes it from state: a record removed
        // on its consumer's `Taken` closes its entry's share.
        for key in block.state_claims().iter().flat_map(StateClaim::retires) {
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
        self.cut_carried(block.state_claims());
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
        CommitFolded {
            actions,
            unanswerable,
            settled,
        }
    }

    /// Cut from the held claims the cells `claims`, a committed block's,
    /// carried at each anchor.
    ///
    /// A claim naming members is read by the rows it names and by
    /// nothing else, so its cells are cut from no held claim: a seat or
    /// exit reading over the same row or leaf at that anchor is still
    /// owed to a block whole. What is held for a verdict question goes
    /// by its row's entry alone, where the questions are stood.
    fn cut_carried(&mut self, claims: &[StateClaim]) {
        let mut carried: BTreeMap<Anchor, BTreeSet<SubstateKey>> = BTreeMap::new();
        for claim in claims.iter().filter(|claim| claim.verdicts.is_empty()) {
            carried
                .entry(claim.anchor)
                .or_default()
                .extend(claim.keys());
        }
        if !carried.is_empty() {
            self.fetched.cut(&carried);
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
                let attested_root = anchor.terminal_settled_txs?;
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
            verdict_claims: self.verdict_claims(),
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
        fetches(wanted)
    }

    /// Ask each counterpart a seat question the committed tip stands,
    /// at its newest commit-proven header standing at `now`.
    ///
    /// A question is asked once per header, and again at a newer one
    /// only after the fetch returns without the cycle, backing off as an
    /// answer does: plain contention reads no cycle, and asking it every
    /// block would spend a fetch per contended pair per block. One the
    /// claims this validator holds to offer already prove is not asked
    /// again, and a question the tip no longer stands lets go of the
    /// fetches only it was waiting on.
    pub(crate) fn ask_seats(
        &mut self,
        questions: &[SeatQuestion],
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        let standing: BTreeSet<SeatQuestion> = questions.iter().copied().collect();
        let dropped: Vec<(SeatQuestion, SeatProbe)> = self
            .seats
            .extract_if(.., |question, _| !standing.contains(question))
            .collect();
        let mut released: Vec<(Anchor, SubstateKey)> = dropped
            .iter()
            .flat_map(|(question, probe)| {
                question
                    .keys()
                    .into_iter()
                    .filter(|key| probe.awaits(question, probe.anchor, *key))
                    .map(|key| (probe.anchor, key))
            })
            .collect();
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        for question in standing {
            if question.proven_by(self.fetched.claims()) {
                continue;
            }
            let Some(anchor) = self
                .proven_anchors
                .newest_licensed(question.shard, now, |_| true)
            else {
                continue;
            };
            let prior = self
                .seats
                .get(&question)
                .map(|probe| (probe.anchor, probe.returned, probe.asked));
            if prior.is_some_and(|(asked_at, returned, asked)| {
                !returned || anchor.height.inner() < asked_at.height.inner() + answer_ask_gap(asked)
            }) {
                continue;
            }
            self.seats.insert(
                question,
                SeatProbe {
                    anchor,
                    returned: false,
                    asked: prior.map_or(1, |(_, _, asked)| asked.saturating_add(1)),
                    parts: Vec::new(),
                },
            );
            let asking = wanted.entry(anchor).or_default();
            for key in question.keys() {
                if !asking.contains(&key) {
                    asking.push(key);
                }
            }
        }
        // Judged once this call's own questions are in: a key one of them
        // has just asked for is theirs to wait on, however the fetch layer
        // folds the two asks into one.
        released.retain(|(anchor, key)| !self.fetch_awaited(*anchor, *key));
        let mut actions = fetches(wanted);
        if !released.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::StateProofs(released)));
        }
        actions
    }

    /// Whether a probe of either kind still waits on a fetch of `key` at
    /// `anchor`, so letting it go would strand that probe.
    fn fetch_awaited(&self, anchor: Anchor, key: SubstateKey) -> bool {
        self.probes
            .values()
            .any(|probe| !probe.returned && probe.anchor == anchor && probe.question.key == key)
            || self
                .seats
                .iter()
                .any(|(question, probe)| probe.awaits(question, anchor, key))
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
            if self.fetched.reads(shard, key)
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

    /// The pacing a record's question about its answer carries from the
    /// last derivation, or a fresh one.
    ///
    /// The question stands as long as the record does. An answer is
    /// written only while its record stands and goes only once the
    /// record reads absent, so no window bounds it: a consumer that halts
    /// can write its answer after recovering, and a reclaim a recovery
    /// discards is composed again from the next reading.
    fn answer_pacing(&self, claim: SubstateKey) -> (Option<BlockHeight>, u32) {
        match self.asks.get(&claim) {
            Some(Asked::Answer { asked_at, step, .. }) => (*asked_at, *step),
            _ => (None, 0),
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
        let mut cells = BTreeMap::new();
        let mut awaited = BTreeSet::new();
        let mut owed = BTreeMap::new();
        self.local_crossings.clear();
        for (key, value) in self.index.crossing_rows(local) {
            match CrossingLeaf::read(&ProtocolHasher, key, &value) {
                Some(CrossingLeaf::Record { cell, .. }) => {
                    let id = CrossingId::of_record(key.owner, &cell);
                    let derived = self.cells_of(&id);
                    cells.insert(id, derived);
                    let (claim, decline) = (derived.taken, derived.never);
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
                    let (asked_at, step) = self.answer_pacing(claim);
                    for asked in [claim, decline] {
                        asks.insert(
                            asked,
                            Asked::Answer {
                                id,
                                due_from,
                                asked_at,
                                step,
                            },
                        );
                    }
                }
                Some(CrossingLeaf::Answer { id, answer }) => {
                    let derived = self.cells_of(&id);
                    cells.insert(id, derived);
                    let record = derived.record;
                    names.insert(record, id);
                    if trie.shard_for_prefix(record.owner) == local {
                        if !self.index.present(record) {
                            self.local_crossings.insert(id);
                        }
                        continue;
                    }
                    let (present_at, reread) = match self.asks.get(&record) {
                        Some(Asked::Record {
                            present_at, reread, ..
                        }) => (*present_at, *reread),
                        _ => (None, false),
                    };
                    let validity_end = WeightedTimestamp::from_millis(answer.validity_end_ms);
                    let exit = (answer.answered == Answered::Never && !answer.seen)
                        .then_some((answer.tx, validity_end));
                    if let Some((tx, _)) = exit {
                        let holder = trie.shard_for_prefix(record.owner);
                        asks.insert(member_row_leaf(holder, tx), Asked::Exit);
                        asks.insert(committed_tx_cell_key(holder, tx, validity_end), Asked::Exit);
                    }
                    asks.insert(
                        record,
                        Asked::Record {
                            id,
                            due_from: Deadline::of(validity_end).at(),
                            present_at,
                            reread,
                            exit,
                        },
                    );
                }
                None => {}
            }
        }
        self.asks = asks;
        self.names = names;
        self.cells = cells;
        self.repushed.retain(|record, _| owed.contains_key(record));
        self.owed = owed;
        self.awaited = awaited;
    }

    /// The cells `id` derives, read from the last derivation of the
    /// questions where a row named the crossing then.
    fn cells_of(&self, id: &CrossingId) -> CrossingCells {
        self.cells
            .get(id)
            .copied()
            .unwrap_or_else(|| CrossingCells::of(id))
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
    /// [`MAX_ANSWER_ASK_GAP`] heights, for as long as the record stands.
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
                Asked::Answer { id, .. } => **key == self.cells_of(id).taken,
                Asked::Record { .. } | Asked::Exit => false,
            })
            .map(|(key, asked)| (*key, *asked))
            .collect();
        for (claim, asked) in claims {
            let Asked::Answer {
                id,
                due_from,
                asked_at,
                step,
            } = asked
            else {
                continue;
            };
            if now < due_from {
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
            let decline = self.cells_of(&id).never;
            for key in [claim, decline] {
                self.asks.insert(
                    key,
                    Asked::Answer {
                        id,
                        due_from,
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
            if self.fetched.reads(holder, record.key) {
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
                present_at,
                reread,
                exit,
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
                || self
                    .fetched
                    .read_at(shard, record)
                    .iter()
                    .any(|at| asked.wants(*at))
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
                            present_at,
                            reread: false,
                            exit,
                        },
                    );
                } else {
                    record_crossing_fallback_ask("consumer");
                }
                let asking = wanted.entry(anchor).or_default();
                asking.push(record);
                if let Some((tx, validity_end)) = exit {
                    asking.push(member_row_leaf(shard, tx));
                    asking.push(committed_tx_cell_key(shard, tx, validity_end));
                }
            }
        }
    }

    /// Take a proof fetched at `anchor` for `questions`, each whole, and
    /// hold what is worth a block's bytes.
    ///
    /// Every question asked at the anchor that the proof reads is closed
    /// there. Its reading is the leaf where the leaf reads present, and
    /// the leaf, the row and the marker where it reads absent, and it is
    /// held only where [`VerdictQuestion::offers`] holds and no reading
    /// at this mark or a newer one is held for the question already.
    ///
    /// The readings held from one proof are one claim, cut from the
    /// proof to their cells and naming their members: at most
    /// [`MAX_VERDICT_ASKS_PER_SIBLING`] readings, since that is what one
    /// request asks, so no more than three times that many cells.
    pub(crate) fn on_verdict_proof_fetched(
        &mut self,
        anchor: Anchor,
        questions: &[VerdictCells],
        proof: &MerkleInclusionProof,
        windows: EpochWindows,
    ) {
        let sibling = anchor.shard;
        let keys: Vec<SubstateKey> = questions.iter().flat_map(VerdictCells::keys).collect();
        let Ok(inclusions) = proof.inclusions(anchor.state_root, sibling, &keys) else {
            tracing::warn!(
                shard = ?sibling,
                height = anchor.height.inner(),
                "A fetched verdict proof does not answer for its keys"
            );
            return;
        };
        let read: BTreeMap<SubstateKey, Inclusion> = inclusions.into_iter().collect();
        let mark = ReadMark::of(&anchor, windows);
        let mut cells: Vec<(SubstateKey, Inclusion)> = Vec::new();
        let mut taken: Vec<(TxHash, VerdictCells)> = Vec::new();
        for of in questions {
            let Some(named) = self
                .verdict_leaves
                .get(&of.leaf)
                .copied()
                .filter(|(shard, _)| *shard == sibling)
            else {
                continue;
            };
            let Some(ask) = self.verdicts.get_mut(&named) else {
                continue;
            };
            if ask.returned || ask.asked_at != Some(anchor) || ask.cells != *of {
                continue;
            }
            let (Some(leaf), Some(row), Some(marker)) =
                (read.get(&of.leaf), read.get(&of.row), read.get(&of.marker))
            else {
                continue;
            };
            ask.returned = true;
            let question = ask.question;
            let Some(said) = said_at(
                *leaf,
                Some((*row, *marker)),
                anchor.ts,
                question.validity_end,
                question.yes,
                question.accepted,
            ) else {
                continue;
            };
            if !question.offers(mark, said)
                || self
                    .heard
                    .reading(named)
                    .is_some_and(|held| held.mark >= mark)
            {
                continue;
            }
            taken.push((question.tx, *of));
            cells.push((of.leaf, *leaf));
            if !leaf.is_present() {
                cells.extend([(of.row, *row), (of.marker, *marker)]);
            }
        }
        if taken.is_empty() {
            return;
        }
        let kept: Vec<SubstateKey> = cells.iter().map(|(key, _)| *key).collect();
        let Ok(cut) = proof.restrict(&kept) else {
            tracing::warn!(
                shard = ?sibling,
                height = anchor.height.inner(),
                "A fetched verdict proof cannot be cut to the readings it answers"
            );
            return;
        };
        let claim = StateClaim::new(anchor, cells, cut).hearing(taken.iter().map(|(tx, _)| *tx));
        self.heard.hold(claim, mark, &taken);
    }

    /// Stand the verdict questions the committed tip puts, and ask the
    /// ones due at their sibling's newest commit-proven header standing
    /// at `now`: each as its leaf, row and marker together, through the
    /// fetch verdict questions keep to themselves.
    ///
    /// A question is first asked one sibling header after it first
    /// stood, so the push of the block that wrote the leaf answers it
    /// before any fetch goes out, and again only once its last ask came
    /// back, backing off as an answer does. It is asked whatever the
    /// row has already heard, a yes included: a sibling that says yes
    /// goes on to accept or to leave, and a push of that which did not
    /// land is read by the next ask.
    ///
    /// A question is not asked while a reading held for it could ride a
    /// block: one above the row's entry, at an anchor still proven and
    /// inside the horizon a block admits, in a claim that waits behind
    /// no other. A reading at an anchor no block could carry is let go
    /// and its question asked again; one that waits is kept, and its
    /// question is asked again on its backoff, the newer reading taking
    /// its place.
    ///
    /// Toward one sibling one request is out at a time, of at most
    /// [`MAX_VERDICT_ASKS_PER_SIBLING`] questions, each request at a
    /// newer header than the last. So a sibling that never answers holds
    /// one request's places in the fetch and no more, and two claims
    /// fetched from one sibling never sit at one anchor. Of the
    /// questions due, the ones asked longest ago go first.
    ///
    /// A held reading is let go of here and nowhere else: once the row's
    /// entry has reached the mark it was read at, once its question no
    /// longer stands, or once no block could carry its anchor. A
    /// question no longer standing also lets go of the fetch it was
    /// waiting on.
    ///
    /// One pass over the questions and one lookup each, one walk of the
    /// claims held, one reading of the proven anchors per sibling, and
    /// three key derivations for a question standing for the first time.
    pub(crate) fn ask_verdicts(
        &mut self,
        questions: &[VerdictQuestion],
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        let standing: BTreeSet<(ShardId, TxHash)> = questions
            .iter()
            .map(|question| (question.sibling, question.tx))
            .collect();
        let mut released = self.stand_down_verdicts(&standing);
        self.judge_heard(now);
        let mut toward: BTreeMap<ShardId, Toward> = BTreeMap::new();
        let mut heard: Vec<((ShardId, TxHash), VerdictCells)> = Vec::new();
        for question in questions {
            let sibling = question.sibling;
            let named = (sibling, question.tx);
            let toward = toward.entry(sibling).or_insert_with(|| Toward {
                newest: self.proven_anchors.newest_licensed(sibling, now, |_| true),
                out: false,
                due: Vec::new(),
            });
            let ask = self.verdicts.entry(named).or_insert_with(|| {
                let cells = verdict_cells(question);
                self.verdict_leaves.insert(cells.leaf, named);
                VerdictAsk {
                    question: *question,
                    cells,
                    since: toward.newest.map(|anchor| anchor.height),
                    asked_at: None,
                    returned: false,
                    asked: 0,
                }
            });
            ask.question = *question;
            let held = match self.heard.reading(named) {
                Some(held) if question.entry.is_some_and(|entry| held.mark <= entry.mark) => {
                    heard.push((named, ask.cells));
                    false
                }
                Some(held) => !held.waits,
                None => false,
            };
            // An ask whose header this validator no longer holds proven
            // is one no peer need still serve: it is put again.
            if let Some(at) = ask.asked_at.filter(|_| !ask.returned) {
                if self.proven_anchors.at(at.shard, at.height) == Some(at) {
                    toward.out = true;
                } else {
                    released.push((at, ask.cells));
                    ask.returned = true;
                }
            }
            let Some(anchor) = toward.newest.filter(|_| !held) else {
                continue;
            };
            let due = match ask.asked_at {
                None => ask.since.is_none_or(|since| anchor.height > since),
                Some(at) => {
                    ask.returned
                        && anchor.height.inner() >= at.height.inner() + answer_ask_gap(ask.asked)
                }
            };
            if due {
                toward
                    .due
                    .push((ask.asked_at.map(|at| at.height), question.tx));
            }
        }
        self.heard.retire(&heard);
        self.verdict_asked
            .retain(|sibling, _| toward.contains_key(sibling));
        let mut actions = Vec::new();
        for (sibling, mut toward) in toward {
            let Some(anchor) = toward.newest else {
                continue;
            };
            let asked_here = self
                .verdict_asked
                .get(&sibling)
                .is_some_and(|last| anchor.height <= *last);
            if toward.out || asked_here || toward.due.is_empty() {
                continue;
            }
            toward.due.sort_by_key(|(last, _)| *last);
            toward.due.truncate(MAX_VERDICT_ASKS_PER_SIBLING);
            let mut ids = Vec::with_capacity(toward.due.len());
            for (_, tx) in toward.due {
                let Some(ask) = self.verdicts.get_mut(&(sibling, tx)) else {
                    continue;
                };
                ask.asked_at = Some(anchor);
                ask.returned = false;
                ask.asked = ask.asked.saturating_add(1);
                ids.push((anchor, ask.cells));
            }
            self.verdict_asked.insert(sibling, anchor.height);
            actions.push(Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::VerdictProofs(ids),
                shard: sibling,
                preferred: None,
                class: None,
            }));
        }
        if !released.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::VerdictProofs(released)));
        }
        actions
    }

    /// Let go of every verdict question not among `standing`: its leaf
    /// is no longer looked up, the reading held for it goes, and the
    /// fetch it still waits on is returned to be abandoned.
    fn stand_down_verdicts(
        &mut self,
        standing: &BTreeSet<(ShardId, TxHash)>,
    ) -> Vec<(Anchor, VerdictCells)> {
        let dropped: Vec<((ShardId, TxHash), VerdictAsk)> = self
            .verdicts
            .extract_if(.., |question, _| !standing.contains(question))
            .collect();
        let mut released = Vec::new();
        let mut gone = Vec::with_capacity(dropped.len());
        for (named, ask) in dropped {
            self.verdict_leaves.remove(&ask.cells.leaf);
            gone.push((named, ask.cells));
            if let Some(anchor) = ask.asked_at.filter(|_| !ask.returned) {
                released.push((anchor, ask.cells));
            }
        }
        self.heard.retire(&gone);
        released
    }

    /// Let go of every claim held for a verdict question at an anchor no
    /// block could carry it at, and mark the ones that wait.
    ///
    /// A block admits a claim only at an anchor no recovery fences and
    /// no older than a retention horizon. The proven anchors forget a
    /// fenced or aged header, so a claim stands only at one still held
    /// there and inside the horizon at `now`.
    ///
    /// A claim waits where a claim held for another question at its
    /// anchor reads a key inside its span: a block carries one anchor's
    /// claims as ascending disjoint runs, and the other rides first, as
    /// it is held.
    fn judge_heard(&mut self, now: WeightedTimestamp) {
        let proven = &self.proven_anchors;
        self.heard.retain(|claim| {
            proven.at(claim.anchor.shard, claim.anchor.height) == Some(claim.anchor)
                && now.elapsed_since(claim.anchor.ts) <= RETENTION_HORIZON
        });
        let mut spans: BTreeMap<Anchor, Vec<(SubstateKey, SubstateKey)>> = self
            .heard
            .anchors()
            .map(|anchor| (anchor, Vec::new()))
            .collect();
        if spans.is_empty() {
            return;
        }
        for claim in self.fetched.claims() {
            if let (Some(at), Some((lo, _)), Some((hi, _))) = (
                spans.get_mut(&claim.anchor),
                claim.cells.first(),
                claim.cells.last(),
            ) {
                at.push((*lo, *hi));
            }
        }
        self.heard.wait_behind(&spans);
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
        for (reading, victim) in self.answer_seats(anchor, keys, proof, &inclusions) {
            self.hold_seat_reading(&reading, victim);
        }
        if answering.is_empty() {
            return;
        }
        // A cell a held claim at this anchor already reads is not held
        // twice; the transactions this proof spoke for lean on that
        // claim instead.
        let mut fresh = answering.clone();
        for (held, held_for) in self.fetched.speaking() {
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
            .hold(StateClaim::new(anchor, cells, proof).naming(named))
            .extend(speaks_for);
    }

    /// Take a fetched proof at `anchor` into the seat questions it speaks
    /// to, and return the readings to hold to offer, each with the victim
    /// it speaks for.
    ///
    /// Each question keeps the part of the proof that reads its own keys,
    /// and closes once every one of them has come back. Its readings are
    /// held only where together they read the cycle: anything else is
    /// plain contention, and the question is put again at a newer header.
    fn answer_seats(
        &mut self,
        anchor: Anchor,
        keys: &[SubstateKey],
        proof: &MerkleInclusionProof,
        inclusions: &[(SubstateKey, Inclusion)],
    ) -> Vec<(StateClaim, TxHash)> {
        let mut held = Vec::new();
        for (question, probe) in &mut self.seats {
            let arrived: Vec<SubstateKey> = question
                .keys()
                .into_iter()
                .filter(|key| keys.contains(key) && probe.awaits(question, anchor, *key))
                .collect();
            if arrived.is_empty() {
                continue;
            }
            let Ok(cut) = proof.restrict(&arrived) else {
                continue;
            };
            let cells = inclusions
                .iter()
                .filter(|(key, _)| arrived.contains(key))
                .map(|&(key, inclusion)| (key, Stated::Inclusion(inclusion)));
            probe.parts.push(StateClaim::new(anchor, cells, cut));
            if question.keys().iter().any(|key| probe.read(*key).is_none()) {
                continue;
            }
            probe.returned = true;
            let parts = std::mem::take(&mut probe.parts);
            if question.proven_by(&parts) {
                held.extend(parts.into_iter().map(|part| (part, question.waiting)));
            }
        }
        held
    }

    /// Hold a seat reading to offer, speaking for `victim`: the cells a
    /// held claim at its anchor already reads lean on that claim instead,
    /// so the claims at one anchor stay disjoint.
    fn hold_seat_reading(&mut self, reading: &StateClaim, victim: TxHash) {
        let mut fresh: BTreeSet<SubstateKey> = reading.keys().into_iter().collect();
        for (held, held_for) in self.fetched.speaking() {
            if held.anchor != reading.anchor {
                continue;
            }
            let covered: Vec<SubstateKey> = held
                .keys()
                .into_iter()
                .filter(|key| fresh.contains(key))
                .collect();
            if !covered.is_empty() {
                held_for.insert(victim);
                for key in covered {
                    fresh.remove(&key);
                }
            }
        }
        if let Some(rest) = reading.restrict(|key| fresh.contains(&key)) {
            self.fetched.hold(rest).insert(victim);
        }
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
            self.fold_present(claim);
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

    /// Cut from every held claim the fenced readings below the floor the
    /// frontier now sets for its producer, whether a fetch or a push
    /// brought them, and keep the claim's other cells for the
    /// transactions it speaks for. A reading the frontier does not fence
    /// is left to the age bound and the ledger: below the floor it is
    /// admissible.
    fn drop_below_floor(&mut self, windows: EpochWindows) {
        let below: Vec<StateClaim> = self
            .fetched
            .claims()
            .filter(|claim| {
                self.frontier
                    .refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows))
                    && fenced_cells(&self.asks, claim).next().is_some()
            })
            .cloned()
            .collect();
        if below.is_empty() {
            return;
        }
        let mut cut: BTreeMap<Anchor, BTreeSet<SubstateKey>> = BTreeMap::new();
        for claim in &below {
            cut.entry(claim.anchor)
                .or_default()
                .extend(fenced_cells(&self.asks, claim).map(|(key, _)| key));
            self.refuse_fenced(claim);
        }
        self.fetched.cut(&cut);
    }

    /// What of a pushed claim is worth holding: all of it at or above
    /// the read frontier's floor for its producer, and below the floor
    /// the cells the frontier does not fence, which every voter still
    /// admits. `None` where nothing is left. A fenced reading cut here
    /// starts its key's read over, as a held one the floor rises past
    /// does.
    pub(crate) fn cut_pushed(
        &mut self,
        claim: StateClaim,
        windows: EpochWindows,
    ) -> Option<StateClaim> {
        if !self
            .frontier
            .refuses(claim.anchor.shard, ReadMark::of(&claim.anchor, windows))
        {
            return Some(claim);
        }
        let fenced: BTreeSet<SubstateKey> = fenced_cells(&self.asks, &claim)
            .map(|(key, _)| key)
            .collect();
        if fenced.is_empty() {
            return Some(claim);
        }
        self.refuse_fenced(&claim);
        claim.restrict(|key| !fenced.contains(&key))
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
    fn fold_present(&mut self, stated: &StateClaim) {
        let shard = stated.anchor.shard;
        for (key, asked) in &mut self.asks {
            let Asked::Record { present_at, .. } = asked else {
                continue;
            };
            if !ShardTrie::shard_owns_prefix(shard, key.owner) {
                continue;
            }
            if matches!(stated.reading(*key), Some(Inclusion::Present(_)))
                && present_at.is_none_or(|present| stated.anchor.height > present.height)
            {
                *present_at = Some(stated.anchor);
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

    /// The claims this validator holds that no block has carried yet,
    /// one producer's together in anchor order and the producers by
    /// their oldest anchor: the section's budget is spent in this order
    /// and cuts what does not fit, so no claim of a producer rides while
    /// an older one of it is held back, and the producer closest to
    /// aging out goes first rather than a busy one starving another.
    /// A claim naming a crossing or holding a value raises its
    /// producer's frontier entry, so a younger one carried ahead of an
    /// older record presence or deleting absence would have the older
    /// refused at its next block.
    fn state_claims(&self) -> Vec<StateClaim> {
        let mut oldest: BTreeMap<ShardId, WeightedTimestamp> = BTreeMap::new();
        for claim in self.fetched.claims() {
            oldest
                .entry(claim.anchor.shard)
                .and_modify(|ts| *ts = (*ts).min(claim.anchor.ts))
                .or_insert(claim.anchor.ts);
        }
        let mut claims: Vec<StateClaim> = self.fetched.claims().cloned().collect();
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

    /// The claims this validator holds for its rows' verdict questions,
    /// oldest anchor first, as far as one block's count and bytes of
    /// claims reach: each as it is held, with no proof cut here, and
    /// none that waits behind another claim at its anchor.
    ///
    /// A claim held for a verdict question names no crossing and holds
    /// no value, so it raises no frontier and may ride after a younger
    /// claim of its producer.
    fn verdict_claims(&self) -> Vec<StateClaim> {
        let mut weight = 0usize;
        self.heard
            .riding()
            .take(MAX_STATE_CLAIMS_PER_BLOCK)
            .take_while(|claim| {
                weight = weight.saturating_add(claim.wire_weight());
                state_claims_admit_block(weight)
            })
            .cloned()
            .collect()
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
        for held in self.fetched.claims() {
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
        let _ = self.fetched.hold(kept);
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
        released.retain(|(anchor, key)| !self.fetch_awaited(*anchor, *key));
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

    /// Note a verified certificate before it is routed: one from a
    /// record's holder naming the transaction arms the consumer's read
    /// of the record.
    ///
    /// Nothing it says reaches the mempool. A leg's terminal is what its
    /// own chain closes it on, which every replica of the shard reads
    /// alike: a certificate one replica heard and another missed would
    /// make two answers of one transaction.
    pub(crate) fn on_certificate(
        &mut self,
        ec: &Arc<Verified<ExecutionCertificate>>,
        now: WeightedTimestamp,
    ) {
        self.records.certified(
            ec.shard_id(),
            ec.tx_outcomes().iter().map(TxOutcome::tx_hash),
            now,
        );
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
    use hyperscale_types::test_utils::{proven_claim, state_and_proof};
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, BlockHeight, CommittedAt, Deadline, Hash, Heard,
        LocalKey, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE, ResourceAddr, RoutePrefix, Said,
        StateRoot, evidence_admits_block,
    };
    use hyperscale_vm_effects::{
        Answered, CrossingAnswer, CrossingCell, Hash32, IntentHash, Terms,
    };

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
        answering_with(|id, cell| id.answer(cell.tx, Answered::Taken, cell.validity_end_ms))
    }

    /// [`answering`] with the consumer standing `answer_of` the record.
    fn answering_with(
        answer_of: impl Fn(&CrossingId, &CrossingCell) -> CrossingAnswer,
    ) -> Answering {
        let anchors = Arc::new(ProvenAnchors::default());
        let rows = Arc::new(TestRows::default());
        // A deadline at the clock the tests ask at: nothing is asked
        // before it.
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let id = CrossingId::of_record(producer_record(0x42).owner, &cell);
        let standing = answer_of(&id, &cell);
        let answer = id.answer_key(&ProtocolHasher, standing.answered);
        rows.put(answer, standing.to_bytes());
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
            verdicts: Capped::empty(),
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
                .claims()
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
            .claims()
            .find(|claim| claim.reading(record).is_some())
            .cloned()
            .expect("the proof landed as a reading");
        assert!(
            matches!(landed.reading(record), Some(Inclusion::Present(_))),
            "the fixture's proof says the record stands",
        );
        counterparts.fold_present(&landed);
        counterparts.release_answered_fetches(&trie);
        assert!(
            !counterparts
                .fetched
                .claims()
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

        counterparts.fold_present(&reading(at(1_000), record, Inclusion::Present([7; 32])));
        assert!(
            !asked(&counterparts).wants(at(1_000)),
            "not asked again at the header it was already read at",
        );
        assert!(
            asked(&counterparts).wants(at(1_001)),
            "but at the next one it is"
        );

        counterparts.fold_present(&reading(at(1_001), record, Inclusion::Absent));
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
                .claims()
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

    /// A decline an abandonment wrote asks, beside its record and at the
    /// same anchor, the two keys that prove its producer's member exited:
    /// the member row and the committed marker on the record's shard.
    /// A seen answer asks its record alone
    /// ([`a_consumer_asks_its_producer_about_the_record_its_answer_names`]).
    #[test]
    fn an_unseen_never_asks_its_exit_keys_at_one_anchor() {
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let Answering {
            mut counterparts,
            trie,
            anchors,
            record,
            ..
        } = answering_with(|id, cell| id.unseen_never(cell.tx, cell.validity_end_ms));
        let now = WeightedTimestamp::from_millis(60_000);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: now,
        };
        anchors.record(anchor);
        let asked = counterparts.probe(&trie, now, &[], EpochWindows::new(0));
        let validity_end = WeightedTimestamp::from_millis(cell.validity_end_ms);
        let mut expected = vec![
            (anchor, record),
            (anchor, member_row_leaf(PRODUCER, cell.tx)),
            (
                anchor,
                committed_tx_cell_key(PRODUCER, cell.tx, validity_end),
            ),
        ];
        expected.sort_unstable();
        let [
            Action::Fetch(FetchRequest::Ask {
                ids: FetchIds::StateProofs(keys),
                shard,
                ..
            }),
        ] = asked.as_slice()
        else {
            panic!("one ask for the record and its exit keys: {asked:?}");
        };
        let mut keys = keys.clone();
        keys.sort_unstable();
        assert_eq!(*shard, PRODUCER);
        assert_eq!(keys, expected, "all three at the one anchor");
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
            Asked::Record { present_at, .. } => present_at,
            Asked::Answer { .. } | Asked::Exit => panic!("an answer asks about its record"),
        };
        counterparts.fold_present(&present_at(CONSUMER));
        assert_eq!(
            seen(&counterparts),
            None,
            "the consumer's own anchor does not own the producer's prefix",
        );
        let owner = present_at(PRODUCER);
        counterparts.fold_present(&owner);
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
            verdicts: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        };
        for held in [claim(PRODUCER, 30), claim(other, 20), claim(PRODUCER, 10)] {
            let _ = counterparts.fetched.hold(held);
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
                .claims()
                .any(|claim| claim.reading(record).is_some()),
            "before it is folded the reading is still what the question wants",
        );

        // Folded as a **presence**, which is the reading that still has
        // a successor: the record stands, so the question is put again
        // at the producer's next header. An absence has no successor —
        // it is the licence itself — so it could not tell a spent
        // reading from a held-down one.
        counterparts.fold_present(&reading(anchor, record, Inclusion::Present([9; 32])));
        counterparts.release_answered_fetches(&trie);
        assert!(
            !counterparts
                .fetched
                .claims()
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
        producer.fold_present(&read);
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
        assert_eq!(seated.cells, through.cells);
    }

    /// The cells kept for a crossing are the ones its identity derives,
    /// kept for exactly the crossings a row names: a derivation after a
    /// row has gone keeps nothing of it.
    #[test]
    fn the_cells_kept_for_a_crossing_are_its_own_while_its_row_stands() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, _, rows) = producing(3, deadline);
        let derived = |producer: &Counterparts| {
            producer
                .cells
                .iter()
                .map(|(id, cells)| (*id, *cells))
                .collect::<Vec<_>>()
        };
        let by_identity = |seeds: &[u8]| {
            let mut cells: Vec<(CrossingId, CrossingCells)> = seeds
                .iter()
                .map(|seed| producer_crossing(*seed, deadline))
                .map(|id| (id, CrossingCells::of(&id)))
                .collect();
            cells.sort_unstable_by_key(|(id, _)| *id);
            cells
        };
        assert_eq!(derived(&producer), by_identity(&[0, 1, 2]));
        producer.derive_asks(&trie);
        assert_eq!(derived(&producer), by_identity(&[0, 1, 2]));

        rows.remove(record_of(1, deadline));
        producer.derive_asks(&trie);
        assert_eq!(derived(&producer), by_identity(&[0, 2]));
        assert_eq!(
            producer.cells_of(&producer_crossing(1, deadline)),
            CrossingCells::of(&producer_crossing(1, deadline)),
            "a crossing no row names is derived where it is asked about"
        );
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

    /// A record's question stands as long as the record, escrowed or
    /// owed: past every window it is still asked at the capped pace, so
    /// an answer a consumer writes late, or one whose push was lost, is
    /// read however long after.
    #[test]
    fn a_record_past_its_window_is_still_asked() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(36_000)).at();
        let past = deadline
            .plus(MAX_VALIDITY_RANGE)
            .plus(Duration::from_secs(3_600));
        let escrowed = Terms::Escrowed {
            credit: producer_record(0),
        };
        for terms in [escrowed, Terms::Owed] {
            let asked = asked_heights(terms, past, 400);
            assert_eq!(&asked[..8], &[1, 2, 4, 8, 16, 32, 64, 128], "{terms:?}");
        }
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
        assert_eq!(
            counterparts.cut_pushed(removal, windows),
            None,
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

    /// The floor the frontier sets rising past a held claim cuts the
    /// reading it fences, here the absence of the record behind an
    /// answer this shard holds, and keeps the claim's other cell under
    /// the proof cut to it, for the transactions the claim spoke for. A
    /// claim left with no cell goes whole.
    #[test]
    fn a_fenced_cell_below_the_floor_is_cut_from_its_claim() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let beside = producer_record(0x77);
        let held = proven_claim(PRODUCER, 3, &[beside], &[record, beside]);
        let alone = proven_claim(PRODUCER, 4, &[], &[record]);
        let speaks_for = TxHash::from(Hash::from_bytes(b"beside"));
        counterparts.fetched.hold(held.clone()).insert(speaks_for);
        let _ = counterparts.fetched.hold(alone.clone());

        counterparts.drop_below_floor(windows);
        assert_eq!(
            counterparts.fetched.claims().cloned().collect::<Vec<_>>(),
            vec![held.clone(), alone],
            "with no floor nothing is cut",
        );

        let floor = Anchor {
            height: BlockHeight::new(6),
            ..held.anchor
        };
        counterparts.frontier =
            ReadFrontier::from_entries([(PRODUCER, ReadMark::of(&floor, windows))]);
        counterparts.drop_below_floor(windows);
        let kept: Vec<StateClaim> = counterparts.fetched.claims().cloned().collect();
        assert_eq!(kept.len(), 1, "the claim reading the record alone goes");
        assert_eq!(kept[0].anchor, held.anchor);
        assert_eq!(kept[0].keys(), vec![beside], "the fenced cell is cut");
        assert_eq!(kept[0].verify(), Ok(()), "under the proof cut to the rest");
        assert_eq!(
            counterparts.fetched.claims[&kept[0]],
            BTreeSet::from([speaks_for]),
        );
        assert!(!counterparts.fetched.reads(PRODUCER, record));
        assert!(counterparts.fetched.reads(PRODUCER, beside));
        assert_eq!(
            readings_kept(&counterparts.fetched),
            readings_by_walk(&counterparts.fetched),
        );
    }

    /// The floor passing a fenced record absence cuts that absence and no
    /// other cell read at its anchor. The member row of the transaction
    /// whose exit the absence waits on is also a cell of a seat question
    /// naming that transaction as its holder, where it must read present,
    /// and a seat reading is admissible below the floor: it stays whole
    /// and still proves its cycle.
    #[test]
    fn a_seat_reading_beside_a_fenced_absence_outlives_the_cut() {
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering_with(|id, cell| id.unseen_never(cell.tx, cell.validity_end_ms));
        assert!(matches!(
            counterparts.asks.get(&record),
            Some(Asked::Record {
                exit: Some((tx, _)),
                ..
            }) if *tx == cell.tx
        ));
        let windows = EpochWindows::new(0);
        let question = SeatQuestion {
            shard: PRODUCER,
            waiting: TxHash::from(Hash::from_bytes(&[2; 32])),
            holder: cell.tx,
        };
        let keys = question.keys();
        let [seat, row, ..] = keys;
        assert_eq!(row, member_row_leaf(PRODUCER, cell.tx));
        let asked: Vec<SubstateKey> = keys.into_iter().chain([record]).collect();
        let whole = proven_claim(PRODUCER, 3, &[seat, row], &asked);
        let absence = whole.restrict(|key| key == record).expect("one cell");
        let reading = whole.restrict(|key| key != record).expect("four cells");
        let _ = counterparts.fetched.hold(absence);
        let _ = counterparts.fetched.hold(reading.clone());
        assert!(question.proven_by(counterparts.fetched.claims()));

        let floor = Anchor {
            height: BlockHeight::new(6),
            ..whole.anchor
        };
        counterparts.frontier =
            ReadFrontier::from_entries([(PRODUCER, ReadMark::of(&floor, windows))]);
        counterparts.drop_below_floor(windows);
        assert!(
            !counterparts.fetched.reads(PRODUCER, record),
            "the fenced absence is cut",
        );
        assert_eq!(
            counterparts.fetched.claims().cloned().collect::<Vec<_>>(),
            vec![reading],
            "and the seat reading at its anchor is left as it was",
        );
        assert!(
            question.proven_by(counterparts.fetched.claims()),
            "so it still proves the cycle",
        );
    }

    /// A pushed claim below the floor is refused only for the readings
    /// the frontier fences: one carrying none is kept whole, one carrying
    /// a fenced reading beside another cell is kept as the other cell,
    /// and at or above the floor nothing is cut.
    #[test]
    fn a_pushed_bare_claim_below_the_floor_is_kept() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let beside = producer_record(0x77);
        let bare = proven_claim(PRODUCER, 3, &[beside], &[beside]);
        let mixed = proven_claim(PRODUCER, 3, &[beside], &[record, beside]);
        let above = proven_claim(PRODUCER, 6, &[beside], &[record, beside]);
        let floor = Anchor {
            height: BlockHeight::new(6),
            ..bare.anchor
        };
        counterparts.frontier =
            ReadFrontier::from_entries([(PRODUCER, ReadMark::of(&floor, windows))]);

        assert_eq!(
            counterparts.cut_pushed(bare.clone(), windows),
            Some(bare),
            "a claim the fence judges nothing of is admissible below the floor",
        );
        let kept = counterparts
            .cut_pushed(mixed, windows)
            .expect("the cell beside the removal is kept");
        assert_eq!(kept.keys(), vec![beside]);
        assert_eq!(kept.verify(), Ok(()));
        assert_eq!(
            counterparts.cut_pushed(above.clone(), windows),
            Some(above),
            "at the floor the removal is the licence",
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

        assert_eq!(
            producer.fetched.readings,
            readings_by_walk(&producer.fetched)
        );
    }

    /// Where each cell the held claims read was read, by a walk of
    /// every claim, each cell's anchors in order.
    fn readings_by_walk(held: &HeldClaims) -> BTreeMap<(ShardId, SubstateKey), Vec<Anchor>> {
        let mut readings: BTreeMap<(ShardId, SubstateKey), Vec<Anchor>> = BTreeMap::new();
        for claim in held.claims.keys() {
            for key in claim.keys() {
                readings
                    .entry((claim.anchor.shard, key))
                    .or_default()
                    .push(claim.anchor);
            }
        }
        for read_at in readings.values_mut() {
            read_at.sort_unstable();
        }
        readings
    }

    /// The held claims' readings as kept, each cell's anchors in order.
    fn readings_kept(held: &HeldClaims) -> BTreeMap<(ShardId, SubstateKey), Vec<Anchor>> {
        let mut readings = held.readings.clone();
        for read_at in readings.values_mut() {
            read_at.sort_unstable();
        }
        readings
    }

    /// The readings kept beside the held claims are what a walk of the
    /// claims finds, through every way a claim is held, cut and let go
    /// of, and what is asked of them is what the walk answers.
    #[test]
    fn the_readings_kept_are_what_a_walk_of_the_held_claims_finds() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let keys = [
            claim_of(0, deadline),
            consumer_decline(0, deadline),
            claim_of(1, deadline),
            consumer_decline(1, deadline),
        ];
        let at = |height: u64, asked: &[SubstateKey]| {
            let (state_root, proof) = state_and_proof(CONSUMER, &[keys[1]], asked);
            let anchor = Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(height),
                state_root,
                ts: deadline.at(),
            };
            let inclusions = proof
                .inclusions(state_root, CONSUMER, asked)
                .expect("the fixture proof answers for its keys");
            let cells = inclusions
                .into_iter()
                .map(|(key, inclusion)| (key, Stated::Inclusion(inclusion)));
            StateClaim::new(anchor, cells, proof)
        };
        let agrees = |held: &HeldClaims| {
            assert_eq!(readings_kept(held), readings_by_walk(held));
            for key in keys {
                for shard in [CONSUMER, PRODUCER] {
                    let walked: Vec<Anchor> = held
                        .claims
                        .keys()
                        .filter(|claim| claim.anchor.shard == shard && claim.reading(key).is_some())
                        .map(|claim| claim.anchor)
                        .collect();
                    assert_eq!(held.reads(shard, key), !walked.is_empty());
                    let mut read_at = held.read_at(shard, key).to_vec();
                    read_at.sort_unstable();
                    assert_eq!(read_at, walked);
                }
            }
        };

        let mut held = HeldClaims::default();
        agrees(&held);
        let whole = at(7, &keys);
        let pair = at(8, &keys[..2]);
        let other = at(9, &keys[1..]);
        for claim in [&whole, &pair, &other, &pair] {
            let _ = held.hold(claim.clone());
            agrees(&held);
        }
        assert_eq!(held.claims.len(), 3, "a claim held twice is held once");

        // A block carrying part of one claim leaves the rest of it, and
        // one carrying all of another leaves nothing.
        let carried = BTreeMap::from([
            (whole.anchor, BTreeSet::from([keys[0], keys[3]])),
            (pair.anchor, BTreeSet::from([keys[0], keys[1]])),
        ]);
        held.cut(&carried);
        agrees(&held);
        assert_eq!(held.claims.len(), 2);
        assert!(!held.reads(CONSUMER, keys[0]));

        held.retain(|claim, _| claim.anchor != other.anchor);
        agrees(&held);
        assert_eq!(held.claims.len(), 1);

        held.retain(|claim, _| claim.anchor == other.anchor);
        agrees(&held);
        assert!(held.is_empty() && held.readings.is_empty());
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
            both.retires(),
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

    /// A seat question whose keys come back in separate answers closes on
    /// the last of them, and its readings are held to offer only where
    /// together they read the cycle; a question the tip no longer stands
    /// lets go of the fetch it was waiting on.
    #[test]
    fn a_seat_question_closes_on_its_last_reading_however_they_arrive() {
        let anchors = Arc::new(ProvenAnchors::default());
        let mut counterparts = Counterparts::new(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::new(TestRows::default()) as _,
            ReadFrontier::default(),
        );
        let tx = |seed: u8| TxHash::from(Hash::from_bytes(&[seed; 32]));
        let question = SeatQuestion {
            shard: PRODUCER,
            waiting: tx(2),
            holder: tx(1),
        };
        let [seat, row, none, unsaid] = question.keys();
        let (state_root, _) = state_and_proof(PRODUCER, &[seat, row], &[seat, row, none, unsaid]);
        let now = WeightedTimestamp::from_millis(10_000);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);

        let asked = counterparts.ask_seats(&[question], now);
        assert!(
            matches!(
                asked.as_slice(),
                [Action::Fetch(FetchRequest::Ask { ids: FetchIds::StateProofs(ids), .. })]
                    if ids.len() == 4
            ),
            "the four cells are asked at the newest anchor: {asked:?}",
        );

        let (_, first) = state_and_proof(PRODUCER, &[seat, row], &[seat]);
        counterparts.on_proof_fetched(anchor, &[seat], &first, &[]);
        assert!(
            counterparts.fetched.is_empty(),
            "one reading of four is held back"
        );
        let (_, more) = state_and_proof(PRODUCER, &[seat, row], &[row, none]);
        counterparts.on_proof_fetched(anchor, &[row, none], &more, &[]);
        assert!(
            counterparts.fetched.is_empty(),
            "three readings of four are held back: the holder's verdict leaf is unread",
        );
        let (_, rest) = state_and_proof(PRODUCER, &[seat, row], &[unsaid]);
        counterparts.on_proof_fetched(anchor, &[unsaid], &rest, &[]);
        assert!(
            question.proven_by(counterparts.fetched.claims()),
            "the last reading closes the question, and the cycle is held to offer",
        );
        assert!(
            counterparts.ask_seats(&[question], now).is_empty(),
            "a question the held claims prove is not asked again",
        );

        // A question still out when the tip stops standing it lets go of
        // its fetch.
        let other = SeatQuestion {
            shard: PRODUCER,
            waiting: tx(4),
            holder: tx(3),
        };
        assert_eq!(counterparts.ask_seats(&[question, other], now).len(), 1);
        let released = counterparts.ask_seats(&[question], now);
        assert!(
            matches!(
                released.as_slice(),
                [Action::AbandonFetch(FetchIds::StateProofs(ids))] if ids.len() == 4
            ),
            "the dropped question releases its four cells: {released:?}",
        );

        // One that drops as another asks the same holder's cells at the
        // same anchor releases only the cell no question is left waiting on.
        let first = SeatQuestion {
            shard: PRODUCER,
            waiting: tx(6),
            holder: tx(5),
        };
        let next = SeatQuestion {
            waiting: tx(7),
            ..first
        };
        assert_eq!(counterparts.ask_seats(&[question, first], now).len(), 1);
        let handed_on = counterparts.ask_seats(&[question, next], now);
        let abandoned: Vec<&(Anchor, SubstateKey)> = handed_on
            .iter()
            .filter_map(|action| match action {
                Action::AbandonFetch(FetchIds::StateProofs(ids)) => Some(ids),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            abandoned,
            vec![&(anchor, first.keys()[0])],
            "the holder's cells stay asked for the question taking them over",
        );
    }

    /// A seat question answered with the holder's verdict leaf standing
    /// closes with nothing held to offer: a holder whose verdict leaf
    /// stands proves no cycle, and the question is put again only at a
    /// newer header.
    #[test]
    fn a_seat_reading_beside_the_holders_verdict_leaf_is_not_offered() {
        let anchors = Arc::new(ProvenAnchors::default());
        let mut counterparts = Counterparts::new(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::new(TestRows::default()) as _,
            ReadFrontier::default(),
        );
        let tx = |seed: u8| TxHash::from(Hash::from_bytes(&[seed; 32]));
        let question = SeatQuestion {
            shard: PRODUCER,
            waiting: tx(2),
            holder: tx(1),
        };
        let keys = question.keys();
        let [seat, row, _, said] = keys;
        let (state_root, proof) = state_and_proof(PRODUCER, &[seat, row, said], &keys);
        let now = WeightedTimestamp::from_millis(10_000);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);

        assert_eq!(counterparts.ask_seats(&[question], now).len(), 1);
        counterparts.on_proof_fetched(anchor, &keys, &proof, &[]);
        assert!(
            counterparts.fetched.is_empty(),
            "a holder whose verdict leaf stands reads no cycle",
        );
        assert!(
            counterparts.seats[&question].returned,
            "and the question is closed at this header",
        );
        assert!(
            counterparts.ask_seats(&[question], now).is_empty(),
            "so it is not asked there again",
        );
    }

    /// A grid of ten-second epochs, on which the anchors below are
    /// marked: ten heights to an epoch.
    const GRID: EpochWindows = EpochWindows::new(10_000);

    /// A second sibling of the consumer's rows.
    const OTHER: ShardId = ShardId::leaf(2, 3);

    /// A consumer with no rows of its own, and the anchors it holds
    /// proven.
    fn hearing() -> (Counterparts, Arc<ProvenAnchors>) {
        let anchors = Arc::new(ProvenAnchors::default());
        let counterparts = Counterparts::new(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::new(TestRows::default()) as _,
            ReadFrontier::default(),
        );
        (counterparts, anchors)
    }

    /// The question a stated row here puts to `sibling` about the member
    /// seeded `seed`, with nothing heard yet. The yes it reads for is
    /// the value a fixture tree holds at the verdict leaf.
    fn question_toward(sibling: ShardId, seed: u16) -> VerdictQuestion {
        let tx = TxHash::from(Hash::from_bytes(&seed.to_be_bytes()));
        let leaf = verdict_leaf(sibling, tx);
        VerdictQuestion {
            sibling,
            tx,
            validity_end: WeightedTimestamp::from_millis(50_000),
            yes: Hash::from_hash_bytes(&jmt_value_hash(&leaf.to_bytes())),
            accepted: Hash::from_bytes(b"accepted"),
            entry: None,
            counted: true,
        }
    }

    fn verdict_question(seed: u16) -> VerdictQuestion {
        question_toward(PRODUCER, seed)
    }

    fn having_heard(
        question: VerdictQuestion,
        mark: ReadMark,
        said: Option<Said>,
    ) -> VerdictQuestion {
        VerdictQuestion {
            entry: Some(Heard {
                shard: question.sibling,
                mark,
                said,
            }),
            ..question
        }
    }

    /// `shard`'s header at `height`, one second a height, over a tree
    /// holding `present`.
    fn header_at(shard: ShardId, height: u64, present: &[SubstateKey]) -> Anchor {
        let (state_root, _) = state_and_proof(shard, present, &[]);
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root,
            ts: WeightedTimestamp::from_millis(height * 1_000),
        }
    }

    fn producer_at(height: u64, present: &[SubstateKey]) -> Anchor {
        header_at(PRODUCER, height, present)
    }

    /// Answer a fetch of `questions` at `anchor`, over a tree holding
    /// `present`.
    fn answer(
        counterparts: &mut Counterparts,
        anchor: Anchor,
        present: &[SubstateKey],
        questions: &[VerdictCells],
    ) {
        let keys: Vec<SubstateKey> = questions.iter().flat_map(VerdictCells::keys).collect();
        let (_, proof) = state_and_proof(anchor.shard, present, &keys);
        counterparts.on_verdict_proof_fetched(anchor, questions, &proof, GRID);
    }

    /// A claim at `anchor` reading `keys` over a tree holding `present`.
    fn read_at(anchor: Anchor, present: &[SubstateKey], keys: &[SubstateKey]) -> StateClaim {
        let (_, proof) = state_and_proof(anchor.shard, present, keys);
        let cells = proof
            .inclusions(anchor.state_root, anchor.shard, keys)
            .expect("the fixture proof answers for its keys");
        StateClaim::new(anchor, cells, proof)
    }

    /// The questions `actions` ask, each with the anchor asked at.
    fn asked(actions: &[Action]) -> Vec<(Anchor, VerdictCells)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::VerdictProofs(ids),
                    ..
                }) => Some(ids.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn mark_at(anchor: &Anchor) -> ReadMark {
        ReadMark::of(anchor, GRID)
    }

    /// A key beside `key` under its owner, above it or below it.
    fn beside_key(key: SubstateKey, above: bool) -> SubstateKey {
        (1..=u8::MAX)
            .map(|flip| {
                let mut other = key;
                other.local.0[15] ^= flip;
                other
            })
            .find(|other| (*other > key) == above)
            .expect("a key on that side")
    }

    const LATE: WeightedTimestamp = WeightedTimestamp::from_millis(40_000);

    /// Stand `question`, ask it at `PRODUCER`'s header at height 8 and
    /// answer it over a tree holding `present`: the anchor it was read
    /// at.
    fn read_once(
        counterparts: &mut Counterparts,
        anchors: &ProvenAnchors,
        question: VerdictQuestion,
        present: &[SubstateKey],
    ) -> Anchor {
        anchors.record(producer_at(7, present));
        counterparts.ask_verdicts(&[question], LATE);
        let at = producer_at(8, present);
        anchors.record(at);
        assert_eq!(counterparts.ask_verdicts(&[question], LATE).len(), 1);
        answer(counterparts, at, present, &[verdict_cells(&question)]);
        at
    }

    /// A question waits one sibling header before its first ask, so the
    /// push of the block that wrote the leaf can answer it first, and
    /// is then asked as one id, its three cells together at one anchor,
    /// through the verdict fetch. While that fetch is out it is not
    /// asked again.
    #[test]
    fn a_question_is_first_asked_one_sibling_header_after_it_stands() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        anchors.record(producer_at(7, &[]));
        assert!(
            counterparts.ask_verdicts(&[question], LATE).is_empty(),
            "nothing is asked at the header standing when the row began to hear",
        );
        assert!(counterparts.ask_verdicts(&[question], LATE).is_empty());

        let next = producer_at(8, &[]);
        anchors.record(next);
        let fetch = counterparts.ask_verdicts(&[question], LATE);
        assert_eq!(fetch.len(), 1, "one fetch at one anchor");
        assert_eq!(
            asked(&fetch),
            vec![(next, cells)],
            "the question, whole: the leaf, the row and the marker",
        );
        anchors.record(producer_at(9, &[]));
        assert!(
            counterparts.ask_verdicts(&[question], LATE).is_empty(),
            "a question whose fetch is out is not put again",
        );
    }

    /// A yes heard is not the end of a question: the sibling goes on to
    /// accept or to leave, so the question is put again on its backoff,
    /// and the reading that says yes again is spent on no block.
    #[test]
    fn a_fresh_yes_is_asked_again() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let first = read_once(&mut counterparts, &anchors, question, &[cells.leaf]);
        let held = counterparts.verdict_claims();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].keys(), vec![cells.leaf], "a yes is its one cell");
        assert_eq!(held[0].verdicts.to_vec(), vec![question.tx]);
        assert!(counterparts.state_claims().is_empty());

        anchors.record(producer_at(9, &[cells.leaf]));
        assert!(
            counterparts.ask_verdicts(&[question], LATE).is_empty(),
            "a question whose answer is held to offer is not put again",
        );

        // The row hears the yes at the mark it was read at.
        let heard = having_heard(question, mark_at(&first), Some(Said::Yes));
        let fetch = counterparts.ask_verdicts(&[heard], LATE);
        assert!(counterparts.heard.is_empty(), "the heard reading is let go");
        let again = producer_at(9, &[cells.leaf]);
        assert_eq!(
            asked(&fetch),
            vec![(again, cells)],
            "and the yes is asked about again, a header on",
        );
        answer(&mut counterparts, again, &[cells.leaf], &[cells]);
        assert!(
            counterparts.heard.is_empty(),
            "the same yes at a newer mark is not offered",
        );
        anchors.record(producer_at(10, &[cells.leaf]));
        assert!(
            counterparts.ask_verdicts(&[heard], LATE).is_empty(),
            "the asks back off",
        );
        anchors.record(producer_at(11, &[cells.leaf]));
        assert_eq!(counterparts.ask_verdicts(&[heard], LATE).len(), 1);
    }

    /// What is offered is what would change the row: a first reading
    /// that says nothing, and an unchanged answer at a newer mark, are
    /// spent on no block. A yes read an epoch after the one held is
    /// offered, since a row counts a yes only while it is recent; and an
    /// answer over an entry the window does not count is offered
    /// whatever it says.
    #[test]
    fn a_mark_only_change_is_not_offered() {
        let unstated = |entry| {
            let (mut counterparts, anchors) = hearing();
            let question = VerdictQuestion {
                entry,
                ..verdict_question(1)
            };
            let cells = verdict_cells(&question);
            read_once(&mut counterparts, &anchors, question, &[cells.row]);
            counterparts.heard.is_empty()
        };
        assert!(unstated(None), "a first not-stated reading is not offered");
        let said_nothing = Heard {
            shard: PRODUCER,
            mark: mark_at(&producer_at(5, &[])),
            said: None,
        };
        assert!(
            unstated(Some(said_nothing)),
            "nor a newer mark on a row that already heard nothing stated",
        );

        let renewed = |counted: bool, read_at: u64| {
            let (mut counterparts, anchors) = hearing();
            let base = VerdictQuestion {
                counted,
                ..verdict_question(1)
            };
            let cells = verdict_cells(&base);
            let heard_at = producer_at(8, &[cells.leaf]);
            let question = having_heard(base, mark_at(&heard_at), Some(Said::Yes));
            anchors.record(producer_at(read_at - 1, &[cells.leaf]));
            counterparts.ask_verdicts(&[question], LATE);
            let at = producer_at(read_at, &[cells.leaf]);
            anchors.record(at);
            assert_eq!(counterparts.ask_verdicts(&[question], LATE).len(), 1);
            assert!(mark_at(&at) > mark_at(&heard_at));
            answer(&mut counterparts, at, &[cells.leaf], &[cells]);
            !counterparts.heard.is_empty()
        };
        assert!(renewed(true, 12), "a yes an epoch on renews the row's");
        assert!(!renewed(true, 9), "but not within the epoch it was read in");
        assert!(
            renewed(false, 9),
            "where it replaces an entry the window does not count",
        );
    }

    /// A leaf read absent is offered only with the row and the marker it
    /// is judged beside: all three in one claim naming the member.
    #[test]
    fn an_absent_leaf_is_held_with_its_row_and_marker_in_one_claim() {
        let (mut counterparts, anchors) = hearing();
        let base = verdict_question(1);
        let cells = verdict_cells(&base);
        let question = having_heard(base, mark_at(&producer_at(5, &[])), Some(Said::Yes));
        read_once(&mut counterparts, &anchors, question, &[cells.marker]);
        let held = counterparts.verdict_claims();
        assert_eq!(held.len(), 1);
        let mut expected = cells.keys().to_vec();
        expected.sort_unstable();
        assert_eq!(held[0].keys(), expected, "the leaf, the row and the marker");
        assert_eq!(held[0].verdicts.to_vec(), vec![question.tx]);
        assert!(held[0].is_well_formed());
    }

    /// One answer's readings are held as one claim: a present leaf as
    /// its one cell, an absent one as its three, each beside its
    /// member's name, and nothing of a question whose reading is worth
    /// no block. A row hearing one of them cuts that reading from the
    /// claim and leaves the rest a claim in its own right.
    #[test]
    fn one_answer_is_held_as_one_claim_of_its_readings() {
        let (mut counterparts, anchors) = hearing();
        let said_yes = verdict_question(1);
        let unstated = verdict_question(3);
        let (yes, gone, silent) = (
            verdict_cells(&said_yes),
            verdict_cells(&verdict_question(2)),
            verdict_cells(&unstated),
        );
        let left = having_heard(
            verdict_question(2),
            mark_at(&producer_at(5, &[])),
            Some(Said::Yes),
        );
        let questions = [said_yes, left, unstated];
        let present = [yes.leaf, gone.marker, silent.row];
        anchors.record(producer_at(7, &present));
        counterparts.ask_verdicts(&questions, LATE);
        let at = producer_at(8, &present);
        anchors.record(at);
        let fetch = counterparts.ask_verdicts(&questions, LATE);
        assert_eq!(fetch.len(), 1, "one request for all three");
        answer(&mut counterparts, at, &present, &[yes, gone, silent]);

        let held = counterparts.verdict_claims();
        assert_eq!(held.len(), 1, "one claim an answer");
        let mut expected = vec![yes.leaf, gone.leaf, gone.row, gone.marker];
        expected.sort_unstable();
        assert_eq!(held[0].keys(), expected);
        let mut named = vec![said_yes.tx, left.tx];
        named.sort_unstable();
        assert_eq!(held[0].verdicts.to_vec(), named);
        assert!(held[0].is_well_formed() && held[0].verify().is_ok());
        assert!(
            counterparts
                .verdicts
                .values()
                .all(|ask| ask.returned && ask.asked_at == Some(at)),
            "every question the answer read is closed at the anchor",
        );

        let heard = having_heard(said_yes, mark_at(&at), Some(Said::Yes));
        counterparts.ask_verdicts(&[heard, left, unstated], LATE);
        let rest = counterparts.verdict_claims();
        assert_eq!(rest.len(), 1);
        let mut expected = gone.keys().to_vec();
        expected.sort_unstable();
        assert_eq!(rest[0].keys(), expected, "the heard reading is cut out");
        assert_eq!(rest[0].verdicts.to_vec(), vec![left.tx]);
        assert!(rest[0].is_well_formed() && rest[0].verify().is_ok());
    }

    /// A question the tip no longer stands, as when its sibling has left
    /// the trie, is not asked: its fetch is let go, its leaf is no
    /// longer looked up, and what was held for it is dropped.
    #[test]
    fn a_gone_sibling_is_not_asked() {
        let (mut counterparts, anchors) = hearing();
        let (held, out) = (verdict_question(1), verdict_question(2));
        let cells = verdict_cells(&held);
        read_once(&mut counterparts, &anchors, held, &[cells.leaf]);
        assert!(!counterparts.heard.is_empty());

        counterparts.ask_verdicts(&[held, out], LATE);
        let next = producer_at(9, &[cells.leaf]);
        anchors.record(next);
        assert_eq!(
            asked(&counterparts.ask_verdicts(&[held, out], LATE)),
            vec![(next, verdict_cells(&out))],
            "the second question is out at the next header",
        );

        let released = counterparts.ask_verdicts(&[], LATE);
        let outstanding = vec![(next, verdict_cells(&out))];
        assert!(
            matches!(
                released.as_slice(),
                [Action::AbandonFetch(FetchIds::VerdictProofs(ids))] if *ids == outstanding
            ),
            "only the fetch still out is let go: {released:?}",
        );
        assert!(counterparts.verdicts.is_empty() && counterparts.verdict_leaves.is_empty());
        assert!(counterparts.verdict_asked.is_empty());
        assert!(counterparts.heard.is_empty(), "and its reading is dropped");
        anchors.record(producer_at(10, &[cells.leaf]));
        assert!(counterparts.ask_verdicts(&[], LATE).is_empty());
    }

    /// A block that carried a verdict cell lets go of nothing held for a
    /// verdict question, named or not: the reading goes only once the
    /// row's entry has reached the mark it was read at.
    #[test]
    fn a_verdict_cell_a_block_carried_is_still_held_to_offer() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let at = read_once(&mut counterparts, &anchors, question, &[cells.leaf]);
        let offered = counterparts.verdict_claims();
        assert_eq!(offered.len(), 1);

        let nameless = read_at(at, &[cells.leaf], &[cells.leaf]);
        counterparts.cut_carried(&[nameless.clone(), nameless.hearing([question.tx])]);
        counterparts.ask_verdicts(&[question], LATE);
        assert_eq!(
            counterparts.verdict_claims(),
            offered,
            "the row heard nothing, so the reading is offered again",
        );

        let below = having_heard(question, mark_at(&producer_at(7, &[])), Some(Said::Left));
        counterparts.ask_verdicts(&[below], LATE);
        assert_eq!(
            counterparts.verdict_claims(),
            offered,
            "an older entry lets nothing go"
        );

        let heard = having_heard(question, mark_at(&at), Some(Said::Yes));
        counterparts.ask_verdicts(&[heard], LATE);
        assert!(
            counterparts.heard.is_empty(),
            "the entry reaching the reading's mark is what lets it go",
        );
    }

    /// A committed claim naming members cuts nothing from a claim held
    /// for another question at its anchor: a seat reading over the same
    /// row and leaf is still owed to a block whole. The same cells
    /// carried under no name are cut, as any carried cell is.
    #[test]
    fn a_carried_verdict_claim_cuts_nothing_from_a_held_seat_reading() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let at = producer_at(8, &[cells.leaf]);
        anchors.record(at);
        let seat = read_at(at, &[cells.leaf], &[cells.row, cells.leaf]);
        counterparts.hold_seat_reading(&seat, question.tx);

        let named = read_at(at, &[cells.leaf], &[cells.leaf]).hearing([question.tx]);
        counterparts.cut_carried(std::slice::from_ref(&named));
        assert_eq!(
            counterparts.state_claims(),
            vec![seat],
            "the seat reading keeps the leaf a verdict claim carried",
        );

        let nameless = read_at(at, &[cells.leaf], &[cells.leaf]);
        counterparts.cut_carried(&[named, nameless]);
        assert_eq!(
            counterparts
                .state_claims()
                .iter()
                .flat_map(StateClaim::keys)
                .collect::<Vec<_>>(),
            vec![cells.row],
            "a claim naming nobody cuts the cells it carried",
        );
    }

    /// A reading at an anchor no block could carry silences nothing: it
    /// is let go, and its question is asked again. So for an anchor this
    /// validator no longer holds proven, as one a recovery fenced, and
    /// for one a retention horizon behind the clock.
    #[test]
    fn a_reading_no_block_could_carry_is_let_go_and_its_question_asked_again() {
        let holding = || {
            let (mut counterparts, anchors) = hearing();
            let question = verdict_question(1);
            let cells = verdict_cells(&question);
            let at = read_once(&mut counterparts, &anchors, question, &[cells.leaf]);
            assert_eq!(counterparts.verdict_claims().len(), 1);
            (counterparts, anchors, question, at)
        };

        let (mut counterparts, anchors, question, at) = holding();
        let cells = verdict_cells(&question);
        let past = at.ts.plus(RETENTION_HORIZON).plus(Duration::from_secs(5));
        let newer = producer_at(past.as_millis() / 1_000, &[cells.leaf]);
        anchors.record(newer);
        anchors.retire_below(past);
        assert_eq!(anchors.at(PRODUCER, at.height), None);
        let fetch = counterparts.ask_verdicts(&[question], past);
        assert_eq!(asked(&fetch), vec![(newer, cells)], "asked again");
        assert!(counterparts.heard.is_empty(), "and the reading is let go");

        let (mut counterparts, anchors, question, at) = holding();
        let cells = verdict_cells(&question);
        let past = at.ts.plus(RETENTION_HORIZON).plus(Duration::from_millis(1));
        let newer = producer_at(past.as_millis() / 1_000, &[cells.leaf]);
        anchors.record(newer);
        assert_eq!(anchors.at(PRODUCER, at.height), Some(at), "still proven");
        let fetch = counterparts.ask_verdicts(&[question], past);
        assert_eq!(asked(&fetch), vec![(newer, cells)], "asked again");
        assert!(counterparts.heard.is_empty(), "and the reading is let go");
    }

    /// A claim held for another question rides exactly as it is held,
    /// whatever verdict cells sit at its anchor. A verdict claim whose
    /// span it reaches into waits for it: it is not offered, and its
    /// question is asked again rather than silenced. Once the other has
    /// ridden the verdict claim is offered, and a newer reading takes
    /// its place whenever one comes.
    #[test]
    fn a_verdict_claim_behind_another_claim_waits_and_its_question_is_asked_again() {
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let leaf = cells.leaf;
        // A verdict reading held at an anchor where another question's
        // reading has a key either side of the verdict cell.
        let waiting = || {
            let (mut counterparts, anchors) = hearing();
            let at = read_once(&mut counterparts, &anchors, question, &[leaf]);
            let first = counterparts.verdict_claims();
            assert_eq!(first.len(), 1);
            let either_side = [beside_key(leaf, false), beside_key(leaf, true)];
            let crossing = read_at(at, &[leaf], &either_side);
            let _ = counterparts.fetched.hold(crossing.clone());
            assert!(
                counterparts.ask_verdicts(&[question], LATE).is_empty(),
                "no newer header to ask at yet",
            );
            assert_eq!(
                counterparts.state_claims(),
                vec![crossing],
                "the other claim is offered as it is held, byte for byte",
            );
            assert!(
                counterparts.verdict_claims().is_empty(),
                "the verdict claim inside its span waits",
            );
            assert!(!counterparts.heard.is_empty(), "and is kept");
            (counterparts, anchors, first)
        };

        // The other claim rides: the verdict claim is offered again.
        let (mut counterparts, _, first) = waiting();
        let ridden = counterparts.state_claims();
        counterparts.cut_carried(&ridden);
        counterparts.ask_verdicts(&[question], LATE);
        assert_eq!(counterparts.verdict_claims(), first);

        // It does not ride: the question is asked again at the next
        // header, and the newer reading replaces the one that waits.
        let (mut counterparts, anchors, _) = waiting();
        let next = producer_at(9, &[leaf]);
        anchors.record(next);
        let fetch = counterparts.ask_verdicts(&[question], LATE);
        assert_eq!(asked(&fetch), vec![(next, cells)], "asked again");
        answer(&mut counterparts, next, &[leaf], &[cells]);
        let offered = counterparts.verdict_claims();
        assert_eq!(offered.len(), 1, "one reading a question");
        assert_eq!(offered[0].anchor, next, "the newest");
        assert_eq!(counterparts.heard.claims.len(), 1);
        assert_eq!(counterparts.state_claims().len(), 1);
    }

    /// A reading for another question is held whole though a verdict
    /// claim at its anchor reads some of its cells, and no other
    /// question is stood down by a cell a verdict claim holds.
    #[test]
    fn a_seat_reading_is_held_whole_beside_a_verdict_claim_of_its_cells() {
        let (mut counterparts, anchors) = hearing();
        let base = verdict_question(1);
        let cells = verdict_cells(&base);
        let question = having_heard(base, mark_at(&producer_at(5, &[])), Some(Said::Yes));
        let at = read_once(&mut counterparts, &anchors, question, &[cells.marker]);
        assert_eq!(counterparts.verdict_claims().len(), 1);
        assert!(
            counterparts.fetched.is_empty() && !counterparts.fetched.reads(PRODUCER, cells.row),
            "nothing held for a verdict question is among the other claims",
        );

        let reading = read_at(at, &[cells.marker], &[cells.row, cells.leaf]);
        counterparts.hold_seat_reading(&reading, question.tx);
        assert_eq!(
            counterparts.state_claims(),
            vec![reading],
            "the seat reading holds every cell of its own",
        );
        assert!(counterparts.fetched.reads(PRODUCER, cells.row));
        assert!(!counterparts.fetched.reads(PRODUCER, cells.marker));
    }

    /// The order the other claims are offered in is theirs alone: a
    /// verdict claim held long at an old anchor moves no producer's
    /// claims ahead of another's.
    #[test]
    fn a_long_held_verdict_claim_does_not_reorder_the_other_claims() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        anchors.record(producer_at(1, &[cells.leaf]));
        counterparts.ask_verdicts(&[question], LATE);
        let old = producer_at(2, &[cells.leaf]);
        anchors.record(old);
        counterparts.ask_verdicts(&[question], LATE);
        answer(&mut counterparts, old, &[cells.leaf], &[cells]);
        assert_eq!(counterparts.verdict_claims().len(), 1);

        let other = ShardId::leaf(2, 0);
        let older = proven_claim(
            other,
            5,
            &[],
            &[verdict_leaf(
                other,
                TxHash::from(Hash::from_bytes(b"elsewhere")),
            )],
        );
        let newer = proven_claim(PRODUCER, 9, &[], &[producer_record(3)]);
        let _ = counterparts.fetched.hold(newer.clone());
        let _ = counterparts.fetched.hold(older.clone());
        assert_eq!(
            counterparts.state_claims(),
            vec![older, newer],
            "the producers ride by the oldest anchor of the claims held for them",
        );
    }

    /// Toward one sibling one request is out at a time, of no more
    /// questions than a request carries, so a sibling that never answers
    /// holds that many places of the fetch and a question toward another
    /// sibling is still asked. The silent sibling is asked nothing more
    /// until the header it was asked at is no longer proven; its
    /// questions never asked then go first.
    #[test]
    fn one_request_is_out_toward_a_sibling_and_another_sibling_is_still_asked() {
        let (mut counterparts, anchors) = hearing();
        let silent: Vec<VerdictQuestion> = (1..=64).map(verdict_question).collect();
        let healthy = question_toward(OTHER, 1);
        let mut questions = silent.clone();
        questions.push(healthy);
        anchors.record(producer_at(7, &[]));
        anchors.record(header_at(OTHER, 7, &[]));
        assert!(counterparts.ask_verdicts(&questions, LATE).is_empty());

        let (first, other) = (producer_at(8, &[]), header_at(OTHER, 8, &[]));
        anchors.record(first);
        anchors.record(other);
        let fetch = counterparts.ask_verdicts(&questions, LATE);
        let out = asked(&fetch);
        let toward = |shard: ShardId| out.iter().filter(|(at, _)| at.shard == shard).count();
        assert_eq!(toward(PRODUCER), MAX_VERDICT_ASKS_PER_SIBLING);
        assert_eq!(toward(OTHER), 1, "the other sibling is asked beside it");
        let first_asked: BTreeSet<VerdictCells> = out
            .iter()
            .filter(|(at, _)| at.shard == PRODUCER)
            .map(|(_, cells)| *cells)
            .collect();

        // The healthy sibling answers and is asked again on its backoff;
        // the silent one is asked nothing more, header after header.
        answer(&mut counterparts, other, &[], &[verdict_cells(&healthy)]);
        for height in 9..=12 {
            anchors.record(producer_at(height, &[]));
            anchors.record(header_at(OTHER, height, &[]));
            let fetch = counterparts.ask_verdicts(&questions, LATE);
            for (at, cells) in asked(&fetch) {
                assert_eq!(
                    at.shard, OTHER,
                    "nothing more goes toward the silent sibling at height {height}",
                );
                answer(&mut counterparts, at, &[], &[cells]);
            }
        }
        assert_eq!(
            counterparts
                .verdicts
                .values()
                .filter(|ask| ask.question.sibling == OTHER)
                .map(|ask| ask.asked)
                .sum::<u32>(),
            3,
            "the healthy sibling's question went out again at heights 9 and 11",
        );

        // The header the silent sibling was asked at ages out: its
        // request is let go and the next one goes out.
        let past = first
            .ts
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_secs(5));
        let late = producer_at(past.as_millis() / 1_000, &[]);
        anchors.record(late);
        anchors.retire_below(past);
        let fetch = counterparts.ask_verdicts(&silent, past);
        let released: Vec<(Anchor, VerdictCells)> = fetch
            .iter()
            .filter_map(|action| match action {
                Action::AbandonFetch(FetchIds::VerdictProofs(ids)) => Some(ids.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(released.len(), MAX_VERDICT_ASKS_PER_SIBLING);
        assert!(released.iter().all(|(at, _)| *at == first));
        let again = asked(&fetch);
        assert_eq!(again.len(), MAX_VERDICT_ASKS_PER_SIBLING);
        assert!(
            again
                .iter()
                .all(|(at, cells)| *at == late && !first_asked.contains(cells)),
            "the questions never asked go before the ones let go",
        );
    }

    /// Two requests to one sibling never go to one header, so two claims
    /// fetched from it never sit at one anchor.
    #[test]
    fn a_sibling_is_asked_once_a_header() {
        let (mut counterparts, anchors) = hearing();
        let questions: Vec<VerdictQuestion> = (1..=30).map(verdict_question).collect();
        anchors.record(producer_at(7, &[]));
        counterparts.ask_verdicts(&questions, LATE);
        let at = producer_at(8, &[]);
        anchors.record(at);
        let out = asked(&counterparts.ask_verdicts(&questions, LATE));
        assert_eq!(out.len(), MAX_VERDICT_ASKS_PER_SIBLING);
        let cells: Vec<VerdictCells> = out.iter().map(|(_, cells)| *cells).collect();
        answer(&mut counterparts, at, &[], &cells);
        assert!(
            counterparts.ask_verdicts(&questions, LATE).is_empty(),
            "the rest wait for the sibling's next header",
        );
        let next = producer_at(9, &[]);
        anchors.record(next);
        let out = asked(&counterparts.ask_verdicts(&questions, LATE));
        assert_eq!(out.len(), MAX_VERDICT_ASKS_PER_SIBLING);
        assert!(out.iter().all(|(anchor, _)| *anchor == next));
        assert!(
            out[..9].iter().all(|(_, asked)| !cells.contains(asked)),
            "the nine never asked go first",
        );
    }

    /// No more verdict claims are offered than one block could carry,
    /// the oldest anchors first.
    #[test]
    fn no_more_verdict_claims_are_offered_than_a_block_carries() {
        let (mut counterparts, _) = hearing();
        let held = u16::try_from(MAX_STATE_CLAIMS_PER_BLOCK + 8).expect("a small fixture");
        for seed in 1..=held {
            let question = verdict_question(seed);
            let cells = verdict_cells(&question);
            let at = producer_at(1_000 - u64::from(seed), &[cells.leaf]);
            let claim = read_at(at, &[cells.leaf], &[cells.leaf]).hearing([question.tx]);
            counterparts
                .heard
                .hold(claim, mark_at(&at), &[(question.tx, cells)]);
        }
        assert_eq!(counterparts.heard.claims.len(), usize::from(held));
        let offered = counterparts.verdict_claims();
        assert_eq!(offered.len(), MAX_STATE_CLAIMS_PER_BLOCK);
        assert!(
            offered
                .windows(2)
                .all(|pair| pair[0].anchor.ts < pair[1].anchor.ts),
            "oldest first",
        );
        assert_eq!(
            offered[0].anchor.height,
            BlockHeight::new(1_000 - u64::from(held))
        );
        let weight: usize = offered.iter().map(StateClaim::wire_weight).sum();
        assert!(state_claims_admit_block(weight));
    }
}
