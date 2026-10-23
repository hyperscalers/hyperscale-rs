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
use std::time::Duration;

use hyperscale_core::{Action, FetchIds, FetchRequest};
use hyperscale_engine::tick_select::SeatQuestion;
use hyperscale_metrics::{
    record_boundary_cells_asked, record_boundary_claims_carried, record_boundary_drained,
    record_decline_folded, record_fenced_claim, record_rebuilt_record_entry, record_reclaim_folded,
    record_records_repushed, record_repush_due, record_repush_paused, record_sibling_absence_read,
    record_sibling_question_pending, set_standing_answers, set_wanted_records,
};
#[cfg(test)]
use hyperscale_storage::CrossingJournal;
use hyperscale_storage::{
    CrossingCursor, committed_tx_cell_key, member_row_leaf, reclaimed, unclaimed_records,
};
use hyperscale_types::network::response::ServedValue;
#[cfg(test)]
use hyperscale_types::shard_prefix_path;
use hyperscale_types::{
    ABANDONMENT_RECORD_BYTES, AbandonmentRecord, Address, Anchor, Block, BlockHeight,
    BoundaryAttestation, BoundaryOffer, CarriedClaims, CounterpartMirror, Deadline, EpochWindows,
    ExecutionCertificate, FrontierInputs, Inclusion, Issuer, LocalKey, MAX_CLAIMS_PER_BLOCK,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_PROVISION_TARGET_SHARDS, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MAX_VALIDITY_RANGE,
    MAX_VERDICT_CLAIMS_BYTES, MerkleInclusionProof, ProvenAnchors, RETENTION_HORIZON, ReadFrontier,
    ReadMark, STATE_CLAIM_CELL_BYTES, SettledTxSet, ShardId, ShardTrie, StateClaim, Stated,
    SubstateKey, TerminalEvidence, TickLine, TopologySchedule, TxHash, TxOutcome, TxResolution,
    UnsettledTx, VerdictCells, VerdictQuestion, Verifiable, Verified, WeightedTimestamp,
    answer_hashes, said_at, verdict_leaf,
};
use hyperscale_vm_effects::{
    Answered, CrossingCell, CrossingId, CrossingLeaf, ProtocolHasher, Terms,
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
    /// name a record does not carry stays uncovered and is offered again
    /// next block.
    fn take(&mut self, unsettled: &mut Vec<UnsettledTx>) {
        let mut spend = ABANDONMENT_RECORD_BYTES;
        let mut names = 0;
        for weight in unsettled.iter().map(UnsettledTx::wire_weight) {
            if names == self.names || spend + weight > self.bytes {
                break;
            }
            spend += weight;
            names += 1;
        }
        unsettled.truncate(names);
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
    /// The crossing records and answers under `shard`'s prefix that
    /// moved since `since`, or every one of them where the index cannot
    /// say what moved, each with its bytes as the persisted tip holds
    /// them, ascending by key; and where the reader stands once it has
    /// read them.
    fn crossing_changes(
        &self,
        shard: ShardId,
        since: Option<CrossingCursor>,
    ) -> (CrossingRead, Option<CrossingCursor>);

    /// The bytes `key` holds at the persisted tip, if it holds any.
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>>;

    /// Whether `key` reads present at the persisted tip.
    fn present(&self, key: SubstateKey) -> bool {
        self.cell(key).is_some()
    }
}

/// What one read of a [`CrossingIndex`] brings.
#[derive(Debug)]
pub enum CrossingRead {
    /// Every row, with its bytes.
    Whole(Vec<(SubstateKey, Vec<u8>)>),
    /// The rows that moved, each with its bytes, or `None` where it is
    /// gone.
    Changed(Vec<(SubstateKey, Option<Vec<u8>>)>),
}

/// The index a shard's store answers with, bound once the store's
/// chain is open: a replica is built before its shard's chain exists,
/// and the shard loop binds the slot once it does.
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
    fn crossing_changes(
        &self,
        shard: ShardId,
        since: Option<CrossingCursor>,
    ) -> (CrossingRead, Option<CrossingCursor>) {
        self.bound().map_or_else(
            || (CrossingRead::Whole(Vec::new()), None),
            |index| index.crossing_changes(shard, since),
        )
    }

    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.bound().and_then(|index| index.cell(key))
    }
}

/// Crossing rows written out by hand: what a test holds where a store
/// would, with a journal of the keys each write touched.
#[cfg(test)]
#[derive(Default)]
pub struct TestRows(std::sync::Mutex<TestCells>);

/// The cells a [`TestRows`] holds, and the journal of its writes, one
/// version a write.
#[cfg(test)]
#[derive(Default)]
pub struct TestCells {
    cells: BTreeMap<SubstateKey, Vec<u8>>,
    journal: CrossingJournal,
    version: u64,
}

#[cfg(test)]
impl TestCells {
    fn write(&mut self, key: SubstateKey, value: Option<Vec<u8>>) {
        match value {
            Some(value) => self.cells.insert(key, value),
            None => self.cells.remove(&key),
        };
        self.version += 1;
        self.journal.record(self.version, [key]);
    }

    fn read(
        &self,
        shard: ShardId,
        since: Option<CrossingCursor>,
    ) -> (CrossingRead, Option<CrossingCursor>) {
        let (changed, cursor) = self
            .journal
            .since(&shard_prefix_path(shard), since, self.version);
        let read = changed.map_or_else(
            || {
                CrossingRead::Whole(
                    self.cells
                        .keys()
                        .filter_map(|key| self.row(shard, *key).map(|value| (*key, value.clone())))
                        .collect(),
                )
            },
            |keys| {
                CrossingRead::Changed(
                    keys.into_iter()
                        .map(|key| (key, self.row(shard, key).cloned()))
                        .collect(),
                )
            },
        );
        (read, Some(cursor))
    }

    fn row(&self, shard: ShardId, key: SubstateKey) -> Option<&Vec<u8>> {
        self.cells.get(&key).filter(|value| {
            ShardTrie::shard_owns_prefix(shard, key.owner)
                && CrossingLeaf::read(&ProtocolHasher, key, value).is_some()
        })
    }
}

#[cfg(test)]
impl TestRows {
    /// A cell at `key`, crossing leaf or not.
    pub fn put(&self, key: SubstateKey, value: Vec<u8>) {
        self.cells().write(key, Some(value));
    }

    /// The cell at `key` gone.
    pub fn remove(&self, key: SubstateKey) {
        self.cells().write(key, None);
    }

    /// Start the journal over, as a store its readers no longer follow:
    /// the next read is whole.
    pub fn restart(&self) {
        let mut cells = self.cells();
        let version = cells.version;
        cells.journal.restart(version);
    }

    fn cells(&self) -> std::sync::MutexGuard<'_, TestCells> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
impl CrossingIndex for TestRows {
    fn crossing_changes(
        &self,
        shard: ShardId,
        since: Option<CrossingCursor>,
    ) -> (CrossingRead, Option<CrossingCursor>) {
        self.cells().read(shard, since)
    }

    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells().cells.get(&key).cloned()
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

/// How many verdict claims one proposal is offered, as they are held.
///
/// Wider than the places a block always has for verdict claims: the
/// proposer cuts each claim to what a row at its parent would hear, and
/// the oldest held are the ones a block not yet committed has carried.
const VERDICT_OFFER_CLAIMS: usize = MAX_STATE_CLAIMS_PER_BLOCK;

/// The bytes of verdict claims one proposal is offered, as they are
/// held: wider than [`MAX_VERDICT_CLAIMS_BYTES`], the bytes a block
/// always has for them, as [`VERDICT_OFFER_CLAIMS`] is wider than its
/// places.
const VERDICT_OFFER_BYTES: usize = MAX_STATE_CLAIMS_BYTES;

const _: () = assert!(
    VERDICT_OFFER_BYTES > MAX_VERDICT_CLAIMS_BYTES
        && VERDICT_OFFER_CLAIMS > MAX_CLAIMS_PER_BLOCK - MAX_STATE_CLAIMS_PER_BLOCK
);

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

/// The most cells the boundary claims of one offer read: what a block's
/// claims could hold of them if no proof weighed anything, so no offer
/// is wider than a block could carry.
const BOUNDARY_OFFER_CELLS: usize = MAX_STATE_CLAIMS_BYTES / STATE_CLAIM_CELL_BYTES;

/// `span` in whole milliseconds, saturating.
fn millis(span: Duration) -> u64 {
    u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

/// The widest gap, in the counterpart's heights, between two asks of a
/// question nothing has answered.
const MAX_ANSWER_ASK_GAP: u64 = 64;

/// Whether `newest`, a counterpart's height, is the widest ask gap or
/// more past `asked`, the height something was read or asked at.
const fn past_ask_gap(newest: BlockHeight, asked: BlockHeight) -> bool {
    newest.inner() >= asked.inner().saturating_add(MAX_ANSWER_ASK_GAP)
}

/// The gap, in the counterpart's heights, before the next ask of an
/// answer asked `asked` times without one: `2^(asked-1)`, capped at
/// [`MAX_ANSWER_ASK_GAP`], so the asks fall at `h, h+1, h+3, h+7, ...`.
fn answer_ask_gap(asked: u32) -> u64 {
    (1u64 << asked.saturating_sub(1).min(6)).min(MAX_ANSWER_ASK_GAP)
}

/// One carried record's re-push pacing on this validator alone.
///
/// A fresh `Taken` a push brings retires nothing, since a recovery of
/// the consumer's shard can discard it, but it says the consumer
/// answered: the record waits for that answer read at a boundary, and is
/// pushed no more meanwhile. The pause clears at the first boundary of
/// the answer key's holder whose clock is later than the pushed reading
/// and whose read of the key is refuted or let go. A later clock is a
/// later state of the holder's chain or of a chain recovered past the
/// pushed block, and either way one that holds no such `Taken` where the
/// read refutes it. Heights do not order a recovery's branches, so the
/// comparison is by clock. No pause is set after the refutation that
/// would clear it: the coordinator drops a push of a discarded `Taken`
/// before it is offered here, as fenced once the recovery is in this
/// validator's schedule (`TopologySchedule::recovery_orphaned`), which
/// holds the recovery before any boundary of the recovered chain, as
/// `anchor_disagrees` once the recovered chain passes its height, or at
/// the horizon.
///
/// A pause lasts at most until the holder's next recorded boundary is
/// read: one epoch crossing of the holder at most, or the first boundary
/// of a recovered chain. A validator that seeds its pauses at a start or
/// a seat pushes none of its past-due records again for up to that long,
/// and where a whole committee restarts none of its members does: a
/// decline that needs the push is delayed, never lost.
/// A read let go because the key's holder moved clears a pause whose
/// `Taken` may stand, which costs only pushes until the new holder's
/// boundary holds it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Repush {
    /// When the record was last pushed again, at this shard's height,
    /// and how many times, if it has been.
    last: Option<(BlockHeight, u32)>,
    /// The clock of the newest fresh `Taken` of the record's own
    /// transaction a push brought, while it stands for the answer.
    paused_from: Option<WeightedTimestamp>,
    /// Whether a re-push has found the record due.
    found_due: bool,
    /// The clock of the boundary that last cleared a pause on the
    /// record, if one has. That boundary refuted or let go every reading
    /// of the `Taken` no later than it, so a push read at or before it
    /// pauses nothing.
    cleared_at: Option<WeightedTimestamp>,
}

/// One record this shard holds for a consumer elsewhere, which it
/// pushes to the consumer's shard again until the record goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carried {
    /// The crossing the record holds.
    id: CrossingId,
    /// The instant its re-push opens: an owed record's deadline, and an
    /// escrowed record's validity end.
    due_from: WeightedTimestamp,
    /// Whether the record is escrowed: one its consumer's shard keeps
    /// unasked, under [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`].
    escrowed: bool,
}

/// One answer this shard holds whose record another shard holds: the
/// cells whose reading at a boundary of that shard deletes it.
///
/// An answer goes only on its record read absent with its producing
/// member's exit proven, at a boundary the beacon recorded for the
/// record's shard: the one state of that shard no recovery discards. So
/// every answer row reads its record's key and its member's row leaf at
/// each boundary, and the member's committed marker where the boundary's
/// clock is short of the transaction's validity end. Before then the
/// marker is what shows the transaction committed there; past it the
/// shard admits the transaction no more, and the row's absence is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnswerRow {
    /// The shard holding the record's prefix.
    holder: ShardId,
    /// The record's key.
    record: SubstateKey,
    /// The row of the answering transaction's member on the holder.
    row: SubstateKey,
    /// That transaction's committed marker on the holder.
    marker: SubstateKey,
    /// The transaction's validity end.
    validity_end: WeightedTimestamp,
}

impl AnswerRow {
    /// The cells the answer's deletion reads at `boundary`, ascending.
    fn cells(&self, boundary: &Anchor) -> Vec<SubstateKey> {
        let mut cells = vec![self.record, self.row];
        if boundary.ts < self.validity_end {
            cells.push(self.marker);
        }
        cells.sort_unstable();
        cells
    }
}

/// One question a record this shard holds puts to its consumer's shard:
/// the consumer's `Taken` or `Never` of the record's own transaction,
/// read at a boundary the beacon recorded for the shard holding the
/// answer key. Every carried record asks its `Taken`, which retires it,
/// and an escrowed one its `Never` too, which takes it back.
///
/// An answer the consumer's shard wrote above its last recorded boundary
/// is one a recovery of that shard can discard, with every state after
/// it. A `Taken` lost so leaves the value taken by nobody, and a `Never`
/// lost so leaves a chain that can take the record where the lost one
/// refused it. So the record goes only on a reading at a boundary, which
/// no recovery discards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnswerAsk {
    /// The shard holding the answer key's prefix.
    holder: ShardId,
    /// The crossing the record holds.
    id: CrossingId,
    /// The record, which names the transaction whose answer it goes on,
    /// its validity end, and the cell its return credits.
    record: CrossingCell,
    /// Which answer is asked.
    answered: Answered,
}

impl AnswerAsk {
    /// The question `cell`, the record of `id`, puts of its `answered`
    /// answer under `trie`.
    fn of(trie: &ShardTrie, id: CrossingId, cell: &CrossingCell, answered: Answered) -> Self {
        Self {
            holder: trie.shard_for_prefix(id.answer_key(&ProtocolHasher, answered).owner),
            id,
            record: *cell,
            answered,
        }
    }

    /// The key asked.
    fn key(&self) -> SubstateKey {
        self.id.answer_key(&ProtocolHasher, self.answered)
    }

    /// The earliest boundary clock that can show the answer. A `Taken`
    /// is written no earlier than its transaction is admitted, which is
    /// no earlier than [`MAX_VALIDITY_RANGE`] before its validity end.
    /// A decline is written only from the validity end, and a refusal's
    /// `Never` is asked no sooner either.
    fn from(&self) -> WeightedTimestamp {
        let end = WeightedTimestamp::from_millis(self.record.validity_end_ms);
        match self.answered {
            Answered::Taken => end.minus(MAX_VALIDITY_RANGE),
            Answered::Never => end,
        }
    }
}

/// What one crossing row of this shard's puts, derived where the row is
/// read.
#[derive(Debug, Clone)]
enum RowRead {
    /// A record whose consumer another shard holds: what it asks of the
    /// consumer, and what this shard pushes it again and returns on.
    Carried {
        id: CrossingId,
        cells: CrossingCells,
        carried: Carried,
        asks: Vec<AnswerAsk>,
    },
    /// A record whose consumer this shard holds, which this shard's own
    /// fold settles off a reading at the parent.
    Settling {
        id: CrossingId,
        cells: CrossingCells,
        cell: CrossingCell,
    },
    /// An answer whose record another shard holds.
    Answer {
        id: CrossingId,
        row: AnswerRow,
        bytes: usize,
    },
    /// An answer whose record this shard holds.
    Closing {
        id: CrossingId,
        record: SubstateKey,
        bytes: usize,
    },
}

impl RowRead {
    /// What `value` at `key`, a crossing row under `local`'s prefix,
    /// puts under `trie`, if it is a crossing leaf.
    fn of(trie: &ShardTrie, local: ShardId, key: SubstateKey, value: &[u8]) -> Option<Self> {
        match CrossingLeaf::read(&ProtocolHasher, key, value)? {
            CrossingLeaf::Record { cell, .. } => {
                let id = CrossingId::of_record(key.owner, &cell);
                let cells = CrossingCells::of(&id);
                if trie.shard_for_prefix(cells.taken.owner) == local {
                    return Some(Self::Settling { id, cells, cell });
                }
                let end = WeightedTimestamp::from_millis(cell.validity_end_ms);
                let owed = cell.terms == Terms::Owed;
                let carried = Carried {
                    id,
                    due_from: if owed { Deadline::of(end).at() } else { end },
                    escrowed: !owed,
                };
                // Every escrowed record goes back on this chain: to its
                // credit cell, or to its owner's principal vault.
                let mut asks = vec![AnswerAsk::of(trie, id, &cell, Answered::Taken)];
                if !owed {
                    asks.push(AnswerAsk::of(trie, id, &cell, Answered::Never));
                }
                Some(Self::Carried {
                    id,
                    cells,
                    carried,
                    asks,
                })
            }
            CrossingLeaf::Answer { id, answer } => {
                let bytes = key.to_bytes().len() + value.len();
                let record = id.record_key(&ProtocolHasher);
                let holder = trie.shard_for_prefix(record.owner);
                if holder == local {
                    return Some(Self::Closing { id, record, bytes });
                }
                let validity_end = WeightedTimestamp::from_millis(answer.validity_end_ms);
                Some(Self::Answer {
                    id,
                    row: AnswerRow {
                        holder,
                        record,
                        row: member_row_leaf(holder, answer.tx),
                        marker: committed_tx_cell_key(holder, answer.tx, validity_end),
                        validity_end,
                    },
                    bytes,
                })
            }
        }
    }
}

/// The lowest key in key order.
const LOWEST_KEY: SubstateKey = SubstateKey {
    owner: Address::MIN,
    local: LocalKey([0; 16]),
};

/// What a standing row is, kept to take it down: the rest of what it
/// puts is in the maps it put it in.
#[derive(Debug, Clone, Copy)]
enum RowKind {
    /// A record, with the claim and decline keys of its crossing.
    Record {
        taken: SubstateKey,
        never: SubstateKey,
    },
    /// An answer, with its bytes.
    Answer { bytes: usize },
}

/// The crossing rows of this shard's as the index last read them, and
/// what each puts, kept from one commit to the next and moved by the
/// rows that moved: a commit reads the rows written or removed since the
/// last, and the whole index only where the index cannot say what moved
/// or the trie the rows were read under has changed.
#[derive(Debug, Default)]
struct CrossingRows {
    /// Where the index was last read to.
    cursor: Option<CrossingCursor>,
    /// The trie the rows were read under, which says which shard holds
    /// each record and each consumer.
    trie: Option<ShardTrie>,
    /// Every row, with what takes it down.
    rows: BTreeMap<SubstateKey, RowKind>,

    /// The answers whose record another shard holds, by answer key, each
    /// with the cells its deletion reads.
    answers: BTreeMap<SubstateKey, AnswerRow>,

    /// Each cell an answer's deletion reads, with the answer: a record
    /// key is read by the answers to its record, and a row leaf and a
    /// committed marker by every answer of the transaction.
    readers: BTreeSet<(SubstateKey, SubstateKey)>,

    /// How many of `answers` each shard holds the record of.
    holders: BTreeMap<ShardId, usize>,

    /// The questions the records whose consumer another shard holds put
    /// at its boundaries, by answer key: every one's `Taken`, which
    /// retires it, and an escrowed one's `Never`, which takes it back.
    answer_asks: BTreeMap<SubstateKey, AnswerAsk>,

    /// The crossing a reading of each key speaks for, over every row,
    /// with how many rows name it there: a record's answers and an
    /// answer's record, whoever asks about them. A record an entry here
    /// settles is asked about by the entry under its transaction's name,
    /// and its readings still have to name the crossing for the fold to
    /// settle on them.
    names: BTreeMap<SubstateKey, (CrossingId, usize)>,

    /// The claim keys of the records whose consumer this shard holds: a
    /// pushed answer to one is kept to offer, read at the parent.
    awaited: BTreeSet<SubstateKey>,

    /// Every record this shard holds for a consumer elsewhere: what the
    /// consumer's fold credits or declines only once a reading reaches
    /// it, and so what this shard sends it again until the record goes.
    carried: BTreeMap<SubstateKey, Carried>,

    /// The records whose consumer this shard holds, by record key, and
    /// the answers whose record it holds, by answer key: the crossings
    /// whose two ends are here, read again at every commit, since what
    /// settles them turns on the clock and on cells no row holds.
    settling: BTreeMap<SubstateKey, (CrossingId, CrossingCell)>,
    closing: BTreeMap<SubstateKey, (CrossingId, SubstateKey)>,

    /// How many answers stand, and their bytes.
    standing: usize,
    standing_bytes: usize,

    /// The cells whose boundary readings may no longer be needed since
    /// the readings were last judged: every cell of an answer gone or
    /// refuted at a boundary, and every answer key a record asked that
    /// is gone.
    unread: BTreeSet<SubstateKey>,

    /// Whether every held boundary reading is to be judged again: the
    /// rows were read whole.
    rejudge: bool,

    /// The `Taken` keys of the records the last read put up.
    newly_carried: Vec<SubstateKey>,
}

impl CrossingRows {
    /// Take what a read of the index under `trie` brought, `read` to
    /// `cursor`, for `local`.
    fn take(
        &mut self,
        trie: &ShardTrie,
        local: ShardId,
        read: CrossingRead,
        cursor: Option<CrossingCursor>,
    ) {
        self.newly_carried.clear();
        match read {
            CrossingRead::Whole(rows) => {
                *self = Self {
                    rejudge: true,
                    ..Self::default()
                };
                for (key, value) in rows {
                    if let Some(read) = RowRead::of(trie, local, key, &value) {
                        self.put(key, read);
                    }
                }
            }
            CrossingRead::Changed(rows) => {
                for (key, value) in rows {
                    self.retract(key);
                    if let Some(read) =
                        value.and_then(|value| RowRead::of(trie, local, key, &value))
                    {
                        self.put(key, read);
                    }
                }
            }
        }
        self.cursor = cursor;
        self.trie = Some(trie.clone());
    }

    /// Where the index is to be read from under `trie`: from the last
    /// read, or whole where the rows were read under another trie.
    fn since(&self, trie: &ShardTrie) -> Option<CrossingCursor> {
        self.cursor.filter(|_| self.trie.as_ref() == Some(trie))
    }

    fn name(&mut self, key: SubstateKey, id: CrossingId) {
        self.names.entry(key).or_insert((id, 0)).1 += 1;
    }

    fn unname(&mut self, key: SubstateKey) {
        if let Some((_, count)) = self.names.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                self.names.remove(&key);
            }
        }
    }

    /// Stand `read` at `key`.
    fn put(&mut self, key: SubstateKey, read: RowRead) {
        let kind = match &read {
            RowRead::Carried { cells, .. } | RowRead::Settling { cells, .. } => RowKind::Record {
                taken: cells.taken,
                never: cells.never,
            },
            RowRead::Answer { bytes, .. } | RowRead::Closing { bytes, .. } => {
                RowKind::Answer { bytes: *bytes }
            }
        };
        match read {
            RowRead::Carried {
                id,
                cells,
                carried,
                asks,
            } => {
                self.name(cells.taken, id);
                self.name(cells.never, id);
                self.newly_carried.push(cells.taken);
                self.carried.insert(key, carried);
                for ask in asks {
                    self.answer_asks.insert(ask.key(), ask);
                }
            }
            RowRead::Settling { id, cells, cell } => {
                self.name(cells.taken, id);
                self.name(cells.never, id);
                self.awaited.insert(cells.taken);
                self.settling.insert(key, (id, cell));
            }
            RowRead::Answer { id, row, bytes } => {
                self.name(row.record, id);
                for cell in [row.record, row.row, row.marker] {
                    self.readers.insert((cell, key));
                }
                *self.holders.entry(row.holder).or_default() += 1;
                self.answers.insert(key, row);
                self.standing += 1;
                self.standing_bytes += bytes;
            }
            RowRead::Closing { id, record, bytes } => {
                self.name(record, id);
                self.closing.insert(key, (id, record));
                self.standing += 1;
                self.standing_bytes += bytes;
            }
        }
        self.rows.insert(key, kind);
    }

    /// Take down whatever stands at `key`.
    fn retract(&mut self, key: SubstateKey) {
        match self.rows.remove(&key) {
            Some(RowKind::Record { taken, never }) => {
                self.unname(taken);
                self.unname(never);
                self.awaited.remove(&taken);
                self.carried.remove(&key);
                self.settling.remove(&key);
                for answer in [taken, never] {
                    if self.answer_asks.remove(&answer).is_some() {
                        self.unread.insert(answer);
                    }
                }
            }
            Some(RowKind::Answer { bytes }) => {
                if let Some(row) = self.answers.remove(&key) {
                    self.unname(row.record);
                    for cell in [row.record, row.row, row.marker] {
                        self.readers.remove(&(cell, key));
                        self.unread.insert(cell);
                    }
                    if let Some(count) = self.holders.get_mut(&row.holder) {
                        *count -= 1;
                        if *count == 0 {
                            self.holders.remove(&row.holder);
                        }
                    }
                }
                if let Some((_, record)) = self.closing.remove(&key) {
                    self.unname(record);
                }
                self.standing -= 1;
                self.standing_bytes -= bytes;
            }
            None => {}
        }
    }

    /// The answers whose deletion reads `cell`.
    fn readers_of(&self, cell: SubstateKey) -> impl Iterator<Item = &AnswerRow> + '_ {
        self.readers
            .range((cell, LOWEST_KEY)..)
            .take_while(move |(read, _)| *read == cell)
            .filter_map(|(_, answer)| self.answers.get(answer))
    }

    /// The answers whose deletion reads `record` as its record's key,
    /// by answer key.
    fn answers_to(
        &self,
        record: SubstateKey,
    ) -> impl Iterator<Item = (&SubstateKey, &AnswerRow)> + '_ {
        self.readers
            .range((record, LOWEST_KEY)..)
            .take_while(move |(read, _)| *read == record)
            .filter_map(|(_, answer)| self.answers.get_key_value(answer))
            .filter(move |(_, row)| row.record == record)
    }

    /// What `cell` has to read at a boundary for a deletion to be made
    /// of it, if an answer's deletion reads it: a committed marker
    /// present, as `true`, and a record or a row leaf absent.
    fn deleting(&self, cell: SubstateKey) -> Option<bool> {
        self.readers_of(cell).next().map(|row| row.marker == cell)
    }

    /// Note every cell of the answers reading `cell` as one whose
    /// readings are to be judged again.
    fn unread_with(&mut self, cell: SubstateKey) {
        let cells: Vec<SubstateKey> = self
            .readers_of(cell)
            .flat_map(|row| [row.record, row.row, row.marker])
            .collect();
        self.unread.extend(cells);
        self.unread.insert(cell);
    }

    /// Whether `key` is the `Taken` of a record this shard holds for a
    /// consumer elsewhere: a key read only at the consumer's boundaries,
    /// whose fresh reading retires nothing.
    fn retires_on(&self, key: SubstateKey) -> bool {
        self.answer_asks
            .get(&key)
            .is_some_and(|ask| ask.answered == Answered::Taken)
    }

    /// Whether an answer's deletion, or a record's retirement or return,
    /// reads `cell` at `anchor`.
    fn reads_at(&self, anchor: &Anchor, cell: SubstateKey) -> bool {
        self.readers_of(cell)
            .any(|row| row.holder == anchor.shard && row.cells(anchor).contains(&cell))
            || self
                .answer_asks
                .get(&cell)
                .is_some_and(|ask| ask.holder == anchor.shard)
    }

    /// Whether a deletion, a retirement or a return can still be made at
    /// `anchor` of a reading of `cell`, with `refuted` read there the
    /// way none needs.
    fn needed_at(
        &self,
        anchor: &Anchor,
        cell: SubstateKey,
        refuted: &BTreeSet<SubstateKey>,
    ) -> bool {
        self.readers_of(cell).any(|row| {
            row.holder == anchor.shard && {
                let cells = row.cells(anchor);
                cells.contains(&cell) && !cells.iter().any(|read| refuted.contains(read))
            }
        }) || self
            .answer_asks
            .get(&cell)
            .is_some_and(|ask| ask.holder == anchor.shard && !refuted.contains(&cell))
    }
}

/// The readings held at one boundary anchor.
#[derive(Debug)]
struct BoundaryReadings {
    /// The claims held, ascending, the spans of their keys disjoint: one
    /// anchor's readings as a block carries them. Every cell reads the
    /// way a deletion needs it.
    claims: Vec<StateClaim>,
    /// The cells those claims read.
    cells: BTreeSet<SubstateKey>,
    /// The cells that read here the way no deletion needs: a record
    /// present, a row standing, a marker absent. An answer whose
    /// deletion reads one is not deleted at this anchor.
    refuted: BTreeSet<SubstateKey>,
    /// The cells asked here whose reading has not come back.
    pending: BTreeSet<SubstateKey>,
    /// The committed clock the anchor was first asked at.
    asked_at: WeightedTimestamp,
    /// Whether a reading is or was held here that no commit has yet
    /// found gone: what the drain's gauge is read off, and nothing else.
    draining: bool,
}

impl BoundaryReadings {
    /// Drop the held cells `gone` names, each claim reading one cut to
    /// the rest with its proof.
    ///
    /// A claim is cut only where a dropped cell falls inside its span,
    /// read off the span's two ends rather than its cells.
    fn drop_cells(&mut self, gone: &BTreeSet<SubstateKey>) {
        if gone.is_empty() {
            return;
        }
        let span = |claim: &StateClaim| {
            claim
                .cells
                .first()
                .zip(claim.cells.last())
                .map(|((lo, _), (hi, _))| (*lo, *hi))
        };
        self.claims = std::mem::take(&mut self.claims)
            .into_iter()
            .filter_map(|claim| match span(&claim) {
                Some((lo, hi)) if gone.range(lo..=hi).next().is_some() => {
                    claim.restrict(|key| !gone.contains(&key))
                }
                _ => Some(claim),
            })
            .collect();
        for key in gone {
            self.cells.remove(key);
        }
    }
}

/// The readings held at the boundaries the beacon recorded for other
/// shards, each of which goes toward deleting an answer of this shard's,
/// or retiring or returning a record of this shard's.
///
/// Held apart from every other claim. A boundary is the oldest anchor a
/// producer is read at and an epoch's deletions become readable at one
/// beacon fold, so offered in a producer's anchor order they would take
/// the claims section ahead of every reading a member waits on. Nothing
/// waits on a deletion, and no floor a fresh claim raises refuses a
/// boundary reading, so they are offered last and in what the rest
/// leaves. A boundary reading also retires a record, and a retirement is
/// what lets its consumer delete the answer.
#[derive(Debug, Default)]
struct BoundaryClaims {
    /// What is held, refuted and awaited at each anchor asked at.
    at: BTreeMap<Anchor, BoundaryReadings>,
}

impl BoundaryClaims {
    /// The cells asked at `anchor` whose reading has not come back, if
    /// anything was asked there.
    fn pending(&self, anchor: &Anchor) -> Option<&BTreeSet<SubstateKey>> {
        self.at.get(anchor).map(|at| &at.pending)
    }

    /// The cells held at `anchor`.
    #[cfg(test)]
    fn cells(&self, anchor: &Anchor) -> BTreeSet<SubstateKey> {
        self.at
            .get(anchor)
            .map_or_else(BTreeSet::new, |at| at.cells.clone())
    }

    /// Note `cells` asked at `anchor`, at the committed clock `now`.
    fn ask(
        &mut self,
        anchor: Anchor,
        now: WeightedTimestamp,
        cells: impl IntoIterator<Item = SubstateKey>,
    ) {
        self.at
            .entry(anchor)
            .or_insert_with(|| BoundaryReadings {
                claims: Vec::new(),
                cells: BTreeSet::new(),
                refuted: BTreeSet::new(),
                pending: BTreeSet::new(),
                asked_at: now,
                draining: false,
            })
            .pending
            .extend(cells);
    }

    /// Take what came back for `arrived`, cells asked at `anchor`:
    /// `refuted` the ones that prove nothing, and `claim` the rest, held
    /// cut to the cells no held claim at the anchor reads already.
    ///
    /// The claims at the anchor stay one key-ordered list in disjoint
    /// spans. A claim that comes back from the anchor's one sorted ask is
    /// a span of it already; one whose cells straddle a held claim's, as
    /// a fetch asked again brings them, is cut with that claim into
    /// spans, and no other held claim is touched.
    fn hold(
        &mut self,
        anchor: Anchor,
        arrived: &BTreeSet<SubstateKey>,
        claim: Option<StateClaim>,
        refuted: BTreeSet<SubstateKey>,
    ) {
        let Some(at) = self.at.get_mut(&anchor) else {
            return;
        };
        at.pending.retain(|key| !arrived.contains(key));
        at.refuted.extend(refuted);
        let Some(fresh) = claim.and_then(|claim| claim.restrict(|key| !at.cells.contains(&key)))
        else {
            return;
        };
        at.draining = true;
        at.cells.extend(fresh.keys());
        let span = |claim: &StateClaim| {
            claim
                .cells
                .first()
                .zip(claim.cells.last())
                .map(|((lo, _), (hi, _))| (*lo, *hi))
        };
        let reach = span(&fresh);
        let (straddling, mut apart): (Vec<StateClaim>, Vec<StateClaim>) =
            std::mem::take(&mut at.claims)
                .into_iter()
                .partition(|held| {
                    span(held)
                        .zip(reach)
                        .is_some_and(|((lo, hi), (from, to))| lo <= to && from <= hi)
                });
        apart.extend(in_disjoint_spans(straddling.into_iter().chain([fresh])));
        apart.sort_unstable_by_key(|claim| claim.cells.first().map(|(key, _)| *key));
        at.claims = apart;
    }

    /// Keep the anchors `stands` answers for, and at each the cells an
    /// answer still `reads` there, held only where one is still `needed`
    /// for a deletion against what is refuted there; of the cells
    /// `judged` names where it names any, and of every cell otherwise.
    /// Hands back the cells still asked for that nothing needs any more,
    /// for their fetches to be let go, and the clock each anchor was
    /// asked at whose held readings have now all gone.
    fn settle(
        &mut self,
        stands: impl Fn(&Anchor) -> bool,
        judged: Option<&BTreeSet<SubstateKey>>,
        reads: impl Fn(&Anchor, SubstateKey) -> bool,
        needed: impl Fn(&Anchor, SubstateKey, &BTreeSet<SubstateKey>) -> bool,
    ) -> (Vec<(Anchor, SubstateKey)>, Vec<WeightedTimestamp>) {
        let mut released = Vec::new();
        let mut drained = Vec::new();
        self.at.retain(|anchor, at| {
            let standing = stands(anchor);
            let BoundaryReadings {
                pending, refuted, ..
            } = at;
            let gone: Vec<SubstateKey> = match judged {
                _ if !standing => pending.iter().copied().collect(),
                Some(judged) => judged
                    .iter()
                    .filter(|key| pending.contains(key) && !needed(anchor, **key, refuted))
                    .copied()
                    .collect(),
                None => pending
                    .iter()
                    .filter(|key| !needed(anchor, **key, refuted))
                    .copied()
                    .collect(),
            };
            for key in gone {
                pending.remove(&key);
                released.push((*anchor, key));
            }
            let unneeded: BTreeSet<SubstateKey> = match judged {
                _ if !standing => at.cells.clone(),
                Some(judged) => judged
                    .iter()
                    .filter(|key| at.cells.contains(key) && !needed(anchor, **key, &at.refuted))
                    .copied()
                    .collect(),
                None => at
                    .cells
                    .iter()
                    .filter(|key| !needed(anchor, **key, &at.refuted))
                    .copied()
                    .collect(),
            };
            match judged {
                Some(judged) => {
                    let unread: Vec<SubstateKey> = judged
                        .iter()
                        .filter(|key| at.refuted.contains(key) && !reads(anchor, **key))
                        .copied()
                        .collect();
                    for key in unread {
                        at.refuted.remove(&key);
                    }
                }
                None => at.refuted.retain(|key| reads(anchor, *key)),
            }
            at.drop_cells(&unneeded);
            if at.draining && at.claims.is_empty() && at.pending.is_empty() {
                at.draining = false;
                drained.push(at.asked_at);
            }
            standing
        });
        (released, drained)
    }

    /// Cut from the claims held at each anchor the cells `carried` names
    /// there.
    fn cut(&mut self, carried: &BTreeMap<Anchor, BTreeSet<SubstateKey>>) {
        for (anchor, keys) in carried {
            if let Some(at) = self.at.get_mut(anchor) {
                at.drop_cells(keys);
            }
        }
    }
}

/// Whether a key of `keys` falls inside `claim`'s span of keys.
fn meets(claim: &StateClaim, keys: &BTreeSet<SubstateKey>) -> bool {
    claim
        .cells
        .first()
        .zip(claim.cells.last())
        .is_some_and(|((lo, _), (hi, _))| keys.range(*lo..=*hi).next().is_some())
}

/// `claims`, all at one anchor, as one key-ordered list cut into claims
/// whose key spans are disjoint: the form a block carries one anchor's
/// readings in. A cell two of them read is kept in the first.
///
/// A claim whose cells straddle another's is cut at each cell of the
/// other's that falls inside it, its proof cut with it, and one whose
/// span meets no other's passes through whole.
fn in_disjoint_spans(claims: impl IntoIterator<Item = StateClaim>) -> Vec<StateClaim> {
    let claims: Vec<StateClaim> = claims.into_iter().collect();
    let mut reads: BTreeMap<SubstateKey, usize> = BTreeMap::new();
    for (at, claim) in claims.iter().enumerate() {
        for key in claim.keys() {
            reads.entry(key).or_insert(at);
        }
    }
    let mut spans: Vec<(usize, BTreeSet<SubstateKey>)> = Vec::new();
    for (key, at) in reads {
        match spans.last_mut() {
            Some((last, span)) if *last == at => {
                span.insert(key);
            }
            _ => spans.push((at, BTreeSet::from([key]))),
        }
    }
    spans
        .into_iter()
        .filter_map(|(at, span)| claims[at].restrict(|key| span.contains(&key)))
        .collect()
}

/// Whether any leaf-driven question of this shard's wants a reading of
/// `key`: the answer to a record whose two ends are here, or a record a
/// consumer here waits on. An answer to a record whose consumer another
/// shard holds is read only at that shard's boundaries, apart from every
/// other reading.
///
/// Two sites need exactly this set: a fetch that lands is offered in a
/// block only if something here wants it, and a reading held to offer is
/// kept only while something here wants it. None of these questions
/// names a transaction of this chain's, which is why the keys are read
/// rather than the names.
fn wants_reading(
    awaited: &BTreeSet<SubstateKey>,
    wanted: &BTreeSet<SubstateKey>,
    key: SubstateKey,
) -> bool {
    awaited.contains(&key) || wanted.contains(&key)
}

/// Whether `claim` holds at `key` an owed record this shard's commit
/// fold would credit: one whose consumer sits under `local`'s prefix and
/// for which no `Taken` of its transaction stands at the persisted tip.
///
/// Nothing here asks about such a record — the shard runs no member of
/// its transaction — so a push of it is kept on this rule alone, until
/// the fold's `Taken` lands. A `Taken` of another transaction answered
/// a record that stood at this key before, and the fold credits past
/// it.
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
                && !index
                    .cell(crossing.id.answer_key(&ProtocolHasher, Answered::Taken))
                    .is_some_and(|value| {
                        Issuer::from(&cell).answered_by(&crossing.id, Answered::Taken, &value)
                    }) =>
        {
            Some(crossing.id)
        }
        _ => None,
    }
}

/// The most escrowed records nothing here asked for that are held to
/// offer at once for one producing lineage, and the most a producer
/// pushes again to one consumer's shard at one height.
const MAX_UNSOLICITED_RECORDS_PER_PRODUCER: usize = 16;

/// The record `claim` holds at `key` with its value, and its crossing.
fn held_record(claim: &StateClaim, key: SubstateKey) -> Option<(CrossingId, CrossingCell)> {
    match CrossingLeaf::read(&ProtocolHasher, key, claim.held(key)?)? {
        CrossingLeaf::Record { crossing, cell } => Some((crossing.id, cell)),
        CrossingLeaf::Answer { .. } => None,
    }
}

/// Whether `cell` is an escrowed record for a consumer under `local`'s
/// prefix whose transaction's validity end `now` has reached.
///
/// From that end no block here admits the record's transaction, so no
/// member comes to want the record that does not want it already.
fn past_its_taking(cell: &CrossingCell, local: ShardId, now: WeightedTimestamp) -> bool {
    matches!(cell.terms, Terms::Escrowed { .. })
        && ShardTrie::shard_owns_prefix(local, cell.consumer)
        && now >= WeightedTimestamp::from_millis(cell.validity_end_ms)
}

/// Whether a block `local`'s chain commits at `now` could decline the
/// escrowed record `cell` of `id`, as far as the persisted tip says: the
/// record's consumer sits under `local`'s prefix, `now` has reached its
/// transaction's validity end, no answer of its transaction stands, and
/// no member row of its transaction stands on `local`.
///
/// These are the terms the fold declines on, read here where the fold
/// reads them at the block's parent. A row absent past the end stays
/// absent. A row standing is a member that may yet take the record: one
/// waiting on its arrival, one holding it, or one a tick has run and
/// not yet settled. A reading of the record declines nothing while it
/// stands, and the record is pushed again once it is gone. An answer of
/// the transaction is the take or the decline already made. An answer
/// of another transaction answered a record that stood at this key
/// before.
fn declinable_here(
    id: &CrossingId,
    cell: &CrossingCell,
    local: ShardId,
    now: WeightedTimestamp,
    index: &dyn CrossingIndex,
) -> bool {
    let answered = |answered: Answered| {
        index
            .cell(id.answer_key(&ProtocolHasher, answered))
            .is_some_and(|value| Issuer::from(cell).answered_by(id, answered, &value))
    };
    past_its_taking(cell, local, now)
        && !answered(Answered::Taken)
        && !answered(Answered::Never)
        && !index.present(member_row_leaf(local, cell.tx))
}

/// The crossing and issuer of the escrowed record `claim` holds at
/// `key`, where a block `local`'s chain commits at `now` could decline
/// it ([`declinable_here`]).
///
/// Nothing here asks for the reading a decline is written on, so a push
/// of such a record is kept on this rule alone, until the fold's `Never`
/// lands.
fn escrowed_here(
    claim: &StateClaim,
    key: SubstateKey,
    local: ShardId,
    now: WeightedTimestamp,
    index: &dyn CrossingIndex,
) -> Option<(CrossingId, Issuer)> {
    let (id, cell) = held_record(claim, key)?;
    declinable_here(&id, &cell, local, now, index).then_some((id, Issuer::from(&cell)))
}

/// How many escrowed records `block` declines on `local`, as its own
/// content reads: a record held for a consumer here, at or past its
/// transaction's validity end, beside that transaction's member row read
/// absent at the parent.
///
/// The fold also leaves alone a record its transaction already answered
/// at the parent, which only the parent's state says and the commit
/// stream carries none of. A proposer reads a row only beside a record
/// that fold declines, so this counts past the fold's writes only where
/// one transaction issued two records here and one already stands
/// answered, or where a block reads a row no decline of it needs.
fn declined_in(block: &Block, local: ShardId) -> usize {
    let anchor = block.header().parent_qc().weighted_timestamp();
    unclaimed_records(block.state_claims(), local)
        .iter()
        .filter(|(_, cell)| {
            let row = member_row_leaf(local, cell.tx);
            anchor >= WeightedTimestamp::from_millis(cell.validity_end_ms)
                && block.state_claims().iter().any(|claim| {
                    claim.anchor.shard == local && claim.reading(row) == Some(Inclusion::Absent)
                })
        })
        .count()
}

/// Whether one of two shards is the other or an ancestor of it: one
/// producing lineage, whose readings raise one another's floors.
fn one_lineage(a: ShardId, b: ShardId) -> bool {
    a == b || a.is_ancestor_of(b) || b.is_ancestor_of(a)
}

/// The cells of `claim` the read frontier fences below its floor: the
/// ones held with a value that reads as a crossing record.
fn fenced_cells(claim: &StateClaim) -> impl Iterator<Item = SubstateKey> + '_ {
    claim.cells.iter().filter_map(|(key, stated)| {
        matches!(
            CrossingLeaf::read(&ProtocolHasher, *key, stated.held()?),
            Some(CrossingLeaf::Record { .. })
        )
        .then_some(*key)
    })
}

/// One fetch per anchor, asking every key `wanted` names at it once.
fn fetches(wanted: BTreeMap<Anchor, Vec<SubstateKey>>) -> Vec<Action> {
    wanted
        .into_iter()
        .map(|(anchor, mut keys)| {
            let mut asked = BTreeSet::new();
            keys.retain(|key| asked.insert(*key));
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
/// header it was asked at, and whether the fetch has returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    question: Question,
    anchor: Anchor,
    returned: bool,
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
    /// The `Taken` keys of the records the commit's read put up: every
    /// record carried on a whole read, and on a read of the changes every
    /// record row it wrote. A held push naming one is placed again, so a
    /// push that landed before its record was carried here paces the
    /// record's re-push.
    pub(crate) carried: Vec<SubstateKey>,
}

/// What this validator holds to offer in a block it proposes.
pub struct Offers {
    /// Claims its own fetches proved that no block has carried yet, in
    /// the one order a block carries them.
    pub state_claims: Vec<StateClaim>,
    /// The claims it holds for its rows' verdict questions, which a
    /// block carries in what the others and the local crossings leave
    /// of its claims section, and never in less than the bytes and the
    /// places verdict claims have to themselves.
    pub verdict_claims: Vec<StateClaim>,
    /// The readings it holds at the boundaries the beacon recorded for
    /// other shards, by anchor with the records of this shard's each
    /// returns and the answers each deletes, the anchor closest to
    /// leaving the schedule first. A block carries them after every
    /// other claim, in what those leave.
    pub boundary_claims: Vec<BoundaryOffer>,
    /// The readings it holds at the same boundaries that retire records
    /// of this shard's, by anchor, one consumer's `Taken` an item. A
    /// boundary reading is what retires a record, and a retirement is
    /// what lets its consumer delete the answer, so these are offered
    /// apart from the deletions and the returns.
    pub retirement_claims: Vec<BoundaryOffer>,
    /// The records it has evidence for and has not yet written down.
    pub abandonment_records: Vec<AbandonmentRecord>,
    /// The crossings whose two ends share this shard and whose
    /// settlement the rows say is due, for the block to read at its
    /// parent: a record whose answer reads present here, and an answer
    /// whose record routes here and reads absent. A record taken back on
    /// a `Never` read at a boundary is read there too, as part of the
    /// boundary offer that carries the `Never`.
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

    /// The crossing rows of this shard's and what each puts: the
    /// questions the records put of their consumers, the answers whose
    /// deletion is read at a boundary, the returns read there, and the
    /// crossings whose two ends are here.
    rows: CrossingRows,

    /// The boundary each holder was last asked at, for the answers this
    /// shard holds whose record it holds and the declines it holds of
    /// records here: each asks once per boundary the head publishes for
    /// that shard. Node-local pacing, so a restarted replica asks at the
    /// boundary then published.
    boundary_asked: BTreeMap<ShardId, Anchor>,

    /// The readings held at those boundaries, apart from every other
    /// held claim.
    boundaries: BoundaryClaims,

    /// Each carried record's re-push pacing ([`Repush`]): node-local, so
    /// a new account seeds what it can of it at its first read of the
    /// rows. One entry at most per carried record.
    repushed: BTreeMap<SubstateKey, Repush>,

    /// Whether the rows have been read since this account was built: the
    /// first read seeds a pause on every record already due, which a push
    /// this account never saw may have answered.
    seeded: bool,

    /// The committed clock as of the last commit or push: what an
    /// escrowed record's validity end is read against where no caller
    /// hands a clock in.
    clock: WeightedTimestamp,

    /// The read frontier as the committed chain leaves it: how far
    /// along each producer this shard has read, the copy the fold's own
    /// rule advances here at every commit. Read to drop the record
    /// presences held to offer below it.
    frontier: ReadFrontier,

    /// The records a consumer here waits on with no arrival for, as of
    /// the last commit: the candidates' filed requirements and the
    /// pool's delivering bodies. What a fetched or pushed reading of a
    /// record is kept to offer against.
    wanted: BTreeSet<SubstateKey>,

    /// Each of `wanted` with the transaction whose member waits on it.
    /// A record is an arrival only for the transaction that issued it,
    /// so a record another transaction left at a wanted key is one
    /// nothing here waits on.
    wanted_of: BTreeSet<(SubstateKey, TxHash)>,

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

    /// The verdict leaves of the questions that first stood at the last
    /// standing: what a push parked ahead of its question is released
    /// by. Replaced at every standing, so no more than the questions.
    stood: Vec<SubstateKey>,
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
            rows: CrossingRows::default(),
            boundary_asked: BTreeMap::new(),
            boundaries: BoundaryClaims::default(),
            repushed: BTreeMap::new(),
            seeded: false,
            clock: WeightedTimestamp::ZERO,
            frontier,
            wanted: BTreeSet::new(),
            wanted_of: BTreeSet::new(),
            records: RecordReads::new(),
            local_crossings: BTreeSet::new(),
            probes: BTreeMap::new(),
            seats: BTreeMap::new(),
            verdicts: BTreeMap::new(),
            verdict_leaves: BTreeMap::new(),
            verdict_asked: BTreeMap::new(),
            heard: HeardClaims::default(),
            stood: Vec::new(),
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
        self.clock = now;
        self.gc_settled_sets(topology_schedule, now);
        self.want(wanted);
        set_wanted_records(self.wanted.len());
        // What the block's claims settle is marked gone on the entry that
        // issued it, as the fold removes it from state: a record removed
        // on its consumer's `Taken` of the entry's transaction closes
        // that entry's share.
        let local = self.ledger.local();
        let block_anchor = block.header().parent_qc().weighted_timestamp();
        let retired: Vec<(SubstateKey, TxHash)> = block
            .state_claims()
            .iter()
            .flat_map(|claim| claim.retires(local, block_anchor, |id| self.ledger.issuers_of(id)))
            .collect();
        for (record, tx_hash) in retired {
            self.ledger.settled(record, tx_hash);
        }
        // What the fold takes back is marked returned on the entry that
        // issued it: a record returned on its consumer's `Never` closes
        // that entry's share as an abort.
        let returned = reclaimed(block.state_claims(), local, block_anchor);
        record_reclaim_folded(returned.len());
        record_decline_folded(declined_in(block, local));
        for (record, cell) in returned {
            self.ledger.returned(record, cell.tx);
        }
        // The reads still worth pacing: the records something here
        // waits on.
        self.records.sweep(now, &self.wanted);
        self.count_carried(block);
        // A reading the chain now carries is everybody's: its answers
        // are folded here, and nothing offers it again. Retired by key
        // from every held claim at the anchor, so a claim another
        // proposer cut differently leaves only what the block carried,
        // and the remainder of a cut claim is offered whole.
        self.cut_carried(&CarriedClaims::of(
            self.ledger.local(),
            block.state_claims(),
        ));
        self.fold_state_claims(block);
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
        // a delivery finalized in one block close together. A leg whose
        // row the block fates closes as its abort.
        let mut settled: Vec<(TxHash, TxResolution)> = block
            .tick_manifest()
            .iter()
            .filter_map(|line| match line {
                TickLine::Fate { tx, .. } => self.ledger.fated(*tx),
                TickLine::Member { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
            })
            .collect();
        settled.extend(self.ledger.closes());
        let unanswerable = self.ledger.prune(now);
        // The frontier as this block leaves it, after the licence above
        // read the floor its parent left; then what the raise refuses
        // of the claims held to offer.
        self.frontier
            .advance(&FrontierInputs::of_block(block, windows));
        self.drop_below_floor(windows);
        let carried = self.derive_asks(trie);
        actions.extend(self.settle_boundaries(topology_schedule, now));
        actions.extend(self.release_answered_fetches());
        self.cap_held_unsolicited();
        // The committed clock is what opens a leg's deadline, so the
        // cores gone silent past it are asked here.
        actions.extend(self.probe(trie, now, wanted, windows));
        actions.extend(self.ask_boundaries(topology_schedule, now));
        CommitFolded {
            actions,
            unanswerable,
            settled,
            carried,
        }
    }

    /// Cut from the held claims what `carried`, a committed block's
    /// claims, carried at each anchor.
    ///
    /// A claim naming members is read by the rows it names and by
    /// nothing else, so its cells are not among `carried`'s and are cut
    /// from no held claim: a seat or exit reading over the same row or
    /// leaf at that anchor is still owed to a block whole. What is held
    /// for a verdict question goes by its row's entry alone, where the
    /// questions are stood.
    fn cut_carried(&mut self, carried: &CarriedClaims) {
        if !carried.cells().is_empty() {
            self.fetched.cut(carried.cells());
        }
        // A deletion a block carried is not offered again. The row and
        // the marker read beside it stay held: another answer of the
        // same transaction reads them too.
        self.boundaries.cut(carried.deleted());
    }

    /// Whether this validator's re-push of `record` stands paused.
    #[cfg(test)]
    pub(crate) fn repush_paused(&self, record: SubstateKey) -> bool {
        self.repushed
            .get(&record)
            .is_some_and(|repush| repush.paused_from.is_some())
    }

    /// Whether the records here ask `answer` at their consumers'
    /// boundaries.
    #[cfg(test)]
    pub(crate) fn asks_at_boundaries(&self, answer: SubstateKey) -> bool {
        self.rows.answer_asks.contains_key(&answer)
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

    /// What this validator holds to offer in a block it proposes,
    /// passing over what `carried`, the chain from the folded tip to the
    /// block's parent, carries: a fetched cell at the anchor it was
    /// carried at, an answer whose record was deleted at any anchor, a
    /// `Never` read present, and a crossing read at a parent. Each comes
    /// back once its carrier folds, where the fold has not retired it.
    #[must_use]
    pub(crate) fn offers(&self, carried: &CarriedClaims) -> Offers {
        let (boundary_claims, retirement_claims) = self.boundary_claims(carried);
        Offers {
            state_claims: self.state_claims(carried),
            verdict_claims: self.verdict_claims(),
            boundary_claims,
            retirement_claims,
            abandonment_records: self.abandonment_records(),
            local_crossings: self
                .local_crossings
                .iter()
                .filter(|id| !carried.reads_locally(id))
                .copied()
                .collect(),
        }
    }

    /// Ask each counterpart what this shard waits on it for.
    ///
    /// Two questions, each from the instant it opens. A core member
    /// asks each sibling's committed cell past the transaction's
    /// deadline: any one read absent inside its window is the whole
    /// answer, while a sibling that still holds its cell included the
    /// transaction and answers with its certificate, so it is asked
    /// again at each newer header ([`Self::ask_entries`]). A record a
    /// member here waits on is read off its producer
    /// ([`Self::ask_wanted_records`]). Each is asked against that shard's
    /// newest commit-proven header the question stands at, of those
    /// standing at `now`, the chain's committed clock.
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
    /// The cell is named from signed content and the counterpart shard
    /// alone, so nothing but the header and the proof is fetched.
    pub(crate) fn probe(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        records: &[WantedRecord],
        windows: EpochWindows,
    ) -> Vec<Action> {
        self.want(records);
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        self.ask_entries(now, &mut wanted);
        self.ask_wanted_records(trie, now, records, windows, &mut wanted);
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
            let Some(anchor) = self.proven_anchors.newest_licensed(question.shard, now, ..) else {
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
        now: WeightedTimestamp,
        wanted: &mut BTreeMap<Anchor, Vec<SubstateKey>>,
    ) {
        for question in self.ledger.questions() {
            if !question.open_at(now) {
                continue;
            }
            let Question { shard, key, .. } = question;
            // The newest header the question stands at, of those
            // standing at the chain's clock: the one the shard is
            // likeliest to still serve, and the one every member of
            // this committee is asking of.
            let Some(anchor) =
                self.proven_anchors
                    .newest_licensed(shard, now, question.asked_within())
            else {
                continue;
            };
            // A question in flight, one whose answer this validator
            // holds to offer and one the chain answered are left alone:
            // a core's header lands every block, and moving a probe to
            // each new one abandons the fetch before its answer
            // returns. A probe whose fetch returned a reading that
            // answered nothing is moved on, which is how a cell read
            // present is asked again — at a newer header, not of the
            // same one every block. A core's cell has no push
            // to stand in for, so it is asked at every newer header.
            let prior = self.probes.get(&(shard, key)).copied();
            if self.fetched.reads(shard, key)
                || prior.is_some_and(|probe| {
                    !probe.returned || anchor.height.inner() <= probe.anchor.height.inner()
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
                },
            );
            wanted.entry(anchor).or_default().push(key);
        }
    }

    /// The questions this shard's crossing rows put, moved by the rows
    /// the index has written or removed since the last commit, keeping
    /// the pacing of every question that still stands; and the local
    /// crossings a settlement is due for.
    ///
    /// A record row asks for its consumer's claim key, of whichever shard
    /// holds the key's prefix, and an escrowed one whose credit cell is
    /// under this shard's prefix reads its consumer's decline key at each
    /// boundary the beacon records for that shard.
    /// An answer row asks nothing of a fresh header: it reads its
    /// record's key and its producing member's exit at each boundary the
    /// beacon records for the shard holding the record. Both boundary
    /// readings are [`Self::ask_boundaries`]'. A key that
    /// routes here is never asked. A crossing whose two ends are here is
    /// offered for the block to read at its parent: an owed record, an
    /// escrowed record an answer of its transaction stands for or that
    /// the fold could decline, and an answer whose record reads absent.
    ///
    /// Every record is asked about, whether or not an entry of the
    /// ledger's issued it: the row is what stands for as long as the
    /// record does. An answer is written only while its record stands
    /// and goes only once the record reads absent, so no window bounds
    /// the question: a consumer that halts can write its answer after
    /// recovering, and a return a recovery discards is made again on the
    /// next reading.
    ///
    /// Returns the `Taken` keys of the records this read put up, which a
    /// push that ran ahead of a record's commit here may carry.
    pub(crate) fn derive_asks(&mut self, trie: &ShardTrie) -> Vec<SubstateKey> {
        let local = self.ledger.local();
        let (read, cursor) = self.index.crossing_changes(local, self.rows.since(trie));
        self.rows.take(trie, local, read, cursor);
        set_standing_answers(local.inner(), self.rows.standing, self.rows.standing_bytes);
        let carried = &self.rows.carried;
        self.repushed
            .retain(|record, _| carried.contains_key(record));
        if !std::mem::replace(&mut self.seeded, true) {
            for (record, carried) in &self.rows.carried {
                if self.clock < carried.due_from {
                    continue;
                }
                let paused = &mut self.repushed.entry(*record).or_default().paused_from;
                if paused.is_none() {
                    *paused = Some(self.clock);
                    record_repush_paused("seeded");
                }
            }
        }
        let settling: BTreeSet<CrossingId> = self
            .rows
            .settling
            .values()
            .filter(|(id, cell)| self.settles_at_the_parent(id, cell))
            .map(|(id, _)| *id)
            .chain(
                self.rows
                    .closing
                    .values()
                    .filter(|(_, record)| !self.index.present(*record))
                    .map(|(id, _)| *id),
            )
            .collect();
        self.local_crossings = settling;
        std::mem::take(&mut self.rows.newly_carried)
    }

    /// Take `records` as what consumers here wait on from now.
    fn want(&mut self, records: &[WantedRecord]) {
        self.wanted = records.iter().map(|record| record.key).collect();
        self.wanted_of = records
            .iter()
            .map(|record| (record.key, record.tx))
            .collect();
    }

    /// Whether a block reading `id`'s cells at its parent has something
    /// to settle of the record `cell`, whose consumer this shard holds.
    ///
    /// A record whose consumer a merge brought here is settled by this
    /// shard's own fold, off its reading at the parent: an owed record
    /// credited at once, and an escrowed one retired on its transaction's
    /// `Taken`, taken back on its `Never`, or declined where the fold
    /// could decline it ([`declinable_here`], at the committed clock).
    fn settles_at_the_parent(&self, id: &CrossingId, cell: &CrossingCell) -> bool {
        let answered = |answered: Answered| {
            self.index
                .cell(id.answer_key(&ProtocolHasher, answered))
                .is_some_and(|value| Issuer::from(cell).answered_by(id, answered, &value))
        };
        cell.terms == Terms::Owed
            || answered(Answered::Taken)
            || answered(Answered::Never)
            || declinable_here(
                id,
                cell,
                self.ledger.local(),
                self.clock,
                self.index.as_ref(),
            )
    }

    /// Clear the pause on the record whose `Taken` `key` is, where
    /// `anchor`, a boundary of the key's holder whose read of it is
    /// refuted or let go, is later than the pushed reading: no state of
    /// the holder from there holds that `Taken`.
    fn resume(&mut self, key: &SubstateKey, anchor: &Anchor, outcome: &str) {
        let Some(ask) = self
            .rows
            .answer_asks
            .get(key)
            .filter(|ask| ask.answered == Answered::Taken)
        else {
            return;
        };
        if let Some(entry) = self
            .repushed
            .get_mut(&ask.id.record_key(&ProtocolHasher))
            .filter(|entry| entry.paused_from.is_some_and(|from| anchor.ts > from))
        {
            entry.paused_from = None;
            entry.cleared_at = Some(anchor.ts);
            record_repush_paused(outcome);
        }
    }

    /// The records to push to their consumers again at `height`, by the
    /// shard holding each consumer's prefix under `trie`, ascending.
    ///
    /// A record's consumer settles it only once a reading reaches it,
    /// and past the instant the push opens nothing there asks. An owed
    /// record is credited by the consumer's fold, whose shard runs no
    /// member of the transaction, and is pushed again from its deadline.
    /// An escrowed record no member took is declined by the consumer's
    /// fold from its transaction's validity end, and is pushed again
    /// from that end and no sooner: before it a member there may still
    /// take the record, and asks for it. Each is pushed at this shard's
    /// heights `h, h+1, h+3, h+7, ...` with the gap capped at
    /// [`MAX_ANSWER_ASK_GAP`], for as long as it stands, which is until
    /// the fold here reads the consumer's answer attested: at a boundary
    /// of the consumer's shard, or at this shard's own parent.
    ///
    /// At most [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`] escrowed records
    /// go to one shard at one height, which is what that shard holds of
    /// them at once. The ones pushed longest ago go first, a record
    /// never pushed before any, so the places rotate over every record
    /// standing; one left out is due at the next height.
    ///
    /// A record whose consumer's fresh `Taken` a push brought is paused
    /// ([`Repush`]) and passed over before the escrowed count, so it
    /// takes no place under the cap.
    ///
    /// The pacing is taken as the push is, so a call only a proposer
    /// makes paces only its own pushes.
    pub(crate) fn record_repushes(
        &mut self,
        trie: &ShardTrie,
        now: WeightedTimestamp,
        height: BlockHeight,
    ) -> BTreeMap<ShardId, Vec<SubstateKey>> {
        let mut due: Vec<(Option<BlockHeight>, WeightedTimestamp, SubstateKey, u32)> = Vec::new();
        for (record, carried) in &self.rows.carried {
            if now < carried.due_from {
                continue;
            }
            let entry = self.repushed.entry(*record).or_default();
            if !entry.found_due {
                entry.found_due = true;
                record_repush_due(entry.paused_from.is_some());
            }
            if entry.paused_from.is_some() {
                continue;
            }
            let (at, times) = entry.last.unzip();
            let times = times.unwrap_or(0);
            if at.is_none_or(|at: BlockHeight| height.inner() >= at.inner() + answer_ask_gap(times))
            {
                due.push((at, carried.due_from, *record, times));
            }
        }
        due.sort_unstable();
        let mut targets: BTreeMap<ShardId, Vec<SubstateKey>> = BTreeMap::new();
        let mut unsolicited: BTreeMap<ShardId, usize> = BTreeMap::new();
        for (_, _, record, times) in due {
            let carried = self.rows.carried[&record];
            let target = trie.shard_for_prefix(carried.id.consumer);
            if carried.escrowed {
                let sent = unsolicited.entry(target).or_default();
                if *sent == MAX_UNSOLICITED_RECORDS_PER_PRODUCER {
                    continue;
                }
                *sent += 1;
            }
            let entry = self.repushed.entry(record).or_default();
            entry.last = Some((height, times.saturating_add(1)));
            let kind = if carried.escrowed { "escrowed" } else { "owed" };
            record_records_repushed(kind, entry.cleared_at.is_some());
            targets.entry(target).or_default().push(record);
        }
        for records in targets.values_mut() {
            records.sort_unstable();
        }
        targets
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
            .newest_licensed(shard, now, ..)
            .filter(|anchor| !self.frontier.refuses(shard, ReadMark::of(anchor, windows)))
    }

    /// The answers this shard holds ask, once per boundary the head
    /// publishes for the shard holding each one's record: is the record
    /// gone there, and has its producing member exited? And the records
    /// it holds ask, once per boundary the head publishes for the shard
    /// holding each answer key: has the consumer answered it, `Taken` or,
    /// for an escrowed one, `Never`?
    ///
    /// Every answer of one holder is asked together at the holder's
    /// boundary, in one key-ordered list of record keys, row leaves,
    /// markers and answer keys, so what comes back is that list cut into
    /// claims. An answer that first stands after its holder's boundary was
    /// asked waits for the next: the boundary then published is older than
    /// the answer and shows nothing of what followed it. An answer key is
    /// asked only at a boundary whose own clock is at or past the earliest
    /// that can show it ([`AnswerAsk::from`]). A record a recovery of this
    /// shard puts back is read whole, since the store starts a new line of
    /// its crossing journal, and is asked at its holder's next boundary.
    /// The cells are asked at the anchor the beacon recorded, whose root
    /// the proof is checked against, so no header of the holder's is needed
    /// and none this validator's schedule does not hold is ever asked at. A
    /// holder whose head record is its terminal is asked nothing, since no
    /// claim stands there: its answers wait for the shard the trie routes
    /// the record to next, and are asked at that shard's boundary.
    fn ask_boundaries(
        &mut self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        let head = topology_schedule.head();
        let holders: BTreeSet<ShardId> = self
            .rows
            .holders
            .keys()
            .copied()
            .chain(self.rows.answer_asks.values().map(|ask| ask.holder))
            .collect();
        self.boundary_asked
            .retain(|holder, _| holders.contains(holder));
        let mut wanted: BTreeMap<Anchor, Vec<SubstateKey>> = BTreeMap::new();
        for holder in holders {
            let Some(boundary) = head
                .boundary(holder)
                .map(|record| record.anchor(holder))
                .filter(|anchor| {
                    topology_schedule.attests_boundary(anchor) == BoundaryAttestation::Stands
                })
            else {
                continue;
            };
            let shows = |ask: &AnswerAsk| ask.holder == holder && boundary.ts >= ask.from();
            if self.boundary_asked.insert(holder, boundary) == Some(boundary) {
                continue;
            }
            let cells: BTreeSet<SubstateKey> = self
                .rows
                .answers
                .values()
                .filter(|row| row.holder == holder)
                .flat_map(|row| row.cells(&boundary))
                .chain(
                    self.rows
                        .answer_asks
                        .iter()
                        .filter(|(_, ask)| shows(ask))
                        .map(|(key, _)| *key),
                )
                .collect();
            if cells.is_empty() {
                continue;
            }
            record_boundary_cells_asked(cells.len());
            self.boundaries.ask(boundary, now, cells.iter().copied());
            wanted.entry(boundary).or_default().extend(cells);
        }
        fetches(wanted)
    }

    /// Keep the boundary readings an answer here can still be deleted
    /// on, or a record here returned on, and let go of the fetches out
    /// for the rest.
    ///
    /// A reading stands while this validator's schedule records its
    /// anchor as a boundary, since a claim at any other is one every
    /// voter refuses or defers, and while an answer row reads its cell
    /// there with nothing read at that anchor that proves the opposite:
    /// a record present, a row standing or a marker absent leaves the
    /// answer to the next boundary. A decline key stands while its
    /// record does, read present as the record's own transaction's
    /// `Never`; anything else read there leaves it to the next boundary.
    fn settle_boundaries(
        &mut self,
        topology_schedule: &TopologySchedule,
        now: WeightedTimestamp,
    ) -> Vec<Action> {
        // Only the cells whose readers moved since the last commit are
        // judged, unless the rows were read whole.
        let rejudge = std::mem::take(&mut self.rows.rejudge);
        let unread = std::mem::take(&mut self.rows.unread);
        let rows = &self.rows;
        let (released, drained) = self.boundaries.settle(
            |anchor| topology_schedule.attests_boundary(anchor) == BoundaryAttestation::Stands,
            (!rejudge).then_some(&unread),
            |anchor, key| rows.reads_at(anchor, key),
            |anchor, key, refuted| rows.needed_at(anchor, key, refuted),
        );
        for asked_at in drained {
            record_boundary_drained(millis(now.elapsed_since(asked_at)));
        }
        for (anchor, key) in &released {
            self.resume(key, anchor, "released");
        }
        if released.is_empty() {
            Vec::new()
        } else {
            vec![Action::AbandonFetch(FetchIds::StateProofs(released))]
        }
    }

    /// Take the readings a proof fetched at `anchor` brings for the
    /// cells still asked there as a boundary's, and hand those cells
    /// back: each held where it reads the way a deletion, a retirement
    /// or a return needs, as one claim cut from the proof to those cells
    /// and naming the crossing of each record read absent and each answer
    /// read present, and noted as refuting its answers' deletion or its
    /// record's retirement or return at this boundary where it reads the
    /// other way. An answer key reads the way its record needs only as
    /// that answer of the transaction whose record stands here. Nothing
    /// is taken at an anchor no boundary was asked at.
    fn hold_boundary_readings(
        &mut self,
        anchor: Anchor,
        inclusions: &[(SubstateKey, Inclusion)],
        proof: &MerkleInclusionProof,
    ) -> BTreeSet<SubstateKey> {
        let asked: BTreeSet<SubstateKey> =
            self.boundaries
                .pending(&anchor)
                .map_or_else(BTreeSet::new, |pending| {
                    inclusions
                        .iter()
                        .map(|(key, _)| *key)
                        .filter(|key| pending.contains(key))
                        .collect()
                });
        if asked.is_empty() {
            return asked;
        }
        let mut proving: Vec<(SubstateKey, Inclusion)> = Vec::new();
        let mut refuted: BTreeSet<SubstateKey> = BTreeSet::new();
        for &(key, inclusion) in inclusions.iter().filter(|(key, _)| asked.contains(key)) {
            let proves = match (
                self.rows.deleting(key).as_ref(),
                self.rows.answer_asks.get(&key),
            ) {
                (Some(present), _) => Some(inclusion.is_present() == *present),
                (None, Some(ask)) => Some(matches!(
                    inclusion,
                    Inclusion::Present(stated)
                        if answer_hashes(&ask.id, Issuer::from(&ask.record), ask.answered)
                            .contains(&stated)
                )),
                (None, None) => None,
            };
            match proves {
                Some(true) => proving.push((key, inclusion)),
                Some(false) => {
                    refuted.insert(key);
                }
                None => {}
            }
        }
        let kept: Vec<SubstateKey> = proving.iter().map(|(key, _)| *key).collect();
        let claim = (!kept.is_empty())
            .then(|| proof.restrict(&kept).ok())
            .flatten()
            .map(|proof| {
                let named: Vec<(SubstateKey, CrossingId)> = kept
                    .iter()
                    .filter_map(|key| self.crossing_of(*key).map(|id| (*key, id)))
                    .collect();
                StateClaim::new(anchor, proving, proof).naming(named)
            });
        // A refuted cell leaves its answers to the next boundary, and
        // what else they read here may be needed by none.
        for key in &refuted {
            self.rows.unread_with(*key);
            self.resume(key, &anchor, "refuted");
        }
        self.boundaries.hold(anchor, &asked, claim, refuted);
        asked
    }

    /// The boundary readings held, by anchor, with the returns and the
    /// deletions each anchor's readings carry whole: every record here
    /// whose consumer's `Never` is held, and every answer whose record,
    /// row leaf and marker, as far as its deletion reads them there, are
    /// all held. The returns go first, since a refund waits on them and
    /// nothing waits on a deletion. The anchor nearest to leaving the
    /// schedule goes first, and a reading whole at two anchors is offered
    /// at the older alone.
    ///
    /// An anchor's deletions are taken in its record keys' order, from
    /// the first whose answer still stands: the records a block deletes
    /// then sit side by side in their producer's tree, and the proofs a
    /// block merges for them share their paths. What the chain to the
    /// parent carries, `carried`, is passed over before the bound below
    /// is charged, so the next block is offered the run after it.
    ///
    /// Apart from those, each anchor's retirements: every record here
    /// whose consumer's `Taken` is held, one item each. A retirement is
    /// what lets its consumer delete the answer, which nothing else
    /// does, so a block spends on retirements by their own rule rather
    /// than behind the deletions.
    ///
    /// What is offered is cut to those cells, and to no more of them, of
    /// each kind, than a block's claims could hold if no proof weighed
    /// anything, so the offer costs a proposal no more than the block it
    /// builds whatever stands behind it. Hands back the returns and
    /// deletions, and the retirements.
    fn boundary_claims(&self, carried: &CarriedClaims) -> (Vec<BoundaryOffer>, Vec<BoundaryOffer>) {
        let mut anchors: Vec<(&Anchor, &BoundaryReadings)> = self
            .boundaries
            .at
            .iter()
            .filter(|(_, at)| !at.claims.is_empty())
            .collect();
        anchors.sort_unstable_by_key(|(anchor, _)| (anchor.ts, **anchor));
        let mut offered: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut room = BOUNDARY_OFFER_CELLS;
        let mut retiring_room = BOUNDARY_OFFER_CELLS;
        let mut offers = Vec::new();
        let mut retirements = Vec::new();
        let cut_to = |at: &BoundaryReadings, items: Vec<Vec<SubstateKey>>| {
            let read: BTreeSet<SubstateKey> = items.iter().flatten().copied().collect();
            BoundaryOffer {
                claims: at
                    .claims
                    .iter()
                    .filter_map(|claim| claim.restrict(|key| read.contains(&key)))
                    .collect(),
                deletions: items,
            }
        };
        for (anchor, at) in anchors {
            let mut returns: Vec<Vec<SubstateKey>> = Vec::new();
            let mut retiring: Vec<Vec<SubstateKey>> = Vec::new();
            for (answer, ask) in &self.rows.answer_asks {
                if ask.holder != anchor.shard
                    || offered.contains(answer)
                    || !at.cells.contains(answer)
                    || carried.answers(*answer)
                {
                    continue;
                }
                let (room, items) = match ask.answered {
                    Answered::Never => (&mut room, &mut returns),
                    Answered::Taken => (&mut retiring_room, &mut retiring),
                };
                if *room == 0 {
                    continue;
                }
                *room -= 1;
                offered.insert(*answer);
                items.push(vec![*answer]);
            }
            if !retiring.is_empty() {
                retirements.push(cut_to(at, retiring));
            }
            'records: for record in &at.cells {
                if carried.deletes(*record) {
                    continue;
                }
                for (answer, row) in self.rows.answers_to(*record) {
                    if row.holder != anchor.shard || offered.contains(answer) {
                        continue;
                    }
                    let cells = row.cells(anchor);
                    if !cells.iter().all(|cell| at.cells.contains(cell)) {
                        continue;
                    }
                    if cells.len() > room {
                        break 'records;
                    }
                    room -= cells.len();
                    offered.insert(*answer);
                    returns.push(cells);
                }
            }
            if !returns.is_empty() {
                offers.push(cut_to(at, returns));
            }
        }
        (offers, retirements)
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
    /// A question is not asked while a reading is held for it above the
    /// row's entry, at an anchor still proven and inside the horizon a
    /// block admits. A reading at an anchor no block could carry is let
    /// go and its question asked again. One in a claim that waits behind
    /// another silences its question as one that rides does, since the
    /// claim it waits behind rides or is let go and a newer reading
    /// would only wait again at its own anchor; but only until the
    /// sibling's headers have run [`MAX_ANSWER_ASK_GAP`] past the
    /// waiting reading's anchor, where the question is asked again and
    /// the newer reading takes its place.
    ///
    /// Toward one sibling one request is out at a time, of at most
    /// [`MAX_VERDICT_ASKS_PER_SIBLING`] questions, each request at a
    /// newer header than the last. So a sibling that never answers holds
    /// one request's places in the fetch and no more, and two claims
    /// fetched from one sibling never sit at one anchor. A request
    /// nothing has answered lapses once the sibling's headers have run
    /// [`MAX_ANSWER_ASK_GAP`] past the one it was put at, or that header
    /// is no longer proven: its fetch is abandoned and its questions are
    /// due again at once, so an answer lost or refused without end
    /// holds the sibling's asks back for that many headers and no
    /// longer. Of the questions due, the ones asked longest ago go
    /// first.
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
        self.stood.clear();
        let mut released = self.stand_down_verdicts(&standing);
        self.judge_heard(now);
        let mut toward: BTreeMap<ShardId, Toward> = BTreeMap::new();
        let mut heard: Vec<((ShardId, TxHash), VerdictCells)> = Vec::new();
        for question in questions {
            let sibling = question.sibling;
            let named = (sibling, question.tx);
            let toward = toward.entry(sibling).or_insert_with(|| Toward {
                newest: self.proven_anchors.newest_licensed(sibling, now, ..),
                out: false,
                due: Vec::new(),
            });
            let ask = self.verdicts.entry(named).or_insert_with(|| {
                let cells = verdict_cells(question);
                self.verdict_leaves.insert(cells.leaf, named);
                self.stood.push(cells.leaf);
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
                Some(held) => {
                    !held.waits
                        || toward.newest.is_none_or(|newest| {
                            !past_ask_gap(newest.height, held.claim.anchor.height)
                        })
                }
                None => false,
            };
            // An ask whose header this validator no longer holds proven
            // is one no peer need still serve, and one the sibling's
            // headers have run the widest ask gap past is one nothing is
            // going to answer: either is let go and put again.
            if let Some(at) = ask.asked_at.filter(|_| !ask.returned) {
                let lapsed = toward
                    .newest
                    .is_some_and(|newest| past_ask_gap(newest.height, at.height));
                if !lapsed && self.proven_anchors.at(at.shard, at.height) == Some(at) {
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
        let mut actions = self.put_verdict_requests(toward);
        if !released.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::VerdictProofs(released)));
        }
        actions
    }

    /// Put one request to each sibling of `toward` that has questions
    /// due, none out, and a header newer than the last one it was asked
    /// at: the questions asked longest ago, as many as a request
    /// carries.
    fn put_verdict_requests(&mut self, toward: BTreeMap<ShardId, Toward>) -> Vec<Action> {
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

    /// The verdict leaves of the questions that first stood at the last
    /// standing.
    pub(crate) fn newly_stood(&self) -> &[SubstateKey] {
        &self.stood
    }

    /// Keep of a pushed claim naming verdicts what the questions
    /// standing here want, and hand back the part worth holding for a
    /// question not standing yet.
    ///
    /// Each member the claim names is judged as a fetched reading is: by
    /// its leaf, with the row and marker where the leaf is absent, and
    /// kept only where [`VerdictQuestion::offers`] holds and no reading
    /// at this mark or a newer one is held for the question already, so
    /// a push at every header leaves one reading a question, the newest.
    /// What is kept is one claim, cut from the pushed one: as many
    /// readings as the push proved together that a question here wants.
    /// A claim that is not a well-formed verdict claim, as
    /// [`StateClaim::is_verdict_claim`] tells one, holds a value or names
    /// a crossing beside its members or names nobody, and none of it is
    /// kept. A member no question
    /// stands for is handed back where its leaf is present: the row here
    /// may yet come to hear, and then asks for exactly that cell. A leaf
    /// pushed absent for such a member is dropped, since the marker it
    /// is judged beside is keyed by terms only a standing question
    /// holds.
    ///
    /// # Errors
    ///
    /// Why the whole claim is dropped, as the push metric labels it:
    /// `aged` where its anchor is a retention horizon behind `now`, and
    /// `malformed` where it is not a verdict claim in the one form a
    /// claim takes.
    pub(crate) fn offer_pushed_verdicts(
        &mut self,
        claim: &StateClaim,
        now: WeightedTimestamp,
        windows: EpochWindows,
    ) -> Result<Option<StateClaim>, &'static str> {
        if now.elapsed_since(claim.anchor.ts) > RETENTION_HORIZON {
            return Err("aged");
        }
        if !claim.is_verdict_claim() || !claim.is_well_formed() {
            return Err("malformed");
        }
        let anchor = claim.anchor;
        let sibling = anchor.shard;
        let mark = ReadMark::of(&anchor, windows);
        let mut kept: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut taken: Vec<(TxHash, VerdictCells)> = Vec::new();
        let mut early: BTreeSet<SubstateKey> = BTreeSet::new();
        for tx in claim.verdicts.iter() {
            let leaf_key = verdict_leaf(sibling, *tx);
            let Some(leaf) = claim.reading(leaf_key) else {
                continue;
            };
            let named = (sibling, *tx);
            let Some(ask) = self.verdicts.get(&named) else {
                if leaf.is_present() {
                    early.insert(leaf_key);
                }
                continue;
            };
            let (question, of) = (ask.question, ask.cells);
            let beside = claim.reading(of.row).zip(claim.reading(of.marker));
            let Some(said) = said_at(
                leaf,
                beside,
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
            taken.push((*tx, of));
            kept.insert(of.leaf);
            if !leaf.is_present() {
                kept.extend([of.row, of.marker]);
            }
        }
        if let Some(part) = claim.restrict(|key| kept.contains(&key)) {
            self.heard.hold(part, mark, &taken);
        }
        Ok(claim.restrict(|key| early.contains(&key)))
    }

    /// Let go of every claim held for a verdict question at an anchor no
    /// block could carry it at, and mark the ones that wait.
    ///
    /// A block admits a claim held for a verdict question only at an
    /// anchor in no recovery's band and no older than a retention
    /// horizon. The proven anchors forget a header in a recovery's band
    /// ([`ProvenAnchors::forget_orphaned`]) and an aged one, so a claim
    /// stands only at one still held there and inside the horizon at
    /// `now`.
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
        // The cells asked at a boundary for an answer's deletion are
        // held apart, and are no other question's to keep.
        let at_boundary = self.hold_boundary_readings(anchor, &inclusions, proof);
        // A question the proof answered is not put again, and the
        // reading that answered it is the one held to offer: what the
        // answer means is still the chain's to say, and until a block
        // carries the claim nothing here has composed anything from it.
        //
        // One rule for both, because a reading that answers nothing is
        // worth neither. A question is asked only at a header inside its
        // window, so a reading that answers nothing is a sibling's cell
        // read present, or a cell read for a member already answered
        // for. Offering one spends the section on a cell that covers
        // nothing.
        let mut answering: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut speaks_for: BTreeSet<TxHash> = BTreeSet::new();
        for question in &answered {
            let Some(&(_, inclusion)) = inclusions.iter().find(|(key, _)| *key == question.key)
            else {
                continue;
            };
            if self.ledger.answers(question, anchor.ts, inclusion) {
                answering.insert(question.key);
                speaks_for.insert(question.tx_hash);
            } else {
                record_sibling_question_pending();
            }
        }
        answering.extend(
            inclusions
                .iter()
                .map(|(key, _)| *key)
                .filter(|key| !at_boundary.contains(key))
                .filter(|key| wants_reading(&self.rows.awaited, &self.wanted, *key)),
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
        self.rows.names.get(&key).map(|(id, _)| *id)
    }

    /// Fold the claims a committed block carries into the answers every
    /// replica holds.
    ///
    /// A claim answers every cell of the ledger's on the anchor's shard
    /// whose window the anchor's clock sits inside — whether or not this
    /// replica had a probe out, and wherever its own probe sat — so a
    /// replica that never fetched reads the same answer as the one that
    /// did. Only a sibling's committed cell read absent answers; one read
    /// present is a sibling that included the transaction, and is asked
    /// again at the next header. The first proof to answer a cell is the
    /// answer; a later one adds nothing.
    fn fold_state_claims(&mut self, block: &Block) {
        if block.state_claims().is_empty() {
            return;
        }
        let questions = self.ledger.questions();
        for claim in block.state_claims() {
            self.fold_cells(claim, &questions);
        }
    }

    /// Count the claims the block carries that the commit fold acts on
    /// by their anchor: a record presence, which the read frontier
    /// fences, and a boundary claim reading a record absent under its
    /// crossing's name, which is what deletes an answer. The boundary
    /// claims are counted by the bytes they cost the block and the
    /// deletions they read, since an epoch's arrive together.
    fn count_carried(&self, block: &Block) {
        let block_anchor = block.header().parent_qc().weighted_timestamp();
        let (mut bytes, mut deletions) = (0usize, 0usize);
        for claim in block.state_claims() {
            if fenced_cells(claim).next().is_some() {
                record_fenced_claim("record", true);
            }
            if claim.anchor.shard != self.ledger.local() && claim.at_boundary(block_anchor) {
                bytes += claim.wire_weight();
                let deleting = claim.deleting().count();
                deletions += deleting;
                if deleting != 0 {
                    record_fenced_claim("removed", true);
                }
            }
        }
        if bytes != 0 {
            record_boundary_claims_carried(bytes, deletions);
        }
    }

    /// Cut from every held claim the record presences below the floor
    /// the frontier now sets for its producer, whether a fetch or a push
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
                    && fenced_cells(claim).next().is_some()
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
                .extend(fenced_cells(claim));
            self.refuse_fenced(claim);
        }
        self.fetched.cut(&cut);
    }

    /// What of a pushed claim is worth holding: all of it at or above
    /// the read frontier's floor for its producer, and below the floor
    /// the cells the frontier does not fence, which every voter still
    /// admits. `None` where nothing is left. A record presence cut here
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
        let fenced: BTreeSet<SubstateKey> = fenced_cells(&claim).collect();
        if fenced.is_empty() {
            return Some(claim);
        }
        self.refuse_fenced(&claim);
        claim.restrict(|key| !fenced.contains(&key))
    }

    /// Count a claim the frontier refused a record presence of and
    /// start the read of each record a consumer here waits on over, so
    /// the next probe asks again at a proven anchor at or above the
    /// floor.
    fn refuse_fenced(&mut self, claim: &StateClaim) {
        if fenced_cells(claim).next().is_none() {
            return;
        }
        record_fenced_claim("record", false);
        for key in claim.keys() {
            if self.wanted.contains(&key) {
                self.records.reset(key);
            }
        }
    }

    /// Fold one claim's answers into the questions the ledger is
    /// waiting on.
    fn fold_cells(&mut self, claim: &StateClaim, questions: &[Question]) {
        for question in questions {
            if question.shard != claim.anchor.shard {
                continue;
            }
            // Judged per cell by the one rule, whoever fetched the
            // proof: an absence of the sibling's committed cell, read
            // inside its window. A question never sent may still be
            // answered by a claim a block carries.
            let answered = claim
                .reading(question.key)
                .is_some_and(|inclusion| question.answered_by(claim.anchor.ts, inclusion));
            if answered
                && self
                    .ledger
                    .record_absence(question.tx_hash, question.shard, question.key)
            {
                record_sibling_absence_read();
            }
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
    /// older record presence would have the older refused at its next
    /// block. No boundary claim is among them: those are held apart, as
    /// [`Self::boundary_claims`] offers them.
    ///
    /// An escrowed record nothing here asked for ([`Self::unsolicited`])
    /// is offered named for its crossing, which is what the fold
    /// declines it under, and rides in its producer's anchor order with
    /// that producer's other claims, since its reading raises the same
    /// frontier entry theirs do. So a producer holding a reading
    /// something here asked for carries its unsolicited records with
    /// it, each at its own anchor, and those ride ahead of another
    /// producer's wanted reading wherever their producer's oldest anchor
    /// is the older: at most
    /// [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`] records for a producing
    /// lineage. Only a producer for which nothing but unsolicited
    /// records is held is offered after every producer holding a wanted
    /// reading.
    fn state_claims(&self, carried: &CarriedClaims) -> Vec<StateClaim> {
        // Per producer: whether only unsolicited records are held for
        // it, and its oldest anchor.
        let mut producers: BTreeMap<ShardId, (bool, WeightedTimestamp)> = BTreeMap::new();
        let mut claims: Vec<StateClaim> = Vec::new();
        for held in self.fetched.claims() {
            // What the chain to the parent carries at the claim's anchor
            // is passed over, and the rest offered as a claim of its own.
            let rest;
            let claim = match carried.cells_at(&held.anchor) {
                Some(keys) if meets(held, keys) => {
                    let Some(cut) = held.restrict(|key| !keys.contains(&key)) else {
                        continue;
                    };
                    rest = cut;
                    &rest
                }
                _ => held,
            };
            let unsolicited: Vec<(SubstateKey, CrossingId)> = claim
                .keys()
                .into_iter()
                .filter_map(|key| self.unsolicited(claim, key).map(|(id, _)| (key, id)))
                .collect();
            let unasked = unsolicited.len() == claim.cells.len();
            producers
                .entry(claim.anchor.shard)
                .and_modify(|(only_unasked, ts)| {
                    *only_unasked &= unasked;
                    *ts = (*ts).min(claim.anchor.ts);
                })
                .or_insert((unasked, claim.anchor.ts));
            claims.push(if unsolicited.is_empty() {
                claim.clone()
            } else {
                let named: Vec<(SubstateKey, CrossingId)> =
                    claim.crossings.iter().copied().chain(unsolicited).collect();
                claim.clone().naming(named)
            });
        }
        claims.sort_by_key(|claim| {
            (
                producers[&claim.anchor.shard],
                claim.anchor.shard,
                claim.anchor.height,
                claim.anchor.ts,
            )
        });
        claims
    }

    /// The crossing and validity end of the escrowed record `claim`
    /// holds at `key`, where no member here waits on it and the fold
    /// could decline it ([`escrowed_here`], at the committed clock): a
    /// record held unasked, under
    /// [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`] for its producing
    /// lineage.
    ///
    /// A want is matched by the record's own transaction, as an arrival
    /// is: a member waiting at this key for another transaction's
    /// record takes nothing from this one, and leaves it unsolicited.
    fn unsolicited(
        &self,
        claim: &StateClaim,
        key: SubstateKey,
    ) -> Option<(CrossingId, WeightedTimestamp)> {
        let (id, issuer) = escrowed_here(
            claim,
            key,
            self.ledger.local(),
            self.clock,
            self.index.as_ref(),
        )?;
        (!self.wanted_of.contains(&(key, issuer.tx)))
            .then_some((id, WeightedTimestamp::from_millis(issuer.validity_end_ms)))
    }

    /// Hold no more than [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`]
    /// unsolicited records for `producer`'s lineage, counting
    /// `arriving`, the validity end and key of each one a push brings,
    /// and hand back the arrivals there is no place for.
    ///
    /// The records of oldest validity end are the ones held: an arrival
    /// older than a held record takes its place, and what is left out
    /// comes again by its producer's next push. An arrival a held claim
    /// of the lineage reads already is not held twice.
    fn cap_unsolicited(
        &mut self,
        producer: ShardId,
        arriving: Vec<(WeightedTimestamp, SubstateKey)>,
    ) -> BTreeSet<SubstateKey> {
        let mut held: Vec<(WeightedTimestamp, SubstateKey, Option<Anchor>)> = self
            .fetched
            .claims()
            .filter(|held| one_lineage(held.anchor.shard, producer))
            .flat_map(|held| {
                held.keys().into_iter().filter_map(|key| {
                    self.unsolicited(held, key)
                        .map(|(_, end)| (end, key, Some(held.anchor)))
                })
            })
            .collect();
        let mut refused = BTreeSet::new();
        for (end, key) in arriving {
            if held.iter().any(|(_, held, _)| *held == key) {
                refused.insert(key);
            } else {
                held.push((end, key, None));
            }
        }
        if held.len() <= MAX_UNSOLICITED_RECORDS_PER_PRODUCER {
            return refused;
        }
        held.sort_unstable();
        let mut evicted: BTreeMap<Anchor, BTreeSet<SubstateKey>> = BTreeMap::new();
        for (_, key, at) in held.split_off(MAX_UNSOLICITED_RECORDS_PER_PRODUCER) {
            match at {
                Some(anchor) => {
                    evicted.entry(anchor).or_default().insert(key);
                }
                None => {
                    refused.insert(key);
                }
            }
        }
        if !evicted.is_empty() {
            self.fetched.cut(&evicted);
        }
        refused
    }

    /// Hold the cap of unsolicited records for every producing lineage
    /// a claim is held for: a record a member here waited on is one
    /// nothing asks for once that member's row is gone and its
    /// transaction's validity end has passed.
    fn cap_held_unsolicited(&mut self) {
        let unasked: Vec<ShardId> = self
            .fetched
            .claims()
            .flat_map(|claim| {
                claim
                    .keys()
                    .into_iter()
                    .filter(|key| self.unsolicited(claim, *key).is_some())
                    .map(|_| claim.anchor.shard)
            })
            .collect();
        if unasked.len() <= MAX_UNSOLICITED_RECORDS_PER_PRODUCER {
            return;
        }
        for producer in unasked.into_iter().collect::<BTreeSet<ShardId>>() {
            let _ = self.cap_unsolicited(producer, Vec::new());
        }
    }

    /// The claims this validator holds for its rows' verdict questions,
    /// oldest anchor first, as far as [`VERDICT_OFFER_CLAIMS`] and
    /// [`VERDICT_OFFER_BYTES`] reach: each as it is held, with no proof
    /// cut here, and none that waits behind another claim at its anchor.
    ///
    /// A claim held for a verdict question names no crossing and holds
    /// no value, so it raises no frontier and may ride after a younger
    /// claim of its producer.
    fn verdict_claims(&self) -> Vec<StateClaim> {
        let mut weight = 0usize;
        self.heard
            .riding()
            .take(VERDICT_OFFER_CLAIMS)
            .take_while(|claim| {
                weight = weight.saturating_add(claim.wire_weight());
                weight <= VERDICT_OFFER_BYTES
            })
            .cloned()
            .collect()
    }

    /// Pause the re-push of every record whose consumer's `Taken` of the
    /// record's own transaction `claim`, a push, reads present, from the
    /// claim's clock, keeping the later of two. A claim no later than the
    /// boundary that last cleared the record's pause pauses nothing: that
    /// boundary already refuted or let go its reading.
    fn pause_on(&mut self, claim: &StateClaim) {
        let pausing: Vec<SubstateKey> = claim
            .keys()
            .into_iter()
            .filter_map(|key| self.rows.answer_asks.get(&key))
            .filter(|ask| {
                ask.answered == Answered::Taken
                    && claim.answers(&ask.id, Issuer::from(&ask.record), Answered::Taken)
            })
            .map(|ask| ask.id.record_key(&ProtocolHasher))
            .collect();
        let at = claim.anchor.ts;
        for record in pausing {
            let entry = self.repushed.entry(record).or_default();
            if entry.cleared_at.is_none_or(|cleared| at > cleared)
                && entry.paused_from.is_none_or(|from| from < at)
            {
                entry.paused_from = Some(at);
                record_repush_paused("set");
            }
        }
    }

    /// Keep a pushed claim's cells while something here wants them, and
    /// say whether the claim is done with: `false` where nothing wants
    /// it yet and something may come to. `records` is the wanted set as
    /// the coordinator derives it now, since a push lands between the
    /// commits and probes that otherwise refresh it. A claim carrying
    /// nothing wanted costs no memory here: a push that lands before
    /// its consumer's transaction commits here, or before any body
    /// reports its record, is the caller's to hold for the want. One
    /// carrying only escrowed records past their taking
    /// ([`past_its_taking`]) is held for no want, since none can be
    /// filed for it, and neither is one carrying only the consumer's
    /// `Taken` of records this shard holds: a pushed `Taken` is pacing
    /// for its producer, which retires only on a reading at a boundary
    /// of the consumer's shard.
    ///
    /// Two kinds of record are kept that nothing here asks for: an owed
    /// record this shard's fold credits ([`owed_here`]), and an escrowed
    /// record it could decline ([`escrowed_here`]), the latter under
    /// [`MAX_UNSOLICITED_RECORDS_PER_PRODUCER`] for its producing
    /// lineage, oldest validity end first. One the cap has no place for
    /// is let go, and its producer pushes it again. An escrowed record
    /// whose transaction holds a member row here is not one: it is
    /// kept only where that member waits on it, and takes no place
    /// under the cap.
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
        self.want(records);
        self.clock = now;
        self.pause_on(claim);
        let anchor = claim.anchor;
        let local = self.ledger.local();
        let unasked: Vec<(WeightedTimestamp, SubstateKey)> = claim
            .keys()
            .into_iter()
            .filter_map(|key| self.unsolicited(claim, key).map(|(_, end)| (end, key)))
            .collect();
        let mut wanted: BTreeSet<SubstateKey> = claim
            .keys()
            .into_iter()
            .filter(|key| {
                wants_reading(&self.rows.awaited, &self.wanted, *key)
                    || owed_here(claim, *key, local, self.index.as_ref()).is_some()
            })
            .chain(unasked.iter().map(|(_, key)| *key))
            .collect();
        if wanted.is_empty() {
            return claim.keys().into_iter().all(|key| {
                held_record(claim, key).is_some_and(|(_, cell)| past_its_taking(&cell, local, now))
                    || self.rows.retires_on(key)
            });
        }
        for held in self.fetched.claims() {
            if held.anchor == anchor {
                for key in held.keys() {
                    wanted.remove(&key);
                }
            }
        }
        let unasked: Vec<(WeightedTimestamp, SubstateKey)> = unasked
            .into_iter()
            .filter(|(_, key)| wanted.contains(key))
            .collect();
        for refused in self.cap_unsolicited(anchor.shard, unasked) {
            wanted.remove(&refused);
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
    fn release_answered_fetches(&mut self) -> Vec<Action> {
        let unresolved = &self.ledger;
        // A claim is worth carrying while something still wants what it
        // answers: a transaction the ledger owes an outcome for, or a
        // leaf-driven question of this shard's, by [`wants_reading`] —
        // the same predicate that decided the reading was worth keeping
        // when the fetch landed — or a record this shard's fold credits
        // or declines unasked.
        // A claim stands only at an anchor this validator still holds
        // commit-proven, since a retired or fenced anchor is one no
        // voter could stand it at, so one whose anchor is gone is let go
        // of here.
        let awaited = &self.rows.awaited;
        let wanted = &self.wanted;
        let proven = &self.proven_anchors;
        let local = unresolved.local();
        let index = self.index.as_ref();
        let now = self.clock;
        self.fetched.retain(|claim, speaks_for| {
            if proven.at(claim.anchor.shard, claim.anchor.height) != Some(claim.anchor) {
                return false;
            }
            speaks_for
                .iter()
                .any(|tx_hash| unresolved.contains(*tx_hash))
                || claim.cells.iter().any(|(key, _)| {
                    wants_reading(awaited, wanted, *key)
                        || owed_here(claim, *key, local, index).is_some()
                        || escrowed_here(claim, *key, local, now, index).is_some()
                })
        });
        // The one retention rule for what counterparts said: an entry
        // there speaks for a transaction this ledger still owes an
        // outcome for, and the ledger is here.
        self.mirror.retain(&|tx_hash| unresolved.contains(tx_hash));
        // A probe lives while its question is open, and the ledger says
        // which those are.
        let open: BTreeSet<(ShardId, SubstateKey)> = unresolved
            .questions()
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
    /// down: what each departed counterpart left of its business here,
    /// by the transactions the ledger still owes an outcome for. A
    /// record standing here with no ledger entry is named by none: the
    /// departed shard may have taken it, and what says so is its answer,
    /// which its successor holds under the same key.
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
                records.insert(
                    shard,
                    AbandonmentRecord::new(shard, settled.terminal_wt, unsettled),
                );
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

    /// Whether `shard`'s certificate naming `tx` is held as evidence that
    /// arms a read of the records `tx` writes there.
    #[cfg(test)]
    pub(crate) fn heard_certificate(&self, shard: ShardId, tx: TxHash) -> bool {
        self.records.heard(shard, tx)
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
    /// retaining one only leaks memory.
    fn gc_settled_sets(&self, topology_schedule: &TopologySchedule, now: WeightedTimestamp) {
        self.mirror
            .retain_departures(&|shard| topology_schedule.terminal_evidence_readable(shard, now));
    }
}

#[cfg(test)]
mod tests {
    use std::iter::once;
    use std::time::Duration;

    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
    use hyperscale_metrics_memory::MemoryRecorder;
    use hyperscale_storage::{Substates, owed_credits, unclaimed_declines};
    use hyperscale_types::state_key::jmt_value_hash;
    use hyperscale_types::test_utils::{proven_claim, state_and_proof, state_and_proof_holding};
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, BeaconWitnessLeafCount, BlockHash, BlockHeight,
        CollectionId, CommittedAt, Deadline, Epoch, Hash, Heard, LocalKey, MAX_FINALIZATION_DELAY,
        MAX_PROOFS_PER_QUERY, NetworkDefinition, ResourceAddr, RoutePrefix, Said, SettledTxsRoot,
        ShardAnchor, StateRoot, StateWrites, TopologySnapshot, ValidatorSet, encode_amount,
        evidence_admits_block,
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
        }
    }

    /// The boundary block of `PRODUCER` at `height` and `ts_ms`, as a
    /// state anchor over a tree holding `present`, with a proof of
    /// `asked` under it.
    fn boundary_of(
        height: u64,
        ts_ms: u64,
        present: &[SubstateKey],
        asked: &[SubstateKey],
    ) -> (Anchor, MerkleInclusionProof) {
        let (state_root, proof) = state_and_proof(PRODUCER, present, asked);
        (
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            proof,
        )
    }

    /// A schedule holding one window for each of `boundaries`, each
    /// recording that boundary for its shard, with the last as its head.
    fn recording(boundaries: &[Anchor]) -> TopologySchedule {
        let snapshot = |boundary: Option<&Anchor>| {
            let snapshot = TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(Vec::new()),
            );
            Arc::new(
                snapshot.with_boundaries(
                    boundary
                        .map(|anchor| {
                            (
                                anchor.shard,
                                ShardAnchor {
                                    state_root: anchor.state_root,
                                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
                                    height: anchor.height,
                                    weighted_timestamp: anchor.ts,
                                    witness_base: BeaconWitnessLeafCount::ZERO,
                                    terminal_settled_txs: None,
                                    handoff_complete: None,
                                    terminal_epoch: None,
                                },
                            )
                        })
                        .into_iter()
                        .collect(),
                ),
            )
        };
        let mut schedule = TopologySchedule::new(1_000_000, Epoch::GENESIS, snapshot(None));
        for (at, boundary) in boundaries.iter().enumerate() {
            schedule.insert(Epoch::new(at as u64 + 1), snapshot(Some(boundary)));
        }
        schedule.set_head(snapshot(boundaries.last()));
        schedule
    }

    /// The cells every fetch among `actions` asks, by the anchor asked
    /// at, each list in the order asked.
    fn asked_at(actions: &[Action]) -> Vec<(Anchor, Vec<SubstateKey>)> {
        actions
            .iter()
            .map(|action| match action {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::StateProofs(ids),
                    shard,
                    ..
                }) => {
                    let anchor = ids.first().expect("a fetch asks something").0;
                    assert_eq!(*shard, anchor.shard);
                    assert!(ids.iter().all(|(at, _)| *at == anchor));
                    (anchor, ids.iter().map(|(_, key)| *key).collect())
                }
                other => panic!("a fetch: {other:?}"),
            })
            .collect()
    }

    /// The row leaf and committed marker, on `PRODUCER`, of the
    /// transaction behind the fixtures' answer.
    fn exit_cells() -> (SubstateKey, SubstateKey) {
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        (
            member_row_leaf(PRODUCER, cell.tx),
            committed_tx_cell_key(
                PRODUCER,
                cell.tx,
                WeightedTimestamp::from_millis(cell.validity_end_ms),
            ),
        )
    }

    /// An answer asks its record's holder once per boundary the head
    /// publishes for it, at that boundary's anchor and no fresh header:
    /// its record's key and its producing member's row leaf, in key
    /// order, and the member's committed marker too where the
    /// boundary's clock is short of the transaction's validity end. A
    /// `Taken` and a `Never` ask alike, seen or not. Nothing is asked
    /// twice at one boundary, the next boundary published is asked once,
    /// and an answer that first stands after its holder's boundary was
    /// asked waits for the next, where every answer of the holder is
    /// asked in one list.
    #[test]
    fn an_answer_asks_once_per_boundary_of_its_producer() {
        let now = WeightedTimestamp::from_millis(400_000);
        let (row, marker) = exit_cells();
        for answer_of in [
            (|id, cell| id.answer(cell.tx, Answered::Taken, cell.validity_end_ms))
                as fn(&CrossingId, &CrossingCell) -> CrossingAnswer,
            |id, cell| id.answer(cell.tx, Answered::Never, cell.validity_end_ms),
            |id, cell| id.unseen_never(cell.tx, cell.validity_end_ms),
        ] {
            let Answering {
                mut counterparts,
                trie,
                anchors,
                rows,
                record,
                ..
            } = answering_with(answer_of);
            let mut expected = vec![record, row];
            expected.sort_unstable();

            assert!(
                counterparts.ask_boundaries(&recording(&[]), now).is_empty(),
                "with no boundary recorded for the holder nothing is asked",
            );
            // A fresh header of the producer's is no place to ask.
            let fresh = Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(700),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: now,
            };
            anchors.record(fresh);
            assert!(
                counterparts
                    .probe(&trie, now, &[], EpochWindows::new(0))
                    .is_empty(),
                "an answer asks nothing at a fresh header",
            );

            let validity_end_ms =
                producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)))
                    .validity_end_ms;
            let (early, _) = boundary_of(40, validity_end_ms - 1, &[], &[]);
            let asked = counterparts.ask_boundaries(&recording(&[early]), now);
            let mut with_marker = vec![record, row, marker];
            with_marker.sort_unstable();
            assert_eq!(
                asked_at(&asked),
                vec![(early, with_marker)],
                "short of the validity end the marker is what shows the transaction committed",
            );

            let (first, _) = boundary_of(80, 300_000, &[], &[]);
            let schedule = recording(&[early, first]);
            let asked = counterparts.ask_boundaries(&schedule, now);
            assert_eq!(asked_at(&asked), vec![(first, expected.clone())]);
            assert!(
                counterparts.ask_boundaries(&schedule, now).is_empty(),
                "once per boundary",
            );

            // A second answer of the same holder, standing only now.
            let later = producer_cell(0x43, Deadline::of(WeightedTimestamp::from_millis(36_000)));
            let later_id = CrossingId::of_record(producer_record(0x43).owner, &later);
            rows.put(
                later_id.answer_key(&ProtocolHasher, Answered::Taken),
                later_id
                    .answer(later.tx, Answered::Taken, later.validity_end_ms)
                    .to_bytes(),
            );
            counterparts.derive_asks(&trie);
            assert!(
                counterparts.ask_boundaries(&schedule, now).is_empty(),
                "an answer that stands after the boundary was asked waits for the next",
            );

            let (second, _) = boundary_of(120, 600_000, &[], &[]);
            let asked = counterparts.ask_boundaries(&recording(&[first, second]), now);
            let mut both = vec![
                record,
                row,
                later_id.record_key(&ProtocolHasher),
                member_row_leaf(PRODUCER, later.tx),
            ];
            both.sort_unstable();
            assert_eq!(
                asked_at(&asked),
                vec![(second, both)],
                "every answer of the holder in one key-ordered list at its next boundary",
            );
        }
    }

    /// A boundary of `CONSUMER` at `height` and `ts_ms` holding the
    /// answers `present`, each `id`'s answer of its way by its
    /// transaction for the record `cell`, with a proof of `asked` under
    /// it.
    fn answered_at(
        id: &CrossingId,
        cell: &CrossingCell,
        present: &[(Answered, TxHash)],
        asked: &[SubstateKey],
        height: u64,
        ts_ms: u64,
    ) -> (Anchor, MerkleInclusionProof) {
        let held: Vec<(SubstateKey, Vec<u8>)> = present
            .iter()
            .map(|(answered, by)| {
                (
                    id.answer_key(&ProtocolHasher, *answered),
                    id.answer(*by, *answered, cell.validity_end_ms).to_bytes(),
                )
            })
            .collect();
        let (state_root, proof) = state_and_proof_holding(CONSUMER, &held, asked);
        (
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(height),
                state_root,
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            proof,
        )
    }

    /// An escrowed record of `PRODUCER`'s for `CONSUMER`, standing in
    /// `rows`, read by a producer over them: the producer, the record's
    /// crossing and cell, and its `Taken` and `Never` keys.
    fn escrowed_producer(
        rows: &Arc<TestRows>,
        seed: u8,
        validity_end_ms: u64,
    ) -> (
        Counterparts,
        CrossingId,
        CrossingCell,
        SubstateKey,
        SubstateKey,
    ) {
        let cell = CrossingCell {
            terms: Terms::Escrowed {
                credit: producer_record(seed.wrapping_add(1)),
            },
            validity_end_ms,
            ..producer_cell(seed, Deadline::of(WeightedTimestamp::from_millis(36_000)))
        };
        let id = CrossingId::of_record(producer_record(seed).owner, &cell);
        rows.put(id.record_key(&ProtocolHasher), cell.to_bytes());
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(rows) as _,
            ReadFrontier::default(),
        );
        producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        (producer, id, cell, taken, never)
    }

    /// `keys`, sorted.
    fn sorted(mut keys: Vec<SubstateKey>) -> Vec<SubstateKey> {
        keys.sort_unstable();
        keys
    }

    /// An escrowed record whose consumer another shard holds reads the
    /// consumer's answers once per boundary the head publishes for that
    /// shard and at no fresh header: its `Taken` at every such boundary,
    /// and its `Never` from the record's validity end. It holds a
    /// reading to offer only as the answer of the record's own
    /// transaction. Held, a `Never` is offered as a return of its own and
    /// a `Taken` as a retirement of its own; an answer of another
    /// transaction at the key is held for nothing, and the next boundary
    /// is asked again.
    #[test]
    fn a_record_reads_its_consumers_answers_once_per_boundary() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, taken, never) = escrowed_producer(&rows, 0x52, 36_000);
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let end = WeightedTimestamp::from_millis(cell.validity_end_ms);
        let anchors = Arc::clone(&producer.proven_anchors);
        anchors.record(Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(700),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: end,
        });
        let asked = producer.probe(&trie, end, &[], EpochWindows::new(0));
        assert!(
            asked_at(&asked)
                .iter()
                .all(|(_, keys)| !keys.contains(&never) && !keys.contains(&taken)),
            "a fresh header is asked no answer: {asked:?}",
        );

        let (early, nothing) = answered_at(&id, &cell, &[], &[taken], 20, 30_000);
        let schedule = recording(&[early]);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&schedule, end)),
            vec![(early, vec![taken])],
            "short of the validity end the Taken alone is asked",
        );
        assert!(
            producer.ask_boundaries(&schedule, end).is_empty(),
            "once per boundary",
        );
        producer.on_proof_fetched(early, &[taken], &nothing, &[]);
        let offers = producer.offers(&CarriedClaims::default());
        assert!(
            offers.retirement_claims.is_empty(),
            "an absence retires nothing"
        );

        let stranger = TxHash::from(Hash::from_bytes(b"another transaction"));
        let both = sorted(vec![taken, never]);
        let (first, refusing) = answered_at(
            &id,
            &cell,
            &[(Answered::Taken, stranger), (Answered::Never, stranger)],
            &both,
            40,
            40_000,
        );
        let schedule = recording(&[early, first]);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&schedule, end)),
            vec![(first, both.clone())]
        );
        producer.on_proof_fetched(first, &both, &refusing, &[]);
        let offers = producer.offers(&CarriedClaims::default());
        assert!(
            offers.boundary_claims.is_empty() && offers.retirement_claims.is_empty(),
            "another transaction's answers retire and return nothing of this record",
        );

        let (second, answering) = answered_at(
            &id,
            &cell,
            &[(Answered::Taken, cell.tx), (Answered::Never, cell.tx)],
            &both,
            80,
            60_000,
        );
        let schedule = recording(&[early, first, second]);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&schedule, end)),
            vec![(second, both.clone())],
            "the next boundary is asked again",
        );
        producer.on_proof_fetched(second, &both, &answering, &[]);
        let offers = producer.offers(&CarriedClaims::default());
        assert_eq!(offers.boundary_claims.len(), 1);
        assert_eq!(offers.boundary_claims[0].deletions, vec![vec![never]]);
        assert_eq!(offers.retirement_claims.len(), 1);
        assert_eq!(offers.retirement_claims[0].deletions, vec![vec![taken]]);
        assert!(
            offers.retirement_claims[0].claims.iter().any(|claim| {
                claim.crossing_of(taken) == Some(id)
                    && claim.answers(&id, Issuer::from(&cell), Answered::Taken)
            }),
            "the record's own Taken is offered, named for its crossing",
        );
        rows.remove(id.record_key(&ProtocolHasher));
        producer.derive_asks(&trie);
        let _ = producer.settle_boundaries(&schedule, end);
        let offers = producer.offers(&CarriedClaims::default());
        assert!(
            offers.boundary_claims.is_empty() && offers.retirement_claims.is_empty(),
            "a record gone asks and offers nothing",
        );
    }

    /// A record's `Taken` is asked at a boundary only where the
    /// boundary's own clock is at or past the earliest its transaction
    /// could be admitted, [`MAX_VALIDITY_RANGE`] before its validity end.
    #[test]
    fn a_taken_is_asked_only_at_a_boundary_from_its_admission() {
        let rows = Arc::new(TestRows::default());
        let end_ms = 1_000_000;
        let (mut producer, _, _, taken, _) = escrowed_producer(&rows, 0x61, end_ms);
        let admitted = u64::try_from(MAX_VALIDITY_RANGE.as_millis()).expect("a range of minutes");
        let at = |height: u64, ts_ms: u64| Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(ts_ms),
        };
        let now = WeightedTimestamp::from_millis(end_ms);
        let before = at(10, end_ms - admitted - 1);
        assert!(
            producer
                .ask_boundaries(&recording(&[before]), now)
                .is_empty(),
            "a boundary older than the transaction can show no take of it",
        );
        let from = at(11, end_ms - admitted);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&recording(&[before, from]), now)),
            vec![(from, vec![taken])],
        );
    }

    /// A record's `Never` is asked at a boundary only where the
    /// boundary's own clock is at or past its validity end, from which
    /// its consumer can decline it.
    #[test]
    fn a_never_is_asked_only_at_a_boundary_from_the_validity_end() {
        let rows = Arc::new(TestRows::default());
        let end_ms = 1_000_000;
        let (mut producer, _, _, taken, never) = escrowed_producer(&rows, 0x62, end_ms);
        let at = |height: u64, ts_ms: u64| Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(ts_ms),
        };
        let now = WeightedTimestamp::from_millis(end_ms);
        let before = at(10, end_ms - 1);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&recording(&[before]), now)),
            vec![(before, vec![taken])],
            "short of the validity end the Never is not asked",
        );
        let from = at(11, end_ms);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&recording(&[before, from]), now)),
            vec![(from, sorted(vec![taken, never]))],
        );
    }

    /// A record a rollback of this shard's store puts back reaches the
    /// rows as a whole read, the store's crossing journal on a new line,
    /// and is asked at its holder's next boundary rather than the one
    /// already asked.
    #[test]
    fn a_record_put_back_by_a_rollback_is_asked_at_its_holders_next_boundary() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, taken, never) = escrowed_producer(&rows, 0x63, 36_000);
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let end = WeightedTimestamp::from_millis(cell.validity_end_ms);
        let at = |height: u64, ts: WeightedTimestamp| Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts,
        };
        let (current, next) = (at(40, end), at(80, end.plus(Duration::from_secs(30))));
        let both = sorted(vec![taken, never]);
        let schedule = recording(&[current]);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&schedule, end)),
            vec![(current, both.clone())],
        );
        let record = id.record_key(&ProtocolHasher);
        rows.remove(record);
        producer.derive_asks(&trie);
        let _ = producer.settle_boundaries(&schedule, end);

        rows.restart();
        rows.put(record, cell.to_bytes());
        producer.derive_asks(&trie);
        assert!(
            producer.rows.rejudge,
            "the read after the rollback is whole"
        );
        let _ = producer.settle_boundaries(&schedule, end);
        assert!(
            producer.ask_boundaries(&schedule, end).is_empty(),
            "the boundary already asked is asked nothing again",
        );
        assert_eq!(
            asked_at(&producer.ask_boundaries(&recording(&[current, next]), end)),
            vec![(next, both)],
            "the record put back is asked at the holder's next boundary",
        );
    }

    /// The clock [`escrowed_producer`]'s records fall due at.
    const DUE_MS: u64 = 36_000;

    /// A push from `CONSUMER`, at `ts_ms`, of `id`'s `Taken` as `by`
    /// answers the record `cell`.
    fn pushed_taken(id: &CrossingId, cell: &CrossingCell, by: TxHash, ts_ms: u64) -> StateClaim {
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let (anchor, proof) = answered_at(id, cell, &[(Answered::Taken, by)], &[taken], 30, ts_ms);
        let cells = proof
            .inclusions(anchor.state_root, CONSUMER, &[taken])
            .expect("the fixture proof answers for its key");
        StateClaim::new(anchor, cells, proof)
    }

    /// Whether `producer` pushes `record` again at `height`, the clock
    /// past every fixture's due instant.
    fn pushes(producer: &mut Counterparts, record: SubstateKey, height: u64) -> bool {
        producer
            .record_repushes(
                &ShardTrie::from_leaves([CONSUMER, PRODUCER]),
                WeightedTimestamp::from_millis(100_000),
                BlockHeight::new(height),
            )
            .values()
            .any(|records| records.contains(&record))
    }

    /// The clock `producer`'s re-push of `record` is paused from.
    fn paused_from(producer: &Counterparts, record: SubstateKey) -> Option<u64> {
        producer
            .repushed
            .get(&record)
            .and_then(|repush| repush.paused_from)
            .map(WeightedTimestamp::as_millis)
    }

    /// Ask `producer`'s record's answers at a boundary of `CONSUMER` at
    /// `ts_ms`, and serve them as `present` reads.
    fn read_at_boundary(
        producer: &mut Counterparts,
        (id, cell): (&CrossingId, &CrossingCell),
        present: &[(Answered, TxHash)],
        height: u64,
        ts_ms: u64,
    ) {
        let both = sorted(vec![
            id.answer_key(&ProtocolHasher, Answered::Taken),
            id.answer_key(&ProtocolHasher, Answered::Never),
        ]);
        let (boundary, proof) = answered_at(id, cell, present, &both, height, ts_ms);
        let asked = producer.ask_boundaries(
            &recording(&[boundary]),
            WeightedTimestamp::from_millis(ts_ms),
        );
        assert!(!asked.is_empty(), "the boundary is asked");
        producer.on_proof_fetched(boundary, &both, &proof, &[]);
    }

    /// A pushed `Taken` of the record's own transaction pauses its
    /// re-push: the record is pushed no more while the pause stands, and
    /// the claim is done with.
    #[test]
    fn a_pushed_taken_pauses_its_records_repush() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x71, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        assert!(producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now));
        assert_eq!(paused_from(&producer, record), Some(40_000));
        assert!(
            !pushes(&mut producer, record, 1),
            "a paused record is pushed no more"
        );
    }

    /// A boundary of the holder later than the pushed reading that reads
    /// the `Taken` absent clears the pause, and the record is pushed
    /// again, counted as a push after a pause.
    #[test]
    fn a_refutation_at_a_later_boundary_resumes_the_repush() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x72, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        let recorder = MemoryRecorder::new();
        with_recorder(&recorder, || {
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
            read_at_boundary(&mut producer, (&id, &cell), &[], 40, 50_000);
        });
        assert_eq!(paused_from(&producer, record), None);
        assert_eq!(recorder.counter("repush_paused", Some("refuted")), 1);
        let pushed = with_recorder(&recorder, || pushes(&mut producer, record, 1));
        assert!(pushed, "the record is pushed again");
        assert_eq!(
            recorder.counter("records_repushed_after_a_pause", Some("escrowed")),
            1,
        );
    }

    /// A push placed again once a later boundary cleared its pause, as a
    /// claim held early is when its record is carried, pauses nothing:
    /// that boundary refuted it. A push read past the clear pauses again.
    #[test]
    fn a_push_no_later_than_the_clear_pauses_nothing() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x7A, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        let pushed = pushed_taken(&id, &cell, cell.tx, 40_000);
        let recorder = MemoryRecorder::new();
        with_recorder(&recorder, || {
            producer.offer_pushed(&pushed, &[], now);
            read_at_boundary(&mut producer, (&id, &cell), &[], 40, 50_000);
            producer.offer_pushed(&pushed, &[], now);
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 50_000), &[], now);
        });
        assert_eq!(paused_from(&producer, record), None);
        assert_eq!(recorder.counter("repush_paused", Some("set")), 1);
        assert!(
            pushes(&mut producer, record, 1),
            "the record is pushed again"
        );
        with_recorder(&recorder, || {
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 55_000), &[], now);
        });
        assert_eq!(paused_from(&producer, record), Some(55_000));
        assert_eq!(recorder.counter("repush_paused", Some("set")), 2);
    }

    /// A refutation at a boundary no later than the pushed reading leaves
    /// the pause: that boundary is older than the `Taken`.
    #[test]
    fn a_refutation_at_an_earlier_boundary_leaves_the_pause() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x73, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        read_at_boundary(&mut producer, (&id, &cell), &[], 40, 40_000);
        assert_eq!(paused_from(&producer, record), Some(40_000));
        assert!(!pushes(&mut producer, record, 1));
    }

    /// A read of the `Taken` at a later boundary let go clears the
    /// pause, as a refutation there does: a read that never comes back
    /// holds no record paused for good.
    #[test]
    fn a_read_let_go_at_a_later_boundary_resumes_the_repush() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x74, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        let boundary = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(40),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(50_000),
        };
        let _ = producer.ask_boundaries(&recording(&[boundary]), now);
        let recorder = MemoryRecorder::new();
        let released = with_recorder(&recorder, || {
            producer.settle_boundaries(&recording(&[]), now)
        });
        assert!(!released.is_empty(), "the read is let go");
        assert_eq!(paused_from(&producer, record), None);
        assert_eq!(recorder.counter("repush_paused", Some("released")), 1);
        assert!(pushes(&mut producer, record, 1));
    }

    /// A `Taken` held present at a later boundary keeps the pause: it is
    /// an attested `Taken`, and the record needs no further push.
    #[test]
    fn a_taken_held_present_keeps_the_repush_paused() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x75, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        read_at_boundary(
            &mut producer,
            (&id, &cell),
            &[(Answered::Taken, cell.tx)],
            40,
            50_000,
        );
        assert_eq!(paused_from(&producer, record), Some(40_000));
        assert!(!pushes(&mut producer, record, 1));
    }

    /// A pushed `Taken` another transaction left at the key is no answer
    /// to this record and pauses nothing.
    #[test]
    fn a_taken_of_another_transaction_pauses_nothing() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x76, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let stranger = TxHash::from(Hash::from_bytes(b"another transaction"));
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, stranger, 40_000), &[], now);
        assert_eq!(paused_from(&producer, record), None);
        assert!(pushes(&mut producer, record, 1));
    }

    /// A paused escrowed record takes no place under the cap on records
    /// pushed to one shard at one height: the others fill it.
    #[test]
    fn a_paused_escrowed_record_takes_no_place_under_the_cap() {
        let rows = Arc::new(TestRows::default());
        let records: Vec<(SubstateKey, CrossingId, CrossingCell)> = (0
            ..=MAX_UNSOLICITED_RECORDS_PER_PRODUCER)
            .map(|seed| {
                let (record, id, cell) =
                    escrowed_record(u8::try_from(seed).expect("small"), DUE_MS);
                rows.put(record, cell.to_bytes());
                (record, id, cell)
            })
            .collect();
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        let (paused, id, cell) = &records[0];
        producer.offer_pushed(
            &pushed_taken(id, cell, cell.tx, 40_000),
            &[],
            WeightedTimestamp::from_millis(40_000),
        );
        let pushed = producer.record_repushes(
            &ShardTrie::from_leaves([CONSUMER, PRODUCER]),
            WeightedTimestamp::from_millis(100_000),
            BlockHeight::new(1),
        );
        let pushed = &pushed[&CONSUMER];
        assert_eq!(pushed.len(), MAX_UNSOLICITED_RECORDS_PER_PRODUCER);
        assert!(!pushed.contains(paused));
        assert!(
            records[1..]
                .iter()
                .all(|(record, _, _)| pushed.contains(record)),
            "every unpaused record goes at the first height",
        );
    }

    /// Of two pushed clocks the later is kept, and a pause is counted set
    /// only where a push sets or raises it.
    #[test]
    fn the_later_of_two_pushed_clocks_is_kept() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x77, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        let recorder = MemoryRecorder::new();
        with_recorder(&recorder, || {
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 35_000), &[], now);
        });
        assert_eq!(paused_from(&producer, record), Some(40_000));
        assert_eq!(recorder.counter("repush_paused", Some("set")), 1);
        let later = WeightedTimestamp::from_millis(45_000);
        with_recorder(&recorder, || {
            producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 45_000), &[], later);
        });
        assert_eq!(paused_from(&producer, record), Some(45_000));
        assert_eq!(recorder.counter("repush_paused", Some("set")), 2);
    }

    /// A new account seeds a pause, at its first read of the rows, on
    /// every record already past its due instant: a push it never saw
    /// may have answered it.
    #[test]
    fn a_new_counterparts_seeds_a_pause_on_every_past_due_record() {
        let rows = Arc::new(TestRows::default());
        let (record, _, cell) = escrowed_record(0x78, DUE_MS);
        rows.put(record, cell.to_bytes());
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        producer.clock = WeightedTimestamp::from_millis(50_000);
        let recorder = MemoryRecorder::new();
        with_recorder(&recorder, || {
            producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        });
        assert_eq!(paused_from(&producer, record), Some(50_000));
        assert_eq!(recorder.counter("repush_paused", Some("seeded")), 1);
        assert!(!pushes(&mut producer, record, 1));
    }

    /// A seeded pause stands through a refutation at a boundary older
    /// than the replica's clock, and clears at the first later one that
    /// refutes the `Taken`.
    #[test]
    fn a_seeded_pause_clears_at_a_later_refuting_boundary() {
        let rows = Arc::new(TestRows::default());
        let (record, id, cell) = escrowed_record(0x7B, DUE_MS);
        rows.put(record, cell.to_bytes());
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        producer.clock = WeightedTimestamp::from_millis(50_000);
        producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        read_at_boundary(&mut producer, (&id, &cell), &[], 40, 45_000);
        assert_eq!(
            paused_from(&producer, record),
            Some(50_000),
            "a boundary older than the seat stands for no push it missed",
        );
        read_at_boundary(&mut producer, (&id, &cell), &[], 41, 60_000);
        assert_eq!(paused_from(&producer, record), None);
        assert!(pushes(&mut producer, record, 1));
    }

    /// A pause stands across a reshape of its answer key's holder that
    /// finds no read of the key pending: the rows are read whole under
    /// the new trie, and the pacing is kept by the record.
    #[test]
    fn a_pause_stands_across_a_reshape_of_its_holder() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, taken, _) = escrowed_producer(&rows, 0x7C, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        let (left, right) = CONSUMER.children();
        let split = ShardTrie::from_leaves([left, right, PRODUCER]);
        assert!([left, right].contains(&split.shard_for_prefix(taken.owner)));
        producer.derive_asks(&split);
        assert_eq!(paused_from(&producer, record), Some(40_000));
        assert!(!pushes(&mut producer, record, 1));
    }

    /// A read of the `Taken` pending at the old holder's later boundary
    /// when a reshape moves the key is let go, and its pause clears with
    /// it: the record is pushed again until a boundary of the new holder
    /// is read.
    #[test]
    fn a_read_let_go_by_a_reshape_of_its_holder_resumes_the_repush() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x7D, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        let boundary = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(40),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(50_000),
        };
        let schedule = recording(&[boundary]);
        assert!(!producer.ask_boundaries(&schedule, now).is_empty());
        let (left, right) = CONSUMER.children();
        producer.derive_asks(&ShardTrie::from_leaves([left, right, PRODUCER]));
        let recorder = MemoryRecorder::new();
        let released = with_recorder(&recorder, || producer.settle_boundaries(&schedule, now));
        assert!(!released.is_empty(), "the read at the old holder is let go");
        assert_eq!(paused_from(&producer, record), None);
        assert_eq!(recorder.counter("repush_paused", Some("released")), 1);
        assert!(pushes(&mut producer, record, 1));
    }

    /// A record that falls due after the account's first read is not
    /// seeded a pause: no push it missed can stand for it.
    #[test]
    fn a_record_falling_due_after_the_seeding_is_not_paused() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, _, _, _) = escrowed_producer(&rows, 0x79, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        producer.clock = WeightedTimestamp::from_millis(50_000);
        producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        assert_eq!(paused_from(&producer, record), None);
        assert!(pushes(&mut producer, record, 1));
    }

    /// A pause survives a whole read of the rows: the pacing is kept by
    /// the record it stands for.
    #[test]
    fn a_hint_survives_a_whole_read() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, _, _) = escrowed_producer(&rows, 0x7A, DUE_MS);
        let record = id.record_key(&ProtocolHasher);
        let now = WeightedTimestamp::from_millis(40_000);
        producer.offer_pushed(&pushed_taken(&id, &cell, cell.tx, 40_000), &[], now);
        rows.restart();
        producer.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        assert!(producer.rows.rejudge, "the read was whole");
        assert_eq!(paused_from(&producer, record), Some(40_000));
    }

    /// Two records' answers held at one boundary: one record's `Never`
    /// is offered among the returns and deletions, and the other's
    /// `Taken` apart from them, as a retirement offer of its own.
    #[test]
    fn retirements_are_offered_apart_from_deletions_and_returns() {
        let rows = Arc::new(TestRows::default());
        let (_, declined_id, declined, declined_taken, declined_never) =
            escrowed_producer(&rows, 0x65, 36_000);
        let (mut producer, taken_id, took, taken, taken_never) =
            escrowed_producer(&rows, 0x67, 36_000);
        let asked = sorted(vec![declined_taken, declined_never, taken, taken_never]);
        let held = [
            (
                declined_never,
                declined_id
                    .answer(declined.tx, Answered::Never, declined.validity_end_ms)
                    .to_bytes(),
            ),
            (
                taken,
                taken_id
                    .answer(took.tx, Answered::Taken, took.validity_end_ms)
                    .to_bytes(),
            ),
        ];
        let (state_root, proof) = state_and_proof_holding(CONSUMER, &held, &asked);
        let boundary = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(40),
            state_root,
            ts: WeightedTimestamp::from_millis(60_000),
        };
        let end = WeightedTimestamp::from_millis(36_000);
        assert_eq!(
            asked_at(&producer.ask_boundaries(&recording(&[boundary]), end)),
            vec![(boundary, asked.clone())],
        );
        producer.on_proof_fetched(boundary, &asked, &proof, &[]);
        let offers = producer.offers(&CarriedClaims::default());
        assert_eq!(
            offers
                .boundary_claims
                .iter()
                .map(|offer| offer.deletions.clone())
                .collect::<Vec<_>>(),
            vec![vec![vec![declined_never]]],
        );
        assert_eq!(
            offers
                .retirement_claims
                .iter()
                .map(|offer| offer.deletions.clone())
                .collect::<Vec<_>>(),
            vec![vec![vec![taken]]],
        );
        assert!(
            offers.retirement_claims[0]
                .claims
                .iter()
                .all(|claim| claim.keys() == vec![taken]),
            "a retirement offer reads its Taken and nothing else",
        );
    }

    /// A retirement the chain to the parent carries is not offered
    /// again.
    #[test]
    fn a_carried_retirement_is_not_offered_again() {
        let rows = Arc::new(TestRows::default());
        let (mut producer, id, cell, taken, never) = escrowed_producer(&rows, 0x68, 36_000);
        let both = sorted(vec![taken, never]);
        let (boundary, proof) =
            answered_at(&id, &cell, &[(Answered::Taken, cell.tx)], &both, 40, 60_000);
        let end = WeightedTimestamp::from_millis(36_000);
        let _ = producer.ask_boundaries(&recording(&[boundary]), end);
        producer.on_proof_fetched(boundary, &both, &proof, &[]);
        let offered = producer.offers(&CarriedClaims::default()).retirement_claims;
        assert_eq!(offered.len(), 1);
        let carried = CarriedClaims::of(PRODUCER, &offered[0].carrying(1));
        assert!(carried.answers(taken));
        assert!(
            producer.offers(&carried).retirement_claims.is_empty(),
            "a retirement the chain to the parent carries waits for its fold",
        );
    }

    /// The `at`th escrowed record of `PRODUCER`'s for `CONSUMER`, each of
    /// its own transaction, returning `amount` to `credit`.
    fn escrowed(at: u16, credit: SubstateKey, amount: u128) -> CrossingCell {
        let mut seed = [0x5D; 32];
        seed[..2].copy_from_slice(&at.to_le_bytes());
        CrossingCell {
            amount,
            intent: IntentHash(Hash32(seed)),
            tx: TxHash::from(Hash::from_bytes(&seed)),
            terms: Terms::Escrowed { credit },
            ..producer_cell(0x5D, Deadline::of(WeightedTimestamp::from_millis(36_000)))
        }
    }

    /// The decline key of the record `cell` under `PRODUCER`'s prefix.
    fn decline_of(cell: &CrossingCell) -> SubstateKey {
        CrossingId::of_record(producer_record(0).owner, cell)
            .answer_key(&ProtocolHasher, Answered::Never)
    }

    /// A producer on `local` under `trie` holding `records`, with `cells`
    /// beside them, that has asked one boundary of `CONSUMER` for every
    /// record's decline key it asks about and holds each record's own
    /// `Never` read there: the producer, its rows, and the keys asked.
    fn declined_at_one_boundary(
        local: ShardId,
        trie: &ShardTrie,
        records: &[CrossingCell],
        cells: &[(SubstateKey, Vec<u8>)],
    ) -> (Counterparts, Arc<TestRows>, Vec<SubstateKey>) {
        let rows = Arc::new(TestRows::default());
        let mut held = Vec::new();
        for cell in records {
            let id = CrossingId::of_record(producer_record(0).owner, cell);
            rows.put(id.record_key(&ProtocolHasher), cell.to_bytes());
            held.push((
                decline_of(cell),
                id.answer(cell.tx, Answered::Never, cell.validity_end_ms)
                    .to_bytes(),
            ));
        }
        for (key, bytes) in cells {
            rows.put(*key, bytes.clone());
        }
        let mut producer = Counterparts::new(
            local,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        producer.derive_asks(trie);
        let (state_root, _) = state_and_proof_holding(CONSUMER, &held, &[]);
        let boundary = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(80),
            state_root,
            ts: WeightedTimestamp::from_millis(60_000),
        };
        let end = WeightedTimestamp::from_millis(records[0].validity_end_ms);
        let mut asked = Vec::new();
        for (_, keys) in asked_at(&producer.ask_boundaries(&recording(&[boundary]), end)) {
            for served in keys.chunks(MAX_PROOFS_PER_QUERY) {
                let (_, proof) = state_and_proof_holding(CONSUMER, &held, served);
                producer.on_proof_fetched(boundary, served, &proof, &[]);
            }
            asked.extend(keys);
        }
        (producer, rows, asked)
    }

    /// The decline keys of the returns `producer` offers, in the order
    /// offered.
    fn offered_returns(producer: &Counterparts) -> Vec<SubstateKey> {
        producer
            .offers(&CarriedClaims::default())
            .boundary_claims
            .iter()
            .flat_map(|offer| offer.deletions.iter())
            .filter_map(|cells| match cells.as_slice() {
                [never]
                    if producer
                        .rows
                        .answer_asks
                        .get(never)
                        .is_some_and(|ask| ask.answered == Answered::Never) =>
                {
                    Some(*never)
                }
                _ => None,
            })
            .collect()
    }

    /// A return whose credit cell cannot take it is offered as any other
    /// is: its credit cell holding bytes that are no amount, or without
    /// room within `u128`. The fold lands it at its owner's principal
    /// vault.
    #[test]
    fn a_return_its_credit_cell_cannot_take_is_offered() {
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let full = encode_amount(u128::MAX - 999).to_vec();
        for (seed, held) in [(0xD2, vec![7; 40]), (0xD3, full)] {
            let credit = producer_record(seed);
            let record = escrowed(0, credit, 1_000);
            let (producer, _, asked) =
                declined_at_one_boundary(PRODUCER, &trie, &[record], &[(credit, held)]);
            assert!(asked.contains(&decline_of(&record)));
            assert_eq!(offered_returns(&producer), vec![decline_of(&record)]);
        }
    }

    /// A chain holding both ends of each of `records`, with each one's
    /// own `Never` standing and `cells` beside them: the producer, its
    /// rows, and each record's crossing in order.
    fn declined_on_one_chain(
        records: &[CrossingCell],
        cells: &[(SubstateKey, Vec<u8>)],
    ) -> (Counterparts, Arc<TestRows>, Vec<CrossingId>) {
        let rows = Arc::new(TestRows::default());
        let ids: Vec<CrossingId> = records
            .iter()
            .map(|cell| {
                let id = CrossingId::of_record(producer_record(0).owner, cell);
                rows.put(id.record_key(&ProtocolHasher), cell.to_bytes());
                rows.put(
                    id.answer_key(&ProtocolHasher, Answered::Never),
                    id.answer(cell.tx, Answered::Never, cell.validity_end_ms)
                        .to_bytes(),
                );
                id
            })
            .collect();
        for (key, bytes) in cells {
            rows.put(*key, bytes.clone());
        }
        let mut counterparts = Counterparts::new(
            ShardId::ROOT,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        counterparts.derive_asks(&ShardTrie::from_leaves([ShardId::ROOT]));
        (counterparts, rows, ids)
    }

    /// A crossing whose two ends this chain holds, its consumer's
    /// `Never` standing, is handed to a proposal to read at its parent
    /// whatever its credit cell holds: a return the cell cannot take
    /// lands at its owner's principal vault.
    #[test]
    fn a_return_on_a_chain_holding_both_ends_is_read_at_the_parent() {
        let credit = producer_record(0xD6);
        let record = escrowed(0, credit, 1_000);
        let (counterparts, _, ids) = declined_on_one_chain(&[record], &[(credit, vec![1, 2, 3])]);
        assert_eq!(
            counterparts
                .offers(&CarriedClaims::default())
                .local_crossings,
            ids
        );
    }

    /// An answer whose record's shard has departed is deleted at a
    /// boundary of the shard holding the record's prefix now. The
    /// departed shard's terminal record is asked nothing, while the trie
    /// still routes the record to it and after: it is no boundary a
    /// claim stands at. Once the trie routes the record to a successor,
    /// the answer asks at the boundary the head publishes for that
    /// successor, for the record's key and the row leaf its transaction
    /// would hold on the successor's chain.
    #[test]
    fn an_answer_whose_producer_departed_asks_at_its_successors_boundary() {
        let now = WeightedTimestamp::from_millis(400_000);
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let recorded = |anchor: &Anchor, terminal: bool| ShardAnchor {
            state_root: anchor.state_root,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
            height: anchor.height,
            weighted_timestamp: anchor.ts,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: terminal.then_some(SettledTxsRoot::ZERO),
            handoff_complete: None,
            terminal_epoch: terminal.then_some(Epoch::new(1)),
        };
        let publishing = |records: Vec<(ShardId, ShardAnchor)>| {
            let snapshot = Arc::new(
                TopologySnapshot::new(
                    NetworkDefinition::simulator(),
                    2,
                    ValidatorSet::new(Vec::new()),
                )
                .with_boundaries(records.into_iter().collect()),
            );
            TopologySchedule::new(1_000_000, Epoch::GENESIS, snapshot)
        };

        let (terminal, _) = boundary_of(90, 300_000, &[], &[]);
        let departing = publishing(vec![(PRODUCER, recorded(&terminal, true))]);
        assert!(
            counterparts.ask_boundaries(&departing, now).is_empty(),
            "the terminal record is no boundary to ask at",
        );

        let (left, right) = PRODUCER.children();
        let split = ShardTrie::from_leaves([CONSUMER, left, right]);
        let successor = split.shard_for_prefix(record.owner);
        assert!([left, right].contains(&successor));
        counterparts.derive_asks(&split);
        let seeded = Anchor {
            shard: successor,
            height: BlockHeight::new(91),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"seeded")),
            ts: terminal.ts,
        };
        let departed = publishing(vec![
            (PRODUCER, recorded(&terminal, true)),
            (successor, recorded(&seeded, false)),
        ]);
        let tx = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000))).tx;
        let mut expected = vec![record, member_row_leaf(successor, tx)];
        expected.sort_unstable();
        assert_eq!(
            asked_at(&counterparts.ask_boundaries(&departed, now)),
            vec![(seeded, expected)],
        );
    }

    /// A claim held to offer is let go once its anchor is more than a
    /// horizon behind the committed clock: the anchor is retired from
    /// the commit-proven headers at that clock, and a claim is kept only
    /// at an anchor still held. So a claim no block carried is held no
    /// longer than a proposer could carry it.
    #[test]
    fn a_held_claim_is_let_go_once_its_anchor_ages_past_the_horizon() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        // No row here names the cells, so each is read unnamed, for the
        // records a consumer here waits on.
        let (mut producer, _, anchors, _rows) = producing(0, deadline);
        let claim = claim_of(0, deadline);
        let decline = consumer_decline(0, deadline);
        let now = deadline.at();
        let (state_root, proof) = state_and_proof(CONSUMER, &[decline], &[claim, decline]);
        let anchor = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        producer.wanted = BTreeSet::from([claim]);
        producer.on_proof_fetched(anchor, &[claim, decline], &proof, &[]);

        let at_the_horizon = now.plus(RETENTION_HORIZON);
        anchors.retire_below(at_the_horizon);
        producer.release_answered_fetches();
        assert_eq!(producer.state_claims(&CarriedClaims::default()).len(), 1);

        anchors.retire_below(at_the_horizon.plus(Duration::from_millis(1)));
        producer.release_answered_fetches();
        assert!(producer.state_claims(&CarriedClaims::default()).is_empty());
    }

    /// A consumer of `PRODUCER`'s holding `count` `Taken` answers, each
    /// of its own crossing and transaction, with the answers' record
    /// keys and row leaves.
    fn answering_many(count: u8) -> (Answering, Vec<(SubstateKey, SubstateKey)>) {
        let fixture = answering();
        let mut cells = vec![(fixture.record, exit_cells().0)];
        for seed in 0..count.saturating_sub(1) {
            let cell = producer_cell(seed, Deadline::of(WeightedTimestamp::from_millis(36_000)));
            let id = CrossingId::of_record(producer_record(seed).owner, &cell);
            fixture.rows.put(
                id.answer_key(&ProtocolHasher, Answered::Taken),
                id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                    .to_bytes(),
            );
            cells.push((
                id.record_key(&ProtocolHasher),
                member_row_leaf(PRODUCER, cell.tx),
            ));
        }
        let mut fixture = fixture;
        fixture.counterparts.derive_asks(&fixture.trie);
        (fixture, cells)
    }

    /// A deletion is offered once every cell it reads is held at one
    /// boundary, whichever proofs brought them, and never before: a
    /// record's absence alone, come back in one answer, waits for the
    /// row leaf in another. The claims held at the boundary are one
    /// key-ordered list in disjoint spans, each record's absence naming
    /// its crossing. A cell that reads the way no deletion needs, a
    /// record still present or a row standing, leaves its answer to the
    /// next boundary and holds nothing.
    #[test]
    fn a_deletion_is_offered_whole_once_its_cells_are_held() {
        let nothing = CarriedClaims::default();
        let (
            Answering {
                mut counterparts, ..
            },
            cells,
        ) = answering_many(4);
        let now = WeightedTimestamp::from_millis(400_000);
        let records: Vec<SubstateKey> = cells.iter().map(|(record, _)| *record).collect();
        let row_leaves: Vec<SubstateKey> = cells.iter().map(|(_, row)| *row).collect();
        // The third answer's record still stands at the boundary, and
        // the fourth's member row does.
        let present = [records[2], row_leaves[3]];
        let (boundary, _) = boundary_of(80, 300_000, &present, &[]);
        let schedule = recording(&[boundary]);
        assert_eq!(counterparts.ask_boundaries(&schedule, now).len(), 1);
        let fetched = |counterparts: &mut Counterparts, keys: &[SubstateKey]| {
            let (at, proof) = boundary_of(80, 300_000, &present, keys);
            assert_eq!(at, boundary);
            counterparts.on_proof_fetched(boundary, keys, &proof, &[]);
        };

        fetched(&mut counterparts, &records);
        assert!(
            counterparts.offers(&nothing).boundary_claims.is_empty(),
            "a record's absence without its member's row leaf deletes nothing",
        );
        assert!(counterparts.offers(&nothing).state_claims.is_empty());

        // The row leaves come back in two answers whose cells straddle
        // one another's.
        let mut sorted = row_leaves;
        sorted.sort_unstable();
        fetched(&mut counterparts, &[sorted[0], sorted[2]]);
        fetched(&mut counterparts, &[sorted[1], sorted[3]]);
        let offered = counterparts.offers(&nothing).boundary_claims;
        assert_eq!(offered.len(), 1, "one offer an anchor");
        let offer = &offered[0];
        let mut whole: Vec<Vec<SubstateKey>> = cells[..2]
            .iter()
            .map(|(record, row)| {
                let mut read = vec![*record, *row];
                read.sort_unstable();
                read
            })
            .collect();
        whole.sort_by_key(|read| {
            *read
                .iter()
                .find(|key| records.contains(key))
                .expect("a record key")
        });
        assert_eq!(
            offer.deletions, whole,
            "the two answers whose record and row both read gone, by record key",
        );
        let carried = offer.carrying(offer.deletions.len());
        assert!(carried.iter().all(|claim| claim.anchor == boundary));
        assert!(carried.iter().all(|claim| claim.verify().is_ok()
            && claim.is_well_formed()
            && claim.reads_as_a_boundary()),);
        assert!(
            carried
                .windows(2)
                .all(|pair| pair[0].keys().last() < pair[1].keys().first()),
            "one key-ordered list, cut into claims whose spans are disjoint",
        );
        let read: BTreeSet<SubstateKey> = carried.iter().flat_map(StateClaim::keys).collect();
        assert_eq!(
            read,
            whole.iter().flatten().copied().collect::<BTreeSet<_>>(),
            "and no cell of an answer the boundary does not delete",
        );
        for record in &records[..2] {
            assert!(
                carried
                    .iter()
                    .any(|claim| claim.deleting().any(|key| key == *record)),
                "each record's absence names its crossing",
            );
        }
        assert_eq!(
            offer.carrying(1).iter().flat_map(StateClaim::keys).count(),
            2
        );

        // What a commit keeps is what a deletion can still read, at
        // that commit and at every one after it.
        for _ in 0..2 {
            assert!(counterparts.settle_boundaries(&schedule, now).is_empty());
            assert_eq!(
                counterparts.boundaries.cells(&boundary),
                whole.iter().flatten().copied().collect::<BTreeSet<_>>(),
                "the readings beside a refuted one are let go",
            );
        }
        assert_eq!(
            counterparts.offers(&nothing).boundary_claims[0].deletions,
            whole
        );
    }

    /// A burst of deletions, every answer of a producer readable at one
    /// boundary at once, takes no place from a reading something waits
    /// on. The boundary claims are held apart from the claims offered
    /// for crossing, seat and ledger questions, so what is offered there
    /// is what was offered before the burst, in the same order, the
    /// producer's own fresh claims included; the burst is offered beside
    /// them for a block to carry in what they leave. A boundary is the
    /// oldest anchor of its producer, and offered in the producer's
    /// anchor order it would have gone first.
    #[test]
    fn a_boundary_burst_takes_no_place_from_a_wanted_reading() {
        let (
            Answering {
                mut counterparts,
                anchors,
                ..
            },
            cells,
        ) = answering_many(24);
        let now = WeightedTimestamp::from_millis(400_000);

        // Readings something waits on: a record a consumer here wants,
        // read at the producer's fresh header and at another shard's.
        let other = ShardId::leaf(2, 0);
        let wanted = [
            (PRODUCER, 900, producer_record(0xE0)),
            (
                other,
                20,
                SubstateKey {
                    owner: Address::new([0x11; 31], AddressClass::Component),
                    local: LocalKey([0xE1; 16]),
                },
            ),
        ];
        counterparts.wanted = wanted.iter().map(|(_, _, key)| *key).collect();
        for (shard, height, key) in wanted {
            let (state_root, proof) = state_and_proof(shard, &[], &[key]);
            let anchor = Anchor {
                shard,
                height: BlockHeight::new(height),
                state_root,
                ts: now,
            };
            anchors.record(anchor);
            counterparts.on_proof_fetched(anchor, &[key], &proof, &[]);
        }
        let before = counterparts.offers(&CarriedClaims::default());
        assert_eq!(before.state_claims.len(), 2);
        assert!(before.boundary_claims.is_empty());

        let (boundary, _) = boundary_of(80, 300_000, &[], &[]);
        assert!(
            before
                .state_claims
                .iter()
                .all(|claim| claim.anchor.ts > boundary.ts),
            "the boundary is older than every fresh claim of its producer",
        );
        let schedule = recording(&[boundary]);
        let asked = counterparts.ask_boundaries(&schedule, now);
        let keys = asked_at(&asked).remove(0).1;
        assert_eq!(keys.len(), 2 * cells.len());
        for chunk in keys.chunks(7) {
            let (_, proof) = boundary_of(80, 300_000, &[], chunk);
            counterparts.on_proof_fetched(boundary, chunk, &proof, &[]);
        }

        let after = counterparts.offers(&CarriedClaims::default());
        assert_eq!(
            after.state_claims, before.state_claims,
            "the burst takes no place among the readings something waits on",
        );
        assert_eq!(after.verdict_claims, before.verdict_claims);
        assert_eq!(after.boundary_claims.len(), 1);
        assert_eq!(
            after.boundary_claims[0].deletions.len(),
            cells.len(),
            "and is offered whole beside them, for what they leave of a block",
        );
        assert!(
            after.boundary_claims[0]
                .claims
                .iter()
                .all(|claim| claim.anchor == boundary),
        );

        // A block carrying some of the deletions leaves the rest held,
        // and the fresh claims as they were.
        let carried = after.boundary_claims[0].carrying(5);
        counterparts.cut_carried(&CarriedClaims::of(CONSUMER, &carried));
        let left = counterparts.offers(&CarriedClaims::default());
        assert_eq!(left.state_claims, before.state_claims);
        assert_eq!(left.boundary_claims[0].deletions.len(), cells.len() - 5);
    }

    /// A proposer offers a boundary claim only at an anchor its own
    /// schedule records as a boundary. It asks at none its head does not
    /// publish, so a reading at a boundary the beacon recorded and this
    /// replica has yet to fold is held nowhere, however it arrives; and
    /// what it holds at a boundary goes, with the fetches still out for
    /// it, once no window it holds records that boundary any more.
    #[test]
    fn a_proposer_behind_the_beacon_offers_no_boundary_claim() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let now = WeightedTimestamp::from_millis(900_000);
        let (row, _) = exit_cells();
        let mut asked = vec![record, row];
        asked.sort_unstable();
        let (older, older_proof) = boundary_of(80, 300_000, &[], &[record]);
        let (newer, newer_proof) = boundary_of(120, 600_000, &[], &asked);
        let behind = recording(&[older]);

        assert_eq!(
            asked_at(&counterparts.ask_boundaries(&behind, now)),
            vec![(older, asked.clone())]
        );
        counterparts.on_proof_fetched(newer, &asked, &newer_proof, &[]);
        assert!(
            counterparts
                .offers(&CarriedClaims::default())
                .boundary_claims
                .is_empty(),
            "a reading at a boundary this replica has not folded is not held",
        );
        assert!(
            counterparts
                .offers(&CarriedClaims::default())
                .state_claims
                .is_empty(),
            "among the boundary claims or anywhere else",
        );

        // Half of what was asked at the boundary it does hold arrives.
        counterparts.on_proof_fetched(older, &[record], &older_proof, &[]);
        assert!(counterparts.settle_boundaries(&behind, now).is_empty());
        assert_eq!(
            counterparts.boundaries.cells(&older),
            BTreeSet::from([record])
        );

        // Its beacon folds on until no window it holds records the
        // older boundary.
        let ahead = recording(&[newer]);
        assert_eq!(ahead.attests_boundary(&older), BoundaryAttestation::Unknown);
        let released = counterparts.settle_boundaries(&ahead, now);
        assert!(
            matches!(
                released.as_slice(),
                [Action::AbandonFetch(FetchIds::StateProofs(ids))] if ids.as_slice() == [(older, row)]
            ),
            "the fetch still out at the evicted boundary is let go: {released:?}",
        );
        assert!(counterparts.boundaries.cells(&older).is_empty());
        assert!(
            counterparts
                .offers(&CarriedClaims::default())
                .boundary_claims
                .is_empty()
        );

        // And it asks, holds and offers at the boundary it now records.
        assert_eq!(
            asked_at(&counterparts.ask_boundaries(&ahead, now)),
            vec![(newer, asked.clone())]
        );
        counterparts.on_proof_fetched(newer, &asked, &newer_proof, &[]);
        let offered = counterparts
            .offers(&CarriedClaims::default())
            .boundary_claims;
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].deletions, vec![asked]);
    }

    /// The row leaf and marker read beside a record's absence stay held
    /// when a block carries that deletion: another answer of the same
    /// transaction reads them too, and is offered whole at the next
    /// block. The record's absence a block carried is not offered again.
    #[test]
    fn a_carried_deletion_leaves_its_exit_readings_to_the_members_other_answers() {
        let Answering {
            mut counterparts,
            trie,
            rows,
            record,
            ..
        } = answering();
        let now = WeightedTimestamp::from_millis(400_000);
        let (row, _) = exit_cells();
        // A second crossing of the same transaction to this consumer.
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let second = CrossingCell { output: 1, ..cell };
        let second_id = CrossingId::of_record(producer_record(0x42).owner, &second);
        rows.put(
            second_id.answer_key(&ProtocolHasher, Answered::Taken),
            second_id
                .answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                .to_bytes(),
        );
        counterparts.derive_asks(&trie);
        let other_record = second_id.record_key(&ProtocolHasher);
        let mut asked = vec![record, other_record, row];
        asked.sort_unstable();
        let (boundary, proof) = boundary_of(80, 300_000, &[], &asked);
        let schedule = recording(&[boundary]);
        assert_eq!(
            asked_at(&counterparts.ask_boundaries(&schedule, now)),
            vec![(boundary, asked.clone())],
            "one row leaf serves both answers",
        );
        counterparts.on_proof_fetched(boundary, &asked, &proof, &[]);
        let offer = counterparts
            .offers(&CarriedClaims::default())
            .boundary_claims
            .remove(0);
        assert_eq!(offer.deletions.len(), 2);

        let first = offer.carrying(1);
        let carried: BTreeSet<SubstateKey> = first.iter().flat_map(StateClaim::keys).collect();
        counterparts.cut_carried(&CarriedClaims::of(CONSUMER, &first));
        let left = counterparts
            .offers(&CarriedClaims::default())
            .boundary_claims
            .remove(0);
        assert_eq!(left.deletions.len(), 1, "the other answer is still whole");
        assert!(left.deletions[0].contains(&row));
        assert!(
            left.deletions[0]
                .iter()
                .all(|key| *key == row || !carried.contains(key)),
            "and the record a block carried is not offered again",
        );
    }

    /// A consumer standing `Taken` answers to records of `PRODUCER`,
    /// each of its own transaction, with every cell their deletions read
    /// held at one boundary that reads them all gone.
    struct Backlog {
        counterparts: Counterparts,
        trie: ShardTrie,
        rows: Arc<TestRows>,
        boundary: Anchor,
        /// Each answer's record key and its own key, by record key.
        crossings: Vec<(SubstateKey, SubstateKey)>,
    }

    /// [`Backlog`] of `count` answers, their cells fetched `per_fetch`
    /// at a time.
    fn backlog(count: u32, per_fetch: usize) -> Backlog {
        let rows = Arc::new(TestRows::default());
        let base = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let seeded = |at: u32, tag: u8| {
            *Hash::from_bytes(&[&[tag][..], &at.to_le_bytes()].concat()).as_bytes()
        };
        let mut crossings: Vec<(SubstateKey, SubstateKey)> = (0..count)
            .map(|at| {
                let cell = CrossingCell {
                    intent: IntentHash(Hash32(seeded(at, 0xA1))),
                    tx: TxHash::from(Hash::from_bytes(&seeded(at, 0xA2))),
                    ..base
                };
                let id = CrossingId::of_record(producer_record(0).owner, &cell);
                let answer = id.answer_key(&ProtocolHasher, Answered::Taken);
                rows.put(
                    answer,
                    id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                        .to_bytes(),
                );
                (id.record_key(&ProtocolHasher), answer)
            })
            .collect();
        crossings.sort_unstable();
        let mut counterparts = Counterparts::new(
            CONSUMER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        counterparts.derive_asks(&trie);
        let now = WeightedTimestamp::from_millis(400_000);
        let (boundary, _) = boundary_of(80, 300_000, &[], &[]);
        let asked: Vec<SubstateKey> =
            asked_at(&counterparts.ask_boundaries(&recording(&[boundary]), now))
                .into_iter()
                .flat_map(|(at, keys)| {
                    assert_eq!(at, boundary);
                    keys
                })
                .collect();
        assert_eq!(asked.len(), 2 * crossings.len(), "a record and a row each");
        for chunk in asked.chunks(per_fetch) {
            let (_, proof) = boundary_of(80, 300_000, &[], chunk);
            counterparts.on_proof_fetched(boundary, chunk, &proof, &[]);
        }
        Backlog {
            counterparts,
            trie,
            rows,
            boundary,
            crossings,
        }
    }

    /// The record key a deletion's cells read.
    fn record_read(backlog: &Backlog, cells: &[SubstateKey]) -> SubstateKey {
        *cells
            .iter()
            .find(|cell| {
                backlog
                    .crossings
                    .binary_search_by_key(*cell, |(record, _)| *record)
                    .is_ok()
            })
            .expect("a deletion reads its record")
    }

    /// An anchor's deletions are offered in record key order from the
    /// first its backlog still stands, so the records a block deletes
    /// sit side by side in the producer's tree and their proofs share
    /// their paths. Each block takes the run after the one the block
    /// before it carried, and no offer reaches past its bound into the
    /// rest of the backlog.
    #[test]
    fn successive_blocks_take_successive_runs_of_an_anchors_backlog() {
        const RUN: usize = 200;
        let mut backlog = backlog(2_400, MAX_PROOFS_PER_QUERY);
        let records: Vec<SubstateKey> = backlog
            .crossings
            .iter()
            .map(|(record, _)| *record)
            .collect();
        let mut deleted = 0;
        for block in 0..4 {
            let offer = backlog
                .counterparts
                .offers(&CarriedClaims::default())
                .boundary_claims
                .remove(0);
            assert!(
                offer
                    .claims
                    .iter()
                    .all(|claim| claim.anchor == backlog.boundary)
            );
            let offered: Vec<SubstateKey> = offer
                .deletions
                .iter()
                .map(|cells| record_read(&backlog, cells))
                .collect();
            assert!(
                offered.len() < records.len() - deleted,
                "block {block}: the backlog is past what one offer holds",
            );
            assert_eq!(
                offered,
                records[deleted..deleted + offered.len()],
                "block {block} is offered the run after the last one carried, by record key",
            );
            let carried = offer.carrying(RUN);
            let gone: BTreeSet<SubstateKey> =
                carried.iter().flat_map(StateClaim::deleting).collect();
            assert_eq!(
                gone,
                records[deleted..deleted + RUN].iter().copied().collect(),
                "block {block} carries the first {RUN} of its run",
            );
            // Its commit deletes their answers, and cuts what it carried.
            backlog
                .counterparts
                .cut_carried(&CarriedClaims::of(CONSUMER, &carried));
            for (record, answer) in &backlog.crossings {
                if gone.contains(record) {
                    backlog.rows.remove(*answer);
                }
            }
            backlog.counterparts.derive_asks(&backlog.trie);
            deleted += RUN;
        }
    }

    /// A proposer whose fold trails its parent by two blocks passes over
    /// what those two carry: with no commit cut between them, each of
    /// three pipelined blocks is offered the run after the one the block
    /// before it carried, and as many deletions as the first, since what
    /// is passed over is not charged to the room. Once a carrier folds,
    /// the carried set it leaves behind changes nothing the cut has not
    /// already retired.
    #[test]
    fn pipelined_offers_take_successive_runs_of_an_anchors_backlog() {
        const RUN: usize = 200;
        let mut backlog = backlog(2_400, MAX_PROOFS_PER_QUERY);
        let records: Vec<SubstateKey> = backlog
            .crossings
            .iter()
            .map(|(record, _)| *record)
            .collect();
        let mut carried = CarriedClaims::default();
        let mut first = None;
        let mut full = None;
        for block in 0..3 {
            let offer = backlog
                .counterparts
                .offers(&carried)
                .boundary_claims
                .remove(0);
            let offered: Vec<SubstateKey> = offer
                .deletions
                .iter()
                .map(|cells| record_read(&backlog, cells))
                .collect();
            assert_eq!(
                offered[..RUN],
                records[block * RUN..(block + 1) * RUN],
                "block {block} is offered the run after the ones its unfolded ancestors carry",
            );
            assert!(
                records.len() - block * RUN > offered.len(),
                "the backlog left to block {block} outruns the room",
            );
            assert_eq!(
                offered.len(),
                *full.get_or_insert(offered.len()),
                "block {block}'s room is charged for nothing its ancestors carry",
            );
            let pieces = CarriedClaims::of(CONSUMER, &offer.carrying(RUN));
            carried.extend(&pieces);
            first.get_or_insert(pieces);
        }

        let first = first.expect("three blocks");
        backlog.counterparts.cut_carried(&first);
        for (record, answer) in &backlog.crossings[..RUN] {
            assert!(first.deletes(*record));
            backlog.rows.remove(*answer);
        }
        backlog.counterparts.derive_asks(&backlog.trie);
        assert_eq!(
            backlog.counterparts.offers(&first).boundary_claims,
            backlog
                .counterparts
                .offers(&CarriedClaims::default())
                .boundary_claims,
            "a folded carrier's set passes over nothing the fold left",
        );
    }

    /// A return and a crossing read at the parent are passed over while
    /// a block carrying them is unfolded. The fold does not cut either:
    /// a return its block did not land, and a crossing its read did not
    /// settle, are offered again once the block folds.
    #[test]
    fn a_carried_return_and_local_crossing_come_back_after_the_fold() {
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let credit = producer_record(0xD7);
        let record = escrowed(0, credit, 1_000);
        let (mut producer, _, _) = declined_at_one_boundary(
            PRODUCER,
            &trie,
            &[record],
            &[(credit, encode_amount(5).to_vec())],
        );
        assert_eq!(offered_returns(&producer), vec![decline_of(&record)]);
        let offer = producer
            .offers(&CarriedClaims::default())
            .boundary_claims
            .remove(0);
        let carried = CarriedClaims::of(PRODUCER, &offer.carrying(1));
        assert!(carried.answers(decline_of(&record)));
        assert!(
            producer.offers(&carried).boundary_claims.is_empty(),
            "the return its unfolded block carries is passed over",
        );
        producer.cut_carried(&carried);
        producer.derive_asks(&trie);
        assert_eq!(
            offered_returns(&producer),
            vec![decline_of(&record)],
            "a return the block did not land is offered again once it folds",
        );

        let (mut local, _, ids) =
            declined_on_one_chain(&[escrowed(1, credit, 1_000)], &[(credit, vec![1, 2, 3])]);
        let parent = Anchor {
            shard: ShardId::ROOT,
            height: BlockHeight::new(9),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"parent")),
            ts: WeightedTimestamp::from_millis(9_000),
        };
        let read = StateClaim::new(
            parent,
            [(
                ids[0].record_key(&ProtocolHasher),
                Inclusion::Present([1; 32]),
            )],
            MerkleInclusionProof::dummy(),
        )
        .naming([(ids[0].record_key(&ProtocolHasher), ids[0])]);
        let carried = CarriedClaims::of(ShardId::ROOT, &[read]);
        assert!(
            local.offers(&carried).local_crossings.is_empty(),
            "the crossing its unfolded block reads at the parent is passed over",
        );
        local.cut_carried(&carried);
        local.derive_asks(&ShardTrie::from_leaves([ShardId::ROOT]));
        assert_eq!(
            local.offers(&CarriedClaims::default()).local_crossings,
            ids,
            "and offered again once the block folds",
        );
    }

    /// The claims a block carries of an offer are its pieces merged: one
    /// claim for each run of [`MAX_PROOFS_PER_QUERY`] cells, its proof
    /// the union of the pieces', where the pieces are cut from the held
    /// claims one each. The merged claims read every cell the pieces
    /// did and as they did, name the same crossings, delete the same
    /// records, verify under the anchor's root in the one order a block
    /// carries claims in, weigh less, and leave behind them what the
    /// pieces would have.
    #[test]
    fn a_merged_boundary_claim_carries_what_its_pieces_did() {
        const ANSWERS: u32 = 600;
        let offer = backlog(ANSWERS, 7)
            .counterparts
            .offers(&CarriedClaims::default())
            .boundary_claims
            .remove(0);
        assert_eq!(offer.deletions.len(), ANSWERS as usize);
        assert!(
            offer.claims.len() > 100,
            "the cells are held in many claims"
        );
        let readings = |claims: &[StateClaim]| -> Vec<(SubstateKey, Stated)> {
            let mut cells: Vec<(SubstateKey, Stated)> = claims
                .iter()
                .flat_map(|claim| claim.cells.iter().cloned())
                .collect();
            cells.sort_unstable();
            cells
        };
        let named = |claims: &[StateClaim]| -> Vec<(SubstateKey, CrossingId)> {
            let mut named: Vec<(SubstateKey, CrossingId)> = claims
                .iter()
                .flat_map(|claim| claim.crossings.iter().copied())
                .collect();
            named.sort_unstable();
            named
        };
        let deleted = |claims: &[StateClaim]| -> BTreeSet<SubstateKey> {
            claims.iter().flat_map(StateClaim::deleting).collect()
        };
        let weight =
            |claims: &[StateClaim]| -> usize { claims.iter().map(StateClaim::wire_weight).sum() };
        for carried in [1, 2, 37, 128, 129, 300, offer.deletions.len()] {
            let keys: BTreeSet<SubstateKey> = offer.deletions[..carried]
                .iter()
                .flatten()
                .copied()
                .collect();
            let pieces: Vec<StateClaim> = offer
                .claims
                .iter()
                .filter_map(|claim| claim.restrict(|key| keys.contains(&key)))
                .collect();
            let merged = offer.carrying(carried);
            assert_eq!(
                merged.len(),
                keys.len().div_ceil(MAX_PROOFS_PER_QUERY),
                "{carried} deletions: one claim a run of cells, from {} pieces",
                pieces.len(),
            );
            for claim in &merged {
                assert_eq!(claim.anchor, offer.claims[0].anchor);
                assert!(claim.is_well_formed() && claim.reads_as_a_boundary());
                assert_eq!(claim.verify(), Ok(()), "every cell against the one root");
            }
            assert!(
                merged
                    .windows(2)
                    .all(|pair| pair[0].keys().last() < pair[1].keys().first()),
                "one key-ordered list, cut into claims whose spans are disjoint",
            );
            assert_eq!(readings(&merged), readings(&pieces));
            assert_eq!(named(&merged), named(&pieces));
            assert_eq!(deleted(&merged), deleted(&pieces));
            assert_eq!(deleted(&merged).len(), carried);
            assert!(
                weight(&merged) < weight(&pieces) || pieces.len() == merged.len(),
                "{carried} deletions weigh {} merged against {} in pieces",
                weight(&merged),
                weight(&pieces),
            );

            let mut by_merged = backlog(ANSWERS, 7).counterparts;
            let mut by_pieces = backlog(ANSWERS, 7).counterparts;
            by_merged.cut_carried(&CarriedClaims::of(CONSUMER, &merged));
            by_pieces.cut_carried(&CarriedClaims::of(CONSUMER, &pieces));
            assert_eq!(
                by_merged.offers(&CarriedClaims::default()).boundary_claims,
                by_pieces.offers(&CarriedClaims::default()).boundary_claims,
                "{carried} deletions leave the same behind either way",
            );
        }
    }

    /// A consumer's state holding no cell at all.
    struct NoCells;

    impl Substates for NoCells {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    /// A consumer whose producer was recovered below a retirement keeps
    /// no reading that would credit the record again. The retirement's
    /// absence is no reading this shard holds to offer, so no block of
    /// its own proposing deletes the `Taken` on it; with the `Taken`
    /// standing, the recovered chain's push of the record, which passes
    /// the read frontier at a later epoch, is dropped, and what is held
    /// to offer credits nothing.
    #[test]
    fn a_recovered_producers_owed_record_is_not_kept_under_its_standing_taken() {
        const EPOCH_MS: u64 = 300_000;
        let windows = EpochWindows::new(EPOCH_MS);
        let deadline = Deadline::of(WeightedTimestamp::from_millis(EPOCH_MS + 36_000));
        let record = record_of(0, deadline);
        let id = producer_crossing(0, deadline);
        let cell = producer_cell(0, deadline);
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let rows = Arc::new(TestRows::default());
        rows.put(
            taken,
            id.answer(cell.tx, Answered::Taken, cell.validity_end_ms)
                .to_bytes(),
        );

        // The discarded suffix: the record retired at height 103, read
        // there by the consumer, whose frontier entry it raised.
        let suffix_mark = ReadMark {
            epoch: windows.epoch_for(WeightedTimestamp::from_millis(EPOCH_MS + 15_000)),
            height: BlockHeight::new(103),
        };
        let (suffix_root, suffix_proof) = state_and_proof(PRODUCER, &[], &[record]);
        let suffix = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(103),
            state_root: suffix_root,
            ts: WeightedTimestamp::from_millis(EPOCH_MS + 15_000),
        };
        let anchors = Arc::new(ProvenAnchors::default());
        anchors.record(suffix);
        let mut counterparts = Counterparts::new(
            CONSUMER,
            Arc::clone(&anchors),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::from_entries([(PRODUCER, suffix_mark)]),
        );
        counterparts.derive_asks(&ShardTrie::from_leaves([CONSUMER, PRODUCER]));
        let retired = StateClaim::new(suffix, [(record, Inclusion::Absent)], suffix_proof.clone());
        let during = WeightedTimestamp::from_millis(EPOCH_MS + 16_000);
        assert!(
            !counterparts.offer_pushed(&retired, &[], during),
            "a fresh absence of the record is nothing this shard keeps to offer",
        );
        counterparts.on_proof_fetched(suffix, &[record], &suffix_proof, &[]);
        assert!(
            counterparts
                .offers(&CarriedClaims::default())
                .state_claims
                .is_empty()
        );
        assert!(rows.cell(taken).is_some(), "so the Taken stands");

        // The producer is recovered to its boundary sixteen epochs on,
        // and its fresh chain pushes the record standing again.
        let bridge_ms = 18 * EPOCH_MS;
        let (state_root, proof) = state_and_proof(PRODUCER, &[record], &[record]);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(97),
            state_root,
            ts: WeightedTimestamp::from_millis(bridge_ms + 5_000),
        };
        anchors.record(anchor);
        let pushed = StateClaim::new(
            anchor,
            [(
                record,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            proof,
        );
        let now = WeightedTimestamp::from_millis(bridge_ms + 6_000);
        let cut = counterparts.cut_pushed(pushed.clone(), windows);
        assert_eq!(
            cut.as_ref(),
            Some(&pushed),
            "a mark at a lower height in a later epoch passes the frontier's floor",
        );
        assert!(
            !counterparts.offer_pushed(&pushed, &[], now),
            "with the Taken standing the recovered chain's push is dropped",
        );
        let offered = counterparts.offers(&CarriedClaims::default()).state_claims;
        let writes = owed_credits(&offered, &StateWrites::default(), &NoCells);
        assert_eq!(
            writes.movements.values().map(|m| m.credit).sum::<u128>(),
            0,
            "and nothing held to offer credits the record again",
        );

        // Had the Taken gone on the retirement, the same push would be
        // kept and would credit the record a second time.
        rows.remove(taken);
        assert!(counterparts.offer_pushed(&pushed, &[], now));
        let offered = counterparts.offers(&CarriedClaims::default()).state_claims;
        let writes = owed_credits(&offered, &StateWrites::default(), &NoCells);
        assert_eq!(
            writes.movements.values().map(|m| m.credit).sum::<u128>(),
            cell.amount,
        );
    }

    /// A departure names no crossing off a leaf. A record this shard
    /// holds with no ledger entry, escrowed for a consumer on a shard
    /// that departed past the record's deadline without settling its
    /// transaction inside the window its settled set covers, is offered
    /// in no abandonment record: the departed shard may have taken it
    /// before that window, and only its answer says.
    #[test]
    fn a_departure_names_no_crossing_off_a_leaf() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (producer, _, _, rows) = producing(1, deadline);
        let escrowed = CrossingCell {
            terms: Terms::Escrowed {
                credit: producer_record(0x60),
            },
            ..producer_cell(0, deadline)
        };
        rows.put(record_of(0, deadline), escrowed.to_bytes());
        let cut = deadline.at().plus(Duration::from_secs(600));
        assert!(
            ShardTrie::shard_owns_route(CONSUMER, RoutePrefix::of(escrowed.consumer))
                && deadline.at() <= cut
                && !producer.ledger.contains(escrowed.tx),
            "the record a leaf would have named: escrowed, its consumer's route the \
             departed shard's, its deadline past by the cut, and no entry here",
        );
        producer.on_settled(
            CONSUMER,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: cut,
            },
        );
        assert!(
            producer
                .offers(&CarriedClaims::default())
                .abandonment_records
                .is_empty(),
            "the departure names nothing off the record's leaf",
        );
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
            .state_claims(&CarriedClaims::default())
            .iter()
            .map(|claim| (claim.anchor.shard, claim.anchor.height.inner()))
            .collect();
        assert_eq!(
            offered,
            vec![(PRODUCER, 10), (PRODUCER, 30), (other, 20)],
            "the producer with the oldest anchor goes first, whole, then the next",
        );
    }

    /// A fetched claim is offered less the cells the chain to the parent
    /// carries at its anchor, and not at all where the chain carries
    /// every one. Cells carried at another anchor pass over nothing.
    #[test]
    fn a_fetched_claim_is_offered_less_what_the_chain_carries() {
        let Answering {
            mut counterparts, ..
        } = answering();
        let mut keys: Vec<SubstateKey> = (0x61..0x64).map(producer_record).collect();
        keys.sort_unstable();
        let (state_root, proof) = state_and_proof_holding(PRODUCER, &[(keys[0], vec![1])], &keys);
        let anchor = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(10),
            state_root,
            ts: WeightedTimestamp::from_millis(10_000),
        };
        let cells = proof
            .inclusions(state_root, PRODUCER, &keys)
            .expect("the proof answers for its keys");
        let held = StateClaim::new(anchor, cells, proof);
        let _ = counterparts.fetched.hold(held.clone());
        let middle = held.restrict(|key| key == keys[1]).expect("a held cell");
        let carried = |claims: &[StateClaim]| CarriedClaims::of(CONSUMER, claims);

        assert_eq!(
            counterparts.state_claims(&carried(std::slice::from_ref(&middle))),
            vec![held.restrict(|key| key != keys[1]).expect("the rest")],
        );
        assert!(
            counterparts
                .state_claims(&carried(std::slice::from_ref(&held)))
                .is_empty()
        );
        let elsewhere = StateClaim {
            anchor: Anchor {
                height: BlockHeight::new(11),
                ..anchor
            },
            ..middle
        };
        assert_eq!(
            counterparts.state_claims(&carried(&[elsewhere])),
            vec![held],
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
            counterparts
                .offers(&CarriedClaims::default())
                .local_crossings
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
            counterparts
                .offers(&CarriedClaims::default())
                .local_crossings
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
    /// answer: a decline read present leaves the record's `Taken` asked,
    /// and it goes only with the record. An owed record, which nothing
    /// takes back, asks no decline at all.
    #[test]
    fn the_asks_hold_no_verdict() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let (mut producer, trie, _anchors, rows) = producing(1, deadline);
        let (claim, decline) = (claim_of(0, deadline), consumer_decline(0, deadline));
        rows.put(
            decline,
            producer_crossing(0, deadline)
                .answer(
                    producer_cell(0, deadline).tx,
                    Answered::Never,
                    producer_cell(0, deadline).validity_end_ms,
                )
                .to_bytes(),
        );
        producer.derive_asks(&trie);
        assert!(
            producer.rows.answer_asks.contains_key(&claim)
                && !producer.rows.answer_asks.contains_key(&decline),
            "the refusal is block content, not a flag here",
        );
        rows.remove(record_of(0, deadline));
        producer.derive_asks(&trie);
        assert!(
            producer.rows.answer_asks.is_empty(),
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
            seated.rows.answer_asks.keys().collect::<Vec<_>>(),
            through.rows.answer_asks.keys().collect::<Vec<_>>(),
        );
        assert_eq!(seated.rows.names, through.rows.names);
    }

    /// A pushed `Taken` of a record this shard holds is pacing for the
    /// producer and is held to offer by nothing, since a fresh reading of
    /// it retires nothing; and the claim carrying it alone is done with,
    /// so nothing parks it to wait for a want.
    #[test]
    fn a_pushed_taken_alone_is_not_parked_early() {
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
        assert!(
            producer.offer_pushed(&pushed, &[], WeightedTimestamp::from_millis(2_000)),
            "the claim is done with: nothing parks it",
        );
        assert!(
            producer.state_claims(&CarriedClaims::default()).is_empty(),
            "and nothing offers it in a block",
        );
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
                .record_repushes(
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
                    producer.record_repushes(&trie, deadline.at(), BlockHeight::new(*height));
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
                .record_repushes(&trie, deadline.at(), BlockHeight::new(64))
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
            (kept, counterparts.state_claims(&CarriedClaims::default()))
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
        let cell = producer_cell(0, deadline);
        let standing = |tx: TxHash| {
            let rows = Arc::new(TestRows::default());
            rows.put(
                id.answer_key(&ProtocolHasher, Answered::Taken),
                id.answer(tx, Answered::Taken, cell.validity_end_ms)
                    .to_bytes(),
            );
            rows
        };
        assert!(
            !offered(CONSUMER, standing(cell.tx)).0,
            "and once its Taken stands there is nothing to credit",
        );
        assert!(
            offered(
                CONSUMER,
                standing(TxHash::from(Hash::from_bytes(b"an earlier transaction"))),
            )
            .0,
            "a Taken another transaction left at the key answers nothing for this record",
        );
    }

    /// An escrowed record under a prefix `PRODUCER` holds, for a consumer
    /// `CONSUMER` holds, whose transaction's validity ends at `end_ms`,
    /// with the key it sits at.
    fn escrowed_record(seed: u8, end_ms: u64) -> (SubstateKey, CrossingId, CrossingCell) {
        let cell = CrossingCell {
            validity_end_ms: end_ms,
            terms: Terms::Escrowed {
                credit: producer_record(seed),
            },
            ..producer_cell(seed, Deadline::of(WeightedTimestamp::from_millis(end_ms)))
        };
        let id = CrossingId::of_record(producer_record(seed).owner, &cell);
        (id.record_key(&ProtocolHasher), id, cell)
    }

    /// A push of the one record `cell` at `key`, read at `producer`'s
    /// `height`.
    fn pushed_record(
        producer: ShardId,
        height: u64,
        key: SubstateKey,
        cell: &CrossingCell,
    ) -> StateClaim {
        StateClaim {
            anchor: Anchor {
                shard: producer,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: WeightedTimestamp::from_millis(height * 1_000),
            },
            cells: Capped::new(vec![(
                key,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )])
            .expect("one cell"),
            crossings: Capped::empty(),
            verdicts: Capped::empty(),
            proof: MerkleInclusionProof::dummy(),
        }
    }

    /// A consumer on `CONSUMER` holding nothing, over `rows`.
    fn consuming(rows: &Arc<TestRows>) -> Counterparts {
        Counterparts::new(
            CONSUMER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(rows) as _,
            ReadFrontier::default(),
        )
    }

    /// An escrowed record whose consumer is elsewhere is pushed again
    /// from its transaction's validity end and no sooner, at this
    /// shard's heights `1, 2, 4, 8, 16, ...` with the gap capped, and is
    /// asked about from the same instant; an owed record still waits
    /// for its deadline. No more than the cap goes to one shard at one
    /// height, the records left out going at the next.
    #[test]
    fn an_escrowed_record_is_pushed_from_its_validity_end_and_no_sooner() {
        let end = WeightedTimestamp::from_millis(36_000);
        let rows = Arc::new(TestRows::default());
        let (record, _, cell) = escrowed_record(0, 36_000);
        rows.put(record, cell.to_bytes());
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let producer_over = |rows: &Arc<TestRows>| {
            let mut producer = Counterparts::new(
                PRODUCER,
                Arc::new(ProvenAnchors::default()),
                Arc::new(CounterpartMirror::default()),
                Arc::clone(rows) as _,
                ReadFrontier::default(),
            );
            producer.derive_asks(&trie);
            producer
        };
        let mut producer = producer_over(&rows);
        assert!(
            producer
                .record_repushes(
                    &trie,
                    end.minus(Duration::from_millis(1)),
                    BlockHeight::new(1)
                )
                .is_empty(),
            "short of the end a member of the consumer's may still take it, and asks",
        );
        let pushed: Vec<u64> = (1..=200)
            .filter(|height| {
                let targets = producer.record_repushes(&trie, end, BlockHeight::new(*height));
                if targets.is_empty() {
                    return false;
                }
                assert_eq!(targets, BTreeMap::from([(CONSUMER, vec![record])]));
                true
            })
            .collect();
        assert_eq!(&pushed[..7], &[1, 2, 4, 8, 16, 32, 64]);
        assert!(
            pushed
                .windows(2)
                .all(|pair| pair[1] - pair[0] <= MAX_ANSWER_ASK_GAP),
            "the gap never passes the cap: {pushed:?}",
        );

        rows.remove(record);
        producer.derive_asks(&trie);
        assert!(
            producer
                .record_repushes(&trie, end, BlockHeight::new(400))
                .is_empty(),
            "a record gone is pushed no more",
        );

        // Twenty standing at once: the cap at the first height, and the
        // four left out ahead of any second push at the next.
        let many = Arc::new(TestRows::default());
        let records: BTreeSet<SubstateKey> = (0..20)
            .map(|seed| {
                let (record, _, cell) = escrowed_record(seed, 36_000);
                many.put(record, cell.to_bytes());
                record
            })
            .collect();
        let mut producer = producer_over(&many);
        let first = producer.record_repushes(&trie, end, BlockHeight::new(1));
        assert_eq!(first[&CONSUMER].len(), MAX_UNSOLICITED_RECORDS_PER_PRODUCER);
        let second = producer.record_repushes(&trie, end, BlockHeight::new(2));
        let left_out: BTreeSet<SubstateKey> = records
            .iter()
            .filter(|record| !first[&CONSUMER].contains(record))
            .copied()
            .collect();
        assert_eq!(
            second[&CONSUMER].len(),
            MAX_UNSOLICITED_RECORDS_PER_PRODUCER
        );
        assert!(
            left_out
                .iter()
                .all(|record| second[&CONSUMER].contains(record)),
            "the records the cap left out go first at the next height",
        );
    }

    /// A consumer's shard keeps a pushed escrowed record nothing here
    /// asked for from its transaction's validity end, while no answer
    /// of its transaction stands, and offers it named for its crossing.
    #[test]
    fn a_pushed_escrowed_record_is_kept_from_its_validity_end_while_unanswered() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);

        let (early, _, early_cell) = escrowed_record(0xF0, 100_001);
        assert!(
            !consumer.offer_pushed(&pushed_record(PRODUCER, 1, early, &early_cell), &[], now),
            "short of its validity end nothing here wants an unasked record",
        );

        let (declined, declined_id, declined_cell) = escrowed_record(0xF1, 2_000);
        let never = declined_id.answer_key(&ProtocolHasher, Answered::Never);
        rows.put(
            never,
            declined_id
                .answer(declined_cell.tx, Answered::Never, 2_000)
                .to_bytes(),
        );
        assert!(
            consumer.offer_pushed(
                &pushed_record(PRODUCER, 2, declined, &declined_cell),
                &[],
                now
            ),
            "one its transaction's answer stands for is held for no later want",
        );
        assert!(
            consumer.state_claims(&CarriedClaims::default()).is_empty(),
            "and is not kept: it is already answered",
        );
        rows.put(
            never,
            declined_id
                .answer(
                    TxHash::from(Hash::from_bytes(b"another transaction")),
                    Answered::Never,
                    2_000,
                )
                .to_bytes(),
        );
        assert!(
            consumer.offer_pushed(
                &pushed_record(PRODUCER, 2, declined, &declined_cell),
                &[],
                now
            ),
            "an answer of another transaction answers nothing for this record",
        );
        let offered = consumer.state_claims(&CarriedClaims::default());
        assert_eq!(
            offered
                .iter()
                .flat_map(|claim| claim.crossings.iter().copied())
                .collect::<Vec<_>>(),
            vec![(declined, declined_id)],
            "named for its crossing, which is what the fold declines it under",
        );
    }

    /// A consumer's shard holds no more than the cap of unsolicited
    /// records for one producing lineage, those of oldest validity end:
    /// an older arrival takes the youngest's place, and any other
    /// arrival past the cap is let go. A record a member waits on is
    /// held past the cap.
    #[test]
    fn a_producer_holds_no_more_than_its_cap_of_unsolicited_records() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);
        let held = |consumer: &Counterparts| -> BTreeSet<SubstateKey> {
            consumer
                .state_claims(&CarriedClaims::default())
                .iter()
                .flat_map(StateClaim::keys)
                .collect()
        };

        // Sixteen, with validity ends at seconds 5 to 20.
        let record = |seed: u8| escrowed_record(seed, u64::from(seed) * 1_000);
        for seed in 5..=20u8 {
            let (key, _, cell) = record(seed);
            assert!(consumer.offer_pushed(
                &pushed_record(PRODUCER, u64::from(seed), key, &cell),
                &[],
                now
            ));
        }
        let sixteen: BTreeSet<SubstateKey> = (5..=20).map(|seed| record(seed).0).collect();
        assert_eq!(held(&consumer), sixteen);

        // A younger one past the cap is let go, whichever shard of the
        // lineage it is read on; a second push of one held is not held
        // twice.
        let (younger, _, younger_cell) = record(21);
        let child = ShardId::leaf(2, 2);
        assert!(one_lineage(child, PRODUCER));
        for producer in [PRODUCER, child] {
            assert!(
                consumer.offer_pushed(
                    &pushed_record(producer, 30, younger, &younger_cell),
                    &[],
                    now
                ),
                "wanted, with no place for it",
            );
            assert_eq!(held(&consumer), sixteen);
        }
        let (again, _, again_cell) = record(7);
        assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 31, again, &again_cell), &[], now));
        assert_eq!(consumer.state_claims(&CarriedClaims::default()).len(), 16);

        // An older one takes the youngest's place.
        let (older, _, older_cell) = record(1);
        assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 32, older, &older_cell), &[], now));
        let mut expected = sixteen;
        expected.remove(&record(20).0);
        expected.insert(older);
        assert_eq!(held(&consumer), expected);

        // A record a member here waits on is no unsolicited one: it is
        // held past the cap, and offered unnamed.
        let wanted = [WantedRecord {
            key: younger,
            tx: younger_cell.tx,
            arms_at: None,
        }];
        assert!(consumer.offer_pushed(
            &pushed_record(PRODUCER, 33, younger, &younger_cell),
            &wanted,
            now
        ));
        let offered = consumer.state_claims(&CarriedClaims::default());
        assert_eq!(offered.len(), 17);
        assert!(
            offered
                .iter()
                .all(|claim| claim.crossing_of(younger).is_none()),
            "a wanted record rides as its member's arrival",
        );
    }

    /// A producer for which only unsolicited records are held is offered
    /// after every producer holding a reading something here asked for,
    /// whatever its anchors' age; one producer's claims stay together in
    /// anchor order, its unsolicited records among them.
    #[test]
    fn a_wanted_reading_is_offered_ahead_of_an_unsolicited_producer() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);
        let (unasked, _, unasked_cell) = escrowed_record(1, 1_000);
        let (also_unasked, _, also_unasked_cell) = escrowed_record(2, 1_000);
        let (awaited, _, awaited_cell) = escrowed_record(3, 200_000);
        let wanted = [WantedRecord {
            key: awaited,
            tx: awaited_cell.tx,
            arms_at: None,
        }];
        let asked = ShardId::leaf(2, 3);
        // The unasked producer's anchor is the oldest held.
        for claim in [
            pushed_record(PRODUCER, 5, unasked, &unasked_cell),
            pushed_record(asked, 40, awaited, &awaited_cell),
            pushed_record(asked, 30, also_unasked, &also_unasked_cell),
        ] {
            assert!(consumer.offer_pushed(&claim, &wanted, now));
        }
        let offered: Vec<(ShardId, u64)> = consumer
            .state_claims(&CarriedClaims::default())
            .iter()
            .map(|claim| (claim.anchor.shard, claim.anchor.height.inner()))
            .collect();
        assert_eq!(
            offered,
            vec![(asked, 30), (asked, 40), (PRODUCER, 5)],
            "the producer a member waits on goes first, whole and in anchor order",
        );

        // With nothing asked of either, the oldest anchor leads.
        let mut unasking = consuming(&rows);
        for claim in [
            pushed_record(asked, 30, also_unasked, &also_unasked_cell),
            pushed_record(PRODUCER, 5, unasked, &unasked_cell),
        ] {
            assert!(unasking.offer_pushed(&claim, &[], now));
        }
        let offered: Vec<(ShardId, u64)> = unasking
            .state_claims(&CarriedClaims::default())
            .iter()
            .map(|claim| (claim.anchor.shard, claim.anchor.height.inner()))
            .collect();
        assert_eq!(offered, vec![(PRODUCER, 5), (asked, 30)]);
    }

    impl Substates for TestRows {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            CrossingIndex::cell(self, key)
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    /// The crossings the claims `consumer` offers are named for.
    fn named(consumer: &Counterparts) -> Vec<(SubstateKey, CrossingId)> {
        consumer
            .state_claims(&CarriedClaims::default())
            .iter()
            .flat_map(|claim| claim.crossings.iter().copied())
            .collect()
    }

    /// The keys the claims `consumer` offers read.
    fn offered_keys(consumer: &Counterparts) -> BTreeSet<SubstateKey> {
        consumer
            .state_claims(&CarriedClaims::default())
            .iter()
            .flat_map(StateClaim::keys)
            .collect()
    }

    /// A record whose transaction holds a member row here is one a
    /// member may yet take, and the fold declines nothing on a reading
    /// of it: no push of it is kept, however many come. Once the row is
    /// gone the next push is kept and offered named.
    #[test]
    fn a_record_whose_transaction_holds_a_row_here_is_not_kept() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);
        let (key, id, cell) = escrowed_record(0xF1, 2_000);
        let row = member_row_leaf(CONSUMER, cell.tx);
        rows.put(row, vec![1]);
        for height in 1..=64 {
            assert!(
                consumer.offer_pushed(&pushed_record(PRODUCER, height, key, &cell), &[], now),
                "past its validity end the record is held for no later want",
            );
            assert!(
                consumer.state_claims(&CarriedClaims::default()).is_empty(),
                "the push at height {height} is kept by nothing while the row stands",
            );
        }

        rows.remove(row);
        assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 65, key, &cell), &[], now));
        assert_eq!(named(&consumer), vec![(key, id)]);
    }

    /// Records whose transactions hold rows here take no place under the
    /// cap: sixteen of them, each older than a record no member can
    /// take, leave that record its place. With their rows gone they are
    /// held in turn, oldest validity end first.
    #[test]
    fn records_a_member_may_take_hold_no_place_against_a_declinable_one() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);
        let record = |seed: u8| escrowed_record(seed, u64::from(seed) * 1_000);
        for seed in 5..=20u8 {
            let (key, _, cell) = record(seed);
            rows.put(member_row_leaf(CONSUMER, cell.tx), vec![1]);
            assert!(consumer.offer_pushed(
                &pushed_record(PRODUCER, u64::from(seed), key, &cell),
                &[],
                now
            ));
            assert!(consumer.state_claims(&CarriedClaims::default()).is_empty());
        }
        let (younger, younger_id, younger_cell) = record(21);
        assert!(consumer.offer_pushed(
            &pushed_record(PRODUCER, 30, younger, &younger_cell),
            &[],
            now
        ));
        assert_eq!(named(&consumer), vec![(younger, younger_id)]);

        for seed in 5..=20u8 {
            let (key, _, cell) = record(seed);
            rows.remove(member_row_leaf(CONSUMER, cell.tx));
            assert!(consumer.offer_pushed(
                &pushed_record(PRODUCER, 40 + u64::from(seed), key, &cell),
                &[],
                now
            ));
        }
        assert_eq!(
            offered_keys(&consumer),
            (5..=20).map(|seed| record(seed).0).collect(),
            "the sixteen of oldest validity end are the ones held",
        );
    }

    /// A kept record is held across commits for as long as the fold
    /// could decline it, and let go once an answer of its transaction
    /// stands or a member row of its transaction does.
    #[test]
    fn a_kept_record_is_held_until_it_is_answered_or_a_member_stands() {
        let now = WeightedTimestamp::from_millis(100_000);
        let (key, id, cell) = escrowed_record(0xF1, 2_000);
        let kept = |rows: &Arc<TestRows>| {
            let mut consumer = consuming(rows);
            let claim = pushed_record(PRODUCER, 7, key, &cell);
            consumer.proven_anchors.record(claim.anchor);
            assert!(consumer.offer_pushed(&claim, &[], now));
            consumer
        };

        let rows = Arc::new(TestRows::default());
        let mut consumer = kept(&rows);
        for _ in 0..3 {
            consumer.release_answered_fetches();
            assert_eq!(
                named(&consumer),
                vec![(key, id)],
                "nothing asked for the reading, and it is held for its decline",
            );
        }
        rows.put(
            id.answer_key(&ProtocolHasher, Answered::Never),
            id.answer(cell.tx, Answered::Never, cell.validity_end_ms)
                .to_bytes(),
        );
        consumer.release_answered_fetches();
        assert!(
            consumer.state_claims(&CarriedClaims::default()).is_empty(),
            "the decline is written, and the reading answers nothing more",
        );

        let rows = Arc::new(TestRows::default());
        let mut consumer = kept(&rows);
        rows.put(member_row_leaf(CONSUMER, cell.tx), vec![1]);
        consumer.release_answered_fetches();
        assert!(
            consumer.state_claims(&CarriedClaims::default()).is_empty(),
            "a member of the transaction stands, and may yet take the record",
        );
    }

    /// A record a member here waited on is one nothing asks for once the
    /// member is gone and its transaction's validity end has passed, so
    /// the records held past the cap as wanted are cut to the cap at the
    /// commit that finds them unasked, oldest validity end kept.
    #[test]
    fn records_no_member_waits_on_any_more_are_held_under_the_cap() {
        let rows = Arc::new(TestRows::default());
        let mut consumer = consuming(&rows);
        let now = WeightedTimestamp::from_millis(100_000);
        let record = |seed: u8| escrowed_record(seed, u64::from(seed) * 1_000);
        let wanted: Vec<WantedRecord> = (1..=17u8)
            .map(|seed| {
                let (key, _, cell) = record(seed);
                WantedRecord {
                    key,
                    tx: cell.tx,
                    arms_at: None,
                }
            })
            .collect();
        for seed in 1..=17u8 {
            let (key, _, cell) = record(seed);
            assert!(consumer.offer_pushed(
                &pushed_record(PRODUCER, u64::from(seed), key, &cell),
                &wanted,
                now
            ));
        }
        assert_eq!(offered_keys(&consumer).len(), 17);
        assert!(named(&consumer).is_empty(), "each rides as an arrival");

        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let _ = consumer.probe(&trie, now, &[], EpochWindows::new(0));
        consumer.cap_held_unsolicited();
        assert_eq!(
            offered_keys(&consumer),
            (1..=16).map(|seed| record(seed).0).collect(),
            "the youngest validity end is the one let go",
        );
        assert_eq!(named(&consumer).len(), 16);
    }

    /// A chain holding both ends of an escrowed crossing offers the
    /// record to its own blocks from the record's validity end, where no
    /// answer of its transaction stands and no member row of it does:
    /// the reading its fold declines on. Short of the end, or while a
    /// member stands, nothing is read.
    #[test]
    fn a_chain_holding_both_ends_offers_an_unanswered_record_from_its_validity_end() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let end = deadline.validity_end();
        let trie = ShardTrie::from_leaves([ShardId::ROOT]);
        let id = producer_crossing(0, deadline);
        let cell = CrossingCell {
            terms: Terms::Escrowed {
                credit: producer_record(0),
            },
            ..producer_cell(0, deadline)
        };
        let rows = Arc::new(TestRows::default());
        rows.put(record_of(0, deadline), cell.to_bytes());
        let mut merged = Counterparts::new(
            ShardId::ROOT,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        let mut offered_at = |clock: WeightedTimestamp| {
            merged.clock = clock;
            merged.derive_asks(&trie);
            merged.offers(&CarriedClaims::default()).local_crossings
        };

        assert!(
            offered_at(end.minus(Duration::from_millis(1))).is_empty(),
            "short of the end a block here may yet commit the transaction",
        );
        assert_eq!(offered_at(end), vec![id]);

        let row = member_row_leaf(ShardId::ROOT, cell.tx);
        rows.put(row, vec![1]);
        assert!(
            offered_at(end).is_empty(),
            "a member of the transaction stands, and may yet take the record",
        );
        rows.remove(row);
        assert_eq!(offered_at(end), vec![id]);
    }

    /// A want is for the record of one transaction. A record another
    /// transaction carrying the same intent left at the key a member
    /// waits on is no arrival of that member's, so from its own
    /// transaction's validity end it is kept and named for its decline
    /// like any record nothing asked for. The record of the waiting
    /// member's own transaction rides unnamed, as its arrival.
    #[test]
    fn a_record_is_wanted_by_its_own_transaction_alone() {
        let now = WeightedTimestamp::from_millis(100_000);
        let (key, id, cell) = escrowed_record(0xF1, 2_000);
        let wanted_by = |tx: TxHash| {
            [WantedRecord {
                key,
                tx,
                arms_at: None,
            }]
        };
        let offered = |wanted: &[WantedRecord]| {
            let rows = Arc::new(TestRows::default());
            let mut consumer = consuming(&rows);
            assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 2, key, &cell), wanted, now));
            assert_eq!(offered_keys(&consumer), BTreeSet::from([key]));
            named(&consumer)
        };

        let later = TxHash::from(Hash::from_bytes(b"a later transaction"));
        assert_ne!(later, cell.tx);
        assert_eq!(
            offered(&wanted_by(later)),
            vec![(key, id)],
            "another transaction's want names nothing of this record",
        );
        assert!(
            offered(&wanted_by(cell.tx)).is_empty(),
            "its own transaction's member takes it as an arrival",
        );
    }

    /// A record whose own transaction lost the decline key is carried
    /// to its consumer's chain and declined there in its own right.
    ///
    /// Two transactions carrying one intent were abandoned on the
    /// consumer's chain, and the `Never` of the later stands at the
    /// decline key. It binds nothing of the record the earlier issued,
    /// so the producer pushes the record from its validity end, the
    /// consumer's shard keeps it and offers it named, and the fold
    /// writes the record's own `Never` over the other. That answer
    /// binds the record, and the next push of it is kept by nothing.
    #[test]
    fn a_record_whose_decline_another_transaction_wrote_over_still_returns() {
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let (key, id, cell) = escrowed_record(0xF1, 36_000);
        let end = WeightedTimestamp::from_millis(36_000);
        let decline = id.answer_key(&ProtocolHasher, Answered::Never);
        let later = TxHash::from(Hash::from_bytes(b"a later transaction"));

        let standing = Arc::new(TestRows::default());
        standing.put(key, cell.to_bytes());
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&standing) as _,
            ReadFrontier::default(),
        );
        producer.derive_asks(&trie);
        assert_eq!(
            producer.record_repushes(&trie, end, BlockHeight::new(4)),
            BTreeMap::from([(CONSUMER, vec![key])]),
        );

        let rows = Arc::new(TestRows::default());
        rows.put(
            decline,
            id.answer(later, Answered::Never, 36_000).to_bytes(),
        );
        let mut consumer = consuming(&rows);
        assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 4, key, &cell), &[], end));
        let mut block = consumer.state_claims(&CarriedClaims::default());
        assert_eq!(named(&consumer), vec![(key, id)]);
        block.push(StateClaim::new(
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(9),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: end,
            },
            [(member_row_leaf(CONSUMER, cell.tx), Inclusion::Absent)],
            MerkleInclusionProof::new(Vec::new()),
        ));
        let writes = unclaimed_declines(&block, CONSUMER, end, rows.as_ref());
        let own = id.answer(cell.tx, Answered::Never, 36_000).to_bytes();
        assert_eq!(
            writes.cells,
            BTreeMap::from([(decline, Some(own.clone()))]),
            "the fold writes the record's own Never over the other transaction's",
        );

        rows.put(decline, own.clone());
        assert!(Issuer::from(&cell).answered_by(&id, Answered::Never, &own));
        assert!(consumer.offer_pushed(&pushed_record(PRODUCER, 5, key, &cell), &[], end));
        assert!(
            consumer
                .state_claims(&CarriedClaims::default())
                .iter()
                .all(|held| held.anchor.height != BlockHeight::new(5)),
            "declined once: the record's own answer stands, and the next push is not kept",
        );
    }

    /// A claim at `PRODUCER`'s `height` holding the fixtures' record at
    /// `record`, with `present` read present and `absent` read absent
    /// beside it.
    fn holding_the_record(
        height: u64,
        record: SubstateKey,
        present: &[SubstateKey],
        absent: &[SubstateKey],
    ) -> StateClaim {
        let value =
            producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000))).to_bytes();
        let leaves: Vec<(SubstateKey, Vec<u8>)> = once((record, value.clone()))
            .chain(present.iter().map(|key| (*key, key.to_bytes().to_vec())))
            .collect();
        let asked: Vec<SubstateKey> = once(record)
            .chain(present.iter().copied())
            .chain(absent.iter().copied())
            .collect();
        let (state_root, proof) = state_and_proof_holding(PRODUCER, &leaves, &asked);
        let readings = proof
            .inclusions(state_root, PRODUCER, &asked)
            .expect("the fixture proof answers for its keys");
        StateClaim::new(
            Anchor {
                shard: PRODUCER,
                height: BlockHeight::new(height),
                state_root,
                ts: WeightedTimestamp::from_millis(height * 1_000),
            },
            readings.into_iter().map(|(key, inclusion)| {
                if key == record {
                    (
                        key,
                        Stated::Held(Bytes::new(value.clone()).expect("a record fits")),
                    )
                } else {
                    (key, Stated::Inclusion(inclusion))
                }
            }),
            proof,
        )
    }

    /// The floor the frontier sets rising past a held claim cuts the
    /// reading it fences, a record presence, and keeps the claim's other
    /// cell under the proof cut to it, for the transactions the claim
    /// spoke for. A claim left with no cell goes whole.
    #[test]
    fn a_fenced_cell_below_the_floor_is_cut_from_its_claim() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let beside = producer_record(0x77);
        let held = holding_the_record(3, record, &[beside], &[]);
        let alone = holding_the_record(4, record, &[], &[]);
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

    /// The floor passing a fenced record presence cuts that presence and
    /// no other cell read at its anchor. A seat reading is admissible
    /// below the floor: it stays whole and still proves its cycle.
    #[test]
    fn a_seat_reading_beside_a_fenced_record_outlives_the_cut() {
        let cell = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let question = SeatQuestion {
            shard: PRODUCER,
            waiting: TxHash::from(Hash::from_bytes(&[2; 32])),
            holder: cell.tx,
        };
        let keys = question.keys();
        let [seat, row, ..] = keys;
        assert_eq!(row, member_row_leaf(PRODUCER, cell.tx));
        let absent: Vec<SubstateKey> = keys
            .into_iter()
            .filter(|key| *key != seat && *key != row)
            .collect();
        let whole = holding_the_record(3, record, &[seat, row], &absent);
        let presence = whole.restrict(|key| key == record).expect("one cell");
        let reading = whole.restrict(|key| key != record).expect("four cells");
        let _ = counterparts.fetched.hold(presence);
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
            "the fenced presence is cut",
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
    /// the frontier fences: one carrying none is kept whole, an absence
    /// of a record among them, one carrying a record presence beside
    /// another cell is kept as the other cell, and at or above the floor
    /// nothing is cut.
    #[test]
    fn a_pushed_bare_claim_below_the_floor_is_kept() {
        let Answering {
            mut counterparts,
            record,
            ..
        } = answering();
        let windows = EpochWindows::new(0);
        let beside = producer_record(0x77);
        let bare = proven_claim(PRODUCER, 3, &[beside], &[record, beside]);
        let mixed = holding_the_record(3, record, &[beside], &[]);
        let above = holding_the_record(6, record, &[beside], &[]);
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
            .expect("the cell beside the record is kept");
        assert_eq!(kept.keys(), vec![beside]);
        assert_eq!(kept.verify(), Ok(()));
        assert_eq!(
            counterparts.cut_pushed(above.clone(), windows),
            Some(above),
            "at the floor nothing is fenced",
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
        // No row here names the cells, so each is read unnamed, for the
        // records a consumer here waits on.
        let (mut producer, _, anchors, _rows) = producing(0, deadline);
        let (claim0, claim1, claim2) = (
            claim_of(0, deadline),
            claim_of(1, deadline),
            claim_of(2, deadline),
        );
        let now = deadline.at();
        // One tree for both fetches, so both proofs reconstruct the
        // one root the anchor names.
        let (state_root, first) = state_and_proof(CONSUMER, &[claim0], &[claim0, claim1]);
        let (same_root, second) = state_and_proof(CONSUMER, &[claim0], &[claim1, claim2]);
        assert_eq!(state_root, same_root);
        let anchor = Anchor {
            shard: CONSUMER,
            height: BlockHeight::new(7),
            state_root,
            ts: now,
        };
        anchors.record(anchor);
        producer.wanted = BTreeSet::from([claim0, claim1, claim2]);

        // The fixture tree's leaf value is the key's own bytes; served
        // beside the proof, it rides in the claim as a held reading.
        let served = (claim0, Bytes::new(claim0.to_bytes().to_vec()).unwrap());
        producer.on_proof_fetched(anchor, &[claim0, claim1], &first, &[served]);
        let held = producer.state_claims(&CarriedClaims::default());
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[0].held(claim0),
            Some(claim0.to_bytes().as_slice()),
            "the served value is held in the claim",
        );
        assert_eq!(held[0].held(claim1), None);
        assert_eq!(held[0].keys(), {
            let mut keys = vec![claim0, claim1];
            keys.sort_unstable();
            keys
        });
        assert_eq!(
            held[0].verify(),
            Ok(()),
            "the proof covers exactly the claim's keys"
        );

        producer.on_proof_fetched(anchor, &[claim1, claim2], &second, &[]);
        let held = producer.state_claims(&CarriedClaims::default());
        assert_eq!(held.len(), 2, "the overlap is held once");
        let fresh = held
            .iter()
            .find(|claim| claim.keys() == vec![claim2])
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
                    let mut read_at = held
                        .readings
                        .get(&(shard, key))
                        .cloned()
                        .unwrap_or_default();
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
    /// value a consumer demonstrably holds. So the fold retires the
    /// record on the claim, in the block that carries both at a boundary
    /// of the consumer's shard, and takes nothing back on the decline.
    #[test]
    fn a_claim_read_present_answers_over_a_decline_beside_it() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(60_000));
        let id = producer_crossing(0, deadline);
        let claim = claim_of(0, deadline);
        let decline = consumer_decline(0, deadline);
        let issuer = Issuer::from(&producer_cell(0, deadline));
        let stating = |answered: Answered| {
            Inclusion::Present(jmt_value_hash(
                &id.answer(issuer.tx, answered, issuer.validity_end_ms)
                    .to_bytes(),
            ))
        };

        let both = StateClaim::new(
            Anchor {
                shard: CONSUMER,
                height: BlockHeight::new(7),
                state_root: StateRoot::from_raw(Hash::ZERO),
                ts: deadline.at(),
            },
            [
                (claim, stating(Answered::Taken)),
                (decline, stating(Answered::Never)),
            ],
            MerkleInclusionProof::dummy(),
        )
        .naming([(claim, id), (decline, id)]);
        let boundary = deadline
            .at()
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_millis(1));
        assert_eq!(
            both.retires(PRODUCER, boundary, |named| (*named == id).then_some(issuer)),
            vec![(id.record_key(&ProtocolHasher), issuer.tx)],
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

    /// The fetches `actions` abandon, each with the anchor it was put
    /// at.
    fn abandoned(actions: &[Action]) -> Vec<(Anchor, VerdictCells)> {
        actions
            .iter()
            .filter_map(|action| match action {
                Action::AbandonFetch(FetchIds::VerdictProofs(ids)) => Some(ids.clone()),
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

    /// A clock past every header the fixtures below record.
    const FAR: WeightedTimestamp = WeightedTimestamp::from_millis(80_000);

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
        assert!(
            counterparts
                .state_claims(&CarriedClaims::default())
                .is_empty()
        );

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
        counterparts.cut_carried(&CarriedClaims::of(
            CONSUMER,
            &[nameless.clone(), nameless.hearing([question.tx])],
        ));
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
        counterparts.cut_carried(&CarriedClaims::of(CONSUMER, std::slice::from_ref(&named)));
        assert_eq!(
            counterparts.state_claims(&CarriedClaims::default()),
            vec![seat],
            "the seat reading keeps the leaf a verdict claim carried",
        );

        let nameless = read_at(at, &[cells.leaf], &[cells.leaf]);
        counterparts.cut_carried(&CarriedClaims::of(CONSUMER, &[named, nameless]));
        assert_eq!(
            counterparts
                .state_claims(&CarriedClaims::default())
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
    /// question is not asked again, so no newer reading takes its place
    /// while the other claim is about to ride. Once the other has ridden
    /// the verdict claim is offered. A claim that never rides silences
    /// the question only until the sibling's headers have run the
    /// widest ask gap past the waiting reading's anchor.
    #[test]
    fn a_verdict_claim_behind_another_claim_waits_and_is_asked_again_only_past_the_ask_gap() {
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
                counterparts.state_claims(&CarriedClaims::default()),
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
        let ridden = counterparts.state_claims(&CarriedClaims::default());
        counterparts.cut_carried(&CarriedClaims::of(CONSUMER, &ridden));
        counterparts.ask_verdicts(&[question], LATE);
        assert_eq!(counterparts.verdict_claims(), first);

        // It does not ride: the question is not asked again while the
        // reading waits, short of the widest ask gap past its anchor.
        let (mut counterparts, anchors, first) = waiting();
        let at = first[0].anchor;
        for height in [
            at.height.inner() + 1,
            at.height.inner() + MAX_ANSWER_ASK_GAP - 1,
        ] {
            anchors.record(producer_at(height, &[leaf]));
            assert!(
                counterparts.ask_verdicts(&[question], FAR).is_empty(),
                "a reading that waits is not asked for again at height {height}",
            );
        }
        assert_eq!(
            counterparts
                .heard
                .reading((PRODUCER, question.tx))
                .map(|held| held.claim.anchor),
            Some(at),
            "and it is the reading still held",
        );

        // Past the gap it is asked again, and the newer reading replaces
        // the one that waits.
        let next = producer_at(at.height.inner() + MAX_ANSWER_ASK_GAP, &[leaf]);
        anchors.record(next);
        let fetch = counterparts.ask_verdicts(&[question], FAR);
        assert_eq!(asked(&fetch), vec![(next, cells)], "asked again");
        answer(&mut counterparts, next, &[leaf], &[cells]);
        let offered = counterparts.verdict_claims();
        assert_eq!(offered.len(), 1, "one reading a question");
        assert_eq!(offered[0].anchor, next, "the newest");
        assert_eq!(counterparts.heard.claims.len(), 1);
        assert_eq!(
            counterparts.state_claims(&CarriedClaims::default()).len(),
            1
        );
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
            counterparts.state_claims(&CarriedClaims::default()),
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
            counterparts.state_claims(&CarriedClaims::default()),
            vec![older, newer],
            "the producers ride by the oldest anchor of the claims held for them",
        );
    }

    /// Toward one sibling one request is out at a time, of no more
    /// questions than a request carries, so a sibling that never answers
    /// holds that many places of the fetch and a question toward another
    /// sibling is still asked. The silent sibling is asked nothing more
    /// until its request lapses, here by the header it was asked at no
    /// longer being proven; its questions never asked then go first.
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
        let released = abandoned(&fetch);
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

    /// A request nothing answers lapses once the sibling's headers have
    /// run the widest ask gap past the one it was put at, though that
    /// header is still proven: its fetch is abandoned and its questions
    /// are put again at the newest header. An answer to the lapsed
    /// request arriving after that is no reading.
    #[test]
    fn an_unanswered_request_lapses_once_the_widest_ask_gap_has_passed() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        anchors.record(producer_at(7, &[]));
        counterparts.ask_verdicts(&[question], FAR);
        let first = producer_at(8, &[]);
        anchors.record(first);
        let fetch = counterparts.ask_verdicts(&[question], FAR);
        assert_eq!(asked(&fetch), vec![(first, cells)]);

        anchors.record(producer_at(8 + MAX_ANSWER_ASK_GAP - 1, &[]));
        assert!(
            counterparts.ask_verdicts(&[question], FAR).is_empty(),
            "short of the gap the request is still out",
        );

        let lapsed = producer_at(8 + MAX_ANSWER_ASK_GAP, &[]);
        anchors.record(lapsed);
        assert_eq!(anchors.at(PRODUCER, first.height), Some(first));
        let fetch = counterparts.ask_verdicts(&[question], FAR);
        assert_eq!(
            abandoned(&fetch),
            vec![(first, cells)],
            "the fetch still out is let go",
        );
        assert_eq!(
            asked(&fetch),
            vec![(lapsed, cells)],
            "and the question is put at the newest header",
        );
        answer(&mut counterparts, first, &[cells.leaf], &[cells]);
        assert!(
            counterparts.heard.is_empty(),
            "an answer to the lapsed request is not held",
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

    /// No more verdict claims are offered than the offer's count and
    /// bytes reach, the oldest anchors first.
    #[test]
    fn verdict_claims_are_offered_to_a_bound_oldest_first() {
        let (mut counterparts, _) = hearing();
        let held = u16::try_from(VERDICT_OFFER_CLAIMS + 8).expect("a small fixture");
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
        assert_eq!(offered.len(), VERDICT_OFFER_CLAIMS);
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
        assert!(weight <= VERDICT_OFFER_BYTES);
    }

    /// A claim a sibling pushed at `anchor` over `keys`, naming `named`,
    /// proved against a tree holding `present`.
    fn pushed(
        anchor: Anchor,
        present: &[SubstateKey],
        keys: &[SubstateKey],
        named: &[TxHash],
    ) -> StateClaim {
        read_at(anchor, present, keys).hearing(named.iter().copied())
    }

    /// A pushed leaf answers a standing question as a fetched one does,
    /// and the question it answers is then never asked: the push came
    /// first.
    #[test]
    fn a_pushed_leaf_answers_before_the_ask() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let at = producer_at(7, &[cells.leaf]);
        anchors.record(at);
        assert!(counterparts.ask_verdicts(&[question], LATE).is_empty());
        assert_eq!(counterparts.newly_stood(), [cells.leaf]);

        let push = pushed(at, &[cells.leaf], &[cells.leaf], &[question.tx]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&push, LATE, GRID),
            Ok(None)
        );
        assert_eq!(counterparts.verdict_claims(), vec![push.clone()]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&push, LATE, GRID),
            Ok(None),
            "a second push of a reading held at the mark adds nothing",
        );
        assert_eq!(counterparts.verdict_claims(), vec![push]);
        assert_eq!(counterparts.heard.claims.len(), 1);

        anchors.record(producer_at(8, &[cells.leaf]));
        anchors.record(producer_at(9, &[cells.leaf]));
        assert!(
            counterparts.ask_verdicts(&[question], LATE).is_empty(),
            "the question the push answered is not asked",
        );
        assert!(counterparts.newly_stood().is_empty());
    }

    /// Of a pushed claim, a member whose question stands is judged by
    /// the offer rule, and a member nobody asks about yet is handed back
    /// to hold where its leaf is present and dropped where it is absent.
    #[test]
    fn a_push_ahead_of_its_question_is_handed_back_to_hold() {
        let (mut counterparts, anchors) = hearing();
        let (asked, unasked, gone) = (
            verdict_question(1),
            verdict_question(2),
            verdict_question(3),
        );
        let leaf = |question: &VerdictQuestion| verdict_cells(question).leaf;
        let present = [leaf(&asked), leaf(&unasked)];
        let at = producer_at(7, &present);
        anchors.record(at);
        let heard = having_heard(asked, mark_at(&at), Some(Said::Yes));
        counterparts.ask_verdicts(&[heard], LATE);

        let keys = [leaf(&asked), leaf(&unasked), leaf(&gone)];
        let push = pushed(at, &present, &keys, &[asked.tx, unasked.tx, gone.tx]);
        let early = counterparts
            .offer_pushed_verdicts(&push, LATE, GRID)
            .expect("a claim of verdict cells alone, in the horizon")
            .expect("the unasked member's leaf is handed back");
        assert_eq!(early.keys(), vec![leaf(&unasked)]);
        assert_eq!(early.verdicts.to_vec(), vec![unasked.tx]);
        assert!(
            counterparts.heard.is_empty(),
            "the yes already heard at this mark is not offered",
        );

        // The handed-back leaf answers the question once it stands.
        counterparts.ask_verdicts(&[heard, unasked], LATE);
        assert_eq!(counterparts.newly_stood(), [leaf(&unasked)]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&early, LATE, GRID),
            Ok(None)
        );
        assert_eq!(counterparts.verdict_claims(), vec![early]);
    }

    /// A leaf pushed deleted is kept only beside the row and marker the
    /// same push carries, the three in one claim.
    #[test]
    fn a_pushed_deletion_is_kept_with_its_row_and_marker() {
        let (mut counterparts, anchors) = hearing();
        let base = verdict_question(1);
        let cells = verdict_cells(&base);
        let question = having_heard(base, mark_at(&producer_at(5, &[])), Some(Said::Yes));
        let at = producer_at(7, &[cells.marker]);
        anchors.record(at);
        counterparts.ask_verdicts(&[question], LATE);

        let alone = pushed(at, &[cells.marker], &[cells.leaf], &[question.tx]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&alone, LATE, GRID),
            Ok(None)
        );
        assert!(
            counterparts.heard.is_empty(),
            "an absent leaf alone says nothing"
        );

        let whole = pushed(at, &[cells.marker], &cells.keys(), &[question.tx]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&whole, LATE, GRID),
            Ok(None)
        );
        assert_eq!(counterparts.verdict_claims(), vec![whole]);
    }

    /// A sibling's validator may push a valid reading of one leaf at
    /// every header it proves. One reading is held a question, the
    /// newest: each newer push takes the place of the one held, and an
    /// older one arriving late is not held at all.
    #[test]
    fn a_reading_pushed_at_every_header_leaves_one_held_the_newest() {
        let (mut counterparts, anchors) = hearing();
        let (question, beside) = (verdict_question(1), verdict_question(2));
        let leaves = [verdict_cells(&question).leaf, verdict_cells(&beside).leaf];
        let questions = [question, beside];
        let named = [question.tx, beside.tx];
        let headers: Vec<Anchor> = (7..=12)
            .map(|height| {
                let at = producer_at(height, &leaves);
                anchors.record(at);
                at
            })
            .collect();
        counterparts.ask_verdicts(&questions, LATE);

        // The first push reads both; every later one reads the first
        // question alone.
        let both = pushed(headers[0], &leaves, &leaves, &named);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&both, LATE, GRID),
            Ok(None)
        );
        for at in &headers[1..] {
            let push = pushed(*at, &leaves, &leaves[..1], &named[..1]);
            assert_eq!(
                counterparts.offer_pushed_verdicts(&push, LATE, GRID),
                Ok(None)
            );
        }
        let newest = *headers.last().expect("six headers");
        let offered = counterparts.verdict_claims();
        assert_eq!(offered.len(), 2, "one reading a question");
        assert_eq!(
            (offered[0].anchor, offered[0].verdicts.to_vec()),
            (headers[0], vec![beside.tx]),
            "the first claim is cut down to the reading nothing replaced",
        );
        assert_eq!(offered[0].keys(), vec![leaves[1]]);
        assert!(offered[0].verify().is_ok());
        assert_eq!(
            (offered[1].anchor, offered[1].verdicts.to_vec()),
            (newest, vec![question.tx]),
        );
        assert_eq!(counterparts.heard.readings.len(), 2);

        let late = pushed(headers[2], &leaves, &leaves[..1], &named[..1]);
        assert_eq!(
            counterparts.offer_pushed_verdicts(&late, LATE, GRID),
            Ok(None)
        );
        assert_eq!(counterparts.verdict_claims(), offered);
    }

    /// A pushed claim no block could carry, and one that is no verdict
    /// claim, are dropped whole and say why: nothing of either is held
    /// or handed back.
    #[test]
    fn a_pushed_verdict_claim_dropped_whole_says_why() {
        let (mut counterparts, anchors) = hearing();
        let question = verdict_question(1);
        let cells = verdict_cells(&question);
        let at = producer_at(7, &[cells.leaf]);
        anchors.record(at);
        counterparts.ask_verdicts(&[question], LATE);
        let push = pushed(at, &[cells.leaf], &[cells.leaf], &[question.tx]);

        let past = at.ts.plus(RETENTION_HORIZON).plus(Duration::from_millis(1));
        assert_eq!(
            counterparts.offer_pushed_verdicts(&push, past, GRID),
            Err("aged"),
        );
        let naming = push
            .clone()
            .naming([(cells.leaf, producer_crossing(1, Deadline::of(LATE)))]);
        let nameless = read_at(at, &[cells.leaf], &[cells.leaf]);
        for other in [naming, nameless] {
            assert_eq!(
                counterparts.offer_pushed_verdicts(&other, LATE, GRID),
                Err("malformed"),
            );
        }
        assert!(counterparts.heard.is_empty());
        assert_eq!(
            counterparts.offer_pushed_verdicts(&push, LATE, GRID),
            Ok(None)
        );
        assert_eq!(counterparts.verdict_claims(), vec![push]);
    }

    /// An index read only whole: what a replica holds that follows no
    /// change, at every commit.
    struct ReadWhole(Arc<TestRows>);

    impl CrossingIndex for ReadWhole {
        fn crossing_changes(
            &self,
            shard: ShardId,
            _since: Option<CrossingCursor>,
        ) -> (CrossingRead, Option<CrossingCursor>) {
            (self.0.crossing_changes(shard, None).0, None)
        }

        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.cell(key)
        }
    }

    /// A small deterministic generator, so a failing sequence replays.
    struct Draws(u64);

    impl Draws {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % n as u64).expect("small")
        }

        fn one_in(&mut self, n: usize) -> bool {
            self.below(n) == 0
        }
    }

    /// What a replica derives from its rows and holds at its boundaries,
    /// less how it came to read them.
    fn derived(counterparts: &Counterparts) -> String {
        let rows = &counterparts.rows;
        format!(
            "{:?}",
            (
                (
                    &rows.rows.keys().collect::<Vec<_>>(),
                    &rows.answers,
                    &rows.readers,
                    &rows.holders,
                    &rows.answer_asks,
                    &rows.names,
                ),
                (
                    &rows.awaited,
                    &rows.carried,
                    &rows.settling,
                    &rows.closing,
                    rows.standing,
                    rows.standing_bytes,
                ),
                &counterparts.local_crossings,
                &counterparts.repushed,
                &counterparts.boundaries,
                &counterparts.boundary_asked,
            )
        )
    }

    /// The address with every body byte `byte`.
    fn differential_address(byte: u8) -> Address {
        Address::new([byte; 31], AddressClass::Component)
    }

    /// Crossing `c` of the differential, its transaction `tx`: answered
    /// here with its record on the producer, recorded here for a
    /// consumer on the producer, or both ends here.
    fn differential_crossing(
        c: usize,
        tx: usize,
        late: bool,
        terms: Terms,
    ) -> (CrossingId, CrossingCell) {
        let base = producer_cell(0x42, Deadline::of(WeightedTimestamp::from_millis(36_000)));
        let (producer, consumer) = match c % 3 {
            0 => (differential_address(0xAA), differential_address(0x11)),
            1 => (differential_address(0x2A), differential_address(0xBB)),
            _ => (differential_address(0x2A), differential_address(0x11)),
        };
        let cell = CrossingCell {
            intent: IntentHash(Hash32([u8::try_from(c).expect("small"); 32])),
            tx: TxHash::from(Hash::from_bytes(
                &[u8::try_from(c * 4 + tx).expect("small"); 32],
            )),
            validity_end_ms: base.validity_end_ms + if late { 600_000 } else { 0 },
            consumer,
            terms,
            ..base
        };
        (CrossingId::of_record(producer, &cell), cell)
    }

    /// The credit cells the differential's escrowed records return to:
    /// one under the consumer's prefix, one under the producer's.
    fn differential_credits() -> [SubstateKey; 2] {
        [
            SubstateKey {
                owner: differential_address(0x23),
                local: LocalKey([0x23; 16]),
            },
            SubstateKey {
                owner: differential_address(0xB3),
                local: LocalKey([0xB3; 16]),
            },
        ]
    }

    /// Every cell under the producer's prefix a boundary of the
    /// differential can be asked about, with the values a tree may hold
    /// there.
    fn differential_universe() -> BTreeMap<SubstateKey, Vec<Vec<u8>>> {
        let mut universe: BTreeMap<SubstateKey, Vec<Vec<u8>>> = BTreeMap::new();
        for c in 0..18 {
            for tx in 0..2 {
                for late in [false, true] {
                    let (id, cell) = differential_crossing(c, tx, late, Terms::Owed);
                    let end = WeightedTimestamp::from_millis(cell.validity_end_ms);
                    let mut cells = vec![
                        member_row_leaf(PRODUCER, cell.tx),
                        committed_tx_cell_key(PRODUCER, cell.tx, end),
                    ];
                    if c % 3 == 0 {
                        cells.push(id.record_key(&ProtocolHasher));
                    }
                    for key in cells {
                        universe.entry(key).or_insert_with(|| vec![vec![7, 7, 7]]);
                    }
                    if c % 3 == 1 {
                        universe
                            .entry(id.answer_key(&ProtocolHasher, Answered::Never))
                            .or_insert_with(|| vec![vec![7, 7, 7]])
                            .push(
                                id.answer(cell.tx, Answered::Never, cell.validity_end_ms)
                                    .to_bytes(),
                            );
                    }
                }
            }
        }
        universe
    }

    /// Write, rewrite or remove a few of the differential's rows, or its
    /// credit cell, at random.
    fn write_at_random(draws: &mut Draws, rows: &TestRows, written: &mut Vec<SubstateKey>) {
        let credits = differential_credits();
        for _ in 0..draws.below(4) {
            match draws.below(10) {
                0..=3 => {
                    let c = draws.below(18);
                    let c = if c % 3 == 1 { c + 1 } else { c };
                    let (id, cell) =
                        differential_crossing(c, draws.below(2), draws.one_in(2), Terms::Owed);
                    let answer = match draws.below(3) {
                        0 => id.answer(cell.tx, Answered::Taken, cell.validity_end_ms),
                        1 => id.answer(cell.tx, Answered::Never, cell.validity_end_ms),
                        _ => id.unseen_never(cell.tx, cell.validity_end_ms),
                    };
                    let key = id.answer_key(&ProtocolHasher, answer.answered);
                    rows.put(key, answer.to_bytes());
                    written.push(key);
                }
                4..=6 => {
                    let c = 1 + 3 * draws.below(6) + usize::from(draws.one_in(3));
                    let terms = if draws.one_in(3) {
                        Terms::Owed
                    } else {
                        Terms::Escrowed {
                            credit: credits[usize::from(draws.one_in(4))],
                        }
                    };
                    let (id, cell) =
                        differential_crossing(c, draws.below(2), draws.one_in(2), terms);
                    let key = id.record_key(&ProtocolHasher);
                    rows.put(key, cell.to_bytes());
                    written.push(key);
                }
                7 | 8 if !written.is_empty() => {
                    let key = written.swap_remove(draws.below(written.len()));
                    rows.remove(key);
                }
                _ => {
                    let credit = credits[0];
                    if draws.one_in(2) {
                        rows.put(credit, encode_amount(40).to_vec());
                    } else {
                        rows.put(credit, vec![1, 2, 3]);
                    }
                }
            }
        }
    }

    /// The `at`th boundary of the differential's producer, counting from
    /// one, over a tree holding some of `universe`, and what the tree
    /// holds. The first stands ten seconds past the validity end of the
    /// crossings that end early and the rest follow a minute apart.
    fn differential_boundary(
        draws: &mut Draws,
        universe: &BTreeMap<SubstateKey, Vec<Vec<u8>>>,
        at: u64,
    ) -> (Anchor, Vec<(SubstateKey, Vec<u8>)>) {
        let mut held = Vec::new();
        for (key, values) in universe {
            if draws.one_in(3) {
                held.push((*key, values[draws.below(values.len())].clone()));
            }
        }
        assert!(at >= 1, "boundaries count from one");
        let (state_root, _) = state_and_proof_holding(PRODUCER, &held, &[]);
        let end = differential_crossing(0, 0, false, Terms::Owed)
            .1
            .validity_end_ms;
        let boundary = Anchor {
            shard: PRODUCER,
            height: BlockHeight::new(40 * at),
            state_root,
            ts: WeightedTimestamp::from_millis(end + 60_000 * at - 50_000),
        };
        (boundary, held)
    }

    /// Serve some of what `replicas` still ask at each boundary, both
    /// alike, out of that boundary's tree in `trees`: a cell not served
    /// stays asked for, until it is served or let go.
    fn serve_at_random(
        draws: &mut Draws,
        trees: &BTreeMap<Anchor, Vec<(SubstateKey, Vec<u8>)>>,
        replicas: [&mut Counterparts; 2],
    ) {
        let [following, whole] = replicas;
        let waiting: Vec<(Anchor, Vec<SubstateKey>)> = following
            .boundaries
            .at
            .iter()
            .map(|(anchor, at)| (*anchor, at.pending.iter().copied().collect()))
            .collect();
        for (anchor, keys) in waiting {
            let keys: Vec<SubstateKey> = keys.into_iter().filter(|_| draws.one_in(2)).collect();
            if keys.is_empty() {
                continue;
            }
            let (_, proof) = state_and_proof_holding(PRODUCER, &trees[&anchor], &keys);
            following.on_proof_fetched(anchor, &keys, &proof, &[]);
            whole.on_proof_fetched(anchor, &keys, &proof, &[]);
        }
    }

    /// Claims held at one boundary, each cut to the cells a dropped set
    /// leaves, hold what restricting every claim to the cells not
    /// dropped holds: whichever cells of a claim's span go, its first
    /// and last among them.
    #[test]
    fn dropping_cells_leaves_each_claim_restricted_to_the_rest() {
        let mut draws = Draws(0x5DEE_CE66_D1A4_F00D);
        for round in 0..200 {
            let keys: BTreeSet<SubstateKey> = (0..=draws.below(40))
                .map(|_| {
                    let mut local = [0u8; 16];
                    local[..8].copy_from_slice(&draws.next().to_le_bytes());
                    SubstateKey {
                        owner: producer_record(0).owner,
                        local: LocalKey(local),
                    }
                })
                .collect();
            let keys: Vec<SubstateKey> = keys.into_iter().collect();
            let present: Vec<SubstateKey> =
                keys.iter().filter(|_| draws.one_in(2)).copied().collect();
            let mut claims = Vec::new();
            let mut rest = keys.as_slice();
            while !rest.is_empty() {
                let (span, after) = rest.split_at(1 + draws.below(rest.len()));
                claims.push(proven_claim(PRODUCER, 9, &present, span));
                rest = after;
            }
            let gone: BTreeSet<SubstateKey> = keys
                .iter()
                .enumerate()
                .filter(|(at, _)| *at + 1 == keys.len() || draws.one_in(3))
                .map(|(_, key)| *key)
                .collect();
            let mut held = BoundaryReadings {
                cells: keys.iter().copied().collect(),
                claims: claims.clone(),
                refuted: BTreeSet::new(),
                pending: BTreeSet::new(),
                asked_at: WeightedTimestamp::ZERO,
                draining: true,
            };
            held.drop_cells(&gone);
            let reference: Vec<StateClaim> = claims
                .iter()
                .filter_map(|claim| claim.restrict(|key| !gone.contains(&key)))
                .collect();
            assert_eq!(held.claims, reference, "round {round}");
            assert!(held.claims.iter().all(|claim| claim.verify().is_ok()));
            assert_eq!(
                held.cells,
                keys.iter()
                    .filter(|key| !gone.contains(key))
                    .copied()
                    .collect(),
                "round {round}"
            );
        }
    }

    /// The crossing each key of `all`, a shard's rows under `trie`,
    /// names, and the answers whose record another shard holds: one
    /// pass over the rows, as a derivation from scratch.
    fn one_pass(
        trie: &ShardTrie,
        all: &[(SubstateKey, Vec<u8>)],
    ) -> (BTreeMap<SubstateKey, CrossingId>, Vec<AnswerRow>) {
        let mut names: BTreeMap<SubstateKey, CrossingId> = BTreeMap::new();
        let mut answers: Vec<AnswerRow> = Vec::new();
        for (key, value) in all {
            match CrossingLeaf::read(&ProtocolHasher, *key, value) {
                Some(CrossingLeaf::Record { cell, .. }) => {
                    let id = CrossingId::of_record(key.owner, &cell);
                    names.insert(id.answer_key(&ProtocolHasher, Answered::Taken), id);
                    names.insert(id.answer_key(&ProtocolHasher, Answered::Never), id);
                }
                Some(CrossingLeaf::Answer { id, answer }) => {
                    let record = id.record_key(&ProtocolHasher);
                    names.insert(record, id);
                    let holder = trie.shard_for_prefix(record.owner);
                    if holder != CONSUMER {
                        let end = WeightedTimestamp::from_millis(answer.validity_end_ms);
                        answers.push(AnswerRow {
                            holder,
                            record,
                            row: member_row_leaf(holder, answer.tx),
                            marker: committed_tx_cell_key(holder, answer.tx, end),
                            validity_end: end,
                        });
                    }
                }
                None => {}
            }
        }
        (names, answers)
    }

    /// The rows a replica holds, put and taken down in any order, answer
    /// what one pass over the rows derives: each key's crossing, each
    /// cell's deleting reading, the holders, and at a boundary which
    /// cells an answer or a return reads and which a deletion or a
    /// return still needs against what is refuted there.
    #[test]
    fn the_rows_answer_what_one_pass_over_them_derives() {
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let universe = differential_universe();
        for seed in 1..=16u64 {
            let mut draws = Draws(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
            let index = TestRows::default();
            let mut rows = CrossingRows::default();
            let mut written = Vec::new();
            for step in 0..120 {
                write_at_random(&mut draws, &index, &mut written);
                let (read, cursor) = index.crossing_changes(CONSUMER, rows.since(&trie));
                rows.take(&trie, CONSUMER, read, cursor);
                let CrossingRead::Whole(all) = index.crossing_changes(CONSUMER, None).0 else {
                    panic!("no cursor reads whole");
                };
                let (names, answers) = one_pass(&trie, &all);
                assert_eq!(
                    rows.names
                        .iter()
                        .map(|(key, (id, _))| (*key, *id))
                        .collect::<BTreeMap<_, _>>(),
                    names,
                    "seed {seed} step {step}"
                );
                let deleting: BTreeMap<SubstateKey, bool> = answers
                    .iter()
                    .flat_map(|row| [(row.record, false), (row.row, false), (row.marker, true)])
                    .collect();
                let mut holders: BTreeMap<ShardId, usize> = BTreeMap::new();
                for row in &answers {
                    *holders.entry(row.holder).or_default() += 1;
                }
                assert_eq!(rows.holders, holders, "seed {seed} step {step}");
                let at = 1 + draws.below(4) as u64;
                let (anchor, _) = differential_boundary(&mut draws, &universe, at);
                let refuted: BTreeSet<SubstateKey> = universe
                    .keys()
                    .chain(deleting.keys())
                    .filter(|_| draws.one_in(3))
                    .copied()
                    .collect();
                let (mut reads, mut needed) = (BTreeSet::new(), BTreeSet::new());
                for row in answers.iter().filter(|row| row.holder == anchor.shard) {
                    let cells = row.cells(&anchor);
                    if !cells.iter().any(|cell| refuted.contains(cell)) {
                        needed.extend(cells.iter().copied());
                    }
                    reads.extend(cells);
                }
                for (answer, _) in rows
                    .answer_asks
                    .iter()
                    .filter(|(_, ask)| ask.holder == anchor.shard)
                {
                    if !refuted.contains(answer) {
                        needed.insert(*answer);
                    }
                    reads.insert(*answer);
                }
                for key in universe.keys().chain(deleting.keys()) {
                    assert_eq!(
                        rows.deleting(*key),
                        deleting.get(key).copied(),
                        "seed {seed} step {step}"
                    );
                    assert_eq!(
                        rows.reads_at(&anchor, *key),
                        reads.contains(key),
                        "seed {seed} step {step}"
                    );
                    assert_eq!(
                        rows.needed_at(&anchor, *key, &refuted),
                        needed.contains(key),
                        "seed {seed} step {step}"
                    );
                }
            }
        }
    }

    /// Rows written, rewritten and removed at random, a journal that
    /// restarts, a trie that splits the records' holder, boundaries asked
    /// and read with some cells refuted, and deletions carried: a replica
    /// following the index's changes holds after every commit exactly
    /// what one reading the rows whole at every commit holds, and both
    /// ask, release and offer alike.
    #[test]
    fn a_replica_following_the_changes_holds_what_one_reading_them_whole_holds() {
        let whole_trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let split_trie =
            ShardTrie::from_leaves([CONSUMER, ShardId::leaf(2, 2), ShardId::leaf(2, 3)]);
        let universe = differential_universe();
        for seed in 1..=24u64 {
            let mut draws = Draws(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let rows = Arc::new(TestRows::default());
            let new = |index: Arc<dyn CrossingIndex>| {
                Counterparts::new(
                    CONSUMER,
                    Arc::new(ProvenAnchors::default()),
                    Arc::new(CounterpartMirror::default()),
                    index,
                    ReadFrontier::default(),
                )
            };
            let mut following = new(Arc::clone(&rows) as _);
            let mut whole = new(Arc::new(ReadWhole(Arc::clone(&rows))));
            let mut trie = whole_trie.clone();
            let mut boundaries: Vec<Anchor> = Vec::new();
            let mut written: Vec<SubstateKey> = Vec::new();
            let mut trees: BTreeMap<Anchor, Vec<(SubstateKey, Vec<u8>)>> = BTreeMap::new();
            for step in 0..240 {
                let now = WeightedTimestamp::from_millis(500_000 + 1_000 * step);
                write_at_random(&mut draws, &rows, &mut written);
                if draws.one_in(25) {
                    rows.restart();
                }
                if draws.one_in(30) {
                    trie = if trie == whole_trie {
                        split_trie.clone()
                    } else {
                        whole_trie.clone()
                    };
                }
                if draws.one_in(12) {
                    let (boundary, held) =
                        differential_boundary(&mut draws, &universe, boundaries.len() as u64 + 1);
                    trees.insert(boundary, held);
                    boundaries.push(boundary);
                }
                let schedule = recording(&boundaries[boundaries.len().saturating_sub(3)..]);
                // The commit: what each derives, keeps and asks.
                following.clock = now;
                whole.clock = now;
                following.derive_asks(&trie);
                whole.derive_asks(&trie);
                let released = following.settle_boundaries(&schedule, now);
                assert_eq!(
                    format!("{released:?}"),
                    format!("{:?}", whole.settle_boundaries(&schedule, now)),
                    "seed {seed} step {step}"
                );
                let asked = following.ask_boundaries(&schedule, now);
                assert_eq!(
                    format!("{asked:?}"),
                    format!("{:?}", whole.ask_boundaries(&schedule, now)),
                    "seed {seed} step {step}"
                );
                assert_eq!(
                    derived(&following),
                    derived(&whole),
                    "seed {seed} step {step}"
                );
                serve_at_random(&mut draws, &trees, [&mut following, &mut whole]);
                // A block carrying part of the first offer.
                let offered = following.offers(&CarriedClaims::default()).boundary_claims;
                assert_eq!(
                    format!("{offered:?}"),
                    format!(
                        "{:?}",
                        whole.offers(&CarriedClaims::default()).boundary_claims
                    ),
                    "seed {seed} step {step}"
                );
                if let Some(offer) = offered.first().filter(|_| draws.one_in(2)) {
                    let carried = offer.carrying(1 + draws.below(offer.deletions.len()));
                    following.cut_carried(&CarriedClaims::of(CONSUMER, &carried));
                    whole.cut_carried(&CarriedClaims::of(CONSUMER, &carried));
                    // The fold deletes the answers whose records the
                    // block read absent.
                    for claim in &carried {
                        for record in claim.deleting() {
                            if let Some(id) = following.crossing_of(record) {
                                for answered in [Answered::Taken, Answered::Never] {
                                    let key = id.answer_key(&ProtocolHasher, answered);
                                    if draws.one_in(2) {
                                        rows.remove(key);
                                        written.retain(|written| *written != key);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// `recorder` installed while `f` runs.
    fn with_recorder<R>(recorder: &MemoryRecorder, f: impl FnOnce() -> R) -> R {
        let scoped: Arc<dyn MetricsRecorder> = Arc::new(recorder.clone());
        with_scoped_recorder(scoped, f)
    }

    /// Records the cap holds back are each counted due once, when first
    /// found due, and each pushed once, the held-back one first at the
    /// next height.
    #[test]
    fn a_record_the_cap_holds_back_is_found_due_once() {
        let end = WeightedTimestamp::from_millis(36_000);
        let trie = ShardTrie::from_leaves([CONSUMER, PRODUCER]);
        let rows = Arc::new(TestRows::default());
        let records: BTreeSet<SubstateKey> = (0..=MAX_UNSOLICITED_RECORDS_PER_PRODUCER)
            .map(|seed| {
                let (record, _, cell) = escrowed_record(u8::try_from(seed).expect("small"), 36_000);
                rows.put(record, cell.to_bytes());
                record
            })
            .collect();
        let mut producer = Counterparts::new(
            PRODUCER,
            Arc::new(ProvenAnchors::default()),
            Arc::new(CounterpartMirror::default()),
            Arc::clone(&rows) as _,
            ReadFrontier::default(),
        );
        producer.derive_asks(&trie);
        let recorder = MemoryRecorder::new();
        let (first, second) = with_recorder(&recorder, || {
            (
                producer.record_repushes(&trie, end, BlockHeight::new(1)),
                producer.record_repushes(&trie, end, BlockHeight::new(2)),
            )
        });
        assert_eq!(first[&CONSUMER].len(), MAX_UNSOLICITED_RECORDS_PER_PRODUCER);
        let held_back: Vec<SubstateKey> = records
            .iter()
            .filter(|record| !first[&CONSUMER].contains(record))
            .copied()
            .collect();
        assert_eq!(held_back.len(), 1);
        assert!(
            second[&CONSUMER].contains(&held_back[0]),
            "the held-back record goes at the next height",
        );
        assert_eq!(
            recorder.counter("repush_due", None),
            u64::try_from(records.len()).expect("small"),
            "each record is counted due once, held back or not",
        );
        assert_eq!(
            recorder.counter("records_repushed", Some("escrowed")),
            u64::try_from(MAX_UNSOLICITED_RECORDS_PER_PRODUCER * 2).expect("small"),
            "and each push is counted",
        );
    }
}
