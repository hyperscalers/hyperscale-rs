//! In-flight proposal correlation and the variant taxonomy of proposal
//! kinds.
//!
//! Proposal building is asynchronous: the coordinator emits a
//! `BuildProposal` action, the runner executes it on a worker thread, and
//! the result comes back as a `ProposalBuilt` event. Between those two
//! moments, another `try_propose` could fire (e.g. a repeated
//! proposal-retry latch) or the round could advance. [`ProposalTracker`]
//! holds the `(height, round)` of the in-flight build so the
//! `ProposalBuilt` handler can detect stale callbacks and the `try_propose`
//! path can back off while a build is already pending.
//!
//! [`ProposalKind`] names the three shapes of proposal the coordinator can
//! emit — full content, empty fallback, empty sync — so a single
//! build-and-dispatch helper can drive them uniformly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_engine::tick_select::{ManifestInputs, terms_of};
use hyperscale_storage::{
    SettledHalf, Substates, committed_tx_cell_key, member_row_leaf, unclaimed_records,
};
use hyperscale_types::{
    AbandonmentRecord, Anchor, BeaconWitnessLeafCount, BlockHash, BlockHeight, BoundaryAttestation,
    BoundaryOffer, CarriedClaims, Epoch, EpochWindows, Finalization, FrontierInputs, Hash,
    Inclusion, IntakeView, LocalTimestamp, MAX_CLAIMS_PER_BLOCK, MAX_HELD_VALUE_BYTES,
    MAX_HOLDS_PER_MEMBER, MAX_PROOFS_PER_QUERY, MAX_STATE_CLAIMS_BYTES, MAX_STATE_CLAIMS_PER_BLOCK,
    MemberCollection, ProposerTimestamp, Provisions, ReadFence, ReadMark, ReadySignal,
    ReshapeTrigger, RevealChain, Round, STATE_CLAIM_BYTES, STATE_CLAIM_CELL_BYTES,
    STATE_CLAIM_CROSSING_BYTES, ShardId, StateClaim, SubstateClaim, SubstateKey,
    TimeoutCertificate, TopologySnapshot, Transaction, TxHash, UnsettledTx, ValidatorId,
    Verifiable, Verified, WeightedTimestamp, claims_admit_block, state_claims_admit_block,
    tick_terms_admit_block, verdict_leaf,
};
use hyperscale_vm_effects::CrossingId;
use tracing::debug;

use crate::admission::{
    Committed, FinalizationsFold, FinalizationsSection, ProvisionsFold, ProvisionsSection,
    RecordsFold, RecordsSection, Section, StateClaimsFold, StateClaimsSection, TransactionsFold,
    TransactionsSection, admit_each, predated_at, unwrapped,
};
use crate::carried::CommittedCarried;
use crate::chain_view::ChainView;
use crate::commit_dedup::CommitDedupIndex;
use crate::precut::Precut;
use crate::verification::VerificationPipeline;

/// What a proposer asks its node for: the content of the block it is
/// about to build, selected against the readings handed over here.
///
/// The coordinator makes one of these once it has resolved the parent
/// the block extends, so everything read through it is read at that
/// parent and the committed tip behind it.
pub struct ProposalAsk<'a> {
    /// What the ready set is filled against.
    pub intake: IntakeView<'a>,
    /// The committee the block is classified under.
    pub(crate) committee: &'a TopologySnapshot,
    pub(crate) local_shard: ShardId,
    pub(crate) dedup: &'a CommitDedupIndex,
    pub(crate) committed_anchor: WeightedTimestamp,
    /// What the blocks between the committed tip and the parent carry in
    /// their claims.
    pub(crate) pending_carried: &'a CarriedClaims,
    /// What the committed blocks carry in their claims, by height.
    pub(crate) committed_carried: &'a CommittedCarried,
}

impl ProposalAsk<'_> {
    /// What the chain from `folded`, the height a node's execution has
    /// folded through, up to the parent carries in its claims: the
    /// blocks above the committed tip, and the committed blocks above
    /// `folded`. The offer passes over all of it, since the fold that
    /// retires it has not run.
    #[must_use]
    pub fn carried_above(&self, folded: BlockHeight) -> CarriedClaims {
        let mut carried = self.pending_carried.clone();
        for committed in self.committed_carried.above(folded) {
            carried.extend(committed);
        }
        carried
    }

    /// Whether the engagement evidence for `tx` is in hand, as the
    /// block's committee places it: it is single-shard, this shard is
    /// the payer's, the payer's bundle rides the proposal, or a
    /// committed block's engagements name it.
    ///
    /// `riding` answers whether a bundle from the payer's shard naming
    /// the transaction is among the provisions the node offers this
    /// proposal. The committed tier is the one a voter's committed arm
    /// reads, asked at the committed tip's anchor, the clock the
    /// proposer knows: the proposal's own anchor sits at or above it,
    /// and the transactions section drops whatever lapses between the
    /// two.
    #[must_use]
    pub fn engagement_held(
        &self,
        tx: &Transaction,
        riding: impl FnOnce(ShardId, TxHash) -> bool,
    ) -> bool {
        if self.committee.is_single_shard_transaction(tx) {
            return true;
        }
        let payer_shard = self.committee.shard_trie().shard_for_prefix(tx.fee_payer());
        if payer_shard == self.local_shard {
            return true;
        }
        let tx_hash = tx.hash();
        self.dedup
            .engaged(payer_shard, tx_hash, self.committed_anchor, self.committee)
            || riding(payer_shard, tx_hash)
    }
}

/// What a node offers a proposal: each section's candidates, which the
/// coordinator admits against the chain behind the parent before any of
/// them is built into the block.
#[derive(Debug, Default)]
pub struct ProposalInputs {
    /// The pool's ready set, in hash order.
    pub ready_txs: Vec<Arc<Verified<Transaction>>>,
    /// Finalizations execution holds ready to commit.
    pub finalizations: Vec<Arc<Verifiable<Finalization>>>,
    /// Provision bundles queued from remote shards.
    pub provisions: Vec<Arc<Verifiable<Provisions>>>,
    /// What departed counterparts left of this chain's business.
    pub abandonment_records: Vec<AbandonmentRecord>,
    /// Proofs of counterparts' cells this validator's fetches answered.
    pub state_claims: Vec<StateClaim>,
    /// Proofs of siblings' verdict cells, for the rows that hear them.
    pub verdict_claims: Vec<StateClaim>,
    /// Readings at the boundaries the beacon recorded for counterparts,
    /// each anchor's with the deletions they license.
    pub boundary_claims: Vec<BoundaryOffer>,
    /// Crossings whose ends share this shard.
    pub local_crossings: Vec<CrossingId>,
}

/// Variant-specific content for a proposal build.
///
/// The coordinator uses this to pass proposal-kind-specific inputs
/// (payload, timestamp source, `is_fallback` flag, logging label) to its
/// unified build-and-dispatch helper.
#[derive(Debug)]
pub enum ProposalKind {
    /// Normal proposal with a filtered payload and a real-clock timestamp.
    Normal(Box<ProposalPayload>),
    /// View-change fallback: empty payload, parent's weighted timestamp
    /// (prevents Byzantine proposers from manipulating consensus time on
    /// timeout), `is_fallback = true`.
    Fallback,
    /// Syncing proposer: empty payload, normal timestamp. Proposer is
    /// online with an accurate clock but can't execute transactions.
    Sync,
}

/// What a normal proposal carries, each list already selected against
/// the chain. Empty for a block that exists only to advance the chain.
#[derive(Debug, Default)]
pub struct ProposalPayload {
    pub(crate) transactions: Vec<Arc<Verified<Transaction>>>,
    pub(crate) finalizations: Vec<Arc<Verifiable<Finalization>>>,
    pub(crate) provisions: Vec<Arc<Verifiable<Provisions>>>,
    pub(crate) abandonment_records: Vec<AbandonmentRecord>,
    pub(crate) state_claims: Vec<StateClaim>,
    /// The crossings whose ends share this shard, and those whose record
    /// the block takes back, for the builder to read at the parent beside
    /// the claims.
    pub(crate) local_crossings: Vec<CrossingId>,
    /// The transactions whose member rows the builder may read absent
    /// at the parent, as [`ParentReads::rowless`] gives them.
    pub(crate) rowless: Vec<TxHash>,
    /// What the read frontier judges of the claims selected, for the
    /// builder to drop against the parent state.
    pub(crate) fence: ReadFence,
}

#[derive(Debug, Clone)]
pub struct PendingProposal {
    pub(crate) height: BlockHeight,
    pub(crate) round: Round,
}

pub struct ProposalTracker {
    pending: Option<PendingProposal>,
    /// Slot for a proposal that `dispatch_or_defer` could not dispatch
    /// because the parent JMT tree wasn't available yet. Consulted from
    /// `can_propose` so repeated proposal-retry / QC-formed events for
    /// the same `(height, round)` don't spin through `assemble_build_action`
    /// while we're blocked waiting on `VerificationPipeline` to unblock.
    deferred: Option<PendingProposal>,
}

/// Result of correlating a `ProposalBuilt` callback against the tracker.
#[derive(Debug)]
pub enum TakeResult {
    /// The callback matches the in-flight build; the slot has been cleared.
    Matched,
    /// No build was in flight when the callback arrived.
    NotPending,
    /// A build was in flight but for different coordinates. The slot is
    /// preserved so the matching callback can still be handled later.
    Mismatch { expected: PendingProposal },
}

impl ProposalTracker {
    pub(crate) const fn new() -> Self {
        Self {
            pending: None,
            deferred: None,
        }
    }

    /// Record a new in-flight build. A successful dispatch also invalidates
    /// any deferred slot for a prior attempt.
    pub(crate) const fn start(&mut self, height: BlockHeight, round: Round) {
        self.pending = Some(PendingProposal { height, round });
        self.deferred = None;
    }

    /// Read the in-flight build, if any.
    pub(crate) const fn pending(&self) -> Option<&PendingProposal> {
        self.pending.as_ref()
    }

    /// Drop both the in-flight and deferred slots. Called on round advance
    /// so a stale build completing later is discarded by the next
    /// `take_matching` and the deferred slot doesn't gate the new round's
    /// `(height, round)` target.
    pub(crate) const fn clear(&mut self) {
        self.pending = None;
        self.deferred = None;
    }

    /// Record that a build for `(height, round)` could not dispatch because
    /// the parent JMT tree wasn't available. Consulted by `can_propose` to
    /// suppress re-entry until `clear_deferred` fires.
    pub(crate) const fn mark_deferred(&mut self, height: BlockHeight, round: Round) {
        self.deferred = Some(PendingProposal { height, round });
    }

    /// Read the deferred slot, if any.
    pub(crate) const fn deferred(&self) -> Option<&PendingProposal> {
        self.deferred.as_ref()
    }

    /// Drop the deferred slot. Called when the verification pipeline signals
    /// that the awaited parent tree has landed, so the next `try_propose`
    /// actually re-dispatches.
    pub(crate) const fn clear_deferred(&mut self) {
        self.deferred = None;
    }

    /// Consume the in-flight build iff its `(height, round)` matches.
    pub(crate) fn take_matching(&mut self, height: BlockHeight, round: Round) -> TakeResult {
        match self.pending.take() {
            None => TakeResult::NotPending,
            Some(p) if p.height == height && p.round == round => TakeResult::Matched,
            Some(p) => {
                let expected = p.clone();
                self.pending = Some(p);
                TakeResult::Mismatch { expected }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Payload selection
// ═══════════════════════════════════════════════════════════════════════════

/// What a proposer answers for itself that its voters answer at the
/// fence: the precut rule for transactions opening before the chain's
/// origin.
#[derive(Clone, Copy)]
pub struct Prefilter<'a> {
    /// The precut rule for transactions opening before the origin.
    pub(crate) precut: &'a Precut,
}

/// Filter ready transactions for proposal inclusion. Drops what the
/// voters' delegated root check refuses — a `validity_range` malformed
/// against the anchor or not containing it — and what their fence defers on
/// — a transaction opening before the chain's origin that the precut rule
/// does not yet pass; then keeps what
/// [`TransactionsSection`] admits, folding into `fold`. A transaction
/// that does not fit the sweep cap is skipped rather than ending the
/// selection, so a large composition never starves the small ones
/// behind it.
///
/// A transaction reaching beyond this shard is charged the weight of the
/// terms entry its block states for it, against the terms section's
/// budget, and one that would carry the sum past the budget is left
/// pooled with the selection continuing behind it. One reaching no
/// further is ready in the block that commits it and is charged nothing.
/// A transaction declaring more accesses than a member's terms carry is
/// passed over before any terms are derived for it: admission refuses
/// it, and its terms cannot be stated.
///
/// Logs the refusals when non-zero.
pub fn select_transactions(
    ctx: &Committed<'_>,
    prefilter: Prefilter<'_>,
    fold: &mut TransactionsFold<'_>,
    ready_txs: &[Arc<Verified<Transaction>>],
) -> Vec<Arc<Verified<Transaction>>> {
    let before = ready_txs.len();
    let mut expired = 0;
    let mut predates = 0;
    let candidates: Vec<Arc<Verified<Transaction>>> = ready_txs
        .iter()
        .filter(|tx| {
            let h = tx.hash();
            let range = tx.validity_range();
            if !range.is_well_formed(ctx.anchor) || !range.contains(ctx.anchor) {
                expired += 1;
                return false;
            }
            // Opened before this chain did, so a predecessor may have
            // committed it. Offerable once the precut rule passes it —
            // for a right child, once the parent's terminal state proved
            // its marker absent; anything else a voter defers on or
            // refuses. Zero for a chain born at network genesis.
            if range.start_timestamp_inclusive < ctx.chain_origin
                && !prefilter
                    .precut
                    .admissible(h, range.end_timestamp_exclusive)
            {
                predates += 1;
                return false;
            }
            true
        })
        .cloned()
        .collect();
    let mut refused = 0usize;
    let mut unstated = 0usize;
    let mut stated = 0usize;
    let mut selected = Vec::with_capacity(candidates.len());
    for tx in candidates {
        if tx.routing().declared_modes.len() > MAX_HOLDS_PER_MEMBER {
            refused += 1;
            continue;
        }
        let charged = if ctx.snapshot.is_single_shard_transaction(&tx) {
            stated
        } else {
            stated.saturating_add(terms_of(&tx, ctx.snapshot, ctx.local_shard).wire_weight())
        };
        if !tick_terms_admit_block(charged) {
            unstated += 1;
            continue;
        }
        if TransactionsSection::admit(ctx, fold, &tx).is_err() {
            refused += 1;
            continue;
        }
        stated = charged;
        selected.push(tx);
    }
    if expired > 0 || predates > 0 || refused > 0 || unstated > 0 {
        debug!(
            expired,
            predates,
            refused,
            unstated,
            before,
            after = selected.len(),
            "Filtered proposal candidates"
        );
    }
    selected
}

/// Select finalizations for inclusion: what [`FinalizationsSection`]
/// admits, in the caller's order, folding into `fold`.
///
/// Order is the caller's and is preserved. It arrives in the order the
/// ticks executed, which is the order their receipts have to settle in —
/// two ticks writing one cell each carry an absolute computed from their
/// own baseline, and settlement is last writer per cell, so the later
/// execution must land last. Re-sorting here by kickoff height would
/// invert exactly the pairs that matter: a tick held back from its own
/// block's tick executes after a later-numbered one it shares a cell
/// with. The store hands them over in tick order, a tick's determined
/// half ahead of its legs half, so the order rule drops only what a gap
/// in that order would have made unofferable anyway, and the cap drops a
/// suffix.
pub fn select_finalizations(
    ctx: &Committed<'_>,
    fold: &mut FinalizationsFold,
    finalizations: Vec<Arc<Verifiable<Finalization>>>,
) -> Vec<Arc<Verifiable<Finalization>>> {
    admit_each::<FinalizationsSection, _>(ctx, fold, finalizations, unwrapped).0
}

/// Select the boundary records for inclusion: each trimmed to the names
/// [`RecordsSection::name_stands`] admits — a name a finalization in
/// the block resolves, or one the chain already resolved, is refused by
/// every voter — and to the crossings the departed shard was the one to
/// take, with an emptied record dropped rather than offered, then what
/// [`RecordsSection`] admits in canonical order.
///
/// A departure's evidence stops answering at the departed shard's
/// terminal-evidence expiry, read at the block's anchor. The composing
/// side holds the set against the *committed* frontier while the vote
/// reads the block's own anchor, which runs ahead of it, so the two can
/// disagree by up to the pipeline's depth: without this the proposer
/// offers a record every voter refuses, and because a chain that
/// commits nothing never advances the frontier that would retire the
/// set, the next proposal carries it again.
pub fn select_abandonment_records(
    ctx: &Committed<'_>,
    fold: &mut RecordsFold<'_>,
    records: Vec<AbandonmentRecord>,
) -> Vec<AbandonmentRecord> {
    let departures: Vec<(ShardId, WeightedTimestamp)> =
        ctx.schedule.departures_at(ctx.anchor).collect();
    let mut trimmed: Vec<AbandonmentRecord> = records
        .into_iter()
        .filter_map(|record| {
            let kept: Vec<UnsettledTx> = record
                .unsettled()
                .iter()
                .filter(|entry| {
                    entry.party(
                        ctx.local_shard,
                        record.shard(),
                        record.terminal_wt(),
                        &departures,
                    ) && RecordsSection::name_stands(ctx, fold, entry.tx_hash).is_ok()
                })
                .cloned()
                .collect();
            let kept = AbandonmentRecord::new(record.shard(), record.terminal_wt(), kept);
            (kept.names() > 0).then_some(kept)
        })
        .collect();
    trimmed.sort_by_key(AbandonmentRecord::shard);
    admit_each::<RecordsSection<'_>, _>(ctx, fold, trimmed, |record| record).0
}

/// The claims a block may carry of counterparts' cells for every
/// question but a verdict question: what [`StateClaimsSection`] admits,
/// in the one order it carries them, spent against those claims' byte
/// budget in the order the composer offers them.
///
/// The budget is spent in the offered order, one producer's claims
/// together in anchor order and the producers by their oldest anchor,
/// so no claim of a producer rides while an older one of it is held
/// back and one busy producer cannot starve another. The first claim
/// that does not fit is cut to the longest key prefix whose piece fits,
/// that piece is kept and the spending ends there: a claim is split by
/// key, never dropped whole, and the composer offers the remainder at
/// the next proposal, which passes over what the chain to its parent
/// carries.
/// What was kept is then sorted into the section's order and admitted.
/// What the order rule refuses waits a block, with every claim of its
/// producer's lineage anchored above it, so the frontier this block
/// raises never passes a claim it held back.
///
/// A claim anchored more than a horizon before the block
/// ([`StateClaim::at_boundary`]) is passed over and charged nothing,
/// whatever it reads: a voter holds such a claim's anchor to the
/// boundaries its schedule records and to no header, so only
/// [`spend_on_boundary_claims`], which asks the schedule, carries one.
#[must_use]
pub fn select_state_claims(
    ctx: &Committed<'_>,
    fold: &mut StateClaimsFold,
    state_claims: Vec<StateClaim>,
) -> Vec<StateClaim> {
    let mut kept = Vec::new();
    let mut weight = 0usize;
    for claim in state_claims {
        if kept.len() >= MAX_STATE_CLAIMS_PER_BLOCK {
            break;
        }
        if claim.at_boundary(ctx.anchor) {
            continue;
        }
        if state_claims_admit_block(weight.saturating_add(claim.wire_weight())) {
            weight = weight.saturating_add(claim.wire_weight());
            kept.push(claim);
            continue;
        }
        let keys = claim.keys();
        let piece = (1..keys.len()).rev().find_map(|kept| {
            let piece = claim.restrict(|key| keys[..kept].contains(&key))?;
            state_claims_admit_block(weight.saturating_add(piece.wire_weight())).then_some(piece)
        });
        if let Some(piece) = piece {
            kept.push(piece);
        }
        break;
    }
    kept.sort_unstable();
    kept.dedup();
    // A claim the order rule refuses rides a later block, and so does
    // every claim of its producer's lineage anchored above it: a carried
    // claim that names a crossing or holds a value raises its producer's
    // read frontier, and a floor raised past a held record presence
    // refuses it unread.
    let mut refused: Vec<Anchor> = Vec::new();
    kept.into_iter()
        .filter(|claim| {
            let behind = |anchor: &Anchor| {
                claim.anchor.height > anchor.height
                    && (anchor.shard.is_ancestor_of(claim.anchor.shard)
                        || claim.anchor.shard.is_ancestor_of(anchor.shard))
            };
            if refused.iter().any(behind) {
                return false;
            }
            if !fold.in_order(claim) {
                refused.push(claim.anchor);
                return false;
            }
            StateClaimsSection::admit(ctx, fold, claim).is_ok()
        })
        .collect()
}

/// What a block reads at its own parent beside the claims it carries of
/// other shards, for the builder to read there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParentReads {
    /// The crossings whose ends share this shard, and those whose record
    /// the block takes back beside a `Never` it carries.
    pub crossings: Vec<CrossingId>,
    /// The transactions whose member rows may be read absent: each
    /// issued an escrowed record the block's claims hold for a consumer
    /// here past its validity end, and holds no row at the parent. The
    /// reading a decline is written on.
    pub rowless: Vec<TxHash>,
}

/// The claims section of a block, spent in the order of what it gates:
/// the claims held for crossing, seat and ledger questions first, as
/// [`select_state_claims`] takes them; then the parent's readings, the
/// member rows a decline of those claims reads, as [`rowless_issuers`]
/// names them, and the local crossings, as [`trim_parent_reads`] fits
/// both behind those; then the claims held for verdict questions, in
/// what bytes and places the first two leave of the section; and the
/// boundary claims last, in what all three leave. So no verdict reading
/// takes a place from a reading that gates execution, at any anchor or
/// at the parent, and none waits on one: the
/// first two spend no more than [`MAX_STATE_CLAIMS_BYTES`] and
/// [`MAX_STATE_CLAIMS_PER_BLOCK`] between them, of a section holding
/// `MAX_CLAIMS_BYTES` and [`MAX_CLAIMS_PER_BLOCK`], so what is left to
/// the verdict claims is never under `MAX_VERDICT_CLAIMS_BYTES`, and is
/// more wherever the first two take less. Each claim is charged as
/// admission charges it.
///
/// The verdict claims are taken in the order offered, each cut first to
/// what a row at the parent would hear once the block's `finalizations`
/// have settled, by [`heard_at_the_parent`], and carried only where it
/// fits the section's order beside what is already selected: a claim
/// whose key span meets another claim's at its anchor waits a block, and
/// refuses nothing. The proof of a claim is cut only once the claim is
/// known to have a place. A claim the bytes left do not hold is cut to
/// as many of its readings, in member order, as fit, by
/// [`longest_fitting_prefix`]: a reading rides whole or waits. The
/// spending ends at the first claim carried cut, and a claim admission
/// refuses, cut or whole, is passed over for the ones behind it.
///
/// `finalizations` are the ones the block carries, as
/// [`select_finalizations`] admitted them. They are read for the rows
/// they delete and nothing else: no claim held for another question and
/// no local crossing is chosen by them.
///
/// A boundary claim is the reading an answer is deleted on, or a record
/// taken back on, and no member waits on either: no take, no retirement.
/// An epoch's become offerable together, at the beacon fold that records
/// the boundary they are read at, and a boundary is the oldest anchor
/// any producer is read at. So `boundary_claims` are held apart from
/// every order above and spent last, by [`spend_on_boundary_claims`]:
/// they take no byte and no place from a reading a member waits on,
/// whatever their number, and never ride ahead of their producer's fresh
/// claims. One carried a block later is still admissible, since no floor
/// a fresh claim raises refuses a boundary reading. A record a block
/// takes back is one unit with the consumer's `Never` it goes back on:
/// the spend charges the record's reading at the parent beside the
/// `Never` that carries it, and hands the record's crossing back to be
/// read there.
#[must_use]
pub fn select_claims(
    ctx: &Committed<'_>,
    fold: &mut StateClaimsFold,
    state_claims: Vec<StateClaim>,
    verdict_claims: Vec<StateClaim>,
    boundary_claims: &[BoundaryOffer],
    local_crossings: Vec<CrossingId>,
    finalizations: &[Arc<Verifiable<Finalization>>],
) -> (Vec<StateClaim>, ParentReads) {
    let mut selected = select_state_claims(ctx, fold, state_claims);
    let rowless = rowless_issuers(ctx, &selected);
    let crossings = local_crossings;
    let mut at_parent = trim_parent_reads(&selected, ParentReads { crossings, rowless });
    let (local_claims, local_weight) =
        parent_reads_weight(at_parent.crossings.len(), at_parent.rowless.len());
    let others = fold.weight.saturating_add(local_weight);
    let mut weight = fold.verdict_weight;
    let fresh = selected.len().saturating_add(local_claims);
    let mut count = fresh;
    let mut spans: BTreeMap<Anchor, Vec<(SubstateKey, SubstateKey)>> = BTreeMap::new();
    for claim in &selected {
        if let Some(((lo, _), (hi, _))) = claim.cells.first().zip(claim.cells.last()) {
            spans.entry(claim.anchor).or_default().push((*lo, *hi));
        }
    }
    let settled: BTreeSet<TxHash> = if verdict_claims.is_empty() {
        BTreeSet::new()
    } else {
        finalizations
            .iter()
            .flat_map(|fw| SettledHalf::of(fw.as_unverified()).deleted)
            .collect()
    };
    for claim in verdict_claims {
        if count >= MAX_CLAIMS_PER_BLOCK {
            break;
        }
        let heard = heard_at_the_parent(ctx, &settled, &claim, &claim.verdicts);
        let Some((lo, hi)) = heard.first().zip(heard.last()).map(|(lo, hi)| (*lo, *hi)) else {
            continue;
        };
        let beside = spans.entry(claim.anchor).or_default();
        if beside.iter().any(|(from, to)| *from <= hi && lo <= *to) {
            continue;
        }
        let whole = if heard.len() == claim.cells.len() {
            claim
        } else if let Some(cut) = claim.restrict(|key| heard.contains(&key)) {
            cut
        } else {
            continue;
        };
        let fits = |piece: &StateClaim| {
            claims_admit_block(
                others
                    .saturating_add(weight)
                    .saturating_add(piece.wire_weight()),
            )
        };
        let cut = !fits(&whole);
        let kept = if cut {
            longest_fitting_prefix(whole.verdicts.len(), |readings| {
                let cells = heard_at_the_parent(ctx, &settled, &whole, &whole.verdicts[..readings]);
                whole
                    .restrict(|key| cells.binary_search(&key).is_ok())
                    .filter(|piece| fits(piece))
            })
        } else {
            Some(whole)
        };
        let Some(kept) = kept else {
            continue;
        };
        let mut alone = StateClaimsFold {
            weight: others,
            verdict_weight: weight,
            ..StateClaimsFold::default()
        };
        if StateClaimsSection::admit(ctx, &mut alone, &kept).is_err() {
            continue;
        }
        weight = alone.verdict_weight;
        count += 1;
        if let Some(((lo, _), (hi, _))) = kept.cells.first().zip(kept.cells.last()) {
            beside.push((*lo, *hi));
        }
        selected.push(kept);
        if cut {
            break;
        }
    }
    fold.verdict_weight = weight;
    let mut left = StateClaimsFold {
        weight: others,
        verdict_weight: weight,
        count: fresh,
        previous: None,
    };
    let (boundary, returned) = spend_on_boundary_claims(
        ctx,
        &mut left,
        MAX_CLAIMS_PER_BLOCK.saturating_sub(count),
        boundary_claims,
    );
    selected.extend(boundary);
    selected.sort_unstable();
    at_parent.crossings.extend(returned);
    (selected, at_parent)
}

/// The transactions whose member rows a block carrying `selected` may
/// read absent at its parent, ascending and each once: the issuer of
/// each escrowed record the claims hold for a consumer this shard
/// holds, where the block's clock is at or past the record's validity
/// end and the parent's family holds no row for the issuer.
///
/// A decline is written on that reading. A record short of its validity
/// end is one a block here may yet commit the transaction of, and one
/// whose issuer holds a row is one a member here may yet take, so
/// neither row is named. Whether an answer of the transaction already
/// stands is the parent state's to say, which the builder reads and
/// this does not: a row named for such a record is left unread there.
fn rowless_issuers(ctx: &Committed<'_>, selected: &[StateClaim]) -> Vec<TxHash> {
    let mut issuers: Vec<TxHash> = unclaimed_records(selected, ctx.local_shard)
        .into_iter()
        .map(|(_, cell)| cell)
        .filter(|cell| ctx.anchor >= WeightedTimestamp::from_millis(cell.validity_end_ms))
        .map(|cell| cell.tx)
        .filter(|tx| {
            let row = MemberCollection::Members.entry(ctx.local_shard, *tx);
            ctx.members
                .entries_in_range(row.owner, row.collection, row.order, row.order, 1)
                .is_empty()
        })
        .collect();
    issuers.sort_unstable();
    issuers.dedup();
    issuers
}

/// The boundary claims a block carries in what `spent` leaves of its
/// claims section and `places` of its claims: of each anchor's offer in
/// turn, every deletion where they all fit, and otherwise as many whole
/// deletions, in the order offered, as do, by
/// [`longest_fitting_prefix`]. A deletion rides whole or waits, since a
/// record's absence carried without its producing member's row leaf
/// deletes nothing. The spending ends at the first offer carried cut.
///
/// An offer is carried only where every claim of it is at a boundary of
/// the block ([`StateClaim::at_boundary`]), this proposer's own schedule
/// records its anchor as a boundary, and admission admits each in turn.
/// One read at an anchor still fresh to the block deletes and takes back
/// nothing, and a `Never` there is refused, so it waits for the anchor
/// to age;
/// one at an anchor the schedule does not record is one a voter holding
/// the same schedule defers or refuses, at the cost of the round.
/// `spent` is charged what is carried, as admission charges it: a
/// boundary claim names no member, so it is held to the bytes and the
/// count of the claims that are not verdict claims.
///
/// A `Never` carried is a record of this shard's taken back, whose
/// record the block reads at its parent beside it. The two are one
/// unit: each `Never` is charged the reading of its record too, at
/// [`RETURN_READING_BYTES`], in the same spend, so a return is carried
/// whole or waits, and no record is read for a `Never` left out. Hands
/// back the claims and the crossing of every record they take back.
fn spend_on_boundary_claims(
    ctx: &Committed<'_>,
    spent: &mut StateClaimsFold,
    places: usize,
    offers: &[BoundaryOffer],
) -> (Vec<StateClaim>, Vec<CrossingId>) {
    let mut carried: Vec<StateClaim> = Vec::new();
    let mut returned: Vec<CrossingId> = Vec::new();
    for offer in offers {
        if !offer.claims.iter().all(|claim| {
            claim.at_boundary(ctx.anchor)
                && ctx.schedule.attests_boundary(&claim.anchor) == BoundaryAttestation::Stands
        }) {
            continue;
        }
        let admitted = |deletions: usize, spent: &StateClaimsFold, taken: usize| {
            let pieces = offer.carrying(deletions);
            let mut after = StateClaimsFold {
                weight: spent.weight,
                verdict_weight: spent.verdict_weight,
                count: spent.count,
                previous: None,
            };
            let returns = returned_by(&pieces);
            let (claims, weight) = return_reads(returned.len(), returns.len());
            after.weight = after.weight.saturating_add(weight);
            after.count = after.count.saturating_add(claims);
            (!pieces.is_empty()
                && taken.saturating_add(pieces.len()).saturating_add(claims) <= places
                && pieces
                    .iter()
                    .all(|piece| StateClaimsSection::admit(ctx, &mut after, piece).is_ok()))
            .then_some((pieces, returns, after))
        };
        let taken = || carried.len() + return_reads(0, returned.len()).0;
        let whole = admitted(offer.deletions.len(), &*spent, taken());
        let cut = whole.is_none();
        let kept = whole.or_else(|| {
            longest_fitting_prefix(offer.deletions.len(), |deletions| {
                admitted(deletions, &*spent, taken())
            })
        });
        if let Some((pieces, returns, after)) = kept {
            spent.weight = after.weight;
            spent.count = after.count;
            carried.extend(pieces);
            returned.extend(returns);
        }
        if cut {
            break;
        }
    }
    (carried, returned)
}

/// The crossings whose consumer's `Never` `pieces` read present under
/// the crossing's name: the records a block carrying them takes back.
fn returned_by(pieces: &[StateClaim]) -> Vec<CrossingId> {
    pieces
        .iter()
        .flat_map(|claim| claim.returning().map(|(_, id)| id))
        .collect()
}

/// What reading at the parent the records of `more` returns costs, beside
/// `before` already charged: the claims they add, each reading
/// [`MAX_PROOFS_PER_QUERY`] records, and their bytes.
const fn return_reads(before: usize, more: usize) -> (usize, usize) {
    let claims =
        (before + more).div_ceil(MAX_PROOFS_PER_QUERY) - before.div_ceil(MAX_PROOFS_PER_QUERY);
    (
        claims,
        claims * STATE_CLAIM_BYTES + more * RETURN_READING_BYTES,
    )
}

/// What one record taken back is weighed at, read at the parent: one
/// named reading, with the record's value.
const RETURN_READING_BYTES: usize =
    STATE_CLAIM_CELL_BYTES + STATE_CLAIM_CROSSING_BYTES + MAX_HELD_VALUE_BYTES + 4;

/// The piece `piece` builds of the longest prefix of `len` readings,
/// short of them all, that it builds a piece of: `piece` answers `None`
/// for a prefix whose piece does not fit.
///
/// Found by bisection, which rests on a longer prefix fitting only where
/// every shorter one does: where that fails the piece found is shorter
/// than the longest that fits, and never one that does not fit.
fn longest_fitting_prefix<T>(len: usize, mut piece: impl FnMut(usize) -> Option<T>) -> Option<T> {
    let (mut fits, mut over) = (0, len);
    let mut found = None;
    while over - fits > 1 {
        let readings = fits + (over - fits) / 2;
        if let Some(fitting) = piece(readings) {
            found = Some(fitting);
            fits = readings;
        } else {
            over = readings;
        }
    }
    found
}

/// The cells of `claim`, held for verdict questions, that a row at the
/// parent would hear for the members `named`, ascending, in a block
/// whose finalizations delete the rows of `settled`.
///
/// A member's reading is kept where the parent's rows hold a hearing row
/// for it that the block does not delete, that awaits the claim's shard
/// and whose entry for that shard sits below the claim's mark: a reading
/// an ancestor already carried, one for a row the chain to the parent
/// has settled, or one for a row this block settles, which the fold
/// deletes before any row hears, is spent on nothing. A row the block's
/// own stating half first makes hear is not at the parent a row that
/// hears, so its reading rides the next block. A leaf read present is
/// its one cell; a leaf read absent is kept only where the claim holds
/// the member's row and committed marker too, and then as all three.
/// Every other cell is left out. This is the proposer's economy, not a
/// rule of admission, except for one cut: a reading for a row that
/// predates the chain the claim's shard runs at its anchor, as
/// [`predated_at`] tells one, is left out because admission refuses it.
fn heard_at_the_parent(
    ctx: &Committed<'_>,
    settled: &BTreeSet<TxHash>,
    claim: &StateClaim,
    named: &[TxHash],
) -> Vec<SubstateKey> {
    let sibling = claim.anchor.shard;
    let mark = ReadMark::of(&claim.anchor, ctx.windows);
    let predated = predated_at(ctx, &claim.anchor);
    let mut heard: Vec<SubstateKey> = Vec::new();
    for tx in named {
        let Some(row) = ctx.members.members.get(tx).filter(|row| {
            !settled.contains(tx)
                && !predated(row)
                && row.state.hears()
                && row.awaits.contains(&sibling)
                && !row
                    .hearing
                    .iter()
                    .any(|entry| entry.shard == sibling && entry.mark >= mark)
        }) else {
            continue;
        };
        let leaf = verdict_leaf(sibling, *tx);
        let beside = [
            member_row_leaf(sibling, *tx),
            committed_tx_cell_key(sibling, *tx, row.deadline.validity_end()),
        ];
        match claim.reading(leaf) {
            Some(Inclusion::Present(_)) => heard.push(leaf),
            Some(Inclusion::Absent) if beside.iter().all(|key| claim.reading(*key).is_some()) => {
                heard.push(leaf);
                heard.extend(beside);
            }
            _ => {}
        }
    }
    heard.sort_unstable();
    heard
}

/// How many claims, weighing how many bytes, a block's readings of its
/// own parent are counted at: `crossings` local crossings, three keyed
/// and named readings each, and `rows` member rows, one keyed reading
/// each, with the empty proof, cut into claims of
/// [`MAX_PROOFS_PER_QUERY`] readings. The claims are counted as if the
/// two kinds were cut apart, which is never fewer than they are cut
/// into together.
const fn parent_reads_weight(crossings: usize, rows: usize) -> (usize, usize) {
    let claims =
        crossings.div_ceil(LOCAL_CROSSINGS_PER_CLAIM) + rows.div_ceil(MAX_PROOFS_PER_QUERY);
    (
        claims,
        claims * STATE_CLAIM_BYTES
            + crossings * LOCAL_CROSSING_BYTES
            + rows * STATE_CLAIM_CELL_BYTES,
    )
}

/// What one local crossing is weighed at. A record rides with its
/// value, which a crossing of either kind is weighed at: the bound is
/// the widest record and its length. A crossing read for a decline is
/// its record and one member row, which is under the three named
/// readings it is weighed at.
const LOCAL_CROSSING_BYTES: usize =
    3 * (STATE_CLAIM_CELL_BYTES + STATE_CLAIM_CROSSING_BYTES) + MAX_HELD_VALUE_BYTES + 4;

/// How many local crossings one claim reads.
const LOCAL_CROSSINGS_PER_CLAIM: usize = MAX_PROOFS_PER_QUERY / 3;

/// The readings of `offered` the budget of the claims that are not
/// verdict claims still carries once `selected` is in it, read at the
/// parent with the empty proof and cut into claims of
/// [`MAX_PROOFS_PER_QUERY`] readings: the member rows first, each of
/// which completes a record reading `selected` already spends on, and
/// the local crossings in what those leave. What does not fit waits a
/// block.
#[must_use]
pub fn trim_parent_reads(selected: &[StateClaim], mut offered: ParentReads) -> ParentReads {
    let spent: usize = selected.iter().map(StateClaim::wire_weight).sum();
    let room = MAX_STATE_CLAIMS_BYTES.saturating_sub(spent);
    let claims_left = MAX_STATE_CLAIMS_PER_BLOCK.saturating_sub(selected.len());
    let fits = |crossings: usize, rows: usize| {
        let (claims, weight) = parent_reads_weight(crossings, rows);
        weight <= room && claims <= claims_left
    };
    let rows = (0..=offered.rowless.len())
        .take_while(|rows| fits(0, *rows))
        .last()
        .unwrap_or(0);
    let crossings = (0..=offered.crossings.len())
        .take_while(|crossings| fits(*crossings, rows))
        .last()
        .unwrap_or(0);
    offered.rowless.truncate(rows);
    offered.crossings.truncate(crossings);
    offered
}

/// Select provisions for inclusion: what [`ProvisionsSection`] admits
/// from the FIFO queue, folding into `fold`. Oldest batches go first so
/// the queue drains monotonically; unselected batches remain queued for
/// the next proposal.
pub fn select_provisions(
    ctx: &Committed<'_>,
    fold: &mut ProvisionsFold,
    provisions: Vec<Arc<Verifiable<Provisions>>>,
) -> Vec<Arc<Verifiable<Provisions>>> {
    admit_each::<ProvisionsSection, _>(ctx, fold, provisions, unwrapped).0
}

// ═══════════════════════════════════════════════════════════════════════════
// Build + dispatch
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of assembling a proposal build action.
///
/// `assemble_build_action` returns this so the coordinator can decide what
/// mutations to apply (e.g. recording leader activity, starting the
/// tracker, deferring if the parent tree isn't ready).
pub struct BuildActionPlan {
    /// The `BuildProposal` action ready for dispatch.
    pub(crate) action: Action,
    /// Parent hash, forwarded to the tracker / verification pipeline.
    pub(crate) parent_block_hash: BlockHash,
    /// Parent block height, same rationale.
    pub(crate) parent_block_height: BlockHeight,
    /// Whether to record leader activity: `Fallback` / `Sync` count as
    /// proposer progress; `Normal` does not (it isn't progress until the
    /// QC forms).
    pub(crate) record_leader_activity: bool,
    /// Logging label for the "proposal built" info event.
    pub(crate) log_label: &'static str,
}

/// Assemble a `BuildProposal` action for the given `ProposalKind`.
///
/// Pure with respect to the coordinator — reads only from the chain view
/// and the supplied inputs, writes nothing. The caller applies the returned
/// mutations (leader activity, tracker.start, dispatch-or-defer).
///
/// `ready_signals` and the `beacon_witness_*` trio are pre-derived by
/// the coordinator (which owns the `BeaconWitnessAccumulator`, the
/// `ReadySignalPool`, and the window-resolved schedule entry) and
/// threaded through the action so `build_proposal` doesn't need to know
/// about the accumulator type.
#[allow(clippy::too_many_arguments)] // assemble fans a coordinator-side bundle into the action
pub fn assemble_build_action(
    me: ValidatorId,
    local_shard: ShardId,
    chain: &ChainView,
    height: BlockHeight,
    round: Round,
    now: LocalTimestamp,
    kind: ProposalKind,
    ready_signals: Vec<ReadySignal>,
    reshape_trigger: Option<ReshapeTrigger>,
    parent_witness_leaves: Vec<Hash>,
    beacon_witness_base: BeaconWitnessLeafCount,
    parent_reveal_chain: RevealChain,
    parent_committee_anchor_epoch: Epoch,
    committee_anchor_epoch: Epoch,
    carry_split_child_roots: bool,
    carry_terminal_settled_txs: bool,
    coasting: bool,
    settled_txs_window_floor: Option<WeightedTimestamp>,
    classification_topology_snapshot: Arc<TopologySnapshot>,
    substate: SubstateClaim,
    windows: EpochWindows,
    manifest: ManifestInputs,
    timeout_cert: Option<TimeoutCertificate>,
) -> BuildActionPlan {
    let (parent_block_hash, parent_qc) = chain.proposal_parent();
    let parent_block_height = parent_qc.height();
    let parent_state_root = chain.parent_state_root(parent_block_hash);
    let parent_settled_frontier = chain.parent_settled_frontier(parent_block_hash);
    let sweep = chain.block_sweep(parent_block_hash, coasting);
    let parent_load = chain.parent_load_checked(parent_block_hash);

    let (timestamp, is_fallback, payload, log_label, record_leader_activity) = match kind {
        ProposalKind::Normal(payload) => (
            ProposerTimestamp::from_local(now),
            false,
            *payload,
            "Requesting block build for proposal",
            false,
        ),
        ProposalKind::Fallback => (
            ProposerTimestamp::from_millis(parent_qc.weighted_timestamp().as_millis()),
            true,
            ProposalPayload::default(),
            "Building fallback block (leader timeout)",
            true,
        ),
        ProposalKind::Sync => (
            ProposerTimestamp::from_local(now),
            false,
            ProposalPayload::default(),
            "Building sync block (syncing, empty payload)",
            true,
        ),
    };
    let ProposalPayload {
        transactions,
        finalizations,
        provisions,
        abandonment_records,
        state_claims,
        local_crossings,
        rowless,
        fence,
    } = payload;
    let parent_anchor = Anchor {
        shard: local_shard,
        height: parent_block_height,
        state_root: parent_state_root,
        ts: parent_qc.weighted_timestamp(),
    };
    let frontier = FrontierInputs::for_block(
        &state_claims,
        windows,
        parent_qc.weighted_timestamp(),
        local_shard,
    );

    // The proposer's new BlockHeader will carry parent_qc in its wire
    // form; HBOR encoding is byte-identical between the raw and
    // verified shapes, but the field type is raw.
    let parent_qc_raw = parent_qc.into_inner();
    let action = Action::BuildProposal {
        shard_id: local_shard,
        chain_origin: chain.chain_origin().anchor_wt,
        proposer: me,
        height,
        round,
        parent_block_hash,
        parent_qc: parent_qc_raw,
        timestamp,
        is_fallback,
        parent_state_root,
        parent_block_height,
        transactions,
        finalizations,
        provisions,
        abandonment_records,
        state_claims,
        parent_settled_frontier,
        sweep,
        parent_load,
        substate,
        ready_signals,
        reshape_trigger,
        parent_witness_leaves,
        beacon_witness_base,
        parent_reveal_chain,
        parent_committee_anchor_epoch,
        committee_anchor_epoch,
        carry_split_child_roots,
        carry_terminal_settled_txs,
        settled_txs_window_floor,
        classification_topology_snapshot,
        frontier,
        fence,
        parent_anchor,
        local_crossings,
        rowless,
        manifest,
        timeout_cert,
    };

    BuildActionPlan {
        action,
        parent_block_hash,
        parent_block_height,
        record_leader_activity,
        log_label,
    }
}

/// Dispatch a built proposal action, deferring instead if the parent's JMT
/// tree isn't available yet.
///
/// Even empty blocks need the parent root node: `noop_jmt_snapshot` copies
/// it to the new version so the overlay chain stays intact. Without that, a
/// child block's `VerifyStateRoot` hits `ParentVersionMissing`. A
/// sync-admitted parent is verified at admission like any other, so a
/// fully redrawn recovery committee builds over the halted tip once that
/// verification lands.
///
/// `parent_tree_held` is the caller's reading of that tree, the same one
/// it decided on before asking for the block's content.
///
/// When deferred, the verification pipeline unblocks and re-enters
/// `try_propose` via the proposal-retry latch when the parent tree lands.
pub fn dispatch_or_defer(
    tracker: &mut ProposalTracker,
    verification: &mut VerificationPipeline,
    plan: BuildActionPlan,
    parent_tree_held: bool,
    block_height: BlockHeight,
    round: Round,
) -> Vec<Action> {
    if parent_tree_held {
        tracker.start(block_height, round);
        vec![plan.action]
    } else {
        verification.defer_proposal(plan.parent_block_hash, plan.parent_block_height);
        tracker.mark_deferred(block_height, round);
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::slice::from_ref;
    use std::time::Duration;

    use hyperscale_hbor::Capped;
    use hyperscale_storage::{MemberRow, RowState, committed_tx_cell_key, member_row_leaf};
    use hyperscale_types::test_utils::{
        finalization_of, install_stub_protocol_statics, make_finalization, make_finalization_on,
        make_leg_finalization, proven_claim, stub_abort_charge, stub_transaction,
        stub_transaction_binding, test_key, test_prefix, test_principal,
    };
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CommittedAt, Deadline, ExecutionOutcome,
        GlobalReceiptHash, Hash, Heard, LocalKey, MAX_CLAIMS_BYTES, MAX_INTENTS,
        MAX_SWEEPABLE_CREATED_PER_BLOCK, MAX_TICK_TERMS_BYTES, MAX_VALIDITY_RANGE,
        MAX_VERDICT_CLAIMS_BYTES, NetworkDefinition, Owes, RETENTION_HORIZON, RoutePrefix, Said,
        ShardAnchor, StateRoot, TimestampRange, TopologySchedule, TransactionDecision, TxHash,
        TxOutcome, UnsettledTx, ValidatorSet,
    };
    use hyperscale_vm_effects::{Answered, Hash32, IntentHash, ProtocolHasher};

    use super::*;
    use crate::admission::admit_all;
    use crate::admission::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use crate::commit_dedup::CommitDedupIndex;
    use crate::validation::tests::{verdict_claims_at, wide_claims, wide_claims_at};

    /// Admission under `snapshot` at `anchor` for a chain that began at
    /// `origin`, with `txs` behind the parent and `dedup` committed.
    fn against(
        snapshot: TopologySnapshot,
        anchor: WeightedTimestamp,
        origin: WeightedTimestamp,
        txs: HashSet<TxHash>,
        dedup: CommitDedupIndex,
    ) -> Against {
        let mut against = Against::window(snapshot);
        against.anchor = anchor;
        against.chain_origin = origin;
        against.chain.txs = txs;
        against.dedup = dedup;
        against
    }

    /// Admission for a finalization offer: a chain born at genesis with
    /// `dedup` committed.
    fn finalizations_against(dedup: CommitDedupIndex) -> Against {
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ));
        against.dedup = dedup;
        against
    }

    const DEPARTED: ShardId = ShardId::leaf(1, 0);
    const SURVIVOR: ShardId = ShardId::leaf(1, 1);

    /// A schedule in which `DEPARTED` left at the fixtures' cut, with its
    /// handoff stamped complete at `handoff_complete` or still open.
    fn departed_schedule(handoff_complete: Option<Epoch>) -> TopologySchedule {
        departures(&[DEPARTED], &[SURVIVOR], handoff_complete)
    }

    /// The one name the record fixtures carry: it reaches a route
    /// `DEPARTED` held, remote to `SURVIVOR`.
    fn stranded() -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(b"stranded")),
            deadline: Deadline::of(WeightedTimestamp::from_millis(5_000)),
            charged: 3,
            charge: stub_abort_charge(3),
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::ZERO,
                committee_anchor: WeightedTimestamp::ZERO,
            },
            reach: Capped::from_array([RoutePrefix::of(Address::new(
                [0x00; 31],
                AddressClass::Principal,
            ))]),
        }
    }

    /// A boundary record is offered only while the vote can still accept
    /// it. The vote reads the block's own anchor, which runs ahead of the
    /// committed frontier the composing side holds its evidence against,
    /// so the anchor is what decides here too — against the same
    /// handoff-anchored evidence window the fence itself derives.
    #[test]
    fn select_abandonment_records_stops_at_the_evidence_expiry() {
        let record = AbandonmentRecord::new(
            DEPARTED,
            WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
            [stranded()],
        );
        let offered = |sched: &TopologySchedule, anchor: WeightedTimestamp| {
            let mut against =
                Against::schedule(TopologySnapshot::clone(sched.head()), sched.clone());
            against.anchor = anchor;
            against.local_shard = SURVIVOR;
            let ctx = against.ctx();
            let finalizations = FinalizationsFold::from(&ctx);
            select_abandonment_records(
                &ctx,
                &mut RecordsFold::after(&finalizations),
                vec![record.clone()],
            )
            .len()
        };

        let handoff = Epoch::new(4);
        let stamped = departed_schedule(Some(handoff));
        let expiry = stamped.windows().handoff_evidence_expiry(handoff);
        assert_eq!(offered(&stamped, expiry), 1, "to the last instant of it");
        assert_eq!(
            offered(&stamped, expiry.plus(Duration::from_millis(1))),
            0,
            "past it every voter refuses the claim, so it must not be offered",
        );

        let open = departed_schedule(None);
        assert_eq!(
            offered(&open, expiry.plus(Duration::from_millis(1))),
            1,
            "an unstamped handoff holds the window open however late the anchor",
        );
    }

    /// A record loses the names a finalization in the same block
    /// resolves, an emptied one being dropped rather than offered.
    #[test]
    fn a_record_is_stripped_of_what_the_block_resolves() {
        let handoff = Epoch::new(4);
        let stamped = departed_schedule(Some(handoff));
        let inside = stamped.windows().handoff_evidence_expiry(handoff);
        let refused = AbandonmentRecord::new(
            DEPARTED,
            WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
            [stranded()],
        );
        let mut against =
            Against::schedule(TopologySnapshot::clone(stamped.head()), stamped.clone());
        against.anchor = inside;
        against.local_shard = SURVIVOR;
        let resolving = Arc::new(Verifiable::from(make_finalization_on(
            SURVIVOR,
            BlockHeight::new(1),
            stranded().tx_hash,
            TransactionDecision::Accept,
        )));
        against.holding_settled(from_ref(&resolving));
        let ctx = against.ctx();
        let none = FinalizationsFold::from(&ctx);
        assert_eq!(
            select_abandonment_records(
                &ctx,
                &mut RecordsFold::after(&none),
                vec![refused.clone()],
            )
            .len(),
            1,
            "inside the window the record is offered whole",
        );

        let mut resolved = FinalizationsFold::from(&ctx);
        assert_eq!(
            select_finalizations(&ctx, &mut resolved, vec![resolving]).len(),
            1
        );
        assert!(
            select_abandonment_records(&ctx, &mut RecordsFold::after(&resolved), vec![refused])
                .is_empty(),
            "a name this block resolves is stripped, and an emptied record is dropped",
        );
    }

    /// A proposer offers one verdict per transaction. A settlement and an
    /// abandonment for the same transaction are different ticks, so
    /// nothing about their identity separates them — the second is
    /// dropped because of the transaction it names, which is the rule the
    /// voters apply to the same list.
    #[test]
    fn select_finalizations_offers_one_verdict_per_transaction() {
        let tx_hash = TxHash::from(Hash::from_bytes(b"contested"));
        let settled: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept).into(),
        );
        let abandoned: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization(BlockHeight::new(9), tx_hash, TransactionDecision::Aborted).into(),
        );
        assert_ne!(settled.tick_id(), abandoned.tick_id());

        let mut against = finalizations_against(CommitDedupIndex::new());
        against.holding_settled(&[Arc::clone(&settled), Arc::clone(&abandoned)]);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        let selected = select_finalizations(&ctx, &mut fold, vec![Arc::clone(&settled), abandoned]);
        assert_eq!(selected.len(), 1, "the second verdict is dropped");
        assert_eq!(selected[0].tick_id(), settled.tick_id());
        assert_eq!(fold.tx_count, 1);
    }

    /// A finalization whose members decide nothing is offered once, and
    /// the block that commits it keeps it out of the next proposal.
    ///
    /// The offer's dedup asks whether the chain already resolved the
    /// names a finalization carries a verdict on. A member that reaches
    /// no verdict — a leg whose success bears none, since its core
    /// decides — contributes no such name, so a certificate carrying
    /// only those asks the question of an empty set. `all()` over
    /// an empty iterator is true, and the proposer re-offers the same
    /// certificate on every block while the settlement frontier stands
    /// still.
    #[test]
    fn select_finalizations_drops_a_committed_offer_that_decided_nothing() {
        let tx_hash = TxHash::from(Hash::from_bytes(b"retired"));
        let committed: Arc<Verifiable<Finalization>> =
            Arc::new(make_leg_finalization(BlockHeight::new(1), tx_hash).into());
        assert_eq!(
            committed.deciding_tx_hashes().count(),
            0,
            "the fixture has to decide nothing, or it tests the ordinary path",
        );
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[Arc::clone(&committed)]);

        let against = finalizations_against(dedup_index);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        let selected = select_finalizations(&ctx, &mut fold, vec![committed]);
        assert!(
            selected.is_empty(),
            "a certificate the chain already carries was offered again",
        );
    }

    /// A transaction a committed block already resolved keeps its
    /// finalization out of the next proposal, whichever verdict each
    /// carried.
    #[test]
    fn select_finalizations_drops_what_the_retention_window_resolved() {
        let tx_hash = TxHash::from(Hash::from_bytes(b"already resolved"));
        let committed: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept).into(),
        );
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(from_ref(&committed));

        let abandoned: Arc<Verifiable<Finalization>> = Arc::new(
            make_finalization(BlockHeight::new(9), tx_hash, TransactionDecision::Aborted).into(),
        );
        let against = finalizations_against(dedup_index);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        let selected = select_finalizations(&ctx, &mut fold, vec![abandoned]);
        assert!(selected.is_empty());
        assert_eq!(fold.tx_count, 0);
    }

    #[test]
    fn start_records_pending_slot() {
        let mut tracker = ProposalTracker::new();
        assert!(tracker.pending().is_none());

        tracker.start(BlockHeight::new(5), Round::new(1));
        let p = tracker.pending().unwrap();
        assert_eq!(p.height, BlockHeight::new(5));
        assert_eq!(p.round, Round::new(1));
    }

    #[test]
    fn take_matching_clears_on_match() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight::new(5), Round::new(1));

        let result = tracker.take_matching(BlockHeight::new(5), Round::new(1));
        assert!(matches!(result, TakeResult::Matched));
        assert!(tracker.pending().is_none());
    }

    #[test]
    fn take_matching_preserves_slot_on_mismatch() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight::new(5), Round::new(1));

        let result = tracker.take_matching(BlockHeight::new(5), Round::new(2));
        match result {
            TakeResult::Mismatch { expected } => {
                assert_eq!(expected.height, BlockHeight::new(5));
                assert_eq!(expected.round, Round::new(1));
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
        assert!(
            tracker.pending().is_some(),
            "slot must be preserved on mismatch"
        );
    }

    #[test]
    fn take_matching_returns_not_pending_when_empty() {
        let mut tracker = ProposalTracker::new();
        assert!(matches!(
            tracker.take_matching(BlockHeight::new(5), Round::new(1)),
            TakeResult::NotPending
        ));
    }

    #[test]
    fn mark_deferred_records_slot_without_touching_pending() {
        let mut tracker = ProposalTracker::new();
        tracker.mark_deferred(BlockHeight::new(5), Round::new(1));

        let d = tracker.deferred().unwrap();
        assert_eq!(d.height, BlockHeight::new(5));
        assert_eq!(d.round, Round::new(1));
        assert!(tracker.pending().is_none());
    }

    #[test]
    fn start_clears_deferred() {
        let mut tracker = ProposalTracker::new();
        tracker.mark_deferred(BlockHeight::new(5), Round::new(1));
        tracker.start(BlockHeight::new(5), Round::new(1));

        assert!(tracker.deferred().is_none());
        assert!(tracker.pending().is_some());
    }

    #[test]
    fn clear_drops_both_slots() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight::new(5), Round::new(1));
        tracker.mark_deferred(BlockHeight::new(6), Round::new(2));
        tracker.clear();

        assert!(tracker.pending().is_none());
        assert!(tracker.deferred().is_none());
    }

    #[test]
    fn clear_deferred_leaves_pending_intact() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight::new(5), Round::new(1));
        tracker.mark_deferred(BlockHeight::new(6), Round::new(2));
        tracker.clear_deferred();

        assert!(tracker.deferred().is_none());
        assert!(tracker.pending().is_some());
    }

    // ─── select_transactions: validity-window filter ───────────────────

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn tx_with_range(seed: u8, range: TimestampRange) -> Arc<Verified<Transaction>> {
        install_stub_protocol_statics();
        Arc::new(Verified::<Transaction>::from_persisted(stub_transaction(
            test_principal(seed),
            &[test_prefix(seed)],
            1_000,
            range,
        )))
    }

    fn empty_dedup_index() -> CommitDedupIndex {
        CommitDedupIndex::new()
    }

    /// The window every case here selects against.
    fn window_listing_no_packages() -> TopologySnapshot {
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        )
    }

    /// The parent terminal a right child asks.
    fn parent_terminal() -> Anchor {
        Anchor {
            shard: ShardId::leaf(1, 0),
            height: BlockHeight::new(9),
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        }
    }

    /// A split's right child whose parent has answered nothing, so no
    /// pre-cut transaction is admissible. Cases anchored at
    /// `WeightedTimestamp::ZERO` never consult it, since nothing opens
    /// before an origin of zero.
    fn refuses_precut() -> Precut {
        install_stub_protocol_statics();
        let terminal = parent_terminal();
        Precut::adopted(terminal.shard.children().1, &[terminal])
    }

    /// The same right child, with the marker of the transaction `tx_hash`
    /// ending at `validity_end` proven absent from its parent's terminal
    /// state.
    fn admits_precut(tx_hash: TxHash, validity_end: WeightedTimestamp) -> Precut {
        let mut precut = refuses_precut();
        let terminal = parent_terminal();
        precut.record(
            terminal,
            committed_tx_cell_key(terminal.shard, tx_hash, validity_end),
            false,
        );
        precut
    }

    /// A transaction opening before the chain's origin is dropped while
    /// unresolved, and offered once the parent's terminal state has
    /// proven its marker absent.
    #[test]
    fn select_transactions_offers_a_precut_tx_only_once_resolved_absent() {
        let cut = ts(10_000);
        let anchor = ts(10_500);
        // Opens before the cut, still valid at the anchor: exactly the
        // population the successor cannot judge on its own.
        let candidate = tx_with_range(9, TimestampRange::new(ts(9_000), ts(40_000)));
        let hash = candidate.hash();
        let txs = vec![candidate];

        let refused = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                cut,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );
        assert!(
            refused.is_empty(),
            "an unresolved pre-cut transaction is not offered"
        );

        let admitted = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                cut,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &admits_precut(hash, ts(40_000)),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );
        assert_eq!(
            admitted.len(),
            1,
            "proven absent from every predecessor, so this is its first commit"
        );
    }

    #[test]
    fn select_transactions_drops_expired_txs() {
        // Anchor in the future of the tx's range.
        let anchor = ts(100_000);
        let expired_range = TimestampRange::new(ts(0), ts(1_000));
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));

        let txs = vec![
            tx_with_range(1, expired_range),
            tx_with_range(2, valid_range),
        ];

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert_eq!(selected.len(), 1, "only the in-range tx should survive");
        assert_eq!(selected[0].hash(), txs[1].hash());
    }

    #[test]
    fn select_transactions_drops_not_yet_valid_txs() {
        // Anchor sits before the tx's start.
        let anchor = ts(50);
        let future_range = TimestampRange::new(ts(1_000), ts(60_000));
        let txs = vec![tx_with_range(3, future_range)];

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert!(
            selected.is_empty(),
            "tx whose start is past anchor should be filtered"
        );
    }

    #[test]
    fn select_transactions_drops_malformed_ranges() {
        let anchor = ts(1_000);
        // Length over MAX_VALIDITY_RANGE.
        let too_wide = TimestampRange::new(
            ts(0),
            anchor.plus(MAX_VALIDITY_RANGE + Duration::from_secs(1)),
        );
        let txs = vec![tx_with_range(4, too_wide)];

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert!(selected.is_empty(), "malformed range should be filtered");
    }

    #[test]
    fn selection_skips_what_would_overrun_the_sweep_creation_cap() {
        install_stub_protocol_statics();
        let anchor = ts(1_000);
        let range = TimestampRange::new(ts(500), anchor.plus(Duration::from_mins(1)));
        let binding = |seed: u32, bound: usize| -> Arc<Verified<Transaction>> {
            Arc::new(Verified::<Transaction>::from_persisted(
                stub_transaction_binding(seed, bound, range),
            ))
        };
        // Fill the cap, then offer one that cannot fit followed by one
        // that can. Skipping rather than stopping is what keeps a large
        // composition from starving the small ones behind it. Each fully
        // composed transaction creates one nullifier per intent, all on
        // this one shard, and its committed cell beside them — which
        // every transaction writes, so the smallest one still costs two.
        // Every nullifier is a signature to verify, so enough fully
        // composed transactions to fill the cap would pass the compute
        // cap first; the fold starts near the cap and three fill it.
        let cells = MAX_INTENTS + 1;
        let full = 3;
        let provisions = ProvisionsFold::default();
        let mut fold = TransactionsFold::beside(&provisions);
        fold.sweepable = MAX_SWEEPABLE_CREATED_PER_BLOCK - full * cells - (cells / 2);
        let mut txs: Vec<Arc<Verified<Transaction>>> = (0..full)
            .map(|i| {
                binding(
                    u32::try_from(i).expect("fewer than u32 transactions"),
                    MAX_INTENTS - 1,
                )
            })
            .collect();
        let overflows = binding(u32::MAX, MAX_INTENTS - 1);
        let fits = binding(u32::MAX - 1, 0);
        txs.push(overflows.clone());
        txs.push(fits.clone());

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut fold,
            &txs,
        );

        assert_eq!(
            selected.len(),
            full + 1,
            "the one that cannot fit is skipped"
        );
        assert!(selected.iter().any(|tx| tx.hash() == fits.hash()));
        assert!(!selected.iter().any(|tx| tx.hash() == overflows.hash()));
    }

    #[test]
    fn select_transactions_drops_at_upper_bound_exclusive() {
        // Half-open: end_timestamp_exclusive == anchor must be filtered.
        let anchor = ts(1_000);
        let range = TimestampRange::new(ts(500), anchor); // [500, 1000)
        let txs = vec![tx_with_range(5, range)];

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert!(
            selected.is_empty(),
            "anchor == end_exclusive must be excluded (half-open)"
        );
    }

    /// The composer spends the section's bytes: the first claim that
    /// does not fit is cut to the longest key prefix whose piece fits,
    /// the piece passes admission, the section ends there, and the
    /// remainder is a claim a next proposal carries.
    #[test]
    fn a_claim_past_the_budget_is_cut_to_its_longest_fitting_prefix() {
        let (_, wide) = wide_claims(ShardId::leaf(1, 0));
        let ctx = finalizations_against(CommitDedupIndex::new());
        let mut fold = StateClaimsFold::default();
        let selected = select_state_claims(&ctx.ctx(), &mut fold, wide.clone());
        assert!(!selected.is_empty() && selected.len() < wide.len());
        assert!(state_claims_admit_block(
            selected.iter().map(StateClaim::wire_weight).sum()
        ));
        let cut = selected.last().expect("something was carried");
        let whole = &wide[selected.len() - 1];
        assert_ne!(
            cut, whole,
            "the last claim carried is a piece of the one that did not fit"
        );
        assert!(
            whole.keys().starts_with(&cut.keys()),
            "cut to a prefix of its keys",
        );
        assert!(
            !state_claims_admit_block(
                selected[..selected.len() - 1]
                    .iter()
                    .map(StateClaim::wire_weight)
                    .sum::<usize>()
                    + whole.wire_weight()
            ),
            "the whole did not fit",
        );
        let mut checked = StateClaimsFold::default();
        assert!(
            admit_all::<StateClaimsSection>(&ctx.ctx(), &mut checked, &selected).is_ok(),
            "what the composer selected passes admission",
        );

        let carried = cut.keys();
        let remainder = whole
            .restrict(|key| !carried.contains(&key))
            .expect("the cut left something");
        let mut next = StateClaimsFold::default();
        assert_eq!(
            select_state_claims(&ctx.ctx(), &mut next, vec![remainder.clone()]),
            vec![remainder],
            "the remainder rides the next proposal whole",
        );
    }

    /// The shard whose verdict cells the fixtures below read.
    const SIBLING: ShardId = ShardId::leaf(1, 0);

    fn heard_member(seed: usize) -> TxHash {
        TxHash::from(Hash::from_bytes(&seed.to_le_bytes()))
    }

    /// `tx`'s row at the parent, stated and awaiting [`SIBLING`], having
    /// heard `heard` of it.
    fn stated_row(tx: TxHash, heard: Option<Heard>) -> MemberRow {
        MemberRow {
            tx,
            deadline: Deadline::of(WeightedTimestamp::from_millis(9_000)),
            committed: WeightedTimestamp::ZERO,
            height: BlockHeight::new(1),
            state: RowState::Stated {
                tick: BlockHeight::new(1),
                receipt: GlobalReceiptHash::from_raw(Hash::from_bytes(b"receipt")),
            },
            holds: Capped::empty(),
            reach: Capped::from_array([SIBLING]),
            awaits: Capped::from_array([SIBLING]),
            charge: stub_abort_charge(0),
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            owes: Owes::default(),
            waiting: None,
            covered: false,
            executed: true,
            hearing: Capped::new(heard.into_iter().collect()).expect("one entry"),
        }
    }

    /// Admission at a parent whose rows are `rows`, in a window that
    /// runs [`SIBLING`].
    fn hearing_at_the_parent(rows: impl IntoIterator<Item = MemberRow>) -> Against {
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.members.members = rows.into_iter().map(|row| (row.tx, row)).collect();
        against
    }

    /// `tx`'s verdict leaf, member row and committed marker on
    /// [`SIBLING`], as a row built by [`stated_row`] keys them.
    fn verdict_cells(tx: TxHash) -> [SubstateKey; 3] {
        [
            verdict_leaf(SIBLING, tx),
            member_row_leaf(SIBLING, tx),
            committed_tx_cell_key(SIBLING, tx, stated_row(tx, None).deadline.validity_end()),
        ]
    }

    fn crossing(seed: u8) -> CrossingId {
        CrossingId {
            producer: test_prefix(seed),
            consumer: test_prefix(seed),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    /// Verdict claims are spent last: a full set of them takes no byte
    /// and no place from the claims held for other questions or from
    /// the local crossings, and fills only what those leave of the
    /// section's count.
    #[test]
    fn a_full_set_of_verdict_claims_leaves_every_other_claim_its_place() {
        let members: Vec<TxHash> = (0..MAX_CLAIMS_PER_BLOCK + 40).map(heard_member).collect();
        let leaves: Vec<SubstateKey> = members
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let verdicts: Vec<StateClaim> = members
            .iter()
            .zip(&leaves)
            .map(|(tx, leaf)| proven_claim(SIBLING, 3, &leaves, &[*leaf]).hearing([*tx]))
            .collect();
        let gating = vec![
            proven_claim(SIBLING, 4, &[], &[test_key(7)]),
            proven_claim(SIBLING, 5, &[], &[test_key(8)]),
        ];
        let local: Vec<CrossingId> = (0..6).map(crossing).collect();
        let against = hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None)));
        let ctx = against.ctx();

        let alone = select_claims(
            &ctx,
            &mut StateClaimsFold::default(),
            gating.clone(),
            Vec::new(),
            &[],
            local.clone(),
            &[],
        );
        assert_eq!(
            alone,
            (
                gating.clone(),
                ParentReads {
                    crossings: local.clone(),
                    rowless: Vec::new(),
                },
            ),
        );

        let (
            selected,
            ParentReads {
                crossings: kept_local,
                ..
            },
        ) = select_claims(
            &ctx,
            &mut StateClaimsFold::default(),
            gating.clone(),
            verdicts,
            &[],
            local.clone(),
            &[],
        );
        assert_eq!(kept_local, local, "every local crossing keeps its place");
        assert!(
            gating.iter().all(|claim| selected.contains(claim)),
            "every other claim rides whole",
        );
        let (local_claims, local_weight) = parent_reads_weight(local.len(), 0);
        let heard = selected.iter().filter(|claim| claim.is_verdict_claim());
        assert_eq!(
            heard.count(),
            MAX_CLAIMS_PER_BLOCK - gating.len() - local_claims,
            "the verdict claims fill what is left of the count, and no more",
        );
        assert!(claims_admit_block(
            selected.iter().map(StateClaim::wire_weight).sum::<usize>() + local_weight
        ));
        let mut checked = StateClaimsFold::default();
        assert!(admit_all::<StateClaimsSection>(&ctx, &mut checked, &selected).is_ok());
    }

    /// A block whose other claims reach their count still carries
    /// verdict claims, in the places only they take.
    #[test]
    fn verdict_claims_keep_their_places_beside_a_full_count_of_other_claims() {
        let mut keys: Vec<SubstateKey> = (0..=u8::MAX)
            .flat_map(|at| [0x30, 0x31].map(|owner| (owner, at)))
            .map(|(owner, at)| SubstateKey {
                owner: test_prefix(owner),
                local: LocalKey([at; 16]),
            })
            .collect();
        keys.sort_unstable();
        keys.truncate(MAX_STATE_CLAIMS_PER_BLOCK + 8);
        let gating: Vec<StateClaim> = keys
            .iter()
            .map(|key| proven_claim(SIBLING, 4, &keys, from_ref(key)))
            .collect();
        let members: Vec<TxHash> = (0..MAX_CLAIMS_PER_BLOCK - MAX_STATE_CLAIMS_PER_BLOCK + 8)
            .map(heard_member)
            .collect();
        let leaves: Vec<SubstateKey> = members
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let verdicts: Vec<StateClaim> = members
            .iter()
            .zip(&leaves)
            .map(|(tx, leaf)| proven_claim(SIBLING, 3, &leaves, &[*leaf]).hearing([*tx]))
            .collect();
        let against = hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None)));
        let ctx = against.ctx();
        let mut fold = StateClaimsFold::default();
        let (
            selected,
            ParentReads {
                crossings: kept_local,
                ..
            },
        ) = select_claims(
            &ctx,
            &mut fold,
            gating,
            verdicts,
            &[],
            vec![crossing(1)],
            &[],
        );
        let heard = selected
            .iter()
            .filter(|claim| claim.is_verdict_claim())
            .count();
        assert_eq!(
            (selected.len() - heard, kept_local.len()),
            (MAX_STATE_CLAIMS_PER_BLOCK, 0),
            "the other claims reach their count and stop there",
        );
        assert_eq!(heard, MAX_CLAIMS_PER_BLOCK - MAX_STATE_CLAIMS_PER_BLOCK);
        assert!(claims_admit_block(fold.weight + fold.verdict_weight));
        let mut checked = StateClaimsFold::default();
        assert_eq!(
            admit_all::<StateClaimsSection>(&ctx, &mut checked, &selected),
            Ok(()),
        );
    }

    /// The height the burst fixture's boundary sits at, and the height a
    /// fresh claim of a block anchored a millisecond past that
    /// boundary's horizon sits at.
    fn boundary_and_fresh_heights() -> (u64, u64) {
        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        (3, 3 + horizon_ms / 1_000)
    }

    /// The anchor of a block `beyond_ms` past the horizon of the burst
    /// fixture's boundary.
    fn past_the_boundary(beyond_ms: u64) -> WeightedTimestamp {
        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        WeightedTimestamp::from_millis(
            boundary_and_fresh_heights().0 * 1_000 + horizon_ms + beyond_ms,
        )
    }

    /// `against` with the one window of its schedule recording `boundary`
    /// as the boundary of its shard.
    fn recording(mut against: Against, boundary: &Anchor) -> Against {
        let recorded = ShardAnchor {
            state_root: boundary.state_root,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
            height: boundary.height,
            weighted_timestamp: boundary.ts,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        let snapshot = against
            .snapshot
            .clone()
            .with_boundaries(BTreeMap::from([(boundary.shard, recorded)]));
        against.schedule = TopologySchedule::new(u64::MAX / 2, Epoch::GENESIS, Arc::new(snapshot));
        against
    }

    /// More deletions at one boundary of [`SIBLING`] than a block holds,
    /// each reading two cells that sit in different claims of the
    /// anchor's key-ordered list, and that list's keys.
    fn boundary_burst() -> (BoundaryOffer, Vec<SubstateKey>) {
        let (leaves, claims) = wide_claims_at(SIBLING, boundary_and_fresh_heights().0);
        let mut sorted = leaves;
        sorted.sort_unstable();
        let half = sorted.len() / 2;
        let deletions = (0..half)
            .map(|at| vec![sorted[at], sorted[at + half]])
            .collect();
        (BoundaryOffer { claims, deletions }, sorted)
    }

    /// How many of the burst's deletions `carried` reads whole, having
    /// checked that it reads no cell of any other.
    fn whole_deletions(sorted: &[SubstateKey], carried: &[StateClaim]) -> usize {
        let half = sorted.len() / 2;
        let keys: BTreeSet<SubstateKey> = carried.iter().flat_map(StateClaim::keys).collect();
        let whole = (0..half)
            .filter(|at| keys.contains(&sorted[*at]) && keys.contains(&sorted[at + half]))
            .count();
        assert_eq!(
            keys.len(),
            2 * whole,
            "every cell carried is of a whole deletion"
        );
        whole
    }

    /// A burst of boundary claims, more than a block holds, is spent in
    /// what every other claim leaves and takes nothing from any of them:
    /// the claims held for other questions, the local crossings and the
    /// verdict claims a block carries beside the burst are the ones it
    /// carries without it. What the burst is cut to is whole deletions,
    /// each with every cell it reads though they sit in different
    /// claims, and passes admission.
    #[test]
    fn a_boundary_burst_is_spent_in_what_every_other_claim_leaves() {
        let (_, fresh_height) = boundary_and_fresh_heights();
        let (burst, sorted) = boundary_burst();
        let members: Vec<TxHash> = (0..MAX_CLAIMS_PER_BLOCK + 40).map(heard_member).collect();
        let verdict_leaves: Vec<SubstateKey> = members
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let verdicts: Vec<StateClaim> = members
            .iter()
            .zip(&verdict_leaves)
            .map(|(tx, leaf)| {
                proven_claim(SIBLING, fresh_height, &verdict_leaves, &[*leaf]).hearing([*tx])
            })
            .collect();
        let wanted = vec![
            proven_claim(SIBLING, fresh_height, &[], &[test_key(7)]),
            proven_claim(SIBLING, fresh_height + 1, &[], &[test_key(8)]),
        ];
        let (_, filling) = wide_claims_at(SIBLING, fresh_height);

        let mut against = recording(
            hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None))),
            &burst.claims[0].anchor,
        );
        against.anchor = past_the_boundary(1);
        let ctx = against.ctx();
        let selecting =
            |state: &[StateClaim], verdicts: &[StateClaim], boundary: &[BoundaryOffer]| {
                let (
                    selected,
                    ParentReads {
                        crossings: local, ..
                    },
                ) = select_claims(
                    &ctx,
                    &mut StateClaimsFold::default(),
                    state.to_vec(),
                    verdicts.to_vec(),
                    boundary,
                    vec![crossing(1)],
                    &[],
                );
                let mut checked = StateClaimsFold::default();
                assert_eq!(
                    admit_all::<StateClaimsSection>(&ctx, &mut checked, &selected),
                    Ok(()),
                    "what is selected passes admission",
                );
                let (carried, others): (Vec<StateClaim>, Vec<StateClaim>) = selected
                    .into_iter()
                    .partition(|claim| claim.at_boundary(ctx.anchor));
                (carried, others, local)
            };

        let (carried, others, _) = selecting(&[], &[], from_ref(&burst));
        assert!(others.is_empty());
        let whole = whole_deletions(&sorted, &carried);
        assert!(
            0 < whole && whole < burst.deletions.len(),
            "the burst is cut to the deletions that fit: {whole}",
        );
        assert!(state_claims_admit_block(
            carried.iter().map(StateClaim::wire_weight).sum()
        ));

        for (state, verdicts) in [
            (wanted.clone(), Vec::new()),
            (wanted, verdicts.clone()),
            (filling.clone(), Vec::new()),
            (filling, verdicts),
        ] {
            let (none, without, local_without) = selecting(&state, &verdicts, &[]);
            assert!(none.is_empty());
            let (carried, with, local_with) = selecting(&state, &verdicts, from_ref(&burst));
            assert_eq!(
                (with, local_with),
                (without, local_without),
                "the burst takes no byte and no place from any other claim",
            );
            whole_deletions(&sorted, &carried);
        }
    }

    /// A record a block reads at its parent to take back rides only
    /// beside the consumer's `Never` the block carries at a boundary of
    /// the consumer's shard, which is what names it: where the section
    /// leaves that `Never` out the record is not read, and a crossing
    /// whose answers this chain holds is read whatever the section
    /// carries.
    #[test]
    fn a_record_is_read_at_the_parent_only_beside_the_never_a_block_carries() {
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.local_shard = SURVIVOR;
        let returned = CrossingId {
            producer: test_prefix(0xA1),
            consumer: test_prefix(0x21),
            intent: IntentHash(Hash32([0xA1; 32])),
            local: 0,
            output: 0,
        };
        let held = CrossingId {
            producer: test_prefix(0xA2),
            consumer: test_prefix(0xA3),
            ..returned
        };
        let never = returned.answer_key(&ProtocolHasher, Answered::Never);
        let (boundary_height, _) = boundary_and_fresh_heights();
        let claim =
            proven_claim(SIBLING, boundary_height, &[never], &[never]).naming([(never, returned)]);
        let offer = BoundaryOffer {
            claims: vec![claim.clone()],
            deletions: vec![vec![never]],
        };
        let mut against = recording(against, &claim.anchor);
        against.anchor = past_the_boundary(1);
        let read = |offers: &[BoundaryOffer]| {
            let (selected, at_parent) = select_claims(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                Vec::new(),
                Vec::new(),
                offers,
                vec![held],
                &[],
            );
            (selected.len(), at_parent.crossings)
        };
        assert_eq!(read(from_ref(&offer)), (1, vec![held, returned]));
        assert_eq!(
            read(&[]),
            (0, vec![held]),
            "a record whose Never the block does not carry is read for nothing",
        );
    }

    /// A proposer holding more of its consumers' `Nevers` at a boundary
    /// than a block carries still takes records back in every block: each
    /// `Never` carried names its record for the parent reading, the two
    /// charged together inside the section's budget for the claims that
    /// are not verdict claims, so the readings of records whose `Never`
    /// waits never crowd out the ones that ride. With fresh claims
    /// filling half the section, what is left still carries returns.
    #[test]
    fn a_proposer_holding_more_nevers_than_a_block_carries_still_returns_records() {
        let (boundary_height, fresh_height) = boundary_and_fresh_heights();
        let (_, filling) = wide_claims_at(SIBLING, fresh_height);
        let half: Vec<StateClaim> = filling
            .iter()
            .scan(0usize, |weight, claim| {
                *weight += claim.wire_weight();
                (*weight <= MAX_STATE_CLAIMS_BYTES / 2).then(|| claim.clone())
            })
            .collect();
        for n in [1usize, 50, 200, 300, 600, 1_000] {
            let ids: Vec<CrossingId> = (0..n)
                .map(|at| {
                    let mut intent = [0xA1; 32];
                    intent[..8].copy_from_slice(&(at as u64).to_le_bytes());
                    CrossingId {
                        producer: test_prefix(0xA1),
                        consumer: test_prefix(0x21),
                        intent: IntentHash(Hash32(intent)),
                        local: 0,
                        output: 0,
                    }
                })
                .collect();
            let mut nevers: Vec<(SubstateKey, CrossingId)> = ids
                .iter()
                .map(|id| (id.answer_key(&ProtocolHasher, Answered::Never), *id))
                .collect();
            nevers.sort_unstable();
            let keys: Vec<SubstateKey> = nevers.iter().map(|(key, _)| *key).collect();
            let claims: Vec<StateClaim> = nevers
                .chunks(200)
                .map(|chunk| {
                    let asked: Vec<SubstateKey> = chunk.iter().map(|(key, _)| *key).collect();
                    proven_claim(SIBLING, boundary_height, &keys, &asked)
                        .naming(chunk.iter().copied())
                })
                .collect();
            let offer = BoundaryOffer {
                claims: claims.clone(),
                deletions: keys.iter().map(|key| vec![*key]).collect(),
            };
            let mut against = Against::window(TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(Vec::new()),
            ));
            against.local_shard = SURVIVOR;
            let mut against = recording(against, &claims[0].anchor);
            against.anchor = past_the_boundary(1);
            let ctx = against.ctx();
            for fresh in [Vec::new(), half.clone()] {
                let filled = !fresh.is_empty();
                let (selected, at_parent) = select_claims(
                    &ctx,
                    &mut StateClaimsFold::default(),
                    fresh,
                    Vec::new(),
                    from_ref(&offer),
                    Vec::new(),
                    &[],
                );
                let carried: Vec<CrossingId> = selected
                    .iter()
                    .flat_map(|claim| claim.crossings.iter())
                    .filter(|(key, _)| keys.binary_search(key).is_ok())
                    .map(|(_, id)| *id)
                    .collect();
                assert!(
                    !carried.is_empty(),
                    "{n} held, filled {filled}: none carried"
                );
                let mut read: Vec<CrossingId> = at_parent.crossings;
                read.sort_unstable();
                let mut paired = carried.clone();
                paired.sort_unstable();
                assert_eq!(
                    read, paired,
                    "{n} held, filled {filled}: every Never carried is read"
                );
                let mut checked = StateClaimsFold::default();
                assert_eq!(
                    admit_all::<StateClaimsSection>(&ctx, &mut checked, &selected),
                    Ok(()),
                );
                let (_, reading) = return_reads(0, carried.len());
                assert!(
                    state_claims_admit_block(checked.weight + reading),
                    "{n} held, filled {filled}: the returns' readings fit beside them",
                );
            }
        }
    }

    /// A claim held for a ledger or seat question rides among a block's
    /// ordinary claims up to the horizon and not a millisecond past it,
    /// whether or not the proposer's schedule records its anchor: past
    /// the horizon admission takes it for a boundary claim, and every
    /// voter holds its anchor to the schedule, whatever header it holds.
    /// It is charged nothing, and a younger claim of its producer rides
    /// without it.
    #[test]
    fn a_claim_aged_past_the_horizon_rides_only_as_a_boundary_offer() {
        let (aged_height, fresh_height) = boundary_and_fresh_heights();
        let held = proven_claim(SIBLING, aged_height, &[], &[test_key(7)]);
        let younger = proven_claim(SIBLING, fresh_height, &[], &[test_key(8)]);
        let selected_at = |anchor: WeightedTimestamp, recorded: bool| {
            let mut against = hearing_at_the_parent([]);
            if recorded {
                against = recording(against, &held.anchor);
            }
            against.anchor = anchor;
            let mut fold = StateClaimsFold::default();
            let (selected, _) = select_claims(
                &against.ctx(),
                &mut fold,
                vec![held.clone(), younger.clone()],
                Vec::new(),
                &[],
                Vec::new(),
                &[],
            );
            (selected, fold.weight)
        };
        let (at_the_horizon, both) = selected_at(past_the_boundary(0), false);
        assert_eq!(at_the_horizon, vec![held.clone(), younger.clone()]);
        for recorded in [false, true] {
            let (past, weight) = selected_at(past_the_boundary(1), recorded);
            assert_eq!(
                past,
                vec![younger.clone()],
                "the aged claim is no ordinary claim, its anchor recorded: {recorded}",
            );
            assert!(weight < both, "and is charged nothing");
        }
    }

    /// A boundary offer is carried only once its anchor has aged past
    /// the horizon and only where the proposer's own schedule records
    /// the anchor as a boundary. A reading still fresh to the block is
    /// no boundary claim: admission would carry it as a fresh claim,
    /// which deletes nothing. One at an anchor the schedule does not
    /// record would cost the proposer its round.
    #[test]
    fn a_boundary_offer_waits_for_its_anchor_to_age_and_its_boundary_to_stand() {
        let (burst, _) = boundary_burst();
        let carried = |anchor: WeightedTimestamp, recorded: bool| {
            let mut against = hearing_at_the_parent([]);
            if recorded {
                against = recording(against, &burst.claims[0].anchor);
            }
            against.anchor = anchor;
            select_claims(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                Vec::new(),
                Vec::new(),
                from_ref(&burst),
                Vec::new(),
                &[],
            )
            .0
        };
        assert!(carried(past_the_boundary(0), true).is_empty());
        assert!(carried(past_the_boundary(1), false).is_empty());
        assert!(!carried(past_the_boundary(1), true).is_empty());
    }

    /// A recovered shard's first boundary is the bridge block its
    /// crossing folds at, anchored below the bridge at a height above the
    /// frontier, inside the recovery's band. A boundary offer there is
    /// held to the beacon's record and not to the band, so it is carried,
    /// and the offer of another shard behind it is carried too, while
    /// the recovery is pending and after its record clears.
    #[test]
    fn a_boundary_offer_at_a_recovered_shards_first_boundary_stalls_no_other_offer() {
        use hyperscale_types::{RecoveryBinding, RecoveryCause, ShardRecovery};

        const OTHER: ShardId = ShardId::leaf(1, 1);
        let offer = |shard: ShardId, seed: u8| {
            let asked = vec![test_key(seed), test_key(seed + 1)];
            BoundaryOffer {
                claims: vec![proven_claim(shard, 3, &[test_key(seed + 2)], &asked)],
                deletions: vec![asked],
            }
        };
        let (first, other) = (offer(SIBLING, 0x50), offer(OTHER, 0xD0));
        let record = |anchor: &Anchor| ShardAnchor {
            state_root: anchor.state_root,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary")),
            height: anchor.height,
            weighted_timestamp: anchor.ts,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        for pending in [true, false] {
            let mut against = hearing_at_the_parent([]);
            let mut snapshot = against.snapshot.clone().with_recoveries(BTreeMap::from([(
                SIBLING,
                vec![RecoveryBinding {
                    rotated_at: Epoch::GENESIS,
                    attested_frontier: BlockHeight::new(2),
                    completed: !pending,
                }],
            )]));
            if pending {
                snapshot = snapshot.with_pending_recoveries(BTreeMap::from([(
                    SIBLING,
                    ShardRecovery {
                        cause: RecoveryCause::Halt,
                        rotated_at: Epoch::GENESIS,
                        retained: Vec::new(),
                        attested_frontier: BlockHeight::new(2),
                    },
                )]));
            }
            let records = [&first, &other].map(|offer| {
                let anchor = offer.claims[0].anchor;
                (anchor.shard, record(&anchor))
            });
            against.snapshot = snapshot.clone();
            against.schedule = TopologySchedule::new(
                u64::MAX / 2,
                Epoch::GENESIS,
                Arc::new(snapshot.with_boundaries(BTreeMap::from(records))),
            );
            against.anchor = past_the_boundary(1);
            let anchor = first.claims[0].anchor;
            assert!(
                against.snapshot.recovery_orphaned(
                    against.schedule.windows(),
                    SIBLING,
                    anchor.ts,
                    anchor.height,
                ),
                "the first boundary lies in the recovery's band",
            );
            let (carried, _) = select_claims(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                Vec::new(),
                Vec::new(),
                &[first.clone(), other.clone()],
                Vec::new(),
                &[],
            );
            let shards: BTreeSet<ShardId> =
                carried.iter().map(|claim| claim.anchor.shard).collect();
            assert_eq!(
                shards,
                BTreeSet::from([SIBLING, OTHER]),
                "pending {pending}"
            );
        }
    }

    /// Only what a row at the parent would hear is carried: a reading
    /// the row's entry has already reached, as when an ancestor not yet
    /// committed carried it, a reading for a row the chain to the parent
    /// has settled, and a reading for a row that does not hear are spent
    /// on nothing.
    #[test]
    fn a_reading_no_row_at_the_parent_would_hear_is_not_carried() {
        let [fresh, carried, settled, pending] = [1, 2, 3, 4].map(heard_member);
        let leaves: Vec<SubstateKey> = [fresh, carried, settled, pending]
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let claim =
            proven_claim(SIBLING, 3, &leaves, &leaves).hearing([fresh, carried, settled, pending]);
        let at = |height: u64| Heard {
            shard: SIBLING,
            mark: ReadMark {
                epoch: Epoch::GENESIS,
                height: BlockHeight::new(height),
            },
            said: Some(Said::Yes),
        };
        let mut waiting = stated_row(pending, None);
        waiting.state = RowState::Pending;
        let against = hearing_at_the_parent([
            stated_row(fresh, Some(at(2))),
            stated_row(carried, Some(at(3))),
            waiting,
        ]);
        let (selected, _) = select_claims(
            &against.ctx(),
            &mut StateClaimsFold::default(),
            Vec::new(),
            vec![claim.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(
            selected,
            vec![
                claim
                    .restrict(|key| key == verdict_leaf(SIBLING, fresh))
                    .expect("one cell kept"),
            ],
            "the one reading above its row's entry rides, under its one name",
        );
        assert_eq!(selected[0].verdicts.to_vec(), vec![fresh]);

        let nobody = hearing_at_the_parent([stated_row(carried, Some(at(3)))]);
        let (selected, _) = select_claims(
            &nobody.ctx(),
            &mut StateClaimsFold::default(),
            Vec::new(),
            vec![claim],
            &[],
            Vec::new(),
            &[],
        );
        assert!(
            selected.is_empty(),
            "a claim left naming nothing is not carried"
        );
    }

    /// A verdict claim is cut to the rows that awaited the chain its
    /// anchor's shard runs: a reading of a later chain under the same id
    /// is not carried for a row committed before that chain's first
    /// window, which admission refuses, and the claim rides for the row
    /// committed in that window, which awaited it.
    #[test]
    fn the_composer_carries_no_reading_of_a_later_life() {
        const LATER_LIFE: u64 = 7;
        let [earlier, awaited] = [1, 2].map(heard_member);
        let leaves = [earlier, awaited].map(|tx| verdict_leaf(SIBLING, tx));
        let claim = proven_claim(SIBLING, 9, &leaves, &leaves).hearing([earlier, awaited]);
        let committed = |tx: TxHash, ms: u64| MemberRow {
            committed: WeightedTimestamp::from_millis(ms),
            ..stated_row(tx, None)
        };
        let window = |life: u64| {
            Arc::new(
                TopologySnapshot::new(
                    NetworkDefinition::simulator(),
                    2,
                    ValidatorSet::new(Vec::new()),
                )
                .with_formed(BTreeMap::from([
                    (SIBLING, Epoch::new(life)),
                    (ShardId::leaf(1, 1), Epoch::GENESIS),
                ])),
            )
        };
        let (before, after) = (window(0), window(LATER_LIFE));
        let mut schedule = TopologySchedule::new(1_000, Epoch::GENESIS, Arc::clone(&before));
        for epoch in 1..=20 {
            let snapshot = if epoch < LATER_LIFE { &before } else { &after };
            schedule.insert(Epoch::new(epoch), Arc::clone(snapshot));
        }
        schedule.set_head(Arc::clone(&after));
        let mut against = Against::schedule((*after).clone(), schedule);
        against.local_shard = ShardId::leaf(1, 1);
        against.anchor = WeightedTimestamp::from_millis(10_000);
        against.members.members = [
            committed(earlier, LATER_LIFE * 1_000 - 1),
            committed(awaited, LATER_LIFE * 1_000),
        ]
        .into_iter()
        .map(|row| (row.tx, row))
        .collect();

        let (selected, _) = select_claims(
            &against.ctx(),
            &mut StateClaimsFold::default(),
            Vec::new(),
            vec![claim.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(
            selected,
            vec![
                claim
                    .restrict(|key| key == verdict_leaf(SIBLING, awaited))
                    .expect("one cell kept"),
            ],
            "the reading rides for the row that awaited the later chain alone",
        );
        assert_eq!(selected[0].verdicts.to_vec(), vec![awaited]);
        assert_eq!(
            admit_all::<StateClaimsSection>(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                &selected
            ),
            Ok(()),
        );
    }

    /// A reading for a row the block's own finalizations settle is not
    /// carried: the fold settles before it hears, so the reading would
    /// reach no row. A reading for a row the block leaves standing rides
    /// beside it.
    #[test]
    fn a_reading_for_a_row_the_block_settles_is_not_carried() {
        let [settled, standing] = [1, 2].map(heard_member);
        let leaves: Vec<SubstateKey> = [settled, standing]
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let claim = proven_claim(SIBLING, 3, &leaves, &leaves).hearing([settled, standing]);
        let against =
            hearing_at_the_parent([stated_row(settled, None), stated_row(standing, None)]);
        let settling: Arc<Verifiable<Finalization>> = Arc::new(
            finalization_of(
                BlockHeight::new(1),
                vec![
                    TxOutcome::new(
                        settled,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )
                    .charging(0),
                ],
            )
            .into(),
        );
        let select = |finalizations: &[Arc<Verifiable<Finalization>>]| {
            select_claims(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                Vec::new(),
                vec![claim.clone()],
                &[],
                Vec::new(),
                finalizations,
            )
            .0
        };
        assert_eq!(
            select(&[]),
            vec![claim.clone()],
            "with nothing settled both readings ride",
        );
        let selected = select(from_ref(&settling));
        assert_eq!(
            selected,
            vec![
                claim
                    .restrict(|key| key == verdict_leaf(SIBLING, standing))
                    .expect("one cell kept"),
            ],
            "the reading for the row left standing rides, under its one name",
        );
        assert_eq!(selected[0].verdicts.to_vec(), vec![standing]);
    }

    /// A leaf read absent rides only in a claim holding the row and the
    /// marker it is judged beside, all three or none: offered without
    /// them it is not carried, and where another question's claim at the
    /// anchor reaches into the reading's span, the reading waits and the
    /// other claim rides as it is.
    #[test]
    fn an_absent_leaf_rides_with_its_row_and_marker_or_not_at_all() {
        let tx = heard_member(1);
        let [leaf, row, marker] = verdict_cells(tx);
        let whole = proven_claim(SIBLING, 3, &[], &[leaf, row, marker]).hearing([tx]);
        let alone = proven_claim(SIBLING, 3, &[], &[leaf]).hearing([tx]);
        let short = proven_claim(SIBLING, 3, &[], &[leaf, row]).hearing([tx]);
        let against = hearing_at_the_parent([stated_row(tx, None)]);
        let select = |gating: Vec<StateClaim>, verdicts: Vec<StateClaim>| {
            select_claims(
                &against.ctx(),
                &mut StateClaimsFold::default(),
                gating,
                verdicts,
                &[],
                Vec::new(),
                &[],
            )
            .0
        };

        assert_eq!(
            select(Vec::new(), vec![whole.clone()]),
            vec![whole.clone()],
            "the three cells ride in their one claim",
        );
        assert!(select(Vec::new(), vec![alone]).is_empty());
        assert!(select(Vec::new(), vec![short]).is_empty());

        let other = proven_claim(SIBLING, 3, &[], &[row]);
        assert_eq!(
            select(vec![other.clone()], vec![whole]),
            vec![other],
            "the other claim rides as it is and no cell of the reading does",
        );
    }

    /// Two verdict claims at one anchor whose keys interleave do not
    /// ride one block: the first offered rides and the other waits,
    /// spending nothing. Two whose spans are apart both ride.
    #[test]
    fn of_two_interleaved_verdict_claims_the_second_waits_a_block() {
        let members: Vec<TxHash> = (1..=4).map(heard_member).collect();
        let mut keyed: Vec<(SubstateKey, TxHash)> = members
            .iter()
            .map(|tx| (verdict_leaf(SIBLING, *tx), *tx))
            .collect();
        keyed.sort_unstable();
        let leaves: Vec<SubstateKey> = keyed.iter().map(|(leaf, _)| *leaf).collect();
        let [(low, low_tx), (mid, mid_tx), (high, high_tx), (top, top_tx)] =
            [keyed[0], keyed[1], keyed[2], keyed[3]];
        let outer = proven_claim(SIBLING, 3, &leaves, &[low, high]).hearing([low_tx, high_tx]);
        let inner = proven_claim(SIBLING, 3, &leaves, &[mid]).hearing([mid_tx]);
        let apart = proven_claim(SIBLING, 3, &leaves, &[top]).hearing([top_tx]);
        let against = hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None)));
        let select = |verdicts: Vec<StateClaim>| {
            let mut fold = StateClaimsFold::default();
            let (selected, _) = select_claims(
                &against.ctx(),
                &mut fold,
                Vec::new(),
                verdicts,
                &[],
                Vec::new(),
                &[],
            );
            assert_eq!(
                (fold.weight, fold.verdict_weight),
                (
                    0,
                    selected.iter().map(StateClaim::wire_weight).sum::<usize>()
                ),
                "only what rides is weighed, and as verdict claims",
            );
            let mut checked = StateClaimsFold::default();
            assert!(
                admit_all::<StateClaimsSection>(&against.ctx(), &mut checked, &selected).is_ok()
            );
            selected
        };
        assert_eq!(
            select(vec![outer.clone(), inner.clone(), apart.clone()]),
            vec![outer.clone(), apart.clone()],
            "the claim inside the first one's span waits",
        );
        assert_eq!(
            select(vec![inner.clone(), outer, apart.clone()]),
            vec![inner, apart]
        );
    }

    /// The first verdict claim the bytes left do not hold is cut to the
    /// readings that fit, each whole, and nothing is taken after it.
    #[test]
    fn a_verdict_claim_over_the_bytes_left_is_cut_by_whole_readings() {
        let members: Vec<TxHash> = (1..=3).map(heard_member).collect();
        let cells: Vec<SubstateKey> = members.iter().flat_map(|tx| verdict_cells(*tx)).collect();
        let batch = proven_claim(SIBLING, 3, &[], &cells).hearing(members.clone());
        let after = proven_claim(SIBLING, 4, &[], &verdict_cells(heard_member(4)))
            .hearing([heard_member(4)]);
        let against = hearing_at_the_parent(
            members
                .iter()
                .copied()
                .chain([heard_member(4)])
                .map(|tx| stated_row(tx, None)),
        );
        let two = batch
            .restrict(|key| {
                batch.verdicts[..2]
                    .iter()
                    .any(|tx| verdict_cells(*tx).contains(&key))
            })
            .expect("two readings");
        let mut fold = StateClaimsFold {
            verdict_weight: MAX_CLAIMS_BYTES - two.wire_weight(),
            ..StateClaimsFold::default()
        };
        assert!(!claims_admit_block(
            fold.verdict_weight + batch.wire_weight()
        ));
        let (selected, _) = select_claims(
            &against.ctx(),
            &mut fold,
            Vec::new(),
            vec![batch, after],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(selected, vec![two], "two readings fit, each whole");
        assert_eq!((fold.weight, fold.verdict_weight), (0, MAX_CLAIMS_BYTES));
    }

    /// A verdict claim admission refuses does not end the spending: cut
    /// to the readings that fit and refused for its proof, it is passed
    /// over, and a smaller claim behind it rides.
    #[test]
    fn a_cut_verdict_claim_admission_refuses_is_passed_over() {
        let members: Vec<TxHash> = (1..=3).map(heard_member).collect();
        let cells: Vec<SubstateKey> = members.iter().flat_map(|tx| verdict_cells(*tx)).collect();
        let mut unproven = proven_claim(SIBLING, 3, &[], &cells).hearing(members.clone());
        unproven.anchor.state_root = StateRoot::from_raw(Hash::from_bytes(b"another root"));
        let after = proven_claim(SIBLING, 4, &[], &verdict_cells(heard_member(4)))
            .hearing([heard_member(4)]);
        let against = hearing_at_the_parent(
            members
                .iter()
                .copied()
                .chain([heard_member(4)])
                .map(|tx| stated_row(tx, None)),
        );
        let two = unproven
            .restrict(|key| {
                unproven.verdicts[..2]
                    .iter()
                    .any(|tx| verdict_cells(*tx).contains(&key))
            })
            .expect("two readings");
        assert!(two.is_well_formed() && two.verify().is_err());
        assert!(after.wire_weight() <= two.wire_weight());
        let mut fold = StateClaimsFold {
            verdict_weight: MAX_CLAIMS_BYTES - two.wire_weight(),
            ..StateClaimsFold::default()
        };
        assert!(!claims_admit_block(
            fold.verdict_weight + unproven.wire_weight()
        ));
        let (selected, _) = select_claims(
            &against.ctx(),
            &mut fold,
            Vec::new(),
            vec![unproven, after.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(selected, vec![after], "the claim behind it rides");
    }

    /// A verdict claim no reading of which fits the bytes left does not
    /// end the spending: it is passed over, and a smaller claim behind
    /// it rides.
    #[test]
    fn a_verdict_claim_with_no_reading_that_fits_is_passed_over() {
        let members: Vec<TxHash> = (1..=2).map(heard_member).collect();
        let cells: Vec<SubstateKey> = members.iter().flat_map(|tx| verdict_cells(*tx)).collect();
        let wide = proven_claim(SIBLING, 3, &[], &cells).hearing(members.clone());
        let last = heard_member(3);
        let leaf = verdict_leaf(SIBLING, last);
        let after = proven_claim(SIBLING, 4, &[leaf], &[leaf]).hearing([last]);
        let against = hearing_at_the_parent(
            members
                .iter()
                .copied()
                .chain([last])
                .map(|tx| stated_row(tx, None)),
        );
        let one = wide
            .restrict(|key| verdict_cells(wide.verdicts[0]).contains(&key))
            .expect("one reading");
        assert!(
            after.wire_weight() < one.wire_weight(),
            "{} {}",
            after.wire_weight(),
            one.wire_weight()
        );
        let mut fold = StateClaimsFold {
            verdict_weight: MAX_CLAIMS_BYTES - after.wire_weight(),
            ..StateClaimsFold::default()
        };
        let (selected, _) = select_claims(
            &against.ctx(),
            &mut fold,
            Vec::new(),
            vec![wide, after.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(selected, vec![after], "the claim behind it rides");
    }

    /// The pieces of a claim of `readings` members' present verdict
    /// leaves on [`SIBLING`], by how many of its readings each keeps in
    /// member order, beside the claim and its members.
    fn pieces_by_reading(readings: usize) -> (Vec<TxHash>, StateClaim, Vec<StateClaim>) {
        let members: Vec<TxHash> = (0..readings).map(heard_member).collect();
        let leaves: Vec<SubstateKey> = members
            .iter()
            .map(|tx| verdict_leaf(SIBLING, *tx))
            .collect();
        let whole = proven_claim(SIBLING, 3, &leaves, &leaves).hearing(members.clone());
        let pieces = (1..=readings)
            .map(|kept| {
                whole
                    .restrict(|key| {
                        whole.verdicts[..kept]
                            .iter()
                            .any(|tx| key == verdict_leaf(SIBLING, *tx))
                    })
                    .expect("a prefix of the readings")
            })
            .collect();
        (members, whole, pieces)
    }

    /// A claim of many readings the bytes left do not hold is cut to
    /// the most of them that fit: the piece a search down from the whole
    /// claim, one reading at a time, stops at.
    #[test]
    fn a_cut_verdict_claim_carries_the_most_readings_that_fit() {
        let (members, whole, pieces) = pieces_by_reading(MAX_PROOFS_PER_QUERY);
        let against = hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None)));
        let weights: Vec<usize> = pieces.iter().map(StateClaim::wire_weight).collect();
        for kept in [1, 2, 37, 128, 200, MAX_PROOFS_PER_QUERY - 1] {
            for room in [weights[kept - 1], weights[kept] - 1] {
                let longest = (1..members.len())
                    .rev()
                    .find(|readings| weights[readings - 1] <= room)
                    .expect("one reading fits");
                let mut fold = StateClaimsFold {
                    verdict_weight: MAX_CLAIMS_BYTES - room,
                    ..StateClaimsFold::default()
                };
                let (selected, _) = select_claims(
                    &against.ctx(),
                    &mut fold,
                    Vec::new(),
                    vec![whole.clone()],
                    &[],
                    Vec::new(),
                    &[],
                );
                assert_eq!(
                    selected,
                    vec![pieces[longest - 1].clone()],
                    "{longest} readings fit {room} bytes",
                );
            }
        }
        let mut fold = StateClaimsFold {
            verdict_weight: MAX_CLAIMS_BYTES - (weights[0] - 1),
            ..StateClaimsFold::default()
        };
        let (selected, _) = select_claims(
            &against.ctx(),
            &mut fold,
            Vec::new(),
            vec![whole],
            &[],
            Vec::new(),
            &[],
        );
        assert!(selected.is_empty(), "no reading fits");
    }

    /// The longest fitting prefix is the one a search down from the
    /// whole stops at, and it is found in a logarithm of pieces built.
    #[test]
    fn the_longest_fitting_prefix_is_found_in_a_logarithm_of_pieces() {
        for len in [0usize, 1, 2, 3, 16, 255, 256] {
            for fitting in 0..=len {
                let mut built = 0u32;
                let found = longest_fitting_prefix(len, |readings| {
                    built += 1;
                    (readings <= fitting).then_some(readings)
                });
                let longest = (1..len).rev().find(|readings| *readings <= fitting);
                assert_eq!(found, longest, "{fitting} of {len} fit");
                assert!(
                    built <= len.max(1).ilog2() + 1,
                    "{built} pieces built for {len} readings",
                );
            }
        }
    }

    /// Select the fixture's verdict claims behind `gating` and `local`,
    /// and hold what rides to the section: the verdict claims offered
    /// first ride whole, the one the bytes stop at rides cut to the last
    /// reading that fits, and admission takes what was selected.
    /// Returns the bytes the other claims and the local crossings are
    /// counted at, and the bytes of the verdict claims.
    fn spent_to_the_last_reading(gating: Vec<StateClaim>, local: &[CrossingId]) -> (usize, usize) {
        let (members, heard) = verdict_claims_at(SIBLING, 3);
        let against = hearing_at_the_parent(members.iter().map(|tx| stated_row(*tx, None)));
        let ctx = against.ctx();
        let mut fold = StateClaimsFold::default();
        let (
            selected,
            ParentReads {
                crossings: kept_local,
                ..
            },
        ) = select_claims(
            &ctx,
            &mut fold,
            gating,
            heard.clone(),
            &[],
            local.to_vec(),
            &[],
        );

        let weigh = |verdict: bool| -> usize {
            selected
                .iter()
                .filter(|claim| claim.is_verdict_claim() == verdict)
                .map(StateClaim::wire_weight)
                .sum()
        };
        let (_, local_weight) = parent_reads_weight(kept_local.len(), 0);
        let others = weigh(false) + local_weight;
        assert!(
            local.is_empty() || (!kept_local.is_empty() && kept_local.len() < local.len()),
            "the local crossings take what the other claims leave: {}",
            kept_local.len(),
        );
        assert!(state_claims_admit_block(others));

        let verdicts: Vec<&StateClaim> = selected
            .iter()
            .filter(|claim| claim.is_verdict_claim())
            .collect();
        let last = *verdicts.last().expect("verdict claims ride");
        let whole = verdicts.len() - usize::from(*last != heard[verdicts.len() - 1]);
        assert_eq!(
            verdicts[..whole],
            heard[..whole].iter().collect::<Vec<_>>(),
            "the claims offered first ride whole",
        );
        assert!(claims_admit_block(others + weigh(true)));
        // The claim the bytes stopped at, and how many of its readings
        // ride: one more of them would not fit.
        let stopped = &heard[whole];
        let riding = if whole < verdicts.len() {
            last.verdicts.len()
        } else {
            0
        };
        let one_more = stopped
            .restrict(|key| {
                stopped.verdicts[..=riding]
                    .iter()
                    .any(|tx| key == verdict_leaf(SIBLING, *tx))
            })
            .expect("the claim the bytes stopped at holds a reading more");
        let before: usize = heard[..whole].iter().map(StateClaim::wire_weight).sum();
        assert!(
            !claims_admit_block(others + before + one_more.wire_weight()),
            "and the next is cut to the readings the section holds, to the last one",
        );
        assert_eq!(
            (fold.weight, fold.verdict_weight),
            (weigh(false), weigh(true))
        );
        let mut checked = StateClaimsFold::default();
        assert_eq!(
            admit_all::<StateClaimsSection>(&ctx, &mut checked, &selected),
            Ok(()),
            "what the composer selected passes admission",
        );
        (others, weigh(true))
    }

    /// A block whose other claims and local crossings fill their budget
    /// carries the bytes only verdict claims spend, to within one
    /// reading: no verdict reading waits on a reading of another kind.
    #[test]
    fn verdict_claims_ride_beside_a_full_budget_of_other_claims() {
        // The wide claims that fit whole, so the local crossings have
        // room behind them to fill.
        let (_, mut wide) = wide_claims_at(SIBLING, 4);
        let mut weight = 0usize;
        wide.retain(|claim| {
            weight += claim.wire_weight();
            state_claims_admit_block(weight)
        });
        let local: Vec<CrossingId> = (0..=u8::MAX).map(crossing).collect();
        let (others, verdicts) = spent_to_the_last_reading(wide, &local);
        assert!(
            !state_claims_admit_block(others + LOCAL_CROSSING_BYTES),
            "the other claims and the local crossings fill their budget",
        );
        let room = MAX_CLAIMS_BYTES - others;
        assert!(
            (MAX_VERDICT_CLAIMS_BYTES..MAX_VERDICT_CLAIMS_BYTES + LOCAL_CROSSING_BYTES)
                .contains(&room),
            "which leaves the verdict claims their own bytes: {room}",
        );
        assert!(verdicts <= room);
    }

    /// A block with no other claim carries verdict claims to within one
    /// reading of the whole section: they spend what the others leave.
    #[test]
    fn verdict_claims_take_what_the_other_claims_leave() {
        let (others, verdicts) = spent_to_the_last_reading(Vec::new(), &[]);
        assert_eq!(others, 0);
        assert!(
            verdicts > MAX_STATE_CLAIMS_BYTES,
            "{verdicts} bytes of verdict claims ride, past the bytes only they spend",
        );
    }

    /// Verdict claims past the section's budget wait a block and are
    /// not dropped: offered again at each next parent, where the rows
    /// have heard what the block before carried, every reading rides
    /// once, each block inside the budget.
    #[test]
    fn verdict_claims_past_the_budget_wait_a_block() {
        let (members, heard) = verdict_claims_at(SIBLING, 3);
        let at_the_anchor = Heard {
            shard: SIBLING,
            mark: ReadMark {
                epoch: Epoch::GENESIS,
                height: BlockHeight::new(3),
            },
            said: Some(Said::Yes),
        };
        let mut carried: BTreeSet<TxHash> = BTreeSet::new();
        let mut blocks = 0usize;
        while carried.len() < members.len() {
            let against = hearing_at_the_parent(
                members
                    .iter()
                    .map(|tx| stated_row(*tx, carried.contains(tx).then_some(at_the_anchor))),
            );
            let mut fold = StateClaimsFold::default();
            let (selected, _) = select_claims(
                &against.ctx(),
                &mut fold,
                Vec::new(),
                heard.clone(),
                &[],
                Vec::new(),
                &[],
            );
            let weight: usize = selected.iter().map(StateClaim::wire_weight).sum();
            assert!(
                claims_admit_block(weight),
                "block {blocks} carries {weight} bytes of verdict claims",
            );
            assert_eq!((fold.weight, fold.verdict_weight), (0, weight));
            let named: Vec<TxHash> = selected
                .iter()
                .flat_map(|claim| claim.verdicts.iter().copied())
                .collect();
            assert!(!named.is_empty(), "every block carries some of what waits");
            for tx in named {
                assert!(carried.insert(tx), "no reading rides twice");
            }
            blocks += 1;
        }
        assert!(blocks > 1, "the readings outrun one block's budget");
    }

    /// A claim is charged by its kind, by the proposer and by admission
    /// alike: a verdict claim to the section alone, and every other
    /// claim to its own share of the section too. A claim naming a
    /// member beside a crossing is of no kind: admission refuses it as
    /// ill-formed, and a proposer offered it passes it over.
    #[test]
    fn a_claim_is_charged_by_its_kind() {
        let tx = heard_member(1);
        let leaf = verdict_leaf(SIBLING, tx);
        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xC0; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x21; 32])),
            local: 0,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let verdict = proven_claim(SIBLING, 3, &[leaf], &[leaf]).hearing([tx]);
        let gating = proven_claim(SIBLING, 4, &[], &[test_key(0x11)]);
        let crossing = proven_claim(SIBLING, 5, &[leaf], &[leaf, record]).naming([(record, id)]);
        let mixed = crossing.clone().hearing([tx]);
        assert!(verdict.is_verdict_claim());
        assert!(!gating.is_verdict_claim() && !crossing.is_verdict_claim());
        assert_eq!(mixed.verify(), Ok(()));
        let [heard, gates, crosses] = [&verdict, &gating, &crossing].map(StateClaim::wire_weight);

        let mut against = beside_a_producer();
        against.members.members = BTreeMap::from([(tx, stated_row(tx, None))]);
        let ctx = against.ctx();

        let mut voter = StateClaimsFold::default();
        for (claim, spent) in [
            (&verdict, (0, heard, 0)),
            (&gating, (gates, heard, 1)),
            (&crossing, (gates + crosses, heard, 2)),
        ] {
            assert_eq!(StateClaimsSection::admit(&ctx, &mut voter, claim), Ok(()));
            assert_eq!((voter.weight, voter.verdict_weight, voter.count), spent);
        }
        let err = StateClaimsSection::admit(&ctx, &mut StateClaimsFold::default(), &mixed)
            .expect_err("a member named beside a crossing");
        assert!(
            err.contains("names a member beside a crossing or a value"),
            "{err}"
        );

        let mut proposer = StateClaimsFold::default();
        let (selected, _) = select_claims(
            &ctx,
            &mut proposer,
            vec![gating.clone(), crossing.clone()],
            vec![verdict.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(selected, vec![verdict.clone(), gating.clone(), crossing]);
        assert_eq!(
            (proposer.weight, proposer.verdict_weight, proposer.count),
            (voter.weight, voter.verdict_weight, voter.count),
            "the proposer spends the section as admission charges it",
        );

        let mut proposer = StateClaimsFold::default();
        let (selected, _) = select_claims(
            &ctx,
            &mut proposer,
            vec![gating.clone(), mixed],
            vec![verdict.clone()],
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(selected, vec![verdict, gating]);
        assert_eq!(
            (proposer.weight, proposer.verdict_weight, proposer.count),
            (gates, heard, 1),
            "a claim of no kind is charged to nothing",
        );
    }

    /// The budget is spent in the order the composer offers, one
    /// producer's claims in anchor order: with room for both, a claim at
    /// `a1` and one at `a2 > a1` both ride; with room for one, the one
    /// at `a1` rides whole and the one at `a2` is cut behind it, so no
    /// reading at `a2` is carried while one at `a1` is held back.
    #[test]
    fn a_producers_older_anchor_rides_before_its_newer_one() {
        let (_, at_a1) = wide_claims_at(ShardId::leaf(1, 0), 3);
        let (_, at_a2) = wide_claims_at(ShardId::leaf(1, 0), 4);
        let ctx = finalizations_against(CommitDedupIndex::new());
        let is_whole = |carried: &StateClaim, offered: &[StateClaim]| offered.contains(carried);

        let both = vec![at_a1[0].clone(), at_a2[0].clone()];
        let mut fold = StateClaimsFold::default();
        let selected = select_state_claims(&ctx.ctx(), &mut fold, both.clone());
        assert_eq!(selected.len(), 2, "with room for both, both ride");
        assert!(selected.iter().all(|claim| is_whole(claim, &both)));

        // `a1`'s claims until `a2`'s first no longer fits whole behind
        // them, then `a2`'s first.
        let mut offered: Vec<StateClaim> = Vec::new();
        let mut weight = 0usize;
        for claim in &at_a1 {
            if !state_claims_admit_block(weight + at_a2[0].wire_weight()) {
                break;
            }
            weight += claim.wire_weight();
            offered.push(claim.clone());
        }
        let older = offered.len();
        assert!(
            older > 0 && state_claims_admit_block(weight),
            "the fixture's a1 claims fit by themselves",
        );
        assert!(
            !state_claims_admit_block(weight + at_a2[0].wire_weight()),
            "and leave no room for a2's whole",
        );
        offered.push(at_a2[0].clone());
        let mut fold = StateClaimsFold::default();
        let selected = select_state_claims(&ctx.ctx(), &mut fold, offered.clone());
        let (carried_a1, carried_a2): (Vec<&StateClaim>, Vec<&StateClaim>) = selected
            .iter()
            .partition(|claim| claim.anchor.height == BlockHeight::new(3));
        assert_eq!(carried_a1.len(), older, "every claim at a1 rides");
        assert!(
            carried_a1.iter().all(|claim| is_whole(claim, &offered)),
            "and rides whole",
        );
        assert!(
            carried_a2.iter().all(|claim| !is_whole(claim, &offered)),
            "what rides at a2 is a piece cut behind a1's, never the whole",
        );
    }

    /// Admission on the second of two shards, where a crossing the
    /// first produces is a counterpart's to read.
    fn beside_a_producer() -> Against {
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.local_shard = ShardId::leaf(1, 1);
        against
    }

    /// What is left of a claim once the readings the floor refuses are
    /// cut from it passes admission, as a proposer's cut leaves it and as
    /// a holder's does: the proof cut to the kept cells bears them out,
    /// and the piece is in the section's form.
    #[test]
    fn a_claim_cut_at_the_floor_leaves_a_piece_admission_takes() {
        use hyperscale_hbor::Bytes;
        use hyperscale_storage::member_row_leaf;
        use hyperscale_types::test_utils::{state_and_proof_holding, test_key};
        use hyperscale_types::{Epoch, EpochWindows, ReadFrontier, ReadMark, Stated};
        use hyperscale_vm_effects::{Hash32, IntentHash, ProtocolHasher, Terms};
        use hyperscale_vm_types::ResourceAddr;

        use crate::read_fence::{drop_refused, read_fence};

        let producer = ShardId::leaf(1, 0);
        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xC0; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x21; 32])),
            local: 0,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let issuer = TxHash::from(Hash::from_bytes(b"issuer"));
        let row = member_row_leaf(producer, issuer);
        let marker = committed_tx_cell_key(producer, issuer, ts(9_000));
        let beside = test_key(0x11);
        let value = id
            .cell(
                issuer,
                ResourceAddr::new([0xE1; 31]),
                40,
                9_000,
                Terms::Escrowed {
                    credit: test_key(0x21),
                },
            )
            .to_bytes();
        let cell = |key: SubstateKey| (key, key.to_bytes().to_vec());
        let asked = [record, row, marker, beside];
        let (state_root, proof) = state_and_proof_holding(
            producer,
            &[(record, value.clone()), cell(marker), cell(beside)],
            &asked,
        );
        let anchor = Anchor {
            shard: producer,
            height: BlockHeight::new(3),
            state_root,
            ts: ts(3_000),
        };
        let readings = proof
            .inclusions(state_root, producer, &asked)
            .expect("the fixture proof answers for its keys");
        let whole = StateClaim::new(
            anchor,
            readings.into_iter().map(|(key, inclusion)| {
                if key == record {
                    (key, Stated::Held(Bytes::new(value.clone()).unwrap()))
                } else {
                    (key, Stated::Inclusion(inclusion))
                }
            }),
            proof,
        )
        .naming([(record, id)]);
        let ctx = beside_a_producer();
        let admitted = |claims: &[StateClaim]| {
            admit_all::<StateClaimsSection>(&ctx.ctx(), &mut StateClaimsFold::default(), claims)
        };
        assert!(admitted(from_ref(&whole)).is_ok());

        let windows = EpochWindows::new(1_000_000);
        let raised = ReadFrontier::from_entries([(
            producer,
            ReadMark {
                epoch: Epoch::GENESIS,
                height: BlockHeight::new(9),
            },
        )]);
        let fence = read_fence(from_ref(&whole), windows);
        let dropped = drop_refused(vec![whole.clone()], &fence, windows, &raised);
        assert_eq!(dropped.refused, 1, "the record presence");
        assert_eq!(dropped.claims.len(), 1);
        assert!(dropped.claims[0].reading(record).is_none());
        assert!(dropped.claims[0].crossings.is_empty());
        assert!(admitted(&dropped.claims).is_ok());

        let held = whole
            .restrict(|key| key == beside)
            .expect("the cell beside the record");
        assert!(admitted(&[held]).is_ok());
    }

    /// Two claims of one producer at one anchor whose keys interleave
    /// cannot both ride: the order rule keeps the first and the second
    /// waits a block. Nothing of that producer's lineage anchored above
    /// it rides beside the first, since the frontier the block raises
    /// would retire the held claim unread; another producer's claim is
    /// untouched.
    #[test]
    fn a_claim_the_order_rule_refuses_holds_its_producer_back() {
        use hyperscale_types::SubstateKey;
        use hyperscale_types::test_utils::{proven_claim, test_key};

        let producer = ShardId::leaf(1, 0);
        let other = ShardId::leaf(1, 1);
        let mut keys: Vec<SubstateKey> = (1u8..=4).map(test_key).collect();
        keys.sort_unstable();
        let first = proven_claim(producer, 3, &[], &[keys[1], keys[3]]);
        let interleaved = proven_claim(producer, 3, &[], &[keys[2]]);
        let newer = proven_claim(producer, 4, &[], &[keys[0]]);
        let elsewhere = proven_claim(other, 4, &[], &[test_key(0x81)]);
        let ctx = finalizations_against(CommitDedupIndex::new());

        let mut fold = StateClaimsFold::default();
        let selected = select_state_claims(
            &ctx.ctx(),
            &mut fold,
            vec![first.clone(), interleaved, newer, elsewhere.clone()],
        );
        assert_eq!(selected, vec![first, elsewhere]);
    }

    /// A proposer reads, at its parent, the member row of every
    /// transaction whose escrowed record its claims hold for a consumer
    /// here and whose row the parent's family does not hold: the reading
    /// a decline is written on. A record whose issuer holds a row is one
    /// a member may yet take, a record short of its validity end is one
    /// a block may yet commit the transaction of, and a record for a
    /// consumer elsewhere is nobody's here to decline, so none of those
    /// rows is named. The block the reading completes passes admission.
    #[test]
    fn a_held_record_whose_issuer_holds_no_row_has_its_row_read_at_the_parent() {
        use hyperscale_hbor::Bytes;
        use hyperscale_storage::{MemberIndex, member_row_leaf};
        use hyperscale_types::test_utils::{state_and_proof_holding, test_key};
        use hyperscale_types::{Inclusion, Stated};
        use hyperscale_vm_effects::{Hash32, IntentHash, ProtocolHasher, Terms};
        use hyperscale_vm_types::ResourceAddr;

        use crate::local_crossings::parent_claims;

        let producer = ShardId::leaf(1, 0);
        let issuer = TxHash::from(Hash::from_bytes(b"issuer"));
        let held_until = |consumer: u8, validity_end_ms: u64| {
            let id = CrossingId {
                producer: Address::new([0x21; 31], AddressClass::Component),
                consumer: Address::new([consumer; 31], AddressClass::Component),
                intent: IntentHash(Hash32([consumer; 32])),
                local: 0,
                output: 0,
            };
            let record = id.record_key(&ProtocolHasher);
            let value = id
                .cell(
                    issuer,
                    ResourceAddr::new([0xE1; 31]),
                    40,
                    validity_end_ms,
                    Terms::Escrowed {
                        credit: test_key(0x21),
                    },
                )
                .to_bytes();
            let (state_root, proof) =
                state_and_proof_holding(producer, &[(record, value.clone())], &[record]);
            StateClaim::new(
                Anchor {
                    shard: producer,
                    height: BlockHeight::new(3),
                    state_root,
                    ts: ts(3_000),
                },
                [(record, Stated::Held(Bytes::new(value).unwrap()))],
                proof,
            )
            .naming([(record, id)])
        };
        let mut ctx = beside_a_producer();
        ctx.members = MemberIndex::empty(ctx.local_shard);
        ctx.parent.shard = ctx.local_shard;
        let end = ctx.anchor.as_millis();
        let held = |consumer: u8| held_until(consumer, end);
        let reads = |ctx: &Against, claim: &StateClaim| {
            let (selected, at_parent) = select_claims(
                &ctx.ctx(),
                &mut StateClaimsFold::default(),
                vec![claim.clone()],
                Vec::new(),
                &[],
                Vec::new(),
                &[],
            );
            assert_eq!(selected, from_ref(claim));
            assert!(at_parent.crossings.is_empty());
            at_parent.rowless
        };

        let inbound = held(0xC0);
        assert_eq!(reads(&ctx, &inbound), [issuer]);
        assert!(
            reads(&ctx, &held(0x40)).is_empty(),
            "a record whose consumer another shard holds",
        );
        assert!(
            reads(&ctx, &held_until(0xC0, end + 1)).is_empty(),
            "a record the block's clock is short of the validity end of",
        );

        let parent = ctx.parent;
        let at_parent = parent_claims(&[], &[issuer], parent, &ctx.members);
        assert_eq!(at_parent.len(), 1);
        assert_eq!(
            at_parent[0].reading(member_row_leaf(ctx.local_shard, issuer)),
            Some(Inclusion::Absent),
        );
        let mut block = vec![inbound.clone(), at_parent[0].clone()];
        block.sort_unstable();
        assert_eq!(
            admit_all::<StateClaimsSection>(&ctx.ctx(), &mut StateClaimsFold::default(), &block),
            Ok(()),
        );

        ctx.members.members.insert(issuer, stated_row(issuer, None));
        assert!(
            reads(&ctx, &inbound).is_empty(),
            "a record whose issuer holds a row here",
        );
    }

    /// The shard the carriage fixtures below read records on, and the
    /// transaction that issued them.
    const RECORD_PRODUCER: ShardId = ShardId::leaf(1, 0);

    fn record_issuer() -> TxHash {
        TxHash::from(Hash::from_bytes(b"issuer"))
    }

    /// An escrowed record `RECORD_PRODUCER` holds for a consumer on the
    /// second of two shards, whose transaction's validity ends at nine
    /// seconds: its crossing, its key and its bytes.
    fn escrowed_for_a_consumer_here(seed: u8) -> (CrossingId, SubstateKey, Vec<u8>) {
        use hyperscale_types::test_utils::test_key;
        use hyperscale_vm_effects::Terms;
        use hyperscale_vm_types::ResourceAddr;

        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xC0; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        };
        let value = id
            .cell(
                record_issuer(),
                ResourceAddr::new([0xE1; 31]),
                40,
                9_000,
                Terms::Escrowed {
                    credit: test_key(0x21),
                },
            )
            .to_bytes();
        (id, id.record_key(&ProtocolHasher), value)
    }

    /// A claim at `RECORD_PRODUCER`'s `height` holding the value of each
    /// of `held`, over a tree holding exactly `present`.
    fn holding(
        height: u64,
        present: &[(SubstateKey, Vec<u8>)],
        held: &[(SubstateKey, Vec<u8>)],
    ) -> StateClaim {
        use hyperscale_hbor::Bytes;
        use hyperscale_types::Stated;
        use hyperscale_types::test_utils::state_and_proof_holding;

        let keys: Vec<SubstateKey> = held.iter().map(|(key, _)| *key).collect();
        let (state_root, proof) = state_and_proof_holding(RECORD_PRODUCER, present, &keys);
        StateClaim::new(
            Anchor {
                shard: RECORD_PRODUCER,
                height: BlockHeight::new(height),
                state_root,
                ts: ts(height * 1_000),
            },
            held.iter()
                .map(|(key, value)| (*key, Stated::Held(Bytes::new(value.clone()).unwrap()))),
            proof,
        )
    }

    /// Admission on the second of two shards whose parent holds no
    /// member row, at a block anchored past the fixtures' validity end.
    fn consuming_with_no_rows() -> Against {
        use hyperscale_storage::MemberIndex;

        let mut ctx = beside_a_producer();
        ctx.members = MemberIndex::empty(ctx.local_shard);
        ctx.parent.shard = ctx.local_shard;
        ctx.anchor = ts(10_000);
        ctx
    }

    /// A record whose transaction holds a member row at the parent
    /// declines nothing, however it is offered. Unnamed, it is a
    /// member's arrival. Named for a decline, as a proposer whose
    /// persisted tip trails the parent may still offer it, it rides
    /// whole in its place and the block reads no row absent, so the
    /// fold writes nothing. With the row gone the named record rides,
    /// its row is read, and the fold declines.
    #[test]
    fn a_record_with_a_row_standing_is_carried_and_declines_nothing() {
        use hyperscale_storage::{member_row_leaf, unclaimed_declines};
        use hyperscale_types::test_utils::test_key;
        use hyperscale_vm_effects::Answered;

        use crate::local_crossings::parent_claims;

        let (id, record, value) = escrowed_for_a_consumer_here(0x21);
        let beside = test_key(0x11);
        let cells = [(record, value), (beside, beside.to_bytes().to_vec())];
        let arrival = holding(3, &cells, &cells);
        let for_a_decline = arrival.clone().naming([(record, id)]);

        let mut ctx = consuming_with_no_rows();
        ctx.members
            .members
            .insert(record_issuer(), stated_row(record_issuer(), None));
        let block = |ctx: &Against, claim: &StateClaim| {
            let (mut claims, at_parent) = select_claims(
                &ctx.ctx(),
                &mut StateClaimsFold::default(),
                vec![claim.clone()],
                Vec::new(),
                &[],
                Vec::new(),
                &[],
            );
            claims.extend(parent_claims(
                &at_parent.crossings,
                &at_parent.rowless,
                ctx.parent,
                &ctx.members,
            ));
            claims
        };
        let declines = |ctx: &Against, claims: &[StateClaim]| {
            unclaimed_declines(claims, ctx.local_shard, ctx.anchor, &ctx.members)
                .cells
                .into_keys()
                .collect::<Vec<_>>()
        };

        for offered in [&arrival, &for_a_decline] {
            let carried = block(&ctx, offered);
            assert_eq!(
                carried,
                from_ref(offered),
                "the reading rides whole, and no row is read beside it",
            );
            assert!(declines(&ctx, &carried).is_empty());
            assert_eq!(
                admit_all::<StateClaimsSection>(
                    &ctx.ctx(),
                    &mut StateClaimsFold::default(),
                    &carried
                ),
                Ok(()),
            );
        }

        ctx.members.members.remove(&record_issuer());
        let carried = block(&ctx, &for_a_decline);
        assert!(carried.contains(&for_a_decline));
        assert!(carried.iter().any(|claim| {
            claim.reading(member_row_leaf(ctx.local_shard, record_issuer()))
                == Some(Inclusion::Absent)
        }));
        assert_eq!(
            declines(&ctx, &carried),
            vec![id.answer_key(&ProtocolHasher, Answered::Never)],
        );
    }

    /// A named record whose transaction holds a row at the parent rides
    /// in its producer's anchor order beside a younger claim of that
    /// producer, so the floor the block raises passes no reading it left
    /// behind: the record's own anchor is under the floor only once its
    /// reading is committed.
    #[test]
    fn a_record_with_a_row_standing_rides_under_the_floor_a_younger_claim_raises() {
        use hyperscale_types::test_utils::test_key;
        use hyperscale_types::{EpochWindows, ReadFrontier};

        let windows = EpochWindows::new(1_000_000);
        let mut ctx = consuming_with_no_rows();
        ctx.members
            .members
            .insert(record_issuer(), stated_row(record_issuer(), None));
        let (id, record, value) = escrowed_for_a_consumer_here(0x21);
        let cells = [(record, value)];
        let older = holding(3, &cells, &cells).naming([(record, id)]);
        let beside = test_key(0x11);
        let younger_cells = [(beside, beside.to_bytes().to_vec())];
        let younger = holding(4, &younger_cells, &younger_cells);
        let (carried, at_parent) = select_claims(
            &ctx.ctx(),
            &mut StateClaimsFold::default(),
            vec![older.clone(), younger.clone()],
            Vec::new(),
            &[],
            Vec::new(),
            &[],
        );
        assert_eq!(
            carried,
            vec![older.clone(), younger.clone()],
            "both ride, the older first",
        );
        assert!(
            at_parent.rowless.is_empty(),
            "and the standing row is not read"
        );

        let mut frontier = ReadFrontier::default();
        frontier.advance(&FrontierInputs::for_block(
            &carried,
            windows,
            ctx.anchor,
            ctx.local_shard,
        ));
        assert_eq!(
            frontier.entry(RECORD_PRODUCER),
            Some(ReadMark::of(&younger.anchor, windows)),
        );
        assert!(
            frontier.refuses(RECORD_PRODUCER, ReadMark::of(&older.anchor, windows)),
            "the floor passes the older reading only in the block that carried it",
        );
    }

    /// An unsolicited record rides in its producer's anchor order, so it
    /// is offered behind every older claim of that producer. Where the
    /// budget cuts a wanted reading at `a1`, the spending ends there and
    /// the unsolicited record at `a2 > a1` is not carried: the block
    /// raises its producer's floor to `a1` and no further, and what was
    /// cut from the wanted reading is admissible at the next block. Had
    /// the record been carried, the floor at `a2` would refuse it.
    #[test]
    fn an_unsolicited_record_raises_no_floor_past_a_held_wanted_reading() {
        use hyperscale_types::{EpochWindows, ReadFrontier};

        let windows = EpochWindows::new(1_000_000);
        let ctx = consuming_with_no_rows();
        let (id, record, value) = escrowed_for_a_consumer_here(0x21);
        let unsolicited = [(record, value)];
        let unsolicited = holding(4, &unsolicited, &unsolicited).naming([(record, id)]);

        // Wanted readings at `a1`: held values no claim names, as a
        // member's arrivals ride, and more of them than a section holds.
        let mut cells: Vec<(SubstateKey, Vec<u8>)> = (0u16..1_024)
            .map(|at| {
                let key = SubstateKey {
                    owner: test_prefix(u8::try_from(at / 256).expect("under 8")),
                    local: LocalKey([u8::try_from(at % 256).expect("masked"); 16]),
                };
                (key, vec![0xA1; 200])
            })
            .collect();
        cells.sort_unstable();
        let wanted: Vec<StateClaim> = cells
            .chunks(64)
            .map(|chunk| holding(3, &cells, chunk))
            .collect();
        assert!(
            !state_claims_admit_block(wanted.iter().map(StateClaim::wire_weight).sum()),
            "the fixture's wanted readings must outrun the budget",
        );
        let (a1, a2) = (wanted[0].anchor, unsolicited.anchor);
        let select = |offered: Vec<StateClaim>| {
            select_claims(
                &ctx.ctx(),
                &mut StateClaimsFold::default(),
                offered,
                Vec::new(),
                &[],
                Vec::new(),
                &[],
            )
        };
        let floor_after = |carried: &[StateClaim]| {
            let mut frontier = ReadFrontier::default();
            frontier.advance(&FrontierInputs::for_block(
                carried,
                windows,
                ctx.anchor,
                ctx.local_shard,
            ));
            frontier
        };

        // With room for both, both ride and the record's row is read.
        let (carried, at_parent) = select(vec![wanted[0].clone(), unsolicited.clone()]);
        assert_eq!(carried, vec![wanted[0].clone(), unsolicited.clone()]);
        assert_eq!(at_parent.rowless, [record_issuer()]);
        assert!(
            floor_after(&carried).refuses(RECORD_PRODUCER, ReadMark::of(&a1, windows)),
            "a record carried at a2 raises the floor past a1",
        );

        // With the wanted readings cut by the budget, the record waits.
        let mut offered = wanted;
        offered.push(unsolicited);
        let (carried, at_parent) = select(offered);
        let read: BTreeSet<SubstateKey> = carried.iter().flat_map(StateClaim::keys).collect();
        assert!(
            read.len() < cells.len(),
            "the budget cut a wanted reading from the block",
        );
        assert!(carried.iter().all(|claim| claim.anchor == a1));
        assert!(!read.contains(&record) && at_parent.rowless.is_empty());
        let frontier = floor_after(&carried);
        assert_eq!(
            frontier.entry(RECORD_PRODUCER),
            Some(ReadMark::of(&a1, windows))
        );
        assert!(
            !frontier.refuses(RECORD_PRODUCER, ReadMark::of(&a1, windows)),
            "what the budget cut at a1 is admissible at the next block",
        );
        assert!(!frontier.refuses(RECORD_PRODUCER, ReadMark::of(&a2, windows)));
    }

    /// The rows a decline reads ride ahead of the local crossings in
    /// the room the section has left: every row and a prefix of the
    /// crossings behind a section near its budget, and neither behind a
    /// full one.
    #[test]
    fn the_rows_a_decline_reads_ride_ahead_of_the_local_crossings() {
        let rowless: Vec<TxHash> = (0..8).map(heard_member).collect();
        let crossings: Vec<CrossingId> = (0..200).map(crossing).collect();
        let offered = ParentReads {
            crossings: crossings.clone(),
            rowless: rowless.clone(),
        };
        assert_eq!(trim_parent_reads(&[], offered.clone()), offered);

        let (_, wide) = wide_claims(ShardId::leaf(1, 0));
        let mut selected: Vec<StateClaim> = Vec::new();
        let mut weight = 0usize;
        for claim in wide {
            if state_claims_admit_block(weight + claim.wire_weight()) {
                weight += claim.wire_weight();
                selected.push(claim);
            }
        }
        let kept = trim_parent_reads(&selected, offered.clone());
        assert_eq!(kept.rowless, rowless, "every row rides");
        assert!(kept.crossings.len() < crossings.len());
        assert_eq!(
            kept.crossings,
            trim_parent_reads(
                &selected,
                ParentReads {
                    crossings,
                    rowless: Vec::new()
                }
            )
            .crossings[..kept.crossings.len()],
            "the crossings take what the rows leave",
        );
        let (claims, carried) = parent_reads_weight(kept.crossings.len(), kept.rowless.len());
        assert!(state_claims_admit_block(weight + carried));
        assert!(selected.len() + claims <= MAX_STATE_CLAIMS_PER_BLOCK);

        let full: Vec<StateClaim> = selected
            .iter()
            .cycle()
            .take(MAX_STATE_CLAIMS_PER_BLOCK)
            .cloned()
            .collect();
        assert_eq!(trim_parent_reads(&full, offered), ParentReads::default());
    }

    /// The crossings whose ends share this shard ride in the room the
    /// section has left: all of them into an empty section, a prefix of
    /// them behind a section near its budget, and none behind a full
    /// one. What does not fit waits a block.
    #[test]
    fn local_crossings_past_the_section_budget_wait_a_block() {
        use hyperscale_vm_effects::{Hash32, IntentHash};

        let crossing = |seed: u16| {
            let [hi, lo] = seed.to_be_bytes();
            let mut body = [lo; 31];
            body[0] = hi;
            CrossingId {
                producer: Address::new(body, AddressClass::Component),
                consumer: Address::new([0xC0; 31], AddressClass::Component),
                intent: IntentHash(Hash32([lo; 32])),
                local: 0,
                output: 0,
            }
        };
        let offered: Vec<CrossingId> = (0..200).map(crossing).collect();
        let trim = |selected: &[StateClaim]| {
            trim_parent_reads(
                selected,
                ParentReads {
                    crossings: offered.clone(),
                    rowless: Vec::new(),
                },
            )
            .crossings
        };
        assert_eq!(trim(&[]), offered, "an empty section carries them all");

        let (_, wide) = wide_claims(ShardId::leaf(1, 0));
        let mut selected: Vec<StateClaim> = Vec::new();
        let mut weight = 0usize;
        for claim in wide {
            if state_claims_admit_block(weight + claim.wire_weight()) {
                weight += claim.wire_weight();
                selected.push(claim);
            }
        }
        let kept = trim(&selected);
        assert!(
            !kept.is_empty() && kept.len() < offered.len(),
            "a section near its budget carries some and not all: {}",
            kept.len(),
        );
        assert_eq!(kept, offered[..kept.len()], "the prefix offered");
        let per_crossing =
            3 * (STATE_CLAIM_CELL_BYTES + STATE_CLAIM_CROSSING_BYTES) + MAX_HELD_VALUE_BYTES + 4;
        let carried = weight
            + (kept.len() / (MAX_PROOFS_PER_QUERY / 3) + 1) * STATE_CLAIM_BYTES
            + kept.len() * per_crossing;
        assert!(state_claims_admit_block(carried), "and what is kept fits");
        assert!(
            !state_claims_admit_block(carried + per_crossing),
            "one more would not",
        );
    }

    #[test]
    fn select_transactions_keeps_at_lower_bound_inclusive() {
        // Half-open: start_timestamp_inclusive == anchor must be kept.
        let anchor = ts(1_000);
        let range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));
        let txs = vec![tx_with_range(6, range)];

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                HashSet::new(),
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert_eq!(selected.len(), 1, "anchor == start_inclusive must be kept");
    }

    #[test]
    fn select_transactions_dedup_short_circuits_validity_check() {
        // Tx in QC chain — should be dropped without consulting the
        // validity range. We pass an obviously-invalid range to confirm.
        let anchor = ts(100_000);
        let any_range = TimestampRange::new(ts(0), ts(1_000));
        let tx = tx_with_range(7, any_range);
        let mut chain = HashSet::new();
        chain.insert(tx.hash());

        let selected = select_transactions(
            &against(
                window_listing_no_packages(),
                anchor,
                WeightedTimestamp::ZERO,
                chain,
                empty_dedup_index(),
            )
            .ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &[tx],
        );
        assert!(selected.is_empty());
    }

    // ─── select_transactions: the terms charge ─────────────────────────

    const LEFT: ShardId = ShardId::leaf(1, 0);

    /// Two shards, as [`LEFT`] selects against them.
    fn left_of_two(anchor: WeightedTimestamp) -> Against {
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.anchor = anchor;
        against.local_shard = LEFT;
        against
    }

    /// `count` owners on `shard` under `committee`, the `nth` run of
    /// them: no two runs share an owner.
    fn owners_on(
        committee: &TopologySnapshot,
        shard: ShardId,
        nth: u32,
        count: usize,
    ) -> Vec<Address> {
        (0u32..)
            .map(|at| {
                let mut bytes = [0xC0u8; 31];
                bytes[0] = at.to_le_bytes()[0].wrapping_mul(0x9D);
                bytes[1..5].copy_from_slice(&at.to_le_bytes());
                bytes[5..9].copy_from_slice(&nth.to_le_bytes());
                Address::new(bytes, AddressClass::Component)
            })
            .filter(|owner| committee.shard_for_prefix(*owner) == shard)
            .take(count)
            .collect()
    }

    /// A transaction paid on [`LEFT`] that writes `width` owners there
    /// and, where it `reaches`, one on the other shard.
    fn declaring(
        committee: &TopologySnapshot,
        nth: u32,
        width: usize,
        reaches: bool,
        range: TimestampRange,
    ) -> Arc<Verified<Transaction>> {
        install_stub_protocol_statics();
        let payer = (0u8..=255)
            .map(test_principal)
            .find(|payer| committee.shard_for_prefix(payer.address()) == LEFT)
            .expect("a payer routes to each shard");
        let mut owners = owners_on(committee, LEFT, nth, width);
        if reaches {
            owners.extend(owners_on(committee, ShardId::leaf(1, 1), nth, 1));
        }
        let tx = stub_transaction(payer, &owners, u128::MAX >> 1, range);
        assert_eq!(committee.is_single_shard_transaction(&tx), !reaches);
        Arc::new(Verified::<Transaction>::from_persisted(tx))
    }

    /// A transaction reaching beyond the shard is charged the entry its
    /// block states for it, and one that would carry the section past
    /// its budget is left pooled with the selection going on behind it;
    /// one reaching no further is charged nothing, however much it
    /// declares.
    #[test]
    fn a_transaction_past_the_selection_charge_is_left_pooled() {
        let anchor = ts(1_000);
        let range = TimestampRange::new(ts(500), anchor.plus(Duration::from_mins(1)));
        let against = left_of_two(anchor);
        let committee = &against.snapshot;
        let wide = |nth: u32| declaring(committee, nth, 1_300, true, range);
        let weight = |tx: &Transaction| terms_of(tx, committee, LEFT).wire_weight();
        let fitting = MAX_TICK_TERMS_BYTES / weight(&wide(0));
        let narrow = declaring(committee, 9_000, 1, true, range);
        assert!(
            fitting * weight(&wide(0)) + weight(&narrow) <= MAX_TICK_TERMS_BYTES,
            "what the wide ones leave of the budget carries a narrow one",
        );
        let local = declaring(committee, 9_001, 1_300, false, range);

        let mut txs: Vec<Arc<Verified<Transaction>>> = (0..=fitting)
            .map(|nth| wide(u32::try_from(nth).expect("fewer than u32 transactions")))
            .collect();
        let past = Arc::clone(&txs[fitting]);
        txs.extend([Arc::clone(&narrow), Arc::clone(&local)]);

        let provisions = ProvisionsFold::default();
        let selected = select_transactions(
            &against.ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&provisions),
            &txs,
        );
        let selected: Vec<TxHash> = selected.iter().map(|tx| tx.hash()).collect();
        let expected: Vec<TxHash> = txs[..fitting]
            .iter()
            .chain([&narrow, &local])
            .map(|tx| tx.hash())
            .collect();
        assert_eq!(
            selected, expected,
            "the one past the budget is passed over, and those behind it are taken",
        );
        assert!(!selected.contains(&past.hash()));
    }

    /// A transaction declaring more accesses than a member's terms carry
    /// is passed over before any terms are derived for it, whether or
    /// not it reaches beyond the shard, and the one behind it is
    /// selected.
    #[test]
    fn a_transaction_declaring_past_the_holds_cap_is_never_selected() {
        let anchor = ts(1_000);
        let range = TimestampRange::new(ts(500), anchor.plus(Duration::from_mins(1)));
        let against = left_of_two(anchor);
        let committee = &against.snapshot;
        let reaching = declaring(committee, 0, MAX_HOLDS_PER_MEMBER, true, range);
        let local = declaring(committee, 1, MAX_HOLDS_PER_MEMBER + 1, false, range);
        for past in [&reaching, &local] {
            assert_eq!(
                past.routing().declared_modes.len(),
                MAX_HOLDS_PER_MEMBER + 1
            );
        }
        let behind = declaring(committee, 2, 1, true, range);

        let provisions = ProvisionsFold::default();
        let selected = select_transactions(
            &against.ctx(),
            Prefilter {
                precut: &refuses_precut(),
            },
            &mut TransactionsFold::beside(&provisions),
            &[reaching, Arc::clone(&local), Arc::clone(&behind)],
        );
        assert_eq!(
            selected.iter().map(|tx| tx.hash()).collect::<Vec<_>>(),
            [behind.hash()],
        );
        let err = admit_all::<TransactionsSection<'_>>(
            &against.ctx(),
            &mut TransactionsFold::beside(&provisions),
            [&**local],
        )
        .expect_err("a voter refuses the block that carries it");
        assert!(err.contains("declares more accesses"), "{err}");
    }
}
