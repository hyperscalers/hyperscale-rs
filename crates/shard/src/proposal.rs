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

use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;

use hyperscale_core::{Action, FeeDemand};
use hyperscale_engine::legs::Classified;
use hyperscale_types::{
    AbandonmentRecord, BeaconWitnessLeafCount, BlockHash, BlockHeight, CrossingReoffer, Epoch,
    Finalization, Hash, LocalTimestamp, Probed, ProposerTimestamp, Provisions, ReadySignal,
    ReshapeTrigger, RevealChain, Round, ShardId, StateClaim, SubstateKey, TopologySchedule,
    TopologySnapshot, Transaction, TxHash, UnsettledTx, ValidatorId, Verifiable, Verified,
    WeightedTimestamp,
};
use tracing::debug;

use crate::admission::{
    Admission, FinalizationsFold, FinalizationsSection, ProvisionsFold, ProvisionsSection,
    RecordsFold, RecordsSection, ReoffersFold, ReoffersSection, StateClaimsFold,
    StateClaimsSection, TransactionsFold, TransactionsSection, admit_each, unwrapped,
};
use crate::chain_view::ChainView;
use crate::precut::Precut;
use crate::verification::VerificationPipeline;

/// Variant-specific content for a proposal build.
///
/// The coordinator uses this to pass proposal-kind-specific inputs
/// (payload, timestamp source, `is_fallback` flag, logging label) to its
/// unified build-and-dispatch helper.
#[derive(Debug)]
pub enum ProposalKind {
    /// Normal proposal with a filtered payload and a real-clock timestamp.
    Normal(ProposalPayload),
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
    pub(crate) reoffers: Vec<CrossingReoffer>,
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

/// What a proposer answers for itself that its voters answer by
/// delegation or at the fence: the validity window each transaction is
/// held to, with the late deliveries the anchor admits past their
/// validity end, and the predecessors' answers for transactions opening
/// before the chain's origin.
#[derive(Clone, Copy)]
pub struct Prefilter<'a> {
    /// The predecessors' answers for transactions opening before the
    /// origin.
    pub(crate) precut: &'a Precut,
    /// Transactions this shard only delivers for, admissible past their
    /// validity end to the delivery window's close.
    pub(crate) late_deliveries: &'a HashSet<TxHash>,
}

/// Filter ready transactions for proposal inclusion. Drops what the
/// voters' delegated root check refuses — a `validity_range` malformed
/// against the anchor or not containing it, unless the block licenses
/// the transaction as a late delivery — and what their fence defers on
/// — a transaction opening before the chain's origin that no
/// predecessor has proven absent; then keeps what
/// [`TransactionsSection`] admits, folding into `fold`. A transaction
/// that does not fit the sweep cap is skipped rather than ending the
/// selection, so a large composition never starves the small ones
/// behind it.
///
/// Logs the refusals when non-zero.
pub fn select_transactions(
    ctx: &Admission<'_>,
    prefilter: &Prefilter<'_>,
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
            // A delivery is admissible past its transaction's window on
            // a licence rather than on a clock — the same rule the
            // voters' root check reads.
            let range = tx.validity_range();
            let admitted = range.contains(ctx.anchor) || prefilter.late_deliveries.contains(&h);
            if !range.is_well_formed(ctx.anchor) || !admitted {
                expired += 1;
                return false;
            }
            // Opened before this chain did, so it belongs to the
            // predecessor that ran before the cut. Offerable only where
            // every predecessor proved it absent from its committed set;
            // anything else a voter defers on or refuses. Zero for a
            // chain born at network genesis.
            if range.start_timestamp_inclusive < ctx.chain_origin
                && !prefilter.precut.admissible(&h)
            {
                predates += 1;
                return false;
            }
            true
        })
        .cloned()
        .collect();
    let (selected, refused) =
        admit_each::<TransactionsSection<'_>, _>(ctx, fold, candidates, |tx| tx.as_ref());
    if expired > 0 || predates > 0 || refused > 0 {
        debug!(
            expired,
            predates,
            refused,
            before,
            after = selected.len(),
            "Filtered proposal candidates"
        );
    }
    selected
}

/// The transactions among `txs`, past their validity end at `anchor`,
/// that `local_shard` only delivers for and that `state_claims`
/// licenses: frozen divided against the trie of `anchor`'s window with
/// this shard outside the core and every leg here a delivery, and every
/// record that delivery consumes proved present by a claim the block
/// carries.
///
/// Computed against the block's own anchor and the block's own claims,
/// by the proposer selecting and by every voter checking, so the set is
/// one set. Empty when the anchor's window is not retained — a block
/// there is refused on other grounds.
///
/// **The licence is the record read present, and nothing about when.**
/// A presence answers wherever it was taken, and a claim at an old
/// anchor is admitted on purpose: there is no recency rule here and
/// there cannot be one, because which anchor is newest is a question
/// each validator answers from its own fetches, so a voter holding a
/// newer one would refuse a block with nothing to fetch that would
/// change its mind. What stops a stale proof mattering sits on the other
/// side — a consumer deletes the answer it holds only once no replay
/// could still be served against the record — so the wait lives on that
/// deletion rather than on this admission.
#[must_use]
pub fn late_deliveries<T: Deref<Target = Transaction>>(
    txs: &[Arc<T>],
    state_claims: &[StateClaim],
    topology_schedule: &TopologySchedule,
    anchor: WeightedTimestamp,
    local_shard: ShardId,
) -> HashSet<TxHash> {
    let Some(window) = topology_schedule.at(anchor) else {
        return HashSet::new();
    };
    let trie = window.shard_trie();
    txs.iter()
        .filter(|tx| anchor >= tx.validity_range().end_timestamp_exclusive)
        .filter(|tx| {
            let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
            classified.only_delivers_at(local_shard)
                && classified
                    .records_consumed(local_shard)
                    .into_iter()
                    .all(|record| record_stands(state_claims, record))
        })
        .map(|tx| tx.hash())
        .collect()
}

/// Whether some claim the block carries reads `record` present.
///
/// At any anchor the claim names. A record is written by the one
/// execution that issues the crossing and is swept by nothing, so a
/// presence read anywhere is a presence — which is [`Probed::Record`]'s
/// own rule, asked here rather than restated.
fn record_stands(state_claims: &[StateClaim], record: SubstateKey) -> bool {
    state_claims.iter().any(|claim| {
        claim
            .reading(record)
            .and_then(|inclusion| Probed::Record.read(inclusion))
            .is_some()
    })
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
/// with. The store hands them over in tick order, so the order rule
/// drops only what a gap in that order would have made unofferable
/// anyway, and the cap drops a suffix.
pub fn select_finalizations(
    ctx: &Admission<'_>,
    fold: &mut FinalizationsFold,
    finalizations: Vec<Arc<Verifiable<Finalization>>>,
) -> Vec<Arc<Verifiable<Finalization>>> {
    admit_each::<FinalizationsSection, _>(ctx, fold, finalizations, unwrapped).0
}

/// Select the boundary records for inclusion: each trimmed to the names
/// [`RecordsSection::name_stands`] admits — a name a finalization in
/// the block resolves, or one the chain already resolved, is refused by
/// every voter — with an emptied record dropped rather than offered,
/// then what [`RecordsSection`] admits in canonical order.
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
    ctx: &Admission<'_>,
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
            (!kept.is_empty())
                .then(|| AbandonmentRecord::new(record.shard(), record.terminal_wt(), kept))
        })
        .collect();
    trimmed.sort_by_key(AbandonmentRecord::shard);
    admit_each::<RecordsSection<'_>, _>(ctx, fold, trimmed, |record| record).0
}

/// The proofs a block may carry of counterparts' cells: what
/// [`StateClaimsSection`] admits, in the one order it carries them —
/// ascending, without repeats, and no more than the block's cap, with
/// the rest waiting a block.
#[must_use]
pub fn select_state_claims(
    ctx: &Admission<'_>,
    fold: &mut StateClaimsFold,
    state_claims: Vec<StateClaim>,
) -> Vec<StateClaim> {
    let mut sorted = state_claims;
    sorted.sort_unstable();
    sorted.dedup();
    admit_each::<StateClaimsSection, _>(ctx, fold, sorted, |bundle| bundle).0
}

/// The crossings a block may offer again: what
/// [`ReoffersSection`] admits from the ledger's outstanding set, in the
/// one order it carries them — ascending, without repeats, and no more
/// than the block's cap, with the rest waiting a block.
///
/// An offer naming no record promises a bundle with nothing in it, so
/// it is dropped rather than carried: the crossing stays outstanding
/// and is offered again when it has something to carry.
#[must_use]
pub fn select_reoffers(
    ctx: &Admission<'_>,
    fold: &mut ReoffersFold,
    reoffers: Vec<CrossingReoffer>,
) -> Vec<CrossingReoffer> {
    let mut sorted: Vec<CrossingReoffer> = reoffers
        .into_iter()
        .filter(CrossingReoffer::is_well_formed)
        .collect();
    sorted.sort_unstable();
    sorted.dedup();
    admit_each::<ReoffersSection, _>(ctx, fold, sorted, |offer| offer).0
}

/// Select provisions for inclusion: what [`ProvisionsSection`] admits
/// from the FIFO queue, folding into `fold`. Oldest batches go first so
/// the queue drains monotonically; unselected batches remain queued for
/// the next proposal.
pub fn select_provisions(
    ctx: &Admission<'_>,
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
    carry_terminal_roots: bool,
    settled_txs_window_floor: Option<WeightedTimestamp>,
    classification_topology_snapshot: Arc<TopologySnapshot>,
    fee_checks: Vec<FeeDemand>,
    fee_read_height: BlockHeight,
    substate_bytes: Option<u64>,
) -> BuildActionPlan {
    let (parent_block_hash, parent_qc) = chain.proposal_parent();
    let parent_block_height = parent_qc.height();
    let parent_state_root = chain.parent_state_root(parent_block_hash);
    let parent_in_flight = chain.parent_in_flight(parent_block_hash);
    let parent_settled_frontier = chain.parent_settled_frontier(parent_block_hash);
    let parent_sweep_frontier = chain.parent_sweep_frontier(parent_block_hash);
    let parent_load = chain.parent_load_checked(parent_block_hash);

    let (timestamp, is_fallback, payload, log_label, record_leader_activity) = match kind {
        ProposalKind::Normal(payload) => (
            ProposerTimestamp::from_local(now),
            false,
            payload,
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
        reoffers,
    } = payload;

    // The proposer's new BlockHeader will carry parent_qc in its wire
    // form; HBOR encoding is byte-identical between the raw and
    // verified shapes, but the field type is raw.
    let parent_qc_raw = parent_qc.into_inner();
    let action = Action::BuildProposal {
        shard_id: local_shard,
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
        reoffers,
        fee_checks,
        fee_read_height,
        parent_in_flight,
        parent_settled_frontier,
        parent_sweep_frontier,
        parent_load,
        substate_bytes,
        ready_signals,
        reshape_trigger,
        parent_witness_leaves,
        beacon_witness_base,
        parent_reveal_chain,
        parent_committee_anchor_epoch,
        committee_anchor_epoch,
        carry_split_child_roots,
        carry_terminal_roots,
        settled_txs_window_floor,
        classification_topology_snapshot,
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
/// When deferred, the verification pipeline unblocks and re-enters
/// `try_propose` via the proposal-retry latch when the parent tree lands.
pub fn dispatch_or_defer(
    tracker: &mut ProposalTracker,
    verification: &mut VerificationPipeline,
    plan: BuildActionPlan,
    block_height: BlockHeight,
    round: Round,
) -> Vec<Action> {
    if verification.parent_tree_available(plan.parent_block_height, plan.parent_block_hash) {
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
    use std::time::Duration;

    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, make_finalization, make_undecided_finalization,
        stub_abort_charge, stub_transaction, stub_transaction_binding, test_prefix, test_principal,
    };
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, CommittedAt, CommittedTxsRoot, Deadline, Hash,
        Inclusion, LocalKey, MAX_INTENTS, MAX_SWEEPABLE_CREATED_PER_BLOCK, MAX_VALIDITY_RANGE,
        NetworkDefinition, PredecessorTerminal, RoutePrefix, StateRoot, TimestampRange,
        TransactionDecision, UnsettledTx, ValidatorSet,
    };

    use super::*;
    use crate::admission::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use crate::commit_dedup::CommitDedupIndex;

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

        let resolving = Arc::new(Verifiable::from(make_finalization(
            BlockHeight::new(1),
            stranded().tx_hash,
            TransactionDecision::Accept,
        )));
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

        let against = finalizations_against(CommitDedupIndex::new());
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
    /// no verdict — a retirement, whose `Membership::housekeeping`
    /// decides nothing — contributes no such name, so a certificate
    /// carrying only those asks the question of an empty set. `all()` over
    /// an empty iterator is true, and the proposer re-offers the same
    /// certificate on every block while the settlement frontier stands
    /// still.
    #[test]
    fn select_finalizations_drops_a_committed_offer_that_decided_nothing() {
        let tx_hash = TxHash::from(Hash::from_bytes(b"retired"));
        let committed: Arc<Verifiable<Finalization>> = Arc::new(
            make_undecided_finalization(BlockHeight::new(1), tx_hash, TransactionDecision::Accept)
                .into(),
        );
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
        dedup_index.register_committed_certs(std::slice::from_ref(&committed));

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

    /// A successor of one chain that has answered nothing, so no pre-cut
    /// transaction is admissible. Cases anchored at
    /// `WeightedTimestamp::ZERO` never consult it, since nothing opens
    /// before an origin of zero.
    fn refuses_precut() -> Precut {
        Precut::succeeding(vec![PredecessorTerminal {
            shard: ShardId::leaf(1, 0),
            height: BlockHeight::new(9),
            block_hash: BlockHash::ZERO,
            committed_txs_root: CommittedTxsRoot::ZERO,
        }])
    }

    /// The same successor, with `tx_hash` proven absent from its
    /// predecessor's committed set.
    fn admits_precut(tx_hash: TxHash) -> Precut {
        let mut precut = refuses_precut();
        precut.record(precut.predecessors()[0].shard, tx_hash, true);
        precut
    }

    /// A transaction opening before the chain's origin is dropped while
    /// unresolved, and offered once every predecessor has proven it
    /// absent — the whole point of the committed set, seen from the
    /// proposer's side.
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &admits_precut(hash),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &txs,
        );

        assert!(
            selected.is_empty(),
            "anchor == end_exclusive must be excluded (half-open)"
        );
    }

    /// A record read present licenses a late delivery, at whatever
    /// anchor the reading was taken, and nothing else does.
    ///
    /// Both arms matter and they are not symmetric. A record is written
    /// by the one execution that issues the crossing and swept by
    /// nothing, so a presence anywhere is a presence and an old anchor
    /// is admitted on purpose — which is why there is no recency rule
    /// here. An absence says only that the producer has disposed of it
    /// by some road, which licenses nobody: it is the reading a replay
    /// would arrive holding.
    #[test]
    fn a_late_delivery_is_licensed_by_the_record_read_present() {
        let record = SubstateKey {
            owner: Address::new([0xAA; 31], AddressClass::Component),
            local: LocalKey([0x01; 16]),
        };
        let claim = |height: u64, inclusion: Inclusion| {
            StateClaim::new(
                Anchor {
                    shard: ShardId::leaf(1, 1),
                    height: BlockHeight::new(height),
                    state_root: StateRoot::from_raw(Hash::ZERO),
                    ts: ts(1_000),
                },
                [(record, inclusion)],
            )
        };

        assert!(
            !record_stands(&[], record),
            "a block carrying nothing licenses nothing"
        );
        assert!(
            record_stands(&[claim(7, Inclusion::Present([0xAB; 32]))], record),
            "the record proved present is the whole licence",
        );
        assert!(
            record_stands(&[claim(1, Inclusion::Present([0xAB; 32]))], record),
            "and it answers at an old anchor too: a presence is not bounded by a clock",
        );
        assert!(
            !record_stands(&[claim(7, Inclusion::Absent)], record),
            "a record read absent says the producer disposed of it, which licenses nobody",
        );
        let elsewhere = SubstateKey {
            local: LocalKey([0x02; 16]),
            ..record
        };
        assert!(
            !record_stands(&[claim(7, Inclusion::Present([0xAB; 32]))], elsewhere),
            "and a claim over some other cell is not this crossing's licence",
        );
    }

    /// A transaction named a late delivery is offered past its validity
    /// end at any anchor; one not named is dropped at the validity end
    /// as before.
    #[test]
    fn select_transactions_offers_a_named_late_delivery_at_any_anchor() {
        let end = ts(1_000);
        let range = TimestampRange::new(ts(500), end);
        let delivery = tx_with_range(7, range);
        let other = tx_with_range(8, range);
        let late: HashSet<TxHash> = std::iter::once(delivery.hash()).collect();
        let txs = vec![delivery.clone(), other];

        let select = |anchor: WeightedTimestamp| -> Vec<TxHash> {
            select_transactions(
                &against(
                    window_listing_no_packages(),
                    anchor,
                    WeightedTimestamp::ZERO,
                    HashSet::new(),
                    empty_dedup_index(),
                )
                .ctx(),
                &Prefilter {
                    precut: &refuses_precut(),
                    late_deliveries: &late,
                },
                &mut TransactionsFold::beside(&ProvisionsFold::default()),
                &txs,
            )
            .iter()
            .map(|tx| tx.hash())
            .collect()
        };
        assert_eq!(
            select(end),
            vec![delivery.hash()],
            "at the end only the delivery"
        );
        assert_eq!(
            select(end.plus(Duration::from_hours(24))),
            vec![delivery.hash()],
            "and at any anchor past it, since the licence the set stands for is \
             not on a clock"
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
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
            &Prefilter {
                precut: &refuses_precut(),
                late_deliveries: &HashSet::new(),
            },
            &mut TransactionsFold::beside(&ProvisionsFold::default()),
            &[tx],
        );
        assert!(selected.is_empty());
    }
}
