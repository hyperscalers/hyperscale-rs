//! In-flight proposal correlation and the variant taxonomy of proposal
//! kinds.
//!
//! Proposal building is asynchronous: the coordinator emits a
//! `BuildProposal` action, the runner executes it on a worker thread, and
//! the result comes back as a `ProposalBuilt` event. Between those two
//! moments, another `try_propose` could fire (e.g. a repeated
//! `ContentAvailable`) or the round could advance. [`ProposalTracker`]
//! holds the `(height, round)` of the in-flight build so the
//! `ProposalBuilt` handler can detect stale callbacks and the `try_propose`
//! path can back off while a build is already pending.
//!
//! [`ProposalKind`] names the three shapes of proposal the coordinator can
//! emit — full content, empty fallback, empty sync — so a single
//! build-and-dispatch helper can drive them uniformly.

use hyperscale_core::Action;
use hyperscale_types::{
    BlockHash, BlockHeight, FinalizedWave, ProposerTimestamp, Provision, ProvisionHash, Round,
    RoutableTransaction, TopologySnapshot, TxHash, WaveIdHash, WeightedTimestamp,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::chain_view::ChainView;
use crate::tx_cache::CommittedTxCache;
use crate::verification::VerificationPipeline;

/// Variant-specific content for a proposal build.
///
/// The coordinator uses this to pass proposal-kind-specific inputs
/// (payload, timestamp source, `is_fallback` flag, logging label) to its
/// unified build-and-dispatch helper.
#[derive(Debug)]
pub(crate) enum ProposalKind {
    /// Normal proposal with a filtered payload and a real-clock timestamp.
    Normal {
        transactions: Vec<Arc<RoutableTransaction>>,
        finalized_waves: Vec<Arc<FinalizedWave>>,
        provision_batches: Vec<Arc<Provision>>,
        finalized_tx_count: u32,
    },
    /// View-change fallback: empty payload, parent's weighted timestamp
    /// (prevents Byzantine proposers from manipulating consensus time on
    /// timeout), `is_fallback = true`.
    Fallback,
    /// Syncing proposer: empty payload, normal timestamp. Proposer is
    /// online with an accurate clock but can't execute transactions.
    Sync,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingProposal {
    pub height: BlockHeight,
    pub round: Round,
}

pub(crate) struct ProposalTracker {
    pending: Option<PendingProposal>,
    /// Slot for a proposal that `dispatch_or_defer` could not dispatch
    /// because the parent JMT tree wasn't available yet. Consulted from
    /// `can_propose` so repeated `ContentAvailable` / QC-formed events for
    /// the same `(height, round)` don't spin through `assemble_build_action`
    /// while we're blocked waiting on `VerificationPipeline` to unblock.
    deferred: Option<PendingProposal>,
}

/// Result of correlating a `ProposalBuilt` callback against the tracker.
#[derive(Debug)]
pub(crate) enum TakeResult {
    /// The callback matches the in-flight build; the slot has been cleared.
    Matched,
    /// No build was in flight when the callback arrived.
    NotPending,
    /// A build was in flight but for different coordinates. The slot is
    /// preserved so the matching callback can still be handled later.
    Mismatch { expected: PendingProposal },
}

impl ProposalTracker {
    pub fn new() -> Self {
        Self {
            pending: None,
            deferred: None,
        }
    }

    /// Record a new in-flight build. A successful dispatch also invalidates
    /// any deferred slot for a prior attempt.
    pub fn start(&mut self, height: BlockHeight, round: Round) {
        self.pending = Some(PendingProposal { height, round });
        self.deferred = None;
    }

    /// Read the in-flight build, if any.
    pub fn pending(&self) -> Option<&PendingProposal> {
        self.pending.as_ref()
    }

    /// Drop both the in-flight and deferred slots. Called on round advance
    /// so a stale build completing later is discarded by the next
    /// `take_matching` and the deferred slot doesn't gate the new round's
    /// `(height, round)` target.
    pub fn clear(&mut self) {
        self.pending = None;
        self.deferred = None;
    }

    /// Record that a build for `(height, round)` could not dispatch because
    /// the parent JMT tree wasn't available. Consulted by `can_propose` to
    /// suppress re-entry until `clear_deferred` fires.
    pub fn mark_deferred(&mut self, height: BlockHeight, round: Round) {
        self.deferred = Some(PendingProposal { height, round });
    }

    /// Read the deferred slot, if any.
    pub fn deferred(&self) -> Option<&PendingProposal> {
        self.deferred.as_ref()
    }

    /// Drop the deferred slot. Called when the verification pipeline signals
    /// that the awaited parent tree has landed, so the next `try_propose`
    /// actually re-dispatches.
    pub fn clear_deferred(&mut self) {
        self.deferred = None;
    }

    /// Consume the in-flight build iff its `(height, round)` matches.
    pub fn take_matching(&mut self, height: BlockHeight, round: Round) -> TakeResult {
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

/// Filter ready transactions for proposal inclusion. Drops, in this order:
///
/// 1. Txs already in the QC chain (ancestors in the two-chain window) or the
///    retention-backed committed-tx cache (historically-committed hashes that
///    survive past mempool eviction — critical after sync).
/// 2. Txs whose `validity_range` is malformed against `validity_anchor`, or
///    whose half-open range does not contain `validity_anchor`. This is the
///    same expression voters apply during block verification, anchored on
///    the parent QC's weighted_timestamp; filtering here saves us from
///    proposing blocks that will be rejected.
///
/// Logs the dedup and expiry counts when non-zero.
pub(crate) fn select_transactions(
    ready_txs: &[Arc<RoutableTransaction>],
    qc_chain_tx_hashes: &HashSet<TxHash>,
    tx_cache: &CommittedTxCache,
    validity_anchor: WeightedTimestamp,
) -> Vec<Arc<RoutableTransaction>> {
    let before = ready_txs.len();
    let mut deduped = 0;
    let mut expired = 0;
    let filtered: Vec<_> = ready_txs
        .iter()
        .filter(|tx| {
            let h = tx.hash();
            if qc_chain_tx_hashes.contains(&h) || tx_cache.contains_tx(&h) {
                deduped += 1;
                return false;
            }
            if !tx.validity_range.is_well_formed(validity_anchor)
                || !tx.validity_range.contains(validity_anchor)
            {
                expired += 1;
                return false;
            }
            true
        })
        .cloned()
        .collect();
    if deduped > 0 || expired > 0 {
        debug!(
            deduped,
            expired,
            before,
            after = filtered.len(),
            "Filtered proposal candidates"
        );
    }
    filtered
}

/// Select finalized waves for inclusion: drop those already in the QC
/// chain, sort by kickoff height (tie-breaking by wave hash for canonical
/// manifest order), and cap the total finalized-tx count at the
/// `max_finalized_txs` limit. Returns `(waves, total_tx_count)`.
///
/// Canonical order matters: verifiers flatten receipts into JMT work_items
/// in manifest order, and the BTreeMap collapse there is last-writer-wins,
/// so the proposer must produce a deterministic order.
pub(crate) fn select_finalized_waves(
    finalized_waves: Vec<Arc<FinalizedWave>>,
    qc_chain_cert_hashes: &HashSet<WaveIdHash>,
    max_finalized_txs: usize,
) -> (Vec<Arc<FinalizedWave>>, usize) {
    let mut candidate_waves: Vec<_> = finalized_waves
        .into_iter()
        .filter(|fw| !qc_chain_cert_hashes.contains(&fw.wave_id_hash()))
        .collect();
    candidate_waves.sort_by_key(|fw| (fw.wave_id().block_height, fw.wave_id_hash()));

    let mut finalized_tx_count = 0usize;
    let waves_to_propose: Vec<_> = candidate_waves
        .into_iter()
        .take_while(|fw| {
            let new_total = finalized_tx_count.saturating_add(fw.tx_count());
            if new_total <= max_finalized_txs {
                finalized_tx_count = new_total;
                true
            } else {
                false
            }
        })
        .collect();
    (waves_to_propose, finalized_tx_count)
}

/// Select provision batches for inclusion: drop those already in the QC
/// chain, then take from the FIFO queue until the running tx-count total
/// would exceed `max_provision_txs`. Oldest batches go first so the queue
/// drains monotonically; unselected batches remain queued for the next
/// proposal.
pub(crate) fn select_provision_batches(
    provision_batches: Vec<Arc<Provision>>,
    qc_chain_provision_hashes: &HashSet<ProvisionHash>,
    max_provision_txs: usize,
) -> Vec<Arc<Provision>> {
    let mut running_tx_count = 0usize;
    provision_batches
        .into_iter()
        .filter(|b| !qc_chain_provision_hashes.contains(&b.hash()))
        .take_while(|b| {
            let new_total = running_tx_count.saturating_add(b.transactions.len());
            if new_total <= max_provision_txs {
                running_tx_count = new_total;
                true
            } else {
                false
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Build + dispatch
// ═══════════════════════════════════════════════════════════════════════════

/// Outcome of assembling a proposal build action.
///
/// `assemble_build_action` returns this so the coordinator can decide what
/// mutations to apply (e.g. recording leader activity, starting the
/// tracker, deferring if the parent tree isn't ready).
pub(crate) struct BuildActionPlan {
    /// The `BuildProposal` action ready for dispatch.
    pub action: Action,
    /// Parent hash, forwarded to the tracker / verification pipeline.
    pub parent_hash: BlockHash,
    /// Parent block height, same rationale.
    pub parent_block_height: BlockHeight,
    /// Whether to record leader activity: `Fallback` / `Sync` count as
    /// proposer progress; `Normal` does not (it isn't progress until the
    /// QC forms).
    pub record_leader_activity: bool,
    /// Logging label for the "proposal built" info event.
    pub log_label: &'static str,
}

/// Assemble a `BuildProposal` action for the given `ProposalKind`.
///
/// Pure with respect to the coordinator — reads only from the chain view
/// and the supplied inputs, writes nothing. The caller applies the returned
/// mutations (leader activity, tracker.start, dispatch-or-defer).
pub(crate) fn assemble_build_action(
    topology: &TopologySnapshot,
    chain: &ChainView,
    height: BlockHeight,
    round: Round,
    now: Duration,
    kind: ProposalKind,
) -> BuildActionPlan {
    let (parent_hash, parent_qc) = chain.proposal_parent();
    let parent_block_height = parent_qc.height;
    let parent_state_root = chain.parent_state_root(parent_hash);
    let parent_in_flight = chain.parent_in_flight(parent_hash);

    let (
        timestamp,
        is_fallback,
        transactions,
        finalized_waves,
        provision_batches,
        finalized_tx_count,
        log_label,
        record_leader_activity,
    ) = match kind {
        ProposalKind::Normal {
            transactions,
            finalized_waves,
            provision_batches,
            finalized_tx_count,
        } => (
            ProposerTimestamp(now.as_millis() as u64),
            false,
            transactions,
            finalized_waves,
            provision_batches,
            finalized_tx_count,
            "Requesting block build for proposal",
            false,
        ),
        ProposalKind::Fallback => (
            ProposerTimestamp(parent_qc.weighted_timestamp.as_millis()),
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            "Building fallback block (leader timeout)",
            true,
        ),
        ProposalKind::Sync => (
            ProposerTimestamp(now.as_millis() as u64),
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            "Building sync block (syncing, empty payload)",
            true,
        ),
    };

    let action = Action::BuildProposal {
        shard_group_id: topology.local_shard(),
        proposer: topology.local_validator_id(),
        height,
        round,
        parent_hash,
        parent_qc,
        timestamp,
        is_fallback,
        parent_state_root,
        parent_block_height,
        transactions,
        finalized_waves,
        provision_batches,
        parent_in_flight,
        finalized_tx_count,
    };

    BuildActionPlan {
        action,
        parent_hash,
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
/// child block's `VerifyStateRoot` hits `ParentVersionMissing`.
///
/// When deferred, the verification pipeline unblocks and re-enters
/// `try_propose` via `ContentAvailable` when the parent tree lands.
pub(crate) fn dispatch_or_defer(
    tracker: &mut ProposalTracker,
    verification: &mut VerificationPipeline,
    parent_hash: BlockHash,
    parent_block_height: BlockHeight,
    block_height: BlockHeight,
    round: Round,
    action: Action,
) -> Vec<Action> {
    if verification.parent_tree_available(parent_block_height, parent_hash) {
        tracker.start(block_height, round);
        vec![action]
    } else {
        verification.defer_proposal(parent_hash, parent_block_height);
        tracker.mark_deferred(block_height, round);
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_records_pending_slot() {
        let mut tracker = ProposalTracker::new();
        assert!(tracker.pending().is_none());

        tracker.start(BlockHeight(5), Round(1));
        let p = tracker.pending().unwrap();
        assert_eq!(p.height, BlockHeight(5));
        assert_eq!(p.round, Round(1));
    }

    #[test]
    fn take_matching_clears_on_match() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight(5), Round(1));

        let result = tracker.take_matching(BlockHeight(5), Round(1));
        assert!(matches!(result, TakeResult::Matched));
        assert!(tracker.pending().is_none());
    }

    #[test]
    fn take_matching_preserves_slot_on_mismatch() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight(5), Round(1));

        let result = tracker.take_matching(BlockHeight(5), Round(2));
        match result {
            TakeResult::Mismatch { expected } => {
                assert_eq!(expected.height, BlockHeight(5));
                assert_eq!(expected.round, Round(1));
            }
            other => panic!("expected Mismatch, got {:?}", other),
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
            tracker.take_matching(BlockHeight(5), Round(1)),
            TakeResult::NotPending
        ));
    }

    #[test]
    fn mark_deferred_records_slot_without_touching_pending() {
        let mut tracker = ProposalTracker::new();
        tracker.mark_deferred(BlockHeight(5), Round(1));

        let d = tracker.deferred().unwrap();
        assert_eq!(d.height, BlockHeight(5));
        assert_eq!(d.round, Round(1));
        assert!(tracker.pending().is_none());
    }

    #[test]
    fn start_clears_deferred() {
        let mut tracker = ProposalTracker::new();
        tracker.mark_deferred(BlockHeight(5), Round(1));
        tracker.start(BlockHeight(5), Round(1));

        assert!(tracker.deferred().is_none());
        assert!(tracker.pending().is_some());
    }

    #[test]
    fn clear_drops_both_slots() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight(5), Round(1));
        tracker.mark_deferred(BlockHeight(6), Round(2));
        tracker.clear();

        assert!(tracker.pending().is_none());
        assert!(tracker.deferred().is_none());
    }

    #[test]
    fn clear_deferred_leaves_pending_intact() {
        let mut tracker = ProposalTracker::new();
        tracker.start(BlockHeight(5), Round(1));
        tracker.mark_deferred(BlockHeight(6), Round(2));
        tracker.clear_deferred();

        assert!(tracker.deferred().is_none());
        assert!(tracker.pending().is_some());
    }

    // ─── select_transactions: validity-window filter ───────────────────

    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{routable_from_notarized_v1, TimestampRange};

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn tx_with_range(seed: u8, range: TimestampRange) -> Arc<RoutableTransaction> {
        let notarized = test_notarized_transaction_v1(&[seed]);
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized"))
    }

    fn empty_tx_cache() -> CommittedTxCache {
        CommittedTxCache::new()
    }

    #[test]
    fn select_transactions_drops_expired_txs() {
        // Anchor in the future of the tx's range.
        let anchor = ts(100_000);
        let expired_range = TimestampRange::new(ts(0), ts(1_000));
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_secs(60)));

        let txs = vec![
            tx_with_range(1, expired_range),
            tx_with_range(2, valid_range),
        ];

        let selected = select_transactions(&txs, &HashSet::new(), &empty_tx_cache(), anchor);

        assert_eq!(selected.len(), 1, "only the in-range tx should survive");
        assert_eq!(selected[0].hash(), txs[1].hash());
    }

    #[test]
    fn select_transactions_drops_not_yet_valid_txs() {
        // Anchor sits before the tx's start.
        let anchor = ts(50);
        let future_range = TimestampRange::new(ts(1_000), ts(60_000));
        let txs = vec![tx_with_range(3, future_range)];

        let selected = select_transactions(&txs, &HashSet::new(), &empty_tx_cache(), anchor);

        assert!(
            selected.is_empty(),
            "tx whose start is past anchor should be filtered"
        );
    }

    #[test]
    fn select_transactions_drops_malformed_ranges() {
        let anchor = ts(1_000);
        // Length over MAX_VALIDITY_RANGE (5 min).
        let too_wide = TimestampRange::new(ts(0), anchor.plus(Duration::from_secs(10 * 60)));
        let txs = vec![tx_with_range(4, too_wide)];

        let selected = select_transactions(&txs, &HashSet::new(), &empty_tx_cache(), anchor);

        assert!(selected.is_empty(), "malformed range should be filtered");
    }

    #[test]
    fn select_transactions_drops_at_upper_bound_exclusive() {
        // Half-open: end_timestamp_exclusive == anchor must be filtered.
        let anchor = ts(1_000);
        let range = TimestampRange::new(ts(500), anchor); // [500, 1000)
        let txs = vec![tx_with_range(5, range)];

        let selected = select_transactions(&txs, &HashSet::new(), &empty_tx_cache(), anchor);

        assert!(
            selected.is_empty(),
            "anchor == end_exclusive must be excluded (half-open)"
        );
    }

    #[test]
    fn select_transactions_keeps_at_lower_bound_inclusive() {
        // Half-open: start_timestamp_inclusive == anchor must be kept.
        let anchor = ts(1_000);
        let range = TimestampRange::new(anchor, anchor.plus(Duration::from_secs(60)));
        let txs = vec![tx_with_range(6, range)];

        let selected = select_transactions(&txs, &HashSet::new(), &empty_tx_cache(), anchor);

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

        let selected = select_transactions(&[tx], &chain, &empty_tx_cache(), anchor);
        assert!(selected.is_empty());
    }
}
