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
    BlockHash, BlockHeight, FinalizedWave, ProposerTimestamp, Provision, Round,
    RoutableTransaction, TopologySnapshot, TxHash, WaveIdHash,
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
        Self { pending: None }
    }

    /// Record a new in-flight build.
    pub fn start(&mut self, height: BlockHeight, round: Round) {
        self.pending = Some(PendingProposal { height, round });
    }

    /// Read the in-flight build, if any.
    pub fn pending(&self) -> Option<&PendingProposal> {
        self.pending.as_ref()
    }

    /// Drop the in-flight build without matching. Called on round advance
    /// so a stale build completing later is discarded by the next
    /// `take_matching`.
    pub fn clear(&mut self) {
        self.pending = None;
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

/// Filter ready transactions for proposal inclusion: drop those already in
/// the QC chain (ancestors in the two-chain window) and those in the
/// retention-backed committed-tx cache (historically-committed hashes that
/// survive past mempool eviction — critical after sync). Logs the dedup
/// count when it is non-zero.
pub(crate) fn select_transactions(
    ready_txs: &[Arc<RoutableTransaction>],
    qc_chain_tx_hashes: &HashSet<TxHash>,
    tx_cache: &CommittedTxCache,
) -> Vec<Arc<RoutableTransaction>> {
    let before = ready_txs.len();
    let filtered: Vec<_> = ready_txs
        .iter()
        .filter(|tx| {
            let h = tx.hash();
            !qc_chain_tx_hashes.contains(&h) && !tx_cache.contains_tx(&h)
        })
        .cloned()
        .collect();
    let deduped = before - filtered.len();
    if deduped > 0 {
        debug!(
            deduped,
            before,
            after = filtered.len(),
            "Filtered transactions already in QC chain or committed"
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
}
