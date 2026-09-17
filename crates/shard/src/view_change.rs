//! View change liveness state: current round, the round timer and its
//! backoff, and leader-activity timestamps.
//!
//! When its round timer fires a validator broadcasts a `Timeout` (the
//! coordinator's pacemaker); the round advances only on a 2f+1 timeout quorum,
//! or by syncing forward to a verified QC's round. This controller owns the
//! local round clock and the signals that decide when that timer fires:
//!
//! - `view` — current round.
//! - `view_at_height_start` — round when the current height began; drives
//!   the backoff (the timeout doubles per round abandoned at the height).
//! - `last_leader_activity` — any signal from the leader (proposal, header,
//!   QC, commit) resets the timeout.
//! - `last_header_reset` — rate-limits `record_header_activity` to once per
//!   `(height, round)` so a Byzantine leader can't spam different headers to
//!   delay view changes indefinitely.

use std::time::Duration;

use hyperscale_types::{
    BlockHeader, BlockHeight, LocalTimestamp, PROGRESS_WAIT_MULTIPLIER, Round,
    VIEW_CHANGE_DELAY_MULTIPLIER, VIEW_CHANGE_TIMEOUT_DEFAULT, VIEW_CHANGE_TIMEOUT_MAX,
    VIEW_CHANGE_TIMEOUT_MIN,
};

use crate::coordinator::SPECULATIVE_VERIFY_GAP;
use crate::delay::{CommittedSample, DelayEstimator};

/// How far past the verified `high_qc` round a single validator's unverified
/// header or vote may nudge the local view. Anchored to verified progress so a
/// Byzantine peer can't ratchet the view across repeated observations. Held
/// well below the speculative-verification round-gap so a block proposed at the
/// dragged-to round still extends `high_qc` within the window that gets
/// verified and voted — otherwise a flood could park the view at a round where
/// every candidate is gap-skipped and the shard wedges. Larger, quorum-attested
/// advances come from the timeout pacemaker; a node further behind catches up
/// via verified QC adoption and block-sync.
const VIEW_SYNC_GAP: u64 = 256;

// The dragged-to round must stay votable under the speculative-verification
// floor — see both constants' docs.
const _: () = assert!(VIEW_SYNC_GAP <= SPECULATIVE_VERIFY_GAP);

pub struct ViewChangeController {
    /// Current round.
    pub(crate) view: Round,

    /// Round at the start of the current height. Drives the backoff:
    /// `rounds_at_height = view - view_at_height_start`. Reset to `view`
    /// when `committed_height` advances.
    pub(crate) view_at_height_start: Round,

    /// Time of last leader activity (proposal, header receipt, QC, commit).
    /// `None` until the first activity is recorded — prevents spurious view
    /// changes before any leader has had a chance to act.
    pub(crate) last_leader_activity: Option<LocalTimestamp>,

    /// `(height, round)` for which the leader-activity timer was last reset on
    /// header receipt. Ensures a single reset per `(height, round)` so a
    /// Byzantine leader can't spam headers to delay view changes.
    pub(crate) last_header_reset: Option<(BlockHeight, Round)>,

    /// Cumulative count of view changes (round advances due to local
    /// leader-activity timeout). Self-originated only; does not count
    /// rounds we advanced to via `sync_to_qc_round` because some other
    /// validator timed out and we're catching up.
    pub(crate) view_changes: u64,

    /// Cumulative count of view syncs (rounds we jumped to because a
    /// header / vote / QC arrived carrying a higher round than ours).
    /// Distinct from `view_changes`: a node that never times out itself
    /// can still see its `view` climb to thousands if peers keep timing
    /// out and it perpetually catches up. Watching only `view_changes`
    /// hides cluster-wide view-change activity at the slowest validator.
    pub(crate) view_syncs: u64,

    /// Network delay as the committed chain measures it.
    delay: DelayEstimator,
}

impl ViewChangeController {
    /// Start the round clock at `initial_view` — `high_qc.round + 1`, the
    /// round the first block after the recovered (or genesis) QC is proposed
    /// in. Rounds increase per block, so this is the genesis QC's round (0)
    /// plus one on a fresh start.
    pub(crate) const fn new(initial_view: Round) -> Self {
        Self {
            view: initial_view,
            view_at_height_start: initial_view,
            last_leader_activity: None,
            last_header_reset: None,
            view_changes: 0,
            view_syncs: 0,
            delay: DelayEstimator::new(),
        }
    }

    /// Start the round clock as [`Self::new`] does, with the delay estimate
    /// seeded from `recent_headers`: the committed headers just below the
    /// tip, ascending, that the store kept across the restart.
    pub(crate) fn recovered(initial_view: Round, recent_headers: &[BlockHeader]) -> Self {
        let mut controller = Self::new(initial_view);
        for header in recent_headers {
            controller.delay.replay(Self::sample(header));
        }
        controller
    }

    /// Feed a committed header, in chain order, to the delay estimate.
    /// `committee_len` is the size of the committee that certified it.
    pub(crate) fn observe_commit(&mut self, header: &BlockHeader, committee_len: usize) {
        self.delay.observe(Self::sample(header), committee_len);
    }

    fn sample(header: &BlockHeader) -> CommittedSample {
        let parent_qc = header.parent_qc();
        CommittedSample {
            round: header.round(),
            timestamp: header.timestamp(),
            is_fallback: header.is_fallback(),
            parent_qc_round: parent_qc.round(),
            parent_qc_weighted_timestamp: parent_qc.weighted_timestamp(),
        }
    }

    /// The chain-derived delay estimate, once a full rotation has committed.
    pub(crate) fn delay(&self) -> Option<Duration> {
        self.delay.delay()
    }

    /// Record a direct signal of leader progress (proposal, QC, commit).
    pub(crate) const fn record_leader_activity(&mut self, now: LocalTimestamp) {
        self.last_leader_activity = Some(now);
    }

    /// Record leader progress from a received header, rate-limited to once
    /// per `(height, round)` to thwart Byzantine header-spam.
    pub(crate) fn record_header_activity(
        &mut self,
        height: BlockHeight,
        round: Round,
        now: LocalTimestamp,
    ) {
        let key = (height, round);
        if self.last_header_reset != Some(key) {
            self.last_leader_activity = Some(now);
            self.last_header_reset = Some(key);
        }
    }

    /// The round timer's base: `VIEW_CHANGE_DELAY_MULTIPLIER` network delays
    /// as the committed chain measures them, bounded, or the default while
    /// the chain has yet to measure a full rotation.
    pub(crate) fn base_timeout(&self) -> Duration {
        self.delay
            .delay()
            .map_or(VIEW_CHANGE_TIMEOUT_DEFAULT, |delay| {
                (delay * VIEW_CHANGE_DELAY_MULTIPLIER)
                    .clamp(VIEW_CHANGE_TIMEOUT_MIN, VIEW_CHANGE_TIMEOUT_MAX)
            })
    }

    /// View change timeout for the current round: the base doubled per
    /// round already abandoned at this height, capped at
    /// `VIEW_CHANGE_TIMEOUT_MAX`. All validators compute the same timeout:
    /// the base is a function of the committed chain and round numbers are
    /// QC- and header-attested.
    pub(crate) fn current_timeout(&self) -> Duration {
        let rounds_at_height = self
            .view
            .inner()
            .saturating_sub(self.view_at_height_start.inner());
        // Five doublings of the floor already clear the cap.
        let doublings = u32::try_from(rounds_at_height.min(5)).expect("at most five");
        self.base_timeout()
            .saturating_mul(1 << doublings)
            .min(VIEW_CHANGE_TIMEOUT_MAX)
    }

    /// Ceiling on view-change suppression while a proposal is in flight:
    /// `PROGRESS_WAIT_MULTIPLIER` round timer bases.
    pub(crate) fn progress_wait(&self) -> Duration {
        self.base_timeout() * PROGRESS_WAIT_MULTIPLIER
    }

    /// Time remaining until the view change timer should fire.
    pub(crate) fn remaining_timeout(&self, now: LocalTimestamp) -> Duration {
        let timeout = self.current_timeout();
        let deadline = self
            .last_leader_activity
            .unwrap_or(LocalTimestamp::ZERO)
            .plus(timeout);
        if now >= deadline {
            Duration::from_millis(100)
        } else {
            deadline.saturating_sub(now)
        }
    }

    /// Returns `true` if the leader has been silent longer than the current
    /// timeout and a view change should fire.
    pub(crate) fn timeout_elapsed(&self, now: LocalTimestamp) -> bool {
        let Some(last_activity) = self.last_leader_activity else {
            return false;
        };
        now.saturating_sub(last_activity) >= self.current_timeout()
    }

    /// Called when committed height advances: rebase linear-backoff tracking
    /// so the next height starts with a fresh round counter.
    pub(crate) const fn reset_for_height_advance(&mut self) {
        self.view_at_height_start = self.view;
    }

    /// Advance the round one past a verified QC's round, so the next block is
    /// proposed in a fresh round. A QC for round `r` means the chain reached
    /// `r`; the proposer of the successor block moves to `r + 1`. This is what
    /// makes rounds strictly increase per block. Returns `true` if the view
    /// advanced.
    pub(crate) fn advance_on_qc(&mut self, qc_round: Round) -> bool {
        self.sync_to_qc_round(qc_round.next())
    }

    /// Advance the view to `target` because a 2f+1 timeout quorum proved the
    /// round abandoned. Counts as a view change (the pacemaker synchronised the
    /// cluster), and clears the header-reset tracker so the new round accepts a
    /// fresh header-activity reset. Returns `true` if the view advanced.
    pub(crate) fn advance_to(&mut self, target: Round) -> bool {
        if target > self.view {
            self.view = target;
            self.view_changes += 1;
            self.last_header_reset = None;
            true
        } else {
            false
        }
    }

    /// Synchronize the local round to a higher round proven by a verified
    /// quorum certificate. A QC at round R proves 2f+1 validators reached R,
    /// so the target reflects real network progress and is adopted as-is.
    /// Returns `true` if the view was advanced.
    pub(crate) fn sync_to_qc_round(&mut self, qc_round: Round) -> bool {
        if qc_round > self.view {
            self.view = qc_round;
            self.view_syncs += 1;
            true
        } else {
            false
        }
    }

    /// Synchronize the local round to a higher round observed on a single
    /// validator's header or vote. Unlike [`Self::sync_to_qc_round`], the
    /// source is one validator's unverified round claim, so the advance is
    /// capped at `VIEW_SYNC_GAP` beyond `verified_round` — the round of the
    /// highest QC the node has actually verified (`high_qc`). Anchoring the cap
    /// to verified progress, not the current view, bounds the view absolutely:
    /// a Byzantine validator can't escalate it across repeated observations
    /// (each capping relative to the last), only nudge it a bounded gap past
    /// what a quorum has certified. A node further behind than the cap catches
    /// up through verified QC sync as it applies blocks. Returns `true` if the
    /// view was advanced.
    pub(crate) fn sync_to_observed_round(
        &mut self,
        observed_round: Round,
        verified_round: Round,
    ) -> bool {
        let ceiling = Round::new(verified_round.inner().saturating_add(VIEW_SYNC_GAP));
        self.sync_to_qc_round(observed_round.min(ceiling))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{ProposerTimestamp, WeightedTimestamp};

    use super::*;

    /// A controller whose chain has committed a full rotation of `n`
    /// blocks, each measuring `delay_ms` from proposer stamp to quorum vote.
    fn with_delay(delay_ms: u64, n: usize) -> ViewChangeController {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        for i in 1..=u64::try_from(n).unwrap() + 1 {
            vc.delay.observe(
                CommittedSample {
                    round: Round::new(i),
                    timestamp: ProposerTimestamp::from_millis(i * 1_000),
                    is_fallback: false,
                    parent_qc_round: Round::new(i - 1),
                    parent_qc_weighted_timestamp: WeightedTimestamp::from_millis(
                        (i - 1) * 1_000 + delay_ms,
                    ),
                },
                n,
            );
        }
        vc
    }

    #[test]
    fn base_is_the_default_until_a_rotation_has_committed() {
        let vc = ViewChangeController::new(Round::INITIAL);
        assert_eq!(vc.delay(), None);
        assert_eq!(vc.base_timeout(), VIEW_CHANGE_TIMEOUT_DEFAULT);
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT_DEFAULT);
        assert_eq!(
            vc.progress_wait(),
            VIEW_CHANGE_TIMEOUT_DEFAULT * PROGRESS_WAIT_MULTIPLIER
        );
    }

    #[test]
    fn base_is_six_delays_bounded_both_ways() {
        let vc = with_delay(300, 4);
        assert_eq!(vc.delay(), Some(Duration::from_millis(300)));
        assert_eq!(vc.base_timeout(), Duration::from_millis(1_800));
        assert_eq!(vc.progress_wait(), Duration::from_millis(5_400));

        // Faster than the floor allows.
        assert_eq!(with_delay(20, 4).base_timeout(), VIEW_CHANGE_TIMEOUT_MIN);
        // Slower than the cap allows.
        assert_eq!(
            with_delay(60_000, 4).base_timeout(),
            VIEW_CHANGE_TIMEOUT_MAX
        );
    }

    #[test]
    fn current_timeout_doubles_per_round_at_height() {
        let mut vc = with_delay(300, 4);
        let base = Duration::from_millis(1_800);
        assert_eq!(vc.current_timeout(), base);

        vc.view = Round::new(1);
        assert_eq!(vc.current_timeout(), base * 2);

        vc.view = Round::new(3);
        assert_eq!(vc.current_timeout(), base * 8);
    }

    #[test]
    fn current_timeout_respects_cap() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.view = Round::new(10_000);
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT_MAX);

        let mut floored = with_delay(20, 4);
        floored.view = Round::new(10_000);
        assert_eq!(floored.current_timeout(), VIEW_CHANGE_TIMEOUT_MAX);
    }

    #[test]
    fn reset_for_height_advance_rebases_round_counter() {
        let mut vc = ViewChangeController::new(Round::INITIAL);

        vc.view = Round::new(2);
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT_DEFAULT * 4);

        vc.reset_for_height_advance();
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT_DEFAULT);
    }

    #[test]
    fn advance_to_increments_view_and_metric_and_clears_header_reset() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.last_header_reset = Some((BlockHeight::new(5), Round::new(0)));

        assert!(vc.advance_to(Round::new(3)));

        assert_eq!(vc.view, Round::new(3));
        assert_eq!(vc.view_changes, 1);
        assert!(vc.last_header_reset.is_none());

        // A target at or below the current view is a no-op and doesn't tick
        // the counter.
        assert!(!vc.advance_to(Round::new(3)));
        assert_eq!(vc.view, Round::new(3));
        assert_eq!(vc.view_changes, 1);
    }

    #[test]
    fn sync_to_qc_round_only_advances_forward() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.view = Round::new(5);

        assert!(!vc.sync_to_qc_round(Round::new(3)));
        assert_eq!(vc.view, Round::new(5));

        assert!(!vc.sync_to_qc_round(Round::new(5)));
        assert_eq!(vc.view, Round::new(5));

        assert!(vc.sync_to_qc_round(Round::new(10)));
        assert_eq!(vc.view, Round::new(10));
    }

    #[test]
    fn sync_to_observed_round_caps_advance_at_gap_beyond_verified() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        let verified = Round::INITIAL;

        // A far-ahead claim advances the view by at most VIEW_SYNC_GAP beyond
        // verified progress.
        assert!(vc.sync_to_observed_round(Round::new(u64::MAX), verified));
        assert_eq!(vc.view, Round::new(VIEW_SYNC_GAP));

        // With verified progress unchanged, repeated far-ahead claims can't
        // escalate the view further — the cap is anchored to `verified`, not the
        // already-inflated current view. This denies the cross-observation
        // griefing that a per-view cap allowed.
        assert!(!vc.sync_to_observed_round(Round::new(u64::MAX), verified));
        assert_eq!(vc.view, Round::new(VIEW_SYNC_GAP));

        // Once verified progress advances, the ceiling rises and the view may
        // follow another bounded step.
        let verified = Round::new(VIEW_SYNC_GAP);
        assert!(vc.sync_to_observed_round(Round::new(u64::MAX), verified));
        assert_eq!(vc.view, Round::new(2 * VIEW_SYNC_GAP));
    }

    #[test]
    fn sync_to_observed_round_adopts_nearby_round_exactly() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.view = Round::new(10);

        // Within the cap (verified + MAX_ROUND_GAP): adopted verbatim.
        assert!(vc.sync_to_observed_round(Round::new(20), Round::INITIAL));
        assert_eq!(vc.view, Round::new(20));

        // Not ahead: no advance.
        assert!(!vc.sync_to_observed_round(Round::new(15), Round::INITIAL));
        assert_eq!(vc.view, Round::new(20));
    }

    #[test]
    fn record_header_activity_is_rate_limited_per_height_round() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        let t1 = LocalTimestamp::from_millis(1_000);
        let t2 = LocalTimestamp::from_millis(2_000);

        vc.record_header_activity(BlockHeight::new(5), Round::new(0), t1);
        assert_eq!(vc.last_leader_activity, Some(t1));

        // Same (height, round): must not reset again.
        vc.record_header_activity(BlockHeight::new(5), Round::new(0), t2);
        assert_eq!(vc.last_leader_activity, Some(t1));

        // Different round at same height: resets.
        vc.record_header_activity(BlockHeight::new(5), Round::new(1), t2);
        assert_eq!(vc.last_leader_activity, Some(t2));
    }

    #[test]
    fn timeout_elapsed_requires_recorded_leader_activity() {
        let vc = ViewChangeController::new(Round::INITIAL);
        assert!(!vc.timeout_elapsed(LocalTimestamp::from_millis(u64::MAX / 2)));
    }

    #[test]
    fn timeout_elapsed_true_once_past_deadline() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        let activity = LocalTimestamp::from_millis(10_000);
        vc.record_leader_activity(activity);

        let before = activity.plus(
            VIEW_CHANGE_TIMEOUT_DEFAULT
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        let after = activity.plus(VIEW_CHANGE_TIMEOUT_DEFAULT);

        assert!(!vc.timeout_elapsed(before));
        assert!(vc.timeout_elapsed(after));
    }
}
