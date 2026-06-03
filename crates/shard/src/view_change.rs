//! View change liveness state: current round, linear-backoff tracking, and
//! leader-activity timestamps.
//!
//! When its round timer fires a validator broadcasts a `Timeout` (the
//! coordinator's pacemaker); the round advances only on a 2f+1 timeout quorum,
//! or by syncing forward to a verified QC's round. This controller owns the
//! local round clock and the signals that decide when that timer fires:
//!
//! - `view` — current round.
//! - `view_at_height_start` — round when the current height began; drives
//!   linear backoff (timeout grows with rounds attempted at the height).
//! - `last_leader_activity` — any signal from the leader (proposal, header,
//!   QC, commit) resets the timeout.
//! - `last_header_reset` — rate-limits `record_header_activity` to once per
//!   `(height, round)` so a Byzantine leader can't spam different headers to
//!   delay view changes indefinitely.

use std::time::Duration;

use hyperscale_types::{
    BlockHeight, LocalTimestamp, MAX_ROUND_GAP, Round, VIEW_CHANGE_TIMEOUT,
    VIEW_CHANGE_TIMEOUT_INCREMENT, VIEW_CHANGE_TIMEOUT_MAX,
};

pub struct ViewChangeController {
    /// Current round.
    pub(crate) view: Round,

    /// Round at the start of the current height. Used by the linear-backoff
    /// timeout formula: `rounds_at_height = view - view_at_height_start`.
    /// Reset to `view` when `committed_height` advances.
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
}

impl ViewChangeController {
    /// Start the round clock at `initial_view` — `high_qc.round + 1`, the
    /// round the first block after the recovered (or genesis) QC is proposed
    /// in. Rounds increase per block, so this is the genesis QC's round (0)
    /// plus one on a fresh start.
    pub const fn new(initial_view: Round) -> Self {
        Self {
            view: initial_view,
            view_at_height_start: initial_view,
            last_leader_activity: None,
            last_header_reset: None,
            view_changes: 0,
            view_syncs: 0,
        }
    }

    /// Record a direct signal of leader progress (proposal, QC, commit).
    pub const fn record_leader_activity(&mut self, now: LocalTimestamp) {
        self.last_leader_activity = Some(now);
    }

    /// Record leader progress from a received header, rate-limited to once
    /// per `(height, round)` to thwart Byzantine header-spam.
    pub fn record_header_activity(
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

    /// Linear-backoff view change timeout for the current round.
    ///
    /// `timeout = min(VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT *
    /// rounds_at_height, VIEW_CHANGE_TIMEOUT_MAX)`. All validators compute
    /// the same timeout because round numbers are QC- and header-attested,
    /// so the formula is deterministic network-wide.
    pub fn current_timeout(&self) -> Duration {
        let rounds_at_height = self
            .view
            .inner()
            .saturating_sub(self.view_at_height_start.inner());
        let rounds_factor = u32::try_from(rounds_at_height).unwrap_or(u32::MAX);
        let timeout = VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT * rounds_factor;
        timeout.min(VIEW_CHANGE_TIMEOUT_MAX)
    }

    /// Time remaining until the view change timer should fire.
    pub fn remaining_timeout(&self, now: LocalTimestamp) -> Duration {
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
    pub fn timeout_elapsed(&self, now: LocalTimestamp) -> bool {
        let Some(last_activity) = self.last_leader_activity else {
            return false;
        };
        now.saturating_sub(last_activity) >= self.current_timeout()
    }

    /// Called when committed height advances: rebase linear-backoff tracking
    /// so the next height starts with a fresh round counter.
    pub const fn reset_for_height_advance(&mut self) {
        self.view_at_height_start = self.view;
    }

    /// Advance the round one past a verified QC's round, so the next block is
    /// proposed in a fresh round. A QC for round `r` means the chain reached
    /// `r`; the proposer of the successor block moves to `r + 1`. This is what
    /// makes rounds strictly increase per block. Returns `true` if the view
    /// advanced.
    pub fn advance_on_qc(&mut self, qc_round: Round) -> bool {
        self.sync_to_qc_round(qc_round.next())
    }

    /// Advance the view to `target` because a 2f+1 timeout quorum proved the
    /// round abandoned. Counts as a view change (the pacemaker synchronised the
    /// cluster), and clears the header-reset tracker so the new round accepts a
    /// fresh header-activity reset. Returns `true` if the view advanced.
    pub fn advance_to(&mut self, target: Round) -> bool {
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
    pub fn sync_to_qc_round(&mut self, qc_round: Round) -> bool {
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
    /// capped at `MAX_ROUND_GAP` beyond the current view. This lets a lagging
    /// node converge a bounded amount per observation while denying a
    /// Byzantine validator the ability to fling the view toward `Round`'s
    /// overflow boundary, where the next [`Self::advance`] would panic. A node
    /// further behind than the cap catches up through verified QC sync as it
    /// applies blocks. Returns `true` if the view was advanced.
    pub fn sync_to_observed_round(&mut self, observed_round: Round) -> bool {
        let ceiling = Round::new(self.view.inner().saturating_add(MAX_ROUND_GAP));
        self.sync_to_qc_round(observed_round.min(ceiling))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_timeout_grows_linearly_with_rounds_at_height() {
        let mut vc = ViewChangeController::new(Round::INITIAL);

        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT);

        vc.view = Round::new(1);
        assert_eq!(
            vc.current_timeout(),
            VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT
        );

        vc.view = Round::new(4);
        assert_eq!(
            vc.current_timeout(),
            VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT * 4
        );
    }

    #[test]
    fn current_timeout_respects_cap() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.view = Round::new(10_000);
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT_MAX);
    }

    #[test]
    fn reset_for_height_advance_rebases_round_counter() {
        let mut vc = ViewChangeController::new(Round::INITIAL);

        vc.view = Round::new(5);
        assert_eq!(
            vc.current_timeout(),
            VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT * 5
        );

        vc.reset_for_height_advance();
        assert_eq!(vc.current_timeout(), VIEW_CHANGE_TIMEOUT);
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
    fn sync_to_observed_round_caps_advance_at_max_gap() {
        let mut vc = ViewChangeController::new(Round::INITIAL);

        // A far-ahead claim advances the view by at most MAX_ROUND_GAP.
        assert!(vc.sync_to_observed_round(Round::new(u64::MAX)));
        assert_eq!(vc.view, Round::new(MAX_ROUND_GAP));

        // A second far-ahead claim advances by another bounded step, so the
        // view can never be flung to Round's overflow boundary in one message.
        assert!(vc.sync_to_observed_round(Round::new(u64::MAX)));
        assert_eq!(vc.view, Round::new(2 * MAX_ROUND_GAP));
    }

    #[test]
    fn sync_to_observed_round_adopts_nearby_round_exactly() {
        let mut vc = ViewChangeController::new(Round::INITIAL);
        vc.view = Round::new(10);

        // Within the cap: adopted verbatim.
        assert!(vc.sync_to_observed_round(Round::new(20)));
        assert_eq!(vc.view, Round::new(20));

        // Not ahead: no advance.
        assert!(!vc.sync_to_observed_round(Round::new(15)));
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
            VIEW_CHANGE_TIMEOUT
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        );
        let after = activity.plus(VIEW_CHANGE_TIMEOUT);

        assert!(!vc.timeout_elapsed(before));
        assert!(vc.timeout_elapsed(after));
    }
}
