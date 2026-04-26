//! View change liveness state: current round, linear-backoff tracking, and
//! leader-activity timestamps.
//!
//! HotStuff-2 uses implicit view changes: each validator advances its round
//! locally on timeout, no coordinated TC message required. The controller
//! owns the local round clock and the signals that determine when the
//! timeout fires:
//!
//! - `view` — current round.
//! - `view_at_height_start` — round when the current height began; drives
//!   linear backoff (timeout grows with rounds attempted at the height).
//! - `last_leader_activity` — any signal from the leader (proposal, header,
//!   QC, commit) resets the timeout.
//! - `last_header_reset` — rate-limits `record_header_activity` to once per
//!   `(height, round)` so a Byzantine leader can't spam different headers to
//!   delay view changes indefinitely.

use crate::config::BftConfig;
use hyperscale_types::{BlockHeight, LocalTimestamp, Round};
use std::time::Duration;

pub(crate) struct ViewChangeController {
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
    pub fn new() -> Self {
        Self {
            view: Round::INITIAL,
            view_at_height_start: Round::INITIAL,
            last_leader_activity: None,
            last_header_reset: None,
            view_changes: 0,
            view_syncs: 0,
        }
    }

    /// Record a direct signal of leader progress (proposal, QC, commit).
    pub fn record_leader_activity(&mut self, now: LocalTimestamp) {
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
    /// `timeout = min(base + increment * rounds_at_height, max_cap)`. All
    /// validators compute the same timeout because round numbers are QC- and
    /// header-attested, so the formula is deterministic network-wide.
    pub fn current_timeout(&self, config: &BftConfig) -> Duration {
        let rounds_at_height = self.view.0.saturating_sub(self.view_at_height_start.0);
        let rounds_factor = u32::try_from(rounds_at_height).unwrap_or(u32::MAX);
        let timeout =
            config.view_change_timeout + config.view_change_timeout_increment * rounds_factor;
        match config.view_change_timeout_max {
            Some(max) => timeout.min(max),
            None => timeout,
        }
    }

    /// Time remaining until the view change timer should fire.
    pub fn remaining_timeout(&self, config: &BftConfig, now: LocalTimestamp) -> Duration {
        let timeout = self.current_timeout(config);
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
    pub fn timeout_elapsed(&self, config: &BftConfig, now: LocalTimestamp) -> bool {
        let Some(last_activity) = self.last_leader_activity else {
            return false;
        };
        now.saturating_sub(last_activity) >= self.current_timeout(config)
    }

    /// Called when committed height advances: rebase linear-backoff tracking
    /// so the next height starts with a fresh round counter.
    pub fn reset_for_height_advance(&mut self) {
        self.view_at_height_start = self.view;
    }

    /// Advance to the next round (implicit view change). Increments the
    /// counter and clears the header-reset tracker (a fresh round is allowed
    /// to accept one header-activity reset). Returns the new round.
    pub fn advance(&mut self) -> Round {
        self.view += 1;
        self.view_changes += 1;
        self.last_header_reset = None;
        self.view
    }

    /// Synchronize the local round to a higher round seen on a QC, header,
    /// or vote. Keeps us from falling behind the rest of the network after
    /// a partition or when peers are timing out faster than we are.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(base_ms: u64, inc_ms: u64, cap_ms: Option<u64>) -> BftConfig {
        BftConfig {
            view_change_timeout: Duration::from_millis(base_ms),
            view_change_timeout_increment: Duration::from_millis(inc_ms),
            view_change_timeout_max: cap_ms.map(Duration::from_millis),
            ..BftConfig::default()
        }
    }

    #[test]
    fn current_timeout_grows_linearly_with_rounds_at_height() {
        let mut vc = ViewChangeController::new();
        let config = cfg(1000, 500, None);

        assert_eq!(vc.current_timeout(&config), Duration::from_secs(1));

        vc.view = Round(1);
        assert_eq!(vc.current_timeout(&config), Duration::from_millis(1500));

        vc.view = Round(4);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(3));
    }

    #[test]
    fn current_timeout_respects_cap() {
        let mut vc = ViewChangeController::new();
        let config = cfg(1000, 500, Some(2000));

        vc.view = Round(10);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(2));
    }

    #[test]
    fn reset_for_height_advance_rebases_round_counter() {
        let mut vc = ViewChangeController::new();
        let config = cfg(1000, 500, None);

        vc.view = Round(5);
        assert_eq!(vc.current_timeout(&config), Duration::from_millis(3500));

        vc.reset_for_height_advance();
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(1));
    }

    #[test]
    fn advance_increments_view_and_metric_and_clears_header_reset() {
        let mut vc = ViewChangeController::new();
        vc.last_header_reset = Some((BlockHeight(5), Round(0)));

        let new_round = vc.advance();

        assert_eq!(new_round, Round(1));
        assert_eq!(vc.view, Round(1));
        assert_eq!(vc.view_changes, 1);
        assert!(vc.last_header_reset.is_none());
    }

    #[test]
    fn sync_to_qc_round_only_advances_forward() {
        let mut vc = ViewChangeController::new();
        vc.view = Round(5);

        assert!(!vc.sync_to_qc_round(Round(3)));
        assert_eq!(vc.view, Round(5));

        assert!(!vc.sync_to_qc_round(Round(5)));
        assert_eq!(vc.view, Round(5));

        assert!(vc.sync_to_qc_round(Round(10)));
        assert_eq!(vc.view, Round(10));
    }

    #[test]
    fn record_header_activity_is_rate_limited_per_height_round() {
        let mut vc = ViewChangeController::new();
        let t1 = LocalTimestamp::from_millis(1_000);
        let t2 = LocalTimestamp::from_millis(2_000);

        vc.record_header_activity(BlockHeight(5), Round(0), t1);
        assert_eq!(vc.last_leader_activity, Some(t1));

        // Same (height, round): must not reset again.
        vc.record_header_activity(BlockHeight(5), Round(0), t2);
        assert_eq!(vc.last_leader_activity, Some(t1));

        // Different round at same height: resets.
        vc.record_header_activity(BlockHeight(5), Round(1), t2);
        assert_eq!(vc.last_leader_activity, Some(t2));
    }

    #[test]
    fn timeout_elapsed_requires_recorded_leader_activity() {
        let vc = ViewChangeController::new();
        let config = cfg(1000, 0, None);
        assert!(!vc.timeout_elapsed(&config, LocalTimestamp::from_millis(100_000)));
    }

    #[test]
    fn timeout_elapsed_true_once_past_deadline() {
        let mut vc = ViewChangeController::new();
        let config = cfg(1000, 0, None);
        vc.record_leader_activity(LocalTimestamp::from_millis(10_000));

        assert!(!vc.timeout_elapsed(&config, LocalTimestamp::from_millis(10_500)));
        assert!(vc.timeout_elapsed(&config, LocalTimestamp::from_millis(11_000)));
    }

    #[test]
    fn zero_increment_disables_backoff() {
        let mut vc = ViewChangeController::new();
        let config = cfg(5000, 0, None);

        assert_eq!(vc.current_timeout(&config), Duration::from_secs(5));

        vc.view = Round(10);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(5));

        vc.view = Round(100);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(5));
    }

    #[test]
    fn no_cap_allows_unbounded_backoff() {
        let mut vc = ViewChangeController::new();
        let config = cfg(5000, 1000, None);

        vc.view = Round(100);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(5 + 100));

        vc.view = Round(1000);
        assert_eq!(vc.current_timeout(&config), Duration::from_secs(5 + 1000));
    }
}
