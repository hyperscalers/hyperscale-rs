//! Timer-driven dispatch arms.
//!
//! Two `ProtocolEvent` variants drive the periodic timers: `CleanupTimer`
//! (mempool / shard consensus housekeeping) and `ViewChangeTimer` (leader liveness).
//! Proposal-retry-on-new-content uses the post-dispatch latch on the shard
//! coordinator, not a timer.

use hyperscale_core::{Action, TimerId};
use tracing::instrument;

use super::NodeStateMachine;

impl NodeStateMachine {
    #[instrument(skip(self))]
    pub(super) fn on_cleanup_timer(&mut self) -> Vec<Action> {
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.shard_coordinator.config().cleanup_interval,
        }];

        // Pending blocks that need fetch requests. Delayed to give gossip
        // and local certificate creation time to fill in missing data first.
        actions.extend(
            self.shard_coordinator
                .check_pending_block_fetches(&self.topology_snapshot, false),
        );

        // Check if we're behind and need to catch up via sync. Handles the
        // case where latest_qc > committed_height — the network progressed
        // but we're stuck.
        actions.extend(
            self.shard_coordinator
                .check_sync_health(&self.topology_snapshot),
        );

        // Drop tombstones whose `end_timestamp_exclusive` has passed — past
        // expiry, validator-side validity check rejects re-submission anyway.
        self.mempool_coordinator.cleanup_expired_tombstones();

        // Drop pending-pool entries past their `end_timestamp_exclusive`.
        // The proposer filter already skips them; this sweep keeps the pool
        // from accumulating dead entries when expiry outpaces selection.
        self.mempool_coordinator.cleanup_expired_pending();

        actions
    }

    pub(super) fn on_view_change_timer(&mut self) -> Vec<Action> {
        if let Some(actions) = self
            .shard_coordinator
            .check_round_timeout(&self.topology_snapshot)
        {
            actions
        } else {
            // Conditions not met yet. Reschedule for the remaining time
            // until the actual timeout fires (relative to last_leader_activity).
            let remaining = self.shard_coordinator.remaining_view_change_timeout();
            vec![Action::SetTimer {
                id: TimerId::ViewChange,
                duration: remaining,
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
    use hyperscale_types::LocalTimestamp;

    use super::super::test_support::TestNode;
    use crate::assert_emits;

    /// `CleanupTimer` is the only thing keeping its own loop alive — it
    /// must reschedule itself before doing anything else, so a missed
    /// reschedule silently halts mempool / shard consensus housekeeping.
    #[test]
    fn cleanup_timer_reschedules_itself() {
        let TestNode { mut node, .. } = TestNode::new();

        let actions = node.handle(LocalTimestamp::ZERO, ProtocolEvent::CleanupTimer);

        assert!(
            matches!(
                actions.first(),
                Some(Action::SetTimer {
                    id: TimerId::Cleanup,
                    ..
                })
            ),
            "CleanupTimer must lead with its own reschedule; got {actions:?}",
        );
    }

    /// `ViewChangeTimer` reschedules itself with the shard coordinator's
    /// reported remaining timeout when no view change is needed yet.
    /// On a freshly-built node, `check_round_timeout` returns `None`, so
    /// we exercise the reschedule branch.
    #[test]
    fn view_change_timer_reschedules_with_remaining_timeout() {
        let TestNode { mut node, .. } = TestNode::new();
        let expected = node.shard_coordinator.remaining_view_change_timeout();

        let actions = node.handle(LocalTimestamp::ZERO, ProtocolEvent::ViewChangeTimer);

        assert_eq!(
            actions.len(),
            1,
            "expected single reschedule; got {actions:?}"
        );
        assert_emits!(
            actions,
            Action::SetTimer {
                id: TimerId::ViewChange,
                duration,
            } if *duration == expected
        );
    }
}
