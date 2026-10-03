//! Timer-driven dispatch arms.
//!
//! Two `ProtocolEvent` variants drive the periodic timers: `CleanupTimer`
//! (mempool / shard consensus housekeeping) and `ViewChangeTimer` (leader liveness).
//! Proposal-retry-on-new-content uses the post-dispatch latch on the shard
//! coordinator, not a timer.

use hyperscale_core::{Action, TimerId};
use hyperscale_types::TopologySchedule;
use tracing::instrument;

use super::ShardParticipation;

/// Consecutive cleanup ticks of unchanged committed height before the
/// cross-shard fallback fetches are flushed. At the default one-second cleanup
/// interval this is ~5s — aligned with the per-fallback gossip grace, so it
/// fires only on a genuine stall, not a transient gap between commits.
pub(in crate::state) const STALL_RECOVERY_TICKS: u32 = 5;

/// Cleanup ticks a coasting chain offers its unincluded pool back over
/// before falling silent until dissolution. At the default one-second
/// interval this covers the seating of successors that flip from the
/// terminal cut, which is the common case; the dissolution offer is what
/// covers a successor that takes longer.
const HANDBACK_ATTEMPTS: u32 = 5;

impl ShardParticipation {
    #[instrument(skip(self, sched))]
    pub(in crate::state) fn on_cleanup_timer(&mut self, sched: &TopologySchedule) -> Vec<Action> {
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.shard_coordinator.config().cleanup_interval,
        }];

        // Pending blocks that need fetch requests. Delayed to give gossip
        // and local certificate creation time to fill in missing data first.
        actions.extend(self.shard_coordinator.check_pending_block_fetches(false));

        // Check if we're behind and need to catch up via sync. Handles the
        // case where latest_qc > committed_height — the network progressed
        // but we're stuck.
        actions.extend(self.shard_coordinator.check_sync_health(sched));

        // A proposal fetched for a round the view has passed could no
        // longer be voted on.
        actions.extend(self.shard_coordinator.release_passed_proposal_fetches());

        actions.extend(self.recover_stalled_fallback_fetches(sched));

        // Ask the predecessors about anything still refused for opening
        // before this chain did. Also the only pass that runs when the
        // outstanding set has emptied, which is what releases the last
        // query's slot.
        actions.extend(self.scan_precut_queries());

        actions.extend(self.hand_back_pending_pool(sched));

        // Drop tombstones whose `end_timestamp_exclusive` has passed — past
        // expiry, validator-side validity check rejects re-submission anyway.
        self.mempool_coordinator.cleanup_expired_tombstones();

        // Drop pending-pool entries past their `end_timestamp_exclusive`.
        // The proposer filter already skips them; this sweep keeps the pool
        // from accumulating dead entries when expiry outpaces selection.
        self.mempool_coordinator.cleanup_expired_pending();

        actions
    }

    /// Offer back what this chain admitted and never included, once its
    /// successors are live.
    ///
    /// The terminal sweep drives every *committed* transaction to its
    /// abort, because no later block on this chain can decide one. It
    /// leaves the `Pending` entries alone, and those have nowhere to go:
    /// this chain proposes only empty coast blocks from here, its mempool
    /// dies with it, and a successor constructs an empty one. Without this
    /// the client's last word on such a transaction is the `Pending` it
    /// was given on submission.
    ///
    /// Gated on dissolution rather than quiescence, which is where the
    /// sweep runs. Quiescence is the last block that can decide anything,
    /// but the successors do not exist yet at that point and an offer made
    /// then reaches nothing. Dissolution is the beacon showing them live.
    ///
    /// Driven from the cleanup timer rather than from block commit,
    /// because a dissolved chain has stopped proposing and may commit
    /// nothing further to hang the edge on.
    fn hand_back_pending_pool(&mut self, sched: &TopologySchedule) -> Vec<Action> {
        if self.pending_pool_handed_back || !self.shard_coordinator.quiescent(sched) {
            return Vec::new();
        }
        // Offered from quiescence rather than once at dissolution. The
        // successors seat from the terminal cut, well ahead of the fold
        // that shows them live, so an early offer usually lands — and
        // waiting for that fold leaves a client watching `Pending` for
        // the epoch or two it takes.
        //
        // An offer made before they seat reaches nothing, so a few go out
        // while the chain coasts, and one more when the beacon shows them
        // live, which is the point an offer is certain to have somewhere
        // to go. The repeats cost a duplicate the receiving pool drops.
        let dissolved = self.shard_coordinator.dissolved(sched);
        self.handback_attempts = self.handback_attempts.saturating_add(1);
        self.pending_pool_handed_back = dissolved;
        if !dissolved && self.handback_attempts > HANDBACK_ATTEMPTS {
            return Vec::new();
        }
        let txs = self.mempool_coordinator.pending_for_handback();
        if txs.is_empty() {
            return Vec::new();
        }
        tracing::info!(
            shard = ?self.local_shard,
            count = txs.len(),
            dissolved,
            "Offering back what this chain never included"
        );
        vec![Action::ReofferTransactions { txs }]
    }

    /// Flush the cross-shard fallback fetches when the shard has stalled.
    ///
    /// Headers, provisions, execution certs, and cross-shard txs each fall back
    /// to a peer fetch when their gossip is missing, but those fallbacks are
    /// only swept on block commit — so a shard stuck on the very data a fetch
    /// would recover stops sweeping exactly when it must. Once the committed
    /// height has gone unchanged for [`STALL_RECOVERY_TICKS`] cleanup ticks,
    /// flush all four eagerly. The fetches are idempotent and dedupe in flight,
    /// so flushing while still genuinely waiting is harmless.
    fn recover_stalled_fallback_fetches(&mut self, sched: &TopologySchedule) -> Vec<Action> {
        let height = self.shard_coordinator.committed_height();
        if self.last_cleanup_height == Some(height) {
            self.cleanup_stall_ticks = self.cleanup_stall_ticks.saturating_add(1);
        } else {
            self.cleanup_stall_ticks = 0;
            self.last_cleanup_height = Some(height);
        }
        if self.cleanup_stall_ticks < STALL_RECOVERY_TICKS {
            return Vec::new();
        }

        let mut actions = self
            .remote_headers_coordinator
            .flush_expected_headers(sched);
        actions.extend(self.provisions_coordinator.flush_expected_provisions());
        actions.extend(self.execution_coordinator.flush_expected_certs());
        actions.extend(self.mempool_coordinator.flush_expected_txs());
        actions
    }

    pub(in crate::state) fn on_view_change_timer(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        if let Some(actions) = self.shard_coordinator.check_round_timeout(sched) {
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

    use crate::assert_emits;
    use crate::state::test_support::TestNode;

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
        let expected = node.shard_coordinator().remaining_view_change_timeout();

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

    /// `handle` must feed wall-clock into the beacon coordinator, not
    /// only the shard coordinator. The beacon's epoch-pacing gate
    /// (`committee_start_due` / `duration_until_next_epoch_boundary`)
    /// reads this clock; left at `ZERO` the gate never fires and the
    /// committee-start / skip timers arm against a frozen clock.
    #[test]
    fn handle_advances_beacon_coordinator_clock() {
        let TestNode { mut node, .. } = TestNode::new();
        assert_eq!(node.beacon_coordinator().now(), LocalTimestamp::ZERO);

        let now = LocalTimestamp::from_millis(123_456);
        let _ = node.handle(now, ProtocolEvent::CleanupTimer);

        assert_eq!(
            node.beacon_coordinator().now(),
            now,
            "handle must propagate wall-clock into the beacon coordinator",
        );
    }
}
