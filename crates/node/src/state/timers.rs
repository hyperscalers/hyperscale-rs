//! Timer-driven dispatch arms.
//!
//! Three `ProtocolEvent` variants drive the periodic and event-driven timers:
//! `CleanupTimer` (mempool / BFT housekeeping), `ViewChangeTimer` (leader
//! liveness), and `ContentAvailable` (re-trigger proposal building once new
//! content lands).

use super::NodeStateMachine;
use hyperscale_core::{Action, TimerId};
use tracing::instrument;

impl NodeStateMachine {
    #[instrument(skip(self))]
    pub(super) fn on_cleanup_timer(&mut self) -> Vec<Action> {
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.bft.config().cleanup_interval,
        }];

        // Pending blocks that need fetch requests. Delayed to give gossip
        // and local certificate creation time to fill in missing data first.
        actions.extend(
            self.bft
                .check_pending_block_fetches(self.topology.snapshot(), false),
        );

        // Check if we're behind and need to catch up via sync. Handles the
        // case where latest_qc > committed_height — the network progressed
        // but we're stuck.
        actions.extend(self.bft.check_sync_health(self.topology.snapshot()));

        // Drop tombstones whose `end_timestamp_exclusive` has passed — past
        // expiry, validator-side validity check rejects re-submission anyway.
        self.mempool.cleanup_expired_tombstones();

        // Drop pending-pool entries past their `end_timestamp_exclusive`.
        // The proposer filter already skips them; this sweep keeps the pool
        // from accumulating dead entries when expiry outpaces selection.
        self.mempool.cleanup_expired_pending();

        actions
    }

    pub(super) fn on_view_change_timer(&mut self) -> Vec<Action> {
        if let Some(actions) = self.bft.check_round_timeout(self.topology.snapshot()) {
            actions
        } else {
            // Conditions not met yet. Reschedule for the remaining time
            // until the actual timeout fires (relative to last_leader_activity).
            let remaining = self.bft.remaining_view_change_timeout();
            vec![Action::SetTimer {
                id: TimerId::ViewChange,
                duration: remaining,
            }]
        }
    }
}
