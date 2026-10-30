//! A merge keeper's collect of one terminating child's span.

use hyperscale_types::network::request::GetStateRangeRequest;
use hyperscale_types::network::response::GetStateRangeResponse;
use hyperscale_types::{ShardAnchor, ShardId, shard_prefix_path};

use super::snap_sync::{SnapSync, StateRangeOutcome};
use super::{SPLIT_BITS, STATE_CHUNK_LIMIT};

/// Assembles a terminating child's committed state into the reformed
/// parent's store, verified against the child's `anchor`. State only: the
/// reformed parent's witness domain starts fresh and its chain has no
/// history below the anchor, so there is no window to fetch and nothing to
/// walk. The union finalize is the keeper's, at the parent's genesis height,
/// so the collect ends once every sub-range is staged.
pub struct SpanCollect {
    snap: SnapSync,
    staged: bool,
}

impl SpanCollect {
    pub fn new(child: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            snap: SnapSync::new(
                anchor,
                shard_prefix_path(child),
                SPLIT_BITS,
                STATE_CHUNK_LIMIT,
            ),
            staged: false,
        }
    }

    /// A request for every idle sub-range, as `(sub_range, request)`.
    pub fn next_requests(&mut self) -> Vec<(usize, GetStateRangeRequest)> {
        if self.staged {
            return Vec::new();
        }
        self.snap.next_requests()
    }

    /// Feed one state range response for `sub_range`. A staged outcome
    /// must be persisted by the driver before it pumps further responses.
    pub fn on_state_range(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> StateRangeOutcome {
        if self.staged {
            return StateRangeOutcome::Rejected("state response after the span staged");
        }
        let outcome = self.snap.on_response(sub_range, response);
        if matches!(outcome, StateRangeOutcome::Staged { .. }) && self.snap.is_complete() {
            self.staged = true;
        }
        outcome
    }

    /// Re-arm a state sub-range after a transport-level failure.
    pub fn on_state_range_failure(&mut self, sub_range: usize) {
        if !self.staged {
            self.snap.on_failure(sub_range);
        }
    }

    /// Whether every sub-range is staged.
    pub const fn is_staged(&self) -> bool {
        self.staged
    }
}
