//! Timer scheduling abstraction.
//!
//! The state machine emits `Action::SetTimer` and `Action::CancelTimer`.
//! This trait abstracts the runtime side:
//! - Production: `ProdTimerManager` spawns tokio tasks
//! - Simulation: inserts into a deterministic event queue
//!
//! Shard-scoped timers (`ViewChange`, `Cleanup`) carry the emitting
//! vnode's shard at queue time so the firing event routes to the right
//! hosted shard under cross-shard hosting. Process-scoped timers
//! (`FetchTick`) ignore the shard argument when firing.

use std::time::Duration;

use hyperscale_types::ShardGroupId;

use crate::input::NodeInput;
use crate::protocol_event::ProtocolEvent;

/// Timer identification for scheduled events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// View change timeout — one-shot, reset on leader activity.
    /// Shard-scoped.
    ViewChange,
    /// Periodic cleanup timer. Shard-scoped.
    Cleanup,
    /// Periodic tick for the fetch protocol (retry pending fetches).
    /// Process-scoped — fans out across all hosted shards on fire.
    FetchTick,
}

impl TimerId {
    /// Convert this timer ID to the corresponding [`NodeInput`] event.
    /// `shard` is the emitting vnode's shard for shard-scoped timers
    /// and is ignored for `FetchTick`.
    #[must_use]
    pub fn into_event(self, shard: ShardGroupId) -> NodeInput {
        match self {
            Self::ViewChange => NodeInput::protocol(shard, ProtocolEvent::ViewChangeTimer),
            Self::Cleanup => NodeInput::protocol(shard, ProtocolEvent::CleanupTimer),
            Self::FetchTick => NodeInput::FetchTick,
        }
    }
}

/// Abstraction for scheduling and cancelling timers.
///
/// Implementations convert timer requests into runtime-specific mechanisms:
/// - `ProdTimerManager` (in `hyperscale_production`) uses `tokio::spawn` + `tokio::time::sleep`
/// - Simulation inserts into a seeded deterministic event queue
pub trait TimerScheduler {
    /// Schedule a timer to fire after `duration`. Replaces any existing timer with the same `id`.
    fn set_timer(&mut self, id: TimerId, duration: Duration);
    /// Cancel a previously-scheduled timer; no-op if not set.
    fn cancel_timer(&mut self, id: TimerId);
}
