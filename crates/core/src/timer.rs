//! Timer scheduling abstraction.
//!
//! The state machine emits `Action::SetTimer` and `Action::CancelTimer`.
//! This trait abstracts the runtime side:
//! - Production: `TimerManager` spawns tokio tasks
//! - Simulation: inserts into a deterministic event queue

use crate::input::NodeInput;
use crate::protocol_event::ProtocolEvent;
use std::time::Duration;

/// Timer identification for scheduled events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// View change timeout — one-shot, reset on leader activity.
    ViewChange,
    /// Periodic cleanup timer
    Cleanup,
    /// Global consensus timer (epoch management)
    GlobalConsensus,
    /// Periodic tick for the fetch protocol (retry pending fetches)
    FetchTick,
}

impl TimerId {
    /// Convert this timer ID to the corresponding [`NodeInput`] event.
    #[must_use]
    pub fn into_event(self) -> NodeInput {
        match self {
            TimerId::ViewChange => NodeInput::Protocol(ProtocolEvent::ViewChangeTimer),
            TimerId::Cleanup => NodeInput::Protocol(ProtocolEvent::CleanupTimer),
            TimerId::GlobalConsensus => NodeInput::Protocol(ProtocolEvent::GlobalConsensusTimer),
            TimerId::FetchTick => NodeInput::FetchTick,
        }
    }
}

/// Abstraction for scheduling and cancelling timers.
///
/// Implementations convert timer requests into runtime-specific mechanisms:
/// - [`TimerManager`](hyperscale_production) uses `tokio::spawn` + `tokio::time::sleep`
/// - Simulation inserts into a seeded deterministic event queue
pub trait TimerScheduler {
    /// Schedule a timer to fire after `duration`. Replaces any existing timer with the same `id`.
    fn set_timer(&mut self, id: TimerId, duration: Duration);
    /// Cancel a previously-scheduled timer; no-op if not set.
    fn cancel_timer(&mut self, id: TimerId);
}
