//! Timer scheduling abstraction.
//!
//! The state machine emits `Action::SetTimer` and `Action::CancelTimer`.
//! This trait abstracts the runtime side:
//! - Production: `TimerManager` spawns tokio tasks
//! - Simulation: inserts into a deterministic event queue

use crate::TimerId;
use std::time::Duration;

/// Abstraction for scheduling and cancelling timers.
///
/// Implementations convert timer requests into runtime-specific mechanisms:
/// - [`TimerManager`](hyperscale_production) uses `tokio::spawn` + `tokio::time::sleep`
/// - Simulation inserts into a seeded deterministic event queue
pub trait TimerScheduler {
    fn set_timer(&mut self, id: TimerId, duration: Duration);
    fn cancel_timer(&mut self, id: TimerId);
}
