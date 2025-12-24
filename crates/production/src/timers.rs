//! Timer management for production runner.
//!
//! Provides tokio-based timer implementation for the deterministic state machine.
//! Timers are spawned as tokio tasks and can be cancelled.

use hyperscale_core::{Event, TimerId};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace};

/// Convert a TimerId to the corresponding Event.
fn timer_event(id: TimerId) -> Event {
    match id {
        TimerId::Proposal => Event::ProposalTimer,
        TimerId::Cleanup => Event::CleanupTimer,
        TimerId::GlobalConsensus => Event::GlobalConsensusTimer,
    }
}

/// Manages timers for the production runner.
///
/// Each timer is a tokio task that sleeps for the specified duration and then
/// sends the appropriate timer event to the event channel.
pub struct TimerManager {
    /// Active timers (id -> task handle).
    timers: HashMap<TimerId, JoinHandle<()>>,
    /// Event sender for timer fires.
    event_tx: mpsc::Sender<Event>,
}

impl TimerManager {
    /// Create a new timer manager.
    pub fn new(event_tx: mpsc::Sender<Event>) -> Self {
        Self {
            timers: HashMap::new(),
            event_tx,
        }
    }

    /// Set a timer that will fire after the given duration.
    ///
    /// If a timer with the same ID already exists, it is cancelled first.
    pub fn set_timer(&mut self, id: TimerId, duration: Duration) {
        // Cancel existing timer with same ID
        self.cancel_timer(id.clone());

        let event_tx = self.event_tx.clone();
        let timer_id = id.clone();
        let timer_id_for_log = id.clone();

        let handle = tokio::spawn(async move {
            tracing::trace!(?timer_id, ?duration, "Timer task started, sleeping");
            tokio::time::sleep(duration).await;
            tracing::trace!(?timer_id, "Timer fired, sending event");
            let event = timer_event(timer_id);
            if event_tx.send(event).await.is_err() {
                // Timer ID was moved into event, use separate clone for debug
            }
        });

        self.timers.insert(id, handle);
        debug!(id = ?timer_id_for_log, ?duration, "Timer set");
    }

    /// Cancel a timer.
    ///
    /// If the timer doesn't exist or has already fired, this is a no-op.
    pub fn cancel_timer(&mut self, id: TimerId) {
        if let Some(handle) = self.timers.remove(&id) {
            handle.abort();
            debug!(?id, "Timer cancelled");
        }
    }

    /// Cancel all timers.
    ///
    /// Called during shutdown.
    pub fn cancel_all(&mut self) {
        for (id, handle) in self.timers.drain() {
            handle.abort();
            trace!(?id, "Timer cancelled (shutdown)");
        }
    }

    /// Get the number of active timers.
    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.timers.len()
    }
}

impl Drop for TimerManager {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_timer_fires() {
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let mut manager = TimerManager::new(event_tx);

        let id = TimerId::Proposal;
        manager.set_timer(id, Duration::from_millis(10));

        // Wait for timer to fire
        let event = tokio::time::timeout(Duration::from_millis(100), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert!(matches!(event, Event::ProposalTimer));
    }

    #[tokio::test]
    async fn test_timer_cancel() {
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let mut manager = TimerManager::new(event_tx);

        let id = TimerId::Proposal;
        manager.set_timer(id.clone(), Duration::from_millis(50));
        manager.cancel_timer(id);

        // Timer should not fire
        let result = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await;
        assert!(result.is_err(), "Timer should have been cancelled");
    }

    #[tokio::test]
    async fn test_timer_replace() {
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let mut manager = TimerManager::new(event_tx);

        let id = TimerId::Proposal;

        // Set timer for 100ms
        manager.set_timer(id.clone(), Duration::from_millis(100));

        // Replace with 10ms timer
        manager.set_timer(id, Duration::from_millis(10));

        // Should fire quickly (the 10ms timer)
        let event = tokio::time::timeout(Duration::from_millis(50), event_rx.recv())
            .await
            .expect("timeout - timer didn't fire quickly")
            .expect("channel closed");

        assert!(matches!(event, Event::ProposalTimer));
    }

    #[tokio::test]
    async fn test_multiple_timers() {
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let mut manager = TimerManager::new(event_tx);

        manager.set_timer(TimerId::Proposal, Duration::from_millis(10));
        manager.set_timer(TimerId::Cleanup, Duration::from_millis(20));

        assert_eq!(manager.active_count(), 2);

        // First timer fires
        let event1 = tokio::time::timeout(Duration::from_millis(50), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        // Second timer fires
        let event2 = tokio::time::timeout(Duration::from_millis(50), event_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        // Both should be timer events (Proposal and Cleanup in some order)
        let is_proposal = matches!(event1, Event::ProposalTimer);
        let is_cleanup = matches!(event1, Event::CleanupTimer);
        assert!(is_proposal || is_cleanup);

        let is_proposal2 = matches!(event2, Event::ProposalTimer);
        let is_cleanup2 = matches!(event2, Event::CleanupTimer);
        assert!(is_proposal2 || is_cleanup2);
    }

    #[tokio::test]
    async fn test_cancel_all() {
        let (event_tx, mut event_rx) = mpsc::channel(10);
        let mut manager = TimerManager::new(event_tx);

        manager.set_timer(TimerId::Proposal, Duration::from_millis(50));
        manager.set_timer(TimerId::Cleanup, Duration::from_millis(50));

        assert_eq!(manager.active_count(), 2);

        manager.cancel_all();

        assert_eq!(manager.active_count(), 0);

        // No timers should fire
        let result = tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await;
        assert!(result.is_err(), "No timers should have fired");
    }
}
