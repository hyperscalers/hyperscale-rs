//! The reconnection backoff every transport holds per peer stream: how long
//! a stream that just failed stays closed to new attempts.
//!
//! Sans-IO, like [`retry`](crate::retry). Time is whatever instant type the
//! transport's clock produces, so the production transport keys it on
//! `Instant` and the simulator on its simulated `Duration`. The transport
//! owns the map, escalates an entry when a stream fails, and removes it when
//! a stream is next established.
//!
//! Two series: a transient failure (a timeout, a reset, a failed open)
//! starts at [`INITIAL_BACKOFF`] and doubles to [`MAX_BACKOFF`]; a peer that
//! answers that it does not serve the protocol starts at
//! [`UNSUPPORTED_INITIAL_BACKOFF`] and doubles to [`UNSUPPORTED_MAX_BACKOFF`].
//! A failure of the other class re-enters its own series from wherever the
//! previous one left off, clamped to its bounds.

use std::ops::{Add, Sub};
use std::time::Duration;

/// Initial reconnection backoff after the first stream failure.
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum reconnection backoff (cap for the geometric series).
pub const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Multiplier applied on each consecutive failure.
pub const BACKOFF_MULTIPLIER: u32 = 2;

/// Initial backoff after a peer answers that it does not serve the requested
/// protocol.
///
/// Starts near [`MAX_BACKOFF`] so a seating race — probing a peer moments
/// before a reshape registers a fresh shard's handler — recovers in seconds.
pub const UNSUPPORTED_INITIAL_BACKOFF: Duration = Duration::from_secs(5);

/// Backoff cap once a peer keeps answering "protocol unsupported".
///
/// A peer's protocol table only changes when a reshape seats or unseats a
/// vnode — an epoch-scale event — so a requester chasing a drained shard
/// converges to one probe a minute instead of hammering every peer at
/// [`MAX_BACKOFF`] cadence for the whole retention window.
pub const UNSUPPORTED_MAX_BACKOFF: Duration = Duration::from_mins(1);

/// Why a stream failed, which picks the series its backoff escalates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFailure {
    /// A timeout, a reset, or an open that failed for any reason other than
    /// the peer refusing the protocol.
    Transient,
    /// The peer answered that it does not serve the protocol.
    Unsupported,
}

/// One stream's backoff: when it may next be attempted, and the step of the
/// series that scheduled it.
///
/// Stays in the transport's map after it lapses, so the next failure
/// escalates from it, until a stream is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamBackoff<T> {
    next_attempt: T,
    current: Duration,
}

impl<T: Copy + Ord + Add<Duration, Output = T> + Sub<Output = Duration>> StreamBackoff<T> {
    /// The backoff a stream holds after `failure` at `now`, escalating from
    /// `previous` when the stream already held one.
    #[must_use]
    pub fn after(previous: Option<&Self>, failure: StreamFailure, now: T) -> Self {
        let (initial, max) = match failure {
            StreamFailure::Transient => (INITIAL_BACKOFF, MAX_BACKOFF),
            StreamFailure::Unsupported => (UNSUPPORTED_INITIAL_BACKOFF, UNSUPPORTED_MAX_BACKOFF),
        };
        let current = previous.map_or(initial, |state| {
            (state.current * BACKOFF_MULTIPLIER).clamp(initial, max)
        });
        Self {
            next_attempt: now + current,
            current,
        }
    }

    /// How much longer the stream stays closed to attempts at `now`;
    /// `None` once it is open again.
    #[must_use]
    pub fn held_for(&self, now: T) -> Option<Duration> {
        (now < self.next_attempt).then(|| self.next_attempt - now)
    }

    /// When the stream may next be attempted.
    #[must_use]
    pub const fn next_attempt(&self) -> T {
        self.next_attempt
    }

    /// The step of the series that scheduled [`Self::next_attempt`].
    #[must_use]
    pub const fn current(&self) -> Duration {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Duration = Duration::from_secs(100);

    fn walk(failures: &[StreamFailure]) -> Option<StreamBackoff<Duration>> {
        failures.iter().fold(None, |previous, &failure| {
            Some(StreamBackoff::after(previous.as_ref(), failure, NOW))
        })
    }

    #[test]
    fn the_first_failure_holds_the_stream_for_the_initial_backoff() {
        let state = walk(&[StreamFailure::Transient]).unwrap();
        assert_eq!(state.current(), INITIAL_BACKOFF);
        assert_eq!(state.next_attempt(), NOW + INITIAL_BACKOFF);
        assert_eq!(
            state.held_for(NOW + INITIAL_BACKOFF / 4),
            Some(INITIAL_BACKOFF * 3 / 4)
        );
        assert_eq!(state.held_for(NOW + INITIAL_BACKOFF), None);
    }

    #[test]
    fn the_transient_series_doubles_then_caps() {
        let mut previous = None;
        let mut expected = INITIAL_BACKOFF;
        for step in 0..32 {
            let state = StreamBackoff::after(previous.as_ref(), StreamFailure::Transient, NOW);
            assert_eq!(state.current(), expected, "step {step}");
            previous = Some(state);
            expected = (expected * BACKOFF_MULTIPLIER).min(MAX_BACKOFF);
        }
        assert_eq!(previous.unwrap().current(), MAX_BACKOFF);
    }

    #[test]
    fn the_unsupported_series_starts_high_and_caps_at_its_own_max() {
        let mut previous = None;
        let mut expected = UNSUPPORTED_INITIAL_BACKOFF;
        for step in 0..8 {
            let state = StreamBackoff::after(previous.as_ref(), StreamFailure::Unsupported, NOW);
            assert_eq!(state.current(), expected, "step {step}");
            previous = Some(state);
            expected = (expected * BACKOFF_MULTIPLIER).min(UNSUPPORTED_MAX_BACKOFF);
        }
        assert_eq!(previous.unwrap().current(), UNSUPPORTED_MAX_BACKOFF);
    }

    #[test]
    fn a_transient_failure_after_unsupported_returns_to_the_standard_cap() {
        let mut failures = vec![StreamFailure::Unsupported; 8];
        failures.push(StreamFailure::Transient);
        assert_eq!(walk(&failures).unwrap().current(), MAX_BACKOFF);
    }

    #[test]
    fn unsupported_after_transient_jumps_to_the_unsupported_initial() {
        let state = walk(&[StreamFailure::Transient, StreamFailure::Unsupported]).unwrap();
        assert_eq!(state.current(), UNSUPPORTED_INITIAL_BACKOFF);
    }
}
