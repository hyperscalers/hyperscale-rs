//! Exponential backoff scheduler.
//!
//! Tracks rounds of attempts and gates retries behind an `Instant` deadline.
//! Round `n` waits `(base * 2^n).min(max)` milliseconds before the next attempt.

use std::time::{Duration, Instant};

const DEFAULT_BASE_MS: u64 = 500;
const DEFAULT_MAX_MS: u64 = 30_000;

/// Exponential-backoff timer.
#[derive(Debug, Clone)]
pub struct RetryClock {
    rounds: u32,
    next_retry_at: Option<Instant>,
    base_ms: u64,
    max_ms: u64,
}

impl RetryClock {
    /// Build a clock with default backoff (500ms base, 30s ceiling).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rounds: 0,
            next_retry_at: None,
            base_ms: DEFAULT_BASE_MS,
            max_ms: DEFAULT_MAX_MS,
        }
    }

    /// Returns true if the next attempt is permitted at `now`.
    #[must_use]
    pub fn is_ready(&self, now: Instant) -> bool {
        self.next_retry_at.is_none_or(|deadline| now >= deadline)
    }

    /// Advance the round counter and schedule the next retry deadline. Call
    /// after every peer in the rotation has been tried and failed.
    pub fn advance_round(&mut self, now: Instant) {
        self.rounds = self.rounds.saturating_add(1);
        let backoff_ms = self
            .base_ms
            .saturating_mul(2u64.saturating_pow(self.rounds))
            .min(self.max_ms);
        self.next_retry_at = Some(now + Duration::from_millis(backoff_ms));
    }

    /// Reset rounds to zero and clear any pending backoff. Used when a
    /// duplicate request refreshes the entry's peer list.
    pub const fn reset(&mut self) {
        self.rounds = 0;
        self.next_retry_at = None;
    }

    #[cfg(test)]
    pub(super) const fn rounds(&self) -> u32 {
        self.rounds
    }
}

impl Default for RetryClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_clock_is_ready() {
        let clock = RetryClock::new();
        assert!(clock.is_ready(Instant::now()));
        assert_eq!(clock.rounds(), 0);
    }

    #[test]
    fn advance_round_blocks_until_deadline() {
        let mut clock = RetryClock::new();
        let t0 = Instant::now();
        clock.advance_round(t0);

        assert_eq!(clock.rounds(), 1);
        assert!(!clock.is_ready(t0));
        assert!(!clock.is_ready(t0 + Duration::from_millis(999)));
        assert!(clock.is_ready(t0 + Duration::from_secs(1)));
    }

    #[test]
    fn backoff_doubles_each_round() {
        let mut clock = RetryClock::new();
        let t0 = Instant::now();
        clock.advance_round(t0);
        assert!(!clock.is_ready(t0 + Duration::from_millis(999)));
        assert!(clock.is_ready(t0 + Duration::from_secs(1)));
        clock.advance_round(t0);
        assert!(!clock.is_ready(t0 + Duration::from_millis(1999)));
        assert!(clock.is_ready(t0 + Duration::from_secs(2)));
        clock.advance_round(t0);
        assert!(!clock.is_ready(t0 + Duration::from_millis(3999)));
        assert!(clock.is_ready(t0 + Duration::from_secs(4)));
    }

    #[test]
    fn backoff_clamps_at_max() {
        let mut clock = RetryClock::new();
        let t0 = Instant::now();
        for _ in 0..20 {
            clock.advance_round(t0);
        }
        // After many rounds, the deadline is exactly max ms past t0.
        assert!(clock.is_ready(t0 + Duration::from_secs(30)));
    }

    #[test]
    fn reset_clears_state() {
        let mut clock = RetryClock::new();
        clock.advance_round(Instant::now());
        clock.advance_round(Instant::now());
        assert_eq!(clock.rounds(), 2);

        clock.reset();
        assert_eq!(clock.rounds(), 0);
        assert!(clock.is_ready(Instant::now()));
    }
}
