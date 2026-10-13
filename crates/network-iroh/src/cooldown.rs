//! Per-peer failure rate tracking with an escalating cooldown.
//!
//! A peer whose inbound traffic keeps failing still costs a task and a read
//! each time. Past a threshold of failures within a window the peer cools
//! down: its traffic of that kind is dropped unread for a period that
//! doubles each time the threshold is hit again, and one success restores
//! it.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use iroh::EndpointId;

/// Number of failures within [`FAILURE_WINDOW`] before triggering a
/// cooldown.
const FAILURE_THRESHOLD: u32 = 8;

/// Time window for counting failures. Resets when the window elapses.
const FAILURE_WINDOW: Duration = Duration::from_secs(10);

/// Initial cooldown duration after the failure threshold is exceeded.
const INITIAL_COOLDOWN: Duration = Duration::from_secs(1);

/// Maximum cooldown duration (exponential backoff cap).
const MAX_COOLDOWN: Duration = Duration::from_secs(30);

/// Failure tracking state of one peer.
struct PeerRateState {
    /// Failures observed in the current window.
    failures: u32,
    /// When the current failure-counting window started.
    window_start: Instant,
    /// The peer is cooling down until this time, if it is.
    cooldown_until: Option<Instant>,
    /// Duration of the next cooldown (doubles after each).
    backoff: Duration,
}

/// Tracks failures per peer and says which peers are cooling down.
#[derive(Default)]
pub struct FailureCooldown {
    peers: DashMap<EndpointId, PeerRateState>,
}

impl FailureCooldown {
    /// Record a failure for `peer`. Returns the cooldown the peer has just
    /// entered when this failure took it past the threshold.
    pub fn record_failure(&self, peer: EndpointId) -> Option<Duration> {
        let now = Instant::now();
        let mut state = self.peers.entry(peer).or_insert_with(|| PeerRateState {
            failures: 0,
            window_start: now,
            cooldown_until: None,
            backoff: INITIAL_COOLDOWN,
        });
        if now.saturating_duration_since(state.window_start) > FAILURE_WINDOW {
            state.failures = 0;
            state.window_start = now;
        }
        state.failures += 1;

        (state.failures >= FAILURE_THRESHOLD && state.cooldown_until.is_none()).then(|| {
            let cooldown = state.backoff;
            state.cooldown_until = Some(now + cooldown);
            state.backoff = (cooldown * 2).min(MAX_COOLDOWN);
            cooldown
        })
    }

    /// Record a success for `peer`, so a recovered peer regains trust at
    /// once.
    pub fn record_success(&self, peer: EndpointId) {
        if let Some(mut state) = self.peers.get_mut(&peer) {
            state.failures = 0;
            state.cooldown_until = None;
            state.backoff = INITIAL_COOLDOWN;
        }
    }

    /// Whether `peer` is cooling down. A lapsed cooldown is cleared and the
    /// failure window reset, so the peer gets a fresh chance; its backoff
    /// is kept, so a re-trigger lasts longer.
    pub fn cooling_down(&self, peer: EndpointId) -> bool {
        if let Some(mut state) = self.peers.get_mut(&peer)
            && let Some(until) = state.cooldown_until
        {
            if Instant::now() < until {
                return true;
            }
            state.cooldown_until = None;
            state.failures = 0;
            state.window_start = Instant::now();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn random_peer() -> EndpointId {
        SecretKey::generate().public()
    }

    /// The backoff the next cooldown of `peer` would last.
    fn next_backoff(cooldown: &FailureCooldown, peer: EndpointId) -> Duration {
        cooldown.peers.get(&peer).expect("entry exists").backoff
    }

    #[test]
    fn failures_past_the_threshold_cool_the_peer_down() {
        let cooldown = FailureCooldown::default();
        let peer = random_peer();

        for _ in 0..FAILURE_THRESHOLD - 1 {
            assert_eq!(cooldown.record_failure(peer), None);
        }
        assert!(!cooldown.cooling_down(peer), "below the threshold");

        assert_eq!(cooldown.record_failure(peer), Some(INITIAL_COOLDOWN));
        assert!(cooldown.cooling_down(peer), "at the threshold");
        assert_eq!(next_backoff(&cooldown, peer), INITIAL_COOLDOWN * 2);
        assert!(!cooldown.cooling_down(random_peer()), "peers are isolated");
    }

    #[test]
    fn a_lapsed_cooldown_admits_again_and_keeps_its_backoff() {
        let cooldown = FailureCooldown::default();
        let peer = random_peer();
        cooldown.peers.insert(
            peer,
            PeerRateState {
                failures: FAILURE_THRESHOLD,
                window_start: Instant::now(),
                cooldown_until: Instant::now().checked_sub(Duration::from_millis(1)),
                backoff: INITIAL_COOLDOWN * 2,
            },
        );

        assert!(!cooldown.cooling_down(peer));
        for _ in 0..FAILURE_THRESHOLD - 1 {
            assert_eq!(cooldown.record_failure(peer), None, "the window restarted");
        }
        assert_eq!(
            cooldown.record_failure(peer),
            Some(INITIAL_COOLDOWN * 2),
            "a second cooldown lasts longer"
        );
    }

    #[test]
    fn a_success_restores_a_peer_at_once() {
        let cooldown = FailureCooldown::default();
        let peer = random_peer();
        for _ in 0..FAILURE_THRESHOLD {
            cooldown.record_failure(peer);
        }
        cooldown.record_success(peer);

        assert!(!cooldown.cooling_down(peer));
        assert_eq!(next_backoff(&cooldown, peer), INITIAL_COOLDOWN);
    }
}
