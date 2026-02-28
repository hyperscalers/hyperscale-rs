//! Timeout and backoff computation based on peer RTT history.

use super::{
    RequestManager, RequestPriority, DEFAULT_STREAM_TIMEOUT, MAX_STREAM_TIMEOUT,
    MIN_STREAM_TIMEOUT, STREAM_TIMEOUT_RTT_MULTIPLIER,
};
use libp2p::PeerId;
use std::time::Duration;

/// Compute speculative timeout from optional RTT EMA.
///
/// If RTT is known, uses `rtt * multiplier` clamped to `[min, max]`.
/// If unknown, returns `max` (conservative).
fn speculative_timeout_from_rtt(
    rtt_ema_secs: Option<f64>,
    multiplier: f64,
    min: Duration,
    max: Duration,
) -> Duration {
    rtt_ema_secs
        .map(|rtt| {
            let rtt_based = Duration::from_secs_f64(rtt * multiplier);
            rtt_based.clamp(min, max)
        })
        .unwrap_or(max)
}

/// Compute stream timeout from optional RTT EMA.
///
/// Uses 5x RTT clamped to `[500ms, 5s]`. Falls back to 1s when RTT is unknown.
fn stream_timeout_from_rtt(rtt_ema_secs: Option<f64>) -> Duration {
    rtt_ema_secs
        .map(|rtt| {
            let rtt_based = Duration::from_secs_f64(rtt * STREAM_TIMEOUT_RTT_MULTIPLIER);
            rtt_based.clamp(MIN_STREAM_TIMEOUT, MAX_STREAM_TIMEOUT)
        })
        .unwrap_or(DEFAULT_STREAM_TIMEOUT)
}

/// Compute initial backoff from optional RTT EMA and priority.
///
/// Base backoff is `rtt * 0.5` clamped to `[50ms, 1s]`, then adjusted by priority:
/// - Critical: 0.7x (shorter backoff)
/// - Normal: 1.0x
/// - Background: 1.5x (longer backoff)
fn initial_backoff_from_rtt(
    rtt_ema_secs: Option<f64>,
    default_backoff: Duration,
    priority: RequestPriority,
) -> Duration {
    let base_backoff = rtt_ema_secs
        .map(|rtt| {
            let rtt_based = Duration::from_secs_f64(rtt * 0.5);
            rtt_based.clamp(Duration::from_millis(50), Duration::from_secs(1))
        })
        .unwrap_or(default_backoff);

    match priority {
        RequestPriority::Critical => base_backoff.mul_f32(0.7),
        RequestPriority::Normal => base_backoff,
        RequestPriority::Background => base_backoff.mul_f32(1.5),
    }
}

impl RequestManager {
    /// Compute the speculative retry timeout based on peer's RTT history.
    pub(super) fn compute_speculative_timeout(&self, peer: &PeerId) -> Duration {
        speculative_timeout_from_rtt(
            self.health.rtt_ema_secs(peer),
            self.config.speculative_retry_multiplier,
            self.config.speculative_retry_min,
            self.config.speculative_retry_max,
        )
    }

    /// Compute the stream timeout based on peer's RTT history.
    ///
    /// Uses 5x RTT as the timeout, clamped to reasonable bounds.
    /// This ensures we don't wait 5 seconds for a peer with 100ms RTT.
    pub(super) fn compute_stream_timeout(&self, peer: &PeerId) -> Duration {
        stream_timeout_from_rtt(self.health.rtt_ema_secs(peer))
    }

    /// Compute initial backoff based on peer RTT and priority.
    ///
    /// For peers with known RTT, use a fraction of their RTT as initial backoff.
    /// Priority adjusts this: Critical requests use shorter backoff, Background longer.
    pub(super) fn compute_initial_backoff(
        &self,
        peer: &PeerId,
        priority: RequestPriority,
    ) -> Duration {
        initial_backoff_from_rtt(
            self.health.rtt_ema_secs(peer),
            self.config.initial_backoff,
            priority,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speculative_timeout_known_rtt() {
        let min = Duration::from_millis(200);
        let max = Duration::from_secs(2);
        let multiplier = 2.0;

        // 100ms RTT * 2.0 = 200ms (at min)
        let timeout = speculative_timeout_from_rtt(Some(0.1), multiplier, min, max);
        assert_eq!(timeout, min);

        // 500ms RTT * 2.0 = 1000ms (in range)
        let timeout = speculative_timeout_from_rtt(Some(0.5), multiplier, min, max);
        assert_eq!(timeout, Duration::from_secs(1));

        // 2000ms RTT * 2.0 = 4000ms (clamped to max)
        let timeout = speculative_timeout_from_rtt(Some(2.0), multiplier, min, max);
        assert_eq!(timeout, max);
    }

    #[test]
    fn test_speculative_timeout_unknown_rtt() {
        let max = Duration::from_secs(2);
        let timeout = speculative_timeout_from_rtt(None, 2.0, Duration::from_millis(200), max);
        assert_eq!(timeout, max);
    }

    #[test]
    fn test_stream_timeout_known_rtt() {
        // 100ms * 5 = 500ms (at min)
        let timeout = stream_timeout_from_rtt(Some(0.1));
        assert_eq!(timeout, MIN_STREAM_TIMEOUT);

        // 200ms * 5 = 1000ms (in range)
        let timeout = stream_timeout_from_rtt(Some(0.2));
        assert_eq!(timeout, Duration::from_secs(1));

        // 2000ms * 5 = 10000ms (clamped to max)
        let timeout = stream_timeout_from_rtt(Some(2.0));
        assert_eq!(timeout, MAX_STREAM_TIMEOUT);
    }

    #[test]
    fn test_stream_timeout_unknown_rtt() {
        let timeout = stream_timeout_from_rtt(None);
        assert_eq!(timeout, DEFAULT_STREAM_TIMEOUT);
    }

    #[test]
    fn test_initial_backoff_known_rtt() {
        let default = Duration::from_millis(100);

        // 200ms RTT * 0.5 = 100ms
        let normal = initial_backoff_from_rtt(Some(0.2), default, RequestPriority::Normal);
        assert_eq!(normal, Duration::from_millis(100));

        // Critical should be shorter
        let critical = initial_backoff_from_rtt(Some(0.2), default, RequestPriority::Critical);
        assert!(critical < normal);

        // Background should be longer
        let background = initial_backoff_from_rtt(Some(0.2), default, RequestPriority::Background);
        assert!(background > normal);
    }

    #[test]
    fn test_initial_backoff_unknown_rtt() {
        let default = Duration::from_millis(100);
        let backoff = initial_backoff_from_rtt(None, default, RequestPriority::Normal);
        assert_eq!(backoff, default);
    }

    #[test]
    fn test_initial_backoff_clamps_to_range() {
        let default = Duration::from_millis(100);

        // Very low RTT: 1ms * 0.5 = 0.5ms -> clamped to 50ms
        let backoff = initial_backoff_from_rtt(Some(0.001), default, RequestPriority::Normal);
        assert_eq!(backoff, Duration::from_millis(50));

        // Very high RTT: 10s * 0.5 = 5s -> clamped to 1s
        let backoff = initial_backoff_from_rtt(Some(10.0), default, RequestPriority::Normal);
        assert_eq!(backoff, Duration::from_secs(1));
    }

    #[test]
    fn test_priority_ordering() {
        let default = Duration::from_millis(100);
        let rtt = Some(0.2);

        let critical = initial_backoff_from_rtt(rtt, default, RequestPriority::Critical);
        let normal = initial_backoff_from_rtt(rtt, default, RequestPriority::Normal);
        let background = initial_backoff_from_rtt(rtt, default, RequestPriority::Background);

        assert!(critical < normal, "Critical should be shorter than Normal");
        assert!(
            normal < background,
            "Normal should be shorter than Background"
        );
    }
}
