//! Timeout and backoff computation based on peer RTT history.

use super::{
    MAX_STREAM_TIMEOUT, MIN_STREAM_TIMEOUT_COLD, MIN_STREAM_TIMEOUT_WARM, RequestManager,
    STREAM_TIMEOUT_RTT_MULTIPLIER, uses_relaxed_retry,
};
use hyperscale_types::MessageClass;
use libp2p::PeerId;
use std::time::Duration;

/// Compute stream timeout from optional RTT EMA.
///
/// If an RTT estimate exists (peer has succeeded at least once), use
/// `rtt × multiplier` clamped to `[MIN_WARM, MAX]`. If the peer is cold
/// (no RTT data yet), use `MIN_STREAM_TIMEOUT_COLD` — wide enough to avoid
/// the self-reinforcing-trap where aggressive timeouts prevent the EMA
/// from ever being seeded.
fn stream_timeout_from_rtt(rtt_ema_secs: Option<f64>) -> Duration {
    rtt_ema_secs.map_or(MIN_STREAM_TIMEOUT_COLD, |rtt| {
        Duration::from_secs_f64(rtt * STREAM_TIMEOUT_RTT_MULTIPLIER)
            .clamp(MIN_STREAM_TIMEOUT_WARM, MAX_STREAM_TIMEOUT)
    })
}

/// Compute initial backoff from optional RTT EMA and class.
///
/// Base backoff is `rtt * 0.5` clamped to `[50ms, 1s]`, then adjusted by class:
/// - Tight regime (`Consensus` / `BlockCompletion` / `CrossShardProgress`): 0.7×
/// - Relaxed regime (`Recovery` / `Bulk`): 1.5×
fn initial_backoff_from_rtt(
    rtt_ema_secs: Option<f64>,
    default_backoff: Duration,
    class: MessageClass,
) -> Duration {
    let base_backoff = rtt_ema_secs.map_or(default_backoff, |rtt| {
        let rtt_based = Duration::from_secs_f64(rtt * 0.5);
        rtt_based.clamp(Duration::from_millis(50), Duration::from_secs(1))
    });

    if uses_relaxed_retry(class) {
        base_backoff.mul_f32(1.5)
    } else {
        base_backoff.mul_f32(0.7)
    }
}

impl RequestManager {
    /// Compute the stream timeout based on peer's RTT history.
    ///
    /// Uses 5x RTT as the timeout, clamped to reasonable bounds.
    /// This ensures we don't wait 5 seconds for a peer with 100ms RTT.
    pub(super) fn compute_stream_timeout(&self, peer: &PeerId) -> Duration {
        stream_timeout_from_rtt(self.health.rtt_ema_secs(peer))
    }

    /// Compute initial backoff based on peer RTT and class.
    ///
    /// For peers with known RTT, use a fraction of their RTT as initial backoff.
    /// Class adjusts this: tight-regime classes get a shorter backoff, relaxed
    /// (Recovery, Bulk) get a longer one.
    pub(super) fn compute_initial_backoff(&self, peer: &PeerId, class: MessageClass) -> Duration {
        initial_backoff_from_rtt(
            self.health.rtt_ema_secs(peer),
            self.config.initial_backoff,
            class,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_timeout_known_rtt() {
        // 5ms × 5 = 25ms → clamped up to warm floor (300ms)
        let timeout = stream_timeout_from_rtt(Some(0.005));
        assert_eq!(timeout, MIN_STREAM_TIMEOUT_WARM);

        // 200ms × 5 = 1000ms (in range)
        let timeout = stream_timeout_from_rtt(Some(0.2));
        assert_eq!(timeout, Duration::from_secs(1));

        // 5s × 5 = 25s → clamped down to MAX (10s)
        let timeout = stream_timeout_from_rtt(Some(5.0));
        assert_eq!(timeout, MAX_STREAM_TIMEOUT);
    }

    #[test]
    fn test_stream_timeout_unknown_rtt() {
        // Cold peer (no successful request yet) uses the wider cold floor.
        let timeout = stream_timeout_from_rtt(None);
        assert_eq!(timeout, MIN_STREAM_TIMEOUT_COLD);
    }

    /// Allow ±1ms slop to absorb f32 rounding in the multiplier.
    #[allow(clippy::cast_precision_loss)] // ms values are well under f64 mantissa
    fn assert_near_ms(actual: Duration, expected_ms: u64) {
        let actual_ms = actual.as_secs_f64() * 1000.0;
        let diff = (actual_ms - expected_ms as f64).abs();
        assert!(
            diff < 1.0,
            "expected ≈{expected_ms}ms, got {actual_ms}ms (diff {diff})"
        );
    }

    #[test]
    fn test_initial_backoff_known_rtt() {
        let default = Duration::from_millis(100);

        // 200ms RTT * 0.5 = 100ms; CrossShardProgress is tight regime → ≈70ms
        let tight = initial_backoff_from_rtt(Some(0.2), default, MessageClass::CrossShardProgress);
        assert_near_ms(tight, 70);

        // Recovery is relaxed regime → ≈150ms
        let relaxed = initial_backoff_from_rtt(Some(0.2), default, MessageClass::Recovery);
        assert_near_ms(relaxed, 150);

        assert!(tight < relaxed);
    }

    #[test]
    fn test_initial_backoff_unknown_rtt() {
        // Cold peer uses the configured default before applying the class
        // multiplier — tight regime returns ≈ default × 0.7.
        let default = Duration::from_millis(100);
        let backoff = initial_backoff_from_rtt(None, default, MessageClass::Consensus);
        assert_near_ms(backoff, 70);
    }

    #[test]
    fn test_initial_backoff_clamps_to_range() {
        let default = Duration::from_millis(100);

        // Very low RTT: 1ms * 0.5 = 0.5ms -> clamped to 50ms (then × 0.7 ≈ 35ms)
        let backoff = initial_backoff_from_rtt(Some(0.001), default, MessageClass::Consensus);
        assert_near_ms(backoff, 35);

        // Very high RTT: 10s * 0.5 = 5s -> clamped to 1s (then × 0.7 ≈ 700ms)
        let backoff = initial_backoff_from_rtt(Some(10.0), default, MessageClass::Consensus);
        assert_near_ms(backoff, 700);
    }

    #[test]
    fn test_class_ordering() {
        let default = Duration::from_millis(100);
        let rtt = Some(0.2);

        let consensus = initial_backoff_from_rtt(rtt, default, MessageClass::Consensus);
        let block_completion =
            initial_backoff_from_rtt(rtt, default, MessageClass::BlockCompletion);
        let cross_shard = initial_backoff_from_rtt(rtt, default, MessageClass::CrossShardProgress);
        let recovery = initial_backoff_from_rtt(rtt, default, MessageClass::Recovery);
        let bulk = initial_backoff_from_rtt(rtt, default, MessageClass::Bulk);

        // Tight regime — all equal, shorter than relaxed.
        assert_eq!(consensus, block_completion);
        assert_eq!(block_completion, cross_shard);
        // Relaxed regime — equal to each other, longer than tight.
        assert_eq!(recovery, bulk);
        assert!(consensus < recovery);
    }
}
