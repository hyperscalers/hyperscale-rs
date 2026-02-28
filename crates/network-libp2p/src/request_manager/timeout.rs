//! Timeout and backoff computation based on peer RTT history.

use super::{
    RequestManager, RequestPriority, DEFAULT_STREAM_TIMEOUT, MAX_STREAM_TIMEOUT,
    MIN_STREAM_TIMEOUT, STREAM_TIMEOUT_RTT_MULTIPLIER,
};
use libp2p::PeerId;
use std::time::Duration;

impl RequestManager {
    /// Compute the speculative retry timeout based on peer's RTT history.
    pub(super) fn compute_speculative_timeout(&self, peer: &PeerId) -> Duration {
        self.health
            .rtt_ema_secs(peer)
            .map(|rtt| {
                let rtt_based =
                    Duration::from_secs_f64(rtt * self.config.speculative_retry_multiplier);
                rtt_based.clamp(
                    self.config.speculative_retry_min,
                    self.config.speculative_retry_max,
                )
            })
            .unwrap_or(self.config.speculative_retry_max)
    }

    /// Compute the stream timeout based on peer's RTT history.
    ///
    /// Uses 5x RTT as the timeout, clamped to reasonable bounds.
    /// This ensures we don't wait 5 seconds for a peer with 100ms RTT.
    pub(super) fn compute_stream_timeout(&self, peer: &PeerId) -> Duration {
        self.health
            .rtt_ema_secs(peer)
            .map(|rtt| {
                let rtt_based = Duration::from_secs_f64(rtt * STREAM_TIMEOUT_RTT_MULTIPLIER);
                rtt_based.clamp(MIN_STREAM_TIMEOUT, MAX_STREAM_TIMEOUT)
            })
            .unwrap_or(DEFAULT_STREAM_TIMEOUT)
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
        let base_backoff = self
            .health
            .rtt_ema_secs(peer)
            .map(|rtt| {
                let rtt_based = Duration::from_secs_f64(rtt * 0.5);
                rtt_based.clamp(Duration::from_millis(50), Duration::from_secs(1))
            })
            .unwrap_or(self.config.initial_backoff);

        match priority {
            RequestPriority::Critical => base_backoff.mul_f32(0.7),
            RequestPriority::Normal => base_backoff,
            RequestPriority::Background => base_backoff.mul_f32(1.5),
        }
    }
}
