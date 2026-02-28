//! Adaptive concurrency control for request management.

use super::{RequestError, RequestManager};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Compute the reduced concurrency value (halve, but don't go below min).
fn compute_reduced_concurrency(current: usize, min: usize) -> usize {
    (current / 2).max(min)
}

/// Compute new concurrency level after a potential increase.
///
/// Returns `None` if no increase should happen (already at max, or success rate below target).
/// Uses additive increase with larger steps when further from max for fast recovery.
fn compute_increased_concurrency(
    current: usize,
    max: usize,
    success_rate: f64,
    target_success_rate: f64,
) -> Option<usize> {
    if current >= max {
        return None;
    }
    if success_rate < target_success_rate {
        return None;
    }

    let headroom_ratio = current as f64 / max as f64;
    let increment = if headroom_ratio < 0.5 {
        4
    } else if headroom_ratio < 0.75 {
        2
    } else {
        1
    };

    Some((current + increment).min(max))
}

impl RequestManager {
    /// Wait for a concurrency slot to become available.
    pub(super) async fn acquire_slot(&self) -> Result<(), RequestError> {
        let start = Instant::now();
        let max_wait = Duration::from_secs(30);

        loop {
            let current = self.in_flight.load(Ordering::Relaxed);
            let limit = self.effective_concurrent.load(Ordering::Relaxed);

            if current < limit {
                // Try to acquire slot with CAS
                if self
                    .in_flight
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
                {
                    return Ok(());
                }
                // CAS failed, another thread got it, loop and retry
            }

            // Check for timeout
            if start.elapsed() > max_wait {
                warn!(current, limit, "Timed out waiting for concurrency slot");
                return Err(RequestError::Exhausted { attempts: 0 });
            }

            // Wait a bit before retrying
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Reduce effective concurrency due to poor network conditions.
    /// Currently unused but kept for future adaptive concurrency control.
    #[allow(dead_code)]
    pub(super) fn reduce_concurrency(&self) {
        let current = self.effective_concurrent.load(Ordering::Relaxed);
        let new = compute_reduced_concurrency(current, self.config.min_concurrent);

        if new < current {
            self.effective_concurrent.store(new, Ordering::Relaxed);
            info!(
                from = current,
                to = new,
                "Reduced concurrency due to network conditions"
            );
        }
    }

    /// Maybe increase concurrency if conditions are good.
    ///
    /// Uses additive increase: grows faster when further from max to enable
    /// quick recovery after congestion events that reduced concurrency.
    pub(super) fn maybe_increase_concurrency(&self) {
        let current = self.effective_concurrent.load(Ordering::Relaxed);
        let success_rate = self.health.global_success_rate();

        if let Some(new) = compute_increased_concurrency(
            current,
            self.config.max_concurrent,
            success_rate,
            self.config.target_success_rate,
        ) {
            self.effective_concurrent.store(new, Ordering::Relaxed);
            trace!(
                from = current,
                to = new,
                increment = new - current,
                success_rate,
                "Increased concurrency"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_concurrency_halves() {
        assert_eq!(compute_reduced_concurrency(64, 4), 32);
        assert_eq!(compute_reduced_concurrency(32, 4), 16);
        assert_eq!(compute_reduced_concurrency(16, 4), 8);
    }

    #[test]
    fn test_reduce_concurrency_respects_min() {
        assert_eq!(compute_reduced_concurrency(8, 4), 4);
        assert_eq!(compute_reduced_concurrency(4, 4), 4);
        assert_eq!(compute_reduced_concurrency(2, 4), 4);
    }

    #[test]
    fn test_reduce_concurrency_at_one() {
        // Edge case: current=1, min=1
        assert_eq!(compute_reduced_concurrency(1, 1), 1);
    }

    #[test]
    fn test_increase_concurrency_at_max() {
        assert_eq!(compute_increased_concurrency(64, 64, 0.9, 0.5), None);
    }

    #[test]
    fn test_increase_concurrency_below_target() {
        // Success rate below target - should not increase
        assert_eq!(compute_increased_concurrency(32, 64, 0.3, 0.5), None);
    }

    #[test]
    fn test_increase_concurrency_fast_recovery_below_50pct() {
        // At 20/64 (31%), should increment by 4
        let result = compute_increased_concurrency(20, 64, 0.9, 0.5);
        assert_eq!(result, Some(24));
    }

    #[test]
    fn test_increase_concurrency_medium_recovery_50_75pct() {
        // At 40/64 (62.5%), should increment by 2
        let result = compute_increased_concurrency(40, 64, 0.9, 0.5);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_increase_concurrency_slow_above_75pct() {
        // At 60/64 (93.75%), should increment by 1
        let result = compute_increased_concurrency(60, 64, 0.9, 0.5);
        assert_eq!(result, Some(61));
    }

    #[test]
    fn test_increase_concurrency_caps_at_max() {
        // At 63/64, increment by 1 -> 64 (at max)
        let result = compute_increased_concurrency(63, 64, 0.9, 0.5);
        assert_eq!(result, Some(64));
    }

    #[test]
    fn test_increase_concurrency_at_exactly_target() {
        // Success rate exactly at target - should increase
        let result = compute_increased_concurrency(32, 64, 0.5, 0.5);
        assert_eq!(result, Some(34));
    }

    #[test]
    fn test_increase_concurrency_boundary_at_50pct() {
        // At exactly 50% of max (32/64), headroom_ratio = 0.5, so >= 0.5
        // Should get increment=2 (in the 0.5..0.75 bracket)
        let result = compute_increased_concurrency(32, 64, 0.9, 0.5);
        assert_eq!(result, Some(34));
    }

    #[test]
    fn test_increase_concurrency_boundary_at_75pct() {
        // At exactly 75% of max (48/64), headroom_ratio = 0.75, so >= 0.75
        // Should get increment=1
        let result = compute_increased_concurrency(48, 64, 0.9, 0.5);
        assert_eq!(result, Some(49));
    }
}
