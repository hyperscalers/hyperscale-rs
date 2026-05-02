//! Adaptive concurrency control for request management.

use super::{RequestError, RequestManager, uses_relaxed_retry};
use hyperscale_types::MessageClass;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

/// Pure admission decision: would a request of `class` be admitted right now?
///
/// Returns `true` when the global pool has room AND, if the class is
/// sheddable (`Recovery` / `Bulk`), the sheddable subset is below its own
/// cap. Used both by the live CAS loop in `acquire_slot` and by the unit
/// tests below.
const fn would_admit(
    in_flight: usize,
    limit: usize,
    sheddable_in_flight: usize,
    sheddable_cap: usize,
    class: MessageClass,
) -> bool {
    if in_flight >= limit {
        return false;
    }
    if uses_relaxed_retry(class) && sheddable_in_flight >= sheddable_cap {
        return false;
    }
    true
}

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

    #[allow(clippy::cast_precision_loss)]
    // ratio used only for bucketed thresholds, precision irrelevant
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
    ///
    /// Hot-path classes acquire freely against `effective_concurrent`.
    /// Sheddable classes (`Recovery` / `Bulk`) additionally observe
    /// `config.sheddable_max_concurrent` so a catchup / DA-backfill burst
    /// can never fill the global pool and starve the hot path.
    pub(super) async fn acquire_slot(&self, class: MessageClass) -> Result<(), RequestError> {
        let start = Instant::now();
        let max_wait = Duration::from_secs(30);
        let sheddable = uses_relaxed_retry(class);
        let sheddable_cap = self.config.sheddable_max_concurrent;

        loop {
            let current = self.in_flight.load(Ordering::Relaxed);
            let limit = self.effective_concurrent.load(Ordering::Relaxed);
            let sheddable_now = self.sheddable_in_flight.load(Ordering::Relaxed);

            if would_admit(current, limit, sheddable_now, sheddable_cap, class)
                && self
                    .in_flight
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                    .is_ok()
            {
                if sheddable {
                    self.sheddable_in_flight.fetch_add(1, Ordering::SeqCst);
                }
                return Ok(());
            }

            if start.elapsed() > max_wait {
                warn!(
                    current,
                    limit,
                    sheddable_now,
                    sheddable_cap,
                    ?class,
                    "Timed out waiting for concurrency slot"
                );
                return Err(RequestError::Exhausted { attempts: 0 });
            }

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

    // ── Per-class admission ───────────────────────────────────────────

    #[test]
    fn admit_hot_below_global_limit() {
        // Hot classes are admitted as long as the global pool has room.
        for class in [
            MessageClass::Consensus,
            MessageClass::BlockCompletion,
            MessageClass::CrossShardProgress,
        ] {
            assert!(would_admit(0, 64, 0, 16, class));
            assert!(would_admit(63, 64, 16, 16, class));
            assert!(!would_admit(64, 64, 0, 16, class));
        }
    }

    #[test]
    fn admit_sheddable_below_subset_cap() {
        // Sheddable classes admit only while sheddable_in_flight < cap.
        for class in [MessageClass::Recovery, MessageClass::Bulk] {
            assert!(would_admit(0, 64, 0, 16, class));
            assert!(would_admit(20, 64, 15, 16, class));
            assert!(!would_admit(20, 64, 16, 16, class));
        }
    }

    #[test]
    fn sheddable_flood_does_not_starve_hot() {
        // The motivating regression: 16 sheddable in-flight (subset cap)
        // out of 64 global. Hot classes still see 48 slots of headroom.
        let in_flight = 16;
        let sheddable_in_flight = 16;

        // Sheddable is now blocked.
        assert!(!would_admit(
            in_flight,
            64,
            sheddable_in_flight,
            16,
            MessageClass::Recovery
        ));
        assert!(!would_admit(
            in_flight,
            64,
            sheddable_in_flight,
            16,
            MessageClass::Bulk
        ));

        // Hot path still admitted.
        for class in [
            MessageClass::Consensus,
            MessageClass::BlockCompletion,
            MessageClass::CrossShardProgress,
        ] {
            assert!(would_admit(in_flight, 64, sheddable_in_flight, 16, class));
        }
    }

    #[test]
    fn global_limit_blocks_every_class() {
        // When the global pool is full, no class is admitted.
        for class in [
            MessageClass::Consensus,
            MessageClass::BlockCompletion,
            MessageClass::CrossShardProgress,
            MessageClass::Recovery,
            MessageClass::Bulk,
        ] {
            assert!(!would_admit(64, 64, 0, 16, class));
        }
    }
}
