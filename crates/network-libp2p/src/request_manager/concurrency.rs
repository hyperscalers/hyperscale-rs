//! Adaptive concurrency control for request management.

use super::{RequestError, RequestManager};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

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
        let new = (current / 2).max(self.config.min_concurrent);

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

        if current >= self.config.max_concurrent {
            return;
        }

        // Only increase if success rate is above target
        let success_rate = self.health.global_success_rate();
        if success_rate >= self.config.target_success_rate {
            // Increase by larger amount when further from max (faster recovery)
            // At 50% of max: increase by 4, at 75%: increase by 2, at 90%+: increase by 1
            let headroom_ratio = current as f64 / self.config.max_concurrent as f64;
            let increment = if headroom_ratio < 0.5 {
                4
            } else if headroom_ratio < 0.75 {
                2
            } else {
                1
            };

            let new = (current + increment).min(self.config.max_concurrent);
            self.effective_concurrent.store(new, Ordering::Relaxed);
            trace!(
                from = current,
                to = new,
                increment,
                success_rate,
                "Increased concurrency"
            );
        }
    }
}
