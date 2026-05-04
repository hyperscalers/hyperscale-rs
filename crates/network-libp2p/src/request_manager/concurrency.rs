//! Per-class admission control for the request pool.
//!
//! Three caps run in tandem: a global pool, a sheddable subset
//! (`Recovery` + `Bulk`), and a cross-shard subset (`CrossShardProgress`).
//! Hot-path classes (`Consensus`, `BlockCompletion`) only check the global
//! cap, and the two subset caps reserve room for them within it.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hyperscale_metrics::{record_request_slot_wait, set_request_slots_in_flight};
use hyperscale_types::MessageClass;
use tokio::time::sleep;
use tracing::warn;

use super::{RequestError, RequestManager, is_cross_shard, uses_relaxed_retry};

/// Pure admission decision: would a request of `class` be admitted right now?
///
/// Three checks run in order:
/// 1. Global pool has room (`in_flight < limit`).
/// 2. If `class` is sheddable (`Recovery` / `Bulk`), the sheddable subset
///    is below its own cap.
/// 3. If `class` is `CrossShardProgress`, the cross-shard subset is below
///    its own cap.
///
/// Hot-path classes (`Consensus`, `BlockCompletion`) only check (1) — and
/// the other two caps reserve room for them within the global pool.
/// Used both by the live CAS loop in `acquire_slot` and by the unit
/// tests below.
const fn would_admit(
    in_flight: usize,
    limit: usize,
    sheddable_in_flight: usize,
    sheddable_cap: usize,
    cross_shard_in_flight: usize,
    cross_shard_cap: usize,
    class: MessageClass,
) -> bool {
    if in_flight >= limit {
        return false;
    }
    if uses_relaxed_retry(class) && sheddable_in_flight >= sheddable_cap {
        return false;
    }
    if is_cross_shard(class) && cross_shard_in_flight >= cross_shard_cap {
        return false;
    }
    true
}

impl RequestManager {
    /// Wait for a concurrency slot to become available.
    ///
    /// Hot-path classes acquire freely against `config.max_concurrent`.
    /// Sheddable classes (`Recovery` / `Bulk`) additionally observe
    /// `config.sheddable_max_concurrent` so a catchup / DA-backfill burst
    /// can never fill the global pool and starve the hot path.
    pub(super) async fn acquire_slot(&self, class: MessageClass) -> Result<(), RequestError> {
        let start = Instant::now();
        let max_wait = Duration::from_secs(30);
        let sheddable = uses_relaxed_retry(class);
        let cross = is_cross_shard(class);
        let limit = self.config.max_concurrent;
        let sheddable_cap = self.config.sheddable_max_concurrent;
        let cross_cap = self.config.cross_shard_max_concurrent;

        loop {
            let current = self.in_flight.load(Ordering::Relaxed);
            let sheddable_now = self.sheddable_in_flight.load(Ordering::Relaxed);
            let cross_now = self.cross_shard_in_flight.load(Ordering::Relaxed);

            if would_admit(
                current,
                limit,
                sheddable_now,
                sheddable_cap,
                cross_now,
                cross_cap,
                class,
            ) && self
                .in_flight
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                if sheddable {
                    self.sheddable_in_flight.fetch_add(1, Ordering::SeqCst);
                }
                if cross {
                    self.cross_shard_in_flight.fetch_add(1, Ordering::SeqCst);
                }
                let idx = Self::class_index(class);
                let class_now = self.per_class_in_flight[idx].fetch_add(1, Ordering::SeqCst) + 1;
                set_request_slots_in_flight(class.as_str(), class_now);
                record_request_slot_wait(class.as_str(), start.elapsed().as_secs_f64());
                return Ok(());
            }

            if start.elapsed() > max_wait {
                warn!(
                    current,
                    limit,
                    sheddable_now,
                    sheddable_cap,
                    cross_now,
                    cross_cap,
                    ?class,
                    "Timed out waiting for concurrency slot"
                );
                record_request_slot_wait(class.as_str(), start.elapsed().as_secs_f64());
                return Err(RequestError::Exhausted { attempts: 0 });
            }

            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Release a slot held by `class`. Decrements the global, per-class,
    /// and (if applicable) sheddable / cross-shard counters and re-emits
    /// the gauge.
    pub(super) fn release_slot(&self, class: MessageClass) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        if uses_relaxed_retry(class) {
            self.sheddable_in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        if is_cross_shard(class) {
            self.cross_shard_in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        let idx = Self::class_index(class);
        let class_now = self.per_class_in_flight[idx].fetch_sub(1, Ordering::SeqCst) - 1;
        set_request_slots_in_flight(class.as_str(), class_now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default budgets used by the admission tests below: 64 global,
    /// 16 sheddable, 24 cross-shard → 24 reserved for hot-path classes.
    const SHEDDABLE_CAP: usize = 16;
    const CROSS_CAP: usize = 24;

    #[test]
    fn admit_hot_below_global_limit() {
        // Hot classes (Consensus, BlockCompletion) are admitted as long
        // as the global pool has room — neither subset cap applies.
        for class in [MessageClass::Consensus, MessageClass::BlockCompletion] {
            assert!(would_admit(0, 64, 0, SHEDDABLE_CAP, 0, CROSS_CAP, class));
            assert!(would_admit(
                63,
                64,
                SHEDDABLE_CAP,
                SHEDDABLE_CAP,
                CROSS_CAP,
                CROSS_CAP,
                class
            ));
            assert!(!would_admit(64, 64, 0, SHEDDABLE_CAP, 0, CROSS_CAP, class));
        }
    }

    #[test]
    fn admit_sheddable_below_subset_cap() {
        // Sheddable classes admit only while sheddable_in_flight < cap.
        for class in [MessageClass::Recovery, MessageClass::Bulk] {
            assert!(would_admit(0, 64, 0, SHEDDABLE_CAP, 0, CROSS_CAP, class));
            assert!(would_admit(20, 64, 15, SHEDDABLE_CAP, 0, CROSS_CAP, class));
            assert!(!would_admit(
                20,
                64,
                SHEDDABLE_CAP,
                SHEDDABLE_CAP,
                0,
                CROSS_CAP,
                class
            ));
        }
    }

    #[test]
    fn admit_cross_shard_below_subset_cap() {
        // CrossShardProgress admits only while cross_shard_in_flight < cap.
        let class = MessageClass::CrossShardProgress;
        assert!(would_admit(0, 64, 0, SHEDDABLE_CAP, 0, CROSS_CAP, class));
        assert!(would_admit(
            30,
            64,
            0,
            SHEDDABLE_CAP,
            CROSS_CAP - 1,
            CROSS_CAP,
            class
        ));
        assert!(!would_admit(
            30,
            64,
            0,
            SHEDDABLE_CAP,
            CROSS_CAP,
            CROSS_CAP,
            class
        ));
    }

    #[test]
    fn sheddable_flood_does_not_starve_hot() {
        // 16 sheddable in-flight out of 64 global. Hot classes still see
        // 48 slots of headroom; CrossShardProgress sees its own 24 cap.
        let in_flight = SHEDDABLE_CAP;
        let sheddable_now = SHEDDABLE_CAP;

        for class in [MessageClass::Recovery, MessageClass::Bulk] {
            assert!(!would_admit(
                in_flight,
                64,
                sheddable_now,
                SHEDDABLE_CAP,
                0,
                CROSS_CAP,
                class
            ));
        }

        for class in [
            MessageClass::Consensus,
            MessageClass::BlockCompletion,
            MessageClass::CrossShardProgress,
        ] {
            assert!(would_admit(
                in_flight,
                64,
                sheddable_now,
                SHEDDABLE_CAP,
                0,
                CROSS_CAP,
                class
            ));
        }
    }

    #[test]
    fn cross_shard_flood_does_not_starve_consensus() {
        // The motivating regression for the three-pool reservation: a
        // CrossShardProgress storm at the cross-shard cap must not block
        // Consensus / BlockCompletion. Hot path keeps 24 reserved.
        let cross_now = CROSS_CAP;
        let in_flight = cross_now;

        // CrossShardProgress is now blocked.
        assert!(!would_admit(
            in_flight,
            64,
            0,
            SHEDDABLE_CAP,
            cross_now,
            CROSS_CAP,
            MessageClass::CrossShardProgress
        ));

        // Hot classes still admitted (24 reserved + sheddable headroom).
        for class in [MessageClass::Consensus, MessageClass::BlockCompletion] {
            assert!(would_admit(
                in_flight,
                64,
                0,
                SHEDDABLE_CAP,
                cross_now,
                CROSS_CAP,
                class
            ));
        }
    }

    #[test]
    fn worst_case_load_still_admits_hot() {
        // Both subsets at their caps simultaneously: 16 sheddable + 24
        // cross-shard = 40 of 64. Hot path retains the remaining 24
        // slots — the design's reservation contract.
        let sheddable_now = SHEDDABLE_CAP;
        let cross_now = CROSS_CAP;
        let in_flight = sheddable_now + cross_now;
        assert_eq!(in_flight, 40);

        for class in [MessageClass::Consensus, MessageClass::BlockCompletion] {
            assert!(would_admit(
                in_flight,
                64,
                sheddable_now,
                SHEDDABLE_CAP,
                cross_now,
                CROSS_CAP,
                class
            ));
        }

        // The two capped classes are at their limits.
        assert!(!would_admit(
            in_flight,
            64,
            sheddable_now,
            SHEDDABLE_CAP,
            cross_now,
            CROSS_CAP,
            MessageClass::Recovery
        ));
        assert!(!would_admit(
            in_flight,
            64,
            sheddable_now,
            SHEDDABLE_CAP,
            cross_now,
            CROSS_CAP,
            MessageClass::CrossShardProgress
        ));
    }

    #[test]
    fn global_limit_blocks_every_class() {
        // When the global pool is full, no class is admitted regardless
        // of subset occupancy.
        for class in [
            MessageClass::Consensus,
            MessageClass::BlockCompletion,
            MessageClass::CrossShardProgress,
            MessageClass::Recovery,
            MessageClass::Bulk,
        ] {
            assert!(!would_admit(64, 64, 0, SHEDDABLE_CAP, 0, CROSS_CAP, class));
        }
    }
}
