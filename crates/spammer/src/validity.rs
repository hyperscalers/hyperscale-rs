//! Helper for building per-tx `TimestampRange` values from local wall clock.
//!
//! The chain enforces validity windows against the parent QC's
//! `WeightedTimestamp` — a BFT-authenticated millisecond clock. Submitters
//! use their own wall clock; the 60s default range absorbs sub-second
//! skew between submitter and chain.

use hyperscale_types::{TimestampRange, WeightedTimestamp};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default forward budget for spammer-submitted transactions.
///
/// Sets how far into the future `end_timestamp_exclusive` is from the
/// submission instant. Comfortably under
/// [`hyperscale_types::MAX_VALIDITY_RANGE`].
pub const SPAMMER_VALIDITY_BUDGET: Duration = Duration::from_mins(1);

/// Source of validity ranges for generated transactions.
///
/// Wall-clock by default ([`wall_clock`]); the simulator overrides this with
/// a closure reading its simulated millisecond clock so submitted txs sit
/// within the chain's authenticated `weighted_timestamp` window instead of
/// floating in real-world epoch.
pub type ValidityClock = Arc<dyn Fn() -> TimestampRange + Send + Sync>;

/// Build a validity range anchored on the local wall clock with a 60s
/// forward budget. `start_timestamp_inclusive = now`,
/// `end_timestamp_exclusive = now + SPAMMER_VALIDITY_BUDGET`.
#[must_use]
pub fn validity_range_for_now() -> TimestampRange {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    range_starting_at(WeightedTimestamp::from_millis(now_ms))
}

/// Build a validity range starting at the given anchor with a
/// `SPAMMER_VALIDITY_BUDGET`-wide window.
#[must_use]
pub fn range_starting_at(start: WeightedTimestamp) -> TimestampRange {
    TimestampRange::new(start, start.plus(SPAMMER_VALIDITY_BUDGET))
}

/// Default [`ValidityClock`] anchoring on the local wall clock.
#[must_use]
pub fn wall_clock() -> ValidityClock {
    Arc::new(validity_range_for_now)
}
