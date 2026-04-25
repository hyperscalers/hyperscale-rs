//! Helper for building per-tx `TimestampRange` values from local wall clock.
//!
//! The chain enforces validity windows against the parent QC's
//! `WeightedTimestamp` — a BFT-authenticated millisecond clock. Submitters
//! use their own wall clock; the 60s default range absorbs sub-second
//! skew between submitter and chain.

use hyperscale_types::{TimestampRange, WeightedTimestamp};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default forward budget for spammer-submitted transactions: how far
/// into the future `end_timestamp_exclusive` is set from the submission
/// instant. Comfortably under [`hyperscale_types::MAX_VALIDITY_RANGE`].
pub const SPAMMER_VALIDITY_BUDGET: Duration = Duration::from_secs(60);

/// Build a validity range anchored on the local wall clock with a 60s
/// forward budget. `start_timestamp_inclusive = now`,
/// `end_timestamp_exclusive = now + SPAMMER_VALIDITY_BUDGET`.
pub fn validity_range_for_now() -> TimestampRange {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let start = WeightedTimestamp::from_millis(now_ms);
    TimestampRange::new(start, start.plus(SPAMMER_VALIDITY_BUDGET))
}
