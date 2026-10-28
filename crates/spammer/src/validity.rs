//! Helper for building per-tx `TimestampRange` values on the chain's clock.
//!
//! The chain enforces validity windows against the parent QC's
//! `WeightedTimestamp` — a BFT-authenticated clock in Unix milliseconds.
//! Submitters read their own wall clock; the 60s default range absorbs
//! sub-second skew between submitter and chain.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyperscale_types::{TimestampRange, WeightedTimestamp};

/// Default forward budget for spammer-submitted transactions.
///
/// Sets how far into the future `end_timestamp_exclusive` is from the
/// submission instant. Comfortably under
/// [`hyperscale_types::MAX_VALIDITY_RANGE`].
pub(crate) const SPAMMER_VALIDITY_BUDGET: Duration = Duration::from_mins(1);

/// Source of validity ranges for generated transactions.
///
/// [`wall_clock`] against a live network; the simulator substitutes a
/// closure reading its simulated millisecond clock.
pub type ValidityClock = Arc<dyn Fn() -> TimestampRange + Send + Sync>;

/// Build a validity range starting at the given anchor with a
/// `SPAMMER_VALIDITY_BUDGET`-wide window.
#[must_use]
pub fn range_starting_at(start: WeightedTimestamp) -> TimestampRange {
    TimestampRange::new(start, start.plus(SPAMMER_VALIDITY_BUDGET))
}

/// A [`ValidityClock`] opening each window at the local wall clock's
/// reading of now, which is the chain's clock.
#[must_use]
pub fn wall_clock() -> ValidityClock {
    Arc::new(|| {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        range_starting_at(WeightedTimestamp::from_millis(unix_ms))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window opens at the wall clock's Unix reading of now, which is
    /// the time the node judges it by.
    #[test]
    fn a_window_opens_at_the_chains_reading_of_now() {
        let unix_ms = || {
            u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
        };
        let before = unix_ms();
        let range = wall_clock()();
        let after = unix_ms();

        let opened = range.start_timestamp_inclusive.as_millis();
        assert!(
            (before..=after).contains(&opened),
            "the window opens at now, {before}..={after} ms, not at {opened} ms"
        );
        assert_eq!(
            range.end_timestamp_exclusive,
            range
                .start_timestamp_inclusive
                .plus(SPAMMER_VALIDITY_BUDGET)
        );
    }
}
