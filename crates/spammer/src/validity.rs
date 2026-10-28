//! Helper for building per-tx `TimestampRange` values on the chain's clock.
//!
//! The chain enforces validity windows against the parent QC's
//! `WeightedTimestamp` — a BFT-authenticated millisecond clock that counts
//! from the network's genesis instant, not from the Unix epoch. Submitters
//! read their own wall clock and subtract that instant; the 60s default
//! range absorbs sub-second skew between submitter and chain.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hyperscale_types::{BeaconChainConfig, TimestampRange, WeightedTimestamp};

/// Default forward budget for spammer-submitted transactions.
///
/// Sets how far into the future `end_timestamp_exclusive` is from the
/// submission instant. Comfortably under
/// [`hyperscale_types::MAX_VALIDITY_RANGE`].
pub(crate) const SPAMMER_VALIDITY_BUDGET: Duration = Duration::from_mins(1);

/// Source of validity ranges for generated transactions.
///
/// [`chain_clock`] against a live network; the simulator substitutes a
/// closure reading its simulated millisecond clock.
pub type ValidityClock = Arc<dyn Fn() -> TimestampRange + Send + Sync>;

/// Build a validity range starting at the given anchor with a
/// `SPAMMER_VALIDITY_BUDGET`-wide window.
#[must_use]
pub fn range_starting_at(start: WeightedTimestamp) -> TimestampRange {
    TimestampRange::new(start, start.plus(SPAMMER_VALIDITY_BUDGET))
}

/// A [`ValidityClock`] opening each window at the chain time of the local
/// wall clock, on a network whose genesis instant is
/// `genesis_timestamp_ms`.
#[must_use]
pub fn chain_clock(genesis_timestamp_ms: u64) -> ValidityClock {
    let chain = BeaconChainConfig {
        genesis_timestamp_ms,
        ..BeaconChainConfig::default()
    };
    Arc::new(move || range_starting_at(chain.chain_time(SystemTime::now())))
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    /// A window opens at the chain time the node judges it by, which counts
    /// from genesis: one stamped in Unix milliseconds would open decades
    /// past every block's anchor and never be proposed.
    #[test]
    fn a_window_opens_at_the_chains_reading_of_now() {
        let genesis_timestamp_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            - 42_000;

        let range = chain_clock(genesis_timestamp_ms)();

        let opened = range.start_timestamp_inclusive.as_millis();
        assert!(
            (42_000..42_000 + 60_000).contains(&opened),
            "the window opens about 42 s into the chain, at {opened} ms"
        );
        assert_eq!(
            range.end_timestamp_exclusive,
            range
                .start_timestamp_inclusive
                .plus(SPAMMER_VALIDITY_BUDGET)
        );
    }
}
