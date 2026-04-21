//! Typed timestamps for consensus and proposal wall-clocks.
//!
//! Two distinct timestamp categories share millisecond representation but
//! carry very different trust guarantees:
//!
//! - [`WeightedTimestamp`] — BFT-authenticated stake-weighted median produced
//!   on every QC. Safe to anchor consensus deadlines on; all validators derive
//!   the same value for a given committed block.
//! - [`ProposerTimestamp`] — the proposer's local wall-clock embedded in a
//!   block header at proposal time. Not authenticated; used only for BFT
//!   liveness bounds (rushed/stale header rejection) and local-only latency
//!   metrics. Must never feed a deterministic timeout — that's what
//!   `WeightedTimestamp` is for.
//!
//! Both wrap `u64` ms and are `#[sbor(transparent)]` so the wire encoding
//! stays identical to the bare `u64` fields they replace.

use sbor::prelude::*;
use std::fmt;
use std::time::Duration;

/// BFT-authenticated, stake-weighted block timestamp in milliseconds.
///
/// Derived from the QC: `sum(timestamp_i * stake_i) / sum(stake_i)` over the
/// 2f+1 voters that formed the QC. Because every honest validator aggregates
/// the same vote set, every validator derives the same `WeightedTimestamp`
/// for the same committed block.
///
/// This is the only timestamp type safe to anchor consensus deadlines on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor, Default)]
#[sbor(transparent)]
pub struct WeightedTimestamp(pub u64);

impl WeightedTimestamp {
    /// Genesis / zero timestamp.
    pub const ZERO: Self = WeightedTimestamp(0);

    /// Wrap a raw ms value. Prefer
    /// [`QuorumCertificate::weighted_timestamp`] at produce sites.
    pub const fn from_millis(ms: u64) -> Self {
        WeightedTimestamp(ms)
    }

    /// Raw ms value — use sparingly, only at serialization / FFI boundaries
    /// (log fields, metrics, wire format that hasn't been migrated yet).
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Duration elapsed between two weighted timestamps, saturating at zero.
    ///
    /// Reads as "how long after `earlier` was `self` produced". Used for
    /// deadline checks like `committed.elapsed_since(wave_start) >= WAVE_TIMEOUT`.
    pub fn elapsed_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    /// Return `self + duration`, saturating on overflow.
    pub fn plus(self, duration: Duration) -> Self {
        let add = duration.as_millis().try_into().unwrap_or(u64::MAX);
        WeightedTimestamp(self.0.saturating_add(add))
    }

    /// Return `self - duration`, saturating at zero.
    ///
    /// Used for cutoff computations: `committed.minus(retention)` gives the
    /// lower edge of the retention window.
    pub fn minus(self, duration: Duration) -> Self {
        let sub = duration.as_millis().try_into().unwrap_or(u64::MAX);
        WeightedTimestamp(self.0.saturating_sub(sub))
    }
}

impl fmt::Display for WeightedTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Unauthenticated, single-validator wall-clock timestamp in milliseconds.
///
/// Carried on two types:
/// - [`BlockHeader`](crate::BlockHeader) — the proposer's local clock at proposal time.
/// - [`BlockVote`](crate::BlockVote) — each voter's local clock at vote time.
///
/// Both feed into the stake-weighted calculation that produces the QC's
/// `weighted_timestamp`. Individually, a single Byzantine validator can set
/// this to any value — nothing in the consensus state machine should anchor
/// deterministic behavior on a single `ProposerTimestamp`. Use
/// [`WeightedTimestamp`] for that.
///
/// Legitimate uses:
/// - BFT liveness bounds in `on_block_header` (reject rushed/stale proposals
///   against the local validator's own clock).
/// - Local-only latency metrics (no divergence consequence).
/// - Input to stake-weighted aggregation when forming a QC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor, Default)]
#[sbor(transparent)]
pub struct ProposerTimestamp(pub u64);

impl ProposerTimestamp {
    /// Genesis / zero timestamp.
    pub const ZERO: Self = ProposerTimestamp(0);

    /// Wrap a raw ms value — callers must be producing a proposer wall-clock,
    /// not a derived / authenticated value.
    pub const fn from_millis(ms: u64) -> Self {
        ProposerTimestamp(ms)
    }

    /// Raw ms value — use at serialization / metrics boundaries only.
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ProposerTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_since_saturates_at_zero() {
        let a = WeightedTimestamp(1_000);
        let b = WeightedTimestamp(3_000);
        assert_eq!(b.elapsed_since(a), Duration::from_millis(2_000));
        assert_eq!(a.elapsed_since(b), Duration::ZERO);
    }

    #[test]
    fn plus_adds_duration() {
        let a = WeightedTimestamp(1_000);
        assert_eq!(a.plus(Duration::from_millis(500)), WeightedTimestamp(1_500));
    }

    #[test]
    fn minus_saturates_at_zero() {
        let a = WeightedTimestamp(1_000);
        assert_eq!(a.minus(Duration::from_millis(300)), WeightedTimestamp(700));
        assert_eq!(a.minus(Duration::from_secs(100)), WeightedTimestamp(0));
    }
}
