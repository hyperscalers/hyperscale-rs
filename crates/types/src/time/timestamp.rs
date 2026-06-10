//! Typed timestamps for consensus and proposal wall-clocks.
//!
//! Three distinct timestamp categories share millisecond representation but
//! carry very different trust guarantees:
//!
//! - [`WeightedTimestamp`] — BFT-authenticated stake-weighted median produced
//!   on every QC. Safe to anchor consensus deadlines on; all validators derive
//!   the same value for a given committed block.
//! - [`ProposerTimestamp`] — the proposer's local wall-clock embedded in a
//!   block header at proposal time. Not authenticated; used only for shard consensus
//!   liveness bounds (rushed/stale header rejection) and local-only latency
//!   metrics. Must never feed a deterministic timeout — that's what
//!   `WeightedTimestamp` is for.
//! - [`LocalTimestamp`] — this validator's own monotonic wall-clock,
//!   minted at the IO boundary. Used for view-change timers, IO retry
//!   backoff, and proposer-skew checks. Never serialized; never compared
//!   against `WeightedTimestamp` (the type system forbids it). Boundary
//!   crossings to other timestamp types are explicit per-method casts.
//!
//! All three wrap `u64` ms. `WeightedTimestamp` and `ProposerTimestamp` are
//! `#[sbor(transparent)]` (they ride on QCs and headers); `LocalTimestamp`
//! is local-only and deliberately not wired.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use sbor::prelude::*;

/// BFT-authenticated block timestamp in milliseconds.
///
/// Each QC carries the mean of the timestamps of the 2f+1 votes that formed
/// it (every node is one vote), clamped so it never precedes the parent QC's
/// value. Two aggregators collecting different quorum subsets for the same
/// block can therefore produce different means, and the field rides outside
/// the QC's signed message — so a QC's own `weighted_timestamp` is neither
/// unique nor unforgeable on its own. The canonical, hash-pinned timestamp
/// for a block is the one its committing child embeds as `parent_qc`: anchor
/// deterministic deadlines on `header.parent_qc().weighted_timestamp()`,
/// never on a received block's own `qc().weighted_timestamp()`.
///
/// This is the only timestamp type safe to anchor consensus deadlines on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor, Default)]
#[sbor(transparent)]
pub struct WeightedTimestamp(u64);

impl WeightedTimestamp {
    /// Genesis / zero timestamp.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw ms value. Prefer
    /// [`QuorumCertificate::weighted_timestamp`](crate::QuorumCertificate::weighted_timestamp)
    /// at produce sites.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Raw ms value — use sparingly, only at serialization / FFI boundaries
    /// (log fields, metrics, wire format that hasn't been migrated yet).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Duration elapsed between two weighted timestamps, saturating at zero.
    ///
    /// Reads as "how long after `earlier` was `self` produced". Used for
    /// deadline checks like `committed.elapsed_since(wave_start) >= WAVE_TIMEOUT`.
    #[must_use]
    pub const fn elapsed_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    /// Return `self + duration`, saturating on overflow.
    #[must_use]
    pub fn plus(self, duration: Duration) -> Self {
        let add = duration.as_millis().try_into().unwrap_or(u64::MAX);
        Self(self.0.saturating_add(add))
    }

    /// Return `self - duration`, saturating at zero.
    ///
    /// Used for cutoff computations: `committed.minus(retention)` gives the
    /// lower edge of the retention window.
    #[must_use]
    pub fn minus(self, duration: Duration) -> Self {
        let sub = duration.as_millis().try_into().unwrap_or(u64::MAX);
        Self(self.0.saturating_sub(sub))
    }
}

impl Display for WeightedTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// The largest epoch-boundary weighted timestamp strictly below `wt`
/// (`k × epoch_duration_ms` for the greatest `k ≥ 1`), or `None` when no
/// boundary lies below it.
#[must_use]
pub const fn epoch_boundary_below(wt: u64, epoch_duration_ms: u64) -> Option<u64> {
    if epoch_duration_ms == 0 || wt == 0 {
        return None;
    }
    let k = (wt - 1) / epoch_duration_ms;
    if k == 0 {
        None
    } else {
        Some(k * epoch_duration_ms)
    }
}

/// Whether a block is its shard's epoch-boundary crossing.
///
/// The first block across some `k × epoch_duration_ms` cut: the block's
/// certifying QC (`qc_wt`) sits past a boundary that the block's parent
/// QC (`parent_qc_wt`) sits at or before. Pure over the chain's epoch
/// duration, so the beacon fold and the shard-side checkpoint trigger
/// apply the identical test.
#[must_use]
pub const fn is_epoch_crossing(
    parent_qc_wt: WeightedTimestamp,
    qc_wt: WeightedTimestamp,
    epoch_duration_ms: u64,
) -> bool {
    match epoch_boundary_below(qc_wt.as_millis(), epoch_duration_ms) {
        Some(cut) => parent_qc_wt.as_millis() <= cut,
        None => false,
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
/// - shard consensus liveness bounds in `on_block_header` (reject rushed/stale proposals
///   against the local validator's own clock).
/// - Local-only latency metrics (no divergence consequence).
/// - Input to stake-weighted aggregation when forming a QC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor, Default)]
#[sbor(transparent)]
pub struct ProposerTimestamp(u64);

impl ProposerTimestamp {
    /// Genesis / zero timestamp.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw ms value — callers must be producing a proposer wall-clock,
    /// not a derived / authenticated value.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Mint a `ProposerTimestamp` from this validator's local wall-clock.
    /// The single legitimate boundary cast: a proposer / voter encodes its
    /// own `LocalTimestamp` into the header / vote payload, where the
    /// stake-weighted aggregation will later combine 2f+1 of them into a
    /// `WeightedTimestamp`. No other `LocalTimestamp` → `ProposerTimestamp`
    /// path exists.
    #[must_use]
    pub const fn from_local(local: LocalTimestamp) -> Self {
        Self(local.as_millis())
    }

    /// Raw ms value — use at serialization / metrics boundaries only.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl Display for ProposerTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Single-validator monotonic wall-clock timestamp in milliseconds.
///
/// Minted by the IO boundary (production `io_loop` or simulator driver) and
/// fed into state machines via `StateMachine::set_time`. Anchors view-change
/// timers, IO retry backoff, and the proposer-skew check on incoming
/// headers — every use case where the question is "how much local
/// wall-clock has passed?", not "what time do all validators agree it is?".
///
/// Constructed once-per-process from `(SystemTime::now(), Instant::now())`
/// at `io_loop` init: every subsequent `LocalTimestamp::now()` reads as
/// `origin_system_ms + (Instant::now() - origin_instant)`. This gives ms
/// values comparable in unit (and roughly in epoch) with `WeightedTimestamp`
/// and `ProposerTimestamp` while preserving `Instant`-grade monotonicity
/// against NTP steps.
///
/// Deliberately has no `BasicSbor` derive and no `From`/`Into` to/from
/// the shard consensus-authenticated timestamp types. Cross-clock comparisons require
/// an explicit method, so the question "which clock am I anchoring on?"
/// surfaces at every boundary instead of being lost to coercion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct LocalTimestamp(u64);

impl LocalTimestamp {
    /// Process-start / zero timestamp.
    pub const ZERO: Self = Self(0);

    /// Wrap a raw ms value. Production callers should mint via the
    /// `io_loop`'s clock origin; tests and simulator drivers may use this
    /// directly.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Raw ms value — use at the proposer-skew boundary (where it's
    /// compared against `ProposerTimestamp::as_millis()`) or at metrics
    /// emission. Never feed this into a `WeightedTimestamp` constructor.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Duration elapsed between two local timestamps, saturating at zero.
    ///
    /// Reads as "how long after `earlier` was `self` produced". Used for
    /// view-change deadline checks like
    /// `now.elapsed_since(last_leader_activity) >= timeout`.
    #[must_use]
    pub const fn elapsed_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    /// Saturating subtraction returning a `Duration`. Equivalent to
    /// `elapsed_since` but reads naturally at sites that frame the
    /// computation as "now minus origin".
    #[must_use]
    pub const fn saturating_sub(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    /// Return `self + duration`, saturating on overflow.
    #[must_use]
    pub fn plus(self, duration: Duration) -> Self {
        let add = duration.as_millis().try_into().unwrap_or(u64::MAX);
        Self(self.0.saturating_add(add))
    }

    /// Return `self - duration`, saturating at zero.
    #[must_use]
    pub fn minus(self, duration: Duration) -> Self {
        let sub = duration.as_millis().try_into().unwrap_or(u64::MAX);
        Self(self.0.saturating_sub(sub))
    }
}

impl Display for LocalTimestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_since_saturates_at_zero() {
        let a = WeightedTimestamp::from_millis(1_000);
        let b = WeightedTimestamp::from_millis(3_000);
        assert_eq!(b.elapsed_since(a), Duration::from_secs(2));
        assert_eq!(a.elapsed_since(b), Duration::ZERO);
    }

    #[test]
    fn plus_adds_duration() {
        let a = WeightedTimestamp::from_millis(1_000);
        assert_eq!(
            a.plus(Duration::from_millis(500)),
            WeightedTimestamp::from_millis(1_500)
        );
    }

    #[test]
    fn minus_saturates_at_zero() {
        let a = WeightedTimestamp::from_millis(1_000);
        assert_eq!(
            a.minus(Duration::from_millis(300)),
            WeightedTimestamp::from_millis(700)
        );
        assert_eq!(
            a.minus(Duration::from_secs(100)),
            WeightedTimestamp::from_millis(0)
        );
    }

    #[test]
    fn local_elapsed_since_saturates_at_zero() {
        let a = LocalTimestamp::from_millis(1_000);
        let b = LocalTimestamp::from_millis(3_000);
        assert_eq!(b.elapsed_since(a), Duration::from_secs(2));
        assert_eq!(a.elapsed_since(b), Duration::ZERO);
    }

    #[test]
    fn local_saturating_sub_matches_elapsed_since() {
        let a = LocalTimestamp::from_millis(500);
        let b = LocalTimestamp::from_millis(2_500);
        assert_eq!(b.saturating_sub(a), b.elapsed_since(a));
        assert_eq!(a.saturating_sub(b), Duration::ZERO);
    }

    #[test]
    fn local_plus_adds_duration() {
        let a = LocalTimestamp::from_millis(1_000);
        assert_eq!(
            a.plus(Duration::from_millis(500)),
            LocalTimestamp::from_millis(1_500)
        );
    }

    #[test]
    fn local_minus_saturates_at_zero() {
        let a = LocalTimestamp::from_millis(1_000);
        assert_eq!(
            a.minus(Duration::from_millis(300)),
            LocalTimestamp::from_millis(700)
        );
        assert_eq!(
            a.minus(Duration::from_secs(100)),
            LocalTimestamp::from_millis(0)
        );
    }

    #[test]
    fn local_orders_by_ms() {
        assert!(LocalTimestamp::from_millis(1_000) < LocalTimestamp::from_millis(2_000));
        assert_eq!(
            LocalTimestamp::from_millis(1_000),
            LocalTimestamp::from_millis(1_000)
        );
    }

    #[test]
    fn local_plus_saturates_on_overflow() {
        let near_max = LocalTimestamp::from_millis(u64::MAX - 10);
        assert_eq!(
            near_max.plus(Duration::from_secs(1)),
            LocalTimestamp::from_millis(u64::MAX)
        );
    }

    #[test]
    fn local_zero_is_default() {
        assert_eq!(LocalTimestamp::default(), LocalTimestamp::ZERO);
        assert_eq!(LocalTimestamp::ZERO.as_millis(), 0);
    }
}
