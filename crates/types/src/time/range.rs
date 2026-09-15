//! Half-open `[start_timestamp_inclusive, end_timestamp_exclusive)` range
//! over [`WeightedTimestamp`] used as a transaction validity window.
//!
//! Anchored on the parent QC's `weighted_timestamp` at every check site:
//! a tx may appear in a block iff
//! `range.start_timestamp_inclusive <= block.qc.weighted_timestamp
//!  < range.end_timestamp_exclusive`. The "parent QC" anchor means the
//! check uses the QC the proposer attached to this block, not the QC
//! that will eventually certify this block (which doesn't exist at vote
//! time). The one-block lag — the certifying QC may carry a slightly
//! later `weighted_timestamp` than the parent — is intentional, bounded,
//! and well under [`MAX_VALIDITY_RANGE`].
//!
//! Both range length and the forward edge are capped at
//! [`MAX_VALIDITY_RANGE`] so derived state (provisions, ECs, mempool
//! tombstones, dedup caches, conflict-detector entries) inherits the
//! same bound and can be dropped deterministically on every node.
//!
//! The range is judged against proposer timestamps: start inclusive,
//! end exclusive.

use std::time::Duration;

use hyperscale_hbor::Hbor;

use crate::WeightedTimestamp;

/// Hard upper bound on validity range length and forward edge from the
/// anchoring `weighted_timestamp`.
///
/// The longest a signed transaction can be anyone's business, and so the
/// term every tx-derived retention window is sized from: a transaction
/// included at the last instant of its window gets
/// [`MAX_FINALIZATION_DELAY`] beyond it to terminate, and the sum is
/// [`RETENTION_HORIZON`].
///
/// Bounded on both sides. Above by [`EPOCH_DURATION`]: an artifact that
/// outlives the committee epoch that produced it forces every successor
/// of a reshape to reach back further than the reshape itself spans.
/// Below by [`SKIP_TIMEOUT`] — a beacon skip and its recovery must not
/// expire every transaction a shard is holding — for which a small
/// multiple is the margin.
///
/// [`MAX_FINALIZATION_DELAY`]: crate::MAX_FINALIZATION_DELAY
/// [`RETENTION_HORIZON`]: crate::RETENTION_HORIZON
/// [`EPOCH_DURATION`]: crate::EPOCH_DURATION
/// [`SKIP_TIMEOUT`]: crate::SKIP_TIMEOUT
pub const MAX_VALIDITY_RANGE: Duration = Duration::from_secs(120);

/// Hard upper bound on how long a subintent may stand open.
///
/// A standing offer wants to outlive a transaction, and it may: the
/// bounds above are the *transaction* window's, and neither reaches
/// here. The reshape argument bounds artifacts a successor must read
/// from a predecessor's chain, and a subintent's window governs no such
/// artifact — it governs a nullifier cell, which is state, and state
/// migrates with its owner's prefix at every split and merge. Each
/// transaction binding an offer still carries its own
/// [`MAX_VALIDITY_RANGE`] window, so an offer signed a month ago and
/// bound today yields a transaction whose window opened today.
///
/// What a long offer does cost is a resident nullifier per unspent one,
/// for its window plus [`RETENTION_HORIZON`]. That is a state-growth
/// question rather than a correctness one.
///
/// Nothing tx-derived may be sized from this. [`RETENTION_HORIZON`] and
/// the fold window built on it retain chain artifacts — provisions,
/// execution certificates, tombstones, conflict entries — and every one
/// of them answers to [`MAX_VALIDITY_RANGE`]. Size a retention window
/// from this constant instead and a month-old offer extends the life of
/// every artifact on the chain.
///
/// [`RETENTION_HORIZON`]: crate::RETENTION_HORIZON
pub const MAX_SUBINTENT_VALIDITY_RANGE: Duration = Duration::from_hours(24 * 30);

/// Half-open `[start, end)` range of [`WeightedTimestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub struct TimestampRange {
    /// Inclusive lower bound: a tx is in-range iff `start <= ts`.
    pub start_timestamp_inclusive: WeightedTimestamp,
    /// Exclusive upper bound: a tx is in-range iff `ts < end`.
    pub end_timestamp_exclusive: WeightedTimestamp,
}

impl TimestampRange {
    /// Construct a half-open `[start, end)` range. No validation —
    /// callers can build malformed (empty/inverted) ranges; use
    /// [`Self::is_well_formed`] to check.
    #[must_use]
    pub const fn new(
        start_timestamp_inclusive: WeightedTimestamp,
        end_timestamp_exclusive: WeightedTimestamp,
    ) -> Self {
        Self {
            start_timestamp_inclusive,
            end_timestamp_exclusive,
        }
    }

    /// True iff `ts` falls inside the half-open range.
    #[must_use]
    pub fn contains(&self, ts: WeightedTimestamp) -> bool {
        self.start_timestamp_inclusive <= ts && ts < self.end_timestamp_exclusive
    }

    /// Range length, saturating at zero. Zero for malformed (empty or
    /// inverted) ranges; well-formed ranges return `end - start`.
    #[must_use]
    pub(crate) const fn length(&self) -> Duration {
        self.end_timestamp_exclusive
            .elapsed_since(self.start_timestamp_inclusive)
    }

    /// Whether the range is ordered and no longer than `cap`.
    ///
    /// The clock-free half of well-formedness: a subintent's window is
    /// held to this at derivation, where there is no anchor to check a
    /// forward edge against and none is wanted — an offer's forward edge
    /// is bounded by the transaction that binds it, whose own window
    /// [`Self::is_well_formed`] holds to the anchor.
    #[must_use]
    pub fn is_well_formed_length(&self, cap: Duration) -> bool {
        self.start_timestamp_inclusive < self.end_timestamp_exclusive && self.length() <= cap
    }

    /// The overlap of two ranges, or `None` if they share no instant.
    ///
    /// What a transaction's window becomes when it binds an offer: the
    /// tighter start, the tighter end, and a refusal when the two do not
    /// meet.
    #[must_use]
    pub fn intersect(&self, other: Self) -> Option<Self> {
        let start = self
            .start_timestamp_inclusive
            .max(other.start_timestamp_inclusive);
        let end = self
            .end_timestamp_exclusive
            .min(other.end_timestamp_exclusive);
        (start < end).then(|| Self::new(start, end))
    }

    /// Validate the range against a block's anchoring weighted timestamp:
    /// `start < end`, length within cap, and forward edge within cap of
    /// the anchor. The anchor is the parent QC's `weighted_timestamp` —
    /// see the module-level note on the one-block lag.
    #[must_use]
    pub fn is_well_formed(&self, anchor: WeightedTimestamp) -> bool {
        self.start_timestamp_inclusive < self.end_timestamp_exclusive
            && self.length() <= MAX_VALIDITY_RANGE
            && self.end_timestamp_exclusive <= anchor.plus(MAX_VALIDITY_RANGE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    #[test]
    fn contains_lower_bound_is_inclusive() {
        let r = TimestampRange::new(ts(100), ts(200));
        assert!(r.contains(ts(100)));
    }

    #[test]
    fn contains_upper_bound_is_exclusive() {
        let r = TimestampRange::new(ts(100), ts(200));
        assert!(!r.contains(ts(200)));
        assert!(r.contains(ts(199)));
    }

    #[test]
    fn contains_outside_range_is_false() {
        let r = TimestampRange::new(ts(100), ts(200));
        assert!(!r.contains(ts(99)));
        assert!(!r.contains(ts(201)));
    }

    #[test]
    fn length_returns_end_minus_start() {
        let r = TimestampRange::new(ts(100), ts(350));
        assert_eq!(r.length(), Duration::from_millis(250));
    }

    #[test]
    fn length_of_inverted_range_saturates_to_zero() {
        let r = TimestampRange::new(ts(200), ts(100));
        assert_eq!(r.length(), Duration::ZERO);
    }

    #[test]
    fn well_formed_within_caps_passes() {
        let anchor = ts(1_000_000);
        let r = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));
        assert!(r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_at_max_range_length_passes() {
        let anchor = ts(1_000_000);
        let r = TimestampRange::new(anchor, anchor.plus(MAX_VALIDITY_RANGE));
        assert!(r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_over_max_range_length_fails() {
        let anchor = ts(1_000_000);
        let r = TimestampRange::new(
            anchor,
            anchor.plus(MAX_VALIDITY_RANGE + Duration::from_millis(1)),
        );
        assert!(!r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_with_end_past_anchor_plus_cap_fails() {
        let anchor = ts(1_000_000);
        // Tight range, but its forward edge is well past `anchor + cap`.
        let far_start = anchor.plus(MAX_VALIDITY_RANGE);
        let r = TimestampRange::new(far_start, far_start.plus(Duration::from_secs(1)));
        assert!(!r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_with_start_in_past_within_length_cap_passes() {
        // `start_timestamp_inclusive` may sit before the anchor as long as the
        // range length stays within `MAX_VALIDITY_RANGE` — useful for txs
        // submitted before this block's anchor that still have headroom.
        let anchor = ts(10_000_000);
        let start = anchor.minus(Duration::from_secs(30));
        let end = anchor.plus(Duration::from_secs(30));
        let r = TimestampRange::new(start, end);
        assert!(r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_with_start_far_in_past_fails_via_length_cap() {
        // A start arbitrarily far in the past pushes range length past the
        // cap even when the forward edge is in budget.
        let anchor = ts(10_000_000);
        let r = TimestampRange::new(ts(0), anchor.plus(Duration::from_mins(1)));
        assert!(!r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_inverted_range_fails() {
        let anchor = ts(1_000_000);
        let r = TimestampRange::new(ts(200), ts(100));
        assert!(!r.is_well_formed(anchor));
    }

    #[test]
    fn well_formed_empty_range_fails() {
        let anchor = ts(1_000_000);
        let r = TimestampRange::new(ts(100), ts(100));
        assert!(!r.is_well_formed(anchor));
    }
}
