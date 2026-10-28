//! Epoch-window arithmetic over the chain's weighted-time grid.
//!
//! One origin (the genesis instant) and one window length
//! (`epoch_duration_ms`) partition weighted time into fixed
//! `[origin + k·dur, origin + (k+1)·dur)` windows, one per [`Epoch`]. Every consumer that maps
//! between a [`WeightedTimestamp`] and an [`Epoch`] — the topology schedule's
//! committee lookup, the beacon fold's boundary detection, the merge/split cut
//! composition, the wall-clock pacing — resolves it here, so the two edge
//! semantics stay consistent:
//!
//! - **Window membership** ([`epoch_for`](EpochWindows::epoch_for)): the
//!   boundary instant `origin + k·dur` belongs to the *later* window `k`.
//! - **Boundary crossing** ([`boundary_below`](EpochWindows::boundary_below) /
//!   [`is_crossing`](EpochWindows::is_crossing)): a QC attested at exactly
//!   `origin + k·dur` has *not yet* crossed boundary `k` (strictly below).
//!
//! These differ at the exact boundary instant, so a crossing test must never
//! be rebuilt as `epoch_for(parent) != epoch_for(qc)` — it would diverge from
//! the strictly-below form at `wt = origin + k·dur`. That form, here, is
//! canonical.
//!
//! Timestamps are Unix milliseconds; the origin is the only place genesis
//! enters epoch numbering. A timestamp before it is in the genesis window.

use std::ops::Range;

use super::timestamp::WeightedTimestamp;
use crate::{Epoch, RETENTION_HORIZON, TERMINAL_EVIDENCE_EPOCHS};

/// The chain's epoch-window grid: weighted time from the genesis instant
/// partitioned into fixed `epoch_duration_ms` windows, one per [`Epoch`].
///
/// A zero duration is the single-committee / pre-rotation case: every
/// timestamp folds to [`Epoch::GENESIS`] and no boundary crossing exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochWindows {
    origin_ms: u64,
    epoch_duration_ms: u64,
}

impl EpochWindows {
    /// Build a grid whose genesis window opens at `origin_ms` and whose
    /// windows are `epoch_duration_ms` long.
    #[must_use]
    pub const fn new(origin_ms: u64, epoch_duration_ms: u64) -> Self {
        Self {
            origin_ms,
            epoch_duration_ms,
        }
    }

    /// The instant the genesis window opens.
    #[must_use]
    pub const fn origin(self) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(self.origin_ms)
    }

    /// Window length in milliseconds. Zero means a single fixed window.
    #[must_use]
    pub const fn epoch_duration_ms(self) -> u64 {
        self.epoch_duration_ms
    }

    /// Epoch whose window contains `wt` —
    /// `floor((wt − origin) / epoch_duration_ms)`. A zero duration, or a
    /// timestamp before the origin, folds to [`Epoch::GENESIS`].
    #[must_use]
    pub const fn epoch_for(self, wt: WeightedTimestamp) -> Epoch {
        match self.since_origin(wt).checked_div(self.epoch_duration_ms) {
            Some(epoch) => Epoch::new(epoch),
            None => Epoch::GENESIS,
        }
    }

    /// The half-open weighted-time window
    /// `[origin + epoch·dur, origin + (epoch+1)·dur)` that `epoch` governs.
    /// `.start` is the window's opening instant; `.end` is the cut at its
    /// close (the opening of the next window). Both saturate at
    /// [`u64::MAX`].
    #[must_use]
    pub const fn window_of(self, epoch: Epoch) -> Range<WeightedTimestamp> {
        let start = self
            .origin_ms
            .saturating_add(epoch.inner().saturating_mul(self.epoch_duration_ms));
        let end = self.origin_ms.saturating_add(
            epoch
                .inner()
                .saturating_add(1)
                .saturating_mul(self.epoch_duration_ms),
        );
        WeightedTimestamp::from_millis(start)..WeightedTimestamp::from_millis(end)
    }

    /// A terminating leaf's settled-transaction window floor: the opening
    /// of the epoch its reshape was admitted, backed off by
    /// [`RETENTION_HORIZON`] to cover a tick that finalized against the
    /// fence just after it armed but executed up to a full tick lifetime
    /// earlier.
    #[must_use]
    pub fn settled_window_floor(self, admitted: Epoch) -> WeightedTimestamp {
        self.window_of(admitted).start.minus(RETENTION_HORIZON)
    }

    /// The instant terminal evidence anchored at `anchor` stops being
    /// answerable: [`TERMINAL_EVIDENCE_EPOCHS`] windows past it.
    ///
    /// The anchor always falls on a window boundary, so this is the close
    /// of the window that many later.
    #[must_use]
    pub const fn terminal_evidence_expiry(self, anchor: WeightedTimestamp) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(
            anchor.as_millis().saturating_add(
                self.epoch_duration_ms
                    .saturating_mul(TERMINAL_EVIDENCE_EPOCHS),
            ),
        )
    }

    /// The instant a departed shard's terminal evidence stops being
    /// readable: [`TERMINAL_EVIDENCE_EPOCHS`] windows past the epoch the
    /// beacon stamped its handoff complete (successors produced past
    /// genesis). Every consumer of a departed shard's settled set derives
    /// its bound here — the beacon retaining the terminal boundary
    /// record, the acquisition driving the fetch, and the split-boundary
    /// fence judging a claim — so none of them stops reading while
    /// another still expects an answer. Counted from the handoff rather
    /// than the cut, because evidence is only acquirable once the
    /// boundary has folded and the network has delivered, and the
    /// handoff's completion is the one deterministic milestone bounding
    /// both.
    #[must_use]
    pub const fn handoff_evidence_expiry(self, handoff_complete: Epoch) -> WeightedTimestamp {
        self.terminal_evidence_expiry(self.window_of(handoff_complete).end)
    }

    /// The largest epoch boundary strictly below `wt`, as `(epoch, cut)` where
    /// `cut = origin + epoch·dur` is the boundary instant and `epoch` is the
    /// window it opens. `None` when no boundary lies below `wt` — it falls in
    /// the genesis window or before it, or the duration is zero.
    #[must_use]
    pub(crate) const fn boundary_below(
        self,
        wt: WeightedTimestamp,
    ) -> Option<(Epoch, WeightedTimestamp)> {
        let since = self.since_origin(wt);
        if self.epoch_duration_ms == 0 || since == 0 {
            return None;
        }
        let k = (since - 1) / self.epoch_duration_ms;
        if k == 0 {
            None
        } else {
            Some((
                Epoch::new(k),
                WeightedTimestamp::from_millis(self.origin_ms + k * self.epoch_duration_ms),
            ))
        }
    }

    /// Milliseconds from the origin to `wt`, zero for a timestamp before it.
    const fn since_origin(self, wt: WeightedTimestamp) -> u64 {
        wt.as_millis().saturating_sub(self.origin_ms)
    }

    /// Whether a block certified at `qc_wt` is the first across an epoch
    /// boundary: a boundary lies at or below `qc_wt` that the block's parent
    /// (`parent_qc_wt`) sits at or before. The boundary instant itself counts
    /// as *not yet crossed*, so a chain pausing exactly on a cut crosses
    /// only once it produces a block past it.
    #[must_use]
    pub const fn is_crossing(
        self,
        parent_qc_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> bool {
        match self.boundary_below(qc_wt) {
            Some((_, cut)) => parent_qc_wt.as_millis() <= cut.as_millis(),
            None => false,
        }
    }

    /// The epoch boundary `qc_wt` crosses relative to `parent_qc_wt`, if any —
    /// [`is_crossing`](Self::is_crossing) with the crossed epoch surfaced for
    /// callers that key on it.
    #[must_use]
    pub const fn crossing_epoch(
        self,
        parent_qc_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> Option<Epoch> {
        match self.boundary_below(qc_wt) {
            Some((epoch, cut)) => {
                if parent_qc_wt.as_millis() <= cut.as_millis() {
                    Some(epoch)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// The epoch a chain's terminal contributes for: the boundary its
    /// parent QC crossed, the largest strictly below `parent_qc_wt`. The
    /// terminal is the first block whose parent QC lands past the cut, so
    /// the block before it is the crossing, and this is the epoch
    /// [`crossing_epoch`](Self::crossing_epoch) names for it.
    #[must_use]
    pub const fn terminal_crossing_epoch(self, parent_qc_wt: WeightedTimestamp) -> Option<Epoch> {
        match self.boundary_below(parent_qc_wt) {
            Some((epoch, _)) => Some(epoch),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUR: u64 = 1_000;

    fn wt(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    #[test]
    fn epoch_for_floors_and_owns_the_boundary_instant() {
        let w = EpochWindows::new(0, DUR);
        assert_eq!(w.epoch_for(wt(0)), Epoch::GENESIS);
        assert_eq!(w.epoch_for(wt(999)), Epoch::GENESIS);
        // The boundary instant belongs to the later window.
        assert_eq!(w.epoch_for(wt(1_000)), Epoch::new(1));
        assert_eq!(w.epoch_for(wt(2_500)), Epoch::new(2));
    }

    #[test]
    fn window_of_brackets_the_epoch() {
        let w = EpochWindows::new(0, DUR);
        let g = w.window_of(Epoch::GENESIS);
        assert_eq!(g.start, wt(0));
        assert_eq!(g.end, wt(1_000));
        let two = w.window_of(Epoch::new(2));
        assert_eq!(two.start, wt(2_000));
        assert_eq!(two.end, wt(3_000));
        // Membership and bracketing agree on the half-open edges.
        assert_eq!(w.epoch_for(two.start), Epoch::new(2));
        assert_eq!(w.epoch_for(two.end), Epoch::new(3));
    }

    #[test]
    fn boundary_below_is_strictly_below() {
        let w = EpochWindows::new(0, DUR);
        assert_eq!(w.boundary_below(wt(0)), None);
        // Inside the genesis window there is no boundary below.
        assert_eq!(w.boundary_below(wt(999)), None);
        // The boundary instant itself has no boundary *strictly* below it.
        assert_eq!(w.boundary_below(wt(1_000)), None);
        // Just past it, the boundary below is the one it crossed.
        assert_eq!(
            w.boundary_below(wt(1_001)),
            Some((Epoch::new(1), wt(1_000)))
        );
        // Still epoch 1's boundary right up to (but not at) the next instant.
        assert_eq!(
            w.boundary_below(wt(1_999)),
            Some((Epoch::new(1), wt(1_000)))
        );
        assert_eq!(
            w.boundary_below(wt(2_000)),
            Some((Epoch::new(1), wt(1_000)))
        );
        assert_eq!(
            w.boundary_below(wt(2_001)),
            Some((Epoch::new(2), wt(2_000)))
        );
    }

    #[test]
    fn crossing_is_strict_at_the_boundary_instant() {
        let w = EpochWindows::new(0, DUR);
        // The footgun: a block sitting exactly on the boundary with its parent
        // inside the prior window has NOT crossed. A naive `epoch_for(parent)
        // != epoch_for(qc)` test would diverge here (0 != 1 → crossing), so it
        // must never be substituted for the strictly-below form.
        assert!(!w.is_crossing(wt(999), wt(1_000)));
        assert_eq!(w.crossing_epoch(wt(999), wt(1_000)), None);
        // One step past the boundary, with the parent at or before the cut, is
        // the crossing of epoch 1.
        assert!(w.is_crossing(wt(1_000), wt(1_001)));
        assert_eq!(w.crossing_epoch(wt(1_000), wt(1_001)), Some(Epoch::new(1)));
        assert!(w.is_crossing(wt(900), wt(1_500)));
        assert_eq!(w.crossing_epoch(wt(900), wt(1_500)), Some(Epoch::new(1)));
        // Both inside the same window: no crossing.
        assert!(!w.is_crossing(wt(1_100), wt(1_500)));
        assert_eq!(w.crossing_epoch(wt(1_100), wt(1_500)), None);
    }

    #[test]
    fn the_origin_opens_the_genesis_window() {
        const ORIGIN: u64 = 1_700_000_000_000;
        let w = EpochWindows::new(ORIGIN, DUR);
        // Before the origin is the genesis window; nothing underflows.
        assert_eq!(w.epoch_for(wt(0)), Epoch::GENESIS);
        assert_eq!(w.epoch_for(wt(ORIGIN - 1)), Epoch::GENESIS);
        assert_eq!(w.epoch_for(wt(ORIGIN + 999)), Epoch::GENESIS);
        assert_eq!(w.epoch_for(wt(ORIGIN + 1_000)), Epoch::new(1));
        assert_eq!(w.window_of(Epoch::new(2)).start, wt(ORIGIN + 2_000));
        assert_eq!(w.window_of(Epoch::new(2)).end, wt(ORIGIN + 3_000));
        assert_eq!(w.boundary_below(wt(ORIGIN)), None);
        assert_eq!(w.boundary_below(wt(ORIGIN - 5)), None);
        assert_eq!(w.boundary_below(wt(ORIGIN + 1_000)), None);
        assert_eq!(
            w.boundary_below(wt(ORIGIN + 1_001)),
            Some((Epoch::new(1), wt(ORIGIN + 1_000)))
        );
        assert!(!w.is_crossing(wt(ORIGIN + 999), wt(ORIGIN + 1_000)));
        assert!(w.is_crossing(wt(ORIGIN + 1_000), wt(ORIGIN + 1_001)));
        // Epoch numbering agrees with a genesis-relative grid at every instant.
        let relative = EpochWindows::new(0, DUR);
        for at in [0, 1, 999, 1_000, 1_001, 7_654_321] {
            assert_eq!(w.epoch_for(wt(ORIGIN + at)), relative.epoch_for(wt(at)));
        }
    }

    #[test]
    fn zero_duration_folds_to_genesis_with_no_boundaries() {
        let w = EpochWindows::new(0, 0);
        assert_eq!(w.epoch_for(wt(123_456)), Epoch::GENESIS);
        assert_eq!(w.boundary_below(wt(123_456)), None);
        assert!(!w.is_crossing(wt(0), wt(123_456)));
        assert_eq!(w.crossing_epoch(wt(0), wt(123_456)), None);
    }
}
