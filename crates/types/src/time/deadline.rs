//! A transaction's deadline, and every window the protocol reads off it.
//!
//! A cross-shard transaction can no longer finalize anywhere past its
//! validity end plus [`MAX_FINALIZATION_DELAY`]: that instant is its
//! [`Deadline`], derived from signed content, so every shard names the
//! same one without coordinating. Everything the protocol asks about
//! the transaction afterwards — whether a delivery may still be
//! admitted, whether a cell's absence means anything, how long a leg
//! entry stands — is a [`Window`] read off that one instant, stated
//! here once rather than at each consumer. Misreading either end of any
//! of them by one term is a double spend.

use std::ops::Range;
use std::time::Duration;

use hyperscale_hbor::Hbor;

use crate::{
    EPOCH_DURATION, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE, RETENTION_HORIZON,
    TERMINAL_EVIDENCE_EPOCHS, Transaction, WeightedTimestamp,
};

/// The span past the deadline a leg entry stands, waiting on the
/// answers to the records it issued, before a fate lets its row go.
///
/// The deadline plus this window is pinned to
/// [`TERMINAL_EVIDENCE_EPOCHS`] windows, so an entry stands exactly as
/// long as the reshape evidence a departure is judged by stays readable.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(
    EPOCH_DURATION.as_secs() * TERMINAL_EVIDENCE_EPOCHS - MAX_FINALIZATION_DELAY.as_secs(),
);

/// The span past the deadline a member whose verdict a sibling shares
/// may still state, before an abort ends it.
///
/// The deadline's own [`MAX_FINALIZATION_DELAY`] term budgets a core
/// block's commit and propagation, not the stating of what it ran; this
/// covers a view change, a late provision and a stating backlog. A
/// duration rather than a count of windows: what it waits on does not
/// scale with epoch length.
pub const STATING_GRACE: Duration = Duration::from_mins(5);

/// How long a transaction's evidence outlives the moment it was
/// committed: everything its shape reaches, ends by.
///
/// A transaction committed at `T` states a validity end at most one
/// [`MAX_VALIDITY_RANGE`] on and a deadline one
/// [`MAX_FINALIZATION_DELAY`] past that — [`RETENTION_HORIZON`] in
/// total. A leg entry stands one [`CLAIM_WINDOW`] further, which is
/// where a record a reshape successor inherits stops being decidable.
/// Past this nothing of the transaction can be asked or answered.
///
/// A duration rather than a count of windows, because none of its terms
/// is a window: a chain that runs shorter epochs measures the same span
/// in more of them.
pub const TRANSACTION_EVIDENCE_HORIZON: Duration =
    Duration::from_secs(RETENTION_HORIZON.as_secs() + CLAIM_WINDOW.as_secs());

/// The moment past which a transaction can no longer finalize anywhere:
/// its validity end plus [`MAX_FINALIZATION_DELAY`].
///
/// Before it a core may still legitimately commit — admission fences
/// the core at `block_wt < validity_end`, and the extra term is the
/// propagation budget for that block to be committed and served, not
/// admission slack. Also the anchor every absence question is asked
/// from, so a voter holding a name's deadline finds each window without
/// the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Hbor)]
#[hbor(transparent)]
pub struct Deadline(WeightedTimestamp);

impl Deadline {
    /// The deadline of a transaction whose validity ends at
    /// `validity_end`.
    #[must_use]
    pub fn of(validity_end: WeightedTimestamp) -> Self {
        Self(validity_end.plus(MAX_FINALIZATION_DELAY))
    }

    /// The deadline `tx`'s own validity range fixes.
    #[must_use]
    pub fn of_transaction(tx: &Transaction) -> Self {
        Self::of(tx.validity_range().end_timestamp_exclusive)
    }

    /// The instant itself.
    #[must_use]
    pub const fn at(self) -> WeightedTimestamp {
        self.0
    }

    /// The validity end the deadline was derived from.
    #[must_use]
    pub fn validity_end(self) -> WeightedTimestamp {
        self.0.minus(MAX_FINALIZATION_DELAY)
    }

    /// Whether `clock` sits at or past the deadline.
    #[must_use]
    pub fn passed(self, clock: WeightedTimestamp) -> bool {
        clock >= self.0
    }
}

/// A half-open window read off a transaction's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Window {
    /// Where a core's committed cell being absent proves only that the
    /// core never included the transaction: from the deadline, since
    /// before it the core may still commit, to the cell's own sweep two
    /// [`MAX_VALIDITY_RANGE`]s on, past which a proof is a true proof of
    /// a cell that was present. A core that included and refused the
    /// transaction keeps its cell and answers its producers with a
    /// `Never` instead.
    ///
    /// Two ranges, and they are not one span counted twice. A core may
    /// abandon anywhere inside the one range its abandonment is
    /// admissible in; reading the absence a core that never included
    /// the transaction leaves is a probe at a counterpart's own anchor,
    /// which needs a range of its own.
    Core,
    /// Where a leg entry stands: from the deadline to one
    /// [`CLAIM_WINDOW`] on, past which no evidence that could decide the
    /// leg can still be taken.
    ///
    /// A liveness bound rather than a soundness one, and the only
    /// crossing rule left that is a span at all: every verdict is a
    /// presence, which answers at whatever anchor it was taken. What
    /// this sizes is how long the chain waits on a leg's records.
    LegEntry,
    /// Where a member in flight whose verdict a sibling shares may still
    /// state: from the deadline to one [`STATING_GRACE`] on. Past it the
    /// member has said nothing a sibling could read, and an abort ends
    /// it.
    Stating,
}

impl Window {
    /// The window, for a transaction with this `deadline`.
    #[must_use]
    pub fn of(self, deadline: Deadline) -> Range<WeightedTimestamp> {
        let at = deadline.at();
        match self {
            Self::Core => at..at.plus(MAX_VALIDITY_RANGE * 2),
            Self::LegEntry => at..at.plus(CLAIM_WINDOW),
            Self::Stating => at..at.plus(STATING_GRACE),
        }
    }
}

/// The last anchor a block may carry `tx` at, which is how long an index
/// refusing a second inclusion has to remember it.
///
/// The deadline, for every transaction and every shape. A transaction is
/// admissible while its validity range contains the anchor, and never
/// past it: an owed crossing's delivery is its consumer's commit fold,
/// which admits no transaction at all.
#[must_use]
pub fn admissible_until(tx: &Transaction) -> WeightedTimestamp {
    Deadline::of_transaction(tx).at()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_vm_types::COMMITTED_GRACE_MS;

    use super::{CLAIM_WINDOW, Deadline, STATING_GRACE, Window};
    use crate::{MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE, WeightedTimestamp};

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
    }

    /// Whether an absence of a core member's committed cell read at
    /// `read_at` answers for a transaction with this `deadline`.
    fn answers_at(read_at: WeightedTimestamp, deadline: Deadline) -> bool {
        Window::Core.of(deadline).contains(&read_at)
    }

    /// Every transaction is admissible to its own deadline, whatever it
    /// carries.
    ///
    /// The index refusing a second inclusion is a tier that deep and no
    /// deeper. A delivery consuming an owed crossing is admissible past
    /// it, and what lets it in is the record proved present in the block
    /// that admits it — a licence the body cannot be asked about, which
    /// is why this reads nothing but the window.
    #[test]
    fn every_transaction_is_admissible_to_its_own_deadline() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        assert_eq!(deadline.at(), validity_end.plus(MAX_FINALIZATION_DELAY));
        assert_eq!(deadline.validity_end(), validity_end);
        assert!(deadline.passed(deadline.at()));
        assert!(!deadline.passed(deadline.at().minus(Duration::from_millis(1))));
    }

    /// The deadline is a boundary, and an absence answers on one side of
    /// it and not the other — one millisecond either way.
    #[test]
    fn the_absence_anchor_is_inclusive_at_the_deadline_and_not_before() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        assert_eq!(deadline.at(), validity_end.plus(MAX_FINALIZATION_DELAY));
        assert_eq!(deadline.validity_end(), validity_end);

        let at = deadline.at();
        assert!(!answers_at(at.minus(Duration::from_millis(1)), deadline));
        assert!(answers_at(at, deadline));
        assert!(answers_at(at.plus(Duration::from_millis(1)), deadline));
        assert!(!deadline.passed(at.minus(Duration::from_millis(1))));
        assert!(deadline.passed(at));
    }

    /// The core window closes where the committed cell may be swept: a
    /// proof there is a true proof of a cell that was present, so it
    /// licenses nothing.
    ///
    /// Short of it an absence answers at any anchor, a whole range past
    /// the last moment a core may abandon in, so a core member whose
    /// question lands late still reads what a sibling that never
    /// included the transaction left.
    #[test]
    fn an_absence_answers_a_range_past_the_last_moment_a_core_may_refuse() {
        let deadline = Deadline::of(ms(60_000));
        // An abandonment is admissible for one range from the deadline.
        let last_refusal = deadline.at().plus(MAX_VALIDITY_RANGE);
        assert!(
            answers_at(last_refusal, deadline),
            "an absence at the last moment a core may abandon in is one a sibling can read",
        );
        assert!(
            answers_at(
                last_refusal
                    .plus(MAX_VALIDITY_RANGE)
                    .minus(Duration::from_millis(1)),
                deadline,
            ),
            "and stays readable for a range past it",
        );
        assert!(
            !answers_at(last_refusal.plus(MAX_VALIDITY_RANGE), deadline),
            "and no longer, which is where the cell sweeps",
        );
    }

    #[test]
    fn an_absence_licenses_nothing_once_the_cell_it_asks_about_may_be_swept() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        let core = Window::Core.of(deadline);
        assert_eq!(
            core.end,
            validity_end.plus(Duration::from_millis(COMMITTED_GRACE_MS)),
            "which is where the committed cell it asks about is swept",
        );
        assert_eq!(
            core.end.elapsed_since(core.start),
            MAX_VALIDITY_RANGE * 2,
            "one range for the refusal to land in, one to read the absence it leaves",
        );
        assert!(answers_at(
            core.end.minus(Duration::from_millis(1)),
            deadline
        ));
        assert!(!answers_at(core.end, deadline));
        assert!(!answers_at(
            core.end.plus(Duration::from_secs(60)),
            deadline
        ));

        assert_eq!(
            Window::LegEntry.of(deadline),
            core.start..deadline.at().plus(CLAIM_WINDOW),
            "a leg entry stands one claim window past the deadline",
        );
    }

    /// Each window against the figure it is derived from, not against
    /// the other.
    ///
    /// Both open at the deadline and neither is the other's: a leg entry
    /// stands a [`CLAIM_WINDOW`] past it, where a core's absence answers
    /// for one range to refuse in and one to read the refusal. Asserting one
    /// against the other would make a change to either look like a
    /// change to both.
    #[test]
    fn each_window_is_read_off_its_own_figure() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);

        assert_eq!(
            Window::LegEntry.of(deadline),
            deadline.at()..deadline.at().plus(CLAIM_WINDOW),
            "a leg entry stands one claim window past the deadline",
        );
        assert_eq!(
            Window::Core.of(deadline),
            deadline.at()..deadline.at().plus(MAX_VALIDITY_RANGE * 2),
            "a core's absence answers for one range to refuse in and one to read it",
        );
        assert_eq!(
            Window::Stating.of(deadline),
            deadline.at()..deadline.at().plus(STATING_GRACE),
            "a shared member may state one grace past the deadline",
        );
    }

    /// A probe at the validity end itself licenses nothing: a core block
    /// admitted a millisecond before it is inside the propagation budget
    /// and may still commit. The gap is the whole of the delay, so the
    /// latest legitimately admitted core block has that long to land.
    #[test]
    fn a_probe_at_the_validity_end_is_inside_the_propagation_budget() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        let latest_core_admission = validity_end.minus(Duration::from_millis(1));
        assert!(!answers_at(validity_end, deadline));
        assert!(
            deadline.at().elapsed_since(latest_core_admission) > MAX_FINALIZATION_DELAY,
            "the anchor sits a full delay past the last block the core could admit",
        );
    }
}
