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
    EPOCH_DURATION, Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE, RETENTION_HORIZON,
    TERMINAL_EVIDENCE_EPOCHS, Transaction, WeightedTimestamp,
};

/// The span past the deadline in which a record can be disposed of at
/// all.
///
/// Two validity ranges is the floor — the span a core's absence answers
/// in, which a leg entry has to outlive or the reclaim that absence
/// licenses can never be composed.
///
/// The deadline plus this window is pinned to
/// [`TERMINAL_EVIDENCE_EPOCHS`] windows, so an entry stands exactly as
/// long as the reshape evidence a departure is judged by stays readable.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(
    EPOCH_DURATION.as_secs() * TERMINAL_EVIDENCE_EPOCHS - MAX_FINALIZATION_DELAY.as_secs(),
);

const _: () = assert!(
    CLAIM_WINDOW.as_secs() >= MAX_VALIDITY_RANGE.as_secs() * 2,
    "a leg entry stands to the close of the window a core's absence answers in",
);

/// How long a transaction's evidence outlives the moment it was
/// committed: everything its shape reaches, ends by.
///
/// A transaction committed at `T` states a validity end at most one
/// [`MAX_VALIDITY_RANGE`] on and a deadline one
/// [`MAX_FINALIZATION_DELAY`] past that — [`RETENTION_HORIZON`] in
/// total. A leg entry stands one [`CLAIM_WINDOW`] further, which is
/// where a record a reshape successor inherits stops being decidable.
/// Past this nothing of the transaction can be asked, answered or
/// reclaimed.
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
    /// this sizes is how long the chain keeps asking — floored at the
    /// span a core's absence has to be provable in, so a reclaim can be
    /// composed at all.
    LegEntry,
}

impl Window {
    /// The window, for a transaction with this `deadline`.
    #[must_use]
    pub fn of(self, deadline: Deadline) -> Range<WeightedTimestamp> {
        let at = deadline.at();
        match self {
            Self::Core => at..at.plus(MAX_VALIDITY_RANGE * 2),
            Self::LegEntry => at..at.plus(CLAIM_WINDOW),
        }
    }
}

/// The last anchor a block may carry `tx` at, which is how long an index
/// refusing a second inclusion has to remember it.
///
/// The deadline, for every transaction and every shape. A transaction is
/// admissible while its validity range contains the anchor; past that a
/// member consuming an owed crossing may still be admitted, and what
/// licenses that is the crossing's record proved present in the block
/// admitting it rather than an instant. So there is no window here, and
/// the index is a tier deep enough to refuse a second inclusion of what
/// the chain has already carried and no deeper.
///
/// A delivery is not refused by this index past the deadline, and is not
/// meant to be: nothing tombstones one, so re-admission stays open
/// indefinitely and the claim cell the delivery writes is what refuses a
/// second one. An index that tried to be that guard would have to hold
/// every committed transaction to the widest shape's window, for the
/// sake of the crossings in it.
#[must_use]
pub fn admissible_until(tx: &Transaction) -> WeightedTimestamp {
    Deadline::of_transaction(tx).at()
}

/// Which counterpart cell a probe asks about, and so which reading of
/// it answers.
///
/// Each cell is written by one execution and by nothing else, so what
/// a reading says is a property of the cell. A committed cell is
/// written at a core member's inclusion and removed by no verdict, so
/// only its absence is an answer: present, the member included the
/// transaction and answers for it itself, with a claim or a `Never`
/// beside the cell, and the cell is asked again at a newer header. A
/// claim cell
/// is written by the execution that takes the crossing, so only its
/// presence is an answer — and that holds whichever consumer wrote it.
/// A core's claim is absent while a sibling is still pending, and the
/// committed cell says whether it ever will be; a delivery's is absent
/// while the delivery has not run, and the crossing behind it is the
/// consumer's whenever it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Probed {
    /// A core member's committed cell, past the transaction's deadline:
    /// absent only where the member never included the transaction.
    Core,
    /// A consumer's claim cell: present says that consumer holds the
    /// crossing. For a core it means its certificate speaks next; for a
    /// delivery it is what lets the issuer retire the record.
    Claim,
    /// A consumer's decline cell: present says that consumer will never
    /// take the crossing, so the value is the producer's to credit back.
    ///
    /// [`Self::Claim`]'s other half, and the same shape — only a
    /// presence answers, and its absence says nothing but that the
    /// consumer has not spoken. The two are two keys under one owner, so
    /// one probe asks both and one claim carries both readings.
    Decline,
}

impl Probed {
    /// The window an *absence* of this cell is read in, `None` where an
    /// absence never answers.
    #[must_use]
    pub(crate) const fn absence_window(self) -> Option<Window> {
        match self {
            Self::Core => Some(Window::Core),
            Self::Claim | Self::Decline => None,
        }
    }

    /// Whether an *absence* taken at `probed_wt` answers this question
    /// for a transaction with this `deadline`.
    ///
    /// The window the probe anchors in. Before it the counterpart may
    /// still write the cell, and past it the sweep may have taken one
    /// that was there, so an absence outside says nothing either way.
    #[must_use]
    pub(crate) fn absence_answers_at(
        self,
        probed_wt: WeightedTimestamp,
        deadline: Deadline,
    ) -> bool {
        self.absence_window()
            .is_some_and(|window| window.of(deadline).contains(&probed_wt))
    }

    /// The earliest anchor a *presence* of this cell is asked at, for a
    /// transaction with this `deadline`, `None` where a presence never
    /// answers.
    ///
    /// A presence answers wherever it was taken, so this bounds only
    /// when the question is worth putting: a consumer's claim is there
    /// by the deadline or the consumer has not run yet.
    #[must_use]
    pub(crate) const fn presence_asked_from(self, deadline: Deadline) -> Option<WeightedTimestamp> {
        match self {
            Self::Core => None,
            Self::Claim | Self::Decline => Some(deadline.at()),
        }
    }

    /// Whether a header at `anchor_wt` is one to ask this question at,
    /// for a transaction with this `deadline`: inside the window an
    /// absence answers in, or past the point a presence is asked from.
    #[must_use]
    pub fn asks_at(self, anchor_wt: WeightedTimestamp, deadline: Deadline) -> bool {
        self.absence_answers_at(anchor_wt, deadline)
            || self
                .presence_asked_from(deadline)
                .is_some_and(|from| anchor_wt >= from)
    }

    /// What `inclusion` of the probed cell, read at `probed_wt`, says
    /// for a transaction with this `deadline`: the inclusion itself, or
    /// `None` where it says nothing.
    ///
    /// A presence is bounded by neither end of a window: the cell was
    /// written by the one execution that writes it, whenever the reading
    /// was taken. An absence has to be read inside the window its cell
    /// is still standing in, or it is a swept cell rather than a write
    /// that never happened — which is the whole of why a retirement can
    /// be licensed across a cut and a reclaim cannot. Which readings
    /// answer at all is [`Self::read`].
    #[must_use]
    pub fn answer(
        self,
        probed_wt: WeightedTimestamp,
        deadline: Deadline,
        inclusion: Inclusion,
    ) -> Option<Inclusion> {
        if matches!(inclusion, Inclusion::Absent) && !self.absence_answers_at(probed_wt, deadline) {
            return None;
        }
        self.read(inclusion)
    }

    /// What `inclusion` of the probed cell says, whatever the clock: the
    /// inclusion itself, or `None` where it says nothing.
    ///
    /// The one rule, stated once, so the prober asks only what a reading
    /// would answer and the fold reads a carried proof by the same rule
    /// whoever fetched it. A committed cell answers absent — the member
    /// never included the transaction — and present is a member that
    /// included it, whose verdict is a claim or a `Never` beside the
    /// cell. A claim and a decline answer present — each is
    /// written once by the one thing that writes it and is swept by
    /// nothing — and either absence says only that the consumer has not
    /// answered that way. A record answers present —
    /// it is written by the one execution that issues the crossing and
    /// is swept by nothing, so a presence read at any anchor is a
    /// presence — and its absence says only that the producer has
    /// disposed of it by some road, which no asker can yet name.
    ///
    /// Public because a question with no absence window has no clock to
    /// be read against, so its reader has nothing to hand
    /// [`Self::answer`] and asks this directly.
    #[must_use]
    pub const fn read(self, inclusion: Inclusion) -> Option<Inclusion> {
        match (inclusion, self) {
            (Inclusion::Present(_), Self::Claim | Self::Decline)
            | (Inclusion::Absent, Self::Core) => Some(inclusion),
            (Inclusion::Present(_), Self::Core)
            | (Inclusion::Absent, Self::Claim | Self::Decline) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_vm_types::COMMITTED_GRACE_MS;

    use super::{CLAIM_WINDOW, Deadline, Probed, Window};
    use crate::{Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE, WeightedTimestamp};

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
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

    /// The deadline is a boundary, and a reclaim is licensed on one side
    /// of it and not the other — one millisecond either way.
    #[test]
    fn the_absence_anchor_is_inclusive_at_the_deadline_and_not_before() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        assert_eq!(deadline.at(), validity_end.plus(MAX_FINALIZATION_DELAY));
        assert_eq!(deadline.validity_end(), validity_end);

        let at = deadline.at();
        assert!(!Probed::Core.absence_answers_at(at.minus(Duration::from_millis(1)), deadline));
        assert!(Probed::Core.absence_answers_at(at, deadline));
        assert!(Probed::Core.absence_answers_at(at.plus(Duration::from_millis(1)), deadline));
        assert!(!deadline.passed(at.minus(Duration::from_millis(1))));
        assert!(deadline.passed(at));
    }

    /// The core window closes where the committed cell may be swept: a
    /// proof there is a true proof of a cell that was present, so it
    /// licenses nothing.
    ///
    /// Short of it an absence answers at any anchor, a whole range past
    /// the last moment a core may abandon in, so a leg whose probe lands
    /// late still reads what a core that never included the transaction
    /// left.
    #[test]
    fn an_absence_answers_a_range_past_the_last_moment_a_core_may_refuse() {
        let deadline = Deadline::of(ms(60_000));
        // An abandonment is admissible for one range from the deadline.
        let last_refusal = deadline.at().plus(MAX_VALIDITY_RANGE);
        assert!(
            Probed::Core.absence_answers_at(last_refusal, deadline),
            "an absence at the last moment a core may abandon in is one a leg can read",
        );
        assert!(
            Probed::Core.absence_answers_at(
                last_refusal
                    .plus(MAX_VALIDITY_RANGE)
                    .minus(Duration::from_millis(1)),
                deadline,
            ),
            "and stays readable for a range past it",
        );
        assert!(
            !Probed::Core.absence_answers_at(last_refusal.plus(MAX_VALIDITY_RANGE), deadline),
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
        assert!(
            Probed::Core.absence_answers_at(core.end.minus(Duration::from_millis(1)), deadline)
        );
        assert!(!Probed::Core.absence_answers_at(core.end, deadline));
        assert!(!Probed::Core.absence_answers_at(core.end.plus(Duration::from_secs(60)), deadline));

        assert_eq!(
            Window::LegEntry.of(deadline),
            core.start..deadline.at().plus(CLAIM_WINDOW),
            "a leg entry stands one claim window past the deadline, which is the \
             span an absence has to be provable in",
        );
    }

    /// Each window against the figure it is derived from, not against
    /// the other.
    ///
    /// Both open at the deadline and neither is the other's: a leg entry
    /// stands a [`CLAIM_WINDOW`] past it, floored so an absence can be
    /// proved and a reclaim composed, where a core's absence answers for
    /// one range to refuse in and one to read the refusal. Asserting one
    /// against the other would make a change to either look like a
    /// change to both.
    #[test]
    fn each_window_is_read_off_its_own_figure() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);

        assert_eq!(
            Window::LegEntry.of(deadline),
            deadline.at()..deadline.at().plus(CLAIM_WINDOW),
            "a leg entry stands the span an absence answers in",
        );
        assert_eq!(
            Window::Core.of(deadline),
            deadline.at()..deadline.at().plus(MAX_VALIDITY_RANGE * 2),
            "a core's absence answers for one range to refuse in and one to read it",
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
        assert!(!Probed::Core.absence_answers_at(validity_end, deadline));
        assert!(
            deadline.at().elapsed_since(latest_core_admission) > MAX_FINALIZATION_DELAY,
            "the anchor sits a full delay past the last block the core could admit",
        );
    }

    /// Both answer cells answer only by being present, whichever
    /// consumer wrote them and at whatever anchor. A claim is absent
    /// while the consumer has not taken the crossing; a decline while it
    /// has not refused. Neither absence licenses taking a record back,
    /// at any anchor — which is the whole of what this plan's two cells
    /// are for, and the property a sweep on either would destroy.
    #[test]
    fn both_answers_answer_only_by_being_present() {
        let validity_end = ms(300_000);
        let deadline = Deadline::of(validity_end);
        for probed in [Probed::Claim, Probed::Decline] {
            for anchor in [
                validity_end,
                deadline.at(),
                deadline.at().plus(MAX_VALIDITY_RANGE),
                deadline.at().plus(CLAIM_WINDOW),
            ] {
                assert!(
                    !probed.absence_answers_at(anchor, deadline),
                    "an absence of {probed:?} at {anchor:?} says only that the \
                     consumer has not answered that way"
                );
            }
            assert_eq!(probed.presence_asked_from(deadline), Some(deadline.at()));
        }
    }

    /// A committed cell answers absent and never present; a claim, a
    /// decline and a record answer present and never absent.
    #[test]
    fn each_cell_answers_with_the_reading_its_writer_makes_final() {
        let present = Inclusion::Present([7; 32]);
        assert_eq!(Probed::Core.read(present), None);
        assert_eq!(
            Probed::Core.read(Inclusion::Absent),
            Some(Inclusion::Absent)
        );
        assert_eq!(Probed::Claim.read(present), Some(present));
        assert_eq!(Probed::Claim.read(Inclusion::Absent), None);
        assert_eq!(Probed::Decline.read(present), Some(present));
        assert_eq!(Probed::Decline.read(Inclusion::Absent), None);
    }

    /// A claim is asked from the deadline and not before; a committed
    /// cell only inside its absence window.
    #[test]
    fn a_presence_question_opens_at_the_deadline() {
        let deadline = Deadline::of(ms(60_000));
        assert!(!Probed::Claim.asks_at(deadline.at().minus(Duration::from_millis(1)), deadline));
        assert!(Probed::Claim.asks_at(deadline.at(), deadline));
        assert!(Probed::Core.asks_at(deadline.at(), deadline));
    }
}
