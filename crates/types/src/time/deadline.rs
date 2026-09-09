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
    CLAIM_VISIBILITY_LAG, EPOCH_DURATION, Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE,
    RETENTION_HORIZON, TERMINAL_EVIDENCE_EPOCHS, Transaction, WeightedTimestamp,
};

/// The span past the deadline in which the claim cell a crossing's
/// consumer writes is still standing, and so the whole of the span in
/// which a record can be disposed of at all.
///
/// Two validity ranges is the floor — one for the delivery window to
/// close and the lapse to be proved, one more for the reclaim that
/// proves it to commit — and the figure sits far above it. A record
/// written near a reshape cut is inherited by a successor that decides
/// it against a claim cell now on some other chain, so the window has to
/// be the one every other bound on reshape evidence is:
/// [`TERMINAL_EVIDENCE_EPOCHS`] windows, less the deadline the cell's
/// expiry is measured from. Shorter and the record is one nobody can
/// dispose of, its value stranded where presence and absence are both
/// unprovable.
pub const CLAIM_WINDOW: Duration = Duration::from_secs(
    EPOCH_DURATION.as_secs() * TERMINAL_EVIDENCE_EPOCHS - MAX_FINALIZATION_DELAY.as_secs(),
);

const _: () = assert!(
    CLAIM_WINDOW.as_secs() >= MAX_VALIDITY_RANGE.as_secs() * 2,
    "a lapse has a range to be proved in and its reclaim a range to commit in",
);

/// How long a transaction's evidence outlives the moment it was
/// committed: everything its shape reaches, ends by.
///
/// A transaction committed at `T` states a validity end at most one
/// [`MAX_VALIDITY_RANGE`] on and a deadline one
/// [`MAX_FINALIZATION_DELAY`] past that — [`RETENTION_HORIZON`] in
/// total. A leg entry stands one [`CLAIM_WINDOW`] further, to where the
/// claim cell both its members are proved against is swept. Past this
/// nothing of the transaction can be asked, answered or reclaimed.
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

    /// The deadline an escrow record's expiry was derived from.
    ///
    /// A record is never swept — no arm of the sweep reaches it, which
    /// is what makes it a balance rather than a witness. What the expiry
    /// names is the sweep of the claim cell the record is decided
    /// against, keyed by the same figure so the two agree, and the
    /// producing intent's deadline sits one [`CLAIM_WINDOW`] before it.
    /// For a reader holding the record and no body.
    #[must_use]
    pub const fn from_expiry(expiry_ms: u64) -> Self {
        Self(WeightedTimestamp::from_millis(
            expiry_ms.saturating_sub(CLAIM_WINDOW.as_secs() * 1_000),
        ))
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
    /// Where a delivery of the transaction's outbound value may be
    /// admitted: from the validity end, since inside it the transaction
    /// is admissible as itself, for one [`MAX_VALIDITY_RANGE`]. A
    /// delivery bears no verdict, so the deadline does not bound it;
    /// what does is that one admitted at the last moment has claimed by
    /// [`MAX_FINALIZATION_DELAY`] past the close or never will.
    Delivery,
    /// Where a core's committed cell being absent proves the core never
    /// took the transaction — never included it, or included it and
    /// refused, which retracts the cell: from the deadline, since
    /// before it the core may still commit, to the cell's own sweep one
    /// [`MAX_VALIDITY_RANGE`] on, past which a proof is a true proof of
    /// a cell that was present.
    Core,
    /// Where a delivery's claim cell being absent proves the crossing
    /// lapsed: from the delivery window's close plus
    /// [`MAX_FINALIZATION_DELAY`] — a delivery admitted under the close
    /// has committed its claim by then or never will — to the claim
    /// cell's sweep.
    Lapse,
    /// Where a leg entry stands: from the deadline to the claim cell
    /// both its members are proved against being swept, one
    /// [`CLAIM_WINDOW`] on, past which no evidence that could decide
    /// the leg can still be taken.
    LegEntry,
}

impl Window {
    /// The window, for a transaction with this `deadline`.
    #[must_use]
    pub fn of(self, deadline: Deadline) -> Range<WeightedTimestamp> {
        let at = deadline.at();
        match self {
            Self::Delivery => {
                let validity_end = deadline.validity_end();
                validity_end..validity_end.plus(MAX_VALIDITY_RANGE)
            }
            Self::Core => at..at.plus(MAX_VALIDITY_RANGE),
            Self::LegEntry => at..at.plus(CLAIM_WINDOW),
            Self::Lapse => at.plus(MAX_VALIDITY_RANGE)..at.plus(CLAIM_WINDOW),
        }
    }
}

/// Which counterpart cell a probe asks about, and so which reading of
/// it answers.
///
/// Each cell is written by one execution and by nothing else, so what
/// a reading says is a property of the cell. A committed cell is
/// written at a core member's inclusion and retracted by its refusal,
/// so only its absence is an answer: present, the member is still
/// pending, and the cell is asked again at a newer header. A core
/// consumer's claim cell is written by the consuming finalization, and
/// only once every core member certified, so only its presence is an
/// answer: absent, a sibling may still be pending, and the committed
/// cell says whether it ever will be. A delivery's claim cell is written
/// by a member that awaits nobody, so both readings answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Probed {
    /// A core member's committed cell, past the transaction's deadline:
    /// absent where the member never included the transaction, or
    /// included it and refused.
    Core,
    /// A delivering shard's claim cell, past the crossing's lapse.
    Delivery,
    /// A core consumer's claim cell: present says the core took the
    /// crossing, and its certificate speaks next.
    Claim,
}

impl Probed {
    /// Every cell a probe asks about, in the order a block carries their
    /// records.
    pub const ALL: [Self; 3] = [Self::Core, Self::Delivery, Self::Claim];

    /// The window an *absence* of this cell is read in, `None` where an
    /// absence never answers.
    #[must_use]
    pub const fn absence_window(self) -> Option<Window> {
        match self {
            Self::Core => Some(Window::Core),
            Self::Delivery => Some(Window::Lapse),
            Self::Claim => None,
        }
    }

    /// Whether an *absence* taken at `probed_wt` answers this question
    /// for a transaction with this `deadline`.
    ///
    /// The window the probe anchors in. Before it the counterpart may
    /// still write the cell, and past it the sweep may have taken one
    /// that was there, so an absence outside says nothing either way.
    #[must_use]
    pub fn absence_answers_at(self, probed_wt: WeightedTimestamp, deadline: Deadline) -> bool {
        self.absence_window()
            .is_some_and(|window| window.of(deadline).contains(&probed_wt))
    }

    /// The earliest anchor a *presence* of this cell is asked at, for a
    /// transaction with this `deadline`, `None` where a presence never
    /// answers.
    ///
    /// A presence answers wherever it was taken, so this bounds only
    /// when the question is worth putting: a core consumer's claim is
    /// there by the deadline or a sibling is pending, and a delivery's
    /// by the lapse or never. A consumer's claiming success opens the
    /// question earlier, and that cue is the prober's to read.
    #[must_use]
    pub fn presence_asked_from(self, deadline: Deadline) -> Option<WeightedTimestamp> {
        match self {
            Self::Core => None,
            Self::Claim => Some(deadline.at()),
            Self::Delivery => Some(Window::Lapse.of(deadline).start),
        }
    }

    /// Whether a header at `anchor_wt` is one to ask this question at,
    /// for a transaction with this `deadline` whose consumer's claiming
    /// success, if one was heard, was spoken at `cued`: inside the
    /// window an absence answers in, or past the point a presence is
    /// asked from — the question's own, or one
    /// [`CLAIM_VISIBILITY_LAG`] past the cue, whichever is earlier,
    /// since the reading a cue is after is a presence and a presence
    /// answers wherever it was taken.
    #[must_use]
    pub fn asks_at(
        self,
        anchor_wt: WeightedTimestamp,
        deadline: Deadline,
        cued: Option<WeightedTimestamp>,
    ) -> bool {
        self.absence_answers_at(anchor_wt, deadline)
            || self.presence_asked_from(deadline).is_some_and(|from| {
                anchor_wt >= from
                    || cued.is_some_and(|cued| anchor_wt >= cued.plus(CLAIM_VISIBILITY_LAG))
            })
    }

    /// What `inclusion` of the probed cell, read at `probed_wt`, says
    /// for a transaction with this `deadline`: the inclusion itself, or
    /// `None` where it says nothing.
    ///
    /// A presence is bounded by neither end of a window: the cell was
    /// written by the one execution that writes it, whenever the reading
    /// was taken, and a swept one reads absent rather than present. That
    /// asymmetry is the whole of why a retirement can be licensed across
    /// a cut and a reclaim cannot. An absence answers only inside its
    /// window. Which readings answer at all is [`Self::read`].
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
    /// never included the transaction, or refused and retracted the
    /// cell — and present is a member still pending, whose refusal may
    /// yet retract it. A core consumer's claim answers present — the
    /// consuming finalization committed, which it does only once every
    /// core member certified — and absent is a sibling still pending. A
    /// delivery's claim answers either way.
    #[must_use]
    pub const fn read(self, inclusion: Inclusion) -> Option<Inclusion> {
        match (inclusion, self) {
            (Inclusion::Present(_), Self::Claim | Self::Delivery)
            | (Inclusion::Absent, Self::Core | Self::Delivery) => Some(inclusion),
            (Inclusion::Present(_), Self::Core) | (Inclusion::Absent, Self::Claim) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_vm_types::{ARTIFACT_GRACE_MS, CROSSING_GRACE_MS};

    use super::{CLAIM_WINDOW, Deadline, Probed, Window};
    use crate::{
        CLAIM_VISIBILITY_LAG, Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE,
        RETENTION_HORIZON, WeightedTimestamp,
    };

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
    }

    /// A delivery is admissible from the validity end to the window's
    /// close, half-open at both ends the way the window itself is, and
    /// the close sits one finalization delay short of the record's sweep.
    #[test]
    fn the_delivery_window_opens_at_the_validity_end_and_closes_short_of_the_sweep() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        let window = Window::Delivery.of(deadline);
        assert_eq!(window.start, validity_end);
        assert_eq!(window.end, validity_end.plus(MAX_VALIDITY_RANGE));
        assert_eq!(
            validity_end
                .plus(RETENTION_HORIZON)
                .elapsed_since(window.end),
            MAX_FINALIZATION_DELAY,
            "the sweep is a full delay past the close"
        );
        assert!(!window.contains(&validity_end.minus(Duration::from_millis(1))));
        assert!(window.contains(&validity_end));
        assert!(window.contains(&window.end.minus(Duration::from_millis(1))));
        assert!(!window.contains(&window.end));
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
    /// licenses nothing. The claim windows close at the crossing
    /// family's grace, the claim cell's own sweep.
    ///
    /// Each window's own end is the sweep of the cell its absence asks
    /// about, and the two families are sized apart: the core window is
    /// one validity range wide, and the lapse runs from the same offset
    /// to a sweep the crossing family sets far later.
    #[test]
    fn an_absence_licenses_nothing_once_the_cell_it_asks_about_may_be_swept() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        let core = Window::Core.of(deadline);
        assert_eq!(core.end, validity_end.plus(RETENTION_HORIZON));
        assert_eq!(
            core.end,
            validity_end.plus(Duration::from_millis(ARTIFACT_GRACE_MS)),
            "which is where the committed cell it asks about is swept",
        );
        assert_eq!(core.end.elapsed_since(core.start), MAX_VALIDITY_RANGE);
        assert!(
            Probed::Core.absence_answers_at(core.end.minus(Duration::from_millis(1)), deadline)
        );
        assert!(!Probed::Core.absence_answers_at(core.end, deadline));
        assert!(!Probed::Core.absence_answers_at(core.end.plus(Duration::from_secs(60)), deadline));

        let lapse = Window::Lapse.of(deadline);
        assert_eq!(
            lapse.end,
            validity_end.plus(Duration::from_millis(CROSSING_GRACE_MS)),
            "the claim cell's grace, keyed to a window never earlier than this one",
        );
        assert_eq!(lapse.start, core.start.plus(MAX_VALIDITY_RANGE));
        assert!(
            Probed::Delivery
                .absence_answers_at(lapse.end.minus(Duration::from_millis(1)), deadline)
        );
        assert!(!Probed::Delivery.absence_answers_at(lapse.end, deadline));
        assert_eq!(Window::LegEntry.of(deadline), core.start..lapse.end);
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

    /// The lapse opens one validity range past the deadline: the
    /// delivery window's close plus the same propagation budget the
    /// core's admission leaves, so a delivery admitted at the last
    /// moment has committed its claim by it or never will. Absence
    /// licenses a reclaim at the anchor and past it, never short of it.
    #[test]
    fn a_lapse_is_proved_no_earlier_than_the_close_plus_the_finalization_delay() {
        let validity_end = ms(300_000);
        let deadline = Deadline::of(validity_end);
        let lapse = Window::Lapse.of(deadline);
        assert_eq!(lapse.start, deadline.at().plus(MAX_VALIDITY_RANGE));
        let close = Window::Delivery.of(deadline).end;
        assert_eq!(lapse.start, close.plus(MAX_FINALIZATION_DELAY));
        assert!(
            !Probed::Delivery
                .absence_answers_at(lapse.start.minus(Duration::from_millis(1)), deadline)
        );
        assert!(Probed::Delivery.absence_answers_at(lapse.start, deadline));
        assert!(
            Probed::Delivery.absence_answers_at(lapse.start.plus(Duration::from_secs(1)), deadline)
        );
        assert!(
            !Probed::Delivery.absence_answers_at(close, deadline),
            "the close itself is not the lapse: a claim admitted under it may still commit",
        );
    }

    /// A record's expiry names the deadline it was derived from, and the
    /// claim window read off that deadline ends exactly at the expiry.
    #[test]
    fn an_escrow_expiry_reads_back_to_its_deadline() {
        let validity_end = ms(60_000);
        let expiry_ms = validity_end.as_millis() + CROSSING_GRACE_MS;
        let deadline = Deadline::from_expiry(expiry_ms);
        assert_eq!(deadline, Deadline::of(validity_end));
        let entry = Window::LegEntry.of(deadline);
        assert_eq!(entry.end, ms(expiry_ms));
        assert_eq!(entry.end.elapsed_since(entry.start), CLAIM_WINDOW);
    }

    /// A committed cell answers absent and never present, a core
    /// consumer's claim answers present and never absent, and a
    /// delivery's claim answers either way.
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
        assert_eq!(Probed::Delivery.read(present), Some(present));
        assert_eq!(
            Probed::Delivery.read(Inclusion::Absent),
            Some(Inclusion::Absent)
        );
    }

    /// A core consumer's claim is asked from the deadline, or one lag
    /// past a cue heard earlier; a delivery's from its lapse or the same
    /// cue; a committed cell only inside its absence window, since a cue
    /// promises a presence and a present committed cell answers nothing.
    #[test]
    fn a_cue_opens_a_presence_question_early_and_never_a_committed_cell() {
        let deadline = Deadline::of(ms(60_000));
        let cued = deadline.at().minus(Duration::from_secs(30));
        let readable = cued.plus(CLAIM_VISIBILITY_LAG);
        assert!(!Probed::Claim.asks_at(
            readable.minus(Duration::from_millis(1)),
            deadline,
            Some(cued)
        ));
        assert!(Probed::Claim.asks_at(readable, deadline, Some(cued)));
        assert!(!Probed::Claim.asks_at(
            deadline.at().minus(Duration::from_millis(1)),
            deadline,
            None
        ));
        assert!(Probed::Claim.asks_at(deadline.at(), deadline, None));
        assert!(Probed::Delivery.asks_at(readable, deadline, Some(cued)));
        assert!(!Probed::Delivery.asks_at(deadline.at(), deadline, None));
        assert!(Probed::Delivery.asks_at(Window::Lapse.of(deadline).start, deadline, None));
        assert!(!Probed::Core.asks_at(readable, deadline, Some(cued)));
        assert!(Probed::Core.asks_at(deadline.at(), deadline, Some(cued)));
    }
}
