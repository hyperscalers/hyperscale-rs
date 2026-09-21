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
use hyperscale_vm_types::{CROSSING_GRACE_MS, LegRole};

use crate::{
    CLAIM_VISIBILITY_LAG, EPOCH_DURATION, Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE,
    RETENTION_HORIZON, TERMINAL_EVIDENCE_EPOCHS, Transaction, WeightedTimestamp,
};

/// The span past the deadline in which the claim cell a crossing's
/// consumer writes is still standing, and so the whole of the span in
/// which a record can be disposed of at all.
///
/// Two validity ranges is the floor — the span a core's absence answers
/// in, which a leg entry has to outlive or the reclaim that absence
/// licenses can never be composed. A record
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
    "a leg entry stands to the close of the window a core's absence answers in",
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
    /// Where a member consuming an owed crossing may be admitted: from
    /// the validity end, since inside it the transaction is admissible
    /// as itself, to the expiry the record it consumes states.
    ///
    /// Read off the record's own grace and not off [`CLAIM_WINDOW`],
    /// which is a floor the absence path needs and this path proves
    /// nothing by. An owed crossing bears no verdict, so the deadline
    /// does not bound it, and nothing takes it back meanwhile. What
    /// bounds it is the claim cell: that cell is the only thing refusing
    /// a second claim, it is swept at the record's expiry, and a member
    /// admitted past the sweep could claim what was claimed already.
    Owed,
    /// Where a core's committed cell being absent proves the core never
    /// took the transaction — never included it, or included it and
    /// refused, which retracts the cell: from the deadline, since
    /// before it the core may still commit, to the cell's own sweep two
    /// [`MAX_VALIDITY_RANGE`]s on, past which a proof is a true proof of
    /// a cell that was present.
    ///
    /// Two ranges, and they are not one span counted twice. A core may
    /// abandon anywhere inside the one range its abandonment is
    /// admissible in, and the refusal that retracts the cell lands
    /// wherever it does; reading the absence that leaves is a probe at
    /// a counterpart's own anchor, which needs a range of its own. One
    /// range for both makes a refusal at the end of it unreadable, and
    /// every crossing that fed the core strands on a cell nobody can
    /// prove absent.
    Core,
    /// Where a leg entry stands: from the deadline to the claim cell
    /// both its members are proved against being swept, one
    /// [`CLAIM_WINDOW`] on, past which no evidence that could decide
    /// the leg can still be taken.
    ///
    /// [`CLAIM_WINDOW`] is this window's figure, derived for it: the
    /// span an absence has to be provable in, floored so a reclaim can
    /// be composed at all and so a reshape successor can decide a record
    /// it inherited. That [`Self::Owed`] currently ends at the same
    /// instant is arithmetic, not a shared reason.
    LegEntry,
}

impl Window {
    /// The window, for a transaction with this `deadline`.
    #[must_use]
    pub fn of(self, deadline: Deadline) -> Range<WeightedTimestamp> {
        let at = deadline.at();
        match self {
            Self::Owed => {
                let validity_end = deadline.validity_end();
                validity_end..validity_end.plus(Duration::from_millis(CROSSING_GRACE_MS))
            }
            Self::Core => at..at.plus(MAX_VALIDITY_RANGE * 2),
            Self::LegEntry => at..at.plus(CLAIM_WINDOW),
        }
    }
}

/// The last anchor a block may carry `tx` at, which is how long an index
/// refusing a second inclusion has to remember it.
///
/// A transaction is admissible while its validity range contains the
/// anchor, and past that only as a member consuming an owed crossing —
/// to the close of [`Window::Owed`], the expiry that crossing's record
/// states.
///
/// Only a transaction with an outbound leg issues an owed crossing, and
/// settling a placement onto the legs promotes toward the core and never
/// to [`LegRole::Outbound`], so the stored roles answer this without
/// one. That is what lets an index ask it off the body alone, and it is
/// what keeps the ordinary transaction — one carrying no crossing at
/// all — out of a window sized for the one shape that needs it: an owed
/// crossing's grace is a [`CLAIM_WINDOW`] where a deadline is one
/// [`MAX_FINALIZATION_DELAY`], and an index holding every committed
/// transaction to the wider of the two is holding the whole of a shard's
/// traffic for the sake of the crossings in it.
#[must_use]
pub fn admissible_until(tx: &Transaction) -> WeightedTimestamp {
    let deadline = Deadline::of_transaction(tx);
    if tx.legs().iter().any(|leg| leg.role == LegRole::Outbound) {
        Window::Owed.of(deadline).end
    } else {
        deadline.at()
    }
}

/// Which counterpart cell a probe asks about, and so which reading of
/// it answers.
///
/// Each cell is written by one execution and by nothing else, so what
/// a reading says is a property of the cell. A committed cell is
/// written at a core member's inclusion and retracted by its refusal,
/// so only its absence is an answer: present, the member is still
/// pending, and the cell is asked again at a newer header. A claim cell
/// is written by the execution that takes the crossing, so only its
/// presence is an answer — and that holds whichever consumer wrote it.
/// A core's claim is absent while a sibling is still pending, and the
/// committed cell says whether it ever will be; a delivery's is absent
/// while the delivery has not run, and the crossing behind it is the
/// consumer's whenever it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Probed {
    /// A core member's committed cell, past the transaction's deadline:
    /// absent where the member never included the transaction, or
    /// included it and refused.
    Core,
    /// A consumer's claim cell: present says that consumer holds the
    /// crossing. For a core it means its certificate speaks next; for a
    /// delivery it is what lets the issuer retire the record.
    Claim,
    /// The record cell of a crossing, asked of the producer's chain by a
    /// consumer that answered it: present says the producer still holds
    /// the value, so a delivery consuming it has something to run
    /// against and a claim answering it is not yet cleanable.
    Record,
}

impl Probed {
    /// The window an *absence* of this cell is read in, `None` where an
    /// absence never answers.
    #[must_use]
    pub(crate) const fn absence_window(self) -> Option<Window> {
        match self {
            Self::Core => Some(Window::Core),
            Self::Claim | Self::Record => None,
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
    /// by the deadline or the consumer has not run yet. A consumer's
    /// claiming success opens the question earlier, and that cue is the
    /// prober's to read.
    #[must_use]
    pub(crate) const fn presence_asked_from(self, deadline: Deadline) -> Option<WeightedTimestamp> {
        match self {
            Self::Core => None,
            Self::Claim | Self::Record => Some(deadline.at()),
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
    /// delivery's claim answers either way. A record answers present —
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
            (Inclusion::Present(_), Self::Claim | Self::Record)
            | (Inclusion::Absent, Self::Core) => Some(inclusion),
            (Inclusion::Present(_), Self::Core)
            | (Inclusion::Absent, Self::Claim | Self::Record) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyperscale_vm_types::{COMMITTED_GRACE_MS, CROSSING_GRACE_MS};

    use super::{CLAIM_WINDOW, Deadline, Probed, Window};
    use crate::{
        CLAIM_VISIBILITY_LAG, Inclusion, MAX_FINALIZATION_DELAY, MAX_VALIDITY_RANGE,
        WeightedTimestamp,
    };

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
    }

    /// A delivery is admissible from the validity end to the expiry its
    /// record states, half-open at both ends the way the window itself
    /// is.
    #[test]
    fn the_delivery_window_opens_at_the_validity_end_and_closes_at_the_expiry() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);
        let window = Window::Owed.of(deadline);
        assert_eq!(window.start, validity_end);
        assert_eq!(window.end, deadline.at().plus(CLAIM_WINDOW));
        assert_eq!(
            window.end.as_millis(),
            validity_end.as_millis() + CROSSING_GRACE_MS,
            "a delivery is admissible to exactly the expiry its record states"
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
    /// A refusal at the last moment a core may abandon in is still
    /// readable, and stays so for a range past it.
    ///
    /// The abandonment window and the window an absence answers in were
    /// the same span, so a core abandoning at the end of its own left a
    /// retraction no leg could prove — and every crossing that fed it
    /// stranded on a cell nobody could read absent.
    #[test]
    fn an_absence_answers_a_range_past_the_last_moment_a_core_may_refuse() {
        let deadline = Deadline::of(ms(60_000));
        // An abandonment is admissible for one range from the deadline,
        // so this is the last anchor a retraction can land at.
        let last_refusal = deadline.at().plus(MAX_VALIDITY_RANGE);
        assert!(
            Probed::Core.absence_answers_at(last_refusal, deadline),
            "a retraction left at the last moment is one a leg can read",
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
    /// They end at the same instant today, and for unrelated reasons: a
    /// leg entry stands a [`CLAIM_WINDOW`] past the deadline, floored so
    /// an absence can be proved and a reclaim composed; an owed crossing
    /// is claimable to the expiry its own record states. Asserting one
    /// against the other would make a change to either look like a
    /// change to both.
    #[test]
    fn each_window_is_read_off_its_own_figure() {
        let validity_end = ms(60_000);
        let deadline = Deadline::of(validity_end);

        assert_eq!(
            Window::Owed.of(deadline),
            validity_end..validity_end.plus(Duration::from_millis(CROSSING_GRACE_MS)),
            "an owed crossing is claimable to the expiry its record states",
        );
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

    /// A claim cell answers only by being present, whichever consumer
    /// wrote it. A core's is absent while a sibling is still pending; a
    /// delivery's while the delivery has not run, and the crossing
    /// behind that one is the consumer's whenever it does. Neither
    /// absence licenses taking a record back, at any anchor.
    #[test]
    fn a_claim_answers_only_by_being_present() {
        let validity_end = ms(300_000);
        let deadline = Deadline::of(validity_end);
        for anchor in [
            validity_end,
            deadline.at(),
            deadline.at().plus(MAX_VALIDITY_RANGE),
            Window::Owed.of(deadline).end,
            deadline.at().plus(CLAIM_WINDOW),
        ] {
            assert!(
                !Probed::Claim.absence_answers_at(anchor, deadline),
                "an absence at {anchor:?} says only that the consumer has not run"
            );
        }
        assert_eq!(
            Probed::Claim.presence_asked_from(deadline),
            Some(deadline.at())
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
        assert_eq!(Probed::Record.read(present), Some(present));
        assert_eq!(Probed::Record.read(Inclusion::Absent), None);
    }

    /// A record answers present at any anchor and absent at none.
    ///
    /// Nothing sweeps a record, so the presence needs no window and is
    /// taken wherever it was read. The absence is the half a consumer
    /// that answered the crossing may read, and nobody else — so until
    /// the asker that may read it exists, it answers nothing at all,
    /// which is what keeps a record reading out of the set a coverage is
    /// decided by.
    #[test]
    fn a_record_answers_present_at_any_anchor_and_absent_at_none() {
        let deadline = Deadline::of(ms(60_000));
        assert_eq!(Probed::Record.absence_window(), None);
        assert_eq!(
            Probed::Record.presence_asked_from(deadline),
            Some(deadline.at()),
        );
        for at in [
            deadline.at(),
            Window::Core.of(deadline).end,
            Window::LegEntry.of(deadline).end.plus(MAX_VALIDITY_RANGE),
        ] {
            assert!(!Probed::Record.absence_answers_at(at, deadline));
            assert!(Probed::Record.asks_at(at, deadline, None));
            assert_eq!(
                Probed::Record.answer(at, deadline, Inclusion::Present([7; 32])),
                Some(Inclusion::Present([7; 32])),
            );
            assert_eq!(Probed::Record.answer(at, deadline, Inclusion::Absent), None);
        }
    }

    /// A claim is asked from the deadline, or one lag past a cue heard
    /// earlier; a committed cell only inside its absence window, since a
    /// cue promises a presence and a present committed cell answers
    /// nothing.
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
        assert!(!Probed::Core.asks_at(readable, deadline, Some(cued)));
        assert!(Probed::Core.asks_at(deadline.at(), deadline, Some(cued)));
    }
}
