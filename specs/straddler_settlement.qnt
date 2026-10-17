// Model D (register: specs/README.md) — straddler settlement: atomicity
// across a terminating shard, INV-RESHAPE-5 composed with Model C's
// reading rule.
//
// Shard 1 is P (reshapes and terminates at its cut); shard 2 is Q (the
// survivor). One core transaction may straddle the boundary. Each shard
// states its own outcome; a stated row accepts only on the sibling's
// committed state. The beacon latches P's drain, which pauses core
// intake toward and from P, and schedules P's cut only once P has
// asserted, under that latch, that no row of it hears. Once P is gone,
// Q reads it from Q's own entry alone: an accepted entry accepts, and
// anything else is a leaving.
//
// Code anchors:
//   - The latch: `drained` (crates/beacon/src/state/reshape.rs) sets
//     `Admission.drain_by` at the first fold whose readiness gate
//     passes and schedules nothing in it; `prune_stale_reshapes`
//     (crates/beacon/src/state/witness.rs) cancels a latched record at
//     `drain_by`.
//   - The pause: `TopologySchedule::reshaping_at` (crates/types/src/
//     topology/schedule.rs). While P reads as reshaping, a core
//     transaction toward or from P is not admitted
//     (`TransactionsSection::admit`, crates/shard/src/admission.rs).
//   - The quiet assertion: `MemberIndex::quiet` (crates/storage/src/
//     shard/members.rs) carried in the trigger's `settling`; the witness
//     fold raises a sticky quiet bit only on a latched record whose
//     admission the assertion names (`answers`, witness.rs), and
//     `drained` schedules only on that bit.
//   - The stating window: `Exit::of` (crates/engine/src/tick_select.rs)
//     aborts a shared member in flight once `Window::Stating` of its
//     deadline has closed.
//   - `value_of` (crates/types/src/shard/verdict.rs): a live sibling's
//     `Yes` counts only where the reading is at most an epoch old; a gone
//     sibling's accept is an `Accepted` entry, and anything else is
//     `Left`.
//   - `terminal_fates` (tick_select.rs): `End` for an accepted row, a
//     fate for every other, and an error for any row that hears.
//
// Modeling assumptions:
//   - One core transaction on two shards; execution determinism and
//     honest committees as in Model C.
//   - Epochs are a global counter, bounded by MAX_EPOCH; they age
//     readings only. The reshape's own steps (latch, quiet assertion,
//     schedule, cancel, cut) are free environment moves, so every
//     interleaving of them with the rows is explored.
//   - A pending member may state while P drains. The code does not run
//     it there; allowing it only widens what the model explores.
//   - The stating window may close on any row in flight at any time,
//     which over-approximates its clock.
//   - A reading is the sibling's committed state at the instant it is
//     taken, marked with that epoch; the newest wins.
//
// Run:
//   quint typecheck specs/straddler_settlement.qnt
//   quint run    --main=straddler_ok       --invariant=invAll specs/straddler_settlement.qnt
//   quint verify --main=straddler_ok       --invariant=invAll --max-steps=8 specs/straddler_settlement.qnt
//   quint test   --main=straddler_ungated  --match=cutUnderAYes specs/straddler_settlement.qnt
//     (scripted witness: Q accepts on P's yes, the cut falls without a
//      quiet assertion, and P's terminal fates its stated row)
//   quint verify --main=straddler_ungated  --invariant=invAtomic --max-steps=10 specs/straddler_settlement.qnt
//   quint test   --main=straddler_unpaused --match=yesAfterQuiet specs/straddler_settlement.qnt
//     (scripted witness: P asserts quiet, then admits and states the
//      transaction while draining, and the cut falls under that yes)
//   quint verify --main=straddler_unpaused --invariant=invQuietStays --max-steps=6 specs/straddler_settlement.qnt

module straddler_settlement {
  const MAX_EPOCH: int
  // Broken twin: the cut is scheduled without a quiet assertion.
  const IGNORE_QUIET: bool
  // Broken twin: core intake toward and from P stays open while it
  // drains.
  const IGNORE_PAUSE: bool

  pure val P = 1
  pure val Q = 2
  pure val SHARDS = Set(P, Q)
  pure def other(s: int): int = if (s == P) Q else P

  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // Rows.
  pure val IN_FLIGHT = 10
  pure val STATED = 11
  pure val ACCEPTED = 12
  pure val GONE = 13

  // Readings.
  pure val YES = 20
  pure val SAID_ACCEPTED = 21
  pure val LEFT = 22

  // P's reshape.
  pure val LIVE = 30
  pure val DRAINING = 31
  pure val SCHEDULED = 32
  pure val CUT = 33

  // The global epoch.
  var epoch: int
  // Each shard's row (NONE before it commits).
  var row: int -> int
  // The newest reading each shard holds of its sibling, and its epoch.
  var heard: int -> int
  var heardAt: int -> int
  // Terminal verdict per shard.
  var terminal: int -> int
  // Where P's reshape stands.
  var phase: int
  // The record's quiet bit: raised by an assertion under the latch,
  // cleared only with the record.
  var quiet: bool
  // P's terminal met a row that hears.
  var fatedHearing: bool

  def hears(r: int): bool = r == IN_FLIGHT or r == STATED or r == ACCEPTED
  def pQuiet: bool = not(hears(row.get(P)))
  def pGone: bool = phase == CUT
  def paused: bool =
    not(IGNORE_PAUSE) and (phase == DRAINING or phase == SCHEDULED)

  def said(s: int): int =
    if (row.get(s) == STATED) YES
    else if (row.get(s) == ACCEPTED) SAID_ACCEPTED
    else if (row.get(s) == GONE) LEFT
    else NONE

  // `value_of` of `s`'s sibling as `s` decides at the current epoch:
  // SAID_ACCEPTED, LEFT, YES (counted), or NONE (wait).
  def value(s: int): int =
    if (s == Q and pGone)
      if (heard.get(s) == SAID_ACCEPTED) SAID_ACCEPTED else LEFT
    else if (heard.get(s) == SAID_ACCEPTED) SAID_ACCEPTED
    else if (heard.get(s) == LEFT) LEFT
    else if (heard.get(s) == YES and heardAt.get(s) + 1 >= epoch) YES
    else NONE

  action init = all {
    epoch' = 0,
    row' = SHARDS.mapBy(s => NONE),
    heard' = SHARDS.mapBy(s => NONE),
    heardAt' = SHARDS.mapBy(s => NONE),
    terminal' = SHARDS.mapBy(s => NONE),
    phase' = LIVE,
    quiet' = false,
    fatedHearing' = false,
  }

  // Both shards admit the transaction, while P runs and is not paused.
  action commitAt(s: int): bool = all {
    row.get(s) == NONE,
    not(pGone),
    not(paused),
    row' = row.put(s, IN_FLIGHT),
    epoch' = epoch, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, phase' = phase, quiet' = quiet,
    fatedHearing' = fatedHearing,
  }

  // The stating half: a yes or a refusal.
  action stateAs(s: int, o: int): bool = all {
    row.get(s) == IN_FLIGHT,
    not(s == P and pGone),
    row' = row.put(s, if (o == SUCC) STATED else GONE),
    terminal' = if (o == SUCC) terminal else terminal.put(s, ABORT),
    epoch' = epoch, heard' = heard, heardAt' = heardAt,
    phase' = phase, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  // The stating window closes on a row that never stated: it is
  // aborted, having said nothing a sibling could read.
  action unstatedAt(s: int): bool = all {
    row.get(s) == IN_FLIGHT,
    not(s == P and pGone),
    row' = row.put(s, GONE),
    terminal' = terminal.put(s, ABORT),
    epoch' = epoch, heard' = heard, heardAt' = heardAt,
    phase' = phase, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  // A reading of the live sibling's committed state lands.
  action readAt(s: int): bool = all {
    row.get(s) == STATED or row.get(s) == ACCEPTED,
    not(pGone),
    said(other(s)) != NONE,
    heard' = heard.put(s, said(other(s))),
    heardAt' = heardAt.put(s, epoch),
    epoch' = epoch, row' = row, terminal' = terminal,
    phase' = phase, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  action decideAt(s: int): bool = all {
    row.get(s) == STATED,
    not(s == P and pGone),
    value(s) != NONE,
    row' = row.put(s, if (value(s) == LEFT) GONE else ACCEPTED),
    terminal' = terminal.put(s, if (value(s) == LEFT) ABORT else SUCC),
    epoch' = epoch, heard' = heard, heardAt' = heardAt,
    phase' = phase, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  // An accepted row ends once its sibling has accepted or left.
  action endAt(s: int): bool = all {
    row.get(s) == ACCEPTED,
    not(s == P and pGone),
    value(s) == SAID_ACCEPTED or value(s) == LEFT,
    row' = row.put(s, GONE),
    epoch' = epoch, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, phase' = phase, quiet' = quiet,
    fatedHearing' = fatedHearing,
  }

  // The readiness gate passes and the beacon latches P's drain.
  action latch: bool = all {
    phase == LIVE,
    phase' = DRAINING,
    quiet' = false,
    epoch' = epoch, row' = row, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, fatedHearing' = fatedHearing,
  }

  // P asserts quiet under the latch; the bit is sticky.
  action assertQuiet: bool = all {
    phase == DRAINING,
    pQuiet,
    quiet' = true,
    epoch' = epoch, row' = row, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, phase' = phase, fatedHearing' = fatedHearing,
  }

  // The beacon schedules the cut, which can no longer be revoked.
  action schedule: bool = all {
    phase == DRAINING,
    quiet or IGNORE_QUIET,
    phase' = SCHEDULED,
    epoch' = epoch, row' = row, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  // The drain deadline passes unscheduled: the record cancels, cutting
  // nothing, and intake reopens.
  action cancel: bool = all {
    phase == DRAINING,
    phase' = LIVE,
    quiet' = false,
    epoch' = epoch, row' = row, heard' = heard, heardAt' = heardAt,
    terminal' = terminal, fatedHearing' = fatedHearing,
  }

  // P's terminal commits: `End` for an accepted row, a fate for any
  // other.
  action cut: bool = all {
    phase == SCHEDULED,
    phase' = CUT,
    fatedHearing' = (fatedHearing or row.get(P) == STATED or row.get(P) == ACCEPTED),
    row' = if (row.get(P) != NONE) row.put(P, GONE) else row,
    terminal' = if (row.get(P) == IN_FLIGHT or row.get(P) == STATED)
                  terminal.put(P, ABORT)
                else terminal,
    epoch' = epoch, heard' = heard, heardAt' = heardAt, quiet' = quiet,
  }

  action advance: bool = all {
    epoch < MAX_EPOCH,
    epoch' = epoch + 1,
    row' = row, heard' = heard, heardAt' = heardAt, terminal' = terminal,
    phase' = phase, quiet' = quiet, fatedHearing' = fatedHearing,
  }

  action step = any {
    advance,
    latch,
    assertQuiet,
    schedule,
    cancel,
    cut,
    nondet s = SHARDS.oneOf()
    any {
      commitAt(s),
      nondet o = Set(SUCC, ABORT).oneOf()
      stateAs(s, o),
      unstatedAt(s),
      readAt(s),
      decideAt(s),
      endAt(s),
    },
  }

  // INV-EXEC-1 across the cut: verdicts agree.
  val invAtomic = SHARDS.forall(x => SHARDS.forall(y =>
    terminal.get(x) == NONE or terminal.get(y) == NONE or
    terminal.get(x) == terminal.get(y)))

  // Nothing of P stands past its terminal.
  val invTerminalClears = pGone implies (row.get(P) == NONE or row.get(P) == GONE)

  // No terminal meets a row that hears.
  val invNoCutUnderAYes = not(fatedHearing)

  // A raised quiet bit stays true of P's rows until the cut.
  val invQuietStays =
    ((phase == DRAINING or phase == SCHEDULED) and quiet) implies pQuiet

  val invAll = invAtomic and invTerminalClears and invNoCutUnderAYes and invQuietStays

  // The ungated twin, scripted: Q accepts on P's yes, and the cut falls
  // with P's row still stated.
  run cutUnderAYes =
    init
      .then(commitAt(P))
      .then(commitAt(Q))
      .then(stateAs(P, SUCC))
      .then(stateAs(Q, SUCC))
      .then(readAt(Q))
      .then(decideAt(Q))
      .then(latch)
      .then(schedule)
      .then(cut)
      .expect(not(invAtomic) and not(invNoCutUnderAYes))

  // The unpaused twin, scripted: P asserts quiet before the transaction
  // reaches it, admits and states it while draining, and the cut falls
  // under the yes Q accepted on.
  run yesAfterQuiet =
    init
      .then(latch)
      .then(assertQuiet)
      .then(commitAt(P))
      .expect(not(invQuietStays))
      .then(commitAt(Q))
      .then(stateAs(P, SUCC))
      .then(stateAs(Q, SUCC))
      .then(readAt(Q))
      .then(decideAt(Q))
      .then(schedule)
      .then(cut)
      .expect(not(invAtomic))

  // The healthy path: both state, accept and end before P drains, P
  // asserts quiet, and the cut fates nothing.
  run quietCutTest =
    init
      .then(commitAt(P))
      .then(commitAt(Q))
      .then(stateAs(P, SUCC))
      .then(stateAs(Q, SUCC))
      .then(readAt(Q))
      .then(decideAt(Q))
      .then(readAt(P))
      .then(decideAt(P))
      .then(readAt(Q))
      .then(endAt(Q))
      .then(latch)
      .then(endAt(P))
      .then(assertQuiet)
      .then(schedule)
      .then(cut)
      .expect(invAll and terminal.get(P) == SUCC and terminal.get(Q) == SUCC)

  // A row that never states blocks nothing past its stating window: Q's
  // yes reads P left once P's row is aborted, and P quiets.
  run unstatedRowQuietsTest =
    init
      .then(commitAt(P))
      .then(commitAt(Q))
      .then(stateAs(Q, SUCC))
      .then(latch)
      .then(unstatedAt(P))
      .then(assertQuiet)
      .then(readAt(Q))
      .then(decideAt(Q))
      .then(schedule)
      .then(cut)
      .expect(invAll and terminal.get(P) == ABORT and terminal.get(Q) == ABORT)
}

// Healthy configuration.
module straddler_ok {
  import straddler_settlement(MAX_EPOCH = 3, IGNORE_QUIET = false, IGNORE_PAUSE = false).*
}

// Broken twin: the cut ignores the quiet gate and falls under P's yes.
module straddler_ungated {
  import straddler_settlement(MAX_EPOCH = 3, IGNORE_QUIET = true, IGNORE_PAUSE = false).*
}

// Broken twin: intake stays open while P drains, so a quiet bit that
// has risen stops being true and the cut falls under a later yes.
module straddler_unpaused {
  import straddler_settlement(MAX_EPOCH = 3, IGNORE_QUIET = false, IGNORE_PAUSE = true).*
}
