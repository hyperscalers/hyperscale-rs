// Model L (register: specs/README.md) — the crossing lifecycle: an
// escrowed value crossing is issued by its producer's shard and disposed
// at most once (INV-EXEC-11), never left with no admissible disposal
// (INV-EXEC-12), and never lost to a recovery of the consumer.
// Both disposals are the producer's commit fold reading the consumer's
// one answer of the issuing transaction at a boundary of the consumer's
// shard: retired on its `Taken`, taken back on its `Never`.
//
// One crossing of one transaction T, two shards: the producer P and the
// consumer C. Shard consensus is an oracle (Model B): a chain is a
// monotone attested clock plus ordered commits, and a committee is honest
// (INV-SEC-1). The adversary is C's halt recovery: it discards the suffix
// of C's committed state above the last boundary the beacon recorded for
// C, and the member C's chain held then may run again.
//
// Code anchors:
//   - The take: a member of T on C runs only while its block's anchor is
//     before T's deadline and is named `Aborted` past it (`select_members`
//     in crates/engine/src/tick_select.rs), writes `Taken`, and the
//     kernel refuses it where T's `Never` already stands (`standing_marker`
//     in vm/crates/kernel/src/executor.rs; `SCREEN` here).
//   - The refusal: a member that aborts writes T's `Never` where no answer
//     of T stands (`never_answers` in crates/engine/src/executor.rs).
//   - The decline: C's commit fold writes T's `Never` for a record it
//     holds a reading of, where the block's anchor is at or past T's
//     validity end, T's member row reads absent at the parent, and no
//     answer of T stands (`unclaimed_declines` in
//     crates/storage/src/shard/crossings.rs).
//   - The retirement: P's commit fold removes the record on T's `Taken`
//     read present at a boundary of C (`StateClaim::retires`, which reads
//     `StateClaim::attested`; `crossing_settlements` in
//     crates/storage/src/shard/crossings.rs), never on a fresh one, which
//     a recovery of C may discard.
//   - The return: P's commit fold removes the record and credits the cell
//     its value left on T's `Never` read present at a boundary of C
//     (`reclaimed` and `reclaim_credits` in
//     crates/storage/src/shard/crossings.rs, `StateClaim::at_boundary`),
//     never on a fresh one, which a recovery of C may discard.
//
// Modeling assumptions:
//   - One clock: P's chain issues before T's validity end on the clock C's
//     rules read, so the two chains' skew enters nothing modelled here.
//   - A reading is P's the moment C's state holds it: carriage, pacing and
//     the read frontier are liveness, and a reading that never arrives
//     leaves the record standing, which `invDisposed` would report.
//   - Owed crossings are not modelled: nothing takes one back
//     (`Terms::Owed`, which `reclaimed` filters out), and C's fold credits
//     it.
//   - A chain holding both ends reads at its own parent, which is that
//     chain's own durable state; it is the boundary case with every block
//     a boundary.
//   - Answers are never deleted: the deletion of T's answer once P's
//     record is read absent at a boundary of P with T's member exited
//     there (`crossing_settlements`, `exit_proven`) is outside the model.
//   - P never recovers: a take or a credit read off a suffix of P's that
//     a recovery discards is outside the model.
//   - C may fate T's row, ending it with no answer written (`FATES`); the
//     `fates_ok` instance checks the healthy rules with it.
//
// Run (quint 0.32.0, Apalache 0.56.1, OpenJDK 17):
//   quint typecheck specs/crossing_lifecycle.qnt
//   # healthy instances (each about 12s at depth 14):
//   quint verify --main=crossing_ok   --invariant=invAll --max-steps=14 specs/crossing_lifecycle.qnt
//   quint verify --main=unscreened_ok --invariant=invAll --max-steps=14 specs/crossing_lifecycle.qnt
//   quint verify --main=fates_ok      --invariant=invAll --max-steps=14 specs/crossing_lifecycle.qnt
//   # twins, each violating at its floor (7, 7, 6, 4, 5) and clean one step below it:
//   quint verify --main=fresh_never_return     --invariant=invExclusive --max-steps=7 specs/crossing_lifecycle.qnt
//   quint verify --main=decline_beside_a_row   --invariant=invExclusive --max-steps=7 specs/crossing_lifecycle.qnt
//   quint verify --main=decline_before_the_end --invariant=invExclusive --max-steps=6 specs/crossing_lifecycle.qnt
//   quint verify --main=no_decline             --invariant=invDisposed  --max-steps=4 specs/crossing_lifecycle.qnt
//   quint verify --main=fresh_taken_retire     --invariant=invConserved --max-steps=5 specs/crossing_lifecycle.qnt
// Give every concurrent `verify` its own `--server-endpoint=localhost:<port>`.

module crossing_core {
  // T's validity end: P issues and C admits T only before it.
  const END: int
  // T's deadline: a member of T runs only before it.
  const DEADLINE: int
  // The earliest C clock the decline is written at. Healthy: END.
  // Twin `decline_before_the_end`: 0.
  const DECLINE_FROM: int
  // Whether the decline reads T's member row absent. Twin
  // `decline_beside_a_row`: false.
  const ROW_CHECK: bool
  // Whether C's fold declines at all. Twin `no_decline`: false.
  const DECLINE: bool
  // Whether the kernel refuses a take under T's own `Never`. The healthy
  // instance holds with it and without it (`unscreened_ok`): the decline
  // rule alone carries exclusivity, and the screen is its backstop.
  const SCREEN: bool
  // Whether P returns the record on a fresh `Never` rather than on one
  // read at a boundary of C. Twin `fresh_never_return`: true.
  const FRESH_NEVER: bool
  // Whether P retires the record on a fresh `Taken` rather than on one
  // read at a boundary of C. Twin `fresh_taken_retire`: true.
  const FRESH_TAKEN: bool
  // Whether C's chain may fate T's row, ending it with no answer written
  // (a terminal, or a member nobody can answer for). `fates_ok`: true.
  const FATES: bool
  // How many recoveries of C the run may take.
  const MAX_RECOVERIES: int
  // Max clock advance per step, and where the clock stops.
  const MAX_TICK: int
  const MAX_CLOCK: int

  pure val NONE = "none"
  pure val STANDING = "standing"
  pure val GONE = "gone"
  pure val TAKEN = "taken"
  pure val NEVER = "never"

  // C's attested chain clock (monotone, through recoveries too).
  var clock: int
  // P's leg ran and wrote the record.
  var issued: bool
  // The record stands in P's state.
  var recordStands: bool
  // P's fold removed the record on T's `Taken`.
  var retired: bool
  // P's fold took the record back on T's `Never`.
  var returned: bool
  // C's committed state: whether C committed T, T's member row, and T's
  // one answer.
  var committed: bool
  var row: str
  var answer: str
  // The same, as of the last boundary the beacon recorded for C: what a
  // recovery of C cannot discard.
  var durableCommitted: bool
  var durableRow: str
  var durableAnswer: str
  var recoveries: int

  action init = all {
    clock' = 0,
    issued' = false,
    recordStands' = false,
    retired' = false,
    returned' = false,
    committed' = false,
    row' = NONE,
    answer' = NONE,
    durableCommitted' = false,
    durableRow' = NONE,
    durableAnswer' = NONE,
    recoveries' = 0,
  }

  action keepProducer = all {
    issued' = issued, recordStands' = recordStands,
    retired' = retired, returned' = returned,
  }

  action keepConsumer = all {
    committed' = committed, row' = row, answer' = answer,
  }

  action keepDurable = all {
    durableCommitted' = durableCommitted, durableRow' = durableRow,
    durableAnswer' = durableAnswer, recoveries' = recoveries,
  }

  action tick = {
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      clock + d <= MAX_CLOCK,
      clock' = clock + d,
      keepProducer, keepConsumer, keepDurable,
    }
  }

  // P's leg runs before T's validity end and writes the record.
  val canIssue = not(issued) and clock < END
  action issue = all {
    canIssue,
    issued' = true, recordStands' = true,
    retired' = retired, returned' = returned,
    clock' = clock, keepConsumer, keepDurable,
  }

  // C's chain commits T before its validity end, writing its member row.
  val canCommit = not(committed) and clock < END
  action commitT = all {
    canCommit,
    committed' = true, row' = STANDING, answer' = answer,
    clock' = clock, keepProducer, keepDurable,
  }

  // T's member on C runs before the deadline over the record's arrival
  // and takes the crossing.
  val canTake = row == STANDING and issued and clock < DEADLINE
    and (not(SCREEN) or answer != NEVER)
  action take = all {
    canTake,
    answer' = TAKEN, row' = GONE, committed' = committed,
    clock' = clock, keepProducer, keepDurable,
  }

  // T's member on C aborts, writing T's `Never` where no answer of T
  // stands.
  val canRefuse = row == STANDING
  action refuse = all {
    canRefuse,
    answer' = if (answer == NONE) NEVER else answer,
    row' = GONE, committed' = committed,
    clock' = clock, keepProducer, keepDurable,
  }

  // C's fold declines a record it holds a reading of.
  val canDecline = DECLINE and recordStands and clock >= DECLINE_FROM
    and (not(ROW_CHECK) or row != STANDING) and answer == NONE
  action decline = all {
    canDecline,
    answer' = NEVER, row' = row, committed' = committed,
    clock' = clock, keepProducer, keepDurable,
  }

  // The beacon records a boundary of C: what C holds now is durable.
  val atBoundary = durableCommitted == committed and durableRow == row
    and durableAnswer == answer
  action boundary = all {
    not(atBoundary),
    durableCommitted' = committed, durableRow' = row, durableAnswer' = answer,
    recoveries' = recoveries,
    clock' = clock, keepProducer, keepConsumer,
  }

  // C halts and recovers: the suffix above its last boundary is
  // discarded.
  action recover = all {
    recoveries < MAX_RECOVERIES,
    not(atBoundary),
    committed' = durableCommitted, row' = durableRow, answer' = durableAnswer,
    recoveries' = recoveries + 1,
    durableCommitted' = durableCommitted, durableRow' = durableRow,
    durableAnswer' = durableAnswer,
    clock' = clock, keepProducer,
  }

  // C's chain fates T's row; no answer is written.
  action fate = all {
    FATES, row == STANDING,
    row' = GONE, answer' = answer, committed' = committed,
    clock' = clock, keepProducer, keepDurable,
  }

  // P's fold retires the record on T's `Taken`.
  val takenRead = if (FRESH_TAKEN) answer == TAKEN else durableAnswer == TAKEN
  val canRetire = recordStands and takenRead
  action retire = all {
    canRetire,
    recordStands' = false, retired' = true,
    issued' = issued, returned' = returned,
    clock' = clock, keepConsumer, keepDurable,
  }

  // P's fold takes the record back on T's `Never`.
  val neverRead = if (FRESH_NEVER) answer == NEVER else durableAnswer == NEVER
  val canReturn = recordStands and neverRead
  action giveBack = all {
    canReturn,
    recordStands' = false, returned' = true,
    issued' = issued, retired' = retired,
    clock' = clock, keepConsumer, keepDurable,
  }

  action step = any {
    tick, issue, commitT, take, refuse, decline, boundary, recover, retire,
    giveBack, fate,
  }

  // INV-EXEC-11: the crossing goes back to P only where C holds no take
  // of it.
  val invExclusive = not(returned and answer == TAKEN)

  // The crossing leaves P on a retirement only where C holds its take:
  // no recovery of C leaves the value gone from P and never arrived.
  val invConserved = not(retired and answer != TAKEN)

  // C's one answer of T is never contradicted once it is durable.
  val invAnswerStable = durableAnswer != NONE implies answer == durableAnswer

  // Nothing but a recovery is left to happen.
  val quiescent = not(canIssue or canCommit or canTake or canRefuse
    or canDecline or canRetire or canReturn) and atBoundary

  // INV-EXEC-12: once the clock has run out and nothing is left to
  // happen, the record is gone.
  val invDisposed = (clock == MAX_CLOCK and quiescent) implies not(recordStands)

  val invAll = invExclusive and invConserved and invAnswerStable and invDisposed
}

// Healthy: the decline from T's validity end over T's row read absent,
// the screen, and the retirement and the return on an answer read at a
// boundary of C.
module crossing_ok {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = true,
    SCREEN = true, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Healthy without the screen: the decline rule alone keeps a take from
// following a `Never` of T.
module unscreened_ok {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = true,
    SCREEN = false, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Twin: P returns the record on a fresh `Never`. T's member refuses
// before its deadline, P takes the record back, C recovers below the
// refusal, and the member runs again and takes the crossing.
module fresh_never_return {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = true,
    SCREEN = true, FRESH_NEVER = true, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Twin: the decline reads no member row, and no screen stands behind it.
// C declines past the validity end while T's member still waits, P takes
// the record back, and the member takes the crossing before the deadline.
module decline_beside_a_row {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = false, DECLINE = true,
    SCREEN = false, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Twin: the decline is written before the validity end, with no screen
// behind it. C declines before it commits T, then commits it, and the
// member takes the crossing the producer took back.
module decline_before_the_end {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 0, ROW_CHECK = true, DECLINE = true,
    SCREEN = false, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Twin: C's fold never declines. A record whose consumer's chain never
// commits T stands with nobody to answer for it.
module no_decline {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = false,
    SCREEN = true, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// The healthy instance with C's fate of T's row.
module fates_ok {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = true,
    SCREEN = true, FRESH_NEVER = false, FRESH_TAKEN = false, FATES = true,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}

// Twin: P retires the record on a fresh `Taken`. T's member takes the
// crossing, P retires the record, and C recovers below the take: the
// value has left P and C holds no take of it.
module fresh_taken_retire {
  import crossing_core(
    END = 2, DEADLINE = 3, DECLINE_FROM = 2, ROW_CHECK = true, DECLINE = true,
    SCREEN = true, FRESH_NEVER = false, FRESH_TAKEN = true, FATES = false,
    MAX_RECOVERIES = 2, MAX_TICK = 2, MAX_CLOCK = 5
  ).*
}
