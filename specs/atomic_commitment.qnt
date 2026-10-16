// Model C (register: specs/README.md) — cross-shard atomic commitment:
// provision → execute → state → read, with attested deadlines, checked
// for INV-EXEC-1 (same terminal outcome on every participating shard).
//
// Shard consensus is an oracle here (Model B): each shard is a monotone
// attested clock plus an ordered commit of the transaction, and each
// committee is honest (INV-SEC-1, priced separately in
// committee_security.md), so a shard's committed state says one thing at
// a time. A core member learns its sibling's verdict only by reading the
// sibling's committed state; no certificate crosses.
//
// Code anchors:
//   - Deadline and vote branches: `can_emit_vote`
//     (crates/execution/src/tick_state.rs) — fully provisioned (vote real
//     outcomes once committed_ts >= all_provisioned_at) or timed out
//     (all-abort once committed_ts >= tick_ts + MAX_FINALIZATION_DELAY).
//   - Stating: the tick's stating half settles a refusal on the shard's
//     own certificate and moves a success to `RowState::Stated`, beside a
//     `VerdictLeaf::Yes` (crates/storage/src/shard/members.rs).
//   - Reading: `sibling_said` and the hear step (members.rs) record the
//     newest reading of the sibling's leaf, or of its row and committed
//     marker where the leaf is absent: `Yes`, `Accepted` or `Left`.
//   - Deciding: `decide` (crates/types/src/shard/verdict.rs) — a stated
//     row accepts on any `Accepted`, refuses on any `Left`, accepts on a
//     `Yes` of every sibling, and waits otherwise; an accepted row ends
//     once every sibling has accepted or left.
//   - Exits: `Exit::of` (crates/engine/src/tick_select.rs) — a stated row
//     leaves only on what it hears; no deadline ends it.
//
// Modeling assumptions:
//   - One core transaction on two shards. INV-EXEC-4 (conflict tiebreak)
//     is deferred to a later revision of this model.
//   - Execution determinism is an axiom (INV-DET-1): success on both
//     shards is the same success, so outcomes are {SUCC, ABORT}.
//   - Clocks are per-shard monotone integers (Model A). Provisions are
//     delivered fully asynchronously. A reading is the sibling's committed
//     state at the instant it is taken; an older reading delivered late
//     loses to the newest, so delivery delay adds no behaviour a read at
//     the earlier instant does not have.
//   - No recovery, no departure: the tear a recovery leaves and a departed
//     sibling's terminal lines are shard_recovery.qnt's and
//     straddler_settlement.qnt's.
//
// Run:
//   quint typecheck specs/atomic_commitment.qnt
//   quint run    --main=commit_ok       --invariant=invAtomic specs/atomic_commitment.qnt
//   quint verify --main=commit_ok       --invariant=invAtomic --max-steps=8 specs/atomic_commitment.qnt
//   quint test   --main=commit_deadline --match=deadlineTear specs/atomic_commitment.qnt
//     (scripted witness: a stated row aborted at its deadline after its
//      sibling accepted on its yes)
//   quint verify --main=commit_deadline --invariant=invAtomic --max-steps=10 specs/atomic_commitment.qnt

module atomic_commitment {
  // Finalization delay in clock units.
  const TIMEOUT: int
  // Max clock advance per step.
  const MAX_TICK: int
  // Broken twin: a stated row also leaves at its deadline, as an
  // in-flight row does.
  const DEADLINE_EXITS_STATED: bool

  pure val SHARDS = Set(1, 2)
  pure def other(s: int): int = if (s == 1) 2 else 1

  // Outcomes and readings. NONE encodes absence in int-valued maps.
  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // Where a shard's row stands.
  pure val IN_FLIGHT = 10
  pure val STATED = 11
  pure val ACCEPTED = 12
  pure val GONE = 13

  // What a reading of a sibling says.
  pure val YES = 20
  pure val SAID_ACCEPTED = 21
  pure val LEFT = 22

  // Per-shard attested chain clock (monotone).
  var clock: int -> int
  // Clock value at which the shard committed the tx (NONE before): the
  // tick_ts, and the row written.
  var committedAt: int -> int
  // Clock value at which the shard absorbed the counterparty's provisions
  // (NONE before): all_provisioned_at.
  var provisionedAt: int -> int
  // The shard's row (NONE before it commits).
  var row: int -> int
  // The newest reading each shard's row holds of its sibling (NONE before
  // any).
  var heard: int -> int
  // Terminal verdict per shard (NONE until decided).
  var terminal: int -> int

  // What a reading of `s`'s committed state says now: the leaf where
  // present, else the row gone beside its committed marker.
  def said(s: int): int =
    if (row.get(s) == STATED) YES
    else if (row.get(s) == ACCEPTED) SAID_ACCEPTED
    else if (row.get(s) == GONE) LEFT
    else NONE

  action init = all {
    clock' = SHARDS.mapBy(s => 0),
    committedAt' = SHARDS.mapBy(s => NONE),
    provisionedAt' = SHARDS.mapBy(s => NONE),
    row' = SHARDS.mapBy(s => NONE),
    heard' = SHARDS.mapBy(s => NONE),
    terminal' = SHARDS.mapBy(s => NONE),
  }

  action tickBy(s: int, d: int): bool = all {
    clock' = clock.setBy(s, c => c + d),
    committedAt' = committedAt, provisionedAt' = provisionedAt,
    row' = row, heard' = heard, terminal' = terminal,
  }

  action tick = {
    nondet s = SHARDS.oneOf()
    nondet d = 1.to(MAX_TICK).oneOf()
    tickBy(s, d)
  }

  // The shard's chain commits the tx (consensus oracle): the row is
  // written in flight.
  action commitTxAt(s: int): bool = all {
    committedAt.get(s) == NONE,
    committedAt' = committedAt.put(s, clock.get(s)),
    row' = row.put(s, IN_FLIGHT),
    clock' = clock, provisionedAt' = provisionedAt,
    heard' = heard, terminal' = terminal,
  }

  action commitTx = { nondet s = SHARDS.oneOf() commitTxAt(s) }

  // The destination absorbs the counterparty's provisions, any time after
  // both sides committed.
  action absorbAt(dst: int): bool = all {
    provisionedAt.get(dst) == NONE,
    committedAt.get(dst) != NONE,
    committedAt.get(other(dst)) != NONE,
    provisionedAt' = provisionedAt.put(dst, clock.get(dst)),
    clock' = clock, committedAt' = committedAt,
    row' = row, heard' = heard, terminal' = terminal,
  }

  action absorbProvisions = { nondet dst = SHARDS.oneOf() absorbAt(dst) }

  // The stating half commits on the shard's own certificate —
  // `can_emit_vote`, both branches. A success states a yes; a refusal
  // settles there, and the row goes.
  action stateAs(s: int, o: int): bool = all {
    row.get(s) == IN_FLIGHT,
    if (o == SUCC)
      provisionedAt.get(s) != NONE and clock.get(s) >= provisionedAt.get(s)
    else
      provisionedAt.get(s) == NONE and clock.get(s) >= committedAt.get(s) + TIMEOUT,
    row' = row.put(s, if (o == SUCC) STATED else GONE),
    terminal' = if (o == SUCC) terminal else terminal.put(s, ABORT),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, heard' = heard,
  }

  action state = {
    nondet s = SHARDS.oneOf()
    nondet o = Set(SUCC, ABORT).oneOf()
    stateAs(s, o)
  }

  // A sibling not yet committed has no row to read, and an absence with
  // no committed marker beside it is no reading.
  action readAt(dst: int, reading: int): bool = all {
    row.get(dst) == STATED or row.get(dst) == ACCEPTED,
    reading != NONE,
    heard' = heard.put(dst, reading),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, row' = row, terminal' = terminal,
  }

  // A claim on the sibling's state at its current committed instant
  // lands on the reader's chain: the newest reading wins.
  action read = {
    nondet dst = SHARDS.oneOf()
    readAt(dst, said(other(dst)))
  }

  // `decide` over a stated row: accept on an accepted or yes sibling,
  // refuse by an abort line on one that left.
  action decideAt(s: int): bool = all {
    row.get(s) == STATED,
    heard.get(s) == YES or heard.get(s) == SAID_ACCEPTED or heard.get(s) == LEFT,
    row' = row.put(s, if (heard.get(s) == LEFT) GONE else ACCEPTED),
    terminal' = terminal.put(s, if (heard.get(s) == LEFT) ABORT else SUCC),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, heard' = heard,
  }

  action decide = { nondet s = SHARDS.oneOf() decideAt(s) }

  // An accepted row ends once its sibling has accepted or left.
  action endAt(s: int): bool = all {
    row.get(s) == ACCEPTED,
    heard.get(s) == SAID_ACCEPTED or heard.get(s) == LEFT,
    row' = row.put(s, GONE),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, heard' = heard, terminal' = terminal,
  }

  action end = { nondet s = SHARDS.oneOf() endAt(s) }

  // The broken twin's exit: a stated row aborted at its deadline, as a
  // record or a clock ends an in-flight row.
  action deadlineAbortAt(s: int): bool = all {
    DEADLINE_EXITS_STATED,
    row.get(s) == STATED,
    clock.get(s) >= committedAt.get(s) + TIMEOUT,
    row' = row.put(s, GONE),
    terminal' = terminal.put(s, ABORT),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, heard' = heard,
  }

  action deadlineAbort = { nondet s = SHARDS.oneOf() deadlineAbortAt(s) }

  action step = any {
    tick, commitTx, absorbProvisions, state, read, decide, end, deadlineAbort,
  }

  // INV-EXEC-1: shards that reached a terminal verdict agree on it.
  val invAtomic = SHARDS.forall(x => SHARDS.forall(y =>
    terminal.get(x) == NONE or terminal.get(y) == NONE or
    terminal.get(x) == terminal.get(y)))

  // The leaf is the row: a shard reads `Yes` exactly while its sibling's
  // row is stated, so an accept rests on a yes that has not been refused.
  val invAcceptOnYes = SHARDS.forall(s =>
    terminal.get(s) != SUCC or terminal.get(other(s)) != ABORT)

  // The deadline twin, scripted: both shards state a yes, shard 2 reads
  // shard 1's and accepts, and shard 1's stated row is aborted at its
  // deadline.
  run deadlineTear =
    init
      .then(commitTxAt(1))
      .then(commitTxAt(2))
      .then(absorbAt(1))
      .then(absorbAt(2))
      .then(stateAs(1, SUCC))
      .then(stateAs(2, SUCC))
      .then(readAt(2, YES))
      .then(decideAt(2))
      .then(tickBy(1, TIMEOUT))
      .then(deadlineAbortAt(1))
      .expect(not(invAtomic))
}

// Healthy configuration: a stated row leaves only on what it hears.
// Deadline heterogeneity, late provisions, and every reading
// interleaving are in scope — atomicity must survive them on the
// reading rule alone.
module commit_ok {
  import atomic_commitment(TIMEOUT = 3, MAX_TICK = 4, DEADLINE_EXITS_STATED = false).*
}

// Broken twin: a stated row also leaves at its deadline. A sibling that
// accepted on its yes keeps its accept, and the route is torn.
module commit_deadline {
  import atomic_commitment(TIMEOUT = 3, MAX_TICK = 4, DEADLINE_EXITS_STATED = true).*
}
