// Model D (register: specs/README.md) — straddler settlement: atomicity
// across a terminating shard, INV-RESHAPE-5 composed with Model C's
// reading rule.
//
// Shard 1 is P (terminates at a reshape cut); shard 2 is Q (survivor).
// One core transaction may straddle the boundary. Each shard states its
// own outcome; a stated row accepts only on the sibling's committed
// state. Once P is gone, Q reads P from the `End` lines of P's terminal
// block, which names every accepted row P still held, and fates every
// other row.
//
// Code anchors:
//   - Terminating: `terminates_at_next_boundary` (crates/types/src/
//     topology/schedule.rs), read at a block's anchor epoch. Through P's
//     final epoch a core transaction toward P is not admitted on either
//     shard (`TransactionsSection::admit`, crates/shard/src/admission.rs)
//     and a pending core member is not run (`select_members`,
//     crates/engine/src/tick_select.rs).
//   - `value_of` (crates/types/src/shard/verdict.rs): a live sibling's
//     `Yes` counts only where the sibling is not terminating and the
//     reading is at most an epoch old; a gone sibling's accept is an
//     `Accepted` entry or its name among the terminal's `End` lines, and
//     its absence there is `Left`.
//   - `terminal_fates` (tick_select.rs): `End` for an accepted row, a
//     fate for every other.
//   - A terminating shard's readings for its stated rows ride first
//     within the verdict claims' budget (`select_claims`,
//     crates/shard/src/proposal.rs).
//
// Modeling assumptions:
//   - One core transaction on two shards; execution determinism and
//     honest committees as in Model C.
//   - Epochs are a global counter. P is terminating through epoch
//     CUT - 1 and gone from CUT, its terminal committed at the
//     transition.
//   - A reading is the sibling's committed state at the instant it is
//     taken, marked with that epoch; the newest wins.
//   - The final epoch suffices for P to read an accept Q made before it:
//     P's terminal is not taken while Q's row accepted before P's final
//     epoch and P's row still stands stated. Without that assumption the
//     tear is the plan's residual 2, a fault (a cut lasting P's whole last
//     epoch).
//
// Run:
//   quint typecheck specs/straddler_settlement.qnt
//   quint run    --main=straddler_ok          --invariant=invAll specs/straddler_settlement.qnt
//   quint verify --main=straddler_ok          --invariant=invAll --max-steps=10 specs/straddler_settlement.qnt
//   quint test   --main=straddler_unterminating --match=finalEpochYes specs/straddler_settlement.qnt
//     (scripted witness: Q counts P's yes in P's final epoch, P never
//      reads Q's accept before its cut, and its terminal fates the row)
//   quint verify --main=straddler_unterminating --invariant=invAtomic --max-steps=10 specs/straddler_settlement.qnt

module straddler_settlement {
  // The epoch at which P's terminal has committed.
  const CUT: int
  // Broken twin: a sibling's yes counts whether or not it is terminating,
  // and a core transaction toward a terminating shard is admitted.
  const IGNORE_TERMINATING: bool

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

  // The global epoch.
  var epoch: int
  // Each shard's row (NONE before it commits).
  var row: int -> int
  // The epoch each shard's row accepted at (NONE otherwise).
  var acceptedAt: int -> int
  // The newest reading each shard holds of its sibling, and its epoch.
  var heard: int -> int
  var heardAt: int -> int
  // Whether P's terminal ended the transaction by an `End` line (NONE
  // before the terminal).
  var ended: int
  // Terminal verdict per shard.
  var terminal: int -> int

  def terminating: bool = not(IGNORE_TERMINATING) and epoch == CUT - 1
  def pGone: bool = epoch >= CUT

  def said(s: int): int =
    if (row.get(s) == STATED) YES
    else if (row.get(s) == ACCEPTED) SAID_ACCEPTED
    else if (row.get(s) == GONE) LEFT
    else NONE

  // `value_of` of `s`'s sibling as `s` decides at the current epoch:
  // SAID_ACCEPTED, LEFT, YES (counted), or NONE (wait).
  def value(s: int): int =
    if (s == Q and pGone)
      if (heard.get(s) == SAID_ACCEPTED) SAID_ACCEPTED
      else if (ended == 1) SAID_ACCEPTED
      else LEFT
    else if (heard.get(s) == SAID_ACCEPTED) SAID_ACCEPTED
    else if (heard.get(s) == LEFT) LEFT
    else if (heard.get(s) == YES and heardAt.get(s) + 1 >= epoch
             and not(other(s) == P and terminating)) YES
    else NONE

  action init = all {
    epoch' = 0,
    row' = SHARDS.mapBy(s => NONE),
    acceptedAt' = SHARDS.mapBy(s => NONE),
    heard' = SHARDS.mapBy(s => NONE),
    heardAt' = SHARDS.mapBy(s => NONE),
    ended' = NONE,
    terminal' = SHARDS.mapBy(s => NONE),
  }

  // Both shards admit the transaction, outside P's final epoch.
  action commitAt(s: int): bool = all {
    row.get(s) == NONE,
    not(pGone),
    not(terminating),
    row' = row.put(s, IN_FLIGHT),
    epoch' = epoch, acceptedAt' = acceptedAt, heard' = heard,
    heardAt' = heardAt, ended' = ended, terminal' = terminal,
  }

  // The stating half: a yes or a refusal. A pending member is not run
  // while P is terminating.
  action stateAs(s: int, o: int): bool = all {
    row.get(s) == IN_FLIGHT,
    not(s == P and pGone),
    not(terminating),
    row' = row.put(s, if (o == SUCC) STATED else GONE),
    terminal' = if (o == SUCC) terminal else terminal.put(s, ABORT),
    epoch' = epoch, acceptedAt' = acceptedAt, heard' = heard,
    heardAt' = heardAt, ended' = ended,
  }

  // A reading of the live sibling's committed state lands.
  action readAt(s: int): bool = all {
    row.get(s) == STATED or row.get(s) == ACCEPTED,
    not(s == P and pGone),
    not(s == Q and pGone),
    said(other(s)) != NONE,
    heard' = heard.put(s, said(other(s))),
    heardAt' = heardAt.put(s, epoch),
    epoch' = epoch, row' = row, acceptedAt' = acceptedAt,
    ended' = ended, terminal' = terminal,
  }

  action decideAt(s: int): bool = all {
    row.get(s) == STATED,
    not(s == P and pGone),
    value(s) != NONE,
    row' = row.put(s, if (value(s) == LEFT) GONE else ACCEPTED),
    acceptedAt' = if (value(s) == LEFT) acceptedAt else acceptedAt.put(s, epoch),
    terminal' = terminal.put(s, if (value(s) == LEFT) ABORT else SUCC),
    epoch' = epoch, heard' = heard, heardAt' = heardAt, ended' = ended,
  }

  // An accepted row ends once its sibling has accepted or left.
  action endAt(s: int): bool = all {
    row.get(s) == ACCEPTED,
    not(s == P and pGone),
    value(s) == SAID_ACCEPTED or value(s) == LEFT,
    row' = row.put(s, GONE),
    epoch' = epoch, acceptedAt' = acceptedAt, heard' = heard,
    heardAt' = heardAt, ended' = ended, terminal' = terminal,
  }

  // The epoch advances; at CUT, P's terminal commits: `End` for an
  // accepted row, a fate for every other. Not taken while P has yet to
  // read an accept Q made before P's final epoch.
  action advance: bool = all {
    not(pGone),
    epoch + 1 == CUT implies not(
      row.get(P) == STATED and acceptedAt.get(Q) != NONE and acceptedAt.get(Q) < CUT - 1),
    epoch' = epoch + 1,
    ended' = if (epoch + 1 == CUT) (if (row.get(P) == ACCEPTED) 1 else 0) else ended,
    row' = if (epoch + 1 == CUT and row.get(P) != NONE) row.put(P, GONE) else row,
    terminal' = if (epoch + 1 == CUT and row.get(P) != NONE and row.get(P) != ACCEPTED
                    and terminal.get(P) == NONE)
                  terminal.put(P, ABORT)
                else terminal,
    acceptedAt' = acceptedAt, heard' = heard, heardAt' = heardAt,
  }

  action step = any {
    advance,
    nondet s = SHARDS.oneOf()
    any {
      commitAt(s),
      nondet o = Set(SUCC, ABORT).oneOf()
      stateAs(s, o),
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
  val invTerminalClears = pGone implies row.get(P) == NONE or row.get(P) == GONE

  val invAll = invAtomic and invTerminalClears

  // The terminating twin, scripted: in P's final epoch Q counts P's yes
  // and accepts, P never reads Q's accept, and P's terminal fates its
  // stated row.
  run finalEpochYes =
    init
      .then(commitAt(P))
      .then(commitAt(Q))
      .then(stateAs(P, SUCC))
      .then(stateAs(Q, SUCC))
      .then(advance)
      .then(readAt(Q))
      .then(decideAt(Q))
      .then(advance)
      .expect(not(invAtomic))
}

// Healthy configuration: P's cut at epoch 2, so its final epoch is 1.
module straddler_ok {
  import straddler_settlement(CUT = 2, IGNORE_TERMINATING = false).*
}

// Broken twin: no terminating rule. Q accepts on P's yes in P's final
// epoch, which P has no epoch left to read.
module straddler_unterminating {
  import straddler_settlement(CUT = 2, IGNORE_TERMINATING = true).*
}
