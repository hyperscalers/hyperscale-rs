// Model J (register: specs/README.md) — VM cross-shard fee assurance:
// payer-first commitment with the max_fee reservation as block validity,
// commit-proof-gated counterpart engagement, engagement-echo-gated payer
// voting with the validity-window deadline abort at the floor, and the
// successor sweep under payer-shard termination. Checked for INV-VM-HOST-1
// (no counterpart engages without an engaged reservation), INV-VM-HOST-2
// (every engaged reservation resolves exactly once, burn classes by
// verdict, conservation), INV-VM-HOST-3 (the payer speaks once, on its own
// chain content), and INV-VM-OBJ-2's fee-side clause (a bond is posted only
// against substates that committed, and a balance that cannot cover one
// records debt rather than forgiving it).
//
// Shard P is the payer's (fee_payer's prefix routes there); shard Q is a
// non-payer counterpart. One cross-shard VM transaction whose legs are
// commutative (empty dependency sets), so the payer's bundle carries
// transaction hashes and no state — it exists because it is the
// engagement evidence, not because state needs provisioning.
//
// Model C (atomic_commitment.qnt) supplies the EC-exchange shape: shard
// consensus is an oracle, committees are honest (INV-SEC-1), emitted ECs
// deliver asynchronously, success finalization needs unanimous coverage.
// The fee layer this model adds on top:
//   - P's block commits the transaction only if the payer's balance
//     covers max_fee; commitment engages the reservation (held, not
//     spent).
//   - Q engages — its commit of the transaction, which in the
//     implementation is proposal inclusion, lock acquisition, and its
//     own execution — only holding the commit proof.
//   - Engagement is barred outside the transaction's validity window on
//     Q's attested clock, and engagement emits an echo toward P: Q's
//     committing block owes the payer a (possibly empty) bundle, the
//     mirror of the payer bundle Q engaged on.
//   - P executes at commit but votes once, on a condition that is a pure
//     function of its own chain: success when every counterpart's
//     engagement echo has committed into P's chain, or all-abort when
//     its attested clock passes the window without one. Because P never
//     speaks twice, the window-edge race — Q engaging late with its
//     success EC in flight — resolves through worst-wins as a mutual
//     abort, never a verdict split. The deadline threshold needs no skew
//     bound for safety; a margin above the window end only tunes how
//     often a could-have-succeeded transaction pays the floor.
//   - Resolution at P: success burns ACTUAL, releases the surplus, and
//     posts the committed substates' bond — out of balance where it
//     reaches, as recorded debt where it does not. Any abort burns FLOOR
//     and releases the remainder, and posts no bond at all: it wrote no
//     substates, which is the same fact that makes it atomic.
//   - P terminating mid-flight (reshape) stamps abort-by-omission for an
//     unfinalized transaction (Model D's rule) and the successor sweep resolves
//     the reservation it inherited; abandonment is modeled atomic with the
//     terminal stamp.
//
// Where this abstraction is stricter than the implementation, and why
// that is the safe direction: the model treats a reservation as a
// substate that moves with the subtree, so a successor must sweep what it
// inherits and the `fee_unswept` twin exhibits the wedge when it does
// not. The implementation's reservation is a committed cell under the
// payer vault's owner, beside a per-vault total. The model debits the
// ceiling when the reservation engages; the implementation leaves the
// balance where it is and judges every debit of the vault under the
// holds standing on it. The two make the same value unavailable for as
// long as the reservation stands.
// Two consequences of that gap are worth naming rather than reading off
// the model: a terminal that leaves a transaction unfinalized settles no receipt
// and so burns nothing, where the model burns FLOOR; and the abstraction
// cannot see that a payer's own withdraw declares the vault its fee burns
// from, which is what makes a reservation's encumbrance indistinguishable
// from a conflict lock in any end-to-end test.
//
// Code anchors:
//   - Reservation as block validity: the `VerifyVmReservations`
//     verification (crates/shard) demanded from chain content.
//   - Engagement gate: the proposal seam consults the
//     `ProvisioningTracker` (crates/execution/src/provisioning.rs) —
//     the payer's bundle is absorbable only against a commit-proven
//     header (`on_committed_remote_header`,
//     crates/provisions/src/coordinator.rs), so "payer ∈ received"
//     is the commit proof held.
//   - Engagement echo: every VM participant's commit emits its bundle
//     to the payer (`provision_tx_roots` fan-out + the emit/serve
//     paths); absorption records it per (tx, source shard).
//   - Payer vote gating: `TickState::can_emit_vote`
//     (crates/execution/src/tick_state.rs) gains the engagement-coverage
//     requirement beside the dispatch requirement, with the same
//     all-abort vote shape as the unprovisioned timeout.
//   - Burn and release: transaction finalization at the payer shard; the abort
//     floor rides the fee record on the payer's EC outcomes.
//   - Successor sweep: the straddler abandonment at the deadline
//     (crates/execution/src/coordinator.rs), extended to resolve
//     inherited reservations.
//
// Modeling assumptions (on top of Model C's):
//   - One transaction, transaction = transaction; amounts are integers with
//     FLOOR < ACTUAL < MAX_FEE so the burn classes are distinguishable.
//   - Execution outcomes are honest-success: a user-error abort at Q
//     resolves through the same abort-dominant EC exchange and burns the
//     same floor class, so it adds no new fee behavior.
//   - Per-shard clocks advance independently with no skew bound: the
//     deadline vote's safety must not depend on one, and doesn't.
//   - When both vote conditions hold (the echo committed after the
//     deadline passed but before P voted), the implementation picks by
//     chain order deterministically; the model leaves both enabled so
//     safety is checked under either choice.
//   - Atomicity under P's termination is Model D's property (the
//     straddler fence, INV-RESHAPE-5) and is taken as an oracle:
//     invAtomic is scoped to runs where P has not terminated. This model
//     checks only that the reservation resolves under termination.
//   - Liveness is not checked temporally (as in Model C): "terminally
//     settles or releases" is checked as safety at every terminal state,
//     plus the scripted deadline-abort run.
//
// Run:
//   quint typecheck specs/vm_fee_assurance.qnt
//   quint verify --main=fee_ok        --invariant=invAll --max-steps=12 specs/vm_fee_assurance.qnt
//     (the shipped gate: engagement on commit proof, payer votes on echo
//      or deadline, conservation, resolution at every terminal)
//   quint verify --main=fee_insolvent --invariant=invAllIdle --max-steps=12 specs/vm_fee_assurance.qnt
//     (an insolvent payer commits nowhere and engages nothing)
//   quint test   --main=fee_ok        --match=deadlineFloor specs/vm_fee_assurance.qnt
//     (scripted: no engagement echo ever commits; P's deadline vote
//      resolves the reservation at the floor)
//   quint test   --main=fee_ok        --match=echoRace specs/vm_fee_assurance.qnt
//     (scripted: Q engages at the window edge, its success EC in flight,
//      while P's deadline vote fires — both sides abort, consistently)
//   quint verify --main=fee_indebted  --invariant=invAll --max-steps=10 specs/vm_fee_assurance.qnt
//     (the bond outruns the balance: the shortfall is recorded as debt)
//   quint verify --main=fee_bonded_abort --invariant=invNoBondOnAbort --max-steps=12 specs/vm_fee_assurance.qnt
//     (broken twin: an abort bonds substates it never wrote)
//   quint verify --main=fee_ungated   --invariant=invEngageGated --max-steps=8 specs/vm_fee_assurance.qnt
//     (ungated twin: an optimistic counterpart engages locks for an
//      insolvent payer that never commits)
//   quint test   --main=fee_certified --match=certifiedAbandon specs/vm_fee_assurance.qnt
//   quint verify --main=fee_certified --invariant=invEngageGated --max-steps=8 specs/vm_fee_assurance.qnt
//     (certified-not-committed twin: the payer's certified block is
//      abandoned on a fork after the counterpart engaged)
//   quint verify --main=fee_unswept   --invariant=invResolvedAtTerminal --max-steps=12 specs/vm_fee_assurance.qnt
//     (no-sweep twin: P terminates holding the reservation forever)
//   quint test   --main=fee_timer     --match=timerSplit specs/vm_fee_assurance.qnt
//   quint verify --main=fee_timer     --invariant=invAtomicScoped --max-steps=12 specs/vm_fee_assurance.qnt
//     (local-timer twin: P votes success ungated and later expires on
//      its own clock — a second statement; Q finalizes success while P
//      aborts, the verdict split the echo gate exists to prevent)

module vm_fee_assurance {
  // Max clock advance per step.
  const MAX_TICK: int
  // The signed fee ceiling the payer's block reserves.
  const MAX_FEE: int
  // The EC-attested actual a success burns. FLOOR < ACTUAL < MAX_FEE.
  const ACTUAL: int
  // The abort-class floor.
  const FLOOR: int
  // The storage bond a committed transaction's substates carry. Posted
  // out of the payer's balance at settlement, refundable to whoever
  // later deletes them — burned value and bonded value are different
  // things, and INV-VM-OBJ-2 conserves the second.
  const BOND: int
  // Broken twin: an abort posts a bond for substates it never wrote.
  const BOND_ON_ABORT: bool
  // The payer's liquid balance at genesis.
  const BALANCE: int
  // The validity window's end on each shard's attested clock: engagement
  // is barred strictly after it at Q; P's deadline vote arms strictly
  // after it at P.
  const WINDOW: int
  // Broken twin: Q engages without the commit proof (the ungated
  // optimistic counterpart).
  const ENGAGE_UNGATED: bool
  // Broken twin: the payer's bundle is consumable against a certified
  // header, before the block commit-proves.
  const ENGAGE_ON_CERTIFIED: bool
  // Healthy: P's success vote waits for the engagement echo to commit on
  // its own chain. Twin: P votes success at commit, before knowing
  // whether any counterpart will ever engage.
  const VOTE_ON_ECHO: bool
  // Broken twin: P, having already voted success, expires the
  // reservation on its own clock — the two-statement local timer.
  const LOCAL_TIMER_ABORT: bool
  // The successor sweep resolves an inherited reservation at P's
  // terminal; the twin drops it.
  const SWEEP_ON_TERMINATION: bool

  pure val P = 1
  pure val Q = 2
  pure val SHARDS = Set(P, Q)
  pure def other(s: int): int = if (s == P) Q else P

  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // Per-shard attested chain clock (monotone; Model A).
  var clock: int -> int
  // P's proposal carrying the transaction is certified (a QC exists). A
  // certified block can still be abandoned on a fork — that distinction
  // is the whole reason engagement demands commitment.
  var pCert: bool
  // P's certified proposal was abandoned; the transaction never commits
  // at P in this run.
  var pAbandoned: bool
  // Clock value at which each shard committed the transaction (NONE
  // before). At P this is the payer block engaging the reservation; at Q
  // it is engagement — inclusion, locks, its own execution.
  var committedAt: int -> int
  // Q holds the transaction commit proof: the payer's bundle, verified
  // against a commit-proven header of P's committing block.
  var qHasProof: bool
  // Q's engagement echo — the bundle its committing block owes the payer
  // — has committed into P's chain. Chain content at P, so P's vote
  // condition over it is deterministic across P's committee.
  var pEchoCommitted: bool
  // ECs each shard's committee emitted (at most one per shard: the
  // committee speaks once). Q emits SUCC on execution; P emits SUCC on
  // echo coverage or ABORT on its deadline.
  var emitted: int -> Set[int]
  // First-wins EC admission rows, as Model C.
  var admitted: int -> (int -> int)
  // Terminal verdict per shard.
  var terminal: int -> int
  // P has reached its reshape terminal block; its chain is frozen.
  var pTerminal: bool
  // The payer's fee accounting: liquid balance, held reservation,
  // cumulative burn. INV-VM-HOST-2's conserved quantities.
  var balance: int
  var held: int
  var burned: int
  // INV-VM-OBJ-2's quantities: bonds posted against committed substates, and
  // the debt a payer whose balance could not cover one still owes.
  var bonded: int
  var debt: int

  action init = all {
    clock' = SHARDS.mapBy(s => 0),
    pCert' = false,
    pAbandoned' = false,
    committedAt' = SHARDS.mapBy(s => NONE),
    qHasProof' = false,
    pEchoCommitted' = false,
    emitted' = SHARDS.mapBy(s => Set()),
    admitted' = SHARDS.mapBy(dst => SHARDS.mapBy(src => NONE)),
    terminal' = SHARDS.mapBy(s => NONE),
    pTerminal' = false,
    balance' = BALANCE,
    held' = 0,
    burned' = 0,
    bonded' = 0,
    debt' = 0,
  }

  // Frame groups: every action updates some groups and frames the rest
  // explicitly (Quint actions assign every variable).
  action frameClock = clock' = clock
  action frameCert = all { pCert' = pCert, pAbandoned' = pAbandoned }
  action frameCommitted = committedAt' = committedAt
  action frameSignals = all {
    qHasProof' = qHasProof, pEchoCommitted' = pEchoCommitted,
  }
  action frameEc = all { emitted' = emitted, admitted' = admitted }
  action frameTerm = all { terminal' = terminal, pTerminal' = pTerminal }
  action frameFees = all {
    balance' = balance, held' = held, burned' = burned,
    bonded' = bonded, debt' = debt,
  }

  action tick = {
    nondet s = SHARDS.oneOf()
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      // A terminated P's chain is frozen; its clock no longer attests.
      s == Q or not(pTerminal),
      clock' = clock.setBy(s, c => c + d),
      frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
    }
  }

  // P's proposal carrying the transaction certifies. Block validity
  // (the reservation check) already held at proposal: an insolvent
  // payer's transaction is never in a valid block, so certification
  // itself requires the balance to cover the reservation.
  action pCertify = all {
    not(pCert),
    not(pTerminal),
    balance >= MAX_FEE,
    pCert' = true,
    pAbandoned' = pAbandoned,
    frameClock, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
  }

  // The certified block commits (Model B's commit rule holds it): the
  // reservation engages — held, not spent.
  action pCommit = all {
    pCert,
    not(pAbandoned),
    not(pTerminal),
    committedAt.get(P) == NONE,
    committedAt' = committedAt.put(P, clock.get(P)),
    balance' = balance - MAX_FEE,
    held' = held + MAX_FEE,
    burned' = burned,
    bonded' = bonded,
    debt' = debt,
    frameClock, frameCert, frameSignals, frameEc, frameTerm,
  }

  // The certified block is abandoned on a fork; the transaction never
  // commits at P. Certification alone admits this — which is exactly
  // what the certified-evidence twin ignores.
  action pAbandon = all {
    pCert,
    committedAt.get(P) == NONE,
    not(pAbandoned),
    pAbandoned' = true,
    pCert' = pCert,
    frameClock, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
  }

  // Q receives the transaction commit proof. Healthy: the payer's
  // bundle joins a commit-proven header of P's committing block
  // (on_committed_remote_header), so the proof exists only once P
  // committed. Twin: the bundle is consumed against the certified
  // header.
  action deliverProof = all {
    not(qHasProof),
    if (ENGAGE_ON_CERTIFIED) pCert else committedAt.get(P) != NONE,
    qHasProof' = true,
    pEchoCommitted' = pEchoCommitted,
    frameClock, frameCert, frameCommitted, frameEc, frameTerm, frameFees,
  }

  // Q engages: proposal inclusion, locks, its own execution — its
  // commit of the transaction. Gated on the proof (healthy) and on the
  // validity window on Q's own attested clock. Past its window no
  // honest Q committee engages: the window closing without inclusion is
  // frozen on Q's chain.
  action qEngage = all {
    committedAt.get(Q) == NONE,
    clock.get(Q) <= WINDOW,
    ENGAGE_UNGATED or qHasProof,
    committedAt' = committedAt.put(Q, clock.get(Q)),
    frameClock, frameCert, frameSignals, frameEc, frameTerm, frameFees,
  }

  // Q's engagement echo commits into P's chain: the bundle Q's
  // committing block owes the payer, absorbed and committed like any
  // provisions. Only from here is P's success vote enabled.
  action deliverEcho = all {
    committedAt.get(Q) != NONE,
    not(pEchoCommitted),
    not(pTerminal),
    pEchoCommitted' = true,
    qHasProof' = qHasProof,
    frameClock, frameCert, frameCommitted, frameEc, frameTerm, frameFees,
  }

  // A shard's committee emits its success EC — its single statement.
  // Q speaks at engagement (it executed its leg there). P speaks only
  // once the engagement echo is chain content (healthy), or immediately
  // at commit (the ungated twin).
  action emitEcAt(s: int): bool = all {
    s == Q or not(pTerminal),
    committedAt.get(s) != NONE,
    s == Q or not(VOTE_ON_ECHO) or pEchoCommitted,
    emitted.get(s).size() == 0,
    emitted' = emitted.setBy(s, es => es.union(Set(SUCC))),
    admitted' = admitted.setBy(s, row =>
      if (row.get(s) == NONE) row.put(s, SUCC) else row),
    frameClock, frameCert, frameCommitted, frameSignals, frameTerm, frameFees,
  }

  action emitEc = {
    nondet s = SHARDS.oneOf()
    emitEcAt(s)
  }

  // The deadline vote: P's attested clock passed the window with no
  // engagement echo committed, so P's single statement is all-abort
  // (with the fee record attached in the implementation). Safety does
  // not depend on any skew bound between P's and Q's clocks: if Q
  // engaged late, its success EC merely loses worst-wins to this abort,
  // on both sides. Both conditions may hold at once (an echo committing
  // after the deadline); the implementation picks by chain order, the
  // model checks both choices.
  action pDeadlineVote = all {
    VOTE_ON_ECHO,
    not(pTerminal),
    committedAt.get(P) != NONE,
    clock.get(P) > WINDOW,
    emitted.get(P).size() == 0,
    emitted' = emitted.setBy(P, es => es.union(Set(ABORT))),
    admitted' = admitted.setBy(P, row =>
      if (row.get(P) == NONE) row.put(P, ABORT) else row),
    frameClock, frameCert, frameCommitted, frameSignals, frameTerm, frameFees,
  }

  // Network delivers an emitted EC; first-wins admission. An emitted EC
  // is a gossip-time artifact — deliverable even after P terminates
  // (Model D's H2 lesson).
  action deliverEcAt(dst: int): bool = {
    nondet o = emitted.get(other(dst)).oneOf()
    all {
      admitted.get(dst).get(other(dst)) == NONE,
      admitted' = admitted.setBy(dst, row => row.put(other(dst), o)),
      emitted' = emitted,
      frameClock, frameCert, frameCommitted, frameSignals, frameTerm, frameFees,
    }
  }

  action deliverEc = {
    nondet dst = SHARDS.oneOf()
    deliverEcAt(dst)
  }

  // Success finalization: unanimous EC coverage (Model C). At P this
  // resolves the reservation — burn the attested actual, release the
  // surplus.
  action finalizeSucc = {
    nondet s = SHARDS.oneOf()
    val row = admitted.get(s)
    all {
      s == Q or not(pTerminal),
      terminal.get(s) == NONE,
      row.get(s) == SUCC,
      row.get(other(s)) == SUCC,
      terminal' = terminal.put(s, SUCC),
      if (s == P) all {
        // The surplus refunds, the actual burns, and the committed
        // substates post their bond — out of balance where it reaches,
        // as recorded debt where it does not.
        val available = balance + (MAX_FEE - ACTUAL)
        val posted = if (available >= BOND) BOND else available
        all {
          balance' = available - posted,
          held' = held - MAX_FEE,
          burned' = burned + ACTUAL,
          bonded' = bonded + BOND,
          debt' = debt + (BOND - posted),
        }
      } else all {
        balance' = balance, held' = held, burned' = burned,
        bonded' = bonded, debt' = debt,
      },
      pTerminal' = pTerminal,
      frameClock, frameCert, frameCommitted, frameSignals, frameEc,
    }
  }

  // Abort finalization: worst-wins, and a shard's own abort EC needs no
  // counterpart coverage — the transaction completes on it (the tracker-abort
  // rule). At P this resolves the reservation at the floor.
  action finalizeAbortAt(s: int): bool = {
    val row = admitted.get(s)
    all {
      s == Q or not(pTerminal),
      terminal.get(s) == NONE,
      or {
        row.get(s) == ABORT,
        row.get(s) != NONE and row.get(other(s)) == ABORT,
      },
      terminal' = terminal.put(s, ABORT),
      if (s == P) all {
        balance' = balance + (MAX_FEE - FLOOR) - (if (BOND_ON_ABORT) BOND else 0),
        held' = held - MAX_FEE,
        burned' = burned + FLOOR,
        bonded' = bonded + (if (BOND_ON_ABORT) BOND else 0),
        debt' = debt,
      } else all {
        balance' = balance, held' = held, burned' = burned,
        bonded' = bonded, debt' = debt,
      },
      pTerminal' = pTerminal,
      frameClock, frameCert, frameCommitted, frameSignals, frameEc,
    }
  }

  action finalizeAbort = {
    nondet s = SHARDS.oneOf()
    finalizeAbortAt(s)
  }

  // The local-timer twin: P already voted success, then expires the
  // reservation on its own clock anyway — a second statement its
  // broadcast success EC contradicts. Q can finalize success on that
  // EC while P records an abort: the verdict split the echo gate makes
  // structurally impossible.
  action pLocalTimerAbort = all {
    LOCAL_TIMER_ABORT,
    not(pTerminal),
    terminal.get(P) == NONE,
    committedAt.get(P) != NONE,
    emitted.get(P) == Set(SUCC),
    clock.get(P) > WINDOW,
    admitted.get(P).get(Q) == NONE,
    terminal' = terminal.put(P, ABORT),
    pTerminal' = pTerminal,
    balance' = balance + (MAX_FEE - FLOOR),
    held' = held - MAX_FEE,
    burned' = burned + FLOOR,
    bonded' = bonded,
    debt' = debt,
    frameClock, frameCert, frameCommitted, frameSignals, frameEc,
  }

  // P reaches its reshape terminal mid-flight: the chain freezes, an
  // unfinalized transaction stamps abort-by-omission (Model D), and the
  // successor's sweep resolves the reservation it inherited — the
  // reservation is a substate and moves with the subtree. The sweep is
  // atomic with the stamp here; the twin drops it and the reservation
  // wedges.
  action pTerminate = all {
    not(pTerminal),
    committedAt.get(P) != NONE,
    terminal.get(P) == NONE,
    pTerminal' = true,
    terminal' = terminal.put(P, ABORT),
    if (SWEEP_ON_TERMINATION) all {
      balance' = balance + (MAX_FEE - FLOOR),
      held' = held - MAX_FEE,
      burned' = burned + FLOOR,
      bonded' = bonded,
      debt' = debt,
    } else all {
      balance' = balance, held' = held, burned' = burned,
      bonded' = bonded, debt' = debt,
    },
    frameClock, frameCert, frameCommitted, frameSignals, frameEc,
  }

  action step = any {
    tick, pCertify, pCommit, pAbandon, deliverProof, qEngage, deliverEcho,
    emitEc, pDeadlineVote, deliverEc, finalizeSucc, finalizeAbort,
    pLocalTimerAbort, pTerminate,
  }

  // INV-VM-HOST-1: engagement is evidence-gated. Q committed implies P
  // committed — under the healthy gate, Q moreover holds the proof.
  val invEngageGated =
    committedAt.get(Q) == NONE or committedAt.get(P) != NONE

  // INV-VM-HOST-2: the conserved quantities. Fees never move cross-shard —
  // Q has no fee state to conserve, structurally.
  val invConserve = balance + held + burned + bonded == BALANCE + debt

  // INV-VM-OBJ-2: a bond is posted only against substates that committed.
  // An aborted transaction wrote none, so it carries no bond — the same
  // fact that makes the abort atomic, read on the storage side.
  val invNoBondOnAbort = terminal.get(P) != ABORT or bonded == 0

  // INV-VM-OBJ-2: what a payer's balance could not cover is recorded as
  // debt, never silently forgiven — and debt exists only against a
  // posted bond.
  val invDebtBacked = debt >= 0 and debt <= bonded

  // The reservation is all-or-nothing while held.
  val invHeldShape = held == 0 or held == MAX_FEE

  // Burn classes: nothing before a terminal; the attested actual on
  // success; the floor on any abort.
  val invBurnClass = and {
    burned == 0 or terminal.get(P) != NONE,
    terminal.get(P) == NONE or
      (terminal.get(P) == SUCC and burned == ACTUAL) or
      (terminal.get(P) == ABORT and burned == FLOOR),
  }

  // Every engaged reservation terminally settles or releases: a
  // terminal P never still holds it.
  val invResolvedAtTerminal = terminal.get(P) == NONE or held == 0

  // The payer speaks once: its success vote exists only with the
  // engagement echo committed on its own chain (healthy gate only).
  val invVoteGated =
    not(VOTE_ON_ECHO) or not(emitted.get(P).contains(SUCC)) or pEchoCommitted

  // Model C's atomicity, scoped away from P's termination (Model D's
  // fence owns that corner).
  val invAtomicScoped =
    pTerminal or terminal.get(P) == NONE or terminal.get(Q) == NONE or
    terminal.get(P) == terminal.get(Q)

  val invAll = and {
    invEngageGated, invConserve, invHeldShape, invBurnClass,
    invResolvedAtTerminal, invVoteGated, invAtomicScoped,
    invNoBondOnAbort, invDebtBacked,
  }

  // The insolvent payer's world: nothing certifies, commits, engages,
  // holds, or burns anywhere.
  val invIdle = and {
    committedAt.get(P) == NONE,
    committedAt.get(Q) == NONE,
    held == 0,
    burned == 0,
    balance == BALANCE,
    bonded == 0,
    debt == 0,
  }

  val invAllIdle = and { invAll, invIdle }

  // Scripted: the deadline vote settles the floor. P commits and
  // reserves; no engagement echo ever commits (the bundle is lost or Q
  // never engages); P's clock passes the window; its single all-abort
  // statement completes its own transaction and resolves the reservation.
  run deadlineFloor =
    init
      .then(pCertify)
      .then(pCommit)
      .then(all {
        clock' = clock.setBy(P, c => c + WINDOW + 1),
        frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
      })
      .then(pDeadlineVote)
      .then(finalizeAbortAt(P))
      .expect(and {
        invAll,
        terminal.get(P) == ABORT,
        burned == FLOOR,
        held == 0,
        balance == BALANCE - FLOOR,
      })

  // Scripted: the window-edge race resolves as a mutual abort. Q engages
  // in its window and emits its success EC; P's deadline fires before
  // the echo commits; P's abort EC reaches Q and worst-wins aborts both
  // sides — consistency, at the price of a forgone success.
  run echoRace =
    init
      .then(pCertify)
      .then(pCommit)
      .then(deliverProof)
      .then(qEngage)
      .then(emitEcAt(Q))
      .then(all {
        clock' = clock.setBy(P, c => c + WINDOW + 1),
        frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
      })
      .then(pDeadlineVote)
      .then(deliverEcAt(P))
      .then(finalizeAbortAt(P))
      .then(deliverEcAt(Q))
      .then(finalizeAbortAt(Q))
      .expect(and {
        invAll,
        terminal.get(P) == ABORT,
        terminal.get(Q) == ABORT,
        burned == FLOOR,
        held == 0,
      })

  // Scripted (certified twin): the bundle joins a merely-certified
  // header; Q engages; the certified block abandons on a fork — Q holds
  // locks for a transaction the payer shard never committed.
  run certifiedAbandon =
    init
      .then(pCertify)
      .then(deliverProof)
      .then(qEngage)
      .then(pAbandon)
      .expect(and {
        not(invEngageGated),
        committedAt.get(Q) != NONE,
        committedAt.get(P) == NONE,
        held == 0,
      })

  // Scripted (local-timer twin): P votes success ungated, Q engages and
  // finalizes success on it, and P then expires on its own clock — the
  // verdict splits.
  run timerSplit =
    init
      .then(pCertify)
      .then(pCommit)
      .then(emitEcAt(P))
      .then(deliverProof)
      .then(qEngage)
      .then(emitEcAt(Q))
      .then(deliverEcAt(Q))
      .then(finalizeSucc)
      .then(all {
        clock' = clock.setBy(P, c => c + WINDOW + 1),
        frameCert, frameCommitted, frameSignals, frameEc, frameTerm, frameFees,
      })
      .then(pLocalTimerAbort)
      .expect(and {
        terminal.get(P) == ABORT,
        terminal.get(Q) == SUCC,
        not(invAtomicScoped),
      })
}

// Healthy configuration: the shipped gate. Engagement demands the commit
// proof, the payer votes on committed echo or deadline, the successor
// sweep resolves inherited reservations.
module fee_ok {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// The insolvent payer: the balance cannot cover max_fee, so block
// validity refuses the transaction everywhere it could matter.
module fee_insolvent {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 3,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// Broken twin: the ungated optimistic counterpart — engagement without
// evidence, against an insolvent payer that never commits.
module fee_ungated {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 3,
    WINDOW = 4, ENGAGE_UNGATED = true, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// Broken twin: engagement evidence anchored on certification — a
// certified block can be abandoned on a fork after the counterpart
// engaged.
module fee_certified {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = true,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// Broken twin: no successor sweep — P terminates holding the
// reservation, and nothing ever resolves it.
module fee_unswept {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = false, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// Broken twin: the ungated payer vote plus a local-timer expiry — the
// pre-echo world. P's success EC is out while its timer aborts locally;
// the verdict splits between the shards.
module fee_timer {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = false, LOCAL_TIMER_ABORT = true,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = false
  ).*
}

// The indebted payer: its balance covers the fee ceiling but not the
// bond its committed substates carry, so the shortfall is recorded as
// debt rather than forgiven.
module fee_indebted {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 9, BOND_ON_ABORT = false
  ).*
}

// Broken twin: an abort posts a bond for substates it never wrote —
// storage accounting drifting from what actually committed.
module fee_bonded_abort {
  import vm_fee_assurance(
    MAX_TICK = 3, MAX_FEE = 4, ACTUAL = 2, FLOOR = 1, BALANCE = 6,
    WINDOW = 4, ENGAGE_UNGATED = false, ENGAGE_ON_CERTIFIED = false,
    VOTE_ON_ECHO = true, LOCAL_TIMER_ABORT = false,
    SWEEP_ON_TERMINATION = true, BOND = 2, BOND_ON_ABORT = true
  ).*
}
