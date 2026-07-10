// Model F (register: specs/README.md) — the reshape lifecycle and its
// staffing. INV-RESHAPE-1 (seating gate), INV-RESHAPE-7 (staffing
// stability), INV-RESHAPE-8 (bounded lifecycle, staffing half), and the
// reshape clauses of INV-SEC-2.
//
// Two modules, mirroring the implementation's own split between the
// shard-side ready-signal transport and the beacon fold that consumes it:
//
//   `ready_signal_admission` — the local ready-signal pool as an
//   abstract-tick state machine. A committee member admits an observer's
//   signal, holds it until it has rested `DWELL` ticks (so the gossip
//   fan-out converges), then the proposer drains it into a block. The one
//   load-bearing rule: a re-emission of an unchanged window must *keep* the
//   earlier arrival stamp so dwell accrues — a reshape observer re-asserts
//   every pump, far more often than `DWELL`, and resetting the stamp each
//   time pins dwell below the threshold forever. This module pins that
//   rule (the shipped `7e0773ec` fix); the fold module layered on top takes
//   "an emitted signal is eventually drained" as an axiom it justifies.
//
//   `reshape_lifecycle` — the pure beacon fold (added in a later phase).
//
// Code anchors:
//   - Pool + dwell rule: crates/shard/src/ready_signal_pool.rs —
//     `ReadySignalPool::admit` (keep `received_at` on an unchanged window,
//     reset on a new one), `drain_eligible` (dwell + window-coverage gate),
//     `evict_expired` (drop past window end). `MIN_READY_SIGNAL_DWELL`.
//   - Signal window: crates/types/src/beacon/ready_signal.rs —
//     `ready_signal_window` (two epochs, scaled to `epoch_duration_ms`).
//
// Properties (docs/08-invariants.md):
//   invDwellAccrues — a signal held continuously since first admission for
//                     at least `DWELL` ticks is dwell-eligible: elapsed time
//                     since first-seen translates into accrued dwell. The
//                     `keep-on-repeat` admit rule is exactly what makes this
//                     hold under continuous re-emission (INV-RESHAPE-8
//                     liveness enabler). The `reshape_dwell_reset` twin
//                     resets the stamp on every repeat and violates it.
//   invWellFormed  — a held signal's arrival stamp is not in the future.
//
// Modeling assumptions:
//   - One observer, one signal. The pool is keyed by validator, so entries
//     are independent; a single entry captures the admit/drain/dwell rule.
//   - Ticks are unit and deterministic. The dwell rule concerns re-admission,
//     not timing granularity, so variable ticks add nothing here; the fold
//     module reintroduces epoch-scale timing where it matters.
//   - `now` doubles as the proposal weighted timestamp: the window covers it
//     when `wstart <= now <= wend`. Faithful to the `drain_eligible` gate,
//     which tests the proposal's parent-QC WT against `[start, end]`.
//   - Crypto and gossip are ideal: a signal in the pool is authentic; the
//     `DWELL` rest stands in for fan-out convergence.
//
// Run:
//   quint typecheck specs/reshape_lifecycle.qnt
//   quint verify --main=ready_signal_ok    --invariant=invAll         specs/reshape_lifecycle.qnt
//   quint verify --main=ready_signal_reset --invariant=invDwellAccrues specs/reshape_lifecycle.qnt
//     (the twin resets dwell on re-emit; expect a counterexample)
//   quint test   --main=ready_signal_ok    --match=dwellAdmitsUnderReemit  specs/reshape_lifecycle.qnt
//   quint test   --main=ready_signal_reset --match=dwellStarvesUnderReemit specs/reshape_lifecycle.qnt

module ready_signal_admission {
  // Ticks a signal must rest in the pool before it is drain-eligible.
  const DWELL: int
  // Weighted-time span the emitted window covers, from its start.
  const WINDOW: int
  // Broken twin: re-emitting an unchanged window resets the arrival stamp,
  // discarding accrued dwell. False is the shipped keep-on-repeat rule.
  const RESET_DWELL_ON_REEMIT: bool

  // Real time / proposal weighted timestamp (unified, unit ticks).
  var now: int
  // The single tracked pool entry.
  var present: bool
  var wstart: int
  var wend: int
  // Tick the entry's current stamp was set (drives the dwell gate).
  var received: int
  // Tick the entry's current window was first admitted — ghost state for
  // the accrual invariant, unaffected by keep-on-repeat re-admission.
  var firstSeen: int
  // The proposer has drained the signal into a block.
  var drained: bool

  action init = all {
    now' = 0,
    present' = false,
    wstart' = 0,
    wend' = 0,
    received' = 0,
    firstSeen' = 0,
    drained' = false,
  }

  action tick = all {
    now' = now + 1,
    present' = present,
    wstart' = wstart,
    wend' = wend,
    received' = received,
    firstSeen' = firstSeen,
    drained' = drained,
  }

  // Emit a signal against a fresh anchor: a new window opening at `now`.
  // Resets the stamp legitimately (a genuinely new window), so firstSeen
  // moves with it.
  action emitFresh = all {
    now' = now,
    present' = true,
    wstart' = now,
    wend' = now + WINDOW,
    received' = now,
    firstSeen' = now,
    drained' = drained,
  }

  // Re-assert the signal already held: the reshape pump, same window. The
  // keep-on-repeat rule (healthy) leaves the stamp; the twin resets it.
  action reemit = all {
    present,
    now' = now,
    present' = true,
    wstart' = wstart,
    wend' = wend,
    received' = if (RESET_DWELL_ON_REEMIT) now else received,
    firstSeen' = firstSeen,
    drained' = drained,
  }

  // The signal has rested long enough and its window covers the proposal.
  def drainable = present and now - received >= DWELL and wstart <= now and now <= wend

  // Proposer drains a dwell-eligible signal into a block.
  action drain = all {
    drainable,
    now' = now,
    present' = false,
    wstart' = wstart,
    wend' = wend,
    received' = received,
    firstSeen' = firstSeen,
    drained' = true,
  }

  // The window passed uncollected; the pool reaps it.
  action expire = all {
    present,
    now > wend,
    now' = now,
    present' = false,
    wstart' = wstart,
    wend' = wend,
    received' = received,
    firstSeen' = firstSeen,
    drained' = drained,
  }

  action step = any { tick, emitFresh, reemit, drain, expire }

  // A signal continuously held since first admission for at least DWELL
  // ticks is dwell-eligible — elapsed time since first-seen becomes accrued
  // dwell. Keep-on-repeat is what preserves this under re-emission.
  val invDwellAccrues =
    (present and now - firstSeen >= DWELL) implies (now - received >= DWELL)

  // A held entry's arrival stamp is never in the future.
  val invWellFormed = not(present) or received <= now

  val invAll = invDwellAccrues and invWellFormed

  // Healthy: re-emitting every tick (cadence 1 < DWELL) still drains,
  // because the stamp is kept and dwell accrues to the threshold.
  run dwellAdmitsUnderReemit =
    init
      .then(emitFresh)
      .then(tick).then(reemit)
      .then(tick).then(reemit)
      .then(tick).then(reemit)
      .then(drain)
      .expect(drained)

  // Twin: the same re-emit-every-tick schedule keeps resetting the stamp,
  // so after DWELL ticks the signal is still not drainable — starvation.
  run dwellStarvesUnderReemit =
    init
      .then(emitFresh)
      .then(tick).then(reemit)
      .then(tick).then(reemit)
      .then(tick).then(reemit)
      .expect(not(drainable))
}

// Healthy: keep-on-repeat. Dwell accrues; the signal drains.
module ready_signal_ok {
  import ready_signal_admission(DWELL = 3, WINDOW = 6, RESET_DWELL_ON_REEMIT = false).*
}

// Broken twin: reset-on-repeat. A live observer's signal never accrues
// dwell under continuous re-emission — the pre-`7e0773ec` starvation.
module ready_signal_reset {
  import ready_signal_admission(DWELL = 3, WINDOW = 6, RESET_DWELL_ON_REEMIT = true).*
}
