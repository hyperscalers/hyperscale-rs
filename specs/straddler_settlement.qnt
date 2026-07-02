// Model D (register: specs/README.md) — straddler settlement: atomicity
// across a terminating shard, INV-RESHAPE-5/6 composed with Model C's
// abort-dominant finalization.
//
// Shard 1 is P (terminates at a reshape cut); shard 2 is Q (survivor).
// One cross-shard transaction straddles the boundary, in flight during P's
// reshape: P has an admitted terminating reshape throughout (the model's
// premise — this is the window the fence governs). The fence decides Q's
// side from frozen chain content: P settled the wave on-chain at or before
// its terminal block, or the wave finalizes nowhere.
//
// The fence engages from the moment P is *scheduled* to terminate — an
// admitted reshape — not only once P is past-terminal. A survivor that
// finalized on EC-completeness in the pre-boundary window could apply a
// wave P never settles: P produces its own EC yet, under an asymmetric
// partition, never receives Q's before its terminal block. So while P is
// scheduled-but-live the fence defers — on evidence only, never a clock
// deadline; once P terminates it resolves against S_P (present -> pass,
// absent -> abort). The three twins each break one load-bearing piece:
// `straddler_preboundary` fences only past-terminal (the survivor commits
// one-sided in the scheduled window), `straddler_unfenced` fences nothing
// (a late-materialized EC — H2 — completes an unsettled wave after
// termination), and `straddler_windowed` shrinks S_P to a fixed span
// behind the terminal (the sweep aborts a wave P settled early in the
// scheduled window — verdict divergence with no partition).
//
// Code anchors:
//   - The fence: `settled_set_verdict`
//     (crates/types/src/topology/settled_set.rs) — for each remote EC
//     naming a terminating-or-terminated shard: settled set not yet
//     existent -> Defer; acquired and absent -> Reject; in-set -> Pass;
//     past retention horizon or schedule-evicted -> Reject. The
//     scheduled-terminal test is `TopologySchedule::termination_scheduled`
//     (active and lookahead `split_pending`/`merge_pending`, plus the
//     coast via `terminates_at_next_boundary`). Enforced at vote and at
//     local finalization. A deferred wave holds until evidence resolves
//     it (`emit_or_gate_finalized` / `redrive_gated_finalizations`,
//     crates/execution/src/coordinator.rs) — no clock evicts the hold.
//   - The window: the terminal's `settled_waves_root` commits P's
//     settlements over `[admission − wave lifetime, terminal]` —
//     `TopologySchedule::settled_window_floor` supplies the floor,
//     `PendingChain::settled_waves_in_window`
//     (crates/storage/src/shard/pending_chain.rs) walks it. SP_HORIZON
//     parameterizes this coverage here.
//   - Acquisition: one-shot verified fetch against the beacon-attested
//     `settled_waves_root` read from the node's own fold
//     (crates/node/src/shard/cross_shard/settled_set.rs) — INV-RESHAPE-6
//     is taken as an oracle: acquisition delivers exactly S_P.
//   - Counterpart sweep: `record_settled_waves` +
//     `take_ready_counterpart_aborts`
//     (crates/execution/src/coordinator.rs) — once the partner's settled
//     coverage naming us is fully ingested (or the horizon passes), any
//     wave still lacking the partner's coverage is doomed: locks release,
//     transactions abort.
//   - Parent-side termination: writes apply only at finalization, so a
//     transaction unfinalized at P's terminal block never enters the
//     frozen content P's successors inherit — abort by omission. Modeled
//     as an ABORT verdict stamped at termination.
//
// Modeling assumptions (on top of Model C's, which this file extends):
//   - P's chain freezes at termination: no further commits, absorbs,
//     finalizations, or clock advance. EC *emission* stays enabled with
//     guards over the frozen state — this is H2, an EC materialized from
//     held vote shares after termination. EC existence is gossip-time; the
//     settled set is chain content. The distinction is the whole design.
//   - Acquisition is exact (INV-RESHAPE-6 oracle): the fetched list
//     recomputes to the beacon-attested root. S_P's *coverage* is the
//     modeled parameter: `SP_HORIZON < 0` is the shipped window, floored
//     at the reshape's admission, which covers every settlement the
//     fence can hold a straddler against — S_P is then exact over fenced
//     waves. A window that misses a settlement makes absence stop
//     implying "unsettled", and the sweep turns the gap into a verdict
//     divergence — widening the absent case is the unsafe direction
//     (`straddler_windowed`).
//   - Single transaction, wave = transaction, as in Model C.
//
// Run:
//   quint typecheck specs/straddler_settlement.qnt
//   quint verify --main=straddler_ok          --invariant=invAll --max-steps=10 specs/straddler_settlement.qnt
//     (the shipped fence: atomicity holds through the whole lifecycle)
//   quint verify --main=straddler_preboundary --invariant=invAtomic --max-steps=10 specs/straddler_settlement.qnt
//     (past-terminal-only fence: the pre-boundary one-sided commit)
//   quint test   --main=straddler_unfenced    --match=h2Attack specs/straddler_settlement.qnt
//     (scripted H2: a late EC completes an unsettled wave after termination)
//   quint test   --main=straddler_windowed    --match=spWindowMiss specs/straddler_settlement.qnt
//     (scripted window miss: the sweep aborts a wave P settled early)

module straddler_settlement {
  // Wave timeout in clock units.
  const TIMEOUT: int
  // Max clock advance per step.
  const MAX_TICK: int
  // Fence a wave naming P once P is past-terminal (require S_P).
  const FENCE_PAST_TERMINAL: bool
  // Additionally defer while P is scheduled-but-not-yet-terminal — the
  // pre-boundary layer the shipped fence adds.
  const FENCE_SCHEDULED: bool
  // The span behind P's terminal that the S_P reconstruction covers, in
  // P's clock units. Negative models the shipped window, floored at the
  // reshape's admission: the fence holds straddlers from admission and a
  // wave's settlement cannot precede the hold by more than a wave
  // lifetime, so the admission-floored window covers every settlement Q
  // can still be holding against — S_P is exact over fenced waves.
  // Non-negative models a fixed terminal-relative span, which misses
  // settlements once P's coast outlives it.
  const SP_HORIZON: int

  // Shard 1 = P (terminates), shard 2 = Q (survivor).
  pure val P = 1
  pure val Q = 2
  pure val SHARDS = Set(P, Q)
  pure def other(s: int): int = if (s == P) Q else P

  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // P has an admitted terminating reshape for the whole run — the model's
  // premise (a straddler in flight during a reshape). The survivor reads
  // this from frozen schedule content, so the fence engages throughout.
  pure val pScheduled = true

  // Model C state (same semantics; see atomic_commitment.qnt).
  var clock: int -> int
  var committedAt: int -> int
  var provisionedAt: int -> int
  var emitted: int -> Set[int]
  var admitted: int -> (int -> int)
  var terminal: int -> int
  // P has reached its terminal block.
  var pTerminal: bool
  // Frozen at termination: did the wave settle (finalize on P's chain at
  // or before the terminal block)? Meaningful only once pTerminal.
  var settledOnP: bool
  // Q has acquired S_P (root-verified against its own beacon fold).
  var qHasSP: bool
  // P's clock when its chain finalized the wave (either verdict) — the
  // settlement instant the reconstruction horizon measures from.
  var pSettledAt: int
  // P's clock at its terminal block. Meaningful only once pTerminal.
  var pTerminalAt: int

  action init = all {
    clock' = SHARDS.mapBy(s => 0),
    committedAt' = SHARDS.mapBy(s => NONE),
    provisionedAt' = SHARDS.mapBy(s => NONE),
    emitted' = SHARDS.mapBy(s => Set()),
    admitted' = SHARDS.mapBy(dst => SHARDS.mapBy(src => NONE)),
    terminal' = SHARDS.mapBy(s => NONE),
    pTerminal' = false,
    settledOnP' = false,
    qHasSP' = false,
    pSettledAt' = NONE,
    pTerminalAt' = NONE,
  }

  // ── Model C actions, gated by P's chain freeze ─────────────────────────

  action tick = {
    nondet s = SHARDS.oneOf()
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      s == Q or not(pTerminal),
      clock' = clock.setBy(s, c => c + d),
      committedAt' = committedAt, provisionedAt' = provisionedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
      pTerminal' = pTerminal,
      settledOnP' = settledOnP, qHasSP' = qHasSP,
      pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
    }
  }

  action commitTx = {
    nondet s = SHARDS.oneOf()
    all {
      s == Q or not(pTerminal),
      committedAt.get(s) == NONE,
      committedAt' = committedAt.put(s, clock.get(s)),
      clock' = clock, provisionedAt' = provisionedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
      pTerminal' = pTerminal,
      settledOnP' = settledOnP, qHasSP' = qHasSP,
      pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
    }
  }

  action absorbProvisions = {
    nondet dst = SHARDS.oneOf()
    all {
      dst == Q or not(pTerminal),
      provisionedAt.get(dst) == NONE,
      committedAt.get(dst) != NONE,
      committedAt.get(other(dst)) != NONE,
      provisionedAt' = provisionedAt.put(dst, clock.get(dst)),
      clock' = clock, committedAt' = committedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
      pTerminal' = pTerminal,
      settledOnP' = settledOnP, qHasSP' = qHasSP,
      pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
    }
  }

  // EC emission — deliberately NOT gated on P's termination: an EC is
  // aggregatable from held vote shares arbitrarily late (H2). Guards
  // evaluate over P's frozen chain state, so a late EC is exactly the EC
  // that could have formed at the terminal cut. Honest committees emit once.
  action emitEcAs(s: int, o: int): bool = all {
    committedAt.get(s) != NONE,
    emitted.get(s).size() == 0,
    if (o == SUCC)
      provisionedAt.get(s) != NONE and clock.get(s) >= provisionedAt.get(s)
    else
      provisionedAt.get(s) == NONE and clock.get(s) >= committedAt.get(s) + TIMEOUT,
    emitted' = emitted.setBy(s, es => es.union(Set(o))),
    admitted' = admitted.setBy(s, row =>
      if (row.get(s) == NONE) row.put(s, o) else row),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, terminal' = terminal,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  action emitEc = {
    nondet s = SHARDS.oneOf()
    nondet o = Set(SUCC, ABORT).oneOf()
    emitEcAs(s, o)
  }

  action deliverEcTo(dst: int, o: int): bool = all {
    emitted.get(other(dst)).contains(o),
    admitted.get(dst).get(other(dst)) == NONE,
    admitted' = admitted.setBy(dst, row => row.put(other(dst), o)),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, emitted' = emitted, terminal' = terminal,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  action deliverEc = {
    nondet dst = SHARDS.oneOf()
    nondet o = emitted.get(other(dst)).oneOf()
    deliverEcTo(dst, o)
  }

  // Whether S_P resolves the wave as settled for Q: P finalized it at or
  // before its terminal block AND the settlement lies within the
  // reconstruction horizon. Under the shipped admission-floored window
  // (`SP_HORIZON < 0`) this equals `settledOnP`; a terminal-relative span
  // drops settlements older than the horizon, and absence then stops
  // implying "P never settled it" — widening the absent case is the
  // unsafe direction, not a conservative one.
  def spContains: bool = and {
    settledOnP,
    SP_HORIZON < 0 or pTerminalAt - pSettledAt <= SP_HORIZON,
  }

  // The survivor's finalization fence. Q may finalize iff P's termination
  // does not forbid it: while P is scheduled-but-live, `FENCE_SCHEDULED`
  // defers — on evidence only, never a clock deadline; once P is
  // past-terminal, `FENCE_PAST_TERMINAL` requires S_P to resolve the wave
  // (acquired and in the reconstructed set). P itself finalizes only
  // while its chain lives.
  def fenceAdmits(s: int): bool =
    s == P or all {
      not(FENCE_SCHEDULED and pScheduled and not(pTerminal)),
      not(FENCE_PAST_TERMINAL and pTerminal) or (qHasSP and spContains),
    }

  action finalizeAt(s: int): bool = {
    val row = admitted.get(s)
    all {
      terminal.get(s) == NONE,
      s == Q or not(pTerminal),
      fenceAdmits(s),
      row.get(s) != NONE,
      row.get(s) == ABORT or row.get(other(s)) == ABORT or
        (row.get(s) == SUCC and row.get(other(s)) == SUCC),
      terminal' = terminal.put(s,
        if (row.get(s) == ABORT or row.get(other(s)) == ABORT) ABORT else SUCC),
      clock' = clock, committedAt' = committedAt,
      provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
      pTerminal' = pTerminal,
      settledOnP' = settledOnP, qHasSP' = qHasSP,
      pSettledAt' = if (s == P) clock.get(P) else pSettledAt,
      pTerminalAt' = pTerminalAt,
    }
  }

  action finalize = {
    nondet s = SHARDS.oneOf()
    finalizeAt(s)
  }

  // ── Termination and settlement ──────────────────────────────────────────

  // P reaches its terminal block: the chain freezes, the settled set is
  // fixed by frozen content, and anything unfinalized aborts by omission
  // (its writes never enter the frozen state P's successors inherit).
  action terminateP = all {
    not(pTerminal),
    pTerminal' = true,
    settledOnP' = terminal.get(P) != NONE,
    terminal' = if (terminal.get(P) == NONE) terminal.put(P, ABORT) else terminal,
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
    qHasSP' = qHasSP,
    pSettledAt' = pSettledAt,
    pTerminalAt' = clock.get(P),
  }

  // Q acquires S_P: a one-shot verified fetch whose root check is an
  // oracle (INV-RESHAPE-6 — the root came from Q's own beacon fold).
  action acquireSP = all {
    pTerminal,
    not(qHasSP),
    qHasSP' = true,
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
    terminal' = terminal, pTerminal' = pTerminal,
    settledOnP' = settledOnP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  // The counterpart sweep: with S_P acquired and the wave not in it, no
  // admissible P coverage can ever exist (any late EC is fence-rejected),
  // so the wave is doomed — locks release, the transaction aborts. Sound
  // exactly when absence from S_P implies P never settled the wave — the
  // coverage premise the windowed twin breaks.
  action sweepQ = all {
    FENCE_PAST_TERMINAL,
    pTerminal,
    qHasSP,
    not(spContains),
    terminal.get(Q) == NONE,
    committedAt.get(Q) != NONE,
    terminal' = terminal.put(Q, ABORT),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  action step = any {
    tick, commitTx, absorbProvisions, emitEc, deliverEc, finalize,
    terminateP, acquireSP, sweepQ,
  }

  // INV-EXEC-1 across the boundary (INV-RESHAPE-5's payoff): terminal
  // verdicts never disagree.
  val invAtomic = SHARDS.forall(x => SHARDS.forall(y =>
    terminal.get(x) == NONE or terminal.get(y) == NONE or
    terminal.get(x) == terminal.get(y)))

  // INV-RESHAPE-5 stated directly: the survivor finalizes success for a
  // wave naming past-terminal P only if P settled it.
  val invFence = not(pTerminal and terminal.get(Q) == SUCC and not(settledOnP))

  val invAll = invAtomic and invFence

  // ── Scripted cores for the H2 witness ───────────────────────────────────

  action commitTxAt(s: int): bool = all {
    s == Q or not(pTerminal),
    committedAt.get(s) == NONE,
    committedAt' = committedAt.put(s, clock.get(s)),
    clock' = clock, provisionedAt' = provisionedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  action absorbAt(dst: int): bool = all {
    dst == Q or not(pTerminal),
    provisionedAt.get(dst) == NONE,
    committedAt.get(dst) != NONE,
    committedAt.get(other(dst)) != NONE,
    provisionedAt' = provisionedAt.put(dst, clock.get(dst)),
    clock' = clock, committedAt' = committedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  action tickAt(s: int, d: int): bool = all {
    s == Q or not(pTerminal),
    clock' = clock.setBy(s, c => c + d),
    committedAt' = committedAt, provisionedAt' = provisionedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
    pTerminal' = pTerminal,
    settledOnP' = settledOnP, qHasSP' = qHasSP,
    pSettledAt' = pSettledAt, pTerminalAt' = pTerminalAt,
  }

  // The windowed-S_P miss, scripted: P settles the wave early in its
  // scheduled window, coasts past the reconstruction horizon, and
  // terminates; Q — correctly fenced the whole time — acquires an S_P
  // that no longer reaches the settlement, and the sweep aborts a wave
  // P settled. The verdicts diverge with no partition and no Byzantine
  // behavior: the exact shape the production-epoch straddler sims caught.
  run spWindowMiss =
    init
      .then(commitTxAt(P))
      .then(commitTxAt(Q))
      .then(absorbAt(P))
      .then(absorbAt(Q))
      .then(emitEcAs(P, SUCC))
      .then(emitEcAs(Q, SUCC))
      .then(deliverEcTo(P, SUCC))
      .then(finalizeAt(P))
      .then(tickAt(P, 2))
      .then(terminateP)
      .then(acquireSP)
      .then(sweepQ)
      .expect(not(invAtomic))

  // H2, scripted (unfenced twin): both sides commit and provision; P's
  // validators vote but no FinalizedWave lands before the terminal block;
  // P terminates — the transaction aborts by omission in frozen content.
  // The EC then materializes from held shares, reaches Q, and Q finalizes
  // success against a chain that never applied it.
  run h2Attack =
    init
      .then(commitTxAt(P))
      .then(commitTxAt(Q))
      .then(absorbAt(P))
      .then(absorbAt(Q))
      .then(terminateP)
      .then(emitEcAs(P, SUCC))
      .then(emitEcAs(Q, SUCC))
      .then(deliverEcTo(Q, SUCC))
      .then(finalizeAt(Q))
      .expect(not(invAtomic))
}

// The shipped fence: defers from scheduling, requires S_P past terminal.
// Atomicity and the fence property hold through the whole lifecycle, late
// EC materialization included.
module straddler_ok {
  import straddler_settlement(
    TIMEOUT = 3, MAX_TICK = 4, FENCE_PAST_TERMINAL = true, FENCE_SCHEDULED = true,
    SP_HORIZON = -1
  ).*
}

// Twin — past-terminal-only fence: nothing defers while P is scheduled but
// still live, so the survivor can finalize a straddler one-sided before P's
// terminal block.
module straddler_preboundary {
  import straddler_settlement(
    TIMEOUT = 3, MAX_TICK = 4, FENCE_PAST_TERMINAL = true, FENCE_SCHEDULED = false,
    SP_HORIZON = -1
  ).*
}

// Twin — unfenced: a late-materialized EC completes an unsettled wave on
// the survivor after termination (H2). One-sided commit.
module straddler_unfenced {
  import straddler_settlement(
    TIMEOUT = 3, MAX_TICK = 4, FENCE_PAST_TERMINAL = false, FENCE_SCHEDULED = false,
    SP_HORIZON = -1
  ).*
}

// Twin — terminal-relative S_P window: the reconstruction spans a fixed
// horizon behind P's terminal instead of reaching the reshape's admission,
// so a wave P settled early in the scheduled window vanishes from S_P once
// the coast outlives the horizon. The sweep then aborts a wave P settled —
// the regression the admission-floored window closes.
module straddler_windowed {
  import straddler_settlement(
    TIMEOUT = 3, MAX_TICK = 4, FENCE_PAST_TERMINAL = true, FENCE_SCHEDULED = true,
    SP_HORIZON = 1
  ).*
}
