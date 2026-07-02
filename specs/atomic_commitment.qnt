// Model C (register: specs/README.md) — cross-shard atomic commitment:
// provision → execute → certify with attested deadlines, checked for
// INV-EXEC-1 (same terminal outcome on every participating shard).
//
// Shard consensus is an oracle here (Model B): each shard is a monotone
// attested clock plus an ordered commit of the transaction, and each committee
// is honest (INV-SEC-1, priced separately in committee_security.md), so a
// shard emits exactly one ExecutionCertificate per wave. The broken twin
// removes exactly that — an equivocating committee emits two ECs — and
// first-wins admission does the rest.
//
// Code anchors (crates/execution/src/wave_state.rs unless noted):
//   - Deadline and vote branches: `can_emit_vote` — fully provisioned
//     (vote real outcomes once committed_ts >= all_provisioned_at) or
//     timed out (all-abort once committed_ts >= wave_start_ts +
//     WAVE_TIMEOUT, with wave_start_ts = the LOCAL block's weighted
//     timestamp, coordinator.rs wave creation). Provisions absorbed after
//     the deadline but before voting still take the success branch — the
//     deadline bites only while unprovisioned.
//   - Abort dominance: `add_execution_certificate` — any shard's EC
//     reporting abort latches `tracker_aborted`, terminal per tx.
//   - Success unanimity: `is_complete` — a non-aborted tx needs EC
//     coverage from every participating shard, plus the local EC.
//   - First-wins EC admission: `seen_ec_wave_ids` dedup in
//     `add_execution_certificate`.
//   - Cross-shard agreement is per transaction, not per receipt root:
//     `ExecutionOutcome::Succeeded { receipt_hash }`
//     (crates/types/src/wave/outcome.rs); wave grouping is per shard, so
//     global roots are not comparable across shards.
//
// Modeling assumptions:
//   - One cross-shard transaction on two shards; the wave is the
//     transaction (per-shard wave grouping affects liveness, not the
//     atomicity core). INV-EXEC-4 (conflict tiebreak) is deferred to a
//     later revision of this model.
//   - Execution determinism is an axiom (INV-DET-1): success outcomes on
//     both shards carry the same receipt, so outcomes are just
//     {SUCC, ABORT}.
//   - Clocks are per-shard monotone integers (Model A justifies treating
//     the attested chain clock as monotone); network delivery of
//     provisions and ECs is fully asynchronous — any interleaving.
//   - Termination (INV-EXEC-5) is not checked temporally; the atomicity
//     invariant covers every reachable terminal combination.
//
// Run:
//   quint typecheck specs/atomic_commitment.qnt
//   quint run    --main=commit_ok   --invariant=invAtomic specs/atomic_commitment.qnt
//   quint verify --main=commit_ok   --invariant=invAtomic --max-steps=12 specs/atomic_commitment.qnt
//   quint test   --main=commit_equiv --match=equivocationAttack specs/atomic_commitment.qnt
//     (scripted witness: an equivocating committee plus first-wins
//      admission finalizes SUCC on one shard and ABORT on the other)
//   quint verify --main=commit_equiv --invariant=invAtomic --max-steps=12 specs/atomic_commitment.qnt

module atomic_commitment {
  // Wave timeout in clock units.
  const TIMEOUT: int
  // Max clock advance per step.
  const MAX_TICK: int
  // Broken twin: a shard's committee may equivocate, emitting two ECs.
  const EC_EQUIVOCATION: bool

  pure val SHARDS = Set(1, 2)
  pure def other(s: int): int = if (s == 1) 2 else 1

  // Outcomes. NONE encodes absence in int-valued maps.
  pure val NONE = -1
  pure val SUCC = 1
  pure val ABORT = 2

  // Per-shard attested chain clock (monotone).
  var clock: int -> int
  // Clock value at which the shard committed the tx (NONE before). This is
  // the wave_start_ts: locks engage, provisions to the counterparty become
  // an attested fact.
  var committedAt: int -> int
  // Clock value at which the shard absorbed the counterparty's provisions
  // (NONE before): all_provisioned_at.
  var provisionedAt: int -> int
  // ECs the shard's committee has emitted (outcome values). Honest: at
  // most one. Twin: an equivocating committee may emit both.
  var emitted: int -> Set[int]
  // First-wins admission: admitted.get(dst).get(src) is the one EC from
  // src's committee that dst has admitted (NONE before).
  var admitted: int -> (int -> int)
  // Terminal verdict per shard (NONE until finalized).
  var terminal: int -> int

  action init = all {
    clock' = SHARDS.mapBy(s => 0),
    committedAt' = SHARDS.mapBy(s => NONE),
    provisionedAt' = SHARDS.mapBy(s => NONE),
    emitted' = SHARDS.mapBy(s => Set()),
    admitted' = SHARDS.mapBy(dst => SHARDS.mapBy(src => NONE)),
    terminal' = SHARDS.mapBy(s => NONE),
  }

  action tick = {
    nondet s = SHARDS.oneOf()
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      clock' = clock.setBy(s, c => c + d),
      committedAt' = committedAt, provisionedAt' = provisionedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
    }
  }

  // The shard's chain commits the tx (consensus oracle): locks engage,
  // wave_start_ts is stamped, provisions toward the counterparty exist
  // from here on as attested facts.
  action commitTx = {
    nondet s = SHARDS.oneOf()
    all {
      committedAt.get(s) == NONE,
      committedAt' = committedAt.put(s, clock.get(s)),
      clock' = clock, provisionedAt' = provisionedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
    }
  }

  // The destination absorbs the counterparty's provisions, any time after
  // both sides committed (network is asynchronous — arbitrarily late,
  // including past the destination's deadline).
  action absorbProvisions = {
    nondet dst = SHARDS.oneOf()
    all {
      provisionedAt.get(dst) == NONE,
      committedAt.get(dst) != NONE,
      committedAt.get(other(dst)) != NONE,
      provisionedAt' = provisionedAt.put(dst, clock.get(dst)),
      clock' = clock, committedAt' = committedAt,
      emitted' = emitted, admitted' = admitted, terminal' = terminal,
    }
  }

  // The shard's committee emits its EC — `can_emit_vote`, both branches.
  // Success: provisioned and the chain clock has reached the absorb stamp.
  // Abort: still unprovisioned once the chain clock passes
  // wave_start_ts + TIMEOUT.
  // A shard emits its own EC into its admitted row immediately (the local
  // EC is always included — `create_wave_certificate`).
  action emitEc = {
    nondet s = SHARDS.oneOf()
    nondet o = Set(SUCC, ABORT).oneOf()
    all {
      committedAt.get(s) != NONE,
      // Honest committees follow `can_emit_vote` and emit once. The twin's
      // equivocating committee is Byzantine: any verdict, unguarded, up to
      // two distinct ECs — a forged quorum isn't bound by the vote rule.
      if (EC_EQUIVOCATION)
        emitted.get(s).size() < 2 and not(emitted.get(s).contains(o))
      else all {
        emitted.get(s).size() == 0,
        if (o == SUCC)
          provisionedAt.get(s) != NONE and clock.get(s) >= provisionedAt.get(s)
        else
          provisionedAt.get(s) == NONE and clock.get(s) >= committedAt.get(s) + TIMEOUT,
      },
      emitted' = emitted.setBy(s, es => es.union(Set(o))),
      admitted' = admitted.setBy(s, row =>
        if (row.get(s) == NONE) row.put(s, o) else row),
      clock' = clock, committedAt' = committedAt,
      provisionedAt' = provisionedAt, terminal' = terminal,
    }
  }

  // Network delivers some emitted EC from src's committee to dst;
  // first-wins admission latches it (`seen_ec_wave_ids`).
  action deliverEc = {
    nondet dst = SHARDS.oneOf()
    nondet o = emitted.get(other(dst)).oneOf()
    all {
      admitted.get(dst).get(other(dst)) == NONE,
      admitted' = admitted.setBy(dst, row => row.put(other(dst), o)),
      clock' = clock, committedAt' = committedAt,
      provisionedAt' = provisionedAt, emitted' = emitted, terminal' = terminal,
    }
  }

  // Finalization — `is_complete` + outcome derivation: the local EC must
  // be admitted; any admitted abort is terminal (abort dominance);
  // otherwise success requires admitted coverage from every participant
  // (success unanimity).
  action finalize = {
    nondet s = SHARDS.oneOf()
    val row = admitted.get(s)
    all {
      terminal.get(s) == NONE,
      row.get(s) != NONE,
      row.get(s) == ABORT or row.get(other(s)) == ABORT or
        (row.get(s) == SUCC and row.get(other(s)) == SUCC),
      terminal' = terminal.put(s,
        if (row.get(s) == ABORT or row.get(other(s)) == ABORT) ABORT else SUCC),
      clock' = clock, committedAt' = committedAt,
      provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
    }
  }

  action step = any { tick, commitTx, absorbProvisions, emitEc, deliverEc, finalize }

  // INV-EXEC-1: shards that reached a terminal verdict agree on it.
  val invAtomic = SHARDS.forall(x => SHARDS.forall(y =>
    terminal.get(x) == NONE or terminal.get(y) == NONE or
    terminal.get(x) == terminal.get(y)))

  // The equivocation attack, scripted (twin instances only): shard 1's
  // committee times out (abort EC) and equivocates a success EC; shard 2,
  // provisioned in time, admits the success EC first and finalizes SUCC,
  // while shard 1 finalizes ABORT from its own EC.
  run equivocationAttack =
    init
      .then(commitTxAt(1))
      .then(commitTxAt(2))
      .then(absorbAt(2))
      .then(tickBy(1, TIMEOUT))
      .then(emitEcAs(1, ABORT))
      .then(emitEcAs(1, SUCC))
      .then(emitEcAs(2, SUCC))
      .then(deliverEcTo(2, SUCC))
      .then(finalizeAt(2))
      .then(finalizeAt(1))
      .expect(not(invAtomic))

  // Parameterized cores for scripted runs (same semantics as the nondet
  // wrappers above).
  action commitTxAt(s: int): bool = all {
    committedAt.get(s) == NONE,
    committedAt' = committedAt.put(s, clock.get(s)),
    clock' = clock, provisionedAt' = provisionedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
  }

  action absorbAt(dst: int): bool = all {
    provisionedAt.get(dst) == NONE,
    committedAt.get(dst) != NONE,
    committedAt.get(other(dst)) != NONE,
    provisionedAt' = provisionedAt.put(dst, clock.get(dst)),
    clock' = clock, committedAt' = committedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
  }

  action tickBy(s: int, d: int): bool = all {
    clock' = clock.setBy(s, c => c + d),
    committedAt' = committedAt, provisionedAt' = provisionedAt,
    emitted' = emitted, admitted' = admitted, terminal' = terminal,
  }

  action emitEcAs(s: int, o: int): bool = all {
    committedAt.get(s) != NONE,
    if (EC_EQUIVOCATION)
      emitted.get(s).size() < 2 and not(emitted.get(s).contains(o))
    else all {
      emitted.get(s).size() == 0,
      if (o == SUCC)
        provisionedAt.get(s) != NONE and clock.get(s) >= provisionedAt.get(s)
      else
        provisionedAt.get(s) == NONE and clock.get(s) >= committedAt.get(s) + TIMEOUT,
    },
    emitted' = emitted.setBy(s, es => es.union(Set(o))),
    admitted' = admitted.setBy(s, row =>
      if (row.get(s) == NONE) row.put(s, o) else row),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, terminal' = terminal,
  }

  action deliverEcTo(dst: int, o: int): bool = all {
    emitted.get(other(dst)).contains(o),
    admitted.get(dst).get(other(dst)) == NONE,
    admitted' = admitted.setBy(dst, row => row.put(other(dst), o)),
    clock' = clock, committedAt' = committedAt,
    provisionedAt' = provisionedAt, emitted' = emitted, terminal' = terminal,
  }

  action finalizeAt(s: int): bool = {
    val row = admitted.get(s)
    all {
      terminal.get(s) == NONE,
      row.get(s) != NONE,
      row.get(s) == ABORT or row.get(other(s)) == ABORT or
        (row.get(s) == SUCC and row.get(other(s)) == SUCC),
      terminal' = terminal.put(s,
        if (row.get(s) == ABORT or row.get(other(s)) == ABORT) ABORT else SUCC),
      clock' = clock, committedAt' = committedAt,
      provisionedAt' = provisionedAt, emitted' = emitted, admitted' = admitted,
    }
  }
}

// Healthy configuration: one EC per committee per wave. Deadline
// heterogeneity, late provisions, and every delivery interleaving are all
// in scope — atomicity must survive them on the strength of abort
// dominance + success unanimity alone.
module commit_ok {
  import atomic_commitment(TIMEOUT = 3, MAX_TICK = 4, EC_EQUIVOCATION = false).*
}

// Broken twin: an equivocating committee (INV-SEC-1 violated on one
// shard) emits both verdicts; first-wins admission splits the observers.
module commit_equiv {
  import atomic_commitment(TIMEOUT = 3, MAX_TICK = 4, EC_EQUIVOCATION = true).*
}
