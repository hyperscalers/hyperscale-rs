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
//   `reshape_lifecycle` — the pure beacon fold for a split: trigger
//   admission under the pool gate, the frozen-seed cohort draw and its
//   child assignment, the sticky ready fold, TTL lapse/re-staff and
//   abandonment, and the 2f+1-per-child seating gate. A `synced` ground
//   truth records which observers actually synced each child, so the
//   seating gate can be checked at its semantic floor rather than by seat
//   count alone. A ready signal is bound only to its emitter — it carries
//   a validity window but no child; the fold classifies it by the emitter's
//   *current* seat. Pool churn (a spare validator swapping in during a
//   lapse) can move an observer's assignment even under a frozen seed, and
//   the `UNBOUND_READY` twin then folds a still-valid signal from the
//   observer's prior seat against its new one.
//
// Code anchors:
//   - Pool + dwell rule: crates/shard/src/ready_signal_pool.rs —
//     `ReadySignalPool::admit` (keep `received_at` on an unchanged window,
//     reset on a new one), `drain_eligible` (dwell + window-coverage gate),
//     `evict_expired` (drop past window end). `MIN_READY_SIGNAL_DWELL`.
//   - Signal window: crates/types/src/beacon/ready_signal.rs —
//     `ready_signal_window` (two epochs, scaled to `epoch_duration_ms`);
//     the signal binds only `(network, validator, wt_window)`.
//   - Fold + draw: crates/beacon/src/state/witness.rs (admission, re-staff,
//     `ReshapeReady` fold, `prune_stale_reshapes`) and
//     crates/beacon/src/state/reshape.rs (`draw_split_cohort`,
//     `try_execute_split`); classification is
//     crates/types/src/shard/roots/beacon_witness.rs `ready_leaf_payload`
//     (by the emitter's current seat, not the signal's content).
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
//   invConservation      — placements partition: the pool, the two child
//                          cohorts, and the bench are disjoint and cover
//                          every observer; lapse/abandon/churn move whole
//                          seats.
//   invSeatStability     — an observer's child assignment never drifts from
//                          its first-ever assignment across a lapse/re-staff
//                          cycle (INV-RESHAPE-7 as the register states it).
//                          Holds without pool churn; the `reshape_split_churn`
//                          instance shows a frozen-seed re-staff over a
//                          *churned* pool violates it — the register's
//                          "cannot move an observer's sync target" is only
//                          true for an unchanged pool.
//   invNoHonestFalseReady — no honest observer is ready-flagged for a child
//                          it has not synced — the seating-soundness premise.
//                          A drifted assignment alone does not break it (a
//                          child-bound signal will not fold for the new
//                          seat); the `reshape_unbound_ready` twin, whose
//                          fold ignores the signal's origin child, does.
//   invSeatingGate       — if the split executed, each child seats a quorum
//                          of genuinely honest-synced members (INV-RESHAPE-1
//                          at its semantic floor, not seat count).
//
// Modeling assumptions:
//   - Ticks are unit and deterministic. The dwell rule concerns re-admission,
//     not timing granularity; the fold module carries epoch-scale timing
//     where the TTLs and the signal window matter.
//   - `now` doubles as the proposal weighted timestamp: the window covers it
//     when `wstart <= now <= wend`. Faithful to the `drain_eligible` gate.
//   - Parent halves are trusted honest-synced counts (a live parent committee,
//     ready by construction); the cohort observers are the set-valued state.
//   - Crypto and gossip are ideal: a signal in the pool is authentic; the
//     `DWELL` rest stands in for fan-out convergence.
//   - Eviction-timing note. `evict_expired` reaps a signal past its two-epoch
//     window, but an observer re-emits every reshape pump (sub-second),
//     refreshing the pooled copy, so the signal stays live until the
//     observer detects the lapse and stops — about one epoch after the fold
//     lapses. A re-assertion re-staffs within roughly one further epoch, so
//     the two-epoch window has not closed: survival to the re-staff is the
//     realistic case. `expireSig` models eviction as free (fire any time),
//     so the checker covers both eviction-before-re-staff (no fold) and
//     survival (the finding), rather than hard-coding a race outcome.
//   - The shuffle key is parity-based, not the production hash — two
//     orderings suffice to exercise a frozen-seed re-staff, pool-churn
//     drift, and the epoch-seeded twin, and it keeps the checker tractable.
//
// Run:
//   quint typecheck specs/reshape_lifecycle.qnt
//   quint verify --main=ready_signal_ok    --invariant=invAll         specs/reshape_lifecycle.qnt
//   quint verify --main=ready_signal_reset --invariant=invDwellAccrues specs/reshape_lifecycle.qnt
//     (the twin resets dwell on re-emit; expect a counterexample)
//   quint test   --main=ready_signal_ok    --match=dwellAdmitsUnderReemit  specs/reshape_lifecycle.qnt
//   quint test   --main=ready_signal_reset --match=dwellStarvesUnderReemit specs/reshape_lifecycle.qnt
//   quint verify --main=reshape_split_ok     --invariant=invAll --max-steps=10 specs/reshape_lifecycle.qnt
//     (the healthy split: staffing soundness holds through admit, lapse/
//      re-staff, and the seating gate)
//   quint verify --main=reshape_split_churn  --invariant=invSeatStability --max-steps=8 specs/reshape_lifecycle.qnt
//     (pool churn drifts a frozen-seed re-staff off an observer's first
//      assignment; expect a counterexample — the INV-RESHAPE-7 over-claim)
//   quint verify --main=reshape_split_churn  --invariant=invNoHonestFalseReady --max-steps=8 specs/reshape_lifecycle.qnt
//     (but with a child-bound signal the drift is benign; expect it to hold)
//   quint verify --main=reshape_unbound_ready --invariant=invNoHonestFalseReady --max-steps=10 specs/reshape_lifecycle.qnt
//     (the finding: an unbound signal from the observer's prior seat folds
//      for its churned-to seat; expect a counterexample)

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

// The beacon fold for a split. The two children are L and R; one splitting
// shard whose parent halves contribute `PARENT_HALF_L` / `PARENT_HALF_R`
// trusted honest-synced members. Cohort observers are drawn from the pool;
// a spare sits on the bench and can churn into the pool during a lapse.
//
// The draw is rank-based on a seed frozen at admission (a seeded shuffle
// split in half), so an observer's child assignment depends on the drawn
// pool's composition — a re-staff over an unchanged pool reproduces it, a
// re-staff over a churned pool can move it.
//
// A ready signal is held in the pool until evicted (`liveSig`) and carries
// no child. The fold marks a validator ready for its current seat; the
// healthy rule
// additionally checks the validator synced that seat's child (a child-bound
// signal), while the `UNBOUND_READY` twin does not — so a signal emitted for
// a prior seat can fold for a churned-to seat.
module reshape_lifecycle {
  // Committee target: a full cohort is this many observers.
  const SHARD_SIZE: int
  // Byzantine tolerance and quorum: committee 3F+1, quorum 2F+1.
  const F: int
  // Honest-synced parent-half members contributed to each child at the flip.
  const PARENT_HALF_L: int
  const PARENT_HALF_R: int
  // Trigger goes quiet for this many epochs → the split lapses (cohort
  // returned, record + seed retained).
  const TRIGGER_TTL: int
  // Ungated this many epochs after admission → the split abandons.
  const READY_TTL: int
  // The fixed Byzantine validator set (observers only). Honest = complement.
  const BYZ: Set[int]
  // Candidate cohort seeds the beacon randomness can freeze at admission.
  const SEEDS: Set[int]
  // Broken twin: the draw seeds on the running epoch, not the frozen seed,
  // so a re-staff re-rolls the assignment. False is the shipped frozen seed.
  const EPOCH_SEEDED_DRAW: bool
  // Whether a benched spare can churn into the pool during a lapse.
  const POOL_CHURN: bool
  // Broken twin: the ready fold ignores the signal's origin child and marks
  // the validator ready for whatever seat it currently holds. False is the
  // child-bound signal the fix would carry.
  const UNBOUND_READY: bool

  pure val QUORUM = 2 * F + 1
  // The observer identities: a full cohort's worth plus one benched spare.
  pure val IDS = 1.to(SHARD_SIZE + 1)

  // Deterministic per-(seed, validator) ordering key for the shuffle: the
  // seed's parity picks the direction, giving two distinct orderings over
  // the drawn set. Kept free of costly arithmetic (no modular hashing) so
  // the bounded checker stays tractable; the two orderings suffice to
  // exercise a frozen-seed re-staff, pool-churn drift, and the epoch twin.
  pure def keyOf(effSeed: int, v: int): int =
    if (effSeed % 2 == 0) v else SHARD_SIZE + 2 - v
  // How many of `d` rank strictly below `v` (keys are distinct on 1..N).
  pure def lowerCount(effSeed: int, d: Set[int], v: int): int =
    d.filter(u => keyOf(effSeed, u) < keyOf(effSeed, v)).size()
  // Lower half → L child. Splits an even draw exactly in half.
  pure def assignL(effSeed: int, d: Set[int], v: int): bool =
    lowerCount(effSeed, d, v) < d.size() / 2
  pure def drawL(effSeed: int, d: Set[int]): Set[int] = d.filter(v => assignL(effSeed, d, v))
  pure def drawR(effSeed: int, d: Set[int]): Set[int] = d.filter(v => not(assignL(effSeed, d, v)))

  // Current epoch.
  var epoch: int
  // Free observers eligible to be drawn into the cohort.
  var pool: Set[int]
  // Inactive spares — neither pooled nor cohorted.
  var benched: Set[int]
  // A split is admitted and pending.
  var pendingPresent: bool
  // The cohort seed, frozen at admission.
  var seed: int
  // Drawn observers assigned to each child.
  var cohortL: Set[int]
  var cohortR: Set[int]
  // Observers whose ready leaf has folded, per child seat.
  var readyL: Set[int]
  var readyR: Set[int]
  // Ground truth: observers that have actually synced each child's state.
  var syncedL: Set[int]
  var syncedR: Set[int]
  // Observers holding a still-valid ready signal in the proposer pool. A
  // signal enters on sync and leaves by `expireSig` — the abstraction of
  // `evict_expired`: eviction may fire at any time, or the signal may
  // persist (an observer re-emits every pump, so it stays live until the
  // observer detects the lapse; see the header's eviction-timing note).
  var liveSig: Set[int]
  // First-ever child assignment of each observer, retained across lapse —
  // the anchor the stability invariant measures drift against.
  var everAssignedL: Set[int]
  var everAssignedR: Set[int]
  // Trigger and admission clocks (epochs).
  var lastAsserted: int
  var admittedAt: int
  // The split has executed; the model is terminal (only the clock advances).
  var executed: bool

  action init = all {
    epoch' = 0,
    pool' = 1.to(SHARD_SIZE),
    benched' = Set(SHARD_SIZE + 1),
    pendingPresent' = false,
    seed' = 0,
    cohortL' = Set(),
    cohortR' = Set(),
    readyL' = Set(),
    readyR' = Set(),
    syncedL' = Set(),
    syncedR' = Set(),
    liveSig' = Set(),
    everAssignedL' = Set(),
    everAssignedR' = Set(),
    lastAsserted' = 0,
    admittedAt' = 0,
    executed' = false,
  }

  // The seed a draw uses: frozen (healthy) or re-rolled from the epoch (twin).
  def drawSeed(s: int): int = if (EPOCH_SEEDED_DRAW) s + epoch else s
  // Whether validator v holds an unexpired ready signal.
  def live(v: int): bool = liveSig.contains(v)

  // First admission: pool gate met, draw the cohort, freeze the seed.
  action admit = {
    nondet s = SEEDS.oneOf()
    val newL = drawL(drawSeed(s), pool)
    val newR = drawR(drawSeed(s), pool)
    all {
      not(executed),
      not(pendingPresent),
      pool.size() == SHARD_SIZE,
      epoch' = epoch,
      pool' = Set(),
      benched' = benched,
      pendingPresent' = true,
      seed' = s,
      cohortL' = newL,
      cohortR' = newR,
      readyL' = Set(),
      readyR' = Set(),
      syncedL' = syncedL,
      syncedR' = syncedR,
      liveSig' = liveSig,
      everAssignedL' = everAssignedL.union(newL.exclude(everAssignedL.union(everAssignedR))),
      everAssignedR' = everAssignedR.union(newR.exclude(everAssignedL.union(everAssignedR))),
      lastAsserted' = epoch,
      admittedAt' = epoch,
      executed' = false,
    }
  }

  // Re-assertion after a lapse: re-staff from the retained seed over the
  // current pool. Fresh seats fold ready:false; the synced store and any
  // still-valid ready signal are kept.
  action reassert = {
    val d = drawSeed(seed)
    val newL = drawL(d, pool)
    val newR = drawR(d, pool)
    all {
      not(executed),
      pendingPresent,
      cohortL.union(cohortR) == Set(),
      pool.size() == SHARD_SIZE,
      epoch' = epoch,
      pool' = Set(),
      benched' = benched,
      pendingPresent' = true,
      seed' = seed,
      cohortL' = newL,
      cohortR' = newR,
      readyL' = Set(),
      readyR' = Set(),
      syncedL' = syncedL,
      syncedR' = syncedR,
      liveSig' = liveSig,
      everAssignedL' = everAssignedL.union(newL.exclude(everAssignedL.union(everAssignedR))),
      everAssignedR' = everAssignedR.union(newR.exclude(everAssignedL.union(everAssignedR))),
      lastAsserted' = epoch,
      admittedAt' = admittedAt,
      executed' = false,
    }
  }

  // An observer completes syncing the child it is currently assigned, and
  // emits a ready signal into the proposer pool.
  action syncStep = {
    nondet v = IDS.oneOf()
    all {
      not(executed),
      cohortL.contains(v) or cohortR.contains(v),
      syncedL' = if (cohortL.contains(v)) syncedL.union(Set(v)) else syncedL,
      syncedR' = if (cohortR.contains(v)) syncedR.union(Set(v)) else syncedR,
      liveSig' = liveSig.union(Set(v)),
      epoch' = epoch,
      pool' = pool,
      benched' = benched,
      pendingPresent' = pendingPresent,
      seed' = seed,
      cohortL' = cohortL,
      cohortR' = cohortR,
      readyL' = readyL,
      readyR' = readyR,
      everAssignedL' = everAssignedL,
      everAssignedR' = everAssignedR,
      lastAsserted' = lastAsserted,
      admittedAt' = admittedAt,
      executed' = false,
    }
  }

  // A held signal is evicted from the proposer pool (its window passed
  // without collection). The abstraction of `evict_expired`: it may fire at
  // any time, so the checker explores both eviction-before-re-staff and
  // survival-to-re-staff.
  action expireSig = {
    nondet v = IDS.oneOf()
    all {
      not(executed),
      liveSig.contains(v),
      liveSig' = liveSig.exclude(Set(v)),
      epoch' = epoch,
      pool' = pool,
      benched' = benched,
      pendingPresent' = pendingPresent,
      seed' = seed,
      cohortL' = cohortL,
      cohortR' = cohortR,
      readyL' = readyL,
      readyR' = readyR,
      syncedL' = syncedL,
      syncedR' = syncedR,
      everAssignedL' = everAssignedL,
      everAssignedR' = everAssignedR,
      lastAsserted' = lastAsserted,
      admittedAt' = admittedAt,
      executed' = false,
    }
  }

  // The ready fold. A validator with a live signal, currently seated on a
  // child, is marked ready for that seat. The child-bound rule additionally
  // requires it synced that child; the unbound twin does not.
  action foldReady = {
    nondet v = IDS.oneOf()
    val readyForL = cohortL.contains(v) and live(v) and (UNBOUND_READY or syncedL.contains(v))
    val readyForR = cohortR.contains(v) and live(v) and (UNBOUND_READY or syncedR.contains(v))
    all {
      not(executed),
      readyForL or readyForR,
      readyL' = if (readyForL) readyL.union(Set(v)) else readyL,
      readyR' = if (readyForR) readyR.union(Set(v)) else readyR,
      epoch' = epoch,
      pool' = pool,
      benched' = benched,
      pendingPresent' = pendingPresent,
      seed' = seed,
      cohortL' = cohortL,
      cohortR' = cohortR,
      syncedL' = syncedL,
      syncedR' = syncedR,
      liveSig' = liveSig,
      everAssignedL' = everAssignedL,
      everAssignedR' = everAssignedR,
      lastAsserted' = lastAsserted,
      admittedAt' = admittedAt,
      executed' = false,
    }
  }

  // Pool churn during a lapse: a benched spare swaps in for a pooled member
  // (a jail-plus-activation, or another reshape returning its cohort). Keeps
  // the pool at target size but changes its composition.
  action churn = {
    nondet vout = pool.oneOf()
    nondet vin = benched.oneOf()
    all {
      POOL_CHURN,
      not(executed),
      pendingPresent,
      cohortL.union(cohortR) == Set(),
      benched != Set(),
      pool' = pool.exclude(Set(vout)).union(Set(vin)),
      benched' = benched.exclude(Set(vin)).union(Set(vout)),
      epoch' = epoch,
      pendingPresent' = pendingPresent,
      seed' = seed,
      cohortL' = cohortL,
      cohortR' = cohortR,
      readyL' = readyL,
      readyR' = readyR,
      syncedL' = syncedL,
      syncedR' = syncedR,
      liveSig' = liveSig,
      everAssignedL' = everAssignedL,
      everAssignedR' = everAssignedR,
      lastAsserted' = lastAsserted,
      admittedAt' = admittedAt,
      executed' = false,
    }
  }

  // Trigger quiet for TRIGGER_TTL but still inside the readiness TTL: the
  // cohort returns to the pool, the record and seed are retained.
  action lapse = all {
    not(executed),
    pendingPresent,
    cohortL.union(cohortR) != Set(),
    epoch - lastAsserted >= TRIGGER_TTL,
    epoch - admittedAt < READY_TTL,
    epoch' = epoch,
    pool' = pool.union(cohortL).union(cohortR),
    benched' = benched,
    pendingPresent' = true,
    seed' = seed,
    cohortL' = Set(),
    cohortR' = Set(),
    readyL' = Set(),
    readyR' = Set(),
    syncedL' = syncedL,
    syncedR' = syncedR,
    liveSig' = liveSig,
    everAssignedL' = everAssignedL,
    everAssignedR' = everAssignedR,
    lastAsserted' = lastAsserted,
    admittedAt' = admittedAt,
    executed' = false,
  }

  // Ungated for READY_TTL after admission: abandon, returning the cohort to
  // the pool and clearing the reshape's identity and any held signals.
  action abandon = all {
    not(executed),
    pendingPresent,
    epoch - admittedAt >= READY_TTL,
    epoch' = epoch,
    pool' = pool.union(cohortL).union(cohortR),
    benched' = benched,
    pendingPresent' = false,
    seed' = 0,
    cohortL' = Set(),
    cohortR' = Set(),
    readyL' = Set(),
    readyR' = Set(),
    syncedL' = Set(),
    syncedR' = Set(),
    liveSig' = Set(),
    everAssignedL' = Set(),
    everAssignedR' = Set(),
    lastAsserted' = lastAsserted,
    admittedAt' = admittedAt,
    executed' = false,
  }

  // The seating gate: parent halves plus ready cohort seats reach 2f+1 for
  // both children. The code counts ready seats, synced or not. Once fired
  // the model is terminal — the seated sets freeze for the invariant.
  action execute = all {
    not(executed),
    pendingPresent,
    PARENT_HALF_L + readyL.size() >= QUORUM,
    PARENT_HALF_R + readyR.size() >= QUORUM,
    executed' = true,
    epoch' = epoch,
    pool' = pool,
    benched' = benched,
    pendingPresent' = false,
    seed' = seed,
    cohortL' = cohortL,
    cohortR' = cohortR,
    readyL' = readyL,
    readyR' = readyR,
    syncedL' = syncedL,
    syncedR' = syncedR,
    liveSig' = liveSig,
    everAssignedL' = everAssignedL,
    everAssignedR' = everAssignedR,
    lastAsserted' = lastAsserted,
    admittedAt' = admittedAt,
  }

  action tick = all {
    epoch' = epoch + 1,
    pool' = pool,
    benched' = benched,
    pendingPresent' = pendingPresent,
    seed' = seed,
    cohortL' = cohortL,
    cohortR' = cohortR,
    readyL' = readyL,
    readyR' = readyR,
    syncedL' = syncedL,
    syncedR' = syncedR,
    liveSig' = liveSig,
    everAssignedL' = everAssignedL,
    everAssignedR' = everAssignedR,
    lastAsserted' = lastAsserted,
    admittedAt' = admittedAt,
    executed' = executed,
  }

  action step = any {
    admit, reassert, syncStep, expireSig, foldReady, churn, lapse, abandon, execute, tick,
  }

  // Honest-synced members a child actually has: its parent half (trusted
  // live) plus ready cohort seats that genuinely synced that child and are
  // honest. Byzantine seats never count toward the functional floor.
  def functionalL = PARENT_HALF_L + cohortL.intersect(syncedL).exclude(BYZ).size()
  def functionalR = PARENT_HALF_R + cohortR.intersect(syncedR).exclude(BYZ).size()

  // Placements partition: the pool, the two cohorts, and the bench are
  // disjoint and cover every observer.
  val invConservation = and {
    pool.union(cohortL).union(cohortR).union(benched) == IDS,
    cohortL.intersect(cohortR) == Set(),
    pool.intersect(cohortL) == Set(),
    pool.intersect(cohortR) == Set(),
    benched.intersect(pool) == Set(),
    benched.intersect(cohortL) == Set(),
    benched.intersect(cohortR) == Set(),
  }

  // INV-RESHAPE-7: an observer's child assignment never drifts from its
  // first-ever assignment across a lapse/re-staff cycle.
  val invSeatStability = and {
    cohortL.intersect(everAssignedR) == Set(),
    cohortR.intersect(everAssignedL) == Set(),
  }

  // Seating soundness premise: no honest observer is ready-flagged for a
  // child it has not synced. This is the invariant the unbound-signal
  // finding targets.
  val invNoHonestFalseReady = and {
    readyL.exclude(BYZ).subseteq(syncedL),
    readyR.exclude(BYZ).subseteq(syncedR),
  }

  // INV-RESHAPE-1 (semantic floor): if the split executed, each child seats
  // at least a quorum of genuinely honest-synced members.
  val invSeatingGate =
    executed implies (functionalL >= QUORUM and functionalR >= QUORUM)

  val invAll = and {
    invConservation,
    invSeatStability,
    invNoHonestFalseReady,
    invSeatingGate,
  }
}

// Healthy split: frozen seed, honest cohort, no pool churn, child-bound
// signal. Staffing soundness holds through admit, lapse/re-staff, execute.
module reshape_split_ok {
  import reshape_lifecycle(
    SHARD_SIZE = 4, F = 1, PARENT_HALF_L = 2, PARENT_HALF_R = 2,
    TRIGGER_TTL = 2, READY_TTL = 5, BYZ = Set(),
    SEEDS = Set(1, 2), EPOCH_SEEDED_DRAW = false, POOL_CHURN = false,
    UNBOUND_READY = false
  ).*
}

// Pool churn, child-bound signal. The frozen-seed re-staff over a churned
// pool drifts an observer off its first assignment (invSeatStability fails),
// but the drift is benign: a child-bound signal will not fold for the new
// seat, so invNoHonestFalseReady and invSeatingGate still hold.
module reshape_split_churn {
  import reshape_lifecycle(
    SHARD_SIZE = 4, F = 1, PARENT_HALF_L = 2, PARENT_HALF_R = 2,
    TRIGGER_TTL = 2, READY_TTL = 5, BYZ = Set(),
    SEEDS = Set(1, 2), EPOCH_SEEDED_DRAW = false, POOL_CHURN = true,
    UNBOUND_READY = false
  ).*
}

// The finding. Pool churn plus an unbound signal: a still-valid ready signal
// emitted for the observer's prior seat folds for the seat it churned to,
// marking it ready without ever syncing that child — invNoHonestFalseReady
// (and, downstream, invSeatingGate) fails with no Byzantine actor.
module reshape_unbound_ready {
  import reshape_lifecycle(
    SHARD_SIZE = 4, F = 1, PARENT_HALF_L = 2, PARENT_HALF_R = 2,
    TRIGGER_TTL = 2, READY_TTL = 5, BYZ = Set(),
    SEEDS = Set(1, 2), EPOCH_SEEDED_DRAW = false, POOL_CHURN = true,
    UNBOUND_READY = true
  ).*
}

// The shipped fix's twin, no pool churn needed: an epoch-seeded draw (not the
// frozen `cohort_seed`) re-rolls the child assignment on every re-staff, so a
// lapse and re-assert at a later epoch drifts an observer off its first child.
// This is the joiner child-swap the frozen seed closed; `invSeatStability`
// fails, showing the freeze is load-bearing against epoch churn.
module reshape_epoch_seeded {
  import reshape_lifecycle(
    SHARD_SIZE = 4, F = 1, PARENT_HALF_L = 2, PARENT_HALF_R = 2,
    TRIGGER_TTL = 2, READY_TTL = 5, BYZ = Set(),
    SEEDS = Set(1, 2), EPOCH_SEEDED_DRAW = true, POOL_CHURN = false,
    UNBOUND_READY = false
  ).*
}

// The merge fold, and the split/merge asymmetry it makes precise. Two sibling
// children C1 and C2 merge into their parent: both assert a merge trigger,
// and on pairing the beacon draws a keeper committee — half from each child,
// from the members that child already runs. Keepers stay on their child and
// take on a second duty (assembling the merged store); a keeper's assignment
// is therefore its *membership*, not a seed-derived slot, so it cannot drift
// the way a split observer's child can. A merge whose half goes quiet cancels
// clean — keepers were never moved, so nothing is retained and no re-staff can
// re-roll them.
//
// The keeper draw prefers members already ready and backfills any shortfall
// from the not-yet-ready half, so the merged committee always reaches target
// size; execution still gates on a 2f+1 ready keeper quorum. The
// `reshape_short_draw` twin draws ready members only, with no backfill, so a
// child short on ready at pairing seats a merged committee below target — the
// `merge_seats_full_keeper_committee` regression (a single-shard merge is not
// top-up-eligible, so an under-sized committee never heals).
//
// Code anchors: crates/beacon/src/state/reshape.rs `draw_merge_keepers`
// (ready-preferring draw with backfill), `try_execute_merge` (2f+1 ready
// gate); crates/beacon/src/state/witness.rs (pairing, per-child cancel);
// crates/beacon/src/state/committee.rs (the shuffle pins keepers).
//
// Run:
//   quint verify --main=reshape_epoch_seeded --invariant=invSeatStability --max-steps=10 specs/reshape_lifecycle.qnt
//     (epoch-seeded re-staff drifts the assignment; expect a counterexample)
//   quint verify --main=reshape_merge_ok    --invariant=invAll --max-steps=8 specs/reshape_lifecycle.qnt
//     (backfilled draw: the merged committee seats at target with a ready quorum)
//   quint verify --main=reshape_merge_short --invariant=invKeeperSized --max-steps=8 specs/reshape_lifecycle.qnt
//     (ready-only draw: a child short on ready seats below target; expect a counterexample)
module reshape_merge {
  // Merged committee target; each child contributes half its keepers.
  const SHARD_SIZE: int
  // Byzantine tolerance and quorum: committee 3F+1, quorum 2F+1.
  const F: int
  // A merge half goes quiet for this many epochs → the merge cancels.
  const TRIGGER_TTL: int
  // The fixed Byzantine keeper set. Honest = complement.
  const BYZ: Set[int]
  // Broken twin: draw only ready members, no backfill, so a child short on
  // ready at pairing seats the merged committee below target. False is the
  // shipped ready-preferring draw that backfills to target size.
  const SHORT_DRAW: bool

  pure val QUORUM = 2 * F + 1
  pure val HALF = SHARD_SIZE / 2
  // The two sibling children's committees: the low half and the high half.
  pure val C1 = 1.to(HALF)
  pure val C2 = (HALF + 1).to(SHARD_SIZE)

  // Current epoch.
  var epoch: int
  // Last epoch each child asserted its merge trigger (-1 = not asserted).
  var assert1: int
  var assert2: int
  // The merge has paired and drawn keepers.
  var paired: bool
  // Drawn keepers (each runs the child it is a member of).
  var keepers: Set[int]
  // Members that have synced their own child (readiness the draw reads).
  var readyC1: Set[int]
  var readyC2: Set[int]
  // Keepers that have assembled the merged store (synced the sibling).
  var keeperSynced: Set[int]
  // The merge has executed; the model is terminal.
  var executed: bool

  action init = all {
    epoch' = 0,
    assert1' = -1,
    assert2' = -1,
    paired' = false,
    keepers' = Set(),
    readyC1' = Set(),
    readyC2' = Set(),
    keeperSynced' = Set(),
    executed' = false,
  }

  // A child asserts (or refreshes) its merge trigger.
  action assertHalf1 = all {
    not(executed),
    assert1' = epoch,
    epoch' = epoch, assert2' = assert2, paired' = paired, keepers' = keepers,
    readyC1' = readyC1, readyC2' = readyC2, keeperSynced' = keeperSynced,
    executed' = false,
  }

  action assertHalf2 = all {
    not(executed),
    assert2' = epoch,
    epoch' = epoch, assert1' = assert1, paired' = paired, keepers' = keepers,
    readyC1' = readyC1, readyC2' = readyC2, keeperSynced' = keeperSynced,
    executed' = false,
  }

  // A member finishes syncing its own child (grows the readiness the draw
  // reads at pairing).
  action readyStep = {
    nondet v = C1.union(C2).oneOf()
    all {
      not(executed),
      not(paired),
      readyC1' = if (C1.contains(v)) readyC1.union(Set(v)) else readyC1,
      readyC2' = if (C2.contains(v)) readyC2.union(Set(v)) else readyC2,
      epoch' = epoch, assert1' = assert1, assert2' = assert2, paired' = paired,
      keepers' = keepers, keeperSynced' = keeperSynced, executed' = false,
    }
  }

  // Both halves asserted: draw the keeper committee. The healthy draw takes
  // each child's half (backfilled to size); the twin takes only ready members.
  action pair = all {
    not(executed),
    not(paired),
    assert1 >= 0,
    assert2 >= 0,
    keepers' = if (SHORT_DRAW) readyC1.union(readyC2) else C1.union(C2),
    paired' = true,
    epoch' = epoch, assert1' = assert1, assert2' = assert2,
    readyC1' = readyC1, readyC2' = readyC2, keeperSynced' = keeperSynced,
    executed' = false,
  }

  // A keeper assembles the merged store (syncs the sibling child).
  action keeperSyncStep = {
    nondet v = C1.union(C2).oneOf()
    all {
      not(executed),
      paired,
      keepers.contains(v),
      keeperSynced' = keeperSynced.union(Set(v)),
      epoch' = epoch, assert1' = assert1, assert2' = assert2, paired' = paired,
      keepers' = keepers, readyC1' = readyC1, readyC2' = readyC2,
      executed' = false,
    }
  }

  // A half goes quiet past the trigger TTL: the merge cancels clean —
  // keepers are released (they never left their child), halves must reassert.
  action cancel = all {
    not(executed),
    paired,
    epoch - assert1 >= TRIGGER_TTL or epoch - assert2 >= TRIGGER_TTL,
    paired' = false,
    keepers' = Set(),
    keeperSynced' = Set(),
    assert1' = -1,
    assert2' = -1,
    epoch' = epoch, readyC1' = readyC1, readyC2' = readyC2, executed' = false,
  }

  // The gate: a 2f+1 quorum of keepers has assembled the merged store.
  action execute = all {
    not(executed),
    paired,
    keeperSynced.size() >= QUORUM,
    executed' = true,
    epoch' = epoch, assert1' = assert1, assert2' = assert2, paired' = paired,
    keepers' = keepers, readyC1' = readyC1, readyC2' = readyC2,
    keeperSynced' = keeperSynced,
  }

  action tick = all {
    epoch' = epoch + 1,
    assert1' = assert1, assert2' = assert2, paired' = paired, keepers' = keepers,
    readyC1' = readyC1, readyC2' = readyC2, keeperSynced' = keeperSynced,
    executed' = executed,
  }

  action step = any {
    assertHalf1, assertHalf2, readyStep, pair, keeperSyncStep, cancel, execute, tick,
  }

  // Keepers are drawn from the two children only, and only synced keepers
  // count as merge-ready — every keeper runs the child it belongs to, so a
  // keeper's assignment cannot drift (the split/merge asymmetry).
  val invConservation = and {
    keepers.subseteq(C1.union(C2)),
    keeperSynced.subseteq(keepers),
    readyC1.subseteq(C1),
    readyC2.subseteq(C2),
  }

  // INV-RESHAPE-1 / INV-RESHAPE-8 staffing: a paired merge draws a committee
  // at target size. The short-draw twin seats a child short on ready below it.
  val invKeeperSized = paired implies keepers.size() == SHARD_SIZE

  // INV-RESHAPE-1 (semantic floor): an executed merge has a 2f+1 honest quorum
  // of keepers holding the merged store.
  val invKeeperGate =
    executed implies keeperSynced.exclude(BYZ).size() >= QUORUM

  val invAll = and { invConservation, invKeeperSized, invKeeperGate }
}

// Healthy merge: ready-preferring draw with backfill. The merged committee
// seats at target size and executes on a 2f+1 ready keeper quorum.
module reshape_merge_ok {
  import reshape_merge(SHARD_SIZE = 4, F = 1, TRIGGER_TTL = 2, BYZ = Set(), SHORT_DRAW = false).*
}

// Broken twin: ready-only draw. A child short on ready at pairing seats the
// merged committee below target size — the `merge_seats_full_keeper_committee`
// regression, which a single-shard merge cannot top up.
module reshape_merge_short {
  import reshape_merge(SHARD_SIZE = 4, F = 1, TRIGGER_TTL = 2, BYZ = Set(), SHORT_DRAW = true).*
}
