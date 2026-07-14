// Model G (register: specs/README.md) — halt detection and the full
// committee re-draw. The `halt_detection` module checks INV-SEC-9 (halt
// detection and recovery) and the recovery clause of INV-SEC-2 (rotation
// never touches a recovering shard); INV-SEC-8, the recovery bridge, is
// the register row's other half.
//
// One subject shard, folded by the committed beacon epoch sequence. The
// environment plays that sequence: per epoch the shard either contributes
// a genuine crossing, contributes nothing, or has its already-recorded
// crossing re-ride a proposal (a stale re-fold); the beacon itself either
// commits the epoch or skips it. The detector, the re-draw, the retention,
// and the shuffle skip are transcribed from the fold; everything else in
// the network exists only as that input trace.
//
// Code anchors:
//   - Miss counting: crates/beacon/src/state/epoch.rs `record_boundaries` —
//     a genuine crossing resets `consecutive_misses` and clears the pending
//     recovery; a re-fold of the recorded crossing with no witness progress
//     is skipped (no refresh — refreshing would reset the counter and
//     release retention on data the fold already consumed); every
//     unrefreshed live shard bumps. A skip epoch folds no boundaries and
//     bumps nothing (`apply_epoch`, `ApplyEpochInput::Skip`), so a beacon
//     commit drought never reads as a shard halt.
//   - Detector: crates/types/src/beacon/state.rs `halted_shards` — live,
//     not a reshape-pending placeholder (a genesis-born placeholder is NOT
//     exempt), not reshape-involved, misses strictly past
//     `HALT_THRESHOLD_EPOCHS` (crates/types/src/beacon/constants.rs).
//   - Recovery: crates/beacon/src/state/committee.rs
//     `recover_halted_committee` — all-or-nothing full draw from the free
//     pool (a short pool defers and the shard retries each fold), fresh
//     committee seated whole, replaced committee pooled and folded into
//     the `HaltRecovery` retention (a stalled recovery's own fresh
//     committee joins the successor record's retention). Detection and
//     recovery run in `apply_epoch` on skip epochs too — the recovery
//     rides beacon liveness, not shard traffic.
//   - Shuffle skip: crates/beacon/src/state/committee.rs
//     `run_shuffle_step` — rotation skips a recovering shard (a rotated-in
//     draw could never fold its Ready witness on a chain that has not
//     produced; each rotation would shrink the workable consensus subset).
//
// Properties:
//   invDetectorSound — a live, non-reshaping shard that has missed more
//                      than THRESHOLD observed folds is flagged or already
//                      under recovery, however its stale crossing is
//                      re-proposed (INV-SEC-9, detection half). The
//                      `halt_refresh_on_refold` twin refreshes the
//                      watermark on a consumed crossing and violates it: a
//                      halted shard whose stale crossing keeps riding
//                      proposals never flags.
//   invNoFalseFlag   — every detector firing is genuine: the shard had
//                      really missed more than THRESHOLD observed folds at
//                      that fold, and a flagged state implies the same
//                      (INV-SEC-9's calibration premise). The
//                      `halt_wallclock_watermark` twin advances the
//                      counter on skip epochs too and violates it: a
//                      beacon commit drought flags a healthy shard — the
//                      cascade the observed-folds rule prevents.
//   invRetention     — while a recovery pends, every committee a recovery
//                      has replaced since the last genuine crossing is in
//                      the retained routing set (the fold-forward across a
//                      stalled recovery), and retention exists only while
//                      a recovery pends. The refresh twin also breaks this
//                      on a longer trace: the bogus refresh releases the
//                      retention, and the next re-draw starts it empty.
//   invRecoveryHygiene — placements partition (committee/pool/bench
//                      disjoint, covering all validators), the committee
//                      is always full-size (all-or-nothing re-draw, no
//                      partial re-seed), and while a recovery pends the
//                      committee is exactly the last fresh draw — no
//                      rotation touches it (INV-SEC-2, recovery clause).
//
// Modeling assumptions:
//   - The fold is a pure function of (state, epoch input) by construction —
//     every action's update is deterministic given the environment's
//     choice, mirroring INV-BEACON-2; there is no separate determinism
//     invariant to check.
//   - The re-draw is a nondeterministic full-size subset of the pool —
//     the image of every deterministic sampler, `sample_committee`
//     included, so the checked properties over-approximate the shipped
//     draw. Draw distribution is SEC-1's subject (committee_security.md
//     §10 table S prices the grind-resistance), and replica agreement on
//     the concrete draw is INV-BEACON-2's fold determinism; here only
//     all-or-nothing and pool-only sourcing matter. The replaced
//     committee's exclusion from its own replacement draw is structural:
//     the pool and the committee partition.
//   - Shuffle victim choice is nondeterministic. The FIFO tenure rule is a
//     grind lever priced in SEC-1, not a reachability property; the
//     eligible-floor rotation hold is likewise transcribed but not
//     adjudicated (with one shard, `beacon_eligible` reduces to the
//     committee, and the recovering shard's sit-out is definitional).
//   - Exemptions are point-in-time: misses keep accruing while a shard is
//     reshape-involved (the bump excludes only terminal records), so a
//     shard that leaves a long reshape with a genuinely quiet chain flags
//     at the next fold. Deliberate — misses measure real quiet, and the
//     exemption only suppresses flagging while the quiet is legitimate.
//   - Residual, noted not adjudicated: rotation keeps running on a
//     halted-but-not-yet-flagged shard (the skip begins at the re-draw),
//     so up to one tip-holding member per shuffle interval can leave the
//     committee before the recovery seats and thus sit outside the
//     retained routing set. Retention guarantees the cohorts a recovery
//     replaced, not every server since the halt began.
//
// Run:
//   quint typecheck specs/halt_recovery.qnt
//   quint test --main=halt_detection_ok specs/halt_recovery.qnt
//   quint verify --main=halt_detection_ok --invariant=invAll --max-steps=6 specs/halt_recovery.qnt
//     (holds; depth 6 covers the full double-recovery lifecycle at
//      THRESHOLD = 1 — seed, halt, re-draw, stall, second re-draw, clear)
//   quint verify --main=halt_refresh_on_refold --invariant=invDetectorSound --max-steps=6 specs/halt_recovery.qnt
//     (the twin refreshes on a consumed crossing; expect a counterexample)
//   quint verify --main=halt_refresh_on_refold --invariant=invRetention --max-steps=7 specs/halt_recovery.qnt
//     (the bogus refresh also releases a pending recovery's retention;
//      expect a counterexample)
//   quint verify --main=halt_wallclock_watermark --invariant=invNoFalseFlag --max-steps=6 specs/halt_recovery.qnt
//     (the twin bumps on skip epochs; expect a counterexample)

module halt_detection {
  // Committee size (production 128; model scale).
  const SHARD_SIZE: int
  // Flag strictly past this many consecutive missed observed folds
  // (`HALT_THRESHOLD_EPOCHS`; model-scaled).
  const THRESHOLD: int
  // The validator universe: the initial committee plus the free pool.
  const VALIDATORS: Set[int]
  // Broken twin: a re-fold of the already-recorded crossing refreshes the
  // watermark and releases retention. False is the shipped skip.
  const REFRESH_ON_REFOLD: bool
  // Broken twin: the miss counter advances on skip epochs too — a
  // wall-clock watermark. False is the shipped observed-folds rule.
  const BUMP_ON_SKIP: bool

  // ── The subject shard's boundary record ──
  // The chain has recorded a crossing (`block_hash != ZERO`).
  var seeded: bool
  // The record was created at network genesis: an unseeded genesis-born
  // chain is not placeholder-exempt — nothing gates its start, so never
  // producing is a halt.
  var bornAtGenesis: bool
  var terminal: bool
  // `reshape_involves`: the shard is a pending reshape's target or child.
  var reshaping: bool
  // `ShardBoundary::consecutive_misses`.
  var misses: int

  // ── Staffing ──
  var committee: Set[int]
  var pool: Set[int]
  // Deactivated validators (out of the pool, can re-activate).
  var benched: Set[int]
  // The `pending_recoveries` entry.
  var recoveryPending: bool
  var retained: Set[int]

  // ── Ground truth (ghost) ──
  // Observed (non-skip) folds since the chain's last genuine crossing —
  // the environment's bookkeeping, independent of the watermark rules.
  var groundMisses: int
  // Every committee a recovery has replaced since the last genuine
  // crossing.
  var replacedAccum: Set[int]
  // Whether a rotation has touched the committee since the last re-draw
  // seated it. The committee mutates only through the shuffle and the
  // re-draw, so this flag carries "the committee is exactly the last
  // fresh draw" without a symbolic set equality.
  var rotatedSinceDraw: bool
  // Monotone: every detector firing so far was genuine (the ground count
  // really exceeded THRESHOLD at that fold). Latched at firing time
  // because the fold flags and re-draws atomically, so a false flag never
  // survives into a stored flagged state.
  var flagGroundOk: bool

  // `halted_shards` on the stored state.
  val flagged: bool = and {
    not(terminal),
    seeded or bornAtGenesis,
    not(reshaping),
    misses > THRESHOLD,
  }

  // The shared tail of every fold: store the new watermark, then run the
  // detector and — at the same fold — the all-or-nothing re-draw
  // (`apply_epoch`: `halted_shards` then `recover_halted_committees`).
  // `newGround` is the environment's own count of observed quiet folds.
  action detectRecover(newMisses: int, newGround: int): bool = {
    val fires = and {
      not(terminal),
      seeded or bornAtGenesis,
      not(reshaping),
      newMisses > THRESHOLD,
    }
    if (fires and pool.size() >= SHARD_SIZE) {
      // Any full-size pool subset. With one shard the pool never exceeds
      // SHARD_SIZE + 1 (the committee holds the rest of the universe), so
      // every full-size subset is the pool minus at most one leftover —
      // element-level nondeterminism, exact at these instance constants
      // and far cheaper for the solver than a powerset pick.
      nondet leftover = pool.oneOf()
      val fresh = if (pool.size() == SHARD_SIZE) pool else pool.exclude(Set(leftover))
      all {
        committee' = fresh,
        pool' = pool.exclude(fresh).union(committee),
        benched' = benched,
        recoveryPending' = true,
        // Fold-forward: a stalled recovery's own fresh committee joins the
        // successor record's retention.
        retained' = retained.union(committee),
        replacedAccum' = replacedAccum.union(committee),
        rotatedSinceDraw' = false,
        // The recovery resets the watermark: the fresh committee gets a
        // full threshold of observed folds before the shard re-flags.
        misses' = 0,
        groundMisses' = newGround,
        flagGroundOk' = flagGroundOk and newGround > THRESHOLD,
        seeded' = seeded,
        bornAtGenesis' = bornAtGenesis,
        terminal' = terminal,
        reshaping' = reshaping,
      }
    } else all {
      misses' = newMisses,
      groundMisses' = newGround,
      // A firing deferred on a short pool is still a firing.
      flagGroundOk' = if (fires) flagGroundOk and newGround > THRESHOLD else flagGroundOk,
      committee' = committee,
      pool' = pool,
      benched' = benched,
      recoveryPending' = recoveryPending,
      retained' = retained,
      replacedAccum' = replacedAccum,
      rotatedSinceDraw' = rotatedSinceDraw,
      seeded' = seeded,
      bornAtGenesis' = bornAtGenesis,
      terminal' = terminal,
      reshaping' = reshaping,
    }
  }

  // A committed epoch whose boundaries include the shard's genuine
  // crossing: refresh the record, clear the pending recovery (the fresh
  // committee produced — the recovery is complete).
  action foldCross = all {
    not(terminal),
    seeded' = true,
    misses' = 0,
    groundMisses' = 0,
    recoveryPending' = false,
    retained' = Set(),
    replacedAccum' = Set(),
    committee' = committee,
    pool' = pool,
    benched' = benched,
    rotatedSinceDraw' = rotatedSinceDraw,
    flagGroundOk' = flagGroundOk,
    bornAtGenesis' = bornAtGenesis,
    terminal' = terminal,
    reshaping' = reshaping,
  }

  // A committed epoch with no qualifying contribution from the shard.
  action foldQuiet = all {
    not(terminal),
    detectRecover(misses + 1, groundMisses + 1),
  }

  // A committed epoch where the shard's already-recorded crossing rides a
  // proposal again with no witness progress. The shipped fold skips the
  // record — the shard is unrefreshed, so the bump applies and a halted
  // shard still flags. The twin treats it as fresh: watermark reset and
  // pending retention released on data the fold already consumed.
  action foldRefold = all {
    not(terminal),
    seeded,
    if (REFRESH_ON_REFOLD) all {
      misses' = 0,
      recoveryPending' = false,
      retained' = Set(),
      groundMisses' = groundMisses + 1,
      replacedAccum' = replacedAccum,
      committee' = committee,
      pool' = pool,
      benched' = benched,
      rotatedSinceDraw' = rotatedSinceDraw,
      flagGroundOk' = flagGroundOk,
      seeded' = seeded,
      bornAtGenesis' = bornAtGenesis,
      terminal' = terminal,
      reshaping' = reshaping,
    } else detectRecover(misses + 1, groundMisses + 1),
  }

  // A skip epoch: no boundary fold, no bump — but detection and recovery
  // still run on the carried state, so a deferred re-draw can seat as
  // soon as the pool refills, skip or not. The twin bumps here too.
  action skipEpoch =
    detectRecover(if (BUMP_ON_SKIP) misses + 1 else misses, groundMisses)

  // One trickle rotation on the shard: swap one member for a pool draw.
  // Skips a recovering, reshaping, or terminal shard. Victim choice is
  // nondeterministic (see the header).
  action shuffle = {
    nondet victim = VALIDATORS.oneOf()
    nondet joiner = VALIDATORS.oneOf()
    all {
      not(recoveryPending),
      not(reshaping),
      not(terminal),
      victim.in(committee),
      joiner.in(pool),
      committee' = committee.exclude(Set(victim)).union(Set(joiner)),
      pool' = pool.exclude(Set(joiner)).union(Set(victim)),
      benched' = benched,
      misses' = misses,
      groundMisses' = groundMisses,
      recoveryPending' = recoveryPending,
      retained' = retained,
      replacedAccum' = replacedAccum,
      rotatedSinceDraw' = true,
      flagGroundOk' = flagGroundOk,
      seeded' = seeded,
      bornAtGenesis' = bornAtGenesis,
      terminal' = terminal,
      reshaping' = reshaping,
    }
  }

  // A reshape admits naming the shard / executes or lapses away.
  action beginReshape = all {
    not(reshaping),
    not(terminal),
    reshaping' = true,
    seeded' = seeded, bornAtGenesis' = bornAtGenesis, terminal' = terminal,
    misses' = misses, committee' = committee, pool' = pool,
    benched' = benched, recoveryPending' = recoveryPending,
    retained' = retained, groundMisses' = groundMisses,
    replacedAccum' = replacedAccum, rotatedSinceDraw' = rotatedSinceDraw,
    flagGroundOk' = flagGroundOk,
  }
  action endReshape = all {
    reshaping,
    reshaping' = false,
    seeded' = seeded, bornAtGenesis' = bornAtGenesis, terminal' = terminal,
    misses' = misses, committee' = committee, pool' = pool,
    benched' = benched, recoveryPending' = recoveryPending,
    retained' = retained, groundMisses' = groundMisses,
    replacedAccum' = replacedAccum, rotatedSinceDraw' = rotatedSinceDraw,
    flagGroundOk' = flagGroundOk,
  }

  // The shard's chain reaches a scheduled terminal cut (absorbing).
  action markTerminal = all {
    seeded,
    not(terminal),
    terminal' = true,
    seeded' = seeded, bornAtGenesis' = bornAtGenesis, reshaping' = reshaping,
    misses' = misses, committee' = committee, pool' = pool,
    benched' = benched, recoveryPending' = recoveryPending,
    retained' = retained, groundMisses' = groundMisses,
    replacedAccum' = replacedAccum, rotatedSinceDraw' = rotatedSinceDraw,
    flagGroundOk' = flagGroundOk,
  }

  // Pool churn: a pooled validator deactivates, a benched one
  // re-activates. Reaches the short-pool deferral and the later retry.
  action poolLeave = {
    nondet v = VALIDATORS.oneOf()
    all {
      v.in(pool),
      pool' = pool.exclude(Set(v)),
      benched' = benched.union(Set(v)),
      committee' = committee, misses' = misses,
      groundMisses' = groundMisses, recoveryPending' = recoveryPending,
      retained' = retained, replacedAccum' = replacedAccum,
      rotatedSinceDraw' = rotatedSinceDraw, flagGroundOk' = flagGroundOk,
      seeded' = seeded, bornAtGenesis' = bornAtGenesis,
      terminal' = terminal, reshaping' = reshaping,
    }
  }
  action poolJoin = {
    nondet v = VALIDATORS.oneOf()
    all {
      v.in(benched),
      benched' = benched.exclude(Set(v)),
      pool' = pool.union(Set(v)),
      committee' = committee, misses' = misses,
      groundMisses' = groundMisses, recoveryPending' = recoveryPending,
      retained' = retained, replacedAccum' = replacedAccum,
      rotatedSinceDraw' = rotatedSinceDraw, flagGroundOk' = flagGroundOk,
      seeded' = seeded, bornAtGenesis' = bornAtGenesis,
      terminal' = terminal, reshaping' = reshaping,
    }
  }

  action init = {
    // The record starts live-seeded, as a reshape-pending placeholder
    // (unseeded, created later than genesis), or as a genesis-born chain
    // that has not yet produced — the detector treats the three apart.
    nondet startSeeded = Set(true, false).oneOf()
    nondet genesisBorn = Set(true, false).oneOf()
    all {
      seeded' = startSeeded,
      bornAtGenesis' = genesisBorn,
      terminal' = false,
      reshaping' = false,
      misses' = 0,
      committee' = 1.to(SHARD_SIZE),
      pool' = VALIDATORS.exclude(1.to(SHARD_SIZE)),
      benched' = Set(),
      recoveryPending' = false,
      retained' = Set(),
      groundMisses' = 0,
      replacedAccum' = Set(),
      rotatedSinceDraw' = false,
      flagGroundOk' = true,
    }
  }

  action step = any {
    foldCross,
    foldQuiet,
    foldRefold,
    skipEpoch,
    shuffle,
    beginReshape,
    endReshape,
    markTerminal,
    poolLeave,
    poolJoin,
  }

  // ── Invariants ──

  val invDetectorSound = and {
    groundMisses > THRESHOLD,
    not(terminal),
    not(reshaping),
    seeded or bornAtGenesis,
  } implies (flagged or recoveryPending)

  val invNoFalseFlag = and {
    flagGroundOk,
    flagged implies groundMisses > THRESHOLD,
  }

  val invRetention = and {
    recoveryPending implies replacedAccum.subseteq(retained),
    not(recoveryPending) implies retained == Set(),
  }

  val invRecoveryHygiene = and {
    committee.size() == SHARD_SIZE,
    committee.intersect(pool) == Set(),
    committee.intersect(benched) == Set(),
    pool.intersect(benched) == Set(),
    committee.union(pool).union(benched) == VALIDATORS,
    recoveryPending implies not(rotatedSinceDraw),
  }

  val invAll = and {
    invDetectorSound,
    invNoFalseFlag,
    invRetention,
    invRecoveryHygiene,
  }

  // ── Scripted witnesses ──

  // Halt, flag-and-re-draw at one fold, stall again, re-draw again with
  // the first fresh committee folded into the retention, then the first
  // genuine crossing clears the record. THRESHOLD = 1 in the instances.
  run haltRecoverRedrawClearTest =
    init
      .then(foldCross)
      .then(foldQuiet)
      .then(foldQuiet)
      .expect(and {
        recoveryPending,
        misses == 0,
        retained == 1.to(4),
        committee.subseteq(5.to(9)),
        committee.size() == SHARD_SIZE,
      })
      .then(foldQuiet)
      .then(foldQuiet)
      .expect(recoveryPending and 1.to(4).subseteq(retained) and retained.size() == 8)
      .then(foldCross)
      .expect(not(recoveryPending) and retained == Set() and misses == 0)

  // A short pool defers the re-draw — the shard stays flagged, nothing is
  // partially re-seeded — and the refilled pool seats it at the next
  // fold, a skip epoch included.
  run poolShortDefersThenRecoversTest =
    init
      .then(foldCross)
      .then(poolLeave)
      .then(poolLeave)
      .then(foldQuiet)
      .then(foldQuiet)
      .expect(flagged and not(recoveryPending) and committee == 1.to(4))
      .then(poolJoin)
      .then(skipEpoch)
      .expect(recoveryPending and misses == 0)

  // A beacon commit drought is not a shard halt: skip epochs advance
  // nothing.
  run droughtNeverFlagsTest =
    init
      .then(foldCross)
      .then(skipEpoch)
      .then(skipEpoch)
      .then(skipEpoch)
      .then(skipEpoch)
      .then(skipEpoch)
      .expect(not(flagged) and not(recoveryPending) and misses == 0)
}

// The shipped rules: the re-fold of a consumed crossing is skipped, skip
// epochs bump nothing.
module halt_detection_ok {
  import halt_detection(
    SHARD_SIZE = 4, THRESHOLD = 1, VALIDATORS = 1.to(9),
    REFRESH_ON_REFOLD = false, BUMP_ON_SKIP = false
  ).*
}

// Broken twin: a stale re-fold refreshes the watermark, so a halted shard
// whose recorded crossing keeps riding proposals never flags —
// invDetectorSound fails (and, on a longer trace, the bogus refresh
// releases a pending recovery's retention and invRetention fails).
module halt_refresh_on_refold {
  import halt_detection(
    SHARD_SIZE = 4, THRESHOLD = 1, VALIDATORS = 1.to(9),
    REFRESH_ON_REFOLD = true, BUMP_ON_SKIP = false
  ).*
}

// Broken twin: the counter advances on skip epochs — a wall-clock
// watermark. A beacon commit drought then flags a shard that crossed at
// the last observed fold — invNoFalseFlag fails.
module halt_wallclock_watermark {
  import halt_detection(
    SHARD_SIZE = 4, THRESHOLD = 1, VALIDATORS = 1.to(9),
    REFRESH_ON_REFOLD = false, BUMP_ON_SKIP = true
  ).*
}
