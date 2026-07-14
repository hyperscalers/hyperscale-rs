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

// The recovery bridge: the authority handoff from the retained (halted)
// committee to the fresh one — INV-SEC-8. The one module in the register
// whose adversary exceeds the `BYZ ≤ F` axiom: the retained committee
// holds f+1..2f corrupt (the recovery exists because that bound failed),
// while the fresh committee holds ≤ f (a full re-draw, SEC-1 table S).
// Model B is the per-committee consensus oracle (a certificate needs a
// quorum, an honest voter extends only a chain it admits, commit is a
// height-contiguous certified pair); Model A is the clock oracle (one
// global window counter; skew appears only as the bounded drag an
// adversarial vote minority exerts on a certificate's aggregate stamp —
// one window under the window its honest votes opened in).
//
// Code anchors:
//   - Bridge + resolution: crates/types/src/topology/schedule.rs
//     `recovery_bridge` (= rotated_at + 1), `lookup_for_shard_live`
//     (anchor below the bridge resolves the fresh committee),
//     `lookup_for_shard_certified` (re-bind iff the anchor sits below the
//     bridge AND the certificate's window lands at or past the window
//     before it; the halted suffix fails the second conjunct and resolves
//     its own windows). A replica that has not folded the recovery
//     resolves the anchor window as ever and defers what its head cannot
//     cover.
//   - Quiesce + empty bridge blocks: crates/shard/src/coordinator.rs
//     `recovery_quiesced` (no proposal or vote on stale-anchored work
//     before the bridge window opens on the voter's own clock — the rule
//     that makes every fresh certificate land at or past BRIDGE − 1) and
//     `recovery_bridging` (a bridge block carries no content).
//
// The environment is free: the old committee may keep certifying (the
// halt is the corrupt cohort's choice, and the coalition of the corrupt
// pair plus a not-yet-folded honest member is a quorum), fold order is
// arbitrary, and certificates stamp the current window minus a
// nondeterministic one-window drag. Heights abstract Model B's safe-vote
// rule to height-contiguity: an honest voter signs height h only if some
// certificate it admits sits at h − 1 (the halted tip TIP is the frozen
// prefix; TIP + 1 is the contested extension).
//
// Properties (INV-SEC-8):
//   invSuffixVerifiable — every certificate the old committee formed
//                      strictly below the re-bind tolerance (its window
//                      before BRIDGE − 1) resolves the old committee at
//                      every honest replica, folded or not: the recovery
//                      never orphans the halted suffix.
//   invBridgeBindable — every fresh-committee certificate lands at or
//                      past BRIDGE − 1, so the certified re-bind always
//                      binds it: the quiesce is what makes the one-window
//                      tolerance sufficient, mechanized.
//   invBridgeEmpty    — a fresh-side certificate over a stale-anchored
//                      (bridge) block carries no content.
//   invNoStaleCommit  — no post-rotation old-side height-contiguous pair
//                      is admissible at a replica that folded the
//                      recovery: stale authority can dangle a lone
//                      certificate inside the tolerance window, but it
//                      cannot commit there.
//
// Modeling assumptions:
//   - A certificate stamped in the rotation window with maximal drag
//     lands at BRIDGE − 2 and legitimately escapes the re-bind — the
//     design's own tolerance. Admission-level exclusivity is therefore
//     false by design; the checked property is commit-level.
//   - A pre-rotation certificate over the contested height (a crossing
//     the beacon never folded) stays admissible everywhere; the runtime
//     harvest adopts or orphans it. Admission-level cross-side conflict
//     at the contested height is likewise tolerated by design.
//   - Identities: OLD ∩ FRESH = ∅ (the replaced committee is excluded
//     from its own replacement draw).

module recovery_bridge {
  // The retained committee and its corrupt subset: f+1..2f corrupt — at
  // SHARD_SIZE 4 (f = 1), exactly two.
  const OLD: Set[int]
  const OLD_BYZ: Set[int]
  // The fresh committee: at most f corrupt.
  const FRESH: Set[int]
  const FRESH_BYZ: Set[int]
  const QUORUM: int
  // The epoch the beacon committed the recovery.
  const ROTATED_AT: int
  // The halted chain's frozen tip; TIP + 1 is the contested extension.
  const TIP: int
  // The halted tip's weighted timestamp — the floor every vote extending
  // it is clamped up to (`vote_set.rs` clamps each vote to the parent QC's
  // WT). Stale by construction (the chain stopped windows ago).
  const TIP_WT: int
  const MAX_WINDOW: int
  const MAX_HEIGHT: int

  val BRIDGE: int = ROTATED_AT + 1
  val OLD_HONEST: Set[int] = OLD.exclude(OLD_BYZ)
  val FRESH_HONEST: Set[int] = FRESH.exclude(FRESH_BYZ)

  type Qc = {
    h: int,
    anchor: int,
    qcw: int,
    isFresh: bool,
    content: bool,
    // Ghost: formed at or after the rotation fold.
    postR: bool,
  }

  // The wall-clock window.
  var now: int
  // The beacon committed the recovery (a chain fact; replicas fold it
  // individually).
  var rotated: bool
  // Honest replicas that have folded it, in any order.
  var foldedSet: Set[int]
  // Every certificate ever formed.
  var certified: Set[Qc]

  // `lookup_for_shard_certified` at a replica that folded the recovery.
  pure def resolvesFreshAtFolded(q: Qc): bool =
    (q.anchor < BRIDGE and q.qcw + 1 >= BRIDGE) or q.anchor >= BRIDGE

  pure def admissibleAtFolded(q: Qc): bool =
    if (q.isFresh) resolvesFreshAtFolded(q) else not(resolvesFreshAtFolded(q))

  // At a replica that has not folded: the anchor window resolves as
  // ever; a window past its beacon head (which sits below the rotation)
  // defers — inadmissible until the fold self-heals it.
  pure def admissibleAtUnfolded(q: Qc): bool =
    not(q.isFresh) and q.anchor < BRIDGE

  // The floor a block extending height `h - 1` clamps its votes up to:
  // the parent's QC weighted timestamp, or the halted tip's WT at the
  // contested boundary. Non-decreasing along a chain (`vote_set.rs`
  // monotonicity clamp).
  def floorFor(fresh: bool, h: int): int =
    if (h <= TIP + 1) TIP_WT
    else certified.fold(TIP_WT, (acc, q) =>
      if (q.isFresh == fresh and q.h == h - 1 and q.qcw > acc) q.qcw else acc)

  // The QC weighted timestamp is the mean of the clamped vote stamps
  // (`vote_set.rs`): honest signers stamp the current window `now`,
  // Byzantine signers stamp anything at or above the floor — so the
  // achievable mean runs from all-honest (`now`) down to the
  // honest-only contribution `(nHonest·now + nByz·floor) / quorumSize`.
  // A committee at or below f keeps an honest majority in every quorum,
  // pinning the mean within a window of `now`; the retained committee is
  // beyond f, so its honest-minority quorums cannot. `qcw` is picked from
  // a constant band and guarded into that achievable range (the
  // Apalache subset-pick pattern).
  def qcwAchievable(qcw: int, nHonest: int, nSigners: int, floor: int): bool = and {
    qcw <= now,
    qcw >= floor,
    // qcw >= (nHonest·now + (nSigners − nHonest)·floor) / nSigners,
    // cross-multiplied to stay in integers.
    qcw * nSigners >= nHonest * now + (nSigners - nHonest) * floor,
  }

  // ── Action cores (parameterized, shared by the nondet step and the
  //    scripted witnesses) ──

  action certifyOldAs(signers: Set[int], h: int, anchor: int, qcw: int, content: bool): bool = all {
    signers.subseteq(OLD),
    signers.size() >= QUORUM,
    // Every honest signer enforces its local rules; a quorum always
    // contains one (the corrupt pair is short of it).
    signers.intersect(OLD_HONEST).forall(v => and {
      // A folded member resolves the fresh committee for live work and
      // stops signing — the honest-stop, per replica.
      not(v.in(foldedSet)),
      // Plausible anchor, below the unfolded head (which sits below the
      // rotation).
      anchor <= now,
      anchor < BRIDGE,
      // Height-contiguous extension of a chain it admits.
      h == 0 or certified.exists(q => not(q.isFresh) and q.h == h - 1),
    }),
    h >= 0, h <= MAX_HEIGHT,
    // The halt froze the chain at TIP: the corrupt withheld TIP + 1, which
    // is *why* it halted. So pre-rotation the old committee never certifies
    // past the tip — a post-rotation old cert past TIP is the orphan the
    // lagging cohort extends.
    not(rotated) implies h <= TIP,
    qcwAchievable(qcw, signers.intersect(OLD_HONEST).size(), signers.size(),
      floorFor(false, h)),
    certified' = certified.union(Set({
      h: h, anchor: anchor, qcw: qcw, isFresh: false,
      content: content, postR: rotated,
    })),
    now' = now,
    rotated' = rotated,
    foldedSet' = foldedSet,
  }

  action certifyFreshAs(signers: Set[int], h: int, anchor: int, qcw: int, content: bool): bool = all {
    rotated,
    signers.subseteq(FRESH),
    signers.size() >= QUORUM,
    signers.intersect(FRESH_HONEST).forall(v => and {
      // A fresh member acts only once it has folded the recovery that
      // seats it.
      v.in(foldedSet),
      anchor <= now,
      // The harvest hands it the frozen prefix; it extends past the tip,
      // height-contiguously.
      h == TIP + 1 or certified.exists(q => q.isFresh and q.h == h - 1),
      // The quiesce: no vote on stale-anchored work before the bridge
      // window opens on the voter's clock — and a bridge block is empty.
      (anchor < BRIDGE) implies (now >= BRIDGE and not(content)),
    }),
    h >= 0, h <= MAX_HEIGHT,
    qcwAchievable(qcw, signers.intersect(FRESH_HONEST).size(), signers.size(),
      floorFor(true, h)),
    certified' = certified.union(Set({
      h: h, anchor: anchor, qcw: qcw, isFresh: true,
      content: content, postR: true,
    })),
    now' = now,
    rotated' = rotated,
    foldedSet' = foldedSet,
  }

  // ── Nondet wrappers ──

  action certifyOld = {
    nondet signers = OLD.powerset().oneOf()
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    nondet anchor = 0.to(MAX_WINDOW).oneOf()
    nondet qcw = 0.to(MAX_WINDOW).oneOf()
    nondet content = Set(true, false).oneOf()
    certifyOldAs(signers, h, anchor, qcw, content)
  }

  action certifyFresh = {
    nondet signers = FRESH.powerset().oneOf()
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    nondet anchor = 0.to(MAX_WINDOW).oneOf()
    nondet qcw = 0.to(MAX_WINDOW).oneOf()
    nondet content = Set(true, false).oneOf()
    certifyFreshAs(signers, h, anchor, qcw, content)
  }

  action tick = all {
    now < MAX_WINDOW,
    now' = now + 1,
    rotated' = rotated,
    foldedSet' = foldedSet,
    certified' = certified,
  }

  // The beacon commits the recovery at its epoch.
  action rotate = all {
    not(rotated),
    now == ROTATED_AT,
    rotated' = true,
    now' = now,
    foldedSet' = foldedSet,
    certified' = certified,
  }

  // A replica folds the committed recovery — any honest member, any
  // order, no fairness: a replica may lag to the horizon.
  action foldLands = {
    nondet v = OLD_HONEST.union(FRESH_HONEST).oneOf()
    all {
      rotated,
      not(v.in(foldedSet)),
      foldedSet' = foldedSet.union(Set(v)),
      now' = now,
      rotated' = rotated,
      certified' = certified,
    }
  }

  action init = all {
    now' = 0,
    rotated' = false,
    foldedSet' = Set(),
    certified' = Set(),
  }

  action step = any {
    tick,
    rotate,
    foldLands,
    certifyOld,
    certifyFresh,
  }

  // ── Invariants ──

  val invSuffixVerifiable = certified.forall(q =>
    (not(q.isFresh) and q.qcw + 1 < BRIDGE) implies
      (admissibleAtFolded(q) and admissibleAtUnfolded(q)))

  val invBridgeBindable = certified.forall(q =>
    q.isFresh implies q.qcw + 1 >= BRIDGE)

  val invBridgeEmpty = certified.forall(q =>
    (q.isFresh and q.anchor < BRIDGE) implies not(q.content))

  // A two-chain commit: a certificate at h with a child certificate at
  // h + 1, both admissible at a replica that folded the recovery.
  def committedPairAtFolded(fresh: bool, h: int): bool =
    certified.exists(q => and {
      q.isFresh == fresh, q.h == h, q.postR, admissibleAtFolded(q),
    }) and certified.exists(s => and {
      s.isFresh == fresh, s.h == h + 1, s.postR, admissibleAtFolded(s),
    })

  // Re-certifying the frozen prefix (h <= TIP) is benign — both
  // committees inherit it. The safety property is that no *old-committee*
  // two-chain commit past the tip is admissible at a folded replica: the
  // orphan branch the lagging cohort could extend must never finalize
  // where a folded replica can see it.
  val invNoStaleCommit = 0.to(MAX_HEIGHT).forall(h =>
    (h > TIP) implies not(committedPairAtFolded(false, h)))

  // The sharp fork: an old-side and a fresh-side commit at the same
  // contested height, both admissible at a folded replica.
  val invNoFork = 0.to(MAX_HEIGHT).forall(h =>
    (h > TIP) implies not(committedPairAtFolded(false, h) and committedPairAtFolded(true, h)))

  val invAll = and {
    invSuffixVerifiable,
    invBridgeBindable,
    invBridgeEmpty,
    invNoStaleCommit,
    invNoFork,
  }

  // ── Scripted witness: the healthy handoff ──

  // Build the suffix, halt, rotate, fold, quiesce lapse, empty bridge
  // block, then a content block past the bridge — the recovery's
  // happy path end to end.
  run bridgeHandoffTest =
    init
      // The halted prefix, built at the tip's window (now = 0) — a
      // healthy honest-majority chain up to TIP, stale-stamped.
      .then(certifyOldAs(Set(1, 2, 3), 0, 0, 0, true))
      .then(certifyOldAs(Set(2, 3, 4), 1, 0, 0, true))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(rotate)
      .then(foldLands)
      .then(foldLands)
      .then(foldLands)
      .then(foldLands)
      .then(foldLands)
      .then(tick)
      // The fresh committee, post-quiesce (now = 4 = BRIDGE): an empty
      // bridge block then a content block anchored at the bridge.
      .then(certifyFreshAs(Set(6, 7, 8), 2, 1, 4, false))
      .then(certifyFreshAs(Set(5, 6, 7, 8), 3, 4, 4, true))
      .expect(and {
        invAll,
        // The suffix resolves the old committee everywhere; the bridge
        // block re-binds to the fresh committee at folded replicas.
        certified.forall(q => not(q.isFresh) implies admissibleAtFolded(q)),
        certified.forall(q => q.isFresh implies admissibleAtFolded(q)),
      })
}

// The shipped bridge rules, checked under the beyond-f retained
// committee: the corrupt pair plus any not-yet-folded honest member is a
// quorum, fold order is free, and certificate stamps drag one window.
module recovery_bridge_ok {
  import recovery_bridge(
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1, 2),
    FRESH = Set(5, 6, 7, 8), FRESH_BYZ = Set(5),
    QUORUM = 3, ROTATED_AT = 3, TIP = 1, TIP_WT = 0,
    MAX_WINDOW = 6, MAX_HEIGHT = 3
  ).*
}

// Control: the retained committee with no corrupt members. The old
// cohort can still produce post-rotation from its lagging honest members,
// but with no Byzantine stamp to drag the mean, its QC timestamp equals
// `now >= ROTATED_AT`, so the certified re-bind always resolves the fresh
// committee and the orphan is rejected. `invAll` holds — isolating the
// corrupt timestamp drag as the mechanism, not the un-quiesced old
// committee alone.
module recovery_bridge_honest_old {
  import recovery_bridge(
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(),
    FRESH = Set(5, 6, 7, 8), FRESH_BYZ = Set(5),
    QUORUM = 3, ROTATED_AT = 3, TIP = 1, TIP_WT = 0,
    MAX_WINDOW = 6, MAX_HEIGHT = 3
  ).*
}


// The cross-shard freeze — INV-SEC-8's other half, and the fix for the
// cascade escalation of finding G-1. A halted shard's committed suffix
// made cross-shard commitments (execution certificates other shards
// finalized waves on); the retained beyond-f committee can forge NEW ECs
// extending the halted tip, and a consuming shard resolves the source
// committee for an EC by its anchor window
// (`topology_schedule.lookup(ec.vote_anchor_ts())`,
// execution/src/coordinator.rs:2149) — the PLAIN lookup, no recovery
// bridge — so a stale-anchored orphan EC resolves the old committee and
// its beyond-f signatures verify. Without a fence, the orphan exports a
// forged finalization cross-shard: an f+1 liveness halt becomes an
// INV-EXEC-1 cascade.
//
// The fix is a beacon mandate. At the fold that flags the halt, the
// beacon stamps a freeze: from that fold, folded network-wide, no shard
// accepts a NEW old-committee cross-shard artifact from the halted shard
// above the beacon-attested frontier. The beacon is the only actor that
// is honest-majority (pool ratification), globally observed (every shard
// folds it), and unforgeable by the halted committee — so the cutoff is
// authenticated and synchronized, not a per-consumer guess. Structurally
// this is shard termination: the frozen committee is a shard cut at the
// freeze, in-flight waves abort (abort-dominant, Model C, safe), attested
// finalizations carry, and the fresh committee is the successor.
//
// This module models the consuming side only: an honest consumer shard
// folds the beacon freeze and decides whether to finalize a wave on an EC
// purportedly from the halted source. It does NOT re-model consensus
// (Module 2) or the 2PC wave lifecycle (Models C/D) — only the trust
// surface the freeze governs.
//
// Code anchors:
//   - Cross-shard EC committee resolution: crates/execution/src/coordinator.rs
//     `verify_fetched_finalized_wave` / the live EC path
//     (`topology_schedule.lookup(ec.vote_anchor_ts())`, :2149 and :1315);
//     `ec_has_shard_quorum_power` (crates/execution/src/lookups.rs:51)
//     checks the signer power against that resolved committee.
//   - The freeze is the beacon fold's mandate (to be built): a
//     `frozen`/`freeze_epoch` marker on the halt-recovery record, folded
//     by every shard, gating the EC committee resolution above.
//
// Properties (INV-SEC-8, cross-shard half):
//   invFenceHolds — once an honest consumer has folded the freeze, it
//                      never finalizes on an old-committee EC above the
//                      frontier attested at fold time: the fence stops the
//                      leak at the cutoff. The `no_freeze` twin (the
//                      shipped state) violates it.
//   invResidualBounded — any orphan (above the true halted tip) an
//                      honest consumer finalized was finalized before it
//                      folded the freeze: the residual is exactly the
//                      detection-latency window, nothing after the cut.
//   invObservable — the fence decides only on beacon-observable data (the
//                      folded freeze + the beacon-attested frontier),
//                      never the true halted tip, which no consumer knows.
//
// Modeling assumptions:
//   - The attested frontier can be POISONED: a consumer that finalizes a
//     forged orphan before folding the freeze attests it, advancing the
//     frontier past the true tip. That poisoning is the irreducible
//     residual (pre-freeze forgeries are irreversible); the fence blocks
//     only NEW forgeries beyond what is already attested — the most any
//     after-the-fact mechanism can do, since a beyond-f committee's
//     exports cannot be un-finalized once honest consumers acted on them.
//   - Consumer fold lag is free (the freeze propagates per replica, like
//     the recovery in the bridge module): an unfolded consumer still
//     accepts old ECs, so the residual includes "at a consumer that has
//     not yet folded the freeze" — bounded by freeze propagation.
//   - One honest consumer; the source's beyond-f committee is an oracle
//     that emits any EC (its signatures always verify against the old
//     committee at a stale anchor — the export path has no timestamp
//     defence, unlike the bridge). The fresh committee's ECs resolve the
//     fresh committee and are always safe to accept.
//
// Run:
//   quint test --main=cross_shard_freeze_ok specs/halt_recovery.qnt
//   quint verify --main=cross_shard_freeze_ok --invariant=invAll --max-steps=8 specs/halt_recovery.qnt
//     (the fence holds: no new forgery crosses the cut, the residual is
//      bounded to the pre-fold poisoning, and the fresh committee stays live)
//   quint verify --main=cross_shard_no_freeze --invariant=invFenceHolds --max-steps=8 specs/halt_recovery.qnt
//     (the shipped state, no fence; expect a counterexample — an orphan is
//      finalized after the halt is detected and the consumer folded)
//   quint verify --main=cross_shard_no_freeze --invariant=invResidualBounded --max-steps=8 specs/halt_recovery.qnt
//     (same twin; the residual is unbounded without the fence)

module cross_shard_freeze {
  // The true halted tip H_t (unknown to any consumer). An old-committee EC
  // above it is an orphan forgery.
  const HALT_TIP: int
  // The beacon-attested frontier at the start — the highest legit
  // S-height an honest consumer had finalized and attested before the
  // window (<= HALT_TIP).
  const ATTESTED_0: int
  // The epoch the beacon folds the freeze (halt detection).
  const FREEZE_EPOCH: int
  const MAX_HEIGHT: int
  const MAX_TIME: int
  // Broken twin: no beacon freeze (the shipped state). The consumer has no
  // authenticated cutoff and keeps resolving the old committee for any
  // stale-anchored EC. True is the fix.
  const FREEZE_FENCE: bool

  var now: int
  // The beacon has folded the freeze (a committed fact).
  var beaconFrozen: bool
  // The honest consumer has folded the freeze.
  var consumerFolded: bool
  // The beacon-attested S frontier from old-committee ECs: the max height
  // an honest consumer has finalized on and attested (forgeries included —
  // the poisoning).
  var attestedFrontier: int
  // Snapshot of `attestedFrontier` when the consumer folded the freeze —
  // the fence caps further old-committee finalization at this height.
  var frontierAtFold: int
  // The fence was breached: a folded consumer finalized an old-committee EC
  // above the fold-time frontier — a NEW cross-shard forgery past the cut.
  var breached: bool
  // The highest orphan (> HALT_TIP) an honest consumer ever finalized, and
  // whether any such finalization happened after the consumer folded.
  var orphanFinalizedPostFold: bool
  // The fresh committee has advanced the shard post-freeze (liveness).
  var freshAdvanced: bool

  // Whether the honest consumer finalizes a wave on an old-committee EC at
  // `srcHeight`. It resolves the old committee at the EC's stale anchor
  // (`lookup(anchor)`), whose signatures verify. The fence — folded freeze
  // + the beacon-attested frontier — is the only gate; without it, any old
  // EC is accepted.
  def acceptsOldEC(srcHeight: int): bool =
    not(FREEZE_FENCE and consumerFolded and srcHeight > attestedFrontier)

  // An honest consumer finalizes a wave on an old-committee EC at
  // `srcHeight`. A finalization at or below the true tip is legit and
  // advances the attested frontier; an orphan (above the tip) accepted
  // before the fence bites poisons it — the residual.
  action consumeOldEC(srcHeight: int): bool = all {
    srcHeight >= 0,
    srcHeight <= MAX_HEIGHT,
    acceptsOldEC(srcHeight),
    // The fence breaks if a folded consumer finalizes above the fold-time
    // frontier — a new forgery past the cut.
    breached' = (breached or (consumerFolded and srcHeight > frontierAtFold)),
    orphanFinalizedPostFold' =
      (orphanFinalizedPostFold or (consumerFolded and srcHeight > HALT_TIP)),
    attestedFrontier' = if (srcHeight > attestedFrontier) srcHeight else attestedFrontier,
    now' = now,
    beaconFrozen' = beaconFrozen,
    consumerFolded' = consumerFolded,
    frontierAtFold' = frontierAtFold,
    freshAdvanced' = freshAdvanced,
  }

  // The fresh committee's EC — resolves the fresh committee, always safe;
  // this is the recovery's liveness continuing past the freeze.
  action consumeFreshEC: bool = all {
    beaconFrozen,
    freshAdvanced' = true,
    now' = now, beaconFrozen' = beaconFrozen, consumerFolded' = consumerFolded,
    attestedFrontier' = attestedFrontier, frontierAtFold' = frontierAtFold,
    breached' = breached, orphanFinalizedPostFold' = orphanFinalizedPostFold,
  }

  action tick: bool = all {
    now < MAX_TIME,
    now' = now + 1,
    // The beacon folds the freeze at its detection epoch.
    beaconFrozen' = (beaconFrozen or (now + 1 >= FREEZE_EPOCH)),
    consumerFolded' = consumerFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    orphanFinalizedPostFold' = orphanFinalizedPostFold,
    freshAdvanced' = freshAdvanced,
  }

  // The consumer folds the committed freeze — any time after the beacon
  // committed it, no fairness (it may lag).
  action consumerFold: bool = all {
    beaconFrozen,
    not(consumerFolded),
    consumerFolded' = true,
    frontierAtFold' = attestedFrontier,
    now' = now, beaconFrozen' = beaconFrozen, attestedFrontier' = attestedFrontier,
    breached' = breached, orphanFinalizedPostFold' = orphanFinalizedPostFold,
    freshAdvanced' = freshAdvanced,
  }

  action init = all {
    now' = 0,
    beaconFrozen' = false,
    consumerFolded' = false,
    attestedFrontier' = ATTESTED_0,
    frontierAtFold' = 0,
    breached' = false,
    orphanFinalizedPostFold' = false,
    freshAdvanced' = false,
  }

  action step = any {
    tick,
    consumerFold,
    consumeFreshEC,
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    consumeOldEC(h),
  }

  // ── Invariants ──

  // The fence holds: no folded consumer finalizes an old-committee EC above
  // the frontier attested when it folded.
  val invFenceHolds = not(breached)

  // The residual is bounded to the pre-fold window: a folded consumer can
  // only finalize an orphan (above the true tip) if the frontier was
  // already poisoned past the tip before it folded — a re-acceptance of an
  // already-attested forgery, never a new one. No fresh leakage crosses
  // the cut.
  val invResidualBounded =
    orphanFinalizedPostFold implies (frontierAtFold > HALT_TIP)

  // The fence reads only observable state — the folded freeze and the
  // attested frontier — never the true halted tip. With the fence on, a
  // folded consumer's finalizations never exceed the attested frontier.
  val invObservable =
    (FREEZE_FENCE and consumerFolded) implies (attestedFrontier == frontierAtFold)

  val invAll = and {
    invFenceHolds,
    invResidualBounded,
    invObservable,
  }

  // ── Scripted witnesses (honest paths — valid under both instances) ──

  // Legit cross-shard history is attested up to the tip, the halt is
  // detected and the beacon freezes, the consumer folds it, and past the
  // fold the fresh committee advances the shard while the fence stays
  // intact and no new orphan is finalized — the recovery stays live and
  // the leak is closed. (A folded consumer attempting an above-frontier
  // old EC is disabled under the fence, which is exactly the fence
  // working; the twin's counterexample exhibits that firing.)
  run freezeClosesLeakTest =
    init
      .then(consumeOldEC(2))
      .expect(attestedFrontier == 2 and not(breached))
      .then(tick)
      .then(tick)
      .then(tick)
      .expect(beaconFrozen)
      .then(consumerFold)
      .expect(frontierAtFold == 2)
      .then(consumeFreshEC)
      .expect(freshAdvanced and not(breached) and not(orphanFinalizedPostFold))

  // The residual: a pre-fold orphan (above the true tip) poisons the
  // attested frontier — irreversible, the detection-latency window — but
  // once the freeze is folded no new orphan is finalized and the fence is
  // never breached.
  run residualPoisonTest =
    init
      .then(consumeOldEC(3))
      .expect(attestedFrontier == 3 and not(breached) and not(orphanFinalizedPostFold))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(consumerFold)
      .expect(frontierAtFold == 3 and not(breached))
}

// The fix: the beacon freeze fence is on.
module cross_shard_freeze_ok {
  import cross_shard_freeze(
    HALT_TIP = 2, ATTESTED_0 = 1, FREEZE_EPOCH = 3,
    MAX_HEIGHT = 4, MAX_TIME = 5, FREEZE_FENCE = true
  ).*
}

// Broken twin: the shipped state — no beacon freeze. The consumer resolves
// the old committee for any stale-anchored EC forever, so orphans keep
// being finalized after the halt is detected and the consumer folded —
// invFenceHolds fails.
module cross_shard_no_freeze {
  import cross_shard_freeze(
    HALT_TIP = 2, ATTESTED_0 = 1, FREEZE_EPOCH = 3,
    MAX_HEIGHT = 4, MAX_TIME = 5, FREEZE_FENCE = false
  ).*
}
