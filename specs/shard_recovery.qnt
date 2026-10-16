// Model G (register: specs/README.md) — halt detection and the full
// committee re-draw. The `halt_detection` module checks INV-SEC-9 (halt
// detection and recovery) and the recovery clause of INV-SEC-2 (rotation
// never touches a recovering shard); INV-SEC-8, the recovery bridge, is
// the register row's other half. The `fork_detection` module checks the
// active-fork reach: commit-proof consumption (INV-SEC-11), fork-proof
// soundness (INV-SEC-12), and the commit-level fork fence (INV-SEC-13) for
// a retained f+1..2f committee running two heads.
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
//     `recover_committee` — all-or-nothing full draw from the free
//     pool (a short pool defers and the shard retries each fold), fresh
//     committee seated whole, replaced committee pooled and folded into
//     the `ShardRecovery` retention (a stalled recovery's own fresh
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
//   quint typecheck specs/shard_recovery.qnt
//   quint test --main=halt_detection_ok specs/shard_recovery.qnt
//   quint verify --main=halt_detection_ok --invariant=invAll --max-steps=6 specs/shard_recovery.qnt
//     (holds; depth 6 covers the full double-recovery lifecycle at
//      THRESHOLD = 1 — seed, halt, re-draw, stall, second re-draw, clear)
//   quint verify --main=halt_refresh_on_refold --invariant=invDetectorSound --max-steps=6 specs/shard_recovery.qnt
//     (the twin refreshes on a consumed crossing; expect a counterexample)
//   quint verify --main=halt_refresh_on_refold --invariant=invRetention --max-steps=7 specs/shard_recovery.qnt
//     (the bogus refresh also releases a pending recovery's retention;
//      expect a counterexample)
//   quint verify --main=halt_wallclock_watermark --invariant=invNoFalseFlag --max-steps=6 specs/shard_recovery.qnt
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
  // (`apply_epoch`: `halted_shards` then `recover_committees`).
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
// carries state its core siblings read: a stated yes, which a sibling
// accepts on. The retained beyond-f committee can certify NEW headers
// extending the halted tip, and a sibling proves a claim on a header by
// the committee its anchor resolves — the PLAIN lookup, no recovery
// bridge — so a stale-anchored orphan header resolves the old committee
// and its beyond-f signatures verify. Without the fence, the orphan
// exports forged state cross-shard: an f+1 liveness halt becomes an
// INV-EXEC-1 cascade.
//
// The fix is a beacon mandate. At the fold that flags the halt, the
// beacon stamps a recovery: from that fold, folded network-wide, no shard
// admits a claim on an old-committee header of the halted shard anchored
// below the recovery's bridge above the beacon-attested frontier. The
// beacon is the only actor that is honest-majority (pool ratification),
// globally observed (every shard folds it), and unforgeable by the halted
// committee — so the cutoff is authenticated and synchronized, not a
// per-sibling guess. Structurally this is shard termination: the frozen
// committee is a shard cut at the freeze, and the fresh committee is the
// successor.
//
// The recovered shard's crossing block, its first anchored at or past the
// bridge, discards every tick its parent's rows hold, and with them every
// tick above the halted tip. A core member the discard releases that ran
// is aborted at once, stated or not: the recovered shard ends its row
// with a recorded outcome. A sibling that reads that exit and has not
// accepted refuses; one that accepted on the yes the discard dropped
// keeps its accept, the tear of a recovery (residual 1), and ends its
// accepted row on the exit.
//
// What bounds the tear is the reading rule, not the fence. A sibling's
// row counts no reading marked below the bridge of the newest recovery
// its view records, at or below the frontier and above it alike, so once
// it has folded the recovery no yes the replaced committee's chain
// stated decides anything there; it accepts only on what the fresh chain
// says past the bridge. The fence keeps a folded sibling from proving new
// orphan state at all, which the crossings it admits on the same claims
// rely on.
//
// This module models the sibling's side only: an honest core sibling
// folds the beacon record, admits claims on headers purportedly from the
// halted shard, accepts on the yeses they read, and meets the recovered
// shard's exit. Admitting and deciding are two steps: the fence refuses
// a claim when it is admitted, and the reading rule refuses a reading
// when the row decides. One core member per source height: the header at
// height `h` states a yes on member `h`. It does NOT re-model consensus
// (Module 2) or the reading lifecycle (Models C/D) — only the trust
// surface the freeze and the bridge govern.
//
// Code anchors:
//   - Claim proof: a claim is proven on the source header its anchor
//     names, resolved by the anchor's clock; `refused_away_from_the_parent`
//     (crates/shard/src/admission.rs) and `place_pushed_claim`
//     (crates/execution/src/coordinator.rs) refuse a claim anchored in a
//     recovery's band, and `ProvenAnchors::forget_orphaned`
//     (crates/types/src/shard/proven_anchors.rs) drops a proven anchor
//     there.
//   - The freeze is the `attested_frontier` on the beacon's `ShardRecovery`
//     record (crates/types/src/beacon/state.rs) — the shard's boundary
//     height as folded at detection, recorded by `recover_committee`
//     (crates/beacon/src/state/committee.rs).
//     `TopologySchedule::recovery_orphaned`
//     (crates/types/src/topology/schedule.rs) is the band: anchored below
//     a bridge, above its frontier.
//   - The reading rule: `counts` (crates/types/src/shard/verdict.rs) — an
//     entry marked below the bridge of the sibling's newest recovery the
//     published window records is no entry; `decide` accepts a stated
//     row on a counted yes, refuses it on a counted exit, and ends an
//     accepted row once the sibling has accepted or left.
//   - The discard and the abort: `member_lines` (crates/engine/src/
//     tick_select.rs) names a `Recovery` discard for every tick row the
//     parent holds on the crossing block (`TopologySchedule::crossing_block`),
//     the fold releases each member of it (`release`, crates/storage/src/
//     shard/members.rs), and `Exit::of` aborts a released shared member
//     that ran at once.
//
// Properties (INV-SEC-8, cross-shard half; INV-EXEC-1 residual 1):
//   invFenceHolds — once an honest sibling has folded the recovery, it
//                      never admits a claim on an old-committee header
//                      above the frontier attested at fold time: the fence
//                      stops the leak at the cutoff. The `no_freeze` twin
//                      (the unfenced counterfactual) violates it.
//   invResidualBounded — every member the two shards end apart is one the
//                      sibling accepted before it folded the recovery: the
//                      tear is decided by arrival order relative to the
//                      fold, at or below the frontier and above it alike,
//                      and nothing read before the bridge decides anything
//                      after. Bounded by the standing-row cap toward one
//                      shard, which this model does not count. The
//                      `pre_bridge_reading` twin counts a reading below the
//                      bridge and violates it.
//   invOneOutcome — the sibling ends a member one way: never both accepted
//                      and refused.
//   invEndsOnExit — an accepted row the sibling ended is one the
//                      recovered shard ended too, by its abort or its
//                      accept.
//   invObservable — the fence decides only on beacon-observable data (the
//                      folded record + the beacon-attested frontier),
//                      never the true halted tip, which no sibling knows.
//
// Modeling assumptions:
//   - The attested frontier can be POISONED: a sibling that accepts on a
//     forged orphan before folding the recovery attests it, advancing the
//     frontier past the true tip. That poisoning is the irreducible
//     residual (pre-freeze forgeries are irreversible); the fence blocks
//     only NEW forgeries beyond what is already attested — the most any
//     after-the-fact mechanism can do, since a beyond-f committee's
//     exports cannot be un-accepted once honest siblings acted on them.
//     (In the implementation the frontier is a pure fold of committed
//     boundary crossings: a crossing the beyond-f committee lands before
//     detection advances it, playing this poisoning role; the model folds
//     that channel into pre-fold sibling attestation, and the stamped
//     frontier does not move once the sibling has folded it.)
//   - Sibling fold lag is free (the recovery propagates per replica, like
//     the recovery in the bridge module): an unfolded sibling still admits
//     and counts old-committee readings, so the residual is "accepted at a
//     sibling that had not yet folded the recovery" — bounded by its
//     propagation. Folding stands for the window that records the
//     recovery being published at the sibling's anchor.
//   - A reading's age rule (a yes no older than the epoch before the
//     anchor's) only narrows what counts; it is left out.
//   - Which ticks the crossing block discards is the environment's: any
//     set holding every height above the halted tip. A member the
//     crossing keeps is still stated and accepts on the sibling's accept
//     as in Model C.
//   - One honest sibling; the source's beyond-f committee is an oracle
//     that certifies any header (its signatures always verify against the
//     old committee at a stale anchor — the claim path has no timestamp
//     defence, unlike the bridge). The fresh committee's headers resolve
//     the fresh committee and are always safe to read.
//
// Run:
//   quint test --main=cross_shard_freeze_ok specs/shard_recovery.qnt
//   quint run --main=cross_shard_freeze_ok --invariant=invAll specs/shard_recovery.qnt
//   quint verify --main=cross_shard_freeze_ok --invariant=invAll --max-steps=8 specs/shard_recovery.qnt
//     (the fence holds: no new forgery crosses the cut, every tear is an
//      accept made before the fold, and the fresh committee stays live)
//   quint verify --main=cross_shard_no_freeze --invariant=invFenceHolds --max-steps=8 specs/shard_recovery.qnt
//     (the unfenced counterfactual; expect a counterexample — an orphan
//      claim is admitted after the halt is detected and the sibling folded)
//   quint test --main=cross_shard_pre_bridge_reading --match=postFoldTear specs/shard_recovery.qnt
//     (scripted witness: a yes read before the fold is accepted on after
//      it, and the crossing aborts the member)
//   quint verify --main=cross_shard_pre_bridge_reading --invariant=invResidualBounded --max-steps=8 specs/shard_recovery.qnt
//     (same tear, found by search)

module cross_shard_freeze {
  // The true halted tip H_t (unknown to any sibling). An old-committee
  // header above it is an orphan forgery.
  const HALT_TIP: int
  // The beacon-attested frontier at the start — the highest legit
  // height an honest sibling had acted on and attested before the window
  // (<= HALT_TIP).
  const ATTESTED_0: int
  // The epoch the beacon folds the recovery (halt detection).
  const FREEZE_EPOCH: int
  const MAX_HEIGHT: int
  const MAX_TIME: int
  // Broken twin: no beacon freeze (the unfenced counterfactual). The
  // sibling has no authenticated cutoff and keeps resolving the old
  // committee for any stale-anchored header. True is the shipped fence.
  const FREEZE_FENCE: bool
  // Broken twin: a reading marked below the bridge still counts once the
  // recovery is folded. True is the shipped reading rule.
  const BRIDGE_RULE: bool

  var now: int
  // The beacon has folded the recovery (a committed fact).
  var beaconFrozen: bool
  // The honest sibling has folded the recovery.
  var siblingFolded: bool
  // The beacon-attested frontier from old-committee headers: the max
  // height an honest sibling has accepted on and attested before it
  // folded (forgeries included — the poisoning).
  var attestedFrontier: int
  // Snapshot of `attestedFrontier` when the sibling folded the recovery —
  // the fence caps further old-committee claims at this height.
  var frontierAtFold: int
  // The fence was breached: a folded sibling admitted a claim on an
  // old-committee header above the fold-time frontier — a NEW cross-shard
  // forgery past the cut.
  var breached: bool
  // The heights whose old-committee header the sibling read a yes off.
  var read: Set[int]
  // The members the sibling accepted, and the subset it accepted before
  // folding the recovery.
  var accepted: Set[int]
  var acceptedPreFold: Set[int]
  // The members the sibling refused on the recovered shard's exit.
  var refused: Set[int]
  // The accepted rows the sibling ended on the recovered shard's exit or
  // accept.
  var ended: Set[int]
  // The recovered shard has committed its crossing block, and the ticks
  // that block discarded, each member of which it aborted there.
  var crossed: bool
  var discarded: Set[int]
  // The members the recovered shard accepted past the bridge, on the
  // sibling's accept.
  var sourceAccepted: Set[int]
  // The fresh committee has advanced the shard post-freeze (liveness).
  var freshAdvanced: bool

  // Whether the sibling admits a claim on an old-committee header at
  // `srcHeight`. It resolves the old committee at the header's stale
  // anchor, whose signatures verify. The fence — folded record + the
  // beacon-attested frontier — is the only gate; without it, any old
  // header proves.
  def admitsOldHeader(srcHeight: int): bool =
    not(FREEZE_FENCE and siblingFolded and srcHeight > attestedFrontier)

  // Whether a reading off an old-committee header counts: every one is
  // marked below the bridge, which the sibling's view records once it has
  // folded the recovery.
  val oldReadingCounts: bool = not(BRIDGE_RULE and siblingFolded)

  // The members the two shards end apart: the sibling accepted, and the
  // recovered shard aborted at its crossing.
  val torn: Set[int] = accepted.intersect(discarded)

  // The sibling admits a claim on an old-committee header at `srcHeight`
  // and records the yes it reads there.
  action readOld(srcHeight: int): bool = all {
    srcHeight >= 1,
    srcHeight <= MAX_HEIGHT,
    admitsOldHeader(srcHeight),
    not(srcHeight.in(read)),
    breached' = (breached or (siblingFolded and srcHeight > frontierAtFold)),
    read' = read.union(Set(srcHeight)),
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    accepted' = accepted,
    acceptedPreFold' = acceptedPreFold,
    refused' = refused,
    ended' = ended,
    crossed' = crossed,
    discarded' = discarded,
    sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  // The sibling's row accepts on a yes it read off an old-committee
  // header, where that reading counts. An accept before the fold attests
  // the height — at or below the true tip legit history, above it the
  // poisoning.
  action acceptOld(srcHeight: int): bool = all {
    srcHeight.in(read),
    oldReadingCounts,
    not(srcHeight.in(accepted.union(refused))),
    accepted' = accepted.union(Set(srcHeight)),
    acceptedPreFold' =
      if (siblingFolded) acceptedPreFold else acceptedPreFold.union(Set(srcHeight)),
    attestedFrontier' =
      if (not(siblingFolded) and srcHeight > attestedFrontier) srcHeight
      else attestedFrontier,
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    refused' = refused,
    ended' = ended,
    crossed' = crossed,
    discarded' = discarded,
    sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  // The recovered shard commits its crossing block, discarding `lost`:
  // every tick above the halted tip, and whichever of the rest no kept
  // block settled. Every member it releases is aborted there.
  action crossBridge(lost: Set[int]): bool = all {
    beaconFrozen,
    not(crossed),
    1.to(MAX_HEIGHT).filter(h => h > HALT_TIP).subseteq(lost),
    crossed' = true,
    discarded' = lost,
    freshAdvanced' = true,
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    accepted' = accepted,
    acceptedPreFold' = acceptedPreFold,
    refused' = refused,
    ended' = ended,
    sourceAccepted' = sourceAccepted,
  }

  // A folded sibling reads the fresh chain past the bridge on a member it
  // shares. An aborted member reads `Left`: a stated row refuses and an
  // accepted one ends. A kept member still reads its yes, which counts
  // there.
  action readFresh(srcHeight: int): bool = all {
    crossed,
    siblingFolded,
    srcHeight >= 1,
    srcHeight <= MAX_HEIGHT,
    if (srcHeight.in(discarded)) all {
      not(srcHeight.in(refused.union(ended))),
      if (srcHeight.in(accepted)) all {
        ended' = ended.union(Set(srcHeight)),
        refused' = refused,
      } else all {
        refused' = refused.union(Set(srcHeight)),
        ended' = ended,
      },
      accepted' = accepted,
      acceptedPreFold' = acceptedPreFold,
    } else all {
      not(srcHeight.in(accepted.union(refused))),
      accepted' = accepted.union(Set(srcHeight)),
      acceptedPreFold' = acceptedPreFold,
      refused' = refused,
      ended' = ended,
    },
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    crossed' = crossed,
    discarded' = discarded,
    sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  // The recovered shard reads the sibling's accept of a member its
  // crossing kept and accepts; the sibling then reads that accept and
  // ends its row.
  action sourceAccept(srcHeight: int): bool = all {
    crossed,
    srcHeight.in(accepted),
    not(srcHeight.in(discarded)),
    not(srcHeight.in(sourceAccepted)),
    sourceAccepted' = sourceAccepted.union(Set(srcHeight)),
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    accepted' = accepted,
    acceptedPreFold' = acceptedPreFold,
    refused' = refused,
    ended' = ended,
    crossed' = crossed,
    discarded' = discarded,
    freshAdvanced' = freshAdvanced,
  }

  action endOnAccept(srcHeight: int): bool = all {
    siblingFolded,
    srcHeight.in(sourceAccepted),
    not(srcHeight.in(ended)),
    ended' = ended.union(Set(srcHeight)),
    now' = now,
    beaconFrozen' = beaconFrozen,
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    accepted' = accepted,
    acceptedPreFold' = acceptedPreFold,
    refused' = refused,
    crossed' = crossed,
    discarded' = discarded,
    sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  action tick: bool = all {
    now < MAX_TIME,
    now' = now + 1,
    // The beacon folds the recovery at its detection epoch.
    beaconFrozen' = (beaconFrozen or (now + 1 >= FREEZE_EPOCH)),
    siblingFolded' = siblingFolded,
    attestedFrontier' = attestedFrontier,
    frontierAtFold' = frontierAtFold,
    breached' = breached,
    read' = read,
    accepted' = accepted,
    acceptedPreFold' = acceptedPreFold,
    refused' = refused,
    ended' = ended,
    crossed' = crossed,
    discarded' = discarded,
    sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  // The sibling folds the committed recovery — any time after the beacon
  // committed it, no fairness (it may lag).
  action siblingFold: bool = all {
    beaconFrozen,
    not(siblingFolded),
    siblingFolded' = true,
    frontierAtFold' = attestedFrontier,
    now' = now, beaconFrozen' = beaconFrozen, attestedFrontier' = attestedFrontier,
    breached' = breached, read' = read, accepted' = accepted,
    acceptedPreFold' = acceptedPreFold, refused' = refused, ended' = ended,
    crossed' = crossed, discarded' = discarded, sourceAccepted' = sourceAccepted,
    freshAdvanced' = freshAdvanced,
  }

  action init = all {
    now' = 0,
    beaconFrozen' = false,
    siblingFolded' = false,
    attestedFrontier' = ATTESTED_0,
    frontierAtFold' = 0,
    breached' = false,
    read' = Set(),
    accepted' = Set(),
    acceptedPreFold' = Set(),
    refused' = Set(),
    ended' = Set(),
    crossed' = false,
    discarded' = Set(),
    sourceAccepted' = Set(),
    freshAdvanced' = false,
  }

  action step = any {
    tick,
    siblingFold,
    nondet h = 1.to(MAX_HEIGHT).oneOf()
    any {
      readOld(h),
      acceptOld(h),
      readFresh(h),
      sourceAccept(h),
      endOnAccept(h),
    },
    nondet lost = 1.to(MAX_HEIGHT).powerset().oneOf()
    crossBridge(lost),
  }

  // ── Invariants ──

  // The fence holds: no folded sibling admits a claim on an old-committee
  // header above the frontier attested when it folded.
  val invFenceHolds = not(breached)

  // Every member the two shards end apart is one the sibling accepted
  // before it folded the recovery. The recovered shard refuses nothing
  // the sibling refused on, so a tear is an accept beside an abort.
  val invResidualBounded =
    torn.subseteq(acceptedPreFold) and refused.intersect(sourceAccepted) == Set()

  // The sibling ends a member one way: never both accepted and refused.
  val invOneOutcome = accepted.intersect(refused) == Set()

  // An accepted row the sibling ended is one the recovered shard ended:
  // aborted at its crossing, or accepted past it.
  val invEndsOnExit =
    ended.subseteq(accepted.intersect(discarded.union(sourceAccepted)))

  // The fence reads only observable state — the folded record and the
  // attested frontier — never the true halted tip. With the fence on, a
  // folded sibling's frontier is the one it folded.
  val invObservable =
    (FREEZE_FENCE and siblingFolded) implies (attestedFrontier == frontierAtFold)

  val invAll = and {
    invFenceHolds,
    invResidualBounded,
    invOneOutcome,
    invEndsOnExit,
    invObservable,
  }

  // ── Scripted witnesses (honest paths — valid under every instance) ──

  // Legit history is read and accepted up to the tip, the halt is
  // detected and the beacon stamps the recovery, the sibling folds it,
  // the crossing keeps that member and aborts the tick above it, and the
  // sibling refuses the aborted member on the exit and ends its accept on
  // the recovered shard's, while the fence stays intact. (A folded
  // sibling admitting an above-frontier old claim is disabled under the
  // fence, which is exactly the fence working; the twin's counterexample
  // exhibits that firing.)
  run freezeClosesLeakTest =
    init
      .then(readOld(2))
      .then(acceptOld(2))
      .expect(attestedFrontier == 2 and not(breached))
      .then(tick)
      .then(tick)
      .then(tick)
      .expect(beaconFrozen)
      .then(siblingFold)
      .expect(frontierAtFold == 2)
      .then(crossBridge(Set(3, 4)))
      .then(readFresh(3))
      .then(sourceAccept(2))
      .then(endOnAccept(2))
      .expect(freshAdvanced and not(breached) and torn == Set()
        and refused == Set(3) and ended == Set(2))

  // The tear: the sibling accepts on a yes read before it folds, and the
  // crossing aborts that member. Its accepted row ends on the exit, and
  // nothing stands.
  run tearAcceptedBeforeFoldTest =
    init
      .then(readOld(2))
      .then(acceptOld(2))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(siblingFold)
      .then(crossBridge(Set(2, 3, 4)))
      .expect(torn == Set(2) and 2.in(acceptedPreFold) and not(breached))
      .then(readFresh(2))
      .expect(ended == Set(2) and invAll)

  // A yes read before the fold and not yet accepted on decides nothing
  // after it, at or below the frontier: the row waits for the fresh
  // chain, which says the abort.
  run readBeforeFoldDecidesNothingTest =
    init
      .then(readOld(1))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(siblingFold)
      .then(crossBridge(Set(1, 3, 4)))
      .then(readFresh(1))
      .expect(refused == Set(1) and torn == Set() and invAll)

  // A pre-fold orphan (above the true tip) poisons the attested frontier —
  // irreversible, the detection-latency window — but once the recovery is
  // folded no new orphan is admitted and the fence is never breached.
  run residualPoisonTest =
    init
      .then(readOld(3))
      .then(acceptOld(3))
      .expect(attestedFrontier == 3 and not(breached))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(siblingFold)
      .expect(frontierAtFold == 3 and not(breached))
      .then(crossBridge(Set(3, 4)))
      .expect(torn == Set(3) and 3.in(acceptedPreFold))
}

// The shipped configuration: the freeze fence and the reading rule are on.
module cross_shard_freeze_ok {
  import cross_shard_freeze(
    HALT_TIP = 2, ATTESTED_0 = 1, FREEZE_EPOCH = 3,
    MAX_HEIGHT = 4, MAX_TIME = 5, FREEZE_FENCE = true, BRIDGE_RULE = true
  ).*
}

// Broken twin: the unfenced counterfactual — no beacon freeze. The
// sibling resolves the old committee for any stale-anchored header
// forever, so orphan claims keep proving after the halt is detected and
// the sibling folded — invFenceHolds fails. The reading rule still keeps
// such a reading from deciding anything.
module cross_shard_no_freeze {
  import cross_shard_freeze(
    HALT_TIP = 2, ATTESTED_0 = 1, FREEZE_EPOCH = 3,
    MAX_HEIGHT = 4, MAX_TIME = 5, FREEZE_FENCE = false, BRIDGE_RULE = true
  ).*
}

// Broken twin: a reading marked below the bridge counts after the fold.
// A yes the sibling read off the replaced committee's chain before it
// folded decides an accept after it, which the crossing aborts —
// invResidualBounded fails on a tear no arrival order before the fold
// explains.
module cross_shard_pre_bridge_reading {
  import cross_shard_freeze(
    HALT_TIP = 2, ATTESTED_0 = 1, FREEZE_EPOCH = 3,
    MAX_HEIGHT = 4, MAX_TIME = 5, FREEZE_FENCE = true, BRIDGE_RULE = false
  ).*

  // The scripted twin witness: a yes read before the fold is accepted on
  // after it, and the crossing aborts the member.
  run postFoldTear =
    init
      .then(readOld(1))
      .then(tick)
      .then(tick)
      .then(tick)
      .then(siblingFold)
      .then(acceptOld(1))
      .then(crossBridge(Set(1, 3, 4)))
      .expect(not(invResidualBounded))
}

// Active-fork detection and the commit-proof consumption gate — the
// loud-attacker reach of the fork work, and the fix for the certified-
// sibling vector docs/05 §1.4 names. A retained f+1..2f committee runs two
// internally consistent heads and serves each to a different consumer
// audience; nothing in the halt detector (which watches the quiet
// watermark) flags it, and pre-spine consumption trusted a bare QC as if
// it were canonical, so two victims could settle against two mere
// certifications and never compare them.
//
// The spine closes it on the consuming side. Cross-shard consumption
// requires a COMMIT PROOF of the source block — its committing
// round-contiguous two-chain, not a bare QC — so a merely-certified
// sibling is unconsumable and the attacker must actually double-commit to
// reach two audiences. Two committed chains at one height cannot exist
// below f+1 corrupt seats (INV-SHARD-1 at the commit level: the two
// committing quorums intersect in at least 2·QUORUM − SHARD_SIZE seats, and
// every shared seat co-signed conflicting commits — a lock violation only a
// corrupt seat commits). The two victims' commit proofs then ARE the
// evidence: assembled as a `ConflictingCommits`, gossiped network-wide, and
// folded by the beacon into a fork-caused `ShardRecovery` whose fence is
// commit-level — no victim consumes either branch's provisions above the
// attested frontier once it folds the record.
//
// This module models the producer (the retained committee emitting commit
// proofs and bare certs for two branches), the assembly (two committed
// heads at one height), the arming (the beacon stamps the recovery at the
// attested frontier), and the consumer fence — the trust surface the
// commit-proof gate and the fork fence govern. It does NOT re-model shard
// consensus (Module B derives INV-SHARD-1); the lock discipline appears
// only as the per-signer guard that makes a conflicting commit pair
// reachable exactly when the committee is beyond f.
//
// Code anchors:
//   - Evidence: crates/types/src/shard/evidence.rs `ShardForkProof`
//     (`ConflictingCommits`) over `CommitProof` (a round-contiguous
//     two-chain plus the parent-hash ancestry link); `verify_resolved`
//     resolves each QC's committee by WT and BLS-checks it.
//   - Commit-proof consumption: the remote-header `proven` set and the
//     `RemoteHeaderCommitted` continuation (crates/remote-headers/src)
//     gate provision and EC consumption on the source's committing
//     two-chain; a bare QC alone defers.
//   - Assembly: crates/remote-headers/src/coordinator.rs `check_fork_at` /
//     `try_assemble_fork` build a `ConflictingCommits` from two distinct
//     commit-proven two-chains at one height.
//   - Fence: crates/node/src/state/participation/shard.rs `on_fork_proven`
//     engages the provisions/remote-header/mempool fences and re-gossips.
//   - Funnel: crates/beacon/src/coordinator.rs `fork_proofs_admissible`
//     re-verifies each proof against the topology schedule at proposal
//     admission; crates/beacon/src/state/epoch.rs `ingest_fork_proofs`
//     folds committed proofs into a `RecoveryCause::Fork` record before
//     `record_boundaries`. The fence cutoff is the record's
//     `attested_frontier` (crates/types/src/beacon/state.rs) = the last
//     folded boundary.
//
// Properties:
//   invHonestNoProof — a `ConflictingCommits` assembles only from a
//                      beyond-f committee: two committed heads at one height
//                      force at least 2·QUORUM − SHARD_SIZE corrupt seats,
//                      so an honest-majority committee never generates a
//                      fork proof (INV-SEC-12; INV-SHARD-1 at the commit
//                      level). The `fork_detection_honest` control has ≤ f
//                      corrupt and never arms a recovery.
//   invNoCertifiedSibling — no victim consumes a merely-certified sibling
//                      (a bare QC with no committing two-chain): the
//                      certified-sibling vector is empty under commit-proof
//                      consumption (INV-SEC-11). The `fork_detection_bare_qc`
//                      twin consumes against a bare QC and violates it.
//   invForkFenceHolds — once a victim has folded the recovery it consumes
//                      neither branch's provisions above the attested
//                      frontier: the fork fence is commit-level and never
//                      retreats (INV-SEC-13, extending `cross_shard_freeze`
//                      from a reading to a commit). The
//                      `fork_detection_no_fence` twin violates it.
//   invArmingIdempotent — the fork recovery is stamped once at the attested
//                      frontier and never moves, however many proofs arrive
//                      (INV-SEC-14, cause-neutral arming).
//   invNoReplayRearm — a proof replayed after the recovery completes is
//                      inert: the completed record's frontier tombstones
//                      every proof at or below it, so re-gossiped evidence
//                      of the answered fork never re-draws the innocent
//                      fresh committee (INV-FORK-NOREPLAY). Replays above
//                      the frontier are out of the tombstone's scope — the
//                      recovery bridge resolves the fresh committee there,
//                      so an old-committee QC fails verification at
//                      admission. The `fork_detection_replay` twin drops
//                      the tombstone and violates it.
//
// Modeling assumptions:
//   - Honest signers obey the safe-vote lock (INV-SHARD-3): a seat never
//     co-signs committed blocks on two branches at one height. This is the
//     only consensus rule imported; whether the corrupt set suffices to
//     span the quorum intersection is left to the checker, so
//     invHonestNoProof is a reachability result, not a definitional guard.
//   - The retained committee is an oracle for its own branches: it emits
//     any commit proof or bare cert its corruption level allows. Consumer
//     fold lag is free — a victim that has not folded the record still
//     consumes above the frontier, so the residual is exactly the detection
//     window (the accepted post-hoc suppressor bound, one epoch).
//   - The attested frontier is the last folded boundary and does not
//     retreat; the fork fence caps consumption there, so a pre-fold
//     consumption is the irreducible residual and no new consumption
//     crosses the cut post-fold.
//
// Run:
//   quint typecheck specs/shard_recovery.qnt
//   quint test --main=fork_detection_ok specs/shard_recovery.qnt
//   quint verify --main=fork_detection_ok --invariant=invAll --max-steps=8 specs/shard_recovery.qnt
//     (holds: a fork assembles only beyond f, the certified sibling is
//      unconsumable, the commit-level fence holds, and arming is idempotent)
//   quint verify --main=fork_detection_bare_qc --invariant=invNoCertifiedSibling --max-steps=8 specs/shard_recovery.qnt
//     (bare-QC consumption; expect a counterexample — a merely-certified
//      sibling that never commits is consumed)
//   quint verify --main=fork_detection_no_fence --invariant=invForkFenceHolds --max-steps=8 specs/shard_recovery.qnt
//     (the unfenced counterfactual; expect a counterexample — a folded
//      victim consumes a branch above the attested frontier)
//   quint verify --main=fork_detection_honest --invariant=invAll --max-steps=8 specs/shard_recovery.qnt
//     (the honest-majority control; no fork assembles, no recovery arms)
//   quint verify --main=fork_detection_replay --invariant=invNoReplayRearm --max-steps=8 specs/shard_recovery.qnt
//     (no completed-recovery tombstone; expect a counterexample — the
//      replayed proof re-arms the recovery after completion)

module fork_detection {
  // Committee size (production 128; model scale). SHARD_SIZE = 3f + 1.
  const SHARD_SIZE: int
  // Quorum threshold (2f + 1).
  const QUORUM: int
  // The retained committee and its corrupt subset. In the attack instance
  // the corrupt subset is f+1..2f — enough to span the quorum intersection
  // and double-commit; in the control it is at most f.
  const OLD: Set[int]
  const OLD_BYZ: Set[int]
  // The beacon-attested frontier = the last folded boundary. Provisions
  // above it are fenced once a victim folds the recovery.
  const FRONTIER: int
  const MAX_HEIGHT: int
  // Broken twin: consume against a bare QC, not a commit proof — the
  // pre-spine gate. True is the shipped commit-proof consumption.
  const COMMIT_PROOF_CONSUMPTION: bool
  // Broken twin: no commit-level fork fence. True is the shipped fence.
  const FORK_FENCE: bool
  // Broken twin: no completed-recovery tombstone — a replayed proof at or
  // below the completed frontier re-folds and re-draws the fresh
  // committee. True is the shipped tombstone.
  const REPLAY_TOMBSTONE: bool

  val OLD_HONEST: Set[int] = OLD.exclude(OLD_BYZ)
  // Two committing quorums share at least this many seats (pigeonhole over
  // a committee of SHARD_SIZE). A conflicting commit pair makes every shared
  // seat a lock violator, so a fork needs this many corrupt seats — f+1 at
  // SHARD_SIZE = 3f+1, QUORUM = 2f+1.
  val INTERSECTION: int = 2 * QUORUM - SHARD_SIZE

  // A committed block: a branch head at a height, with its committing
  // quorum — the signers of the commit proof's two-chain.
  type Commit = { branch: int, h: int, signers: Set[int] }
  // A merely-certified block: a bare QC with no committing two-chain. The
  // certified sibling the commit-proof gate makes unconsumable.
  type Cert = { branch: int, h: int }

  // Commit proofs the retained committee has produced.
  var commits: Set[Commit]
  // Bare certifications the retained committee has produced.
  var certs: Set[Cert]
  // The beacon folded a `ConflictingCommits` into a `ShardRecovery`.
  var forkArmed: bool
  // The fence cutoff stamped at arming (the attested frontier).
  var frozenAt: int
  // A victim folded the recovery — the fence governs from here.
  var consumerFolded: bool
  // A victim consumed a merely-certified sibling (no commit proof) — the
  // certified-sibling vector, which commit-proof consumption closes.
  var consumedUncommitted: bool
  // A folded victim consumed a branch's provisions above the frontier — a
  // commit-level fence breach.
  var fenceBreached: bool
  // The fresh committee's first crossing cleared the pending record; the
  // permanent completed record keeps the frontier as a tombstone.
  var recoveryCompleted: bool
  // A replayed proof re-armed a recovery after completion — the repeatable
  // re-draw of the innocent fresh committee the tombstone closes.
  var rearmed: bool

  // The `ConflictingCommits` assembly: two committed heads at one height on
  // different branches.
  val forkAssembled: bool =
    commits.exists(a => commits.exists(b => and {
      a.branch != b.branch,
      a.h == b.h,
    }))

  // Whether a commit proof (committing two-chain) exists for a branch head.
  def hasCommitProof(branch: int, h: int): bool =
    commits.exists(c => c.branch == branch and c.h == h)

  // Whether a victim may consume a branch's provisions at height h. The
  // commit-proof gate: only against a committing two-chain, never a bare
  // QC. The twin drops the gate — a merely-certified sibling is consumable.
  def consumable(branch: int, h: int): bool =
    if (COMMIT_PROOF_CONSUMPTION) hasCommitProof(branch, h)
    else hasCommitProof(branch, h) or certs.exists(c => c.branch == branch and c.h == h)

  // The retained committee commits a branch at a height. Honest signers
  // obey the safe-vote lock: none may already back a committed block at h
  // on the other branch, so a conflicting pair forms only if the quorum
  // intersection is entirely corrupt.
  action commitBranch(branch: int, h: int, signers: Set[int]): bool = all {
    branch >= 0, branch <= 1,
    h >= 0, h <= MAX_HEIGHT,
    signers.subseteq(OLD),
    signers.size() >= QUORUM,
    signers.intersect(OLD_HONEST).forall(v =>
      not(commits.exists(c => and { c.h == h, c.branch != branch, v.in(c.signers) }))),
    commits' = commits.union(Set({ branch: branch, h: h, signers: signers })),
    certs' = certs,
    forkArmed' = forkArmed,
    frozenAt' = frozenAt,
    consumerFolded' = consumerFolded,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    recoveryCompleted' = recoveryCompleted,
    rearmed' = rearmed,
  }

  // The retained committee emits a bare QC — a merely-certified sibling
  // with no committing two-chain.
  action certifyBranch(branch: int, h: int): bool = all {
    branch >= 0, branch <= 1,
    h >= 0, h <= MAX_HEIGHT,
    certs' = certs.union(Set({ branch: branch, h: h })),
    commits' = commits,
    forkArmed' = forkArmed,
    frozenAt' = frozenAt,
    consumerFolded' = consumerFolded,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    recoveryCompleted' = recoveryCompleted,
    rearmed' = rearmed,
  }

  // The beacon folds the assembled `ConflictingCommits` into a
  // `ShardRecovery`, stamping the fence at the attested frontier.
  // Idempotent: a second proof at the same shard finds the record already
  // stamped and does nothing. Guarded to the pre-completion life of the
  // fork: post-completion re-folds of the answered fork go through
  // `replayProof` (the old committee is this model's only producer, so
  // every post-completion proof is a replay).
  action armFork: bool = all {
    forkAssembled,
    not(forkArmed),
    not(recoveryCompleted),
    forkArmed' = true,
    frozenAt' = FRONTIER,
    commits' = commits,
    certs' = certs,
    consumerFolded' = consumerFolded,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    recoveryCompleted' = recoveryCompleted,
    rearmed' = rearmed,
  }

  // A victim folds the committed recovery — the fence governs from here.
  action consumerFold: bool = all {
    forkArmed,
    not(consumerFolded),
    consumerFolded' = true,
    commits' = commits,
    certs' = certs,
    forkArmed' = forkArmed,
    frozenAt' = frozenAt,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    recoveryCompleted' = recoveryCompleted,
    rearmed' = rearmed,
  }

  // The fresh committee's first crossing completes the recovery: the
  // pending record clears, and the permanent completed record retains the
  // attested frontier as the replay tombstone.
  action completeRecovery: bool = all {
    forkArmed,
    not(recoveryCompleted),
    forkArmed' = false,
    recoveryCompleted' = true,
    commits' = commits,
    certs' = certs,
    frozenAt' = frozenAt,
    consumerFolded' = consumerFolded,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    rearmed' = rearmed,
  }

  // The original proof re-gossips after the recovery completed. Scoped to
  // a conflicting pair at or below the completed frontier — the band whose
  // old-committee QCs verify forever (certified resolution keeps resolving
  // them below the bridge); a replay above the frontier already fails
  // verification at admission, since the bridge resolves the fresh
  // committee there. The shipped tombstone drops the proof at the fold;
  // the twin re-folds it and re-draws the innocent fresh committee.
  action replayProof(h: int): bool = all {
    recoveryCompleted,
    h <= frozenAt,
    commits.exists(a => commits.exists(b => and {
      a.branch != b.branch,
      a.h == h,
      b.h == h,
    })),
    forkArmed' = (forkArmed or not(REPLAY_TOMBSTONE)),
    rearmed' = (rearmed or not(REPLAY_TOMBSTONE)),
    commits' = commits,
    certs' = certs,
    frozenAt' = frozenAt,
    consumerFolded' = consumerFolded,
    consumedUncommitted' = consumedUncommitted,
    fenceBreached' = fenceBreached,
    recoveryCompleted' = recoveryCompleted,
  }

  // A victim consumes a branch's provisions at height h. Requires
  // consumability (the commit-proof gate) and, once the victim has folded
  // the recovery, respects the fence: no consumption above the frontier.
  action consume(branch: int, h: int): bool = all {
    branch >= 0, branch <= 1,
    h >= 0, h <= MAX_HEIGHT,
    consumable(branch, h),
    not(FORK_FENCE and consumerFolded and h > frozenAt),
    consumedUncommitted' = (consumedUncommitted or not(hasCommitProof(branch, h))),
    fenceBreached' = (fenceBreached or (consumerFolded and h > frozenAt)),
    commits' = commits,
    certs' = certs,
    forkArmed' = forkArmed,
    frozenAt' = frozenAt,
    consumerFolded' = consumerFolded,
    recoveryCompleted' = recoveryCompleted,
    rearmed' = rearmed,
  }

  // ── Nondet wrappers ──

  action commitAny = {
    nondet branch = 0.to(1).oneOf()
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    nondet signers = OLD.powerset().oneOf()
    commitBranch(branch, h, signers)
  }

  action certifyAny = {
    nondet branch = 0.to(1).oneOf()
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    certifyBranch(branch, h)
  }

  action consumeAny = {
    nondet branch = 0.to(1).oneOf()
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    consume(branch, h)
  }

  action replayAny = {
    nondet h = 0.to(MAX_HEIGHT).oneOf()
    replayProof(h)
  }

  action init = all {
    commits' = Set(),
    certs' = Set(),
    forkArmed' = false,
    frozenAt' = 0,
    consumerFolded' = false,
    consumedUncommitted' = false,
    fenceBreached' = false,
    recoveryCompleted' = false,
    rearmed' = false,
  }

  action step = any {
    commitAny,
    certifyAny,
    armFork,
    consumerFold,
    completeRecovery,
    replayAny,
    consumeAny,
  }

  // ── Invariants ──

  // A fork proof assembles only from a beyond-f committee: two committed
  // heads at one height force the quorum intersection to be all lock
  // violators, so at least INTERSECTION (= f+1) corrupt seats. An
  // honest-majority committee never generates one.
  val invHonestNoProof =
    forkAssembled implies (OLD_BYZ.size() >= INTERSECTION)

  // Commit-proof consumption keeps the certified-sibling vector empty: a
  // victim never consumes a merely-certified sibling.
  val invNoCertifiedSibling = not(consumedUncommitted)

  // The fork fence is commit-level and monotone: once a victim has folded
  // the recovery, it consumes neither branch's provisions above the
  // attested frontier.
  val invForkFenceHolds = not(fenceBreached)

  // Arming is idempotent: the recovery record is stamped once at the
  // attested frontier and never moves.
  val invArmingIdempotent =
    forkArmed implies (frozenAt == FRONTIER)

  // A proof replayed after the recovery completes is inert: the completed
  // record's frontier tombstones it, so the answered fork never re-draws
  // the innocent fresh committee.
  val invNoReplayRearm = not(rearmed)

  val invAll = and {
    invHonestNoProof,
    invNoCertifiedSibling,
    invForkFenceHolds,
    invArmingIdempotent,
    invNoReplayRearm,
  }

  // ── Scripted witnesses (valid under the shipped instance) ──

  // The retained beyond-f committee double-commits at a contested height
  // (two heads, quorums intersecting exactly in the corrupt pair), the
  // proof assembles, the beacon arms the recovery at the frontier, a victim
  // folds it, and the fence holds: a below-frontier committed branch stays
  // consumable (the residual), while an above-frontier one is disabled
  // under the fence (the fence working — the no_fence twin exhibits that
  // firing as a breach).
  run forkArmsAndFencesTest =
    init
      .then(commitBranch(0, 1, Set(1, 2, 3)))
      .then(commitBranch(0, 3, Set(1, 2, 3)))
      .then(commitBranch(1, 3, Set(1, 2, 4)))
      .expect(forkAssembled and not(forkArmed))
      .then(armFork)
      .expect(forkArmed and frozenAt == 2)
      .then(consume(0, 1))
      .expect(not(fenceBreached))
      .then(consumerFold)
      .then(consume(0, 1))
      .expect(consumerFolded and not(fenceBreached) and not(consumedUncommitted))

  // A branch commits at a height; the sibling is merely certified (a bare
  // QC). Under commit-proof consumption the committed head is consumable
  // but the certified sibling is not — `consume(1, 2)` is disabled, so the
  // certified-sibling vector stays empty. The bare_qc twin fires it.
  run certifiedSiblingUnconsumableTest =
    init
      .then(commitBranch(0, 2, Set(1, 2, 3)))
      .then(certifyBranch(1, 2))
      .then(consume(0, 2))
      .expect(not(consumedUncommitted))

  // The old committee double-commits below the frontier, the recovery arms
  // and completes, and the original proof re-gossips: the tombstone keeps
  // it inert — no re-arm, no re-draw. The replay twin re-folds it.
  run replayedProofInertTest =
    init
      .then(commitBranch(0, 1, Set(1, 2, 3)))
      .then(commitBranch(1, 1, Set(1, 2, 4)))
      .then(armFork)
      .then(completeRecovery)
      .expect(recoveryCompleted and not(forkArmed))
      .then(replayProof(1))
      .expect(not(forkArmed) and not(rearmed))
}

// The shipped rules: consume only against a commit proof, fence at the
// attested frontier, checked under the beyond-f retained committee (the
// corrupt pair spans the quorum intersection, so a fork can assemble).
module fork_detection_ok {
  import fork_detection(
    SHARD_SIZE = 4, QUORUM = 3,
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1, 2),
    FRONTIER = 2, MAX_HEIGHT = 4,
    COMMIT_PROOF_CONSUMPTION = true, FORK_FENCE = true,
    REPLAY_TOMBSTONE = true
  ).*
}

// Broken twin: consume against a bare QC — the pre-spine gate. A victim
// consumes a merely-certified sibling that never commits, reopening the
// certified-sibling vector — invNoCertifiedSibling fails.
module fork_detection_bare_qc {
  import fork_detection(
    SHARD_SIZE = 4, QUORUM = 3,
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1, 2),
    FRONTIER = 2, MAX_HEIGHT = 4,
    COMMIT_PROOF_CONSUMPTION = false, FORK_FENCE = true,
    REPLAY_TOMBSTONE = true
  ).*
}

// Broken twin: no commit-level fork fence. A folded victim keeps consuming
// a branch above the attested frontier — invForkFenceHolds fails.
module fork_detection_no_fence {
  import fork_detection(
    SHARD_SIZE = 4, QUORUM = 3,
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1, 2),
    FRONTIER = 2, MAX_HEIGHT = 4,
    COMMIT_PROOF_CONSUMPTION = true, FORK_FENCE = false,
    REPLAY_TOMBSTONE = true
  ).*
}

// Control: an honest-majority committee (≤ f corrupt). The lock discipline
// makes a conflicting commit pair unreachable, so no fork proof ever
// assembles and no recovery is spuriously armed — invAll holds.
module fork_detection_honest {
  import fork_detection(
    SHARD_SIZE = 4, QUORUM = 3,
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1),
    FRONTIER = 2, MAX_HEIGHT = 4,
    COMMIT_PROOF_CONSUMPTION = true, FORK_FENCE = true,
    REPLAY_TOMBSTONE = true
  ).*
}

// Broken twin: no completed-recovery tombstone. The original proof
// re-gossips after the recovery completes and re-folds, re-drawing the
// innocent fresh committee — invNoReplayRearm fails.
module fork_detection_replay {
  import fork_detection(
    SHARD_SIZE = 4, QUORUM = 3,
    OLD = Set(1, 2, 3, 4), OLD_BYZ = Set(1, 2),
    FRONTIER = 2, MAX_HEIGHT = 4,
    COMMIT_PROOF_CONSUMPTION = true, FORK_FENCE = true,
    REPLAY_TOMBSTONE = false
  ).*
}
