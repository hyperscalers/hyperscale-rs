// Model H (register: specs/README.md) — the beacon-witness fold's window
// arithmetic, which the epoch randomness now rides. The `witness_fold`
// module checks the exactly-once consumption and recovery-fence clauses
// the reveal fold added to INV-BEACON-2's surface; the `witness_window`
// module checks the window-base freeze that keeps a window's two schedule
// writes byte-identical (INV-BEACON-3's bookend discipline applied to
// `witness_window_bases`).
//
// One subject shard's accumulator, folded by the committed beacon epoch
// sequence, plus one reshape generation (the successor's fresh
// accumulator, with the predecessor's terminal record draining
// concurrently). The environment plays the committed sequence: the chain
// grows, a proposer reports a fresh crossing or re-rides the recorded one
// (a drain re-fold), a halt recovery stamps its frontier, the shard
// terminates into a successor. The chunk arithmetic, the fence, and the
// reseat are transcribed from the fold; everything else exists only as
// that input trace.
//
// Code anchors:
//   - Chunk bounds: crates/beacon/src/rules.rs `chunk_bounds` — the fold
//     consumes `[watermark, min(watermark + CAP, boundary_count))`; the
//     range derives from the local watermark, never from the reporter.
//     A boundary whose count regressed below the watermark is rejected
//     (`record_boundaries` monotonicity gate).
//   - Application: crates/beacon/src/state/witness.rs
//     `apply_contribution_witnesses` — exact-range, all-or-nothing; the
//     reveal outputs the randomness fold consumes are collected from
//     exactly the applied chunk (epoch.rs `reveal_outputs`).
//   - Drain re-folds: crates/beacon/src/state/epoch.rs `record_boundaries`
//     — a re-fold of the recorded crossing with witness progress advances
//     the watermark only (no record refresh); its reveals fold like any
//     applied chunk's. Model G carries the detection side (the
//     no-progress re-fold is a miss); here only the applied-leaf
//     bookkeeping matters.
//   - Fence: crates/beacon/src/state/epoch.rs `recovery_frontier_snapshot`
//     (taken before the boundary fold) + `filter_and_roll_randomness`
//     (crates/beacon/src/state/vrf.rs) — while a recovery pends, a
//     crossing beyond the recovery's `attested_frontier` folds its chunk
//     into state but contributes nothing to the seed. The frontier is the
//     recorded crossing's position at stamp time
//     (crates/beacon/src/state/committee.rs `recover_halted_committee`),
//     so the halted chain's legitimate backlog — at or below it — seeds
//     on recovery.
//   - Reseat: crates/beacon/src/state/epoch.rs `seed_split_children` /
//     `compose_merge_parent` — successors start fresh accumulators; the
//     predecessor's terminal record keeps draining until consumed (split
//     children and a merge's composed parent are identical at this
//     abstraction).
//   - Base freeze: crates/beacon/src/state/epoch.rs `apply_epoch` —
//     `witness_window_bases = live_witness_bases()` at the epoch's open,
//     before the fold advances any watermark; the lookahead projection
//     (crates/types/src/beacon/state.rs `derive_next_topology_snapshot`)
//     reads the same live value at the prior epoch's close, so a window's
//     two schedule writes agree.
//
// Properties:
//   invNoDoubleFold — no leaf is applied (and hence no reveal folded into
//                     the seed) twice, across fresh crossings, backlog
//                     drains, and the terminal drain of a reshaped-away
//                     predecessor. The `witness_fold_reporter_range` twin
//                     lets the reporter choose the chunk's start instead
//                     of the local watermark and violates it: a re-sent
//                     chunk re-folds leaves the fold already consumed.
//   invFence        — while a recovery pends, no leaf beyond its attested
//                     frontier enters the seed: the beyond-f retained
//                     committee's post-halt production cannot steer the
//                     draw. The `witness_fold_no_fence` twin folds the
//                     completing crossing's chunk straight into the seed
//                     and violates it.
//   invCoverage     — every leaf below a generation's watermark is
//                     accounted exactly once (seeded, or deterministically
//                     fenced), and nothing at or above it is: the seed is
//                     a pure function of the committed sequence with no
//                     skipped or phantom leaves.
//   invWatermarkSound — watermarks are bounded by their recorded
//                     crossings and chains; the fold never runs ahead of
//                     certified content.
//   invWindowAgree  — (witness_window) a window's active base equals its
//                     lookahead base: both writes read the watermark
//                     between the prior fold and this window's fold. The
//                     `witness_window_live_base` twin defers the active
//                     write past the fold and violates it — the two
//                     schedule writes of one window diverge, which forks
//                     the beacon-witness root across replicas resolving
//                     through different writes.
//
// Modeling assumptions:
//   - Chunks are QC-attested content: a chunk either matches the boundary
//     header exactly or is rejected whole (`contribution_chunk_valid`),
//     so the model applies ranges, never forged leaves. The adversary's
//     levers are scheduling ones: which certified crossing is reported
//     when, how much backlog accumulates, when the chain grows (minted
//     post-halt growth included — the fence, not content validation, is
//     what keeps it out of the seed).
//   - Every leaf is a reveal. Leaf-0 mandatory-ness (`derive_leaves`,
//     enforced by `VerifyBeaconWitnessRoot`) is shard-side validation;
//     at the fold's abstraction the reveal/content distinction changes
//     which applied leaves carry entropy, not the window arithmetic, and
//     exactly-once over all leaves subsumes exactly-once over reveals.
//   - Heights collapse onto leaf counts: with a mandatory reveal per
//     block the two advance in lockstep, and the fence compares positions
//     along one chain, so the collapse preserves every checked ordering.
//   - One reshape generation (the reseat guard), draining concurrently
//     with the successor — enough to exercise the fresh accumulator and
//     the terminal drain; further generations repeat the same shape.
//   - Terminal drains bypass the fence: halt detection exempts terminal
//     records, so no recovery ever pends on the draining predecessor.
//   - Seed determinism itself is not a separate invariant: the fold is a
//     pure function of the committed sequence by construction
//     (INV-BEACON-2), mirroring Model G's treatment.
//
// Run:
//   quint typecheck specs/witness_fold.qnt
//   quint verify --main=witness_fold_ok --invariant=invAll --max-steps=10 specs/witness_fold.qnt
//     (holds; depth 10 covers grow → fresh fold → stamp → clear → drain →
//      reseat → concurrent terminal drain)
//   quint verify --main=witness_fold_reporter_range --invariant=invNoDoubleFold --max-steps=6 specs/witness_fold.qnt
//     (the twin folds a reporter-chosen range; expect a counterexample)
//   quint verify --main=witness_fold_no_fence --invariant=invFence --max-steps=6 specs/witness_fold.qnt
//     (the twin seeds a post-frontier chunk under a pending recovery;
//      expect a counterexample)
//   quint verify --main=witness_window_ok --invariant=invWindowAgree --max-steps=8 specs/witness_fold.qnt
//     (holds)
//   quint verify --main=witness_window_live_base --invariant=invWindowAgree --max-steps=4 specs/witness_fold.qnt
//     (the twin writes the active base after the fold; expect a
//      counterexample)

module witness_fold {
  // Chunk cap per fold (`MAX_WITNESSES_PER_SHARD`; model scale).
  const CAP: int
  // Per-step chain growth bound (leaves; model scale).
  const MAX_GROW: int
  // Constant leaf-index band per generation (Apalache: state-relative
  // ranges are filtered from a constant band).
  const MAX_LEAVES: int
  // Broken twin: the chunk's start comes from the reporter rather than
  // the local watermark. False is the shipped `chunk_bounds`.
  const REPORTER_RANGE: bool
  // Broken twin: the recovery fence is off. False is the shipped fence.
  const FENCE_OFF: bool

  // ── Current-generation accumulator ──
  // Reshape generation: 0 = the original shard, 1 = its successor.
  var gen: int
  // The chain's committed leaf count (ground truth, minted growth
  // included).
  var chainCount: int
  // `ShardBoundary::witness_leaf_count` — the applied watermark.
  var watermark: int
  // The recorded crossing's leaf count (`boundary_count`).
  var recorded: int

  // ── The reshaped-away predecessor's terminal drain slot ──
  var oldActive: bool
  var oldWatermark: int
  var oldRecorded: int

  // ── Halt recovery fence ──
  var recoveryPending: bool
  // `HaltRecovery::attested_frontier`, in the collapsed height≈count
  // coordinates.
  var frontier: int

  // ── Ghosts ──
  // Leaves whose reveal entered the seed, as (generation, leaf index).
  var seeded: Set[(int, int)]
  // Leaves applied under an active fence — state-mutating, seed-inert.
  var fenced: Set[(int, int)]
  // A leaf was applied twice.
  var dupSeen: bool
  // A beyond-frontier leaf entered the seed while its recovery pended.
  var fenceLeak: bool

  pure def minInt(a: int, b: int): int = if (a < b) a else b

  // The leaf band [lo, hi) of generation g, drawn from the constant band.
  pure def leafBand(g: int, lo: int, hi: int): Set[(int, int)] =
    0.to(MAX_LEAVES).filter(i => lo <= i and i < hi).map(i => (g, i))

  action init = all {
    gen' = 0,
    chainCount' = 0,
    watermark' = 0,
    recorded' = 0,
    oldActive' = false,
    oldWatermark' = 0,
    oldRecorded' = 0,
    recoveryPending' = false,
    frontier' = 0,
    seeded' = Set(),
    fenced' = Set(),
    dupSeen' = false,
    fenceLeak' = false,
  }

  // The chain commits more blocks; every block appends its mandatory
  // reveal leaf. Includes a beyond-f committee minting post-halt.
  action grow = {
    nondet n = 1.to(MAX_GROW).oneOf()
    all {
      chainCount + n <= MAX_LEAVES,
      chainCount' = chainCount + n,
      gen' = gen, watermark' = watermark, recorded' = recorded,
      oldActive' = oldActive, oldWatermark' = oldWatermark,
      oldRecorded' = oldRecorded,
      recoveryPending' = recoveryPending, frontier' = frontier,
      seeded' = seeded, fenced' = fenced,
      dupSeen' = dupSeen, fenceLeak' = fenceLeak,
    }
  }

  // A fresh crossing at count c records the shard's new boundary, applies
  // the chunk `[watermark, min(watermark + CAP, c))`, and clears a
  // pending recovery. The fence is judged against the pre-fold snapshot:
  // the completing crossing's own chunk seeds only at or below the
  // frontier.
  action foldFresh = {
    nondet c = 0.to(MAX_LEAVES).oneOf()
    nondet s = 0.to(MAX_LEAVES).oneOf()
    val start = if (REPORTER_RANGE) s else watermark
    val end = minInt(watermark + CAP, c)
    val newLeaves = leafBand(gen, start, end)
    val beyond = recoveryPending and c > frontier
    val fenceApplies = beyond and not(FENCE_OFF)
    all {
      c > recorded,
      c <= chainCount,
      c >= watermark,
      s <= watermark,
      seeded' = if (fenceApplies) seeded else seeded.union(newLeaves),
      fenced' = if (fenceApplies) fenced.union(newLeaves) else fenced,
      dupSeen' = if (newLeaves.intersect(seeded.union(fenced)) != Set()) true else dupSeen,
      fenceLeak' = if (beyond and not(fenceApplies) and newLeaves != Set()) true else fenceLeak,
      watermark' = end,
      recorded' = c,
      recoveryPending' = false,
      gen' = gen, chainCount' = chainCount,
      oldActive' = oldActive, oldWatermark' = oldWatermark,
      oldRecorded' = oldRecorded,
      frontier' = frontier,
    }
  }

  // A drain re-fold of the recorded crossing: watermark-only progress, no
  // record refresh, recovery untouched. The frontier is the recorded
  // crossing's own position, so the fence always admits the drain — the
  // halted chain's legitimate backlog seeds on recovery.
  action foldDrain = {
    val end = minInt(watermark + CAP, recorded)
    val newLeaves = leafBand(gen, watermark, end)
    all {
      watermark < recorded,
      seeded' = seeded.union(newLeaves),
      fenced' = fenced,
      dupSeen' = if (newLeaves.intersect(seeded.union(fenced)) != Set()) true else dupSeen,
      fenceLeak' = fenceLeak,
      watermark' = end,
      gen' = gen, chainCount' = chainCount, recorded' = recorded,
      oldActive' = oldActive, oldWatermark' = oldWatermark,
      oldRecorded' = oldRecorded,
      recoveryPending' = recoveryPending, frontier' = frontier,
    }
  }

  // The detector flags the shard and the re-draw stamps a recovery whose
  // frontier is the recorded crossing's position. Detection calibration
  // is Model G's subject; here any moment is a valid stamp.
  action stampRecovery = all {
    not(recoveryPending),
    recoveryPending' = true,
    frontier' = recorded,
    gen' = gen, chainCount' = chainCount, watermark' = watermark,
    recorded' = recorded,
    oldActive' = oldActive, oldWatermark' = oldWatermark,
    oldRecorded' = oldRecorded,
    seeded' = seeded, fenced' = fenced,
    dupSeen' = dupSeen, fenceLeak' = fenceLeak,
  }

  // The shard terminates at its recorded crossing and a successor seats
  // with a fresh accumulator; the terminal record keeps draining. Leaves
  // past the terminal cut are coast content no fold consumes. One
  // generation suffices — further reseats repeat the same shape.
  action reseat = all {
    gen == 0,
    recorded > 0,
    not(recoveryPending),
    oldActive' = watermark < recorded,
    oldWatermark' = watermark,
    oldRecorded' = recorded,
    gen' = gen + 1,
    chainCount' = 0,
    watermark' = 0,
    recorded' = 0,
    recoveryPending' = false, frontier' = frontier,
    seeded' = seeded, fenced' = fenced,
    dupSeen' = dupSeen, fenceLeak' = fenceLeak,
  }

  // The predecessor's terminal record drains: re-sourced every fold until
  // consumed, then dropped. Terminal records are halt-exempt, so no fence
  // applies.
  action foldOldDrain = {
    val end = minInt(oldWatermark + CAP, oldRecorded)
    val newLeaves = leafBand(gen - 1, oldWatermark, end)
    all {
      oldActive,
      oldWatermark < oldRecorded,
      seeded' = seeded.union(newLeaves),
      fenced' = fenced,
      dupSeen' = if (newLeaves.intersect(seeded.union(fenced)) != Set()) true else dupSeen,
      fenceLeak' = fenceLeak,
      oldWatermark' = end,
      oldActive' = end < oldRecorded,
      gen' = gen, chainCount' = chainCount, watermark' = watermark,
      recorded' = recorded, oldRecorded' = oldRecorded,
      recoveryPending' = recoveryPending, frontier' = frontier,
    }
  }

  action step = any {
    grow,
    foldFresh,
    foldDrain,
    foldOldDrain,
    stampRecovery,
    reseat,
  }

  // ── Invariants ──

  val invNoDoubleFold = not(dupSeen)

  val invFence = not(fenceLeak)

  // Exactly-once accounting: below a generation's watermark every leaf is
  // seeded xor fenced; at or above it, nothing is.
  val invCoverage = and {
    0.to(MAX_LEAVES).forall(i =>
      (i < watermark) implies
        (seeded.contains((gen, i)) or fenced.contains((gen, i)))),
    0.to(MAX_LEAVES).forall(i =>
      (oldActive and i < oldWatermark) implies
        (seeded.contains((gen - 1, i)) or fenced.contains((gen - 1, i)))),
    seeded.union(fenced).forall(l =>
      if (l._1 == gen) l._2 < watermark
      else l._1 == gen - 1 and l._2 < oldWatermark),
    seeded.intersect(fenced) == Set(),
  }

  // The fold never runs ahead of certified content.
  val invWatermarkSound = and {
    watermark <= recorded or recorded == 0,
    recorded <= chainCount,
    watermark <= chainCount,
    oldWatermark <= oldRecorded,
  }

  val invAll = and {
    invNoDoubleFold,
    invFence,
    invCoverage,
    invWatermarkSound,
  }
}

module witness_window {
  // Per-epoch chunk bound (model scale).
  const MAX_CHUNK: int
  // Broken twin: the active write reads the watermark after the epoch's
  // fold advanced it. False is the shipped freeze-at-open.
  const FREEZE_AFTER_FOLD: bool

  // The shard's applied watermark (`live_witness_bases()` proxy).
  var watermark: int
  // The window base the lookahead projection wrote at the prior epoch's
  // close (`derive_next_topology_snapshot`).
  var baseLookahead: int
  // The window base the promotion wrote at this epoch's open
  // (`apply_epoch`: `witness_window_bases = live_witness_bases()`).
  var baseActive: int
  // 0 = awaiting the epoch open, 1 = awaiting the fold, 2 = awaiting the
  // close.
  var phase: int

  action init = all {
    watermark' = 0,
    baseLookahead' = 0,
    baseActive' = 0,
    phase' = 0,
  }

  // Epoch open: promote — the shipped rule freezes this window's active
  // base before the fold; the twin defers it.
  action openWindow = all {
    phase == 0,
    baseActive' = if (FREEZE_AFTER_FOLD) baseActive else watermark,
    phase' = 1,
    watermark' = watermark, baseLookahead' = baseLookahead,
  }

  // The epoch's boundary fold advances the watermark; the twin writes the
  // active base from the post-fold value.
  action foldEpoch = {
    nondet chunk = 0.to(MAX_CHUNK).oneOf()
    all {
      phase == 1,
      watermark' = watermark + chunk,
      baseActive' = if (FREEZE_AFTER_FOLD) watermark + chunk else baseActive,
      phase' = 2,
      baseLookahead' = baseLookahead,
    }
  }

  // Epoch close: the lookahead projection writes the next window's base
  // from the live post-fold watermark.
  action closeWindow = all {
    phase == 2,
    baseLookahead' = watermark,
    phase' = 0,
    watermark' = watermark, baseActive' = baseActive,
  }

  action step = any { openWindow, foldEpoch, closeWindow }

  // A window's two schedule writes agree — the proposer's claimed base
  // (lookahead) and the verifier's resolved base (active) are one value.
  val invWindowAgree = (phase != 0) implies (baseActive == baseLookahead)
}

module witness_fold_ok {
  import witness_fold(
    CAP = 2, MAX_GROW = 2, MAX_LEAVES = 6,
    REPORTER_RANGE = false, FENCE_OFF = false
  ).*
}

module witness_fold_reporter_range {
  import witness_fold(
    CAP = 2, MAX_GROW = 2, MAX_LEAVES = 6,
    REPORTER_RANGE = true, FENCE_OFF = false
  ).*
}

module witness_fold_no_fence {
  import witness_fold(
    CAP = 2, MAX_GROW = 2, MAX_LEAVES = 6,
    REPORTER_RANGE = false, FENCE_OFF = true
  ).*
}

module witness_window_ok {
  import witness_window(MAX_CHUNK = 2, FREEZE_AFTER_FOLD = false).*
}

module witness_window_live_base {
  import witness_window(MAX_CHUNK = 2, FREEZE_AFTER_FOLD = true).*
}
