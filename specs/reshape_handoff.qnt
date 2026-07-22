// Model I (register: specs/README.md) — the reshape cut and successor
// genesis: the handoff seam between a terminating chain and the
// committees that continue its state. Three modules. `split_handoff` —
// the terminal fold's seeding of split children and the member-side
// genesis flip: genesis determinism (INV-RESHAPE-2), the seed guard's
// root continuity (INV-RESHAPE-3), canonical-clock adoption
// (INV-RESHAPE-4), and terminal-record retention (INV-BEACON-8).
// `merge_handoff` — the merge compose: terminal-mark soundness at the
// boundary instant, the both-terminals gate, the cut floor, and the
// keepers' anchor read-back (INV-RESHAPE-2/3/4 on the merge side).
// `canonical_pick` — the per-shard canonical boundary QC choice's
// totality (INV-BEACON-5).
//
// One shard family per module: a splitting parent with two children, or
// two merging children with their reformed parent. The environment plays
// the committed beacon epoch sequence plus the member-side flips: the
// terminating chain folds crossings and its terminal, coast
// re-certifications enter the served pool, the fold seeds or composes
// successors, members derive and adopt genesis, successors produce, the
// retention GC sweeps. Everything else in the network exists only as
// that input trace.
//
// Code anchors:
//   - Terminal marks: crates/beacon/src/state/epoch.rs
//     `carried_terminal_marks` — a contribution is terminal iff the
//     epoch it *crosses* is strictly past the scheduled cut
//     (`crossed > t`); the boundary instant counts as not yet crossed,
//     so the final window's own refresh — certifiable exactly on the
//     cut — stays non-terminal and its pre-freeze state root never
//     reaches a merge compose. Only merge children (no
//     `split_child_roots`) persist `terminal_qc_wt`.
//   - Seeding: crates/beacon/src/state/epoch.rs `seed_split_children` —
//     the terminal header's `split_child_roots` must compose to its
//     state root (`composes_to`, one `hash_internal`) before either
//     child's placeholder fills; a failed pair leaves the children
//     pending (they seed from their own first contributions instead).
//     The seeded anchor carries the child subtree root, the
//     deterministic genesis hash, and the canonical terminal QC's
//     weighted timestamp.
//   - Compose: crates/beacon/src/state/epoch.rs `compose_merge_parents`
//     / `compose_merge_parent` — fires only when both children's
//     lingering records carry `terminal_qc_wt` and the parent is still
//     a placeholder (once-only by the zero-hash guard); the composed
//     root is `hash_internal(r_p0, r_p1)` over the two recorded
//     terminal roots, and the cut is the *start of the epoch containing
//     the left child's terminal QC weighted timestamp* — floored off
//     the certified value, not the scheduled epoch, so extra coast
//     epochs cannot drift it.
//   - Member flips: crates/node/src/reshape/split_flip.rs
//     `split_genesis_from_terminal` and merge_flip.rs
//     `merge_genesis_from_terminals` — the clock is read from
//     `ShardAnchor::weighted_timestamp`, the value the fold composed;
//     the served QC only proves the terminal is certified. A terminal
//     can be re-certified at a higher round during the coast, so the
//     served stamp is a gossip artifact whose value (or floor) can
//     differ. The derived genesis must reconstruct `anchor.block_hash`
//     exactly or the flip fails closed.
//   - Retention: crates/beacon/src/state/epoch.rs
//     `gc_terminal_boundaries` / `successors_live_for_terminal` — a
//     terminal record is released only when its successors are *live*
//     (both split children, or the reformed parent, in
//     `BeaconState.advanced`: produced past genesis — seeding alone is
//     not consumption) AND the retention horizon has passed. The
//     successor enters `advanced` at its first genuine crossing
//     (`record_boundaries`).
//   - Canonical pick: crates/beacon/src/rules.rs
//     `canonical_boundary_qcs` — per shard, the committed proposals'
//     boundary QC with the highest `(weighted_timestamp, block_hash)`,
//     ties broken on the hash so the choice is total and identical on
//     every node regardless of iteration order; assembler, receiver
//     gate (`contributions_well_formed`), and fold all bind to it.
//
// Properties:
//   invGenesisAgree   — (split/merge) every member that completes the
//                       flip adopts the identical genesis — the one the
//                       beacon anchored (INV-RESHAPE-2). The
//                       `split_handoff_served_clock` twin derives the
//                       clock from the served certified QC instead of
//                       the anchor (with nothing composed there is
//                       nothing to fail closed against): two members
//                       served different coast re-certifications adopt
//                       different genesis bytes — a successor-chain
//                       fork with zero Byzantine action.
//   invCanonicalClock — (split) every adopted clock is the canonical
//                       terminal QC weighted timestamp the fold bound —
//                       never a served re-certification's
//                       (INV-RESHAPE-4). Violated by the same twin.
//   invRootContinuity — (split) a seeded child anchor carries the true
//                       subtree root: the claimed pair composed to the
//                       committed terminal root (INV-RESHAPE-3). The
//                       `split_handoff_unchecked_seed` twin skips
//                       `composes_to` and seeds a child whose adopted
//                       root is not the parent's subtree — state
//                       re-keyed by fiat.
//   invRetention      — (split) the parent's terminal record survives
//                       until both children are live (produced past
//                       genesis) and the horizon has passed
//                       (INV-BEACON-8). The `split_handoff_horizon_gc`
//                       twin releases on the horizon alone: the record
//                       drops while a child has never produced — its
//                       unadopted members lose the only serving anchor
//                       for the terminal they still need.
//   invTerminalMarkSound — (merge) a record carrying `terminal_qc_wt`
//                       has genuinely crossed past its cut and holds
//                       the frozen terminal root. The
//                       `merge_handoff_boundary_instant` twin judges
//                       the cut with `crossed >= t`: the final window's
//                       own refresh — pre-freeze root, pre-cut stamp —
//                       is marked terminal.
//   invComposedAnchor — (merge) the composed parent anchor is
//                       `hash_internal` over the two *frozen terminal*
//                       roots, its cut the epoch start of the genuine
//                       left terminal stamp (INV-RESHAPE-3/4). The
//                       `merge_handoff_eager_compose` twin drops the
//                       both-terminals gate and composes over the
//                       still-running sibling's pre-terminal root.
//                       Violated by the boundary-instant twin too.
//   invKeeperReadback — (merge) every keeper's adopted cut is the
//                       anchor's — composed once by the fold, read
//                       back, never re-derived (INV-RESHAPE-4). The
//                       `merge_handoff_refloor` twin re-floors the
//                       served left QC: a re-certification that drifted
//                       into a later epoch floors to a different cut
//                       and the keepers fork.
//   invPickTotal      — (canonical_pick) two consumers folding the same
//                       candidate set in different orders bind the same
//                       canonical QC (INV-BEACON-5). The
//                       `canonical_pick_wt_only` twin compares by
//                       weighted timestamp alone: a stamp tie makes the
//                       pick first-seen, and the two consumers diverge.
//
// Modeling assumptions:
//   - Hashing is perfect: a genesis block is identified by its content
//     (root, clock) and `hash_internal` is injective, so "composes to"
//     is equality on the pair and a hash mismatch is exactly a content
//     mismatch. The genesis fields that never vary across behaviors
//     (heights, parent hashes, the merge's taller-child provenance and
//     left/right compose order, proposer sentinels) ride the identity
//     and are not modeled separately — they are pure functions of
//     inputs the model already fixes (`BlockHeader::split_child_genesis`
//     / `merge_parent_genesis`).
//   - One committed terminal per chain is Model B's commit safety,
//     taken as an oracle; consuming it only against a commit proof is
//     Model G's `fork_detection` (INV-SEC-11). The served pool varies
//     only the *certification stamp* of the one terminal — the coast
//     re-certification `split_flip.rs` documents.
//   - The non-composing claimed pair reaching a committed terminal
//     header models a committee beyond its shard-side `Verify` gate (a
//     defect or a beyond-f quorum); the seed guard is the beacon's own
//     defense in depth, and the healthy fallback (children left
//     pending) is deliberately not a violation — root continuity is
//     about what seeds, not whether seeding happens this fold.
//   - Seating, readiness, and staffing are Model F's subject; snap-sync
//     import verification is INV-STATE-3's; straddler settlement across
//     the same cut is Model D's. Members here adopt whenever the record
//     is fetchable — adoption order and timing are free.
//   - The retention clock collapses window ends onto epoch indices and
//     the horizon onto whole epochs; the GC may fire on any fold once
//     its guard passes, over-approximating the per-fold sweep.
//   - Epoch arithmetic in `merge_handoff` uses the code's two
//     conventions verbatim: crossing epochs via "the boundary instant
//     counts as not yet crossed" (`EpochWindows::is_crossing`), anchor
//     floors via plain window containment (`epoch_for`).
//
// Run:
//   quint typecheck specs/reshape_handoff.qnt
//   quint verify --main=split_handoff_ok --invariant=invAll --max-steps=12 specs/reshape_handoff.qnt
//     (holds; depth 12 covers fold → re-cert → both adoptions → both
//      children live → horizon → release)
//   quint verify --main=split_handoff_served_clock --invariant=invGenesisAgree --max-steps=6 specs/reshape_handoff.qnt
//     (the twin clocks genesis from the served QC; expect a
//      counterexample — invCanonicalClock falls at the same depth)
//   quint verify --main=split_handoff_unchecked_seed --invariant=invRootContinuity --max-steps=4 specs/reshape_handoff.qnt
//     (the twin seeds without `composes_to`; expect a counterexample)
//   quint verify --main=split_handoff_horizon_gc --invariant=invRetention --max-steps=8 specs/reshape_handoff.qnt
//     (the twin releases on the horizon alone; expect a counterexample)
//   quint verify --main=merge_handoff_ok --invariant=invAll --max-steps=12 specs/reshape_handoff.qnt
//     (holds; depth 12 covers both chains crossing to terminal →
//      compose → re-cert → both keepers)
//   quint verify --main=merge_handoff_eager_compose --invariant=invComposedAnchor --max-steps=6 specs/reshape_handoff.qnt
//     (the twin composes on the first terminal; expect a counterexample)
//   quint verify --main=merge_handoff_boundary_instant --invariant=invTerminalMarkSound --max-steps=4 specs/reshape_handoff.qnt
//     (the twin judges the cut inclusively; expect a counterexample)
//   quint verify --main=merge_handoff_refloor --invariant=invKeeperReadback --max-steps=8 specs/reshape_handoff.qnt
//     (the twin re-floors the served left QC; expect a counterexample)
//   quint verify --main=canonical_pick_ok --invariant=invPickTotal --max-steps=8 specs/reshape_handoff.qnt
//     (holds)
//   quint verify --main=canonical_pick_wt_only --invariant=invPickTotal --max-steps=8 specs/reshape_handoff.qnt
//     (the twin drops the hash tiebreak; expect a counterexample)

module split_handoff {
  // Retention horizon in whole epochs (model scale of RETENTION_HORIZON
  // over the terminal window's end).
  const HORIZON: int
  // Epoch band (Apalache: constant ranges only).
  const MAX_EPOCH: int
  // Weighted-timestamp band for terminal stamps and re-certifications.
  const MAX_WT: int
  // Broken twin: members clock genesis from the served certified QC
  // instead of the anchor, with no beacon-composed value to fail closed
  // against. False is the shipped `split_genesis_from_terminal`.
  const SERVED_CLOCK: bool
  // Broken twin: `seed_split_children` skips the `composes_to` guard.
  // False is the shipped seed.
  const UNCHECKED_SEED: bool
  // Broken twin: `gc_terminal_boundaries` releases on the horizon
  // alone, ignoring `successors_live_for_terminal`. False is the
  // shipped retain predicate.
  const GC_HORIZON_ONLY: bool

  // The true child subtree root and a non-composing impostor: with
  // perfect hashing, a claimed pair composes to the terminal root iff
  // it is the true pair.
  pure val TRUE_ROOT: int = 1
  pure val FAKE_ROOT: int = 2

  // Beacon fold clock, in epochs.
  var now: int
  // The parent's terminal crossing has folded.
  var folded: bool
  // Epoch of the terminal fold (the record's terminal window).
  var termEpoch: int
  // The canonical terminal QC weighted timestamp the fold bound — the
  // chain-carried `parent_qc` form, which the anchor records.
  var termWt: int
  // Stamps of QCs the store may serve alongside the terminal: the
  // canonical one plus coast re-certifications.
  var served: Set[int]
  // The children's placeholders have been seeded from the terminal.
  var seeded: bool
  // The seeded anchors carry the true subtree roots.
  var seedGood: bool
  // Member flips: adopted genesis content per pre-staffed member.
  var ad1: bool
  var adRoot1: int
  var adWt1: int
  var ad2: bool
  var adRoot2: int
  var adWt2: int
  // Successors live: the child has folded its first genuine crossing
  // (`BeaconState.advanced`).
  var advL: bool
  var advR: bool
  // The parent's terminal boundary record is still retained.
  var record: bool

  action init = all {
    now' = 0,
    folded' = false,
    termEpoch' = 0,
    termWt' = 0,
    served' = Set(),
    seeded' = false,
    seedGood' = true,
    ad1' = false, adRoot1' = 0, adWt1' = 0,
    ad2' = false, adRoot2' = 0, adWt2' = 0,
    advL' = false,
    advR' = false,
    record' = true,
  }

  // A beacon fold with nothing for this family: the epoch advances.
  action tick = all {
    now < MAX_EPOCH,
    now' = now + 1,
    folded' = folded, termEpoch' = termEpoch, termWt' = termWt,
    served' = served,
    seeded' = seeded, seedGood' = seedGood,
    ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
    ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
    advL' = advL, advR' = advR, record' = record,
  }

  // The parent's terminal crossing folds: the canonical QC binds the
  // stamp, and `seed_split_children` fills both placeholders iff the
  // committed claimed pair composes to the terminal root (the twin
  // seeds regardless). A failed pair leaves the children pending.
  action foldTerminal = {
    nondet w = 1.to(MAX_WT).oneOf()
    nondet good = Set(true, false).oneOf()
    all {
      not(folded),
      folded' = true,
      termEpoch' = now,
      termWt' = w,
      served' = Set(w),
      seeded' = (good or UNCHECKED_SEED),
      seedGood' = good,
      now' = now,
      ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
      ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
      advL' = advL, advR' = advR, record' = record,
    }
  }

  // The coast re-certifies the terminal at a higher round; the served
  // pool gains a stamp the canonical fold never bound.
  action recert = {
    nondet w = 1.to(MAX_WT).oneOf()
    all {
      folded,
      w > termWt,
      served' = served.union(Set(w)),
      now' = now, folded' = folded, termEpoch' = termEpoch,
      termWt' = termWt,
      seeded' = seeded, seedGood' = seedGood,
      ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
      ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
      advL' = advL, advR' = advR, record' = record,
    }
  }

  // The anchor root a member reads back (the seeded child anchor).
  val anchorRoot: int = if (seedGood) TRUE_ROOT else FAKE_ROOT

  // Member 1 completes the flip: fetch the retained terminal with some
  // served QC, derive genesis. Shipped: root and clock read back from
  // the anchor, reconstruction hash-checked (it passes by
  // construction). Twin: clock from the served QC, root from the local
  // chain.
  action adopt1 = {
    nondet sw = 1.to(MAX_WT).oneOf()
    all {
      record,
      seeded,
      not(ad1),
      served.contains(sw),
      ad1' = true,
      adRoot1' = if (SERVED_CLOCK) TRUE_ROOT else anchorRoot,
      adWt1' = if (SERVED_CLOCK) sw else termWt,
      now' = now, folded' = folded, termEpoch' = termEpoch,
      termWt' = termWt, served' = served,
      seeded' = seeded, seedGood' = seedGood,
      ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
      advL' = advL, advR' = advR, record' = record,
    }
  }

  action adopt2 = {
    nondet sw = 1.to(MAX_WT).oneOf()
    all {
      record,
      seeded,
      not(ad2),
      served.contains(sw),
      ad2' = true,
      adRoot2' = if (SERVED_CLOCK) TRUE_ROOT else anchorRoot,
      adWt2' = if (SERVED_CLOCK) sw else termWt,
      now' = now, folded' = folded, termEpoch' = termEpoch,
      termWt' = termWt, served' = served,
      seeded' = seeded, seedGood' = seedGood,
      ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
      advL' = advL, advR' = advR, record' = record,
    }
  }

  // The left child folds its first genuine crossing — it enters
  // `advanced`. Its committee only exists through seated members, so a
  // completed flip is the precondition.
  action advanceL = all {
    seeded,
    ad1 or ad2,
    not(advL),
    advL' = true,
    now' = now, folded' = folded, termEpoch' = termEpoch,
    termWt' = termWt, served' = served,
    seeded' = seeded, seedGood' = seedGood,
    ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
    ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
    advR' = advR, record' = record,
  }

  // The right child's cohort is abstracted away; it goes live any time
  // after seeding.
  action advanceR = all {
    seeded,
    not(advR),
    advR' = true,
    now' = now, folded' = folded, termEpoch' = termEpoch,
    termWt' = termWt, served' = served,
    seeded' = seeded, seedGood' = seedGood,
    ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
    ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
    advL' = advL, record' = record,
  }

  // The retention GC releases the terminal record. Shipped: only once
  // the successors are live AND the horizon has passed; the twin on the
  // horizon alone.
  action gcRelease = all {
    record,
    folded,
    now > termEpoch + HORIZON,
    GC_HORIZON_ONLY or (advL and advR),
    record' = false,
    now' = now, folded' = folded, termEpoch' = termEpoch,
    termWt' = termWt, served' = served,
    seeded' = seeded, seedGood' = seedGood,
    ad1' = ad1, adRoot1' = adRoot1, adWt1' = adWt1,
    ad2' = ad2, adRoot2' = adRoot2, adWt2' = adWt2,
    advL' = advL, advR' = advR,
  }

  action step = any {
    tick,
    foldTerminal,
    recert,
    adopt1,
    adopt2,
    advanceL,
    advanceR,
    gcRelease,
  }

  // ── Invariants ──

  // Every completed flip adopted the identical genesis (INV-RESHAPE-2).
  val invGenesisAgree =
    (ad1 and ad2) implies (adRoot1 == adRoot2 and adWt1 == adWt2)

  // Every adopted clock is the canonical bound stamp (INV-RESHAPE-4).
  val invCanonicalClock = and {
    ad1 implies adWt1 == termWt,
    ad2 implies adWt2 == termWt,
  }

  // A seeded anchor carries the true subtree root (INV-RESHAPE-3).
  val invRootContinuity = seeded implies seedGood

  // The terminal record outlives its dependents (INV-BEACON-8).
  val invRetention =
    (folded and not(record)) implies
      (advL and advR and now > termEpoch + HORIZON)

  val invAll = and {
    invGenesisAgree,
    invCanonicalClock,
    invRootContinuity,
    invRetention,
  }
}

module merge_handoff {
  // Epoch window length in weighted-time units.
  const E_LEN: int
  // Both children's scheduled terminal epoch (the final governed
  // window).
  const T_CUT: int
  // Weighted-timestamp band.
  const MAX_WT: int
  // Broken twin: compose fires on the first terminal, without the
  // both-terminals gate. False is the shipped `compose_merge_parents`.
  const EAGER_COMPOSE: bool
  // Broken twin: terminal is judged `crossed >= t` — the boundary
  // instant counts as crossed. False is the shipped strict
  // `carried_terminal_marks` rule.
  const BOUNDARY_INSTANT: bool
  // Broken twin: keepers re-floor the served left QC instead of
  // reading the anchor's cut. False is the shipped
  // `merge_genesis_from_terminals`.
  const REFLOOR: bool

  // A child record's state root before its chain passes the cut (still
  // evolving) vs the root frozen at the cut.
  pure val PRE_ROOT: int = 1
  pure val TERM_ROOT: int = 2

  // Crossing epochs: the boundary instant counts as not yet crossed
  // (`EpochWindows::is_crossing`), so a stamp exactly on a window edge
  // belongs to the earlier window. Defined for wt >= 1.
  pure def crossEpoch(w: int): int = (w - 1) / E_LEN
  // Anchor floors use plain window containment (`epoch_for`).
  pure def floorStart(w: int): int = (w / E_LEN) * E_LEN

  // Per child: the last folded crossing's stamp (0 = chain start).
  var lastWtL: int
  var lastWtR: int
  // The state root on the child's lingering boundary record.
  var rootL: int
  var rootR: int
  // `terminal_qc_wt` on the record (0 = none).
  var termWtL: int
  var termWtR: int
  // Ground truth: the stamp of the genuine past-cut terminal crossing
  // (0 = none) — independent of how the judgment rule evolves.
  var trueTermWtL: int
  var trueTermWtR: int
  // Served stamps for the left terminal (canonical + coast re-certs).
  var servedL: Set[int]
  // The composed parent anchor.
  var composed: bool
  var compRootL: int
  var compRootR: int
  var compCut: int
  // Keeper flips: adopted cut per keeper.
  var k1: bool
  var kCut1: int
  var k2: bool
  var kCut2: int

  action init = all {
    lastWtL' = 0, lastWtR' = 0,
    rootL' = PRE_ROOT, rootR' = PRE_ROOT,
    termWtL' = 0, termWtR' = 0,
    trueTermWtL' = 0, trueTermWtR' = 0,
    servedL' = Set(),
    composed' = false, compRootL' = 0, compRootR' = 0, compCut' = 0,
    k1' = false, kCut1' = 0,
    k2' = false, kCut2' = 0,
  }

  // The epoch a crossing from `prev` lands in, with chain start below
  // every window.
  pure def prevEpoch(prev: int): int =
    if (prev == 0) -1 else crossEpoch(prev)

  // The left chain folds a boundary crossing at stamp w. The record
  // takes the crossing's root — frozen only once genuinely past the
  // cut — and the terminal judgment stamps or clears `terminal_qc_wt`
  // (`carried_terminal_marks` recomputes marks per contribution). The
  // chain stops after its genuine terminal crossing.
  action crossL = {
    nondet w = 1.to(MAX_WT).oneOf()
    val crossed = crossEpoch(w)
    val genuine = crossed > T_CUT
    val judged = if (BOUNDARY_INSTANT) crossed >= T_CUT else crossed > T_CUT
    all {
      w > lastWtL,
      crossed > prevEpoch(lastWtL),
      prevEpoch(lastWtL) <= T_CUT,
      lastWtL' = w,
      rootL' = if (genuine) TERM_ROOT else PRE_ROOT,
      termWtL' = if (judged) w else 0,
      trueTermWtL' = if (genuine) w else trueTermWtL,
      servedL' = if (judged) Set(w) else servedL,
      lastWtR' = lastWtR, rootR' = rootR, termWtR' = termWtR,
      trueTermWtR' = trueTermWtR,
      composed' = composed, compRootL' = compRootL,
      compRootR' = compRootR, compCut' = compCut,
      k1' = k1, kCut1' = kCut1, k2' = k2, kCut2' = kCut2,
    }
  }

  action crossR = {
    nondet w = 1.to(MAX_WT).oneOf()
    val crossed = crossEpoch(w)
    val genuine = crossed > T_CUT
    val judged = if (BOUNDARY_INSTANT) crossed >= T_CUT else crossed > T_CUT
    all {
      w > lastWtR,
      crossed > prevEpoch(lastWtR),
      prevEpoch(lastWtR) <= T_CUT,
      lastWtR' = w,
      rootR' = if (genuine) TERM_ROOT else PRE_ROOT,
      termWtR' = if (judged) w else 0,
      trueTermWtR' = if (genuine) w else trueTermWtR,
      lastWtL' = lastWtL, rootL' = rootL, termWtL' = termWtL,
      trueTermWtL' = trueTermWtL, servedL' = servedL,
      composed' = composed, compRootL' = compRootL,
      compRootR' = compRootR, compCut' = compCut,
      k1' = k1, kCut1' = kCut1, k2' = k2, kCut2' = kCut2,
    }
  }

  // The left coast re-certifies its terminal at a later stamp —
  // possibly across an epoch edge, where a re-derived floor diverges.
  action recertL = {
    nondet w = 1.to(MAX_WT).oneOf()
    all {
      termWtL != 0,
      w > termWtL,
      servedL' = servedL.union(Set(w)),
      lastWtL' = lastWtL, lastWtR' = lastWtR,
      rootL' = rootL, rootR' = rootR,
      termWtL' = termWtL, termWtR' = termWtR,
      trueTermWtL' = trueTermWtL, trueTermWtR' = trueTermWtR,
      composed' = composed, compRootL' = compRootL,
      compRootR' = compRootR, compCut' = compCut,
      k1' = k1, kCut1' = kCut1, k2' = k2, kCut2' = kCut2,
    }
  }

  // The fold composes the parent anchor from the two lingering child
  // records: root pair as recorded, cut floored from the left record's
  // `terminal_qc_wt`. Shipped gate: both records carry the mark and
  // the parent is still a placeholder (once-only). The twin composes
  // on the left mark alone.
  action compose = all {
    not(composed),
    termWtL != 0,
    EAGER_COMPOSE or termWtR != 0,
    composed' = true,
    compRootL' = rootL,
    compRootR' = rootR,
    compCut' = floorStart(termWtL),
    lastWtL' = lastWtL, lastWtR' = lastWtR,
    rootL' = rootL, rootR' = rootR,
    termWtL' = termWtL, termWtR' = termWtR,
    trueTermWtL' = trueTermWtL, trueTermWtR' = trueTermWtR,
    servedL' = servedL,
    k1' = k1, kCut1' = kCut1, k2' = k2, kCut2' = kCut2,
  }

  // A keeper completes the flip. Shipped: the cut is read back from
  // the composed anchor (reconstruction hash-checked, passing by
  // construction). Twin: the keeper floors its served left QC.
  action adoptK1 = {
    nondet sw = 1.to(MAX_WT).oneOf()
    all {
      composed,
      not(k1),
      servedL.contains(sw),
      k1' = true,
      kCut1' = if (REFLOOR) floorStart(sw) else compCut,
      lastWtL' = lastWtL, lastWtR' = lastWtR,
      rootL' = rootL, rootR' = rootR,
      termWtL' = termWtL, termWtR' = termWtR,
      trueTermWtL' = trueTermWtL, trueTermWtR' = trueTermWtR,
      servedL' = servedL,
      composed' = composed, compRootL' = compRootL,
      compRootR' = compRootR, compCut' = compCut,
      k2' = k2, kCut2' = kCut2,
    }
  }

  action adoptK2 = {
    nondet sw = 1.to(MAX_WT).oneOf()
    all {
      composed,
      not(k2),
      servedL.contains(sw),
      k2' = true,
      kCut2' = if (REFLOOR) floorStart(sw) else compCut,
      lastWtL' = lastWtL, lastWtR' = lastWtR,
      rootL' = rootL, rootR' = rootR,
      termWtL' = termWtL, termWtR' = termWtR,
      trueTermWtL' = trueTermWtL, trueTermWtR' = trueTermWtR,
      servedL' = servedL,
      composed' = composed, compRootL' = compRootL,
      compRootR' = compRootR, compCut' = compCut,
      k1' = k1, kCut1' = kCut1,
    }
  }

  action step = any {
    crossL,
    crossR,
    recertL,
    compose,
    adoptK1,
    adoptK2,
  }

  // ── Invariants ──

  // A terminal-marked record has genuinely crossed its cut and carries
  // the frozen terminal root — never the final window's pre-freeze
  // refresh.
  val invTerminalMarkSound = and {
    termWtL != 0 implies (rootL == TERM_ROOT and termWtL == trueTermWtL),
    termWtR != 0 implies (rootR == TERM_ROOT and termWtR == trueTermWtR),
  }

  // The composed anchor is the frozen terminal pair, its cut the epoch
  // start of the genuine left terminal stamp (INV-RESHAPE-3/4).
  val invComposedAnchor =
    composed implies and {
      compRootL == TERM_ROOT,
      compRootR == TERM_ROOT,
      trueTermWtL != 0,
      compCut == floorStart(trueTermWtL),
    }

  // Every keeper's adopted cut is the anchor's (INV-RESHAPE-2/4).
  val invKeeperReadback = and {
    k1 implies kCut1 == compCut,
    k2 implies kCut2 == compCut,
  }

  val invAll = and {
    invTerminalMarkSound,
    invComposedAnchor,
    invKeeperReadback,
  }
}

module canonical_pick {
  // Broken twin: the pick compares weighted timestamps alone — a tie
  // keeps the first-seen entry, so the result depends on iteration
  // order. False is the shipped `(wt, hash)` lexicographic rule.
  const WT_ONLY: bool

  // Candidate boundary QCs as (weighted timestamp, block hash): a
  // stamp tie between distinct blocks plus a lower straggler.
  pure val CANDS: Set[(int, int)] = Set((5, 1), (5, 2), (3, 3))

  pure def better(c: (int, int), b: (int, int)): bool =
    if (WT_ONLY) c._1 > b._1
    else c._1 > b._1 or (c._1 == b._1 and c._2 > b._2)

  // Two consumers of the same committed proposal set — assembler and
  // verifier — each folding the candidates in their own order.
  var rem1: Set[(int, int)]
  var best1: (int, int)
  var rem2: Set[(int, int)]
  var best2: (int, int)

  action init = all {
    rem1' = CANDS,
    best1' = (0, 0),
    rem2' = CANDS,
    best2' = (0, 0),
  }

  action proc1 = {
    nondet c = rem1.oneOf()
    all {
      rem1 != Set(),
      rem1' = rem1.exclude(Set(c)),
      best1' = if (better(c, best1)) c else best1,
      rem2' = rem2, best2' = best2,
    }
  }

  action proc2 = {
    nondet c = rem2.oneOf()
    all {
      rem2 != Set(),
      rem2' = rem2.exclude(Set(c)),
      best2' = if (better(c, best2)) c else best2,
      rem1' = rem1, best1' = best1,
    }
  }

  // Both folds complete; the pick is final (stutter past the barrier).
  action settled = all {
    rem1 == Set(),
    rem2 == Set(),
    rem1' = rem1, best1' = best1,
    rem2' = rem2, best2' = best2,
  }

  action step = any { proc1, proc2, settled }

  // Both consumers, having folded every candidate, bound the same
  // canonical QC (INV-BEACON-5).
  val invPickTotal =
    (rem1 == Set() and rem2 == Set()) implies best1 == best2
}

module split_handoff_ok {
  import split_handoff(
    HORIZON = 1, MAX_EPOCH = 4, MAX_WT = 4,
    SERVED_CLOCK = false, UNCHECKED_SEED = false, GC_HORIZON_ONLY = false
  ).*
}

module split_handoff_served_clock {
  import split_handoff(
    HORIZON = 1, MAX_EPOCH = 4, MAX_WT = 4,
    SERVED_CLOCK = true, UNCHECKED_SEED = false, GC_HORIZON_ONLY = false
  ).*
}

module split_handoff_unchecked_seed {
  import split_handoff(
    HORIZON = 1, MAX_EPOCH = 4, MAX_WT = 4,
    SERVED_CLOCK = false, UNCHECKED_SEED = true, GC_HORIZON_ONLY = false
  ).*
}

module split_handoff_horizon_gc {
  import split_handoff(
    HORIZON = 1, MAX_EPOCH = 4, MAX_WT = 4,
    SERVED_CLOCK = false, UNCHECKED_SEED = false, GC_HORIZON_ONLY = true
  ).*
}

module merge_handoff_ok {
  import merge_handoff(
    E_LEN = 3, T_CUT = 1, MAX_WT = 10,
    EAGER_COMPOSE = false, BOUNDARY_INSTANT = false, REFLOOR = false
  ).*
}

module merge_handoff_eager_compose {
  import merge_handoff(
    E_LEN = 3, T_CUT = 1, MAX_WT = 10,
    EAGER_COMPOSE = true, BOUNDARY_INSTANT = false, REFLOOR = false
  ).*
}

module merge_handoff_boundary_instant {
  import merge_handoff(
    E_LEN = 3, T_CUT = 1, MAX_WT = 10,
    EAGER_COMPOSE = false, BOUNDARY_INSTANT = true, REFLOOR = false
  ).*
}

module merge_handoff_refloor {
  import merge_handoff(
    E_LEN = 3, T_CUT = 1, MAX_WT = 10,
    EAGER_COMPOSE = false, BOUNDARY_INSTANT = false, REFLOOR = true
  ).*
}

module canonical_pick_ok {
  import canonical_pick(WT_ONLY = false).*
}

module canonical_pick_wt_only {
  import canonical_pick(WT_ONLY = true).*
}
