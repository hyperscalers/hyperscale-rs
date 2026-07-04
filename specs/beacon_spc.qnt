// Model E (register: specs/README.md) — beacon consensus, checked for
// INV-BEACON-1 (one block per epoch): the inner prefix-consensus (PC)
// value algebra, the pool-ratified commit path, and the two-path twin
// whose dual commit shows why both outcomes must ride one pool quorum.
//
// Three modules:
//
//   `beacon_pc` — the three-round PC value pipeline: the Prefix Consensus
//   protocol of Xiang/Tonkikh/Spiegelman, "Prefix Consensus For Censorship
//   Resistant BFT" (arXiv:2602.02892), Algorithm 1. The invariants are the
//   paper's properties for it: Upper Bound (every decided low is a prefix
//   of every decided high — Definition 2.2), low/high pairwise consistency
//   (Corollary 2.3, Definition 8.1), and Validity (the honest inputs'
//   common prefix survives into every decided low). Together they are the
//   agreement core behind INV-BEACON-1: the SPC commit walk cannot resolve
//   conflicting values. Twins: the two-round variant — the paper's
//   Algorithm 7, sound only at n >= 5f+1, run here at n = 3f+1, where
//   Theorem 4.1 proves two rounds cannot work (docs/01 §3.1's equivocation
//   window, mechanized) — and the eager-feed instance (divergent honest
//   inputs collapse the committed low to empty while every proposal is
//   pooled somewhere; the collapse violates none of the paper's properties
//   — Validity is vacuous on divergent inputs — which is why the shipped
//   feed gate demands full coverage, whose non-collapse property the
//   `beacon_pc_full` instance pins).
//
//   `beacon_epoch` — the two-path twin: SPC cert and pool skip cert as
//   independent commits. Its quorums need not intersect, and
//   `poolQuorumFork` reaches the dual commit with zero Byzantine
//   signatures once the pool outgrows the committee — the geometry
//   ratification exists to close. Checks INV-BEACON-1 across the paths
//   with PC agreement as an oracle (at most one Normal block value
//   exists).
//
//   `beacon_epoch_ratified` — the shipped design: the pool is the
//   single quorum system for both outcomes, so any two commit
//   certificates intersect in an honest member at every
//   pool-to-committee ratio. Ratification is two-phase with locks —
//   single-shot Tendermint over the two values — because a
//   single-phase pool vote is safe only under a strict
//   one-vote-per-epoch register, which wedges the epoch when a
//   late-arriving block splits honest votes near the skip deadline, and
//   every recovery that re-votes without lock discipline re-opens the
//   fork (the DIRECT_COMMIT twin).
//
// Code anchors:
//   - Prefix algebra: crates/types/src/beacon/prefix_ops.rs — `mcp`,
//     `mce`, `qc1_certify` (deepest prefix extended by >= f+1 votes;
//     unique per depth by counting).
//   - Round pipeline: crates/beacon/src/pc.rs — `PcInstance` pools one
//     vote per validator per round (`quorum() = n - byzantine_threshold`),
//     aggregates at quorum; crates/types/src/beacon/pc.rs —
//     `build_qc1/2/3` (x = qc1_certify of v_ins; x_p = mcp of vote-2 xs;
//     x_pp/x_pe = mcp/mce of vote-3 x_ps).
//   - Verifier constraints carried into the model as guards: a vote-2's
//     x must equal its embedded QC1's x (`PcQc1VerifyError::CertifyMismatch`,
//     `PcVote2VerifyError::XMismatch`); a vote-3's x_p must equal its
//     embedded QC2's x_p; a QC3's per-signer lengths must sit in
//     [|x_pp|, |x_pe|] with the aggregate signature over x_pe prefixes —
//     so a formable QC3 forces its vote family pairwise consistent.
//   - View-1 input: crates/beacon/src/coordinator.rs
//     `on_spc_input_dwell_timer` / `feed_view_one_input` — the positional
//     proposal-hash vector, fed at full coverage with a bounded dwell
//     fallback to partial.
//   - Ratification: crates/beacon/src/ratify.rs (`RatifyTracker` —
//     registers, polka detection, locks, cert assembly);
//     crates/types/src/beacon/ratify.rs (`RatifyVote`, `RatifyCert`,
//     `ratify_quorum`); crates/beacon/src/coordinator.rs
//     `assemble_and_broadcast_candidate` / `on_beacon_ratify_timer` /
//     `commit_ratified_block`, with `on_beacon_block_received`
//     admission only at tip + 1 and terminal adoption.
//
// Modeling assumptions:
//   - Crypto is ideal: certificates exist iff the vote sets they claim
//     exist; the verifier-forced structural identities above are guards.
//   - Byzantine validators are the fixed set 1..F and sign anything the
//     verifiers would accept, any number of times (per-aggregator
//     equivocation is free); honest validators sign at most one vote per
//     round, and their round-1 vote equals their input vector.
//   - Vote casting and QC formation fold into single actions (Model B's
//     encoding); honest round-2/3 vote content is over-approximated as
//     any certified value of the previous round (the implementation picks
//     the first quorum it assembles — a subset of these behaviors).
//   - Input vectors carry two positions over a three-value alphabet
//     (0 = BOTTOM, 1/2 = proposal hashes) — a scoped-down positional
//     vector; the prefix algebra is length-generic.
//   - One epoch, static pool. The implementation derives the pool per
//     tip (`derive_active_pool`, crates/types/src/beacon/state.rs): the
//     beacon-eligible serving set — ready on a live chain, reshape-fold
//     seats excluded until their chain seeds — so every candidate
//     outcome at one tip shares one signer base, which is the model's
//     POOL. Cross-epoch replay is out of scope: votes bind
//     (anchor, epoch), and chained-epoch mechanization is deferred.
//   - One PC instance. SPC view sequencing, indirect certificates
//     (paper Lemmas A.3-A.5), and the commit-walk parent resolution are
//     deferred to a revision, as is PC liveness. The implementation's
//     walk (`resolve_parent`, crates/beacon/src/spc.rs) carries the
//     paper's Parent semantics (Algorithm 3 line 1): only a value's
//     FIRST non-bottom entry resolves, and a missing preimage defers
//     the walk until the proposal object arrives — resolution is a
//     function of the value, which is the unique-chain premise of the
//     paper's Agreement argument (Lemma A.7) the revision mechanizes.
//
// Run:
//   quint typecheck specs/beacon_spc.qnt
//   quint run    --main=beacon_pc_ok    --invariant=invAll --max-samples=50 --max-steps=8 specs/beacon_spc.qnt
//     (the per-step nondet map spaces make random simulation slow —
//      Apalache is the effective tier for this model)
//   quint verify --main=beacon_pc_ok    --invariant=invAll --max-steps=8 specs/beacon_spc.qnt
//   quint verify --main=beacon_pc_full  --invariant=invLowIsFull --max-steps=8 specs/beacon_spc.qnt
//   quint test   --main=beacon_pc_eager --match=eagerCollapse specs/beacon_spc.qnt
//   quint verify --main=beacon_pc_eager --invariant=invLowNonEmpty --max-steps=6 specs/beacon_spc.qnt
//     (counterexample: the prefix collapse — divergent inputs
//      commit empty)
//   quint test   --main=beacon_pc_two_round --match=equivocationWindow specs/beacon_spc.qnt
//   quint verify --main=beacon_pc_two_round --invariant=invDecisionsConsistent --max-steps=5 specs/beacon_spc.qnt
//     (counterexample: round-1 equivocation forks the decided highs)
//   quint test   --main=beacon_epoch_dual --match=dualPathFork specs/beacon_spc.qnt
//   quint verify --main=beacon_epoch_dual --invariant=invOneBlock --max-steps=5 specs/beacon_spc.qnt
//     (counterexample: Normal and Skip both commit for one epoch —
//      no Byzantine signer required, only asymmetric delivery)
//   quint verify --main=beacon_epoch_exclusive --invariant=invOneBlock --max-steps=8 specs/beacon_spc.qnt
//     (holds: sign-path mutual exclusion restores safety at
//      pool == committee)
//   quint test   --main=beacon_epoch_exclusive_pool --match=poolQuorumFork specs/beacon_spc.qnt
//     (mutual exclusion is insufficient once the pool outgrows the
//      committee — the skip quorum forms without any committee overlap)
//   quint verify --main=beacon_epoch_ratified_pool --invariant=invAll --max-steps=6 specs/beacon_spc.qnt
//     (holds: pool-quorum ratification of both paths closes
//      the dual commit at the exact geometry that refutes sign-path
//      exclusion. Depth 6 is this size's fork horizon, not a guess:
//      the DIRECT_COMMIT twin's dual commit lands within 6 steps at
//      the same pool of 12, and each batched action is a whole
//      protocol phase — a full attack shape is ~5 phases. Depth 7+
//      is intractable here; the deeper depth-8 sweeps run on the
//      smaller instances below)
//   quint verify --main=beacon_epoch_ratified_committee --invariant=invAll --max-steps=8 specs/beacon_spc.qnt
//     (holds: parity with beacon_epoch_exclusive at
//      pool == committee)
//   quint test   --main=beacon_epoch_ratified_pool --match="poolQuorumSettles|splitVoteConverges" specs/beacon_spc.qnt
//   quint test   --main=beacon_epoch_ratified_relock --match=relockConverges specs/beacon_spc.qnt
//   quint verify --main=beacon_epoch_ratified_relock --invariant=invAll --max-steps=7 specs/beacon_spc.qnt
//     (holds: leaving a lock for a strictly newer polka
//      preserves safety — the subtlest honest rule, at the smallest
//      pool where it can fire. Depth 7 covers the rule: the shortest
//      dual cert a broken re-lock admits is five phases, and the
//      three-round exploit shape is seven; step 8 is intractable)
//   quint test   --main=beacon_epoch_ratified_direct --match=directRevoteFork specs/beacon_spc.qnt
//   quint verify --main=beacon_epoch_ratified_direct --invariant=invOneBlock --max-steps=6 specs/beacon_spc.qnt
//     (counterexample: single-phase ratification with re-vote recovery
//      re-opens the fork)

module beacon_pc {
  // Byzantine tolerance: committee 3F+1, quorum 2F+1 (= n - f).
  const F: int
  // Three-round pipeline (the shipped protocol) vs the two-round twin
  // (decide at QC2, no round-3 mutual-extension certification).
  const THREE_ROUND: bool
  // Vectors an honest validator may hold as its view input.
  const INPUT_VECS: Set[List[int]]

  pure val N = 3 * F + 1
  pure val QUORUM = 2 * F + 1
  pure val COMMITTEE = 1.to(N)
  pure val BYZ = 1.to(F)
  pure val HONEST = (F + 1).to(N)

  type Vec = List[int]

  // Alphabet: 0 = BOTTOM (no proposal pooled for the slot), 1/2 = the
  // two slots' proposal hashes. All vectors of length <= 2.
  pure val ELEMS = Set(0, 1, 2)
  pure val VECS0: Set[Vec] = Set(List())
  pure val VECS1 = ELEMS.map(a => [a])
  pure val VECS2 = tuples(ELEMS, ELEMS).map(t => [t._1, t._2])
  pure val ALL_VECS = VECS0.union(VECS1).union(VECS2)
  // The full-coverage input: every slot carries its proposal.
  pure val vFull: Vec = [1, 2]

  pure def isPrefix(p: Vec, v: Vec): bool =
    p.length() <= v.length() and p.indices().forall(i => p[i] == v[i])

  pure def consistent(a: Vec, b: Vec): bool =
    isPrefix(a, b) or isPrefix(b, a)

  // Longest element of a set in which the maximum is unique (common
  // prefixes form a chain; certify candidates are unique per depth by
  // the f+1 counting argument) — the fold order cannot matter.
  pure def maxByLength(s: Set[Vec]): Vec =
    s.fold(List(), (acc, v) => if (v.length() > acc.length()) v else acc)

  // `qc1_certify`: the deepest prefix extended by >= F+1 of the quorum's
  // votes. The empty vector always qualifies, so the result is defined.
  pure def certify(m: int -> Vec, q: Set[int]): Vec =
    maxByLength(ALL_VECS.filter(p =>
      q.filter(v => isPrefix(p, m.get(v))).size() >= F + 1))

  // `mcp` over a set of vectors.
  pure def mcpOf(s: Set[Vec]): Vec =
    maxByLength(ALL_VECS.filter(p => s.forall(v => isPrefix(p, v))))

  // Honest validators' view-input vectors (round-1 vote content).
  var inputs: int -> Vec
  // Round-1 QC values: every certified x.
  var certified1: Set[Vec]
  // Honest round-2 votes: content (meaningful on voted2) and the
  // one-vote-per-round latch.
  var x2: int -> Vec
  var voted2: Set[int]
  // Round-2 QC values: every certified x_p.
  var certified2: Set[Vec]
  // Honest round-3 votes.
  var x3: int -> Vec
  var voted3: Set[int]
  // Decided (low, high) pairs across all aggregators.
  var decisions: Set[{ lo: Vec, hi: Vec }]

  action initWith(m: int -> Vec): bool = all {
    inputs' = m,
    certified1' = Set(),
    x2' = COMMITTEE.mapBy(v => List()),
    voted2' = Set(),
    certified2' = Set(),
    x3' = COMMITTEE.mapBy(v => List()),
    voted3' = Set(),
    decisions' = Set(),
  }

  action init = {
    nondet m = COMMITTEE.setOfMaps(INPUT_VECS).oneOf()
    initWith(m)
  }

  // Core semantics, parameterized so the nondet wrappers and the
  // scripted runs share one definition. Maps passed by scripted runs
  // need only cover the quorum they name.

  // A round-1 quorum aggregates into a QC1. Honest members' votes are
  // their input vectors (the FSM signs v_in exactly once; Input is
  // idempotent); Byzantine members sign anything, differently per
  // aggregator.
  action formQc1As(q: Set[int], m: int -> Vec): bool = all {
    q.subseteq(COMMITTEE),
    q.size() == QUORUM,
    q.forall(v => BYZ.contains(v) or m.get(v) == inputs.get(v)),
    certified1' = certified1.union(Set(certify(m, q))),
    inputs' = inputs, x2' = x2, voted2' = voted2, certified2' = certified2,
    x3' = x3, voted3' = voted3, decisions' = decisions,
  }

  action formQc1 = {
    nondet q = COMMITTEE.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    formQc1As(q, m)
  }

  // Honest validators cast their round-2 votes: each picks a certified
  // round-1 value (the verifier rejects a vote-2 whose x is not its
  // embedded QC1's x), at most once. Batched: any unvoted subset votes
  // in one step — each singleton batch is an interleaving, so batching
  // loses no reachable assignment.
  action castVote2As(s: Set[int], m: int -> Vec): bool = all {
    s.subseteq(HONEST),
    s.size() > 0,
    s.intersect(voted2).size() == 0,
    s.forall(v => certified1.contains(m.get(v))),
    voted2' = voted2.union(s),
    x2' = COMMITTEE.mapBy(v => if (s.contains(v)) m.get(v) else x2.get(v)),
    inputs' = inputs, certified1' = certified1, certified2' = certified2,
    x3' = x3, voted3' = voted3, decisions' = decisions,
  }

  action castVote2 = {
    nondet s = HONEST.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    castVote2As(s, m)
  }

  // A round-2 quorum aggregates into a QC2: x_p = mcp of the votes' xs.
  // Byzantine votes still carry certified round-1 values (the verifier
  // checks the embedded QC1).
  action formQc2As(q: Set[int], m: int -> Vec): bool = all {
    THREE_ROUND,
    q.subseteq(COMMITTEE),
    q.size() == QUORUM,
    q.forall(v =>
      if (BYZ.contains(v)) certified1.contains(m.get(v))
      else voted2.contains(v) and m.get(v) == x2.get(v)),
    certified2' = certified2.union(Set(mcpOf(q.map(v => m.get(v))))),
    inputs' = inputs, certified1' = certified1, x2' = x2, voted2' = voted2,
    x3' = x3, voted3' = voted3, decisions' = decisions,
  }

  action formQc2 = {
    nondet q = COMMITTEE.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    formQc2As(q, m)
  }

  // Honest round-3 votes over certified round-2 values.
  action castVote3As(s: Set[int], m: int -> Vec): bool = all {
    THREE_ROUND,
    s.subseteq(HONEST),
    s.size() > 0,
    s.intersect(voted3).size() == 0,
    s.forall(v => certified2.contains(m.get(v))),
    voted3' = voted3.union(s),
    x3' = COMMITTEE.mapBy(v => if (s.contains(v)) m.get(v) else x3.get(v)),
    inputs' = inputs, certified1' = certified1, x2' = x2, voted2' = voted2,
    certified2' = certified2, decisions' = decisions,
  }

  action castVote3 = {
    nondet s = HONEST.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    castVote3As(s, m)
  }

  // A round-3 quorum decides (x_pp, x_pe) = (mcp, mce) of the votes'
  // x_ps. The pairwise-consistency guard is verifier-forced: the QC3
  // aggregate signature covers each signer's x_pe prefix at its claimed
  // length, so an inconsistent family has no valid certificate.
  action formQc3As(q: Set[int], m: int -> Vec): bool = all {
    THREE_ROUND,
    q.subseteq(COMMITTEE),
    q.size() == QUORUM,
    q.forall(v =>
      if (BYZ.contains(v)) certified2.contains(m.get(v))
      else voted3.contains(v) and m.get(v) == x3.get(v)),
    val xs = q.map(v => m.get(v))
    all {
      xs.forall(a => xs.forall(b => consistent(a, b))),
      decisions' = decisions.union(Set({ lo: mcpOf(xs), hi: maxByLength(xs) })),
    },
    inputs' = inputs, certified1' = certified1, x2' = x2, voted2' = voted2,
    certified2' = certified2, x3' = x3, voted3' = voted3,
  }

  action formQc3 = {
    nondet q = COMMITTEE.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    formQc3As(q, m)
  }

  // The two-round twin: decide directly at QC2. Without the round-3
  // mutual-extension certification there is no certificate binding the
  // high to a consistent family — the aggregator reports some maximal
  // element of the votes' xs, which need not be consistent across
  // aggregators (round-1 equivocation certifies conflicting xs).
  action decide2As(q: Set[int], m: int -> Vec, hi: Vec): bool = all {
    not(THREE_ROUND),
    q.subseteq(COMMITTEE),
    q.size() == QUORUM,
    q.forall(v =>
      if (BYZ.contains(v)) certified1.contains(m.get(v))
      else voted2.contains(v) and m.get(v) == x2.get(v)),
    val xs = q.map(v => m.get(v))
    all {
      xs.contains(hi),
      xs.forall(y => not(isPrefix(hi, y) and y.length() > hi.length())),
      decisions' = decisions.union(Set({ lo: mcpOf(xs), hi: hi })),
    },
    inputs' = inputs, certified1' = certified1, x2' = x2, voted2' = voted2,
    certified2' = certified2, x3' = x3, voted3' = voted3,
  }

  action decide2 = {
    nondet q = COMMITTEE.powerset().oneOf()
    nondet m = COMMITTEE.setOfMaps(ALL_VECS).oneOf()
    nondet hi = ALL_VECS.oneOf()
    decide2As(q, m, hi)
  }

  action step = any { formQc1, castVote2, formQc2, castVote3, formQc3, decide2 }

  // The paper's Prefix Consensus properties, over all decisions from all
  // aggregators. Upper Bound (Definition 2.2): every decided low is a
  // prefix — directed, not merely consistent — of every decided high.
  // Low/high pairwise consistency are the paper's Corollary 2.3 and the
  // Consistency property of Definition 8.1. Together they are what the
  // SPC commit walk needs: consistent vectors that both carry a
  // non-bottom element share their first one, so the walk resolves one
  // parent.
  val invDecisionsConsistent = decisions.forall(d1 => decisions.forall(d2 => all {
    isPrefix(d1.lo, d2.hi),
    consistent(d1.lo, d2.lo),
    consistent(d1.hi, d2.hi),
  }))

  // Validity (Definition 2.2): the honest inputs' maximum common prefix
  // survives into every decided low — the censorship-resistance core.
  val invValidity = {
    val vh = mcpOf(HONEST.map(v => inputs.get(v)))
    decisions.forall(d => isPrefix(vh, d.lo))
  }

  // Certified round-2 values are pairwise consistent (the paper's
  // Lemma 3.1: two vote-2 quorums share an honest signer whose single x
  // bounds both mcps).
  val invCertified2Consistent =
    certified2.forall(a => certified2.forall(b => consistent(a, b)))

  val invAll = invDecisionsConsistent and invValidity and invCertified2Consistent

  // Non-collapse: no decided low is the empty vector. Holds under
  // full-coverage inputs; the eager-feed instance reaches an empty
  // committed low from a 2-2 input split (the empty-PcVector commit).
  val invLowNonEmpty = decisions.forall(d => d.lo.length() > 0)

  // Under full coverage every decision is exactly the full vector: the
  // property the input-feed gate buys.
  val invLowIsFull = decisions.forall(d => d.lo == vFull and d.hi == vFull)

  // The prefix collapse, scripted: honest inputs split 2-2 at slot 0
  // (the Byzantine seat votes with the first camp). Both camps' full
  // vectors certify at round 1 from different quorums; any round-2
  // quorum mixes the camps, so its mcp — and the decided low — is empty.
  run eagerCollapse = {
    initWith(Map(1 -> [1, 2], 2 -> [1, 2], 3 -> [0, 2], 4 -> [0, 2]))
      .then(formQc1As(Set(1, 2, 3), Map(1 -> [1, 2], 2 -> [1, 2], 3 -> [0, 2])))
      .then(formQc1As(Set(2, 3, 4), Map(2 -> [1, 2], 3 -> [0, 2], 4 -> [0, 2])))
      .then(castVote2As(Set(2, 3, 4), Map(2 -> [1, 2], 3 -> [0, 2], 4 -> [0, 2])))
      .then(formQc2As(Set(2, 3, 4), Map(2 -> [1, 2], 3 -> [0, 2], 4 -> [0, 2])))
      .then(castVote3As(Set(2, 3, 4), Map(2 -> List(), 3 -> List(), 4 -> List())))
      .then(formQc3As(Set(2, 3, 4), Map(2 -> List(), 3 -> List(), 4 -> List())))
      .expect(not(invLowNonEmpty))
  }

  // The equivocation window, scripted (two-round instances only): the
  // Byzantine seat signs [1,0] toward one round-1 quorum and [1,2]
  // toward another, certifying two conflicting xs; two QC2-level
  // decisions then report conflicting highs. Round 3 closes exactly
  // this: no QC3 can bind an inconsistent family.
  run equivocationWindow = {
    initWith(Map(1 -> [1, 0], 2 -> [1, 0], 3 -> [1, 2], 4 -> [1, 2]))
      .then(formQc1As(Set(1, 2, 3), Map(1 -> [1, 0], 2 -> [1, 0], 3 -> [1, 2])))
      .then(formQc1As(Set(1, 3, 4), Map(1 -> [1, 2], 3 -> [1, 2], 4 -> [1, 2])))
      .then(castVote2As(Set(2, 3, 4), Map(2 -> [1, 0], 3 -> [1, 2], 4 -> [1, 2])))
      .then(decide2As(Set(1, 2, 3), Map(1 -> [1, 0], 2 -> [1, 0], 3 -> [1, 2]), [1, 0]))
      .then(decide2As(Set(1, 3, 4), Map(1 -> [1, 2], 3 -> [1, 2], 4 -> [1, 2]), [1, 2]))
      .expect(not(invDecisionsConsistent))
  }
}

// Healthy: the shipped three-round pipeline under arbitrary honest
// inputs (any per-slot coverage, including divergent pools from a
// proposal equivocation). The consistency core must hold regardless of
// coverage — only non-collapse depends on the feed gate.
module beacon_pc_ok {
  import beacon_pc(
    F = 1,
    THREE_ROUND = true,
    INPUT_VECS = Set([0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2], [2, 0], [2, 1], [2, 2])
  ).*
}

// Full-coverage feed: every honest input is the complete positional
// vector (the gate `feed_view_one_input` waits for). Decisions collapse
// to exactly the full vector.
module beacon_pc_full {
  import beacon_pc(F = 1, THREE_ROUND = true, INPUT_VECS = Set([1, 2])).*
}

// Eager feed: honest inputs may hold BOTTOM per slot (fed at quorum
// coverage, or past the dwell cap). Consistency still holds; the
// non-collapse property does not — the committed low reaches empty.
module beacon_pc_eager {
  import beacon_pc(
    F = 1,
    THREE_ROUND = true,
    INPUT_VECS = Set([1, 2], [1, 0], [0, 2], [0, 0])
  ).*
}

// Two-round twin: decide at QC2 — the paper's Algorithm 7, which is
// sound only at n >= 5f+1, run at n = 3f+1. Round-1 equivocation
// certifies conflicting values and the decided highs fork; the paper's
// Theorem 4.1 proves no two-round protocol can avoid this at n <= 4f.
module beacon_pc_two_round {
  import beacon_pc(
    F = 1,
    THREE_ROUND = false,
    INPUT_VECS = Set([1, 2], [1, 0], [0, 2], [0, 0])
  ).*
}

// ─────────────────────────────────────────────────────────────────────────

module beacon_epoch {
  // Committee 3F+1 with BYZ = 1..F; the pool adds POOL_EXTRA honest
  // non-committee members.
  const F: int
  const POOL_EXTRA: int
  // Sign-path exclusion: an honest validator signs at most one of the
  // two paths per epoch. Instances with EXCLUSIVE = false drop it.
  const EXCLUSIVE: bool

  pure val N = 3 * F + 1
  pure val QUORUM = 2 * F + 1
  pure val COMMITTEE = 1.to(N)
  pure val BYZ = 1.to(F)
  pure val POOL = 1.to(N + POOL_EXTRA)
  pure val HONEST_POOL = POOL.exclude(BYZ)
  // Skip-cert quorum: ceil(2P/3) + 1 over the active pool.
  pure val SKIP_QUORUM = (2 * (N + POOL_EXTRA) + 2) / 3 + 1

  pure val NONE = 0
  pure val NORMAL = 1
  pure val SKIP = 2

  // Committee members whose signatures back the epoch's SPC certificate
  // (all three PC rounds abstracted into participation; PC agreement is
  // the oracle from `beacon_pc`, so at most one Normal block exists).
  var spcSigners: Set[int]
  // Pool members whose SkipRequests back the skip certificate.
  var skipSigners: Set[int]
  // Per-replica adopted block for the epoch. Adoption is terminal:
  // a block at or below the tip is dropped on receipt.
  var adopted: int -> int

  val spcCert = spcSigners.size() >= QUORUM
  val skipCert = skipSigners.size() >= SKIP_QUORUM

  action init = all {
    spcSigners' = Set(),
    skipSigners' = Set(),
    adopted' = POOL.mapBy(v => NONE),
  }

  // Committee members sign the SPC path. An honest member participates
  // only while its epoch is open (no adopted block).
  action signSpcBy(s: Set[int]): bool = all {
    s.subseteq(COMMITTEE),
    s.size() > 0,
    s.forall(v => BYZ.contains(v) or all {
      adopted.get(v) == NONE,
      not(EXCLUSIVE) or not(skipSigners.contains(v)),
    }),
    spcSigners' = spcSigners.union(s),
    skipSigners' = skipSigners,
    adopted' = adopted,
  }

  action signSpc = {
    nondet s = COMMITTEE.powerset().oneOf()
    signSpcBy(s)
  }

  // Pool members sign SkipRequests. An honest member signs only while
  // the expected block hasn't arrived (`on_beacon_skip_timer` re-checks
  // the deadline against the current tip) — under asynchrony that is
  // any time before its own adoption.
  action signSkipBy(s: Set[int]): bool = all {
    s.subseteq(POOL),
    s.size() > 0,
    s.forall(v => BYZ.contains(v) or all {
      adopted.get(v) == NONE,
      not(EXCLUSIVE) or not(spcSigners.contains(v)),
    }),
    skipSigners' = skipSigners.union(s),
    spcSigners' = spcSigners,
    adopted' = adopted,
  }

  action signSkip = {
    nondet s = POOL.powerset().oneOf()
    signSkipBy(s)
  }

  // First verified block at tip + 1 wins; the other path's block is
  // dropped as at-or-below-tip on every later receipt.
  action adoptNormalBy(v: int): bool = all {
    HONEST_POOL.contains(v),
    spcCert,
    adopted.get(v) == NONE,
    adopted' = adopted.put(v, NORMAL),
    spcSigners' = spcSigners,
    skipSigners' = skipSigners,
  }

  action adoptSkipBy(v: int): bool = all {
    HONEST_POOL.contains(v),
    skipCert,
    adopted.get(v) == NONE,
    adopted' = adopted.put(v, SKIP),
    spcSigners' = spcSigners,
    skipSigners' = skipSigners,
  }

  action adoptNormal = {
    nondet v = HONEST_POOL.oneOf()
    adoptNormalBy(v)
  }

  action adoptSkip = {
    nondet v = HONEST_POOL.oneOf()
    adoptSkipBy(v)
  }

  action step = any { signSpc, signSkip, adoptNormal, adoptSkip }

  // INV-BEACON-1 across the two commit paths: no two honest replicas
  // hold different blocks for the epoch.
  val invOneBlock = not(HONEST_POOL.exists(a => HONEST_POOL.exists(b => all {
    adopted.get(a) == NORMAL,
    adopted.get(b) == SKIP,
  })))

  // The dual-path fork, scripted, with zero Byzantine signatures used:
  // the committee quorum certifies the Normal block; before it reaches
  // the rest of the pool, the pool's skip quorum forms (every signer
  // honestly reports the block missing); one replica verifies Normal
  // first, another Skip first. Both chains extend from there — receipt
  // of the other block drops at-or-below-tip.
  run dualPathFork = {
    init
      .then(signSpcBy(Set(2, 3, 4)))
      .then(signSkipBy(Set(1, 2, 3, 4)))
      .then(adoptNormalBy(2))
      .then(adoptSkipBy(3))
      .expect(not(invOneBlock))
  }

  // Sign-path exclusion cannot help once the pool outgrows the
  // committee: the skip quorum forms entirely from pool members outside
  // the committee (plus the Byzantine seat), disjoint from the SPC
  // quorum by construction.
  run poolQuorumFork = {
    init
      .then(signSpcBy(Set(1, 2, 3)))
      .then(signSkipBy(Set(1, 5, 6, 7, 8, 9, 10, 11, 12)))
      .then(adoptNormalBy(2))
      .then(adoptSkipBy(5))
      .expect(not(invOneBlock))
  }
}

// The twin without the sign-path exclusion: both certificates form and
// adoption is first-verified-wins — honest replicas fork the beacon
// chain at the epoch without a single Byzantine signature.
module beacon_epoch_dual {
  import beacon_epoch(F = 1, POOL_EXTRA = 0, EXCLUSIVE = false).*
}

// Sign-path exclusion at pool == committee: the two quorums intersect
// in an honest signer, so both certificates cannot form.
module beacon_epoch_exclusive {
  import beacon_epoch(F = 1, POOL_EXTRA = 0, EXCLUSIVE = true).*
}

// Sign-path exclusion with a pool of 12 over a committee of 4: the
// skip quorum (9) forms without touching the SPC quorum, and the fork
// returns — the exclusion shrinks the window, it does not close it;
// the geometry ratification closes.
module beacon_epoch_exclusive_pool {
  import beacon_epoch(F = 1, POOL_EXTRA = 8, EXCLUSIVE = true).*
}

// ─────────────────────────────────────────────────────────────────────────

module beacon_epoch_ratified {
  // The pool is the single quorum system for BOTH outcomes. The
  // committee's SPC certificate is a proposal certificate, not a
  // commit; a block — Normal or Skip — commits only through a pool
  // ratification certificate, so any two commit quorums intersect in
  // more than P/3 members, an honest one among them, whatever the
  // pool-to-committee ratio. Skip keeps its role (a dead committee
  // produces no SPC cert and the pool ratifies Skip unaided), and the
  // committee loses unilateral commit authority (a fully Byzantine
  // committee draw can certify proposals, never commit them).
  //
  // Ratification is two-phase with locks — single-shot Tendermint over
  // the two values: a prevote quorum (polka) gates precommits, a
  // precommit quorum commits, and precommitting locks the member; a
  // later round may leave a lock only toward a value with a strictly
  // newer polka. The phases are not ceremony. A single-phase pool vote
  // is safe only under a strict one-vote-per-epoch register, and that
  // wedges the epoch whenever a block arriving near the skip deadline
  // splits honest votes below both quorums — nobody may vote again.
  // Every recovery that re-votes without lock discipline re-opens the
  // fork: the DIRECT_COMMIT twin commits Skip in round 1 and "recovers"
  // into a Normal commit in round 2.
  const F: int
  const POOL_EXTRA: int
  // Rounds available to the ratification instance.
  const MAX_ROUND: int
  // Twin switch: commit at a bare prevote quorum — single-phase, no
  // precommits, no locks — the naive re-vote recovery design.
  const DIRECT_COMMIT: bool

  pure val N = 3 * F + 1
  pure val QUORUM = 2 * F + 1
  pure val COMMITTEE = 1.to(N)
  pure val BYZ = 1.to(F)
  pure val POOL = 1.to(N + POOL_EXTRA)
  pure val HONEST_POOL = POOL.exclude(BYZ)
  // The standard BFT quorum (`ratify_quorum`,
  // crates/types/src/beacon/ratify.rs): 2f+1 at pool 3f+1 — any two
  // quorums share an honest signer while tolerating f unresponsive
  // members. At the pool of 12 this is 9, matching the two-path twin's
  // skip threshold at that size.
  pure val POOL_QUORUM = (N + POOL_EXTRA) - (N + POOL_EXTRA - 1) / 3
  pure val ROUNDS = 1.to(MAX_ROUND)

  pure val NONE = 0
  pure val NORMAL = 1
  pure val SKIP = 2
  pure val VALUES = Set(NORMAL, SKIP)

  // Committee members backing the epoch's SPC certificate — a proposal
  // certificate here, not a commit. PC agreement is the oracle: at
  // most one Normal block value exists.
  var spcSigners: Set[int]
  // Honest ratification votes, one per member per round per phase.
  // Byzantine signatures never appear as records: every quorum check
  // adds F wildcards — "every Byzantine seat countersigns every
  // aggregate", at least as strong as any concrete Byzantine schedule.
  var prevotes: Set[{ m: int, r: int, v: int }]
  var precommits: Set[{ m: int, r: int, v: int }]
  // Highest-round precommit per honest member (v = NONE, r = 0 while
  // unlocked).
  var locks: int -> { v: int, r: int }
  // Honest members' current round — votes never go backwards. Without
  // this the model reaches states no real execution has (a member
  // prevoting round 1 after acting in round 2), and those states fork.
  var roundOf: int -> int
  // Per-replica adopted block for the epoch; adoption is terminal.
  var adopted: int -> int

  val spcCert = spcSigners.size() >= QUORUM

  def prevoteQuorum(r: int, v: int): bool =
    prevotes.filter(p => p.r == r and p.v == v).size() + F >= POOL_QUORUM

  def precommitQuorum(r: int, v: int): bool =
    precommits.filter(p => p.r == r and p.v == v).size() + F >= POOL_QUORUM

  // The commit rule: a pool ratification certificate for `v`.
  def committed(v: int): bool =
    if (DIRECT_COMMIT) ROUNDS.exists(r => prevoteQuorum(r, v))
    else ROUNDS.exists(r => precommitQuorum(r, v))

  action init = all {
    spcSigners' = Set(),
    prevotes' = Set(),
    precommits' = Set(),
    locks' = HONEST_POOL.mapBy(m => { v: NONE, r: 0 }),
    roundOf' = HONEST_POOL.mapBy(m => 1),
    adopted' = POOL.mapBy(m => NONE),
  }

  // Committee members sign the SPC path — unconditionally: with the
  // pool certificate as the commit rule, nothing about safety rides on
  // who signs the proposal certificate.
  action signSpcBy(s: Set[int]): bool = all {
    s.subseteq(COMMITTEE),
    s.size() > 0,
    spcSigners' = spcSigners.union(s),
    prevotes' = prevotes, precommits' = precommits, locks' = locks,
    roundOf' = roundOf, adopted' = adopted,
  }

  action signSpc = {
    nondet s = COMMITTEE.powerset().oneOf()
    signSpcBy(s)
  }

  // Honest members prevote `v` in round `r`: NORMAL only once the
  // SPC-certified block exists to have been received, SKIP any time
  // (the local skip deadline or round timeout — free under asynchrony).
  // A locked member prevotes its lock, unless a strictly newer polka
  // backs the other value (the re-lock rule liveness needs).
  action castPrevotesAs(s: Set[int], r: int, v: int): bool = all {
    s.subseteq(HONEST_POOL),
    s.size() > 0,
    ROUNDS.contains(r),
    VALUES.contains(v),
    v == SKIP or spcCert,
    s.forall(m => all {
      roundOf.get(m) <= r,
      not(prevotes.exists(p => p.m == m and p.r == r)),
      or {
        locks.get(m).v == NONE,
        locks.get(m).v == v,
        ROUNDS.exists(rp => locks.get(m).r < rp and rp < r and prevoteQuorum(rp, v)),
      },
    }),
    prevotes' = prevotes.union(s.map(m => { m: m, r: r, v: v })),
    roundOf' = HONEST_POOL.mapBy(m => if (s.contains(m)) r else roundOf.get(m)),
    spcSigners' = spcSigners, precommits' = precommits, locks' = locks,
    adopted' = adopted,
  }

  action castPrevotes = {
    nondet s = HONEST_POOL.powerset().oneOf()
    nondet r = ROUNDS.oneOf()
    nondet v = VALUES.oneOf()
    castPrevotesAs(s, r, v)
  }

  // Honest members precommit `v` in round `r` upon its polka, locking
  // themselves to it: a precommit is a signed commit-share, and once it
  // exists its signer must assume a certificate may assemble around it.
  action castPrecommitsAs(s: Set[int], r: int, v: int): bool = all {
    not(DIRECT_COMMIT),
    s.subseteq(HONEST_POOL),
    s.size() > 0,
    ROUNDS.contains(r),
    VALUES.contains(v),
    prevoteQuorum(r, v),
    s.forall(m => all {
      roundOf.get(m) <= r,
      not(precommits.exists(p => p.m == m and p.r == r)),
    }),
    precommits' = precommits.union(s.map(m => { m: m, r: r, v: v })),
    locks' = HONEST_POOL.mapBy(m =>
      if (s.contains(m) and r > locks.get(m).r) { v: v, r: r } else locks.get(m)),
    roundOf' = HONEST_POOL.mapBy(m => if (s.contains(m)) r else roundOf.get(m)),
    spcSigners' = spcSigners, prevotes' = prevotes, adopted' = adopted,
  }

  action castPrecommits = {
    nondet s = HONEST_POOL.powerset().oneOf()
    nondet r = ROUNDS.oneOf()
    nondet v = VALUES.oneOf()
    castPrecommitsAs(s, r, v)
  }

  // Adoption follows certificates. A member that once precommitted the
  // other value still adopts what committed — locks discipline votes,
  // not adoption.
  action adoptNormalBy(m: int): bool = all {
    HONEST_POOL.contains(m),
    spcCert,
    committed(NORMAL),
    adopted.get(m) == NONE,
    adopted' = adopted.put(m, NORMAL),
    spcSigners' = spcSigners, prevotes' = prevotes, precommits' = precommits,
    locks' = locks, roundOf' = roundOf,
  }

  action adoptSkipBy(m: int): bool = all {
    HONEST_POOL.contains(m),
    committed(SKIP),
    adopted.get(m) == NONE,
    adopted' = adopted.put(m, SKIP),
    spcSigners' = spcSigners, prevotes' = prevotes, precommits' = precommits,
    locks' = locks, roundOf' = roundOf,
  }

  action adoptNormal = {
    nondet m = HONEST_POOL.oneOf()
    adoptNormalBy(m)
  }

  action adoptSkip = {
    nondet m = HONEST_POOL.oneOf()
    adoptSkipBy(m)
  }

  action step = any { signSpc, castPrevotes, castPrecommits, adoptNormal, adoptSkip }

  // INV-BEACON-1: no two honest replicas hold different blocks for the
  // epoch.
  val invOneBlock = not(HONEST_POOL.exists(a => HONEST_POOL.exists(b => all {
    adopted.get(a) == NORMAL,
    adopted.get(b) == SKIP,
  })))

  // The certificate-level core: the two ratification certificates
  // cannot coexist. Two pool quorums share honest members; within a
  // round each votes once, and across rounds the lock rule pins them.
  val invOneCert = not(committed(NORMAL) and committed(SKIP))

  val invAll = invOneBlock and invOneCert

  // The two-path twin's pool-quorum fork, replayed against
  // ratification (pool 12, quorum 9, Byzantine seat 1): the SPC quorum
  // {1,2,3} certifies the proposal; the far side of the partition
  // prevotes SKIP and ratifies it without touching the committee — and
  // that is now the epoch's ONLY commit. The near side's NORMAL
  // prevotes stall below quorum, Normal is unadoptable, and the
  // minority syncs the skip block on heal instead of forking.
  run poolQuorumSettles = {
    init
      .then(signSpcBy(Set(1, 2, 3)))
      .then(castPrevotesAs(Set(5, 6, 7, 8, 9, 10, 11, 12), 1, SKIP))
      .then(castPrecommitsAs(Set(5, 6, 7, 8, 9, 10, 11, 12), 1, SKIP))
      .then(adoptSkipBy(5))
      .then(castPrevotesAs(Set(2, 3, 4), 1, NORMAL))
      .expect(committed(SKIP) and not(committed(NORMAL)) and invOneBlock)
  }

  // A block arriving at the skip deadline splits round 1 below both
  // quorums — the case a strict one-vote-per-epoch register wedges on.
  // Round 2 converges: no polka formed, so nobody precommitted, nobody
  // is locked, and the pool re-prevotes freely and ratifies Normal.
  run splitVoteConverges = {
    init
      .then(signSpcBy(Set(2, 3, 4)))
      .then(castPrevotesAs(Set(2, 3, 4, 5, 6, 7), 1, NORMAL))
      .then(castPrevotesAs(Set(8, 9, 10, 11, 12), 1, SKIP))
      .then(castPrevotesAs(Set(2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), 2, NORMAL))
      .then(castPrecommitsAs(Set(2, 3, 4, 5, 6, 7, 8, 9), 2, NORMAL))
      .then(adoptNormalBy(2))
      .then(adoptNormalBy(12))
      .expect(committed(NORMAL) and not(committed(SKIP)) and invOneBlock)
  }

  // A partial round-1 lock on Normal (one member precommits on the
  // polka; no certificate forms) must not wedge the epoch after the
  // rest of the pool moves on: the round-2 SKIP polka is strictly newer
  // than the round-1 lock, so the locked member leaves it in round 3
  // and the pool ratifies Skip. Sized for the relock instance (pool 7,
  // quorum 5, MAX_ROUND = 3).
  run relockConverges = {
    init
      .then(signSpcBy(Set(1, 2, 3)))
      .then(castPrevotesAs(Set(2, 3, 4, 5, 6), 1, NORMAL))
      .then(castPrecommitsAs(Set(2), 1, NORMAL))
      .then(castPrevotesAs(Set(3, 4, 5, 6, 7), 2, SKIP))
      .then(castPrevotesAs(Set(2), 3, SKIP))
      .then(castPrevotesAs(Set(3, 4, 5, 6, 7), 3, SKIP))
      .then(castPrecommitsAs(Set(2, 3, 4, 5, 6), 3, SKIP))
      .then(adoptSkipBy(2))
      .expect(committed(SKIP) and not(committed(NORMAL)) and invOneBlock)
  }

  // The naive recovery, mechanized: single-phase ratification (commit
  // at a bare prevote quorum) with re-voting across rounds. The
  // partitioned side ratifies Skip in round 1; the SPC block then
  // surfaces and round 2 "recovers" by re-voting Normal — both
  // certificates exist and the fork is back. Locks are the escape from
  // the register-wedges-or-revote-forks dilemma, which is what the
  // second phase is for.
  run directRevoteFork = {
    init
      .then(signSpcBy(Set(1, 2, 3)))
      .then(castPrevotesAs(Set(5, 6, 7, 8, 9, 10, 11, 12), 1, SKIP))
      .then(adoptSkipBy(5))
      .then(castPrevotesAs(Set(2, 3, 4, 5, 6, 7, 8, 9), 2, NORMAL))
      .then(adoptNormalBy(2))
      .expect(not(invOneBlock))
  }
}

// Ratification at the exact geometry that refutes sign-path exclusion
// (pool 12 over committee 4 — beacon_epoch_exclusive_pool's
// configuration): both paths commit through the pool quorum and the
// dual commit is closed, whatever the delivery order.
module beacon_epoch_ratified_pool {
  import beacon_epoch_ratified(F = 1, POOL_EXTRA = 8, MAX_ROUND = 2, DIRECT_COMMIT = false).*
}

// Three rounds: enough for a lock to form AND be left behind (lock at
// round 1, newer polka at round 2, re-prevote at round 3) — the
// re-lock rule's full reach. The pool shrinks to 7 (quorum 5),
// keeping the extra round verifiable; the fork geometry needs no
// third round and stays with the pool-of-12 instances.
module beacon_epoch_ratified_relock {
  import beacon_epoch_ratified(F = 1, POOL_EXTRA = 3, MAX_ROUND = 3, DIRECT_COMMIT = false).*
}

// Pool == committee parity with `beacon_epoch_exclusive`.
module beacon_epoch_ratified_committee {
  import beacon_epoch_ratified(F = 1, POOL_EXTRA = 0, MAX_ROUND = 2, DIRECT_COMMIT = false).*
}

// The single-phase twin: commits at a bare prevote quorum, so nobody
// ever locks, and cross-round re-voting — any recovery from a split —
// re-opens the dual commit.
module beacon_epoch_ratified_direct {
  import beacon_epoch_ratified(F = 1, POOL_EXTRA = 8, MAX_ROUND = 2, DIRECT_COMMIT = true).*
}
