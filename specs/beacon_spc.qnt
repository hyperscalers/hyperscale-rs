// Model E (register: specs/README.md) — beacon consensus: the inner
// prefix-consensus (PC) value algebra, and the epoch's two commit paths
// (SPC certificate vs pool skip certificate).
//
// Two layers, two modules:
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
//   fix is the full-coverage feed gate, whose non-collapse property the
//   `beacon_pc_full` instance pins).
//
//   `beacon_epoch` — the two commit paths for one epoch, with PC agreement
//   as an oracle (at most one Normal block value exists). Checks
//   INV-BEACON-1 across the paths: no two honest replicas adopt different
//   blocks at the same epoch. The SPC cert is quorum-signed by the
//   committee; the skip cert by > 2/3 of the wider pool; adoption is
//   first-verified-wins at tip + 1 with no cross-path reconciliation
//   (a replica that verifies a competing block for its adopted epoch
//   halts — the implementation detects the fork loudly, which this
//   model treats identically to reaching the invariant violation). The
//   shipped honest rule is the EXCLUSIVE instance's: a round-3 vote and
//   a skip request are mutually exclusive per validator per epoch.
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
//   - Skip path: crates/beacon/src/skip_tracker.rs — pool quorum
//     `ceil(2P/3) + 1`; crates/beacon/src/coordinator.rs
//     `on_beacon_block_received` (admission only at tip + 1 with matching
//     prev hash; a block at or below the tip is dropped) and `adopt_block`
//     (no fork choice, no cross-path arbitration).
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
//     (~75s; the per-step nondet map spaces make random simulation slow —
//      Apalache is the effective tier for this model)
//   quint verify --main=beacon_pc_ok    --invariant=invAll --max-steps=8 specs/beacon_spc.qnt   (~15 min)
//   quint verify --main=beacon_pc_full  --invariant=invLowIsFull --max-steps=8 specs/beacon_spc.qnt   (~3 min)
//   quint test   --main=beacon_pc_eager --match=eagerCollapse specs/beacon_spc.qnt
//   quint verify --main=beacon_pc_eager --invariant=invLowNonEmpty --max-steps=6 specs/beacon_spc.qnt
//     (counterexample in ~21s: the prefix collapse — divergent inputs
//      commit empty)
//   quint test   --main=beacon_pc_two_round --match=equivocationWindow specs/beacon_spc.qnt
//   quint verify --main=beacon_pc_two_round --invariant=invDecisionsConsistent --max-steps=5 specs/beacon_spc.qnt
//     (counterexample in ~32s: round-1 equivocation forks the decided highs)
//   quint test   --main=beacon_epoch_dual --match=dualPathFork specs/beacon_spc.qnt
//   quint verify --main=beacon_epoch_dual --invariant=invOneBlock --max-steps=5 specs/beacon_spc.qnt
//     (counterexample in ~7s: Normal and Skip both commit for one epoch —
//      no Byzantine signer required, only asymmetric delivery)
//   quint verify --main=beacon_epoch_exclusive --invariant=invOneBlock --max-steps=8 specs/beacon_spc.qnt
//     (holds, ~20s: sign-path mutual exclusion restores safety at
//      pool == committee)
//   quint test   --main=beacon_epoch_exclusive_pool --match=poolQuorumFork specs/beacon_spc.qnt
//     (mutual exclusion is insufficient once the pool outgrows the
//      committee — the skip quorum forms without any committee overlap)

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
  // The shipped honest rule (coordinator vote-3 / skip-request
  // exclusion): an honest validator signs at most one of the two paths
  // per epoch. Instances with EXCLUSIVE = false are the twin without
  // it.
  const EXCLUSIVE: bool

  pure val N = 3 * F + 1
  pure val QUORUM = 2 * F + 1
  pure val COMMITTEE = 1.to(N)
  pure val BYZ = 1.to(F)
  pure val POOL = 1.to(N + POOL_EXTRA)
  pure val HONEST_POOL = POOL.exclude(BYZ)
  // skip_tracker quorum: ceil(2P/3) + 1 over the active pool.
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

// The shipped rule at pool == committee: mutual exclusion between the
// sign paths makes the two quorums intersect in an honest signer, so
// both certificates cannot form.
module beacon_epoch_exclusive {
  import beacon_epoch(F = 1, POOL_EXTRA = 0, EXCLUSIVE = true).*
}

// The shipped rule with a pool of 12 over a committee of 4: the skip
// quorum (9) forms without touching the SPC quorum, and the fork
// returns — the exclusion shrinks the window, it does not close it;
// the open finding, detected at contact by the halt.
module beacon_epoch_exclusive_pool {
  import beacon_epoch(F = 1, POOL_EXTRA = 8, EXCLUSIVE = true).*
}
