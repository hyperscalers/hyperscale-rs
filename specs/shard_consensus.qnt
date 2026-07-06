// Model B (register: specs/README.md) — shard consensus safety: the
// HotStuff-2 safe-vote rule and the round-contiguous two-chain commit.
//
// Checks INV-SHARD-1 (no two committed blocks off one chain) with
// INV-SHARD-2/3/4 encoded structurally (see assumptions). The healthy
// instance's never-reset registers are the implementation's durable
// ones (docs/01-consensus-layers.md §1.2); the broken twin
// (`ALLOW_CRASH = true`) models their loss: recovery from the highest
// known QC alone reopens rounds the validator already consumed.
//
// Code anchors (crates/shard/src/coordinator.rs):
//   - Safe-vote predicate: `can_safe_vote` — round strictly beyond
//     `last_voted_round`, parent QC at or above `locked_round`. (The
//     round == current-view condition is dropped here: view binding only
//     restricts behaviors, so omitting it is safety-sound and removes the
//     pacemaker from the model.)
//   - Vote ratchet: `try_vote_on_block` — `last_voted_round = round;
//     locked_round = locked_round.max(parent_qc_round)`. The lock rises
//     only at vote time; QC adoption does not ratchet it.
//   - Timeout ratchet: `broadcast_timeout` path —
//     `last_voted_round = last_voted_round.max(round)`.
//   - Commit rule: `try_two_chain_commit` — a QC at exactly
//     `parent.round + 1` commits its parent; non-contiguous QCs defer.
//   - Crash re-init (broken twin): both registers fall back to the
//     highest known QC's round — the implementation's floor when no
//     durable record survives (`ShardCoordinator::new`); genesis
//     (registers at zero) when none is known.
//
// Modeling assumptions:
//   - Crypto is ideal: a QC for block `b` exists iff a set of >= 2f+1
//     distinct validators cast votes for `b` (one seat, one vote).
//   - Byzantine validators are the fixed set 1..F (a symmetry reduction:
//     validators are interchangeable) and vote without any guard.
//   - Vote casting and QC formation fold into one `certify` action: the
//     action guards are exactly the safe-vote predicate (INV-SHARD-2/3),
//     and the register ratchets apply to the honest voters it names.
//     Individual vote messages are not materialized.
//   - Proposals are unconstrained: any block extending any formed QC may
//     appear, at most one block per (round, tag) with TAGS competitors per
//     round. This over-approximates every proposer behavior, honest or
//     equivocating — safety must not depend on who proposes.
//   - QCs are canonical: a block is certified at its own round, once.
//     Re-certification at higher rounds (reshape coast) is out of scope,
//     as in Model A.
//
// Run:
//   quint typecheck specs/shard_consensus.qnt
//   quint run    --main=shard_ok    --invariant=invNoFork specs/shard_consensus.qnt
//   quint verify --main=shard_ok    --invariant=invNoFork --max-steps=8 specs/shard_consensus.qnt
//     (per-step cost grows steeply past depth 8)
//   quint test   --main=shard_crash --match=crashForkAttack specs/shard_consensus.qnt
//     (the scripted 9-step crash-equivocation witness: one crash + F
//      Byzantine forks the commit)
//   quint verify --main=shard_crash --invariant=invNoFork --max-steps=9 specs/shard_consensus.qnt
//     (Apalache finds the same fork by search; slower than the scripted run)

module shard_consensus {
  // Byzantine tolerance: committee 3F+1, quorum 2F+1.
  const F: int
  // Highest round the model explores (Apalache needs constant ranges).
  const MAX_ROUND: int
  // Distinct competing blocks allowed per round.
  const TAGS: int
  // Enables the crash-recovery action (the register-persistence gap).
  const ALLOW_CRASH: bool

  pure val N = 3 * F + 1
  pure val QUORUM = 2 * F + 1
  pure val VALIDATORS = 1.to(N)
  pure val BYZ = 1.to(F)
  pure val HONEST = (F + 1).to(N)

  pure def max2(a: int, b: int): int = if (a > b) a else b

  // A block: its (round, tag) identity plus the (round, tag) of the block
  // whose QC it extends. `prnd` doubles as the parent QC's round, since a
  // canonical QC certifies a block at the block's own round.
  type Block = { rnd: int, tag: int, prnd: int, ptag: int }

  pure val GENESIS: Block = { rnd: 0, tag: 0, prnd: -1, ptag: 0 }

  // All blocks ever proposed. One block per (rnd, tag) — enforced at
  // proposal — so a (rnd, tag) pair is an unambiguous parent reference.
  var blocks: Set[Block]
  // Blocks whose QC has formed. Genesis's QC is the bootstrap.
  var qcs: Set[Block]
  // Per-validator safe-vote registers (meaningful for honest members only).
  var lastVoted: int -> int
  var locked: int -> int
  // Ghost ancestry: {a, d} means `a` is an ancestor of (or equal to) `d`.
  // Maintained incrementally at proposal so the no-fork invariant is a
  // membership test — a recursive climb inside the invariant is what blows
  // up the SMT encoding.
  var anc: Set[{ a: Block, d: Block }]

  action init = all {
    blocks' = Set(GENESIS),
    qcs' = Set(GENESIS),
    lastVoted' = VALIDATORS.mapBy(v => 0),
    locked' = VALIDATORS.mapBy(v => 0),
    anc' = Set({ a: GENESIS, d: GENESIS }),
  }

  // Core semantics, parameterized so the nondet wrappers below and the
  // scripted attack runs share one definition.

  action proposeAs(parent: Block, r: int, t: int): bool = {
    val nb = { rnd: r, tag: t, prnd: parent.rnd, ptag: parent.tag }
    all {
      qcs.contains(parent),
      r > parent.rnd,
      blocks.forall(x => not(x.rnd == r and x.tag == t)),
      blocks' = blocks.union(Set(nb)),
      anc' = anc
        .union(anc.filter(pr => pr.d == parent).map(pr => { a: pr.a, d: nb }))
        .union(Set({ a: nb, d: nb })),
      qcs' = qcs,
      lastVoted' = lastVoted,
      locked' = locked,
    }
  }

  // Any block extending any certified parent may appear, from anyone.
  action propose = {
    nondet parent = qcs.oneOf()
    nondet r = 1.to(MAX_ROUND).oneOf()
    nondet t = 1.to(TAGS).oneOf()
    proposeAs(parent, r, t)
  }

  // A quorum certifies block `b`. Honest members of the quorum pass the
  // safe-vote predicate and ratchet their registers; Byzantine members are
  // unconstrained. This is vote casting + aggregation in one step.
  action certifyBy(b: Block, voters: Set[int]): bool = {
    all {
      blocks.contains(b),
      not(qcs.contains(b)),
      b.rnd > 0,
      voters.size() >= QUORUM,
      voters.forall(v =>
        BYZ.contains(v) or
        (b.rnd > lastVoted.get(v) and b.prnd >= locked.get(v))
      ),
      qcs' = qcs.union(Set(b)),
      lastVoted' = VALIDATORS.mapBy(v =>
        if (voters.contains(v) and HONEST.contains(v)) b.rnd else lastVoted.get(v)),
      locked' = VALIDATORS.mapBy(v =>
        if (voters.contains(v) and HONEST.contains(v)) max2(locked.get(v), b.prnd)
        else locked.get(v)),
      blocks' = blocks,
      anc' = anc,
    }
  }

  action certify = {
    nondet b = blocks.oneOf()
    nondet voters = VALIDATORS.powerset().oneOf()
    certifyBy(b, voters)
  }

  // Timing out a round consumes it: `last_voted_round` ratchets without a
  // vote, so the round can never be voted afterwards.
  action timeout = {
    nondet v = HONEST.oneOf()
    nondet r = 1.to(MAX_ROUND).oneOf()
    all {
      lastVoted' = lastVoted.setBy(v, old => max2(old, r)),
      locked' = locked,
      blocks' = blocks,
      qcs' = qcs,
      anc' = anc,
    }
  }

  // Crash and recover with the durable register record lost: both
  // registers re-initialize from the highest QC the validator has
  // persisted — which may trail what it voted. Genesis models the
  // fresh-start path (registers at zero).
  action crashAs(v: int, q: Block): bool = all {
    ALLOW_CRASH,
    HONEST.contains(v),
    qcs.contains(q),
    lastVoted' = lastVoted.put(v, q.rnd),
    locked' = locked.put(v, q.rnd),
    blocks' = blocks,
    qcs' = qcs,
    anc' = anc,
  }

  action crash = {
    nondet v = HONEST.oneOf()
    nondet q = qcs.oneOf()
    crashAs(v, q)
  }

  action step = any { propose, certify, timeout, crash }

  // Round-contiguous two-chain: a QC at exactly rnd + 1 commits its parent.
  // Prefix commits are subsumed: an ancestor of a committed block commits
  // with it, and ancestors are chain-ordered by construction.
  val directCommitted = blocks.filter(b =>
    qcs.exists(c => c.prnd == b.rnd and c.ptag == b.tag and c.rnd == b.rnd + 1))

  // INV-SHARD-1: all committed blocks lie on one chain.
  val invNoFork = directCommitted.forall(x =>
    directCommitted.forall(y =>
      anc.contains({ a: x, d: y }) or anc.contains({ a: y, d: x })))

  // The crash-equivocation window, scripted (crash instances only): chain 1
  // commits b1 through validators {1,2,3}; validator 2 crashes and recovers
  // from the genesis QC (registers to zero); the Byzantine validator 1, the
  // recovered 2, and the fresh 4 then assemble a second committed chain.
  // One crash plus F Byzantine forks the commit — the cost of losing
  // the registers.
  run crashForkAttack = {
    val b1 = { rnd: 1, tag: 1, prnd: 0, ptag: 0 }
    val c1 = { rnd: 2, tag: 1, prnd: 1, ptag: 1 }
    val b2 = { rnd: 2, tag: 2, prnd: 0, ptag: 0 }
    val c2 = { rnd: 3, tag: 1, prnd: 2, ptag: 2 }
    init
      .then(proposeAs(GENESIS, 1, 1))
      .then(certifyBy(b1, Set(1, 2, 3)))
      .then(proposeAs(b1, 2, 1))
      .then(certifyBy(c1, Set(1, 2, 3)))
      .then(crashAs(2, GENESIS))
      .then(proposeAs(GENESIS, 2, 2))
      .then(certifyBy(b2, Set(1, 2, 4)))
      .then(proposeAs(b2, 3, 1))
      .then(certifyBy(c2, Set(1, 2, 4)))
      .expect(not(invNoFork))
  }
}

// Healthy configuration: registers never reset; INV-SHARD-1 must hold.
module shard_ok {
  import shard_consensus(F = 1, MAX_ROUND = 3, TAGS = 2, ALLOW_CRASH = false).*
}

// Register loss enabled: one honest crash re-opens consumed rounds, and
// F Byzantine plus the crashed validator can assemble quorums on two
// branches — the regression witness for the durable safe-vote registers.
module shard_crash {
  import shard_consensus(F = 1, MAX_ROUND = 3, TAGS = 2, ALLOW_CRASH = true).*
}
