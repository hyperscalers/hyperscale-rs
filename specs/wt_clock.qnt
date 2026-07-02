// Model A (register: specs/README.md) — the weighted-time clock and its
// epoch-resolution soundness.
//
// Models one shard chain's QC weighted timestamps under Byzantine voters:
// per-vote clamp to the parent QC's timestamp, quorum averaging, and the
// plausibility check applied wherever a QC enters chain state
// (docs/01-consensus-layers.md §1.3, §4).
//
// Code anchors:
//   - Clamp and mean: crates/shard/src/vote_set.rs — per-vote clamp to the
//     parent WT at tally time, every vote weighs one, floor-division mean
//     over the vote count in `build_qc`.
//   - Admission bound: `qc_weighted_timestamp_too_far_ahead` in
//     crates/shard/src/validation.rs (MAX_TIMESTAMP_DELAY +
//     MAX_TIMESTAMP_RUSH, crates/types/src/time/limits.rs), applied at
//     header validation, local aggregation, synced-block admission, and
//     timeout high_qc adoption.
//   - Above-head resolution: `ScheduleLookup::NotYetCommitted` defers at
//     every consumer (crates/types/src/topology/schedule.rs); `Evicted`
//     rejects permanently.
//
// Properties (docs/08-invariants.md):
//   invMonotone  — WT never regresses along the chain (INV-SHARD-6).
//   invPlausible — every admitted WT is within DRIFT + BOUND of real time.
//   invLookahead — every admitted WT resolves to an epoch no later than
//                  epoch_for(now) + 1, i.e. within the L=1 frozen lookahead
//                  (INV-BEACON-3/4). This holds iff DRIFT + BOUND < EPOCH —
//                  the constant coupling this model exists to expose.
//
// Modeling assumptions:
//   - Crypto is ideal: a QC exists iff QUORUM votes were cast; at most F of
//     them Byzantine (INV-SEC-1 taken as premise).
//   - Honest clocks read within DRIFT of real time; Byzantine voters claim
//     anything (the clamp still floors them at the parent WT).
//   - Admission uses the most permissive honest replica: a QC enters chain
//     state if some honest clock (≤ now + DRIFT) accepts wt ≤ clock + BOUND.
//   - One chain, no re-certification: every QC here is the canonical
//     (committing-child) form of INV-SHARD-6.
//   - Votes are encoded as offsets from real time in a constant band ±OFF
//     (Apalache requires constant ranges). OFF is sized so that, at F = 1,
//     every reading that could survive admission is representable; Byzantine
//     readings even further below the band only lower the average, which
//     cannot affect these upper-bound invariants. Larger F needs a wider band.
//   - The mean is over exactly QUORUM votes. The implementation can tally
//     more before building (batch verification may land extras past 2f+1);
//     QUORUM is the worst case for the Byzantine fraction, and the admission
//     bound caps the reachable WT range identically either way.
//
// Run:
//   quint typecheck specs/wt_clock.qnt
//   quint run    --main=wt_clock_ok    --invariant=invAll       specs/wt_clock.qnt
//   quint verify --main=wt_clock_ok    --invariant=invAll       specs/wt_clock.qnt
//   quint verify --main=wt_clock_tight --invariant=invLookahead specs/wt_clock.qnt
//     (the tight instance violates DRIFT + BOUND < EPOCH; expect a counterexample)

module wt_clock {
  // Byzantine tolerance: committee 3F+1, quorum 2F+1.
  const F: int
  // Max distance of an honest clock from real time, either direction.
  const DRIFT: int
  // Plausibility bound: a replica rejects a QC whose wt exceeds its own clock + BOUND.
  const BOUND: int
  // Epoch duration; epochs are half-open WT windows.
  const EPOCH: int
  // Max real-time advance per step (keeps runs interesting, not a protocol constant).
  const MAX_TICK: int

  pure val QUORUM = 2 * F + 1
  // Offset band for vote readings relative to real time. At F = 1 the highest
  // reading that can survive admission is now + QUORUM*(DRIFT+BOUND) + (QUORUM-1)*DRIFT
  // (all co-voters honest at their floor), which this band covers.
  pure val OFF = QUORUM * (DRIFT + BOUND) + (QUORUM - 1) * DRIFT

  pure def max2(a: int, b: int): int = if (a > b) a else b
  pure def epochFor(wt: int): int = wt / EPOCH

  // Real time.
  var now: int
  // Admitted QC weighted timestamps, genesis first.
  var chain: List[int]

  action init = all {
    now' = 0,
    chain' = List(0),
  }

  action tick = {
    nondet d = 1.to(MAX_TICK).oneOf()
    all {
      now' = now + d,
      chain' = chain,
    }
  }

  // Form a QC on the chain head from QUORUM votes, at most F of them cast
  // by a nondeterministically chosen Byzantine subset.
  action formQc = {
    val parent = chain[chain.length() - 1]
    nondet byz = 1.to(QUORUM).powerset().oneOf()
    nondet offs = 1.to(QUORUM).setOfMaps((-OFF).to(OFF)).oneOf()
    // The per-vote clamp: no reading below the parent QC's timestamp.
    val wt = 1.to(QUORUM).fold(0, (acc, i) => acc + max2(parent, now + offs.get(i))) / QUORUM
    all {
      byz.size() <= F,
      // Honest votes read their own clock, within DRIFT of real time.
      1.to(QUORUM).forall(i => byz.contains(i) or (offs.get(i) >= -DRIFT and offs.get(i) <= DRIFT)),
      // Admission: plausible to at least one honest replica.
      wt <= now + DRIFT + BOUND,
      chain' = chain.append(wt),
      now' = now,
    }
  }

  action step = any { tick, formQc }

  // INV-SHARD-6: weighted time is monotone along the chain.
  val invMonotone = 1.to(chain.length() - 1).forall(i => chain[i - 1] <= chain[i])

  // Byzantine skew is bounded: no admitted WT outruns real time by more than
  // DRIFT + BOUND (holds at admission; now only grows afterwards).
  val invPlausible = chain.indices().forall(i => chain[i] <= now + DRIFT + BOUND)

  // INV-BEACON-3/4 soundness: every admitted artifact resolves within the
  // L=1 lookahead — no verifier ever needs a committee the beacon has not
  // yet frozen. Requires DRIFT + BOUND < EPOCH.
  val invLookahead = chain.indices().forall(i => epochFor(chain[i]) <= epochFor(now) + 1)

  val invAll = invMonotone and invPlausible and invLookahead
}

// Healthy configuration: DRIFT + BOUND = 5 < EPOCH = 10.
module wt_clock_ok {
  import wt_clock(F = 1, DRIFT = 2, BOUND = 3, EPOCH = 10, MAX_TICK = 4).*
}

// Broken configuration: DRIFT + BOUND = 5 >= EPOCH = 4, so a Byzantine-skewed
// QC can land two epochs ahead of real time — outside the frozen lookahead.
module wt_clock_tight {
  import wt_clock(F = 1, DRIFT = 2, BOUND = 3, EPOCH = 4, MAX_TICK = 4).*
}
