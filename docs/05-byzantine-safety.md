# Byzantine Safety

This document collects the system's defenses against adversarial validators and adversarial networks: the threat model, how committee honesty is maintained in a sharded setting (sampling, shuffling, jailing), the cryptographic layer, what one shard trusts about another, and the network-level hardening. Fork safety within a shard is treated in [01-consensus-layers.md](01-consensus-layers.md) §1; this document covers why its committee-level assumption is reasonable and everything around it.

Main code homes: committee sampling/shuffling and validator lifecycle in `crates/beacon` (fold modules), quorum math and signing types in `crates/types`, equivocation tracking and Byzantine input bounds in `crates/shard`, message classing in `crates/types` network module, fault injection in `crates/network` and `crates/scenarios`.

---

## 1. Threat model

**Per committee, classical BFT.** Every consensus decision — shard QC, execution certificate, beacon proposal certificate — is made by a committee of size n assuming at most f Byzantine members with n ≥ 3f+1. A beacon block additionally commits only through a ratification quorum of the whole serving pool, so a committee draw that lands fully Byzantine can certify content but never commit it ([01 §3.1](01-consensus-layers.md)). Quorums are strict >2/3 (`VoteCount::has_quorum`); voting power is per seat (one validator, one vote), with stake acting as an admission gate rather than as vote weight — a dynamic, demand-tracking minimum stake governs who may be in the pool at all ([06-resource-economics.md](06-resource-economics.md)). Byzantine members may equivocate, withhold, delay, collude, and time messages adversarially. The network is partially synchronous: safety never depends on timing; liveness resumes under eventual synchrony.

**Globally, an honest supermajority with bounded adaptivity.** Sharding changes the question from "is one committee honest" to "does *every* committee, drawn from a common pool, stay under f Byzantine". The defenses are statistical and procedural:

- **Unpredictable assignment.** Committees are sampled (`sample_committee`, pool draws) from beacon randomness — an accumulator re-mixed every epoch from VRF outputs carried in beacon proposals. Assignment for epoch e+1 is determined only at epoch e's fold, so an adversary cannot know placements far ahead. It *can*, however, bias the fold without any malformed material: a Byzantine beacon member reveals its (key-fixed) VRF output early or withholds it, toggling whether that output joins the seed, and with several such toggles enumerates `2^t` candidate seeds and steers the commit to the best one — a last-revealer grind, one-epoch-ahead and steerable, not merely observable. It is priced and dispositioned in [committee_security.md](../specs/committee_security.md) §10, where the two failure thresholds are defended differently: reaching f+1 corrupt halts the shard — a recoverable *liveness* outcome that a beacon-detected halt undoes by re-drawing the whole committee — while reaching 2f+1 is a *terminal*, unrecoverable compromise (unilateral control mints stake and cascades) with no after-the-fact containment, so its defense is entirely *preventing the march*: a small beacon committee, FIFO eviction, jail-on-first for withholding, a recency-weighted resample, and pool hygiene (β low) together hold a targeted shard below 2f+1 across the tolerated corruption band. (A uniform `id % num_shards` layout exists only as the static genesis/test bootstrap constructor.)
- **Continuous churn.** Membership never sits still (§2), so corrupting a specific shard's committee is a moving target: by the time a slowly-adaptive adversary corrupts members of shard S, rotation has replaced some of them.
- **Expulsion.** Provable misbehavior removes the offending identity from its committee on evidence — permanently for equivocation, for a cooldown for chronic liveness faults (§3). Removal, not confiscation: stake is never slashed.

The residual assumption — that random sampling from a <1/3-corrupt global pool yields <1/3-corrupt committees with overwhelming probability — is a function of committee size, and is the system's fundamental security parameter. It is stated explicitly as INV-SEC-1 in the invariant register because it is an *assumption* the deployment must size for, not a theorem the code enforces.

## 2. Shuffling

The beacon's fold rotates committee membership as a **trickle**: every `SHUFFLE_INTERVAL_EPOCHS`, each shard (skips aside) has one member rotated out and a replacement drawn from the pool.

Design points, each load-bearing:

- **Trickle, not reshuffle.** Wholesale re-assignment would be strongest against adaptive corruption but would force whole committees to re-sync state continuously. One-member-per-interval keeps every committee continuously above quorum with at most one syncing seat, while still fully turning committees over on a bounded timescale — liveness and adaptivity-resistance traded deliberately.
- **Deterministic victim selection** from domain-separated randomness (`DOMAIN_SHUFFLE_EXIT`, epoch, shard) over *ready* members only — rotating out a not-yet-ready member would be a no-op for security and a real cost to liveness.
- **Ordering prevents self-replacement.** The victim is removed, the replacement drawn, and only then is the victim's status flipped to pooled — so it cannot be drawn straight back into the seat it left (it can legitimately land in a different shard later in the same step).
- **Reshape-aware skips.** Shards with pending splits carry their members to their children; merge keepers are pinned; rotating either would seat successor committees below quorum ([02-dynamic-sharding.md](02-dynamic-sharding.md) §5). Skips also apply when the pool is empty or no ready member exists — a rotation that shrinks a committee is worse than none.
- **Top-up.** A separate fold pass refills any committee below target size from the pool — the repair path for committees left short by reshape-depleted pools.

## 3. Jailing, witnesses, and accountability

Accountability acts only on **on-chain evidence**, and it is removal, not confiscation — there is no slashing anywhere. A jailed validator's stake stays in its pool and remains withdrawable ([06-resource-economics.md](06-resource-economics.md)); what is at risk is the seat and, for equivocation, the key.

The target is the operator, not the capital, by design. Pools may hold third-party delegated stake — delegator-level accounting lives in the shard-layer staking contract, and the beacon fold sees only the aggregate that sets a pool's activation count — and delegators cannot foresee an operator's first equivocation. Slashing would burn that innocent capital, and where an operator runs mostly delegated stake it would barely touch the party who actually signed; the consensus layer cannot even see the split to slash it fairly. Permanent key-revocation instead falls on the operator's franchise: the seats, and the on-chain reputation it must rebuild to attract delegation under a fresh identity. The principal stays whole and withdrawable; the decision-maker bears the loss. That is also why the security is structural rather than economic: a corrupt seat is a single-use, non-steerable asset — removed on evidence, and able to regain relevance to any shard only through the beacon's random draw (§2), never by the operator's choice. The evidence pipeline is itself Byzantine-resistant:

- **Equivocation → permanent key-revocation.** Two signed votes at the same (height, round) for different blocks, or double-signed beacon ballots, are self-proving cryptographic proof the key is hostile — no correct node with a secure key can produce them; the evidence rides to the beacon and the identity is jailed with no unjail path. The key is burned, but the operator's stake is untouched: they may withdraw it and re-register under a fresh identity, so permanence is a revoked key plus a re-registration cost, not a destroyed stake. (Vote tracking distinguishes this from legitimate revoting at a higher round after a timeout.)
- **Chronic liveness faults → cooldown jail.** Every skipped proposal round generates a `MissedProposal` witness leaf, deterministically, on every replica; the beacon aggregates per-validator counters and jails on threshold. Performance jails are recoverable: an `Unjail` witness after a cooldown, gated on pool capacity.
- **The witness channel cannot be censored selectively.** Witness leaves live in a per-shard merkle accumulator whose root is QC-attested in every block header. A proposer building block B must extend the accumulator with *all* leaves implied by the chain since the parent — including missed-proposal leaves for skipped rounds — because verifiers recompute the expected root over the same prospective walk (committed state plus uncommitted certified ancestors) and reject a header whose root omits any (INV-SEC-4). A proposer can therefore not quietly drop the leaf that would jail a friend, or mint one to jail a rival: chunks applied at the beacon are contiguous, merkle-proven, and watermarked exactly-once ([01-consensus-layers.md](01-consensus-layers.md) §3.3).
- **Jailing feeds back into topology safely.** A jailed validator leaves its committee immediately; the ready-filtered consensus view shrinks (so quorum math stays sound), and pool draws refill the seat.

## 4. Cryptographic layer

- **Scheme.** BLS12-381 throughout consensus. Aggregation is the enabler: a QC or EC is one aggregated signature plus a signer bitfield over the committee, verified by aggregating the (bitfield-selected) public keys — O(n) key aggregation, O(1) pairing, compact wire size independent of committee size.
- **Domain separation everywhere.** Every signed message type — block votes, timeouts, execution votes, PC/SPC ballots, ready signals — has its own domain tag, and messages bind their full context (network, shard, height, round, hashes). No signature can be replayed across contexts (INV-SEC-5).
- **Committee resolution is part of verification.** Verifying any certificate means resolving the committee from the artifact's canonical weighted timestamp via the topology schedule ([01-consensus-layers.md](01-consensus-layers.md) §4) and checking quorum against *that* membership. There is no ambient "current committee" — an artifact from any epoch in the retention window verifies against exactly the committee that governed it.
- **Post-quantum posture.** The signature layer is a swappable seam; a researched migration path exists (hash-based WOTS+ signatures over Poseidon2 with STARK aggregation) with benchmarked feasibility, and the JMT's generic hasher anticipates the same transition. Not deployed; noted here because the design deliberately avoids coupling that would block it.

## 5. What one shard trusts about another

The inter-shard trust surface is minimal and uniform: **quorums and proofs, never nodes.**

| Artifact | Trust basis |
|---|---|
| Remote chain progress | Remote block headers, QC-verified against the WT-resolved remote committee (remote-header sync, [03-state-and-sync.md](03-state-and-sync.md) §6) |
| Remote state values (provisions) | JMT multiproof into the remote header's QC-attested state root |
| Remote execution outcomes | ExecutionCertificates: 2f+1 aggregated signatures of the remote committee, outcome vector bound to the receipt root at decode |
| A terminated shard's final word | Terminal header + beacon-attested settled-waves root ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4) |
| The topology itself | Each node's own fold of the beacon chain — never a peer's claim |

One seam is weaker than the rest and documented as such: provision `owned_nodes` claims are currently attested at transaction-hash granularity rather than proven into the QC-attested roots byte-for-byte — a Byzantine source has a bounded window to inject bogus ownership, with impact contained to liveness (deterministic aborts, declaration-bounded writes), not safety. See [04-atomic-commitment.md](04-atomic-commitment.md) §5 for the containment argument and the planned hardening.

## 6. Bounded resources: surviving adversarial input volumes

Safety rules make Byzantine *content* harmless; resource bounds make Byzantine *volume* harmless.

- **Per-(height, round) header caps.** At most a small constant number of distinct headers are buffered per slot (an honest proposer signs exactly one; excess is equivocation evidence), with eviction preferring rounds nearest the certified chain.
- **Bounded speculation.** View synchronization advances a replica's view only within a capped gap of its highest QC, and speculative verification of far-round blocks is capped — a flood of high-round garbage cannot inflate views or burn verification CPU.
- **Decode-time size caps.** Wire types use bounded collections (`BoundedVec`, `BoundedBytes`) that reject oversize claims *before allocation* — no peer-controlled length reaches an allocator (INV-SEC-6).
- **Message classes and shedding.** All traffic carries a `MessageClass` on a priority spectrum from live consensus down to bulk catch-up, and the sheddable tail — recovery and bulk transfers — is bounded: bounded queues, capped slot-pool shares, drop-on-overflow. Under load, catch-up and gossip traffic degrade; live consensus does not (INV-SEC-7). This ordering broke a real feedback loop in which a lagging node's bulk backfill starved the very consensus traffic that would have let it stop lagging. Gossip verdicts (accept/reject, feeding libp2p peer scoring) are emitted on every path, so misbehaving gossip peers lose reputation deterministically.
- **Backoff discipline.** All fetch paths (sync FSMs, settled-set acquisition, provision fallback) carry exponential backoff and peer rotation, so a dead or malicious serving peer converts to bounded retry load elsewhere, not a hammering loop.

## 7. Adversarial testing

The fault-injection layer (`Engine` rules on the simulated network; portable fault scenarios in `crates/scenarios`) exercises these defenses deterministically: targeted message-type drops (with probability, direction, and time-window selectors), asymmetric partitions, and crash/rejoin — all on a fault RNG stream seeded disjointly from the master seed, so fault schedules replay byte-identically ([07-determinism-and-testing.md](07-determinism-and-testing.md)). Standing assertions include: no committable fork exists under adversarial scheduling (the `fork_safety` harness asserts `find_fork().is_none()`), partitioned committees halt rather than diverge and resume on heal, isolated validators don't block quorum, and every cross-shard DA channel's loss is recovered by its fetch fallback.

## 8. Properties (summary)

Consolidated with IDs in [08-invariants.md](08-invariants.md).

- **INV-SEC-1 (committee honesty — assumption).** Every committee has <1/3 Byzantine members. Maintained statistically by seeded sampling + churn + expulsion from a <1/3-corrupt global pool; all consensus-layer safety invariants are conditional on it.
- **INV-SEC-2 (shuffle soundness).** Rotation is seeded-deterministic, one seat per shard per interval, never self-replacing, never touching mid-reshape shards, never shrinking a committee.
- **INV-SEC-3 (accountable expulsion).** Equivocation evidence is self-proving and permanently revokes the key (stake is not slashed); liveness-fault jailing derives only from merkle-proven, exactly-once-applied witness leaves and lifts after a cooldown.
- **INV-SEC-4 (witness completeness).** A block's witness root must commit every leaf implied by the chain — proposers can neither omit nor forge witness leaves.
- **INV-SEC-5 (signature hygiene).** All signatures are domain-separated and context-bound; all certificates verify against the WT-resolved committee for their artifact.
- **INV-SEC-6 (bounded decode).** No peer-supplied length is trusted before allocation; per-slot buffers are capped.
- **INV-SEC-7 (priority isolation).** Sheddable traffic classes cannot starve consensus-critical classes.
