# Cassandra vs. hyperscale-rs — side by side

This document sets the two systems next to each other: what each *is*, their shared lineage,
how the comparable consensus machinery lines up, and then two tables — commonalities and
differences — with every entry grounded in the source material.

> **Scope note.** Cassandra is a single-committee consensus protocol. hyperscale-rs is a whole
> sharded platform whose *shard-consensus layer* is HotStuff-2. A fair mechanical comparison is
> **Cassandra ↔ hyperscale's shard consensus** ([01-consensus-layers.md](../01-consensus-layers.md) §1).
> The platform-level pieces (dynamic sharding, cross-shard atomicity, the beacon, the economy)
> have **no Cassandra analogue** — Cassandra simply doesn't operate at that altitude, and says so:
> it positions its technique as an *intra-shard component* that other sharded systems could adopt.

---

## 1. What each system is

### Cassandra (the paper)

A BFT state-machine-replication protocol for **n = 3f+1** replicas under partial synchrony
(Dwork et al.), explicitly built for the messy-network reality the CAP theorem describes:
transient partitions, delay asymmetry, BGP-hijack-style splits. Its thesis is that classical
BFT's "all-or-nothing" liveness is an unnecessary concession — you can keep making *partial*,
safe, recoverable progress in a partition instead of stalling to zero throughput.

Its three complementary mechanisms:

1. **Two-tier certification.** Every proposal can gather two kinds of certificate:
   - **PoA (Proof of Availability)** — a *weak-quorum* certificate from **f+1** votes. Guarantees
     the payload is retrievable (≥1 correct replica holds it) but is **not** a commit.
   - **PoR (Proof of Reliability)** — a *strong-quorum* certificate from **2f+1 (n−f)** votes.
     Certifies global consistency; commitment requires PoRs.
2. **Partitionable leader election** — leaderless base path. There is no designated leader;
   *every* replica proposes each round, and each replica independently selects the strongest
   proposal by a **deterministic proposal-priority rule**: rank by highest referenced PoR round,
   then highest PoA round, then a **threshold-coin** tiebreak derived from proposal signature
   shares. All correct replicas seeing the same proposal set pick the same "leader" — so each
   partition can progress independently.
3. **Decoupled pacemaker** — round advancement stays on the critical path (a PoR, or an **RC**
   = a Round Certificate from f+1 `WishNewRound` messages, advances the round), while **timeout
   calibration runs in the background**, off the critical path: each replica adjusts its local
   timeout δᵢ with a TCP-like AIMD rule (double on failure, *halve* after a fast success),
   never blocking consensus.

Commitment is a **two-PoR (two-chain) rule**: a proposal commits once two consecutive-round PoRs
form a chain extending it. Safety rests on quorum intersection (any two 2f+1 quorums share a
correct replica) plus a locking rule — the same skeleton as HotStuff. **Partial Liveness** is the
new property: any connected component with ≥ f+1 correct replicas keeps forming PoAs (and RCs to
advance rounds) during a partition; on heal, deterministic proposal priority makes everyone
converge on the strongest branch and form fresh PoRs — **implicit reconciliation, no explicit
merge protocol.** A **dual-path** design adds an optimistic linear-communication fast path
(designated collector) that falls back to the quadratic leaderless base path on failure, and
replicas may **speculatively execute** PoA-backed proposals, discarding the work if the branch
loses. Evaluated at 900K TPS (16 replicas) / 480K (104), with ~500K *speculative* TPS sustained
under a partition where classical BFT hits **zero**.

### hyperscale-rs (the platform)

A linearly-scaling sharded smart-contract L1. Its architecture ([overview](../00-overview.md)):

- **Three consensus layers**: **shard consensus** (HotStuff-2 — the piece comparable to Cassandra),
  **execution consensus** (2f+1 `ExecutionCertificate`s over outcome vectors), and **beacon
  consensus** (leaderless prefix consensus PC/SPC, one block per epoch, governs topology).
- **Weighted time** — a BFT-attested distributed clock (per-vote-clamped quorum-averaged
  timestamp, monotone per chain) that resolves *which committee governs which shard when*
  ([01](../01-consensus-layers.md) §1.3, §4).
- **Dynamic sharding** — shards split/merge at runtime as prefix subtrees of one global binary
  JMT, with deterministic genesis derivation and a **straddler-settlement fence** preserving
  cross-shard atomicity even when a participating shard ceases to exist ([02](../02-dynamic-sharding.md)).
- **Atomic cross-shard commitment** — a deterministic **provision → execute → certify** pipeline;
  a transaction commits identically on every participating shard or aborts everywhere, with no
  coordinator and no outcome vote ([04](../04-atomic-commitment.md)).
- **Self-regulating economy** — a market-clearing minimum stake recomputed each epoch, plus
  vnodes ([06](../06-resource-economics.md)).
- **Sans-io determinism** — every protocol component is a pure `handle(now, event) → actions`
  state machine; the identical code runs under a seeded deterministic simulator and under
  production I/O, replaying byte-identically ([07](../07-determinism-and-testing.md)).

Its shard consensus is textbook-modern HotStuff-2: rotating proposer by round
(`proposer_for(round) = committee[round % size]`), two-chain round-contiguous commit, monotone
`locked_round`/`last_voted_round` registers, a **timeout-message pacemaker** (f+1 timeouts
Bracha-amplify, 2f+1 advance the round adopting the quorum-max `high_qc`), and DA-by-vote (a
validator votes only holding the *complete* block, so every QC certifies 2f+1 complete copies —
INV-SHARD-7).

---

## 2. The shared lineage, concretely

The overlap below is not convergent evolution — it is common descent, and the paper makes the
family tree legible:

- Cassandra is **co-authored by Daniel P. Hughes (RadixDLT)**, the designer of Radix Hyperscale
  that hyperscale-rs reimplements. The dedication ("in loving memory") marks the split point.
- Cassandra's Related Work cites **Cerberus** (Hellings, **Hughes**, Primero, Sadoghi, 2023) —
  *"Minimalistic Multi-Shard Byzantine-Resilient Transaction Processing"* — and **ByShard**. These
  are the academic ancestors of hyperscale's cross-shard atomic commitment: per-shard BFT
  committees coordinating an atomic cross-shard commit. hyperscale's provision→execute→certify
  pipeline and "abort is dominant, success is unanimous" rule are that lineage, built out.
- Cassandra explicitly names sharding as the setting its technique *complements*: *"Cassandra's
  partial-progress technique is orthogonal. It could serve as an intra-shard consensus component,
  allowing each committee to process local transactions with non-zero throughput even when a
  partition leaves only f+1 honest replicas connected."* This sentence is, in effect, a design
  memo addressed to a system exactly like hyperscale-rs (see [doc 02](02-secret-sauce-and-recommendations.md)).

So the honest framing: **hyperscale-rs inherited the sharding/atomic-commitment branch of Dan
Hughes' program and made it rigorous; Cassandra pursued the consensus-liveness branch.** Where
they overlap, they overlap by inheritance; where they differ, it is because each optimized a
different axis.

---

## 3. Commonalities

| # | Common ground | In Cassandra | In hyperscale-rs |
|---|---|---|---|
| C1 | **BFT foundation**: n=3f+1, 2f+1 strong quorum, partial synchrony, *safety never depends on timing* | System Model; Safety Thm 1 | Threat model, `VoteCount::has_quorum`, INV-SEC-1 ([05](../05-byzantine-safety.md) §1) |
| C2 | **HotStuff-family two-chain commit** with monotone locks + quorum-intersection fork safety | Two-PoR commit rule; Locking Rule; Lemma 1 | Round-contiguous child-QC commit; `locked_round` monotone, no unlock; INV-SHARD-1/3/4 ([01](../01-consensus-layers.md) §1.4) |
| C3 | **"Two QCs at a height can exist; two *commits* cannot"** — same fork-safety argument | Safety proof via quorum intersection + single-vote rule | Verbatim reasoning; `fork_safety` harness asserts `find_fork().is_none()` |
| C4 | **Pacemaker with retransmitting timeouts + catch-up-from-certificate** | RC / `WishNewRound`; jump to highest justified round on higher cert | Timeout msgs retransmit every fire; view advances to highest known QC ([01](../01-consensus-layers.md) §1.5) |
| C5 | **Compact certificates via aggregate/threshold signatures** | Threshold sigs: (f+1,n) for PoA, (2f+1,n) for PoR | BLS12-381 aggregate + signer bitfield; O(1) pairing ([05](../05-byzantine-safety.md) §4) |
| C6 | **Deterministic, communication-free proposer/leader selection** | Deterministic proposal-priority rule + threshold-coin tiebreak | `proposer_for(round) = committee[round % size]` |
| C7 | **Data availability bound to certificates** | PoA ⇒ ≥1 correct replica stores the proposal (Lemma 11) | Vote-only-when-complete ⇒ QC = DA cert, 2f+1 hold all content (INV-SHARD-7) |
| C8 | **Separate "agree on order" from "agree on outcome / availability"** | PoA (available) vs PoR (committed); speculative exec over PoA | Ordering (QC) decoupled from execution consensus (EC); commit-before-execute ([01](../01-consensus-layers.md) §2) |
| C9 | **Decouple data dissemination from ordering** | Optional Narwhal/Autobahn dissemination layer (§5.3) | Provisions + DA trackers + gossip; class-prioritized so bulk can't starve consensus ([04](../04-atomic-commitment.md) §6) |
| C10 | **Reconciliation emerges from determinism — no explicit merge protocol** | Divergent PoA branches reconcile via deterministic proposal priority on heal | Cross-shard agreement from deterministic execution (identical receipts everywhere), INV-EXEC-1 |
| C11 | **Time used for liveness is kept out of the consensus-critical safety path** | δᵢ affects only round duration, never voting/cert correctness | `LocalTimestamp` never hashed/signed; only `WeightedTimestamp` is consensus-visible (INV-DET-2) |

---

## 4. Differences

| # | Axis | Cassandra | hyperscale-rs |
|---|---|---|---|
| D1 | **Problem solved** | Partition tolerance / *partial liveness* for one committee (vertical axis) | Linear scaling with atomic composability across many committees (horizontal axis) |
| D2 | **Altitude** | A consensus protocol (a component) | A full L1; consensus is one of many layers |
| D3 | **Behavior under partition / sub-quorum** | Component with ≥ **f+1 correct** keeps ordering (PoA) and advancing (RC); reconciles on heal | Shard committee below **2f+1 halts** — safety over liveness; "partitioned committees halt rather than diverge and resume on heal" ([05](../05-byzantine-safety.md) §7). *This is the C1/C4 stall Cassandra targets.* |
| D4 | **Quorum tiers** | **Two**: f+1 (PoA, partial) and 2f+1 (PoR, commit) | **One**: 2f+1 for QC, EC, and beacon alike |
| D5 | **Intermediate "available-not-final" certificate** | **Yes** — PoA is the whole point | **No** analogue; a QC is DA + ordering + finality-eligibility at 2f+1 |
| D6 | **Leader model** | Leaderless base path (all propose, deterministic strongest wins); optimistic leader only on the fast path | Rotating designated proposer by round (single proposer per round) |
| D7 | **Distributed attested clock** | None — δᵢ is local pacing only; no consensus-visible time | **Weighted time**: a BFT-attested clock resolving committees, deadlines, retention, reshape boundaries. No Cassandra counterpart. |
| D8 | **Timeout handling** | Background AIMD calibration (double on fail, halve on fast success), off critical path, per-replica adaptive | Linear growth per failed round at a height, computed from QC-attested data so all replicas agree on the deadline (shared, not adaptive) |
| D9 | **Reconfiguration / membership** | Fixed replica set; threshold keys via pre-runtime DKG; not addressed | Dynamic: seeded sampling, continuous shuffling, jailing on proven evidence, reshape cohorts, elastic committee sizes ([05](../05-byzantine-safety.md) §2–3) |
| D10 | **State model** | Generic SMR log (KV inserts in eval); no state-tree machinery | Global binary JMT, owner-prefixed keying, snap-sync, checkpointing, divergence recovery ([03](../03-state-and-sync.md)) |
| D11 | **Cross-shard atomicity** | Out of scope (single committee) | Core: deterministic provision→execute→certify, straddler-settlement fence across reshapes ([04](../04-atomic-commitment.md), [02](../02-dynamic-sharding.md) §4) |
| D12 | **Economics** | Out of scope | Market-clearing dynamic min-stake + vnodes ([06](../06-resource-economics.md)) |
| D13 | **Assurance method** | Formal proofs (Safety, Liveness w.p.1, Partial Liveness) + empirical eval on ResilientDB | Exhaustive seeded deterministic simulation (byte-identical replay, fault injection) + inline invariant register as the FV starting point ([07](../07-determinism-and-testing.md), [08](../08-invariants.md)) |
| D14 | **Common coin / randomness** | Threshold coin as a *tiebreaker only* (not leader election) | Beacon randomness accumulator (VRF-mixed) seeds sampling/shuffle; proposer selection is pure rotation, no coin |
| D15 | **Implementation** | C++ on Apache ResilientDB | Rust workspace, sans-io, dual harness (simulation + production) |

---

## 5. The one-sentence synthesis

Cassandra and hyperscale-rs agree on the BFT skeleton because they inherited it from the same
place; they diverge because Cassandra spent its innovation budget on **keeping one committee live
through a partition**, while hyperscale-rs spent its budget on **scaling across committees with
atomic composability, an attested clock, live resharding, and deterministic assurance**. The
partition-liveness axis is precisely where hyperscale-rs is most conservative — so Cassandra's core
mechanism is the natural thing to test against it. That test is [doc 02](02-secret-sauce-and-recommendations.md),
and it concludes the mechanism **does not fit** a system built for cross-shard atomic commitment:
partial progress is safe only because nothing outside a committee acts on its non-final results,
which is exactly what cross-shard commitment must do. Two smaller, quorum-independent ideas survive;
the partial-progress core does not.
