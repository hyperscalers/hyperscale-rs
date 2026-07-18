# Secret sauce, and what to do about it

The question this document answers: **is there something in Cassandra that would be genuinely
worth pulling into hyperscale-rs?** The original assessment nominated the two-tier PoA/PoR
partial-progress mechanism as the headline candidate. **On review, the system author rejected it**
(§0): its value doesn't survive contact with cross-shard atomic commitment, and a stuck shard is
better recovered at the beacon layer. Two smaller, orthogonal borrows survive. Everything else
Cassandra does, hyperscale already has in a different form.

> **Read §0 first** — it is the conclusion. §1 below is preserved as the original argument, now
> annotated with why it does not hold.

This is an *assessment*, not a design. Anything touching hyperscale's consensus core should
respect the usual guardrails — don't touch consensus safety, determinism, or signatures without
an explicit scope, and land changes through a design proposal plus regression tests. Read the
recommendations as investigations to open, ranked by value/cost, with the failure modes named.

---

## 0. Author verdict (supersedes the ranking below)

> **The system author (flightofthefox) reviewed this analysis and rejected recommendation #1.**
> The reasoning is decisive and is recorded here as the conclusion; §1 and §5 are annotated to
> reflect it rather than rewritten, so the original argument and its refutation both stay visible.

**The core objection — a fundamental impedance mismatch.** Cassandra's partial progress is *only*
worth its cost if a sub-quorum group can do useful work. In a sharded system pursuing cross-shard
atomic commitment, it cannot:

- The extra fault tolerance (progress with f+1 instead of 2f+1 — e.g. ~66 of 100 nodes offline
  instead of ~33) buys only **PoA**, which is *speculative and retractable*. Commitment still needs
  2f+1 (PoR). Cassandra's safety rests on *"nothing outside the group acts on a PoA, so a losing
  branch can be silently discarded on reconciliation."*
- Cross-shard commitment **violates that premise by construction**: a shard tells another shard
  facts (provisions) that trigger irreversible side effects across a trust boundary. If shard A
  partitions into A′1 and A′2 and both make PoA progress, A′1 can tell shard B *"Alice → Bob $100"*
  while A′2 tells shard C *"Alice → Charlie $100"* — Alice has only $100. On reconciliation one
  branch loses, but B and C **already acted**. The retraction that keeps Cassandra safe locally is
  too late once the effect has escaped the shard.
- **2f+1 is required to emit cross-shard side effects, not merely to make local progress.** The
  only way to keep partial progress safe is to fence it entirely out of the cross-shard path — at
  which point the surviving value is *single-shard-only speculative* work during a rare event, for
  a very large integration cost (quarantining PoA from weighted time, provisioning, and the
  witness/jailing machinery). Not worth it.

**The preferred alternative — beacon-layer liveness recovery.** Handle a stuck shard where
hyperscale already handles topology: at the beacon. If no beacon committee member has seen a header
from shard A for *n* epochs, **deterministically rotate shard A's entire committee** (draw a fresh
one from the pool; it snap-syncs to A's last beacon-attested checkpoint and resumes). Not instant,
but acceptable for an exceptionally rare event.

Why this is clean — sharper than first stated:

- **Nothing final is lost.** If 2f+1 was lost, HotStuff-2 committed nothing in the meantime (by
  definition), so there are no committed-but-lost blocks. The fresh committee resumes from the last
  attested checkpoint and loses only uncommitted work. Snap-sync anchors and the checkpoint ring
  ([03](../03-state-and-sync.md) §4–5) already make this state servable.
- **Cross-shard stays atomic via existing machinery.** In-flight waves on counterpart shards are
  backstopped by the wave deadline (INV-EXEC-5): if rotation is slow, they all-abort
  deterministically. No new atomicity rule needed.
- **A healed old committee cannot do damage.** Post-rotation, its blocks resolve to the wrong
  committee under weighted-time committee binding (INV-SHARD-9) and are rejected everywhere; once
  its members catch up on the beacon, they see they are rotated out and stand down. It composes
  with the existing shuffle/top-up/reshape fold machinery rather than adding a parallel mechanism.

Two honest riders on the alternative:

- **The "rare" claim rests on committee sampling-spread, not jailing.** Jailing clears *chronic*
  liveness faults slowly (missed-proposal thresholds + cooldown); it does **not** prevent the
  *sudden correlated* outage Cassandra motivates with (a whole cloud region dropping at once). What
  makes losing 2f+1 of one small committee unlikely is that randomized sampling
  ([05](../05-byzantine-safety.md) §1–2) spreads a committee across the
  operator/geo population, so no single region/partition holds 2f+1 of it. The assumption weakens
  if sampling is ever not geo-spread or an adversary can concentrate placement.
- **It accepts a hard outage window.** Shard A is *fully* down (single-shard users included) for
  detect + rotate + snap-sync. That is precisely the window Cassandra would have softened — a
  deliberate trade of "rare hard outage" for "zero consensus-core complexity," not a free win.

**What survives the verdict.** The objection targets the PoA/quorum mechanism *only* (recommendation
#1). It does **not** touch recommendations **#2 (decoupled AIMD timeout calibration)** and **#3
(attested-randomness proposer de-biasing)**: both are independent of quorums and of the cross-shard
path, live in the non-consensus time / existing-randomness domains, and remain low-risk
adopt-candidates on their own merits.

---

## 1. The secret sauce: two-tier PoA/PoR partial progress

### What it is

Cassandra's core novelty is a **weak-quorum certificate (`PoA`, f+1) layered beneath the
strong-quorum commit certificate (`PoR`, 2f+1)**, combined with **leaderless partitionable
proposal selection** and a **deterministic proposal-priority rule**. The effect:

- A connected component with as few as **f+1 correct replicas** keeps *ordering* transactions and
  advancing rounds during a partition — forming PoAs (available, ordered, not final) and RCs
  (round certificates from f+1 `WishNewRound`s) — instead of stalling.
- The work is **recoverable**: PoA ⇒ ≥1 correct replica holds the payload (Lemma 11), so nothing
  is lost.
- On heal, **reconciliation is implicit**: deterministic proposal priority (highest PoR round,
  then highest PoA round, then threshold-coin) makes correct replicas converge on the strongest
  branch and extend it with fresh PoRs. No explicit merge protocol, no rollback of committed
  state.
- Safety is **identical** to classical BFT: commitment still needs the two-PoR (2f+1 × 2) chain;
  PoA never commits anything. The paper proves Safety unconditionally (Thm 1) and Partial
  Liveness separately (Thm 3).

### Why it is the right thing to look at for hyperscale

hyperscale's shard consensus is HotStuff-2, which is exactly the **strong-quorum, designated-leader**
design Cassandra was written to improve on under partitions. Today, a hyperscale **shard committee
that cannot assemble 2f+1 halts** — it "halts rather than diverges, and resumes on heal"
([05](../05-byzantine-safety.md) §7). That is the correct *safe* behavior,
but in a sharded system the liveness cost is amplified relative to a monolithic chain:

- **Committees are small.** They are sized to the sampling security parameter (INV-SEC-1), not for
  partition resilience. A network split, a correlated cloud-region outage, or a burst of
  correlated faults drops a *single* committee below 2f+1 far more easily than it would a large
  monolithic validator set. (Cassandra's own motivation — the AWS us-east-1 and Cloudflare 2025
  regional outages — maps directly onto per-region committee exposure.)
- **A halted shard is not isolated.** Cross-shard transactions touching that shard stall: provisions
  don't flow, waves can't finalize, straddlers wait on the fence. One stuck committee radiates
  backpressure. Cassandra's line — *"process local transactions with non-zero throughput even when a
  partition leaves only f+1 honest replicas connected"* — is precisely a fix for the *single-shard*
  liveness hole.

So the highest-value shape is **not** replacing HotStuff-2 wholesale. It is adding a **shard-local
partition-fallback mode**: run HotStuff-2 as the fast path (as today), and when a committee detects
it is stuck below 2f+1, fall into a Cassandra-style PoA/leaderless mode that keeps the shard
*ordering and speculatively executing single-shard work* until quorum returns. This mirrors
Cassandra's own dual-path structure — just with HotStuff-2 in the fast-path slot and Cassandra's
base path as the partition fallback.

### The integration hazards (why this is "investigate", not "adopt")

hyperscale is not a bare consensus protocol, and three of its load-bearing properties resist a
naive PoA graft. Each is a real design boundary, not a detail:

1. **Weighted time assumes 2f+1.** hyperscale's attested clock is a *quorum-averaged, per-vote-clamped*
   timestamp whose Byzantine-boundedness argument relies on 2f+1 aggregation
   ([01](../01-consensus-layers.md) §1.3). An f+1 PoA cannot carry a
   timestamp with the same guarantee. Since committee resolution, deadlines, and retention *all*
   key on weighted time (INV-SHARD-6, INV-SHARD-9), **PoA-ordered blocks must not advance the
   attested clock** — they'd have to be timestamped only provisionally and re-anchored when a PoR
   forms. Defining that cleanly is the crux of the whole effort.

2. **Cross-shard inputs must be final.** Provisions carry a **QC-attested (2f+1) state root**; ECs
   are 2f+1; the straddler fence assumes finalized settled-sets (INV-EXEC-10, INV-RESHAPE-5/6). A
   PoA block's state is *provisional* — it can be reconciled away on heal. Therefore **PoA progress
   must be fenced strictly out of the cross-shard path**: no provisioning from PoA state, no EC over
   PoA waves, PoA-ordered cross-shard transactions held until their block gets a PoR. This aligns
   with Cassandra's "speculative, discard-if-branch-loses" model, but hyperscale would need an
   explicit barrier so a provisional block can never leak into another shard's committed state.
   Effectively: **partial progress is single-shard-only until PoR.**

3. **Rotating-leader assumptions are wired in.** The missed-proposal witness / jailing mechanism
   assumes a *known expected proposer per round* (`proposer_for(round)`; INV-SEC-4) — "who missed a
   proposal" is ill-defined when everyone proposes. DA-by-vote and view-sync bounds also lean on the
   rotation. A leaderless fallback mode must therefore either **suspend liveness-fault accounting
   while in fallback** (partitions shouldn't jail anyone for missed proposals anyway) or define a
   partition-aware witness rule. Cleanest: fallback mode is a distinct, explicitly-scoped consensus
   sub-protocol with its own accountability rules, entered only on detected sub-quorum.

4. **Determinism budget.** hyperscale's crown jewel is byte-identical seeded replay (INV-DET-1/4).
   Cassandra's per-replica adaptive δᵢ and threshold-coin are new state. δᵢ is fine — it lives in
   the `LocalTimestamp` (non-consensus) domain by construction, and the simulator already seeds all
   local timing. The threshold-coin is *also* fine and in fact a **natural fit**: hyperscale already
   has an attested randomness accumulator (see §3). Both must be routed through the existing
   seeded/attested channels, never a fresh RNG.

**Bottom line on the sauce — REVISED, see §0.** The original assessment rated this "high value,
high integration cost, worth a design-first investigation." The author's review sharpened the
cost/benefit to a **rejection**: once PoA is correctly quarantined from the cross-shard path (which
hazard #2 already required), the only surviving value is *single-shard-only speculative* progress
during a rare sub-quorum event — too little to justify quarantining PoA from weighted time,
provisioning, and the witness/jailing machinery. The double-spend in §0 (A′1 → B and A′2 → C over
Alice's single $100) is the crisp demonstration: cross-shard side effects are irreversible once they
cross a shard boundary, so Cassandra's "discard the losing branch on reconciliation" cannot undo
them. **2f+1 is needed to emit cross-shard effects, not just to make local progress.** The preferred
liveness fix is beacon-layer committee rotation (§0), which reuses existing fold/snap-sync/wave-
deadline machinery instead of grafting a second consensus mode onto the shard layer.

*(Retained for the record: had this been pursued, the right first step would have been a
concept/design proposal for a shard-local partition-fallback mode with PoA/PoR quarantine rules
and regression tests for weighted-time monotonicity, no-provision-from-provisional-state,
and atomicity — plus a simulator scenario asserting single-shard partial progress, clean PoR
reconciliation on heal, and zero cross-shard leakage. The deterministic harness could have proven
it, but the author's judgment is that the outcome would not earn its complexity.)*

---

## 2. Lower-risk borrow: decoupled background timeout calibration

Independent of PoA, Cassandra's **decoupled pacemaker** has a self-contained good idea:
**move timeout calibration off the critical path** and make it **adaptive both ways** —
double δ on a failed sync, but also **halve it after a sufficiently fast success** (AIMD, TCP-style,
`δ ← max(δ/2, δ_min)`), so a single transient delay spike doesn't leave rounds permanently long.

hyperscale today grows the round timeout *linearly with failed rounds at a height*, computed from
QC-attested data ([01](../01-consensus-layers.md) §1.5). That is
deterministic and shared (a virtue — all replicas agree on the deadline), but it only *increases*
within a height and resets; it doesn't learn a lower steady-state timeout after conditions improve.

- **Value:** smoother recovery latency after transient network degradation; fewer over-long rounds.
  Medium — a latency/liveness optimization, not a correctness change.
- **Cost:** low. It stays entirely in the `LocalTimestamp` domain (never consensus-visible), so it
  cannot affect safety or determinism as long as the simulator seeds it. Cassandra explicitly notes
  δ "affects only round duration, not the correctness of voting or certification."
- **Caveat:** hyperscale's *shared, attested* deadline is deliberate — replicas agreeing on the
  timeout is load-bearing for the pacemaker's 2f+1-advance step. Any adaptive scheme must keep the
  *consensus-visible* deadline attested/shared and let only the *local* pacing hint adapt. So this
  is "adopt the AIMD idea for the local timer," **not** "make the consensus deadline per-replica."

**Recommendation:** adopt-candidate. Small, scoped, testable in isolation; worth a design note + a
determinism regression test confirming the adaptive timer never leaks into hashed/signed state.

---

## 3. Cheap experiment: threshold-coin tiebreak from attested randomness

Cassandra breaks ties between equally-strong proposals with a **deterministic threshold coin**
(`C_r = ThresholdAggregate(shares)`, `Score = H(C_r ‖ sender)`), unpredictable to the adversary
before the round. hyperscale selects proposers by pure rotation, `committee[round % size]` — fully
deterministic and communication-free, but also **fully predictable**, which is a mild
targeted-DoS handle (an adversary knows exactly who proposes at every future round and can aim
delay/eclipse attacks at them).

hyperscale **already has the ingredient**: the beacon's attested randomness accumulator
(VRF-mixed each epoch), which already seeds committee sampling and shuffling
([05](../05-byzantine-safety.md) §1–2). Deriving proposer order (or a
tiebreak) from that attested randomness instead of raw `round % size` would **de-bias proposer
selection against prediction** while staying deterministic and replay-stable.

- **Value:** low–medium — a modest hardening against targeted proposer DoS; also the exact
  primitive a leaderless fallback (§1) would need for its tiebreak, so it's a natural precursor.
- **Cost:** low — reuses existing attested randomness; no new trust assumption; deterministic by
  construction.
- **Caveat:** must draw from the *already-attested* accumulator (so all replicas agree and replay
  holds), not a live threshold-signing round — hyperscale doesn't need Cassandra's per-round
  threshold-coin protocol because it has a standing attested randomness source.

**Recommendation:** cheap experiment, most compelling *if* §1 is pursued (shared primitive).

---

## 4. What is already covered — don't import

Three Cassandra ideas look tempting but are **already present** in hyperscale in a stronger or
equivalent form. Importing them would be redundant.

| Cassandra idea | Why hyperscale already has it |
|---|---|
| **Speculative execution over provisional ordering** | hyperscale decouples ordering from execution structurally: it *commits blocks before executing them* and agrees outcomes in a separate execution-consensus round (ECs), all at 2f+1 ([01](../01-consensus-layers.md) §2). The "order now, agree outcome later" philosophy is already the spine of cross-shard atomicity. (The one *new* thing PoA adds is speculation over *sub-quorum* ordering — which is §1, not this.) |
| **Dissemination layer decoupled from ordering** (Narwhal/Autobahn) | hyperscale's provision system + DA trackers + class-prioritized gossip already separate data availability from ordering, with the explicit guarantee that bulk/DA traffic cannot starve live consensus (INV-SEC-7; [04](../04-atomic-commitment.md) §6). |
| **Implicit reconciliation from determinism** | hyperscale's entire cross-shard model *is* determinism-driven reconciliation: every honest replica computes identical receipts/roots, so agreement is agreement-by-computation, not by merge protocol (INV-EXEC-1, INV-STATE-1). It leans on determinism at least as hard as Cassandra does. |

---

## 5. Ranked summary

| Rank | Borrow | Value | Cost | Verdict |
|---|---|---|---|---|
| 1 | **Two-tier PoA/PoR partial progress** as a shard-local partition-fallback mode | Low in this system — surviving value is single-shard-only speculative work during a rare event | **High** — quarantine from weighted time + cross-shard path + witness/jailing | **REJECTED by the author (§0).** Cross-shard side effects are irreversible; partial progress can't feed them safely. Recover stuck shards by **beacon-layer committee rotation** instead. |
| 2 | **Decoupled background timeout calibration** (AIMD, halve-on-fast-success) | Medium — smoother post-spike recovery latency | Low — stays in non-consensus time domain | **Adopt-candidate — survives the §0 verdict** (orthogonal to quorums/cross-shard). Keep the *consensus* deadline shared/attested. |
| 3 | **Threshold-coin / attested-randomness proposer de-biasing** | Low–Medium — targeted-DoS hardening | Low — reuses beacon randomness | **Cheap experiment — survives the §0 verdict** (orthogonal to quorums/cross-shard). |
| — | Speculative exec · dissemination decoupling · implicit reconciliation | — | — | **Already present.** Do not import. |
| — | **Beacon-layer committee rotation on liveness timeout** *(author's alternative to #1)* | High — restores stuck-shard liveness | Low–Medium — reuses fold + snap-sync + wave-deadline machinery | **Preferred liveness fix (§0).** Accepts a hard per-shard outage window during detect + rotate + snap-sync. |

### The framing for a community write-up

Cassandra and hyperscale-rs are **two children of Dan Hughes' Radix program that optimized
different axes.** Cassandra asks *"how do we keep one committee live through a partition?"* and
answers with two-tier certification and leaderless partial progress. hyperscale-rs asks *"how do we
scale across committees without losing atomic composability, an attested clock, live resharding, or
deterministic assurance?"* — and treats single-committee liveness conservatively (halt-and-heal).

The tempting synthesis — "drop Cassandra in as hyperscale's intra-shard consensus" — **does not
survive the author's review (§0)**, and the reason is illuminating rather than disappointing:
partial progress is safe in Cassandra *precisely because nothing outside the group ever acts on a
non-final (PoA) result.* Cross-shard atomic commitment is the act of one group emitting facts that
another group acts on irreversibly — the exact premise Cassandra's safety argument forbids being
broken. So the two designs are not just optimizing different axes; the thing that makes Cassandra's
liveness win *safe* is the thing hyperscale's cross-shard model *must* violate. hyperscale's
conservative halt-and-heal is therefore not a gap Cassandra fills — it is the correct posture, and
the residual liveness concern (a rarely-stuck shard) is better answered inside hyperscale's own
world, at the beacon, by rotating the committee. What genuinely crosses over is smaller and
quorum-independent: an adaptive off-critical-path timeout, and attested-randomness proposer
selection.
