# Cassandra vs. hyperscale-rs — a comparative analysis

*Two systems from one lineage: where they overlap, where they diverged, and what — if anything — is worth carrying across.*

---

## What this is

This folder compares two BFT systems that share intellectual DNA but bent in different
directions:

- **Cassandra** — *"Consensus with Partial Progress via Robust Partitionable View
  Synchronization"* (Xie, Kang, Chen, Gupta, **Daniel P. Hughes** †, Sadoghi; UC Davis /
  Oregon / RadixDLT Ltd., arXiv, July 2026). A single-committee BFT **consensus protocol**
  whose headline is *partial progress under network partitions*: a partitioned group that
  cannot reach a 2f+1 quorum keeps making safe, recoverable progress instead of stalling to
  zero. Implemented in C++ on Apache ResilientDB.

- **hyperscale-rs** — the Rust reimplementation (by *flightofthefox*) of Radix Hyperscale,
  the sharded smart-contract platform Dan Hughes designed. A whole L1: three consensus
  layers, dynamic sharding, atomic cross-shard commitment, a BFT-attested clock, a
  self-regulating validator economy, and a sans-io deterministic architecture.

Dan Hughes designed Hyperscale and co-authored Cassandra; he passed away, and the two
efforts continued on separate tracks. Cassandra is where the *consensus-liveness* thinking
went (academic, single-committee, partition-tolerant). hyperscale-rs is where the
*sharding + atomic composability + determinism* thinking went (a built system, with
HotStuff-2 as its shard consensus). **They are two children of one parent research program**
— the common ancestor is visible in Cassandra's own bibliography, which cites *Cerberus*
(Hellings, **Hughes**, Primero, Sadoghi 2023), the minimalistic multi-shard atomic-commitment
protocol that prefigures hyperscale's cross-shard pipeline.

## The documents

| Doc | Contents |
|---|---|
| [01-side-by-side.md](01-side-by-side.md) | Full comparison: scope, lineage, consensus mechanics, a commonalities table and a differences table, each entry technically grounded. |
| [02-secret-sauce-and-recommendations.md](02-secret-sauce-and-recommendations.md) | The "is there secret sauce?" verdict, and a ranked, honest engineering assessment of what to adopt, at what integration cost, and what to leave. |

## TL;DR

**They solve orthogonal problems.** Cassandra improves the *vertical* axis — keeping a single
committee live when the network splits. hyperscale improves the *horizontal* axis — scaling
across many committees while preserving atomic composability. Cassandra is (roughly) a drop-in
for *one shard's consensus*; hyperscale is the entire surrounding system. Comparing them fairly
means comparing Cassandra against hyperscale's **shard-consensus layer only** (HotStuff-2), not
against the whole platform.

**Deep common ground, by descent.** Both are n = 3f+1 partial-synchrony BFT with 2f+1 strong
quorums; both commit on a two-chain rule with monotone locks and quorum-intersection fork
safety; both bind data availability to certificates; both use aggregate/threshold signatures;
both separate "agree on order" from "agree on outcome"; both lean on determinism to avoid
explicit reconciliation. This is not coincidence — it is shared heritage.

**The candidate "secret sauce" — and why it was rejected on review.** Cassandra's headline is
**two-tier certification** — a weak-quorum `PoA` (f+1, *available* but not final) beneath the
strong-quorum `PoR` (2f+1, *committed*) — plus **partitionable leader election** and a
**deterministic proposal-priority rule**, letting a component with as few as **f+1 correct
replicas** keep ordering transactions during a partition and reconcile *implicitly* on heal. It
appears to attack exactly the axis where hyperscale-rs is most conservative: a shard committee
below 2f+1 **halts**.

**The system author (flightofthefox) reviewed the analysis and rejected it.** Partial progress is
safe in Cassandra *only because nothing outside the group acts on a non-final PoA result* — a
losing branch is silently discarded on reconciliation. **Cross-shard atomic commitment violates
that premise by construction:** a shard emits facts (provisions) that another shard acts on
irreversibly. If a partitioned shard makes PoA progress on two branches, one can tell shard B
"Alice → Bob $100" while the other tells shard C "Alice → Charlie $100" for the same $100; B and C
act, and reconciliation's "discard the loser" comes too late. **2f+1 is needed to emit cross-shard
effects, not just to make local progress.** Fenced safely, the only surviving value is
single-shard-only speculative work during a rare event — too little for the integration cost. The
preferred fix for a rarely-stuck shard is **beacon-layer committee rotation**, which reuses
hyperscale's existing fold / snap-sync / wave-deadline machinery. Full reasoning in
[doc 02 §0](02-secret-sauce-and-recommendations.md).

**Verdict (details and the author's alternative in [doc 02](02-secret-sauce-and-recommendations.md)):**

| Idea from Cassandra | Value to hyperscale-rs | Integration cost | Recommendation |
|---|---|---|---|
| Two-tier PoA/PoR partial progress, as a shard-local partition fallback | Low here — retractable progress can't feed cross-shard atomicity | High — quarantine from weighted-time + cross-shard + jailing | **Rejected (author).** Recover stuck shards by **beacon-layer committee rotation** instead. |
| Decoupled **background timeout calibration** (AIMD, off critical path) | Medium — smoother recovery latency after delay spikes | Low — self-contained, non-consensus time domain | **Adopt candidate** — survives the verdict (orthogonal) |
| **Threshold-coin tiebreak** seeded from attested randomness | Low–Medium — de-biases proposer selection vs. targeted DoS | Low — reuses the beacon randomness accumulator | **Cheap experiment** — survives the verdict (orthogonal) |
| Speculative execution / ordering–execution split | — | — | **Already present** (hyperscale decouples ordering from execution at 2f+1) |
| Dissemination-layer decoupling (Narwhal/Autobahn-style) | — | — | **Already present** (provisions + DA + gossip) |
| Implicit reconciliation from determinism | — | — | **Already present** (deterministic cross-shard execution) |

## Method, sources, and honesty notes

- Built from the Cassandra arXiv PDF (17 pp., July 2026) and the hyperscale-rs architecture
  docs under `docs/` as of this analysis. Invariant IDs (`INV-*`) and doc sections are cited so
  every claim is traceable.
- This is a **documentation-level** comparison. It reasons from the papers/docs, not from a
  line-by-line reading of both codebases, and it does not re-derive Cassandra's proofs.
  Recommendations are framed as *investigations to open*, not settled designs — anything
  touching hyperscale's consensus core would go through the usual design-proposal and
  regression-test process before implementation.
- Where hyperscale would have to *change* to accommodate a Cassandra idea, the analysis says
  so plainly rather than overselling the fit.

*A community-facing architecture analysis. Verify against the current papers before relying on
it externally.*
