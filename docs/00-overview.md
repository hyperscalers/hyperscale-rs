# Hyperscale: system overview

Hyperscale is a sharded smart-contract platform that scales **linearly**: add shards, get proportional throughput. It preserves the two properties that sharding normally destroys. The first is **atomic composability**: a transaction touching accounts on several shards either commits everywhere or nowhere. The second is **atomic commitment with BFT finality**: once committed, the result is final and identical on every honest replica, with no cross-shard reconciliation phase, no optimistic rollback, and no bridge.

This document is the whole story in miniature. Each section points into a companion document that carries the full mechanism and its invariants:

| Doc | Covers |
|---|---|
| [01-consensus-layers.md](01-consensus-layers.md) | The three consensus mechanisms — beacon, shard, execution — and the weighted-time clock that harmonizes them |
| [02-dynamic-sharding.md](02-dynamic-sharding.md) | Splitting and merging shards live, and settling transactions that straddle a reshape boundary |
| [03-state-and-sync.md](03-state-and-sync.md) | The binary Jellyfish Merkle Tree, shard checkpointing, snap-sync, and divergence recovery |
| [04-atomic-commitment.md](04-atomic-commitment.md) | Deterministic atomic commitment across shards: the provision–execute–certify pipeline, deterministic aborts, data availability |
| [05-byzantine-safety.md](05-byzantine-safety.md) | The adversary model: committee sampling, node shuffling, jailing, fork safety, network hardening |
| [06-resource-economics.md](06-resource-economics.md) | The self-regulating validator supply — demand-tracking stake pricing — and vnodes as hardware amortization |
| [07-determinism-and-testing.md](07-determinism-and-testing.md) | The sans-io architecture and deterministic simulation that make the system testable end to end |
| [08-invariants.md](08-invariants.md) | Consolidated register of the safety and liveness properties, with stable IDs — the starting point for formal verification |

## The problem being solved

A single BFT chain has a hard throughput ceiling: every validator executes every transaction. Sharding removes the ceiling by partitioning state and validators, but the known designs give something up. Most sharded systems make cross-shard operations asynchronous (message-passing between shards, with user-visible intermediate states), or optimistic (execute first, reconcile or roll back later), or they restrict composability (contracts can only interact within a shard). Hyperscale's position is that none of these compromises is necessary. A transaction declares the state it touches, the shards that own that state cooperate through a proof-carrying commitment protocol, and the transaction commits atomically across all of them — with the same synchronous, composable semantics a single chain provides.

Two further design commitments distinguish the system:

1. **Sharding is dynamic.** Shards split under load and merge when load recedes, at runtime, without halting the network, without operator choreography, and without breaking atomicity for transactions in flight across the boundary. The shard topology is a living structure that tracks demand.
2. **Everything is deterministic.** The entire consensus stack is written as pure state machines with no I/O, no clocks, and no randomness of their own. The same code runs under a deterministic simulator (where whole multi-shard networks, fault injection included, replay byte-identically from a seed) and under production I/O (tokio, libp2p, RocksDB). This is not a testing convenience bolted on afterwards; it is the architectural spine that makes the rest verifiable.

## Three consensus mechanisms, one clock

Hyperscale runs three distinct consensus mechanisms, each shaped for its job, harmonized into one system ([01-consensus-layers.md](01-consensus-layers.md)):

**Shard consensus** orders transactions. Each shard runs an independent HotStuff-2 BFT chain: a rotating proposer, one vote per validator per round, 2f+1 quorum certificates (QCs), and a round-contiguous two-chain commit rule. Shard chains run concurrently and asynchronously with respect to each other; that concurrency is where the linear scaling comes from.

**Execution consensus** agrees on results. Ordering a transaction is not the same as agreeing on what it did. After a block commits, its transactions execute (deterministically, in the Radix Engine), and the shard's validators vote on the outcome. 2f+1 matching votes form an **ExecutionCertificate** attesting the per-transaction outcomes and a receipt root. For cross-shard transactions, each participating shard produces its own certificate over the *same* outcome set, and the bundle of certificates — the wave certificate — is the atomic commit proof. Separating execution agreement from ordering agreement lets a shard commit to *running* a cross-shard transaction before it can know the result. That separation is the key to atomic cross-shard semantics without cross-shard locking of consensus itself.

**Beacon consensus** coordinates the validator set and topology. The beacon is a single, deliberately slow chain — one block per epoch — proposed by a sampled global committee running a prefix-consensus protocol (PC/SPC) and committed by a ratification vote of the serving validator pool. The beacon does not see transactions. It folds a deterministic state machine over per-epoch inputs: shard boundary attestations, validator registration and readiness witnesses, jailing evidence, reshape triggers. From that state it derives the one artifact every other layer depends on: the **topology schedule**, mapping any point in time to the committee that governs each shard at that time.

The harmonizing element is **weighted time (WT)**. Every shard QC carries an aggregate of its voters' clock readings: each vote is clamped to be no earlier than the parent QC's timestamp, then the readings are averaged over the quorum. The clock is therefore monotone along the chain, and values implausibly far ahead of a replica's own clock are rejected wherever a QC enters chain state. This gives every committed block a BFT-attested timestamp that all honest replicas agree on — a distributed clock that Byzantine validators can only boundedly skew. Committees are bound to WT windows: to verify any block, a replica computes `epoch_for(parent_qc.weighted_timestamp)` and looks up the committee in the schedule. The binding is exact, with no grace periods and no skew tolerance, and the schedule is computed one epoch ahead (frozen before the window opens), so every replica resolves the identical committee for any artifact it can ever encounter. Weighted time is what lets dozens of asynchronous shard chains and one slow beacon chain agree on *who is in charge of what, when* without synchronized clocks.

## Atomic cross-shard commitment

Transactions declare their read/write sets up front. A cross-shard transaction is routed to every shard that owns declared state, and commitment proceeds as a deterministic three-stage pipeline — **provision, execute, certify** ([04-atomic-commitment.md](04-atomic-commitment.md)):

1. **Provision.** Each source shard commits the transaction and broadcasts **provisions** — the substate values the other shards need, carried with a JMT merkle multiproof against the source's QC-attested state root. A provision is not a message from a node; it is an attested fact about a committed block.
2. **Execute.** When a shard holds provisions from every counterparty shard, it executes the transaction against the merged state. Execution is deterministic, so every shard — running the same engine on the same inputs — computes the same result. Cross-shard transactions are grouped into **waves**; validators vote on the wave's outcome; 2f+1 votes make the shard's ExecutionCertificate.
3. **Certify.** A wave finalizes when certificates from *all* participating shards agree on the same global receipt root. One shard cannot commit a result the others didn't reach: the outcome vector is inside every certificate, and certificates from different shards over different outcomes simply never assemble into a valid wave certificate.

Liveness is protected by construction rather than by retry. The mempool's ready set enforces that no two in-flight transactions share any declared node, so deadlocks between local transactions cannot form. A deterministic conflict detector aborts true cross-shard cycles by hash order; every replica derives the same verdict from committed state alone. And every wave carries a deadline derived from BFT-attested time, after which it deterministically all-aborts. Every transaction terminates; no lock is held forever; no two shards ever disagree on the terminal outcome.

## Dynamic sharding

State lives in one global **binary Jellyfish Merkle Tree** whose 256-bit keyspace is partitioned by prefix: a shard *is* a subtree ([03-state-and-sync.md](03-state-and-sync.md)). Internal engine objects (vaults, key-value stores) are keyed under their owning account's prefix — owner-prefixed keying — so ownership never straddles a shard boundary and every shard remains a clean prefix subtree. Resharding is therefore a tree operation:

- **Split**: a shard's subtree root has exactly two children; each becomes a new shard's root. `hash_internal(left, right) == parent_root` is the continuity proof.
- **Merge**: two sibling shards' roots compose back into their parent by the same hash. No state is copied or re-keyed in either direction.

The lifecycle is beacon-orchestrated ([02-dynamic-sharding.md](02-dynamic-sharding.md)). A shard whose committed state crosses a byte threshold asserts a split trigger in its block manifest; replicas validate the predicate against their own state, so the trigger is a claim about committed facts, not an operator command. The beacon draws observer cohorts from the validator pool, the observers snap-sync their assigned child's subtree while the parent keeps running (make-before-break), and only when both child committees have 2f+1 *ready* members does the beacon execute the flip. Each child's genesis block is derived purely from frozen chain content — the parent's terminal block plus the beacon-recorded anchor — and must hash exactly to what the beacon committed; any divergence fails closed. Merging is symmetric, with keeper committees drawn half from each child.

The hardest problem is the transaction that straddles the boundary: a cross-shard transaction whose counterparty shard terminates mid-flight. Hyperscale resolves this with the **settled set**. The terminating shard's final block determines exactly which waves it settled, and that set's root is attested into the beacon. Surviving shards fetch and verify the set, then enforce a fence: a wave naming a shard that is terminating (from the moment its reshape is admitted) or terminated finalizes if and only if that shard settled it; everything else deterministically aborts. Every decision derives from frozen chain content, never from message timing, so no straddler can commit on one side and abort on the other.

## Byzantine safety in a sharded world

Per committee, the model is classical BFT: safety is guaranteed with fewer than one-third Byzantine members, and quorums are 2f+1 ([05-byzantine-safety.md](05-byzantine-safety.md)). The claim the security model defends is deliberately bounded: security-competitive with an unsharded BFT chain while scaling far beyond one, not safer than one. Sharding replaces the single chain's hard one-third threshold with a probabilistic conversion from network-wide corruption to per-committee corruption, and the model's job is holding that conversion near one-to-one.

The sharding-specific question is therefore how per-committee honesty is maintained when the adversary can see committee assignments. Hyperscale's answer is layered. Committee membership is drawn by seeded randomness, rolled forward each epoch from beacon entropy, so it cannot be predicted far ahead. Membership **shuffles** continuously — a trickle of one member per shard per interval — preserving quorum while denying a slowly-adaptive adversary time to concentrate corruption on one shard. And misbehavior is expelled: equivocation (a double-signed beacon ballot or a shard double-vote) is self-proving evidence and jailed permanently, while chronic liveness faults are witnessed on-chain (via merkle-proven missed-proposal leaves that a proposer cannot selectively omit) and jailed on threshold. How strong that layered answer actually is — the three corruption tiers (guaranteed safety below one-third, recoverable degradation from f+1, terminal compromise at 2f+1) and the corruption bands the pool tolerates — is [05-byzantine-safety.md](05-byzantine-safety.md) §1.

Cross-shard trust rests only on attested artifacts: a shard verifies a counterparty's headers by that shard's QCs under the WT-resolved committee, provisions by merkle proof against those headers, and results by execution certificates. No shard ever trusts a *node* from another shard — only quorums.

## A self-regulating validator economy

An elastic topology makes validator demand a moving target — every split needs a fresh committee, every merge releases one — so the cost of activating a validator is not fixed but **priced by the protocol itself** ([06-resource-economics.md](06-resource-economics.md)). Each epoch, the beacon fold computes the network's target population (committees × committee size, plus a standing reserve) and sets the minimum activation stake to the market-clearing level. When stake supply is abundant relative to need, the price rises and seat-farming becomes uneconomic. When the network runs short — after a burst of splits, say — the price falls toward a hard sybil floor, refilling the pool exactly when it is needed. Two clamps keep the price safe: it never rises past the point that would eject a sitting validator, and it never falls below the floor that keeps committee corruption expensive.

The complementary mechanism is the **vnode**: one process hosts many validator identities, sharing storage, execution, and networking (two vnodes in one shard share one store and one execution per transaction), so the marginal cost of a seat approaches its stake. Hardware never becomes the binding constraint on an elastic validator supply; stake, the quantity the security model actually prices, always is.

## Determinism as the spine

Everything above is implemented as sans-io state machines: `handle(now, event) → actions`, with no async, no locks, no wall clock, and no OS randomness ([07-determinism-and-testing.md](07-determinism-and-testing.md)). Production runners feed events from libp2p/tokio/RocksDB; the simulator feeds them from a seeded event queue with an in-memory network, fault injection, and inline dispatch. The identical `NodeStateMachine` runs in both. Portable scenarios — full behavioral tests like "split a shard under straddler load and prove atomicity held" — execute on both harnesses, so a scenario that passes in simulation and fails in production (or vice versa) is by construction a real defect, not a flaky test. Multi-shard fault scenarios (partitions, message drops, crash-recovery, reshapes under load) replay byte-identically from a seed. That reproducibility is why the reshaping and settlement machinery — ordinarily the least testable part of a sharded system — is the most heavily exercised code in the repository.

## What to formally verify first

The invariant register ([08-invariants.md](08-invariants.md)) enumerates the full property set, but the critical core is small:

1. **Shard agreement** (INV-SHARD-1): no two honest replicas commit different blocks at a height — the HotStuff-2 safe-vote rule plus the round-contiguous commit rule.
2. **Atomic commitment** (INV-EXEC-1): a cross-shard transaction reaches the same terminal outcome on every participating shard.
3. **Straddler atomicity across reshapes** (INV-RESHAPE-5): the settled-set fence preserves INV-EXEC-1 even when a participating shard ceases to exist.
4. **Topology determinism** (INV-BEACON-3/4): every honest replica resolves the identical committee for any weighted timestamp it can encounter.
5. **State continuity across reshapes** (INV-RESHAPE-2/3): reshape genesis derivation is a pure function of frozen chain content, and subtree roots compose exactly.

Everything else in the system — the DA machinery, the sync protocols, the caches — exists to make these five hold under partial synchrony, faults, and adversarial scheduling.
