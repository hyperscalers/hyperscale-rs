# Determinism and testing: the sans-io architecture

Hyperscale's most consequential engineering decision is not a consensus rule. It is that **the entire protocol stack is written as deterministic state machines with no I/O of their own**, and that the identical code runs under both a deterministic simulator and production I/O. Every property claimed in the other documents is testable *because* of this: multi-shard networks, reshapes under load, partitions, and Byzantine message schedules all replay byte-identically from a seed. The hardest code paths in the system — dynamic resharding, straddler settlement — are rare, multi-epoch, cross-shard interleavings, and for those this architecture is the difference between "believed correct" and "exercised thousands of times under adversarial schedules".

Main code homes: `crates/core` (the state-machine contract), `crates/node` (composition and host), `crates/dispatch*` (work scheduling), `crates/network*` (transport), `crates/simulation` and `crates/scenarios` (the deterministic harness), `crates/production` (the real runner).

---

## 1. The contract: pure state machines

Everything protocol-relevant implements one interface (`crates/core`):

```rust
fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action>
```

- **`ProtocolEvent`** is everything that can happen *to* a node: messages arrived and verified, timers fired, work completed, blocks persisted.
- **`Action`** is everything a node can ask *for*: broadcast this, fetch that, verify this signature batch, execute these transactions, set this timer, persist this block.
- Between the two sits pure logic: no `.await`, no locks, no threads, no I/O, no `Instant::now()`, no OS randomness. The transition is a function of `(state, now, event)` and nothing else (INV-DET-1).

`NodeStateMachine` (`crates/node`) composes the per-domain coordinators — beacon, shard consensus, mempool, execution, provisions, remote headers — behind that single `handle`. Every stateful protocol component down to the sync FSMs and the reshape orchestrator follows the same discipline; anything that needs the time is *fed* the time.

Runners close the loop: they turn `Action`s into real work and completions back into `ProtocolEvent`s. Actions split into inline (timer registry mutations, continuations), delegated (CPU work — signature verification, QC assembly, Radix Engine execution — dispatched to pools via the `Dispatch` trait), network, and persistence. Adding a variant forces updating its routing classification, so the sans-io boundary is maintained mechanically.

## 2. Time discipline

Three time types, three roles, no blending:

| Type | Nature | Used for |
|---|---|---|
| `LocalTimestamp` | Node-local monotone clock, fed into `handle` | Timers, backoff, liveness deadlines. Never consensus-visible: never hashed, never signed |
| `ProposerTimestamp` | One validator's wall-clock claim | Proposal payloads; raw material for QC aggregation; local plausibility checks only |
| `WeightedTimestamp` | Quorum-attested clamped average, monotone per chain | Everything consensus-critical: committee resolution, validity windows, wave deadlines, DA retention, reshape boundaries ([01-consensus-layers.md](01-consensus-layers.md) §1.3) |

The central rule: **state machines never read a clock; they are told the time** (INV-DET-2). In production, runners stamp `LocalTimestamp` from the system clock at the event boundary; in simulation, from the event queue. Any `Instant::now()` inside an FSM is a determinism bug by definition. One such call (in the shared sync FSM) caused a genuinely load-dependent test flake — exactly the class of defect the rule exists to make structurally impossible.

The same discipline covers randomness (consensus randomness comes only from the beacon's attested accumulator; harness randomness only from seeds) and encoding: all wire and hashed types use SBOR with ordered collections (`BTreeMap`/`BTreeSet`, never hash-ordered iteration), so serialization is a pure function of value (INV-DET-5).

## 3. The two harnesses

One `NodeHost<Storage, Network, Dispatch>` is generic over its three I/O seams; the harnesses differ *only* in what they plug in (INV-DET-3):

| Seam | Production | Simulation |
|---|---|---|
| Storage | RocksDB (`storage-rocksdb`) | In-memory persistent structures (`storage-memory`) |
| Network | libp2p: gossipsub + QUIC request/response (`network-libp2p`) | In-memory mesh with seeded latency/jitter/loss and fault rules (`network-memory`) |
| Dispatch | Rayon thread pools, consensus work isolated from bulk throughput work (`dispatch-pooled`) | Inline, sequential (`dispatch-sync`) |
| Time/events | Tokio timers; one pinned thread per hosted shard owning its state machine (no mutex on consensus state) | A single global event queue under one total deterministic order, time first; time advances only by draining it |

The simulator (`crates/simulation`) runs whole networks — many hosts, many shards, the beacon, reshaping, fault injection — in one process, with **every** source of scheduling nondeterminism replaced by the seeded queue. Same seed, same run, byte for byte, faults included: the fault engine draws from an RNG stream salted off the master seed, so injected drops and partitions replay too (INV-DET-4). A failure found at seed N is a permanent, single-command reproduction.

Two structural bonuses of the host model are present in both harnesses. The first is multi-vnode hosting: several validator identities per process share one `Arc<TopologySnapshot>`, per-shard stores, and process-level caches, with a signer-seat mechanism ensuring co-hosted identities can never equivocate during handoffs. The second is local dispatch: co-hosted communication bypasses the transport entirely, handing the receiver the sender's own `Arc`-counted object with no serialization round-trip, while following identical protocol paths. What makes the shortcut sound is the `Verifiable<T>`/`Verified<T>` typestate (`crates/types`): verification is a type-level marker that survives in-process handoffs but cannot be constructed by decoding wire bytes. A payload verified once on a host is never re-verified by a co-hosted identity, and anything from the real network is forced through its predicate before it can carry the marker (INV-DET-6). The economic reading of vnode hosting is in [06-resource-economics.md](06-resource-economics.md) §4.

## 4. Portable scenarios

The layer that makes the parity claim operational (`crates/scenarios`): behavioral tests written against an abstract `Cluster` interface — step the world, submit transactions, query committed heights/topology/mempool, wait for conditions under a budget — with two adapters, one wrapping the simulator and one driving a real multi-process cluster. The scenario code is identical; only the adapter differs.

The catalogue tracks the properties the other documents claim — representative entries: liveness baselines; single- and cross-shard transaction settlement; livelock resolution; validator registration/witness flows; grow-to-N-shards topology lifecycles; split and merge lifecycles including full-strength successor committees; **straddler atomicity across both split and merge boundaries**; and the fault suite (gossip drop recovered by fetch fallback, partition-halt-heal, isolated validators, cross-shard DA channel loss with request-leg loss stacked on top). Fork safety has a dedicated adversarial harness asserting no committable fork exists under hostile scheduling.

The interpretive rule (INV-DET-3's payoff): **a scenario that passes on one harness and fails on the other has found a real defect** — in the production runner, in the fault model's realism, or in a nondeterminism leak — never a "flaky test". Debugging effort always lands on a root cause.

## 5. Why this is load-bearing for the whole design

- **The rare paths get the most testing.** Reshapes, straddler settlement, and partition recovery are weeks-apart events in production but run thousands of seeded permutations in CI. Nearly every subtle defect recorded in this system's development — timestamp-source divergence in reshape genesis, a commit-pipeline prune wedge, an eager-feed prefix collapse in beacon consensus — was found as a deterministic simulation failure, minimized by seed, and fixed with a permanent regression scenario.
- **Determinism is doing double duty.** The same property that makes tests reproducible makes *replicas agree*: consensus-side determinism (execution, folds, conflict verdicts, retention decisions) and test-side determinism (seeded harness) are the same architectural muscle.
- **It is the bridge to formal verification.** Every protocol component is already a pure transition function with explicit inputs — not code entangled with sockets, threads, and clocks — so extracting a model is a translation task, not an archaeology task. Any modeled property can be cross-validated against the running system through the scenario layer. The invariant register ([08-invariants.md](08-invariants.md)) is written against these transition functions.

## 6. Properties

The determinism invariants this document motivates — INV-DET-1 through INV-DET-6 — are stated precisely in [08-invariants.md](08-invariants.md).
