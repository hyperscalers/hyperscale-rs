# Hyperscale system documentation

Architecture documentation for hyperscale-rs: what the system is, the technical qualities that make it distinctive, and the properties it guarantees. These docs serve three consumers:

1. **Technical readers** who want the real design without reading the code — each doc is a self-contained narrative with light code anchoring (crate and type names, no line numbers).
2. **Distillation** — a faithful source from which further-simplified explainers and graphics can be produced.
3. **Formal verification** — critical properties are stated inline where they arise and consolidated with stable IDs in the invariant register.

## Reading order

Start with the overview; it tells the whole story in five pages and links down.

| Doc | Contents |
|---|---|
| [00-overview.md](00-overview.md) | The whole system in miniature: the problem, the three consensus layers, atomic cross-shard commitment, dynamic sharding, the security model, determinism — and the five-property verification core |
| [01-consensus-layers.md](01-consensus-layers.md) | Shard consensus (HotStuff-2), execution consensus (certificates over outcomes), beacon consensus (PC/SPC), and the weighted-time clock + topology schedule that harmonize them |
| [02-dynamic-sharding.md](02-dynamic-sharding.md) | Split and merge lifecycles, deterministic genesis derivation, and straddler settlement (atomicity across a vanishing shard) |
| [03-state-and-sync.md](03-state-and-sync.md) | The binary JMT, owner-prefixed keying, the storage stack, checkpointing, snap-sync, block/remote-header sync, divergence recovery |
| [04-atomic-commitment.md](04-atomic-commitment.md) | Deterministic atomic commitment end to end: declared access, the provision–execute–certify pipeline, deterministic aborts, data availability |
| [05-byzantine-safety.md](05-byzantine-safety.md) | Threat model and the committee security model behind INV-SEC-1 (the three corruption tiers and their defenses, the stake-to-shard-control conversion rate, randomness integrity), committee sampling and shuffling, jailing and conviction, cryptography, cross-shard trust, resource bounds |
| [06-resource-economics.md](06-resource-economics.md) | The self-regulating validator supply: the market-clearing minimum stake, the pool/lifecycle gates it drives, and vnodes as hardware amortization |
| [07-determinism-and-testing.md](07-determinism-and-testing.md) | The sans-io state-machine architecture, the two harnesses, portable scenarios, and why determinism underwrites everything else |
| [08-invariants.md](08-invariants.md) | The consolidated register of safety/liveness properties with stable IDs (INV-*) — the formal-verification starting point |

## Conventions

- **Invariant IDs** (`INV-<AREA>-<n>`) are stable references. They appear inline in each doc where the property arises; the precise statements live once, in [08-invariants.md](08-invariants.md). Cite them rather than restating properties.
- **Code anchors** name crates and load-bearing types (for example `QuorumCertificate` in `crates/types`, `ReshapeOrchestrator` in `crates/node`). They are entry points for a code dive, not line-precise references.
- The docs describe the system as designed and built on `main`; known interim gaps are flagged explicitly where they exist (for example [04-atomic-commitment.md](04-atomic-commitment.md) §5, the register's "known deliberate gaps").
