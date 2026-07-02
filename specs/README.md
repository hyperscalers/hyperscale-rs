# Protocol Models

Machine-checked models of hyperscale's protocols, written in [Quint](https://quint-lang.org/) and checked with Apalache (`quint verify`). The properties come from the invariant register ([docs/08-invariants.md](../docs/08-invariants.md)); models cite INV-* IDs rather than restating them.

## Model register

| Model | File | Scope | Properties | Status |
|---|---|---|---|---|
| **A** | [wt_clock.qnt](wt_clock.qnt) | The weighted-time clock: per-vote clamp, quorum mean, admission plausibility, epoch resolution | INV-SHARD-6, INV-BEACON-3/4 | Verified |
| **B** | [shard_consensus.qnt](shard_consensus.qnt) | Shard consensus (the HotStuff-2 variant): safe-vote rule, round-contiguous commit, crash-recovery register re-init. The broken twin is the register-persistence gap, not artificial constants: one crash + F Byzantine forks the commit (scripted witness + Apalache search) | INV-SHARD-1..4 | Verified (depth 8) |
| **C** | — | Atomic commitment with shard consensus abstracted to a commit oracle: provision → execute → certify, deterministic aborts, wave deadlines | INV-EXEC-1/4/5 | Planned |
| **D** | — | Straddler settlement layered on C: settled set, fence, sweeps, late-EC materialization | INV-RESHAPE-5/6 | Planned |

Models compose by abstraction, not size: each takes the earlier models' verified properties as axioms. B resolves committees through A's clock properties; C treats a shard chain as an atomic commit oracle justified by B; D adds shard termination on top of C. No model ever contains the whole system.

## Discipline

1. **Properties come from the register.** A spec states which INV-* IDs it checks and under which abstraction. If a property isn't in the register, it goes into the register first.
2. **Transitions come from the code, not the docs.** Every modeled rule names its implementing code (crate/file + function) in a comment. The docs are the map; the code is the territory — a model transcribed from prose verifies the documentation. Deviations between model and implementation (simplified quorum counting, symmetry reductions) are stated explicitly with the argument for why they preserve the checked properties.
3. **Assumptions live in the header.** What is idealized (crypto, network), what is an oracle (components verified by an earlier model), and the encoding choices Apalache forces.
4. **Every model ships a broken twin.** Alongside the healthy instance, an instance whose constants or rules violate the property's precondition, with the counterexample reachable by `quint verify`. A checker that has never produced a counterexample against the model proves nothing about the model.
5. **Three tiers, in order.** `quint typecheck` (syntax/types), `quint run --invariant=...` (fast random search), `quint verify --invariant=...` (Apalache: exhaustive over all behaviors to a bounded depth — default 10 steps, raise with `--max-steps`). Bounded checking is not proof; inductive invariants are the upgrade path once a model stabilizes.
6. **Findings close the loop.** A counterexample — or a suspiciously easy pass — is not a result until it is traced through the implementation from first principles and resolved as a code change, a doc change, or a documented non-issue.

## Apalache notes

- Symbolic mode requires **constant integer ranges**: encode state-relative quantities as offsets in a constant band (never `a.to(b)` with a state- or nondet-dependent bound), and pick subsets via `powerset()` with a size guard rather than an index range.
- **[Choreo](https://github.com/quint-co/choreo) is `quint run`-only.** Its row-polymorphic core fails Apalache's type recovery on Choreo's own examples (2PC: Snowcat error on `choreo::s`; MonadBFT: JVM crash), and its test suite never invokes `verify`. Models here are plain Quint; Choreo's file organization (types/protocol/instance split, explicit local-state records) is still worth imitating.
- `quint verify` downloads Apalache automatically on first use; a JDK must be on the PATH.
- Counterexamples land in `_apalache-out/` (gitignored), including ITF JSON traces — the format a future model-based-testing bridge can replay against the Rust state machines.
