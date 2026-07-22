# Dynamic sharding: splits, merges, and straddler settlement

Hyperscale's shard topology is elastic. A shard whose state grows past a threshold **splits** into two children; two sibling shards whose combined state shrinks below a threshold **merge** back into their parent. Both happen at runtime, orchestrated by the beacon, without halting the network — and without breaking atomicity for cross-shard transactions in flight across the boundary.

Three structural choices make this tractable, and everything else in this document is machinery built on them:

1. **A shard is a subtree.** State lives in one global binary JMT; a shard is a prefix subtree of it ([03-state-and-sync.md](03-state-and-sync.md)). A split hands each child one of the parent root's two children; a merge composes the parent root back as `hash_internal(left, right)`. Resharding is a tree operation with a one-hash continuity proof, not a data migration.
2. **The boundary is a block, not a negotiation.** A reshaping shard terminates at a definite **terminal block**, fixed by epoch schedule. The system never waits for in-flight work to drain; that would make the boundary timing-dependent and non-deterministic. Instead, transactions straddling the boundary are settled after the fact by rules over frozen chain content (§4).
3. **Everything derives from committed facts.** Cohort draws are seeded by beacon randomness; readiness is witnessed on-chain; successor genesis blocks are pure functions of the terminal block plus the beacon-recorded anchor, and fail closed on any hash mismatch. No step depends on message timing or operator input.

Main code homes: reshape admission/gating in `crates/beacon` (`PendingReshape`, the fold's reshape module), the flip and duty machinery in `crates/node` (`ReshapeOrchestrator`, split/merge flip, observer/keeper bootstrap), settlement in `crates/node` cross-shard settled-set types plus fence checks in `crates/shard`, thresholds in `crates/types` (`ReshapeThresholds`).

---

## 1. Triggers: load-driven, proof-carrying

A shard proposes its own resharding. When a shard's committed substate byte total crosses `ReshapeThresholds::split_bytes`, its proposer includes a `ReshapeTrigger::Split` assertion in the block manifest. The assertion is a *claim about committed state*, and every replica validates it against its own byte accounting before voting — a Byzantine proposer cannot conjure a split. Merge triggers work the same way against a much lower threshold (`ReshapeThresholds::merge_bytes`, derived from the split threshold); the wide hysteresis gap between a fresh split child's size and the merge threshold prevents split/merge oscillation. Reshaping is disabled unless the thresholds are explicitly configured. Governance can move them by on-chain parameter vote, which is also how operationally driven merges are effected.

One place the predicate is deliberately out of play: across a pending halt recovery, a block whose ancestry crosses the sync-admitted halted suffix carries no assertion, and no replica requires one. The suffix is QC-attested but never locally executed by the fresh committee, so its byte total is unknowable until it commits — a commit that needs the very blocks being gated. Every member of the only committee that can vote there synced the same suffix, so the omission is agreed on both sides. Once the suffix commits and the frontier reconciles from storage, ordinary accounting resumes; an over-threshold shard simply asserts on a later block.

Triggers must be re-asserted; a trigger silent for `RESHAPE_TRIGGER_TTL_EPOCHS` lapses. The beacon tracks each shard's pending reshape in a `PendingReshape` record — `Split { cohort, cohort_seed, ... }` or `Merge { halves, keepers, ... }` — inside `BeaconState`.

## 2. The split lifecycle

**Admission and cohort draw.** On folding a split trigger (gated on the free validator pool being deep enough to staff it), the beacon draws a committee-sized **observer cohort** from the pool, seeded by `cohort_seed` — beacon randomness frozen at admission. The shuffled cohort is halved: the first half is assigned to the left child, the remainder to the right. Observers get status `Observing` and start work immediately. Because the seed is frozen, a lapsed-then-reasserted split re-derives the *identical* cohort — an observer's sync target never moves under it.

**Preparation (make-before-break).** While the parent keeps producing blocks, each observer snap-syncs its assigned child's subtree: a verified range-fetch of the child's key span against the beacon-anchored state root, followed by tailing the parent chain and applying each new block's child-prefix writes ([03-state-and-sync.md](03-state-and-sync.md) §5). When caught up, the observer emits a `ReshapeReady` witness — an on-chain, merkle-proven fact.

**The readiness gate.** The beacon's fold executes the split only when **both** children can seat a live committee: each child's prospective membership — its half of the parent's current committee (assigned deterministically from beacon randomness) plus its ready cohort seats — must reach 2f+1 of the committee target (INV-RESHAPE-1). Parent members carry their readiness and placement epoch across the flip; losing placement history was an observed liveness bug — it strands committees. Until both halves pass, nothing changes. If readiness doesn't arrive within `RESHAPE_READY_TTL_EPOCHS`, the reshape is abandoned and the cohort returns to the pool.

**Execution.** In the first passing fold, the parent's lookahead committee entry is replaced by the two children's committees, the parent's boundary record is marked terminal at a scheduled epoch, and the children receive placeholder boundary records (zero block hash) so they cannot yet be mistaken for snap-sync anchors.

**Terminal coast and the flip.** The parent chain runs to its terminal block `B` — the last block whose canonical weighted timestamp falls inside its final window — then *coasts*: empty fallback blocks that exist only to certify `B` and hand off. The header of the terminal-epoch chain carries `SplitChildRoots`, the two child subtree roots, which every replica checks compose to the parent's state root: `hash_internal(left, right) == parent_root` (INV-RESHAPE-3).

Each child's genesis block is then derived, by every seated member independently, from frozen content only:

```
split_genesis_from_terminal(child, terminal_header, terminal_qc, anchor) → genesis
```

The clock is taken from `anchor.weighted_timestamp` — the canonical parent-QC-derived value the beacon recorded — **never** from the served QC. The terminal block may have been re-certified at a higher round during the coast, and a re-cert's timestamp is a gossip artifact, not consensus content. The derived genesis must hash exactly to the beacon-anchored `ShardAnchor.block_hash`; any mismatch fails closed (INV-RESHAPE-2/4). Children seat, begin proposing at `terminal.height + 1`, and report their own boundary crossings to the beacon; the parent dissolves once the beacon observes both children live.

**Retention for stragglers.** The parent's terminal boundary record is retained in beacon state until both children have seeded, and thereafter until `terminal_wt + RETENTION_HORIZON`, so late joiners and counterpart shards can still resolve the terminal anchor, its committee, and the settled-waves root (INV-BEACON-8).

## 3. The merge lifecycle

Merging is the split run backwards, with one asymmetry: the successors already exist and are running.

**Pairing and keeper draw.** Both children must assert merge triggers within the TTL window. On pairing, the beacon draws a **keeper committee** — half from each child's ready members, seeded from beacon randomness. Keepers keep running their own child (status unchanged) and take on a second duty: building the merged parent store. Keepers are **pinned** — the shuffle skips them, as it skips all mid-reshape shards, because a rotated-out keeper would strand the merged committee below quorum (INV-RESHAPE-7).

**Preparation.** Each keeper snap-syncs the *sibling* child's subtree alongside its own and emits `ReshapeReady` when the merged store is assembled. The merged store is a composition, not a copy: two child subtrees under one root, verified as `hash_internal(left_root, right_root)`.

**Gate and execution.** When ready keepers reach 2f+1 of the merged committee target, the fold executes: both children's lookahead entries are replaced by the parent's (committee = exactly the keepers), both children are marked terminal, non-keepers return to the pool, and the parent gets a placeholder boundary.

**Composition and the flip.** Both children coast to their terminal blocks. The beacon composes the parent's anchor from the two terminal contributions: the state root is `hash_internal(r_left, r_right)`, and the anchor clock is the start of the epoch containing the left child's canonical terminal timestamp. The clock is floored off the terminal's actual weighted timestamp, not its scheduled epoch, so the value stays reproducible even when a child coasts extra epochs past its cut. Keepers derive `merge_genesis_from_terminals(parent, left_terminal, right_terminal, anchor)` with the clock read from `anchor.weighted_timestamp` — never from the served terminal QCs, whose re-certified timestamps could floor to a different epoch — verify the result against the anchor hash, and seat the merged committee; the children dissolve. Each child's terminal boundary is retained until the parent has composed, mirroring the split retention rule.

## 4. Straddler settlement: atomicity across a vanishing shard

The straddler problem: a cross-shard transaction is mid-flight — provisioned, maybe executed, not yet finalized — when one of its participating shards `P` reaches its terminal block and stops existing. The counterpart shard `Q` holds locks and awaits `P`'s execution certificate. Without a rule, two failure modes open, and both were the motivating incidents for this design:

- **H1 (liveness):** `P` dies without delivering; `Q` holds locks forever.
- **H2 (safety):** `P`'s EC is aggregatable from held vote shares *after* termination — `Q` could finalize a result that `P`'s chain never applied, a one-sided commit.

The rejected fix was *inheritance*: let `P`'s children adopt and complete the parent's in-flight work. It fails for a fundamental reason. Whether an EC "exists" is a gossip-time fact — a leader holding vote shares can materialize one arbitrarily late — so different replicas (and the two children) can legitimately disagree on it. Any rule keyed on EC existence turns atomicity into a race. **The only admissible inputs are frozen chain content.** That principle produces the actual design.

**The settled set.** For a terminated shard `P`, define `S_P` as the set of wave ids whose `FinalizedWave` committed in `P`'s chain at or before the terminal block `B`, across the window reaching back to the terminating reshape's admission (backed off by one wave lifetime). The window must reach admission, not a fixed span behind the terminal: the fence below holds straddlers from the moment the reshape is admitted, and a scheduled window spans multiple epochs, so a terminal-relative span would silently drop settlements made early in it and turn their absence from `S_P` into a false "never settled". `S_P` is a pure function of `P`'s frozen chain: each block's certificate root enumerates its finalized waves. `P`'s terminal-epoch headers carry `settled_waves_root`, the merkle root of `S_P`; the beacon fold records that root into `P`'s terminal `ShardBoundary` and projects it into every survivor's `ShardAnchor`. The set is thus **beacon-attested**: a survivor knows the root from its own beacon fold before it fetches a single byte (INV-RESHAPE-6).

**Acquisition.** A survivor that needs the actual set runs a one-shot verified fetch (`SettledWavesAcquisition`): request the window's wave-id list from `P`'s terminal committee, verify `settled_waves_root_from_ids(fetched) == attested_root`, rotate peers on failure, and self-expire once past `terminal_wt + RETENTION_HORIZON`.

**The fence** (a consensus rule, enforced at vote and at local finalization): a block carrying a `FinalizedWave` whose certificate names a shard `P` that has terminated — *or is scheduled to* — is votable if and only if the wave id is in `S_P`. The fence engages the moment `P` has an admitted terminating reshape, not only once `P` is past-terminal. A survivor that finalized a straddler in the window between the reshape's admission and `P`'s terminal block could otherwise apply a wave `P` never settled: `P` produces its own EC yet, under an asymmetric partition, never receives the survivor's before its cut. The verdicts for a wave naming `P` follow: while `P` is scheduled-terminal and the settled set does not yet exist, the wave defers; once `P` is past-terminal and the wave id is in `S_P`, it passes; once the set is acquired and the id is absent, it is rejected; past the retention horizon, it is rejected absolutely. Deferral resolves only on evidence — the settled set arriving, the reshape lapsing, or the schedule evicting `P` — never on a local clock: a deadline abort could contradict a settlement `P` already committed, and `RETENTION_HORIZON` guarantees termination everywhere, not agreement. Symmetric checks gate a replica's own finalization path, so an honest node never produces what the fence would refuse (INV-RESHAPE-5). The scheduled-terminal check keys on frozen schedule content (the active and lookahead windows' pending-reshape projection), so both sides derive the same verdict.

**The abort sweeps** (deterministic cleanup, no consensus needed):

- *Counterpart sweep* on `Q`: once `S_P` is ingested, any transaction naming `P` that still lacks `P`-coverage can never gain it — every other `P`-EC the world could produce is fenced. Release locks, abort, done. This includes the subtle late-EC case: an EC arriving after termination that would complete a wave gets gate-rejected, and the rejection itself feeds the sweep.
- *Parent sweep* on `P`'s own replicas at termination: every committed-but-unfinalized transaction aborts locally — pure cleanup, identical on every replica.

**Quiesce** (policy, not protocol): approaching its terminal cut, a shard's proposers stop selecting new cross-shard transactions (at `cut − WAVE_TIMEOUT − margin`) and then new single-shard transactions, minimizing straddler volume. It is soft — a non-compliant proposer's late transactions simply meet the fence — and the margins are configurable (`split_quiesce_cut`; test builds set them to zero deliberately, to keep straddlers flowing through the fence machinery). Quiesce is a throughput optimization, not a safety dependency: the scheduled-terminal fence, not the margin, is what preserves atomicity for straddlers still in flight near the boundary.

The net guarantee: **a cross-shard transaction finalizes-accept on the survivor if and only if its half applied on the terminated shard's chain at or before the terminal block.** Both sides' verdicts are functions of frozen content, so they cannot disagree — atomicity (INV-EXEC-1) survives the death of a participant.

## 5. The orchestrator: one duty machine, both harnesses

The sequencing above — when to open a store, when to snap-sync, when to re-assert readiness, when to fetch terminals, when to adopt and seat — is driven by a single sans-io `ReshapeOrchestrator` (`crates/node`), shared verbatim by the production supervisor and the simulator. It reads a `ReshapeView` (pending reshapes, boundaries, the topology snapshot, and this host's identities) and steps per-duty state machines:

- **Observer** (split cohort member): open the store, snap-sync the child span, tail the parent while applying child-prefix writes, fetch the terminal, derive and adopt the genesis, seat.
- **Parent-half** (existing member crossing to a child): seed the child store from the local parent store at the terminal crossing, adopt, seat.
- **Keeper** (merge): re-assert ready, assemble the merged store from both children, fetch both terminals, derive and adopt the composed genesis, seat.

All gate predicates are pure functions over committed state (for example, "children seeded" means both child boundaries have non-zero block hashes), so production and simulation provably make the same decisions from the same facts. The orchestrator exists precisely because three hand-written copies of this logic had drifted apart.

Supporting safety and liveness machinery, briefly (details in [05-byzantine-safety.md](05-byzantine-safety.md) and [03-state-and-sync.md](03-state-and-sync.md)): the shuffle skips mid-reshape shards entirely; `top_up_committees` refills any committee left under strength by a reshape-depleted pool; store-lock arbitration keeps the host supervisor from wiping a store a reshape duty is building in; and remote-header routing is terminal-clamped so drained shards' terminal artifacts stay fetchable through the retention window.

## 6. Properties

The reshape invariants this document motivates — INV-RESHAPE-1 through INV-RESHAPE-8 — are stated precisely in [08-invariants.md](08-invariants.md).
