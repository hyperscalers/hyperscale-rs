# Invariant Register

The consolidated register of the system's safety and liveness properties, with stable IDs. Each entry names the property, classifies it, states it precisely enough to be a verification target, and points to the document section that motivates it and the mechanism that enforces it. This is the intended starting point for formal verification: pick a property, model the transition functions it constrains (all of which are pure — see [07-determinism-and-testing.md](07-determinism-and-testing.md)), and prove or model-check it.

**Classification.** *Safety* — never violated in any reachable state, regardless of timing. *Liveness* — eventually holds under eventual synchrony. *Assumption* — a premise the deployment must establish; other properties are conditional on it. *Determinism* — a functional property (same inputs ⇒ same outputs across replicas) that safety properties reduce to.

**Suggested verification order** (dependency-first): INV-SEC-1 (the premise) → INV-SHARD-1..9 (single-chain safety) → INV-BEACON-1..8 (topology determinism) → INV-EXEC-1..10 (atomic commitment) → INV-RESHAPE-1..8 (atomicity under topology change) → INV-STATE / INV-ECON / INV-DET (the supporting reductions).

---

## Committee premise

| ID | Class | Property |
|---|---|---|
| **INV-SEC-1** | Assumption | Every committee (shard, beacon, execution) contains fewer than ⅓ Byzantine members: n ≥ 3f+1, quorum 2f+1 (strict >⅔ by seat count). Maintained statistically by seeded sampling from beacon randomness, trickled shuffling, and expulsion, given a <⅓-corrupt global pool. Premise carries a residual caveat: the epoch seed folds the shard blocks' mandatory reveal leaves — interior reveals are blind to their own producers, leaving a one-sided window-edge lever — and an epoch where no chunk folds falls back to the beacon ceremony's reveals, which a last-revealer can grind. Its two thresholds are defended apart: reaching f+1 is a recoverable *liveness* halt (a beacon-detected full-committee re-draw undoes it), while reaching 2f+1 is *terminal* and so is *prevented* — the grind-resistant seed plus a small beacon committee, FIFO eviction, jailing for withholding, a recency-weighted resample, and pool hygiene hold a targeted shard below 2f+1 across the tolerated band; priced and dispositioned in [committee_security.md](../specs/committee_security.md) §10. All safety properties below are conditional on it. [05 §1](05-byzantine-safety.md) |

## Shard consensus (HotStuff-2) — [01 §1](01-consensus-layers.md)

| ID | Class | Property |
|---|---|---|
| **INV-SHARD-1** | Safety | **Agreement / no fork.** No two honest replicas commit different blocks at the same height. Sibling QCs at one height may exist; sibling commits cannot. Enforced by INV-SHARD-2/3 (vote discipline) + INV-SHARD-4 (commit rule) + quorum intersection. |
| **INV-SHARD-2** | Safety | **One vote per round.** A validator votes or times out at most once per round; `last_voted_round` is strictly monotone and consumed by both actions. |
| **INV-SHARD-3** | Safety | **Lock monotonicity.** `locked_round` never decreases; a vote requires `parent_qc.round ≥ locked_round`. There is no unlock rule of any kind. |
| **INV-SHARD-4** | Safety | **Round-contiguous commit.** A block commits iff a QC forms for a child at exactly `round + 1`; view-change survivors commit only as the prefix of a later direct two-chain. |
| **INV-SHARD-5** | Safety | **Commit linkage.** Every committed block's parent hash equals the previously committed hash; commit order is exactly chain order. |
| **INV-SHARD-6** | Safety | **Canonical weighted time.** A block's canonical timestamp is its committing child's `parent_qc.weighted_timestamp`; it is monotone along the chain; every consensus-relevant deadline and committee lookup uses this form, never a served/re-certified QC's stamp. |
| **INV-SHARD-7** | Safety | **DA by vote.** A validator votes only holding the complete block content; hence every QC certifies that ≥2f+1 validators hold every byte the block commits to. |
| **INV-SHARD-8** | Liveness | **Progress.** Under eventual synchrony with an honest proposer reachable by rotation, every height commits: timeout quorums (2f+1) advance rounds, f+1 amplification makes abandonment contagious, timeouts retransmit, and the adopted `high_qc` is the quorum max. |
| **INV-SHARD-9** | Safety | **Committee-exact verification.** Every certificate is verified against the committee at `epoch_for(canonical WT)` — exactly one committee is acceptable for any artifact. |

## Beacon consensus and topology — [01 §3–4](01-consensus-layers.md)

| ID | Class | Property |
|---|---|---|
| **INV-BEACON-1** | Safety | **One block per epoch.** Every non-genesis block commits through a pool ratification certificate — a precommit quorum of the active pool over the block's hash — so any two commit certificates for one epoch share an honest signer, at every pool-to-committee ratio. The SPC certificate authenticates content only. A replica that verifies a competing block for its adopted epoch halts with the evidence: under ratification that is proof of quorum-scale equivocation — see [01 §3.1](01-consensus-layers.md). |
| **INV-BEACON-2** | Determinism | **Pure fold.** `BeaconState` is a pure function of the committed block sequence; all honest replicas hold byte-identical state at every epoch. |
| **INV-BEACON-3** | Safety | **Lookahead freeze.** The committees governing epoch e+1 are computed and frozen during epoch e's fold. Artifacts can still outrun the frozen head (admission-bounded timestamp skew, or a lagging local fold); INV-BEACON-4 defers those lookups rather than mis-resolving. |
| **INV-BEACON-4** | Safety | **Schedule coverage.** Every weighted timestamp a verifier can legitimately encounter resolves in the topology schedule; lookups below the retention floor are rejected permanently, above the head deferred — never silently mis-resolved. |
| **INV-BEACON-5** | Determinism | **Canonical boundary.** Per epoch and shard, all replicas derive the same single canonical boundary QC (max by `(WT, hash)` over committed proposals). |
| **INV-BEACON-6** | Safety | **Witness integrity.** Witness chunks are contiguous, merkle-proven against the QC-attested boundary header, and applied exactly once against a per-shard watermark. |
| **INV-BEACON-7** | Liveness | **Epoch progress.** A stalled view is skipped by an f+1 indirect certificate; an unrecoverable committee is skipped by the pool ratifying the epoch's canonical skip block, with no committee participation required; epoch production is paced to wall-clock, never ahead of it. Commits need a pool quorum reachable — a partitioned minority stalls rather than forks. |
| **INV-BEACON-8** | Safety | **Terminal retention.** A terminated shard's boundary record (including its settled-waves root) is retained until every dependent has consumed it: split children seeded, merge parent composed, plus the retention horizon. |

## Execution and atomic commitment — [04](04-atomic-commitment.md), [01 §2](01-consensus-layers.md)

| ID | Class | Property |
|---|---|---|
| **INV-EXEC-1** | Safety | **Atomic commitment.** A cross-shard transaction reaches the same terminal outcome (succeeded / aborted / rejected) on every participating shard. Finalization is per transaction: success requires success outcomes (identical receipt hashes, by deterministic execution) from every participant's EC; any participant's abort outcome is terminal — abort dominant, success unanimous. Abort paths are deterministic functions of committed state. |
| **INV-EXEC-2** | Safety | **Certificate soundness.** An EC's receipt root is recomputed from its outcome vector at decode and must match; quorum power and aggregate signature verify against the WT-resolved committee. A valid-looking EC with divergent content cannot exist. |
| **INV-EXEC-3** | Safety | **Partial coupling.** No two transactions simultaneously in flight or ready share any declared node; locks persist from commit to wave finalization. Local deadlock is structurally impossible. |
| **INV-EXEC-4** | Determinism | **Conflict verdicts.** Cross-shard conflict detection reads only committed chain state; ties break by transaction hash; every replica on every shard derives the identical abort set. |
| **INV-EXEC-5** | Liveness | **Termination.** Every wave reaches a terminal outcome by its deadline (source WT + `WAVE_TIMEOUT`); a wave unprovisioned at deadline all-aborts identically everywhere. No lock is held past a computable bound. |
| **INV-EXEC-6** | Determinism | **Ownership merge.** The cross-shard ownership map is merged by fixed rule (remote claims from provisions, local claims from the local snapshot; a vault claimed by both ⇒ deterministic abort); write placement cannot diverge across shards. |
| **INV-EXEC-7** | Safety | **Attested retention.** Every DA retention/eviction decision keys on BFT-attested weighted time; before the horizon, eviction requires positive EC coverage or provable expiry. |
| **INV-EXEC-8** | Safety | **Divergence containment.** A replica whose local execution disagrees with its shard's admitted EC never finalizes or serves its own result; it recovers the canonical wave via sync. |
| **INV-EXEC-9** | Determinism | **Declared bounds.** Engine writes outside the declared/derived node set are dropped by identical rule on all replicas. |
| **INV-EXEC-10** | Safety | **Artifact-only trust.** Cross-shard inputs (headers, provisions, ECs, settled sets) are accepted only as proofs against QC- or beacon-attested content, never on peer authority. *(Known interim gap: provision `owned_nodes` are attested at tx-hash granularity — liveness-impacting only; see [04 §5](04-atomic-commitment.md).)* |

## Dynamic sharding — [02](02-dynamic-sharding.md)

| ID | Class | Property |
|---|---|---|
| **INV-RESHAPE-1** | Safety | **Seating gate.** A split/merge executes only when every successor committee's ready membership ≥ 2f+1 of target; no successor shard ever seats below quorum. |
| **INV-RESHAPE-2** | Determinism | **Genesis determinism.** Successor genesis blocks derive purely from frozen chain content (terminal header/QC) plus the beacon anchor, and must hash exactly to the anchor; mismatch fails closed. |
| **INV-RESHAPE-3** | Safety | **Root continuity.** `hash_internal(left_root, right_root) == parent_root` holds across split and merge; resharding neither creates, loses, nor re-keys any state. |
| **INV-RESHAPE-4** | Determinism | **Canonical clock at the cut.** Reshape genesis timestamps come only from beacon-anchored, parent-QC-derived weighted timestamps (merge: the epoch start of the left terminal's canonical timestamp, composed once by the beacon and read back from the anchor) — never from re-certified QCs. |
| **INV-RESHAPE-5** | Safety | **Straddler fence.** A wave naming a shard P that has terminated — or is scheduled to (an admitted terminating reshape, read from frozen schedule content) — finalizes anywhere iff `wave_id ∈ S_P` (P's on-chain settled set at its terminal block). Not-yet-existent set ⇒ defer; absent ⇒ reject; past horizon ⇒ reject. The fence engages from reshape admission, not only past-terminal, closing the pre-boundary window in which a survivor could otherwise apply a wave P never settled. Preserves INV-EXEC-1 across shard termination. |
| **INV-RESHAPE-6** | Safety | **Attested settlement.** `S_P` is a pure function of P's frozen chain; its root is attested through each survivor's own beacon fold before any fetched set is trusted (root equality checked on receipt). |
| **INV-RESHAPE-7** | Safety | **Staffing stability.** Shuffles skip mid-reshape shards and never shrink a committee. Merge keepers are pinned — a keeper syncs the child it already runs, so its assignment cannot move. A split cohort's draw is re-derived from a seed frozen at admission over the free pool, so a lapse/re-assert cycle reproduces the identical cohort and child assignment when the intervening pool is unchanged. |
| **INV-RESHAPE-8** | Liveness | **Bounded lifecycle.** Triggers lapse by TTL; unready reshapes abandon by TTL and return their cohort; under-strength committees are topped up from the pool; terminal records are retained per INV-BEACON-8 so no dependent is stranded. |

## State and synchronization — [03](03-state-and-sync.md)

| ID | Class | Property |
|---|---|---|
| **INV-STATE-1** | Determinism | **Root agreement.** Same parent state + same receipts ⇒ same JMT root on every replica; the header root is QC-attested. |
| **INV-STATE-2** | Safety | **Clean subtrees.** Every shard is a prefix subtree; owner-prefixed leaf keys place all of an owner's state under the owner's prefix and never re-parent once committed. |
| **INV-STATE-3** | Safety | **Verified import.** Snap-sync imports only leaves proven (with completeness) into a beacon-attested root, with leaf-key and value-hash bindings independently rechecked and the rebuilt root compared against the anchor. |
| **INV-STATE-4** | Safety | **Bounded history.** Versioned reads are bounded by `jmt_history_length`; every protocol requiring historical reads is designed within that window. |
| **INV-STATE-5** | Safety | **One verifier.** Sync-path and consensus-path commits share one state-root verification path; a sync-path mismatch is unrecoverable divergence and halts the node rather than admitting corruption. |
| **INV-STATE-6** | Safety | **Ancestry visibility.** Pending-chain reads traverse parent-hash links to the committed tip; orphaned forks are structurally unreachable. |

## Byzantine resistance — [05](05-byzantine-safety.md)

| ID | Class | Property |
|---|---|---|
| **INV-SEC-2** | Safety | **Shuffle soundness.** Rotation draws are seeded-deterministic and victim selection is the longest-tenured ready member (FIFO); at most one seat per shard per interval, never self-replacing within a draw, never touching a mid-reshape or recovering shard, never shrinking a committee, holding while the beacon-eligible set sits at its BFT floor. |
| **INV-SEC-3** | Safety | **Accountable expulsion.** Equivocation evidence is self-proving and permanently revokes the key (removal, not slashing — stake is preserved and withdrawable); liveness jailing derives only from merkle-proven, exactly-once-applied witness leaves and lifts after a cooldown. Accountability is structural: a corrupt seat is single-use and re-seats only through the beacon's random draw, never by operator choice. |
| **INV-SEC-4** | Safety | **Witness completeness.** A block's witness root must commit every leaf implied by the chain since the parent (including missed-proposal leaves over uncommitted certified ancestors); verifiers recompute and reject omission or fabrication. |
| **INV-SEC-5** | Safety | **Signature hygiene.** Every signature is domain-separated and context-bound; every certificate verifies against the WT-resolved committee for its artifact. |
| **INV-SEC-6** | Safety | **Bounded decode.** No peer-supplied length is trusted before allocation; per-(height, round) buffers, view advancement, and speculative verification are all capped. |
| **INV-SEC-7** | Safety | **Priority isolation.** Sheddable network classes (Recovery, Bulk) are bounded and droppable; consensus-critical classes cannot be starved by them. |
| **INV-SEC-8** | Safety | **Recovery bridge authority.** Across a halt recovery, at most one committee's certificates bind per shard: live work anchored below the bridge epoch resolves only the fresh committee; a certified artifact re-binds to the fresh committee iff its QC window lands at or past the window before the bridge (one skew window of tolerance), while the halted suffix — certified a full halt gap below — keeps resolving its own windows; bridge blocks carry no content. A replica that has not yet folded the recovery defers a bridge block as unverifiable rather than mis-resolving it (the bridge extension of INV-BEACON-4's discipline). |
| **INV-SEC-9** | Liveness | **Halt detection and recovery.** A live, non-reshaping shard that stops crossing is flagged after a threshold of observed folds — misses advance only on epochs the beacon folded boundaries, and a re-fold of an already-consumed crossing never refreshes the watermark — and its committee is re-drawn whole from the pool (all-or-nothing; a short pool defers and retries). The fresh committee seats ready on trust, is quiesced until its first governed window opens, and the recovery clears only on the shard's first genuine crossing; until then every cohort that might hold the halted tip stays routable, the trickle shuffle skips the shard, and its unproven members sit out beacon eligibility. |

## Resource economics — [06](06-resource-economics.md)

| ID | Class | Property |
|---|---|---|
| **INV-ECON-1** | Safety | **No ejection by repricing.** `min_stake ≤ t_no_eject` (the tightest pool's per-validator budget); price movement alone never deactivates a sitting validator — only stake withdrawal can. |
| **INV-ECON-2** | Safety | **Sybil floor.** `min_stake ≥ MIN_STAKE_FLOOR` in every state; activating a seat always costs real stake, however short the network is. |
| **INV-ECON-3** | Safety | **Pool solvency.** Every pool's active validator count is supportable at the current price: `active_count ≤ floor(effective_stake / min_stake)`; enforced at registration and unjail, restored by auto-deactivation when a withdrawal matures. |
| **INV-ECON-4** | Liveness | **Supply elasticity.** The admission price is the market-clearing marginal offering for exactly the target population (lookahead committees × shard size + buffer); scarcity lowers it toward the floor, so the pool refills exactly when topology demand outruns supply. |
| **INV-ECON-5** | Determinism | **Deterministic pricing.** `min_stake` and every gate it feeds are pure functions of `BeaconState` (inherits INV-BEACON-2); the auto-reactivation sweep reprices after each promotion and terminates at a fixpoint. |
| **INV-ECON-6** | Safety | **Co-hosting safety.** Co-hosted vnodes of one validator identity never sign concurrently (per-identity signer seat with an epoch fence); vnode resource sharing is invisible to consensus. |

## Determinism substrate — [07](07-determinism-and-testing.md)

| ID | Class | Property |
|---|---|---|
| **INV-DET-1** | Determinism | **Purity.** Every protocol transition is a pure function of `(state, now, event)`, emitting explicit actions; no I/O, locks, clocks, or OS randomness inside. |
| **INV-DET-2** | Determinism | **Fed time.** Time is an input; consensus randomness is beacon-attested; harness randomness is seeded. No FSM reads a clock. |
| **INV-DET-3** | Determinism | **Harness parity.** Identical protocol code runs under simulation and production; behavioral scenarios are portable, and cross-harness divergence always indicates a real defect. |
| **INV-DET-4** | Determinism | **Seeded reproducibility.** A simulation run, fault injection included, is byte-identical for a given seed. |
| **INV-DET-5** | Determinism | **Deterministic encoding.** All hashed/signed/wire values encode deterministically (SBOR, ordered collections, bounded lengths). |
| **INV-DET-6** | Safety | **Typestate verification.** Verification status is a type-level marker (`Verifiable<T>`/`Verified<T>`): a verified value cannot be constructed by decoding wire bytes (decode always lands unverified), and the marker is preserved only across in-process handoffs within one trust domain (one process = one operator). Nothing is re-verified locally; nothing unverified can masquerade as verified. |

---

## Notes for the verification effort

- **The five-property core** (see [00-overview.md](00-overview.md)): INV-SHARD-1, INV-EXEC-1, INV-RESHAPE-5, INV-BEACON-3/4, INV-RESHAPE-2/3. Everything else either supports these or bounds resources.
- **Reduction structure.** Most safety properties reduce to determinism properties plus quorum intersection. E.g. INV-EXEC-1 = (INV-DET-1 execution determinism) + (INV-EXEC-2 certificate content binding) + (INV-EXEC-4/5 deterministic aborts) + (INV-SEC-1 per-committee honesty). Modeling the determinism layer as given and proving the quorum arguments is the highest-leverage split.
- **Known deliberate gaps** (verification should treat these as documented caveats, not discoveries): provision `owned_nodes` attestation granularity (INV-EXEC-10 note); INV-SEC-1 is an assumption, not a theorem — its statistical parameters (committee size vs. pool corruption) are treated in [05 §1](05-byzantine-safety.md); committee selection is identity-only, so co-hosted vnodes share a fault domain — host-spread is deferred to deployment tooling ([06 §4](06-resource-economics.md)).
- **Existing mechanized anchors.** The `fork_safety` adversarial harness (asserts no committable fork, crash-restart included), the determinism replay test (asserts INV-DET-4), and the straddler-atomicity scenarios (assert INV-RESHAPE-5 end to end on both harnesses) are the executable counterparts to start cross-validating models against.
