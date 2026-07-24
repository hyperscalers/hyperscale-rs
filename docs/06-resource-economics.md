# Resource economics: the self-regulating validator supply

A dynamically sharded network has a problem static-topology chains never face: **demand for validators is a moving target.** Every split creates two committees where one stood; every merge dissolves one; shuffling, jailing, and reshape cohorts all draw on a reserve of unplaced validators. A fixed activation stake cannot serve this. Set high, it starves a growing network of the validators its next split needs; set low, it invites seat-farming when the network needs nobody. Hyperscale instead prices validator activation with a **supply-elastic minimum stake**, recomputed every epoch inside the beacon fold as a pure function of committed state. When the validator supply is abundant relative to what the topology needs, the price of activating a seat rises; when the network is short, the price falls toward a hard floor. No governance intervention, no oracle, no operator judgment — the same deterministic fold that decides committees decides the price ([01-consensus-layers.md](01-consensus-layers.md) §3.2).

This document covers the demand model, the pricing rule, where the price gates validator lifecycle transitions, and — the other half of the resource story — **vnodes**: running multiple validator identities in one process so that the marginal cost of a seat is its stake, not its hardware.

Main code homes: the pricing and pool logic in `crates/types` (`BeaconState::min_stake`, `StakePool`) and `crates/beacon` (fold modules: witness, lifecycle, withdrawals), constants in `crates/types` beacon constants; the vnode model in `crates/node` (`NodeHost`, `Vnode`, `ProcessIo`).

---

## 1. The demand side: a computed target population

Each epoch, the fold derives how many active validators the network *needs*:

```
target = number_of_shard_committees × shard_size + POOL_BUFFER_TARGET
```

The shard count is read from the **lookahead** committees, so topology changes feed demand at the moment they are decided: a split that executes into the lookahead raises the target by a full committee one epoch before the children seat; a merge lowers it. The buffer term keeps a standing reserve of unplaced (`Pooled`) validators over and above seated committees — the slack that absorbs shuffle rotation, reshape cohort draws, and jail replacements without the network ever waiting on new registrations. Jailing itself feeds back into the accounting: jailed and stake-deficient validators do not count as active, so a jailing event frees pool budget and the economics naturally reprice to attract or activate a replacement. The seated population also carries a standing consensus duty: every beacon commit needs a ratification quorum of the serving validators ([01-consensus-layers.md](01-consensus-layers.md) §3.1). Validator liveness is therefore more than staffing slack — a seated set a third or more dark stalls beacon epochs, deliberately, rather than forking.

The sizing constants (`SHARD_CAPACITY`, `POOL_BUFFER_TARGET`, `MIN_STAKE_FLOOR`) are deployment parameters; their values are deliberately out of scope here. What matters structurally is that the target is *computed from the same committed state on every replica*, never configured per node.

## 2. The price: a market-clearing minimum stake

The dynamic minimum stake is:

```
min_stake = max( min(t_admit, t_no_eject), MIN_STAKE_FLOOR )
```

Three forces, one price:

**`t_admit` — the clearing price for exactly `target` seats.** Every stake pool implicitly *offers* seats at descending prices: a pool with effective stake `S` can support one validator at price `S`, two at `S/2`, three at `S/3`, and so on. The fold gathers all offerings from all pools, sorts them descending, and takes the `target`-th one — the marginal price at which the pools would collectively supply exactly the target population. This rule is where the self-regulation lives:

- **Abundant supply** (lots of stake, many pools, more prospective seats than the topology needs): the `target`-th best offering is high, so `min_stake` is high. Activating yet another validator the network doesn't need is expensive.
- **Scarce supply** (fewer prospective seats than target — say, after a burst of splits raised demand): the `target`-th offering is low or doesn't exist, so `min_stake` falls to the floor. Exactly when the network is short, seats become cheap to activate, and the pool refills.

Because the price is the *marginal* offering rather than a threshold rule flipping between states, adjustment is continuous — there is no bang-bang hysteresis to oscillate.

**`t_no_eject` — the incumbent-protection ceiling.** The minimum, across all pools, of `effective_stake / active_count` — the tightest pool's per-validator budget. Capping the price here guarantees that **repricing alone never deactivates a sitting validator**: however abundant supply becomes, the price stops rising at the point where an existing pool could no longer afford its current seats. Only actual stake withdrawal can push a validator out (INV-ECON-1).

**`MIN_STAKE_FLOOR` — the sybil floor.** A hard minimum under everything (INV-ECON-2). However short the network is, a seat never becomes free: the floor is the sybil-resistance backstop that keeps INV-SEC-1's economics meaningful — corrupting a third of a committee must always cost real stake.

## 3. Where the price bites: the validator lifecycle

Stake lives in **pools** (`StakePool`): one pool operates one or more validators; delegation and per-staker accounting live in shard-side staking contracts, and the beacon sees only proof-carrying aggregates — `StakeDeposit` / `StakeWithdraw` witness leaves flowing through the same attested channel as every other governance event ([01-consensus-layers.md](01-consensus-layers.md) §3.3). A pool's *effective* stake is its total minus pending withdrawals, so a withdrawal request reduces capacity immediately while the funds themselves mature through an unbonding delay. A pool convicted of equivocation ([05-byzantine-safety.md](05-byzantine-safety.md) §3) matures nothing until its impound lifts — every pending withdrawal, including ones initiated before the evidence landed, waits out the governed span and then releases whole — and its idle stake is excluded from the activation price and the governance tally, so a dead pool cannot distort either for live ones.

Every capacity decision is the same solvency test at the current price: a pool may have at most `floor(effective_stake / min_stake)` active validators (INV-ECON-3). The test is applied at:

- **Registration.** A `RegisterValidator` witness is accepted only if the pool can support one more active validator at the current `min_stake`. In a tight market the gate is closed; in a short market it is open.
- **Unjailing.** A performance-jailed validator returns (after cooldown) only if the pool can afford the extra seat at the *current* price — jail time doesn't grandfather a stale price.
- **Withdrawal maturation.** When a withdrawal completes, the pool's capacity is recomputed; if it now supports fewer seats than it has, surplus validators are moved to `InsufficientStake` — deactivated, off committees, no longer consuming capacity, but still bound to the pool (and still retroactively accountable for equivocation evidence).
- **Auto-reactivation.** Each epoch, a sweep promotes `InsufficientStake` validators back to `Pooled` wherever capacity has reappeared. Each promotion changes an active count, which can change `t_no_eject`, which can change the global price — so the sweep refreshes `min_stake` after every flip and runs to a fixpoint. Recovery is automatic; there is no manual re-activation transaction.

The incentive side is a fixed per-epoch emission (`EMISSIONS_PER_EPOCH`, sized against an annual issuance target) rewarding active participation; its distribution mechanics live shard-side with the staking contracts.

The result is a closed loop with no exogenous inputs: **topology decides demand; demand and pooled stake decide the price; the price gates activation; activation replenishes the pool the topology draws on.** Every quantity in the loop is a deterministic function of `BeaconState`, so every replica prices every transition identically (INV-ECON-5). The economic layer inherits INV-BEACON-2's replay property, and a light client can recompute the price history from the chain.

## 4. Vnodes: amortizing the hardware cost of a seat

The stake price governs *who may* operate seats; vnodes govern what a seat *costs to run*. A **vnode** is one validator identity — its own BLS key, its own `NodeStateMachine`, its own votes, proposals, and accountability record — and one host process (`NodeHost`) runs any number of them across any set of shards. What is duplicated per identity is exactly the consensus-relevant part; everything expensive is shared:

| Resource | Scope | Notes |
|---|---|---|
| Signing key, consensus state, votes/proposals, miss counters | **Per vnode** | Identity is never shared; each vnode is independently accountable |
| Storage, mempool, commit pipeline, per-shard stores | **Per shard** | Co-hosted same-shard vnodes share one store and one deterministic mempool — state does not double |
| Execution cache, tx validation verdicts, tx status, topology snapshot, network peer, thread pools | **Per host** | One Radix execution per transaction per process; one signature/SBOR validation per transaction; one libp2p identity |

Two vnodes seated in the same shard on one host therefore cost roughly one shard's storage, one shard's execution work, and two signatures — not two of everything. Cross-shard co-hosting shares the process layer (network, dispatch, caches) while keeping per-shard state independent. This is the multi-vnode architecture described in [07-determinism-and-testing.md](07-determinism-and-testing.md) §3, read through an economic lens: **the marginal cost of an additional seat approaches its stake**. That shape is the intended one — stake is the security parameter the protocol prices ([05-byzantine-safety.md](05-byzantine-safety.md) §1); hardware is not. Making seats hardware-cheap lets the validator supply track an elastic topology without capital expenditure tracking it too.

Communication between co-hosted vnodes amortizes a third resource: **serialization and verification work.** Vnode-to-vnode messages inside one process never touch the network stack — the local-dispatch path hands the receiving vnode the very same reference-counted (`Arc`) object the sender holds, with no encode/decode round-trip. Verification status rides along with it. Verified payloads are wrapped in the `Verifiable<T>`/`Verified<T>` typestate (`crates/types`), whose verified marker survives moves, clones, and local-dispatch handoffs but is deliberately impossible to obtain from wire bytes: decoding always lands unverified, and `Verified<T>` has no decode path at all. So a QC, transaction, or certificate whose signature was checked once on a host is checked exactly once, no matter how many co-hosted identities consume it, while anything arriving over the real network is forced back through its verification predicate (INV-DET-6). The trust assumption is stated on the type itself: one process is one operator, a single trust domain.

Co-hosting is safe by construction, not by trust in the operator:

- **No accidental equivocation.** A per-identity signer seat (`BeaconSignerSeat`) with an epoch fence guarantees that during handoffs, flips, and relocations, at most one vnode ever signs for a given validator in a given epoch — the one failure mode co-hosting could add to consensus is structurally excluded (INV-ECON-6).
- **No store fights.** Lock arbitration between vnode duties (a reshape duty building a child store versus a supervisor join on the same shard) is explicit, so co-hosted duties yield rather than deadlock.
- **No protocol special-casing.** Committee sampling, shuffling, and quorum math are identity-only — the protocol neither knows nor cares about host placement. The corollary is a deliberate, documented trade: co-hosted identities share a fault domain (one machine failing takes all its vnodes offline), and nothing in committee selection spreads a host's identities apart. The BFT math is unaffected — an operator's weight in any committee is bounded by the identities (and thus the stake) they place there, which is exactly what the stake price meters — but operational host-spread is left to deployment tooling rather than the protocol.

## 5. Properties

The economic invariants this document motivates — INV-ECON-1 through INV-ECON-6 — are stated precisely in [08-invariants.md](08-invariants.md).
