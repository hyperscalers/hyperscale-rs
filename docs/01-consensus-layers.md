# The three consensus layers

Hyperscale runs three consensus mechanisms, each with a different shape because each answers a different question:

| Layer | Question it answers | Protocol | Cadence | Participants |
|---|---|---|---|---|
| **Shard consensus** | In what order do transactions run? | HotStuff-2 (two-chain, pipelined) | Continuous, per-shard | The shard's committee |
| **Execution consensus** | What did the transactions do? | Vote aggregation into ExecutionCertificates | Per wave, after ordering | The shard's committee (per shard, per wave) |
| **Beacon consensus** | Who governs which shard, when? | Prefix Consensus / Strong Prefix Consensus (PC/SPC) | One block per epoch, wall-clock paced | A sampled global committee |

They are harmonized by a single artifact — the **topology schedule**, a mapping from BFT-attested time to committees — and a single clock, **weighted time**. This document describes each layer and then the harmonization.

Key types are named inline; the main homes are `crates/shard` (shard consensus), `crates/execution` and `crates/types` wave/certificate types (execution consensus), `crates/beacon` (beacon consensus), and `crates/types` topology types (the schedule).

---

## 1. Shard consensus: HotStuff-2

Each shard is an independent BFT chain producing `Block`s over the shard's transactions. The implementation is HotStuff-2: two-chain commit latency, a timeout-message pacemaker instead of view-change certificates, and optimistic pipelining (a proposer proposes immediately after the previous block's QC forms, without waiting for commit).

### 1.1 Heights, rounds, proposers

- **Height** is chain position: strictly sequential, one committed block per height.
- **Round** is a per-block consensus attempt counter that strictly increases along the chain. In a fault-free run, each height consumes one round; view changes (timeouts) burn rounds, so a block's round can exceed its height. Rounds, not heights, drive the safety rules.
- **Proposer selection** is pure rotation by round: `proposer_for(round) = committee[round % committee_size]`. The selection is deterministic given the round and the committee, and the committee itself is resolved from the parent QC's weighted timestamp (§4), so every replica agrees on the proposer without communication.

Three proposal kinds exist: **normal** (payload plus the proposer's wall-clock reading), **fallback** (empty payload on timeout recovery, carrying the parent QC's timestamp so that Byzantine proposers cannot use empty blocks to drag consensus time), and **sync** (empty, for a proposer that is online but still catching up on execution).

### 1.2 Votes and the safe-vote rule

Each validator maintains two monotone local registers: `locked_round` (the highest QC round it has voted to extend) and `last_voted_round` (the highest round in which it has either voted or timed out). A validator votes for block `B` if and only if:

1. `B.round == current_view` — voting is bound to the live round;
2. `B.round > last_voted_round` — at most one vote per round, ever;
3. `B.parent_qc.round >= locked_round` — the block extends a QC at least as high as the local lock.

On voting, both registers ratchet up. On timing out of a round, `last_voted_round` ratchets too, so a timed-out round can never be voted afterwards (INV-SHARD-2). There is **no unlock rule** — `locked_round` never decreases, under any input (INV-SHARD-3). Both registers are durable: they are persisted before any vote or timeout signature leaves the process, and they are recovered on restart floored at the highest known QC's round. A crash costs at most an abstention, never a second signature in a consumed round.

A validator votes only after holding the **complete block** — header plus every transaction, wave, and provision body. This rule turns every QC into a data-availability certificate: 2f+1 validators provably hold the full content, so the block is recoverable from any of them (INV-SHARD-7).

Votes are BLS signatures over a domain-separated message binding the vote's full context — the shard, the chain position and round, the block and parent hashes. A vote is sent to the current round's proposer and, for pipelining, to the next couple of rounds' proposers as well.

### 1.3 Quorum certificates and weighted time

2f+1 votes aggregate into a `QuorumCertificate`: the block identity fields, a signer bitfield indexed by committee order, one aggregated BLS signature, and a **weighted timestamp** — each voter's clock reading clamped to be no earlier than the parent QC's weighted timestamp, then averaged over the quorum (every vote weighs one).

Two facts about this timestamp matter downstream:

- **It is Byzantine-bounded.** The per-vote clamp makes the clock monotone along the chain, so Byzantine voters cannot drag it backwards at all. Forward skew is possible — a mean moves with every vote — but capped. A timestamp implausibly far ahead of the local clock is rejected wherever an untrusted QC enters chain state: header validation, synced-block admission, timeout `high_qc` adoption, and local aggregation itself. A far-future value therefore cannot poison the chain's clock.
- **The canonical value for a block is the one in its committing child.** A QC is not unique (the same block can be re-certified in later rounds, for example during a reshape coast), and a QC's timestamp field rides outside the vote-signed message. The hash-pinned, consensus-canonical timestamp of block `B` is `child.parent_qc.weighted_timestamp` — the value embedded in the child block that committed `B`. Every protocol that anchors deadlines or committee lookups uses this parent-QC form (INV-SHARD-6). The distinction is load-bearing: reshape genesis derivation once diverged precisely by reading a re-cert QC's timestamp instead of the canonical one.

### 1.4 The commit rule

A block `B` commits when a QC forms for a child at **exactly** `B.round + 1` — a round-contiguous two-chain. Blocks proposed after view changes (whose child is not round-contiguous) do not commit immediately; they commit later as the prefix of the first descendant that does form a direct two-chain.

The division of labor between the two rules is the heart of fork safety. The safe-vote rule alone does *not* prevent two QCs at one height: two siblings both extending the same parent QC can each gather a quorum without any validator violating its lock. What it cannot allow is both siblings *committing*. Committing `B` requires a contiguous chain of QCs above it, and quorum intersection (any two 2f+1 quorums share an honest validator, whose lock has ratcheted) forces every subsequent QC to extend the committed branch. One height, at most one committed block (INV-SHARD-1). The `fork_safety` test asserts exactly this under adversarial scheduling.

Every committed block's parent hash must equal the previously committed hash — commit order is exactly chain order (INV-SHARD-5). At commit, the chain state advances atomically: committed height/hash/state-root, the committee anchor timestamp, dedup indices for committed transactions/waves/provisions (retention-bounded), the beacon-witness accumulator (§3.3), and byte-growth counters that feed reshape triggers.

### 1.5 The pacemaker

Liveness under partial synchrony (INV-SHARD-8) is handled by timeout messages, not view-change certificates:

- When a round timer fires, the validator broadcasts `Timeout { shard, round, high_qc }` — a BLS share over `(shard, round)`, carrying its highest known QC.
- **f+1 timeouts** for a round trigger Bracha-style amplification: broadcast your own timeout if you haven't. This guarantees that if any honest validator abandons a round, all eventually do — partitions cannot strand a minority in an old round.
- **2f+1 timeouts** advance the round. The new round's proposer adopts the quorum-max `high_qc` from the collected timeouts, so the chain always continues from the highest certified block any quorum member knew.
- Timers **retransmit** on every fire; a one-shot timeout lost to a partition would wedge the round after healing. The round timeout grows linearly with the number of failed rounds at a height, is capped, and is computed from QC-attested data, so all replicas agree on the deadline.

View synchronization is bounded: observing headers or votes from far-future rounds advances the local view only within a capped gap of the highest known QC, and speculative verification of far-round blocks is bounded, so Byzantine peers cannot inflate a replica's view or burn its CPU ([05-byzantine-safety.md](05-byzantine-safety.md) §6).

### 1.6 What a block carries

The `BlockHeader` binds, under the QC, everything other layers depend on. The load-bearing commitments (a characterization, not a field inventory) are: the parent QC itself (the timestamp source); the state root after this block; merkle roots over the block's content — transactions, finalized waves, receipts, outbound provisions, and per-destination provision-transaction roots; the beacon-witness root (the shard-to-beacon channel, §3.3); and, near reshape boundaries only, the child state roots and the settled-waves root ([02-dynamic-sharding.md](02-dynamic-sharding.md)). The body carries the corresponding content; full provision bodies are dropped to hashes once the block seals past its execution window.

---

## 2. Execution consensus: certificates over outcomes

Ordering and execution are deliberately decoupled. Shard consensus commits blocks *before* executing their transactions; execution then happens against committed order, and its results are agreed by a second, lighter round of consensus. This decoupling is what makes cross-shard atomicity tractable: a shard can commit to running a transaction whose inputs live on four other shards without stalling its consensus on their progress.

### 2.1 Waves

At block commit, the block's transactions are grouped into **waves** — units of execution agreement. Single-shard transactions dispatch immediately. Cross-shard transactions wait in their wave (`WaveState`, `crates/execution`) until provisions from every counterparty shard have arrived and verified ([04-atomic-commitment.md](04-atomic-commitment.md)); then the whole wave executes atomically against the merged state view.

### 2.2 From votes to the ExecutionCertificate

Every validator executes the wave locally — deterministically: same engine, same inputs, same outputs — and sends an `ExecutionVote` asserting the wave's `global_receipt_root`, a merkle root over the per-transaction outcomes. The vote goes to the wave's leader, chosen by a deterministic hash of the wave id over the committee. 2f+1 agreeing votes aggregate into an **`ExecutionCertificate`** (EC). Alongside the usual quorum material (signer bitfield, aggregated BLS signature), the EC carries the wave identity, a BFT-attested anchor timestamp, the receipt root, and the explicit per-transaction outcome vector (succeeded, aborted, or rejected).

A structural detail with safety weight: on decode, an EC's receipt root is **recomputed from its outcome vector** and must match the attested root. A Byzantine aggregator cannot assemble a signature-valid certificate whose claimed root diverges from its claimed outcomes (INV-EXEC-2).

### 2.3 Wave certificates and finalization

For a cross-shard wave, each participating shard produces its own EC covering the wave's transactions. Wave grouping is per shard — a wave id binds the local shard and block — so a remote participant's coverage can arrive under different wave boundaries, even split across several ECs. The **wave certificate** bundles the local EC with the verified remote coverage. Finalization is decided per transaction: success requires a success outcome — carrying the transaction's receipt hash — from every participating shard, while an abort outcome from any single shard is terminal for the transaction. Abort is dominant; success is unanimous. Agreement on success content rests on deterministic execution: honest quorums compute identical per-transaction receipt hashes, so unanimity is agreement. A `FinalizedWave` (the certificate plus the local receipts it attests) rides in a subsequent block, making execution results part of the ordered chain. Receipts are validated against the EC's attestation before they are accepted from any source.

If a validator's local execution disagrees with the EC its shard's quorum produced, that validator marks the wave locally divergent and never finalizes its own result; it recovers the canonical `FinalizedWave` through block sync instead. A locally-buggy replica cannot leak its receipts into the finalized store (INV-EXEC-8; see divergence recovery in [03-state-and-sync.md](03-state-and-sync.md)).

Execution consensus also has a liveness backstop: every wave carries a deadline derived from BFT-attested time, and a wave still unprovisioned at its deadline all-aborts deterministically on every shard (INV-EXEC-5).

---

## 3. Beacon consensus: PC/SPC over epochs

The beacon is the coordination chain: one block per epoch, produced by a sampled global committee. It never sees transactions. Its job is to make the validator set, the shard topology, and reshaping *facts* that every shard resolves identically.

### 3.1 The protocol: prefix consensus under a view sequencer

The inner protocol, **PC (prefix consensus)**, is leaderless: every committee member broadcasts an input vector (the beacon proposals it has seen), and three rounds of vote/QC formation agree on the *longest common prefix* of the inputs. Divergent inputs don't produce conflicting decisions — they shorten the agreed prefix. The third round exists so members commit to a consistent view of round-1 inputs before knowing the final value, closing an equivocation window a two-round variant would leave open.

**SPC (strong prefix consensus)** sequences PC instances across views within an epoch. A view is entered via a signed proposal object from that view's leader. If the leader stalls, f+1 members exchange empty-view reports of their highest certified triple, which aggregate into an *indirect certificate*: it skips the view forward while pinning the next leader to a specific predecessor value, compressing view synchronization into one hash-sized commitment rather than a value re-broadcast. Full-coverage feeding with a bounded dwell ensures PC inputs are complete views rather than racy partial ones (an eager-feed variant demonstrably collapsed prefixes to empty under load).

The SPC certificate is a *proposal* certificate, not a commit: its output broadcasts as a **candidate**, and every non-genesis block — Normal or Skip — commits only through **pool ratification**, a single-shot two-phase vote by the active pool over block hashes. The active pool is derived from the tip's state by the same attested-serving rule the beacon committee draw uses: every validator ready on a live chain, excluding members a reshape fold seated onto a not-yet-seeded chain until it seeds. Ratification liveness rides on a pool quorum actually voting, and a fold-seated member has no serving node until its chain's anchor lands — an anchor produced by folds the pool itself must first ratify — so counting it would raise the quorum above the reachable voter set and wedge every split.

Members prevote the verified candidate's hash, or the epoch's canonical skip-block hash once the skip deadline passes. A prevote quorum (polka) gates each member's precommit; precommitting locks the member to its value, and the lock is left only for a strictly newer polka. A precommit quorum is the commit certificate. The pool is the single quorum system, so any two commit certificates for one epoch share an honest signer and INV-BEACON-1 holds at every pool-to-committee ratio. A committee that draws fully Byzantine can certify content but commit nothing, and a wedged committee is skipped by the pool unaided (INV-BEACON-7).

The price is liveness scope: commits need a pool quorum (`M − ⌊(M−1)/3⌋`) reachable, so a partitioned minority stalls rather than forks, and it converges by adopting the majority's certified block on heal. A replica that verifies a competing block for an epoch it has already adopted still halts with the evidence: under ratification that is proof of quorum-scale equivocation, not an honestly reachable state.

An epoch's agreement yields a `BeaconBlock`: the committed proposal set plus per-shard contributions, authenticated by a `BeaconCert` (SPC certificate plus ratify certificate, ratify certificate alone for a skip, or the genesis config hash). The fold discriminates Normal from Skip by block *content* — a proposal-less block folds as a skip whichever certificate variant commits it — so byte-identical blocks always fold identically.

### 3.2 The fold: BeaconState as a pure function

Beacon state is **not** stored or attested on-chain; it is the result of folding a pure function, `apply_epoch(state, input) → state'`, over the committed block sequence. Every honest replica folding the same blocks holds the byte-identical `BeaconState` (INV-BEACON-2); a light client verifies by replaying the fold. The state carries: the validator registry with lifecycle statuses (pooled, seated, observing a reshape, jailed, revoked, stake-deficient); stake pools, whose aggregates also drive the dynamic activation price ([06-resource-economics.md](06-resource-economics.md)); the current and **next** per-shard committees; per-shard `ShardBoundary` records (§3.3); pending reshape records; governance parameters; and a running randomness accumulator that seeds every committee draw and shuffle — mixed each epoch from the shard blocks' reveal leaves delivered in boundary witness chunks, falling back to the beacon proposals' VRF outputs in an epoch where no chunk folds.

Each epoch's fold opens by promoting last epoch's frozen lookahead to active and closes by freezing the next epoch's lookahead — those bookends carry the ordering that matters (INV-BEACON-3). In between it applies the epoch's inputs: shard contributions (boundaries + witnesses), the randomness roll, validator lifecycle, committee shuffling and top-up, reshape admission and execution.

### 3.3 The shard–beacon channels

**Shards to beacon.** Once per epoch, each shard's boundary-crossing block becomes its contribution. Beacon proposers include the boundary QC per shard; the fold selects the canonical one (max by `(weighted_timestamp, hash)` — one canonical boundary per shard per epoch, INV-BEACON-5) and records a `ShardBoundary`: state root, block hash, height, canonical weighted timestamp, liveness bookkeeping, and — for terminating shards — terminal metadata and the settled-waves root. Alongside the boundary rides a chunk of the shard's **witness log**: governance events (validator registration, stake movements, readiness, missed proposals, reshape triggers, parameter votes) accumulated in a per-shard merkle accumulator whose root is QC-attested in every shard block header. Witness chunks are contiguous, merkle-proven against the boundary header, and applied exactly once against a per-shard watermark (INV-BEACON-6). This channel is the only path by which anything a shard does can affect the validator set — and it is proof-carrying end to end.

**Beacon to shards.** From `BeaconState` the fold derives a **`TopologySnapshot`** — an identity-agnostic projection carrying every shard's committee (both the full membership used for networking and the ready-filtered subset used for consensus quorums), snap-sync anchors (`ShardAnchor`), reshape seat assignments, witness watermarks, and governance parameters. One `Arc<TopologySnapshot>` per epoch is distributed to every vnode on a host. Snapshots stack into the **`TopologySchedule`**: `epoch → snapshot`, queried by weighted timestamp.

### 3.4 Wall-clock pacing and the genesis anchor

Epochs are paced to wall-clock: the beacon's synthetic time advances as `epoch × epoch_duration_ms`, and a committee refuses to start an epoch before its wall-clock boundary — SPC could otherwise race far ahead of the shards whose schedule windows it defines. Production folding is genesis-relative (`BeaconChainConfig.genesis_timestamp_ms`), so the clock starts at zero at network birth rather than at Unix time.

---

## 4. Harmonization: weighted time and the schedule

The three layers stay mutually consistent through one discipline:

**Every committee lookup, everywhere, is `schedule.at(weighted_timestamp)`.** Verifying a shard block's QC, validating a remote shard's header, checking a provision's source attestation, resolving an EC's signing committee, admitting a beacon boundary QC — all of them compute `epoch_for(wt) = floor(wt / epoch_duration_ms)` from the artifact's canonical (parent-QC) weighted timestamp and resolve the committee from the schedule. The binding is exact; there is no grace interval in which two committees are simultaneously acceptable (INV-SHARD-9).

Three properties make this sound:

1. **Lookahead (L=1).** Epoch `e+1`'s committees are computed and frozen during epoch `e`'s fold (INV-BEACON-3), one epoch before any honest artifact is stamped into `e+1`'s window — honest weighted timestamps track real time, and the fold is wall-clock paced. This is the common case, not an impossibility argument: the admission bound on forward skew (`MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH`) is independent of the epoch duration, so a maximally skewed QC can carry a timestamp past the frozen head, and a replica whose own fold lags sees even honest artifacts arrive early. Coverage (property 3) carries both cases: the lookup defers until the fold catches up; it never mis-resolves. The freeze also pre-positions validators: a member joining a committee next epoch has the current epoch to sync.
2. **Monotone attested time.** Weighted timestamps never regress along a shard chain, and epochs are half-open WT windows, so every block resolves to exactly one epoch.
3. **Retention with a consumer-derived floor.** The schedule retains history down to a floor computed from what could still legitimately need verification: the local chain frontier, every shard's last-live boundary, and a hard horizon (`RETENTION_HORIZON`). Lookups below the floor are permanently rejected (`ScheduleLookup::Evicted`) rather than silently missing; lookups above the head are deferred until the beacon catches up (INV-BEACON-4). Terminated reshape shards get clamped extensions so their terminal artifacts remain verifiable until every dependent has consumed them.

The result: dozens of shard chains run at their own speeds, execution agreement trails ordering by its own cadence, and the beacon ticks once an epoch — yet any replica, handed any artifact from any layer, resolves the same governing committee and the same verification verdict as every other replica, using nothing but the artifact's attested timestamp and its own fold of the beacon chain.

---

## 5. Properties

The invariants this document motivates — INV-SHARD-1 through INV-SHARD-9, INV-BEACON-1 through INV-BEACON-7, and the execution-layer INV-EXEC-1/2/5 — are stated precisely in [08-invariants.md](08-invariants.md).
