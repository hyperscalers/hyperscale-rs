# The three consensus layers

Hyperscale runs three consensus mechanisms, each with a different shape because each answers a different question:

| Layer | Question it answers | Protocol | Cadence | Participants |
|---|---|---|---|---|
| **Shard consensus** | In what order do transactions run? | HotStuff-2 (two-chain, pipelined) | Continuous, per-shard | The shard's committee |
| **Execution consensus** | What did the transactions do? | Vote aggregation into ExecutionCertificates | Per tick, after ordering | The shard's committee (per shard, per tick) |
| **Beacon consensus** | Who governs which shard, when? | Prefix Consensus / Strong Prefix Consensus (PC/SPC) | One block per epoch, wall-clock paced | A sampled global committee |

They are harmonized by a single artifact — the **topology schedule**, a mapping from BFT-attested time to committees — and a single clock, **weighted time**. This document describes each layer and then the harmonization.

Key types are named inline; the main homes are `crates/shard` (shard consensus), `crates/execution` and `crates/types` tick/certificate types (execution consensus), `crates/beacon` (beacon consensus), and `crates/types` topology types (the schedule).

---

## 1. Shard consensus: HotStuff-2

Each shard is an independent BFT chain producing `Block`s over the shard's transactions. The implementation is HotStuff-2: two-chain commit latency, a timeout-message pacemaker whose certificates appear only where a block skips rounds, and optimistic pipelining (a proposer proposes immediately after the previous block's QC forms, without waiting for commit).

### 1.1 Heights, rounds, proposers

- **Height** is chain position: strictly sequential, one committed block per height.
- **Round** is a per-block consensus attempt counter that strictly increases along the chain. In a fault-free run, each height consumes one round; view changes (timeouts) burn rounds, so a block's round can exceed its height. Rounds, not heights, drive the safety rules.
- **Proposer selection** is pure rotation by round: `proposer_for(round) = committee[round % committee_size]`. The selection is deterministic given the round and the committee, and the committee itself is resolved from the anchor of the parent block being extended (§4) — a header field every replica reads identically — so every replica agrees on the proposer without communication, before the height's block exists.

Three proposal kinds exist: **normal** (payload plus the proposer's wall-clock reading), **fallback** (empty payload on timeout recovery, carrying the parent QC's timestamp so that Byzantine proposers cannot use empty blocks to drag consensus time), and **sync** (empty, for a proposer that is online but still catching up on execution).

### 1.2 Votes and the safe-vote rule

Each validator maintains two monotone local registers: `locked_round` (the highest QC round it has voted to extend) and `last_voted_round` (the highest round in which it has either voted or timed out). A validator votes for block `B` if and only if:

1. `B.round == current_view` — voting is bound to the live round;
2. `B.round > last_voted_round` — at most one vote per round, ever;
3. `B.parent_qc.round >= locked_round` — the block extends a QC at least as high as the local lock.

On voting, both registers ratchet up. On timing out of a round, `last_voted_round` ratchets too, so a timed-out round can never be voted afterwards (INV-SHARD-2). There is **no unlock rule** — `locked_round` never decreases, under any input (INV-SHARD-3). Both registers are durable: they are persisted before any vote or timeout signature leaves the process, and they are recovered on restart floored at the highest known QC's round. A crash costs at most an abstention, never a second signature in a consumed round.

A validator votes only after holding the **complete block** — header plus every transaction, finalization, and provision body. This rule turns every QC into a data-availability certificate: 2f+1 validators provably hold the full content, so the block is recoverable from any of them (INV-SHARD-7).

Votes are BLS signatures over a domain-separated message binding the vote's full context — the shard, the chain position and round, the block and parent hashes. A vote is sent to the current round's proposer and, for pipelining, to the next couple of rounds' proposers as well.

### 1.3 Quorum certificates and weighted time

2f+1 votes aggregate into a `QuorumCertificate`: the block identity fields, a signer bitfield indexed by committee order, one aggregated BLS signature, and a **weighted timestamp** — each voter's clock reading clamped to be no earlier than the parent QC's weighted timestamp, then taken as the median over the quorum (every vote weighs one).

Two facts about this timestamp matter downstream:

- **It is Byzantine-bounded.** The per-vote clamp makes the clock monotone along the chain, so Byzantine voters cannot drag it backwards at all. Forward skew is bounded by honest clocks: the median of a quorum's clamped readings is always an honest voter's own reading, wherever the forged values sort. A timestamp implausibly far ahead of the local clock is rejected wherever a QC someone else built enters chain state: header validation, synced-block admission, and timeout `high_qc` adoption. A far-future value therefore cannot poison the chain's clock.
- **The canonical value for a block is the one in its committing child.** A QC is not unique (the same block can be re-certified in later rounds, for example during a reshape coast), and a QC's timestamp field rides outside the vote-signed message. The hash-pinned, consensus-canonical timestamp of block `B` is `child.parent_qc.weighted_timestamp` — the value embedded in the child block that committed `B`. This canonical value is also `B`'s **anchor**: where `B` sits on the weighted-time grid is `B.parent_qc.weighted_timestamp`, the canonical timestamp of the block it extends. Every protocol that anchors deadlines or committee lookups uses this parent-QC form (INV-SHARD-6); committee lookups read it one block up — a block's committee keys on its *parent's* anchor, never on the aggregate over the parent (§4). The distinction is load-bearing: reshape genesis derivation once diverged precisely by reading a re-cert QC's timestamp instead of the canonical one.

### 1.4 The commit rule

A block `B` commits when a QC forms for a child at **exactly** `B.round + 1` — a round-contiguous two-chain. Blocks proposed after view changes (whose child is not round-contiguous) do not commit immediately; they commit later as the prefix of the first descendant that does form a direct two-chain.

The division of labor between the two rules is the heart of fork safety. The safe-vote rule alone does *not* prevent two QCs at one height: two siblings both extending the same parent QC can each gather a quorum without any validator violating its lock. What it cannot allow is both siblings *committing*. Committing `B` requires a contiguous chain of QCs above it, and quorum intersection (any two 2f+1 quorums share an honest validator, whose lock has ratcheted) forces every subsequent QC to extend the committed branch. One height, at most one committed block (INV-SHARD-1). The `fork_safety` test asserts exactly this under adversarial scheduling.

Every committed block's parent hash must equal the previously committed hash — commit order is exactly chain order (INV-SHARD-5). At commit, the chain state advances atomically: committed height/hash/state-root, the tip's block and committee anchor timestamps, a committed-transaction marker cell per transaction, retention-bounded dedup indices for verdicts, certificates and provisions, the beacon-witness accumulator (§3.3), and byte-growth counters that feed reshape triggers.

### 1.5 The pacemaker

Liveness under partial synchrony (INV-SHARD-8) is handled by timeout messages. A replica enters a round only on a certificate for the round before it: a QC, or a **timeout certificate** — a quorum's timeouts for that round, aggregated.

- When a round timer fires, the validator broadcasts `Timeout { shard, round, high_qc, high_tc }` — a BLS share over `(shard, round, high_qc.round)`, carrying its highest known QC and timeout certificate.
- **f+1 timeouts** for a round trigger Bracha-style amplification: broadcast your own timeout if you haven't. This guarantees that if any honest validator abandons a round, all eventually do — partitions cannot strand a minority in an old round.
- **2f+1 timeouts** assemble the round's certificate, which enters the next round; a tally whose shares report a QC this replica cannot yet verify moves nothing until that QC lands. A certificate takes only shares reporting no QC round above the assembler's own. The new round's proposer adopts the quorum-max `high_qc` from the collected timeouts, so the chain always continues from the highest certified block any quorum member knew.
- A block that **skips rounds** past its parent QC carries the certificate for the round before its own, and its parent QC must meet every QC round the certificate's signers reported. A block in the round right after its parent QC carries none. Voters check the certificate against the committee signing the block before voting.
- A block's **proposer announces its QC** to the committee as it forms. Votes reach only the proposer and the next two leaders, so without the announcement a next leader could withhold the QC until the others time the certified round out.
- Timers **retransmit** on every fire, carrying the sender's certificates; a one-shot timeout lost to a partition would wedge the round after healing, and a replica left behind in a view split catches up from the certificate on any peer's retransmit. The round timeout doubles with each round abandoned at a height, is capped, and is computed from QC-attested data, so all replicas agree on the deadline.

No single validator's message moves a view — only a certificate a quorum produced does — so no member can jump the committee to its own turn or skip the proposers in between. Speculative verification of far-round blocks is bounded as well, so Byzantine peers cannot burn a replica's CPU with them ([05-byzantine-safety.md](05-byzantine-safety.md) §6).

### 1.6 What a block carries

The `BlockHeader` binds, under the QC, everything other layers depend on. The load-bearing commitments (a characterization, not a field inventory) are: the parent QC itself (the timestamp source); the state root after this block; merkle roots over the block's content — transactions, finalizations, receipts, outbound provisions, per-destination provision-transaction roots, and the tick manifest naming what the block's tick holds and lets go; the beacon-witness root (the shard-to-beacon channel, §3.3); and, near reshape boundaries only, the child state roots and the settled-transaction root ([02-dynamic-sharding.md](02-dynamic-sharding.md)). The body carries the corresponding content; full provision bodies are dropped to hashes once the block seals past its execution window.

---

## 2. Execution consensus: certificates over outcomes

Ordering and execution are deliberately decoupled. Shard consensus commits blocks *before* executing their transactions; execution then happens against committed order, and its results are agreed by a second, lighter round of consensus. This decoupling is what makes cross-shard atomicity tractable: a shard can commit to running a transaction whose inputs live on four other shards without stalling its consensus on their progress.

### 2.1 Ticks

Each block names its own **tick** — the unit of execution agreement, and one batch. The proposer lists its members in the block's tick manifest (`TickManifest`), and every voter checks each line against committed content at the block's parent, so replicas at different committed tips name one list. A member joins when everything it needs has committed: one reaching no further than this shard, and every cross-shard leg whose counterparts' bundles and consumed crossings have committed ([04-atomic-commitment.md](04-atomic-commitment.md)). The lines fold into member rows held as committed state. A transaction that cannot join waits (`TickCandidates`, `crates/execution`) and a later block names it; it has attested nothing meanwhile, so waiting costs it latency and nothing else.

### 2.2 From votes to the ExecutionCertificate

Every validator executes the tick locally — deterministically: same engine, same inputs, same outputs — and sends an `ExecutionVote` asserting the tick's `global_receipt_root`, a merkle root over the per-transaction outcomes. The vote goes to the tick's leader, chosen by a deterministic hash of the tick id over the committee seated at the tick's own block. 2f+1 agreeing votes aggregate into an **`ExecutionCertificate`** (EC). Alongside the usual quorum material (signer bitfield, aggregated BLS signature), the EC carries the tick identity, a BFT-attested anchor timestamp, the receipt root, and per-transaction outcomes (succeeded, aborted, or rejected) — every one on the producing shard's own copy, and on a copy sent to a participant only those naming it, with a sparse proof binding them to the root.

A structural detail with safety weight: on decode, an EC's receipt root is **recomputed from the outcomes it carries**, at their leaf indices and with its proof, and must match the attested root. A Byzantine aggregator cannot assemble a signature-valid certificate whose claimed root diverges from its claimed outcomes (INV-EXEC-2).

### 2.3 Finalization

Each participating shard produces its own EC covering the transactions it ran. A tick id binds a shard and one of its blocks, so a remote participant's coverage arrives under its own tick boundaries and may be split across several ECs — a counterpart runs a transaction in whichever tick it could, not in the one this shard did. A **`Finalization`** bundles the local EC with the verified remote coverage. Finalization is decided per transaction: success requires a success outcome — carrying the transaction's receipt hash — from every participating shard, while an abort outcome from any single shard is terminal for the transaction. Abort is dominant; success is unanimous. Agreement on success content rests on deterministic execution: honest quorums compute identical per-transaction receipt hashes, so unanimity is agreement. It carries the local receipts those certificates attest alongside them, and rides in a subsequent block, making execution results part of the ordered chain. Receipts are validated against the EC's attestation before they are accepted from any source.

If a validator's local execution disagrees with the EC its shard's quorum produced, that validator marks the tick locally divergent and never finalizes its own result; it recovers the canonical `Finalization` through block sync instead. A locally-buggy replica cannot leak its receipts into the finalized store (INV-EXEC-8; see divergence recovery in [03-state-and-sync.md](03-state-and-sync.md)).

Execution consensus also has a liveness backstop, and it belongs to the transaction rather than to any batch: past its own signed validity end plus `MAX_FINALIZATION_DELAY`, a committed transaction still unresolved is attested `Aborted` by a later tick. Both figures are chain content on every replica, so the deadline is derived identically everywhere and abandonment is a certified outcome rather than each node's private cleanup (INV-EXEC-5).

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

Beacon state is **not** stored or attested on-chain; it is the result of folding a pure function, `apply_epoch(state, input) → state'`, over the committed block sequence. Every honest replica folding the same blocks holds the byte-identical `BeaconState` (INV-BEACON-2); a light client verifies by replaying the fold. The state carries: the validator registry with lifecycle statuses (pooled, seated, observing a reshape, jailed, revoked, stake-deficient); stake pools, whose aggregates also drive the dynamic activation price ([06-resource-economics.md](06-resource-economics.md)); the current and **next** per-shard committees; per-shard `ShardBoundary` records (§3.3); pending reshape records; governance parameters; and a running randomness accumulator that seeds every committee draw and shuffle — mixed each epoch from the reveal chain each crossing shard's boundary header carries, falling back to the beacon proposals' VRF outputs in an epoch where no crossing folds.

Each epoch's fold opens by promoting last epoch's frozen lookahead to active and closes by freezing the next epoch's lookahead — those bookends carry the ordering that matters (INV-BEACON-3). In between it applies the epoch's inputs: shard contributions (boundaries + witnesses), the randomness roll, validator lifecycle, committee shuffling and top-up, reshape admission and execution.

### 3.3 The shard–beacon channels

**Shards to beacon.** Once per epoch, each shard's boundary-crossing block becomes its contribution. Beacon proposers include the boundary QC per shard; the fold selects the canonical one (max by `(weighted_timestamp, hash)` — one canonical boundary per shard per epoch, INV-BEACON-5) and records a `ShardBoundary`: state root, block hash, height, canonical weighted timestamp, liveness bookkeeping, and — for terminating shards — terminal metadata and the settled-transaction root. Alongside the boundary rides a chunk of the shard's **witness log**: governance events (validator registration, stake movements, readiness, missed proposals, reshape triggers, parameter votes) accumulated in a per-shard merkle accumulator whose root is QC-attested in every shard block header. Witness chunks are contiguous, merkle-proven against the boundary header, and applied exactly once against a per-shard watermark (INV-BEACON-6). This channel is the only path by which anything a shard does can affect the validator set — and it is proof-carrying end to end.

**Beacon to shards.** From `BeaconState` the fold derives a **`TopologySnapshot`** — an identity-agnostic projection carrying every shard's committee (both the full membership used for networking and the ready-filtered subset used for consensus quorums), snap-sync anchors (`ShardAnchor`), reshape seat assignments, witness watermarks, and governance parameters. One `Arc<TopologySnapshot>` per epoch is distributed to every vnode on a host. Snapshots stack into the **`TopologySchedule`**: `epoch → snapshot`, queried by weighted timestamp.

### 3.4 Wall-clock pacing and the genesis anchor

Epochs are paced to wall-clock: the beacon's synthetic time advances as `epoch × epoch_duration_ms`, and a committee refuses to start an epoch before its wall-clock boundary — SPC could otherwise race far ahead of the shards whose schedule windows it defines. Production folding is genesis-relative (`BeaconChainConfig.genesis_timestamp_ms`), so the clock starts at zero at network birth rather than at Unix time. The pacing is carried by per-validator timer chains that every ratify-eligible validator keeps live — seated on a shard or following from the pool — so the cadence never rests on validators a draw happens to have placed conveniently (INV-BEACON-12).

---

## 4. Harmonization: weighted time and the schedule

The three layers stay mutually consistent through one discipline:

**Every committee lookup, everywhere, is `schedule.at(weighted_timestamp)`** — `epoch_for(wt) = floor(wt / epoch_duration_ms)` over an attested timestamp; what varies per artifact is only which timestamp keys the lookup.

A shard block's committee — the one that elects its proposer, votes on it, and signs the QC over it — anchors on its **parent**: the lookup keys on the parent header's own `parent_qc.weighted_timestamp`. Anchoring one block up is what makes the committee resolvable *before the block exists*, from a header every replica already holds and reads identically. The block's own anchor cannot serve: it is a quorum aggregate whose timestamp varies by which votes each aggregator held, and within that spread of an epoch cut two replicas would resolve two committees and elect two leaders, splitting the round's votes between proposals that both verify. The same parent-anchored resolution governs every consumer of a shard QC — live voting, synced-block admission, remote-header verification, fork-proof checking (a commit proof carries the certified block's parent header for exactly this reason) — so a block verifies under one committee however it arrives. Artifacts that carry their own attested anchor — a provision's source attestation, an execution certificate's tick anchor — resolve at it, and epoch-crossing detection keys on the crossing pair's own grid positions.

The binding is exact; there is no grace interval in which two committees are simultaneously acceptable (INV-SHARD-9).

Three properties make this sound:

1. **Lookahead (L=1).** Epoch `e+1`'s committees are computed and frozen during epoch `e`'s fold (INV-BEACON-3), one epoch before any honest artifact is stamped into `e+1`'s window — honest weighted timestamps track real time, and the fold is wall-clock paced. This is the common case, not an impossibility argument: the admission bound on forward skew (`MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH`) is independent of the epoch duration, so a maximally skewed QC can carry a timestamp past the frozen head, and a replica whose own fold lags sees even honest artifacts arrive early. Coverage (property 3) carries both cases: the lookup defers until the fold catches up; it never mis-resolves. The freeze also pre-positions validators: a member joining a committee next epoch has the current epoch to sync.
2. **Monotone attested time.** Weighted timestamps never regress along a shard chain, and epochs are half-open WT windows, so every block resolves to exactly one epoch.
3. **Retention with a consumer-derived floor.** The schedule retains history down to a floor computed from what could still legitimately need verification: the local chain frontier, every live shard's last-live boundary, every terminated shard's cut, and a hard horizon (`RETENTION_HORIZON`). A terminal record keys the floor on its cut rather than on the fold that delivered it — the shard leaves the trie at the cut, two windows before its contribution folds, so keying on the fold would evict the one window whose trie still carries it. Lookups below the floor are permanently rejected (`ScheduleLookup::Evicted`) rather than silently missing; lookups above the head are deferred until the beacon catches up (INV-BEACON-4). Terminated reshape shards get clamped extensions so their terminal artifacts remain verifiable until every dependent has consumed them.

The result: dozens of shard chains run at their own speeds, execution agreement trails ordering by its own cadence, and the beacon ticks once an epoch — yet any replica, handed any artifact from any layer, resolves the same governing committee and the same verification verdict as every other replica, using nothing but the artifact's attested timestamp and its own fold of the beacon chain.

---

## 5. Properties

The invariants this document motivates — INV-SHARD-1 through INV-SHARD-9, INV-BEACON-1 through INV-BEACON-7 and INV-BEACON-12, and the execution-layer INV-EXEC-1/2/5/8 — are stated precisely in [08-invariants.md](08-invariants.md).
