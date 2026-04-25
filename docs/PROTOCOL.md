# Hyperscale BFT Consensus Protocol

> Stability: **Layer 1 (Frozen)**

## 1. Overview

Hyperscale-rs implements a sharded BFT consensus protocol derived from HotStuff-2. It uses a two-chain commit rule for finality, optimistic pipelining (proposing at `latest_qc.height + 1` rather than `committed_height + 1`), implicit timeout-based view changes with linear backoff, and wave-based cross-shard execution voting. The state machine (`BftState`) is synchronous and event-driven: it consumes `ProtocolEvent`s and emits `Action`s; all I/O is performed by the runner. See `crates/bft/src/lib.rs:7-56` for the architecture overview.

## 2. Two-Chain Commit Rule

A block at height H is committed when a QC forms for height H+1. The certifying chain is: block H receives a QC (carried as `parent_qc` in the height H+1 header), then height H+1 itself receives a QC -- at which point H becomes committable.

Implementation: `crates/bft/src/state.rs:3012` `try_two_chain_commit()`. It extracts `committable_height` and `committable_hash` from the QC (lines 3021-3026), checks that the committable height is above `committed_height` (line 3028), retrieves the certifying QC from the block's `parent_qc` (lines 3035-3038), and emits `Action::Continuation(ProtocolEvent::BlockReadyToCommit { ... })` (line 3049).

Called from both `on_qc_formed` (local QC build) and `on_block_header` (learning a QC via the next block's `parent_qc`), ensuring all validators commit regardless of whether they received votes directly (line 3008-3011 comment).

## 3. Optimistic Pipelining

The protocol proposes at `latest_qc.height + 1`, not `committed_height + 1`. This allows the chain to grow while waiting for the two-chain commit rule to be satisfied.

Implementation: `crates/bft/src/state.rs:825-829` in `on_proposal_timer()`:

```rust
let next_height = self
    .latest_qc
    .as_ref()
    .map(|qc| qc.height.0 + 1)
    .unwrap_or(self.committed_height + 1);
```

The same height calculation is mirrored in `advance_round()` at line 3626-3630 to maintain consistency between normal proposals and view-change proposals.

## 4. QC Formation

A Quorum Certificate requires `2f+1` weighted voting power (`VotePower::has_quorum`). QC construction is deferred to a thread pool via `verify_and_build_qc()` in `crates/bft/src/handlers.rs:36`.

**Signature verification**: BLS12-381 batch verification is attempted first (`batch_verify_bls_same_message`, line 65). If the batch fails, individual verification is used as fallback (lines 82-93). This prevents a single invalid signature from rejecting the entire batch.

**Weighted timestamp**: The QC carries a `weighted_timestamp_ms` computed as the voting-power-weighted average of voter timestamps (lines 114-125 in `handlers.rs`). This provides Byzantine-tolerant consensus time.

**Aggregated signature**: Individual BLS signatures are aggregated into a single `aggregated_signature` with a `SignerBitfield` recording which committee members signed (lines 101-136 in `handlers.rs`).

**Deferred verification pipeline**: QC signature verification is asynchronous. When a block header arrives with a non-genesis `parent_qc`, the header is stored in `VerificationPipeline::pending_qc_verifications` (`crates/bft/src/verification.rs:88`) and an `Action::VerifyQcSignature` is emitted. Voting is deferred until verification completes. See `crates/bft/src/verification.rs:84` `VerificationPipeline` struct.

## 5. Block Validation Pipeline

Before voting, blocks pass through a 5-step validation pipeline. Steps 1-2 are synchronous; steps 3-5 are async (parallel).

### Step 1: Header Validation (synchronous)

`crates/bft/src/state.rs:1662` `validate_header()`:

- Height above `committed_height` (line 1671)
- Correct proposer for height/round via `topology.proposer_for()` (line 1679)
- Parent QC has quorum power (lines 1690-1698)
- Parent QC height = block height - 1 (line 1702)
- `parent_hash` matches `parent_qc.block_hash` (line 1710)
- Timestamp within bounds via `validate_timestamp()` (line 1730); fallback and genesis blocks are exempt (lines 1751-1766)

### Step 2: Content Validation (synchronous)

`crates/bft/src/state.rs:1906-2033`:

- Abort intent validation: `validate_abort_intents()` (line 1910)
- Transaction ordering: `validate_transaction_ordering()` (line 1921)
- Wave field validation: `validate_waves()` (line 1932)
- Duplicate transaction detection: `validate_no_duplicate_transactions()` (line 1943)

### Step 3: QC Signature Verification (async)

Parent QC BLS aggregate signature verified off-thread. Tracked via `VerificationPipeline::pending_qc_verifications` (`crates/bft/src/verification.rs:88`).

### Step 4: Merkle Root Verification (async, parallel)

Multiple root verifications run concurrently (lines 1953-2026 in `state.rs`):

- **State root**: `initiate_state_root_verification()` (line 1965) -- verifies proposer's claimed state root against local JVT computation
- **Transaction root**: `initiate_transaction_root_verification()` (line 1978)
- **Certificate root**: `initiate_certificate_root_verification()` (line 1989)
- **Local receipt root**: `initiate_local_receipt_root_verification()` (line 2010)

### Step 5: Abort Intent Proof Verification (async)

Livelock cycle abort intents carry merkle inclusion proofs that must be verified against remote committed block headers. `initiate_abort_intent_verification()` (line 2019) resolves remote headers and dispatches verification or parks until headers arrive.

If any async verification is pending, the vote is deferred (lines 2030-2031).

## 6. Consensus Safety Rules

### Vote Locking

`crates/bft/src/state.rs:1872-1904`. A validator records `(block_hash, round)` per height in `voted_heights` (line 166). If a vote exists for the same height:
- Same block hash: no-op (line 1877)
- Different block hash: vote refused (line 1893)

### Vote Lock Release

Two mechanisms release vote locks:

1. **Timeout-based unlock** (`advance_round()`, lines 3663-3684): When no QC has formed at the current height (`latest_qc_height < height`), the vote lock is cleared on round advance. Safety is maintained by quorum intersection -- a conflicting block can never reach quorum. More aggressive than standard HotStuff-2 which requires a TC.

2. **QC-based unlock** (`maybe_unlock_for_qc()`, lines 3752-3796): When a QC arrives at height H, all vote locks at heights <= H are removed (lines 3780-3795). Also performs view synchronization: if `qc.round > self.view`, the local view advances to match (line 3772).

### Equivocation Detection

`crates/bft/src/state.rs:2481-2508`. Tracks `(height, voter) -> (block_hash, round)` in `received_votes_by_height`. Equivocation = different block hash at the same height AND round (line 2488). Different blocks at different rounds are legitimate (vote lock release across rounds). Detection is for logging/future slashing, not prevention -- BFT safety relies on quorum intersection (lines 2498-2501).

## 7. Implicit View Changes

View changes are timeout-based and local -- no coordinated view-change voting is required (`crates/bft/src/lib.rs:48-49`).

### Timeout with Linear Backoff

`crates/bft/src/state.rs:627` `current_view_change_timeout()`:

```
timeout = base + increment * rounds_at_height
```

where `rounds_at_height = view - view_at_height_start` (line 632). Optional cap via `view_change_timeout_max` (line 638). The backoff resets when `committed_height` advances (height transition resets `view_at_height_start`).

Timeout is checked via `should_advance_round()` (line 656) which compares elapsed time since `last_leader_activity` against the current timeout.

### Round Advance

`crates/bft/src/state.rs:3623` `advance_round()`: Increments `self.view` (line 3632), performs timeout-based vote unlock if no QC formed (lines 3663-3684), then either:
- If we are the new proposer and vote-locked: re-propose the locked block (line 3698)
- If we are the new proposer and unlocked: build a fallback block (line 3709)
- Otherwise: reschedule the proposal timer (lines 3713-3716)

### Fallback Blocks

`crates/bft/src/state.rs:1082` `build_and_broadcast_fallback_block()`: Empty blocks (no transactions, no certificates, no abort intents) proposed after view change timeout. Timestamp is inherited from parent's `weighted_timestamp_ms` to prevent time manipulation during view changes (line 1099). State root is inherited from parent (lines 1103-1109).

## 8. Cross-Shard Execution Model

Cross-shard transactions use **wave-based execution voting**, NOT two-phase commit. There is no coordinator, no prepare/commit phases, and no lock-based concurrency. Instead, transactions are partitioned into waves by their provision dependency set, and each wave is finalized independently through execution voting and certification.

### Phase 1: Provision

After a block commits, the block proposer sends `StateProvision` messages (`crates/types/src/state.rs:147`) to target shards. Each provision contains pre-computed storage keys and substate values for the transaction's remote state dependencies. Provisions are batched per block with a single aggregated verkle proof.

### Phase 2: Execution

Once all provisions arrive for a wave's transactions, each validator executes the transactions locally. Results are recorded as `TxOutcome` values (`crates/types/src/execution_vote.rs:214`) -- either `Executed { receipt_hash, success, write_nodes }` or `Aborted { reason }`.

Execution batch completion is handled in `crates/execution/src/state.rs:539` `on_execution_batch_completed()`, which caches receipts, checks pending wave receipts, and records outcomes into execution accumulators.

### Phase 3: Voting & Certification

Validators cast `ExecutionVote`s (`crates/types/src/execution_vote.rs:255`) per wave. A vote covers all transactions sharing the same provision dependency set, with `global_receipt_root` being a padded merkle root over per-tx outcome leaves where each leaf = `H(tx_hash || receipt_hash || success_byte)` (see `tx_outcome_leaf()` at `crates/types/src/execution_vote.rs:355`).

A deterministic `wave_leader()` (`crates/types/src/execution_vote.rs:193`) aggregates votes. When 2f+1 voting power is reached, an `ExecutionCertificate` (`crates/types/src/execution_vote.rs:298`) is produced with an aggregated BLS signature and per-tx outcomes.

The EC's `canonical_hash()` (line 334) excludes `aggregated_signature` and `signers` so that different valid 2f+1 subsets produce the same identity hash.

### Phase 4: Finalization

The wave leader broadcasts a `WaveCertificate` (`crates/types/src/wave_certificate.rs:17`) containing `ShardAttestation`s (line 42) -- lean proofs with BLS signatures and EC hashes. Per-tx decisions are NOT embedded in the certificate; they are derived from the referenced ECs.

Resolution is either `WaveResolution::Completed { attestations }` or `WaveResolution::Aborted` (lines 27-38). Finalized waves are included in subsequent block proposals for state commitment.

### Wave Assignment

Transactions are partitioned by remote shard dependency set (`crates/types/src/execution_vote.rs:123` `compute_waves()`):

- **Wave-zero**: Single-shard transactions (no remote dependencies) -- executed immediately
- **Wave {B}**: Transactions needing provisions only from shard B
- **Wave {B,C}**: Transactions needing provisions from both shards B and C

Wave IDs are self-contained (`WaveId` at line 41): `shard_group_id + block_height + remote_shards`. This eliminates composite keys throughout the codebase.

## 9. Livelock Prevention

Cross-shard cycles are resolved by deterministic cycle detection in the `livelock` crate.

### Cycle Detection

`crates/livelock/src/state.rs:64` `LivelockState`. When verified provisions arrive (`on_provision_accepted()`, line 191), the state checks for bidirectional cycles via `check_for_cycle()` (line 315).

A **true cycle** requires node-level overlap (line 343): the remote transaction's state nodes must intersect with the local transaction's needed nodes from that shard. Shard-level co-dependency without node overlap is not a deadlock.

### Deterministic Resolution

Higher-hash loses (line 357): transactions are compared by hash, and the one with the higher hash is deferred. Both shards independently reach the same conclusion without coordination.

The loser's shard requests a merkle inclusion proof for the winner transaction from the source shard (line 381), then constructs an `AbortIntent` with `AbortReason::LivelockCycle` (`crates/types/src/transaction.rs:316`). The abort intent carries the inclusion proof so validators can verify it against the remote committed block header.

### Abort Reasons

`crates/types/src/transaction.rs:300` `AbortReason`:

- `ExecutionTimeout { committed_at }` -- transaction exceeded its execution deadline (N-way cycle fallback)
- `LivelockCycle { winner_tx_hash, source_shard, source_block_height, tx_inclusion_proof }` -- deterministic cycle resolution

Abort intents (`AbortIntent`, line 411) are proposed in blocks and validated by all voters (step 2 of the validation pipeline).

## 10. Protocol Flow Summary

```
                         CONSENSUS LAYER
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  ProposalTimer ──► on_proposal_timer()                      │
  │       │             propose at latest_qc.height + 1         │
  │       ▼                                                     │
  │  BroadcastBlockHeader ──► on_block_header() [validators]    │
  │       │                    validate_header()                 │
  │       │                    validate content (aborts/tx/waves)│
  │       │                    async: verify QC sig, roots       │
  │       ▼                                                     │
  │  create_vote() ──► on_block_vote() [proposer]               │
  │       │             collect in VoteSet                       │
  │       │             dispatch verify_and_build_qc()           │
  │       ▼                                                     │
  │  on_qc_formed()                                             │
  │       │  update latest_qc, maybe_unlock_for_qc()            │
  │       │  try_two_chain_commit() ──► commit block at H-1     │
  │       ▼                                                     │
  │  advance_round() [on timeout]                               │
  │       │  view++, unlock vote if no QC                       │
  │       │  build_and_broadcast_fallback_block() if proposer   │
  │       │  linear backoff: base + increment * rounds          │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

                    CROSS-SHARD EXECUTION LAYER
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  Block committed ──► send StateProvisions to target shards  │
  │       │                                                     │
  │       ▼                                                     │
  │  Provisions received ──► execute wave transactions          │
  │       │                   check_for_cycle() [livelock]      │
  │       ▼                                                     │
  │  ExecutionVote cast per wave (2f+1 for EC)                  │
  │       │  wave_leader() aggregates                           │
  │       ▼                                                     │
  │  ExecutionCertificate ──► WaveCertificate                   │
  │       │  ShardAttestations (proof-only, no tx data)         │
  │       ▼                                                     │
  │  FinalizedWave included in next block proposal              │
  │       state committed on block commit                       │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
```
