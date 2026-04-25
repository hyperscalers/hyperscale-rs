# Glossary -- hyperscale-rs Domain Terms

> Stability: **Reference** -- updated when new terms are introduced

## Consensus Terms

| Term | Definition | Key Type | Source |
|------|-----------|----------|--------|
| Two-Chain Commit | Commit rule: a QC for block N commits block N-1. Derives from HotStuff-2. | `QuorumCertificate::has_committable_block()` | `crates/bft/src/state.rs:3012` fn `try_two_chain_commit` |
| Quorum Certificate (QC) | Aggregated BLS signature from 2f+1 validators proving a block was voted on. Contains shard ID for cross-shard replay prevention. | `QuorumCertificate` | `crates/types/src/quorum_certificate.rs:13` |
| View / Round | Monotonically increasing round counter within a height. Incremented on timeout (implicit view change). | `BftState::view` | `crates/bft/src/state.rs:123` |
| Optimistic Pipelining | Next height is proposed immediately after QC formation (one above highest certified block, not committed block). Chain grows while prior blocks await two-chain commit. | -- | `crates/bft/src/state.rs:822` |
| Fallback Block | Empty block proposed when the leader times out. Inherits parent timestamp to prevent time manipulation during view changes. | `BlockHeader::is_fallback` | `crates/bft/src/state.rs:1082` fn `build_and_broadcast_fallback_block` |
| Vote Lock | Per-height lock preventing a validator from voting for conflicting blocks at the same height. Ensures BFT safety across rounds. | `BftState::voted_heights` | `crates/bft/src/state.rs:1872` |
| Advance Round | Implicit view change: each validator increments `view` locally on timeout and may propose if selected. No coordinated voting required. | `BftState::advance_round()` | `crates/bft/src/state.rs:3623` fn `advance_round` |
| Quorum | Voting threshold: strictly greater than 2/3 of total stake. Formula: `voted * 3 > total * 2`. | `VotePower::has_quorum()` | `crates/types/src/identifiers.rs:83` |
| Block Height | Monotonic block position in a shard's chain. Genesis = 0. | `BlockHeight` | `crates/types/src/identifiers.rs:29` |
| Proposer Rotation | Round-robin leader selection: `(height + round) % committee.len()`. | `TopologySnapshot::proposer_for()` | `crates/types/src/topology.rs:364` |

## Execution Terms

| Term | Definition | Key Type | Source |
|------|-----------|----------|--------|
| Wave | Partition of cross-shard transactions in a block by their provision dependency set (the set of remote shards they need state from). Transactions with identical dependency sets share a wave. **Not** two-phase commit -- this is wave-based execution voting. | `WaveId` | `crates/types/src/execution_vote.rs:41` |
| Wave Zero | Single-shard transactions (empty `remote_shards`). Excluded from cross-shard waves. | `WaveId::is_zero()` | `crates/types/src/execution_vote.rs:65` |
| Execution Vote | A validator's BLS-signed vote on all transactions in a wave. Covers a `global_receipt_root` (padded merkle root over per-tx outcome leaves). | `ExecutionVote` | `crates/types/src/execution_vote.rs:255` |
| Execution Certificate (EC) | Aggregated certificate from 2f+1 execution votes for a wave. Contains per-tx outcomes so remote shards can extract individual results. Canonical hash excludes signature/signers for signer-independence. | `ExecutionCertificate` | `crates/types/src/execution_vote.rs:298` |
| Wave Leader | Sole aggregator of execution votes into an EC. Deterministically selected via `Hash(wave_id) % committee_size`. | `wave_leader()` | `crates/types/src/execution_vote.rs:193` fn `wave_leader` |
| Wave Certificate (WC) | Lean proof of wave-level finalization. Contains shard attestations (BLS signatures + ec_hashes) but NOT per-tx decisions -- those are derived from referenced ECs. | `WaveCertificate` | `crates/types/src/wave_certificate.rs:17` |
| Shard Attestation | Proof half of an EC from a single shard: ec_hash, global_receipt_root, aggregated BLS signature, signer bitfield. Embedded in WaveCertificate. | `ShardAttestation` | `crates/types/src/wave_certificate.rs:42` |
| Finalized Wave | Completed wave with all data for block commit: wave cert, ECs, per-tx decisions, receipt bundles. Shared via `Arc`. | `FinalizedWave` | `crates/types/src/finalized_wave.rs:24` |
| Transaction Decision | Final per-tx outcome after cross-shard coordination. Priority: `Aborted > Reject > Accept`. | `TransactionDecision` | `crates/types/src/transaction.rs:277` |
| Abort Intent | Block-level proposal to abort a transaction. Feeds into execution voting; actual abort takes effect only when a WaveCertificate confirms it. | `AbortIntent` | `crates/types/src/transaction.rs:411` |
| Abort Reason | Why a transaction was aborted: `ExecutionTimeout` (held locks too long) or `LivelockCycle` (higher-hash loser in bidirectional cross-shard cycle). | `AbortReason` | `crates/types/src/transaction.rs:300` |
| State Provision | State entries sent from a source shard to a target shard for cross-shard execution. Only the block proposer sends these. Bundled per-block with a single aggregated verkle proof. | `StateProvision` | `crates/types/src/state.rs:147` |
| Global Receipt | Cross-shard agreement receipt: outcome + event_root + writes_root. Ephemeral -- never stored, only lives for EC aggregation. Hash is what validators sign in execution votes. | `GlobalReceipt` | `crates/types/src/receipt.rs:87` |
| Local Receipt | Per-shard receipt with shard-filtered database updates and events. Feeds `state_root` computation via JVT. Written atomically with block commit. | `LocalReceipt` | `crates/types/src/receipt.rs:129` |

## Data Types

| Term | Definition | Key Type | Source |
|------|-----------|----------|--------|
| Hash | 32-byte Blake3 cryptographic hash. Deterministic, constant-time comparison, safe as HashMap key. `Hash::ZERO` is the all-zeros sentinel. | `Hash` | `crates/types/src/hash.rs:12` |
| ValidatorId | Numeric validator identifier (u64 newtype). | `ValidatorId` | `crates/types/src/identifiers.rs:8` |
| ShardGroupId | Numeric shard group identifier (u64 newtype). NodeIds map to shards via `hash(node_id) % num_shards`. | `ShardGroupId` | `crates/types/src/identifiers.rs:18` |
| NodeId | 30-byte state tree address identifying a substate entity (component, resource, vault). Used for shard routing. | `NodeId` | `crates/types/src/identifiers.rs:98` |
| VotePower | Stake weight (u64 newtype). Minimum value is 1. Provides `has_quorum()` for BFT threshold checks. | `VotePower` | `crates/types/src/identifiers.rs:59` |
| EpochId | Monotonically increasing epoch identifier (u64 newtype). Genesis = 0. Shard membership is stable within an epoch. | `EpochId` | `crates/types/src/epoch.rs:13` |
| SignerBitfield | Compact bitfield tracking which validators contributed to an aggregated BLS signature. Indexed by committee position. | `SignerBitfield` | `crates/types/src/signer_bitfield.rs:10` |
| Block | Complete block: `BlockHeader` + transactions + wave certificates + abort intents. Transactions stored as `Arc<RoutableTransaction>` sorted by hash. | `Block` | `crates/types/src/block.rs:255` |
| BlockHeader | Consensus metadata voted on by validators. Contains chain position, proposer, parent QC, state_root, transaction_root, certificate_root, local_receipt_root, and cross-shard waves. | `BlockHeader` | `crates/types/src/block.rs:121` |
| RoutableTransaction | Radix `UserTransaction` wrapped with routing metadata (`declared_reads`, `declared_writes`). Hash computed from SBOR-encoded payload. | `RoutableTransaction` | `crates/types/src/transaction.rs:13` |
| VerkleInclusionProof | Opaque serialized JVT verkle proof for substate inclusion in the state tree. IPA-based multipoint proof (~576 bytes core) + verifier queries. | `VerkleInclusionProof` | `crates/types/src/proofs.rs:37` |
| TopologySnapshot | Immutable read-only view of shard committee membership. Passed by reference to subsystem methods. All query methods are `&self`. | `TopologySnapshot` | `crates/types/src/topology.rs:41` |

## Architecture Terms

| Term | Definition | Key Type | Source |
|------|-----------|----------|--------|
| StateMachine | Core trait: synchronous, deterministic, no I/O. Processes `ProtocolEvent` -> `Vec<Action>`. Same state + event = same actions. | `trait StateMachine` | `crates/core/src/traits.rs:34` |
| Action | Command emitted by the state machine describing work to perform (network sends, timers, delegated crypto, block commits). The runner executes actions. | `enum Action` | `crates/core/src/action.rs:115` |
| ProtocolEvent | Typed input event for `NodeStateMachine::handle()`. No I/O callbacks -- IoLoop translates `NodeInput` into `ProtocolEvent` first. | `enum ProtocolEvent` | `crates/core/src/protocol_event.rs:40` |
| NodeStateMachine | Top-level state machine composing BFT, execution, mempool, provisions, remote headers, and livelock subsystems. | `NodeStateMachine` | `crates/node/src/state.rs:33` |
| IoLoop | Unified I/O loop processing all actions. Generic over storage (`S`), network (`N`), and dispatch (`D`). Owns the state machine instance. | `IoLoop<S, N, D>` | `crates/node/src/io_loop/mod.rs:182` |
| Dispatch | Trait for scheduling CPU-intensive work on priority-isolated thread pools: consensus crypto, general crypto, tx validation, execution, provisions. | `trait Dispatch` | `crates/dispatch/src/lib.rs:26` |
| BatchAccumulator | Time-and-count-based flushing collector. Items accumulate until a max count or time window is reached. Uses logical time (`Duration`) for simulation compatibility. | `BatchAccumulator<T>` | `crates/node/src/batch_accumulator.rs:17` |
| Continuation | An `Action::Continuation(ProtocolEvent)` -- a follow-on event fed back into the state machine at the same timestamp with internal priority. Used for multi-step protocol transitions. | `Action::Continuation` | `crates/core/src/action.rs:219` |
