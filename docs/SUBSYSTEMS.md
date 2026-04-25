# Subsystem Deep Dives

> Stability: **Layer 3 (Moderate Churn)**

---

## BFT Consensus (~11,542 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/bft/src/state.rs` | 8,650 | Core state machine (`BftState`), event handlers, proposer logic |
| `crates/bft/src/verification.rs` | 992 | Async verification pipeline (QC sigs, state/tx/receipt roots) |
| `crates/bft/src/vote_set.rs` | 511 | Deferred vote collection and quorum tracking |
| `crates/bft/src/handlers.rs` | 418 | Pure cryptographic verification functions (no state mutation) |
| `crates/bft/src/pending.rs` | 422 | Pending block assembly (header + transactions + certificates) |
| `crates/bft/src/sync.rs` | 287 | Sync manager (block buffering, catch-up) |
| `crates/bft/src/config.rs` | 147 | `BftConfig` — all tunable parameters |
| `crates/bft/src/fetch.rs` | 44 | Fetch coordinator for missing block data |
| `crates/bft/src/lib.rs` | 71 | Module structure, re-exports |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `BftState` | `state.rs:109` | Core state machine struct — identity, chain state, pending state, config, time |
| `BftConfig` | `config.rs:7` | All consensus parameters (timeouts, limits, intervals) |
| `BftStats` | `state.rs:22` | Monitoring counters (view_changes, current_round, committed_height) |
| `BftMemoryStats` | `state.rs:32` | Collection size monitoring (pending_blocks, vote_sets, etc.) |
| `RecoveredState` | `state.rs:70` | Crash recovery input (committed_height, hash, latest_qc, jvt_root) |
| `VoteSet` | `vote_set.rs:22` | Per-block vote collection with deferred verification |
| `VerificationPipeline` | `verification.rs` | Tracks in-flight QC sig, state root, tx root verifications |
| `PendingQcVerification` | `verification.rs:23` | Block header awaiting QC signature verification |
| `QcVerificationResult` | `handlers.rs:18` | Result of `verify_and_build_qc()` — QC or verified votes |

### Event/Handler Flow

The `BftState` is a synchronous state machine. Events in, `Vec<Action>` out.

```
ProposalTimer          -> on_proposal_timer()        -> BuildProposal action
BlockHeaderReceived    -> on_block_header()           -> validate, track pending, vote
BlockVoteReceived      -> on_block_vote()             -> collect in VoteSet, batch-verify at quorum
QuorumCertificateResult-> on_qc_result()              -> update chain, two-chain commit check
BlockReadyToCommit     -> on_block_ready_to_commit()  -> CommitBlock action
QcSignatureVerified    -> on_qc_signature_verified()  -> unblock pending vote
BlockRootVerified      -> on_block_root_verified()    -> unblock pending vote (tx/cert/receipt root)
ChainMetadataFetched   -> on_chain_metadata_fetched() -> recovery from storage
```

### Core State Fields (`BftState`, `state.rs:109-260`)

| Field | Type | Purpose |
|-------|------|---------|
| `view` | `u64` | Current view/round number |
| `view_at_height_start` | `u64` | View at height start (for linear backoff) |
| `committed_height` | `u64` | Latest committed block height |
| `committed_hash` | `Hash` | Hash of latest committed block |
| `latest_qc` | `Option<QuorumCertificate>` | Latest QC (certifies highest certified block) |
| `pending_blocks` | `HashMap<Hash, PendingBlock>` | Blocks being assembled |
| `vote_sets` | `HashMap<Hash, VoteSet>` | Vote sets per block hash |
| `voted_heights` | `HashMap<u64, (Hash, u64)>` | Vote lock: height -> (block_hash, round) |
| `received_votes_by_height` | `HashMap<(u64, ValidatorId), (Hash, u64)>` | Equivocation detection |
| `certified_blocks` | `HashMap<Hash, Block>` | QC'd but uncommitted blocks |
| `verification` | `VerificationPipeline` | Async verification tracking |
| `pending_commits` | `BTreeMap<u64, (Hash, QC)>` | Out-of-order commit buffer |
| `pending_commits_awaiting_data` | `HashMap<Hash, (u64, QC)>` | Commits waiting for block data |
| `remote_headers` | `HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>` | Remote headers for merkle proofs |

### Notable Patterns

- **Deferred vote verification** (`vote_set.rs:1-12`): Votes are NOT verified on receipt. Buffered until quorum is possible, then batch-verified in one `VerifyAndBuildQuorumCertificate` action. Saves CPU on votes that never reach quorum.
- **Two-chain commit**: Block at height H commits when QC forms for height H+1 (`lib.rs:44-45`).
- **Vote locking** (`state.rs:159-167`): Once voted at height H, cannot vote for a different block at same height+round. Unlocked on round advance or QC proof.
- **Linear timeout backoff** (`state.rs:627-642`, `current_view_change_timeout()`): `timeout = base + increment * rounds_at_height`, capped at `view_change_timeout_max` (default 30s).
- **Header activity rate limiting** (`state.rs:605-611`, `record_header_activity()`): One timer reset per (height, round) to prevent Byzantine header spam delaying view changes.

### Config Defaults (`BftConfig::default()`, `config.rs:84-101`)

| Parameter | Default | Notes |
|-----------|---------|-------|
| `proposal_interval` | 1000ms | Time between proposal attempts |
| `view_change_timeout` | 5s | Base timeout before round advance |
| `view_change_timeout_increment` | 1000ms | Linear backoff per round |
| `view_change_timeout_max` | 30s | Cap on backoff |
| `max_transactions_per_block` | 4,096 | Block size limit |
| `max_certificates_per_block` | 8,192 | Wave cert limit per block |
| `transaction_fetch_timeout` | 150ms | Missing tx fetch delay |
| `certificate_fetch_timeout` | 500ms | Missing cert fetch delay |
| `min_block_interval` | 500ms | Global rate limit between blocks |
| `min_execution_timeout_blocks` | 30 | Min blocks before abort intent is valid |

---

## Node Orchestration (~9,471 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/node/src/state.rs` | 832 | `NodeStateMachine` — top-level event router, subsystem coordinator |
| `crates/node/src/io_loop/mod.rs` | 1,113 | `IoLoop<S,N,D>` — generic I/O loop (storage, network, dispatch) |
| `crates/node/src/io_loop/actions.rs` | 959 | Action dispatch (network sends, timer ops, storage writes) |
| `crates/node/src/io_loop/handlers.rs` | 500 | Event handlers within IoLoop context |
| `crates/node/src/io_loop/protocols.rs` | 472 | Protocol integration (sync, fetch, provisions) |
| `crates/node/src/action_handler.rs` | 718 | `handle_delegated_action()` — bridges actions to thread pool work |
| `crates/node/src/protocol/sync.rs` | 516 | Sync protocol state machine |
| `crates/node/src/protocol/provision_fetch.rs` | 988 | Provision fetch with peer rotation |
| `crates/node/src/protocol/execution_cert_fetch.rs` | 1,007 | EC fetch with peer rotation |
| `crates/node/src/protocol/inclusion_proof_fetch.rs` | 857 | Livelock proof fetch with peer rotation |
| `crates/node/src/protocol/header_fetch.rs` | 588 | Cross-shard header fetch |
| `crates/node/src/protocol/transaction_fetch.rs` | 426 | Transaction fetch with chunking/retry |
| `crates/node/src/batch_accumulator.rs` | 222 | Time-and-count flush batching |
| `crates/node/src/io_loop/batches.rs` | 104 | Batch flush integration |
| `crates/node/src/io_loop/verify.rs` | 76 | Verification helpers |
| `crates/node/src/config.rs` | 70 | Node configuration |
| `crates/node/src/lib.rs` | 17 | Module structure |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `NodeStateMachine` | `state.rs:33` | Top-level state machine composing bft, execution, mempool, provisions, livelock |
| `IoLoop<S, N, D>` | `io_loop/mod.rs:182` | Generic I/O loop — storage, network, dispatch, caches, protocols |
| `ActionContext` | `action_handler.rs:20` | Context for delegated action execution (storage, executor, topology) |
| `DelegatedResult` | `action_handler.rs:27` | Result of thread pool work (events + optional prepared commit) |
| `DispatchPool` | `action_handler.rs:36` | Pool routing enum: ConsensusCrypto, Crypto, Execution, Provisions |
| `BatchAccumulator<T>` | `batch_accumulator.rs:17` | Time-and-count flush batching (max_count or window, whichever first) |

### Event/Handler Flow (`NodeStateMachine::handle()`, `state.rs:552-818`)

The `NodeStateMachine` implements `StateMachine` trait. Its `handle()` is the central event router:

```
Timers:            CleanupTimer, ProposalTimer
BFT Consensus:    BlockHeaderReceived, BlockVoteReceived, QcFormed, BlockReadyToCommit,
                   QcResult, QcSignatureVerified, RemoteHeaderQcVerified, BlockRootVerified,
                   ProposalBuilt, RemoteBlockCommitted, RemoteHeaderVerified
Block Committed:   BlockCommitted -> on_state_commit_complete() + on_block_committed()
Provisions:        StateProvisionsReceived, StateProvisionsVerified, ProvisionsAccepted,
                   ProvisioningComplete
Execution:         ExecutionBatchCompleted, ExecutionVoteReceived,
                   ExecutionVotesVerifiedAndAggregated, ExecutionCertificateAggregated,
                   ExecutionCertificateReceived, ExecutionCertificateSignatureVerified
Transactions:      TransactionExecuted, WaveCompleted, TransactionGossipReceived
Fetch/Sync:        TransactionFetchDelivered, SyncBlockReadyToApply, SyncComplete,
                   ChainMetadataFetched
Global Consensus:  GlobalConsensusTimer, GlobalBlockReceived, etc. -> ALL RETURN vec![]
```

### Core State Fields (`NodeStateMachine`, `state.rs:33-60`)

| Field | Type | Purpose |
|-------|------|---------|
| `node_index` | `NodeIndex` | Simulation-only routing index |
| `topology` | `TopologyState` | Network topology (shared snapshot) |
| `bft` | `BftState` | BFT consensus state |
| `execution` | `ExecutionState` | Execution pipeline state |
| `mempool` | `MempoolState` | Transaction pool |
| `provisions` | `ProvisionCoordinator` | Cross-shard provision coordination |
| `remote_headers` | `RemoteHeaderCoordinator` | Remote header verification (single source of truth) |
| `livelock` | `LivelockState` | Cycle detection for cross-shard TXs |
| `now` | `Duration` | Current logical time |

### Notable Patterns

- **Dispatch pool routing** (`action_handler.rs:51-78`, `dispatch_pool_for()`): Actions are routed to 4 pools: ConsensusCrypto (liveness-critical), Crypto (general), Execution (single-shard + merkle), Provisions (IPA math).
- **Block committed fan-out** (`state.rs:367-461`, `on_block_committed()`): Single commit triggers: livelock tracking, BFT tx registration, execution abort recording, cert removal, mempool notification, provision cleanup, and wave vote scan. Order matters.
- **State root drain** (`state.rs:799-815`): After every `handle()` call, drains `bft.drain_ready_state_root_verifications()` and attaches `Arc<FinalizedWave>` from execution state.
- **Global consensus stubs** (`state.rs:785-796`): All `GlobalConsensus*` and `Epoch*` events return `vec![]`. Not yet implemented.
- **IoLoop caches** (`io_loop/mod.rs:209-211`): `cert_cache` and `tx_cache` are `Arc<QuickCache>` shared with inbound router for deduplication.
- **Commit ordering guard** (`io_loop/mod.rs:252`): `commit_in_flight: Arc<AtomicBool>` prevents out-of-order block commits across async flushes.

---

## Types (~7,473 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/types/src/transaction.rs` | 1,223 | `RoutableTransaction` — tx with routing metadata |
| `crates/types/src/block.rs` | 751 | `Block`, `BlockHeader`, `CommittedBlockHeader`, merkle roots |
| `crates/types/src/topology.rs` | 702 | `TopologySnapshot` — shard/validator mapping |
| `crates/types/src/execution_vote.rs` | 614 | `ExecutionVote`, `WaveId`, wave assignment |
| `crates/types/src/receipt.rs` | — | `GlobalReceipt`, `LocalReceipt`, `ExecutionOutput` |
| `crates/types/src/hash.rs` | 497 | `Hash` type, merkle tree primitives |
| `crates/types/src/crypto.rs` | 487 | BLS12-381 keys, signatures |
| `crates/types/src/receipt.rs` | 452 | `ReceiptBundle`, `LocalReceipt` |
| `crates/types/src/epoch.rs` | 426 | Epoch transition types |
| `crates/types/src/signing.rs` | 354 | Domain-separated signing messages |
| `crates/types/src/wave_certificate.rs` | 339 | `WaveCertificate` — cross-shard execution proof |
| `crates/types/src/state.rs` | 280 | `StateEntry`, `StateProvision` |
| `crates/types/src/identifiers.rs` | 275 | `ValidatorId`, `ShardGroupId`, `BlockHeight`, `NodeId` |
| `crates/types/src/lib.rs` | 246 | Re-exports |
| `crates/types/src/proofs.rs` | 227 | `TransactionInclusionProof`, merkle proof types |
| `crates/types/src/quorum_certificate.rs` | 152 | `QuorumCertificate` |
| `crates/types/src/signer_bitfield.rs` | 150 | Compact validator set representation |
| `crates/types/src/network.rs` | 133 | Network definitions |
| `crates/types/src/validator.rs` | 120 | Validator info |
| `crates/types/src/finalized_wave.rs` | 45 | `FinalizedWave` — wave cert + receipts + DB updates |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `RoutableTransaction` | `transaction.rs:13` | `UserTransaction` + `declared_reads` + `declared_writes` + cached hash/bytes |
| `Block` | `block.rs` | Header + transactions + certificates + abort intents |
| `BlockHeader` | `block.rs` | Consensus metadata (height, round, parent_qc, proposer, roots) |
| `WaveId` | `execution_vote.rs:30` | Globally unique: shard_group_id + block_height + sorted remote_shards |
| `ExecutionVote` | `execution_vote.rs` | Validator vote on wave execution result (BLS signed) |
| `WaveCertificate` | `wave_certificate.rs` | Aggregated execution proof for a wave across all participating shards |
| `QuorumCertificate` | `quorum_certificate.rs` | Aggregated BLS from 2f+1 validators for a block |

### Notable Patterns

- **Wave assignment** (`execution_vote.rs:1-16`): Transactions partitioned into waves by provision dependency set. Wave-ZERO = single-shard. Wave-{B} = needs shard B. Wave-{B,C} = needs B and C. Stable partition preserves block order.
- **Cached hash/bytes** (`transaction.rs:24-30`): `RoutableTransaction` caches hash and serialized bytes via `OnceLock` to avoid redundant computation.

---

## Production Runner (~1,894 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/production/src/runner.rs` | 852 | `ProductionRunner` builder, thread/channel setup |
| `crates/production/src/event_loop.rs` | 326 | Pinned event loop, `ProdTimerManager`, channel priority |
| `crates/production/src/telemetry.rs` | 593 | Prometheus metrics, telemetry collection |
| `crates/production/src/lib.rs` | 83 | Module structure |
| `crates/production/src/status.rs` | 40 | Node status types |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `ProductionRunner` | `runner.rs` | Builder pattern for assembling production node |
| `ProdIoLoop` | `event_loop.rs:36` | Concrete `IoLoop<SharedStorage, Libp2pNetwork, PooledDispatch>` |
| `PinnedLoopConfig` | `event_loop.rs:39` | Config for pinned thread (3 channel receivers + shutdown) |
| `ProdTimerManager` | `event_loop.rs:68` | Tokio-based timer management (spawn sleep -> crossbeam send) |

### Thread Architecture (`runner.rs:1-42`)

```
Core 0 (pinned std::thread)
  IoLoop — state machine, storage I/O, action handling, batching

Tokio runtime (multi-threaded)
  - Libp2p adapter (gossipsub, streams) -> crossbeam
  - InboundRouter (peer fetch requests)
  - RPC server -> crossbeam
  - ProdTimerManager (tokio sleep -> crossbeam timer events)
  - Metrics collection loop
```

### Channel Priority (`event_loop.rs:1-12`)

```
timer_rx     (priority 1)  >  callback_rx  (priority 2)  >  consensus_rx  (priority 3)
```

Cascading `try_recv`: timers always drained first, then crypto/execution callbacks, then network consensus messages. Falls back to `crossbeam::select!` with batch deadline timeout when nothing is ready.

### Notable Patterns

- **ProdTimerManager** (`event_loop.rs:68-107`, `process_op()`): Spawns `tokio::time::sleep` tasks that send `NodeInput` events into crossbeam channels. Cancels previous timer with same `TimerId` via `JoinHandle::abort()`.
- **Builder pattern** (`runner.rs:200-300`): `ProductionRunner` uses builder with required fields (topology, signing_key, bft_config, storage, network) and optional fields (dispatch, channel_capacity, mempool_config).

---

## Execution (~2,840 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/execution/src/state.rs` | 2,250 | `ExecutionState` — wave tracking, voting, finalization |
| `crates/execution/src/accumulator.rs` | 405 | `ExecutionAccumulator` — per-wave tx result collection |
| `crates/execution/src/handlers.rs` | 162 | Pure execution handler functions |
| `crates/execution/src/lib.rs` | 23 | Module structure, re-exports |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `ExecutionState` | `state.rs:110` | Core execution state machine |
| `CompletionData` | `state.rs:52` | Wave completion output (block_hash, wave_id, global_receipt_root) |
| `CrossShardRegistration` | `state.rs:70` | Registration for provision tracking (tx_hash, required_shards) |
| `BlockCommittedOutput` | `state.rs:84` | Output from `on_block_committed()` (actions + registrations) |
| `ExecutionMemoryStats` | `state.rs:96` | Collection size monitoring |
| `ExecutionAccumulator` | `accumulator.rs` | Per-wave tx result aggregation |

### Core State Fields (`ExecutionState`, `state.rs:110-199`)

| Field | Type | Purpose |
|-------|------|---------|
| `receipt_cache` | `HashMap<Hash, ReceiptBundle>` | In-memory receipts until finalized into `FinalizedWave` |
| `finalized_wave_certificates` | `BTreeMap<WaveId, FinalizedWave>` | Finalized waves ready for block inclusion |
| `committed_height` | `u64` | Current committed height for pruning |
| `pending_provisioning` | `HashMap<Hash, (Arc<RoutableTransaction>, u64)>` | Cross-shard txs waiting for provisions |
| `accumulators` | `HashMap<WaveId, ExecutionAccumulator>` | Per-wave tx result collection |
| `vote_trackers` | `HashMap<WaveId, VoteTracker>` | Execution vote aggregation (wave leader only) |
| `waves_with_ec` | `HashSet<WaveId>` | Waves that have a canonical EC (prevents re-voting) |
| `wave_assignments` | `HashMap<Hash, WaveId>` | tx_hash -> WaveId lookup for current block |
| `early_votes` | `HashMap<WaveId, Vec<ExecutionVote>>` | Votes arriving before tracking starts |
| `wave_certificate_trackers` | `HashMap<WaveId, WaveCertificateTracker>` | Wave-level finalization |
| `expected_exec_certs` | `HashMap<(ShardGroupId, u64, WaveId), ExpectedExecCert>` | Fallback detection for missing ECs |

### Event Flow

```
on_block_committed()               -> setup_execution_tracking(), partition single/cross-shard,
                                      emit ExecuteTransactions / ExecuteCrossShardTransactions
on_execution_batch_completed()     -> cache receipts, check pending_wave_receipts, record outcomes
on_execution_vote()                -> route to vote tracker (wave leader) or buffer early
on_votes_verified()                -> check quorum, aggregate EC
on_certificate_aggregated()        -> broadcast EC, finalize wave
on_wave_certificate()              -> handle incoming EC from remote shard
emit_vote_actions()                -> scan complete waves, emit votes (SINGLE path to voting)
```

### Notable Patterns

- **Single voting path** (`state.rs:1291-1400`, `on_block_committed()` calls `emit_vote_actions()`): All execution votes are emitted during the block commit wave scan, not from `on_execution_batch_completed()`. This ensures deterministic vote emission at each height.
- **Receipt lifecycle**: `receipt_cache` -> `FinalizedWave.receipts` -> atomic block commit. No eager storage writes.
- **5-phase cross-shard protocol** (`state.rs:1-32`): Provisioning -> Verification -> Execution -> Vote Aggregation -> Finalization.

---

## Mempool (~2,167 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/mempool/src/state.rs` | 2,147 | `MempoolState` — pool, ready set, lock contention, backpressure |
| `crates/mempool/src/lib.rs` | 20 | Module structure |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `MempoolState` | `state.rs:178` | Transaction pool with incremental ready set |
| `PoolEntry` | `state.rs` | Per-tx state (status, timestamps, cross_shard flag) |
| `ReadyEntry` | `state.rs` | Ready set entry (tx ref, added_at) |
| `LockContentionStats` | `state.rs` | O(1) stats: locked_nodes, pending, deferred, committed, executed |
| `MempoolConfig` | `state.rs` | Config: max_in_flight, min_dwell_time, pool limits |

### Core State Fields (`MempoolState`, `state.rs:178-249`)

| Field | Type | Purpose |
|-------|------|---------|
| `pool` | `BTreeMap<Hash, PoolEntry>` | All transactions, hash-ordered |
| `tombstones` | `HashMap<Hash, BlockHeight>` | Terminal-state tx hashes (prevents re-add via gossip) |
| `recently_evicted` | `HashMap<Hash, (Arc<RoutableTransaction>, BlockHeight)>` | Evicted txs retained for peer fetch |
| `locked_nodes_cache` | `HashSet<NodeId>` | Incrementally maintained locked nodes |
| `committed_count` / `executed_count` | `usize` | Cached counters for O(1) in_flight |
| `ready` | `BTreeMap<Hash, ReadyEntry>` | Ready txs (no lock conflicts), hash-ordered |
| `deferred_by_nodes` | `HashMap<Hash, HashSet<NodeId>>` | Txs blocked by locked nodes |
| `txs_deferred_by_node` | `HashMap<NodeId, HashSet<Hash>>` | Reverse index: node -> blocked txs |
| `ready_txs_by_node` | `HashMap<NodeId, HashSet<Hash>>` | Reverse index: node -> ready txs |
| `in_flight_by_height` | `BTreeMap<BlockHeight, Vec<Hash>>` | Height-indexed in-flight for timeout scan |
| `committed_abort_intent_hashes` | `HashSet<Hash>` | Dedup committed abort intents |

### Notable Patterns

- **Incremental ready set** (`state.rs:170-177`): Ready set maintained incrementally on every status change. `ready_transactions()` (`state.rs:1114-1154`) is O(ready_set_size) iteration, not O(pool_size) scan.
- **Backpressure** (`state.rs:1121-1129`): `ready_transactions()` returns empty if `effective_in_flight >= max_in_flight`. Effective in-flight accounts for pending commit txs and certs.
- **Min dwell time** (`state.rs:1147-1149`): Transactions must wait `min_dwell_time` in pool before being proposed, allowing gossip propagation.
- **Lock contention** (`state.rs:1166-1181`, `lock_contention_stats()`): All O(1) via cached counters.

---

## Engine (~2,164 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/engine/src/execution.rs` | 603 | Execution output types, provisioned snapshot |
| `crates/engine/src/executor.rs` | 378 | `RadixExecutor` — Radix Engine integration |
| `crates/engine/src/sharding.rs` | 355 | Shard routing, node-to-shard mapping |
| `crates/engine/src/validation.rs` | 281 | Transaction validation |
| `crates/engine/src/genesis.rs` | 187 | Genesis bootstrapping |
| `crates/engine/src/result.rs` | 124 | Execution result types |
| `crates/engine/src/handlers.rs` | 90 | Pure handler functions |
| `crates/engine/src/traits.rs` | 73 | Storage trait definitions |
| `crates/engine/src/lib.rs` | 50 | Module structure |
| `crates/engine/src/error.rs` | 23 | Error types |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `RadixExecutor` | `executor.rs:130` | Stateless executor with cached VM modules and config |
| `ExecutorCaches` | `executor.rs` | Shared `VmModules`, `ExecutionConfig`, `TransactionValidator` |
| `ExecutionOutput` | `execution.rs` | Results from execution (per-tx results) |
| `ProvisionedSnapshot` | `execution.rs` | Layered storage: provisions on top of local state |

### Core Methods (`RadixExecutor`, `executor.rs:136-250`)

| Method | Line | Purpose |
|--------|------|---------|
| `new()` | 141 | Create executor with cached VM modules, exec config, validator |
| `run_genesis()` | 159 | Initialize Radix Engine state (system packages, faucet) |
| `execute_single_shard()` | 191 | Execute local-only txs against storage snapshot |
| `execute_cross_shard()` | 229 | Execute with `ProvisionedSnapshot` (provisions overlaid on local state) |

### CRITICAL GOTCHA

**Engine is READ-ONLY.** `execute_single_shard()` and `execute_cross_shard()` do **NOT** commit writes to storage. Writes are returned in `ExecutionOutput` and committed later when the `WaveCertificate` is included in a committed block. See `executor.rs:183-186` and `executor.rs:214-217`:

> "This method does NOT commit state changes. The writes are returned in the ExecutionOutput
> and should be committed later when the WaveCertificate is included in a committed block."

The executor is stateless (no mutable fields beyond caches). Storage is passed by reference to each method call.

---

## Livelock (~1,472 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/livelock/src/state.rs` | 1,113 | `LivelockState` — cycle detection, abort intents, tombstones |
| `crates/livelock/src/tracker.rs` | 321 | `CommittedCrossShardTracker`, `ProvisionTracker` |
| `crates/livelock/src/lib.rs` | 38 | Module structure, re-exports |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `LivelockState` | `state.rs:64` | Core livelock prevention state machine |
| `LivelockConfig` | `state.rs` | Timeouts and thresholds |
| `CommittedCrossShardTracker` | `tracker.rs` | Tracks committed cross-shard TXs and their required shards |
| `ProvisionTracker` | `tracker.rs` | Tracks (tx_hash, source_shard) provision arrivals |
| `LivelockOutput` | `state.rs` | Output enum: `FetchInclusionProof` |
| `RemoteStateNeeds` | `state.rs` | Remote shards + nodes a TX needs provisions from |

### Core State Fields (`LivelockState`, `state.rs:64-93`)

| Field | Type | Purpose |
|-------|------|---------|
| `committed_tracker` | `CommittedCrossShardTracker` | Committed cross-shard TXs and their shard needs |
| `provision_tracker` | `ProvisionTracker` | (tx_hash, source_shard) dedup for cycle detection |
| `tombstones` | `HashMap<Hash, Duration>` | Completed TXs (discard late provisions) |
| `pending_proof_fetches` | `HashSet<Hash>` | In-flight inclusion proof requests |
| `pending_abort_intents` | `Vec<AbortIntent>` | Abort intents ready for block proposal |
| `pending_abort_intent_hashes` | `HashSet<Hash>` | Dedup for pending abort intents |

### Cycle Detection Flow

```
on_block_committed()           -> register cross-shard TXs with committed_tracker
on_provision_accepted()        -> check for bidirectional cycle with local TXs
  -> check_for_cycle()         -> if cycle: FetchInclusionProof output
on_provisions_accepted_actions() -> group by (source_shard, height), emit RequestTxInclusionProofs
on_inclusion_proof_received()  -> create AbortIntent (deferral), queue for proposal
on_certificate_committed()     -> add tombstone, clean up tracking
```

### Notable Patterns

- **Verified provisions only** (`state.rs:175-184`, `on_provision_accepted()`): Cycle detection only processes provisions that passed QC + merkle proof verification. Prevents Byzantine validators from triggering false deferrals.
- **Tombstone guard** (`state.rs:206-212`): Late-arriving provisions for tombstoned TXs are silently discarded.
- **Dedup** (`state.rs:215-216`): `provision_tracker.add()` returns false if (tx_hash, source_shard) already processed.

---

## Provisions (~1,532 LOC)

### Files

| File | Lines | Role |
|------|------:|------|
| `crates/provisions/src/state.rs` | 1,508 | `ProvisionCoordinator` — provision tracking, verification, joining |
| `crates/provisions/src/lib.rs` | 24 | Module structure, re-exports |

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `ProvisionCoordinator` | `state.rs:75` | Coordinates provision reception, verification, and joining |
| `TxRegistration` | `state.rs` | Registration info: required_shards, registered_at height |
| `ExpectedProvision` | `state.rs` | Expected but not-yet-received provision tracking |

### Core State Fields (`ProvisionCoordinator`, `state.rs:75-121`)

| Field | Type | Purpose |
|-------|------|---------|
| `registered_txs` | `HashMap<Hash, TxRegistration>` | Cross-shard TXs we're tracking |
| `verified_remote_headers` | `HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>` | QC-verified remote headers for proof verification |
| `pending_provisions` | `HashMap<(ShardGroupId, BlockHeight), Vec<ProvisionBatch>>` | Batches waiting for matching remote header |
| `verified_batches` | `BTreeMap<(ShardGroupId, BlockHeight), ProvisionBatch>` | Verified batches (post proof check) |
| `expected_provisions` | `BTreeMap<(ShardGroupId, BlockHeight), ExpectedProvision>` | Timeout tracking for missing provisions |
| `local_committed_height` | `BlockHeight` | For pruning stale entries |

### Event Flow

```
on_tx_registered()             -> register cross-shard TX with required shards
on_verified_remote_header()    -> store header, join with pending provisions -> verify
on_state_provisions_received() -> buffer or join with existing header -> verify
on_state_provisions_verified() -> store verified batch, emit ProvisionsAccepted
on_block_committed()           -> check timeouts, prune stale entries
on_certificate_committed()     -> clean up terminal TX state
```

### Notable Patterns

- **Header-batch join**: Provisions and remote headers can arrive in any order. `ProvisionCoordinator` holds whichever arrives first and joins when the counterpart arrives.
- **Proof verification**: Batches are verified against the committed state root from the QC-verified remote header (merkle inclusion proofs).
