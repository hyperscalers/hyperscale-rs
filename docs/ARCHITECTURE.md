# hyperscale-rs Architecture

> Stability: **Layer 2 (Stable)**

Deterministic BFT consensus built on HotStuff-2. Sync state machine produces
actions; async runner executes them. Trait-based backends swap between
production (libp2p, RocksDB, Rayon) and simulation (in-memory, single-thread).

---

## 1. Crate Dependency Graph

28 crates organized by layer. Arrows point upward (depended-upon).

```
APPLICATION
  +---------------------+   +---------------------+
  | hyperscale-simulator |   | hyperscale-spammer  |
  +---------------------+   +---------------------+
              |                        |
COMPOSITION   |                        |
  +-----------v------------------------v----------+
  | hyperscale-simulation    hyperscale-production |
  +--+--------------------+--------------------+--+
     |                    |                    |
     v                    v                    v
RUNNER / NODE
  +---------------------------------------------------+
  |              hyperscale-node                       |
  |  (IoLoop, NodeStateMachine, ActionHandler, Config) |
  +--+------+------+------+------+------+------+------+
     |      |      |      |      |      |      |
     v      v      v      v      v      v      v
SUBSYSTEM STATE
  +-----+ +-----+ +-------+ +----------+ +--------+ +-------+
  | bft | | exec| | mempl | | provisns | | remote | | livel |
  |     | |ution| |  ool  | |          | | headers| |  ock  |
  +--+--+ +--+--+ +---+---+ +----+-----+ +---+----+ +---+---+
     |      |      |        |          |          |
     v      v      v        v          v          v
ABSTRACTION
  +---------+ +---------+ +---------+ +---------+
  | storage | | network | |dispatch | | metrics |
  | (traits)| | (traits)| | (trait) | | (trait) |
  +---------+ +---------+ +---------+ +---------+
     |   |        |  |        |  |        |  |
     v   v        v  v        v  v        v  v
IMPLEMENTATION
  +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
  |storage| |storage| |network| |network| |dispatc| |dispatc|
  |rocksdb| |memory | |libp2p | |memory | |pooled | |sync   |
  +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
                                    |
TYPES                               |
  +----------+ +----------+ +------v----+ +----------+
  | types    | | messages | | topology  | | engine   |
  +----------+ +----------+ +-----------+ +----------+
  | test-helpers |   | metrics-prometheus |
  +--------------+   +--------------------+
```

### Full crate list

| Crate                         | Role                                 |
|-------------------------------|--------------------------------------|
| `hyperscale-bft`              | BFT consensus state (HotStuff-2)     |
| `hyperscale-core`             | `StateMachine` trait, `Action`, `ProtocolEvent` |
| `hyperscale-dispatch`         | `Dispatch` trait                      |
| `hyperscale-dispatch-pooled`  | Rayon-backed multi-pool dispatch      |
| `hyperscale-dispatch-sync`    | Single-thread dispatch (simulation)  |
| `hyperscale-engine`           | Radix Engine integration             |
| `hyperscale-execution`        | Execution state + wave voting        |
| `hyperscale-livelock`         | Cross-shard livelock prevention      |
| `hyperscale-mempool`          | Transaction mempool state            |
| `hyperscale-messages`         | Network message types (SBOR)         |
| `hyperscale-metrics`          | Metrics trait                        |
| `hyperscale-metrics-prometheus` | Prometheus metrics impl            |
| `hyperscale-network`          | `Network` trait                      |
| `hyperscale-network-libp2p`   | libp2p gossipsub + req/resp impl     |
| `hyperscale-network-memory`   | In-memory network (simulation)       |
| `hyperscale-node`             | `IoLoop`, `NodeStateMachine`, wiring |
| `hyperscale-production`       | Production runner (async, tokio)      |
| `hyperscale-provisions`       | Cross-shard provision coordination   |
| `hyperscale-remote-headers`   | Remote block header coordination     |
| `hyperscale-simulation`       | Deterministic simulation runner      |
| `hyperscale-simulator`        | Simulation harness CLI               |
| `hyperscale-spammer`          | Load generation tool                 |
| `hyperscale-storage`          | Storage traits                       |
| `hyperscale-storage-memory`   | In-memory storage (simulation)       |
| `hyperscale-storage-rocksdb`  | RocksDB storage (production)         |
| `hyperscale-test-helpers`     | Shared test utilities                |
| `hyperscale-topology`         | Shard/validator topology             |
| `hyperscale-types`            | Core domain types                    |

---

## 2. The NodeStateMachine Pattern

The state machine is **synchronous**, **deterministic**, and **pure** (no I/O).
All consensus logic lives here. The runner feeds events, collects actions.

### StateMachine trait

`crates/core/src/traits.rs:34-70`

```rust
pub trait StateMachine {
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action>;
    fn set_time(&mut self, now: Duration);
    fn now(&self) -> Duration;
}
```

**Guarantees**: `handle()` never blocks, never awaits, never performs I/O.
Given identical state + event, always returns identical actions.

### NodeStateMachine struct fields

`crates/node/src/state.rs:33-59`

| Field             | Type                     | Purpose                               |
|-------------------|--------------------------|---------------------------------------|
| `node_index`      | `NodeIndex`              | Simulation routing index              |
| `topology`        | `TopologyState`          | Network topology (shard assignments)  |
| `bft`             | `BftState`               | HotStuff-2 consensus state            |
| `execution`       | `ExecutionState`         | Wave execution + voting               |
| `mempool`         | `MempoolState`           | Transaction pool                      |
| `provisions`      | `ProvisionCoordinator`   | Cross-shard provision coordination     |
| `remote_headers`  | `RemoteHeaderCoordinator`| Remote committed header tracking      |
| `livelock`        | `LivelockState`          | Cross-shard cycle detection           |
| `now`             | `Duration`               | Logical clock                         |

### Action enum

`crates/core/src/action.rs` -- **49 variants** covering:

- Network sends (broadcast headers, votes, certs, provisions, gossip)
- Timer ops (set/cancel)
- Crypto verification (QC, state root, tx root, cert root, receipt root, abort proofs)
- Execution (single-shard, cross-shard)
- Block commit (normal, synced)
- Sync/fetch protocol triggers
- Epoch/topology operations (not yet implemented)

### ProtocolEvent enum

`crates/core/src/protocol_event.rs` -- **41 variants** organized into:

- Timers (3): `ProposalTimer`, `CleanupTimer`, `GlobalConsensusTimer`
- BFT Consensus (12): header/vote/QC/commit/verification events
- Provisions (4): receive/verify/accept/complete
- Execution (5): batch complete, vote, cert aggregation/verification
- Transactions (4): gossip, executed, wave complete, fetch
- Sync (4): block ready, EC verify, complete, metadata
- Global/Epoch (12): not yet implemented, all return `vec![]`

---

## 3. The IoLoop / Runner Pattern

```
  External world (network, timers, RPC)
           |
           v
  +------------------+
  | NodeInput        |  (enum: Protocol(ProtocolEvent) | SubmitTransaction |
  | (crossbeam chan) |   SyncBlockResponse | FetchResult | ...)
  +--------+---------+
           |
           v
  +------------------+
  |     IoLoop       |  crates/node/src/io_loop/mod.rs:182-284
  |                  |
  |  step(input)     |  Intercepts I/O concerns:
  |    |             |  - tx validation batching
  |    | translate   |  - sync protocol
  |    v             |  - fetch protocols (tx, provision, header, EC)
  |  feed_event(pe)  |  - committed header verification
  |    |             |
  |    v             |
  |  state.handle()  |  Pure state machine call
  |    |             |
  |    v             |
  |  Vec<Action>     |
  |    |             |
  |    v             |
  |  process_action()|  Routes each action to:
  |  for action in   |  - network sends
  |    actions       |  - timer ops
  |    |             |  - dispatch pool spawns
  |    v             |  - block commit accumulation
  |  flush_commits() |
  +--------+---------+
           |
           v
  +------------------+
  | Storage/Network/ |  Async I/O backends
  | Dispatch pools   |  Results feed back as NodeInput
  +------------------+
```

### feed_event

`crates/node/src/io_loop/mod.rs:897-903`

```rust
fn feed_event(&mut self, event: ProtocolEvent) {
    let actions = self.state.handle(event);
    self.actions_generated += actions.len();
    for action in actions {
        self.process_action(action);
    }
    self.flush_block_commits();
}
```

### IoLoop struct

`crates/node/src/io_loop/mod.rs:182` -- Generic over `S` (storage), `N` (network), `D` (dispatch).

Key fields:

| Field                     | Type                                 | Purpose                           |
|---------------------------|--------------------------------------|-----------------------------------|
| `state`                   | `NodeStateMachine`                   | The pure state machine            |
| `storage`                 | `Arc<S>`                             | Chain + substate storage          |
| `executor`                | `RadixExecutor`                      | Radix Engine instance             |
| `network`                 | `N`                                  | Message sending                   |
| `dispatch`                | `D`                                  | Thread pool scheduling            |
| `event_sender`            | `Sender<NodeInput>`                  | Self-send channel for callbacks   |
| `sync_protocol`           | `SyncProtocol`                       | Block sync state machine          |
| `transaction_fetch_protocol` | `TransactionFetchProtocol`        | Chunked tx fetch with retry       |
| `provision_fetch_protocol`| `ProvisionFetchProtocol`             | Cross-shard provision fetch       |
| `exec_cert_fetch_protocol`| `ExecCertFetchProtocol`              | Cross-shard EC fetch              |
| `header_fetch_protocol`   | `HeaderFetchProtocol`                | Cross-shard header fetch          |
| `validation_batch`        | `BatchAccumulator<Arc<RoutableTransaction>>` | Tx validation batching    |
| `committed_header_batch`  | `BatchAccumulator<...>`              | Header BLS verification batching  |
| `pending_block_commits`   | `Vec<PendingCommit>`                 | Commit accumulator per step       |
| `commit_in_flight`        | `Arc<AtomicBool>`                    | Guards commit ordering            |
| `tx_status_cache`         | `Arc<QuickCache<Hash, TxStatus>>`    | Shared with RPC handlers          |
| `prepared_commits`        | `Arc<Mutex<HashMap<...>>>`           | Speculative state root cache      |

---

## 4. How Subsystems Compose in Node

`crates/node/src/state.rs:552-818` -- `StateMachine::handle()` is a single
`match` over all 41 `ProtocolEvent` variants, routing to subsystem methods:

```
ProtocolEvent variant         -->  Subsystem method
----------------------------------------------------------------------
ProposalTimer                 -->  self.on_proposal_timer()
CleanupTimer                  -->  self.on_cleanup_timer()
BlockHeaderReceived           -->  self.on_block_header_received()
BlockVoteReceived             -->  self.bft.on_block_vote()
QuorumCertificateFormed       -->  self.on_qc_formed()
BlockReadyToCommit            -->  self.bft.on_block_ready_to_commit()
QuorumCertificateResult       -->  self.bft.on_qc_result()
QcSignatureVerified           -->  self.bft.on_qc_signature_verified()
RemoteBlockCommitted          -->  self.remote_headers.on_remote_block_committed()
RemoteHeaderQcVerified        -->  self.bft.on_verified_remote_header() +
                                   self.remote_headers.on_remote_header_qc_verified()
RemoteHeaderVerified          -->  self.execution.on_verified_remote_header() +
                                   self.provisions.on_verified_remote_header()
BlockRootVerified             -->  self.bft.on_block_root_verified()
ProposalBuilt                 -->  self.bft.on_proposal_built()
BlockCommitted                -->  self.on_state_commit_complete() +
                                   self.on_block_committed()
StateProvisionsReceived       -->  self.provisions.on_state_provisions_received()
StateProvisionsVerified       -->  self.provisions.on_state_provisions_verified()
ProvisionsAccepted            -->  self.livelock.on_provisions_accepted_actions()
ProvisioningComplete          -->  self.execution.on_batch_provisioning_complete()
ExecutionBatchCompleted       -->  self.execution.on_execution_batch_completed()
ExecutionVoteReceived         -->  self.execution.on_execution_vote()
ExecutionVotesVerifiedAndAgg  -->  self.execution.on_votes_verified()
ExecutionCertificateAggregated -> self.execution.on_certificate_aggregated()
ExecutionCertificateReceived  -->  self.execution.on_wave_certificate()
ExecutionCertSignatureVerified -> self.execution.on_certificate_verified()
TransactionExecuted           -->  self.on_transaction_executed()
TransactionGossipReceived     -->  self.on_transaction_gossip_received()
TransactionFetchDelivered     -->  self.bft.on_transaction_fetch_received()
SyncBlockReadyToApply         -->  self.bft.on_sync_block_ready_to_apply()
SyncComplete                  -->  self.on_sync_complete()
ChainMetadataFetched          -->  self.bft.on_chain_metadata_fetched()
Global*/Epoch*/Shard*         -->  vec![]  (not yet implemented)
```

After the main match, `drain_ready_state_root_verifications()` emits any
`Action::VerifyStateRoot` that became unblocked during this event.

---

## 5. Action Dispatch to Thread Pools

`crates/node/src/action_handler.rs:36-79`

Actions map to one of four `DispatchPool` variants, or `None` (handled inline by IoLoop).

| Action                                 | Pool                |
|----------------------------------------|---------------------|
| `VerifyAndBuildQuorumCertificate`      | `ConsensusCrypto`   |
| `VerifyQcSignature`                    | `ConsensusCrypto`   |
| `VerifyRemoteHeaderQc`                 | `ConsensusCrypto`   |
| `VerifyStateRoot`                      | `ConsensusCrypto`   |
| `VerifyTransactionRoot`               | `ConsensusCrypto`   |
| `VerifyCertificateRoot`               | `ConsensusCrypto`   |
| `VerifyLocalReceiptRoot`              | `ConsensusCrypto`   |
| `VerifyAbortIntentProofs`             | `ConsensusCrypto`   |
| `BuildProposal`                        | `ConsensusCrypto`   |
| `AggregateExecutionCertificate`        | `Crypto`            |
| `VerifyAndAggregateExecutionVotes`     | `Crypto`            |
| `VerifyExecutionCertificateSignature`  | `Crypto`            |
| `VerifyProvisionBatch`                | `Provisions`        |
| `FetchAndBroadcastProvisions`          | `Provisions`        |
| `ExecuteTransactions`                  | `Execution`         |
| `ExecuteCrossShardTransactions`        | `Execution`         |
| All others (network, timers, commits)  | `None` (inline)     |

### DispatchPool enum

`crates/node/src/action_handler.rs:36-49`

| Pool              | Priority  | Work type                              |
|-------------------|-----------|----------------------------------------|
| `ConsensusCrypto` | Highest   | QC, state root, proposal -- liveness   |
| `Crypto`          | Normal    | Cert aggregation, EC votes             |
| `Execution`       | Normal    | Radix Engine execution, merkle         |
| `Provisions`      | Normal    | IPA proof gen/verify -- isolated       |

### Dispatch trait

`crates/dispatch/src/lib.rs:26-72`

Methods: `spawn_consensus_crypto()`, `spawn_crypto()`, `try_spawn_crypto()`,
`spawn_tx_validation()`, `spawn_execution()`, `spawn_provisions()`, plus
queue depth queries for each pool.

---

## 6. Trait-Based Backend Swapping

Three abstraction traits enable swapping all I/O between production and simulation.

### Storage traits

| Trait          | File                              | Key methods                                             |
|----------------|-----------------------------------|---------------------------------------------------------|
| `SubstateStore`| `crates/storage/src/store.rs:20`  | `snapshot()`, `jvt_version()`, `state_root_hash()`, `list_substates_for_node_at_height()`, `generate_verkle_proofs()` |
| `ChainReader`  | `crates/storage/src/chain_reader.rs:20` | `get_block()`, `committed_height()`, `latest_qc()`, `get_block_for_sync()`, `get_transactions_batch()`, `get_local_receipt()`, `get_execution_certificates_by_height()` |
| `ChainWriter`  | `crates/storage/src/chain_writer.rs:21` | `prepare_block_commit()`, `commit_prepared_block()`, `commit_block()` |

### Network trait

`crates/network/src/traits.rs:120-201`

Methods: `broadcast_to_shard()`, `broadcast_global()`, `register_gossip_handler()`,
`register_request_handler()`, `notify()`, `register_notification_handler()`,
`update_validator_keys()`, `request()`.

### Implementation matrix

| Trait          | Production                 | Simulation                |
|----------------|----------------------------|---------------------------|
| `SubstateStore + ChainReader + ChainWriter` | `hyperscale-storage-rocksdb` (RocksDB + JVT) | `hyperscale-storage-memory` (in-memory JVT) |
| `Network`      | `hyperscale-network-libp2p` (gossipsub + req/resp) | `hyperscale-network-memory` (channel-based) |
| `Dispatch`     | `hyperscale-dispatch-pooled` (4 Rayon pools) | `hyperscale-dispatch-sync` (inline, single-thread) |

The `IoLoop<S, N, D>` is generic over all three. Production and simulation
crates each instantiate it with their concrete types.

---

## 7. Batching Strategy

`crates/node/src/batch_accumulator.rs:17-71`

`BatchAccumulator<T>` collects items until **count threshold** OR **time window**
expires, whichever comes first. Tracks deadlines as logical `Duration` so both
wall-clock (production) and logical clock (simulation) use the same code path.

```
push(item, now) --> count >= max_count? --> flush
                \-> deadline expired?   --> flush (checked externally)
```

### Default batch config

`crates/node/src/config.rs:51-69`

| Batch                  | Max Count | Window   |
|------------------------|-----------|----------|
| Execution votes        | 64        | 20 ms    |
| Broadcast votes        | 64        | 15 ms    |
| Broadcast certs        | 64        | 15 ms    |
| Tx validation          | 512       | 50 ms    |
| Committed headers      | 32        | 15 ms    |

`ShardedBatchAccumulator<T>` extends the pattern to group items by
`ShardGroupId`, flushing when total count across all shards hits the threshold.

### Weighted push

`push_weighted(item, weight, now)` allows logical count to differ from
`items.len()` -- used when batching grouped vote items where each item
contains multiple individual votes.
