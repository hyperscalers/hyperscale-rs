# Implementation Details

> Stability: **Layer 4 (Active Churn)** -- structures, bounds, and defaults change frequently.

Engine integration is **read-only**; Radix Engine executes but does not own storage layout.

---

## 1. Data Structures and Bounds

### BftState (`crates/bft/src/state.rs:109`)

| Field | Type | Bounded | Location |
|---|---|---|---|
| `pending_blocks` | `HashMap<Hash, PendingBlock>` | **No** | state.rs:151 |
| `vote_sets` | `HashMap<Hash, VoteSet>` | **No** | state.rs:157 |
| `voted_heights` | `HashMap<u64, (Hash, u64)>` | **No** | state.rs:167 |
| `received_votes_by_height` | `HashMap<(u64, ValidatorId), (Hash, u64)>` | **No** | state.rs:180 |
| `certified_blocks` | `HashMap<Hash, Block>` | **No** | state.rs:184 |
| `pending_commits` | `BTreeMap<u64, (Hash, QuorumCertificate)>` | **No** | state.rs:197 |
| `pending_commits_awaiting_data` | `HashMap<Hash, (u64, QuorumCertificate)>` | **No** | state.rs:203 |
| `committed_tx_lookup` | `HashMap<Hash, BlockHeight>` | **No** | state.rs:211 |
| `recently_committed_txs` | `HashSet<Hash>` | **No** | state.rs:217 |
| `recently_committed_certs` | `HashSet<Hash>` | **No** | state.rs:218 |
| `recently_committed_abort_intents` | `HashSet<Hash>` | **No** | state.rs:219 |
| `remote_headers` | `HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>` | **No** | state.rs:223 |
| `remote_header_tips` | `HashMap<ShardGroupId, BlockHeight>` | Bounded by shard count | state.rs:226 |

> **Issue #22**: Every `HashMap`/`BTreeMap` above (except `remote_header_tips`) grows without cap under adversarial load. A Byzantine proposer can inflate `pending_blocks`, `vote_sets`, and `remote_headers` by sending valid-looking but never-committed headers. `committed_tx_lookup` grows monotonically with chain length.

### MempoolState (`crates/mempool/src/state.rs:178`)

| Field | Type | Bounded | Location |
|---|---|---|---|
| `pool` | `BTreeMap<Hash, PoolEntry>` | Soft (`max_pending=8192`) | state.rs:180 |
| `tombstones` | `HashMap<Hash, BlockHeight>` | Pruned after 500 blocks | state.rs:185 |
| `recently_evicted` | `HashMap<Hash, (Arc<RoutableTransaction>, BlockHeight)>` | Pruned after 50 blocks | state.rs:191 |
| `locked_nodes_cache` | `HashSet<NodeId>` | Bounded by `max_in_flight` | state.rs:197 |
| `ready` | `BTreeMap<Hash, ReadyEntry>` | Subset of `pool` | state.rs:217 |
| `deferred_by_nodes` | `HashMap<Hash, HashSet<NodeId>>` | Subset of `pool` | state.rs:222 |
| `txs_deferred_by_node` | `HashMap<NodeId, HashSet<Hash>>` | Reverse index | state.rs:226 |
| `ready_txs_by_node` | `HashMap<NodeId, HashSet<Hash>>` | Reverse index | state.rs:230 |
| `in_flight_by_height` | `BTreeMap<BlockHeight, Vec<Hash>>` | **No** | state.rs:234 |
| `committed_abort_intent_hashes` | `HashSet<Hash>` | **No** | state.rs:239 |

> **Issue #22**: `pool` has soft backpressure via `max_pending` (rejects RPC above 8192) but gossip path in `on_transaction_gossip()` (state.rs:365) has **no size check** -- a peer can flood the pool. `in_flight_by_height` and `committed_abort_intent_hashes` grow unboundedly.

### ExecutionState (`crates/execution/src/state.rs:110`)

| Field | Type | Bounded | Location |
|---|---|---|---|
| `receipt_cache` | `HashMap<Hash, ReceiptBundle>` | **No** | state.rs:117 |
| `finalized_wave_certificates` | `BTreeMap<WaveId, FinalizedWave>` | **No** | state.rs:121 |
| `pending_provisioning` | `HashMap<Hash, (Arc<RoutableTransaction>, u64)>` | **No** | state.rs:132 |
| `accumulators` | `HashMap<WaveId, ExecutionAccumulator>` | **No** | state.rs:139 |
| `vote_trackers` | `HashMap<WaveId, VoteTracker>` | **No** | state.rs:143 |
| `waves_with_ec` | `HashSet<WaveId>` | **No** | state.rs:148 |
| `wave_assignments` | `HashMap<Hash, WaveId>` | **No** | state.rs:152 |
| `early_votes` | `HashMap<WaveId, Vec<ExecutionVote>>` | **No** | state.rs:156 |
| `early_provisioning_complete` | `HashMap<Hash, (Vec<StateProvision>, u64)>` | **No** | state.rs:175 |
| `early_wave_attestations` | `Vec<(Arc<ExecutionCertificate>, u64)>` | **No** | state.rs:181 |
| `pending_wave_receipts` | `HashMap<WaveId, HashSet<Hash>>` | **No** | state.rs:186 |
| `expected_exec_certs` | `HashMap<(ShardGroupId, u64, WaveId), ExpectedExecCert>` | **No** | state.rs:195 |
| `fulfilled_exec_certs` | `HashMap<(ShardGroupId, u64, WaveId), u64>` | **No** | state.rs:201 |

> **Issue #22**: All 13 maps are unbounded. `early_*` buffers are the highest risk -- a peer can send execution votes/provisions/attestations before the local node creates tracking, filling `early_votes`, `early_provisioning_complete`, and `early_wave_attestations` without limit.

### LivelockState (`crates/livelock/src/state.rs:64`)

| Field | Type | Bounded | Location |
|---|---|---|---|
| `tombstones` | `HashMap<Hash, Duration>` | **No** | state.rs:75 |
| `pending_proof_fetches` | `HashSet<Hash>` | **No** | state.rs:79 |
| `pending_abort_intents` | `Vec<AbortIntent>` | **No** | state.rs:83 |
| `pending_abort_intent_hashes` | `HashSet<Hash>` | **No** | state.rs:86 |

> **Issue #22**: `tombstones` keyed by `Duration` expiry but no periodic pruning visible in struct definition. `pending_abort_intents` grows with every detected livelock.

---

## 2. Configuration Parameters

### BftConfig (`crates/bft/src/config.rs:7`)

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `proposal_interval` | `Duration` | 1000ms | Interval between proposal attempts |
| `view_change_timeout` | `Duration` | 5s | Base timeout for view change |
| `view_change_timeout_increment` | `Duration` | 1000ms | Linear backoff per round at same height |
| `view_change_timeout_max` | `Option<Duration>` | 30s | Cap on linear backoff |
| `max_transactions_per_block` | `usize` | 4096 | Block tx limit |
| `max_certificates_per_block` | `usize` | 8192 | Block cert limit |
| `max_timestamp_delay_ms` | `u64` | 30000 | Max proposer clock lag (ms) |
| `max_timestamp_rush_ms` | `u64` | 2000 | Max proposer clock advance (ms) |
| `transaction_fetch_timeout` | `Duration` | 150ms | Fetch missing txs from peers |
| `certificate_fetch_timeout` | `Duration` | 500ms | Fetch missing certs from peers |
| `cleanup_interval` | `Duration` | 1s | Periodic housekeeping timer |
| `min_block_interval` | `Duration` | 500ms | Rate limit between successive blocks |
| `min_execution_timeout_blocks` | `u64` | 30 | Min blocks before execution timeout abort is valid |

### MempoolConfig (`crates/mempool/src/state.rs:53`)

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `max_in_flight` | `usize` | 12288 | Backpressure: max txs holding state locks |
| `max_pending` | `usize` | 8192 | RPC backpressure: reject above this |
| `min_dwell_time` | `Duration` | 150ms | Min time before block inclusion eligibility |

Constants (same file):

| Constant | Value | Location |
|---|---|---|
| `EXECUTION_TIMEOUT_BLOCKS` | 50 | state.rs:29 |
| `TOMBSTONE_RETENTION_BLOCKS` | 500 | state.rs:32 |
| `TRANSACTION_RETENTION_BLOCKS` | 50 | state.rs:23 |

### BatchConfig (`crates/node/src/config.rs:51`)

| Parameter | Default | Purpose |
|---|---|---|
| `execution_vote_max` / `_window` | 64 / 20ms | Batch execution votes |
| `broadcast_vote_max` / `_window` | 64 / 15ms | Batch broadcast votes |
| `broadcast_cert_max` / `_window` | 64 / 15ms | Batch broadcast certs |
| `tx_validation_max` / `_window` | 512 / 50ms | Batch tx validations |
| `committed_header_max` / `_window` | 32 / 15ms | Batch committed headers |

---

## 3. Storage Schema (RocksDB)

### Column Families (`crates/storage-rocksdb/src/column_families.rs:14-87`)

13 column families in `ALL_COLUMN_FAMILIES` (line 73):

| CF Constant | String Name | Key Format | Purpose |
|---|---|---|---|
| `DEFAULT_CF` | `"default"` | metadata keys | Chain metadata, JVT metadata |
| `BLOCKS_CF` | `"blocks"` | height (BE u64) | Block header + manifest |
| `TRANSACTIONS_CF` | `"transactions"` | tx hash | Transaction data |
| `STATE_CF` | `"state"` | storage key bytes | Current substate data |
| `CERTIFICATES_CF` | `"certificates"` | cert hash | Wave certificates |
| `VOTES_CF` | `"votes"` | height (BE u64) | BFT votes |
| `JVT_NODES_CF` | `"jmt_nodes"` | JVT node key | Jellyfish Verkle Tree nodes |
| `STALE_JVT_NODES_CF` | `"stale_jvt_nodes"` | version (BE u64) | Stale JVT nodes pending GC |
| `VERSIONED_SUBSTATES_CF` | `"versioned_substates"` | `storage_key ++ version_BE_8B` | MVCC versioned substates |
| `LOCAL_RECEIPTS_CF` | `"local_receipts"` | tx hash | Local execution receipts |
| `EXECUTION_OUTPUTS_CF` | `"execution_outputs"` | tx hash | Execution output details |
| `EXECUTION_CERTS_CF` | `"execution_certs"` | canonical hash | Execution certificates |
| `EXECUTION_CERTS_BY_HEIGHT_CF` | `"execution_certs_by_height"` | `height_BE_8B ++ hash_32B` | Height index for exec certs |

### Compression Strategy (line 66-70)

Hot-write CFs (`HOT_WRITE_COLUMN_FAMILIES`): `STATE_CF`, `JVT_NODES_CF`, `VERSIONED_SUBSTATES_CF` -- get larger write buffers and tiered compression.

### JVT Key Mapping

JVT node key format is from `jellyfish_verkle_tree`. CF string remains `"jmt_nodes"` for backward compatibility (line 36-37). Stale nodes use version as key; GC deletes entries older than `current_version - jvt_history_length`.

### Prepare-Commit Pattern (`crates/storage/src/chain_writer.rs:21-91`)

Two-phase block commit via `ChainWriter` trait:

1. **`prepare_block_commit()`** (line 37): Takes `parent_state_root` + `DatabaseUpdates` + `block_height`. Computes speculative JVT root. Returns `(state_root, PreparedCommit)`. For RocksDB, `PreparedCommit` contains a `WriteBatch` + `JvtSnapshot`.
2. **`commit_prepared_block()`** (line 54): Applies cached `WriteBatch`/`JvtSnapshot` directly. Falls back to per-certificate recompute if prepared data is stale.
3. **`commit_block()`** (line 69): From-scratch path (no `PreparedCommit`). Used for sync blocks and cache eviction.

Additional methods: `memory_usage_bytes()` (line 81) returns `(block_cache, memtable)` for RocksDB; `node_cache_len()` (line 88) returns JVT cache size.

### Read Traits

- **`SubstateStore`** (`crates/storage/src/store.rs:20`): Extends Radix `SubstateDatabase` with `snapshot()`, `jvt_version()`, `state_root_hash()`, `list_substates_for_node_at_height()`, `generate_verkle_proofs()`.
- **`ChainReader`** (`crates/storage/src/chain_reader.rs:20`): `get_block()`, `committed_height()`, `committed_hash()`, `latest_qc()`, `get_block_for_sync()`, `get_transactions_batch()`, `get_certificates_batch()`, `get_local_receipt()`, `get_execution_certificates_by_height()`, `get_wave_certificate_for_tx()`, `get_ec_hashes_for_tx()`.

---

## 4. Networking (libp2p)

### Topic Format (`crates/network/src/traits.rs:38-48`)

| Scope | Topic Format |
|---|---|
| `TopicScope::Shard` | `hyperscale/{type_id}/shard-{local}/1.0.0` |
| `TopicScope::Global` | `hyperscale/{type_id}/1.0.0` |

### Network Trait (`crates/network/src/traits.rs:120-202`)

| Method | Pattern | Purpose |
|---|---|---|
| `broadcast_to_shard()` | pub/sub | Shard-scoped gossipsub broadcast |
| `broadcast_global()` | pub/sub | All-peer gossipsub broadcast |
| `register_gossip_handler()` | registration | Typed handler + auto-subscribe |
| `register_request_handler()` | registration | Typed request/response handler |
| `notify()` | fire-and-forget | Unicast to specific validators |
| `register_notification_handler()` | registration | Inbound notification handler |
| `update_validator_keys()` | lifecycle | Epoch transition key update |
| `request()` | request/response | Typed request with callback, peer selection, retry |

Gossip validation returns `GossipVerdict` (`Accept`/`Reject`) (traits.rs:56).

### Request Manager (`crates/network-libp2p/src/request_manager/mod.rs:101-164`)

`RequestManagerConfig` defaults:

| Parameter | Default | Purpose |
|---|---|---|
| `max_concurrent` | 64 | Global concurrent request limit |
| `max_per_peer` | 8 | Per-peer concurrent limit |
| `retries_before_rotation` | 3 | Same-peer retries before rotating |
| `max_total_attempts` | 15 | Total retry budget |
| `initial_backoff` | 100ms | First retry delay |
| `max_backoff` | 500ms | Backoff cap |
| `backoff_multiplier` | 1.5 | Exponential backoff factor |
| `target_success_rate` | 0.5 | Below this, reduce concurrency |
| `min_concurrent` | 4 | Floor for adaptive concurrency |
| `speculative_retry_multiplier` | 2.0 | Speculative retry at 2x observed RTT |
| `speculative_retry_min` | 200ms | Floor for speculative retry |
| `speculative_retry_max` | 2s | Ceiling for speculative retry |

Provides weighted peer selection, adaptive concurrency, and exponential backoff (mod.rs:166-173).

---

## 5. Simulation Framework

### SimulationRunner (`crates/simulation/src/runner.rs:48-85`)

| Field | Type | Purpose |
|---|---|---|
| `io_loops` | `Vec<SimIoLoop>` | Per-node IoLoop instances (index = NodeIndex) |
| `event_rxs` | `Vec<Receiver<NodeInput>>` | Per-node crossbeam channel receivers |
| `event_queue` | `BTreeMap<EventKey, NodeInput>` | Global deterministic event queue |
| `sequence` | `u64` | Monotonic counter for deterministic ordering |
| `now` | `Duration` | Current simulation time |
| `network` | `SimulatedNetwork` | Latency, partitions, packet loss |
| `rng` | `ChaCha8Rng` | Seeded PRNG for network conditions |
| `timers` | `HashMap<(NodeIndex, TimerId), EventKey>` | Timer cancellation registry |
| `stats` | `SimulationStats` | Counters: events, messages, drops, timers |

### Event Priority Order (`crates/simulation/src/event_queue.rs:16-50`, `crates/core/src/input.rs:20-33`)

`EventKey` ordering: **time** > **priority** > **node_index** > **sequence**.

Priority enum (`EventPriority`, repr u8):

| Value | Variant | Examples |
|---|---|---|
| 0 | `Internal` | Callbacks, continuations, completions |
| 1 | `Timer` | `ProposalTimer`, `CleanupTimer`, `GlobalConsensusTimer` |
| 2 | `Network` | `BlockHeaderReceived`, `BlockVoteReceived`, `TransactionGossipReceived` |
| 3 | `Client` | External user inputs |

### SimulatedNetwork (`crates/network-memory/src/network.rs:155-196`)

| Field | Type | Purpose |
|---|---|---|
| `config` | `NetworkConfig` | Latency, jitter, packet loss, shard topology |
| `partitions` | `HashSet<(NodeIndex, NodeIndex)>` | Directional partition set |
| `registries` | `Vec<Arc<HandlerRegistry>>` | Per-node handler registries |
| `pending_gossip` | `BinaryHeap<Reverse<ScheduledGossip>>` | Latency queue for gossip |
| `pending_notifications` | `BinaryHeap<Reverse<ScheduledNotification>>` | Latency queue for notifications |
| `pending_responses` | `BinaryHeap<Reverse<ScheduledResponse>>` | Latency queue for responses |
| `gossip_seen` | `Vec<HashSet<u64>>` | Per-node content dedup (matches gossipsub) |

`NetworkConfig` defaults (`network.rs:36-47`):

| Parameter | Default |
|---|---|
| `intra_shard_latency` | 150ms |
| `cross_shard_latency` | 150ms |
| `jitter_fraction` | 0.1 |
| `validators_per_shard` | 4 |
| `num_shards` | 2 |
| `packet_loss_rate` | 0.0 |

Partitions are directional -- add both `(a,b)` and `(b,a)` for bidirectional (network.rs:158-159).

### SimStorage (`crates/storage-memory/src/core.rs:37-44`)

Uses `im::OrdMap` for O(1) structural-sharing clones (core.rs:18). Two independent `RwLock`s:

| Lock | Contents | Location |
|---|---|---|
| `state` | `SharedState`: `im::OrdMap<Vec<u8>, Vec<u8>>` substates + `SimTreeStore` + JVT version/root + MVCC `versioned_substates` | `state.rs:32-44` |
| `consensus` | `ConsensusState`: blocks, certificates, votes, committed metadata | core.rs:43 |

`SharedState` (`crates/storage-memory/src/state.rs:32`): `data` is `OrdMap` (deterministic BTree with structural sharing), `tree_store` is `SimTreeStore` (pruning disabled in sim -- retains all JVT nodes), `versioned_substates` is `BTreeMap` for MVCC prefix scans.

---

## 6. Metrics

### MetricsRecorder (`crates/metrics/src/lib.rs:1-49`)

Global singleton via `OnceLock`. Default is no-op. Install backend at startup:
- Production: `hyperscale_metrics_prometheus::install()`
- Simulation: `hyperscale_metrics_noop::install()` (or defaults to no-op)

Free functions delegate to the singleton: `record_storage_read()`, `record_block_committed()`, etc.

### ChannelDepths (`crates/metrics/src/lib.rs:32-49`)

Tracks event loop channel depths: `callback`, `consensus`, `validated_tx`, `rpc_tx`, `status`, `sync_request`, `tx_request`, `cert_request`.

### MemoryMetrics (`crates/metrics/src/lib.rs:56-145`)

Tracks collection lengths across all state machines:

- **BFT** (9 fields): `bft_pending_blocks`, `bft_vote_sets`, `bft_certified_blocks`, `bft_pending_commits`, `bft_remote_headers`, `bft_pending_qc_verifications`, `bft_verified_qcs`, `bft_pending_state_root_verifications`, `bft_buffered_synced_blocks`
- **Execution** (7 fields): `exec_cache_entries`, `exec_finalized_wave_certificates`, `exec_pending_provisioning`, `exec_accumulators`, `exec_vote_trackers`, `exec_early_votes`, `exec_wave_certificate_trackers`, `exec_expected_exec_certs`
- **Mempool** (6 fields): `mempool_pool`, `mempool_ready`, `mempool_tombstones`, `mempool_recently_evicted`, `mempool_locked_nodes`, `mempool_in_flight_heights`
- **Remote Headers** (3 fields): `rh_pending_headers`, `rh_verified_headers`, `rh_expected_headers`
- **Provisions** (5 fields): `prov_registered_txs`, `prov_verified_remote_headers`, `prov_pending_provisions`, `prov_verified_batches`, `prov_expected_provisions`
- **Livelock** (4 fields): `livelock_tombstones`, `livelock_pending_proof_fetches`, `livelock_pending_abort_intents`, `livelock_tracked_txs`
- **Storage** (3 fields): `jvt_node_cache_entries`, `rocksdb_block_cache_usage_bytes`, `rocksdb_memtable_usage_bytes`

These are entry counts except the `_bytes` suffixed fields.

---

## 7. Active Development Areas

### Issue #22: Unbounded In-Memory Data Structures (DoS Vector)

**Status**: Open, HIGH PRIORITY.

Summary of unbounded structures by crate:

| Crate | Unbounded Fields | Highest Risk |
|---|---|---|
| `bft` | 12 of 14 maps/sets | `pending_blocks`, `vote_sets`, `remote_headers` |
| `mempool` | 2 of 10 (plus gossip bypass) | `in_flight_by_height`, gossip path ignoring `max_pending` |
| `execution` | 13 of 13 maps/sets | `early_votes`, `early_provisioning_complete`, `early_wave_attestations` |
| `livelock` | 4 of 4 maps/sets | `tombstones` (keyed by Duration, no visible prune) |

Mitigation pattern needed: bounded `HashMap` with LRU eviction or height-based pruning. The `MemoryMetrics` struct (metrics/src/lib.rs:56) already tracks all relevant collection sizes -- wire these to alerts and hard caps.

### Issue #18: Transaction/Substate Test Suite

**Status**: Open. Test gap for end-to-end transaction lifecycle and substate read/write correctness across the execution pipeline. DST framework (`SimulationRunner`) exists but needs scenario coverage.

### Issue #17: Fee Model in Sharded Radix Engine

**Status**: Open, design hole. No fee deduction in the current execution path. The engine integration is read-only; fee model requires write-side hooks in the execution pipeline.

### Global Consensus Stubs

Global consensus is stubbed out. Evidence:
- `GlobalConsensusTimer` exists as `TimerId` variant (`crates/core/src/timer.rs:20`)
- `GlobalConsensusConfig` struct defined (`crates/types/src/epoch.rs:316`)
- Node state machine has placeholder: `"When implemented, route to GlobalConsensusState"` (`crates/node/src/state.rs:778`)
- Protocol events `GlobalBlockReceived`, `GlobalBlockVoteReceived` are defined but route to no-ops
