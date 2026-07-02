# State, Checkpointing, and Synchronization

All ledger state in Hyperscale lives in one conceptual structure: a global, versioned, **binary Jellyfish Merkle Tree** (JMT) over a 256-bit keyspace. Shards are prefix subtrees of it. This single decision does a remarkable amount of work — it gives every shard a succinct state commitment per block, gives cross-shard provisioning its merkle proofs, gives new nodes a verifiable fast-sync path, and turns dynamic resharding into a tree operation. This document covers the tree, how the keyspace maps onto shards, the storage stack, checkpointing, the three synchronization protocols (snap-sync, block sync, remote-header sync), and divergence recovery.

Main code homes: `crates/jmt` (the tree), `crates/storage` / `storage-rocksdb` / `storage-memory` (the storage stack), `crates/remote-headers` (cross-shard header tracking), and `crates/node` (snap-sync, block sync, the commit pipeline).

---

## 1. The binary JMT

The tree (`Tree` in `crates/jmt`) is a binary-radix Jellyfish Merkle Tree — arity is a compile-time parameter, deployed binary — generic over the hasher (Blake3 today; the parameterization anticipates an eventual arithmetic-friendly hash such as Poseidon2 for proof-system integration). Keys are fixed 32-byte values; leaves store precomputed value hashes, with raw values living beside the tree in substate storage.

- **Versioned.** Every block commit produces a new tree version via `apply_updates_at(parent_version, new_version, root_path, updates)`, returning the new root hash and a `TreeUpdateBatch` of created/stale nodes. Old versions remain readable — multiple roots coexist in storage — bounded by a retention window (`jmt_history_length`). Everything that reads history (provision fallback serving, historical ownership resolution) is bounded within this window by design (INV-STATE-4).
- **Batched multiproofs.** `Tree::prove(root, keys)` produces a `MultiProof`: per-key claims (present-leaf, empty-subtree, or mismatch-leaf) plus a deduplicated sibling set. One proof covers an arbitrary key batch — this is the workhorse of cross-shard provisioning ([04-atomic-commitment.md](04-atomic-commitment.md)) and snap-sync chunk verification.
- **Subtree-rooted operations.** Updates and proofs are computed against an explicit root *path*, not only the global root — a shard operates entirely within its own prefix subtree.

The state root in every shard block header is the shard's subtree root at that block, recomputed independently by every replica from the parent state plus the block's receipts. Determinism of execution makes this an agreement point: same parent, same receipts, same root, on every honest node (INV-STATE-1).

## 2. Mapping the keyspace to shards

**Shards are prefixes.** A `ShardId` denotes a bit-path; the shard owns every key under that prefix. The global address space is partitioned by the **shard trie** (`ShardTrie` in `crates/types`), whose leaves are the live shards. Data routing is `shard_for(node_id)` — walk the trie by the top bits of the node's routing hash.

**Owner-prefixed keying** is the rule that keeps this partition meaningful. Radix Engine internal objects — vaults, key-value stores — have random NodeIds structurally unrelated to the account that owns them; naively keyed, an account's assets would scatter across all shards. Instead, every substate's JMT leaf key is built as:

```
[ blake3(routing_node)[..16] | blake3(full_storage_key)[16..] ]
```

where `routing_node` is the substate's *owner* (its global ancestor — the account) for owned internal objects, or the node itself for globals. The high half places all of an owner's state contiguously under the owner's prefix; the low half disambiguates the owner's individual substates while binding the full storage key. Consequences:

- An account and everything it owns live in **one** shard, always.
- Because engine-committed objects never change owner once committed (validated against Radix Engine semantics), keys are stable forever — nothing ever needs re-keying, including across splits and merges (INV-STATE-2).
- A snap-sync verifier can check the owner-binding of every shipped leaf from the leaf key alone, without possessing the engine's ownership map.

This keying is what makes [02-dynamic-sharding.md](02-dynamic-sharding.md)'s central identity — `hash_internal(left_child_root, right_child_root) == parent_root` — a complete description of resharing state: split and merge move subtree *roots*, never leaves.

## 3. The storage stack

Storage is trait-abstracted (`crates/storage`) with two full backends: RocksDB for production (`storage-rocksdb`) and an in-memory persistent-structure implementation for deterministic simulation (`storage-memory`). Both implement one umbrella bound; consensus code cannot tell them apart. The capability seams (the trait names track the code; the seams are the design): versioned substate reads with state roots and merkle proof generation (owner-prefixing applied); committed-chain reads and writes (blocks, certificates, receipts); raw JMT node access; boundary import for checkpoints and snap-sync (`BoundaryStore`); and the uncommitted block index (`PendingChain`), whose views **walk parent-hash links back to the committed tip**, so orphaned forks are structurally invisible (INV-STATE-6).

Two RocksDB facts matter above the storage layer: JMT node keys are laid out version-first, so writes stay LSM-append-friendly; and checkpoints are hard-link snapshots (cheap, copy-free).

The commit pipeline (`crates/node` commit coordinator) accumulates committed blocks, prepares each (recomputing the JMT), and flushes to storage asynchronously; receipts are written atomically with their block, so execution results are exactly as durable as the chain itself.

## 4. Checkpointing

A **checkpoint** is the durable, servable image of a shard at an epoch boundary — the material behind every snap-sync anchor.

- **When.** Boundary detection runs at commit time, on the *child* of the boundary block: the crossing is detected when a committed block's `parent_qc.weighted_timestamp` lands in a new epoch window. Using the child's parent-QC timestamp (the canonical one — see [01-consensus-layers.md](01-consensus-layers.md) §1.3) means every replica pins the same boundary block; the boundary block's own QC could be re-certified with a different timestamp and flip the verdict.
- **What.** A hard-link snapshot pinning the full state (substates + JMT nodes + the leaf-key association table used for range serving) at the boundary height. A small ring of recent boundary pins is retained per shard.
- **Attestation.** The same boundary block is what the shard contributes to the beacon that epoch; the resulting `ShardBoundary` record — projected to shards as `ShardAnchor { state_root, block_hash, height, weighted_timestamp, settled_waves_root }` — is the beacon-attested description of the checkpoint. An anchor is trustworthy not because a peer served it but because the joiner's own beacon fold produced it.

## 5. Snap-sync

Snap-sync lets a node acquire a shard's state directly at an anchor, without replaying history. It serves three consumers: fresh joiners, reshape observers building a child store, and merge keepers building the sibling half ([02-dynamic-sharding.md](02-dynamic-sharding.md)).

The assembler (`SnapSync`, sans-io, in `crates/node`) partitions the shard's key span into disjoint sub-ranges fetched in parallel. Each response chunk carries leaves `(leaf_key, storage_key, value)` and a range proof. Three independent bindings tie every chunk to the beacon-attested anchor before a byte is imported (INV-STATE-3):

1. The **range proof** proves the leaf set into `anchor.state_root` — including *completeness*: a serving peer cannot omit in-span leaves undetected.
2. Each leaf key's low half must equal `blake3(storage_key)[16..]`, binding the shipped raw key (and by the high half, its claimed owner) without any ownership metadata.
3. Claimed value hashes are recomputed from the shipped raw values.

Import (`BoundaryStore::import_boundary_state`) rebuilds the subtree from verified leaves and returns the computed root, which the caller compares against the anchor one final time. Anchors that go stale mid-sync (evicted from the serving ring) are handled by defer-and-retry rather than failure.

For reshape children there is a follow-phase: after the bulk import, the observer tails the still-running parent chain and applies each block's child-prefix writes until the terminal crossing, arriving at exactly the child's genesis state.

## 6. Block sync and remote-header sync

Both are instances of one generic sliding-window FSM (`Sync<B: SyncBinding>`, `crates/node`): a target height, a committed watermark, a bounded in-flight window, capped per-height exponential backoff with re-arm on tick, and a hold-then-demote rule for fetched-but-unadmitted heights. The FSM is clocked exclusively by the `LocalTimestamp` fed through its inputs — no internal wall-clock reads — like every other state machine in the system ([07-determinism-and-testing.md](07-determinism-and-testing.md)).

**Block sync** (own shard, lagging replica): fetch committed blocks from peers, verify each block's QC — the QC is the admission ticket; the block's own receipts are not re-executed — and commit through the *same* prepare path as live consensus (§7). A responder serves contiguous prefixes, so a short response is itself evidence of the responder's tip and caps the target.

**Remote-header sync** (`crates/remote-headers`): every shard continuously tracks the *certified headers* of every other shard it might interact with. This is the substrate of cross-shard trust — provision proofs verify against a remote header's state root; provision batches verify against its provision root; expected-EC tracking keys off remote chain progress. Headers arrive by gossip (verified: sender signature, then async QC verification against the WT-resolved remote committee before promotion), with the sliding-window fetch as liveness fallback when gossip goes quiet past a liveness timeout. Two topology-aware details matter:

- **Anchor-floored starts.** A freshly discovered shard (e.g. a reshape child) is tracked from its beacon-attested boundary height, not from zero — its chain simply does not have earlier heights, and probing them stalls the contiguous-prefix logic.
- **Terminal clamping.** A terminated reshape shard remains routable for its retention window, resolving to its *frozen terminal committee* rather than to whatever committee its members joined next — so survivors can keep fetching the terminal artifacts (terminal header, settled-waves window) the settlement machinery needs.

## 7. Divergence recovery

The failure mode being defended against: a replica whose local execution is wrong (bad build, cosmic ray, latent bug) silently corrupting its own store or, worse, exporting corruption to peers.

- **One prepare path.** Both live-consensus commits and sync-path commits run the same `prepare_block_commit`: recompute the state root from the parent state plus the block's finalized receipts, compare against the header's QC-attested root (INV-STATE-5). On the sync path this is the sole execution check — which makes the comparison decisive.
- **Divergence at EC admission.** If a validator's own execution vote disagrees with the EC its shard's quorum admitted, the wave is marked locally divergent and permanently barred from local finalization; the replica recovers the canonical `FinalizedWave` via block sync. Locally produced receipts thus never enter the finalized store unless they match the quorum's attestation (INV-EXEC-8), which is also what makes it sound for serving peers to elide re-serving certificates a syncing node can reconstruct.
- **Ingress validation.** `FinalizedWave`s received from peers are validated receipt-by-receipt against their EC's attestation (existence, hash, outcome) before admission.
- **Fail-fast on poison.** If a sync-path commit's recomputed root mismatches the QC-attested header root, the parent state itself has diverged from canon. There is no block-granular repair for a corrupted tree, so the node emits a full diagnostic (heights, hashes, expected/computed roots) and halts — an operator restores from a checkpoint or resyncs. Halting loudly is the design: a node with poisoned state must not keep voting.

## 8. Properties (summary)

Consolidated with IDs in [08-invariants.md](08-invariants.md).

- **INV-STATE-1 (root determinism).** Same parent state + same receipts ⇒ same state root, on every honest replica; the header root is QC-attested.
- **INV-STATE-2 (clean subtrees).** Every shard is a prefix subtree; owner-prefixed leaf keys never re-parent; an owner's state is co-shard with the owner, permanently.
- **INV-STATE-3 (verified import).** No snap-sync leaf is imported except under a range proof into a beacon-attested root, with key- and value-bindings independently checked, and the rebuilt root re-verified.
- **INV-STATE-4 (bounded history).** Versioned reads are bounded by the retention window; every protocol needing history is designed within it.
- **INV-STATE-5 (one verifier).** Sync-path and consensus-path commits share one state-root verification; a mismatch on the sync path is treated as unrecoverable divergence, halting the node rather than admitting corruption.
- **INV-STATE-6 (ancestry visibility).** Pending-chain reads see only blocks that chain by parent-hash to the committed tip; orphaned forks are structurally unreachable.
