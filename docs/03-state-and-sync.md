# State, checkpointing, and synchronization

All ledger state in Hyperscale lives in one conceptual structure: a global, versioned, **binary Jellyfish Merkle Tree** (JMT) over a 256-bit keyspace. Shards are prefix subtrees of it. This one decision carries the rest of the document: it gives every shard a succinct state commitment per block, it gives cross-shard provisioning its merkle proofs, it gives new nodes a verifiable fast-sync path, and it turns dynamic resharding into a tree operation. This document covers the tree, the mapping from keyspace to shards, the storage stack, checkpointing, the three synchronization protocols (snap-sync, block sync, and remote-header sync), and divergence recovery.

Main code homes: `crates/jmt` (the tree), `crates/storage` / `storage-rocksdb` / `storage-memory` (the storage stack), `crates/remote-headers` (cross-shard header tracking), and `crates/node` (snap-sync, block sync, the commit pipeline).

---

## 1. The binary JMT

The tree (`Tree` in `crates/jmt`) is a binary-radix Jellyfish Merkle Tree, generic over the hasher. Arity is a compile-time parameter; the deployed arity is binary. The deployed hasher is Blake3, and the parameterization anticipates an eventual arithmetic-friendly hash such as Poseidon2 for proof-system integration. Keys are fixed 32-byte values. Leaves store precomputed value hashes; raw values live beside the tree in substate storage.

- **Versioned.** Every block commit produces a new tree version via `apply_updates_at(parent_version, new_version, root_path, updates)`, which returns the new root hash and a `TreeUpdateBatch` of created and stale nodes. Old versions remain readable: multiple roots coexist in storage, bounded by the retention window (`jmt_history_length`). Everything that reads history — provision fallback serving, historical ownership resolution — is designed to stay within that window (INV-STATE-4).
- **Batched multiproofs.** `Tree::prove(root, keys)` produces a `MultiProof`: per-key claims (present-leaf, empty-subtree, or mismatch-leaf) plus a deduplicated sibling set. One proof covers an arbitrary key batch. Batched proofs are the workhorse of cross-shard provisioning ([04-atomic-commitment.md](04-atomic-commitment.md)) and snap-sync chunk verification.
- **Subtree-rooted operations.** Updates and proofs are computed against an explicit root *path*, not only the global root, so a shard operates entirely within its own prefix subtree.

The state root in every shard block header is the shard's subtree root at that block, recomputed independently by every replica from the parent state plus the block's receipts. Because execution is deterministic, the root is an agreement point: same parent, same receipts, same root, on every honest node (INV-STATE-1).

## 2. Mapping the keyspace to shards

**Shards are prefixes.** A `ShardId` denotes a bit-path; the shard owns every key under that prefix. The global address space is partitioned by the **shard trie** (`ShardTrie` in `crates/types`), whose leaves are the live shards. Data routing is `shard_for(node_id)`: walk the trie by the top bits of the node's routing hash.

**Owner-prefixed keying** is the rule that keeps this partition meaningful. Radix Engine internal objects (vaults, key-value stores) have random NodeIds with no structural relation to the account that owns them, so naive keying would scatter an account's assets across all shards. Instead, every substate's JMT leaf key is built as:

```
[ blake3(routing_node)[..16] | blake3(full_storage_key)[16..] ]
```

where `routing_node` is the substate's *owner* — its global ancestor, the account — for owned internal objects, or the node itself for globals. The high half places all of an owner's state contiguously under the owner's prefix. The low half disambiguates the owner's individual substates and binds the full storage key. Three consequences follow:

- An account and everything it owns live in **one** shard, always.
- An engine object never changes owner once committed (validated against Radix Engine semantics), so keys are stable forever: nothing ever needs re-keying, including across splits and merges (INV-STATE-2).
- A snap-sync verifier can check the owner-binding of every shipped leaf from the leaf key alone, without possessing the engine's ownership map.

This keying is why the central identity of [02-dynamic-sharding.md](02-dynamic-sharding.md), `hash_internal(left_child_root, right_child_root) == parent_root`, is a complete description of resharding state: split and merge move subtree *roots*, never leaves.

## 3. The storage stack

Storage is trait-abstracted (`crates/storage`) with two full backends: RocksDB for production (`storage-rocksdb`) and an in-memory persistent-structure implementation for deterministic simulation (`storage-memory`). Both implement one umbrella bound; consensus code cannot tell them apart. The design is its capability seams (the trait names track the code):

- versioned substate reads with state roots and merkle proof generation, with owner-prefixing applied;
- committed-chain reads and writes: blocks, certificates, receipts;
- raw JMT node access;
- boundary import for checkpoints and snap-sync (`BoundaryStore`);
- the uncommitted block index (`PendingChain`), whose views **walk parent-hash links back to the committed tip**, so orphaned forks are structurally invisible (INV-STATE-6).

Two RocksDB facts matter above the storage layer. JMT node keys are laid out version-first, so writes stay LSM-append-friendly. Checkpoints are hard-link snapshots — cheap and copy-free.

The commit pipeline (the `crates/node` commit coordinator) accumulates committed blocks, prepares each one by recomputing the JMT, and flushes to storage asynchronously. Receipts are written atomically with their block, so execution results are exactly as durable as the chain itself.

## 4. Checkpointing

A **checkpoint** is the durable, servable image of a shard at an epoch boundary — the material behind every snap-sync anchor.

- **When.** Boundary detection runs at commit time, on the *child* of the boundary block: the crossing is detected when a committed block's `parent_qc.weighted_timestamp` lands in a new epoch window. The child's parent-QC timestamp is the canonical one ([01-consensus-layers.md](01-consensus-layers.md) §1.3), so every replica pins the same boundary block. The boundary block's own QC would not serve: it can be re-certified with a different timestamp, which would flip the verdict.
- **What.** A hard-link snapshot that pins the full state at the boundary height: substates, JMT nodes, and the leaf-key association table used for range serving. Each shard retains a ring of recent boundary pins sized to the join budget: a joiner syncing a large shard must be able to finish against a boundary its peers still pin, so production retention covers `ready_timeout_epochs`. Hard links pin superseded SSTs, so the ring's disk overhead scales with churn across the window, not with state size.
- **Attestation.** The same boundary block is the shard's contribution to the beacon that epoch. The resulting `ShardBoundary` record, projected to shards as `ShardAnchor { state_root, block_hash, height, weighted_timestamp, settled_waves_root }`, is the beacon-attested description of the checkpoint. An anchor is trustworthy not because a peer served it but because the joiner's own beacon fold produced it.

## 5. Snap-sync

Snap-sync lets a node acquire a shard's state directly at an anchor, without replaying history. It serves three consumers: fresh joiners, reshape observers building a child store, and merge keepers building the sibling half ([02-dynamic-sharding.md](02-dynamic-sharding.md)).

The assembler (`SnapSync`, sans-io, in `crates/node`) partitions the shard's key span into disjoint sub-ranges fetched in parallel. Each response chunk carries leaves `(leaf_key, storage_key, value)` and a range proof. Three independent bindings tie every chunk to the beacon-attested anchor before a byte is imported (INV-STATE-3):

1. The **range proof** proves the leaf set into `anchor.state_root`, completeness included: a serving peer cannot omit in-span leaves undetected.
2. Each leaf key's low half must equal `blake3(storage_key)[16..]`. This binds the shipped raw key — and, through the high half, its claimed owner — without any ownership metadata.
3. Claimed value hashes are recomputed from the shipped raw values.

Verified chunks are staged durably as they arrive (`BoundaryStore::stage_import_chunk`), together with a progress record binding the staged data to its exact anchor; the store proper is untouched until every sub-range is exhausted. The finalize (`BoundaryStore::finalize_boundary_import`) then rebuilds the subtree from the staged leaves and returns the computed root, which the caller compares against the anchor one final time. Staging keeps the assembler's memory bounded by a single wire chunk regardless of shard size, and the progress record lets a restarted joiner resume an interrupted sync against the same anchor without refetching finished sub-ranges — a record that does not bind the currently attested anchor and fetch geometry is wiped instead. An anchor that goes stale mid-sync (evicted from the serving ring) is handled the same way: wipe and retry against the advanced anchor rather than failure.

Reshape children add a follow phase: after the bulk import, the observer tails the still-running parent chain and applies each block's child-prefix writes until the terminal crossing. The result is exactly the child's genesis state.

## 6. Block sync and remote-header sync

Both protocols are instances of one generic sliding-window FSM (`Sync<B: SyncBinding>`, `crates/node`): a target height, a committed watermark, a bounded in-flight window, capped per-height exponential backoff with re-arm on tick, and a hold-then-demote rule for fetched-but-unadmitted heights. Like every other state machine in the system, the FSM is clocked exclusively by the `LocalTimestamp` fed through its inputs; it never reads a wall clock ([07-determinism-and-testing.md](07-determinism-and-testing.md)).

**Block sync** catches a lagging replica up on its own shard: fetch committed blocks from peers, verify each block's QC, and commit through the *same* prepare path as live consensus (§7). The QC is the admission ticket; the block's own receipts are not re-executed. A responder serves contiguous prefixes, so a short response is itself evidence of the responder's tip and caps the target.

**Remote-header sync** (`crates/remote-headers`) has every shard continuously track the *certified headers* of every other shard it might interact with. Those headers are the substrate of cross-shard trust: provision proofs verify against a remote header's state root, provision batches verify against its provision root, and expected-EC tracking keys off remote chain progress. Headers arrive by gossip — the sender signature is checked, then the QC is verified asynchronously against the WT-resolved remote committee before promotion — with the sliding-window fetch as the liveness fallback when gossip goes quiet past a timeout. Two topology-aware details matter:

- **Anchor-floored starts.** A freshly discovered shard (a reshape child, for example) is tracked from its beacon-attested boundary height, not from zero. Its chain simply does not have earlier heights, and probing them stalls the contiguous-prefix logic.
- **Terminal clamping.** A terminated reshape shard remains routable for its retention window, and it resolves to its *frozen terminal committee* rather than to whatever committee its members joined next. Survivors can therefore keep fetching the terminal artifacts the settlement machinery needs: the terminal header and the settled-waves window.

## 7. Divergence recovery

Divergence recovery defends against one failure mode: a replica whose local execution is wrong (bad build, cosmic ray, latent bug) silently corrupting its own store or, worse, exporting corruption to peers.

- **One prepare path.** Both live-consensus commits and sync-path commits run the same `prepare_block_commit`: recompute the state root from the parent state plus the block's finalized receipts, then compare it against the header's QC-attested root (INV-STATE-5). On the sync path this comparison is the sole execution check, which is what makes it decisive.
- **Divergence at EC admission.** If a validator's own execution vote disagrees with the EC its shard's quorum admitted, the wave is marked locally divergent and permanently barred from local finalization, and the replica recovers the canonical `FinalizedWave` through block sync. Locally produced receipts therefore never enter the finalized store unless they match the quorum's attestation (INV-EXEC-8). The same containment is what makes it sound for serving peers to skip re-serving certificates that a syncing node can reconstruct.
- **Ingress validation.** `FinalizedWave`s received from peers are validated receipt by receipt against their EC's attestation (existence, hash, outcome) before admission.
- **Fail-fast on poison.** If a sync-path commit's recomputed root mismatches the QC-attested header root, the parent state itself has diverged from canon. A corrupted tree has no block-granular repair, so the node emits a full diagnostic (heights, hashes, expected and computed roots) and halts; an operator restores from a checkpoint or resyncs. Halting loudly is the design: a node with poisoned state must not keep voting.

## 8. Properties

The state and synchronization invariants this document motivates — INV-STATE-1 through INV-STATE-6 — are stated precisely in [08-invariants.md](08-invariants.md).
