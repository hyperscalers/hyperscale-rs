# Atomic cross-shard commitment

This document covers the machinery that gives Hyperscale single-chain semantics across shards: a transaction touching state on several shards commits atomically — the same terminal outcome, on every participating shard, with BFT finality — or aborts everywhere. The protocol is a deterministic **provision–execute–certify** pipeline built from three ingredients: **declared state access** (the transaction says up front what it touches), **provisions** (QC-attested state transfer between shards), and **execution certificates** (per-shard quorum agreement on a shared outcome vector, described in [01-consensus-layers.md](01-consensus-layers.md) §2).

**If you know two-phase commit, read this first.** The family resemblance is real — ordering a transaction under locks plays the role prepare plays classically — but the three defining features of 2PC are all absent. There is **no coordinator**: the protocol is symmetric across shards, so the coordinator-failure blocking problem that defines textbook 2PC has no analogue. There are **no votes on the outcome**: in 2PC the result is genuinely open until participants' votes are tallied, whereas here it is a deterministic function of committed chain content — which transactions ordered, which provisions landed by the attested deadline, which conflicts resolved which way. Execution certificates *attest* an outcome every honest replica already computed rather than *choosing* one. (The closer lineage is deterministic databases, where determinism replaces commit-time agreement, not distributed transactions.) And **participants don't fail in the 2PC sense**: each "participant" is a BFT-replicated committee, and even a participant shard ceasing to exist mid-flight — a case classical 2PC has no answer for — resolves deterministically through the settled-set fence ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Main code homes: `crates/mempool` (admission, ready set), `crates/provisions` (provision coordination and DA), `crates/execution` (waves, conflict detection, vote aggregation), `crates/engine` (Radix Engine integration, ownership), with the wire types in `crates/types` (`Provisions`, `ProvisionEntry`, `ExecutionCertificate`, `WaveCertificate`, `FinalizedWave`).

---

## 1. Declared access and the mempool

Every transaction declares the set of global nodes (accounts and other global engine objects) it reads and writes. Declaration is the foundation of everything downstream: it determines routing (which shards participate — the shards owning the declared nodes, via the shard trie), it bounds execution (writes outside the declared/derived set are deterministically dropped), and it enables conflict analysis without executing.

The mempool (`MempoolCoordinator`) admits transactions into a hash-ordered pool with process-level dedup caches shared across co-hosted vnodes (`CanonicalTxs` — one signature/SBOR validation per transaction per process; `TxStatusCache` — one status truth for RPC). Terminal-state tombstones prevent re-admission of finished transactions.

**The ready set is the livelock firewall.** `ReadySet::add` enforces **partial coupling**: no two transactions that are simultaneously in flight (committed and holding locks) or ready (eligible for proposal) may share *any* declared node (INV-EXEC-3). A transaction whose declared nodes overlap a lock or another ready transaction is deferred, indexed by the blocking node, and promoted the moment the node frees. Locks are held from commit until the transaction's wave finalizes, and cross-shard transactions extend their locks over all provisioning dependencies. Consequences:

- Two local transactions can never deadlock — they are never in flight together if they could contend.
- Proposal selection is deterministic (hash-ordered iteration up to the block budget — a transaction count, with a gas budget planned), so all replicas agree on eligibility reasoning.
- The invariant is deliberately a *superset* of the minimum needed for cross-shard coupling safety, which structurally defuses gaming strategies that exploit partially-coupled scheduling.

An in-flight cap (`MAX_TX_IN_FLIGHT`) bounds the total lock-holding population, providing backpressure.

## 2. Provision: proven state transfer

When a source shard commits a block containing cross-shard transactions, its proposer broadcasts **`Provisions`** to each destination shard — one bundle per (source block, destination shard):

- Per transaction: the substate values the destination needs (`entries`, canonically sorted), the nodes the transaction needs *from* the destination (`target_nodes`, for conflict detection), and the source's ownership map for its declared accounts (`owned_nodes`: internal object → owning account — see §5).
- A JMT merkle **multiproof** over all carried substates against the source block's state root.

Verification at the destination is two-stage and entirely artifact-based. The source block's header is already held and QC-verified via remote-header sync ([03-state-and-sync.md](03-state-and-sync.md) §6), so verifying a provision bundle means one QC check per source block plus merkle verification of every entry against the attested state root. A provision is a *proof about a committed remote block* — no node in the source shard is trusted, only its quorum (INV-EXEC-10). Verified provisions are persisted and flow into wave assembly.

**The header also pre-announces.** Source block headers carry `provision_targets` (which shards this block provisions) and per-destination `provision_tx_roots`, so destinations know what to expect and can detect absence — absence of data, unlike presence, needs an announcement to be actionable.

## 3. Execute and certify: outcome agreement by determinism

At the destination (and symmetrically on every participant), committed cross-shard transactions group into **waves** keyed by their provisioning dependency set. A wave dispatches when fully provisioned; execution merges local snapshot state with the provisioned remote entries and runs the Radix Engine once per transaction, atomically for the wave.

Determinism across shards is engineered, not assumed:

- **Same inputs.** All participants execute from the same declared set, the same provisioned entries (QC-attested), and the same merged ownership map (§5).
- **Same engine, same outputs.** The engine's output is projected to a shard-invariant form (`CachedVmOutput`): the receipt hash, application events, and outcome are identical everywhere; only the *database updates* are then filtered per shard (each shard persists writes for the nodes it owns). All failures collapse to one canonical failed-receipt hash.
- **Same filtering.** Writes to undeclared/underived nodes are dropped by rule, so engine-internal nondeterminism cannot leak into committed state (INV-EXEC-9).

Validators vote on the wave's `global_receipt_root`; 2f+1 matching votes form the shard's **ExecutionCertificate** with the explicit per-transaction outcome vector, each success outcome carrying its transaction's receipt hash. A wave finalizes per transaction, from the ECs collected local and remote: a transaction succeeds only with a success outcome from **every** participating shard, and an abort outcome from any shard is terminal. Abort is dominant; success is unanimous. Every EC binds its root to its outcome vector (recompute-on-decode, INV-EXEC-2), and deterministic execution means honest quorums attest identical per-transaction receipt hashes, so divergent success content cannot arise within the committee-honesty premise. Atomic commitment is enforced by the unanimity rule over attested outcomes (INV-EXEC-1). The `FinalizedWave` (certificate plus attested local receipts) then rides in a subsequent block, locks release, and the transaction is terminal.

## 4. Aborts: deterministic, total, timely

Every path to abort is a pure function of committed chain state, so all replicas — and all shards — reach the same verdict:

- **Conflict detection** (`ConflictDetector`). A true cross-shard deadlock requires bidirectional overlap: a remote transaction's source entries overlap what a local transaction needs from that shard *and* the remote's targets overlap what the local one owns locally. Conflicts are detected on provision commit (forward) and on local registration (reverse), and resolved by deterministic tiebreak — the lower transaction hash wins, and the loser aborts before executing. Both shards derive identical conflicts from identical committed inputs (INV-EXEC-4).
- **Wave deadline.** Every wave carries a deadline anchored on BFT-attested time (source-block weighted timestamp plus `WAVE_TIMEOUT`). A wave not fully provisioned by its deadline **all-aborts**: every transaction in it aborts, on every participant, regardless of which provisions did arrive (INV-EXEC-5). This is the liveness backstop that guarantees termination even under permanent provision loss — and because the deadline derives from attested time, no two replicas disagree about whether it passed.
- **Reshape-boundary aborts.** When a participating shard terminates in a split/merge, the settled-set fence and counterpart sweep decide every straddler from frozen chain content ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Abort is a first-class terminal outcome inside the EC's outcome vector — an aborted cross-shard transaction is *agreed aborted* with the same finality as a success.

## 5. Ownership: the cross-shard trust seam

Radix Engine internal objects (vaults, KV stores) carry no structural pointer to their owner, and their NodeIds don't reveal their shard. Ownership is resolved by walking declared accounts' substates for SBOR `Own(..)` references (`resolve_owned_nodes`), yielding the vault-to-account map that owner-prefixed keying ([03-state-and-sync.md](03-state-and-sync.md) §2) and update filtering depend on.

For cross-shard execution, each participant builds the merged map (`build_cross_shard_ownership`): local resolution for locally-declared accounts, plus each remote shard's `owned_nodes` claims from its provisions. A vault claimed by both sides **deterministically aborts the transaction**. Healthy state holds one owner per vault, so a contested claim is bogus input, and because the *substate* overlay gives provisioned values precedence over local state, the two committees would otherwise execute divergent VM views. Aborting on a verdict both shards derive identically from identical bytes keeps them in agreement rather than risking shard-divergent write placement (INV-EXEC-6).

**Known interim trust gap, explicitly documented as such:** a provision's substate *entries* are proven into the QC-attested state root, but the `owned_nodes` map itself is attested only through the per-transaction roots (`provision_tx_roots`) at transaction-hash granularity — a Byzantine source committee member has a bounded window in which bogus ownership claims can reach a destination's execution. The failure is contained to *liveness/availability* (deterministic aborts, mis-filtered writes are dropped by declaration bounds), not safety divergence, because both shards apply identical merge rules to identical bytes. The planned hardening is to commit per-transaction `owned_nodes` into the attested provision leaves; the long-term fix is engine-level manifest-deterministic ownership, which eliminates the resolution walk entirely.

## 6. Data availability

The DA design principle: **the artifact you need is either held by someone obligated to serve it, or provably expired.** Every retention decision keys on BFT-attested weighted time, so eviction is a consensus-consistent fact, not a local heuristic (INV-EXEC-7).

- **Outbound provisions** (`OutboundProvisionTracker`): a source shard retains what it broadcast until the destination's EC covers every transaction in the batch (a positive, quorum-signed acknowledgment) or the attested deadline passes. Until then, any destination node can fetch from any source node.
- **Serving fallback**: provision requests are answerable from committed storage — RocksDB plus historical JMT reads — bounded by the JMT retention window, so even a source node that restarted can serve.
- **Expected-transaction backfill** (`ExpectedTxs`): a destination that learns (from provisions) of transactions it never received by gossip fetches them from the source committee after a grace period, and abandons past the retention horizon.
- **Expected provisions**: symmetric tracking on the destination side, with fetch fallback when the gossip path fails.
- **Execution dedup** (`ProcessExecutionCache`): one VM execution per transaction per process, shared across co-hosted vnodes and shards, evicted only when every hosted participant has finalized — so a cached result can never disagree with a certificate a hosted shard later admits.
- **Voting-time DA**: independent of all of the above, a validator votes only holding full block content, so every QC certifies 2f+1 complete copies of everything the block carries ([01-consensus-layers.md](01-consensus-layers.md) §1.2).

Fetch-path plumbing (unified `IdFetch` protocols, abandon-on-terminal notifications, class-based network prioritization so bulk DA traffic cannot starve consensus) is covered in [05-byzantine-safety.md](05-byzantine-safety.md) §6 and [07-determinism-and-testing.md](07-determinism-and-testing.md).

## 7. End-to-end walkthrough

A transaction declaring accounts on shards A and B:

1. **Admission.** Both shards admit it (routing by declared nodes); each shard's ready set holds it until no declared node is contended locally.
2. **Ordering.** A and B each commit it in a block, independently — there is no cross-shard coordination in consensus itself. Locks engage on both sides.
3. **Provisioning.** A's proposer sends B a proven bundle of A's declared substates (and vice versa). Each side verifies against the other's QC-attested header.
4. **Execution.** Both sides now hold identical merged inputs; both execute; both compute the same receipts and the same `global_receipt_root`.
5. **Certification.** A's committee quorum-signs EC_A; B's signs EC_B; the certificates cross by gossip/fetch.
6. **Finalization.** Each side assembles the wave certificate {EC_A, EC_B}, checks root equality, finalizes the wave into a later block, releases locks. The transaction is terminal — identically — on both shards.

Any deviation lands in an abort path whose verdict both sides compute identically: conflict tiebreak (step 2-3), wave deadline (step 3-4 stall), or — if one shard terminates in a reshape — the settled-set fence.

## 8. Properties

The atomic-commitment invariants this document motivates — INV-EXEC-1 through INV-EXEC-10 — are stated precisely in [08-invariants.md](08-invariants.md).
