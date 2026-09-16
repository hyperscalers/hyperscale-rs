# Atomic cross-shard commitment

This document covers the machinery that gives Hyperscale single-chain semantics across shards: a transaction touching state on several shards commits atomically — the same terminal outcome, on every participating shard, with BFT finality — or aborts everywhere. The protocol is a deterministic **provision–execute–certify** pipeline built from three ingredients: **declared state access** (the transaction says up front what it touches), **provisions** (QC-attested state transfer between shards), and **execution certificates** (per-shard quorum agreement on a shared outcome vector, described in [01-consensus-layers.md](01-consensus-layers.md) §2).

**If you know two-phase commit, read this first.** The family resemblance is real — ordering a transaction under locks plays the role prepare plays classically — but the three defining features of 2PC are all absent. There is **no coordinator**: the protocol is symmetric across shards, so the coordinator-failure blocking problem that defines textbook 2PC has no analogue. There are **no votes on the outcome**: in 2PC the result is genuinely open until participants' votes are tallied, whereas here it is a deterministic function of committed chain content — which transactions ordered, and which provisions landed by the attested deadline. Execution certificates *attest* an outcome every honest replica already computed rather than *choosing* one. (The closer lineage is deterministic databases, where determinism replaces commit-time agreement, not distributed transactions.) And **participants don't fail in the 2PC sense**: each "participant" is a BFT-replicated committee, and even a participant shard ceasing to exist mid-flight — a case classical 2PC has no answer for — resolves deterministically through the settled-set fence ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Main code homes: `crates/mempool` (admission and availability), `crates/provisions` (provision coordination and DA), `crates/execution` (ticks, vote aggregation), `crates/engine` (the effect-typed engine and its fee rules), with the wire types in `crates/types` (`Provisions`, `ProvisionEntry`, `ExecutionCertificate`, `Finalization`).

---

## 1. Declared access and the mempool

Every transaction's declared access is derived from its signed envelope through the effect DSL — the set of keys it reads and writes, each carrying the owner prefix that places it. Declaration is the foundation of everything downstream: it determines routing (which shards participate — the shards those prefixes route to, via the shard trie), it bounds execution (a guest reaches a cell only through a capability the derivation granted, so an undeclared write is unreachable), and it enables contention analysis without executing.

The mempool (`MempoolCoordinator`) admits transactions into a hash-ordered pool with process-level dedup caches shared across co-hosted vnodes (`CanonicalTxs` — one signature/HBOR validation per transaction per process; `TxStatusCache` — one status truth for RPC). Terminal-state tombstones prevent re-admission of finished transactions.

**Admission does not arbitrate conflicts.** Selection is hash-ordered iteration over the eligible pool up to the block budget; two transactions touching one cell are both selectable. What sequences them is execution: a committed block's work is one batch, partitioned into conflict groups and run against a single overlay, and each batch's output is the next batch's baseline. Contenders therefore see each other's writes instead of being held apart, and a hot cell no longer costs a commit cycle per transaction.

A work budget (`MAX_DRAIN_WORK`) bounds the drain a shard still owes — committed transactions whose tick has not settled. The total is chain-derived and carried on the block header, so every replica reads the same number rather than one that drifts with its own pipeline position, and what it bounds is *adding* to the drain: a block bringing new transactions to a drain already over budget is invalid, while one carrying only certificates stays valid at any total. See [06-resource-economics.md](06-resource-economics.md) §5 for why the asymmetry is load-bearing.

**Authorization splits between admission and execution.** A VM manifest node names its target by address, and an address is public — naming one is evidence of nothing. Each method a package publishes declares whether reaching it requires an identity: `deposit` does not, because being paid is not a decision the recipient makes, while `withdraw` and the entropy stamp do, because spending an account's funds and writing its leaves are. A guarded node must present a claim, and an intent's own signature resolves to the claim on the account that intent acts as — so moving a second party's funds takes an intent that party's account signed, and an ordinary transfer still settles under the sender's single signature. That much reads only signed content and content-addressed package metadata, never state, so it sits beside the rest of derivation, ahead of ordering and ahead of any fee exposure: an envelope presenting nothing where something is required never enters a block and nobody pays for it (INV-VM-AUTH-1). Whether the keys behind that signature may act as the account is the account's own shard's question, judged against its stored rule at materialization before any body runs (INV-VM-AUTH-6). Whether the claim a call presents is the one its target requires is the target's own question, answered at execution against the target's state, and a call presenting anything else aborts with its sender paying the ceiling they signed (INV-VM-AUTH-2). Accessibility is a declaration the package makes about its own methods, carried in the metadata section its content address covers, so no transaction can weaken it and every shard reads the same one.

## 2. Provision: proven state transfer

When a source shard commits a block containing cross-shard transactions, its proposer broadcasts **`Provisions`** to each destination shard — one bundle per (source block, destination shard):

- Per transaction: the substate values the destination needs (`entries`, canonically sorted) and nothing else — a bundle carries state, never a claim about where state lives (§5).
- A JMT merkle **multiproof** over all carried substates against the source block's state root.

A bundle carries the **read set and nothing else**: fresh reads, and the prior values of read-modify-write keys. A blind write provisions nothing because the destination never needs what it is about to overwrite; an increment provisions nothing because it never reads the value it adds to; a reservation's feasibility is judged where the reserved substate lives. A leg whose dependency set is empty dispatches immediately rather than waiting on a bundle that would carry no state.

An empty bundle is still emitted, and that is a second job the same wire edge does. A counterpart engages a cross-shard transaction only against evidence that the shard paying its fee committed it, and that evidence is exactly the payer's bundle bound to its source block through the header's `provision_tx_roots`, consumable only against a commit-proven header (INV-VM-HOST-1). Every other participant echoes its own commitment back to the payer the same way, which is what lets the payer's single vote be a pure function of its own chain (INV-VM-HOST-3).

Verification at the destination is two-stage and entirely artifact-based. The source block's header is already held and QC-verified via remote-header sync ([03-state-and-sync.md](03-state-and-sync.md) §6), so verifying a provision bundle means one QC check per source block plus merkle verification of every entry against the attested state root. A provision is a *proof about a committed remote block* — no node in the source shard is trusted, only its quorum (INV-EXEC-10). Verified provisions are persisted and flow into tick composition.

**The header also pre-announces.** Source block headers carry per-destination `provision_tx_roots`, so a destination knows what to expect and can detect absence — absence of data, unlike presence, needs an announcement to be actionable. Execution certificates need no such announcement: a shard's own tick names the participants party to each of its members, so the certificates it is owed are a question about its own state.

## 3. Execute and certify: outcome agreement by determinism

At the destination (and symmetrically on every participant), a committed cross-shard transaction joins the first **tick** composed after its provisions complete. Execution merges local snapshot state with the provisioned remote entries and hands the tick's whole batch to the kernel's batch executor at once.

Determinism across shards is engineered, not assumed:

- **Same inputs.** All participants execute from the same declared set and the same provisioned entries (QC-attested), under the same per-transaction environment: the clock and the randomness draw are anchored on the payer shard's committing block, locally available there and riding the payer's bundle everywhere else, so one transaction executes under one environment on every participant.
- **Same engine, same outputs.** The engine's output is projected to a shard-invariant form (`CachedOutput`): the receipt hash, application events, and outcome are identical everywhere; only the *database updates* are then filtered per shard (each shard persists writes for the nodes it owns). All failures collapse to one canonical failed-receipt hash.
- **Same bounds.** A transaction can only write what its declared effects reach, so no execution-internal nondeterminism has a path into committed state (INV-EXEC-9).

Validators vote on the tick's `global_receipt_root`; 2f+1 matching votes form the shard's **ExecutionCertificate** with the explicit per-transaction outcome vector, each success outcome carrying its transaction's receipt hash. A tick finalizes per transaction, from the ECs collected local and remote: a transaction succeeds only with a success outcome from **every** participating shard, and an abort outcome from any shard is terminal. Abort is dominant; success is unanimous. Every EC binds its root to its outcome vector (recompute-on-decode, INV-EXEC-2), and deterministic execution means honest quorums attest identical per-transaction receipt hashes, so divergent success content cannot arise within the committee-honesty premise. Atomic commitment is enforced by the unanimity rule over attested outcomes (INV-EXEC-1). The `Finalization` (every participant's certificate plus the attested local receipts) then rides in a subsequent block, locks release, and the transaction is terminal.

## 4. Aborts: deterministic, total, timely

Every path to abort is a pure function of committed chain state, so all replicas — and all shards — reach the same verdict:

- **Payer deadline.** A VM payer's own leg has no dependencies, so nothing outside the transaction gates it — and it must not run before it knows which verdict it owes, because the tick that runs it is the tick that attests it. It therefore joins a tick once every counterpart's engagement echo has committed on the payer's own chain, or once its signed validity window closes without them; in the second case the tick attests the all-abort carrying the fee record (INV-VM-HOST-3). Both conditions read only the payer's chain, so its committee cannot split into vote buckets, and a counterpart engaging at the window's edge resolves through abort dominance rather than as a verdict split.
- **Reshape-boundary aborts.** When a participating shard terminates in a split/merge, the settled-set fence decides every straddler from frozen chain content ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).
- **Abandonment.** A transaction the fence refused, or one whose batch no surviving execution state can finish, reaches no outcome by any path above. Each shard folds the transactions it has committed and not resolved from its own committed chain, and attests the ones past their own deadline — `validity_range` end plus `MAX_FINALIZATION_DELAY` — as `Aborted` in a later tick. The trigger is chain content on every replica, so the committee signs one verdict rather than each node reporting its own ([02-dynamic-sharding.md](02-dynamic-sharding.md) §4).

Abort is a first-class terminal outcome inside the EC's outcome vector — an aborted cross-shard transaction is *agreed aborted* with the same finality as a success.

## 5. Placement: a seam the key format closes

A substate key **is** its placement: the owner's prefix is the leading half of the key, so which shard owns a cell is a property of the cell's name. Remote-owned keys reach a participant only through provisions and local keys only through its own snapshot, so there is nothing to transfer, no precedence rule to arbitrate, and no contested claim to abort on.

That is worth stating as a closed seam rather than an absent feature, because the alternative was load-bearing and had a cost. Resolving ownership at execution time means a participant has to be *told* where a remote object lives, and a claim carried between shards has to be attested. Substate values prove into the QC-attested state root; a claim about ownership does not, and attesting one at transaction-hash granularity leaves a window in which a Byzantine source committee member's claims reach a destination's execution — contained to liveness only because every shard applies identical rules to identical bytes. Closing that by making the claim unnecessary beats attesting it, and it is the key format rather than any protocol machinery that does so.

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

1. **Admission.** Both shards admit it (routing by declared keys); a non-payer shard parks it until its payer's engagement evidence commits.
2. **Ordering.** A and B each commit it in a block, independently — there is no cross-shard coordination in consensus itself. Locks engage on both sides.
3. **Provisioning.** A's proposer sends B a proven bundle of A's declared substates (and vice versa). Each side verifies against the other's QC-attested header.
4. **Execution.** Both sides now hold identical merged inputs; both execute; both compute the same receipts and the same `global_receipt_root`.
5. **Certification.** A's committee quorum-signs EC_A; B's signs EC_B; the certificates cross by gossip/fetch.
6. **Finalization.** Each side assembles the `Finalization` carrying {EC_A, EC_B}, checks root equality, commits it into a later block, releases locks. The transaction is terminal — identically — on both shards.

Any deviation lands in an abort path whose verdict both sides compute identically: the payer deadline, abandonment at the transaction's own deadline, or — if one shard terminates in a reshape — the settled-set fence.

## 8. Properties

The atomic-commitment invariants this document motivates — INV-EXEC-1 through INV-EXEC-10 — are stated precisely in [08-invariants.md](08-invariants.md); the VM's authority rules INV-VM-AUTH-1 and INV-VM-AUTH-2 are stated in the VM register, [vm/docs/09-invariants.md](../vm/docs/09-invariants.md).
