//! Action types for the deterministic state machine.

mod consensus;
mod execution;
mod provisions;

use std::sync::Arc;
use std::time::Duration;

pub use consensus::ConsensusAction;
pub use execution::ExecutionAction;
use hyperscale_dispatch::DispatchPool;
use hyperscale_engine::legs::Member;
use hyperscale_storage::{CommittedHere, MemberInputs, TickResolution};
use hyperscale_types::{
    BeaconWitnessCommit, BlockHash, BlockHeight, CertifiedBlock, DeclaredRange, Epoch,
    EscrowedValue, Finalization, FrontierInputs, HeaderFetchCount, PriceTable, ReadFence,
    SettledTxsRoot, ShardId, SharedTransactions, SplitChildRoots, StateClaim, StateRoot,
    SubstateEntry, SubstateKey, SweepFrontier, TickId, Transaction, TransactionStatus, TxHash,
    ValidatorId, Verifiable, Verified, WeightedTimestamp,
};
pub use provisions::ProvisionAction;

use crate::{CommitSource, FetchIds, FetchRequest, ProtocolEvent, TimerId};

/// What a [`ConsensusAction::VerifyQcSignature`] answers, echoed back on
/// [`ProtocolEvent::QcSignatureVerified`].
///
/// A block's own QC and the `parent_qc` its header carries certify different
/// blocks, and one block can have both in flight at once (its header arrived
/// through consensus while sync fetched it with its QC), so the result names
/// which of the two it settles rather than the block alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QcSubject {
    /// The `parent_qc` in this block's header, which certifies its parent.
    /// Verifying it gates the vote on this block.
    ParentOf(BlockHash),
    /// The QC sync fetched alongside this block, which certifies the block
    /// itself.
    SyncedBlock(BlockHash),
    /// A certificate over a block this replica does not hold, cited by a
    /// peer: a header's `parent_qc`, an announced QC or a timeout's
    /// carried high QC. Verifying it gates the block sync toward the
    /// height it certifies.
    SyncClaim(SyncClaimId),
}

/// The number the shard coordinator gives a sync claim, so a verification
/// result reaches the claim that dispatched it and not a later one from
/// the same peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncClaimId(pub u64);

/// What a block that arrives as a proposal is held to at its parent,
/// beside the root.
///
/// The two rules that read this validator's own view of the moment the
/// block was made. They are asked of every block the vote pipeline
/// checks, one this validator will not vote on included, and a refusal
/// drops the pending block and the state-root checks deferred on it, and
/// no more: a block a quorum certifies commits on that certificate
/// whatever was answered here, and the check that runs for a block
/// committed that way carries none of this.
#[derive(Debug, Clone)]
pub struct ParentJudgement {
    /// The block's read fence: its record presences, its absences and
    /// the answers its absences delete.
    pub fence: ReadFence,
    /// Whether the schedule lets a block at this anchor only coast, so
    /// its sweep must hold the parent's frontier rather than walk from
    /// it.
    pub coasting: bool,
}

/// What one block's state-root verification takes.
///
/// The block, its parent's state, and every claim checked beside the
/// root. The shard coordinator resolves it against its chain view once
/// the parent's tree is ready, and the state-root handler reads it.
#[derive(Debug, Clone)]
pub struct StateRootCheck {
    /// Block whose state root is being verified.
    pub block_hash: BlockHash,
    /// The block's transactions, whose fees the parent state judges.
    pub transactions: SharedTransactions,
    /// Parent block hash — used to walk the snapshot chain for the overlay.
    pub parent_block_hash: BlockHash,
    /// Base state root (parent block's `state_root`).
    pub parent_state_root: StateRoot,
    /// Height of the parent block (stable anchor for JMT computation).
    pub parent_block_height: BlockHeight,
    /// Expected state root after applying writes.
    pub expected_root: StateRoot,
    /// Finalizations whose receipts the state root covers. The thread
    /// pool merges the receipts' writes from these.
    pub finalizations: Vec<Verifiable<Finalization>>,
    /// The committed markers the block writes, derived by the
    /// coordinator from its transactions and the chain's origin. They
    /// fold with the receipts' writes under the root being verified,
    /// and a row whose own or inherited key the parent state holds
    /// refuses the block.
    pub creations: Vec<CommittedHere>,
    /// Block height being verified.
    pub block_height: BlockHeight,
    /// The header's `split_child_roots` claim, verified beside the
    /// state root.
    pub claimed_split_child_roots: Option<SplitChildRoots>,
    /// Whether the block's window requires the claim (the shard's
    /// final epoch before a split), resolved by the coordinator from
    /// the schedule.
    pub split_child_roots_required: bool,
    /// Whether the block's window requires the terminal settled root —
    /// set on any terminating boundary header (a split parent's or a
    /// merge child's final epoch), broader than
    /// `split_child_roots_required`.
    pub terminal_settled_txs_required: bool,
    /// The header's `terminal_settled_txs` claim, recomputed beside the
    /// state root over the committed retention window when the block
    /// terminates the shard at a boundary.
    pub claimed_terminal_settled_txs: Option<SettledTxsRoot>,
    /// The block's parent-QC weighted timestamp — the anchor the
    /// settled-transaction window walk floors at (`anchor − RETENTION_HORIZON`),
    /// resolved identically by the proposer and every verifier.
    pub parent_weighted_timestamp: WeightedTimestamp,
    /// Where the parent's sweep stopped, which the block's starts
    /// above.
    pub parent_sweep_frontier: SweepFrontier,
    /// The header's own `sweep_frontier` claim.
    ///
    /// A voter recomputes it beside the state root, and the
    /// recomputation is the whole check: a walk from the parent's
    /// frontier under the cap lands on exactly one position, so a
    /// frontier that matches came from the same removal set, and one
    /// that does not is either an incomplete sweep or an overreaching
    /// one. It also carries the obligation to advance, since a
    /// proposer that swept nothing while cells sat below the clock
    /// lands short of where the walk does.
    ///
    /// For a certified block it is the upper end of the interval the
    /// block removed, read as stated.
    pub claimed_sweep_frontier: SweepFrontier,
    /// The schedule's settled-window floor for the shard at the block's
    /// anchor — extends the settled-transaction window back to the reshape's
    /// admission, covering every settlement a counterpart fence can
    /// still hold a straddler against. `None` when no retained window
    /// records one.
    pub settled_txs_window_floor: Option<WeightedTimestamp>,
    /// What the block's claims do to the read frontier, folded under
    /// the root being verified.
    pub frontier: FrontierInputs,
    /// What the block writes to tick membership, folded under the
    /// root being verified.
    pub members: MemberInputs,
    /// What a voter holds the block to at the parent. A refusal by
    /// it, or by any other parent rule, refuses the state root.
    ///
    /// `None` for a block a quorum has already certified, which is
    /// not judged at the parent at all: its voters judged it, the
    /// block commits on its certificate whatever this replica would
    /// say, and a replica that never voted on it may not route its
    /// transactions, which the parent rules read, nor hold the
    /// schedule its proposer built under, which the sweep rule
    /// reads.
    pub parent_judgement: Option<ParentJudgement>,
    /// The block's claims, whose readings license the crossing
    /// settlements folded under the root, and among which the
    /// parent-anchored ones are re-read from the verifier's own
    /// parent view.
    pub state_claims: Vec<StateClaim>,
}

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The transaction to execute.
    pub transaction: Verified<Transaction>,
    /// State entries provisioned by other shards (one `Arc` per source shard
    /// contribution). Engine layers them on top of the local snapshot.
    pub provisions: Vec<Arc<Vec<SubstateEntry>>>,
    /// The transaction clock: the payer-shard committing block's
    /// parent-QC weighted timestamp. On the payer's own shard this is
    /// the tick anchor; elsewhere it is the value the payer's
    /// bundle carried, so every participant executes the transaction
    /// under one clock.
    pub clock: WeightedTimestamp,
    /// The price table the transaction's committing block anchored to.
    ///
    /// Carried for the reason [`Self::clock`] is, and it is the same
    /// reason: the fee lands in a receipt every participant derives, so
    /// a table read off the executing node's head would price one
    /// transaction differently on two shards — and differently again on
    /// one shard replaying the tick after a fold moved the level. The
    /// committing block's window is the one anchor every participant
    /// shares.
    pub prices: PriceTable,
    /// The transaction as classified when its block committed —
    /// carried, never re-derived. What it says of the member is what the
    /// batch reads: whether the transaction reaches beyond this shard,
    /// which makes a member's provisions and arrivals necessary and its
    /// writes filtered to the subtree this shard owns; and whether a
    /// counterpart's verdict can still discard its effects, which makes
    /// its contributions provisional, readable by no later tick until
    /// the verdict resolves them, and its declared cells a claim a later
    /// member must compose with.
    pub member: Member,
    /// What committed bundles attested for the edges this shard's legs
    /// consume, read off the record cells they proved. Empty for a
    /// member that runs the whole shape.
    pub arrivals: Vec<EscrowedValue>,
}

/// A change to the local vnode's reshape-observer duty, carried on
/// [`ParticipationChange::observe`].
///
/// An observer rides the splitting shard's committee for transport but
/// never its consensus subset; its physical work is a child-rooted
/// store synced over the child's key span, served by the splitting
/// shard's committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveDelta {
    /// Drawn into the cohort of `via`'s pending split: open a store
    /// rooted at `child`'s prefix and sync the child's span.
    Begin {
        /// The splitting shard whose committee carries the seat.
        via: ShardId,
        /// The pending child the observer syncs.
        child: ShardId,
    },
    /// The seat was released without executing — the trigger went
    /// quiet or the readiness TTL elapsed: abandon the observation.
    Abandon {
        /// The splitting shard whose committee carried the seat.
        via: ShardId,
        /// The pending child the observer was syncing.
        child: ShardId,
    },
}

/// A change to the local vnode's reshape-keeper duty, carried on
/// [`ParticipationChange::keep`].
///
/// A keeper stays an ordinary member of its child for transport and
/// consensus; its extra physical work is a new `parent`-rooted store —
/// its own child half hard-linked, the `sibling` half synced from the
/// sibling committee, the root stitched — built so the merged chain can
/// start instantly at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepDelta {
    /// Drawn as a keeper of the pending merge under `parent`: build the
    /// merged store, syncing the `sibling` half this keeper doesn't run.
    Begin {
        /// The merged parent this keeper reforms.
        parent: ShardId,
        /// The sibling child whose half the keeper must sync.
        sibling: ShardId,
    },
    /// The merge was cancelled before executing — a required half went
    /// quiet: abandon the keep and drop the half-built merged store.
    Abandon {
        /// The merged parent the keeper was reforming.
        parent: ShardId,
    },
}

/// A beacon-driven change to one vnode's physical shard participation,
/// detected on the lookahead committees one epoch before it takes
/// effect.
///
/// Carried by [`crate::BeaconAction::ReconfigureParticipation`] out of the state
/// machine to whoever owns physical shard membership — the production
/// shard supervisor, or the simulation harness via `StepOutput`. The
/// consumer starts bootstrapping `joins` immediately (snap-sync + tail
/// sync need the lookahead epoch) and schedules `leaves` for the
/// window close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationChange {
    /// The vnode whose placement changed.
    pub validator: ValidatorId,
    /// Shard the validator is placed on at `effective_epoch` but not in
    /// the active window. A validator sits on at most one shard
    /// (`ValidatorStatus::OnShard` is singular), so a placement change
    /// is at most one join plus one leave; at least one of `join`,
    /// `leave`, and `observe` is `Some`. An observer seat never reads
    /// as a placement — a cohort draw surfaces only through `observe`.
    pub join: Option<ShardId>,
    /// Shard the validator is on in the active window but not at
    /// `effective_epoch`.
    pub leave: Option<ShardId>,
    /// Observer-duty delta. `Begin` accompanies no join (observers are
    /// drawn from the pool); `Abandon` can accompany a `join` of the
    /// same shard, when a pool draw immediately re-places the released
    /// observer there as a regular member.
    pub observe: Option<ObserveDelta>,
    /// Keeper-duty delta. A keeper is already a member of its child, so
    /// `Begin`/`Abandon` accompany no placement change — the merge's
    /// execution surfaces the keeper's move onto the parent as the
    /// ordinary join/leave pair instead.
    pub keep: Option<KeepDelta>,
    /// Epoch whose window activates the new placement.
    pub effective_epoch: Epoch,
}

/// A single cross-shard transaction's provisioning needs.
///
/// Collected per-block and emitted via [`ProvisionAction::FetchAndBroadcastProvisions`].
#[derive(Debug, Clone)]
pub struct ProvisionsRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The shards this request serves a bundle to.
    pub targets: Vec<ShardId>,
    /// The locally owned keys of the transaction's read set (fresh
    /// reads and read-modify-write priors) to serve. A request with
    /// none still stages its transaction: the payer shard's bundle is
    /// the engagement evidence and flows with empty entries.
    pub local_keys: Vec<SubstateKey>,
    /// The locally owned collection intervals of the same read set,
    /// served as the entry leaves the interval holds at the source
    /// height.
    pub local_ranges: Vec<DeclaredRange>,
}

/// What a shard replica asks its loop to do.
///
/// Actions are **commands** - they describe something to do. Work the
/// loop hands to a dispatch pool is typed by the coordinator crate that
/// runs it; every other variant the loop carries out inline. The runner
/// may convert results back into events.
#[derive(Debug, Clone, strum::IntoStaticStr)]
#[allow(clippy::large_enum_variant)] // mixed-size variants; boxing every large variant adds allocations on the hot dispatch path
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Delegated work (off the loop's thread, returns callback events)
    // ═══════════════════════════════════════════════════════════════════════
    /// Shard consensus work, run by `hyperscale_shard`.
    Consensus(ConsensusAction),
    /// Execution work, run by `hyperscale_execution`.
    Execution(ExecutionAction),
    /// Provision work, run by `hyperscale_provisions`.
    Provisions(ProvisionAction),

    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// Set a timer to fire after a duration.
    SetTimer {
        /// Timer slot to set; replaces any previous timer with the same id.
        id: TimerId,
        /// How long until the timer fires.
        duration: Duration,
    },

    /// Cancel a previously set timer.
    CancelTimer {
        /// Timer slot to cancel.
        id: TimerId,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Continuation (fed back as ProtocolEvent with Internal priority)
    // ═══════════════════════════════════════════════════════════════════════
    /// A continuation event to be fed back into the state machine.
    ///
    /// The state machine emits this when processing one event produces
    /// a follow-on protocol event that should be processed immediately
    /// (at the same timestamp with Internal priority).
    ///
    /// The I/O loop reroutes a `Continuation` through `event_sender`,
    /// where it re-enters the next `step()` as a [`ProtocolEvent`] and
    /// reaches the one replica of the emitting shard loop. Signers
    /// attached to that replica see it only through what the replica
    /// does with it.
    Continuation(ProtocolEvent),

    /// Resolve tick fates on the tick chain: promote a settled transaction's
    /// provisional entries into the readable fold, or drop an aborted
    /// tick's. Applied synchronously on the shard thread so a dispatch
    /// action emitted later in the same commit reads the resolved chain.
    ResolveTicks {
        /// Tick fates that became known at this commit, in emission order.
        resolutions: Vec<(TickId, TickResolution)>,
    },

    /// Tear down the tick chain at a reshape terminal: the shard's chain
    /// ends and successors seed from settled state, never from tick
    /// outputs.
    ClearTickChain,

    /// Raise the tick chain floor to the parent height of a recovery's
    /// crossing block: no tick above it reads a contribution at or below
    /// it, and a run of a tick at or below it lands nothing.
    RaiseTickFloor {
        /// The crossing block's parent height.
        floor: BlockHeight,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Block Commit
    // ═══════════════════════════════════════════════════════════════════════
    /// Commit a consensus block via its `PreparedCommit` (from `BuildProposal`
    /// or `VerifyStateRoot`). Block data + JMT + substates + receipts + ECs +
    /// consensus metadata are written atomically.
    CommitBlock {
        /// Block + certifying QC, with the full
        /// [`Verified<CertifiedBlock>`] predicate already established
        /// upstream of dispatch. The IO-loop threads this directly
        /// into the `BlockCommitted` event without re-establishing the
        /// predicate.
        certified: Arc<Verified<CertifiedBlock>>,
        /// How this node learned the certifying QC (aggregator vs header).
        source: CommitSource,
        /// Beacon-witness leaves to persist alongside the block in the
        /// same atomic write. Carries the appended payloads, their
        /// accumulator-start index, and the resulting
        /// `leaf_count_at_block_end` stamped into the block's metadata.
        witness: BeaconWitnessCommit,
        /// The committed block's committee anchor — its parent's own
        /// anchor — which classifies its content downstream. Carried from the
        /// commit rather than read at fan-out, because a buffered run commits
        /// in one step and a scalar read afterwards names only its last block.
        committee_anchor: WeightedTimestamp,
    },

    /// Commit a block trusted via QC only — no cached `PreparedCommit` exists
    /// because this node's own state root verification has not landed: an
    /// aggregator that formed the QC without voting, or a sync-admitted
    /// block whose verification is still in flight at its commit.
    ///
    /// The `io_loop` computes the `PreparedCommit` inline and asserts the
    /// computed root matches the block's declared root (same Byzantine
    /// detection as async `VerifyStateRoot`), then feeds into the normal
    /// `flush_block_commits` pipeline for async `RocksDB` persistence.
    CommitBlockByQcOnly {
        /// Block + certifying QC. On the sync path the
        /// [`Verified<CertifiedBlock>`] predicate is established by
        /// BFT-transitive trust in the source committee's QC (see
        /// [`Verified::<CertifiedBlock>::from_qc_attestation`]) rather
        /// than by local per-root verification.
        certified: Arc<Verified<CertifiedBlock>>,
        /// Parent block's state root — base state for JMT computation.
        parent_state_root: StateRoot,
        /// Parent block's height — JMT parent version.
        parent_block_height: BlockHeight,
        /// Where the parent's sweep stopped. The block removed what lies
        /// above it up to the frontier its own header names.
        parent_sweep_frontier: SweepFrontier,
        /// The committed cells the block writes, derived by the
        /// coordinator under the block's own window — the one placement
        /// fact the recomputation reads beyond the block, resolved where
        /// the schedule is.
        creations: Vec<(SubstateKey, Vec<u8>)>,
        /// What the block's claims do to the read frontier, folded under
        /// the root the recomputation checks.
        frontier: FrontierInputs,
        /// How this node learned the certifying QC (aggregator vs header).
        source: CommitSource,
        /// Beacon-witness leaves to persist alongside the block in the
        /// same atomic write — see [`Self::CommitBlock`].
        witness: BeaconWitnessCommit,
        /// The committed block's committee anchor — its parent's own
        /// anchor — which classifies its content downstream. Carried from the
        /// commit rather than read at fan-out, because a buffered run commits
        /// in one step and a scalar read afterwards names only its last block.
        committee_anchor: WeightedTimestamp,
    },

    /// Attach a certified-but-not-yet-committed block to the pending
    /// chain's serving surface. Emitted as soon as a QC verifies against
    /// a held pending block, so block sync can serve the certified tip
    /// to a peer that missed its body — a tip commits only once a child
    /// certifies at the next round, and a peer wedged below the tip may
    /// be exactly the vote that child needs. Fetchers adopt the served
    /// QC without committing on it, so serving a certified sibling that
    /// later loses its round is safe.
    AttachCertifiedUncommitted {
        /// Block + certifying QC.
        certified: Arc<Verified<CertifiedBlock>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // RPC Status / Telemetry
    // ═══════════════════════════════════════════════════════════════════════
    /// Emit transaction status update for RPC status cache.
    ///
    /// Emitted by the mempool whenever a transaction's status changes:
    /// - Pending: Transaction accepted into mempool
    /// - Committed: Transaction included in a committed block
    /// - Executed: Transaction execution complete (accept/reject decision made)
    /// - Completed: Finalization committed, can be evicted
    /// - Deferred: Transaction deferred due to cross-shard livelock
    /// - Retried: Transaction superseded by retry transaction
    ///
    /// The production runner updates the RPC status cache when processing
    /// this action, allowing clients to query transaction status via the
    /// `GET /api/v1/transactions/{hash}` endpoint.
    ///
    /// Latency tracking and phase-time stamping live in the `io_loop`, not
    /// here — the mempool only emits the status itself, and the `io_loop`
    /// stamps wall-clock against its own side cache (`tx_phase_times`)
    /// keyed by `tx_hash`.
    EmitTransactionStatus {
        /// Transaction whose status changed.
        tx_hash: TxHash,
        /// New transaction status.
        status: TransactionStatus,
        /// Whether this is a cross-shard transaction (for metrics labeling).
        cross_shard: bool,
        /// Whether this transaction was submitted locally (via RPC) vs received via gossip/fetch.
        /// Only locally-submitted transactions should contribute to latency metrics.
        submitted_locally: bool,
    },

    /// Notify the `io_loop` that a local execution certificate was just
    /// formed for `tx_hashes`. The `io_loop` stamps `ec_created_at` in its
    /// per-tx phase-time side cache, used for the slow-tx finalization
    /// log. State-machine state isn't affected — this is pure telemetry.
    RecordTxEcCreated {
        /// Transactions whose EC was just formed.
        tx_hashes: Vec<TxHash>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Read Requests (returns callback ProtocolEvent)
    // ═══════════════════════════════════════════════════════════════════════
    /// Restore committed state (height, hash, QC) from local storage.
    ///
    /// Issued at startup as a recovery bootstrap — the runner reads chain
    /// metadata from `RocksDB` and replies with
    /// `ProtocolEvent::CommittedStateRestored { height, hash, qc }`.
    RestoreCommittedState,

    // ═══════════════════════════════════════════════════════════════════════
    // Runner I/O Requests
    // These request the runner to perform network I/O. Sync responses
    // arrive as `ShardScopedInput::BlockSyncResponseReceived`; fetch protocol
    // responses arrive as `ProtocolEvent::*Received` variants.
    // ═══════════════════════════════════════════════════════════════════════
    /// Request the runner to start syncing to a target height.
    ///
    /// Emitted when the state machine detects it's behind (e.g., receives a
    /// block header or QC ahead of committed height). The runner handles
    /// peer selection, fetching, validation, and delivers blocks via
    /// `ProtocolEvent::BlockSyncReadyToApply`.
    StartBlockSync {
        /// The height we need to sync to.
        target: BlockHeight,
    },

    /// Tell block sync that `height` is in chain state with its commit
    /// pending: the FSM holds it out of the fetch window and counts it
    /// toward completion.
    SyncBlockApplied {
        /// The height `apply_synced_block` admitted.
        height: BlockHeight,
    },

    /// Tell block sync to fetch `height` again: a certified sibling of
    /// the block applied there exists, and the chain builds on it
    /// instead.
    ReopenSyncHeight {
        /// The height whose applied block a child's parent QC bypasses.
        height: BlockHeight,
        /// The certified sibling the chain builds on at `height` — the
        /// only block the fetch accepts, since the requester's own store
        /// still answers the height with the one it applied.
        hash: BlockHash,
    },

    /// Tell block sync to stop at what it holds: the target it was raised
    /// to is served by nobody reachable, and the scope completes at its
    /// frontier. A later `StartBlockSync` raises the target again.
    SettleBlockSync,

    /// Request the runner to start (or raise the target of) remote-header
    /// sync for `source_shard`. The runner's `RemoteHeaderSync`
    /// emits range fetches and feeds verified headers back to
    /// [`crate::ProtocolEvent::VerifiedRemoteHeaderReceived`].
    StartRemoteHeaderSync {
        /// Remote shard whose certified header chain we're catching up to.
        source_shard: ShardId,
        /// Highest known target height for that shard's chain.
        target: BlockHeight,
    },

    /// Fetch the certified-header run that commit-proves one remote block.
    ///
    /// Emitted by `RemoteHeaderCoordinator` when a cross-shard consumer is
    /// parked on a source height at or below the shard's attested boundary —
    /// below the remote-header sync anchor, where forward sync never
    /// reaches. The runner issues one range fetch starting at the height;
    /// the returned headers feed the normal QC-verification path and the
    /// commit-proof walk promotes the block, draining the parked consumer.
    FetchCommitProof {
        /// Remote shard whose block needs commit-proving.
        source_shard: ShardId,
        /// The parked source height — the fetch range start.
        from_height: BlockHeight,
        /// Range length. Grows across retries so a round-gapped run (the
        /// committing two-chain sits several certified blocks above the
        /// height) is eventually covered.
        count: HeaderFetchCount,
    },

    /// Issue a network fetch via one of the unified fetch protocols.
    ///
    /// Replaces the family of flat `Fetch*` / `RequestMissing*` variants —
    /// `io_loop`'s dispatcher matches the inner [`FetchRequest`] and dispatches
    /// to the corresponding binding. Admission events (`Continuation(*Admitted
    /// /*Verified)`) drain ids that arrived; explicit cancellation flows
    /// through [`Self::AbandonFetch`] when a consumer's expected-set drops a
    /// key without it ever being admitted.
    Fetch(FetchRequest),

    /// Cancel in-flight fetches the originating coordinator no longer wants.
    ///
    /// Symmetric to [`Self::Fetch`]: the node feeds the ids through
    /// `FetchInput::Abandoned` on the binding that fetches them. Emitted by
    /// coordinators at every expected-set drop site (verification
    /// succeeded, retention-horizon orphan cleanup, deadline eviction).
    AbandonFetch(FetchIds),

    /// Offer transactions this chain never included to whatever holds
    /// their keys now.
    ///
    /// Emitted by a chain quiescing at a reshape boundary, for the pool
    /// entries its terminal sweep does not reach. Repeated a few times
    /// while it awaits its successors and once more when they are live: the
    /// successors seat from the terminal cut, well ahead of the fold that
    /// shows them live, so an early offer usually lands and waiting for
    /// that fold would leave a client watching `Pending` for an epoch or
    /// two. The runner routes each through the same fan-out a client
    /// submission takes, so they resolve against the *current* topology
    /// and land on the successor that now owns the payer rather than on
    /// the committee that is shutting down.
    ///
    /// Best effort in both directions and safe in both. A seat that
    /// hosts no successor drops its copy, and the seats that continue
    /// cover it; a duplicate is deduplicated at admission; and a
    /// transaction the terminating chain did commit is refused by the
    /// successor's pre-cut rule against the predecessor's committed set.
    ReofferTransactions {
        /// Transactions to put back in front of the network.
        txs: Vec<Transaction>,
    },
}

impl Action {
    /// The action type name for telemetry: delegated work by its own
    /// name.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Consensus(action) => action.type_name(),
            Self::Execution(action) => action.type_name(),
            Self::Provisions(action) => action.type_name(),
            other => other.into(),
        }
    }
}

/// Work a shard loop hands to a dispatch pool, run by the coordinator
/// crate whose type it is.
pub trait Delegated: Send + 'static {
    /// The pool the work runs on. Consensus work runs on the
    /// liveness-critical pool; execution and provision work share the
    /// throughput-bound one.
    const POOL: DispatchPool;

    /// The action type name for telemetry.
    fn type_name(&self) -> &'static str;

    /// The shard signer whose key signs this work, or `None` for work no
    /// shard signer signs. For envelope-only work (see
    /// [`Self::envelope_only`]) it names the preferred signer.
    fn signer(&self) -> Option<ValidatorId>;

    /// Whether the signature only authenticates the envelope of a
    /// self-authenticating payload, so any attached committee signer may
    /// sign in place of the preferred one.
    fn envelope_only(&self) -> bool;
}
