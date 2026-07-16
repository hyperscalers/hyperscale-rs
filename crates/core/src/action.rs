//! Action types for the deterministic state machine.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_dispatch::DispatchPool;
use hyperscale_types::{
    BeaconBlockHash, BeaconState, BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot,
    BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PublicKey,
    CandidateBeaconBlock, CertificateRoot, CertifiedBeaconBlock, CertifiedBlock,
    CertifiedBlockHeader, Epoch, ExecutionCertificate, ExecutionVote, FinalizedWave,
    GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, NodeId, PcQc1, PcQc2, PcVector,
    PcVote1, PcVote2, PcVote3, PcVoteEquivocation, ProposerTimestamp, ProvisionHash,
    ProvisionTxRootsMap, Provisions, ProvisionsRoot, QuorumCertificate, RatifyPhase, RatifyRound,
    RatifyVote, ReadySignal, ReshapeThresholds, ReshapeTrigger, Round, RoutableTransaction,
    RoutingCommittees, SafeVoteRegisters, SettledWavesRoot, ShardId, ShardWitnessPayload,
    SharedCertificates, SharedTransactions, SpcEmptyViewMsg, SpcHighTriple, SpcNewCommitMsg,
    SpcProposalObject, SpcView, SplitChildRoots, StateRoot, SubstateEntry, Timeout,
    TopologySnapshot, TransactionRoot, TransactionStatus, TxHash, TxOutcome, ValidatorId,
    Verifiable, Verified, VoteCount, VrfProof, WaveId, WeightedTimestamp,
};

use crate::{CommitSource, FetchAbandon, FetchRequest, ProtocolEvent, TimerId};

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The transaction to execute.
    pub transaction: Arc<Verified<RoutableTransaction>>,
    /// State entries provisioned by other shards (one `Arc` per source shard
    /// contribution). Engine layers them on top of the local snapshot.
    pub provisions: Vec<Arc<Vec<SubstateEntry>>>,
    /// Authoritative `vault → owning_account` map for this tx's declared
    /// accounts, assembled by merging each source shard's
    /// `ProvisionEntry::owned_nodes`. The executor uses this directly
    /// instead of rediscovering ownership by walking the merged view —
    /// whose coverage depends on which partitions each source shipped
    /// and is therefore not shard-invariant.
    pub ownership: HashMap<NodeId, NodeId>,
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
/// Carried by [`Action::ReconfigureParticipation`] out of the state
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
/// Collected per-block and emitted via [`Action::FetchAndBroadcastProvisions`].
#[derive(Debug, Clone)]
pub struct ProvisionsRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// Nodes owned by our shard whose state we need to provision.
    pub local_nodes: Vec<NodeId>,
    /// Per-target-shard nodes this tx reads from each remote shard.
    /// Used to populate `ProvisionEntry::target_nodes` for conflict detection.
    pub target_nodes: Vec<(ShardId, Vec<NodeId>)>,
}

/// Actions the state machine wants to perform.
///
/// Actions are **commands** - they describe something to do.
/// The runner executes actions and may convert results back into events.
#[derive(Debug, Clone, strum::IntoStaticStr)]
#[allow(clippy::large_enum_variant)] // mixed-size shard/beacon variants; boxing every large variant adds allocations on the hot dispatch path
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network: shard consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign and broadcast a block header (proposal) to the local shard.
    ///
    /// The `io_loop` signs the header on the consensus crypto pool before sending.
    BroadcastBlockHeader {
        /// Block header to sign and broadcast.
        header: Box<BlockHeader>,
        /// Manifest listing the block's tx / cert / provision hashes.
        manifest: Box<BlockManifest>,
    },

    /// Sign and broadcast a block vote to the next proposer(s).
    ///
    /// The `io_loop` signs the vote on the consensus crypto pool, then
    /// broadcasts to the next proposer and feeds the signed vote back
    /// to the state machine for local `VoteSet` tracking.
    SignAndBroadcastBlockVote {
        /// Block being voted on.
        block_hash: BlockHash,
        /// Parent of the voted block (from its header), bound into the vote signature.
        parent_block_hash: BlockHash,
        /// Block height.
        height: BlockHeight,
        /// Round at which the vote is being cast.
        round: Round,
        /// Voter's local timestamp at vote time. Aggregated stake-weighted
        /// across votes into the QC's `weighted_timestamp` — the BFT clock.
        timestamp: ProposerTimestamp,
        /// Local-shard validators eligible to propose the next block; they
        /// need this vote to assemble the QC.
        next_proposers: Vec<ValidatorId>,
        /// The safe-vote registers as ratcheted by this vote. The runner
        /// persists them durably before the signature leaves the process,
        /// so a crash-restarted validator can never re-vote this round.
        registers: SafeVoteRegisters,
    },

    /// Sign and broadcast a timeout to the local-shard committee.
    ///
    /// Emitted when the round timer fires instead of advancing locally. The
    /// `io_loop` signs the timeout on the consensus crypto pool, broadcasts it
    /// to `recipients`, and feeds the signed timeout back to the state machine
    /// for the local `TimeoutKeeper`. On `2f+1` timeouts the committee adopts
    /// the maximum `high_qc` and advances the round together.
    SignAndBroadcastTimeout {
        /// Round being abandoned.
        round: Round,
        /// The signer's highest certified block — carried so the next leader
        /// can adopt and extend the quorum-max QC. Self-authenticating.
        high_qc: QuorumCertificate,
        /// Local-shard committee members who tally timeouts for this round.
        recipients: Vec<ValidatorId>,
        /// The safe-vote registers as ratcheted by this timeout. The runner
        /// persists them durably before the signature leaves the process,
        /// so a crash-restarted validator can never vote a round it
        /// already abandoned.
        registers: SafeVoteRegisters,
    },

    /// Sign and broadcast a "ready on shard" signal to the local committee.
    ///
    /// Emitted when block sync reaches the tip while the local validator is
    /// a committee member still outside the consensus subset. The `io_loop`
    /// signs the canonical ready-signal message and notifies `recipients`;
    /// their pools hold the signal until a proposer drains it into a block
    /// manifest and the beacon's `Ready` witness flips `ready: true`.
    SignAndBroadcastReadySignal {
        /// Shard whose synced state the signal attests readiness for — the
        /// emitting member's own shard. Bound into the signed message.
        shard: ShardId,
        /// First weighted timestamp at which the signal is eligible for
        /// inclusion.
        wt_window_start: WeightedTimestamp,
        /// Last eligible inclusion weighted timestamp; the signer re-emits
        /// if the window passes uncollected.
        wt_window_end: WeightedTimestamp,
        /// Local-shard committee members (full membership view).
        recipients: Vec<ValidatorId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Execution Layer (domain-specific, batchable by runner)
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign and send an execution vote to the wave leader for aggregation.
    ///
    /// Emitted by the state machine when a wave completes (all txs executed).
    /// The `io_loop` signs the vote (it owns the signing key) and sends it to
    /// the wave leader (unicast). The leader aggregates 2f+1 votes into an EC.
    SignAndSendExecutionVote {
        /// Block whose wave is being voted on.
        block_hash: BlockHash,
        /// Block height (for correlation).
        block_height: BlockHeight,
        /// Consensus timestamp at which this vote is being cast.
        vote_anchor_ts: WeightedTimestamp,
        /// Wave identifier whose execution is being attested to.
        wave_id: WaveId,
        /// Global receipt root over the wave's per-tx outcomes.
        global_receipt_root: GlobalReceiptRoot,
        /// Per-tx outcomes in wave order. Carried on the vote so the
        /// leader can extract them directly when building the EC.
        tx_outcomes: Vec<TxOutcome>,
        /// The wave leader who collects and aggregates votes for this wave.
        leader: ValidatorId,
    },

    /// Broadcast an execution certificate to local peers or remote shards.
    ///
    /// The wave leader broadcasts to both local committee peers (who need the
    /// EC since they don't aggregate) and remote participating shard committees.
    BroadcastExecutionCertificate {
        /// Target shard receiving the EC.
        shard: ShardId,
        /// Aggregated execution certificate.
        certificate: Arc<Verified<ExecutionCertificate>>,
        /// Target shard peers (excluding self) for the broadcast.
        recipients: Vec<ValidatorId>,
    },

    /// Fetch state entries and broadcast provisions for all cross-shard txs in a block.
    ///
    /// Only the block proposer emits this (once per block). Delegated to the
    /// execution pool where it fetches entries, generates merkle proofs, builds
    /// per-shard provision batches, groups by target shard, and returns batches via
    /// `ProtocolEvent::OutboundProvisionBroadcast` for network broadcast.
    FetchAndBroadcastProvisions {
        /// The committed block whose state is being attested to. Anchors
        /// state reads via `PendingChain::view_at`. Merkle proofs are
        /// generated against this block's state root.
        block_hash: BlockHash,
        /// One entry per cross-shard tx that needs provisioning.
        requests: Vec<ProvisionsRequest>,
        /// Shard producing the provisions (this validator's shard).
        source_shard: ShardId,
        /// Source-shard block height the provisions are anchored to.
        block_height: BlockHeight,
        /// Per-shard recipients for provision broadcasts (excluding self).
        shard_recipients: HashMap<ShardId, Vec<ValidatorId>>,
    },

    /// Sign and broadcast a committed block header globally to all shards.
    ///
    /// Used for the light-client provisions pattern. When a block commits,
    /// this broadcasts the header + QC so remote shards can verify state roots.
    /// The `io_loop` signs on the consensus crypto pool before sending.
    BroadcastCertifiedBlockHeader {
        /// Header + QC bundle to broadcast globally. The proposer builds it
        /// from its locally-verified [`Verified<CertifiedBlock>`], so the
        /// predicate holds at the emit site; the gossip wrapper preserves
        /// the marker across in-process local dispatch.
        certified_header: Verified<CertifiedBlockHeader>,
    },

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
    /// # Invariant: shard coherence
    ///
    /// The I/O loop reroutes a `Continuation` through `event_sender`,
    /// where it re-enters the next `step()` as a [`ProtocolEvent`] and
    /// fans out to **every same-shard vnode** via `dispatch_event` →
    /// `handle_protocol_passthrough`. The emitting vnode is one of the
    /// recipients but not the only one.
    ///
    /// The carried event MUST therefore be *shard-coherent* — meaningful
    /// to every same-shard vnode, not just the emitter. Any new
    /// continuation variant that is genuinely per-vnode (state only the
    /// emitter should react to) needs a different transport — emitting
    /// it via `Continuation` would silently apply it to the vnode's
    /// same-shard peers.
    Continuation(ProtocolEvent),

    // ═══════════════════════════════════════════════════════════════════════
    // Delegated Work (async, returns callback event)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verify block votes and build a Quorum Certificate if quorum is reached.
    ///
    /// This combines vote verification and QC building into a single operation:
    /// 1. Batch-verifies all vote signatures using `batch_verify_bls_same_message`
    /// 2. If enough valid votes for quorum: aggregates signatures into a QC
    /// 3. If not enough valid votes: returns the verified votes so state machine
    ///    can wait for more votes
    ///
    /// This avoids wasting CPU on votes that will never be used (e.g., when a
    /// block never reaches quorum due to view change or leader failure).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::QuorumCertificateResult` when complete.
    VerifyAndBuildQuorumCertificate {
        /// Block hash the QC would be for.
        block_hash: BlockHash,
        /// Shard group this QC belongs to.
        shard_id: ShardId,
        /// Block height.
        height: BlockHeight,
        /// Round number.
        round: Round,
        /// Parent block hash (from the block's header).
        parent_block_hash: BlockHash,
        /// Parent QC's `weighted_timestamp` — monotonicity floor applied to
        /// every vote timestamp during the (uniform) weighted-time aggregation.
        /// Without this, slow-clocked or Byzantine voters can drag the
        /// aggregated `weighted_timestamp` back below the parent's, breaking
        /// deadline pruning and validity-window monotonicity.
        parent_weighted_timestamp: WeightedTimestamp,
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (`committee_index`, vote, `public_key`).
        votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (`committee_index`, vote).
        verified_votes: Vec<(usize, Verified<BlockVote>)>,
        /// Total votes in the committee (the quorum denominator).
        total_votes: VoteCount,
    },

    /// Verify provisions' merkle inclusion proofs.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator` when the header
    /// was promoted to verified, so this only checks merkle proofs against the
    /// certified header's state root.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::StateProvisionsVerified` when complete.
    VerifyProvisions {
        /// The provisions to verify (all from the same source block).
        provisions: Provisions,
        /// The QC-verified committed block header from `RemoteHeaderCoordinator`.
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    },

    /// Aggregate execution votes into an `ExecutionCertificate` (quorum reached).
    ///
    /// Performs BLS signature aggregation on execution votes.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Wave identifier. The producing shard is `wave_id.shard_id`.
        wave_id: WaveId,
        /// Global receipt root (merkle root over per-tx outcome leaves).
        global_receipt_root: GlobalReceiptRoot,
        /// Verified votes to aggregate (with quorum). The first vote's
        /// `tx_outcomes` is used for the EC payload (all quorum votes have
        /// identical outcomes).
        votes: Vec<Verified<ExecutionVote>>,
        /// Ordered committee for the shard (for `SignerBitfield` index mapping).
        committee: Vec<ValidatorId>,
    },

    /// Batch verify execution votes (deferred verification).
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionVotesVerifiedAndAggregated` when complete.
    VerifyAndAggregateExecutionVotes {
        /// Wave identifier.
        wave_id: WaveId,
        /// Block hash for correlation.
        block_hash: BlockHash,
        /// Votes to verify with their public keys.
        votes: Vec<(ExecutionVote, Bls12381G1PublicKey)>,
    },

    /// Verify an execution certificate's aggregated signature.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateSignatureVerified` when complete.
    VerifyExecutionCertificateSignature {
        /// The execution certificate to verify. A
        /// [`Verifiable::Verified`] wrapper short-circuits BLS
        /// verification.
        certificate: Verifiable<ExecutionCertificate>,
        /// Public keys of the signers (in committee order).
        public_keys: Vec<Bls12381G1PublicKey>,
    },

    /// Verify every EC inside a fetched [`FinalizedWave`] in one async dispatch.
    ///
    /// Used by `ExecutionCoordinator::admit_finalized_wave` to keep the
    /// state-machine call off the BLS verification critical path. Carries
    /// per-EC public-key vectors aligned with `wave.execution_certificates()`.
    /// Returns `ProtocolEvent::FinalizedWaveVerified` when complete.
    VerifyFinalizedWave {
        /// The wave whose every EC needs BLS verification before admission.
        /// A [`Verifiable::Verified`] wrapper short-circuits BLS
        /// verification.
        wave: Arc<Verifiable<FinalizedWave>>,
        /// Public keys for each EC, indexed parallel to
        /// `wave.execution_certificates()`.
        ec_public_keys: Vec<Vec<Bls12381G1PublicKey>>,
    },

    /// Verify a Quorum Certificate's aggregated BLS signature **and**
    /// confirm the signers carry quorum-meeting voting power. Both checks
    /// together constitute the [`Verified<QuorumCertificate>`] predicate.
    ///
    /// CRITICAL for shard consensus safety: a Byzantine proposer could otherwise
    /// include a fake QC with invalid signatures or under-quorum signers.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::QcSignatureVerified` when complete.
    VerifyQcSignature {
        /// The QC to verify (carries `shard_id` for self-contained
        /// verification). When the wrapper is already
        /// [`Verifiable::Verified`] — e.g. the caller hit a cached
        /// verified value — the handler short-circuits and emits the
        /// verified result without rerunning BLS aggregation.
        qc: Verifiable<QuorumCertificate>,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
        /// Quorum threshold for the QC's shard.
        quorum_threshold: VoteCount,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as `parent_qc`.
        block_hash: BlockHash,
    },

    /// Verify a wire timeout's BLS share off-thread, then tally it.
    ///
    /// Emitted by the state machine after the cheap committee/shard screen
    /// passes. The consensus crypto pool checks the share against
    /// `voter_public_key` and feeds the result back as
    /// `ProtocolEvent::VerifiedTimeoutReceived`, which the `TimeoutKeeper`
    /// tallies — keeping per-timeout pairing checks off the shard loop thread
    /// during a view change, as the vote path's aggregate verification does.
    VerifyTimeout {
        /// The unverified timeout share to check.
        timeout: Timeout,
        /// The voter's BLS public key, pre-resolved by the state machine from
        /// the topology (where the committee-membership gate also runs).
        voter_public_key: Bls12381G1PublicKey,
    },

    /// Verify a remote block header's QC for cross-shard deferral validation.
    ///
    /// Verifies the aggregated BLS signature on the QC, checks voting power meets
    /// quorum, and confirms `block_hash` matches `hash(header)`.
    ///
    /// Delegated to `ConsensusCrypto` thread pool.
    /// Returns `ProtocolEvent::RemoteHeaderQcVerified` when complete.
    VerifyRemoteHeaderQc {
        /// The remote header to verify.
        certified_header: Arc<CertifiedBlockHeader>,
        /// Sender of the candidate header; threaded back through the
        /// callback so the coordinator can remove the failed candidate
        /// from its pending map on error.
        sender: ValidatorId,
        /// Public keys for the remote shard's committee (from topology).
        committee_public_keys: Vec<Bls12381G1PublicKey>,
        /// Quorum threshold for the remote shard.
        quorum_threshold: VoteCount,
        /// Remote shard ID (for correlation in callback).
        shard: ShardId,
        /// Remote block height (for correlation in callback).
        height: BlockHeight,
    },

    /// Verify a block's local-receipt root and state root against the JMT.
    ///
    /// Runs the receipt-root check as a pre-flight: hashes the receipts in
    /// `finalized_waves` and compares to `expected_local_receipt_root`. If
    /// receipts diverge, the JMT recomputation cannot match `expected_root`
    /// either (receipts ARE the JMT input), so the handler short-circuits
    /// without touching the JMT. On receipt-root pass, applies the block's
    /// shard-local state changes to the JMT and compares the resulting
    /// root against the header's `state_root`.
    ///
    /// Always emits `ProtocolEvent::LocalReceiptRootVerified`. Emits
    /// `ProtocolEvent::StateRootVerified` only on receipt-root pass; on
    /// receipt-root failure the handler short-circuits and the pipeline
    /// rejects the block from the receipt-root event alone.
    ///
    /// The action handler walks the snapshot chain from `parent_block_hash`
    /// to build an overlay of uncommitted tree nodes, then calls
    /// `prepare_block_commit` which computes the JMT root and caches a
    /// `PreparedCommit` for efficient commit later.
    VerifyStateRoot {
        /// Block whose state and receipt roots are being verified.
        block_hash: BlockHash,
        /// Parent block hash — used to walk the snapshot chain for the overlay.
        parent_block_hash: BlockHash,
        /// Base state root (parent block's `state_root`).
        parent_state_root: StateRoot,
        /// Height of the parent block (stable anchor for JMT computation).
        parent_block_height: BlockHeight,
        /// Expected state root after applying writes.
        expected_root: StateRoot,
        /// Expected local-receipt root (pre-flight check before JMT).
        expected_local_receipt_root: LocalReceiptRoot,
        /// Finalized waves whose receipts contribute to both the receipt
        /// root and the state root. The thread pool merges `DatabaseUpdates`
        /// from these.
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        /// Block height being verified.
        block_height: BlockHeight,
        /// The header's `split_child_roots` claim, verified beside the
        /// state root.
        claimed_split_child_roots: Option<SplitChildRoots>,
        /// Whether the block's window requires the claim (the shard's
        /// final epoch before a split), resolved by the coordinator from
        /// the schedule.
        split_child_roots_required: bool,
        /// Whether the block's window requires a `settled_waves_root` — set
        /// on any terminating boundary header (a split parent's or a merge
        /// child's final epoch), broader than `split_child_roots_required`.
        settled_waves_root_required: bool,
        /// The header's `settled_waves_root` claim, recomputed beside the
        /// state root over the committed retention window when the block
        /// terminates the shard at a boundary.
        claimed_settled_waves_root: Option<SettledWavesRoot>,
        /// The block's parent-QC weighted timestamp — the anchor the
        /// settled-waves window walk floors at (`anchor − RETENTION_HORIZON`),
        /// resolved identically by the proposer and every verifier.
        parent_weighted_timestamp: WeightedTimestamp,
        /// The schedule's settled-window floor for the shard at the block's
        /// anchor — extends the settled-waves window back to the reshape's
        /// admission, covering every settlement a counterpart fence can
        /// still hold a straddler against. `None` when no retained window
        /// records one.
        settled_waves_window_floor: Option<WeightedTimestamp>,
    },

    /// Verify a block's beacon-witness root + leaf count.
    ///
    /// Re-derives the new witness leaves from the same three deterministic
    /// sources the proposer used — receipts (via `finalized_waves`), the
    /// missed-round walk over `(parent_round, round)` against
    /// `topology_snapshot`, and the manifest's `ready_signals` — then
    /// applies them against `parent_witness_leaves` (the accumulator state
    /// the parent block left behind) and compares the resulting
    /// `(root, leaf_count)` to the header's claim. A mismatch fails the
    /// check; honest validators reject the block.
    ///
    /// Pure CPU; no JMT dependency. Runs in parallel with the other
    /// per-root verifiers.
    VerifyBeaconWitnessRoot {
        /// Block whose beacon-witness root is being verified.
        block_hash: BlockHash,
        /// Expected accumulator root from the block header.
        expected_root: BeaconWitnessRoot,
        /// Expected accumulator leaf count from the block header.
        expected_leaf_count: BeaconWitnessLeafCount,
        /// The block header's claimed witness window base, checked
        /// against the schedule-resolved value for the block's window.
        claimed_base: BeaconWitnessLeafCount,
        /// Absolute leaf index of `parent_witness_leaves[0]` — the
        /// committed accumulator's retained-window start.
        parent_leaves_start: BeaconWitnessLeafCount,
        /// Accumulator leaves at the parent block — the window the
        /// proposer appended onto. Captured by the coordinator from its
        /// committed accumulator plus any in-chain pending-block deltas.
        parent_witness_leaves: Vec<Hash>,
        /// Parent round; used with `round` to walk
        /// `(parent_round + 1 .. round)` for the `MissedProposal` channel.
        parent_round: Round,
        /// Block height (anchors `MissedProposal`'s `proposer_for` lookup).
        height: BlockHeight,
        /// Block round; the upper bound of the missed-round walk.
        round: Round,
        /// Ready signals the proposer drained into the manifest.
        ready_signals: Vec<ReadySignal>,
        /// The manifest's reshape assertion, validated against the
        /// locally recomputed load predicate.
        reshape_trigger: Option<ReshapeTrigger>,
        /// Committed substate byte total behind the parent block's
        /// post-state — the load the reshape predicate evaluates.
        substate_bytes: u64,
        /// Reshape thresholds in force for this network.
        thresholds: ReshapeThresholds,
        /// Finalized waves whose receipts contribute receipt-sourced
        /// witness events.
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        /// The block's randomness reveal (leaf 0). Its digest is checked
        /// against the recomputed root; the proof's BLS validity against the
        /// proposer's key is verified in the handler.
        randomness_reveal: VrfProof,
        /// Topology snapshot for `proposer_for` lookups in the
        /// missed-round walk.
        topology_snapshot: TopologySnapshot,
    },

    /// Verify a block's transaction root and per-tx validity windows.
    ///
    /// Computes the merkle root from the block's transactions and compares
    /// against the header's `transaction_root`. Also checks that every tx's
    /// `validity_range` is well-formed and contains `validity_anchor` — the
    /// parent QC's `weighted_timestamp` carried on the block. Returns
    /// `ProtocolEvent::TransactionRootVerified` carrying
    /// `Result<Verified<TransactionRoot>, TxRootVerifyError>`; the `Err`
    /// variant distinguishes a merkle-root mismatch from an out-of-window
    /// transaction.
    ///
    /// Pure CPU; no JMT dependency.
    VerifyTransactionRoot {
        /// Block whose transaction root is being verified.
        block_hash: BlockHash,
        /// Expected transaction root from block header.
        expected_root: TransactionRoot,
        /// Transactions in the block.
        transactions: SharedTransactions,
        /// Parent QC's `weighted_timestamp` — the shard consensus-authenticated clock
        /// every honest validator agrees on for this block. The validity
        /// check is `start_inclusive <= anchor < end_exclusive`. The
        /// one-block lag (this block's own QC may carry a slightly later
        /// timestamp) is bounded by `MAX_VALIDITY_RANGE`.
        validity_anchor: WeightedTimestamp,
    },

    /// Verify a block's provisions root.
    ///
    /// Recomputes the merkle root from the provisions hashes in the manifest
    /// and compares against the block header's `provision_root`.
    VerifyProvisionRoot {
        /// Block whose provisions root is being verified.
        block_hash: BlockHash,
        /// Expected provisions root from block header.
        expected_root: ProvisionsRoot,
        /// Provisions hashes from the block manifest.
        batch_hashes: Vec<ProvisionHash>,
    },

    /// Verify a block's receipt root.
    ///
    /// Computes the merkle root from the certificates' `receipt_hash` values
    /// and compares against the block header's claimed `certificate_root`.
    /// Returns `ProtocolEvent::CertificateRootVerified`.
    ///
    /// Pure CPU operation — verified in parallel with state root and transaction root.
    VerifyCertificateRoot {
        /// Block whose certificate root is being verified.
        block_hash: BlockHash,
        /// Expected receipt root from block header.
        expected_root: CertificateRoot,
        /// Finalized waves whose underlying cert `receipt_hash` values form the merkle leaves.
        certificates: SharedCertificates,
    },

    /// Verify a block's per-target-shard provisions commitments.
    ///
    /// Recomputes `compute_provision_tx_roots(topology, transactions)` and
    /// compares against the block header's `provision_tx_roots` by full-map
    /// equality. Catches tampering with which txs are claimed to target
    /// which shard.
    ///
    /// Pure CPU operation — verified in parallel with other root verifications.
    VerifyProvisionTxRoots {
        /// Block whose provision-tx roots are being verified.
        block_hash: BlockHash,
        /// Expected per-target roots from the block header.
        expected: ProvisionTxRootsMap,
        /// Transactions in the block.
        transactions: SharedTransactions,
        /// Topology snapshot used to route txs to target shards.
        topology_snapshot: TopologySnapshot,
    },

    /// Build a complete block proposal.
    ///
    /// Computes the new state root from certificates, builds the complete block,
    /// and caches the `WriteBatch` for efficient commit later.
    ///
    /// Returns `ProtocolEvent::ProposalBuilt` with the complete block.
    ///
    /// This combines state root computation and block building into a single
    /// round-trip, enabling the proposer to use the fast commit path (1 fsync).
    BuildProposal {
        /// Local shard producing this proposal.
        shard_id: ShardId,
        /// Validator id of the proposer (this node).
        proposer: ValidatorId,
        /// Height of the new block.
        height: BlockHeight,
        /// Round at which the proposal is being made.
        round: Round,
        /// Parent block hash; the new block extends this.
        parent_block_hash: BlockHash,
        /// QC over the parent block (genesis QC for the first block).
        parent_qc: QuorumCertificate,
        /// Proposer-supplied timestamp on the new block header.
        timestamp: ProposerTimestamp,
        /// `true` if this is a fallback (empty) proposal during view changes.
        is_fallback: bool,
        /// Parent's state root (base for state root computation via overlay).
        parent_state_root: StateRoot,
        /// Height of the parent block (stable anchor for JMT computation).
        parent_block_height: BlockHeight,
        /// Transactions to include in the proposal.
        transactions: Vec<Arc<Verified<RoutableTransaction>>>,
        /// Finalized waves to include in the block (carries certs + receipts + ECs).
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        /// Provisions from remote shards, included in this block.
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        /// Parent block's in-flight count (for deterministic computation).
        parent_in_flight: InFlightCount,
        /// Number of transactions finalized by wave certificates in this block.
        finalized_tx_count: u32,
        /// Dwell-eligible [`ReadySignal`]s drained from the proposer's pool
        /// for inclusion in the block's manifest. Beacon's `Ready` witness
        /// derives one entry per included signal at block-assembly time.
        ready_signals: Vec<ReadySignal>,
        /// The proposer's reshape assertion for the manifest, derived
        /// from the load predicate over the parent state's substate
        /// count.
        reshape_trigger: Option<ReshapeTrigger>,
        /// The trimmed parent-window accumulator leaves this block's new
        /// witnesses append onto, resolved by the coordinator (which owns the
        /// accumulator and does the ancestor walk). The handler signs the
        /// block's randomness reveal (leaf 0) on the dispatch pool, derives the
        /// block's new leaves over these, and finalizes `beacon_witness_root`
        /// and the leaf count.
        parent_witness_leaves: Vec<Hash>,
        /// The block's `MissedProposal` witness leaves, derived by the
        /// coordinator over `(parent_round, round)` against the block's
        /// committee. Threaded so the handler's leaf derivation matches.
        missed: Vec<ShardWitnessPayload>,
        /// The witness window base of the block's window, resolved by the
        /// coordinator from the same schedule entry as the block's
        /// committee. Stamped verbatim into the header.
        beacon_witness_base: BeaconWitnessLeafCount,
        /// Whether the block's window is the shard's final epoch before
        /// a split, resolved by the coordinator from the schedule. When
        /// set, the handler extracts the root node's two child hashes
        /// from the JMT computation and stamps them into the header as
        /// `split_child_roots`.
        carry_split_child_roots: bool,
        /// Whether the block's window is the shard's final epoch before it
        /// terminates at a reshape boundary — a split parent *or* a merge
        /// child, broader than `carry_split_child_roots`. When set, the
        /// handler computes the `settled_waves_root` over the committed
        /// retention window and stamps it into the header.
        carry_settled_waves_root: bool,
        /// The schedule's settled-window floor for the shard at the block's
        /// anchor, paired with `carry_settled_waves_root` — extends the
        /// committed window walk back to the reshape's admission.
        settled_waves_window_floor: Option<WeightedTimestamp>,
        /// The block's **anchored** committee snapshot, resolved by the
        /// coordinator as `at_for_shard(local_shard, parent_qc.wt)` — the
        /// same one the verifier recomputes against. Classification
        /// (`waves`, `provision_tx_roots`) keys on this, not the `ArcSwap`
        /// head, so a head-flipped proposer at a reshape boundary produces
        /// a header that resolves identically on every replica.
        classification_topology_snapshot: Arc<TopologySnapshot>,
    },

    /// Execute every transaction in a single-shard wave.
    ///
    /// Delegated to the engine thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionBatchCompleted` carrying `wave_id` so the
    /// state machine can route results back to the correct wave.
    ExecuteTransactions {
        /// The wave whose txs are being executed. Single-shard waves have
        /// `remote_shards = {}`; they dispatch immediately at `on_block_committed`.
        wave_id: WaveId,
        /// The committed block whose transactions are being executed.
        /// Paired with `block_height` to anchor state reads via
        /// `PendingChain::view_at` at the block's historical version
        /// regardless of persistence-progress drift.
        block_hash: BlockHash,
        /// Height of `block_hash`. Threaded so reads anchor to the block's
        /// own version even after the entry has been pruned from
        /// [`PendingChain`].
        block_height: BlockHeight,
        /// Transactions to execute (all members of the wave).
        transactions: Vec<Arc<Verified<RoutableTransaction>>>,
        /// State root to anchor reads against.
        state_root: StateRoot,
    },

    /// Execute every transaction in a cross-shard wave, once all its txs are fully provisioned.
    ///
    /// Fired the moment a wave transitions from partially-provisioned to
    /// fully-provisioned (or at block commit if all provisions arrived
    /// early). All txs in the wave are dispatched together.
    /// Returns `ProtocolEvent::ExecutionBatchCompleted` carrying `wave_id`.
    ExecuteCrossShardTransactions {
        /// The wave being executed.
        wave_id: WaveId,
        /// The committed block whose processing kicked off this execution
        /// (either the block carrying the txs, or the block whose committed
        /// provisions unblocked them). Paired with `block_height` to anchor
        /// state reads via `PendingChain::view_at` at the block's historical
        /// version regardless of persistence-progress drift.
        block_hash: BlockHash,
        /// Height of `block_hash`. Threaded so reads anchor to the block's
        /// own version even after the entry has been pruned from
        /// [`PendingChain`].
        block_height: BlockHeight,
        /// The cross-shard execution requests to process (one per tx in the wave).
        requests: Vec<CrossShardExecutionRequest>,
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
    },

    /// Commit a block trusted via QC only — no cached `PreparedCommit` exists
    /// because we didn't run state root verification ourselves (sync path,
    /// or consensus path when we didn't participate in voting).
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
        /// How this node learned the certifying QC (aggregator vs header).
        source: CommitSource,
        /// Beacon-witness leaves to persist alongside the block in the
        /// same atomic write — see [`Self::CommitBlock`].
        witness: BeaconWitnessCommit,
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
    /// - Completed: Wave certificate committed, can be evicted
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
    // Topology
    // ═══════════════════════════════════════════════════════════════════════
    /// Propagate updated topology to the `io_loop` / network layer.
    ///
    /// Emitted by the state machine after any topology mutation. The
    /// `io_loop` stores the snapshot into its shared topology snapshot
    /// (`ArcSwap`), rebuilds `cached_local_peers`, and updates
    /// `local_shard` / `num_shards`.
    TopologyChanged {
        /// Beacon epoch this snapshot was derived at — the monotonic key the
        /// `io_loop` gates the shared `ArcSwap` on, so a slower co-hosted shard
        /// thread folding an older epoch cannot overwrite a newer snapshot a
        /// sibling thread already published.
        epoch: Epoch,
        /// New topology snapshot to propagate.
        topology_snapshot: Arc<TopologySnapshot>,
        /// Terminal-clamped per-shard routing committees, covering every
        /// shard the schedule still retains — including a split parent
        /// draining out of the head, whose committee the head snapshot no
        /// longer carries. The network keys fetch routing on this so a
        /// request to a dissolved shard still reaches its draining members.
        routing_committees: Arc<RoutingCommittees>,
    },

    /// The lookahead committees move this vnode's validator onto or off
    /// a shard at the next window — surface the delta to the runner so
    /// it can reconfigure physical participation (open storage and
    /// bootstrap a joined shard, schedule a left shard's drain).
    ///
    /// Not delegated: the payload travels out of the shard thread to
    /// the process-level owner of shard membership.
    ReconfigureParticipation(ParticipationChange),

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

    /// Request the runner to start (or raise the target of) beacon-chain
    /// gap-fill sync.
    ///
    /// Emitted by `BeaconCoordinator` when it observes a committed beacon
    /// block more than one epoch ahead of its tip. The runner's beacon
    /// `Sync` machine fetches the missing blocks epoch by epoch and feeds
    /// each back as `ProtocolEvent::BeaconBlockSyncReadyToApply`.
    StartBeaconBlockSync {
        /// The epoch we need to sync the beacon chain up to.
        target: Epoch,
    },

    /// Request the runner to start (or raise the target of) remote-header
    /// sync for `source_shard`. The runner's `RemoteHeaderSync`
    /// emits range fetches and feeds verified headers back to
    /// [`crate::ProtocolEvent::RemoteHeaderReceived`].
    StartRemoteHeaderSync {
        /// Remote shard whose certified header chain we're catching up to.
        source_shard: ShardId,
        /// Highest known target height for that shard's chain.
        target: BlockHeight,
        /// Lowest height the source chain holds — its beacon-attested
        /// boundary. A reshape child's chain begins at its split height,
        /// so a fresh sync must anchor here rather than genesis, or the
        /// contiguous-prefix responder returns empty for the non-existent
        /// heights below it and the sync stalls.
        floor: BlockHeight,
    },

    /// Acquire a terminated shard's settled-wave set `S_P` for the
    /// split-boundary fence in one beacon-attested shot.
    ///
    /// Emitted when the node's own beacon fold attests a terminated
    /// shard's `settled_waves_root` it doesn't yet hold `S_P` for. The
    /// I/O loop fetches the shard's complete settled-wave window list
    /// from its terminal committee (`peers`), accepts it only when the
    /// recomputed root equals `attested_root`, and feeds the verified
    /// set back as [`crate::ProtocolEvent::SettledWavesReconstructed`].
    StartSettledWavesAcquisition {
        /// The terminated shard whose settled set to acquire.
        shard: ShardId,
        /// Height of the terminal block `B`.
        terminal_height: BlockHeight,
        /// Hash of the terminal block `B` — the beacon-attested terminal
        /// the window list ends at.
        terminal_block_hash: BlockHash,
        /// `B`'s weighted timestamp — bounds the fence's retention cutoff
        /// once the set is recorded, and the host's self-expiry.
        terminal_wt: WeightedTimestamp,
        /// The beacon-attested `settled_waves_root` the fetched list is
        /// checked against; a mismatch rotates the peer.
        attested_root: SettledWavesRoot,
        /// The terminated shard's terminal committee, asked in rotation.
        peers: Vec<ValidatorId>,
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

    /// Cancel an in-flight fetch the originating coordinator no longer wants.
    ///
    /// Symmetric to [`Self::Fetch`] — `io_loop`'s dispatcher matches the
    /// inner [`FetchAbandon`] and feeds the ids through
    /// `FetchInput::Abandoned` on the corresponding binding. Emitted by
    /// coordinators at every expected-set drop site (verification
    /// succeeded, retention-horizon orphan cleanup, deadline eviction).
    AbandonFetch(FetchAbandon),

    // ═══════════════════════════════════════════════════════════════════════
    // Beacon consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign a PC round-1 vote over `v_in` and broadcast it to the SPC
    /// committee. Handler reconstructs the canonical signing bytes
    /// from `(epoch, view, v_in)`, signs with the local BLS key,
    /// broadcasts the wire-form vote, and feeds the signed vote back
    /// to the state machine via `ProtocolEvent::PcVoteReceived` with
    /// `from = local validator`.
    SignAndBroadcastPcVote1 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Local input vector being signed as `v_in`.
        v_in: PcVector,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a PC round-2 vote derived from `qc1` and broadcast it.
    SignAndBroadcastPcVote2 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Source round-1 QC; `v2.x == qc1.x` is enforced at the
        /// signer.
        qc1: Box<Verified<PcQc1>>,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a PC round-3 vote derived from `qc2` and broadcast it.
    SignAndBroadcastPcVote3 {
        /// Epoch the PC instance belongs to.
        epoch: Epoch,
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Source round-2 QC; `v3.x_p == qc2.x_p` is enforced at the
        /// signer.
        qc2: Box<Verified<PcQc2>>,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign an SPC empty-view attestation and broadcast it. Feeds the
    /// signed message back to the state machine via
    /// `ProtocolEvent::VerifiedSpcEmptyViewReceived`.
    SignAndBroadcastEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// View this empty-view attestation skips.
        view: SpcView,
        /// Local max high triple reported in the attestation, carried
        /// verified-by-construction from the FSM's
        /// [`Verified<SpcHighTriple>`] pool.
        reported: Box<Verified<SpcHighTriple>>,
        /// SPC committee members the message ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-view` notification to the SPC committee — the
    /// cert is already aggregated, no signing happens at the handler.
    BroadcastSpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Proposal object pairing the view with its backing cert,
        /// carried verified-by-construction from the FSM.
        proposal: Box<Verified<SpcProposalObject>>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-commit` notification — the embedded `proof`
    /// is a `PcQc3` that self-authenticates the committed value.
    BroadcastSpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Committed-low message, carried verified-by-construction
        /// from the FSM's inner-PC QC3.
        msg: Box<Verified<SpcNewCommitMsg>>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a VRF reveal, build a `BeaconProposal` carrying the
    /// proposer's `boundary_qcs` and equivocation evidence, and unicast
    /// it to the rest of the beacon committee. Handler feeds the signed
    /// proposal back to the state machine via
    /// `ProtocolEvent::BeaconProposalReceived` with `from = local
    /// validator` so the same admission path peer proposals use also
    /// admits our own. Shard witnesses no longer ride the proposal — they
    /// ride the block's per-shard boundary contributions.
    BuildAndBroadcastBeaconProposal {
        /// Epoch this proposal targets; bound into the VRF reveal's
        /// signing context.
        epoch: Epoch,
        /// Per-shard canonical boundary QCs this proposer observed (only
        /// shards whose witness chunk it can supply), or `None` for an
        /// active shard whose crossing it hasn't yet seen.
        boundary_qcs: BTreeMap<ShardId, Option<QuorumCertificate>>,
        /// Equivocation evidence to embed. Raw — built locally from
        /// verified PC votes.
        equivocations: Vec<PcVoteEquivocation>,
        /// Beacon-committee members the proposal ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a finalized beacon block (post-SPC commit) over the
    /// beacon gossip topic.
    BroadcastBeaconBlock {
        /// Certified block to broadcast.
        block: Arc<Verified<CertifiedBeaconBlock>>,
    },

    /// Verify the certs authenticating a beacon block — the pool
    /// ratify cert on every non-genesis block, plus the SPC proposal
    /// cert on a Normal block — **and** every `PcVoteEquivocation`
    /// carried in the block's committed proposals. Result returns via
    /// [`ProtocolEvent::BeaconBlockVerified`] carrying the block back;
    /// `valid` is the AND-reduction over every cert check and every
    /// equivocation check.
    VerifyBeaconBlock {
        /// Block whose certs + embedded equivocation witnesses are
        /// being verified. A [`Verifiable::Verified`] wrapper
        /// short-circuits dispatch. Carried back through the result
        /// event so the coordinator doesn't have to stash it
        /// separately.
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
        /// Beacon committee for the block's epoch — the SPC cert's
        /// signer base. Positional ordering matches the cert's
        /// bitfields.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        /// Active validator pool at the anchor's epoch — the ratify
        /// cert's signer base. Positional ordering matches the cert's
        /// bitfield.
        active_pool: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `PcVoteEquivocation` evidence. Empty when the block
        /// carries no equivocations. Lookup-shape, order doesn't
        /// matter.
        equivocation_signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Sign and broadcast a [`RatifyVote`] globally. The action handler
    /// signs the vote using the runner-held BLS key (the coordinator
    /// has no signing material), broadcasts the result over the global
    /// beacon-ratify topic, and loops the verified vote back to the
    /// state machine so the local ratification tracker pools its own
    /// contribution. Quorum aggregation happens off-chain inside the
    /// tracker.
    SignAndBroadcastRatifyVote {
        /// Anchor block hash the vote rides against (the latest
        /// committed beacon block at the dispatching coordinator).
        anchor: BeaconBlockHash,
        /// Epoch whose block the vote ratifies. Must be
        /// `current_epoch.next()` at the local tip — older or further
        /// epochs are rejected at admission.
        epoch: Epoch,
        /// Ratification round the vote is cast in.
        round: RatifyRound,
        /// Prevote or precommit.
        phase: RatifyPhase,
        /// Hash of the block the vote names — the verified candidate's
        /// or the canonical skip block's.
        block_hash: BeaconBlockHash,
    },

    /// Verify a single-signer [`RatifyVote`] BLS signature. The result
    /// returns to the state machine carrying the typed verified handle
    /// on success.
    VerifyRatifyVote {
        /// Vote to verify. A [`Verifiable::Verified`] wrapper
        /// short-circuits dispatch.
        vote: Box<Verifiable<RatifyVote>>,
        /// Active validator pool used to look up the signer's pubkey.
        signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Broadcast an SPC-certified [`CandidateBeaconBlock`] over the
    /// beacon gossip topic for pool ratification. The candidate is
    /// self-authenticating (its SPC cert rides along); no signing
    /// needed.
    BroadcastBeaconCandidate {
        /// Candidate to broadcast.
        candidate: Arc<Verified<CandidateBeaconBlock>>,
    },

    /// Verify a [`CandidateBeaconBlock`]: its SPC proposal cert against
    /// the epoch's committee, every `PcVoteEquivocation` carried in its
    /// committed proposals, and the proposal-to-cert content binding.
    /// The result returns to the state machine carrying the candidate
    /// back.
    VerifyBeaconCandidate {
        /// Candidate whose cert + embedded equivocation witnesses are
        /// being verified. A [`Verifiable::Verified`] wrapper
        /// short-circuits dispatch.
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
        /// Beacon committee for the candidate's epoch, in positional
        /// order matching the SPC cert's signer bitfields.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `PcVoteEquivocation` evidence. Empty when the candidate
        /// carries no equivocations.
        equivocation_signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify a round-1 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote1Verified`] carrying the
    /// typed verified handle on success.
    VerifyPcVote1 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A [`Verifiable::Verified`] wrapper
        /// short-circuits BLS dispatch.
        vote: Verifiable<PcVote1>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify a round-2 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote2Verified`].
    VerifyPcVote2 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A [`Verifiable::Verified`] wrapper
        /// short-circuits BLS dispatch; the embedded round-1 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote2>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify a round-3 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote3Verified`].
    VerifyPcVote3 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A [`Verifiable::Verified`] wrapper
        /// short-circuits BLS dispatch; the embedded round-2 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote3>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an SPC `NewView` proposal object. Result returns via
    /// [`ProtocolEvent::SpcNewViewVerified`] carrying the typed
    /// verified handle on success.
    VerifySpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Sender of the `NewView` (carried back through the result event).
        from: ValidatorId,
        /// Proposal object to verify. A [`Verifiable::Verified`]
        /// wrapper short-circuits the dispatch.
        proposal: Box<Verifiable<SpcProposalObject>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an SPC `NewCommit` message. Result returns via
    /// [`ProtocolEvent::SpcNewCommitVerified`].
    VerifySpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Wire-level sender — carried back through the result so the
        /// coordinator can clear its per-`(epoch, view, sender)`
        /// pipeline slot. `NewCommit` is self-authenticating via the
        /// embedded `proof`, so this label is dedup metadata only.
        from: ValidatorId,
        /// New-commit message to verify. A [`Verifiable::Verified`]
        /// wrapper short-circuits dispatch; the embedded QC3 marker
        /// shortcuts its sub-check.
        msg: Box<Verifiable<SpcNewCommitMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an empty-view attestation (sig + embedded reported QC3).
    /// Result returns via [`ProtocolEvent::SpcEmptyViewVerified`].
    VerifySpcEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Attestation to verify. A [`Verifiable::Verified`] wrapper
        /// short-circuits dispatch.
        msg: Box<Verifiable<SpcEmptyViewMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Persist a committed beacon block + its resulting `BeaconState`
    /// to `BeaconStorage`. Both writes go in one atomic batch.
    CommitBeaconBlock {
        /// Certified committed block.
        block: Arc<Verified<CertifiedBeaconBlock>>,
        /// State the block advances to. Boxed to bound enum size.
        state: Box<BeaconState>,
    },
}

impl Action {
    /// Get the action type name for telemetry.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }

    /// Which thread pool this action should run on, or `None` if it's not
    /// delegated (timers, network broadcasts, persist — handled inline by
    /// the runner).
    #[must_use]
    pub const fn dispatch_pool(&self) -> Option<DispatchPool> {
        use hyperscale_dispatch::DispatchPool;
        match self {
            // Liveness-critical: shard QC verify/build, state root,
            // proposal building, sign-and-broadcast for shard
            // consensus; plus beacon per-epoch crypto + sign work.
            Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyTimeout { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::SignAndBroadcastTimeout { .. }
            | Self::SignAndBroadcastReadySignal { .. }
            | Self::BroadcastCertifiedBlockHeader { .. }
            | Self::SignAndBroadcastPcVote1 { .. }
            | Self::SignAndBroadcastPcVote2 { .. }
            | Self::SignAndBroadcastPcVote3 { .. }
            | Self::SignAndBroadcastEmptyView { .. }
            | Self::BroadcastSpcNewView { .. }
            | Self::BroadcastSpcNewCommit { .. }
            | Self::BuildAndBroadcastBeaconProposal { .. }
            | Self::BroadcastBeaconBlock { .. }
            | Self::SignAndBroadcastRatifyVote { .. }
            | Self::BroadcastBeaconCandidate { .. }
            | Self::VerifyBeaconBlock { .. }
            | Self::VerifyRatifyVote { .. }
            | Self::VerifyBeaconCandidate { .. }
            | Self::VerifyPcVote1 { .. }
            | Self::VerifyPcVote2 { .. }
            | Self::VerifyPcVote3 { .. }
            | Self::VerifySpcNewView { .. }
            | Self::VerifySpcNewCommit { .. }
            | Self::VerifySpcEmptyView { .. } => Some(DispatchPool::Consensus),

            // Throughput-bound: provision/cert/wave verification,
            // execution-vote crypto, and Radix Engine execution.
            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalizedWave { .. }
            | Self::VerifyProvisions { .. }
            | Self::FetchAndBroadcastProvisions { .. }
            | Self::SignAndSendExecutionVote { .. }
            | Self::BroadcastExecutionCertificate { .. }
            | Self::ExecuteTransactions { .. }
            | Self::ExecuteCrossShardTransactions { .. } => Some(DispatchPool::Throughput),

            _ => None,
        }
    }

    /// The SPC `(epoch, view)` position this action signs beacon
    /// consensus for under the emitting validator's identity, or
    /// `None` for everything else.
    ///
    /// A validator can host several vnodes at once (a split's parent
    /// and child overlap through the drain; a relocation's old and new
    /// shards likewise), and each runs the full beacon protocol under
    /// the same identity — two of them emitting independently derived
    /// SPC messages is equivocation, which the beacon fold jails. The
    /// dispatch funnel consults this to let exactly one vnode per
    /// validator sign within any one view. A proposal precedes the
    /// first view, so it maps to view zero — the epoch's earliest
    /// claimable position. The `SpcNewView`/`SpcNewCommit` relays are
    /// deliberately absent: their wrapper signature attributes relay
    /// of a self-authenticating cert, which cannot equivocate, and
    /// fencing them would burn a view claim on a non-vote. Maintained
    /// as a total match so a new signing action can't silently bypass
    /// the filter.
    #[must_use]
    pub const fn beacon_signing_position(&self) -> Option<(Epoch, SpcView)> {
        match self {
            Self::BuildAndBroadcastBeaconProposal { epoch, .. } => Some((*epoch, SpcView::new(0))),
            Self::SignAndBroadcastPcVote1 { epoch, view, .. }
            | Self::SignAndBroadcastPcVote2 { epoch, view, .. }
            | Self::SignAndBroadcastPcVote3 { epoch, view, .. }
            | Self::SignAndBroadcastEmptyView { epoch, view, .. } => Some((*epoch, *view)),
            Self::BroadcastSpcNewView { .. }
            | Self::BroadcastSpcNewCommit { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::SignAndBroadcastTimeout { .. }
            | Self::SignAndBroadcastReadySignal { .. }
            | Self::SignAndSendExecutionVote { .. }
            | Self::BroadcastExecutionCertificate { .. }
            | Self::FetchAndBroadcastProvisions { .. }
            | Self::BroadcastCertifiedBlockHeader { .. }
            | Self::SetTimer { .. }
            | Self::CancelTimer { .. }
            | Self::Continuation(_)
            | Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyProvisions { .. }
            | Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalizedWave { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyTimeout { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::BuildProposal { .. }
            | Self::ExecuteTransactions { .. }
            | Self::ExecuteCrossShardTransactions { .. }
            | Self::CommitBlock { .. }
            | Self::CommitBlockByQcOnly { .. }
            | Self::EmitTransactionStatus { .. }
            | Self::RecordTxEcCreated { .. }
            | Self::TopologyChanged { .. }
            | Self::ReconfigureParticipation(_)
            | Self::StartBlockSync { .. }
            | Self::StartBeaconBlockSync { .. }
            | Self::StartRemoteHeaderSync { .. }
            | Self::StartSettledWavesAcquisition { .. }
            | Self::RestoreCommittedState { .. }
            | Self::Fetch(_)
            | Self::AbandonFetch(_)
            | Self::BroadcastBeaconBlock { .. }
            | Self::SignAndBroadcastRatifyVote { .. }
            | Self::BroadcastBeaconCandidate { .. }
            | Self::VerifyBeaconBlock { .. }
            | Self::VerifyRatifyVote { .. }
            | Self::VerifyBeaconCandidate { .. }
            | Self::VerifyPcVote1 { .. }
            | Self::VerifyPcVote2 { .. }
            | Self::VerifyPcVote3 { .. }
            | Self::VerifySpcNewView { .. }
            | Self::VerifySpcNewCommit { .. }
            | Self::VerifySpcEmptyView { .. }
            | Self::CommitBeaconBlock { .. }
            | Self::AttachCertifiedUncommitted { .. } => None,
        }
    }

    /// Whether this action emits SPC consensus traffic — signed votes,
    /// proposals, or attributed relays. The set a dissolved shard's
    /// vnode must stop emitting once its successors are live: its
    /// validator's live vnode carries the duty from there.
    #[must_use]
    pub const fn is_beacon_consensus_emission(&self) -> bool {
        self.beacon_signing_position().is_some()
            || matches!(
                self,
                Self::BroadcastSpcNewView { .. } | Self::BroadcastSpcNewCommit { .. }
            )
    }

    /// The ratify-vote position this action signs under the emitting
    /// validator's identity, or `None` for everything else.
    ///
    /// Distinct from [`Self::beacon_signing_position`]: ratify votes
    /// are fenced per `(epoch, round, phase)` — strictly monotone
    /// across all of a validator's co-hosted vnodes — rather than by
    /// view claim, so a vnode torn down mid-epoch (a reshape drain)
    /// hands the *next vote position* to its successor instead of
    /// fencing the validator out. A coarser fence than the vote
    /// position would allow cross-vnode equivocation.
    #[must_use]
    pub const fn ratify_signing_position(&self) -> Option<(Epoch, RatifyRound, RatifyPhase)> {
        match self {
            Self::SignAndBroadcastRatifyVote {
                epoch,
                round,
                phase,
                ..
            } => Some((*epoch, *round, *phase)),
            _ => None,
        }
    }

    /// Which coordinator crate owns this action's delegated work.
    #[must_use]
    pub const fn owner(&self) -> ActionOwner {
        match self {
            Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyTimeout { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::SignAndBroadcastTimeout { .. }
            | Self::SignAndBroadcastReadySignal { .. }
            | Self::BroadcastCertifiedBlockHeader { .. } => ActionOwner::Shard,

            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalizedWave { .. }
            | Self::ExecuteTransactions { .. }
            | Self::ExecuteCrossShardTransactions { .. }
            | Self::SignAndSendExecutionVote { .. }
            | Self::BroadcastExecutionCertificate { .. } => ActionOwner::Execution,

            Self::VerifyProvisions { .. } | Self::FetchAndBroadcastProvisions { .. } => {
                ActionOwner::Provisions
            }

            Self::SignAndBroadcastPcVote1 { .. }
            | Self::SignAndBroadcastPcVote2 { .. }
            | Self::SignAndBroadcastPcVote3 { .. }
            | Self::SignAndBroadcastEmptyView { .. }
            | Self::BroadcastSpcNewView { .. }
            | Self::BroadcastSpcNewCommit { .. }
            | Self::BuildAndBroadcastBeaconProposal { .. }
            | Self::BroadcastBeaconBlock { .. }
            | Self::SignAndBroadcastRatifyVote { .. }
            | Self::BroadcastBeaconCandidate { .. }
            | Self::VerifyBeaconBlock { .. }
            | Self::VerifyRatifyVote { .. }
            | Self::VerifyBeaconCandidate { .. }
            | Self::VerifyPcVote1 { .. }
            | Self::VerifyPcVote2 { .. }
            | Self::VerifyPcVote3 { .. }
            | Self::VerifySpcNewView { .. }
            | Self::VerifySpcNewCommit { .. }
            | Self::VerifySpcEmptyView { .. } => ActionOwner::Beacon,

            _ => ActionOwner::Local,
        }
    }
}

/// Which coordinator crate owns an [`Action`]'s delegated work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionOwner {
    /// Shard consensus actions: QC build / verify, proposal, header
    /// and vote sign-and-broadcast.
    Shard,
    /// Execution-coordinator actions: wave / EC aggregation,
    /// transaction execution, exec vote / cert sign-and-broadcast.
    Execution,
    /// Provision-coordinator actions: state-provision verification,
    /// outbound provision fetch + broadcast.
    Provisions,
    /// Beacon-coordinator actions: PC/SPC sign-and-broadcast,
    /// beacon-block / candidate / ratify-vote gossip, shard-witness
    /// fetch dispatch, beacon-side crypto verification.
    Beacon,
    /// I/O-loop-internal effects (timers, commits, status emission,
    /// fetch driving, topology plumbing). Not delegated to a worker
    /// pool.
    Local,
}
