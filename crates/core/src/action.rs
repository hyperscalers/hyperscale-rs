//! Action types for the deterministic state machine.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_dispatch::DispatchPool;
use hyperscale_engine::TickEnvironment;
use hyperscale_engine::legs::{Member, Runs};
use hyperscale_storage::TickResolution;
use hyperscale_types::{
    AbandonmentRecord, BeaconBlockHash, BeaconState, BeaconWitnessCommit, BeaconWitnessLeafCount,
    BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote,
    CandidateBeaconBlock, CertificateRoot, CertifiedBeaconBlock, CertifiedBlock,
    CertifiedBlockHeader, CommitWindow, ConsensusPublicKey, DeclaredRange, Epoch, EscrowedValue,
    ExecutionCertificate, ExecutionVote, Finalization, GlobalReceiptRoot, Hash, HeaderFetchCount,
    LocalReceiptRoot, PcQc1, PcQc2, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation,
    PriceTable, PrincipalAddr, ProposerTimestamp, ProvisionHash, ProvisionTxRootsMap, Provisions,
    ProvisionsRoot, QuorumCertificate, RatifyPhase, RatifyRound, RatifyVote, ReadySignal,
    ReshapeThresholds, ReshapeTrigger, ResolvedCommittee, RevealChain, Round, ShardForkProof,
    ShardId, ShardLoad, ShardTrie, ShardVoteEquivocation, SharedCertificates, SharedTransactions,
    SharedWitnessSources, SpcEmptyViewMsg, SpcHighTriple, SpcNewCommitMsg, SpcProposalObject,
    SpcView, SplitChildRoots, StateClaim, StateRoot, SubstateEntry, SubstateKey, SweepFrontier,
    TerminalRoots, TickId, Timeout, TopologySchedule, TopologySnapshot, Transaction,
    TransactionRoot, TransactionStatus, TxHash, TxOutcome, TxsInFlight, UnsettledTx, ValidatorId,
    Verifiable, Verified, VoteCount, VotePosition, WeightedTimestamp,
};

use crate::{CommitSource, FetchIds, FetchRequest, ProtocolEvent, TimerId};

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The transaction to execute, or `None` where this shard holds no
    /// body for it.
    ///
    /// A member running a shape always holds one. The two housekeeping
    /// members read none — every cell they touch is named by the record
    /// leaves `runs` carries — but they keep it where it is there,
    /// because the price still follows the payer's vault and the vault
    /// is the body's to name. `None` is a reshape successor's
    /// housekeeping: its store arrives as a prefix of leaves, no body
    /// arrives with it, and its predecessor's chain settled the price.
    pub transaction: Option<Arc<Verified<Transaction>>>,
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
    /// What this member runs: the transaction as classified when its
    /// block committed — carried, never re-derived — or a settlement of
    /// what a leg here issued. What it says of the member is what the
    /// batch reads: whether the transaction reaches beyond this shard,
    /// which makes a member's provisions and arrivals necessary and its
    /// writes filtered to the subtree this shard owns; and whether a
    /// counterpart's verdict can still discard its effects, which makes
    /// its contributions provisional, readable by no later tick until
    /// the verdict resolves them, and its declared cells a claim a later
    /// member must compose with.
    pub runs: Runs,
    /// What committed bundles attested for the edges this shard's legs
    /// consume, read off the record cells they proved. Empty for a
    /// member that runs the whole shape.
    pub arrivals: Vec<EscrowedValue>,
}

impl CrossShardExecutionRequest {
    /// The shape this member runs and the body it runs over, or `None`
    /// for a housekeeping member.
    ///
    /// The pair travels together or not at all: `Runs::Shape` is the one
    /// arm a body belongs to, and a reclaim or a retirement has neither.
    #[must_use]
    pub const fn shape(&self) -> Option<(&Member, &Arc<Verified<Transaction>>)> {
        match (&self.runs, self.transaction.as_ref()) {
            (Runs::Shape(member), Some(body)) => Some((member, body)),
            _ => None,
        }
    }
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

/// One payer's fee-reservation demand, verified against its vault
/// balance at a deterministic committed height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeDemand {
    /// The payer's fee vault cell.
    pub vault: SubstateKey,
    /// The payer's stored-authority cell, read beside the vault at the
    /// same anchored height: the reservation engages only for signers
    /// the payer's rule admits.
    pub auth_cell: SubstateKey,
    /// The total reservation the payer must cover: this block's newly
    /// engaged fee ceilings plus the in-flight holds derived from chain
    /// content.
    pub demand: u128,
    /// The distinct signer identities behind this block's demands on
    /// this payer, each of which the payer's rule must admit for the
    /// reservation to engage. Ancestor and in-flight holds contribute
    /// demand but no signers — their blocks answered for their own.
    ///
    /// Empty when the demand seeds a proposal builder, whose candidate
    /// transactions carry their own signers.
    pub signers: BTreeSet<PrincipalAddr>,
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
        /// The signing position this vote ratchets — the registers and
        /// the uncommitted chain justifying them. The runner persists it
        /// durably before the signature leaves the process, so a
        /// crash-restarted validator can never re-vote this round, and
        /// comes back able to extend the certificate it locked on.
        position: VotePosition,
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
        /// The signing position this timeout ratchets. The runner
        /// persists it durably before the signature leaves the process,
        /// so a crash-restarted validator can never vote a round it
        /// already abandoned.
        position: VotePosition,
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
    /// Sign and send an execution vote to the tick leader for aggregation.
    ///
    /// Emitted by the state machine when a tick completes (all txs executed).
    /// The `io_loop` signs the vote (it owns the signing key) and sends it to
    /// the tick leader (unicast). The leader aggregates 2f+1 votes into an EC.
    SignAndSendExecutionVote {
        /// Block whose tick is being voted on.
        block_hash: BlockHash,
        /// Block height (for correlation).
        block_height: BlockHeight,
        /// Consensus timestamp at which this vote is being cast.
        vote_anchor_ts: WeightedTimestamp,
        /// Tick identifier whose execution is being attested to.
        tick_id: TickId,
        /// Global receipt root over the tick's per-tx outcomes.
        global_receipt_root: GlobalReceiptRoot,
        /// Per-tx outcomes in tick order. Carried on the vote so the
        /// leader can extract them directly when building the EC.
        tx_outcomes: Vec<TxOutcome>,
        /// The tick leader who collects and aggregates votes for this tick.
        leader: ValidatorId,
    },

    /// Broadcast an execution certificate to local peers or remote shards.
    ///
    /// The tick leader broadcasts to both local committee peers (who need the
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
        /// The source block's parent-QC weighted timestamp, carried on
        /// the bundle wire form and checked against the commit-proven
        /// header at verification.
        source_block_ts: WeightedTimestamp,
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

    /// Broadcast a shard fork proof globally on first local verification.
    ///
    /// The proof self-authenticates (it carries the accused committee's own
    /// QCs), so no signing is needed — the handler wraps it in a
    /// `ShardForkProofGossip` and gossips it; every recipient re-verifies
    /// locally. Broadcast once per forked shard so the network converges on
    /// the fence.
    BroadcastShardForkProof {
        /// The self-proving fork evidence to gossip.
        proof: Box<ShardForkProof>,
    },

    /// Broadcast shard double-vote evidence over global gossip. The pair
    /// is already locally verified and self-authenticating (both
    /// signatures verify under the accused key), so no signing is needed
    /// — the handler wraps it in a `ShardVoteEquivocationGossip`; every
    /// recipient re-verifies locally. This is the recovery lane that
    /// keeps the evidence reachable after its holders leave the source
    /// committee.
    BroadcastShardVoteEquivocation {
        /// The self-proving double-vote pair to gossip.
        evidence: Box<ShardVoteEquivocation>,
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
    /// 1. Batch-verifies all vote signatures through the scheme verifier
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
        votes_to_verify: Vec<(usize, BlockVote, ConsensusPublicKey)>,
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
    /// Performs signature aggregation on execution votes.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Tick identifier. The producing shard is `tick_id.shard_id`.
        tick_id: TickId,
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
        /// Tick identifier.
        tick_id: TickId,
        /// Block hash for correlation.
        block_hash: BlockHash,
        /// Votes to verify with their public keys.
        votes: Vec<(ExecutionVote, ConsensusPublicKey)>,
    },

    /// Verify an execution certificate's aggregated signature.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateSignatureVerified` when complete.
    VerifyExecutionCertificateSignature {
        /// The execution certificate to verify. A
        /// `Verifiable::Verified` wrapper short-circuits
        /// verification.
        certificate: Verifiable<ExecutionCertificate>,
        /// Public keys of the signers (in committee order).
        public_keys: Vec<ConsensusPublicKey>,
    },

    /// Verify every EC inside a fetched [`Finalization`] in one async dispatch.
    ///
    /// Used by `ExecutionCoordinator::admit_finalization` to keep the
    /// state-machine call off the signature verification critical path. Carries
    /// per-EC public-key vectors aligned with
    /// `finalization.execution_certificates()`.
    /// Returns `ProtocolEvent::FinalizationVerified` when complete.
    VerifyFinalization {
        /// The finalization whose every EC needs signature verification
        /// before admission. A `Verifiable::Verified` wrapper
        /// short-circuits verification.
        finalization: Arc<Verifiable<Finalization>>,
        /// Public keys for each EC, indexed parallel to
        /// `finalization.execution_certificates()`.
        ec_public_keys: Vec<Vec<ConsensusPublicKey>>,
    },

    /// Verify a Quorum Certificate's aggregated signature **and**
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
        /// `Verifiable::Verified` — e.g. the caller hit a cached
        /// verified value — the handler short-circuits and emits the
        /// verified result without rerunning signature aggregation.
        qc: Verifiable<QuorumCertificate>,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<ConsensusPublicKey>,
        /// Quorum threshold for the QC's shard.
        quorum_threshold: VoteCount,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as `parent_qc`.
        block_hash: BlockHash,
    },

    /// Verify a wire timeout's signature share off-thread, then tally it.
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
        /// The voter's public key, pre-resolved by the state machine from
        /// the topology (where the committee-membership gate also runs).
        voter_public_key: ConsensusPublicKey,
    },

    /// Verify a remote block header's QC for cross-shard deferral validation.
    ///
    /// Verifies the aggregated signature on the QC, checks voting power meets
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
        committee_public_keys: Vec<ConsensusPublicKey>,
        /// Quorum threshold for the remote shard.
        quorum_threshold: VoteCount,
        /// Remote shard ID (for correlation in callback).
        shard: ShardId,
        /// Remote block height (for correlation in callback).
        height: BlockHeight,
    },

    /// Verify an assembled shard fork proof off the state-machine thread.
    ///
    /// A fork proof costs up to four QC verifications; a flood of garbage
    /// proofs would stall the state machine if run inline. The dispatcher
    /// (which holds the topology schedule) resolves each QC's committee via
    /// [`ShardForkProof::resolve_committees`] and passes them here so the
    /// handler runs pure signature verification — the same emitter-resolves shape as
    /// [`Self::VerifyBeaconBlock`].
    ///
    /// Delegated to the consensus crypto pool. Returns
    /// `ProtocolEvent::ShardForkProofVerified`.
    VerifyShardForkProof {
        /// The proof to verify.
        proof: Box<ShardForkProof>,
        /// Committees resolved for the proof's QCs, positionally aligned to
        /// its canonical QC order.
        committees: Vec<ResolvedCommittee>,
    },

    /// Delegated to the consensus crypto pool. Returns
    /// `ProtocolEvent::ShardVoteEquivocationVerified`.
    VerifyShardVoteEquivocation {
        /// The double-vote pair to verify.
        evidence: Box<ShardVoteEquivocation>,
        /// The accused validator's registered pubkey, resolved by the
        /// state machine from its topology.
        pubkey: ConsensusPublicKey,
    },

    /// Verify a block's local-receipt root and state root against the JMT.
    ///
    /// Runs the receipt-root check as a pre-flight: hashes the receipts in
    /// `finalizations` and compares to `expected_local_receipt_root`. If
    /// receipts diverge, the JMT recomputation cannot match `expected_root`
    /// either (receipts ARE the JMT input), so the handler short-circuits
    /// without touching the JMT. On receipt-root pass, applies the block's
    /// shard-local state changes to the JMT and compares the resulting
    /// root against the header's `state_root`.
    ///
    /// Always completes the local-receipt-root check. Completes the
    /// state-root check only on receipt-root pass; on receipt-root
    /// failure the handler short-circuits and the pipeline rejects the
    /// block from the receipt-root refusal alone.
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
        /// Finalizations whose receipts contribute to both the receipt
        /// root and the state root. The thread pool merges the receipts' writes
        /// from these.
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        /// Hashes of the block's own transactions — its contribution to
        /// the committed-transaction window a terminating boundary header
        /// roots. Carried as hashes because that is all the root needs.
        block_tx_hashes: Vec<TxHash>,
        /// The committed cells the block writes, derived by the
        /// coordinator under the block's own window. They fold with the
        /// receipts' writes under the root being verified.
        creations: Vec<(SubstateKey, Vec<u8>)>,
        /// Block height being verified.
        block_height: BlockHeight,
        /// The header's `split_child_roots` claim, verified beside the
        /// state root.
        claimed_split_child_roots: Option<SplitChildRoots>,
        /// Whether the block's window requires the claim (the shard's
        /// final epoch before a split), resolved by the coordinator from
        /// the schedule.
        split_child_roots_required: bool,
        /// Whether the block's window requires terminal roots — set on any
        /// terminating boundary header (a split parent's or a merge
        /// child's final epoch), broader than `split_child_roots_required`.
        terminal_roots_required: bool,
        /// The header's `terminal_roots` claim, recomputed beside the state
        /// root over the committed retention window when the block
        /// terminates the shard at a boundary.
        claimed_terminal_roots: Option<TerminalRoots>,
        /// The block's parent-QC weighted timestamp — the anchor the
        /// settled-transaction window walk floors at (`anchor − RETENTION_HORIZON`),
        /// resolved identically by the proposer and every verifier.
        parent_weighted_timestamp: WeightedTimestamp,
        /// Where the parent's sweep stopped — the lower end of the
        /// interval this block's removals fill.
        parent_sweep_frontier: SweepFrontier,
        /// The header's own `sweep_frontier` claim, recomputed beside the
        /// state root.
        ///
        /// The recomputation is the whole check: a walk from the parent's
        /// frontier under the cap lands on exactly one position, so a
        /// frontier that matches came from the same removal set, and one
        /// that does not is either an incomplete sweep or an overreaching
        /// one. It also carries the obligation to advance, since a
        /// proposer that swept nothing while cells sat below the clock
        /// lands short of where the walk does.
        claimed_sweep_frontier: SweepFrontier,
        /// The schedule's settled-window floor for the shard at the block's
        /// anchor — extends the settled-transaction window back to the reshape's
        /// admission, covering every settlement a counterpart fence can
        /// still hold a straddler against. `None` when no retained window
        /// records one.
        settled_txs_window_floor: Option<WeightedTimestamp>,
    },

    /// Verify a block's beacon-witness root + leaf count.
    ///
    /// Re-derives the new witness leaves from the same deterministic
    /// sources the proposer used — receipts (via `finalizations`), the
    /// missed-round walk over `(parent_round, round)` against
    /// `topology_snapshot`, and the block's carried `witness_sources` —
    /// then applies them against `parent_witness_leaves` (the accumulator
    /// state the parent block left behind) and compares the resulting
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
        /// Header's claimed reveal chain, recomputed from the parent's and
        /// this block's reveal output.
        claimed_reveal_chain: RevealChain,
        /// Reveal chain on the parent header.
        parent_reveal_chain: RevealChain,
        /// Anchor epoch of the parent header.
        parent_committee_anchor_epoch: Epoch,
        /// Anchor epoch of the block being verified.
        committee_anchor_epoch: Epoch,
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
        /// The block's carried witness sources. Every claim is
        /// re-verified inside the shared verifier before its leaf folds
        /// — equivocation evidence against each equivocator's registered
        /// key, the reshape assertion against the locally recomputed
        /// load predicate, the randomness reveal against the
        /// proposer's key — so an invalid entry fails the block.
        witness_sources: SharedWitnessSources,
        /// Committed substate byte total behind the parent block's
        /// post-state — the load the reshape predicate evaluates. `None`
        /// takes the predicate out of play (reshaping disabled, or the
        /// ancestry crosses a halt recovery's sync-admitted suffix); the
        /// recomputed assertion must then be absent.
        substate_bytes: Option<u64>,
        /// The header's own claim about that total, checked against it.
        claimed_substate_bytes: Option<u64>,
        /// Reshape thresholds in force for this network.
        thresholds: ReshapeThresholds,
        /// Finalizations whose receipts contribute receipt-sourced
        /// witness events.
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
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
    /// `ProtocolEvent::BlockCheckCompleted` for the transaction root; the
    /// verifier's error distinguishes a merkle-root mismatch from an out-of-window
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
        /// Transactions this shard only delivers for, admissible past
        /// their validity end to the delivery window's close.
        late_deliveries: HashSet<TxHash>,
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
    /// Returns `ProtocolEvent::BlockCheckCompleted`.
    ///
    /// Pure CPU operation — verified in parallel with state root and transaction root.
    VerifyCertificateRoot {
        /// Block whose certificate root is being verified.
        block_hash: BlockHash,
        /// Expected receipt root from block header.
        expected_root: CertificateRoot,
        /// Finalizations whose underlying cert `receipt_hash` values form the merkle leaves.
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
        /// Certificates in the block, whose committed outcomes promise
        /// crossing bundles.
        certificates: SharedCertificates,
        /// Topology snapshot used to route txs to target shards.
        topology_snapshot: TopologySnapshot,
    },

    /// Verify a block's payer-shard fee reservations.
    ///
    /// Reads each demanded payer's native vault at `read_height` and
    /// checks it covers the reservation demand the coordinator derived
    /// from chain content. The height is the one the block's own
    /// ancestry proves committed, so every replica verifying the block
    /// reads the same vault version regardless of local commit progress;
    /// the coordinator holds the dispatch until its own commit pipeline
    /// has materialized that height.
    /// Returns `ProtocolEvent::BlockCheckCompleted`.
    VerifyReservations {
        /// Block whose reservations are being verified.
        block_hash: BlockHash,
        /// Per-payer demands; empty demands never dispatch.
        demands: Vec<FeeDemand>,
        /// The ancestry-proven committed height balances are read at.
        read_height: BlockHeight,
        /// The judged block's own parent-QC weighted timestamp — the
        /// transaction clock its members execute under if it commits
        /// them.
        clock: WeightedTimestamp,
    },

    /// Check the figures a block's abandonment records restate against
    /// the committed transactions they name.
    ///
    /// A record restates each name's deadline, reservation and charge so
    /// a replica whose replay never reached the transaction composes the
    /// same abort as one that held it; unchecked, that would let a
    /// proposer choose the vault and the amount an abort burns. Every
    /// figure is a function of the body, and the body is read off the
    /// store — where a validator that committed the transaction holds it
    /// at any distance — so the check needs no window of its own. A body
    /// the store never held answers `Unknown`, and the vote defers on it
    /// rather than accepting.
    /// Returns `ProtocolEvent::BlockCheckCompleted`.
    VerifyResolutions {
        /// Block whose resolutions are being checked.
        block_hash: BlockHash,
        /// Every name the block's records carry.
        entries: Vec<UnsettledTx>,
        /// Every transaction the block's finalizations resolve without
        /// deciding — a delivery or a leg — checked against the lapse
        /// where the body says this shard delivers for it.
        deliveries: Vec<TxHash>,
        /// Every transaction the block's finalizations decide with
        /// success by its own execution, for a member that awaits
        /// nobody, checked against the deadline: past it a leg may
        /// already have taken its crossing back.
        successes: Vec<TxHash>,
        /// The block's own anchor, which the lapse and the deadline are
        /// read against.
        anchor: WeightedTimestamp,
        /// The trie of the anchor's window, which a delivery's body is
        /// classified against.
        trie: ShardTrie,
        /// The window each name states its commit at, keyed by that
        /// anchor: the placement and the table its figures were frozen
        /// under, so a fold moving either never moves a figure already
        /// owed. A name whose window this validator no longer retains
        /// defers the whole check rather than being weighed at another.
        committed_windows: BTreeMap<WeightedTimestamp, CommitWindow>,
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
        transactions: Vec<Arc<Verified<Transaction>>>,
        /// Finalizations to include in the block (carries certs + receipts + ECs).
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        /// Provisions from remote shards, included in this block.
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        /// What departed shards left unresolved of this chain's business
        /// — written down here while the settled sets they were read
        /// from can still be checked against.
        abandonment_records: Vec<AbandonmentRecord>,
        /// Proofs of counterparts' cells this proposer's fetches
        /// answered, for every replica to fold at commit.
        state_claims: Vec<StateClaim>,
        /// Prior fee-reservation demand per local payer among the
        /// candidate transactions — in-flight holds plus the uncommitted
        /// window, excluding the candidates themselves. The builder
        /// accumulates candidate ceilings on top and drops transactions
        /// their payer cannot cover, so a proposal never self-rejects
        /// the voters' reservation verification.
        fee_checks: Vec<FeeDemand>,
        /// The height the builder reads payer balances at — the height
        /// its parent QC's chain proves committed, matching the anchor
        /// voters verify the reservations against.
        fee_read_height: BlockHeight,
        /// Parent block's in-flight count (for deterministic computation).
        parent_in_flight: TxsInFlight,
        /// Parent block's settlement frontier — the highest tick whose
        /// determined half has settled at or below it. The block advances
        /// it by the determined halves it carries, and may carry none
        /// below it.
        parent_settled_frontier: BlockHeight,
        /// Where the parent's sweep stopped — the lower end of the
        /// interval this block's removals fill.
        parent_sweep_frontier: SweepFrontier,
        /// Attested load on the parent's header — the running gas total
        /// this block advances by the gas its own certificates report.
        parent_load: Option<ShardLoad>,
        /// Committed substate byte total behind the parent's post-state —
        /// the level this block attests, resolved by the coordinator ahead
        /// of the build so the header and the reshape assertion it carries
        /// agree on one value. `None` takes the reshape predicate out of
        /// play, and the header states that absence rather than guessing.
        substate_bytes: Option<u64>,
        /// Number of transactions finalized by finalizations in this block.
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
        /// block's randomness reveal on the dispatch pool, derives the
        /// block's new leaves over these, and finalizes `beacon_witness_root`
        /// and the leaf count.
        parent_witness_leaves: Vec<Hash>,
        /// The witness window base of the block's window, resolved by the
        /// coordinator from the same schedule entry as the block's
        /// committee. Stamped verbatim into the header.
        beacon_witness_base: BeaconWitnessLeafCount,
        /// Reveal chain on the parent header — what this block's chain
        /// extends when both anchor in the same epoch.
        parent_reveal_chain: RevealChain,
        /// Anchor epoch of the parent header. Differing from `committee_anchor_epoch`
        /// is what reseeds the chain.
        parent_committee_anchor_epoch: Epoch,
        /// Anchor epoch of the block being built —
        /// `epoch_for(parent_qc.weighted_timestamp)`.
        committee_anchor_epoch: Epoch,
        /// Whether the block's window is the shard's final epoch before
        /// a split, resolved by the coordinator from the schedule. When
        /// set, the handler extracts the root node's two child hashes
        /// from the JMT computation and stamps them into the header as
        /// `split_child_roots`.
        carry_split_child_roots: bool,
        /// Whether the block's window is the shard's final epoch before it
        /// terminates at a reshape boundary — a split parent *or* a merge
        /// child, broader than `carry_split_child_roots`. When set, the
        /// handler computes the `settled_txs_root` over the committed
        /// retention window and stamps it into the header.
        carry_terminal_roots: bool,
        /// The schedule's settled-window floor for the shard at the block's
        /// anchor, paired with `carry_terminal_roots` — extends the
        /// committed window walk back to the reshape's admission.
        settled_txs_window_floor: Option<WeightedTimestamp>,
        /// The block's **anchored** committee snapshot, resolved by the
        /// coordinator as `at_for_shard(local_shard, parent_qc.wt)` — the
        /// same one the verifier recomputes against. Classification
        /// (`ticks`, `provision_tx_roots`) keys on this, not the `ArcSwap`
        /// head, so a head-flipped proposer at a reshape boundary produces
        /// a header that resolves identically on every replica.
        classification_topology_snapshot: Arc<TopologySnapshot>,
    },

    /// Execute one tick's whole batch: the committing block's
    /// local-only tick beside every cross-shard tick whose provisions
    /// completed at that commit, as one executor batch.
    ///
    /// Delegated to the engine thread pool in production, instant in
    /// simulation. Ticks dispatch serially — the coordinator holds the
    /// next tick until this one's `ProtocolEvent::ExecutionBatchCompleted`
    /// returns, because the tick's output is the next tick's baseline.
    /// The handler reads through `TickChain::view_at` at the previous
    /// tick, never through the settlement overlay.
    ExecuteTransactions {
        /// Tick identifier: the committing block's height.
        tick: BlockHeight,
        /// The committing block's parent-QC weighted timestamp.
        tick_ts: WeightedTimestamp,
        /// What the block fixed about the environment: the seeds a
        /// sealed draw may settle on and the epoch grid a clock resolves
        /// against. Resolved by the coordinator off the block's anchored
        /// committee, not the `ArcSwap` head, so every replica executes
        /// the tick over one window however far each has folded the
        /// beacon.
        env: TickEnvironment,
        /// Tick-attributed members of the batch. Results fan back to each
        /// tick by `tick_id`.
        /// The members, each with its provisions and environment.
        requests: Vec<CrossShardExecutionRequest>,
    },

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
        /// Where the parent's sweep stopped — the lower end of the
        /// interval this block's removals fill.
        parent_sweep_frontier: SweepFrontier,
        /// The committed cells the block writes, derived by the
        /// coordinator under the block's own window — the one placement
        /// fact the recomputation reads beyond the block, resolved where
        /// the schedule is.
        creations: Vec<(SubstateKey, Vec<u8>)>,
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
    // Topology
    // ═══════════════════════════════════════════════════════════════════════
    /// Propagate the folded topology to the `io_loop` / network layer.
    ///
    /// Emitted by the state machine on every beacon commit. The io side
    /// publishes the schedule's head as its shared topology snapshot,
    /// keys fetch routing on the schedule's terminal-clamped committees,
    /// and resolves a followed block's window through the schedule.
    TopologyChanged {
        /// Beacon epoch the schedule was folded at — the monotonic key the
        /// `io_loop` gates its publish on, so a slower co-hosted shard
        /// thread folding an older epoch cannot overwrite a newer schedule
        /// a sibling thread already published.
        epoch: Epoch,
        /// The beacon's window schedule as of this fold: the head, the
        /// retained windows and the lookahead, one clone per epoch.
        schedule: Arc<TopologySchedule>,
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
    /// [`crate::ProtocolEvent::VerifiedRemoteHeaderReceived`].
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
    /// while it coasts and once more when its successors are live: the
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
        txs: Vec<Arc<Transaction>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Beacon consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign a PC round-1 vote over `v_in` and broadcast it to the SPC
    /// committee. Handler reconstructs the canonical signing bytes
    /// from `(epoch, view, v_in)`, signs with the local signer,
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
        /// Fork proofs to embed, one per forked shard. Raw — drained from
        /// the local observation buffer of verified proofs.
        fork_proofs: BTreeMap<ShardId, ShardForkProof>,
        /// Shard double-vote pairs to embed. Raw — drained from the
        /// local observation buffer of verified pairs.
        vote_equivocations: Vec<ShardVoteEquivocation>,
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
        /// being verified. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch. Carried back through the result
        /// event so the coordinator doesn't have to stash it
        /// separately.
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
        /// Beacon committee for the block's epoch — the SPC cert's
        /// signer base. Positional ordering matches the cert's
        /// bitfields.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
        /// Active validator pool at the anchor's epoch — the ratify
        /// cert's signer base. Positional ordering matches the cert's
        /// bitfield.
        active_pool: Vec<(ValidatorId, ConsensusPublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `PcVoteEquivocation` evidence. Empty when the block
        /// carries no equivocations. Lookup-shape, order doesn't
        /// matter.
        equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Sign and broadcast a [`RatifyVote`] globally. The action handler
    /// signs the vote using the runner-held signer (the coordinator
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

    /// Verify a single-signer [`RatifyVote`] signature. The result
    /// returns to the state machine carrying the typed verified handle
    /// on success.
    VerifyRatifyVote {
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        vote: Box<Verifiable<RatifyVote>>,
        /// Active validator pool used to look up the signer's pubkey.
        signers: Vec<(ValidatorId, ConsensusPublicKey)>,
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
        /// being verified. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
        /// Beacon committee for the candidate's epoch, in positional
        /// order matching the SPC cert's signer bitfields.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `PcVoteEquivocation` evidence. Empty when the candidate
        /// carries no equivocations.
        equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-1 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote1Verified`] carrying the
    /// typed verified handle on success.
    VerifyPcVote1 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch.
        vote: Verifiable<PcVote1>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-2 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote2Verified`].
    VerifyPcVote2 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch; the embedded round-1 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote2>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify a round-3 PC vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVote3Verified`].
    VerifyPcVote3 {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify. A `Verifiable::Verified` wrapper
        /// short-circuits verify dispatch; the embedded round-2 QC's
        /// marker shortcuts its sub-check.
        vote: Box<Verifiable<PcVote3>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify an SPC `NewView` proposal object. Result returns via
    /// [`ProtocolEvent::SpcNewViewVerified`] carrying the typed
    /// verified handle on success.
    VerifySpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Sender of the `NewView` (carried back through the result event).
        from: ValidatorId,
        /// Proposal object to verify. A `Verifiable::Verified`
        /// wrapper short-circuits the dispatch.
        proposal: Box<Verifiable<SpcProposalObject>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
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
        /// New-commit message to verify. A `Verifiable::Verified`
        /// wrapper short-circuits dispatch; the embedded QC3 marker
        /// shortcuts its sub-check.
        msg: Box<Verifiable<SpcNewCommitMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    },

    /// Verify an empty-view attestation (sig + embedded reported QC3).
    /// Result returns via [`ProtocolEvent::SpcEmptyViewVerified`].
    VerifySpcEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Attestation to verify. A `Verifiable::Verified` wrapper
        /// short-circuits dispatch.
        msg: Box<Verifiable<SpcEmptyViewMsg>>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
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
            | Self::VerifyShardForkProof { .. }
            | Self::VerifyShardVoteEquivocation { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyReservations { .. }
            | Self::VerifyResolutions { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::SignAndBroadcastTimeout { .. }
            | Self::SignAndBroadcastReadySignal { .. }
            | Self::BroadcastCertifiedBlockHeader { .. }
            | Self::BroadcastShardForkProof { .. }
            | Self::BroadcastShardVoteEquivocation { .. }
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

            // Throughput-bound: provision/cert/tick verification,
            // execution-vote crypto, and engine execution.
            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalization { .. }
            | Self::VerifyProvisions { .. }
            | Self::FetchAndBroadcastProvisions { .. }
            | Self::SignAndSendExecutionVote { .. }
            | Self::BroadcastExecutionCertificate { .. }
            | Self::ExecuteTransactions { .. } => Some(DispatchPool::Throughput),

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
            | Self::BroadcastShardForkProof { .. }
            | Self::BroadcastShardVoteEquivocation { .. }
            | Self::SetTimer { .. }
            | Self::CancelTimer { .. }
            | Self::Continuation(_)
            | Self::ReofferTransactions { .. }
            | Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyProvisions { .. }
            | Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalization { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyTimeout { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyShardForkProof { .. }
            | Self::VerifyShardVoteEquivocation { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyReservations { .. }
            | Self::VerifyResolutions { .. }
            | Self::BuildProposal { .. }
            | Self::ExecuteTransactions { .. }
            | Self::ResolveTicks { .. }
            | Self::ClearTickChain
            | Self::CommitBlock { .. }
            | Self::CommitBlockByQcOnly { .. }
            | Self::EmitTransactionStatus { .. }
            | Self::RecordTxEcCreated { .. }
            | Self::TopologyChanged { .. }
            | Self::ReconfigureParticipation(_)
            | Self::StartBlockSync { .. }
            | Self::StartBeaconBlockSync { .. }
            | Self::StartRemoteHeaderSync { .. }
            | Self::FetchCommitProof { .. }
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
            | Self::VerifyShardForkProof { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyReservations { .. }
            | Self::VerifyResolutions { .. }
            | Self::VerifyStateRoot { .. }
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::SignAndBroadcastTimeout { .. }
            | Self::SignAndBroadcastReadySignal { .. }
            | Self::BroadcastCertifiedBlockHeader { .. }
            | Self::BroadcastShardForkProof { .. } => ActionOwner::Shard,

            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalization { .. }
            | Self::ExecuteTransactions { .. }
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
    /// Execution-coordinator actions: tick / EC aggregation,
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
