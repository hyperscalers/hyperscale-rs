//! Action types for the deterministic state machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_dispatch::DispatchPool;
use hyperscale_types::{
    BeaconState, BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash,
    BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PublicKey, CertificateRoot,
    CertifiedBeaconBlock, CertifiedBlock, CommittedBlockHeader, Epoch, ExecutionCertificate,
    ExecutionVote, FinalizedWave, GlobalReceiptRoot, Hash, InFlightCount, LeafIndex,
    LocalReceiptRoot, NodeId, PcQc1, PcQc2, PcQc3, PcVector, PcVoteMessage, ProposerTimestamp,
    ProvisionHash, ProvisionTxRootsMap, Provisions, ProvisionsRoot, QuorumCertificate, ReadySignal,
    Round, RoutableTransaction, ShardGroupId, SharedCertificates, SharedTransactions,
    SkipEpochCert, SkipRequest, SpcCert, SpcEmptyViewMsg, SpcHighTriple, SpcView, StateRoot,
    SubstateEntry, TopologySnapshot, TransactionRoot, TransactionStatus, TxHash, TxOutcome,
    ValidatorId, Verifiable, Verified, VotePower, WaveId, WeightedTimestamp, Witness,
};

use crate::{CommitSource, FetchAbandon, FetchRequest, ProtocolEvent, TimerId};

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The transaction to execute.
    pub transaction: Arc<RoutableTransaction>,
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
    pub target_nodes: Vec<(ShardGroupId, Vec<NodeId>)>,
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
        /// Block height.
        height: BlockHeight,
        /// Round at which the vote is being cast.
        round: Round,
        /// Proposer timestamp from the block header (echoed in the vote).
        timestamp: ProposerTimestamp,
        /// Local-shard validators eligible to propose the next block; they
        /// need this vote to assemble the QC.
        next_proposers: Vec<ValidatorId>,
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
        shard: ShardGroupId,
        /// Aggregated execution certificate.
        certificate: Arc<ExecutionCertificate>,
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
        source_shard: ShardGroupId,
        /// Source-shard block height the provisions are anchored to.
        block_height: BlockHeight,
        /// Per-shard recipients for provision broadcasts (excluding self).
        shard_recipients: HashMap<ShardGroupId, Vec<ValidatorId>>,
    },

    /// Sign and broadcast a committed block header globally to all shards.
    ///
    /// Used for the light-client provisions pattern. When a block commits,
    /// this broadcasts the header + QC so remote shards can verify state roots.
    /// The `io_loop` signs on the consensus crypto pool before sending.
    BroadcastCommittedBlockHeader {
        /// Header + QC bundle to broadcast globally.
        committed_header: CommittedBlockHeader,
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
        shard_group_id: ShardGroupId,
        /// Block height.
        height: BlockHeight,
        /// Round number.
        round: Round,
        /// Parent block hash (from the block's header).
        parent_block_hash: BlockHash,
        /// Parent QC's `weighted_timestamp` — monotonicity floor applied to
        /// every vote timestamp during stake-weighted aggregation. Without
        /// this, slow-clocked or Byzantine voters can drag the aggregated
        /// `weighted_timestamp` back below the parent's, breaking deadline
        /// pruning and validity-window monotonicity.
        parent_weighted_timestamp: WeightedTimestamp,
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (`committee_index`, vote, `public_key`, `voting_power`).
        votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, VotePower)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (`committee_index`, vote, `voting_power`).
        verified_votes: Vec<(usize, Verified<BlockVote>, VotePower)>,
        /// Total voting power in the committee (for quorum calculation).
        total_voting_power: VotePower,
    },

    /// Verify provisions' merkle inclusion proofs.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator` when the header
    /// was promoted to verified, so this only checks merkle proofs against the
    /// committed header's state root.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::StateProvisionsVerified` when complete.
    VerifyProvisions {
        /// The provisions to verify (all from the same source block).
        provisions: Provisions,
        /// The QC-verified committed block header from `RemoteHeaderCoordinator`.
        committed_header: Arc<Verified<CommittedBlockHeader>>,
    },

    /// Aggregate execution votes into an `ExecutionCertificate` (quorum reached).
    ///
    /// Performs BLS signature aggregation on execution votes.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Wave identifier. The producing shard is `wave_id.shard_group_id`.
        wave_id: WaveId,
        /// Global receipt root (merkle root over per-tx outcome leaves).
        global_receipt_root: GlobalReceiptRoot,
        /// Votes to aggregate (with quorum). The first vote's `tx_outcomes`
        /// is used for the EC payload (all quorum votes have identical outcomes).
        votes: Vec<ExecutionVote>,
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
        /// Votes to verify with their public keys and voting power.
        votes: Vec<(ExecutionVote, Bls12381G1PublicKey, VotePower)>,
    },

    /// Verify an execution certificate's aggregated signature.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateSignatureVerified` when complete.
    VerifyExecutionCertificateSignature {
        /// The execution certificate to verify.
        certificate: ExecutionCertificate,
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
        wave: Arc<FinalizedWave>,
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
        /// The QC to verify (carries `shard_group_id` for self-contained
        /// verification). When the wrapper is already
        /// [`Verifiable::Verified`] — e.g. the caller hit a cached
        /// verified value — the handler short-circuits and emits the
        /// verified result without rerunning BLS aggregation.
        qc: Verifiable<QuorumCertificate>,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
        /// Voting power for each committee member (parallel to `public_keys`).
        voting_powers: Vec<VotePower>,
        /// Quorum threshold for the QC's shard.
        quorum_threshold: VotePower,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as `parent_qc`.
        block_hash: BlockHash,
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
        committed_header: Arc<CommittedBlockHeader>,
        /// Sender of the candidate header; threaded back through the
        /// callback so the coordinator can remove the failed candidate
        /// from its pending map on error.
        sender: ValidatorId,
        /// Public keys for the remote shard's committee (from topology).
        committee_public_keys: Vec<Bls12381G1PublicKey>,
        /// Voting power for each committee member (parallel to `committee_public_keys`).
        committee_voting_power: Vec<VotePower>,
        /// Quorum threshold for the remote shard.
        quorum_threshold: VotePower,
        /// Remote shard ID (for correlation in callback).
        shard: ShardGroupId,
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
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Block height being verified.
        block_height: BlockHeight,
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
        /// Accumulator leaves at the parent block — the base the proposer
        /// appended onto. Captured by the coordinator from its committed
        /// accumulator plus any in-chain pending-block deltas.
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
        /// Finalized waves whose receipts contribute receipt-sourced
        /// witness events.
        finalized_waves: Vec<Arc<FinalizedWave>>,
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
        shard_group_id: ShardGroupId,
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
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Finalized waves to include in the block (carries certs + receipts + ECs).
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Provisions from remote shards, included in this block.
        provisions: Vec<Arc<Provisions>>,
        /// Parent block's in-flight count (for deterministic computation).
        parent_in_flight: InFlightCount,
        /// Number of transactions finalized by wave certificates in this block.
        finalized_tx_count: u32,
        /// Dwell-eligible [`ReadySignal`]s drained from the proposer's pool
        /// for inclusion in the block's manifest. Beacon's `Ready` witness
        /// derives one entry per included signal at block-assembly time.
        ready_signals: Vec<ReadySignal>,
        /// Pre-derived beacon-witness accumulator root after this block's
        /// witnesses are appended. The coordinator owns the accumulator
        /// and computes both this and `beacon_witness_leaf_count` before
        /// emitting the action.
        beacon_witness_root: BeaconWitnessRoot,
        /// Pre-derived total accumulator leaf count after this block's
        /// witnesses are appended.
        beacon_witness_leaf_count: BeaconWitnessLeafCount,
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
        transactions: Vec<Arc<RoutableTransaction>>,
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
        /// New topology snapshot to propagate.
        topology_snapshot: Arc<TopologySnapshot>,
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

    /// Request the runner to start (or raise the target of) remote-header
    /// sync for `source_shard`. The runner's `RemoteHeaderSync`
    /// emits range fetches and feeds verified headers back to
    /// [`crate::ProtocolEvent::RemoteHeaderReceived`].
    StartRemoteHeaderSync {
        /// Remote shard whose committed-header chain we're catching up to.
        source_shard: ShardGroupId,
        /// Highest known target height for that shard's chain.
        target: BlockHeight,
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
        qc1: Box<PcQc1>,
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
        qc2: Box<PcQc2>,
        /// SPC committee members the vote ships to (excluding self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign an SPC empty-view attestation and broadcast it. Feeds the
    /// signed message back to the state machine via
    /// `ProtocolEvent::SpcEmptyViewReceived`.
    SignAndBroadcastEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// View this empty-view attestation skips.
        view: SpcView,
        /// Local max high triple reported in the attestation.
        reported: Box<SpcHighTriple>,
        /// SPC committee members the message ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-view` notification to the SPC committee — the
    /// cert is already aggregated, no signing happens at the handler.
    BroadcastSpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// View this notification authorises entry to.
        view: SpcView,
        /// Cert backing the authorisation.
        cert: Box<SpcCert>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a `new-commit` notification — the embedded `proof`
    /// is a `PcQc3` that self-authenticates the committed value.
    BroadcastSpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// View whose inner PC produced this commit.
        view: SpcView,
        /// Committed low value.
        value: PcVector,
        /// PC round-3 cert anchoring `value` as `proof.x_pp`.
        proof: Box<PcQc3>,
        /// SPC committee members the notification ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Sign a VRF reveal, build a `BeaconProposal` carrying
    /// `witnesses`, and unicast it to the rest of the beacon
    /// committee. Handler feeds the signed proposal back to the
    /// state machine via `ProtocolEvent::BeaconProposalReceived`
    /// with `from = local validator` so the same admission path
    /// peer proposals use also admits our own.
    BuildAndBroadcastBeaconProposal {
        /// Epoch this proposal targets; bound into the VRF reveal's
        /// signing context.
        epoch: Epoch,
        /// Drained witnesses + equivocation evidence to embed in the
        /// proposal. Order is preserved into `BeaconProposal::new`'s
        /// `BoundedVec`.
        witnesses: Vec<Witness>,
        /// Beacon-committee members the proposal ships to (excluding
        /// self).
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast a finalized beacon block (post-SPC commit) over the
    /// beacon gossip topic.
    BroadcastBeaconBlock {
        /// Certified block to broadcast.
        block: Arc<CertifiedBeaconBlock>,
    },

    /// Broadcast a locally-signed [`SkipRequest`] to the active-duty
    /// pool. Quorum aggregation happens off-chain inside
    /// `SkipTracker`.
    BroadcastSkipRequest {
        /// Request to broadcast.
        request: Arc<SkipRequest>,
        /// Active-pool validators the request ships to.
        recipients: Vec<ValidatorId>,
    },

    /// Broadcast an assembled [`SkipEpochCert`] to the active-duty
    /// pool. Standalone cert gossip helps late-joining or syncing
    /// nodes that didn't observe the requests directly.
    BroadcastSkipCert {
        /// Cert to broadcast.
        cert: Arc<SkipEpochCert>,
        /// Active-pool validators the cert ships to.
        recipients: Vec<ValidatorId>,
    },

    /// Fetch a batch of shard witnesses by leaf index from a remote
    /// shard's committee.
    FetchShardWitnesses {
        /// Source shard whose witnesses we want.
        shard_id: ShardGroupId,
        /// Hash of the source-shard block whose `beacon_witness_root`
        /// anchors the requested leaves.
        committed_block_hash: BlockHash,
        /// Leaf indices to fetch.
        leaf_indices: Vec<LeafIndex>,
        /// Source-shard committee members; any can serve.
        peers: Vec<ValidatorId>,
    },

    /// Verify the cert authenticating a beacon block (SPC cert on a
    /// Normal block, pool-quorum cert on a Skip block — the handler
    /// reads `block.cert()` to branch) **and** every
    /// `Witness::Equivocation` carried in the block's committed
    /// proposals. Result returns via [`ProtocolEvent::BeaconBlockVerified`]
    /// carrying the block back; `valid` is the AND-reduction over the
    /// cert check and every equivocation check.
    VerifyBeaconBlock {
        /// Block whose cert + embedded equivocation witnesses are
        /// being verified. Carried back through the result event so
        /// the coordinator doesn't have to stash it separately.
        block: Arc<CertifiedBeaconBlock>,
        /// Signers paired with their pubkeys — committee for a Normal
        /// block, active pool for a Skip block. Positional ordering
        /// matches the cert's signer bitfield.
        signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        /// Pubkeys for the validators referenced by embedded
        /// `Witness::Equivocation` evidence. Empty when the block
        /// carries no equivocations. Lookup-shape, order doesn't
        /// matter.
        equivocation_signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify a single-signer [`SkipRequest`] BLS signature. Result
    /// returns via [`ProtocolEvent::SkipRequestVerified`] carrying the
    /// request back.
    VerifySkipRequest {
        /// Request to verify.
        request: Box<SkipRequest>,
        /// Active validator pool used to look up the signer's pubkey.
        signers: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify a PC round vote against its `(epoch, view)` committee.
    /// Result returns via [`ProtocolEvent::PcVoteVerified`] carrying the
    /// vote back so the coordinator can route it into the post-verify
    /// admission path without stashing.
    VerifyPcVote {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote to verify; the variant selects the verifier.
        vote: Box<PcVoteMessage>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an SPC `NewView` cert authorising entry to `view`. Result
    /// returns via [`ProtocolEvent::SpcNewViewVerified`].
    VerifySpcNewView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Sender of the `NewView` (carried back through the result event).
        from: ValidatorId,
        /// View this cert authorises entry to.
        view: SpcView,
        /// Cert to verify.
        cert: Box<SpcCert>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an SPC `NewCommit`'s embedded [`PcQc3`]. Result returns
    /// via [`ProtocolEvent::SpcNewCommitVerified`].
    VerifySpcNewCommit {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Wire-level sender — carried back through the result so the
        /// coordinator can clear its per-`(epoch, view, sender)`
        /// pipeline slot. `NewCommit` is self-authenticating via
        /// `proof`, so this label is dedup metadata only.
        from: ValidatorId,
        /// SPC view whose inner PC produced this commit.
        view: SpcView,
        /// Committed low value.
        value: PcVector,
        /// PC round-3 cert anchoring `value` as `proof.x_pp`.
        proof: Box<PcQc3>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Verify an empty-view attestation (sig + embedded reported QC3).
    /// Result returns via [`ProtocolEvent::SpcEmptyViewVerified`].
    VerifySpcEmptyView {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Attestation to verify.
        msg: Box<SpcEmptyViewMsg>,
        /// Beacon committee at `epoch`, positional order.
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    },

    /// Persist a committed beacon block + its resulting `BeaconState`
    /// to `BeaconStorage`. Both writes go in one atomic batch.
    CommitBeaconBlock {
        /// Certified committed block.
        block: Arc<CertifiedBeaconBlock>,
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
            | Self::BroadcastCommittedBlockHeader { .. }
            | Self::SignAndBroadcastPcVote1 { .. }
            | Self::SignAndBroadcastPcVote2 { .. }
            | Self::SignAndBroadcastPcVote3 { .. }
            | Self::SignAndBroadcastEmptyView { .. }
            | Self::BroadcastSpcNewView { .. }
            | Self::BroadcastSpcNewCommit { .. }
            | Self::BuildAndBroadcastBeaconProposal { .. }
            | Self::BroadcastBeaconBlock { .. }
            | Self::BroadcastSkipRequest { .. }
            | Self::BroadcastSkipCert { .. }
            | Self::FetchShardWitnesses { .. }
            | Self::VerifyBeaconBlock { .. }
            | Self::VerifySkipRequest { .. }
            | Self::VerifyPcVote { .. }
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

    /// Which coordinator crate owns this action's delegated work.
    #[must_use]
    pub const fn owner(&self) -> ActionOwner {
        match self {
            Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyQcSignature { .. }
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
            | Self::BroadcastCommittedBlockHeader { .. } => ActionOwner::Shard,

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
            | Self::BroadcastSkipRequest { .. }
            | Self::BroadcastSkipCert { .. }
            | Self::FetchShardWitnesses { .. }
            | Self::VerifyBeaconBlock { .. }
            | Self::VerifySkipRequest { .. }
            | Self::VerifyPcVote { .. }
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
    /// beacon-block / skip-request / skip-cert gossip, shard-witness
    /// fetch dispatch, beacon-side crypto verification.
    Beacon,
    /// I/O-loop-internal effects (timers, commits, status emission,
    /// fetch driving, topology plumbing). Not delegated to a worker
    /// pool.
    Local,
}
