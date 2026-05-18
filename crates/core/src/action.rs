//! Action types for the deterministic state machine.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_dispatch::DispatchPool;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PublicKey,
    CertificateRoot, CommittedBlockHeader, ExecutionCertificate, ExecutionVote, FinalizedWave,
    GlobalReceiptRoot, InFlightCount, LocalReceiptRoot, NodeId, ProposerTimestamp, ProvisionHash,
    ProvisionTxRoot, Provisions, ProvisionsRoot, QuorumCertificate, Round, RoutableTransaction,
    ShardGroupId, SharedCertificates, SharedTransactions, StateRoot, SubstateEntry,
    TopologySnapshot, TransactionRoot, TransactionStatus, TxHash, TxOutcome, ValidatorId,
    VotePower, WaveId, WeightedTimestamp,
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
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network: BFT
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
        verified_votes: Vec<(usize, BlockVote, VotePower)>,
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
        committed_header: Arc<CommittedBlockHeader>,
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

    /// Verify a Quorum Certificate's aggregated BLS signature.
    ///
    /// This is CRITICAL for BFT safety: we must verify that the QC's aggregated signature
    /// was actually produced by the claimed signers. Without this check, a Byzantine proposer
    /// could include a fake QC with invalid signatures.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::QcSignatureVerified` when complete.
    VerifyQcSignature {
        /// The QC to verify (carries `shard_group_id` for self-contained verification).
        qc: QuorumCertificate,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
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
    /// Emits two `ProtocolEvent::BlockRootVerified` events — one for
    /// `VerificationKind::LocalReceiptRoot`, one for
    /// `VerificationKind::StateRoot`. On receipt-root mismatch, the
    /// state-root event reports `valid=false` so the coordinator's
    /// per-kind tracking still completes.
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

    /// Verify a block's transaction root and per-tx validity windows.
    ///
    /// Computes the merkle root from the block's transactions and compares
    /// against the header's `transaction_root`. Also checks that every tx's
    /// `validity_range` is well-formed and contains `validity_anchor` — the
    /// parent QC's `weighted_timestamp` carried on the block. Returns
    /// `ProtocolEvent::BlockRootVerified { kind: TransactionRoot, valid }`;
    /// `valid` is true iff both the merkle root matches and every tx is
    /// in-window.
    ///
    /// Pure CPU; no JMT dependency.
    VerifyTransactionRoot {
        /// Block whose transaction root is being verified.
        block_hash: BlockHash,
        /// Expected transaction root from block header.
        expected_root: TransactionRoot,
        /// Transactions in the block.
        transactions: SharedTransactions,
        /// Parent QC's `weighted_timestamp` — the BFT-authenticated clock
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
        /// Expected per-target roots from block header.
        expected: std::collections::BTreeMap<ShardGroupId, ProvisionTxRoot>,
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
        /// Anchors state reads via `PendingChain::view_at`.
        block_hash: BlockHash,
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
        /// provisions unblocked them). Anchors state reads via
        /// `PendingChain::view_at`.
        block_hash: BlockHash,
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
        /// Block to commit.
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
        /// How this node learned the certifying QC (aggregator vs header).
        source: CommitSource,
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
        /// Block to commit.
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
        /// Parent block's state root — base state for JMT computation.
        parent_state_root: StateRoot,
        /// Parent block's height — JMT parent version.
        parent_block_height: BlockHeight,
        /// How this node learned the certifying QC (aggregator vs header).
        source: CommitSource,
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
            // Consensus-critical crypto + state root computation + sign-and-broadcast.
            Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyTransactionRoot { .. }
            | Self::VerifyProvisionRoot { .. }
            | Self::VerifyCertificateRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyStateRoot { .. }
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::BroadcastCommittedBlockHeader { .. } => Some(DispatchPool::ConsensusCrypto),

            // General crypto (cert aggregation, provision proofs, exec vote/cert sign+send).
            Self::AggregateExecutionCertificate { .. }
            | Self::VerifyAndAggregateExecutionVotes { .. }
            | Self::VerifyExecutionCertificateSignature { .. }
            | Self::VerifyFinalizedWave { .. }
            | Self::VerifyProvisions { .. }
            | Self::FetchAndBroadcastProvisions { .. }
            | Self::SignAndSendExecutionVote { .. }
            | Self::BroadcastExecutionCertificate { .. } => Some(DispatchPool::Crypto),

            // Transaction execution.
            Self::ExecuteTransactions { .. } | Self::ExecuteCrossShardTransactions { .. } => {
                Some(DispatchPool::Execution)
            }

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
            | Self::BuildProposal { .. }
            | Self::BroadcastBlockHeader { .. }
            | Self::SignAndBroadcastBlockVote { .. }
            | Self::BroadcastCommittedBlockHeader { .. } => ActionOwner::Bft,

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

            _ => ActionOwner::Local,
        }
    }
}

/// Which coordinator crate owns an [`Action`]'s delegated work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionOwner {
    /// BFT consensus actions: QC build / verify, proposal, header
    /// and vote sign-and-broadcast.
    Bft,
    /// Execution-coordinator actions: wave / EC aggregation,
    /// transaction execution, exec vote / cert sign-and-broadcast.
    Execution,
    /// Provision-coordinator actions: state-provision verification,
    /// outbound provision fetch + broadcast.
    Provisions,
    /// I/O-loop-internal effects (timers, commits, status emission,
    /// fetch driving, topology plumbing). Not delegated to a worker
    /// pool.
    Local,
}
