//! Action types for the deterministic state machine.

use crate::{ProtocolEvent, TimerId};
use hyperscale_messages::TransactionGossip;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PublicKey,
    Bls12381G2Signature, CertificateRoot, CommittedBlockHeader, EpochConfig, EpochId,
    ExecutionCertificate, ExecutionVote, FinalizedWave, GlobalReceiptRoot, LocalReceiptRoot,
    NodeId, ProposerTimestamp, ProvisionHash, ProvisionTxRoot, Provisions, ProvisionsRoot,
    QuorumCertificate, ReceiptBundle, Round, RoutableTransaction, ShardGroupId, SignerBitfield,
    StateProvision, StateRoot, TopologySnapshot, TransactionRoot, TransactionStatus, TxHash,
    TxOutcome, ValidatorId, VotePower, WaveId, WaveIdHash, WeightedTimestamp,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// The transaction to execute.
    pub transaction: Arc<RoutableTransaction>,
    /// State provisions from other shards.
    pub provisions: Vec<StateProvision>,
}

/// A single cross-shard transaction's provisioning needs.
///
/// Collected per-block and emitted via [`Action::FetchAndBroadcastProvisions`].
#[derive(Debug, Clone)]
pub struct ProvisionsRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: TxHash,
    /// Nodes owned by our shard whose state we need to provision.
    pub nodes: Vec<NodeId>,
    /// Target shards and the nodes this tx needs from each.
    /// Used to populate `TxEntries::target_nodes` for conflict detection.
    pub targets: Vec<(ShardGroupId, Vec<NodeId>)>,
}

/// Actions the state machine wants to perform.
///
/// Actions are **commands** - they describe something to do.
/// The runner executes actions and may convert results back into events.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network: BFT Consensus
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

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Mempool & Certificates
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a transaction gossip to a shard.
    BroadcastTransaction {
        /// Target shard for the gossip.
        shard: ShardGroupId,
        /// Gossip envelope (sender + transaction payload).
        gossip: Box<TransactionGossip>,
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

    /// Cache an aggregated execution certificate for serving fetch requests.
    ///
    /// Emitted by the wave leader after aggregation and by non-leaders after
    /// receiving and verifying the EC broadcast. The `io_loop` stores these in
    /// the in-memory cache so remote shards can fetch ECs via fallback.
    /// Persistence is handled via wave certificates in `block.certificates`
    /// at commit time.
    TrackExecutionCertificate {
        /// Execution certificate to cache for serving fetch requests.
        certificate: Arc<ExecutionCertificate>,
    },

    /// Fetch state entries and broadcast provisions for all cross-shard txs in a block.
    ///
    /// Only the block proposer emits this (once per block). Delegated to the
    /// execution pool where it fetches entries, generates merkle proofs, builds
    /// `StateProvision`s, groups by target shard, and returns batches via
    /// `NodeInput::ProvisionsReady` for network broadcast.
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
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (`committee_index`, vote, `public_key`, `voting_power`).
        votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (`committee_index`, vote, `voting_power`).
        verified_votes: Vec<(usize, BlockVote, u64)>,
        /// Total voting power in the committee (for quorum calculation).
        total_voting_power: u64,
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
        votes: Vec<(ExecutionVote, Bls12381G1PublicKey, u64)>,
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
        header: Arc<CommittedBlockHeader>,
        /// Public keys for the remote shard's committee (from topology).
        committee_public_keys: Vec<Bls12381G1PublicKey>,
        /// Voting power for each committee member (parallel to `committee_public_keys`).
        committee_voting_power: Vec<u64>,
        /// Quorum threshold for the remote shard.
        quorum_threshold: u64,
        /// Remote shard ID (for correlation in callback).
        shard: ShardGroupId,
        /// Remote block height (for correlation in callback).
        height: BlockHeight,
    },

    /// Verify a block's state root against the JMT.
    ///
    /// Applies the block's shard-local state changes to the JMT and compares the
    /// resulting root against the header's `state_root`.
    /// Returns `ProtocolEvent::BlockRootVerified`.
    ///
    /// The action handler walks the snapshot chain from `parent_block_hash`
    /// to build an overlay of uncommitted tree nodes, then calls
    /// `prepare_block_commit` which computes the JMT root and caches a
    /// `PreparedCommit` for efficient commit later.
    VerifyStateRoot {
        /// Block whose state root is being verified.
        block_hash: BlockHash,
        /// Parent block hash — used to walk the snapshot chain for the overlay.
        parent_block_hash: BlockHash,
        /// Base state root (parent block's `state_root`).
        parent_state_root: StateRoot,
        /// Height of the parent block (stable anchor for JMT computation).
        parent_block_height: BlockHeight,
        /// Expected state root after applying writes.
        expected_root: StateRoot,
        /// Finalized waves whose receipts contribute to the state root.
        /// The thread pool merges `DatabaseUpdates` from these.
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
        transactions: Vec<Arc<RoutableTransaction>>,
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
        certificates: Vec<Arc<FinalizedWave>>,
    },

    /// Verify a block's local receipt root.
    ///
    /// Computes the merkle root from each receipt's `receipt_hash()` and
    /// compares against the block header's claimed `local_receipt_root`.
    /// Returns `ProtocolEvent::LocalReceiptRootVerified`.
    ///
    /// Pure CPU operation — verified in parallel with other root verifications.
    VerifyLocalReceiptRoot {
        /// Block whose local receipt root is being verified.
        block_hash: BlockHash,
        /// Expected local receipt root from block header.
        expected_root: LocalReceiptRoot,
        /// Receipt bundles from finalized waves on the pending block.
        receipts: Vec<ReceiptBundle>,
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
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Topology snapshot used to route txs to target shards.
        topology: TopologySnapshot,
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
        parent_hash: BlockHash,
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
        parent_in_flight: u32,
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
        source: crate::CommitSource,
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
        source: crate::CommitSource,
    },

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
    // Network: BFT Votes
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign and broadcast a block vote to targeted recipients.
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
        /// Targeted vote recipients — the next proposer who needs this vote
        /// to build the QC for the next block.
        recipients: Vec<ValidatorId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Cache a finalized wave so peers can fetch it.
    ///
    /// Emitted by `finalize_wave` in `ExecutionCoordinator` when a wave completes.
    /// The `io_loop` inserts the `FinalizedWave` into `finalized_wave_cache`,
    /// keyed by `wave_id.hash()` (matches `BlockManifest.cert_hashes`).
    CacheFinalizedWave {
        /// Finalized wave to cache.
        wave: Arc<FinalizedWave>,
    },

    /// Persist receipt bundles to disk. Fire-and-forget — no `ProtocolEvent` response.
    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch Management
    // ═══════════════════════════════════════════════════════════════════════
    /// Propose a global block for epoch management.
    ///
    /// Only the designated global proposer (rotating based on epoch height) calls this.
    ProposeGlobalBlock {
        /// Current epoch.
        epoch: EpochId,
        /// Height within the global chain.
        height: BlockHeight,
        /// The proposed next epoch configuration (if this finalizes an epoch).
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Broadcast a shard vote for a global block.
    ///
    /// This is the "shard-level vote" - sent after 2f+1 local validators agree.
    BroadcastGlobalBlockVote {
        /// The block being voted on.
        block_hash: BlockHash,
        /// This shard's ID.
        shard: ShardGroupId,
        /// Aggregated BLS signature from 2f+1 local validators.
        shard_signature: Bls12381G2Signature,
        /// Which validators in this shard signed.
        signers: SignerBitfield,
        /// Total voting power in the shard signature.
        voting_power: VotePower,
    },

    /// Initiate epoch transition.
    ///
    /// Called when `EpochTransitionReady` event is received.
    /// Updates the topology and notifies subsystems.
    TransitionEpoch {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Propagate updated topology to the `io_loop` / network layer.
    ///
    /// Emitted by the state machine after any topology mutation (epoch
    /// transition, shard split/merge). The `io_loop` stores the snapshot
    /// into its shared topology snapshot (`ArcSwap`), rebuilds
    /// `cached_local_peers`, and updates `local_shard` / `num_shards`.
    TopologyChanged {
        /// New topology snapshot to propagate.
        topology: Arc<TopologySnapshot>,
    },

    /// Mark this validator as ready for the new epoch.
    ///
    /// Called after sync completes when validator was in Waiting state.
    MarkValidatorReady {
        /// The epoch.
        epoch: EpochId,
        /// The shard.
        shard: ShardGroupId,
    },

    /// Initiate a shard split.
    ///
    /// Marks the shard as splitting in the topology, triggering transaction rejection.
    InitiateShardSplit {
        /// The shard being split.
        source_shard: ShardGroupId,
        /// The new shard ID.
        new_shard: ShardGroupId,
        /// The hash range split point.
        split_point: u64,
    },

    /// Complete a shard split.
    ///
    /// Called after state migration is complete.
    CompleteShardSplit {
        /// The original shard.
        source_shard: ShardGroupId,
        /// The new shard.
        new_shard: ShardGroupId,
    },

    /// Initiate a shard merge.
    InitiateShardMerge {
        /// First shard.
        shard_a: ShardGroupId,
        /// Second shard.
        shard_b: ShardGroupId,
        /// Resulting shard ID.
        merged_shard: ShardGroupId,
    },

    /// Complete a shard merge.
    CompleteShardMerge {
        /// The merged shard.
        merged_shard: ShardGroupId,
    },

    /// Persist epoch configuration to storage.
    PersistEpochConfig {
        /// The epoch configuration to persist.
        config: Box<EpochConfig>,
    },

    /// Fetch the latest epoch configuration from storage.
    ///
    /// Returns via `ProtocolEvent` (to be added) when complete.
    FetchEpochConfig {
        /// Optional epoch ID to fetch (None = latest).
        epoch: Option<EpochId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Read Requests (returns callback ProtocolEvent)
    // ═══════════════════════════════════════════════════════════════════════
    /// Fetch chain metadata (latest height, hash, QC).
    ///
    /// Returns `ProtocolEvent::ChainMetadataFetched { height, hash, qc }`.
    FetchChainMetadata,

    // ═══════════════════════════════════════════════════════════════════════
    // Runner I/O Requests (network fetches handled by the runner)
    // These request the runner to perform network I/O and deliver results
    // back as NodeInputs (TransactionReceived, SyncBlockResponseReceived)
    // ═══════════════════════════════════════════════════════════════════════
    /// Request the runner to start syncing to a target height.
    ///
    /// Emitted when the state machine detects it's behind (e.g., receives a
    /// block header or QC ahead of committed height). The runner handles
    /// peer selection, fetching, validation, and delivers blocks via
    /// `ProtocolEvent::SyncBlockReadyToApply`.
    StartSync {
        /// The height we need to sync to.
        target_height: BlockHeight,
        /// The hash of the target block (for verification).
        target_hash: BlockHash,
    },

    /// Request the runner to fetch missing transactions for a pending block.
    ///
    /// Emitted when a block header arrives but transactions are missing from
    /// mempool. The runner fetches from the proposer or peers and delivers
    /// results via `ProtocolEvent::TransactionsFetched`, which routes through
    /// mempool admission and emits `Continuation(TransactionsAdmitted)`.
    FetchTransactions {
        /// Hash of the block that needs these transactions.
        block_hash: BlockHash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing transactions.
        tx_hashes: Vec<TxHash>,
    },

    /// Fetch missing provision data for a pending block (pre-BFT-vote).
    ///
    /// Same pattern as `FetchTransactions`: block header arrives, some provision
    /// hashes aren't in the local cache, fetch from proposer or local peers.
    FetchProvisionsLocal {
        /// Hash of the block that needs these provisions.
        block_hash: BlockHash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing provisions.
        batch_hashes: Vec<ProvisionHash>,
    },

    /// Fetch missing finalized wave data for a pending block.
    ///
    /// Emitted by `check_pending_block_fetches()` when a pending block has
    /// missing waves past the fetch timeout. The runner sends a
    /// `GetFinalizedWavesRequest` to the proposer first, falling back to
    /// other local-committee peers from `peers` on empty/failure responses.
    FetchFinalizedWave {
        /// Hash of the block that needs these finalized waves.
        block_hash: BlockHash,
        /// The proposer of the block (tried first).
        proposer: ValidatorId,
        /// Wave ID hashes (from `BlockManifest.cert_hashes`) of missing waves.
        wave_id_hashes: Vec<WaveIdHash>,
        /// Local-committee fallback peer pool (excluding self). The fetch
        /// protocol rotates through these when the proposer doesn't have
        /// the data cached.
        peers: Vec<ValidatorId>,
    },

    /// Request a missing execution certificate from a source shard.
    ///
    /// Emitted when an expected execution cert hasn't arrived within the timeout.
    /// Any peer in the source shard that received the wave leader's EC broadcast can serve it.
    RequestMissingExecutionCert {
        /// The shard that should have sent the execution cert.
        source_shard: ShardGroupId,
        /// The block height whose execution cert is missing.
        block_height: BlockHeight,
        /// Which wave's cert is missing.
        wave_id: WaveId,
        /// All validators in the source shard (candidate peers for the request).
        peers: Vec<ValidatorId>,
    },

    /// Cancel an in-flight execution-cert fetch because the EC arrived
    /// through another path (broadcast) or the wave no longer needs it.
    ///
    /// Without this, the fetch protocol would keep retrying forever even
    /// after the expectation has been fulfilled via `on_wave_certificate`.
    CancelExecutionCertFetch {
        /// Source shard whose EC fetch should be cancelled.
        source_shard: ShardGroupId,
        /// Block height of the EC that no longer needs fetching.
        block_height: BlockHeight,
    },

    /// Request missing provisions from a source shard via cross-shard request.
    ///
    /// Emitted by `ProvisionCoordinator` when a remote block's `waves` field
    /// targets our shard but no provisions have arrived within the timeout window.
    /// This is the fallback recovery mechanism for byzantine proposers that
    /// silently drop provisions.
    ///
    /// The runner sends a `GetProvisionsRequest` to the source shard, and the
    /// response is fed back as `ProvisionsReceived` for normal verification.
    FetchProvisionsRemote {
        /// The shard that should have sent provisions.
        source_shard: ShardGroupId,
        /// The block height whose provisions are missing.
        block_height: BlockHeight,
        /// The block proposer from the source shard (preferred peer for the request).
        proposer: ValidatorId,
        /// All validators in the source shard (candidate peers for the request).
        peers: Vec<ValidatorId>,
    },

    /// Request missing committed block header from a remote shard.
    ///
    /// Emitted by `RemoteHeaderCoordinator` when a remote shard hasn't sent
    /// committed block headers within the liveness timeout. This is the
    /// fallback recovery mechanism for proposer-only gossip.
    ///
    /// The runner sends a `GetCommittedBlockHeaderRequest` to the source shard,
    /// and the response is fed back as `RemoteBlockCommitted` for normal
    /// verification through the coordinator.
    RequestMissingCommittedBlockHeader {
        /// The shard whose headers are missing.
        source_shard: ShardGroupId,
        /// Request headers starting from this height.
        from_height: BlockHeight,
        /// All validators in the source shard (candidate peers for the request).
        peers: Vec<ValidatorId>,
    },
}

impl Action {
    /// Check if this is a continuation action.
    #[must_use]
    pub const fn is_continuation(&self) -> bool {
        matches!(self, Self::Continuation(_))
    }

    /// Get the action type name for telemetry.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }
}
