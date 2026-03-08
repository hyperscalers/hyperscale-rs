//! Action types for the deterministic state machine.

use crate::{ProtocolEvent, TimerId};
use hyperscale_messages::{
    BlockHeaderNotification, BlockVoteNotification, TransactionCertificateNotification,
    TransactionGossip,
};
use hyperscale_types::{
    Block, BlockHeight, BlockVote, Bls12381G1PublicKey, Bls12381G2Signature, CommitmentProof,
    CommittedBlockHeader, EpochConfig, EpochId, ExecutionCertificate, ExecutionVote, Hash, NodeId,
    QuorumCertificate, RoutableTransaction, ShardGroupId, SignerBitfield, StateProvision,
    TransactionAbort, TransactionCertificate, TransactionDefer, ValidatorId, VotePower,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: Hash,
    /// The transaction to execute.
    pub transaction: Arc<RoutableTransaction>,
    /// State provisions from other shards.
    pub provisions: Vec<StateProvision>,
}

/// A single cross-shard transaction's provisioning needs.
///
/// Collected per-block and sent as a batch in [`Action::FetchAndBroadcastProvisions`].
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: Hash,
    /// Nodes owned by our shard whose state we need to provision.
    pub nodes: Vec<NodeId>,
    /// Shards that need this state.
    pub target_shards: Vec<ShardGroupId>,
}

/// Actions the state machine wants to perform.
///
/// Actions are **commands** - they describe something to do.
/// The runner executes actions and may convert results back into events.
#[derive(Debug, Clone)]
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network: BFT Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a block header (proposal) to the local shard.
    BroadcastBlockHeader {
        shard: ShardGroupId,
        header: Box<BlockHeaderNotification>,
    },

    /// Broadcast a block vote to the local shard.
    BroadcastBlockVote {
        shard: ShardGroupId,
        vote: BlockVoteNotification,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Mempool & Certificates
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a transaction gossip to a shard.
    BroadcastTransaction {
        shard: ShardGroupId,
        gossip: Box<TransactionGossip>,
    },

    /// Broadcast a transaction certificate gossip to the local shard.
    BroadcastTransactionCertificate {
        shard: ShardGroupId,
        gossip: TransactionCertificateNotification,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Execution Layer (domain-specific, batchable by runner)
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast an execution vote to the local shard.
    ///
    /// The runner may batch multiple votes into a single network message
    /// for efficiency. State machines emit individual votes.
    BroadcastExecutionVote {
        shard: ShardGroupId,
        vote: ExecutionVote,
    },

    /// Broadcast an execution certificate to a remote participating shard.
    ///
    /// Only emitted for remote shards — local shard peers independently form
    /// the same certificate from the same execution votes.
    /// The runner may batch multiple certificates into a single network message
    /// for efficiency. State machines emit individual certificates.
    BroadcastExecutionCertificate {
        shard: ShardGroupId,
        certificate: Arc<ExecutionCertificate>,
    },

    /// Fetch state entries and broadcast provisions for all cross-shard txs in a block.
    ///
    /// Only the block proposer emits this (once per block). Delegated to the
    /// execution pool where it fetches entries, generates merkle proofs, builds
    /// `StateProvision`s, groups by target shard, and returns batches via
    /// `NodeInput::ProvisionsReady` for network broadcast.
    FetchAndBroadcastProvisions {
        /// One entry per cross-shard tx that needs provisioning.
        requests: Vec<ProvisionRequest>,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        block_timestamp: u64,
        state_version: u64,
    },

    /// Broadcast a committed block header globally to all shards.
    ///
    /// Used for the light-client provisions pattern. When a block commits,
    /// this broadcasts the header + QC so remote shards can verify state roots.
    BroadcastCommittedBlockHeader {
        gossip: hyperscale_messages::CommittedBlockHeaderGossip,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// Set a timer to fire after a duration.
    SetTimer { id: TimerId, duration: Duration },

    /// Cancel a previously set timer.
    CancelTimer { id: TimerId },

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
        block_hash: Hash,
        /// Shard group this QC belongs to.
        shard_group_id: ShardGroupId,
        /// Block height.
        height: BlockHeight,
        /// Round number.
        round: u64,
        /// Parent block hash (from the block's header).
        parent_block_hash: Hash,
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (committee_index, vote, public_key, voting_power).
        votes_to_verify: Vec<(usize, BlockVote, Bls12381G1PublicKey, u64)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (committee_index, vote, voting_power).
        verified_votes: Vec<(usize, BlockVote, u64)>,
        /// Total voting power in the committee (for quorum calculation).
        total_voting_power: u64,
    },

    /// Verify a batch of state provisions' QC and merkle inclusion proofs.
    ///
    /// The QC signature is verified once across candidate headers. Merkle
    /// inclusion proofs are checked per provision against the verified
    /// header's state root.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::StateProvisionsVerified` when complete.
    VerifyStateProvisions {
        /// The state provisions to verify (all from the same block).
        provisions: Vec<StateProvision>,
        /// Candidate committed block headers to try.
        /// In normal operation there is one; with byzantine validators
        /// there may be multiple (one per sender for the same (shard, height)).
        committed_headers: Vec<CommittedBlockHeader>,
        /// Public keys for the source shard's committee (from topology).
        committee_public_keys: Vec<Bls12381G1PublicKey>,
        /// Voting power for each committee member (parallel to `committee_public_keys`).
        /// Used to compute total voting power per-candidate from QC signer indices.
        committee_voting_power: Vec<u64>,
        /// Quorum threshold for the source shard.
        quorum_threshold: u64,
    },

    /// Aggregate execution votes into an ExecutionCertificate (vote quorum reached).
    ///
    /// Performs BLS signature aggregation which is compute-intensive.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Shard group that executed.
        shard: ShardGroupId,
        /// Deterministic hash-chain commitment over execution output writes.
        writes_commitment: Hash,
        /// Votes to aggregate (with quorum).
        votes: Vec<ExecutionVote>,
        /// Read nodes (for certificate).
        read_nodes: Vec<NodeId>,
        /// Committee size (for SignerBitfield capacity).
        committee_size: usize,
    },

    /// Batch verify execution votes and aggregate valid ones (cross-shard Phase 4).
    ///
    /// Defers verification until we have enough votes to possibly reach quorum.
    /// This avoids wasting CPU on votes that will never be used.
    ///
    /// The runner:
    /// 1. Batch-verifies all vote signatures (faster than individual verification)
    /// 2. Reports which votes passed verification with their voting power
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionVotesVerifiedAndAggregated` when complete.
    VerifyAndAggregateExecutionVotes {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Votes to verify with their public keys and voting power.
        /// Each tuple is (vote, public_key, voting_power).
        votes: Vec<(ExecutionVote, Bls12381G1PublicKey, u64)>,
    },

    /// Verify an execution certificate's aggregated signature (cross-shard Phase 5).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateSignatureVerified` when complete.
    VerifyExecutionCertificateSignature {
        /// The certificate to verify.
        certificate: ExecutionCertificate,
        /// Public keys of the signers (in committee order, pre-resolved by state machine).
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
        /// The QC to verify (carries shard_group_id for self-contained verification).
        qc: QuorumCertificate,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as parent_qc.
        block_hash: Hash,
    },

    /// Verify a CommitmentProof's aggregated BLS signature.
    ///
    /// This is CRITICAL for BFT safety: we must verify that the CommitmentProof
    /// has a valid aggregated signature from the claimed signers on the source shard.
    /// Without this check, a Byzantine proposer could include deferrals with forged
    /// proofs, causing honest validators to incorrectly defer transactions.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::CommitmentProofVerified` when complete.
    VerifyCommitmentProof {
        /// Block hash containing this deferral (for correlation).
        block_hash: Hash,
        /// Index of deferral in block's deferred list.
        deferral_index: usize,
        /// The CommitmentProof to verify.
        commitment_proof: CommitmentProof,
        /// Public keys of signers (resolved from SignerBitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
        /// Total voting power of the signers (resolved from SignerBitfield + topology).
        voting_power: u64,
        /// Quorum threshold for source shard.
        quorum_threshold: u64,
    },

    /// Verify a block's state root against the JMT.
    ///
    /// Computes the speculative state root from certificates and compares
    /// against the block header's claimed state_root. Returns `ProtocolEvent::StateRootVerified`.
    ///
    /// Each inner Vec represents one certificate's writes. They must be applied
    /// incrementally (one JMT version per certificate) to match commit-time behavior.
    ///
    /// The verification flow:
    /// 1. Runner checks if local JMT root matches `parent_state_root`
    /// 2. If match, extracts writes from certificates and computes new root
    /// 3. Compares computed root against `expected_root`
    /// 4. If valid, builds and caches a WriteBatch for efficient commit later
    ///
    /// This ensures proposer and verifier compute from the same base state.
    VerifyStateRoot {
        block_hash: Hash,
        /// Base state root to verify from (must match local JMT before computing).
        parent_state_root: Hash,
        /// Expected state root after applying certificate writes.
        expected_root: Hash,
        /// Certificates whose writes will be applied to compute the new root.
        certificates: Vec<Arc<TransactionCertificate>>,
    },

    /// Verify a block's transaction root.
    ///
    /// Computes the merkle root from the block's transactions (retry, priority, normal)
    /// and compares against the block header's claimed transaction_root.
    /// Returns `ProtocolEvent::TransactionRootVerified`.
    ///
    /// This is a pure CPU operation (no JMT dependency) so it can be verified
    /// in parallel with state root verification.
    VerifyTransactionRoot {
        block_hash: Hash,
        /// Expected transaction root from block header.
        expected_root: Hash,
        /// Retry transactions (highest priority section).
        retry_transactions: Vec<Arc<RoutableTransaction>>,
        /// Priority transactions (cross-shard with commitment proofs).
        priority_transactions: Vec<Arc<RoutableTransaction>>,
        /// Normal transactions.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Build a complete block proposal.
    ///
    /// The runner waits for the JMT to reach `parent_state_root`, computes the
    /// new state root, builds the complete block, and caches the WriteBatch for
    /// efficient commit later.
    ///
    /// Returns `ProtocolEvent::ProposalBuilt` with either the complete block or a
    /// timeout if the JMT doesn't catch up within the specified duration.
    ///
    /// This combines state root computation and block building into a single
    /// round-trip, enabling the proposer to use the fast commit path (1 fsync).
    BuildProposal {
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        height: BlockHeight,
        round: u64,
        parent_hash: Hash,
        parent_qc: QuorumCertificate,
        timestamp: u64,
        is_fallback: bool,
        /// Parent's state root. Certs included only if local JMT matches this.
        parent_state_root: Hash,
        /// Parent's state version (base for computing new state_version).
        parent_state_version: u64,
        retry_transactions: Vec<Arc<RoutableTransaction>>,
        priority_transactions: Vec<Arc<RoutableTransaction>>,
        transactions: Vec<Arc<RoutableTransaction>>,
        certificates: Vec<Arc<TransactionCertificate>>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        /// Shard groups that need provisions from this block's transactions.
        provision_targets: Vec<ShardGroupId>,
    },

    /// Execute a batch of single-shard transactions.
    ///
    /// Delegated to the engine thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::TransactionsExecuted` when complete.
    ExecuteTransactions {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
        state_root: Hash,
    },

    /// Speculatively execute single-shard transactions before block commit.
    ///
    /// Triggered when a block header is received, before the block commits via
    /// the 2-chain rule. This hides execution latency behind consensus latency.
    ///
    /// If a speculative result is invalidated (due to committed writes to the
    /// read set), the cached vote is discarded and the transaction falls back
    /// to normal execution on commit.
    ///
    /// Returns `ProtocolEvent::SpeculativeExecutionComplete` when complete (for cache tracking).
    SpeculativeExecute {
        /// Block hash where these transactions appear.
        block_hash: Hash,
        /// Single-shard transactions to execute speculatively.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Execute a cross-shard transaction with provisioned state.
    ///
    /// Used after cross-shard provisioning completes. The runner accumulates these actions
    /// and executes them in parallel batches for efficiency.
    /// Returns `ProtocolEvent::CrossShardTransactionsExecuted` when the batch completes.
    ExecuteCrossShardTransaction {
        /// Transaction hash (for correlation).
        tx_hash: Hash,
        /// The transaction to execute.
        transaction: Arc<RoutableTransaction>,
        /// State provisions from other shards.
        provisions: Vec<StateProvision>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // External Notifications
    // ═══════════════════════════════════════════════════════════════════════
    /// Emit a committed block for external observers.
    ///
    /// Carries the certifying QC so the runner can persist committed metadata
    /// (`set_committed_state`) after JMT state has been applied, not at
    /// certification time.
    EmitCommittedBlock {
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
    },

    /// Emit transaction status update for RPC status cache.
    ///
    /// Emitted by the mempool whenever a transaction's status changes:
    /// - Pending: Transaction accepted into mempool
    /// - Committed: Transaction included in a committed block
    /// - Executed: Transaction execution complete (accept/reject decision made)
    /// - Completed: Transaction certificate committed, can be evicted
    /// - Deferred: Transaction deferred due to cross-shard livelock
    /// - Retried: Transaction superseded by retry transaction
    ///
    /// The production runner updates the RPC status cache when processing
    /// this action, allowing clients to query transaction status via the
    /// `GET /api/v1/transactions/{hash}` endpoint.
    ///
    /// The `added_at` field tracks when the transaction was first added to the
    /// mempool, enabling end-to-end latency metrics for finalized transactions.
    EmitTransactionStatus {
        tx_hash: Hash,
        status: TransactionStatus,
        /// When the transaction was added to the mempool (for latency tracking).
        added_at: Duration,
        /// Whether this is a cross-shard transaction (for metrics labeling).
        cross_shard: bool,
        /// Whether this transaction was submitted locally (via RPC) vs received via gossip/fetch.
        /// Only locally-submitted transactions should contribute to latency metrics.
        submitted_locally: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Persist a certified block to storage for sync availability.
    ///
    /// This stores the block data only — it does NOT update committed metadata.
    /// Committed metadata (`set_committed_state`) is persisted by the runner
    /// after JMT state has been applied, to prevent committed_height from
    /// getting ahead of actual JMT state on crash recovery.
    PersistBlock {
        block: Block,
        /// The QC that certified this block (stored alongside block data).
        qc: QuorumCertificate,
    },

    /// Persist a vote and broadcast it as a single atomic action.
    ///
    /// **BFT Safety Critical**: The runner MUST persist the vote before broadcasting.
    /// This action combines `PersistOwnVote` and `BroadcastToShard` into a single
    /// action, allowing the runner to:
    /// 1. Start persistence (potentially async with fsync)
    /// 2. Wait for persistence to complete
    /// 3. Then broadcast the vote
    PersistAndBroadcastVote {
        height: BlockHeight,
        round: u64,
        block_hash: Hash,
        shard: ShardGroupId,
        vote: BlockVoteNotification,
        /// Targeted vote recipients — the next proposer who needs this vote
        /// to build the QC for the next block.
        recipients: Vec<ValidatorId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Persist a finalized transaction certificate with its state writes.
    ///
    /// This is the deferred commit operation - state writes are only applied when
    /// a `TransactionCertificate` is included in a committed block. The runner
    /// extracts writes from `certificate.shard_proofs[local_shard]` and commits
    /// them atomically with the certificate.
    ///
    /// Stored so we don't re-execute if we crash and recover.
    PersistTransactionCertificate { certificate: TransactionCertificate },

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
        block_hash: Hash,
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
    /// Called when EpochTransitionReady event is received.
    /// Updates the DynamicTopology and notifies subsystems.
    TransitionEpoch {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
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
    /// Returns via ProtocolEvent (to be added) when complete.
    FetchEpochConfig {
        /// Optional epoch ID to fetch (None = latest).
        epoch: Option<EpochId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Read Requests (returns callback ProtocolEvent)
    // ═══════════════════════════════════════════════════════════════════════
    /// Fetch a block by height.
    ///
    /// Returns `ProtocolEvent::BlockFetched { height, block }`.
    FetchBlock { height: BlockHeight },

    /// Fetch chain metadata (latest height, hash, QC).
    ///
    /// Returns `ProtocolEvent::ChainMetadataFetched { height, hash, qc }`.
    FetchChainMetadata,

    // ═══════════════════════════════════════════════════════════════════════
    // Runner I/O Requests (network fetches handled by the runner)
    // These request the runner to perform network I/O and deliver results
    // back as NodeInputs (TransactionReceived, CertificateReceived, SyncBlockResponseReceived)
    // ═══════════════════════════════════════════════════════════════════════
    /// Request the runner to start syncing to a target height.
    ///
    /// Emitted when the state machine detects it's behind (e.g., receives a
    /// block header or QC ahead of committed height). The runner handles
    /// peer selection, fetching, validation, and delivers blocks via
    /// `ProtocolEvent::SyncBlockReadyToApply`.
    StartSync {
        /// The height we need to sync to.
        target_height: u64,
        /// The hash of the target block (for verification).
        target_hash: Hash,
    },

    /// Request the runner to fetch missing transactions for a pending block.
    ///
    /// Emitted when a block header arrives but transactions are missing from
    /// mempool. The runner fetches from the proposer or peers and delivers
    /// results via `ProtocolEvent::TransactionFetchDelivered`.
    FetchTransactions {
        /// Hash of the block that needs these transactions.
        block_hash: Hash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing transactions.
        tx_hashes: Vec<Hash>,
    },

    /// Request the runner to fetch missing certificates for a pending block.
    ///
    /// Emitted when a block header arrives but certificates are missing locally.
    /// The runner fetches from the proposer or peers and delivers results via
    /// `ProtocolEvent::CertificateFetchDelivered`.
    FetchCertificates {
        /// Hash of the block that needs these certificates.
        block_hash: Hash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing certificates (transaction hashes).
        cert_hashes: Vec<Hash>,
    },

    /// Cancel any pending fetch operations for a block.
    ///
    /// Emitted when a pending block is removed from BFT state (committed, stale,
    /// or superseded by sync). The runner should cancel any in-flight fetch
    /// operations for this block to free up resources.
    CancelFetch {
        /// Hash of the block whose fetches should be cancelled.
        block_hash: Hash,
    },

    /// Request missing provisions from a source shard via cross-shard request.
    ///
    /// Emitted by `ProvisionCoordinator` when a remote block's `provision_targets`
    /// includes our shard but no provisions have arrived within the timeout window.
    /// This is the fallback recovery mechanism for byzantine proposers that
    /// silently drop provisions.
    ///
    /// The runner sends a `GetProvisionsRequest` to the source shard, and the
    /// response is fed back as `StateProvisionsReceived` for normal verification.
    RequestMissingProvisions {
        /// The shard that should have sent provisions.
        source_shard: ShardGroupId,
        /// The block height whose provisions are missing.
        block_height: BlockHeight,
        /// The block proposer from the source shard (preferred peer for the request).
        proposer: ValidatorId,
    },
}

impl Action {
    /// Check if this action requires async I/O (network or storage writes).
    pub fn is_async(&self) -> bool {
        matches!(
            self,
            Action::BroadcastBlockHeader { .. }
                | Action::BroadcastBlockVote { .. }
                | Action::BroadcastTransaction { .. }
                | Action::BroadcastTransactionCertificate { .. }
                | Action::BroadcastExecutionVote { .. }
                | Action::BroadcastExecutionCertificate { .. }
                | Action::BroadcastCommittedBlockHeader { .. }
                | Action::PersistBlock { .. }
                | Action::PersistAndBroadcastVote { .. }
                | Action::PersistTransactionCertificate { .. }
                | Action::RequestMissingProvisions { .. }
        )
    }

    /// Check if this action is delegated work (runs on thread pool, returns callback).
    pub fn is_delegated(&self) -> bool {
        matches!(
            self,
            Action::VerifyAndBuildQuorumCertificate { .. }
                | Action::VerifyStateProvisions { .. }
                | Action::AggregateExecutionCertificate { .. }
                | Action::VerifyAndAggregateExecutionVotes { .. }
                | Action::VerifyExecutionCertificateSignature { .. }
                | Action::VerifyQcSignature { .. }
                | Action::VerifyCommitmentProof { .. }
                | Action::VerifyStateRoot { .. }
                | Action::VerifyTransactionRoot { .. }
                | Action::BuildProposal { .. }
                | Action::ExecuteTransactions { .. }
                | Action::SpeculativeExecute { .. }
                | Action::ExecuteCrossShardTransaction { .. }
                | Action::FetchAndBroadcastProvisions { .. }
                | Action::FetchBlock { .. }
                | Action::FetchChainMetadata
        )
    }

    /// Check if this is a continuation action.
    pub fn is_continuation(&self) -> bool {
        matches!(self, Action::Continuation(_))
    }

    /// Get the action type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Network - BFT Consensus
            Action::BroadcastBlockHeader { .. } => "BroadcastBlockHeader",
            Action::BroadcastBlockVote { .. } => "BroadcastBlockVote",

            // Network - Mempool & Certificates
            Action::BroadcastTransaction { .. } => "BroadcastTransaction",
            Action::BroadcastTransactionCertificate { .. } => "BroadcastTransactionCertificate",

            // Network - Execution Layer (batchable)
            Action::BroadcastExecutionVote { .. } => "BroadcastExecutionVote",
            Action::BroadcastExecutionCertificate { .. } => "BroadcastExecutionCertificate",
            Action::BroadcastCommittedBlockHeader { .. } => "BroadcastCommittedBlockHeader",

            // Timers
            Action::SetTimer { .. } => "SetTimer",
            Action::CancelTimer { .. } => "CancelTimer",

            // Continuation
            Action::Continuation(_) => "Continuation",

            // Delegated Work - Crypto Verification
            Action::VerifyAndBuildQuorumCertificate { .. } => "VerifyAndBuildQuorumCertificate",
            Action::VerifyStateProvisions { .. } => "VerifyStateProvisions",
            Action::AggregateExecutionCertificate { .. } => "AggregateExecutionCertificate",
            Action::VerifyAndAggregateExecutionVotes { .. } => "VerifyAndAggregateExecutionVotes",
            Action::VerifyExecutionCertificateSignature { .. } => {
                "VerifyExecutionCertificateSignature"
            }
            Action::VerifyQcSignature { .. } => "VerifyQcSignature",
            Action::VerifyCommitmentProof { .. } => "VerifyCommitmentProof",
            Action::VerifyStateRoot { .. } => "VerifyStateRoot",
            Action::VerifyTransactionRoot { .. } => "VerifyTransactionRoot",
            Action::BuildProposal { .. } => "BuildProposal",

            // Delegated Work - Execution
            Action::ExecuteTransactions { .. } => "ExecuteTransactions",
            Action::SpeculativeExecute { .. } => "SpeculativeExecute",
            Action::ExecuteCrossShardTransaction { .. } => "ExecuteCrossShardTransaction",
            Action::FetchAndBroadcastProvisions { .. } => "FetchAndBroadcastProvisions",

            // External Notifications
            Action::EmitCommittedBlock { .. } => "EmitCommittedBlock",
            Action::EmitTransactionStatus { .. } => "EmitTransactionStatus",

            // Storage - Consensus
            Action::PersistBlock { .. } => "PersistBlock",
            Action::PersistAndBroadcastVote { .. } => "PersistAndBroadcastVote",

            // Storage - Execution
            Action::PersistTransactionCertificate { .. } => "PersistTransactionCertificate",

            // Storage - Read Requests
            Action::FetchBlock { .. } => "FetchBlock",
            Action::FetchChainMetadata => "FetchChainMetadata",

            // Global Consensus / Epoch Management
            Action::ProposeGlobalBlock { .. } => "ProposeGlobalBlock",
            Action::BroadcastGlobalBlockVote { .. } => "BroadcastGlobalBlockVote",
            Action::TransitionEpoch { .. } => "TransitionEpoch",
            Action::MarkValidatorReady { .. } => "MarkValidatorReady",
            Action::InitiateShardSplit { .. } => "InitiateShardSplit",
            Action::CompleteShardSplit { .. } => "CompleteShardSplit",
            Action::InitiateShardMerge { .. } => "InitiateShardMerge",
            Action::CompleteShardMerge { .. } => "CompleteShardMerge",
            Action::PersistEpochConfig { .. } => "PersistEpochConfig",
            Action::FetchEpochConfig { .. } => "FetchEpochConfig",

            // Runner I/O Requests
            Action::StartSync { .. } => "StartSync",
            Action::FetchTransactions { .. } => "FetchTransactions",
            Action::FetchCertificates { .. } => "FetchCertificates",
            Action::CancelFetch { .. } => "CancelFetch",
            Action::RequestMissingProvisions { .. } => "RequestMissingProvisions",
        }
    }
}

// Re-export TransactionStatus from types crate
pub use hyperscale_types::TransactionStatus;
