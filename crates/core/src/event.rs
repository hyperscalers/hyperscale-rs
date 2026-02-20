//! Event types for the deterministic state machine.

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockVote, CommitmentProof, EpochConfig, EpochId,
    ExecutionResult, Hash, QuorumCertificate, RoutableTransaction, ShardGroupId, StateCertificate,
    StateEntry, StateProvision, StateVoteBlock, TransactionAbort, TransactionCertificate,
    TransactionDefer, ValidatorId,
};
use std::sync::Arc;

/// Priority levels for event ordering within the same timestamp.
///
/// Events at the same simulation time are processed in priority order.
/// Lower values = higher priority (processed first).
///
/// This ensures causality is preserved: internal events (consequences of
/// processing an event) are handled before new external inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EventPriority {
    /// Internal events: consequences of prior event processing.
    /// Processed first to maintain causality.
    Internal = 0,

    /// Timer events: scheduled by the node itself.
    Timer = 1,

    /// Network events: external inputs from other nodes.
    Network = 2,

    /// Client events: external inputs from users.
    Client = 3,
}

/// All possible events a node can receive.
///
/// Events are **passive data** - they describe something that happened.
/// The state machine processes events and returns actions.
#[derive(Debug, Clone)]
pub enum Event {
    // ═══════════════════════════════════════════════════════════════════════
    // Timers (priority: Timer)
    // ═══════════════════════════════════════════════════════════════════════
    /// Time to propose a new block (if this node is the proposer).
    /// Also used for implicit round advancement when no QC is formed.
    ProposalTimer,

    /// Periodic cleanup of stale state.
    CleanupTimer,

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - BFT (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block header from another node.
    ///
    /// Note: Sender identity comes from message signatures (ValidatorId),
    /// not from a `from` field. Production uses gossipsub with signed messages.
    ///
    /// Transaction hashes are split into three priority sections:
    /// - retry_hashes: Retry transactions (highest priority)
    /// - priority_hashes: Cross-shard transactions with commitment proofs
    /// - tx_hashes: All other transactions
    BlockHeaderReceived {
        header: BlockHeader,
        /// Retry transaction hashes (highest priority).
        retry_hashes: Vec<Hash>,
        /// Priority transaction hashes (cross-shard with proofs).
        priority_hashes: Vec<Hash>,
        /// Other transaction hashes (normal priority).
        tx_hashes: Vec<Hash>,
        /// Certificate hashes.
        cert_hashes: Vec<Hash>,
        /// Deferred transactions in this block (livelock prevention).
        deferred: Vec<TransactionDefer>,
        /// Aborted transactions in this block.
        aborted: Vec<TransactionAbort>,
        /// Commitment proofs for priority transaction ordering.
        commitment_proofs: std::collections::HashMap<Hash, CommitmentProof>,
    },

    /// Received a vote on a block header.
    ///
    /// Sender identity comes from vote.voter (ValidatorId).
    BlockVoteReceived { vote: BlockVote },

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - Execution (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received state provision for cross-shard execution.
    ///
    /// Sender identity comes from provision.validator_id.
    StateProvisionReceived { provision: StateProvision },

    /// Received a state vote for cross-shard execution.
    ///
    /// Sender identity comes from vote.validator_id.
    StateVoteReceived { vote: StateVoteBlock },

    /// Received a state certificate for cross-shard execution.
    StateCertificateReceived { cert: StateCertificate },

    /// Received a finalized transaction certificate via gossip.
    ///
    /// This is gossiped to same-shard peers so they can persist the certificate
    /// before the proposer includes it in a block. This ensures the certificate
    /// is available for fetch requests when other validators receive the block header.
    TransactionCertificateReceived { certificate: TransactionCertificate },

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - Mempool (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a transaction via gossip (or validated RPC submission).
    TransactionGossipReceived {
        tx: Arc<RoutableTransaction>,
        /// Set to `true` when the transaction originated from this node's RPC.
        /// Propagated to mempool's `PoolEntry` so finalization metrics are only
        /// recorded once (on the submitting node).
        submitted_locally: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Events (priority: Internal)
    // These replace channel sends between async tasks
    // ═══════════════════════════════════════════════════════════════════════
    /// A quorum certificate was formed for a block.
    QuorumCertificateFormed {
        block_hash: Hash,
        qc: QuorumCertificate,
    },

    /// A block is ready to be committed.
    BlockReadyToCommit {
        block_hash: Hash,
        qc: QuorumCertificate,
    },

    /// A block was committed to storage.
    ///
    /// The full block is included so subsystems can process:
    /// - Transactions (execution, mempool status updates)
    /// - Certificates (finalization)
    /// - Deferrals (livelock prevention - release locks, queue retries)
    /// - Aborts (livelock prevention - release locks, mark as failed)
    BlockCommitted {
        /// Hash of the committed block.
        block_hash: Hash,
        /// Height of the committed block.
        height: u64,
        /// The full committed block (includes transactions, certificates, deferrals, aborts).
        block: Block,
    },

    /// Transaction execution completed.
    ///
    /// Emitted by the execution state machine when a TransactionCertificate
    /// is created (either single-shard or cross-shard 2PC completion).
    /// This notifies mempool to update transaction status to Executed.
    ///
    /// Note: State is NOT yet updated at this point. The certificate must be
    /// included in a block (triggering Completed status) before state changes
    /// are applied.
    TransactionExecuted {
        tx_hash: Hash,
        /// Whether the transaction was accepted or rejected.
        accepted: bool,
    },

    /// A transaction's status has changed.
    ///
    /// Emitted by the execution state machine when a transaction transitions
    /// through its lifecycle states (Committed, Executed, etc.).
    /// This allows mempool to track the detailed status of transactions
    /// and ensure proper state lock management.
    TransactionStatusChanged {
        tx_hash: Hash,
        /// The new status of the transaction.
        status: hyperscale_types::TransactionStatus,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Async Callbacks (priority: Internal)
    // Results from delegated work (crypto, execution)
    // ═══════════════════════════════════════════════════════════════════════
    /// Quorum Certificate verification and building result.
    ///
    /// Callback from `Action::VerifyAndBuildQuorumCertificate`.
    ///
    /// Either contains a successfully built QC (if quorum was reached with valid
    /// signatures), or the verified votes that passed signature verification
    /// (so the state machine can wait for more votes and retry).
    QuorumCertificateResult {
        /// Block hash the QC is for.
        block_hash: Hash,
        /// The built QC if quorum was reached with valid signatures.
        qc: Option<QuorumCertificate>,
        /// Votes that passed signature verification, with their committee index
        /// and voting power. Only populated when `qc` is None (need more votes).
        /// Each tuple is (committee_index, vote, voting_power).
        verified_votes: Vec<(usize, BlockVote, u64)>,
    },

    /// Batch provision verification and aggregation completed.
    ///
    /// Callback from `Action::VerifyAndAggregateProvisions`.
    /// Contains only the provisions that passed signature verification,
    /// plus the aggregated commitment proof (if we have enough valid signatures).
    ProvisionsVerifiedAndAggregated {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Source shard the provisions are from.
        source_shard: ShardGroupId,
        /// Provisions that passed signature verification (may be fewer than input).
        verified_provisions: Vec<StateProvision>,
        /// Aggregated commitment proof from valid signatures, if quorum reached.
        /// None if no valid signatures or aggregation failed.
        commitment_proof: Option<CommitmentProof>,
    },

    /// State certificate aggregation completed.
    ///
    /// Callback from `Action::AggregateStateCertificate`.
    /// Contains the aggregated BLS signature proving vote quorum.
    StateCertificateAggregated {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// The aggregated state certificate.
        certificate: StateCertificate,
    },

    /// Batch state vote verification completed.
    ///
    /// Callback from `Action::VerifyAndAggregateStateVotes`.
    /// Contains only the votes that passed signature verification.
    StateVotesVerifiedAndAggregated {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Verified votes with their voting power.
        /// Only includes votes that passed signature verification.
        verified_votes: Vec<(StateVoteBlock, u64)>,
    },

    /// State certificate signature verification completed.
    ///
    /// Callback from `Action::VerifyStateCertificateSignature`.
    StateCertificateSignatureVerified {
        /// The certificate that was verified.
        certificate: StateCertificate,
        /// Whether the aggregated signature is valid.
        valid: bool,
    },

    /// Quorum Certificate signature verification completed.
    ///
    /// Callback from `Action::VerifyQcSignature`.
    QcSignatureVerified {
        /// The block hash this QC verification is associated with.
        /// This is the hash of the block whose header contains this QC as parent_qc.
        block_hash: Hash,
        /// Whether the aggregated signature is valid.
        valid: bool,
    },

    /// CycleProof signature verification completed.
    ///
    /// Callback from `Action::VerifyCycleProof`.
    CycleProofVerified {
        /// Block hash containing this deferral.
        block_hash: Hash,
        /// Index of deferral in block's deferred list.
        deferral_index: usize,
        /// Whether signature is valid AND meets quorum.
        valid: bool,
    },

    /// State root verification completed.
    ///
    /// Callback from `Action::VerifyStateRoot`. Reports whether the block's
    /// claimed state_root matches the computed JMT root after applying all
    /// certificates.
    ///
    /// If valid=false, the validator MUST NOT vote for this block - the proposer
    /// included an incorrect state root.
    StateRootVerified {
        /// Block hash this verification was for.
        block_hash: Hash,
        /// Whether the state root matches.
        /// true = proposer's state_root is correct, safe to vote
        /// false = proposer's state_root is WRONG, reject block
        valid: bool,
    },

    /// Transaction root verification completed.
    ///
    /// Callback from `Action::VerifyTransactionRoot`. Reports whether the block's
    /// claimed transaction_root matches the computed merkle root from the block's
    /// transactions (retry, priority, normal sections).
    ///
    /// If valid=false, the validator MUST NOT vote for this block - the proposer
    /// included an incorrect transaction root.
    TransactionRootVerified {
        /// Block hash this verification was for.
        block_hash: Hash,
        /// Whether the transaction root matches.
        /// true = proposer's transaction_root is correct, safe to vote
        /// false = proposer's transaction_root is WRONG, reject block
        valid: bool,
    },

    /// Proposal block built by the runner.
    ///
    /// Callback from `Action::BuildProposal`. Contains the complete block
    /// ready for broadcast, or indicates timeout if JMT didn't catch up.
    ///
    /// The runner waits for the JMT to reach the parent state, computes the
    /// state root, builds the complete block, and caches the WriteBatch for
    /// efficient commit later.
    ProposalBuilt {
        /// Height of the proposal (for correlation).
        height: BlockHeight,
        /// Round of the proposal (for correlation).
        round: u64,
        /// The built block.
        block: Arc<Block>,
        /// Pre-computed block hash.
        block_hash: Hash,
    },

    /// JMT state commit completed for a block's certificates.
    ///
    /// Sent by the runner after the async `spawn_blocking` JMT commit finishes.
    /// NodeStateMachine tracks the last committed state to ensure proposals
    /// and verifications use up-to-date JMT state.
    ///
    /// This prevents race conditions where speculative root computation reads
    /// stale JMT state because async commits haven't finished yet.
    StateCommitComplete {
        /// Height of the block whose certificates were committed.
        height: u64,
        /// The JMT version after applying all certificates.
        /// This is the version number to use as base for speculative computation.
        state_version: u64,
        /// The resulting JMT state root after applying all certificates.
        state_root: Hash,
    },

    /// Single-shard transaction execution completed.
    TransactionsExecuted {
        block_hash: Hash,
        results: Vec<ExecutionResult>,
    },

    /// Speculative execution of single-shard transactions completed.
    ///
    /// Callback from `Action::SpeculativeExecute`. With inline signing, the votes
    /// have already been sent via `StateVoteReceived` events. This event is used
    /// to update cache tracking (remove from in-flight, mark as speculatively executed).
    ///
    /// The execution state machine uses this to know which transactions have been
    /// speculatively executed, so it can skip re-execution when the block commits.
    SpeculativeExecutionComplete {
        /// Block hash where these transactions appear.
        block_hash: Hash,
        /// Transaction hashes that were speculatively executed.
        /// The votes have already been signed and sent.
        tx_hashes: Vec<Hash>,
    },

    /// Cross-shard transaction execution completed (batch).
    ///
    /// Callback from batched `Action::ExecuteCrossShardTransaction` actions.
    /// The runner accumulates individual actions and executes them in parallel.
    CrossShardTransactionsExecuted { results: Vec<ExecutionResult> },

    /// Merkle root computation completed.
    MerkleRootComputed { tx_hash: Hash, root: Hash },

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Coordinator Events (priority: Internal)
    // Events emitted by ProvisionCoordinator for cross-shard coordination
    // ═══════════════════════════════════════════════════════════════════════
    /// Quorum of provisions reached for a source shard.
    ///
    /// Emitted by ProvisionCoordinator when enough verified provisions have been
    /// collected from a source shard. This is the ONLY trigger for cycle detection
    /// in livelock (Byzantine-safe because only verified provisions count).
    ///
    /// Note: This is emitted per-shard as quorum is reached, not once for all shards.
    /// Livelock uses this for cycle detection; execution waits for all required shards.
    ProvisionQuorumReached {
        /// The transaction these provisions are for.
        tx_hash: Hash,
        /// The source shard that reached quorum.
        source_shard: ShardGroupId,
        /// Aggregated proof of commitment from the source shard.
        ///
        /// Contains the aggregated BLS signature from all validators who provided
        /// provisions, plus the state entries. This proof enables:
        /// - Livelock to build CycleProof for deferrals
        /// - Backpressure bypass for transactions with proof
        commitment_proof: CommitmentProof,
    },

    /// All required shards have reached provision quorum - ready for execution.
    ///
    /// Emitted by ProvisionCoordinator when ALL required source shards have reached
    /// quorum. This triggers cross-shard execution in ExecutionState.
    ProvisioningComplete {
        /// The transaction that is now ready for cross-shard execution.
        tx_hash: Hash,
        /// One provision per required shard (majority-selected from quorum).
        provisions: Vec<StateProvision>,
    },

    /// Cross-shard transaction registered for provision tracking.
    ///
    /// Emitted by ExecutionState when a cross-shard transaction is committed.
    /// ProvisionCoordinator uses this to start tracking provisions for the transaction.
    CrossShardTxRegistered {
        /// The transaction hash.
        tx_hash: Hash,
        /// Shards we need provisions from.
        required_shards: std::collections::BTreeSet<ShardGroupId>,
        /// Quorum threshold per shard.
        quorum_thresholds: std::collections::HashMap<ShardGroupId, usize>,
        /// Block height when committed.
        committed_height: BlockHeight,
    },

    /// Cross-shard transaction completed successfully.
    ///
    /// Emitted when a cross-shard transaction's certificate is committed.
    /// ProvisionCoordinator uses this to clean up tracking state.
    CrossShardTxCompleted {
        /// The transaction hash.
        tx_hash: Hash,
    },

    /// Cross-shard transaction aborted.
    ///
    /// Emitted when a cross-shard transaction is aborted (timeout or failure).
    /// ProvisionCoordinator uses this to clean up tracking state.
    CrossShardTxAborted {
        /// The transaction hash.
        tx_hash: Hash,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks (priority: Internal)
    // Results from storage read operations
    // ═══════════════════════════════════════════════════════════════════════
    /// State entries fetched for cross-shard provisioning.
    ///
    /// Callback from `Action::FetchStateEntries`.
    StateEntriesFetched {
        tx_hash: Hash,
        entries: Vec<StateEntry>,
    },

    /// Block fetched from storage.
    ///
    /// Callback from `Action::FetchBlock`.
    BlockFetched {
        height: BlockHeight,
        block: Option<Block>,
    },

    /// Chain metadata fetched from storage.
    ///
    /// Callback from `Action::FetchChainMetadata`.
    ChainMetadataFetched {
        /// Latest committed height (0 if no blocks committed).
        height: BlockHeight,
        /// Latest block hash (None if no blocks committed).
        hash: Option<Hash>,
        /// Latest QC (None if no blocks committed).
        qc: Option<QuorumCertificate>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Client Requests (priority: Client)
    // ═══════════════════════════════════════════════════════════════════════
    /// Client submitted a transaction.
    SubmitTransaction { tx: Arc<RoutableTransaction> },

    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch Events (priority varies by type)
    // ═══════════════════════════════════════════════════════════════════════
    /// Timer for global consensus operations (priority: Timer).
    GlobalConsensusTimer,

    /// Received a global block proposal from another validator (priority: Network).
    ///
    /// Global blocks contain epoch transition decisions: shuffles, splits, merges.
    GlobalBlockReceived {
        /// Epoch this block belongs to.
        epoch: EpochId,
        /// Block height within the global chain.
        height: BlockHeight,
        /// Proposer of this global block.
        proposer: ValidatorId,
        /// Hash of the proposed block.
        block_hash: Hash,
        /// The next epoch configuration (if this block finalizes an epoch transition).
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Received a vote on a global block (priority: Network).
    ///
    /// This is a "shard vote" - represents 2f+1 agreement within a shard.
    GlobalBlockVoteReceived {
        /// The block being voted on.
        block_hash: Hash,
        /// The shard casting this vote.
        shard: ShardGroupId,
        /// Aggregated signature from 2f+1 validators in the shard.
        shard_signature: hyperscale_types::Bls12381G2Signature,
        /// Which validators in the shard signed.
        signers: hyperscale_types::SignerBitfield,
        /// Total voting power represented.
        voting_power: hyperscale_types::VotePower,
    },

    /// Global quorum certificate formed (priority: Internal).
    ///
    /// 2/3 of shards have voted, epoch transition can proceed.
    GlobalQcFormed {
        /// The block that achieved global quorum.
        block_hash: Hash,
        /// The epoch being finalized.
        epoch: EpochId,
    },

    /// Epoch transition is imminent (priority: Internal).
    ///
    /// Emitted when the local shard reaches epoch_end_height.
    /// Triggers: stop accepting new transactions, drain in-flight ones.
    EpochEndApproaching {
        /// Current epoch that is ending.
        current_epoch: EpochId,
        /// Height at which epoch ends.
        end_height: BlockHeight,
    },

    /// Ready to transition to next epoch (priority: Internal).
    ///
    /// Emitted when:
    /// 1. All in-flight transactions have completed/aborted
    /// 2. Global consensus has finalized the next epoch config
    /// 3. Validator has synced to new shard (if shuffled)
    EpochTransitionReady {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Epoch transition completed (priority: Internal).
    ///
    /// The DynamicTopology has been updated, new epoch is now active.
    EpochTransitionComplete {
        /// The new active epoch.
        new_epoch: EpochId,
        /// This validator's new shard (may have changed due to shuffle).
        new_shard: ShardGroupId,
        /// Whether this validator is in Waiting state (needs to sync).
        is_waiting: bool,
    },

    /// Validator finished syncing to new shard after shuffle (priority: Internal).
    ///
    /// Transitions validator from Waiting to Active state.
    ValidatorSyncComplete {
        /// The epoch in which sync completed.
        epoch: EpochId,
        /// The shard that was synced to.
        shard: ShardGroupId,
    },

    /// Shard split initiated (priority: Internal).
    ///
    /// Emitted when global consensus decides to split a shard.
    /// Triggers: reject new transactions for affected NodeIds, drain in-flight.
    ShardSplitInitiated {
        /// The shard being split.
        source_shard: ShardGroupId,
        /// The new shard that will receive half the state.
        new_shard: ShardGroupId,
        /// The hash range boundary for the split.
        split_point: u64,
    },

    /// Shard split completed (priority: Internal).
    ///
    /// State has been migrated, both shards are now operational.
    ShardSplitComplete {
        /// The original shard (now smaller hash range).
        source_shard: ShardGroupId,
        /// The new shard (other half of hash range).
        new_shard: ShardGroupId,
    },

    /// Shard merge initiated (priority: Internal).
    ShardMergeInitiated {
        /// First shard being merged.
        shard_a: ShardGroupId,
        /// Second shard being merged.
        shard_b: ShardGroupId,
        /// The resulting merged shard ID.
        merged_shard: ShardGroupId,
    },

    /// Shard merge completed (priority: Internal).
    ShardMergeComplete {
        /// The resulting merged shard.
        merged_shard: ShardGroupId,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Sync Protocol Events (priority varies by type)
    // Note: SyncNeeded is now Action::StartSync (runner I/O request)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block from sync (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    /// The runner handles peer selection and retry logic.
    SyncBlockReceived {
        /// The requested block.
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
    },

    /// A synced block is ready to be applied to local state (priority: Internal).
    ///
    /// This is different from BlockReadyToCommit - it's for blocks we fetched
    /// from peers, not blocks we participated in consensus for.
    SyncBlockReadyToApply { block: Block, qc: QuorumCertificate },

    /// Sync completed successfully (priority: Internal).
    SyncComplete {
        /// The height we synced to.
        height: u64,
    },

    /// Sync block response received from network callback (priority: Internal).
    SyncBlockResponseReceived {
        height: u64,
        block: Box<Option<(Block, QuorumCertificate)>>,
    },

    /// Sync block fetch failed from network callback (priority: Internal).
    SyncBlockFetchFailed { height: u64 },

    /// Fetch transactions failed from network callback (priority: Internal).
    FetchTransactionsFailed { block_hash: Hash, hashes: Vec<Hash> },

    /// Fetch certificates failed from network callback (priority: Internal).
    FetchCertificatesFailed { block_hash: Hash, hashes: Vec<Hash> },

    // ═══════════════════════════════════════════════════════════════════════
    // Transaction Fetch Protocol (priority: Network)
    // Used when block header arrives but transactions are missing from mempool
    // BFT emits Action::FetchTransactions; runner handles retries and delivers results.
    // ═══════════════════════════════════════════════════════════════════════
    /// Received transactions from a fetch request (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    TransactionReceived {
        /// Hash of the block these transactions are for.
        block_hash: Hash,
        /// The fetched transactions.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate Fetch Protocol (priority: Network)
    // Used when block header arrives but certificates are missing locally
    // BFT emits Action::FetchCertificates; runner handles retries and delivers results.
    // ═══════════════════════════════════════════════════════════════════════
    /// Received certificates from a fetch request (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    /// Each certificate must be verified before use.
    CertificateReceived {
        /// Hash of the block these certificates are for.
        block_hash: Hash,
        /// The fetched certificates.
        certificates: Vec<TransactionCertificate>,
    },

    /// A fetched certificate has been verified (priority: Internal).
    ///
    /// Emitted after all embedded StateCertificate signatures in a
    /// TransactionCertificate have been verified against topology.
    FetchedCertificateVerified {
        /// Hash of the block this certificate is for.
        block_hash: Hash,
        /// The verified certificate.
        certificate: TransactionCertificate,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Gossiped Certificate Verification (priority: Internal)
    // Runner verifies gossiped TransactionCertificates before persisting.
    // ═══════════════════════════════════════════════════════════════════════
    /// A shard's signature in a gossiped certificate has been verified (priority: Internal).
    ///
    /// Internal callback from the crypto pool. When all shards are verified,
    /// runner emits GossipedCertificateVerified.
    GossipedCertificateSignatureVerified {
        /// Transaction hash identifying the certificate.
        tx_hash: Hash,
        /// Shard whose StateCertificate was verified.
        shard: ShardGroupId,
        /// Whether the aggregated signature is valid.
        valid: bool,
    },

    /// A gossiped TransactionCertificate has been fully verified (priority: Internal).
    ///
    /// Emitted by the runner after verifying all embedded StateCertificate
    /// signatures. The certificate has been persisted to storage; state machine
    /// should cancel local certificate building and add to finalized certificates.
    GossipedCertificateVerified {
        /// The verified certificate.
        certificate: TransactionCertificate,
    },
}

impl Event {
    /// Get the priority for this event type.
    ///
    /// Events at the same timestamp are processed in priority order,
    /// ensuring causality is preserved.
    pub fn priority(&self) -> EventPriority {
        match self {
            // Internal events (processed first at same time)
            Event::QuorumCertificateFormed { .. }
            | Event::BlockReadyToCommit { .. }
            | Event::BlockCommitted { .. }
            | Event::TransactionExecuted { .. }
            | Event::TransactionStatusChanged { .. }
            | Event::QuorumCertificateResult { .. }
            | Event::ProvisionsVerifiedAndAggregated { .. }
            | Event::StateVotesVerifiedAndAggregated { .. }
            | Event::StateCertificateSignatureVerified { .. }
            | Event::QcSignatureVerified { .. }
            | Event::CycleProofVerified { .. }
            | Event::StateRootVerified { .. }
            | Event::TransactionRootVerified { .. }
            | Event::ProposalBuilt { .. }
            | Event::TransactionsExecuted { .. }
            | Event::SpeculativeExecutionComplete { .. }
            | Event::CrossShardTransactionsExecuted { .. }
            | Event::MerkleRootComputed { .. }
            | Event::ProvisionQuorumReached { .. }
            | Event::ProvisioningComplete { .. }
            | Event::CrossShardTxRegistered { .. }
            | Event::CrossShardTxCompleted { .. }
            | Event::CrossShardTxAborted { .. }
            | Event::StateEntriesFetched { .. }
            | Event::BlockFetched { .. }
            | Event::ChainMetadataFetched { .. } => EventPriority::Internal,

            // Timer events
            Event::ProposalTimer
            | Event::CleanupTimer
            | Event::FetchTick
            | Event::GlobalConsensusTimer => EventPriority::Timer,

            // Network events
            Event::BlockHeaderReceived { .. }
            | Event::BlockVoteReceived { .. }
            | Event::StateProvisionReceived { .. }
            | Event::StateVoteReceived { .. }
            | Event::StateCertificateReceived { .. }
            | Event::TransactionGossipReceived { .. }
            | Event::GlobalBlockReceived { .. }
            | Event::GlobalBlockVoteReceived { .. } => EventPriority::Network,

            // Client events (processed last at same time)
            Event::SubmitTransaction { .. } => EventPriority::Client,

            // Global consensus internal events
            Event::GlobalQcFormed { .. }
            | Event::EpochEndApproaching { .. }
            | Event::EpochTransitionReady { .. }
            | Event::EpochTransitionComplete { .. }
            | Event::ValidatorSyncComplete { .. }
            | Event::ShardSplitInitiated { .. }
            | Event::ShardSplitComplete { .. }
            | Event::ShardMergeInitiated { .. }
            | Event::ShardMergeComplete { .. } => EventPriority::Internal,

            // Sync events have varying priorities
            // Note: SyncNeeded is now Action::StartSync
            Event::SyncBlockReadyToApply { .. }
            | Event::SyncComplete { .. }
            | Event::SyncBlockResponseReceived { .. }
            | Event::SyncBlockFetchFailed { .. }
            | Event::FetchTransactionsFailed { .. }
            | Event::FetchCertificatesFailed { .. } => EventPriority::Internal,

            Event::SyncBlockReceived { .. } => EventPriority::Network,

            // Transaction/certificate fetch events (runner handles retries)
            Event::TransactionReceived { .. } => EventPriority::Network,
            Event::CertificateReceived { .. } => EventPriority::Network,
            Event::FetchedCertificateVerified { .. } => EventPriority::Internal,

            // BLS aggregation callbacks
            Event::StateCertificateAggregated { .. } => EventPriority::Internal,

            // Transaction certificate gossip
            Event::TransactionCertificateReceived { .. } => EventPriority::Network,

            // Gossiped certificate verification callbacks
            Event::GossipedCertificateSignatureVerified { .. } => EventPriority::Internal,
            Event::GossipedCertificateVerified { .. } => EventPriority::Internal,

            // JMT state commit callback
            Event::StateCommitComplete { .. } => EventPriority::Internal,
        }
    }

    /// Check if this is an internal event (consequence of prior processing).
    pub fn is_internal(&self) -> bool {
        self.priority() == EventPriority::Internal
    }

    /// Check if this is a network event (from another node).
    pub fn is_network(&self) -> bool {
        self.priority() == EventPriority::Network
    }

    /// Check if this is a client event (from a user).
    pub fn is_client(&self) -> bool {
        self.priority() == EventPriority::Client
    }

    /// Get the event type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Timers
            Event::ProposalTimer => "ProposalTimer",
            Event::CleanupTimer => "CleanupTimer",
            Event::FetchTick => "FetchTick",

            // Network - BFT
            Event::BlockHeaderReceived { .. } => "BlockHeaderReceived",
            Event::BlockVoteReceived { .. } => "BlockVoteReceived",

            // Network - Execution
            Event::StateProvisionReceived { .. } => "StateProvisionReceived",
            Event::StateVoteReceived { .. } => "StateVoteReceived",
            Event::StateCertificateReceived { .. } => "StateCertificateReceived",
            Event::TransactionCertificateReceived { .. } => "TransactionCertificateReceived",

            // Network - Mempool
            Event::TransactionGossipReceived { .. } => "TransactionGossipReceived",

            // Internal Events
            Event::QuorumCertificateFormed { .. } => "QuorumCertificateFormed",
            Event::BlockReadyToCommit { .. } => "BlockReadyToCommit",
            Event::BlockCommitted { .. } => "BlockCommitted",
            Event::TransactionExecuted { .. } => "TransactionExecuted",
            Event::TransactionStatusChanged { .. } => "TransactionStatusChanged",

            // Async Callbacks - Crypto Verification
            Event::QuorumCertificateResult { .. } => "QuorumCertificateResult",
            Event::ProvisionsVerifiedAndAggregated { .. } => "ProvisionsVerifiedAndAggregated",
            Event::StateVotesVerifiedAndAggregated { .. } => "StateVotesVerifiedAndAggregated",
            Event::StateCertificateSignatureVerified { .. } => "StateCertificateSignatureVerified",
            Event::QcSignatureVerified { .. } => "QcSignatureVerified",
            Event::CycleProofVerified { .. } => "CycleProofVerified",
            Event::StateRootVerified { .. } => "StateRootVerified",
            Event::TransactionRootVerified { .. } => "TransactionRootVerified",
            Event::ProposalBuilt { .. } => "ProposalBuilt",

            // Async Callbacks - Execution
            Event::TransactionsExecuted { .. } => "TransactionsExecuted",
            Event::SpeculativeExecutionComplete { .. } => "SpeculativeExecutionComplete",
            Event::CrossShardTransactionsExecuted { .. } => "CrossShardTransactionsExecuted",
            Event::MerkleRootComputed { .. } => "MerkleRootComputed",

            // Provision Coordinator Events
            Event::ProvisionQuorumReached { .. } => "ProvisionQuorumReached",
            Event::ProvisioningComplete { .. } => "ProvisioningComplete",
            Event::CrossShardTxRegistered { .. } => "CrossShardTxRegistered",
            Event::CrossShardTxCompleted { .. } => "CrossShardTxCompleted",
            Event::CrossShardTxAborted { .. } => "CrossShardTxAborted",

            // Storage Callbacks
            Event::StateEntriesFetched { .. } => "StateEntriesFetched",
            Event::BlockFetched { .. } => "BlockFetched",
            Event::ChainMetadataFetched { .. } => "ChainMetadataFetched",

            // Client Requests
            Event::SubmitTransaction { .. } => "SubmitTransaction",

            // Global Consensus / Epoch
            Event::GlobalConsensusTimer => "GlobalConsensusTimer",
            Event::GlobalBlockReceived { .. } => "GlobalBlockReceived",
            Event::GlobalBlockVoteReceived { .. } => "GlobalBlockVoteReceived",
            Event::GlobalQcFormed { .. } => "GlobalQcFormed",
            Event::EpochEndApproaching { .. } => "EpochEndApproaching",
            Event::EpochTransitionReady { .. } => "EpochTransitionReady",
            Event::EpochTransitionComplete { .. } => "EpochTransitionComplete",
            Event::ValidatorSyncComplete { .. } => "ValidatorSyncComplete",
            Event::ShardSplitInitiated { .. } => "ShardSplitInitiated",
            Event::ShardSplitComplete { .. } => "ShardSplitComplete",
            Event::ShardMergeInitiated { .. } => "ShardMergeInitiated",
            Event::ShardMergeComplete { .. } => "ShardMergeComplete",

            // Sync Protocol (SyncNeeded is now Action::StartSync)
            Event::SyncBlockReceived { .. } => "SyncBlockReceived",
            Event::SyncBlockReadyToApply { .. } => "SyncBlockReadyToApply",
            Event::SyncComplete { .. } => "SyncComplete",
            Event::SyncBlockResponseReceived { .. } => "SyncBlockResponseReceived",
            Event::SyncBlockFetchFailed { .. } => "SyncBlockFetchFailed",

            // Transaction/Certificate Fetch Protocol (runner handles retries)
            Event::TransactionReceived { .. } => "TransactionReceived",
            Event::CertificateReceived { .. } => "CertificateReceived",
            Event::FetchedCertificateVerified { .. } => "FetchedCertificateVerified",
            Event::FetchTransactionsFailed { .. } => "FetchTransactionsFailed",
            Event::FetchCertificatesFailed { .. } => "FetchCertificatesFailed",

            // BLS aggregation callbacks
            Event::StateCertificateAggregated { .. } => "StateCertificateAggregated",

            // Gossiped certificate verification
            Event::GossipedCertificateSignatureVerified { .. } => {
                "GossipedCertificateSignatureVerified"
            }
            Event::GossipedCertificateVerified { .. } => "GossipedCertificateVerified",

            // JMT state commit callback
            Event::StateCommitComplete { .. } => "StateCommitComplete",
        }
    }
}
