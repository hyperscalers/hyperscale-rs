//! Action types for the deterministic state machine.

use crate::{ProtocolEvent, TimerId};
use hyperscale_messages::{BlockHeaderNotification, BlockVoteNotification, TransactionGossip};
use hyperscale_types::{
    Block, BlockHeight, BlockVote, Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader,
    Conflict, EpochConfig, EpochId, ExecutionCertificate, ExecutionVote, FinalizedWave, Hash,
    NodeId, ProvisionBatch, QuorumCertificate, ReceiptBundle, RoutableTransaction, ShardGroupId,
    SignerBitfield, StateProvision, TopologySnapshot, TxOutcome, ValidatorId, VotePower,
    WaveCertificate, WaveId,
};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Phase timing breakdown for transaction finalization.
///
/// Tracks wall-clock timestamps (as `Duration` since process start) at each
/// phase transition, enabling diagnosis of slow finalization.
#[derive(Debug, Clone)]
pub struct FinalizationPhaseTimes {
    /// When the transaction was first added to the mempool.
    pub added_at: Duration,
    /// When the block containing the transaction was committed.
    pub committed_at: Option<Duration>,
    /// When the wave certificate was created (execution + vote collection complete).
    pub executed_at: Option<Duration>,
    /// When the transaction reached terminal state (TC committed in block).
    pub completed_at: Duration,
}

impl fmt::Display for FinalizationPhaseTimes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self
            .completed_at
            .saturating_sub(self.added_at)
            .as_secs_f64();
        let mempool_to_commit = self
            .committed_at
            .map(|c| c.saturating_sub(self.added_at).as_secs_f64());
        let commit_to_exec = match (self.committed_at, self.executed_at) {
            (Some(c), Some(e)) => Some(e.saturating_sub(c).as_secs_f64()),
            _ => None,
        };
        let exec_to_complete = self
            .executed_at
            .map(|e| self.completed_at.saturating_sub(e).as_secs_f64());

        write!(f, "total={total:.3}s")?;
        if let Some(v) = mempool_to_commit {
            write!(f, " mempool={v:.3}s")?;
        }
        if let Some(v) = commit_to_exec {
            write!(f, " execution={v:.3}s")?;
        }
        if let Some(v) = exec_to_complete {
            write!(f, " tc_inclusion={v:.3}s")?;
        }
        // If we have committed_at but no executed_at, show the commit→complete span
        if let (Some(c), None) = (self.committed_at, self.executed_at) {
            let v = self.completed_at.saturating_sub(c).as_secs_f64();
            write!(f, " commit_to_complete={v:.3}s")?;
        }
        Ok(())
    }
}

/// Why a transaction inclusion proof is being fetched.
#[derive(Debug, Clone)]
pub enum InclusionProofFetchReason {
    /// Livelock deferral — deliver proof to livelock state machine.
    Deferral {
        /// The transaction being deferred (loser in cycle detection).
        loser_tx_hash: Hash,
    },
}

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

/// A transaction whose provisioning is complete, with all collected provisions.
#[derive(Debug, Clone)]
pub struct ProvisionedTransaction {
    pub tx_hash: Hash,
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

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Mempool & Certificates
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a transaction gossip to a shard.
    BroadcastTransaction {
        shard: ShardGroupId,
        gossip: Box<TransactionGossip>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Execution Layer (domain-specific, batchable by runner)
    // ═══════════════════════════════════════════════════════════════════════
    /// Sign and send an execution vote to the wave leader.
    ///
    /// Emitted by the state machine when a wave completes (all txs executed).
    /// The io_loop signs the vote (it owns the signing key) and sends it to
    /// the wave leader only (N→1 instead of N→N).
    SignAndSendExecutionVote {
        block_hash: Hash,
        block_height: u64,
        /// Consensus height at which this vote is being cast.
        vote_height: u64,
        wave_id: WaveId,
        global_receipt_root: Hash,
        /// Per-tx outcomes in wave order. Carried on the vote so the wave leader
        /// can extract them directly when building the EC (avoids relying on the
        /// leader's local accumulator which may have diverged).
        tx_outcomes: Vec<TxOutcome>,
        /// The wave leader for this wave — sole recipient of the vote.
        target: ValidatorId,
    },

    /// Broadcast an execution certificate to remote participating shards.
    ///
    /// Execution certificates cover all transactions in a wave. Recipients are
    /// the union of all participating shards across all txs in the wave.
    BroadcastExecutionCertificate {
        shard: ShardGroupId,
        certificate: Arc<ExecutionCertificate>,
        /// Target shard peers (excluding self) for the broadcast.
        recipients: Vec<ValidatorId>,
    },

    /// Track an aggregated execution certificate for serving and eventual commit.
    ///
    /// Emitted by all validators after cert aggregation (not just the wave
    /// leader). The io_loop stores these in the in-memory cache for
    /// low-latency serving and queues them in `pending_ec_writes` for
    /// atomic persistence in the next block commit's WriteBatch.
    TrackExecutionCertificate {
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
        /// Per-shard recipients for provision broadcasts (excluding self).
        shard_recipients: HashMap<ShardGroupId, Vec<ValidatorId>>,
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

    /// Verify a provision batch's verkle inclusion proofs.
    ///
    /// The QC was already verified by `RemoteHeaderCoordinator` when the header
    /// was promoted to verified, so this only checks verkle proofs against the
    /// committed header's state root.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::StateProvisionsVerified` when complete.
    VerifyProvisionBatch {
        /// The provision batch to verify (all from the same source block).
        batch: ProvisionBatch,
        /// The QC-verified committed block header from RemoteHeaderCoordinator.
        committed_header: Arc<CommittedBlockHeader>,
    },

    /// Aggregate execution votes into an ExecutionCertificate (quorum reached).
    ///
    /// Performs BLS signature aggregation on execution votes.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionCertificateAggregated` when complete.
    AggregateExecutionCertificate {
        /// Wave identifier.
        wave_id: WaveId,
        /// Shard group that executed.
        shard: ShardGroupId,
        /// Global receipt root (merkle root over per-tx outcome leaves).
        global_receipt_root: Hash,
        /// Votes to aggregate (with quorum). The first vote's `tx_outcomes`
        /// is used for the EC payload (all quorum votes have identical outcomes).
        votes: Vec<ExecutionVote>,
        /// Ordered committee for the shard (for SignerBitfield index mapping).
        committee: Vec<ValidatorId>,
    },

    /// Batch verify execution votes (deferred verification).
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionVotesVerifiedAndAggregated` when complete.
    VerifyAndAggregateExecutionVotes {
        /// Wave identifier.
        wave_id: WaveId,
        /// Block hash for correlation.
        block_hash: Hash,
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
        /// The QC to verify (carries shard_group_id for self-contained verification).
        qc: QuorumCertificate,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<Bls12381G1PublicKey>,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as parent_qc.
        block_hash: Hash,
    },

    /// Verify a remote block header's QC for cross-shard deferral validation.
    ///
    /// Verifies the aggregated BLS signature on the QC, checks voting power meets
    /// quorum, and confirms block_hash matches hash(header).
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

    /// Request a transaction inclusion proof from a source shard for livelock deferral.
    ///
    /// Request a transaction inclusion proof from a source shard.
    ///
    /// Used for both livelock deferrals and priority tx proofs under backpressure.
    /// The I/O loop sends this as a network request; the response is delivered
    /// back as `NodeInput::InclusionProofFetchReceived`.
    RequestTxInclusionProofs {
        /// Source shard to fetch proofs from.
        source_shard: ShardGroupId,
        /// Block height on the source shard.
        source_block_height: BlockHeight,
        /// Transactions to prove inclusion for, with the reason for each.
        entries: Vec<(Hash, InclusionProofFetchReason)>,
        /// Peers in the source shard to send the request to.
        peers: Vec<ValidatorId>,
    },

    /// Verify a block's state root against the JVT.
    ///
    /// Applies the block's shard-local state changes to the JVT and compares the
    /// resulting root against the header's `state_root`.
    /// Returns `ProtocolEvent::StateRootVerified`.
    ///
    /// The verification flow:
    /// 1. Runner checks if local JVT root matches `parent_state_root`
    /// 2. Applies per-certificate updates to compute new JVT root
    /// 3. Compares computed root against `expected_root`
    /// 4. If valid, builds and caches a WriteBatch for efficient commit later
    ///
    /// The caller (state machine) is responsible for sourcing writes from the
    /// execution cache, filtering to local shard, and merging.
    VerifyStateRoot {
        block_hash: Hash,
        /// Base state root to verify from (must match local JVT before computing).
        parent_state_root: Hash,
        /// Expected state root after applying writes.
        expected_root: Hash,
        /// Finalized waves whose receipts contribute to the state root.
        /// The thread pool merges DatabaseUpdates from these.
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Block height (used as JVT version).
        block_height: u64,
    },

    /// Verify a block's transaction root.
    ///
    /// Computes the merkle root from the block's transactions and compares
    /// against the block header's claimed transaction_root.
    /// Returns `ProtocolEvent::TransactionRootVerified`.
    ///
    /// This is a pure CPU operation (no JVT dependency) so it can be verified
    /// in parallel with state root verification.
    VerifyTransactionRoot {
        block_hash: Hash,
        /// Expected transaction root from block header.
        expected_root: Hash,
        /// Transactions in the block.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Verify a block's receipt root.
    ///
    /// Computes the merkle root from the certificates' `receipt_hash` values
    /// and compares against the block header's claimed `certificate_root`.
    /// Returns `ProtocolEvent::CertificateRootVerified`.
    ///
    /// Pure CPU operation — verified in parallel with state root and transaction root.
    VerifyCertificateRoot {
        block_hash: Hash,
        /// Expected receipt root from block header.
        expected_root: Hash,
        /// Wave certificates whose receipt_hash values form the merkle leaves.
        certificates: Vec<Arc<WaveCertificate>>,
    },

    /// Verify a block's local receipt root.
    ///
    /// Computes the merkle root from each receipt's `receipt_hash()` and
    /// compares against the block header's claimed `local_receipt_root`.
    /// Returns `ProtocolEvent::LocalReceiptRootVerified`.
    ///
    /// Pure CPU operation — verified in parallel with other root verifications.
    VerifyLocalReceiptRoot {
        block_hash: Hash,
        /// Expected local receipt root from block header.
        expected_root: Hash,
        /// Receipt bundles from finalized waves on the pending block.
        receipts: Vec<ReceiptBundle>,
    },

    /// Verify conflict inclusion proofs off-thread.
    ///
    /// For each livelock conflict, verifies the merkle inclusion proof for the
    /// winner transaction against the source block's QC-attested `transaction_root`.
    /// Returns `ProtocolEvent::ConflictProofsVerified`.
    VerifyConflictProofs {
        block_hash: Hash,
        /// Pairs of (conflict, transaction_root from remote committed header).
        /// The transaction_root is QC-attested — looked up by NodeStateMachine
        /// from the ProvisionCoordinator's verified remote headers.
        proof_inputs: Vec<(Conflict, Hash)>,
    },

    /// Build a complete block proposal.
    ///
    /// Computes the new state root from certificates, builds the complete block,
    /// and caches the WriteBatch for efficient commit later.
    ///
    /// Returns `ProtocolEvent::ProposalBuilt` with the complete block.
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
        /// Parent's state root. Certs included only if local JVT matches this.
        parent_state_root: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Finalized waves to include in the block (carries certs + receipts + ECs).
        finalized_waves: Vec<Arc<FinalizedWave>>,
        conflicts: Vec<Conflict>,
        /// Cross-shard execution waves in this block.
        waves: Vec<WaveId>,
    },

    /// Execute a batch of single-shard transactions.
    ///
    /// Delegated to the engine thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::ExecutionBatchCompleted` with all votes when complete.
    ExecuteTransactions {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
        state_root: Hash,
    },

    /// Execute a batch of cross-shard transactions with provisioned state.
    ///
    /// Used after cross-shard provisioning completes. The state machine batches
    /// all ready transactions and emits a single action for parallel execution.
    /// Returns `ProtocolEvent::ExecutionBatchCompleted` when complete.
    ExecuteCrossShardTransactions {
        /// The cross-shard execution requests to process.
        requests: Vec<CrossShardExecutionRequest>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Block Commit
    // ═══════════════════════════════════════════════════════════════════════
    /// Commit a consensus block atomically: block data + JVT + substates +
    /// receipts + ECs + consensus metadata.
    ///
    /// Used for blocks this node participated in consensus for. The io_loop
    /// uses the `PreparedCommit` from `VerifyStateRoot` and extracts receipts
    /// from `finalized_waves`.
    CommitBlock {
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
        /// Finalized waves carrying receipts from local execution.
        finalized_waves: Vec<Arc<FinalizedWave>>,
    },

    /// Commit a synced block atomically: block data + JVT + substates +
    /// receipts + ECs + consensus metadata.
    ///
    /// Used for blocks fetched via sync protocol. The io_loop uses receipts
    /// and ECs from `pending_sync_data` (buffered when the sync response
    /// arrived) — no `PreparedCommit` or `finalized_waves` needed.
    CommitSyncedBlock {
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
    /// - Completed: Wave certificate committed, can be evicted
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
        /// Phase timing breakdown for finalized transactions (populated only for terminal statuses).
        phase_times: Option<FinalizationPhaseTimes>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: BFT Votes
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a block vote to targeted recipients.
    ///
    /// Sent to the next proposer who needs this vote to build the QC.
    BroadcastVote {
        vote: BlockVoteNotification,
        /// Targeted vote recipients — the next proposer who needs this vote
        /// to build the QC for the next block.
        recipients: Vec<ValidatorId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Cache a finalized wave certificate so peers can fetch it.
    ///
    /// Emitted by `finalize_wave` in `ExecutionState` when a wave completes.
    /// The io_loop inserts the certificate into `cert_cache` keyed by
    /// `wave_id.hash()`, which matches the `cert_hashes` entries in
    /// `BlockManifest`. Peers fetch wave certificates via
    CacheWaveCertificate { certificate: Arc<WaveCertificate> },

    /// Persist receipt bundles to disk. Fire-and-forget — no ProtocolEvent response.
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
    /// Updates the topology and notifies subsystems.
    TransitionEpoch {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Propagate updated topology to the io_loop / network layer.
    ///
    /// Emitted by the state machine after any topology mutation (epoch
    /// transition, shard split/merge). The io_loop stores the snapshot
    /// into its shared topology snapshot (`ArcSwap`), rebuilds
    /// `cached_local_peers`, and updates `local_shard` / `num_shards`.
    TopologyChanged { topology: Arc<TopologySnapshot> },

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

    /// Cancel any pending fetch operations for a block.
    ///
    /// Emitted when a pending block is removed from BFT state (committed, stale,
    /// or superseded by sync). The runner should cancel any in-flight fetch
    /// operations for this block to free up resources.
    CancelFetch {
        /// Hash of the block whose fetches should be cancelled.
        block_hash: Hash,
    },

    /// Cancel a pending provision fetch request.
    ///
    /// Emitted by `ProvisionCoordinator` when proactive provisions are verified
    /// before the fallback fetch completes. This prevents the fallback response
    /// from delivering duplicate provisions that would leak memory.
    CancelProvisionFetch {
        /// The shard whose provisions were fetched.
        source_shard: ShardGroupId,
        /// The block height of the provisions.
        block_height: BlockHeight,
    },

    /// Request a missing execution certificate from a source shard.
    ///
    /// Emitted when an expected execution cert hasn't arrived within the timeout.
    /// The wave leader may be byzantine or slow, so we request from
    /// any peer in the source shard, preferring the wave leader first.
    RequestMissingExecutionCert {
        /// The shard that should have sent the execution cert.
        source_shard: ShardGroupId,
        /// The block height whose execution cert is missing.
        block_height: u64,
        /// Which wave's cert is missing.
        wave_id: WaveId,
        /// Wave leader for the missing wave (tried first as preferred peer).
        wave_leader: ValidatorId,
        /// All validators in the source shard (candidate peers for the request).
        peers: Vec<ValidatorId>,
    },

    /// Request missing provisions from a source shard via cross-shard request.
    ///
    /// Emitted by `ProvisionCoordinator` when a remote block's `waves` field
    /// targets our shard but no provisions have arrived within the timeout window.
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
    pub fn is_continuation(&self) -> bool {
        matches!(self, Action::Continuation(_))
    }

    /// Get the action type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Network - BFT Consensus
            Action::BroadcastBlockHeader { .. } => "BroadcastBlockHeader",

            // Network - Mempool
            Action::BroadcastTransaction { .. } => "BroadcastTransaction",

            // Network - Execution Layer (batchable)
            Action::SignAndSendExecutionVote { .. } => "SignAndSendExecutionVote",
            Action::BroadcastExecutionCertificate { .. } => "BroadcastExecutionCertificate",
            Action::TrackExecutionCertificate { .. } => "TrackExecutionCertificate",
            Action::BroadcastCommittedBlockHeader { .. } => "BroadcastCommittedBlockHeader",

            // Timers
            Action::SetTimer { .. } => "SetTimer",
            Action::CancelTimer { .. } => "CancelTimer",

            // Continuation
            Action::Continuation(_) => "Continuation",

            // Delegated Work - Crypto Verification
            Action::VerifyAndBuildQuorumCertificate { .. } => "VerifyAndBuildQuorumCertificate",
            Action::VerifyProvisionBatch { .. } => "VerifyProvisionBatch",
            Action::AggregateExecutionCertificate { .. } => "AggregateExecutionCertificate",
            Action::VerifyAndAggregateExecutionVotes { .. } => "VerifyAndAggregateExecutionVotes",
            Action::VerifyExecutionCertificateSignature { .. } => {
                "VerifyExecutionCertificateSignature"
            }
            Action::VerifyQcSignature { .. } => "VerifyQcSignature",
            Action::VerifyRemoteHeaderQc { .. } => "VerifyRemoteHeaderQc",
            Action::VerifyStateRoot { .. } => "VerifyStateRoot",
            Action::VerifyTransactionRoot { .. } => "VerifyTransactionRoot",
            Action::VerifyCertificateRoot { .. } => "VerifyCertificateRoot",
            Action::VerifyLocalReceiptRoot { .. } => "VerifyLocalReceiptRoot",
            Action::VerifyConflictProofs { .. } => "VerifyConflictProofs",
            Action::BuildProposal { .. } => "BuildProposal",

            // Delegated Work - Execution
            Action::ExecuteTransactions { .. } => "ExecuteTransactions",
            Action::ExecuteCrossShardTransactions { .. } => "ExecuteCrossShardTransactions",
            Action::FetchAndBroadcastProvisions { .. } => "FetchAndBroadcastProvisions",

            // External Notifications
            Action::CommitBlock { .. } => "CommitBlock",
            Action::CommitSyncedBlock { .. } => "CommitSyncedBlock",
            Action::EmitTransactionStatus { .. } => "EmitTransactionStatus",

            // Storage - Consensus
            Action::BroadcastVote { .. } => "BroadcastVote",

            // Storage - Execution
            Action::CacheWaveCertificate { .. } => "CacheWaveCertificate",

            // Storage - Read Requests
            Action::FetchChainMetadata => "FetchChainMetadata",

            // Global Consensus / Epoch Management
            Action::ProposeGlobalBlock { .. } => "ProposeGlobalBlock",
            Action::BroadcastGlobalBlockVote { .. } => "BroadcastGlobalBlockVote",
            Action::TransitionEpoch { .. } => "TransitionEpoch",
            Action::TopologyChanged { .. } => "TopologyChanged",
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
            Action::CancelFetch { .. } => "CancelFetch",
            Action::RequestMissingProvisions { .. } => "RequestMissingProvisions",
            Action::RequestMissingExecutionCert { .. } => "RequestMissingExecutionCert",
            Action::CancelProvisionFetch { .. } => "CancelProvisionFetch",
            Action::RequestTxInclusionProofs { .. } => "RequestTxInclusionProof",
            Action::RequestMissingCommittedBlockHeader { .. } => {
                "RequestMissingCommittedBlockHeader"
            }
        }
    }
}

// Re-export TransactionStatus from types crate
pub use hyperscale_types::TransactionStatus;
